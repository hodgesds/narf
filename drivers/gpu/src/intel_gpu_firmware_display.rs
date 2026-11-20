//! Fixed-mode KMS for an external-only Gen12 board still scanning the GOP
//! framebuffer. The CPU copies to the handoff, as in Linux simpledrm.

use crate::drm::card::{
    Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType, NativeOutput,
    PixelFormat,
};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pipes::{self as pipes, Pipe};
use narf_graphics_driver::generic::GenericFb;

/// skl_get_initial_plane_config reads size, stride and GGTT surface from
/// the enabled primary. Require a latched, origin-aligned, linear XRGB8888
/// plane whose bytes are the ones the bootloader actually handed us.
fn matches_pipe(io: &impl MmioWindow, pipe: Pipe, fb: GenericFb, offset: u64) -> bool {
    let plane = pipe.base() + pipes::PLANE_PRIMARY_OFFSET;
    let conf = io.read32(pipe.base() + pipes::PIPECONF_OFFSET);
    let running = pipes::PIPECONF_ENABLE | pipes::PIPECONF_STATE;
    if conf == u32::MAX || conf & running != running {
        return false;
    }
    let ctl = io.read32(plane + pipes::PLANE_CTL_OFFSET);
    // skl_universal_plane_regs.h: ENABLE, ICL format, RGBX order,
    // render/media decompression, tiling, flip, async update and rotation.
    let layout = pipes::PLANE_CTL_ENABLE
        | (31 << 23)
        | (1 << 20)
        | (1 << 15)
        | (7 << 10)
        | (3 << 8)
        | (1 << 4)
        | 3;
    let expected = pipes::PLANE_CTL_ENABLE | pipes::PixelFormat::Argb8888.encode_for_plane_ctl();
    ctl & layout == expected
        && io.read32(plane + pipes::PLANE_OFFSET_OFFSET) == 0
        && io.read32(plane + pipes::PLANE_POS_OFFSET) == 0
        && io.read32(plane + pipes::PLANE_SIZE_OFFSET) == ((fb.height - 1) << 16) | (fb.width - 1)
        && io.read32(plane + pipes::PLANE_STRIDE_OFFSET) & 0xfff == fb.pitch / 64
        && u64::from(io.read32(plane + pipes::PLANE_SURF_OFFSET)) == offset
        && u64::from(io.read32(plane + 0x2c)) == offset // PLANE_SURFLIVE
}

pub(super) fn scanout(
    io: &impl MmioWindow,
    aperture: u64,
    len: u64,
    fb: GenericFb,
) -> Option<GenericFb> {
    let offset = fb.addr.checked_sub(aperture)?;
    // Hotplug and native scanout may use the fixed GGTT windows starting
    // at 16 MiB. Their PTEs must never alias the retained firmware mapping.
    let bytes = u64::from(fb.pitch) * u64::from(fb.height);
    if !io.display_access_ok()
        || fb.addr == 0
        || fb.bpp != 32
        || !(1..=16384).contains(&fb.width)
        || !(1..=16384).contains(&fb.height)
        || fb.pitch < fb.width * 4
        || fb.pitch % 64 != 0
        || fb.pitch / 64 > 0xfff
        || offset & 0xfff != 0
        || offset.checked_add(bytes)? > crate::intel_gpu_gtt::SCANOUT_GTT_OFFSET_PIPE_A
        || fb.addr.checked_add(bytes)? > aperture.checked_add(len)?
    {
        return None;
    }
    if ![Pipe::A, Pipe::B, Pipe::C, Pipe::D]
        .into_iter()
        .any(|pipe| matches_pipe(io, pipe, fb, offset))
        || !io.display_access_ok()
    {
        return None;
    }
    Some(fb)
}

pub(super) fn fixed_mode_card(fb: GenericFb) -> Card {
    let mode = crate::Mode {
        width: fb.width,
        height: fb.height,
        bpp: fb.bpp,
        refresh_hz: 60,
    };
    let mut timing = crate::drm::ioctl::mode_to_wire(&mode);
    // A fixed userspace timing for this framebuffer. No timing is programmed.
    timing.r#type = (1 << 6) | (1 << 3); // DRM_MODE_TYPE_DRIVER | PREFERRED
    let mut card = Card::new("intel-gpu", "NARF Intel iGPU driver", (1, 0, 0));
    card.firmware_scanout = Some(fb);
    card.plane_formats = Some(&[PixelFormat::Xrgb8888 as u32, PixelFormat::Argb8888 as u32]);
    card.crtcs.push(Crtc {
        id: 1,
        mode: Some(mode),
        enabled: true,
        primary_fb: None,
        x: 0,
        y: 0,
    });
    card.encoders.push(Encoder {
        id: 2,
        encoder_type: EncoderType::None,
        possible_crtcs: 1,
        possible_clones: 0,
        crtc_id: Some(1),
    });
    card.connectors.push(Connector {
        id: 3,
        connector_type: ConnectorType::Unknown,
        connector_type_id: 1,
        status: ConnectorStatus::Connected,
        encoder_id: Some(2),
        modes: alloc::vec![mode],
    });
    card.native.push(NativeOutput {
        connector: 3,
        edid: None,
        timings: alloc::vec![timing],
        broadcast_rgb: None,
        vrr_capable: None,
        colorspace: None,
        hdr_output_metadata: None,
        max_bpc: None,
        color_format: None,
    });
    card
}

/// Keep the next physical boot diagnosable from the root log when the GOP
/// handoff and the live register image differ. Called only on probe refusal.
pub(super) fn log_mismatch(io: &impl MmioWindow, aperture: u64, fb: GenericFb) {
    use core::fmt::Write;
    let _ = writeln!(
        narf_console::Writer,
        "intel-gpu: firmware framebuffer {:#x} {}x{} pitch {} bpp {}, GMADR {aperture:#x}",
        fb.addr,
        fb.width,
        fb.height,
        fb.pitch,
        fb.bpp
    );
    for pipe in [Pipe::A, Pipe::B, Pipe::C, Pipe::D] {
        if !io.display_access_ok() {
            break;
        }
        let conf = io.read32(pipe.base() + pipes::PIPECONF_OFFSET);
        if conf == u32::MAX || conf & pipes::PIPECONF_ENABLE == 0 {
            continue;
        }
        let plane = pipe.base() + pipes::PLANE_PRIMARY_OFFSET;
        let _ = writeln!(narf_console::Writer,
            "intel-gpu: firmware pipe {pipe:?} conf={conf:#x} ctl={:#x} size={:#x} stride={:#x} pos={:#x} offset={:#x} surf={:#x} live={:#x}",
            io.read32(plane + pipes::PLANE_CTL_OFFSET), io.read32(plane + pipes::PLANE_SIZE_OFFSET),
            io.read32(plane + pipes::PLANE_STRIDE_OFFSET), io.read32(plane + pipes::PLANE_POS_OFFSET),
            io.read32(plane + pipes::PLANE_OFFSET_OFFSET), io.read32(plane + pipes::PLANE_SURF_OFFSET), io.read32(plane + 0x2c));
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Registers([(u64, u32); 6]);
    impl MmioWindow for Registers {
        fn read32(&self, off: u64) -> u32 {
            self.0
                .iter()
                .find(|(reg, _)| *reg == off)
                .map_or(0, |(_, value)| *value)
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("firmware KMS discovery wrote a display register")
        }
    }

    fn smoke_gen12_external_firmware_kms() -> TestResult {
        let pipe = Pipe::B;
        let plane = pipe.base() + pipes::PLANE_PRIMARY_OFFSET;
        let mut io = Registers([
            (
                pipe.base() + pipes::PIPECONF_OFFSET,
                pipes::PIPECONF_ENABLE | pipes::PIPECONF_STATE,
            ),
            (
                plane + pipes::PLANE_CTL_OFFSET,
                pipes::PLANE_CTL_ENABLE | pipes::PixelFormat::Argb8888.encode_for_plane_ctl(),
            ),
            (plane + pipes::PLANE_SIZE_OFFSET, (599 << 16) | 799),
            (plane + pipes::PLANE_STRIDE_OFFSET, 50),
            (plane + pipes::PLANE_SURF_OFFSET, 0x2000),
            (plane + 0x2c, 0x2000),
        ]);
        let aperture = 0x40_0000_0000;
        let fb = GenericFb::new(aperture + 0x2000, 800, 600, 3200, 32);
        let size = 0x2000 + u64::from(fb.pitch) * u64::from(fb.height);
        let state = fixed_mode_card(scanout(&io, aperture, size, fb).unwrap());
        assert_eq!(state.connectors[0].connector_type, ConnectorType::Unknown);
        assert_eq!(state.encoders[0].encoder_type, EncoderType::None);
        let wire = state.mode_wire(&state.connectors[0].modes[0]);
        assert_eq!((wire.hdisplay, wire.vdisplay), (800, 600));
        assert!(state.accepts_mode(&wire));
        let wrong = crate::drm::ioctl::mode_to_wire(&crate::Mode::FHD_60);
        assert!(!state.accepts_mode(&wrong));
        assert!(state.native[0].edid.is_none());
        // Xorg's modesetting probe counts the resources through the primary
        // node, then asks for the connector IDs in a second ioctl.
        use crate::drm_uapi::{DrmModeCardResUapi, DRM_IOCTL_MODE_GETRESOURCES};
        use narf_filesystem::FileOps;
        let index = crate::drm_registry::register_drm_card_with_state(
            alloc::sync::Arc::new(crate::drm_devfs_bridge::IntelGpuCard::new(
                alloc::string::String::from("firmware KMS test"),
                0x8086,
                0x46b3,
                0,
                0,
            )),
            state,
        );
        let primary = crate::drm_devfs_bridge::DriCardFile::new(index).unwrap();
        let mut resources = DrmModeCardResUapi::default();
        assert_eq!(
            primary.ioctl(
                DRM_IOCTL_MODE_GETRESOURCES,
                &mut resources as *mut _ as usize
            ),
            Ok(0)
        );
        assert_eq!(
            (
                resources.count_connectors,
                resources.count_crtcs,
                resources.count_encoders
            ),
            (1, 1, 1)
        );
        let mut connector = 0u32;
        resources.connector_id_ptr = &mut connector as *mut _ as u64;
        assert_eq!(
            primary.ioctl(
                DRM_IOCTL_MODE_GETRESOURCES,
                &mut resources as *mut _ as usize
            ),
            Ok(0)
        );
        assert_eq!(connector, 3);
        let mut mapped = crate::drm_fb_hook::ScanoutGeom {
            phys: fb.addr,
            width: fb.width,
            height: fb.height,
            stride_bytes: fb.pitch,
            virt: 0xffff_8000_0000_0000,
        };
        assert!(mapped.matches_firmware(fb));
        mapped.phys += 4096;
        assert!(!mapped.matches_firmware(fb));
        assert!(scanout(&io, aperture, size - 1, fb).is_none());
        assert!(scanout(&io, fb.addr + 1, size, fb).is_none());
        for (slot, bad) in [
            (0, pipes::PIPECONF_ENABLE),
            (1, u32::MAX),
            (2, 0),
            (3, 0),
            (4, 0),
            (5, 0),
        ] {
            let old = core::mem::replace(&mut io.0[slot].1, bad);
            assert!(scanout(&io, aperture, size, fb).is_none());
            io.0[slot].1 = old;
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/drm_ioctl", smoke_gen12_external_firmware_kms);
}
