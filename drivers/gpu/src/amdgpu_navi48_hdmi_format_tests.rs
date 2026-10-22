//! Real ioctl preflight over retained connector/SoC snapshots.
use super::*;
use crate::amdgpu_hdr::ColorFormat as F;
use crate::amdgpu_native_kms::{OutputFormatRequest, OutputRoute};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Restore(Option<Outputs>);
impl Drop for Restore {
    fn drop(&mut self) {
        *OUTPUTS.lock() = self.0.take().unwrap();
    }
}
fn fixture() -> (Restore, dml::Soc, Timing, OutputFormatRequest) {
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let timing = Timing {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        h_front_porch: 88,
        h_sync_width: 44,
        v_active: 1080,
        v_total: 1125,
        v_front_porch: 4,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    };
    let mut outputs = Outputs::new();
    outputs.soc = Some(soc);
    outputs.reshape(&[
        (Target::Board(0), ConnectorType::HdmiA, 0),
        (Target::Board(1), ConnectorType::DisplayPort, 1),
    ]);
    let mut edid = alloc::vec![0u8; 256];
    edid[128..132].copy_from_slice(&[2, 3, 12, 0x30]);
    edid[132..140].copy_from_slice(&[0x67, 3, 0x0c, 0, 0x10, 0, 0, 60]);
    edid[255] = narf_edid::compute_checksum(&edid[128..]);
    outputs.connectors[0].edid = edid;
    for c in &mut outputs.connectors {
        c.present = true;
        c.modes = alloc::vec![timing];
    }
    let request = OutputFormatRequest {
        display: 0,
        connector: crate::amdgpu_navi48_kms::connector_id(0),
        color_format: F::Ycbcr422,
        mode: Some(crate::amdgpu_navi48_kms::timing_wire(&timing)),
        max_bpc: Some(12),
        planes: Some((SurfaceFormat::Xrgb8888.fourcc(), boot::PlaneSetup::NONE)),
    };
    let old = core::mem::replace(&mut *OUTPUTS.lock(), outputs);
    (Restore(Some(old)), soc, timing, request)
}
fn route(r: &OutputFormatRequest) -> OutputRoute {
    OutputRoute {
        display: r.display,
        connector: r.connector,
        mode: r.mode,
        planes: r.planes,
    }
}
fn setup(t: Timing, overlays: usize) -> boot::PlaneSetup {
    let geometry = boot::PlaneGeometry {
        src_x: 0,
        src_y: 0,
        width: t.h_active,
        height: t.v_active,
        dst: crate::amdgpu_dcn401_spl::Rect::new(0, 0, t.h_active as i32, t.v_active as i32),
        rotation: crate::amdgpu_dcn401_spl::Rotation::R0,
        blend: crate::amdgpu_dcn401_otg::Blend::default_for(SurfaceFormat::Argb8888),
        surface: crate::amdgpu_dcn401_otg::PlaneSurface::LINEAR,
        fb_size: (t.h_active, t.v_active),
        client: false,
    };
    let mut setup = boot::PlaneSetup::NONE;
    for (n, slot) in setup.overlays.iter_mut().take(overlays).enumerate() {
        *slot = Some(boot::OverlayPlane {
            geometry,
            format: SurfaceFormat::Argb8888,
            underlay: false,
            plane: 100 + n as u32,
        });
    }
    setup
}
fn navi48_hdmi_format_preflight_uses_dark_board_soc_and_preserves_state() -> TestResult {
    let (_restore, _, _, r) = fixture();
    // No CRTC was ever admitted; retained board inputs suffice.
    assert!(OUTPUTS.lock().crtcs.iter().all(|c| c.admitted.is_none()));
    assert!(output_formats_supported(&[r], &[route(&r)]));
    assert!(OUTPUTS.lock().crtcs.iter().all(|c| c.admitted.is_none()));
    assert_eq!(OUTPUTS.lock().connectors[0].color_format, F::Auto);
    OUTPUTS.lock().soc = None;
    assert!(!output_formats_supported(&[r], &[route(&r)]));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_hdmi_format_preflight_uses_dark_board_soc_and_preserves_state
);

fn navi48_hdmi_format_preflight_remaps_siblings_and_releases_disabled_outputs() -> TestResult {
    let (_restore, soc, timing, mut r) = fixture();
    let two = setup(timing, 1);
    let dp = boot::with_planes(
        boot::plane_mode(timing, SurfaceFormat::Xrgb8888),
        SurfaceFormat::Xrgb8888,
        &two,
    );
    assert!(boot::admit_native_modes(&soc, &[dp]).is_ok());
    {
        let mut o = OUTPUTS.lock();
        o.crtcs[1].route = Some(Target::Board(1));
        o.crtcs[1].admitted = Some((soc, dp));
        o.crtcs[1].shown = Some(([0; 128], timing, alloc::vec![timing]));
    }
    r.planes = Some((SurfaceFormat::Xrgb8888.fourcc(), two));
    let moved = OutputRoute {
        display: 2,
        connector: crate::amdgpu_navi48_kms::connector_id(1),
        mode: r.mode,
        planes: None,
    };
    assert!(output_formats_supported(&[r], &[route(&r), moved])); // Four total planes.
    r.planes = Some((SurfaceFormat::Xrgb8888.fourcc(), setup(timing, 3)));
    assert!(!output_formats_supported(&[r], &[route(&r), moved])); // Six planes do not fit.
    assert!(output_formats_supported(&[r], &[route(&r)])); // DP disabled in the same commit.
                                                           // Unknown DP timing/link state cannot be silently replaced with its old plan.
    let mut unknown = moved;
    unknown.mode.as_mut().unwrap().clock += 1000;
    assert!(!output_formats_supported(&[r], &[route(&r), unknown]));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_hdmi_format_preflight_remaps_siblings_and_releases_disabled_outputs
);
