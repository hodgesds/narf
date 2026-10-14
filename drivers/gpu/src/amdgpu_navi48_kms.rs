//! The native Navi48 displays as DRM KMS state on the amdgpu card: one
//! output per lightable board port (the first four), output k being CRTC k
//! (pipe k), encoder k (TMDS type, as amdgpu_dm reports DP, driving only
//! CRTC k) and a DisplayPort or HDMI connector carrying its sink's EDID, the
//! exact timing being scanned out and every other EDID timing the driver
//! can switch the sink to. Only those timings are accepted by SETCRTC/atomic;
//! switching to another of them is a native modeset run by the display
//! monitor. Output 0's objects are ids 1, 2 and 3; output k's add 3k.
use crate::amdgpu_dml::Timing;
use crate::drm::card::{
    Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType, NativeOutput,
};
use crate::drm::ioctl::DrmModeModeInfo;
use crate::Mode;

const CRTC: u32 = 1;
const ENCODER: u32 = 2;
const CONNECTOR: u32 = 3;
/// Outputs at most: one per pipe.
pub const MAX_OUTPUTS: usize = 4;
pub fn crtc_id(output: usize) -> u32 {
    CRTC + 3 * output as u32
}
pub fn encoder_id(output: usize) -> u32 {
    ENCODER + 3 * output as u32
}
pub fn connector_id(output: usize) -> u32 {
    CONNECTOR + 3 * output as u32
}
/// DRM_MODE_FLAG_{P,N}{H,V}SYNC and DRM_MODE_TYPE_{PREFERRED,DRIVER}.
const PHSYNC: u32 = 1;
const NHSYNC: u32 = 2;
const PVSYNC: u32 = 4;
const NVSYNC: u32 = 8;
const PREFERRED_DRIVER: u32 = 0x8 | 0x40;
const DRIVER: u32 = 0x40;

/// DRM_FORMAT_XRGB8888 and ARGB8888: what the native scanout presents.
const PLANE_FORMATS: [u32; 2] = [0x3432_5258, 0x3432_5241];

/// The display (and pipe) behind a native CRTC id.
pub fn crtc_display(crtc_id: u32) -> Option<u8> {
    let k = crtc_id.checked_sub(CRTC)?;
    (k % 3 == 0 && ((k / 3) as usize) < MAX_OUTPUTS).then_some((k / 3) as u8)
}

/// A lit sink as KMS shows it: its EDID, the timing scanned out and every
/// timing it can be switched to.
#[derive(Clone, Copy, Debug)]
pub struct Sink<'a> {
    pub edid: &'a [u8; 128],
    pub timing: &'a Timing,
    pub offered: &'a [Timing],
}

/// One output: its connector type and its sink, while one is lit (or
/// switched off by DRM, still connected).
#[derive(Clone, Copy, Debug)]
pub struct Output<'a> {
    pub kind: ConnectorType,
    pub sink: Option<Sink<'a>>,
}

/// The exact DRM wire form of a DCN timing.
pub fn timing_wire(t: &Timing) -> DrmModeModeInfo {
    let total = u64::from(t.h_total) * u64::from(t.v_total);
    let refresh = (u64::from(t.pixel_clock_khz) * 1000 + total / 2)
        .checked_div(total)
        .unwrap_or(0);
    let hsync_start = t.h_active + t.h_front_porch;
    let vsync_start = t.v_active + t.v_front_porch;
    let mut info = DrmModeModeInfo {
        clock: t.pixel_clock_khz,
        hdisplay: t.h_active as u16,
        hsync_start: hsync_start as u16,
        hsync_end: (hsync_start + t.h_sync_width) as u16,
        htotal: t.h_total as u16,
        vdisplay: t.v_active as u16,
        vsync_start: vsync_start as u16,
        vsync_end: (vsync_start + t.v_sync_width) as u16,
        vtotal: t.v_total as u16,
        vrefresh: refresh as u32,
        flags: (if t.h_sync_positive { PHSYNC } else { NHSYNC })
            | (if t.v_sync_positive { PVSYNC } else { NVSYNC }),
        r#type: PREFERRED_DRIVER,
        ..Default::default()
    };
    let name = alloc::format!("{}x{}", t.h_active, t.v_active);
    let n = name.len().min(info.name.len() - 1);
    info.name[..n].copy_from_slice(&name.as_bytes()[..n]);
    info
}

/// Set the card's outputs to `outputs` (at most `MAX_OUTPUTS`): output k
/// connected to its lit sink, or disconnected. The topology is built for
/// the outputs' count and kept while it stays the same.
pub fn apply(card: &mut Card, outputs: &[Output]) {
    let outputs = &outputs[..outputs.len().min(MAX_OUTPUTS)];
    if card.connectors.len() != outputs.len() {
        card.crtcs.clear();
        card.encoders.clear();
        card.connectors.clear();
        for (k, o) in outputs.iter().enumerate() {
            card.crtcs.push(Crtc {
                id: crtc_id(k),
                mode: None,
                enabled: false,
                primary_fb: None,
                x: 0,
                y: 0,
            });
            card.encoders.push(Encoder {
                id: encoder_id(k),
                encoder_type: EncoderType::Tmds,
                // Each port has its pipe: its encoder drives that CRTC only.
                possible_crtcs: 1 << k,
                possible_clones: 0,
                crtc_id: Some(crtc_id(k)),
            });
            card.connectors.push(Connector {
                id: connector_id(k),
                connector_type: o.kind,
                connector_type_id: 1 + outputs[..k].iter().filter(|p| p.kind == o.kind).count()
                    as u32,
                status: ConnectorStatus::Disconnected,
                encoder_id: Some(encoder_id(k)),
                modes: alloc::vec::Vec::new(),
            });
        }
    }
    let to_mode = |w: &DrmModeModeInfo| Mode {
        width: u32::from(w.hdisplay),
        height: u32::from(w.vdisplay),
        refresh_hz: w.vrefresh as u16,
        bpp: 32,
    };
    let mut native = alloc::vec::Vec::with_capacity(outputs.len());
    for (k, o) in outputs.iter().enumerate() {
        let wire = o.sink.map(|s| timing_wire(s.timing));
        let mode = wire.as_ref().map(to_mode);
        // The running timing first, so a mode that two timings round to the
        // same size and refresh reports the one being scanned out.
        let mut timings: alloc::vec::Vec<DrmModeModeInfo> = wire.into_iter().collect();
        if let Some(sink) = o.sink {
            for t in sink.offered.iter().filter(|t| *t != sink.timing) {
                let w = timing_wire(t);
                // PREFERRED marks only the EDID's first (preferred) timing.
                let w = DrmModeModeInfo {
                    r#type: if Some(t) == sink.offered.first() {
                        PREFERRED_DRIVER
                    } else {
                        DRIVER
                    },
                    ..w
                };
                timings.push(w);
            }
            if let Some(first) = timings.first_mut() {
                if sink.offered.first().is_some_and(|p| p != sink.timing) {
                    first.r#type = DRIVER;
                }
            }
        }
        let mut modes: alloc::vec::Vec<Mode> = alloc::vec::Vec::new();
        for m in timings.iter().map(to_mode) {
            if !modes.contains(&m) {
                modes.push(m);
            }
        }
        if let Ok(crtc) = card.crtc_mut(crtc_id(k)) {
            crtc.mode = mode;
            crtc.enabled = mode.is_some();
            if mode.is_none() {
                crtc.primary_fb = None;
            }
        }
        if let Some(c) = card.connectors.iter_mut().find(|c| c.id == connector_id(k)) {
            c.status = if o.sink.is_some() {
                ConnectorStatus::Connected
            } else {
                ConnectorStatus::Disconnected
            };
            c.modes = modes;
            c.connector_type = o.kind;
        }
        native.push(NativeOutput {
            connector: connector_id(k),
            edid: o.sink.map(|s| *s.edid),
            timings,
            // amdgpu_dm attaches it to HDMI and SST DP connectors, which is
            // all these ever are.
            broadcast_rgb: Some(crate::amdgpu_navi48_boot::broadcast_rgb()),
        });
    }
    // The CRTCs' vblanks are the displays' hardware ones, and their planes
    // scan 32-bit RGB (alpha unused: nothing lies below the primary).
    card.vblank_source = Some(crate::amdgpu_navi48_platform::crtc_vblank);
    card.plane_formats = Some(&PLANE_FORMATS);
    card.native = native;
}

/// Switch output k's CRTC on or off without touching its connector: a
/// DRM-driven disable leaves the sink connected with its modes. On only
/// while a mode is set.
pub fn set_crtc_active(card: &mut Card, output: usize, active: bool) {
    if let Ok(crtc) = card.crtc_mut(crtc_id(output)) {
        crtc.enabled = active && crtc.mode.is_some();
    }
}

/// The registered amdgpu card's KMS state, if any.
type CardState = alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<Card>>;
fn amdgpu_card() -> Option<(u32, Option<CardState>)> {
    let index = (0..crate::drm_registry::count() as u32)
        .find(|&i| crate::drm_registry::driver_name(i) == Some("amdgpu"))?;
    Some((index, crate::drm_registry::mode_state(index)))
}

/// `set_crtc_active` on the registered amdgpu card.
pub fn set_active(output: usize, active: bool) {
    if let Some((_, Some(state))) = amdgpu_card() {
        set_crtc_active(&mut state.lock(), output, active);
    }
}

/// Publish the outputs on the registered amdgpu card, attaching KMS state
/// on first use. Open clients keep their framebuffers.
pub fn publish(outputs: &[Output]) {
    let Some((index, state)) = amdgpu_card() else {
        return;
    };
    match state {
        Some(state) => apply(&mut state.lock(), outputs),
        None => {
            // The base amdgpu KMS ABI only: no render feature level is
            // claimed, so Mesa's radeonsi declines this device rather than
            // issuing render ioctls the native driver does not implement.
            let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
            apply(&mut card, outputs);
            crate::drm_registry::attach_mode_state(index, card);
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_kms_tests.rs"]
mod tests;
