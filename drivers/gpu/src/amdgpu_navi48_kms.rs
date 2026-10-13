//! The native Navi48 display as DRM KMS state on the amdgpu card: one CRTC,
//! one encoder (TMDS type, as amdgpu_dm reports DP) and one DisplayPort
//! connector carrying the sink's EDID and the exact timing being scanned out.
//! Presentation stays the existing CPU copy onto the adopted scanout; only
//! the published timing is accepted by SETCRTC, since the driver cannot yet
//! reprogram a live display to another mode.
use crate::amdgpu_dml::Timing;
use crate::drm::card::{
    Card, Connector, ConnectorStatus, ConnectorType, Crtc, Encoder, EncoderType, NativeOutput,
};
use crate::drm::ioctl::DrmModeModeInfo;
use crate::Mode;

const CRTC: u32 = 1;
const ENCODER: u32 = 2;
const CONNECTOR: u32 = 3;
/// DRM_MODE_FLAG_{P,N}{H,V}SYNC and DRM_MODE_TYPE_{PREFERRED,DRIVER}.
const PHSYNC: u32 = 1;
const NHSYNC: u32 = 2;
const PVSYNC: u32 = 4;
const NVSYNC: u32 = 8;
const PREFERRED_DRIVER: u32 = 0x8 | 0x40;

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

/// Set the card's single output to the lit sink, or to disconnected.
pub fn apply(card: &mut Card, lit: Option<(&[u8; 128], &Timing)>) {
    if card.crtcs.is_empty() {
        card.crtcs.push(Crtc {
            id: CRTC,
            mode: None,
            enabled: false,
            primary_fb: None,
            x: 0,
            y: 0,
        });
        card.encoders.push(Encoder {
            id: ENCODER,
            encoder_type: EncoderType::Tmds,
            possible_crtcs: 1,
            possible_clones: 0,
            crtc_id: Some(CRTC),
        });
        card.connectors.push(Connector {
            id: CONNECTOR,
            connector_type: ConnectorType::DisplayPort,
            connector_type_id: 1,
            status: ConnectorStatus::Disconnected,
            encoder_id: Some(ENCODER),
            modes: alloc::vec::Vec::new(),
        });
    }
    let wire = lit.map(|(_, t)| timing_wire(t));
    let mode = wire.map(|w| Mode {
        width: u32::from(w.hdisplay),
        height: u32::from(w.vdisplay),
        refresh_hz: w.vrefresh as u16,
        bpp: 32,
    });
    if let Ok(crtc) = card.crtc_mut(CRTC) {
        crtc.mode = mode;
        crtc.enabled = mode.is_some();
        if mode.is_none() {
            crtc.primary_fb = None;
        }
    }
    if let Some(c) = card.connectors.iter_mut().find(|c| c.id == CONNECTOR) {
        c.status = if lit.is_some() {
            ConnectorStatus::Connected
        } else {
            ConnectorStatus::Disconnected
        };
        c.modes = mode.into_iter().collect();
    }
    card.native = alloc::vec![NativeOutput {
        connector: CONNECTOR,
        edid: lit.map(|(edid, _)| *edid),
        timings: wire.into_iter().collect(),
    }];
}

/// Publish the lit sink (or its absence) on the registered amdgpu card,
/// attaching KMS state on first use. Open clients keep their framebuffers.
pub fn publish(lit: Option<(&[u8; 128], &Timing)>) {
    let Some(index) = (0..crate::drm_registry::count() as u32)
        .find(|&i| crate::drm_registry::driver_name(i) == Some("amdgpu"))
    else {
        return;
    };
    match crate::drm_registry::mode_state(index) {
        Some(state) => apply(&mut state.lock(), lit),
        None => {
            // The base amdgpu KMS ABI only: no render feature level is
            // claimed, so Mesa's radeonsi declines this device rather than
            // issuing render ioctls the native driver does not implement.
            let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
            apply(&mut card, lit);
            crate::drm_registry::attach_mode_state(index, card);
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_kms_tests.rs"]
mod tests;
