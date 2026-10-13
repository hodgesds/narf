//! The native Navi48 display as DRM KMS state on the amdgpu card: one CRTC,
//! one encoder (TMDS type, as amdgpu_dm reports DP) and one DisplayPort or
//! HDMI connector carrying the sink's EDID, the exact timing being scanned
//! out and every other EDID timing the driver can switch the sink to. Only
//! those timings are accepted by SETCRTC/atomic; switching to another of them
//! is a full native modeset run by the display monitor.
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
const DRIVER: u32 = 0x40;

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

/// Set the card's single output to the lit sink (with its connector type), or
/// to disconnected, keeping the last connector type.
pub fn apply(card: &mut Card, lit: Option<(&[u8; 128], &Timing, &[Timing], ConnectorType)>) {
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
    let to_mode = |w: &DrmModeModeInfo| Mode {
        width: u32::from(w.hdisplay),
        height: u32::from(w.vdisplay),
        refresh_hz: w.vrefresh as u16,
        bpp: 32,
    };
    let wire = lit.map(|(_, t, _, _)| timing_wire(t));
    let mode = wire.as_ref().map(to_mode);
    // The running timing first, so a mode that two timings round to the same
    // size and refresh reports the one being scanned out.
    let mut timings: alloc::vec::Vec<DrmModeModeInfo> = wire.into_iter().collect();
    if let Some((_, active, offered, _)) = lit {
        for t in offered.iter().filter(|t| *t != active) {
            let w = timing_wire(t);
            // PREFERRED marks only the EDID's first (preferred) timing.
            let w = DrmModeModeInfo {
                r#type: if Some(t) == offered.first() {
                    PREFERRED_DRIVER
                } else {
                    DRIVER
                },
                ..w
            };
            timings.push(w);
        }
        if let Some(first) = timings.first_mut() {
            if offered.first().is_some_and(|p| p != active) {
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
        c.modes = modes;
        if let Some((_, _, _, kind)) = lit {
            c.connector_type = kind;
        }
    }
    card.native = alloc::vec![NativeOutput {
        connector: CONNECTOR,
        edid: lit.map(|(edid, _, _, _)| *edid),
        timings,
    }];
}

/// Switch the CRTC on or off without touching the connector: a DRM-driven
/// disable leaves the sink connected with its modes. On only while a mode is
/// set.
pub fn set_crtc_active(card: &mut Card, active: bool) {
    if let Ok(crtc) = card.crtc_mut(CRTC) {
        crtc.enabled = active && crtc.mode.is_some();
    }
}

/// `set_crtc_active` on the registered amdgpu card.
pub fn set_active(active: bool) {
    let Some(index) = (0..crate::drm_registry::count() as u32)
        .find(|&i| crate::drm_registry::driver_name(i) == Some("amdgpu"))
    else {
        return;
    };
    if let Some(state) = crate::drm_registry::mode_state(index) {
        set_crtc_active(&mut state.lock(), active);
    }
}

/// Publish the lit sink (or its absence) on the registered amdgpu card,
/// attaching KMS state on first use. Open clients keep their framebuffers.
pub fn publish(lit: Option<(&[u8; 128], &Timing, &[Timing], ConnectorType)>) {
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
