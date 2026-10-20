//! The native Navi48 displays as DRM KMS state on the amdgpu card: CRTC k is
//! display (pipe) k, id 1 + 3k. Each connector (a board port, or an end
//! device behind an MST branch) has its own encoder (TMDS type, as amdgpu_dm
//! reports DP) whose possible CRTCs the platform chooses, and carries its
//! sink's EDID, the exact timing being scanned out by its routed CRTC and
//! every other EDID timing the driver can switch the sink to. Only those
//! timings are accepted by SETCRTC/atomic; switching to another of them is a
//! native modeset run by the display monitor. Connector index n uses encoder
//! id 2 + 3n and connector id 3 + 3n.
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

/// Every native plane's formats (primary and overlay alike: DCN4's planes
/// are all DC_PLANE_TYPE_DCN_UNIVERSAL): amdgpu_dm's DCN4.0.1 list
/// (`amdgpu_dm_modifiers::DM_PLANE_FORMATS`: rgb_formats, NV12, P010, then
/// the FP16 ones) less those the native scanout does not program
/// (RGBA8888 and the 16-bit UNORM orders), in its order.
pub const PLANE_FORMATS: [u32; 15] = {
    use crate::amdgpu_dcn401_otg::SurfaceFormat as F;
    [
        F::Xrgb8888.fourcc(),
        F::Argb8888.fourcc(),
        F::Xrgb2101010.fourcc(),
        F::Xbgr2101010.fourcc(),
        F::Argb2101010.fourcc(),
        F::Abgr2101010.fourcc(),
        F::Xbgr8888.fourcc(),
        F::Abgr8888.fourcc(),
        F::Rgb565.fourcc(),
        F::Nv12.fourcc(),
        F::P010.fourcc(),
        F::Xrgb16161616f.fourcc(),
        F::Argb16161616f.fourcc(),
        F::Xbgr16161616f.fourcc(),
        F::Abgr16161616f.fourcc(),
    ]
};

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

/// One output: its connector type, optional current sink mode, and optional
/// EDID/mode inventory for a connected sink with no stream.
#[derive(Clone, Copy, Debug)]
pub struct Output<'a> {
    pub kind: ConnectorType,
    pub sink: Option<Sink<'a>>,
    /// Discovered EDID, including a monitor with no lit stream.
    pub edid: Option<&'a [u8; 128]>,
    /// Admitted connector timings when `sink` is None. Requires `edid`;
    /// publishing these does not set or enable a CRTC mode.
    pub offered: &'a [Timing],
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

/// One routed connector: KMS object index `index` (encoder `2 + 3 index`,
/// connector `3 + 3 index`), its type, discovered EDID, admitted timings
/// while no CRTC shows it, the CRTC (display) it is routed to, and the
/// CRTCs its encoder may drive.
#[derive(Clone, Copy, Debug)]
pub struct RoutedConnector<'a> {
    pub index: usize,
    pub kind: ConnectorType,
    pub edid: Option<&'a [u8; 128]>,
    pub offered: &'a [Timing],
    pub crtc: Option<usize>,
    pub possible_crtcs: u32,
}

/// Set the card's outputs to `outputs` (at most `MAX_OUTPUTS`): output k
/// is connector k routed to CRTC k only, connected when it has an EDID,
/// even without a lit sink.
pub fn apply(card: &mut Card, outputs: &[Output]) {
    let outputs = &outputs[..outputs.len().min(MAX_OUTPUTS)];
    let crtcs: alloc::vec::Vec<Option<Sink>> = outputs.iter().map(|o| o.sink).collect();
    let connectors: alloc::vec::Vec<RoutedConnector> = outputs
        .iter()
        .enumerate()
        .map(|(k, o)| RoutedConnector {
            index: k,
            kind: o.kind,
            edid: o.edid,
            offered: o.offered,
            crtc: Some(k),
            possible_crtcs: 1 << k,
        })
        .collect();
    apply_routed(card, &crtcs, &connectors);
}

/// Set the card's CRTCs (display k is `crtcs[k]`: the sink it shows, if
/// any) and connectors. A connector routed to a CRTC with a sink reports
/// that sink's EDID, its running timing first and its switchable timings;
/// otherwise its discovered EDID and admitted timings. Connected when it
/// has an EDID. The topology is rebuilt only when the CRTC count or the
/// connectors' identities change.
pub fn apply_routed(card: &mut Card, crtcs: &[Option<Sink>], connectors: &[RoutedConnector]) {
    apply_routed_vrr(card, crtcs, connectors, None);
}

/// `apply_routed` that also attaches the VRR properties, as amdgpu_dm does
/// on DP and HDMI connectors: each connector's immutable "vrr_capable"
/// (`vrr_capable[n]` for `connectors[n]`, false past its end) and every
/// CRTC's "VRR_ENABLED", whose committed values survive republication.
/// `None` attaches neither (and drops any), as `apply_routed`.
pub fn apply_routed_vrr(
    card: &mut Card,
    crtcs: &[Option<Sink>],
    connectors: &[RoutedConnector],
    vrr_capable: Option<&[bool]>,
) {
    let crtcs = &crtcs[..crtcs.len().min(MAX_OUTPUTS)];
    let same = card.crtcs.len() == crtcs.len()
        && card.connectors.len() == connectors.len()
        && connectors.iter().zip(&card.connectors).all(|(c, have)| {
            have.id == connector_id(c.index)
                && card
                    .encoder(encoder_id(c.index))
                    .is_ok_and(|e| e.possible_crtcs == c.possible_crtcs)
        });
    if !same {
        card.crtcs.clear();
        card.encoders.clear();
        card.connectors.clear();
        for k in 0..crtcs.len() {
            card.crtcs.push(Crtc {
                id: crtc_id(k),
                mode: None,
                enabled: false,
                primary_fb: None,
                x: 0,
                y: 0,
            });
        }
        for (n, c) in connectors.iter().enumerate() {
            card.encoders.push(Encoder {
                id: encoder_id(c.index),
                encoder_type: EncoderType::Tmds,
                possible_crtcs: c.possible_crtcs,
                possible_clones: 0,
                crtc_id: None,
            });
            card.connectors.push(Connector {
                id: connector_id(c.index),
                connector_type: c.kind,
                connector_type_id: 1 + connectors[..n].iter().filter(|p| p.kind == c.kind).count()
                    as u32,
                status: ConnectorStatus::Disconnected,
                encoder_id: Some(encoder_id(c.index)),
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
    for (k, sink) in crtcs.iter().enumerate() {
        let mode = sink.map(|s| to_mode(&timing_wire(s.timing)));
        if let Ok(crtc) = card.crtc_mut(crtc_id(k)) {
            crtc.mode = mode;
            crtc.enabled = mode.is_some();
            if mode.is_none() {
                crtc.primary_fb = None;
            }
        }
    }
    card.vrr_enabled = match vrr_capable {
        Some(_) => (0..crtcs.len())
            .map(|k| {
                let id = crtc_id(k);
                let value = card
                    .vrr_enabled
                    .iter()
                    .find(|&&(c, _)| c == id)
                    .is_some_and(|&(_, v)| v);
                (id, value)
            })
            .collect(),
        None => alloc::vec::Vec::new(),
    };
    let mut native = alloc::vec::Vec::with_capacity(connectors.len());
    for (n, c) in connectors.iter().enumerate() {
        let shown = c.crtc.and_then(|k| crtcs.get(k).copied().flatten());
        let edid = shown.map(|s| s.edid).or(c.edid);
        let wire = shown.map(|s| timing_wire(s.timing));
        // The running timing first, so a mode that two timings round to the
        // same size and refresh reports the one being scanned out.
        let mut timings: alloc::vec::Vec<DrmModeModeInfo> = wire.into_iter().collect();
        let offered = shown.map_or_else(
            || if edid.is_some() { c.offered } else { &[] },
            |s| s.offered,
        );
        for t in offered
            .iter()
            .filter(|t| Some(*t) != shown.map(|s| s.timing))
        {
            let w = timing_wire(t);
            // PREFERRED marks only the first admitted EDID timing.
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
            if shown.is_some_and(|s| offered.first().is_some_and(|p| p != s.timing)) {
                first.r#type = DRIVER;
            }
        }
        let mut modes: alloc::vec::Vec<Mode> = alloc::vec::Vec::new();
        for m in timings.iter().map(to_mode) {
            if !modes.contains(&m) {
                modes.push(m);
            }
        }
        if let Some(e) = card
            .encoders
            .iter_mut()
            .find(|e| e.id == encoder_id(c.index))
        {
            e.crtc_id = c.crtc.filter(|&k| k < crtcs.len()).map(crtc_id);
        }
        if let Some(have) = card
            .connectors
            .iter_mut()
            .find(|x| x.id == connector_id(c.index))
        {
            have.status = if edid.is_some() {
                ConnectorStatus::Connected
            } else {
                ConnectorStatus::Disconnected
            };
            have.modes = modes;
            have.connector_type = c.kind;
        }
        native.push(NativeOutput {
            connector: connector_id(c.index),
            edid: edid.copied(),
            timings,
            // amdgpu_dm attaches it to HDMI and SST DP connectors, which is
            // all these ever are.
            broadcast_rgb: Some(crate::amdgpu_navi48_boot::broadcast_rgb()),
            vrr_capable: vrr_capable.map(|v| v.get(n).copied().unwrap_or(false)),
            colorspace: None,
            hdr_output_metadata: None,
            max_bpc: None,
        });
    }
    // The CRTCs' vblanks are the displays' hardware ones, and their planes
    // scan packed RGB (an A format's alpha blends over the black background:
    // nothing lies below the primary).
    card.vblank_source = Some(crate::amdgpu_navi48_platform::crtc_vblank);
    card.plane_formats = Some(&PLANE_FORMATS);
    // amdgpu_dm's planes: each CRTC's primary and DCN401's three overlays.
    let crtc_ids: alloc::vec::Vec<u32> = card.crtcs.iter().map(|c| c.id).collect();
    card.native_planes = crate::drm_native_planes::planes_for(&card.native_planes, &crtc_ids);
    card.overlay_formats = Some(&PLANE_FORMATS);
    // amdgpu_dm_plane_get_plane_modifiers: GFX12 modifiers on every plane.
    card.gfx12_modifiers = true;
    card.native = native;
    // amdgpu is DRIVER_ATOMIC: the bridge's native atomic path validates
    // MODE_ID/format/route against this owner and commits through it.
    card.native_atomic = true;
}

/// The connector index behind a native connector id.
pub fn connector_index(connector_id: u32) -> Option<usize> {
    let n = connector_id.checked_sub(CONNECTOR)?;
    (n % 3 == 0).then_some((n / 3) as usize)
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
    with_card(|card| apply(card, outputs));
}

/// `apply_routed` on the registered amdgpu card.
pub fn publish_routed(crtcs: &[Option<Sink>], connectors: &[RoutedConnector]) {
    with_card(|card| apply_routed(card, crtcs, connectors));
}

/// What the Navi48 platform attaches to a routed connector beyond its sink.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectorProps {
    /// The immutable "vrr_capable" value.
    pub vrr_capable: bool,
    /// "Colorspace" and "HDR_OUTPUT_METADATA", which amdgpu_dm attaches to
    /// its HDMI and DP connectors (drm_mode_create_{hdmi,dp}_colorspace_property
    /// with the same supported set, drm_connector_attach_hdr_output_metadata_property).
    pub color: bool,
    /// "max bpc", which amdgpu_dm attaches to every connector, MST end
    /// devices included (drm_connector_attach_max_bpc_property(connector,
    /// 8, 16), starting at 16).
    pub max_bpc: bool,
}

/// `apply_routed_vrr` with every native property amdgpu_dm attaches on
/// DCN 4.0.1: the VRR pair, each connector's "Colorspace" and
/// "HDR_OUTPUT_METADATA" where `props[n].color` and "max bpc" where
/// `props[n].max_bpc`, and every CRTC's CTM,
/// GAMMA_LUT and GAMMA_LUT_SIZE (`drm_crtc_enable_color_mgmt(crtc, 0,
/// true, 4096)`: no degamma on 4.0.1) with the legacy 256-entry gamma.
/// Committed values survive republication: a connector keeps its
/// Colorspace, HDR blob and max bpc, a CRTC its CTM, GAMMA_LUT and gamma
/// store.
pub fn apply_routed_native(
    card: &mut Card,
    crtcs: &[Option<Sink>],
    connectors: &[RoutedConnector],
    props: &[ConnectorProps],
) {
    /// A connector's committed Colorspace, HDR blob and max bpc.
    type Committed = (u32, Option<u32>, Option<u32>, Option<u8>);
    let previous: alloc::vec::Vec<Committed> = card
        .native
        .iter()
        .map(|n| (n.connector, n.colorspace, n.hdr_output_metadata, n.max_bpc))
        .collect();
    let vrr: alloc::vec::Vec<bool> = props.iter().map(|p| p.vrr_capable).collect();
    apply_routed_vrr(card, crtcs, connectors, Some(&vrr));
    for (n, c) in connectors.iter().enumerate() {
        let id = connector_id(c.index);
        let attach = props.get(n).is_some_and(|p| p.color);
        let kept = previous.iter().find(|p| p.0 == id);
        if let Some(native) = card.native.iter_mut().find(|x| x.connector == id) {
            native.colorspace = attach.then(|| kept.and_then(|p| p.1).unwrap_or(0));
            native.hdr_output_metadata = attach.then(|| kept.and_then(|p| p.2).unwrap_or(0));
            native.max_bpc = props.get(n).is_some_and(|p| p.max_bpc).then(|| {
                kept.and_then(|p| p.3)
                    .unwrap_or(crate::amdgpu_navi48_boot::MAX_REQUESTED_BPC)
            });
        }
    }
    let crtcs = &crtcs[..crtcs.len().min(MAX_OUTPUTS)];
    card.crtc_color = (0..crtcs.len())
        .map(|k| {
            let id = crtc_id(k);
            card.crtc_color(id)
                .cloned()
                .unwrap_or_else(|| crate::drm::card::CrtcColor::new(id))
        })
        .collect();
    card.collect_blobs();
}

/// `apply_routed_native` on the registered amdgpu card.
pub fn publish_routed_native(
    crtcs: &[Option<Sink>],
    connectors: &[RoutedConnector],
    props: &[ConnectorProps],
) {
    with_card(|card| apply_routed_native(card, crtcs, connectors, props));
}

fn with_card(update: impl FnOnce(&mut Card)) {
    let Some((index, state)) = amdgpu_card() else {
        return;
    };
    match state {
        Some(state) => update(&mut state.lock()),
        None => {
            // The base amdgpu KMS ABI only: no render feature level is
            // claimed, so Mesa's radeonsi declines this device rather than
            // issuing render ioctls the native driver does not implement.
            let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
            update(&mut card);
            crate::drm_registry::attach_mode_state(index, card);
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_kms_tests.rs"]
mod tests;
