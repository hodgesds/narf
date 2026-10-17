//! The native Navi22 display as DRM KMS state on the amdgpu card, after
//! `amdgpu_navi48_kms` (whose CRTC/encoder/connector id scheme and DRM wire
//! forms this reuses): one CRTC per lit pipe (the single-pipe HDMI owner
//! lights pipe 0, CRTC id 1), and one connector per board port in VBIOS
//! route order (DP-1..3 and HDMI-A-1 on the RX 6750 XT), each with its own
//! TMDS-type encoder. A connected sink carries its EDID; its modes are the
//! EDID timings the DCN30 admission accepts (`amdgpu_navi22_modeset::offered`
//! against the board's SoC inputs), so SETCRTC, atomic commits and TEST_ONLY
//! checks only ever accept what DML30 admitted. DP ports report their sinks
//! but offer no mode until the DCN30 DP SST path exists.
//!
//! This module holds what DRM asked for (CRTC on/off, mode, connector) and
//! what the hardware shows; `amdgpu_navi22_platform`'s display monitor
//! converges the hardware to it. All state changes here are short and
//! synchronous: DRM ioctls never wait for the display owner.
use crate::amdgpu_dml::Timing;
use crate::amdgpu_navi22_display::{Connector as Port, Detection, Report, Signal};
use crate::amdgpu_navi22_power_policy::DisplayAdmission;
use crate::drm::card::{Card, ConnectorType};
use crate::drm::ioctl::DrmModeModeInfo;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

/// Pipes this owner can light (`amdgpu_navi22_modeset` drives pipe 0).
pub const MAX_CRTCS: usize = 1;

/// DRM_FORMAT_XRGB8888 and ARGB8888: what the native scanout presents.
const PLANE_FORMATS: [u32; 2] = [0x3432_5258, 0x3432_5241];

/// One board connector and its sink as last detected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorState {
    pub port: Port,
    pub kind: ConnectorType,
    pub present: bool,
    pub edid: Vec<u8>,
    /// DCN30-admitted timings (empty for a sink this owner cannot light).
    pub modes: Vec<Timing>,
    /// No admission inputs existed at detection (nothing lit yet): the
    /// sink may still be lit at its preferred mode, which admits it.
    pub unadmitted: bool,
}
impl ConnectorState {
    /// Whether the single-pipe owner can drive this connector.
    pub fn lightable(&self) -> bool {
        self.port.signal == Signal::Hdmi
            && self.present
            && (self.unadmitted || !self.modes.is_empty())
    }
}

/// What DRM asked of the CRTC, and what it shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrtcState {
    /// DRM wants it on (SETCRTC with a framebuffer, atomic ACTIVE=1).
    pub active: bool,
    /// The mode DRM last set, or None for the sink's preferred mode.
    pub requested: Option<Timing>,
    /// The lit sink: EDID block 0, the running timing, every offered one.
    pub shown: Option<([u8; 128], Timing, Vec<Timing>)>,
    /// The connector (index) it drives.
    pub route: Option<usize>,
    /// DRM chose the route; automatic routing leaves it.
    pub explicit: bool,
}
impl CrtcState {
    pub const fn new() -> Self {
        Self {
            active: true,
            requested: None,
            shown: None,
            route: None,
            explicit: false,
        }
    }
}
impl Default for CrtcState {
    fn default() -> Self {
        Self::new()
    }
}

/// What the display monitor should do next, from requested vs shown state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Nothing,
    /// Tear down the running pipe (CRTC off, rerouted or another mode).
    Unlight,
    /// Light connector `route` at `want`.
    Light {
        route: usize,
        want: Option<Timing>,
    },
}

/// Connectors and the CRTC, under one lock.
#[derive(Debug)]
pub struct Kms {
    pub connectors: Vec<ConnectorState>,
    pub crtc: CrtcState,
    /// The (route, want) the monitor last tried to light, so a sink that
    /// failed is not relit every pass; cleared by any new request.
    pub attempted: Option<(usize, Option<Timing>)>,
}
impl Kms {
    pub const fn new() -> Self {
        Self {
            connectors: Vec::new(),
            crtc: CrtcState::new(),
            attempted: None,
        }
    }
    /// Replace the inventory with a detection. `offered` computes a sink's
    /// admitted timings (None when no admission inputs exist yet). A sink
    /// whose EDID changed voids the CRTC's requested mode.
    pub fn reconcile(
        &mut self,
        reports: &[Report],
        offered: impl Fn(&Port, &[u8]) -> Option<Vec<Timing>>,
    ) {
        let old = core::mem::take(&mut self.connectors);
        for report in reports {
            let kind = match report.connector.signal {
                Signal::Hdmi => ConnectorType::HdmiA,
                Signal::DisplayPort => ConnectorType::DisplayPort,
            };
            let (present, edid) = match &report.detection {
                Detection::Connected(sink) => (true, sink.edid.clone()),
                _ => (false, Vec::new()),
            };
            let (modes, unadmitted) = if present && report.connector.signal == Signal::Hdmi {
                match offered(&report.connector, &edid) {
                    Some(modes) => (modes, false),
                    None => (Vec::new(), true),
                }
            } else {
                (Vec::new(), false)
            };
            let n = self.connectors.len();
            if old
                .get(n)
                .is_some_and(|o| o.port == report.connector && o.edid != edid)
                && self.crtc.route == Some(n)
            {
                self.crtc.requested = None;
            }
            self.connectors.push(ConnectorState {
                port: report.connector,
                kind,
                present,
                edid,
                modes,
                unadmitted,
            });
        }
        if self.crtc.route.is_some_and(|r| r >= self.connectors.len()) {
            self.crtc.route = None;
            self.crtc.explicit = false;
        }
    }
    /// Automatic routing: an unrouted CRTC takes the first lightable sink.
    pub fn assign_route(&mut self) {
        if self.crtc.explicit {
            return;
        }
        if self
            .crtc
            .route
            .is_some_and(|r| !self.connectors[r].lightable())
        {
            self.crtc.route = None;
        }
        if self.crtc.route.is_none() {
            self.crtc.route = self.connectors.iter().position(ConnectorState::lightable);
        }
    }
    /// Timings the CRTC can switch `connector` (default: its route) to.
    pub fn offered(&self, connector: Option<usize>) -> &[Timing] {
        let Some(c) = connector.or(self.crtc.route) else {
            return &[];
        };
        match self.connectors.get(c) {
            Some(x) if x.lightable() => &x.modes,
            _ => &[],
        }
    }
    pub fn find_mode(&self, connector: Option<usize>, mode: &DrmModeModeInfo) -> Option<Timing> {
        let geometry = |w: &DrmModeModeInfo| {
            (
                w.clock,
                [w.hdisplay, w.hsync_start, w.hsync_end, w.htotal],
                [w.vdisplay, w.vsync_start, w.vsync_end, w.vtotal],
            )
        };
        self.offered(connector)
            .iter()
            .copied()
            .find(|t| geometry(&crate::amdgpu_navi48_kms::timing_wire(t)) == geometry(mode))
    }
    /// The next convergence step given whether a pipe runs and at what.
    pub fn next(&self, running: Option<(usize, Timing)>) -> Action {
        let c = &self.crtc;
        let target = c.route.filter(|&r| {
            c.active
                && self
                    .connectors
                    .get(r)
                    .is_some_and(ConnectorState::lightable)
        });
        match (running, target) {
            (Some(_), None) => Action::Unlight,
            (Some((route, shown)), Some(t)) => {
                if route != t || c.requested.is_some_and(|w| w != shown) {
                    Action::Unlight
                } else {
                    Action::Nothing
                }
            }
            (None, Some(route)) if self.attempted != Some((route, c.requested)) => Action::Light {
                route,
                want: c.requested,
            },
            _ => Action::Nothing,
        }
    }
    /// The sink the CRTC shows to DRM: while on and routed to a sink.
    pub fn published(&self) -> Option<&([u8; 128], Timing, Vec<Timing>)> {
        let c = &self.crtc;
        (c.active
            && c.route
                .is_some_and(|r| self.connectors.get(r).is_some_and(|x| x.present)))
        .then_some(c.shown.as_ref())
        .flatten()
    }
}
impl Default for Kms {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) static KMS: narf_lib::sync::IrqSafeSpinLock<Kms> =
    narf_lib::sync::IrqSafeSpinLock::new(Kms::new());
/// The Navi22 card is published: DRM's native-display calls route here.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// A DRM request (or a recovery) is waiting for the display monitor.
static PENDING: AtomicBool = AtomicBool::new(false);

pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}
/// Ask the display monitor to run a pass now.
pub fn wake() {
    PENDING.store(true, Ordering::Release);
}
pub(crate) fn take_pending() -> bool {
    PENDING.swap(false, Ordering::AcqRel)
}

/// The pipe behind a native CRTC id (CRTC k is pipe k).
pub fn crtc_display(crtc_id: u32) -> Option<u8> {
    crate::amdgpu_navi48_kms::crtc_display(crtc_id).filter(|&d| usize::from(d) < MAX_CRTCS)
}

/// Publish the connectors and CRTC on the registered amdgpu card.
pub fn publish() {
    let kms = KMS.lock();
    let crtcs: Vec<Option<crate::amdgpu_navi48_kms::Sink>> = (0..MAX_CRTCS)
        .map(|_| {
            kms.published()
                .map(|(edid, timing, offered)| crate::amdgpu_navi48_kms::Sink {
                    edid,
                    timing,
                    offered,
                })
        })
        .collect();
    let route = kms.crtc.route;
    let connectors: Vec<crate::amdgpu_navi48_kms::RoutedConnector> = kms
        .connectors
        .iter()
        .enumerate()
        .map(|(n, c)| crate::amdgpu_navi48_kms::RoutedConnector {
            index: n,
            kind: c.kind,
            edid: c
                .present
                .then(|| c.edid.get(..128).and_then(|e| e.try_into().ok()))
                .flatten(),
            offered: if c.lightable() { &c.modes } else { &[] },
            crtc: (route == Some(n)).then_some(0),
            possible_crtcs: if c.port.signal == Signal::Hdmi { 1 } else { 0 },
        })
        .collect();
    let off = kms.crtc.shown.is_some() && !kms.crtc.active;
    with_card(|card| {
        crate::amdgpu_navi48_kms::apply_routed(card, &crtcs, &connectors);
        card.vblank_source = Some(crate::amdgpu_navi22_platform::crtc_vblank);
        card.plane_formats = Some(&PLANE_FORMATS);
        if off {
            crate::amdgpu_navi48_kms::set_crtc_active(card, 0, false);
        }
    });
    ACTIVE.store(true, Ordering::Release);
}

type CardState = alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<Card>>;
fn amdgpu_card() -> Option<(u32, Option<CardState>)> {
    let index = (0..crate::drm_registry::count() as u32)
        .find(|&i| crate::drm_registry::driver_name(i) == Some("amdgpu"))?;
    Some((index, crate::drm_registry::mode_state(index)))
}
fn with_card(update: impl FnOnce(&mut Card)) {
    let Some((index, state)) = amdgpu_card() else {
        return;
    };
    match state {
        Some(state) => update(&mut state.lock()),
        None => {
            // The base amdgpu KMS ABI, as amdgpu_navi48_kms publishes it.
            let mut card = Card::new(
                "amdgpu",
                "AMD GPU",
                crate::amdgpu_info_navi22::drm_version(),
            );
            update(&mut card);
            crate::drm_registry::attach_mode_state(index, card);
        }
    }
}

// ── DRM requests (level-triggered; the monitor converges) ───────────────

fn requested(update: impl FnOnce(&mut Kms) -> bool) -> bool {
    let changed = {
        let mut kms = KMS.lock();
        let ok = update(&mut kms);
        if ok {
            kms.attempted = None;
        }
        ok
    };
    if changed {
        wake();
    }
    changed
}
/// Record DRM's CRTC on/off request.
pub fn request_display_active(display: u8, active: bool) {
    if usize::from(display) < MAX_CRTCS {
        requested(|k| {
            k.crtc.active = active;
            true
        });
    }
}
/// The connector index behind a KMS connector id, if it exists.
fn connector_of(kms: &Kms, id: u32) -> Option<usize> {
    crate::amdgpu_navi48_kms::connector_index(id).filter(|&n| n < kms.connectors.len())
}
/// Route the CRTC to connector `connector` (KMS id; None: none). Only an
/// HDMI port can be driven; false for an unknown or undrivable one.
pub fn request_display_route(display: u8, connector: Option<u32>) -> bool {
    if usize::from(display) >= MAX_CRTCS {
        return false;
    }
    requested(|k| {
        let target = match connector {
            Some(id) => match connector_of(k, id) {
                Some(n) if k.connectors[n].port.signal == Signal::Hdmi => Some(n),
                _ => return false,
            },
            None => None,
        };
        if k.crtc.route != target {
            k.crtc.requested = None;
            k.crtc.shown = None;
        }
        k.crtc.route = target;
        k.crtc.explicit = true;
        true
    })
}
/// Route connector `connector` to CRTC `display`, or detach it.
pub fn request_connector_crtc(connector: u32, display: Option<u8>) -> bool {
    match display {
        Some(d) => request_display_route(d, Some(connector)),
        None => requested(|k| {
            let Some(n) = connector_of(k, connector) else {
                return false;
            };
            if k.crtc.route == Some(n) {
                k.crtc.route = None;
                k.crtc.explicit = true;
            }
            true
        }),
    }
}
/// Whether `mode` is a DCN30-admitted timing of the CRTC's connector (or of
/// `connector`, a KMS id, when the same request routes it there). This is
/// the TEST_ONLY / SETCRTC validation.
pub fn display_offers(display: u8, connector: Option<u32>, mode: &DrmModeModeInfo) -> bool {
    if usize::from(display) >= MAX_CRTCS {
        return false;
    }
    let kms = KMS.lock();
    let target = match connector {
        Some(id) => match connector_of(&kms, id) {
            Some(n) => Some(n),
            None => return false,
        },
        None => None,
    };
    kms.find_mode(target, mode).is_some()
}
/// Record the mode DRM set (one of the offered timings; None: preferred).
pub fn request_display_mode(display: u8, mode: Option<&DrmModeModeInfo>) -> bool {
    if usize::from(display) >= MAX_CRTCS {
        return false;
    }
    requested(|k| match mode {
        None => {
            k.crtc.requested = None;
            true
        }
        Some(m) => match k.find_mode(None, m) {
            Some(t) => {
                k.crtc.requested = Some(t);
                true
            }
            None => false,
        },
    })
}
/// Console defaults (on, preferred mode, automatic routing), as
/// drm_fb_helper restores the console on lastclose.
pub fn restore_displays() {
    requested(|k| {
        k.crtc.active = true;
        k.crtc.requested = None;
        k.crtc.explicit = false;
        true
    });
}

/// `DisplayAdmission` of an admitted DML30 plan on `streams` lit pipes, for
/// `amdgpu_navi22_power_policy` (which still refuses every feature). DML30
/// answers DRAM clock change support; this owner keeps stutter off, does not
/// evaluate FCLK switching, installs no PMFW `TABLE_WATERMARKS` and requests
/// no deep-sleep floor, so those stay false. The floors are what the plan was
/// computed at (the board's pinned maximum levels).
pub fn display_admission(
    admitted: &crate::amdgpu_navi22_modeset::Admitted,
    streams: u8,
) -> DisplayAdmission {
    use crate::amdgpu_dml30::DramClockChange;
    let mhz = |khz: u32| u16::try_from(khz / 1000).unwrap_or(u16::MAX);
    DisplayAdmission {
        active_streams: streams,
        dram_clock_change: streams != 0
            && admitted.plan.dram_clock_change != DramClockChange::Unsupported,
        fclk_change: false,
        stutter: false,
        watermarks: false,
        min_uclk_mhz: u16::try_from(admitted.soc.dram_speed_mts / 16).unwrap_or(u16::MAX),
        min_fclk_mhz: mhz(admitted.soc.fabric_khz),
        min_dcefclk_mhz: mhz(admitted.plan.clocks.dcfclk_khz),
        deep_sleep_dcefclk: false,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_kms_tests.rs"]
mod tests;
