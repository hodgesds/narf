//! The native Navi22 display as DRM KMS state on the amdgpu card, after
//! `amdgpu_navi48_kms` (whose CRTC/encoder/connector id scheme and DRM wire
//! forms this reuses): one CRTC per lit pipe (the single-pipe owner lights
//! pipe 0, CRTC id 1; CRTCs 1..3 light with it as one multi-stream context,
//! `amdgpu_navi22_modeset::Group`), and one connector per board port in VBIOS
//! route order (DP-1..3 and HDMI-A-1 on the RX 6750 XT), each with its own
//! TMDS-type encoder. A connected sink carries its EDID; its modes are the
//! EDID timings the DCN30 admission accepts (`amdgpu_navi22_modeset::offered`
//! against the board's SoC inputs), so SETCRTC, atomic commits and TEST_ONLY
//! checks only ever accept what DML30 admitted. A DP sink's modes are also
//! bounded by its link (`dp_validate_mode_timing`): the link its last
//! lighting verified (`amdgpu_dcn30_dp_link::verify_link_cap`), or before
//! that what its receiver caps allow.
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

/// CRTCs published: CRTC 0 is the single-pipe owner's
/// (`amdgpu_navi22_modeset`, pipe 0, presentation); CRTCs 1.. light only
/// as one multi-stream context with CRTC 0 (`amdgpu_navi22_modeset::Group`,
/// one pipe per stream), at most the shared KMS id scheme's four outputs.
pub const MAX_CRTCS: usize = 4; // linux: n/a (amdgpu_navi48_kms MAX_OUTPUTS id scheme)
/// Automatic routing gives the secondary CRTCs the remaining sinks (the
/// `amdgpu.navi22_multi` opt-in); without it only DRM routes them.
static AUTO_MULTI: AtomicBool = AtomicBool::new(false);
pub fn set_auto_multi(on: bool) {
    AUTO_MULTI.store(on, Ordering::Release);
}

/// DRM_FORMAT_XRGB8888 and ARGB8888: what the native scanout presents.
// linux: n/a (DRM_FORMAT_XRGB8888, DRM_FORMAT_ARGB8888: fourcc_code() in drm_fourcc.h)
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
    /// Whether the single-pipe owner can drive this connector (HDMI, or
    /// DP SST through `amdgpu_dcn30_dp_link`).
    pub fn lightable(&self) -> bool {
        self.present && (self.unadmitted || !self.modes.is_empty())
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

/// The multi-stream context's next step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroupAction {
    Nothing,
    /// Tear the lit context down (a CRTC changed, or none but CRTC 0 is
    /// wanted any more).
    Unlight,
    /// Light every (CRTC, connector, requested mode) together.
    Light(Vec<(usize, usize, Option<Timing>)>),
}

/// Connectors and the CRTCs, under one lock.
#[derive(Debug)]
pub struct Kms {
    pub connectors: Vec<ConnectorState>,
    pub crtc: CrtcState,
    /// The (route, want) the monitor last tried to light, so a sink that
    /// failed is not relit every pass; cleared by any new request.
    pub attempted: Option<(usize, Option<Timing>)>,
    /// CRTCs 1.. (lit only with CRTC 0, as one multi-stream context).
    pub secondary: [CrtcState; MAX_CRTCS - 1],
    /// The multi-stream context the monitor last tried, as `attempted`.
    pub attempted_group: Option<Vec<(usize, Option<Timing>)>>,
}
impl Kms {
    pub const fn new() -> Self {
        Self {
            connectors: Vec::new(),
            crtc: CrtcState::new(),
            attempted: None,
            secondary: [const { CrtcState::new() }; MAX_CRTCS - 1],
            attempted_group: None,
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
        self.reconcile_sinks(reports, |port, sink| offered(port, &sink.edid));
    }
    /// `reconcile` with the whole detected sink, which a DP connector's
    /// offers need (its receiver caps and verified link).
    pub fn reconcile_sinks(
        &mut self,
        reports: &[Report],
        offered: impl Fn(&Port, &crate::amdgpu_navi22_display::Sink) -> Option<Vec<Timing>>,
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
            let (modes, unadmitted) = match &report.detection {
                Detection::Connected(sink) => match offered(&report.connector, sink) {
                    Some(modes) => (modes, false),
                    None => (Vec::new(), true),
                },
                _ => (Vec::new(), false),
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
        self.reconcile_secondary(&old);
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
        // As `amdgpu_navi22_modeset::choose`: an HDMI sink first, else the
        // first DisplayPort one.
        if self.crtc.route.is_none() {
            let held = |n: usize| self.secondary.iter().any(|c| c.route == Some(n));
            let first = |signal| {
                (0..self.connectors.len()).find(|&n| {
                    let c = &self.connectors[n];
                    c.port.signal == signal && c.lightable() && !held(n)
                })
            };
            self.crtc.route = first(Signal::Hdmi).or_else(|| first(Signal::DisplayPort));
        }
        self.assign_secondary();
    }
    /// Timings the CRTC can switch `connector` (default: its route) to.
    pub fn offered(&self, connector: Option<usize>) -> &[Timing] {
        self.offered_at(0, connector)
    }
    /// Timings CRTC `d` can switch `connector` (default: its route) to.
    pub fn offered_at(&self, d: usize, connector: Option<usize>) -> &[Timing] {
        let Some(c) = connector.or(self.crtc_at(d).and_then(|c| c.route)) else {
            return &[];
        };
        match self.connectors.get(c) {
            Some(x) if x.lightable() => &x.modes,
            _ => &[],
        }
    }
    pub fn find_mode(&self, connector: Option<usize>, mode: &DrmModeModeInfo) -> Option<Timing> {
        self.find_mode_at(0, connector, mode)
    }
    pub fn find_mode_at(
        &self,
        d: usize,
        connector: Option<usize>,
        mode: &DrmModeModeInfo,
    ) -> Option<Timing> {
        let geometry = |w: &DrmModeModeInfo| {
            (
                w.clock,
                [w.hdisplay, w.hsync_start, w.hsync_end, w.htotal],
                [w.vdisplay, w.vsync_start, w.vsync_end, w.vtotal],
            )
        };
        self.offered_at(d, connector)
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
    /// CRTC `d` (0: the single-pipe owner's).
    pub fn crtc_at(&self, d: usize) -> Option<&CrtcState> {
        match d {
            0 => Some(&self.crtc),
            _ => self.secondary.get(d - 1),
        }
    }
    pub fn crtc_at_mut(&mut self, d: usize) -> Option<&mut CrtcState> {
        match d {
            0 => Some(&mut self.crtc),
            _ => self.secondary.get_mut(d - 1),
        }
    }
    /// The CRTC routed to connector `n`.
    pub fn crtc_of(&self, n: usize) -> Option<usize> {
        (0..MAX_CRTCS).find(|&d| self.crtc_at(d).is_some_and(|c| c.route == Some(n)))
    }
    /// `reconcile_sinks` for CRTCs 1..: routes to vanished connectors drop,
    /// and a changed EDID voids the requested mode.
    fn reconcile_secondary(&mut self, old: &[ConnectorState]) {
        let connectors = &self.connectors;
        for c in &mut self.secondary {
            match c.route {
                Some(r) if r >= connectors.len() => {
                    c.route = None;
                    c.explicit = false;
                    c.requested = None;
                    c.shown = None;
                }
                Some(r)
                    if old.get(r).is_some_and(|o| {
                        o.port == connectors[r].port && o.edid != connectors[r].edid
                    }) =>
                {
                    c.requested = None;
                }
                _ => {}
            }
        }
    }
    /// Automatic routing for CRTCs 1.. (as `amdgpu_navi48`'s): an
    /// automatically routed CRTC drops a sink it can no longer light, or
    /// one CRTC 0 took; with the opt-in, each lightable connector without a
    /// CRTC takes the first free one. DRM's routes stay.
    fn assign_secondary(&mut self) {
        let lead = self.crtc.route;
        for c in &mut self.secondary {
            if !c.explicit
                && c.route.is_some_and(|r| {
                    lead == Some(r)
                        || !self
                            .connectors
                            .get(r)
                            .is_some_and(ConnectorState::lightable)
                })
            {
                c.route = None;
            }
        }
        if !AUTO_MULTI.load(Ordering::Acquire) {
            return;
        }
        for n in 0..self.connectors.len() {
            if !self.connectors[n].lightable() || self.crtc_of(n).is_some() {
                continue;
            }
            if let Some(c) = self
                .secondary
                .iter_mut()
                .find(|c| c.route.is_none() && !c.explicit)
            {
                c.route = Some(n);
            }
        }
    }
    /// Every CRTC that should show a sink: (CRTC, connector, requested mode).
    pub fn targets(&self) -> Vec<(usize, usize, Option<Timing>)> {
        (0..MAX_CRTCS)
            .filter_map(|d| {
                let c = self.crtc_at(d)?;
                let r = c.route?;
                (c.active
                    && self
                        .connectors
                        .get(r)
                        .is_some_and(ConnectorState::lightable))
                .then_some((d, r, c.requested))
            })
            .collect()
    }
    /// The next multi-stream step given the lit context's (CRTC, connector,
    /// timing) per stream. A context is wanted while a CRTC other than 0
    /// should show a sink; it relights whole on any change, as the group
    /// has no incremental add.
    pub fn next_group(&self, running: Option<&[(usize, usize, Timing)]>) -> GroupAction {
        let targets = self.targets();
        let wanted = targets.iter().any(|t| t.0 != 0);
        match (running, wanted) {
            (Some(_), false) => GroupAction::Unlight,
            (Some(lit), true) => {
                let same = lit.len() == targets.len()
                    && lit
                        .iter()
                        .zip(&targets)
                        .all(|(l, t)| l.0 == t.0 && l.1 == t.1 && t.2.is_none_or(|w| w == l.2));
                if same {
                    GroupAction::Nothing
                } else {
                    GroupAction::Unlight
                }
            }
            (None, true) => {
                let key: Vec<_> = targets.iter().map(|t| (t.1, t.2)).collect();
                if self.attempted_group.as_ref() == Some(&key) {
                    GroupAction::Nothing
                } else {
                    GroupAction::Light(targets)
                }
            }
            (None, false) => GroupAction::Nothing,
        }
    }
    /// The sink CRTC `d` shows to DRM: while on and routed to a sink.
    pub fn published_at(&self, d: usize) -> Option<&([u8; 128], Timing, Vec<Timing>)> {
        let c = self.crtc_at(d)?;
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

/// Publish the connectors and CRTCs on the registered amdgpu card: every
/// connector may drive every CRTC (one DIG per stream, any pipe), as DC's
/// `possible_crtcs`.
pub fn publish() {
    let kms = KMS.lock();
    let crtcs: Vec<Option<crate::amdgpu_navi48_kms::Sink>> = (0..MAX_CRTCS)
        .map(|d| {
            kms.published_at(d)
                .map(|(edid, timing, offered)| crate::amdgpu_navi48_kms::Sink {
                    edid,
                    timing,
                    offered,
                })
        })
        .collect();
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
            crtc: kms.crtc_of(n),
            possible_crtcs: (1 << MAX_CRTCS) - 1,
        })
        .collect();
    let off: Vec<usize> = (0..MAX_CRTCS)
        .filter(|&d| {
            kms.crtc_at(d)
                .is_some_and(|c| c.shown.is_some() && !c.active)
        })
        .collect();
    with_card(|card| {
        apply_card(card, &crtcs, &connectors);
        for &d in &off {
            crate::amdgpu_navi48_kms::set_crtc_active(card, d, false);
        }
    });
    ACTIVE.store(true, Ordering::Release);
}

fn apply_card(
    card: &mut Card,
    crtcs: &[Option<crate::amdgpu_navi48_kms::Sink<'_>>],
    connectors: &[crate::amdgpu_navi48_kms::RoutedConnector<'_>],
) {
    crate::amdgpu_navi48_kms::apply_routed(card, crtcs, connectors);
    card.vblank_source = Some(crate::amdgpu_navi22_platform::crtc_vblank);
    card.plane_formats = Some(&PLANE_FORMATS);
    // Share connector/CRTC bookkeeping, not DCN401's plane capabilities.
    // This presenter copies one linear 8888 primary into its DCN30 back
    // buffer; overlays, GFX12 tiling and native plane geometry have no
    // implementation here. Keep the generic atomic primary/cursor ABI.
    card.native_planes.clear();
    card.overlay_formats = None;
    card.gfx12_modifiers = false;
}

type CardState = alloc::sync::Arc<narf_lib::sync::IrqSafeSpinLock<Card>>;
fn amdgpu_card() -> Option<(u32, Option<CardState>)> {
    let index = crate::amdgpu_navi22_cs::drm_card()?;
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
            kms.attempted_group = None;
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
    requested(|k| match k.crtc_at_mut(usize::from(display)) {
        Some(c) => {
            c.active = active;
            true
        }
        None => false,
    });
}
/// The connector index behind a KMS connector id, if it exists.
fn connector_of(kms: &Kms, id: u32) -> Option<usize> {
    crate::amdgpu_navi48_kms::connector_index(id).filter(|&n| n < kms.connectors.len())
}
/// Route the CRTC to connector `connector` (KMS id; None: none). Every
/// board HDMI and DP port can be driven by every CRTC; another CRTC
/// driving that connector loses it. False for an unknown one.
pub fn request_display_route(display: u8, connector: Option<u32>) -> bool {
    let d = usize::from(display);
    if d >= MAX_CRTCS {
        return false;
    }
    requested(|k| {
        let target = match connector {
            Some(id) => match connector_of(k, id) {
                Some(n) => Some(n),
                None => return false,
            },
            None => None,
        };
        if let Some(n) = target {
            for other in (0..MAX_CRTCS).filter(|&o| o != d) {
                if let Some(c) = k.crtc_at_mut(other).filter(|c| c.route == Some(n)) {
                    c.route = None;
                    c.explicit = true;
                    c.requested = None;
                    c.shown = None;
                }
            }
        }
        let Some(c) = k.crtc_at_mut(d) else {
            return false;
        };
        if c.route != target {
            c.requested = None;
            c.shown = None;
        }
        c.route = target;
        c.explicit = true;
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
            if let Some(c) = k.crtc_of(n).and_then(|d| k.crtc_at_mut(d)) {
                c.route = None;
                c.explicit = true;
            }
            true
        }),
    }
}
/// Whether `mode` is a DCN30-admitted timing of the CRTC's connector (or of
/// `connector`, a KMS id, when the same request routes it there). This is
/// the TEST_ONLY / SETCRTC validation.
pub fn display_offers(display: u8, connector: Option<u32>, mode: &DrmModeModeInfo) -> bool {
    let d = usize::from(display);
    if d >= MAX_CRTCS {
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
    kms.find_mode_at(d, target, mode).is_some()
}
/// Record the mode DRM set (one of the offered timings; None: preferred).
pub fn request_display_mode(display: u8, mode: Option<&DrmModeModeInfo>) -> bool {
    let d = usize::from(display);
    if d >= MAX_CRTCS {
        return false;
    }
    requested(|k| {
        let want = match mode {
            None => None,
            Some(m) => match k.find_mode_at(d, None, m) {
                Some(t) => Some(t),
                None => return false,
            },
        };
        match k.crtc_at_mut(d) {
            Some(c) => {
                c.requested = want;
                true
            }
            None => false,
        }
    })
}
/// Console defaults (on, preferred mode, automatic routing), as
/// drm_fb_helper restores the console on lastclose.
pub fn restore_displays() {
    requested(|k| {
        for d in 0..MAX_CRTCS {
            if let Some(c) = k.crtc_at_mut(d) {
                c.active = true;
                c.requested = None;
                c.explicit = false;
            }
        }
        true
    });
}

/// `DisplayAdmission` of an admitted DML30 plan on `streams` lit pipes, for
/// `amdgpu_navi22_power_policy`. DML30 answers DRAM clock change support;
/// `watermarks` is the HUBBUB half (sets A-D programmed from the plan:
/// `hubbub3_program_watermarks`), which the power-saving path ANDs with its
/// PMFW `TABLE_WATERMARKS` upload. This owner keeps stutter off, does not
/// evaluate FCLK switching and requests no deep-sleep floor, so those stay
/// false. The floors are the state the plan was computed at: the board's
/// top state for one stream, the lowest supporting UCLK state for a
/// multi-stream context (`dml30::plan_joint_lowest`).
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
        watermarks: streams != 0,
        // linux: n/a (memclk_mhz * 16, dcn30_resource.c dcn30_update_bw_bounding_box)
        min_uclk_mhz: u16::try_from(admitted.soc.dram_speed_mts / 16).unwrap_or(u16::MAX),
        min_fclk_mhz: mhz(admitted.soc.fabric_khz),
        min_dcefclk_mhz: mhz(admitted.plan.clocks.dcfclk_khz),
        deep_sleep_dcefclk: false,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_kms_tests.rs"]
mod tests;
