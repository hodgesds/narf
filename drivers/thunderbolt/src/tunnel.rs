//! Owned USB4 DisplayPort paths. Configuration writes are recorded for reverse
//! rollback; no enabled firmware path is overwritten. Reference: Linux path.c,
//! tunnel.c, switch.c and usb4.c in /usr/src/linux/drivers/thunderbolt.
use super::{
    cm::{route_depth, CfgSpace},
    control::Config,
    dp_bw::{
        self, DpAdapterCaps, DpRate, DpTunnelInfo, Granularity, ADP_DP_CS_2, ADP_DP_CS_8, CS2_CA,
        CS2_CMMS, CS2_CM_ID_SHIFT, CS2_ESTIMATED_BW_SHIFT, CS2_GROUP_ID_SHIFT, CS8_DR,
        CS8_REQUESTED_BW_MASK, DP_LOCAL_CAP, DP_REMOTE_CAP, DP_STATUS, STATUS_ALLOCATED_BW_SHIFT,
    },
    ring::Error,
    topology::{router_operation, Domain, Port, Router},
};
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub route: u64,
    pub port: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    DisplayPort,
    Usb3,
    /// PCIe tunnelling between a PCIe downstream adapter on an
    /// ancestor router and a PCIe upstream adapter on a device
    /// router. Programmed only when firmware granted the PCIe bit
    /// of the USB4 `_OSC` control mask (see
    /// `firmware::CONTROL_PCIE`); without the grant the CM never
    /// writes a PCIe path and the router's PCIe-tunnelling
    /// configuration bit stays clear.
    Pcie,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TunnelInfo {
    pub domain: u32,
    pub input: Endpoint,
    pub output: Endpoint,
    pub protocol: Protocol,
    pub dprx_done: bool,
    /// DP state (negotiated envelope + live allocation) for
    /// DisplayPort tunnels; `None` for other protocols. Recorded
    /// at activation so suspend/resume replay rebuilds the tunnel
    /// at its recorded rate (see `dp_bw::DpTunnelInfo`).
    pub dp: Option<DpTunnelInfo>,
    /// Fabric bandwidth this tunnel currently consumes, in Mb/s:
    /// the DP grant for DisplayPort, the USB3 handshake's up+down
    /// allocation (converted with the crate's USB3 unit
    /// definition) for USB3, zero for PCIe. DP bandwidth-group
    /// accounting charges every live tunnel sharing a first link
    /// against that link's budget.
    pub consumed_mbps: u32,
}
static DISPLAYS: IrqSafeSpinLock<Vec<TunnelInfo>> = IrqSafeSpinLock::new(Vec::new());
pub(crate) fn forget_domain(id: u32) {
    DISPLAYS.lock().retain(|t| t.domain != id);
}
pub fn displays() -> Vec<TunnelInfo> {
    DISPLAYS
        .lock()
        .iter()
        .filter(|t| t.protocol == Protocol::DisplayPort)
        .cloned()
        .collect()
}
pub fn usb3_tunnels() -> Vec<TunnelInfo> {
    DISPLAYS
        .lock()
        .iter()
        .filter(|t| t.protocol == Protocol::Usb3)
        .cloned()
        .collect()
}
pub fn pcie_tunnels() -> Vec<TunnelInfo> {
    DISPLAYS
        .lock()
        .iter()
        .filter(|t| t.protocol == Protocol::Pcie)
        .cloned()
        .collect()
}

/// The USB4 `_OSC` control mask most recently handed to
/// `reconcile` — exactly the protocol bits firmware granted
/// (see `firmware`). This is the CM's explicit record of what it
/// may program: a caller distinguishing "no PCIe devices present"
/// from "firmware did not grant PCIe control" reads it here
/// instead of inferring from an empty tunnel list.
static GRANTED_CONTROLS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

pub fn granted_controls() -> u32 {
    GRANTED_CONTROLS.load(core::sync::atomic::Ordering::Relaxed)
}

/// True while firmware's `_OSC` grant includes PCIe tunnelling.
/// PCIe paths are programmed only in this state.
pub fn pcie_tunnelling_granted() -> bool {
    granted_controls() & super::firmware::CONTROL_PCIE != 0
}

/// Number of live tunnels across all domains, as published by
/// `reconcile` and drained by teardown / [`forget_domain`]. Every
/// entry is a DisplayPort, USB3 or PCIe path the CM currently owns
/// in the routers; this is the count the device-PM handler gates
/// on.
pub fn live_tunnel_count() -> usize {
    DISPLAYS.lock().len()
}

/// Domains whose CM task exited with tunnel writes still
/// unrolled-back. A poisoned config channel can prevent teardown
/// from restoring the registers a tunnel programmed, so those paths
/// may still exist in the routers even though the domain's published
/// snapshots are gone. Recorded by `topology::run` on exit; read by
/// the device-PM handler, which keeps refusing suspend while any
/// domain is marked (see `pm.rs`).
static ORPHANED_PATH_DOMAINS: IrqSafeSpinLock<Vec<u32>> = IrqSafeSpinLock::new(Vec::new());

/// Record whether `domain`'s CM exited leaving tunnel path writes
/// unrolled-back. Called once per domain from `topology::run`'s exit
/// path, after the teardown loop; `orphaned == false` clears the
/// mark, so a CM that tears everything down cleanly never vetoes
/// suspend after it stops.
pub(crate) fn note_orphaned_paths(domain: u32, orphaned: bool) {
    let mut domains = ORPHANED_PATH_DOMAINS.lock();
    domains.retain(|d| *d != domain);
    if orphaned {
        domains.push(domain);
    }
}

/// Domains whose routers may still carry CM-programmed paths with
/// no live owner able to roll them back.
pub fn orphaned_path_domains() -> Vec<u32> {
    ORPHANED_PATH_DOMAINS.lock().clone()
}

#[doc(hidden)]
pub fn __reset_orphaned_for_test() {
    ORPHANED_PATH_DOMAINS.lock().clear();
}

// ── Tunnel suspend / resume replay (#1035) ──────────────────────
//
// The device-PM handlers (`pm.rs`) run on the boot CPU with
// interrupts gated and may not schedule, sleep, or await a config
// transaction — but quiescing a tunnel *is* config transactions,
// and the tunnels are owned by the per-domain CM task. The two
// sides therefore meet in the latch below:
//
// - The suspend handler calls [`pm_on_suspend`]. While any domain
//   still has live, unquiesced tunnels it latches that domain
//   `SuspendRequested` and returns `Busy` — the documented
//   retry-later verdict. The CM task services the latch from its
//   own loop (`topology::run`), draining each tunnel through the
//   journaled teardown (hop drain before credit release, exactly
//   teardown's order) and recording the tunnel's identity in
//   `records`. Once every domain is quiesced the handler returns
//   `Ok` and the suspend attempt proceeds.
// - The resume handler calls [`pm_on_resume`], which latches
//   `ResumeRequested`. The CM re-scans the topology first, then
//   replays each record through the same `Tunnel::activate` path
//   that programmed it originally — replay, not rediscovery: the
//   recorded endpoints are matched against the re-scanned domain,
//   and a peer that vanished across the sleep is dropped (its
//   paths were drained at quiesce), never replayed.
// - A replay that fails is rolled back through the failed
//   activation's own journal, so no path is left half-programmed,
//   and the tunnel is named in `failures`. Outstanding failures
//   make the suspend handler keep returning `Busy` and the resume
//   handler return `DriverError`; a resume call also re-queues
//   failed tunnels for one retry. Nothing about a failed replay is
//   silent: it is logged by the CM, held in
//   [`replay_failures`], and reflected in both handlers' verdicts.

/// Replay phase of one domain, driven by the PM latch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PmPhase {
    /// Tunnels live (or none recorded); normal reconcile runs.
    Active,
    /// The suspend handler latched a quiesce request; the CM task
    /// drains the domain's tunnels into the replay records.
    SuspendRequested,
    /// All of the domain's tunnels are quiesced and recorded; the
    /// suspend handler now returns `Ok` for the domain.
    Quiesced,
    /// The resume handler latched a replay request; the CM task
    /// replays the records against the re-scanned topology.
    ResumeRequested,
}

#[derive(Debug)]
struct PmDomain {
    domain: u32,
    phase: PmPhase,
    /// Tunnels quiesced for suspend, in quiesce order (reverse of
    /// activation order — replay pops from the end, restoring the
    /// original activation order). A record is the tunnel's
    /// published identity; replay rebuilds the path from it.
    records: Vec<TunnelInfo>,
    /// Tunnels whose replay failed and rolled back, held until a
    /// resume call re-queues them for a retry.
    failures: Vec<TunnelInfo>,
}

static PM_DOMAINS: IrqSafeSpinLock<Vec<PmDomain>> = IrqSafeSpinLock::new(Vec::new());

fn pm_domain_mut(domains: &mut Vec<PmDomain>, domain: u32) -> &mut PmDomain {
    let index = match domains.iter().position(|d| d.domain == domain) {
        Some(i) => i,
        None => {
            domains.push(PmDomain {
                domain,
                phase: PmPhase::Active,
                records: Vec::new(),
                failures: Vec::new(),
            });
            domains.len() - 1
        }
    };
    &mut domains[index]
}

/// The domain's current replay phase (`Active` when the domain
/// has no PM state). The CM loop gates scan/reconcile on it: while
/// a domain is quiescing or quiesced, rediscovery must not
/// reprogram the paths suspend drained.
pub(crate) fn pm_phase(domain: u32) -> PmPhase {
    PM_DOMAINS
        .lock()
        .iter()
        .find(|d| d.domain == domain)
        .map_or(PmPhase::Active, |d| d.phase)
}

/// Tunnels currently quiesced for system suspend, recorded by
/// identity and awaiting replay on resume.
pub fn suspended_tunnels() -> Vec<TunnelInfo> {
    PM_DOMAINS
        .lock()
        .iter()
        .flat_map(|d| d.records.iter().cloned())
        .collect()
}

/// Tunnels whose resume replay failed and rolled back. Non-empty
/// is a named, persistent fault state: the suspend handler keeps
/// refusing (`Busy`) and the resume handler reports
/// `DriverError` while it lasts; a resume call re-queues the
/// recorded tunnels for one retry.
pub fn replay_failures() -> Vec<TunnelInfo> {
    PM_DOMAINS
        .lock()
        .iter()
        .flat_map(|d| d.failures.iter().cloned())
        .collect()
}

#[doc(hidden)]
pub fn __reset_pm_for_test() {
    PM_DOMAINS.lock().clear();
}

/// The CM's device-PM suspend verdict, with the latch side
/// effects described above. Called only from `pm.rs`.
pub(crate) fn pm_on_suspend() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    if !orphaned_path_domains().is_empty() || !replay_failures().is_empty() {
        return Err(DeviceSuspendError::Busy);
    }
    let mut ready = true;
    let mut domains = PM_DOMAINS.lock();
    for state in domains.iter_mut() {
        match state.phase {
            PmPhase::Active | PmPhase::Quiesced => {}
            PmPhase::SuspendRequested => ready = false,
            PmPhase::ResumeRequested => {
                // A suspend attempt supersedes a pending replay:
                // the recorded tunnels are still quiesced, so the
                // CM only has to confirm the quiesced state.
                state.phase = PmPhase::SuspendRequested;
                ready = false;
            }
        }
    }
    // Latch a quiesce request for every domain with live tunnels.
    // Lock order is PM_DOMAINS → DISPLAYS; no other path nests
    // them (teardown and reconcile take DISPLAYS alone, the
    // service functions take PM_DOMAINS only between awaits).
    let live_domains: Vec<u32> = DISPLAYS.lock().iter().map(|t| t.domain).collect();
    for domain in live_domains {
        let state = pm_domain_mut(&mut domains, domain);
        if state.phase != PmPhase::Quiesced {
            state.phase = PmPhase::SuspendRequested;
        }
        ready = false;
    }
    if ready {
        Ok(())
    } else {
        Err(DeviceSuspendError::Busy)
    }
}

/// The CM's device-PM resume verdict: latch replay for every
/// domain holding quiesced tunnels, cancel suspend requests that
/// never reached a quiesce, and re-queue failed replays for one
/// retry. Returns `DriverError` when replay failures are
/// outstanding at call time, so a failed replay is surfaced in
/// the fan-out report even though the retry is queued.
pub(crate) fn pm_on_resume() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let failed = !replay_failures().is_empty();
    let mut domains = PM_DOMAINS.lock();
    for state in domains.iter_mut() {
        if state.phase == PmPhase::Active && !state.failures.is_empty() {
            let retry = core::mem::take(&mut state.failures);
            state.records.extend(retry);
            state.phase = PmPhase::ResumeRequested;
        } else if state.records.is_empty()
            && matches!(state.phase, PmPhase::Quiesced | PmPhase::SuspendRequested)
        {
            // Nothing recorded to replay (the suspend attempt was
            // aborted before the CM quiesced, or the domain had
            // already drained): the domain is simply active again.
            state.phase = PmPhase::Active;
        } else if !state.records.is_empty()
            && matches!(state.phase, PmPhase::Quiesced | PmPhase::SuspendRequested)
        {
            state.phase = PmPhase::ResumeRequested;
        }
    }
    if failed {
        Err(DeviceSuspendError::DriverError)
    } else {
        Ok(())
    }
}

/// Service one domain's latched suspend request: quiesce each of
/// its tunnels through the journaled teardown (hop drain before
/// credit release), recording each tunnel's identity for replay,
/// in reverse activation order — the same order CM exit uses.
/// Called from the CM task (`topology::run`), never from the PM
/// handler. A teardown failure leaves the remaining tunnels live
/// and the request latched, so the handler keeps returning
/// `Busy` and the next service pass retries the quiesce.
pub(crate) async fn service_pm_suspend(
    ctl: &mut impl Config,
    domain: &Domain,
    tunnels: &mut Vec<Tunnel>,
) -> Result<(), Error> {
    if pm_phase(domain.id) != PmPhase::SuspendRequested {
        return Ok(());
    }
    let mut index = tunnels.len();
    while index > 0 {
        index -= 1;
        if tunnels[index].display.domain != domain.id {
            continue;
        }
        let mut tunnel = tunnels.remove(index);
        match tunnel.teardown(ctl, domain).await {
            Ok(()) => {
                let mut domains = PM_DOMAINS.lock();
                pm_domain_mut(&mut domains, domain.id)
                    .records
                    .push(tunnel.display.clone());
            }
            Err(e) => {
                tunnels.insert(index, tunnel);
                return Err(e);
            }
        }
    }
    let mut domains = PM_DOMAINS.lock();
    pm_domain_mut(&mut domains, domain.id).phase = PmPhase::Quiesced;
    Ok(())
}

/// Service one domain's latched resume request: replay each
/// recorded tunnel against the re-scanned `domain`, in the
/// original activation order, through the same activation path
/// that programmed it before the sleep. Records whose endpoints
/// vanished across the sleep are dropped — torn down, not
/// replayed. A failed activation is rolled back through its own
/// journal (never left half-programmed) and the tunnel is named
/// in [`replay_failures`]; if even the rollback fails, the CM
/// keeps the tunnel and its journal so the exit-orphan machinery
/// still accounts for its writes.
pub(crate) async fn service_pm_resume(
    ctl: &mut impl Config,
    domain: &Domain,
    tunnels: &mut Vec<Tunnel>,
) -> Result<(), Error> {
    use core::fmt::Write as _;
    let mut records = {
        let mut domains = PM_DOMAINS.lock();
        match domains.iter_mut().find(|d| d.domain == domain.id) {
            Some(state) if state.phase == PmPhase::ResumeRequested => {
                core::mem::take(&mut state.records)
            }
            _ => return Ok(()),
        }
    };
    while let Some(info) = records.pop() {
        if port(domain, info.input).is_err() || port(domain, info.output).is_err() {
            let _ = writeln!(
                narf_console::Writer,
                "usb4: domain {}: {:?} tunnel (route {:#x} port {} -> route {:#x} port {}) \
                 vanished across suspend; torn down, not replayed",
                domain.id,
                info.protocol,
                info.input.route,
                info.input.port,
                info.output.route,
                info.output.port,
            );
            continue;
        }
        let mut tunnel = Tunnel {
            display: info.clone(),
            writes: Vec::new(),
            resource: false,
            hpd_owned: false,
            bandwidth: None,
        };
        match tunnel.activate(ctl, domain).await {
            Ok(()) => tunnels.push(tunnel),
            Err(e) => {
                let _ =
                    writeln!(
                    narf_console::Writer,
                    "usb4: domain {}: replay of {:?} tunnel (route {:#x} port {} -> route {:#x} \
                     port {}) failed: {e:?}; rolled back, recorded as a replay failure",
                    domain.id, info.protocol, info.input.route, info.input.port, info.output.route,
                    info.output.port,
                );
                if tunnel.teardown(ctl, domain).await.is_err() {
                    tunnels.push(tunnel);
                }
                let mut domains = PM_DOMAINS.lock();
                pm_domain_mut(&mut domains, domain.id).failures.push(info);
            }
        }
    }
    // Republish this domain's live set: replay bypassed reconcile,
    // which is what normally rebuilds the published snapshots.
    {
        let mut displays = DISPLAYS.lock();
        displays.retain(|d| d.domain != domain.id);
        displays.extend(
            tunnels
                .iter()
                .filter(|t| t.display.domain == domain.id)
                .map(|t| t.display.clone()),
        );
    }
    let mut domains = PM_DOMAINS.lock();
    pm_domain_mut(&mut domains, domain.id).phase = PmPhase::Active;
    Ok(())
}

#[derive(Clone, Debug)]
struct Hop {
    route: u64,
    input: Port,
    output: Port,
    id: u16,
    next: u16,
}
#[derive(Debug)]
pub(crate) struct Undo {
    endpoint: Endpoint,
    space: CfgSpace,
    offset: u16,
    words: Vec<u32>,
}
#[derive(Debug)]
pub(crate) struct Tunnel {
    pub display: TunnelInfo,
    // Crate-visible so sibling fixture modules (dp_bw::tests) can
    // construct a tunnel directly, e.g. a suspend/resume replay
    // rebuilt from its recorded TunnelInfo.
    pub(crate) writes: Vec<Undo>,
    pub(crate) resource: bool,
    pub(crate) hpd_owned: bool,
    pub(crate) bandwidth: Option<(u16, u32)>,
}

fn router(domain: &Domain, route: u64) -> Result<&Router, Error> {
    domain
        .routers
        .iter()
        .find(|r| r.route == route)
        .ok_or(Error::Invalid)
}
fn port(domain: &Domain, endpoint: Endpoint) -> Result<&Port, Error> {
    router(domain, endpoint.route)?
        .ports
        .iter()
        .find(|p| p.number == endpoint.port)
        .ok_or(Error::Invalid)
}
fn chain(domain: &Domain, input: Endpoint, output: Endpoint) -> Result<Vec<Hop>, Error> {
    let start = route_depth(input.route);
    let depth = route_depth(output.route);
    let prefix = if start == 0 {
        0
    } else {
        (1u64 << (start * 8)) - 1
    };
    if start >= depth || output.route & prefix != input.route {
        return Err(Error::Invalid);
    }
    let mut hops = Vec::new();
    for level in start..=depth {
        let route = if level == 0 {
            0
        } else {
            output.route & ((1u64 << (level * 8)) - 1)
        };
        let r = router(domain, route)?;
        let in_port = if level == start {
            input.port
        } else {
            r.upstream
        };
        let out_port = if level == depth {
            output.port
        } else {
            (output.route >> (level * 8)) as u8
        };
        hops.push(Hop {
            route,
            input: port(
                domain,
                Endpoint {
                    route,
                    port: in_port,
                },
            )?
            .clone(),
            output: port(
                domain,
                Endpoint {
                    route,
                    port: out_port,
                },
            )?
            .clone(),
            id: 0,
            next: 0,
        });
    }
    Ok(hops)
}
impl Tunnel {
    async fn change(
        &mut self,
        ctl: &mut impl Config,
        endpoint: Endpoint,
        space: CfgSpace,
        offset: u16,
        words: &[u32],
    ) -> Result<(), Error> {
        let old = ctl
            .read(
                endpoint.route,
                endpoint.port,
                space,
                offset,
                words.len() as u8,
            )
            .await?;
        // Record before attempting a write: even an error response may follow
        // a device having consumed part of the configuration transaction.
        self.writes.push(Undo {
            endpoint,
            space,
            offset,
            words: old,
        });
        ctl.write(endpoint.route, endpoint.port, space, offset, words)
            .await
    }
    async fn modify(
        &mut self,
        ctl: &mut impl Config,
        e: Endpoint,
        offset: u16,
        clear: u32,
        set: u32,
    ) -> Result<(), Error> {
        let value = ctl.read(e.route, e.port, CfgSpace::Port, offset, 1).await?[0];
        self.change(ctl, e, CfgSpace::Port, offset, &[(value & !clear) | set])
            .await
    }
    /// True while this tunnel's journal still holds configuration
    /// writes teardown has not rolled back — i.e. paths may still be
    /// programmed in the routers. `topology::run` consults this on
    /// exit to record orphaned paths for the device-PM handler.
    pub(crate) fn has_unrolled_writes(&self) -> bool {
        !self.writes.is_empty()
    }
    pub async fn teardown(&mut self, ctl: &mut impl Config, live: &Domain) -> Result<(), Error> {
        DISPLAYS.lock().retain(|d| {
            !(d.domain == self.display.domain
                && d.input == self.display.input
                && d.output == self.display.output)
        });
        if self.hpd_owned {
            if let Ok(source) = port(live, self.display.input) {
                let e = self.display.input;
                let value = ctl
                    .read(e.route, e.port, CfgSpace::Port, source.adapter_cap + 3, 1)
                    .await?[0];
                ctl.write(
                    e.route,
                    e.port,
                    CfgSpace::Port,
                    source.adapter_cap + 3,
                    &[value | (1 << 9)],
                )
                .await?;
            }
            self.hpd_owned = false;
        }
        // Disable adapters before paths; drain each path before returning its
        // credits. Retain the remaining journal if a drain/write fails.
        while let Some(undo) = self.writes.last() {
            if live.routers.iter().any(|r| r.route == undo.endpoint.route) {
                if undo.space == CfgSpace::Hops {
                    let e = undo.endpoint;
                    let mut words = ctl
                        .read(e.route, e.port, undo.space, undo.offset, 2)
                        .await?;
                    words[0] &= !(1 << 31);
                    ctl.write(e.route, e.port, undo.space, undo.offset, &words)
                        .await?;
                    let deadline = narf_time::Deadline::after_ms(500);
                    loop {
                        if ctl
                            .read(e.route, e.port, undo.space, undo.offset + 1, 1)
                            .await?[0]
                            & (1 << 28)
                            == 0
                        {
                            break;
                        }
                        if deadline.expired() {
                            return Err(Error::Timeout);
                        }
                        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant())
                            .await;
                    }
                }
                ctl.write(
                    undo.endpoint.route,
                    undo.endpoint.port,
                    undo.space,
                    undo.offset,
                    &undo.words,
                )
                .await?;
            }
            self.writes.pop();
        }
        if let Some((cap, old)) = self.bandwidth {
            if port(live, self.display.input).is_ok() {
                usb3_bandwidth(ctl, self.display.input, cap, Some(old)).await?;
            }
            self.bandwidth = None;
        }
        if self.resource && port(live, self.display.input).is_ok() {
            match router_operation(
                ctl,
                self.display.input.route,
                0x12,
                self.display.input.port as u32,
            )
            .await?
            {
                (0, _) => self.resource = false,
                _ => return Err(Error::Failed),
            }
        }
        Ok(())
    }
    async fn path(
        &mut self,
        ctl: &mut impl Config,
        mut hops: Vec<Hop>,
        video: bool,
    ) -> Result<(), Error> {
        let usb = self.display.protocol == Protocol::Usb3;
        let endpoint_id = if video { 9 } else { 8 };
        // Allocate a free incoming HopID on every lane; fixed IDs only apply
        // to protocol adapters. Already enabled firmware paths remain owned.
        for hop in &mut hops {
            let (first, last) = if hop.input.kind == 1 {
                (8, hop.input.max_in_hop.min(2047))
            } else {
                (endpoint_id, endpoint_id)
            };
            if hop.input.max_in_hop < first {
                return Err(Error::Invalid);
            }
            for id in first..=last {
                let h = ctl
                    .read(hop.route, hop.input.number, CfgSpace::Hops, 2 * id, 2)
                    .await?;
                if h[0] & (1 << 31) == 0 {
                    hop.id = id;
                    break;
                }
            }
            if hop.id == 0 {
                return Err(Error::Full);
            }
        }
        for index in 0..hops.len() {
            hops[index].next = hops.get(index + 1).map_or(endpoint_id, |h| h.id);
            if hops[index].next > hops[index].output.max_out_hop {
                return Err(Error::Invalid);
            }
        }
        for (index, hop) in hops.iter().enumerate() {
            let e = Endpoint {
                route: hop.route,
                port: hop.input.number,
            };
            let (status, metadata) = router_operation(ctl, hop.route, 0x33, 0).await?;
            let count = (metadata & 255) as u8;
            if status != 0 || count == 0 || count > 16 {
                return Err(Error::Invalid);
            }
            let params = ctl.read(hop.route, 0, CfgSpace::Switch, 9, count).await?;
            let credit = params
                .iter()
                .find(|w| {
                    **w & 0xffff
                        == if usb {
                            1
                        } else if video {
                            3
                        } else {
                            2
                        }
                })
                .map(|w| (w >> 16) as u16)
                .ok_or(Error::Invalid)?;
            if credit == 0 || (!video && credit > 127) {
                return Err(Error::Invalid);
            }
            if hop.input.kind == 1 {
                let nfc = ctl.read(e.route, e.port, CfgSpace::Port, 4, 1).await?[0] & 1023;
                let mut allocated = nfc;
                // Include firmware and other protocol paths in the admission
                // check, including hop zero's control-channel reservation.
                let mut offset = 0u16;
                let end = (hop.input.max_in_hop + 1) * 2;
                while offset < end {
                    let count = (end - offset).min(60) as u8;
                    let entries = ctl
                        .read(e.route, e.port, CfgSpace::Hops, offset, count)
                        .await?;
                    for entry in entries.chunks_exact(2) {
                        if entry[0] & (1 << 31) != 0 {
                            allocated += (entry[0] >> 17) & 127;
                        }
                    }
                    offset += count as u16;
                }
                if allocated + credit as u32 > hop.input.total_credits as u32 {
                    return Err(Error::Full);
                }
            }
            if video && hop.input.kind == 1 {
                let old = ctl.read(e.route, e.port, CfgSpace::Port, 4, 1).await?[0];
                let nfc = (old & 1023)
                    .checked_add(credit as u32)
                    .ok_or(Error::Invalid)?;
                // Retain space for AUX and the control path; never underflow.
                if nfc + 2 > hop.input.total_credits as u32 || nfc > 1023 {
                    return Err(Error::Full);
                }
                self.change(ctl, e, CfgSpace::Port, 4, &[(old & !1023) | nfc])
                    .await?;
            }
            let old = ctl
                .read(e.route, e.port, CfgSpace::Hops, hop.id * 2, 2)
                .await?;
            let mut words = [
                hop.next as u32 | ((hop.output.number as u32) << 11) | (1 << 31),
                (if usb { 2 } else { 1 })
                    | ((if usb {
                        3
                    } else if video {
                        1
                    } else {
                        2
                    }) << 8),
            ];
            if hop.input.kind == 1 {
                if !video {
                    words[0] |= (credit as u32) << 17;
                    words[1] |= 1 << 24;
                }
            } else {
                // USB4 protocol adapter IFC/ISE and allocated credits are
                // vendor defined. Preserve exactly those fields from hardware.
                words[0] |= old[0] & (127 << 17);
                words[1] |= old[1] & ((1 << 24) | (1 << 26));
            }
            if !video && index + 1 < hops.len() {
                words[1] |= 1 << 25;
            }
            self.change(ctl, e, CfgSpace::Hops, hop.id * 2, &words)
                .await?;
        }
        Ok(())
    }
    pub(crate) async fn activate(
        &mut self,
        ctl: &mut impl Config,
        domain: &Domain,
    ) -> Result<(), Error> {
        if self.display.protocol == Protocol::Usb3 {
            return self.activate_usb3(ctl, domain).await;
        }
        if self.display.protocol == Protocol::Pcie {
            return self.activate_pcie(ctl, domain).await;
        }
        let input = self.display.input;
        let output = self.display.output;
        let source = port(domain, input)?;
        let sink = port(domain, output)?;
        for (e, p) in [(input, source), (output, sink)] {
            if p.adapter_cap == 0
                || ctl
                    .read(e.route, e.port, CfgSpace::Port, p.adapter_cap, 1)
                    .await?[0]
                    & (3 << 30)
                    != 0
            {
                return Err(Error::Full);
            }
        }
        // Query the router's DP resource before allocating it
        // (USB4 router operations: QUERY_DP_RESOURCE 0x10,
        // ALLOC_DP_RESOURCE 0x11, DEALLOC_DP_RESOURCE 0x12). A
        // router that reports the resource unavailable refuses
        // the tunnel before anything is programmed; a router
        // without the query operation falls through to the
        // allocation attempt, as before.
        match router_operation(ctl, input.route, 0x10, input.port as u32).await {
            Ok((0, _)) => {}
            Ok(_) => return Err(Error::Full),
            Err(Error::Remote(0xff)) => {}
            Err(e) => return Err(e),
        }
        match router_operation(ctl, input.route, 0x11, input.port as u32).await {
            Ok((0, _)) => self.resource = true,
            Err(Error::Remote(0xff)) => {}
            Ok(_) => return Err(Error::Full),
            Err(e) => return Err(e),
        }
        self.hpd_owned = true;
        let value = ctl
            .read(
                output.route,
                output.port,
                CfgSpace::Port,
                sink.adapter_cap + 6,
                1,
            )
            .await?[0];
        // CMHS/UF are a handshake, not persistent configuration to replay.
        ctl.write(
            output.route,
            output.port,
            CfgSpace::Port,
            sink.adapter_cap + 6,
            &[value | (1 << 25) | (1 << 26)],
        )
        .await?;
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            if ctl
                .read(
                    output.route,
                    output.port,
                    CfgSpace::Port,
                    sink.adapter_cap + 6,
                    1,
                )
                .await?[0]
                & (1 << 25)
                == 0
            {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
        }
        let in_local = ctl
            .read(
                input.route,
                input.port,
                CfgSpace::Port,
                source.adapter_cap + DP_LOCAL_CAP,
                1,
            )
            .await?[0];
        let out_local = ctl
            .read(
                output.route,
                output.port,
                CfgSpace::Port,
                sink.adapter_cap + DP_LOCAL_CAP,
                1,
            )
            .await?[0];
        let in_caps = DpAdapterCaps::decode(in_local)?;
        let out_caps = DpAdapterCaps::decode(out_local)?;
        // The tunnel envelope, in the shared negotiation
        // vocabulary (see dp_bw): the mutual ceiling of the two
        // adapters. A tunnel replayed from its suspend record
        // demands its recorded envelope, capped by what the
        // adapters still advertise — replay at the recorded rate,
        // renegotiated down only if the hardware shrank.
        let ceiling = (
            DpRate::min(in_caps.max_rate, out_caps.max_rate),
            in_caps.max_lanes.min(out_caps.max_lanes),
        );
        let demand = match self.display.dp {
            Some(recorded) => (
                DpRate::min(recorded.rate, ceiling.0),
                recorded.lanes.min(ceiling.1),
            ),
            None => ceiling,
        };
        // Bandwidth-allocation mode is an IN-adapter property: its
        // LOCAL_CAP must advertise BW_MODE and its granularity
        // must decode. Anything else is programmed in legacy mode
        // (a fixed envelope, no runtime requests).
        let in_cs2 = ctl
            .read(
                input.route,
                input.port,
                CfgSpace::Port,
                source.adapter_cap + ADP_DP_CS_2,
                1,
            )
            .await?[0];
        let granularity = Granularity::decode(in_cs2);
        let bw_mode = in_caps.bw_mode && granularity.is_some();
        let (group, budget, others_mbps) = self.dp_group_accounting(ctl, domain).await?;
        let available = budget.saturating_sub(others_mbps);
        // Fit the envelope under what the group has free, walking
        // the shared fallback ladder — never overcommit the link.
        // Even RBR x1 not fitting refuses the tunnel cleanly,
        // before any path is programmed.
        let Some((rate, lanes)) = dp_bw::fit_link(demand.0, demand.1, available) else {
            return Err(Error::Full);
        };
        let payload = rate.payload_mbps(lanes);
        // Program the negotiated envelope into both REMOTE_CAPs:
        // each adapter learns the link the tunnel will run, at
        // the full negotiated rate — HBR/HBR2/HBR3 as the adapters
        // and the fabric budget support, no longer floored at RBR.
        self.change(
            ctl,
            output,
            CfgSpace::Port,
            sink.adapter_cap + DP_REMOTE_CAP,
            &[dp_bw::remote_cap_word(in_local, rate, lanes, bw_mode)],
        )
        .await?;
        self.change(
            ctl,
            input,
            CfgSpace::Port,
            source.adapter_cap + DP_REMOTE_CAP,
            &[dp_bw::remote_cap_word(out_local, rate, lanes, bw_mode)],
        )
        .await?;
        let allocated_mbps = if bw_mode {
            let gr = granularity.unwrap();
            // Publish the group estimate (budget less the other
            // consumers; this tunnel's own headroom included), the
            // group and CM identity, then grant the tunnel its own
            // payload as the initial allocation. All journaled, so
            // teardown restores the pre-tunnel adapter state.
            let estimated = budget.saturating_sub(others_mbps);
            let cs2 = (in_cs2
                & !((0x7 << CS2_GROUP_ID_SHIFT)
                    | (0xf << CS2_CM_ID_SHIFT)
                    | (0xff << CS2_ESTIMATED_BW_SHIFT)
                    | CS2_CA))
                | CS2_CMMS
                | ((group as u32) << CS2_GROUP_ID_SHIFT)
                | ((domain.id & 0xf) << CS2_CM_ID_SHIFT)
                | (gr.units_floor(estimated) << CS2_ESTIMATED_BW_SHIFT);
            self.change(
                ctl,
                input,
                CfgSpace::Port,
                source.adapter_cap + ADP_DP_CS_2,
                &[cs2],
            )
            .await?;
            let status = ctl
                .read(
                    input.route,
                    input.port,
                    CfgSpace::Port,
                    source.adapter_cap + DP_STATUS,
                    1,
                )
                .await?[0];
            let granted = gr.units_floor(payload);
            self.change(
                ctl,
                input,
                CfgSpace::Port,
                source.adapter_cap + DP_STATUS,
                &[((status & !(0xff << STATUS_ALLOCATED_BW_SHIFT))
                    | (granted << STATUS_ALLOCATED_BW_SHIFT))],
            )
            .await?;
            gr.to_mbps(granted)
        } else {
            payload
        };
        self.display.dp = Some(DpTunnelInfo {
            rate,
            lanes,
            allocated_mbps,
            bw_mode,
            group,
            budget_mbps: budget,
        });
        self.display.consumed_mbps = allocated_mbps;
        let forward = chain(domain, input, output)?;
        self.path(ctl, forward.clone(), true).await?;
        self.path(ctl, forward.clone(), false).await?;
        let reverse = forward
            .into_iter()
            .rev()
            .map(|h| Hop {
                input: h.output,
                output: h.input,
                ..h
            })
            .collect();
        self.path(ctl, reverse, false).await?;
        self.modify(ctl, input, source.adapter_cap, 0, 3 << 30)
            .await?;
        self.modify(ctl, output, sink.adapter_cap, 0, 3 << 30)
            .await?;
        // Publish immediately: group accounting for tunnels
        // activated later in the same reconcile pass (and replay,
        // which bypasses reconcile) reads the live set.
        // reconcile's final rebuild replaces this entry with the
        // same snapshot; teardown removes it.
        DISPLAYS.lock().push(self.display.clone());
        Ok(())
    }

    /// Account this DP tunnel's first-link bandwidth group: read
    /// the link budget from the child router's upstream lane
    /// adapter (raw speed × bonded width, less the guard band;
    /// the Gen 2 floor when the negotiated speed cannot be read),
    /// then charge the published live tunnels sharing the link.
    /// Returns (group id, budget Mb/s, Mb/s consumed by *other*
    /// tunnels in the group). The published set is snapshotted
    /// after the config reads — no lock is held across an await.
    async fn dp_group_accounting(
        &self,
        ctl: &mut impl Config,
        domain: &Domain,
    ) -> Result<(u8, u32, u32), Error> {
        let input = self.display.input;
        let output = self.display.output;
        let key = dp_bw::first_link_key(input, output);
        let mut budget = dp_bw::link_budget_mbps(dp_bw::GEN2_MBPS_PER_LANE, 1);
        if let Ok(child) = router(domain, key.0) {
            let width = 1 + child
                .ports
                .iter()
                .filter(|p| p.kind == 1 && p.secondary)
                .count() as u8;
            if let Some(up) = child
                .ports
                .iter()
                .find(|p| p.kind == 1 && p.number == child.upstream && p.adapter_cap != 0)
            {
                let cs1 = ctl
                    .read(
                        key.0,
                        up.number,
                        CfgSpace::Port,
                        up.adapter_cap + dp_bw::LANE_CS_1,
                        1,
                    )
                    .await?[0];
                if let Some(speed) =
                    dp_bw::lane_speed_mbps((cs1 >> dp_bw::LANE_CURRENT_SPEED_SHIFT) & 0xf)
                {
                    budget = dp_bw::link_budget_mbps(speed, width);
                }
            }
        }
        let published = DISPLAYS.lock().clone();
        let mut keys: Vec<(u64, u8)> = Vec::new();
        let mut others_mbps = 0u32;
        for t in &published {
            if t.domain != domain.id {
                continue;
            }
            let tkey = dp_bw::first_link_key(t.input, t.output);
            if !keys.contains(&tkey) {
                keys.push(tkey);
            }
            if tkey == key && !(t.input == input && t.output == output) {
                others_mbps = others_mbps.saturating_add(t.consumed_mbps);
                if let Some(dp) = t.dp {
                    // A member that accounted against a smaller
                    // budget (the link renegotiated slower) keeps
                    // the group at the smaller figure.
                    budget = budget.min(dp.budget_mbps);
                }
            }
        }
        if !keys.contains(&key) {
            keys.push(key);
        }
        keys.sort_unstable();
        let index = keys.iter().position(|k| *k == key).unwrap_or(0);
        let group = 1 + (index as u8 % dp_bw::MAX_GROUP_ID);
        Ok((group, budget, others_mbps))
    }

    /// Service one pending bandwidth-allocation request on this
    /// tunnel's DP IN adapter (USB4 DP bandwidth-allocation mode).
    /// The adapter raises DR in `ADP_DP_CS_8` with the source's
    /// requested bandwidth; the CM grants at most what the group
    /// has free — the tunnel's own current grant counts towards
    /// what it may hold — writes `ALLOCATED_BW`, and runs the CM
    /// Acknowledge handshake until the adapter clears DR. A grant
    /// below the request is the renegotiation signal: the source
    /// re-trains within the granted envelope. The request is never
    /// silently dropped and the group is never overcommitted.
    /// Returns true when a request was serviced.
    pub(crate) async fn service_dp_bw_request(
        &mut self,
        ctl: &mut impl Config,
        domain: &Domain,
    ) -> Result<bool, Error> {
        let Some(dp) = self.display.dp else {
            return Ok(false);
        };
        if !dp.bw_mode {
            return Ok(false);
        }
        let input = self.display.input;
        let source = port(domain, input)?;
        let cs8 = ctl
            .read(
                input.route,
                input.port,
                CfgSpace::Port,
                source.adapter_cap + ADP_DP_CS_8,
                1,
            )
            .await?[0];
        if cs8 & CS8_DR == 0 {
            return Ok(false);
        }
        let cs2 = ctl
            .read(
                input.route,
                input.port,
                CfgSpace::Port,
                source.adapter_cap + ADP_DP_CS_2,
                1,
            )
            .await?[0];
        let Some(gr) = Granularity::decode(cs2) else {
            // The granularity stopped decoding after activation:
            // leave the request pending rather than guess the unit
            // every exchanged value is denominated in.
            return Ok(false);
        };
        let requested = gr.to_mbps(cs8 & CS8_REQUESTED_BW_MASK);
        let (_, budget, others_mbps) = self.dp_group_accounting(ctl, domain).await?;
        let grant = requested.min(budget.saturating_sub(others_mbps));
        let units = gr.units_floor(grant);
        let status = ctl
            .read(
                input.route,
                input.port,
                CfgSpace::Port,
                source.adapter_cap + DP_STATUS,
                1,
            )
            .await?[0];
        self.change(
            ctl,
            input,
            CfgSpace::Port,
            source.adapter_cap + DP_STATUS,
            &[((status & !(0xff << STATUS_ALLOCATED_BW_SHIFT))
                | (units << STATUS_ALLOCATED_BW_SHIFT))],
        )
        .await?;
        // CM Acknowledge handshake (Linux
        // usb4_dp_port_allocate_bandwidth): set CA, clear CA,
        // wait for the adapter to clear DR, leave CA clear.
        self.change(
            ctl,
            input,
            CfgSpace::Port,
            source.adapter_cap + ADP_DP_CS_2,
            &[cs2 | CS2_CA],
        )
        .await?;
        self.change(
            ctl,
            input,
            CfgSpace::Port,
            source.adapter_cap + ADP_DP_CS_2,
            &[cs2 & !CS2_CA],
        )
        .await?;
        let deadline = narf_time::Deadline::after_ms(500);
        loop {
            if ctl
                .read(
                    input.route,
                    input.port,
                    CfgSpace::Port,
                    source.adapter_cap + ADP_DP_CS_8,
                    1,
                )
                .await?[0]
                & CS8_DR
                == 0
            {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
        }
        let granted_mbps = gr.to_mbps(units);
        if let Some(dp) = self.display.dp.as_mut() {
            dp.allocated_mbps = granted_mbps;
        }
        self.display.consumed_mbps = granted_mbps;
        // Republish so group accounting later in this same pass
        // charges the new grant, not the stale one.
        let mut published = DISPLAYS.lock();
        if let Some(slot) = published.iter_mut().find(|t| {
            t.domain == self.display.domain && t.input == input && t.output == self.display.output
        }) {
            *slot = self.display.clone();
        }
        Ok(true)
    }

    /// Republish this tunnel's group estimate (`ESTIMATED_BW`)
    /// after group membership or grants changed: budget less the
    /// other group members' consumption, this tunnel's own grant
    /// included in what it may use. Writes only on change.
    pub(crate) async fn refresh_dp_estimate(
        &mut self,
        ctl: &mut impl Config,
        domain: &Domain,
    ) -> Result<(), Error> {
        let Some(dp) = self.display.dp else {
            return Ok(());
        };
        if !dp.bw_mode {
            return Ok(());
        }
        let input = self.display.input;
        let source = port(domain, input)?;
        let cs2 = ctl
            .read(
                input.route,
                input.port,
                CfgSpace::Port,
                source.adapter_cap + ADP_DP_CS_2,
                1,
            )
            .await?[0];
        let Some(gr) = Granularity::decode(cs2) else {
            return Ok(());
        };
        let (_, budget, others_mbps) = self.dp_group_accounting(ctl, domain).await?;
        let estimated = gr.units_floor(budget.saturating_sub(others_mbps));
        if estimated == (cs2 >> CS2_ESTIMATED_BW_SHIFT) & 0xff {
            return Ok(());
        }
        self.change(
            ctl,
            input,
            CfgSpace::Port,
            source.adapter_cap + ADP_DP_CS_2,
            &[((cs2 & !(0xff << CS2_ESTIMATED_BW_SHIFT)) | (estimated << CS2_ESTIMATED_BW_SHIFT))],
        )
        .await
    }

    async fn activate_usb3(&mut self, ctl: &mut impl Config, domain: &Domain) -> Result<(), Error> {
        let input = self.display.input;
        let output = self.display.output;
        let source = port(domain, input)?;
        let sink = port(domain, output)?;
        for (e, p) in [(input, source), (output, sink)] {
            if p.adapter_cap == 0
                || ctl
                    .read(e.route, e.port, CfgSpace::Port, p.adapter_cap, 1)
                    .await?[0]
                    & (1 << 31)
                    != 0
            {
                return Err(Error::Full);
            }
        }
        if input.route == 0 {
            let old = ctl
                .read(
                    input.route,
                    input.port,
                    CfgSpace::Port,
                    source.adapter_cap + 2,
                    1,
                )
                .await?[0];
            if old & (1 << 31) != 0 {
                return Err(Error::Full);
            }
            self.bandwidth = Some((source.adapter_cap, old & 0x00ff_ffff));
            let allocation = usb3_bandwidth(ctl, input, source.adapter_cap, None).await?;
            // Charge the handshake's allocation to the DP group
            // ledger: USB3 and DP tunnels sharing a first link
            // draw on the same budget (see dp_bw).
            let scale = ctl
                .read(
                    input.route,
                    input.port,
                    CfgSpace::Port,
                    source.adapter_cap + 3,
                    1,
                )
                .await?[0]
                & 63;
            self.display.consumed_mbps = usb3_units_to_mbps(allocation, scale);
        }
        let forward = chain(domain, input, output)?;
        self.path(ctl, forward.clone(), false).await?;
        let reverse = forward
            .into_iter()
            .rev()
            .map(|h| Hop {
                input: h.output,
                output: h.input,
                ..h
            })
            .collect();
        self.path(ctl, reverse, false).await?;
        self.change(ctl, input, CfgSpace::Port, source.adapter_cap, &[3 << 30])
            .await?;
        self.writes.last_mut().unwrap().words[0] |= 1 << 30;
        self.change(ctl, output, CfgSpace::Port, sink.adapter_cap, &[3 << 30])
            .await?;
        self.writes.last_mut().unwrap().words[0] |= 1 << 30;
        Ok(())
    }

    /// Program one PCIe tunnel: a downstream path from the PCIe
    /// downstream adapter on an ancestor router to the PCIe
    /// upstream adapter on the device router, and the matching
    /// upstream path back. Both paths go through the same journaled
    /// hop programming as USB3/DisplayPort; the PCIe adapters
    /// themselves are enabled last, once the fabric paths exist, by
    /// setting ADP_PCIE_CS_0 PE (bit 31 of the adapter capability
    /// DWORD 0, USB4 PCIe adapter configuration space). An adapter
    /// that is already enabled belongs to firmware or another
    /// tunnel and is never overwritten.
    async fn activate_pcie(&mut self, ctl: &mut impl Config, domain: &Domain) -> Result<(), Error> {
        let input = self.display.input;
        let output = self.display.output;
        let source = port(domain, input)?;
        let sink = port(domain, output)?;
        for (e, p) in [(input, source), (output, sink)] {
            if p.adapter_cap == 0
                || ctl
                    .read(e.route, e.port, CfgSpace::Port, p.adapter_cap, 1)
                    .await?[0]
                    & (1 << 31)
                    != 0
            {
                return Err(Error::Full);
            }
        }
        let forward = chain(domain, input, output)?;
        self.path(ctl, forward.clone(), false).await?;
        let reverse = forward
            .into_iter()
            .rev()
            .map(|h| Hop {
                input: h.output,
                output: h.input,
                ..h
            })
            .collect();
        self.path(ctl, reverse, false).await?;
        // Enable both PCIe adapters only with the paths live; the
        // writes are journaled, so teardown restores the exact
        // pre-enable adapter DWORD (PE clear) in reverse order.
        self.change(ctl, input, CfgSpace::Port, source.adapter_cap, &[1 << 31])
            .await?;
        self.change(ctl, output, CfgSpace::Port, sink.adapter_cap, &[1 << 31])
            .await?;
        Ok(())
    }
}
/// Convert a packed USB3 allocation (up [11:0] | down [23:12],
/// in units of 512 * 2^scale b/s — the unit definition
/// `bandwidth_units` already uses) into Mb/s for the DP group
/// ledger. Saturating: accounting must never under-count a
/// consumer.
fn usb3_units_to_mbps(packed: u32, scale: u32) -> u32 {
    let units = (packed & 4095) + ((packed >> 12) & 4095);
    let unit_bps = 512u64.checked_shl(scale).unwrap_or(u64::MAX);
    let mbps = (units as u64).saturating_mul(unit_bps) / 1_000_000;
    mbps.min(u32::MAX as u64) as u32
}
fn bandwidth_units(scale: u32, consumed: u32) -> Result<u32, Error> {
    let unit = 512u64
        .checked_mul(1u64.checked_shl(scale).ok_or(Error::Invalid)?)
        .ok_or(Error::Invalid)?;
    let minimum = 112_500_000u64.div_ceil(unit) as u32;
    let up = minimum.max(consumed & 4095);
    let down = minimum.max((consumed >> 12) & 4095);
    if up > 4095 || down > 4095 {
        return Err(Error::Invalid);
    }
    Ok(up | (down << 12))
}
async fn usb3_bandwidth(
    ctl: &mut impl Config,
    e: Endpoint,
    cap: u16,
    restore: Option<u32>,
) -> Result<u32, Error> {
    let old = ctl
        .read(e.route, e.port, CfgSpace::Port, cap + 2, 1)
        .await?[0];
    ctl.write(e.route, e.port, CfgSpace::Port, cap + 2, &[old | (1 << 31)])
        .await?;
    let result = async {
        let deadline = narf_time::Deadline::after_ms(1500);
        let consumed = loop {
            let value = ctl
                .read(e.route, e.port, CfgSpace::Port, cap + 1, 1)
                .await?[0];
            if value & (1 << 31) != 0 {
                break value;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
        };
        let allocation = match restore {
            Some(value) => value,
            None => {
                let scale = ctl
                    .read(e.route, e.port, CfgSpace::Port, cap + 3, 1)
                    .await?[0]
                    & 63;
                bandwidth_units(scale, consumed)?
            }
        };
        ctl.write(
            e.route,
            e.port,
            CfgSpace::Port,
            cap + 2,
            &[(old & !0x00ff_ffff) | (1 << 31) | allocation],
        )
        .await?;
        Ok(allocation)
    }
    .await;
    // Always release CMR, including invalid scale/timeout/error paths.
    let value = ctl
        .read(e.route, e.port, CfgSpace::Port, cap + 2, 1)
        .await?[0];
    ctl.write(
        e.route,
        e.port,
        CfgSpace::Port,
        cap + 2,
        &[value & !(1 << 31)],
    )
    .await?;
    let deadline = narf_time::Deadline::after_ms(1500);
    while ctl
        .read(e.route, e.port, CfgSpace::Port, cap + 1, 1)
        .await?[0]
        & (1 << 31)
        != 0
    {
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(10).as_instant()).await;
    }
    result
}

pub(crate) async fn reconcile(
    ctl: &mut impl Config,
    domain: &Domain,
    tunnels: &mut Vec<Tunnel>,
    controls: u32,
) -> Result<(), Error> {
    GRANTED_CONTROLS.store(controls, core::sync::atomic::Ordering::Relaxed);
    let mut index = 0;
    while index < tunnels.len() {
        let t = &mut tunnels[index];
        let present =
            if t.display.protocol == Protocol::Usb3 || t.display.protocol == Protocol::Pcie {
                port(domain, t.display.output).is_ok() && port(domain, t.display.input).is_ok()
            } else if let Ok(p) = port(domain, t.display.output) {
                ctl.read(
                    t.display.output.route,
                    p.number,
                    CfgSpace::Port,
                    p.adapter_cap + 2,
                    1,
                )
                .await?[0]
                    & (1 << 6)
                    != 0
            } else {
                false
            };
        if !present {
            tunnels[index].teardown(ctl, domain).await?;
            tunnels.remove(index);
        } else {
            if t.display.protocol == Protocol::DisplayPort {
                let source = port(domain, t.display.input)?;
                t.display.dprx_done = ctl
                    .read(0, source.number, CfgSpace::Port, source.adapter_cap + 7, 1)
                    .await?[0]
                    & (1 << 31)
                    != 0;
            }
            index += 1;
        }
    }
    // Bandwidth-allocation servicing for live DP tunnels: answer
    // pending allocation requests first (a source is waiting on
    // its grant), then republish group estimates, so a reconcile
    // pass leaves every adapter with a current view. Runs for
    // every live DP tunnel regardless of the creation controls
    // this pass carries.
    for t in tunnels.iter_mut() {
        t.service_dp_bw_request(ctl, domain).await?;
    }
    for t in tunnels.iter_mut() {
        t.refresh_dp_estimate(ctl, domain).await?;
    }
    if controls & 1 != 0 {
        for child in domain.routers.iter().filter(|r| r.route != 0) {
            let depth = route_depth(child.route);
            let parent_route = if depth == 1 {
                0
            } else {
                child.route & ((1u64 << ((depth - 1) * 8)) - 1)
            };
            let parent = router(domain, parent_route)?;
            let lane = (child.route >> ((depth - 1) * 8)) as u8;
            let Some(lane_index) = parent
                .ports
                .iter()
                .filter(|p| p.kind == 1 && !p.secondary)
                .position(|p| p.number == lane)
            else {
                continue;
            };
            let Some(source) = parent
                .ports
                .iter()
                .filter(|p| p.kind == 0x200101)
                .nth(lane_index)
            else {
                continue;
            };
            let Some(sink) = child.ports.iter().find(|p| p.kind == 0x200102) else {
                continue;
            };
            let input = Endpoint {
                route: parent_route,
                port: source.number,
            };
            let output = Endpoint {
                route: child.route,
                port: sink.number,
            };
            if tunnels
                .iter()
                .any(|t| t.display.protocol == Protocol::Usb3 && t.display.output == output)
            {
                continue;
            }
            let mut t = Tunnel {
                display: TunnelInfo {
                    domain: domain.id,
                    input,
                    output,
                    protocol: Protocol::Usb3,
                    dprx_done: false,
                    dp: None,
                    consumed_mbps: 0,
                },
                writes: Vec::new(),
                resource: false,
                hpd_owned: false,
                bandwidth: None,
            };
            match t.activate(ctl, domain).await {
                Ok(()) => tunnels.push(t),
                Err(e) => {
                    if let Err(cleanup) = t.teardown(ctl, domain).await {
                        tunnels.push(t);
                        return Err(cleanup);
                    }
                    if !matches!(e, Error::Full | Error::Remote(_)) {
                        return Err(e);
                    }
                }
            }
        }
    }
    if controls & 2 != 0 {
        let host = router(domain, 0)?;
        // Multiple DP tunnels per domain: each hot-plugged sink
        // with no live tunnel gets its own tunnel on a free DP IN
        // adapter, and the bandwidth-group ledger (see dp_bw)
        // decides whether the fabric can carry it — the guard
        // that used to cap the domain at one DP tunnel is gone
        // because allocation is real now.
        for r in domain.routers.iter().filter(|r| r.route != 0) {
            'sinks: for sink in r
                .ports
                .iter()
                .filter(|p| p.kind == 0x0e0102 && p.adapter_cap != 0)
            {
                let output = Endpoint {
                    route: r.route,
                    port: sink.number,
                };
                if tunnels.iter().any(|t| {
                    t.display.protocol == Protocol::DisplayPort && t.display.output == output
                }) {
                    continue;
                }
                if ctl
                    .read(
                        r.route,
                        sink.number,
                        CfgSpace::Port,
                        sink.adapter_cap + ADP_DP_CS_2,
                        1,
                    )
                    .await?[0]
                    & dp_bw::CS2_HPD
                    == 0
                {
                    continue;
                }
                for source in host.ports.iter().filter(|p| p.kind == 0x0e0101) {
                    let input = Endpoint {
                        route: 0,
                        port: source.number,
                    };
                    if tunnels.iter().any(|t| {
                        t.display.protocol == Protocol::DisplayPort && t.display.input == input
                    }) {
                        continue;
                    }
                    let mut tunnel = Tunnel {
                        display: TunnelInfo {
                            domain: domain.id,
                            input,
                            output,
                            protocol: Protocol::DisplayPort,
                            dprx_done: false,
                            dp: None,
                            consumed_mbps: 0,
                        },
                        writes: Vec::new(),
                        resource: false,
                        hpd_owned: false,
                        bandwidth: None,
                    };
                    match tunnel.activate(ctl, domain).await {
                        Ok(()) => {
                            tunnels.push(tunnel);
                            continue 'sinks;
                        }
                        Err(e) => {
                            if let Err(cleanup) = tunnel.teardown(ctl, domain).await {
                                tunnels.push(tunnel);
                                return Err(cleanup);
                            }
                            if !matches!(e, Error::Full | Error::Remote(_)) {
                                return Err(e);
                            }
                        }
                    }
                }
            }
        }
    }
    if controls & super::firmware::CONTROL_PCIE != 0 {
        for child in domain.routers.iter().filter(|r| r.route != 0) {
            let Some(sink) = child.ports.iter().find(|p| p.kind == 0x100102) else {
                continue;
            };
            let output = Endpoint {
                route: child.route,
                port: sink.number,
            };
            if tunnels
                .iter()
                .any(|t| t.display.protocol == Protocol::Pcie && t.display.output == output)
            {
                continue;
            }
            // The tunnel originates at the nearest ancestor router
            // carrying a PCIe downstream adapter: a farther
            // ancestor's adapter belongs to a different PCIe switch
            // segment and cannot serve this router. An adapter a
            // live PCIe tunnel already claims serves that tunnel
            // only, so this router goes without rather than
            // double-programming the adapter.
            let depth = route_depth(child.route);
            let mut input = None;
            for level in (0..depth).rev() {
                let ancestor_route = if level == 0 {
                    0
                } else {
                    child.route & ((1u64 << (level * 8)) - 1)
                };
                let Ok(ancestor) = router(domain, ancestor_route) else {
                    continue;
                };
                let Some(source) = ancestor.ports.iter().find(|p| p.kind == 0x100101) else {
                    continue;
                };
                let candidate = Endpoint {
                    route: ancestor_route,
                    port: source.number,
                };
                if !tunnels
                    .iter()
                    .any(|t| t.display.protocol == Protocol::Pcie && t.display.input == candidate)
                {
                    input = Some(candidate);
                }
                break;
            }
            let Some(input) = input else {
                continue;
            };
            let mut t = Tunnel {
                display: TunnelInfo {
                    domain: domain.id,
                    input,
                    output,
                    protocol: Protocol::Pcie,
                    dprx_done: false,
                    dp: None,
                    consumed_mbps: 0,
                },
                writes: Vec::new(),
                resource: false,
                hpd_owned: false,
                bandwidth: None,
            };
            match t.activate(ctl, domain).await {
                Ok(()) => tunnels.push(t),
                Err(e) => {
                    if let Err(cleanup) = t.teardown(ctl, domain).await {
                        tunnels.push(t);
                        return Err(cleanup);
                    }
                    if !matches!(e, Error::Full | Error::Remote(_)) {
                        return Err(e);
                    }
                }
            }
        }
    }
    let mut displays = DISPLAYS.lock();
    displays.retain(|d| d.domain != domain.id);
    displays.extend(tunnels.iter().map(|t| t.display.clone()));
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "tunnel_tests.rs"]
pub(crate) mod tests;
