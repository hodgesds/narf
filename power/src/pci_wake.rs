//! Firmware-owned PCI PME -> fixed ACPI GPE -> SCI wake ownership.
//!
//! This module never claims native Root Port PME service or manufactures a
//! wake GPE. Only exact AML PCI topology and the endpoint PM capability can
//! establish a route. Platform composition delegates the Power grant;
//! drivers supply their existing endpoint Write capability.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_acpi::gpe_wake::{WakeGpe, WakeGpeError};
use narf_aml::Value;
use narf_bus::device::{BusDevice, BusKind};
use narf_bus::pci::pme::{self, PmeError, WakeState};
use narf_bus::registry::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Grant, Read, Write};
use narf_lib::sync::IrqSafeSpinLock;

use crate::Power;

pub(super) static AUTHORITY: IrqSafeSpinLock<Option<Cap<Power, Grant>>> =
    IrqSafeSpinLock::new(None);
static QUARANTINED: IrqSafeSpinLock<Vec<Owned>> = IrqSafeSpinLock::new(Vec::new());
static GPE_HITS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WakeError {
    Authority,
    Unsupported,
    Ambiguous,
    Firmware,
    Busy,
    Pme(PmeError),
    Gpe(WakeGpeError),
}

impl From<CapError> for WakeError {
    fn from(_: CapError) -> Self {
        Self::Authority
    }
}

impl From<PmeError> for WakeError {
    fn from(error: PmeError) -> Self {
        Self::Pme(error)
    }
}

impl From<WakeGpeError> for WakeError {
    fn from(error: WakeGpeError) -> Self {
        Self::Gpe(error)
    }
}

/// ACPI system sleep state passed verbatim to _DSW. S0 denotes the
/// firmware-owned device wake route used while the CPU stays in s2idle.
pub use crate::system_pm::SystemSleepState as SleepState;

#[path = "pci_wake_state.rs"]
mod device_state;

impl SleepState {
    fn number(self) -> u8 {
        match self {
            Self::S0Idle => 0,
            Self::S3 => 3,
        }
    }
}

#[derive(Clone, Debug)]
struct Route {
    path: String,
    endpoint_path: Option<String>,
    gpe: u32,
    deepest_sleep: u8,
}

#[derive(Debug)]
struct Owned {
    platform: Cap<Power, Grant>,
    endpoint: Cap<BusDeviceCap, Write>,
    device: BusDevice,
    route: Route,
    gpe: Option<WakeGpe>,
    firmware: bool,
    endpoint_armed: bool,
    ready: bool,
    evidence: WakeEvidence,
}

/// Retained wake route. A dropped live owner attempts synchronous terminal
/// cleanup. If authority or a receipt is unavailable, its actual endpoint,
/// GPE token and granted caps move to quarantine rather than releasing the
/// route or fabricating successful cleanup.
#[derive(Debug)]
pub struct PciWake {
    owned: Option<Owned>,
}

/// Hardware observations only. A shared GPE does not identify which device
/// caused it; PME_Status likewise does not identify a magic/pattern packet.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct WakeEvidence {
    pub gpe_observed: bool,
    pub endpoint_pme_pending: bool,
}

pub(super) struct PowerOp<F>(pub(super) F);
pub(super) struct EndpointOp<F>(pub(super) F);

impl<F, R> CapOp<BusDeviceCap, Write> for EndpointOp<F>
where
    F: FnOnce() -> R,
{
    type Output = R;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<R, CapError> {
        Ok((self.0)())
    }
}

impl<F, R> CapOp<Power, Grant> for PowerOp<F>
where
    F: FnOnce() -> R,
{
    type Output = R;
    fn execute(self, _: &Cap<Power, Grant>) -> Result<R, CapError> {
        Ok((self.0)())
    }
}

/// Install actual platform composition's existing grant. No new grant is
/// minted here or by a wireless driver. Revocation fences subsequent probe,
/// arm and cleanup operations, including every hardware access.
pub fn install_authority(cap: &Cap<Power, Grant>) -> Result<(), WakeError> {
    cap.invoke(PowerOp(|| {
        *AUTHORITY.lock() = Some(*cap);
    }))?;
    Ok(())
}

pub(super) fn delegated_authority() -> Result<Cap<Power, Grant>, WakeError> {
    (*AUTHORITY.lock()).ok_or(WakeError::Authority)
}

pub(super) trait Namespace {
    fn devices(&self) -> Vec<String>;
    fn exists(&self, path: &str) -> bool;
    fn object(&self, path: &str) -> Result<Option<Value>, WakeError>;
}

pub(super) struct Aml;

impl Namespace for Aml {
    fn devices(&self) -> Vec<String> {
        narf_aml::list_all_device_paths()
    }

    fn exists(&self, path: &str) -> bool {
        narf_aml::find_node(path).is_some()
    }

    fn object(&self, path: &str) -> Result<Option<Value>, WakeError> {
        // Exact lookup first: malformed existing objects must not become
        // an absent optional method, nor use the suffix-match fallback.
        if narf_aml::find_node(path).is_none() {
            return Ok(None);
        }
        narf_aml::eval::strict::evaluate_object(path, &[])
            .map(Some)
            .map_err(|_| WakeError::Firmware)
    }
}

fn object(ns: &impl Namespace, path: &str, name: &str) -> Result<Option<Value>, WakeError> {
    ns.object(&format!("{path}.{name}"))
}

fn integer(
    ns: &impl Namespace,
    path: &str,
    name: &str,
    default: Option<u64>,
) -> Result<u64, WakeError> {
    match object(ns, path, name)? {
        Some(Value::Integer(value)) => Ok(value),
        None => default.ok_or(WakeError::Unsupported),
        _ => Err(WakeError::Firmware),
    }
}

fn pci_root_id(value: &Value) -> bool {
    match value {
        Value::String(hid) => matches!(hid.as_str(), "PNP0A03" | "PNP0A08"),
        Value::Integer(hid) if *hid <= u64::from(u32::MAX) => {
            matches!(
                narf_aml::eisa_id_from_u32(*hid as u32).as_str(),
                "PNP0A03" | "PNP0A08"
            )
        }
        Value::Package(ids) => ids.iter().any(pci_root_id),
        _ => false,
    }
}

fn present(ns: &impl Namespace, path: &str) -> Result<bool, WakeError> {
    // _STA absent means present, enabled, visible, functional (ACPI 6.5).
    Ok(integer(ns, path, "_STA", Some(0x0f))? & 1 != 0)
}

/// Match actual registered PCI topology against exact namespace children.
/// Hops are root-port/root-bus devfn first and endpoint last. If firmware
/// omits an endpoint node, only an exactly matched ancestor's _PRW may be
/// used. A same-named node in another scope never supplies a route.
pub(super) struct Matched {
    pub(super) chain: Vec<String>,
    pub(super) exact_endpoint: Option<String>,
}

pub(super) fn match_namespace(
    ns: &impl Namespace,
    segment: u16,
    root_bus: u8,
    hops: &[u8],
) -> Result<Matched, WakeError> {
    if hops.is_empty() || hops.len() > 256 {
        return Err(WakeError::Unsupported);
    }
    let paths = ns.devices();
    let mut roots = Vec::new();
    for path in &paths {
        let hid = object(ns, path, "_HID")?;
        if !hid.as_ref().is_some_and(pci_root_id)
            && !object(ns, path, "_CID")?.as_ref().is_some_and(pci_root_id)
        {
            continue;
        }
        if integer(ns, path, "_SEG", Some(0))? == u64::from(segment)
            && integer(ns, path, "_BBN", Some(0))? == u64::from(root_bus)
            && present(ns, path)?
        {
            roots.push(path.clone());
        }
    }
    let mut matched = match roots.as_slice() {
        [root] => alloc::vec![root.clone()],
        [] => {
            return Ok(Matched {
                chain: Vec::new(),
                exact_endpoint: None,
            });
        }
        _ => return Err(WakeError::Ambiguous),
    };
    for &devfn in hops {
        let parent = matched.last().ok_or(WakeError::Unsupported)?;
        let expected = u64::from(devfn >> 3) << 16 | u64::from(devfn & 7);
        let mut children = Vec::new();
        for path in &paths {
            if path
                .rsplit_once('.')
                .is_none_or(|(scope, _)| scope != parent)
            {
                continue;
            }
            match object(ns, path, "_ADR")? {
                Some(Value::Integer(adr)) if adr == expected && present(ns, path)? => {
                    children.push(path.clone());
                }
                Some(Value::Integer(_)) | None => {}
                _ => return Err(WakeError::Firmware),
            }
        }
        match children.as_slice() {
            [child] => matched.push(child.clone()),
            [] => break,
            _ => return Err(WakeError::Ambiguous),
        }
    }
    let exact_endpoint = (matched.len() == hops.len() + 1)
        .then(|| matched.last().cloned())
        .flatten();
    Ok(Matched {
        chain: matched,
        exact_endpoint,
    })
}

fn discover_route(
    ns: &impl Namespace,
    segment: u16,
    root_bus: u8,
    hops: &[u8],
) -> Result<Route, WakeError> {
    let matched = match_namespace(ns, segment, root_bus, hops)?;
    // Linux acpi_pci_propagate_wakeup also permits the actual host bridge's
    // _PRW after walking upstream bridges. Its exact _SEG/_BBN binds that
    // fallback to this endpoint's real PCI root, without a guessed devfn.
    for path in matched.chain.into_iter().rev() {
        let Some(prw) = object(ns, &path, "_PRW")? else {
            continue;
        };
        // Value has no ACPI ObjectReference. External-GPE-device and power
        // resource forms are therefore explicitly unsupported, never
        // reinterpreted as an integer GPE or a source of ambient authority.
        let Value::Package(items) = prw else {
            return Err(WakeError::Firmware);
        };
        let [Value::Integer(gpe), Value::Integer(deepest)] = items.as_slice() else {
            return Err(WakeError::Unsupported);
        };
        if *gpe >= 128 || *deepest > 5 {
            return Err(WakeError::Unsupported);
        }
        return Ok(Route {
            path,
            endpoint_path: matched.exact_endpoint,
            gpe: *gpe as u32,
            deepest_sleep: *deepest as u8,
        });
    }
    Err(WakeError::Unsupported)
}

pub(super) struct Topology<'a>(pub(super) &'a BusDevice);

impl CapOp<BusDeviceCap, Write> for Topology<'_> {
    type Output = Result<(u16, u8, Vec<u8>), WakeError>;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
        let topology = || {
            let BusKind::Pcie { addr, .. } = self.0.kind else {
                return Err(WakeError::Unsupported);
            };
            let mut current = *self.0;
            let mut hops = Vec::new();
            let devices = narf_bus::registry::devices();
            let mut visited = Vec::new();
            loop {
                let BusKind::Pcie {
                    addr: current_addr, ..
                } = current.kind
                else {
                    return Err(WakeError::Unsupported);
                };
                if current_addr.segment != addr.segment
                    || hops.len() == 256
                    || visited.contains(&current_addr)
                {
                    return Err(WakeError::Ambiguous);
                }
                visited.push(current_addr);
                hops.push(current_addr.device << 3 | current_addr.function);
                let mut parents = devices.iter().filter(|candidate| {
                    let BusKind::Pcie { addr: parent, .. } = candidate.kind else {
                        return false;
                    };
                    parent.segment == addr.segment
                        && parent != current_addr
                        && narf_bus::pci::bridge_bus_range(candidate)
                            .is_some_and(|(secondary, _)| secondary == current_addr.bus)
                });
                match (parents.next(), parents.next()) {
                    (Some(parent), None) => current = *parent,
                    (None, None) => {
                        hops.reverse();
                        return Ok((addr.segment, current_addr.bus, hops));
                    }
                    _ => return Err(WakeError::Ambiguous),
                }
            }
        };
        Ok(topology())
    }
}

fn set_firmware_wake(route: &Route, enable: bool, sleep: u8, device: u8) -> Result<(), WakeError> {
    let dsw = format!("{}._DSW", route.path);
    let psw = format!("{}._PSW", route.path);
    // Linux acpi_device_sleep_wake: _DSW first, fall back to _PSW only
    // for absence; absence of both is valid. Existing malformed/failed
    // methods never become an optional absence.
    if narf_aml::find_node(&dsw).is_some() {
        narf_aml::eval::strict::evaluate_method(
            &dsw,
            &[
                Value::Integer(u64::from(enable)),
                Value::Integer(u64::from(sleep)),
                Value::Integer(u64::from(device)),
            ],
        )
        .map_err(|_| WakeError::Firmware)?;
        return Ok(());
    }
    if narf_aml::find_node(&psw).is_some() {
        narf_aml::eval::strict::evaluate_method(&psw, &[Value::Integer(u64::from(enable))])
            .map_err(|_| WakeError::Firmware)?;
    }
    Ok(())
}

impl PciWake {
    /// Resolve firmware objects inside the delegated Power operation,
    /// deferring explicit PME/GPE arming. Metadata methods may have effects.
    pub fn discover(
        endpoint: &Cap<BusDeviceCap, Write>,
        device: BusDevice,
    ) -> Result<Self, WakeError> {
        let platform = delegated_authority()?;
        let (segment, root_bus, hops) = endpoint.invoke(Topology(&device))??;
        let read: Cap<BusDeviceCap, Read> = endpoint.derive()?;
        pme::status(&read, &device)?;
        // Topology/config observation does not grant later AML execution.
        // Recheck the endpoint at matching entry as well as platform Power.
        let route = endpoint.invoke(EndpointOp(|| {
            platform.invoke(PowerOp(|| discover_route(&Aml, segment, root_bus, &hops)))?
        }))??;
        if narf_acpi::sci_vector().is_none() || !narf_acpi::gpe_wake::supported(route.gpe) {
            return Err(WakeError::Unsupported);
        }
        Ok(Self {
            owned: Some(Owned {
                platform,
                endpoint: *endpoint,
                device,
                route,
                gpe: None,
                firmware: false,
                endpoint_armed: false,
                ready: false,
                evidence: WakeEvidence::default(),
            }),
        })
    }

    /// Validate this endpoint's actual power policy before choosing a
    /// D-state. Ancestor _PRW routing never supplies child _SxD/_SxW.
    pub fn admits(&self, sleep: SleepState, state: WakeState) -> Result<(), WakeError> {
        let owned = self.owned.as_ref().ok_or(WakeError::Busy)?;
        if sleep.number() > owned.route.deepest_sleep || state == WakeState::D3Cold {
            return Err(WakeError::Unsupported);
        }
        owned.platform.invoke(PowerOp(|| {
            let read: Cap<BusDeviceCap, Read> = owned.endpoint.derive()?;
            if !pme::status(&read, &owned.device)?.supports(state) {
                return Err(WakeError::Pme(PmeError::Unsupported));
            }
            owned.endpoint.invoke(EndpointOp(|| {
                device_state::admit(&Aml, owned.route.endpoint_path.as_deref(), sleep, state)
            }))?
        }))?
    }

    pub fn arm(&mut self, sleep: SleepState, state: WakeState) -> Result<(), WakeError> {
        self.admits(sleep, state)?;
        let owned = self.owned.as_mut().ok_or(WakeError::Busy)?;
        if owned.gpe.is_some() || owned.firmware || owned.endpoint_armed {
            return Err(WakeError::Busy);
        }
        if sleep.number() > owned.route.deepest_sleep || state == WakeState::D3Cold {
            // No power-resource/auxiliary-rail owner exists for D3cold.
            return Err(WakeError::Unsupported);
        }
        let platform = owned.platform;
        let result = platform.invoke(PowerOp(|| {
            let read: Cap<BusDeviceCap, Read> = owned.endpoint.derive()?;
            let status = pme::status(&read, &owned.device)?;
            if !status.supports(state) {
                return Err(WakeError::Pme(PmeError::Unsupported));
            }
            if status.enabled {
                return Err(WakeError::Pme(PmeError::AlreadyEnabled));
            }
            let number = owned.route.gpe;
            // SAFETY: current platform Power invocation, exact _PRW,
            // retained lease. Endpoint authority grants no platform writes.
            let gpe = unsafe {
                narf_acpi::gpe_wake::claim_with_prepare(number, || {
                    GPE_HITS[number as usize / 64]
                        .fetch_and(!(1 << (number % 64)), Ordering::AcqRel);
                })?
            };
            owned.evidence = WakeEvidence::default();
            let enabled = gpe.enabled();
            owned.gpe = Some(gpe);
            if !enabled {
                return Err(WakeError::Gpe(WakeGpeError::Readback));
            }
            owned.firmware = true; // retain even a partially failed AML call
            set_firmware_wake(&owned.route, true, sleep.number(), state as u8)?;
            match pme::arm(&owned.endpoint, &owned.device, state) {
                Ok(()) => owned.endpoint_armed = true,
                Err(error) => {
                    // Only Readback follows an actual PMCSR write. All
                    // other arm errors leave the endpoint untouched.
                    owned.endpoint_armed = error == PmeError::Readback;
                    return Err(error.into());
                }
            }
            owned.ready = true;
            Ok(())
        }))?;
        if result.is_err() {
            // Retain every still-live part if undo lacks authority/receipt.
            let _ = cleanup(owned);
        }
        result
    }

    /// Terminal teardown before a new normal device generation. A failure
    /// retains ownership and must abort/recover the driver's normal resume.
    pub fn disarm(&mut self) -> Result<WakeEvidence, WakeError> {
        cleanup(self.owned.as_mut().ok_or(WakeError::Busy)?)
    }

    pub fn armed(&self) -> bool {
        self.owned.as_ref().is_some_and(|owned| owned.ready)
    }

    /// Retain actual ownership without hardware I/O when a device's power
    /// transition cannot be settled by a synchronous Drop. This consumes
    /// the owner and grants no authority or successful cleanup receipt.
    pub fn quarantine(mut self) {
        if let Some(owned) = self.owned.take() {
            QUARANTINED.lock().push(owned);
        }
    }
}

fn cleanup(owned: &mut Owned) -> Result<WakeEvidence, WakeError> {
    cleanup_with_handoff(owned, || {})
}

// The handoff seam permits a native regression to interleave a successor
// after the old hardware receipt but before old host bookkeeping completes.
fn cleanup_with_handoff(
    owned: &mut Owned,
    handoff: impl FnOnce(),
) -> Result<WakeEvidence, WakeError> {
    let platform = owned.platform;
    platform.invoke(PowerOp(|| {
        owned.ready = false;
        if owned.endpoint_armed {
            let observation = pme::disarm_observed(&owned.endpoint, &owned.device)?;
            owned.evidence.endpoint_pme_pending |= observation.pending;
            observation.terminal?;
            owned.endpoint_armed = false;
        }
        if owned.firmware {
            set_firmware_wake(&owned.route, false, 0, 0)?;
            owned.firmware = false;
        }
        if let Some(gpe) = owned.gpe.as_mut() {
            let number = gpe.number();
            // SAFETY: exact retained lease within current platform Power
            // invocation. Failure leaves the token live in owned.gpe.
            unsafe {
                narf_acpi::gpe_wake::release_with_complete(gpe, || {
                    owned.evidence.gpe_observed |= GPE_HITS[number as usize / 64]
                        .fetch_and(!(1 << (number % 64)), Ordering::AcqRel)
                        & (1 << (number % 64))
                        != 0;
                })?
            };
            handoff();
            owned.gpe = None;
        }
        Ok(owned.evidence)
    }))?
}

impl Drop for PciWake {
    fn drop(&mut self) {
        let Some(mut owned) = self.owned.take() else {
            return;
        };
        if (owned.gpe.is_some() || owned.firmware || owned.endpoint_armed)
            && cleanup(&mut owned).is_err()
        {
            QUARANTINED.lock().push(owned);
        }
    }
}

/// SCI hard-IRQ observer, before status is deferred to task-context AML.
/// Atomics only; it does not replace or execute the ordinary GPE handler.
pub fn note_gpe_irq(number: u32) {
    if narf_acpi::gpe_wake::armed(number) {
        GPE_HITS[number as usize / 64].fetch_or(1 << (number % 64), Ordering::Release);
        crate::s2idle::note_wake_event(crate::s2idle::WakeSource::Other);
    }
}

/// A physical event on a still-owned wake route survives the park entry's
/// generic-latch clear. SCI already acknowledged its W1C status, so another
/// hardware interrupt cannot be assumed to reassert that event.
pub fn wake_event_pending() -> bool {
    narf_acpi::gpe_wake::any_armed([
        GPE_HITS[0].load(Ordering::Acquire),
        GPE_HITS[1].load(Ordering::Acquire),
    ])
}

/// Number of owners whose terminal cleanup lacks authority or a receipt.
pub fn quarantined_count() -> usize {
    QUARANTINED.lock().len()
}

#[cfg(feature = "wake-test")]
#[path = "pci_wake_tests.rs"]
mod tests;

#[cfg(all(feature = "wake-test", target_arch = "x86_64"))]
#[path = "pci_wake_native_tests.rs"]
mod native_tests;
