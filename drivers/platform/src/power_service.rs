//! Power-service composition — wires this crate's real event sources
//! and state providers into `narf_power::service`, and installs the
//! action executor that owns the suspend authority.
//!
//! Before this glue, the platform lid driver and button driver
//! exposed subscriber APIs whose only subscribers were tests, the
//! suspend core had no production caller, and
//! `LaptopStateSnapshot` was never produced. The wiring:
//!
//! - lid transitions (`crate::lid`) → `service::on_lid_changed`
//! - button presses (`crate::buttons`) → `service::on_*_button_press`
//! - snapshot providers → live AML evaluation: battery `_BIF`/`_BST`
//!   (PNP0C0A), AC `_PSR` (ACPI0003), the lid driver's cached state
//! - action executor → `PowerAction::Suspend` runs the suspend core
//!   with a freshly minted `Cap<Power, Invoke>` (this composition
//!   site is the authority owner; the service itself holds no cap),
//!   `PowerAction::Freeze` runs `s2idle::suspend_to_idle` under the
//!   same authority, and `PowerAction::PowerOff` defers to the
//!   orderly power-off worker.
//! - the `sleep_request` hook → userspace `/sys/power/state` stores
//!   land in the service's action queue (`freeze` → `Freeze`,
//!   `mem` → `Suspend`). Until this install runs, stores are refused
//!   with ENODEV by design (see `narf_power::sleep_request`).
//!
//! Providers re-walk the namespace and re-evaluate methods on every
//! snapshot, exactly like the platform drivers' own reads; snapshots
//! are UI/diagnostic-rate, not hot-path.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_acpi::ac_adapter::{decode_psr, AcAdapterState};
use narf_acpi::battery::{decode_bif, decode_bst, BatteryInfo, BatteryState};
use narf_aml::eval::evaluate_method;
use narf_aml::{find_all_devices_by_hid, Value};
use narf_capabilities::{Cap, Invoke};
use narf_power::service::{self, PowerAction, StateProviders};
use narf_power::sleep_request::{SleepRequestError, SleepState};

use crate::lid::LidEvent;

/// The composition root's executor: owns the suspend authority and
/// runs actions from the power service's worker (task context).
#[derive(Debug)]
struct PlatformExecutor;

impl service::ActionExecutor for PlatformExecutor {
    fn execute(&self, action: PowerAction) {
        match action {
            PowerAction::Suspend => {
                // The production-S3 gate inside the suspend core
                // decides whether this request actually sleeps the
                // machine; on unvalidated hardware it refuses and
                // the refusal is the log line.
                let cap: Cap<narf_power::Power, Invoke> = Cap::bootstrap();
                match narf_power::suspend::s3_enter(&cap) {
                    Ok(()) => {
                        let _ = writeln!(narf_console::Writer, "  power-service: resumed");
                    }
                    Err(e) => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "  power-service: suspend request not carried out: {e:?}"
                        );
                    }
                }
            }
            PowerAction::Freeze => {
                // The s2idle twin of the S3 arm above: same minted
                // authority, different core. The s2idle production
                // gate inside `suspend_to_idle` decides whether the
                // request actually parks the machine; unarmed or
                // unsupported, the refusal is the log line.
                let cap: Cap<narf_power::Power, Invoke> = Cap::bootstrap();
                match narf_power::s2idle::suspend_to_idle(&cap) {
                    Ok(()) => {
                        let _ = writeln!(narf_console::Writer, "  power-service: resumed");
                    }
                    Err(e) => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "  power-service: freeze request not carried out: {e:?}"
                        );
                    }
                }
            }
            PowerAction::PowerOff => {
                narf_power::orderly::orderly_poweroff(
                    narf_power::orderly::OrderlyReason::PowerService,
                    None,
                );
            }
        }
    }
}

/// The composition's `sleep_request` consumer: forward a parsed
/// userspace sleep request into the service's action queue. It only
/// queues — execution (and the `Cap<Power, Invoke>` it needs) is
/// the executor's, from the worker's task context — because the
/// sysfs writer whose context this runs in holds no Power
/// capability (see `narf_power::sleep_request` module docs).
/// Requests are never refused here: the cores' own gates (the S3
/// production gate, the s2idle arm/support gate) decide at
/// execution time whether a queued request actually sleeps the
/// machine, exactly as for event-driven requests.
fn forward_sleep_request(state: SleepState) -> Result<(), SleepRequestError> {
    service::request_action(match state {
        SleepState::Freeze => PowerAction::Freeze,
        SleepState::Mem => PowerAction::Suspend,
    });
    Ok(())
}

/// Evaluate `<path>` and return its package elements, if any.
fn eval_package(path: &str) -> Option<Vec<Value>> {
    match evaluate_method(path, &[]) {
        Ok(Value::Package(items)) => Some(items),
        _ => None,
    }
}

/// Battery provider for the power service: one battery
/// abstraction over two transports. The ACPI control-method
/// battery (`PNP0C0A`) wins where one exists; machines whose
/// battery subsystem is an ACPI Smart Battery Subsystem
/// (`ACPI0002`) have no control-method battery at all, so the
/// provider falls back to the SBS driver's snapshot, which
/// returns the same `(BatteryInfo, BatteryState)` pair.
fn battery_snapshot() -> Option<(BatteryInfo, BatteryState)> {
    match control_method_battery_snapshot() {
        Some(pair) => Some(pair),
        None => crate::sbs::snapshot_first(),
    }
}

/// First control-method battery's fused info + state, via the same
/// `_BIF` / `_BST` evaluations the battery driver performs.
fn control_method_battery_snapshot() -> Option<(BatteryInfo, BatteryState)> {
    let dev = find_all_devices_by_hid("PNP0C0A").into_iter().next()?;
    let bif = eval_package(&alloc::format!("{}._BIF", dev.path))?;
    if bif.len() < 13 {
        return None;
    }
    let mut ints = [0u32; 9];
    for (i, slot) in ints.iter_mut().enumerate() {
        *slot = bif[i].as_integer() as u32;
    }
    let mut strings: [String; 4] = Default::default();
    for (i, slot) in strings.iter_mut().enumerate() {
        match &bif[9 + i] {
            Value::String(s) => *slot = s.clone(),
            _ => return None,
        }
    }
    let info = decode_bif(&ints, &strings).ok()?;

    let bst = eval_package(&alloc::format!("{}._BST", dev.path))?;
    if bst.len() < 4 {
        return None;
    }
    let mut values = [0u32; 4];
    for (i, slot) in values.iter_mut().enumerate() {
        *slot = bst[i].as_integer() as u32;
    }
    let state = decode_bst(&values).ok()?;
    Some((info, state))
}

/// First AC adapter's live state (`_PSR`).
fn ac_snapshot() -> Option<AcAdapterState> {
    let dev = find_all_devices_by_hid("ACPI0003").into_iter().next()?;
    let v = evaluate_method(&alloc::format!("{}._PSR", dev.path), &[]).ok()?;
    decode_psr(v.as_integer() as u32).ok()
}

/// The (first) lid's cached state, mapped onto the `narf_acpi` type
/// the shared snapshot uses. The lid driver maintains the cache
/// from EC events, so this read never evaluates AML.
fn lid_snapshot() -> Option<narf_acpi::lid::LidState> {
    match crate::lid::lids().first().map(|d| d.state()) {
        Some(crate::lid::LidState::Closed) => Some(narf_acpi::lid::LidState::Closed),
        Some(crate::lid::LidState::Open) => Some(narf_acpi::lid::LidState::Open),
        _ => None,
    }
}

fn providers() -> StateProviders {
    StateProviders {
        ac_adapter: Some(Arc::new(ac_snapshot)),
        lid: Some(Arc::new(lid_snapshot)),
        battery: Some(Arc::new(battery_snapshot)),
        cpu_temp_mc: None,
        gpu_temp_mc: None,
    }
}

/// Stage::Late composition: install the executor, the warning hook,
/// and the state providers; subscribe the event sources. Runs after
/// this crate's Stage::Subsys driver initcalls (lid, buttons) and
/// after narf-power's Stage::Late service-worker registration —
/// and even if the order flipped, queued requests and subscriptions
/// are order-tolerant (requests wait for an executor).
pub fn init() {
    let cap = narf_power::bootstrap_power_authority();
    let _ = service::install_action_executor(&cap, Arc::new(PlatformExecutor));
    // Userspace trigger composition: with the executor in place,
    // install the sleep-request hook so `/sys/power/state` stores
    // reach the service. Installing it here (and only here) is
    // what keeps the store's fail-closed shape honest — no
    // composition, no consumer, ENODEV.
    narf_power::sleep_request::set_sleep_request_hook(forward_sleep_request);
    let _ = service::install_warning_hook(
        &cap,
        Arc::new(|| {
            let _ = writeln!(
                narf_console::Writer,
                "  power-service: WARNING: battery critical with AC offline — save your work"
            );
        }),
    );
    let _ = service::register_state_providers(&cap, providers());

    crate::lid::subscribe(|event| match event {
        LidEvent::Closed => service::on_lid_changed(true),
        LidEvent::Opened => service::on_lid_changed(false),
    });
    crate::buttons::subscribe_power(|_| service::on_power_button_press());
    crate::buttons::subscribe_sleep(|_| service::on_sleep_button_press());

    let _ = writeln!(
        narf_console::Writer,
        "  power-service: event/policy wiring installed"
    );
}
