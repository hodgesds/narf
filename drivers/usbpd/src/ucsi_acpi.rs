//! ACPI PNP0CA0 UCSI transport, matching Linux ucsi_acpi.c's _DSM
//! revision 1 functions 1 (write) and 2 (refresh shared memory).
use super::ucsi::{Error, Ppm, Transport};
use alloc::{format, string::String, sync::Arc, vec::Vec};
use core::{
    fmt::Write as _,
    sync::atomic::{fence, AtomicBool, AtomicU8, Ordering},
};
use narf_aml::{resource::ResourceItem, NameValue, Value};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::ioremap::{ioremap, iounmap, IoMapping, MmioAttrs};

const UUID: [u8; 16] = [
    0xc2, 0x98, 0x83, 0x6f, 0xa4, 0x7c, 0xe4, 0x11, 0xad, 0x36, 0x63, 0x10, 0x42, 0xb5, 0x00, 0x8f,
];
struct PowerState {
    // 0 idle, 1 command sequence, 2 suspended.
    phase: AtomicU8,
    reset: AtomicBool,
}
impl narf_power::device_pm::DevicePmOps for PowerState {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.phase
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| narf_power::device_pm::DevicePmError::Busy)
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        if self.phase.load(Ordering::Acquire) == 2 {
            self.reset.store(true, Ordering::Release);
            self.phase.store(0, Ordering::Release);
        }
        Ok(())
    }
}
struct AcpiTransport {
    path: String,
    mapping: IoMapping,
    len: usize,
}
impl AcpiTransport {
    fn dsm(&self, function: u64) -> Result<(), Error> {
        narf_aml::eval::evaluate_dsm(&self.path, UUID, 1, function, Value::Package(Vec::new()))
            .map(|_| ())
            .map_err(|_| Error::Io)
    }
    fn read(&self, offset: usize, out: &mut [u8]) -> Result<(), Error> {
        if offset
            .checked_add(out.len())
            .is_none_or(|end| end > self.len)
        {
            return Err(Error::Protocol);
        }
        fence(Ordering::SeqCst);
        for (i, byte) in out.iter_mut().enumerate() {
            // SAFETY: _CRS describes the PPM-owned shared region, mapped WB;
            // bounds checked above. Volatile accesses prevent cached Rust loads.
            *byte =
                unsafe { ((self.mapping.va() as usize + offset + i) as *const u8).read_volatile() };
        }
        fence(Ordering::SeqCst);
        Ok(())
    }
}
impl Transport for AcpiTransport {
    fn version(&mut self) -> Result<u16, Error> {
        self.dsm(2)?;
        let mut bytes = [0; 2];
        self.read(0, &mut bytes)?;
        let version = u16::from_le_bytes(bytes);
        let required = if version <= 0x0120 { 48 } else { 528 };
        if self.len < required {
            return Err(Error::Protocol);
        }
        Ok(version)
    }
    fn cci(&mut self) -> Result<u32, Error> {
        self.dsm(2)?;
        let mut bytes = [0; 4];
        self.read(4, &mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }
    fn control(&mut self, command: u64) -> Result<(), Error> {
        if self.len < 16 {
            return Err(Error::Protocol);
        }
        for (i, byte) in command.to_le_bytes().iter().enumerate() {
            // SAFETY: control is bytes 8..16 of our exclusively owned mapping.
            unsafe { ((self.mapping.va() as usize + 8 + i) as *mut u8).write_volatile(*byte) };
        }
        fence(Ordering::SeqCst);
        self.dsm(1)
    }
    fn message(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.read(16, data)
    }
}
impl Drop for AcpiTransport {
    fn drop(&mut self) {
        // SAFETY: the owning task has stopped issuing commands; UCSI shared
        // memory belongs to firmware and is never returned to the allocator.
        unsafe { iounmap(self.mapping) };
    }
}

fn resource(path: &str) -> Option<(u64, u64)> {
    let crs = format!("{path}._CRS");
    let bytes = match narf_aml::find_node(&crs).and_then(|n| n.value) {
        Some(NameValue::Buffer(b)) => b,
        _ => match narf_aml::eval::evaluate_method(&crs, &[]).ok()? {
            Value::Buffer(b) => b,
            _ => return None,
        },
    };
    let resources = narf_aml::resource::decode_resource_template(&bytes).ok()?;
    resources
        .into_iter()
        .find_map(|r| match r {
            ResourceItem::Memory32Fixed { base, length, .. } => Some((base as u64, length as u64)),
            ResourceItem::Memory32 {
                min, max, length, ..
            } if min == max => Some((min as u64, length as u64)),
            ResourceItem::AddressSpace32 {
                kind: 0,
                min,
                translation,
                length,
                ..
            } => (min as u64)
                .checked_add(translation as u64)
                .map(|b| (b, length as u64)),
            ResourceItem::AddressSpace64 {
                kind: 0,
                min,
                translation,
                length,
                ..
            } => min.checked_add(translation).map(|b| (b, length)),
            _ => None,
        })
        .filter(|(base, len)| {
            *base != 0 && (48..=65536).contains(len) && base.checked_add(*len).is_some()
        })
}

/// Slice granularity for the Notify-aware poll wait: the task re-checks
/// the kick flag every 10 ms, so a firmware Notify arriving mid-wait is
/// observed within ~10 ms instead of at the next 100 ms / 1000 ms
/// cadence boundary, and a Notify arriving while the task is polling
/// is honored immediately (the flag is checked before the first sleep).
/// Kicks coalesce into one flag — a Notify storm cannot queue unbounded
/// work — but each kick still triggers a prompt poll, so a sustained
/// storm would poll repeatedly; each poll is bounded to one CCI read
/// plus refreshes of pending connectors only.
const NOTIFY_SLICE_MS: u64 = 10;

/// Per-device Notify kick flags, keyed by ACPI namespace path. The
/// Notify handler is a bare `fn` pointer (it cannot capture the
/// owning task's flag), so `probe()` registers the flag here and the
/// handler looks it up by the target path dispatch hands it. Lock
/// holders never await (register once at probe, find + atomic store
/// in the handler), so the handler cannot deadlock against the task.
static NOTIFY_KICKS: IrqSafeSpinLock<Vec<(String, Arc<AtomicBool>)>> =
    IrqSafeSpinLock::new(Vec::new());

/// Register (or replace) the kick flag for one PNP0CA0 path.
/// Replace-by-path: a second probe of the same device must not leave
/// a stale flag behind that the handler would set while the live task
/// watches a different one.
fn register_notify_kick(path: &str) -> Arc<AtomicBool> {
    let kick = Arc::new(AtomicBool::new(false));
    let mut kicks = NOTIFY_KICKS.lock();
    if let Some(slot) = kicks.iter_mut().find(|(p, _)| p == path) {
        slot.1 = kick.clone();
    } else {
        kicks.push((String::from(path), kick.clone()));
    }
    kick
}

/// ACPI Notify handler for PNP0CA0 devices. Runs in AML-evaluation
/// context: it must never issue commands, evaluate AML, or block — it
/// only sets the owning task's kick flag, and the task polls. The
/// event value is deliberately ignored: Linux's `ucsi_acpi_notify`
/// likewise ignores it (installed with `ACPI_DEVICE_NOTIFY`) and just
/// re-reads CCI. NARF's poll is idempotent state observation
/// (`read_cci` + refresh only pending connectors), so any firmware
/// signal on this path means "state may have changed" and a spurious
/// kick costs at most one extra poll.
fn ucsi_notify_handler(target: &str, _value: u64) {
    let kicks = NOTIFY_KICKS.lock();
    if let Some((_, kick)) = kicks.iter().find(|(p, _)| p == target) {
        kick.store(true, Ordering::Release);
    }
}

/// Wait for either a Notify kick or the cadence deadline, checking the
/// kick flag every `NOTIFY_SLICE_MS`. Returns true if kicked. The
/// flag is checked before the first sleep, so a Notify that arrived
/// while the task was polling is honored without another full slice.
async fn wait_kicked(kick: &AtomicBool, deadline_ms: u64) -> bool {
    let mut waited_ms = 0;
    loop {
        if kick.swap(false, Ordering::AcqRel) {
            return true;
        }
        if waited_ms >= deadline_ms {
            return false;
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(NOTIFY_SLICE_MS).as_instant())
            .await;
        waited_ms += NOTIFY_SLICE_MS;
    }
}

pub(crate) fn probe() -> narf_init::InitResult {
    let mut found = 0;
    for node in narf_aml::find_all_devices_by_hid("PNP0CA0") {
        // Respect a disabled firmware device. Missing _STA means present.
        let sta_path = format!("{}._STA", node.path);
        let sta = match narf_aml::find_node(&sta_path).and_then(|n| n.value) {
            Some(NameValue::Integer(value)) => Some(value),
            _ => match narf_aml::eval::evaluate_method(&sta_path, &[]) {
                Ok(Value::Integer(value)) => Some(value),
                _ => None,
            },
        };
        if let Some(sta) = sta {
            if sta & 3 != 3 {
                continue;
            }
        }
        let Some((base, len)) = resource(&node.path) else {
            let _ = writeln!(
                narf_console::Writer,
                "ucsi: {} has no valid shared memory resource",
                node.path
            );
            continue;
        };
        // SAFETY: a present PNP0CA0's _CRS names firmware shared memory;
        // Linux maps this WB as well. Never remap it as uncached MMIO.
        let Ok(mapping) = (unsafe { ioremap(base, len, MmioAttrs::WriteBack) }) else {
            continue;
        };
        let path = node.path;
        let transport = AcpiTransport {
            path: path.clone(),
            mapping,
            len: len as usize,
        };
        let pm = Arc::new(PowerState {
            phase: AtomicU8::new(1),
            reset: AtomicBool::new(true),
        });
        narf_power::device_pm::register_device_pm_ops(&format!("ucsi:{path}"), pm.clone());
        // ACPI Notify-driven wakeups (#1218): firmware signals connector
        // events with Notify on this device; the handler kicks the
        // task's poll instead of waiting for the next cadence tick.
        // Polling remains as the fallback for platforms whose firmware
        // never notifies, and as the cadence for state drift without
        // a Notify. The PM gate excludes AML/CCI access while firmware
        // is asleep.
        let kick = register_notify_kick(&path);
        narf_aml::sync::register_notify_handler(&path, ucsi_notify_handler);
        narf_scheduler::spawn(async move {
            let mut ppm = match Ppm::new(transport) {
                Ok(ppm) => ppm,
                Err(e) => {
                    pm.phase.store(0, Ordering::Release);
                    let _ = writeln!(narf_console::Writer, "ucsi: {path}: {e:?}");
                    return;
                }
            };
            let mut ports = Vec::new();
            let mut failures = 0;
            pm.phase.store(0, Ordering::Release);
            loop {
                if pm
                    .phase
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let result = if pm.reset.swap(false, Ordering::AcqRel) {
                        match ppm.initialize(&path).await {
                            Ok(current) => {
                                ports = current;
                                let _ = writeln!(
                                    narf_console::Writer,
                                    "ucsi: {path} v{:04x}, {} connectors",
                                    ppm.version,
                                    ports.len()
                                );
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    } else {
                        ppm.poll(&mut ports).await
                    };
                    match result {
                        Ok(()) => failures = 0,
                        Err(e) => {
                            super::ucsi::invalidate(&path);
                            failures += 1;
                            pm.reset.store(true, Ordering::Release);
                            let _ = writeln!(
                                narf_console::Writer,
                                "ucsi: {path} command failed ({failures}/3): {e:?}"
                            );
                        }
                    }
                    pm.phase.store(0, Ordering::Release);
                    if failures == 3 {
                        break;
                    }
                }
                wait_kicked(&kick, if failures == 0 { 100 } else { 1000 }).await;
            }
        });
        found += 1;
    }
    if found == 0 {
        narf_init::InitResult::NotPresent
    } else {
        narf_init::InitResult::Ok
    }
}

// ── Smoke tests ────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub(crate) mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Test-only cleanup: the kick registry is process-global, so each
    /// test removes its own paths (unique per test) at start and end
    /// rather than trusting the harness to isolate statics.
    fn remove_notify_kick(path: &str) {
        let mut kicks = NOTIFY_KICKS.lock();
        kicks.retain(|(p, _)| p != path);
    }

    fn notify_handler_sets_registered_kick_for_any_value() -> TestResult {
        const PATH: &str = "\\_SB.UCSI1";
        remove_notify_kick(PATH);
        let kick = register_notify_kick(PATH);
        ucsi_notify_handler(PATH, 0x80);
        if !kick.load(Ordering::Acquire) {
            return TestResult::Fail("Notify 0x80 should set the registered kick");
        }
        kick.store(false, Ordering::Release);
        ucsi_notify_handler(PATH, 0x00);
        if !kick.load(Ordering::Acquire) {
            return TestResult::Fail("Notify value must be ignored: 0x00 should also kick");
        }
        remove_notify_kick(PATH);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/ucsi-notify",
        notify_handler_sets_registered_kick_for_any_value
    );

    fn notify_handler_ignores_unknown_path() -> TestResult {
        const PATH: &str = "\\_SB.UCSI2";
        remove_notify_kick(PATH);
        let kick = register_notify_kick(PATH);
        ucsi_notify_handler("\\_SB.OTHER", 0x80);
        if kick.load(Ordering::Acquire) {
            return TestResult::Fail("Notify for an unknown path must not set any kick");
        }
        remove_notify_kick(PATH);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/ucsi-notify",
        notify_handler_ignores_unknown_path
    );

    fn notify_kick_replace_by_path() -> TestResult {
        const PATH: &str = "\\_SB.UCSI3";
        remove_notify_kick(PATH);
        let stale = register_notify_kick(PATH);
        let live = register_notify_kick(PATH);
        ucsi_notify_handler(PATH, 0x80);
        if stale.load(Ordering::Acquire) {
            return TestResult::Fail("Re-registration must retire the stale flag");
        }
        if !live.load(Ordering::Acquire) {
            return TestResult::Fail("Handler must set the latest registered flag");
        }
        remove_notify_kick(PATH);
        TestResult::Pass
    }
    kernel_test_in!("drivers/usbpd/ucsi-notify", notify_kick_replace_by_path);

    fn wait_kicked_preset_kick_returns_true_and_consumes() -> TestResult {
        let kick = AtomicBool::new(true);
        if !narf_scheduler::block_on_spin(wait_kicked(&kick, 0)) {
            return TestResult::Fail("Pre-set kick must return true without sleeping");
        }
        if kick.load(Ordering::Acquire) {
            return TestResult::Fail("wait_kicked must consume the kick it honors");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/ucsi-notify",
        wait_kicked_preset_kick_returns_true_and_consumes
    );

    fn wait_kicked_zero_deadline_without_kick_returns_false() -> TestResult {
        let kick = AtomicBool::new(false);
        if narf_scheduler::block_on_spin(wait_kicked(&kick, 0)) {
            return TestResult::Fail("No kick and zero deadline must return false");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/ucsi-notify",
        wait_kicked_zero_deadline_without_kick_returns_false
    );

    fn wait_kicked_waits_full_deadline_without_kick() -> TestResult {
        let kick = AtomicBool::new(false);
        if narf_scheduler::block_on_spin(wait_kicked(&kick, 30)) {
            return TestResult::Fail("No kick must wait out the deadline, not return true");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/ucsi-notify",
        wait_kicked_waits_full_deadline_without_kick
    );

    fn wait_kicked_preset_kick_beats_deadline() -> TestResult {
        let kick = AtomicBool::new(true);
        if !narf_scheduler::block_on_spin(wait_kicked(&kick, 100)) {
            return TestResult::Fail("Pre-set kick must beat a 100 ms deadline");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/usbpd/ucsi-notify",
        wait_kicked_preset_kick_beats_deadline
    );
}
