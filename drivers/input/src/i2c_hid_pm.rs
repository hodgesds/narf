//! System power management for HID-over-I2C devices (issue #770).
//!
//! Why this is an [`AsyncSystemPm`] hook and not a `device_pm`
//! `register_device_pm` entry: the `device_pm` fan-out runs
//! synchronously with interrupts gated, which — per
//! `power/src/system_pm.rs` — "cannot carry an interrupt-driven
//! firmware exchange". An I2C-HID quiesce is exactly that: a
//! SET_POWER command over an async I2C bus whose transfers yield
//! to the executor. Every other async-bus driver in the tree
//! (CDC-ACM, USB serial, iwlwifi, ath10k/ath11k, brcmfmac,
//! cyw43439, mt76, AMDGPU Navi48, Intel GPU GT) registers the
//! same way, so this follows the established pattern instead of
//! inventing a sync bridge that could wedge suspend on a bus
//! mutex held by a pump task parked mid-transfer.
//!
//! Sequences (all framing reused verbatim from `I2cHidDriver`,
//! itself grounded in the Microsoft HID-over-I2C spec §7.2):
//! - **Prepare (suspend):** `SET_POWER(SLEEP)` — opcode 0x08,
//!   data [`POWER_SLEEP`] (0x01) — per bound device.
//! - **Resume:** `RESET` (opcode 0x01, then poll the Input
//!   register for the zero-length sentinel, exactly as
//!   `I2cHidDriver::reset` does), `SET_POWER(ON)` (0x08/0x00),
//!   then, for PTP devices, the `SET_FEATURE(Device Mode =
//!   MULTI_TOUCH)` report the pump sent at probe time — a RESET
//!   drops the mode, so without the re-set the touchpad falls
//!   back to legacy mouse-emulation reporting.
//!
//! State: the pump task owns its `I2cHidDriver` and this module
//! never touches it. At probe time the pump records a snapshot
//! (bus + slave address + descriptor-register address + the
//! descriptor it read + the precomputed PTP mode report bytes)
//! via [`record_device`]. The hooks rebuild a throwaway driver
//! from the snapshot with `I2cHidDriver::from_descriptor` and
//! drive it — no lock is held across an `.await`, and the pump
//! keeps working with its own instance afterwards (its next
//! `read_input_report` just works on the re-armed device; a
//! transient read racing the resume RESET is already tolerated
//! by the pump's bus-error retry).

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_drivers_i2c::I2cBus;
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::device_pm::DeviceSuspendError;
use narf_power::system_pm::{AsyncSystemPm, SystemPmFuture};

use crate::i2c_hid::{HidDescriptor, I2cHidDriver, POWER_ON, POWER_SLEEP};

/// One bound HID-over-I2C device's resume/suspend snapshot.
///
/// `ptp_mode` is the full wire buffer `build_mode_feature_report`
/// produced at probe time — `[report_id, body...]` — or `None`
/// when the device has no PTP Device Mode feature (keyboard-only
/// / touchscreen / sensor devices skip the mode restore).
#[derive(Clone, Debug)]
pub struct I2cHidPmDevice {
    bus: Arc<dyn I2cBus>,
    addr: u8,
    hid_desc_register: u16,
    descriptor: HidDescriptor,
    ptp_mode: Option<Vec<u8>>,
}

impl I2cHidPmDevice {
    /// Key for idempotent re-registration: one entry per
    /// (bus, slave address).
    fn key(&self) -> (alloc::string::String, u8) {
        (alloc::string::String::from(self.bus.name()), self.addr)
    }
}

/// Bound devices, in bind order. Populated by the pump at probe
/// time; read (cloned, lock dropped) by the PM hooks.
static PM_DEVICES: IrqSafeSpinLock<Vec<I2cHidPmDevice>> = IrqSafeSpinLock::new(Vec::new());

/// Whether the "i2c-hid" async hook is registered. `register_pm`
/// is called once from the `i2c-hid-probe` initcalls; the flag
/// keeps a second call (e.g. a re-run of the initcalls) from
/// double-registering — `register_async_system_pm` is idempotent
/// on name anyway, this just avoids pointless churn.
static HOOK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Snapshot one bound device for suspend/resume. Called by the
/// pump after it has read the descriptor, parsed the report
/// descriptor, and (for PTP devices) set multi-touch mode.
/// Re-recording the same (bus, address) replaces the prior
/// snapshot so a pump restart can't double-quiesce a device.
pub fn record_device(driver: &I2cHidDriver, ptp_mode: Option<Vec<u8>>) {
    let Some(descriptor) = driver.descriptor() else {
        return;
    };
    let device = I2cHidPmDevice {
        bus: driver.bus().clone(),
        addr: driver.addr(),
        hid_desc_register: driver.hid_desc_register(),
        descriptor,
        ptp_mode,
    };
    let key = device.key();
    let mut g = PM_DEVICES.lock();
    if let Some(slot) = g.iter_mut().find(|d| d.key() == key) {
        *slot = device;
    } else {
        g.push(device);
    }
}

/// Register the "i2c-hid" async system-PM hook. Called once from
/// `i2c_hid::register_initcalls`; idempotent.
pub fn register_pm() {
    if HOOK_REGISTERED.swap(true, Ordering::AcqRel) {
        return;
    }
    narf_power::system_pm::register_async_system_pm("i2c-hid", Arc::new(I2cHidSystemPm));
}

/// Test hook: drop every recorded device (and the hook flag, so a
/// test can re-register from a clean slate).
#[doc(hidden)]
pub fn __reset_for_test() {
    PM_DEVICES.lock().clear();
    HOOK_REGISTERED.store(false, Ordering::Release);
}

/// Test hook: how many devices are recorded.
#[doc(hidden)]
pub fn __device_count_for_test() -> usize {
    PM_DEVICES.lock().len()
}

/// Test hook: drive one device's suspend sequence directly
/// (prepare path for a single snapshot).
#[doc(hidden)]
pub async fn __suspend_one_for_test(device: &I2cHidPmDevice) -> Result<(), DeviceSuspendError> {
    suspend_one(device).await
}

/// Test hook: drive one device's resume sequence directly.
#[doc(hidden)]
pub async fn __resume_one_for_test(device: &I2cHidPmDevice) -> Result<(), DeviceSuspendError> {
    resume_one(device).await
}

/// Test hook: snapshot the recorded devices.
#[doc(hidden)]
pub fn __devices_for_test() -> Vec<I2cHidPmDevice> {
    PM_DEVICES.lock().clone()
}

/// The hook object: stateless, the device list lives in
/// `PM_DEVICES`.
#[derive(Debug)]
struct I2cHidSystemPm;

impl AsyncSystemPm for I2cHidSystemPm {
    fn prepare_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(async move {
            // Attempt every device even if one fails, so a single
            // wedged touchpad doesn't leave its siblings powered
            // across suspend; the coordinator aborts the transition
            // on the returned error and unwinds the slept devices
            // via our resume.
            let devices = PM_DEVICES.lock().clone();
            let mut first_err = None;
            for device in &devices {
                if let Err(e) = suspend_one(device).await {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
            match first_err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        })
    }

    fn resume_from_suspend<'a>(&'a self) -> SystemPmFuture<'a> {
        Box::pin(async move {
            // Best-effort per device: every device gets its
            // re-arm attempt even if an earlier one fails.
            let devices = PM_DEVICES.lock().clone();
            let mut first_err = None;
            for device in &devices {
                if let Err(e) = resume_one(device).await {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
            match first_err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        })
    }
}

/// Quiesce one device: SET_POWER(SLEEP) over its bus.
async fn suspend_one(device: &I2cHidPmDevice) -> Result<(), DeviceSuspendError> {
    let driver = I2cHidDriver::from_descriptor(
        device.bus.clone(),
        device.addr,
        device.hid_desc_register,
        device.descriptor,
    );
    driver
        .set_power(POWER_SLEEP)
        .await
        .map_err(|_| DeviceSuspendError::DriverError)
}

/// Re-arm one device: RESET (with the zero-length sentinel poll),
/// SET_POWER(ON), then the PTP multi-touch mode restore when the
/// device had one at probe time.
async fn resume_one(device: &I2cHidPmDevice) -> Result<(), DeviceSuspendError> {
    let driver = I2cHidDriver::from_descriptor(
        device.bus.clone(),
        device.addr,
        device.hid_desc_register,
        device.descriptor,
    );
    driver
        .reset()
        .await
        .map_err(|_| DeviceSuspendError::DriverError)?;
    driver
        .set_power(POWER_ON)
        .await
        .map_err(|_| DeviceSuspendError::DriverError)?;
    if let Some(mode) = &device.ptp_mode {
        // Wire buffer is [report_id, body...]; SET_REPORT takes
        // them as separate args (same split as the pump's
        // `set_ptp_multi_touch_mode`). An empty snapshot (never
        // produced by `build_mode_feature_report`, which always
        // emits at least the report ID) is skipped, not indexed.
        let Some((&report_id, body)) = mode.split_first() else {
            return Ok(());
        };
        driver
            .set_feature_report(report_id, body)
            .await
            .map_err(|_| DeviceSuspendError::DriverError)?;
    }
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────
//
// Wire-sequence fixtures for the PM sequences, built from the
// HID-over-I2C spec framing (not from impl constants): the
// expected bytes below are the spec-mandated command frames —
// [cmd_reg LE][data][opcode] for SET_POWER/RESET, the
// SET_REPORT frame for the PTP mode restore. The mock bus is a
// local copy of the `tests.rs` MockBus shape (record writes,
// serve canned reads) because that module is x86_64-only and
// this module is cross-arch.

pub mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use async_trait::async_trait;
    use narf_drivers_i2c::{I2cError, I2cOp};
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Mock I2C bus: records every write payload, serves canned
    /// reads in order (zero-fill when the queue runs dry). Same
    /// shape as the `tests.rs` MockBus.
    #[derive(Debug)]
    struct MockBus {
        canned_reads: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
        captured_writes: IrqSafeSpinLock<Vec<Vec<u8>>>,
    }

    impl MockBus {
        fn new() -> Self {
            Self {
                canned_reads: IrqSafeSpinLock::new(VecDeque::new()),
                captured_writes: IrqSafeSpinLock::new(Vec::new()),
            }
        }
        fn stage_read(&self, data: Vec<u8>) {
            self.canned_reads.lock().push_back(data);
        }
        fn writes(&self) -> Vec<Vec<u8>> {
            self.captured_writes.lock().clone()
        }
    }

    #[async_trait]
    impl I2cBus for MockBus {
        async fn transfer(&self, _addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
            for op in ops.iter_mut() {
                match op {
                    I2cOp::Write(data) => {
                        self.captured_writes.lock().push((*data).to_vec());
                    }
                    I2cOp::Read(buf) => {
                        let canned = self
                            .canned_reads
                            .lock()
                            .pop_front()
                            .unwrap_or_else(|| alloc::vec![0u8; buf.len()]);
                        let n = canned.len().min(buf.len());
                        buf[..n].copy_from_slice(&canned[..n]);
                        for byte in buf.iter_mut().skip(n) {
                            *byte = 0;
                        }
                    }
                }
            }
            Ok(())
        }
        fn name(&self) -> &str {
            "mock-i2c"
        }
    }

    /// The descriptor bytes the `tests.rs` i2c-hid smokes use:
    /// wCommandRegister 0x0005, wInputRegister 0x0003,
    /// wDataRegister 0x0006, wReportDescLength 100.
    fn make_descriptor_bytes() -> Vec<u8> {
        let mut buf = alloc::vec![0u8; crate::i2c_hid::HID_DESC_LENGTH];
        let put16 = |buf: &mut [u8], off: usize, v: u16| {
            buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
        };
        put16(&mut buf, 0, crate::i2c_hid::HID_DESC_LENGTH as u16);
        put16(&mut buf, 2, 0x0100);
        put16(&mut buf, 4, 100);
        put16(&mut buf, 6, 0x0002);
        put16(&mut buf, 8, 0x0003);
        put16(&mut buf, 10, 32);
        put16(&mut buf, 12, 0x0004);
        put16(&mut buf, 14, 32);
        put16(&mut buf, 16, 0x0005);
        put16(&mut buf, 18, 0x0006);
        put16(&mut buf, 20, 0x04F3);
        put16(&mut buf, 22, 0x3045);
        put16(&mut buf, 24, 0x0001);
        buf
    }

    /// Drive an async future to completion without the executor
    /// (the mock bus completes on first poll; `block_on_spin`
    /// re-polls on Pending, which is also how the FCH bus's
    /// yield-based waits make progress under a sync caller).
    fn run<F: core::future::Future>(fut: F) -> F::Output {
        narf_scheduler::block_on_spin(fut)
    }

    /// Build a recorded device on a mock bus: read the descriptor
    /// through a real driver instance, then snapshot it via
    /// `record_device` exactly as the pump does. Returns `None`
    /// when the setup descriptor read fails.
    fn record_mock_device(ptp_mode: Option<Vec<u8>>) -> Option<alloc::sync::Arc<MockBus>> {
        __reset_for_test();
        let bus = alloc::sync::Arc::new(MockBus::new());
        bus.stage_read(make_descriptor_bytes());
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let mut driver = I2cHidDriver::new(bus_dyn, 0x2c, 0x0001);
        let desc = run(async move { driver.read_descriptor().await.ok() })?;
        // `record_device` only needs the cached descriptor, so the
        // snapshot driver is built from the descriptor the setup
        // read returned.
        let bus_dyn2: Arc<dyn I2cBus> = bus.clone();
        let snapshot_driver = I2cHidDriver::from_descriptor(bus_dyn2, 0x2c, 0x0001, desc);
        record_device(&snapshot_driver, ptp_mode);
        Some(bus)
    }

    fn smoke_i2c_hid_pm_suspend_sends_set_power_sleep() -> TestResult {
        let Some(bus) = record_mock_device(None) else {
            return TestResult::Fail("setup descriptor read failed");
        };
        if __device_count_for_test() != 1 {
            return TestResult::Fail("record_device did not record exactly one device");
        }
        let devices = __devices_for_test();
        let r = run(__suspend_one_for_test(&devices[0]));
        if r.is_err() {
            return TestResult::Fail("suspend_one errored on a healthy mock bus");
        }
        let writes = bus.writes();
        // writes[0] is the descriptor-register pointer from the
        // setup read; writes[1] must be SET_POWER(SLEEP):
        // [cmd 0x0005 LE][data 0x01][opcode 0x08].
        if writes.len() != 2 {
            return TestResult::Fail("expected desc-pointer + SET_POWER writes");
        }
        if writes[1] != alloc::vec![0x05, 0x00, 0x01, 0x08] {
            return TestResult::Fail("SET_POWER(SLEEP) frame bytes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-pm",
        smoke_i2c_hid_pm_suspend_sends_set_power_sleep
    );

    fn smoke_i2c_hid_pm_resume_resets_powers_on_restores_ptp() -> TestResult {
        // PTP mode report the pump would have built: report ID 7,
        // one body byte (MULTI_TOUCH mode value 0x03).
        let Some(bus) = record_mock_device(Some(alloc::vec![0x07, 0x03])) else {
            return TestResult::Fail("setup descriptor read failed");
        };
        // RESET's sentinel poll reads the Input register; stage a
        // zero-length report so reset() returns on first poll.
        bus.stage_read(alloc::vec![0u8, 0u8]);
        let devices = __devices_for_test();
        let r = run(__resume_one_for_test(&devices[0]));
        if r.is_err() {
            return TestResult::Fail("resume_one errored on a healthy mock bus");
        }
        let writes = bus.writes();
        // writes[0] = desc-pointer (setup). Then:
        // [1] RESET [05 00 00 01]; [2] input-reg pointer [03 00];
        // [3] SET_POWER(ON) [05 00 00 08];
        // [4] SET_FEATURE(Device Mode): [05 00][(0x03<<4)|0x07]
        //     [0x03][06 00][len 2+1+1=4 LE][07][03].
        if writes.len() != 5 {
            return TestResult::Fail("expected desc + RESET + input + ON + SET_FEATURE writes");
        }
        if writes[1] != alloc::vec![0x05, 0x00, 0x00, 0x01] {
            return TestResult::Fail("RESET frame bytes wrong");
        }
        if writes[2] != alloc::vec![0x03, 0x00] {
            return TestResult::Fail("RESET sentinel input-register pointer wrong");
        }
        if writes[3] != alloc::vec![0x05, 0x00, 0x00, 0x08] {
            return TestResult::Fail("SET_POWER(ON) frame bytes wrong");
        }
        if writes[4] != alloc::vec![0x05, 0x00, 0x37, 0x03, 0x06, 0x00, 0x04, 0x00, 0x07, 0x03] {
            return TestResult::Fail("PTP SET_FEATURE(Device Mode) frame bytes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-pm",
        smoke_i2c_hid_pm_resume_resets_powers_on_restores_ptp
    );

    fn smoke_i2c_hid_pm_resume_without_ptp_skips_mode_restore() -> TestResult {
        let Some(bus) = record_mock_device(None) else {
            return TestResult::Fail("setup descriptor read failed");
        };
        bus.stage_read(alloc::vec![0u8, 0u8]);
        let devices = __devices_for_test();
        if run(__resume_one_for_test(&devices[0])).is_err() {
            return TestResult::Fail("resume_one errored on a healthy mock bus");
        }
        let writes = bus.writes();
        if writes.len() != 4 {
            return TestResult::Fail("non-PTP resume must not emit a SET_FEATURE write");
        }
        if writes[3] != alloc::vec![0x05, 0x00, 0x00, 0x08] {
            return TestResult::Fail("SET_POWER(ON) frame bytes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-pm",
        smoke_i2c_hid_pm_resume_without_ptp_skips_mode_restore
    );

    fn smoke_i2c_hid_pm_record_is_idempotent_per_bus_addr() -> TestResult {
        let Some(bus) = record_mock_device(None) else {
            return TestResult::Fail("setup descriptor read failed");
        };
        if __device_count_for_test() != 1 {
            return TestResult::Fail("first record did not yield one device");
        }
        // Record the same device again: still one entry, and a
        // suspend still emits exactly one SET_POWER(SLEEP).
        let bus_dyn: Arc<dyn I2cBus> = bus.clone();
        let driver = I2cHidDriver::from_descriptor(
            bus_dyn,
            0x2c,
            0x0001,
            HidDescriptor::parse(&make_descriptor_bytes()).unwrap(),
        );
        record_device(&driver, None);
        if __device_count_for_test() != 1 {
            return TestResult::Fail("re-record duplicated the device entry");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-pm",
        smoke_i2c_hid_pm_record_is_idempotent_per_bus_addr
    );

    fn smoke_i2c_hid_pm_hook_prepare_resume_round_trip() -> TestResult {
        // End-to-end through the real registries: reset the
        // system-PM registry, register our hook, prepare via the
        // transition API, then resume — asserting the wire sees
        // SLEEP then RESET + ON, and the transition reports
        // success. Proves the hook is actually reachable from the
        // suspend coordinator, not just callable directly.
        narf_power::system_pm::__reset_for_test();
        let Some(bus) = record_mock_device(None) else {
            return TestResult::Fail("setup descriptor read failed");
        };
        bus.stage_read(alloc::vec![0u8, 0u8]);
        register_pm();
        if narf_power::system_pm::async_system_pm_count() != 1 {
            return TestResult::Fail("hook was not the only registered async hook");
        }
        let transition = run(narf_power::system_pm::prepare_async_system_pm());
        if !transition.succeeded() {
            return TestResult::Fail("prepare transition failed on a healthy mock bus");
        }
        let writes = bus.writes();
        if writes.len() != 2 || writes[1] != alloc::vec![0x05, 0x00, 0x01, 0x08] {
            return TestResult::Fail("prepare did not emit SET_POWER(SLEEP)");
        }
        let failures = run(transition.resume());
        if !failures.is_empty() {
            return TestResult::Fail("resume transition reported failures");
        }
        let writes = bus.writes();
        if writes.len() != 5 {
            return TestResult::Fail("resume did not emit RESET + ON after prepare");
        }
        if writes[2] != alloc::vec![0x05, 0x00, 0x00, 0x01]
            || writes[4] != alloc::vec![0x05, 0x00, 0x00, 0x08]
        {
            return TestResult::Fail("resume wire sequence wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-pm",
        smoke_i2c_hid_pm_hook_prepare_resume_round_trip
    );

    fn smoke_i2c_hid_pm_empty_prepare_is_noop_success() -> TestResult {
        narf_power::system_pm::__reset_for_test();
        __reset_for_test();
        register_pm();
        let transition = run(narf_power::system_pm::prepare_async_system_pm());
        if !transition.succeeded() {
            return TestResult::Fail("prepare with no devices must succeed");
        }
        if !run(transition.resume()).is_empty() {
            return TestResult::Fail("resume with no devices must report no failures");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/input/i2c-hid-pm",
        smoke_i2c_hid_pm_empty_prepare_is_noop_success
    );
}
