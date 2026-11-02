//! Actual wake-vote/RTC words and current cap epochs for the native PM owner.
//! Synthetic device-side registers are not board power measurements.
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_capabilities::{CapError, CapOp};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Device {
    cap: Cap<BusDeviceCap, Write>,
    sources: Option<crate::ath10k::firmware_source::Source>,
    words: BTreeMap<u64, u32>,
    trace: Vec<(u64, Option<u32>)>,
    clock: u64,
    wake_at: Option<u64>,
    hold_rtc: bool,
    sleep_on_release: bool,
    revoke_at: Option<usize>,
}
impl Device {
    fn new() -> Self {
        Self {
            cap: Cap::bootstrap(),
            sources: None,
            words: BTreeMap::from([(0x80000, 0), (0x80004, 0), (0x100, 0x55)]),
            trace: Vec::new(),
            clock: 0,
            wake_at: None,
            hold_rtc: false,
            sleep_on_release: true,
            revoke_at: None,
        }
    }
    fn access(&mut self, register: u64, value: Option<u32>) -> Result<u32, BmiError> {
        let cap = self.cap;
        let source = self.sources.clone();
        let operation = Operation {
            device: self,
            register,
            value,
        };
        match source {
            Some(source) => source
                .invoke_boot(|| cap.invoke(operation))
                .map_err(|_| BmiError::DeviceGone)?
                .map_err(|_| BmiError::Pci),
            None => cap.invoke(operation).map_err(|_| BmiError::Pci),
        }
    }
}
struct Operation<'a> {
    device: &'a mut Device,
    register: u64,
    value: Option<u32>,
}
impl CapOp<BusDeviceCap, Write> for Operation<'_> {
    type Output = u32;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<u32, CapError> {
        let d = self.device;
        d.trace.push((self.register, self.value));
        let result = match self.value {
            Some(value) => {
                d.words.insert(self.register, value);
                if self.register == 0x80004 {
                    if value & 1 != 0 {
                        d.wake_at = Some(d.clock + 5_000);
                    } else {
                        d.wake_at = None;
                        if d.sleep_on_release {
                            d.words.insert(0x80000, 0);
                        }
                    }
                }
                0
            }
            None => {
                if self.register == 0x80000
                    && !d.hold_rtc
                    && d.wake_at.is_some_and(|at| d.clock >= at)
                {
                    d.words.insert(0x80000, 3);
                }
                d.words.get(&self.register).copied().unwrap_or(0)
            }
        };
        if d.revoke_at == Some(d.trace.len()) {
            d.cap.revoke();
        }
        Ok(result)
    }
}
impl Raw for Device {
    fn read(&mut self, register: u64) -> Result<u32, BmiError> {
        self.access(register, None)
    }
    fn write(&mut self, register: u64, value: u32) -> Result<(), BmiError> {
        self.access(register, Some(value)).map(|_| ())
    }
    fn now(&self) -> u64 {
        self.clock
    }
    fn wait_on(&mut self, register: u64) -> Result<(), BmiError> {
        // Device-side virtual settling, not a production register spin or a
        // driver-supplied awake receipt. Read the actual RTC word under Cap.
        self.clock += 5_000;
        if self.read(register)? & 7 == 3 {
            return Ok(());
        }
        self.clock += WAKE_US * 1000;
        if self.read(register)? & 7 == 3 {
            Ok(())
        } else {
            Err(BmiError::Timeout)
        }
    }
}
fn vote(d: &Device) -> u32 {
    d.words[&0x80004] & 1
}
fn smoke_ath10k_host_bus_pm_actual_rtc_counted_leases_and_grace() -> TestResult {
    for hardware in [HwRev::Qca6174, HwRev::Qca9377] {
        for sleep in [false, true] {
            let mut d = Device::new();
            d.sleep_on_release = sleep;
            let mut owner = Owner::new(hardware);
            if owner.activate(&mut d, true).is_err() || d.words[&0x80000] != 3 {
                return TestResult::Fail("host PM admitted awake without real RTC_ON");
            }
            owner.acquire(&mut d).unwrap();
            owner.acquire(&mut d).unwrap();
            owner.hint(true);
            owner.quiet(d.clock, 7).unwrap();
            if owner.references != 2 || owner.idle_poll(&mut d, 7) != Ok(false) || vote(&d) != 1 {
                return TestResult::Fail("live native MMIO references released host wake");
            }
            owner.release().unwrap();
            owner.release().unwrap();
            let began = d.clock;
            owner.quiet(began, 7).unwrap();
            let accesses = d.trace.len();
            d.clock = began + GRACE_NS - 1;
            if owner.idle_poll(&mut d, 7) != Ok(true) || d.trace.len() != accesses || vote(&d) != 1
            {
                return TestResult::Fail("idle pump touched BAR or released wake before60ms");
            }
            d.clock = began + GRACE_NS;
            if owner.idle_poll(&mut d, 7) != Ok(true) || vote(&d) != 0 || owner.awake {
                return TestResult::Fail("actual current host-wake release/readback missing");
            }
            // Both actual RTC sleep and firmware remaining awake are legal:
            // host vote release never manufactures a firmware-sleep ACK.
            if d.words[&0x80000] != if sleep { 0 } else { 3 } {
                return TestResult::Fail("host-vote result replaced actual device RTC fact");
            }
            d.clock = began + BACKSTOP_NS;
            if owner.idle_poll(&mut d, 7) != Ok(false) {
                return TestResult::Fail("missed-edge native backstop was unbounded");
            }
            let before = d.trace.len();
            if owner.access(&mut d, |raw| raw.read(0x100)) != Ok(0x55)
                || owner.references != 0
                || vote(&d) != 1
                || !d.trace[before..].contains(&(0x80004, Some(1)))
                || d.trace.last() != Some(&(0x100, None))
            {
                return TestResult::Fail(
                    "native payload did not follow exact fresh wake/RTC receipt",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/host-bus-pm",
    smoke_ath10k_host_bus_pm_actual_rtc_counted_leases_and_grace
);

fn smoke_ath10k_host_bus_pm_irq_host_activity_and_non_msi_fallback() -> TestResult {
    let mut d = Device::new();
    let mut owner = Owner::new(HwRev::Qca6174);
    owner.activate(&mut d, true).unwrap();
    owner.hint(true);
    owner.quiet(d.clock, 5).unwrap();
    d.clock += GRACE_NS;
    if owner.idle_poll(&mut d, 6) != Ok(false) || vote(&d) != 1 {
        return TestResult::Fail("actual IRQ generation was hidden by old idle lease");
    }
    owner.quiet(d.clock, 6).unwrap();
    if owner.access(&mut d, |raw| raw.write(0x100, 0x77)).is_err()
        || owner.idle.is_some()
        || vote(&d) != 1
    {
        return TestResult::Fail("new native host command inherited old sleep deadline");
    }
    for (hardware, delivered) in [
        (HwRev::Qca6174, false),
        (HwRev::Qca9377, false),
        (HwRev::Qca988x, true),
        (HwRev::Qca9984, true),
        (HwRev::Qca9888, true),
    ] {
        let mut d = Device::new();
        let mut owner = Owner::new(hardware);
        owner.activate(&mut d, delivered).unwrap();
        owner.hint(true);
        owner.quiet(0, 0).unwrap();
        d.clock = BACKSTOP_NS;
        if owner.enabled || owner.idle_poll(&mut d, 0) != Ok(false) || !d.trace.is_empty() {
            return TestResult::Fail("unsupported/no-MSI owner invented host sleep authority");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/host-bus-pm",
    smoke_ath10k_host_bus_pm_irq_host_activity_and_non_msi_fallback
);

fn smoke_ath10k_host_bus_pm_timeout_revocation_and_nonwrapping_denial() -> TestResult {
    let mut d = Device::new();
    d.hold_rtc = true;
    let mut owner = Owner::new(HwRev::Qca6174);
    if owner.activate(&mut d, true) != Err(BmiError::Timeout)
        || !owner.failed
        || owner.references != 0
        || d.trace.iter().any(|(r, _)| *r == 0x100)
    {
        return TestResult::Fail("requested wake became RTC success or native payload access");
    }
    let before = d.trace.len();
    if owner.access(&mut d, |raw| raw.read(0x100)).is_ok() || d.trace.len() != before {
        return TestResult::Fail("failed wake owner reopened without terminal retirement");
    }
    let mut d = Device::new();
    let mut owner = Owner::new(HwRev::Qca6174);
    owner.activate(&mut d, true).unwrap();
    owner.hint(true);
    owner.quiet(d.clock, 0).unwrap();
    d.clock += GRACE_NS;
    owner.idle_poll(&mut d, 0).unwrap();
    let before = d.trace.len();
    d.cap.revoke();
    if owner.access(&mut d, |raw| raw.read(0x100)).is_ok()
        || d.trace.len() != before
        || !owner.failed
    {
        return TestResult::Fail("revoked exact PCI cap accessed wake/RTC/payload");
    }
    let mut d = Device::new();
    let mut owner = Owner::new(HwRev::Qca9377);
    owner.activate(&mut d, true).unwrap();
    owner.references = u32::MAX;
    if owner.acquire(&mut d).is_ok() || !owner.failed {
        return TestResult::Fail("native wake-reference counter wrapped into idle");
    }
    let mut owner = Owner::new(HwRev::Qca9377);
    let mut d = Device::new();
    owner.activate(&mut d, true).unwrap();
    owner.hint(true);
    if owner.quiet(u64::MAX, 0).is_ok() || !owner.failed {
        return TestResult::Fail("native PM deadline wrapped into fresh wake permission");
    }
    let mut d = Device::new();
    d.revoke_at = Some(1); // Actual epoch changes after the native WAKE write.
    let mut owner = Owner::new(HwRev::Qca6174);
    if owner.activate(&mut d, true).is_ok() || !owner.failed || d.trace.len() != 1 {
        return TestResult::Fail("mid-wake PCI revocation allowed later RTC/payload access");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/host-bus-pm",
    smoke_ath10k_host_bus_pm_timeout_revocation_and_nonwrapping_denial
);

#[cfg(feature = "kernel-test")]
fn smoke_ath10k_host_bus_pm_original_firmware_and_terminal_vote_ownership() -> TestResult {
    for index in 0..2 {
        let (source, caps) = match crate::ath10k::firmware_source::fixture() {
            Ok(v) => v,
            Err(e) => return TestResult::Fail(e),
        };
        let mut d = Device::new();
        d.sources = Some(source);
        let mut owner = Owner::new(HwRev::Qca6174);
        owner.activate(&mut d, true).unwrap();
        owner.hint(true);
        owner.quiet(d.clock, 0).unwrap();
        d.clock += GRACE_NS;
        owner.idle_poll(&mut d, 0).unwrap();
        let before = d.trace.len();
        caps[index].revoke();
        if owner.access(&mut d, |raw| raw.read(0x100)).is_ok() || d.trace.len() != before {
            return TestResult::Fail(
                "expired original executable/board source allowed native wake",
            );
        }
        // Production does this only after PciBoot retired/closed HIF and
        // detached the expired executable scope. The same original PCI cap
        // may wake for terminal CE halt/reset; no runtime idle hint survives.
        d.sources = None;
        if owner.terminal_cleanup(&mut d).is_err() || vote(&d) != 1 || owner.enabled {
            return TestResult::Fail("retired native PCI-only cleanup lost actual wake receipt");
        }
        owner.hint(true);
        owner.quiet(d.clock, 0).unwrap();
        if owner.eligible || owner.idle.is_some() || owner.activate(&mut d, true).is_ok() {
            return TestResult::Fail("terminal hardware cleanup recaptured a live RF/HIF owner");
        }
        if owner.stop(&mut d).is_err() || vote(&d) != 0 {
            return TestResult::Fail("terminal stop did not release its current native wake vote");
        }
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/wireless/ath10k/host-bus-pm",
    smoke_ath10k_host_bus_pm_original_firmware_and_terminal_vote_ownership
);
