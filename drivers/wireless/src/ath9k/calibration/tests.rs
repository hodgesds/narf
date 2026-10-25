use super::*;
use alloc::{boxed::Box, collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
#[allow(dead_code)]
mod power_fixture {
    include!("../phy/rates/golden.rs");
    pub(super) fn image() -> &'static [u8] {
        RATE_EEPROM_6
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Write(u64, u32),
    Delay(u64),
}
struct Model {
    seed: u32,
    values: BTreeMap<u64, u32>,
    trace: Vec<Op>,
    now: u64,
    redo: bool,
    spare: usize,
    hold: Option<(u64, u32)>,
    fault: Option<usize>,
    accesses: usize,
    delays: usize,
    pause: Option<usize>,
    gone: bool,
}
impl Model {
    fn new(seed: u32, xe2: bool, redo: bool, correlation: u32) -> Self {
        let mut m = Self {
            seed,
            values: BTreeMap::new(),
            trace: Vec::new(),
            now: 0,
            redo,
            spare: 0,
            hold: None,
            fault: None,
            accesses: 0,
            delays: 0,
            pause: None,
            gone: false,
        };
        for (register, value) in [
            (0x981c, 0),
            (8, 0x20),
            (0x840, 0),
            (0x24, 0),
            (0x8048, 0x02000020),
            (0x4020, 0x000c02ff),
            (0x9c10, 20000),
            (0x9c14, 16000),
            (0x9c18, correlation),
        ] {
            m.values.insert(register, value);
        }
        for (register, clear, set) in [
            (0x9860, 3, 0),
            (0x9920, 0x10000, 0),
            (0x7868, 7, u32::from(xe2)),
            (0xa274, 0x7e000, 3 << 13),
        ] {
            let value = m.raw(register);
            m.values.insert(register, (value & !clear) | set);
        }
        for index in 0..4 {
            m.values.insert(0xa300 + index * 4, (index as u32) << 1);
        }
        m
    }
    fn raw(&self, register: u64) -> u32 {
        self.values
            .get(&register)
            .copied()
            .unwrap_or(if self.seed == 0 {
                0
            } else {
                self.seed ^ register as u32
            })
    }
    fn access(&mut self) -> bool {
        if self.fault == Some(self.accesses) {
            self.gone = true;
        }
        self.accesses += 1;
        !self.gone
    }
    fn encoded_trace(&self) -> Option<&[Op]> {
        let at = self
            .trace
            .iter()
            .position(|op| matches!(op, Op::Write(0x4040, _)))?;
        self.trace.get(at..)
    }
}
impl RegisterIo for Model {
    fn authorized(&self) -> bool {
        !self.gone
    }
    fn read32(&mut self, register: u64) -> u32 {
        if !self.access() {
            return u32::MAX;
        }
        if register == 0x9860 {
            let old = self.raw(register);
            let hold = self.hold.filter(|h| h.0 == register).map_or(0, |h| h.1);
            self.values.insert(register, old & !(3 & !hold));
            if old & 2 != 0 && old & 0x8000 != 0 && hold & 2 == 0 {
                let value = (self.raw(0x9864) & !0x1ff00000) | (((-115i32 as u32) & 511) << 20);
                self.values.insert(0x9864, value);
            }
        }
        if register == 0x9920 && self.hold != Some((0x9920, 0x10000)) {
            let value = self.raw(register) & !0x10000;
            self.values.insert(register, value);
        }
        if register == 0x7840 {
            let bit = (0x5bu32 >> (6 - self.spare % 7)) & 1;
            self.spare += 1;
            return (self.raw(register) & !1) | bit;
        }
        if (0xa35c..0xa39c).contains(&register) {
            return if self.redo { 0 } else { 0x00410020 };
        }
        self.raw(register)
    }
    fn write32(&mut self, register: u64, mut value: u32) {
        if !self.access() {
            return;
        }
        self.trace.push(Op::Write(register, value));
        if register == 0x7868 {
            value = (value & !7) | (self.raw(register) & 7);
        }
        self.values.insert(register, value);
    }
    fn delay_us(&mut self, _: u64) {
        panic!("async calibration used a synchronous wait")
    }
}
impl Io for Model {
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn settle(&mut self, us: u64) {
        self.trace.push(Op::Delay(us));
        self.now += if self.hold.is_some() { 30000001 } else { us };
        self.delays += 1;
        if self.pause == Some(self.delays) {
            core::future::pending::<()>().await;
        }
    }
}
fn image(high: bool) -> [u8; EEPROM_4K_BYTES] {
    let mut image: [u8; EEPROM_4K_BYTES] = power_fixture::image().try_into().unwrap();
    image[8..10].copy_from_slice(&0x64u16.to_le_bytes());
    image[31] = u8::from(high);
    image
}
fn permission() -> Permission {
    Permission {
        country: *b"US",
        ceiling: 0,
    }
}
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    match future.as_mut().poll(&mut cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("self-completing calibration model unexpectedly waited"),
    }
}
fn hash(trace: &[Op]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for op in trace {
        let words = match *op {
            Op::Write(r, v) => [0, r as u32, v],
            Op::Delay(us) => [1, us as u32, 0],
        };
        for word in words {
            for byte in word.to_le_bytes() {
                hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
            }
        }
    }
    hash
}
fn smoke_ath9k_retained_calibration_matches_frozen_reference_traces() -> TestResult {
    if CALIBRATION_CASES.len() != 32 {
        return TestResult::Fail("calibration oracle geometry changed");
    }
    for &(xe2, high, redo, seed, correlation, count, expected) in CALIBRATION_CASES {
        let mut io = Model::new(seed, xe2, redo, correlation);
        let mut calibration = Calibration::default();
        // SAFETY: model owns the parked AR9285 reference and no DMA exists.
        let result = ready(unsafe { calibration.run(&mut io, &image(high), permission(), xe2) });
        let Ok(report) = result else {
            return TestResult::Fail("retained native calibration refused Linux case");
        };
        let Some(trace) = io.encoded_trace() else {
            return TestResult::Fail("PCIe/analog calibration was omitted");
        };
        if trace.len() != count as usize || hash(trace) != expected {
            use core::fmt::Write;
            let _=writeln!(narf_console::Writer,"ath9k cal trace xe2={xe2} high={high} redo={redo} seed={seed:x} corr={correlation:x}: got{} {:x} want{count} {expected:x}",trace.len(),hash(trace));
            return TestResult::Fail(
                "native calibration differs from original Linux register/delay trace",
            );
        }
        if report.country != *b"US"
            || report.frequency_mhz != 2412
            || report.max_power_half_dbm != 0
            || report.pa_offset != if high { None } else { Some(0x5b) }
            || report.measured_noise_dbm != -115
            || report.noise_dbm != -115
            || report.iq_i != if correlation > 0x80000000 { 10 } else { 54 }
            || report.iq_q != 15
            || calibration.state() != State::Ready
            || calibration.report() != Some(report)
            || io.raw(8) & 4 != 0
            || io.raw(0x840) & 0x3ff != 0
            || io.raw(0x24) & 1 != 0
        {
            return TestResult::Fail(
                "calibration receipt exposed a packet engine or wrong measurement",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_retained_calibration_matches_frozen_reference_traces
);

fn smoke_ath9k_calibration_failure_timeout_and_drop_are_terminal() -> TestResult {
    let mut baseline = Model::new(0, false, true, 1400);
    let mut calibration = Calibration::default();
    // SAFETY: owned stopped model with no packet DMA.
    if ready(unsafe { calibration.run(&mut baseline, &image(false), permission(), false) }).is_err()
    {
        return TestResult::Fail("baseline calibration failed");
    }
    for fault in 0..baseline.accesses {
        let mut io = Model::new(0, false, true, 1400);
        io.fault = Some(fault);
        let mut owner = Calibration::default();
        // SAFETY: same exclusive, parked model, with a simulated access loss.
        if ready(unsafe { owner.run(&mut io, &image(false), permission(), false) }).is_ok()
            || owner.report().is_some()
        {
            return TestResult::Fail("failed calibration published a receipt");
        }
        let before = io.trace.len();
        // SAFETY: no reset was performed; failed/unauthorized owner must refuse.
        if ready(unsafe { owner.run(&mut io, &image(false), permission(), false) }).is_ok()
            || io.trace.len() != before
        {
            return TestResult::Fail("failed calibration replayed hardware writes");
        }
    }
    for hold in [(0x9860, 1), (0x9860, 2), (0x9920, 0x10000)] {
        let mut io = Model::new(0, false, true, 1400);
        io.hold = Some(hold);
        let mut owner = Calibration::default();
        // SAFETY: stopped model with a withheld AGC/NF/IQ completion.
        if ready(unsafe { owner.run(&mut io, &image(false), permission(), false) })
            != Err(BringUpError::Timeout)
            || owner.state() != State::Failed
        {
            return TestResult::Fail("calibration deadline did not retain terminal failure");
        }
    }
    for pause in 1..=10 {
        let mut io = Model::new(0, false, true, 1400);
        io.pause = Some(pause);
        let mut owner = Calibration::default();
        let retained_image = image(false);
        // SAFETY: exclusive model; the dropped attempt must remain retained.
        let mut future =
            Box::pin(unsafe { owner.run(&mut io, &retained_image, permission(), false) });
        let mut cx = Context::from_waker(Waker::noop());
        if future.as_mut().poll(&mut cx).is_ready() {
            return TestResult::Fail("calibration cancellation point was not reached");
        }
        drop(future);
        let before = io.trace.len();
        // SAFETY: no independent reset; rejection must precede register access.
        let retry = ready(unsafe { owner.run(&mut io, &image(false), permission(), false) });
        if owner.state() != State::Failed
            || retry != Err(BringUpError::BadState)
            || io.trace.len() != before
        {
            return TestResult::Fail("dropped calibration attempted cleanup/replay");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_calibration_failure_timeout_and_drop_are_terminal
);

fn smoke_ath9k_iq_coefficients_match_native_c_and_keep_full_width_data() -> TestResult {
    for &(i, q, corr, expected_i, expected_q) in IQ_CASES {
        let Ok((actual_i, actual_q)) = iq_coefficients(i, q, corr) else {
            return TestResult::Fail("valid native IQ measurement was rejected");
        };
        if actual_i != expected_i || actual_q as u8 & 31 != expected_q {
            return TestResult::Fail("IQ math differs from signed/unsigned native C");
        }
    }
    for (i, q) in [(0, 0), (1, 0), (64, 64)] {
        if iq_coefficients(i, q, 0) != Err(BringUpError::BadCalibration) {
            return TestResult::Fail("zero-denominator IQ accepted stale factory fallback");
        }
    }
    let mut io = Model::new(0, false, false, u32::MAX);
    if measurement(&mut io, 0x9c18) != Ok(u32::MAX) {
        return TestResult::Fail("legitimate correlation -1 was confused with device removal");
    }
    io.gone = true;
    if measurement(&mut io, 0x9c18) != Err(BringUpError::DeviceGone) {
        return TestResult::Fail("removed IQ device was treated as signed measurement");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_iq_coefficients_match_native_c_and_keep_full_width_data
);

fn smoke_ath9k_calibration_policy_span_limits_and_current_cap() -> TestResult {
    use narf_wireless::reg::RegRule;
    let mut domain = RegulatoryDomain {
        country_code: *b"US",
        rules: vec![RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        }],
    };
    if Permission::from_domain(&domain)
        != Ok(Permission {
            country: *b"US",
            ceiling: 34,
        })
    {
        return TestResult::Fail("signed channel1 full-span ceiling changed");
    }
    domain.rules.push(RegRule {
        freq_start_mhz: 2410,
        freq_end_mhz: 2430,
        max_bandwidth_mhz: 20,
        max_power_dbm: 4,
        flags: RegFlags::empty(),
    });
    if Permission::from_domain(&domain).map(|p| p.ceiling) != Ok(8) {
        return TestResult::Fail("overlapping stricter policy was ignored");
    }
    for flag in [RegFlags::DFS, RegFlags::INDOOR_ONLY, RegFlags::NO_IR] {
        domain.rules[1].flags = flag;
        if Permission::from_domain(&domain) != Err(BringUpError::Policy) {
            return TestResult::Fail("unqualified calibration channel was authorized");
        }
    }
    domain.rules[1].flags = RegFlags::empty();
    domain.rules[1].max_power_dbm = -1;
    if Permission::from_domain(&domain) != Err(BringUpError::Policy) {
        return TestResult::Fail("negative power budget wrapped upward");
    }
    domain.rules.clear();
    if Permission::from_domain(&domain) != Err(BringUpError::Policy) {
        return TestResult::Fail("missing policy became transmit permission");
    }
    use narf_bus::{BarKind, BusDeviceCap, MmioRegion};
    use narf_capabilities::{Cap, Write};
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: super::super::phy::REQUIRED_BAR,
        kind: BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let mut registers = Registers::new(region, cap);
    let mut owner = Calibration::default();
    cap.revoke();
    // SAFETY: deliberately invalid mapping is never accessed with revoked cap.
    if ready(unsafe { owner.run(&mut registers, &image(false), permission(), false) })
        != Err(BringUpError::DeviceGone)
    {
        return TestResult::Fail("revoked calibration owner reached native MMIO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/calibration",
    smoke_ath9k_calibration_policy_span_limits_and_current_cap
);
