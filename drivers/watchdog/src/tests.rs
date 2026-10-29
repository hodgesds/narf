//! Smokes for the watchdog class + iTCO driver.
//!
//! The fixture is a panel-side TCO model: [`FakeTco`] implements
//! the documented TCO state machine (EDC ID 834819) over a byte
//! array, driven by explicit `tick()` calls (test-driven time).
//! Production code only ever reads/writes registers; the model
//! owns the countdown, the first-timeout latch, and the
//! second-timeout latch, so the smokes prove the conversation
//! end-to-end rather than mirroring production's own writes.

#[cfg(any(test, feature = "kernel-test"))]
mod smokes {
    extern crate alloc;

    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::fmt::Debug;

    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    use crate::class::__reset_for_test as wd_reset;
    use crate::class::{
        register_watchdog, unregister_watchdog, watchdog_device, watchdog_devices, WatchdogDevice,
    };
    use crate::itco::{ItcoWatchdog, PortIo};

    // ── Fake TCO block ────────────────────────────────────────────

    /// One recorded register write: (block offset, wide?, value).
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    struct Write {
        off: u16,
        wide: bool,
        val: u16,
    }

    struct FakeState {
        regs: [u8; 0x20],
        reload: u16,
        count: u16,
        expired_once: bool,
        writes: Vec<Write>,
    }

    /// Fake TCO block. Register behaviour follows EDC ID 834819:
    /// RLD read = current count, RLD write = reload from TMR;
    /// STS1 is RW/1C; TMR values 0/1 are ignored; the first
    /// countdown expiry latches TIMEOUT and auto-reloads, and a
    /// second expiry without an intervening RLD write latches
    /// SECOND_TO_STS.
    struct FakeTco {
        base: u16,
        state: IrqSafeSpinLock<FakeState>,
    }

    impl Debug for FakeTco {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("FakeTco").field("base", &self.base).finish()
        }
    }

    const FAKE_TMR_HLT: u16 = 0x0800;
    const FAKE_TIMEOUT: u16 = 0x0008;
    const FAKE_SECOND_TO: u8 = 0x02;

    impl FakeTco {
        fn new(base: u16) -> Self {
            let mut regs = [0u8; 0x20];
            // Power-on state: timer halted, reload default 4 (EDC).
            regs[0x08] = (FAKE_TMR_HLT & 0xff) as u8;
            regs[0x09] = (FAKE_TMR_HLT >> 8) as u8;
            Self {
                base,
                state: IrqSafeSpinLock::new(FakeState {
                    regs,
                    reload: 4,
                    count: 0,
                    expired_once: false,
                    writes: Vec::new(),
                }),
            }
        }

        fn off(&self, port: u16) -> Option<u16> {
            let off = port.wrapping_sub(self.base);
            if off < 0x20 {
                Some(off)
            } else {
                None
            }
        }

        fn read_reg_u16(&self, off: u16) -> u16 {
            let s = self.state.lock();
            match off {
                // RLD read returns the live countdown, not the image.
                0x00 => s.count & 0x03ff,
                0x12 => s.reload,
                _ => u16::from_le_bytes([s.regs[off as usize], s.regs[off as usize + 1]]),
            }
        }

        /// Advance the model by one ~0.6s tick.
        fn tick(&self) {
            let mut s = self.state.lock();
            let cnt = u16::from_le_bytes([s.regs[0x08], s.regs[0x09]]);
            if cnt & FAKE_TMR_HLT != 0 {
                return;
            }
            if s.count == 0 {
                return;
            }
            s.count -= 1;
            if s.count == 0 {
                if !s.expired_once {
                    s.expired_once = true;
                    let sts = u16::from_le_bytes([s.regs[0x04], s.regs[0x05]]) | FAKE_TIMEOUT;
                    s.regs[0x04] = (sts & 0xff) as u8;
                    s.regs[0x05] = (sts >> 8) as u8;
                    s.count = s.reload;
                } else {
                    s.regs[0x06] |= FAKE_SECOND_TO;
                }
            }
        }

        fn ticks(&self, n: u32) {
            for _ in 0..n {
                self.tick();
            }
        }

        fn writes(&self) -> Vec<Write> {
            self.state.lock().writes.clone()
        }

        fn cnt1(&self) -> u16 {
            let s = self.state.lock();
            u16::from_le_bytes([s.regs[0x08], s.regs[0x09]])
        }

        fn sts1(&self) -> u16 {
            let s = self.state.lock();
            u16::from_le_bytes([s.regs[0x04], s.regs[0x05]])
        }

        fn sts2(&self) -> u8 {
            self.state.lock().regs[0x06]
        }

        fn reload(&self) -> u16 {
            self.state.lock().reload
        }

        fn count(&self) -> u16 {
            self.state.lock().count
        }

        /// Test setup: force status-register contents directly.
        fn set_sts(&self, sts1: u16, sts2: u8) {
            let mut s = self.state.lock();
            s.regs[0x04] = (sts1 & 0xff) as u8;
            s.regs[0x05] = (sts1 >> 8) as u8;
            s.regs[0x06] = sts2;
        }
    }

    impl PortIo for FakeTco {
        fn read_u8(&self, port: u16) -> u8 {
            let Some(off) = self.off(port) else {
                return 0xff;
            };
            let s = self.state.lock();
            s.regs[off as usize]
        }

        fn write_u8(&self, port: u16, val: u8) {
            let Some(off) = self.off(port) else {
                return;
            };
            let mut s = self.state.lock();
            s.regs[off as usize] = val;
            s.writes.push(Write {
                off,
                wide: false,
                val: val as u16,
            });
        }

        fn read_u16(&self, port: u16) -> u16 {
            let Some(off) = self.off(port) else {
                return 0xffff;
            };
            self.read_reg_u16(off)
        }

        fn write_u16(&self, port: u16, val: u16) {
            let Some(off) = self.off(port) else {
                return;
            };
            let mut s = self.state.lock();
            s.writes.push(Write {
                off,
                wide: true,
                val,
            });
            match off {
                // Any value reloads; the pending second timeout is
                // averted, but latched status bits are untouched
                // (software clears those via STS1).
                0x00 => {
                    s.count = s.reload;
                    s.expired_once = false;
                }
                // RW/1C: set bits clear, zero bits preserve.
                0x04 => {
                    let cur = u16::from_le_bytes([s.regs[0x04], s.regs[0x05]]) & !val;
                    s.regs[0x04] = (cur & 0xff) as u8;
                    s.regs[0x05] = (cur >> 8) as u8;
                }
                0x06 => {
                    s.regs[0x06] &= !val as u8;
                }
                0x08 => {
                    s.regs[0x08] = (val & 0xff) as u8;
                    s.regs[0x09] = (val >> 8) as u8;
                }
                // EDC: TMR values 0/1 are ignored.
                0x12 => {
                    let v = val & 0x03ff;
                    if v >= 2 {
                        s.reload = v;
                    }
                }
                _ => {
                    s.regs[off as usize] = (val & 0xff) as u8;
                    s.regs[off as usize + 1] = (val >> 8) as u8;
                }
            }
        }
    }

    fn wddt(base: u64, min: u16, max: u16) -> narf_acpi::WddtInfo {
        narf_acpi::WddtInfo {
            timer_max_count: max,
            timer_min_count: min,
            period_us: 0,
            status: 0,
            capability: 0,
            base,
        }
    }

    fn dev(base: u16) -> (Arc<FakeTco>, Arc<ItcoWatchdog<FakePort>>) {
        let fake = Arc::new(FakeTco::new(base));
        let itco = ItcoWatchdog::probe_from_info(wddt(base as u64, 0, 0), FakePort(fake.clone()))
            .expect("probe with a valid base");
        (fake, itco)
    }

    /// `FakeTco` behind `Arc` still implements `PortIo` (the trait
    /// takes `&self`, and `Arc<T: PortIo>` forwards automatically
    /// only via a manual impl — so wrap it explicitly).
    struct FakePort(Arc<FakeTco>);

    impl Debug for FakePort {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_tuple("FakePort").field(&self.0.base).finish()
        }
    }

    impl PortIo for FakePort {
        fn read_u8(&self, port: u16) -> u8 {
            self.0.read_u8(port)
        }
        fn write_u8(&self, port: u16, val: u8) {
            self.0.write_u8(port, val)
        }
        fn read_u16(&self, port: u16) -> u16 {
            self.0.read_u16(port)
        }
        fn write_u16(&self, port: u16, val: u16) {
            self.0.write_u16(port, val)
        }
    }

    // ── 1. Registry add / remove / lookup ──────────────────────────

    fn smoke_registry_add_remove_lookup() -> TestResult {
        wd_reset();
        let (_fake, itco) = dev(0x0400);
        register_watchdog(itco.clone());
        if watchdog_device("watchdog0").is_none() {
            return TestResult::Fail("registered device not found by name");
        }
        if watchdog_devices().len() != 1 {
            return TestResult::Fail("registry snapshot length wrong");
        }
        register_watchdog(itco);
        if watchdog_devices().len() != 1 {
            return TestResult::Fail("duplicate name did not replace");
        }
        unregister_watchdog("watchdog0");
        if watchdog_device("watchdog0").is_some() {
            return TestResult::Fail("unregistered device still found");
        }
        wd_reset();
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_registry_add_remove_lookup);

    // ── 2. Probe rejects unusable bases ────────────────────────────

    fn smoke_probe_rejects_bad_base() -> TestResult {
        let fake = FakeTco::new(0x0400);
        if ItcoWatchdog::probe_from_info(wddt(0, 0, 0), FakePort(Arc::new(fake))).is_some() {
            return TestResult::Fail("zero base probed");
        }
        let fake = FakeTco::new(0x0400);
        if ItcoWatchdog::probe_from_info(wddt(0x1_0000, 0, 0), FakePort(Arc::new(fake))).is_some() {
            return TestResult::Fail("out-of-port-space base probed");
        }
        let fake = Arc::new(FakeTco::new(0x0400));
        let got = ItcoWatchdog::probe_from_info(wddt(0x0400, 0, 0), FakePort(fake))
            .expect("valid base must probe");
        if got.base() != 0x0400 || got.tick_range() != (2, 1023) {
            return TestResult::Fail("probe base/range mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_probe_rejects_bad_base);

    // ── 3. set_timeout write transcript, byte-for-byte ─────────────

    fn smoke_set_timeout_transcript() -> TestResult {
        let (fake, itco) = dev(0x0400);
        // 30s -> ceil(30 / 0.6) = 50 ticks = 0x32.
        if itco.set_timeout(30).is_err() {
            return TestResult::Fail("30s rejected");
        }
        let want = [
            Write {
                off: 0x04,
                wide: true,
                val: 0x0008,
            },
            Write {
                off: 0x12,
                wide: true,
                val: 0x0032,
            },
            Write {
                off: 0x08,
                wide: true,
                val: 0x0000,
            },
            Write {
                off: 0x00,
                wide: true,
                val: 0x0000,
            },
        ];
        if fake.writes().as_slice() != want {
            return TestResult::Fail("set_timeout transcript mismatch");
        }
        if fake.cnt1() & FAKE_TMR_HLT != 0 || fake.count() != 50 || fake.reload() != 50 {
            return TestResult::Fail("timer not armed at 50 ticks");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_set_timeout_transcript);

    // ── 4. Timeout validation + WDDT bounds ────────────────────────

    fn smoke_timeout_validation() -> TestResult {
        let (_fake, itco) = dev(0x0400);
        if itco.set_timeout(0).is_ok() {
            return TestResult::Fail("0s accepted");
        }
        if itco.set_timeout(614).is_ok() {
            return TestResult::Fail("614s accepted (1024 ticks)");
        }
        if itco.set_timeout(613).is_err() {
            return TestResult::Fail("613s rejected (1022 ticks)");
        }
        if itco.set_timeout(1).is_err() {
            return TestResult::Fail("1s rejected (2 ticks)");
        }
        // WDDT bounds [100, 200] ticks: 30s (50) too small,
        // 90s (150) fine, 150s (250) too big.
        let fake = Arc::new(FakeTco::new(0x0400));
        let bounded =
            ItcoWatchdog::probe_from_info(wddt(0x0400, 100, 200), FakePort(fake)).expect("probe");
        if bounded.set_timeout(30).is_ok()
            || bounded.set_timeout(150).is_ok()
            || bounded.set_timeout(90).is_err()
        {
            return TestResult::Fail("WDDT bound enforcement wrong");
        }
        // Degenerate WDDT ranges fall back to the EDC range.
        let fake = Arc::new(FakeTco::new(0x0400));
        let fallback =
            ItcoWatchdog::probe_from_info(wddt(0x0400, 500, 100), FakePort(fake)).expect("probe");
        if fallback.tick_range() != (2, 1023) {
            return TestResult::Fail("inverted WDDT range did not fall back");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_timeout_validation);

    // ── 5. Pet clears ONLY the TIMEOUT bit (masking-defeating) ─────

    fn smoke_pet_clears_only_timeout() -> TestResult {
        let (fake, itco) = dev(0x0400);
        if itco.set_timeout(30).is_err() {
            return TestResult::Fail("arm failed");
        }
        // TIMEOUT | CPUSMI | BIOSWR: a blanket STS1 clear would
        // wipe all three; the driver must clear only TIMEOUT.
        fake.set_sts(0x010a, 0x00);
        itco.pet();
        if fake.sts1() != 0x0102 {
            return TestResult::Fail("pet cleared bits outside TIMEOUT");
        }
        // And the reload happened (count back at the armed value).
        if fake.count() != 50 {
            return TestResult::Fail("pet did not reload");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_pet_clears_only_timeout);

    // ── 6. Full arm / pet / expire conversation ────────────────────

    fn smoke_arm_pet_expire_conversation() -> TestResult {
        let (fake, itco) = dev(0x0400);
        if itco.set_timeout(30).is_err() {
            return TestResult::Fail("arm failed");
        }
        fake.ticks(50);
        if fake.sts1() & FAKE_TIMEOUT == 0 || fake.sts2() & FAKE_SECOND_TO != 0 {
            return TestResult::Fail("first expiry did not latch TIMEOUT alone");
        }
        itco.pet();
        if fake.sts1() & FAKE_TIMEOUT != 0 {
            return TestResult::Fail("pet did not clear TIMEOUT");
        }
        fake.ticks(50);
        if fake.sts2() & FAKE_SECOND_TO != 0 {
            return TestResult::Fail("pet did not avert the second timeout");
        }
        // No pet now: the next full countdown is a second expiry.
        fake.ticks(50);
        if fake.sts2() & FAKE_SECOND_TO == 0 {
            return TestResult::Fail("second expiry did not latch SECOND_TO_STS");
        }
        let st = itco.status();
        if !st.armed || !st.timed_out || !st.second_timeout {
            return TestResult::Fail("status does not report the double expiry");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_arm_pet_expire_conversation);

    // ── 7. Stop halts; timeleft tracks the countdown ───────────────

    fn smoke_stop_halts_and_timeleft() -> TestResult {
        let (fake, itco) = dev(0x0400);
        if itco.set_timeout(30).is_err() {
            return TestResult::Fail("arm failed");
        }
        fake.ticks(10);
        // 40 ticks left -> 40 * 0.6 = 24s.
        if itco.status().timeleft_secs != 24 || !itco.status().armed {
            return TestResult::Fail("timeleft/armed wrong mid-countdown");
        }
        itco.stop();
        if fake.cnt1() & FAKE_TMR_HLT == 0 || itco.status().armed {
            return TestResult::Fail("stop did not halt");
        }
        fake.ticks(50);
        if itco.status().timeleft_secs != 24 {
            return TestResult::Fail("halted timer kept counting");
        }
        // Re-arm works after a stop.
        if itco.set_timeout(30).is_err() || !itco.status().armed {
            return TestResult::Fail("re-arm after stop failed");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_stop_halts_and_timeleft);

    // ── 8. Preset status bits read back (cross-check) ──────────────

    fn smoke_preset_status_readback() -> TestResult {
        let (fake, itco) = dev(0x0400);
        fake.set_sts(0x0008, 0x02);
        let st = itco.status();
        if !st.timed_out || !st.second_timeout {
            return TestResult::Fail("preset status bits not reported");
        }
        if st.no_reboot_control {
            return TestResult::Fail("driver claims NO_REBOOT control it lacks");
        }
        fake.set_sts(0x0000, 0x00);
        let st = itco.status();
        if st.timed_out || st.second_timeout {
            return TestResult::Fail("cleared status bits still reported");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_preset_status_readback);

    // ── 9. TMR ignores 0/1 (EDC rule, model-level) ──────────────────

    fn smoke_tmr_ignores_zero_and_one() -> TestResult {
        let fake = FakeTco::new(0x0400);
        fake.write_u16(0x0400 + 0x12, 1);
        if fake.reload() != 4 {
            return TestResult::Fail("TMR write of 1 changed the reload value");
        }
        fake.write_u16(0x0400 + 0x12, 0);
        if fake.reload() != 4 {
            return TestResult::Fail("TMR write of 0 changed the reload value");
        }
        fake.write_u16(0x0400 + 0x12, 50);
        if fake.reload() != 50 {
            return TestResult::Fail("TMR write of 50 did not stick");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_tmr_ignores_zero_and_one);

    // ── 10. Disarmed status: no timeleft, no latches ───────────────

    fn smoke_disarmed_status() -> TestResult {
        let (_fake, itco) = dev(0x0400);
        let st = itco.status();
        if st.armed || st.timed_out || st.second_timeout || st.timeleft_secs != 0 {
            return TestResult::Fail("fresh device reports live state");
        }
        // Petting a disarmed device is harmless.
        itco.pet();
        if itco.status().armed {
            return TestResult::Fail("pet armed a disarmed device");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/watchdog", smoke_disarmed_status);
}
