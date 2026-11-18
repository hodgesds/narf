//! RAM-only actual ANI control/counter regressions; no RF measurement claim.
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Model {
    regs: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    now: Cell<u64>,
    ignore: Cell<Option<u64>>,
}
impl Model {
    fn new() -> Self {
        let model = Self {
            regs: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
            now: Cell::new(0),
            ignore: Cell::new(None),
        };
        for (r, v) in [
            (0x9824, 0x1234000c),
            (0x9828, 0x03456701),
            (0x982c, 0x01234567),
            (0x9e10, 7 << 12),
            (0x9820, 5 << 6),
            (0x9810, 20 << 1),
            (0x9830, 19 << 9),
            (0x9fd0, 3),
        ] {
            model.regs.borrow_mut().insert(r, v);
        }
        model
    }
    fn observe(&self, ofdm: u32, cck: u32) {
        self.now.set(self.now.get() + 1_000_000);
        for (r, v) in [
            (0x80f8, 44_000_000),
            (0x80f4, 9),
            (0x80f0, 0),
            (0x80ec, 0),
            (0x812c, ofdm),
            (0x8134, cck),
        ] {
            self.regs.borrow_mut().insert(r, v);
        }
    }
}
impl Io for Model {
    fn read(&self, r: u64) -> Result<u32, Error> {
        Ok(*self.regs.borrow().get(&r).unwrap_or(&0))
    }
    fn write(&self, r: u64, v: u32) -> Result<(), Error> {
        self.writes.borrow_mut().push((r, v));
        if self.ignore.get() != Some(r) {
            self.regs.borrow_mut().insert(r, v);
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now.get()
    }
    fn delay_us(&self, _: u64) {}
}
fn checked(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    match f() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn smoke_ar9003_ani_actual_counter_source_levels_relative_ini_and_chip_controls() -> TestResult {
    checked(|| {
        for device in [0x0032, 0x0034, 0x0036] {
            let io = Model::new();
            let ini = Settings::read(&io, device).map_err(|_| "ANI initial source snapshot")?;
            let mut owner = Owner::begin(&io, device, if device == 0x0034 { 3 } else { 1 }, ini)
                .map_err(|_| "actual ANI begin")?;
            owner.beacon(80);
            io.writes.borrow_mut().clear();
            for _ in 0..6 {
                io.observe(5000, 0);
                owner
                    .service(&io)
                    .map_err(|_| "actual high OFDM counter service")?;
            }
            if owner.levels.ofdm != 9
                || owner.levels.weak
                || owner.current.0[3] >> 12 != 19
                || owner.current.0[5] >> 1 != 22
                || owner.current.0[6] >> 9 != 22
                || io.read(0x9828).unwrap() & 1 != 0
            {
                return Err("AR9003 levels/relative INI clamps/weak gate wrong");
            }
            if device == 0x0032 {
                if owner.current.0[0] != (127 << 17) | (127 << 24) | 31 {
                    return Err("AR9485 source weak thresholds missing");
                }
            } else if io
                .writes
                .borrow()
                .iter()
                .any(|(r, _)| matches!(r, 0x9824 | 0x982c))
            {
                return Err("9462/9565 borrowed9485 weak threshold writes");
            }
            if io.writes.borrow().iter().any(|(r, _)| *r == 0x9fd0) {
                return Err("OFDM altered MRC CCK");
            }
            // No synthesized listen sample: zero cycles restarts counters,
            // even when a large error count was actually observed.
            io.observe(5000, 0);
            io.regs.borrow_mut().insert(0x80f8, 0);
            owner
                .service(&io)
                .map_err(|_| "source zero-listen restart")?;
            if owner.levels.ofdm != 9 || owner.ofdm_errors != 0 || io.read(0x812c).unwrap() != 0 {
                return Err("zero listen fabricated an ANI period");
            }
        }
        for (device, rx) in [(0x0034, 3), (0x0034, 1), (0x0032, 1), (0x0036, 1)] {
            let io = Model::new();
            let ini = Settings::read(&io, device).unwrap();
            let mut owner = Owner::begin(&io, device, rx, ini).unwrap();
            owner.beacon(80);
            io.writes.borrow_mut().clear();
            for _ in 0..2 {
                io.observe(1000, 1000);
                owner.service(&io).map_err(|_| "actual CCK trigger")?;
            }
            let mrc = io
                .writes
                .borrow()
                .iter()
                .any(|(r, v)| *r == 0x9fd0 && v & 3 == 0);
            if owner.levels.cck != 4 || mrc != (device == 0x0034 && rx != 1) {
                return Err("chip/RX-cap specific source MRC control wrong");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ar9003_ani_actual_counter_source_levels_relative_ini_and_chip_controls
);

fn smoke_ar9003_ani_ignored_program_and_current_p_latch_are_terminal() -> TestResult {
    checked(|| {
        let _policy = crate::ath9k::ht::tests::Policy::install();
        let id = super::super::antenna::tests::device();
        let (_, grant, _) =
            super::super::antenna::tests::fixture(id, 0).map_err(|_| "P original N48A fixture")?;
        let (image, _) = super::super::antenna::tests::factory(0);
        let domain = narf_wireless::reg::db::snapshot().ok_or("P policy")?;
        let permission = crate::ath9k::calibration::Permission::from_domain_dual(&domain, 2412)
            .map_err(|_| "P host")?
            .with_ceiling(0);
        let report = super::super::calib::Report {
            frequency_mhz: 2412,
            five_ghz: false,
            rx_chainmask: 1,
            tx_chainmask: 1,
            peak_caldac: [None; 3],
            carrier_leak: None,
            default_nf: [-95; 3],
            tx_iq_cal: None,
            tx_iq_cal_enabled: false,
            tx_clcal: None,
        };
        let plan =
            super::super::power::plan(&image, 2412, 0x12, 0, 1).map_err(|_| "P source plan")?;
        let io = Model::new();
        let ini = Settings::read(&io, 0x0032).unwrap();
        let base = Base::new(grant, permission, &report, &plan, ini)
            .map_err(|_| "P actual completed binding")?;
        let cap = narf_capabilities::Cap::bootstrap();
        let source =
            qualification::synthetic(base.clone(), cap).map_err(|_| "P distinct format")?;
        let latch = super::super::antenna::manual::Latch::new();
        let old = latch.clone();
        latch
            .install_ani(source)
            .map_err(|_| "P install before native effect")?;
        let mut owner = latch
            .current(true, || Owner::begin(&io, 0x0032, 1, ini))
            .map_err(|_| "actual joint P start")?;
        if !latch.retained() || latch.bound() || !latch.ani_bound() {
            return Err("P aliased D setting or lost terminal retention");
        }
        io.observe(5000, 0);
        io.ignore.set(Some(0x9810));
        if old.current(true, || owner.service(&io)).is_ok()
            || latch.current(true, || Ok(())).is_ok()
        {
            return Err("ignored ANI program became live current receipt");
        }
        let before = io.writes.borrow().len();
        cap.revoke();
        if old.current(true, || io.write(0x9810, 0)).is_ok() || io.writes.borrow().len() != before {
            return Err("captured publication/source token bypassed revoked P");
        }
        // Independent healthy latch: this refusal must come from the real
        // P capability, rather than the ignored-write failure above.
        let cap = narf_capabilities::Cap::bootstrap();
        let source = qualification::synthetic(base, cap).map_err(|_| "fresh P distinct format")?;
        let latch = super::super::antenna::manual::Latch::new();
        let old = latch.clone();
        latch.install_ani(source).map_err(|_| "healthy P install")?;
        old.current(true, || Ok(()))
            .map_err(|_| "healthy original captured token")?;
        cap.revoke();
        if old.current(true, || io.write(0x9810, 0)).is_ok()
            || io.writes.borrow().len() != before
            || !latch.retained()
        {
            return Err("actual P revoke reached effects or discarded the retained source");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ar9003_ani_ignored_program_and_current_p_latch_are_terminal
);
