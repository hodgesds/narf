use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Io {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
}
impl Ath10kMmio for Io {
    fn read32(&mut self, r: u64) -> u32 {
        *self.regs.get(&r).unwrap_or(&0)
    }
    fn write32(&mut self, r: u64, v: u32) {
        self.regs.insert(r, v);
        self.writes.push((r, v));
    }
}
fn reg(io: &Io, r: u64) -> u32 {
    *io.regs.get(&r).unwrap_or(&0)
}

fn smoke_ath10k_irq_program_matches_linux_register_tables() -> TestResult {
    let a = Program::for_hw(HwRev::Qca988x).unwrap();
    let b = Program::for_hw(HwRev::Qca6174).unwrap();
    let c = Program::for_hw(HwRev::Qca9984).unwrap();
    if Program::for_hw(HwRev::Qca9887) != Some(a)
        || Program::for_hw(HwRev::Qca9377) != Some(b)
        || Program::for_hw(HwRev::Qca99x0) != Some(c)
        || Program::for_hw(HwRev::Qca9888) != Some(c)
        || Program::for_hw(HwRev::Ar9462Legacy).is_some()
    {
        return TestResult::Fail("hw.c register-map family selection differs");
    }
    if (a.ce_wrapper, a.intr_clear, a.fw_mask, a.ce_mask_all) != (0x57000, 0x14, 0x400, 0x7f800)
        || (b.ce_wrapper, b.soc_core, b.fw_indicator) != (0x34000, 0x3a000, 0x3a028)
        || (c.ce_wrapper, c.intr_clear, c.fw_mask, c.ce_mask_all)
            != (0x4d000, 0x10, 0x100000, 0xfff00)
        || (c.summary_lsb, c.summary_mask, c.ce_count) != (12, 0xfff000, 12)
        || !a.fw_msi_gate
        || c.fw_msi_gate
    {
        return TestResult::Fail("PCIe interrupt constants differ from Linux hw.c");
    }
    if serviced_pipes(&[2, 3, 4, 5, 8]) != alloc::vec![0, 1, 2, 3, 5, 8]
        || serviced_pipes(&[2, 3, 4]) != alloc::vec![0, 1, 2, 3]
    {
        return TestResult::Fail("CE4 DIS_INTR / CE7 no-callback engines must stay polled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/irq",
    smoke_ath10k_irq_program_matches_linux_register_tables
);

fn smoke_ath10k_irq_enable_then_disable_round_trip() -> TestResult {
    for hw in [HwRev::Qca988x, HwRev::Qca6174, HwRev::Qca9984] {
        let p = Program::for_hw(hw).unwrap();
        let mut io = Io::default();
        // Stale watermark/error enables survive from firmware or a prior owner.
        for pipe in 0..p.ce_count {
            io.regs
                .insert(p.ce(pipe) + ce_off::HOST_IE, HOST_IS_WATERMARK | 0x100);
            io.regs
                .insert(p.ce(pipe) + ce_off::MISC_IE, MISC_IS_ERRORS | 0x1);
        }
        io.regs.insert(p.soc_core, 0x2000);
        p.enable(&mut io, &serviced_pipes(&[2, 3, 4, 5]));
        for pipe in 0..p.ce_count {
            let ie = reg(&io, p.ce(pipe) + ce_off::HOST_IE);
            let want = matches!(pipe, 0 | 1 | 2 | 3 | 5);
            if (ie & HOST_IS_COPY_COMPLETE != 0) != want || ie & HOST_IS_WATERMARK != 0 {
                return TestResult::Fail("per-engine copy-complete enable differs");
            }
            if ie & 0x100 == 0 {
                return TestResult::Fail("unrelated HOST_IE bits must be preserved");
            }
        }
        if reg(&io, p.soc_core + 8) != p.fw_mask | p.ce_mask_all {
            return TestResult::Fail("PCIE_INTR_ENABLE must carry firmware + CE masks");
        }
        let gate = reg(&io, p.soc_core) & CORE_CTRL_PCIE_REG_31 != 0;
        if gate != p.fw_msi_gate || reg(&io, p.soc_core) & 0x2000 == 0 {
            return TestResult::Fail("firmware MSI gate differs from msi_fw_unmask");
        }
        // Teardown: ath10k_pci_irq_disable.
        io.writes.clear();
        p.disable(&mut io);
        for pipe in 0..p.ce_count {
            let ie = reg(&io, p.ce(pipe) + ce_off::HOST_IE);
            let misc = reg(&io, p.ce(pipe) + ce_off::MISC_IE);
            if ie & (HOST_IS_COPY_COMPLETE | HOST_IS_WATERMARK) != 0 || misc & MISC_IS_ERRORS != 0 {
                return TestResult::Fail("teardown left an engine interrupt enabled");
            }
        }
        if reg(&io, p.soc_core + 8) != 0
            || reg(&io, p.soc_core + p.intr_clear) != p.fw_mask | p.ce_mask_all
            || reg(&io, p.soc_core) & CORE_CTRL_PCIE_REG_31 != 0
        {
            return TestResult::Fail("teardown must mask + clear the line and firmware MSI");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/irq",
    smoke_ath10k_irq_enable_then_disable_round_trip
);

fn smoke_ath10k_irq_service_clears_summary_engines_then_rearms() -> TestResult {
    let p = Program::for_hw(HwRev::Qca988x).unwrap();
    let mut io = Io::default();
    io.regs.insert(p.ce_wrapper, (1 << 2 | 1 << 5) << 8);
    if p.begin(&mut io) != Service::Engines(0x24) {
        return TestResult::Fail("summary bitmap not decoded");
    }
    let cleared: Vec<u64> = io
        .writes
        .iter()
        .filter(|(r, v)| r & 0x3ff == 0x30 && *v == 0x1f)
        .map(|(r, _)| *r)
        .collect();
    if cleared != alloc::vec![p.ce(2) + 0x30, p.ce(5) + 0x30] {
        return TestResult::Fail("only summarized engines may have HOST_IS cleared");
    }
    if reg(&io, p.soc_core + 8) != 0 {
        return TestResult::Fail("line must stay masked across ring service");
    }
    // A completion re-asserted while servicing: reschedule, stay masked.
    if !p.finish(&mut io) || reg(&io, p.soc_core + 8) != 0 {
        return TestResult::Fail("re-asserted summary must reschedule without unmask");
    }
    io.regs.insert(p.ce_wrapper, 0);
    if p.finish(&mut io) || reg(&io, p.soc_core + 8) != p.fw_mask | p.ce_mask_all {
        return TestResult::Fail("empty summary must re-enable the line");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/irq",
    smoke_ath10k_irq_service_clears_summary_engines_then_rearms
);

fn smoke_ath10k_irq_firmware_crash_preempts_engine_service() -> TestResult {
    let p = Program::for_hw(HwRev::Qca6174).unwrap();
    let mut io = Io::default();
    io.regs.insert(p.fw_indicator, FW_IND_EVENT_PENDING | 2);
    io.regs.insert(p.ce_wrapper, 0xff00);
    if p.begin(&mut io) != Service::Crashed {
        return TestResult::Fail("crash indicator must be checked before CE service");
    }
    if reg(&io, p.fw_indicator) != 2 || io.writes.len() != 1 {
        return TestResult::Fail("crash clear must only drop EVENT_PENDING");
    }
    if p.take_crash(&mut io) {
        return TestResult::Fail("a cleared crash must not be reported twice");
    }
    // Surprise removal reads all-ones: neither a crash nor engine work.
    io.regs.insert(p.fw_indicator, u32::MAX);
    io.regs.insert(p.ce_wrapper, u32::MAX);
    io.regs.insert(p.soc_core + 0xc, u32::MAX);
    if p.take_crash(&mut io) || p.summary(&mut io) != 0 || p.pending(&mut io) {
        return TestResult::Fail("all-ones reads must not be decoded as events");
    }
    io.regs.insert(p.soc_core + 0xc, 0x400);
    if !p.pending(&mut io) {
        return TestResult::Fail("INTx cause with firmware bit must be pending");
    }
    io.regs.insert(p.soc_core + 0xc, 0x1);
    if p.pending(&mut io) {
        return TestResult::Fail("unrelated cause bits must not claim a shared line");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/irq",
    smoke_ath10k_irq_firmware_crash_preempts_engine_service
);

struct Gate(bool);
impl Future for Gate {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
fn smoke_ath10k_irq_signal_wakes_and_falls_back() -> TestResult {
    let signal = Signal::new();
    let mut cx = Context::from_waker(Waker::noop());
    let seen = signal.count();
    let mut wait = signal.wait(seen, Gate(false));
    if Pin::new(&mut wait).poll(&mut cx) != Poll::Pending {
        return TestResult::Fail("wait without event or timer must pend");
    }
    signal.raise();
    if Pin::new(&mut wait).poll(&mut cx) != Poll::Ready(true) {
        return TestResult::Fail("vector raise must end the wait");
    }
    let seen = signal.count();
    let mut timer = signal.wait(seen, Gate(true));
    if Pin::new(&mut timer).poll(&mut cx) != Poll::Ready(false) {
        return TestResult::Fail("backstop timer must end an idle wait");
    }
    // An edge between sampling and waiting is never lost.
    signal.raise();
    let mut late = signal.wait(seen, Gate(false));
    if Pin::new(&mut late).poll(&mut cx) != Poll::Ready(true) {
        return TestResult::Fail("raise after sampling must not be lost");
    }
    if fallback_ms(true) != 10 || fallback_ms(false) != 1 {
        return TestResult::Fail("polled owners must keep the 1 ms service period");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/irq",
    smoke_ath10k_irq_signal_wakes_and_falls_back
);
