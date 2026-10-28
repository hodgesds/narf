use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Op {
    Write(u32, u32),
    Poll(u32),
    Delay,
    Master,
}
/// Register model of the RTL8852B HCI DMA stop/busy block.
pub(in crate::rtw89) struct Model {
    registers: BTreeMap<u32, u32>,
    pub(in crate::rtw89) bme: bool,
    pub(in crate::rtw89) tx_busy_reads: u32,
    pub(in crate::rtw89) rx_busy_reads: u32,
    pub(in crate::rtw89) ignore_stop: bool,
    pub(in crate::rtw89) ignore_master: bool,
    pub(in crate::rtw89) busy_after_master: bool,
    pub(in crate::rtw89) gone: bool,
    pub(in crate::rtw89) ops: Vec<Op>,
}
impl Model {
    pub(in crate::rtw89) fn new() -> Self {
        let mut registers = BTreeMap::new();
        // Running station: only CH12 stop clear, HCI and DMA enabled.
        registers.insert(STOP1, 0);
        registers.insert(INIT_CFG1, HCI_EN | 1 << 5);
        registers.insert(HCI_FUNC_EN, 3);
        registers.insert(BUSY1, 0);
        Self {
            registers,
            bme: true,
            tx_busy_reads: 0,
            rx_busy_reads: 0,
            ignore_stop: false,
            ignore_master: false,
            busy_after_master: false,
            gone: false,
            ops: Vec::new(),
        }
    }
    pub(in crate::rtw89) fn word(&self, address: u32) -> u32 {
        self.registers.get(&address).copied().unwrap_or(0)
    }
}
impl Port for Model {
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        if self.gone {
            return Ok(u32::MAX);
        }
        if address != BUSY1 {
            return Ok(self.word(address));
        }
        self.ops.push(Op::Poll(address));
        let mut busy = 0;
        // Independent engines: each busy count drains one per read.
        if self.tx_busy_reads != 0 {
            self.tx_busy_reads -= 1;
            busy |= 1 << 8;
        }
        if self.rx_busy_reads != 0 {
            self.rx_busy_reads -= 1;
            busy |= 2;
        }
        if self.busy_after_master && !self.bme {
            busy |= 1 << 18;
        }
        Ok(busy)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.ops.push(Op::Write(address, value));
        if !(self.ignore_stop && address == STOP1) {
            self.registers.insert(address, value);
        }
        Ok(())
    }
    fn bus_master(&mut self) -> Result<bool, power::Error> {
        if self.gone {
            return Err(power::Error::Gone);
        }
        Ok(self.bme)
    }
    fn clear_bus_master(&mut self) -> Result<(), power::Error> {
        self.ops.push(Op::Master);
        if !self.ignore_master {
            self.bme = false;
        }
        Ok(())
    }
    fn delay_us(&mut self, us: u64) {
        assert_eq!(us, 10);
        self.ops.push(Op::Delay);
    }
}

fn smoke_rtw89_dma_stop_proves_idle_after_linux_order_and_bme_off() -> TestResult {
    let mut model = Model::new();
    // TX idle on the fourth read; RX (draining in parallel) on the seventh.
    model.tx_busy_reads = 3;
    model.rx_busy_reads = 6;
    if stop(&mut model).is_err() {
        return TestResult::Fail("draining engines did not yield the idle proof");
    }
    let master = model.ops.iter().position(|op| *op == Op::Master);
    let last_poll_before = model.ops.iter().rposition(|op| *op == Op::Delay);
    let first_write = model.ops.iter().position(|op| matches!(op, Op::Write(..)));
    if model.word(STOP1) & STOPPED != STOPPED
        || model.word(STOP1) & (1 << 20) == 0
        || model.word(INIT_CFG1) != 1 << 5
        || model.word(HCI_FUNC_EN) != 0
        || model.bme
        || model.ops.iter().filter(|op| **op == Op::Delay).count() != 5
        || first_write != Some(0)
        || master.is_none()
        || last_poll_before.is_none_or(|delay| Some(delay) > master)
        // Flushing re-read behind BME-off.
        || !model.ops[master.unwrap()..].contains(&Op::Poll(BUSY1))
    {
        return TestResult::Fail("stop order, PCIEIO/HCI closure or BME-off flush read differed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/dma_stop",
    smoke_rtw89_dma_stop_proves_idle_after_linux_order_and_bme_off
);

type Case = (fn(&mut Model), Error);
fn smoke_rtw89_dma_stop_busy_ignored_and_gone_keep_dma_pinned() -> TestResult {
    let cases: [Case; 6] = [
        (|m| m.tx_busy_reads = 11, Error::TxBusy),
        (|m| m.rx_busy_reads = 12, Error::RxBusy),
        (|m| m.ignore_stop = true, Error::Ignored),
        (|m| m.ignore_master = true, Error::Master),
        (|m| m.busy_after_master = true, Error::TxBusy),
        (|m| m.gone = true, Error::Register(power::Error::Gone)),
    ];
    for (setup, expected) in cases {
        let mut model = Model::new();
        setup(&mut model);
        let result = stop(&mut model);
        if result.as_ref().err() != Some(&expected) {
            return TestResult::Fail("a stop failure produced the idle proof or a wrong error");
        }
        // BME is always attempted, even after a busy timeout.
        if !model.gone && !model.ops.contains(&Op::Master) {
            return TestResult::Fail("busy engines skipped the BME-off closure");
        }
    }
    // Ten 10us polls still idle on the eleventh read (100us budget).
    let mut model = Model::new();
    model.tx_busy_reads = 10;
    if stop(&mut model).is_err() {
        return TestResult::Fail("read_poll_timeout(10, 100) budget was shorter than Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/dma_stop",
    smoke_rtw89_dma_stop_busy_ignored_and_gone_keep_dma_pinned
);

fn smoke_rtw89_dma_stop_verify_rechecks_master_and_busy() -> TestResult {
    let mut model = Model::new();
    if stop(&mut model).is_err() || verify(&mut model).is_err() {
        return TestResult::Fail("idle stopped function did not verify");
    }
    model.bme = true;
    if verify(&mut model) != Err(Error::Master) {
        return TestResult::Fail("re-enabled BME passed reclamation verification");
    }
    model.bme = false;
    model.registers.insert(INIT_CFG1, HCI_EN);
    if verify(&mut model) != Err(Error::Ignored) {
        return TestResult::Fail("reopened HCI passed reclamation verification");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/dma_stop",
    smoke_rtw89_dma_stop_verify_rechecks_master_and_busy
);
