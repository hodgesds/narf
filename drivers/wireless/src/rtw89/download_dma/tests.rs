use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Case {
    chip: ChipId,
    init: u32,
    tx: u32,
    rx: u32,
    hci: u32,
    tx_internal: u32,
    rx_internal: u32,
    io_address: u32,
    io_stop: u32,
    stop_address: u32,
    channels: u32,
    wpdma: u32,
    fw: u32,
}
include!("golden.rs");
struct Model {
    memory: Vec<u32>,
    writes: Vec<(u32, u32)>,
    operations: usize,
    fail: Option<usize>,
    ignore: Option<usize>,
    gone: bool,
}
impl Model {
    fn new(case: &Case, seed: u32) -> Self {
        let mut memory = vec![seed; 16384];
        memory[case.init as usize / 4] &= !(case.tx | case.rx);
        memory[case.stop_address as usize / 4] |= case.channels | case.wpdma;
        memory[case.io_address as usize / 4] |= case.io_stop;
        memory[case.hci as usize / 4] &= !(case.tx_internal | case.rx_internal);
        Self {
            memory,
            writes: Vec::new(),
            operations: 0,
            fail: None,
            ignore: None,
            gone: false,
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        let at = self.operations;
        self.operations += 1;
        if self.fail == Some(at) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
}
impl Io for Model {
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.access()?;
        if self.gone {
            Ok(u32::MAX)
        } else {
            Ok(self.memory[a as usize / 4])
        }
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.access()?;
        let n = self.writes.len();
        self.writes.push((a, v));
        if self.ignore != Some(n) {
            self.memory[a as usize / 4] = v;
        }
        Ok(())
    }
    fn read8(&mut self, _: u32) -> Result<u8, Error> {
        panic!("download DMA uses complete dwords")
    }
    fn read16(&mut self, _: u32) -> Result<u16, Error> {
        panic!("download DMA uses complete dwords")
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), Error> {
        panic!("download DMA uses complete dwords")
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), Error> {
        panic!("download DMA uses complete dwords")
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {
        panic!("synchronous preparation cannot retain a wait")
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Err(Error::Unsupported)
    }
}
fn smoke_rtw89_download_activation_keeps_every_rx_and_packet_channel_closed() -> TestResult {
    for case in CASES {
        for seed in [0, 0xa5a5a5a5] {
            let mut model = Model::new(case, seed);
            if prepare(&mut model, case.chip) != Ok(()) {
                return TestResult::Fail("CH12 preparation rejected actual Linux profile");
            }
            let init = model.memory[case.init as usize / 4];
            let stop = model.memory[case.stop_address as usize / 4];
            let hci = model.memory[case.hci as usize / 4];
            if init & (case.tx | case.rx) != case.tx
                || stop & case.channels != case.channels & !case.fw
                || stop & case.wpdma == 0
                || model.memory[case.io_address as usize / 4] & case.io_stop != 0
                || hci & (case.tx_internal | case.rx_internal) != case.tx_internal
            {
                return TestResult::Fail(
                    "download activation enabled RX/packet DMA or used wrong TX bit",
                );
            }
            for &(address, value) in &model.writes {
                if address == case.init && value & case.rx != 0
                    || address == case.hci && value & case.rx_internal != 0
                {
                    return TestResult::Fail(
                        "download activation transiently enabled unowned RX DMA",
                    );
                }
            }
            if model.writes.iter().any(|(address, _)| {
                ![case.init, case.hci, case.stop_address, case.io_address].contains(address)
            }) {
                return TestResult::Fail(
                    "download activation touched ring/IRQ/publication registers",
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_download_activation_keeps_every_rx_and_packet_channel_closed
);
fn smoke_rtw89_download_activation_errors_ignored_writes_and_dirty_state_fail() -> TestResult {
    for case in CASES {
        let mut baseline = Model::new(case, 0);
        if prepare(&mut baseline, case.chip) != Ok(()) {
            return TestResult::Fail("download DMA negative baseline");
        }
        for failure in 0..baseline.operations {
            let mut model = Model::new(case, 0);
            model.fail = Some(failure);
            if prepare(&mut model, case.chip).is_ok() {
                return TestResult::Fail("download activation ignored register failure");
            }
        }
        for ignored in 0..baseline.writes.len() {
            let mut model = Model::new(case, 0);
            model.ignore = Some(ignored);
            if prepare(&mut model, case.chip).is_ok() {
                return TestResult::Fail("download activation ignored missing programming");
            }
        }
        let mut model = Model::new(case, 0);
        model.memory[case.init as usize / 4] |= case.rx;
        if prepare(&mut model, case.chip) != Err(Error::Access) || !model.writes.is_empty() {
            return TestResult::Fail("active inherited RX was accepted as prepared");
        }
        let mut model = Model::new(case, 0);
        model.memory[case.stop_address as usize / 4] &= !case.wpdma;
        if prepare(&mut model, case.chip) != Err(Error::Access) || !model.writes.is_empty() {
            return TestResult::Fail("unfenced inherited WPDMA was accepted");
        }
        let mut model = Model::new(case, 0);
        model.gone = true;
        if prepare(&mut model, case.chip) != Err(Error::Gone) || !model.writes.is_empty() {
            return TestResult::Fail("download DMA disappearance was ignored");
        }
    }
    let mut model = Model::new(&CASES[0], 0);
    if prepare(&mut model, ChipId::Rtl8922A) != Err(Error::Unsupported) || model.operations != 0 {
        return TestResult::Fail("BE used AX download activation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_download_activation_errors_ignored_writes_and_dirty_state_fail
);
