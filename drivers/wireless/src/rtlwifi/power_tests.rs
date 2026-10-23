use super::*;
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Op {
    Read(u16),
    Write(u16, u8),
    Delay(u64),
}
struct Model {
    bytes: Vec<u8>,
    trace: Vec<Op>,
    fail: Option<usize>,
}
struct Fake(IrqSafeSpinLock<Model>);
impl Fake {
    fn new() -> Self {
        let mut bytes = vec![0xa5; 256];
        bytes[5] = 0xfe; // HWPDN + both suspend bits, unrelated bits retained.
        bytes[6] = 0xb2; // Power ready; WLON reset bit initially zero.
        bytes[2] = 0xff;
        bytes[0x26] = 0x45;
        bytes[0x23] = 0xf7;
        Self(IrqSafeSpinLock::new(Model {
            bytes,
            trace: Vec::new(),
            fail: None,
        }))
    }
}
impl Io for Fake {
    fn read8(&self, offset: u16) -> Result<u8, PwrSeqError> {
        let mut m = self.0.lock();
        let fail = m.fail == Some(m.trace.len());
        m.trace.push(Op::Read(offset));
        if fail {
            return Err(PwrSeqError::Access);
        }
        // The requested MAC state transition completes in hardware before
        // its next read; the fixture does not clear any unrelated bit.
        if offset == 5 && m.bytes[5] & 1 != 0 {
            m.bytes[5] &= !1;
        }
        Ok(m.bytes[usize::from(offset)])
    }
    fn write8(&self, offset: u16, value: u8) -> Result<(), PwrSeqError> {
        let mut m = self.0.lock();
        let fail = m.fail == Some(m.trace.len());
        m.trace.push(Op::Write(offset, value));
        if fail {
            return Err(PwrSeqError::Access);
        }
        m.bytes[usize::from(offset)] = value;
        Ok(())
    }
    fn delay_us(&self, micros: u64) {
        self.0.lock().trace.push(Op::Delay(micros));
    }
}
fn run(io: &Fake, table: &[WlanPwrCfg]) -> Result<(), PwrSeqError> {
    run_with(io, PWR_CUT_A_MSK, PWR_FAB_TSMC_MSK, PWR_INTF_PCI_MSK, table)
}
fn smoke_rtlwifi_8188ee_complete_enable_flow() -> TestResult {
    let io = Fake::new();
    if run(&io, RTL8188EE_PWR_ON).is_err() {
        return TestResult::Fail("complete enable flow rejected");
    }
    let m = io.0.lock();
    // Literal result of Linux RTL8188EE_NIC_ENABLE_FLOW PCI rows, from
    // CardDisabled through BB reset, Schmitt, state request and LDO-normal.
    let expected = vec![
        Op::Read(5),
        Op::Write(5, 0xe6),
        Op::Read(6),
        Op::Read(2),
        Op::Write(2, 0xfc),
        Op::Read(0x26),
        Op::Write(0x26, 0xc5),
        Op::Read(5),
        Op::Write(5, 0x66),
        Op::Read(5),
        Op::Write(5, 0x66),
        Op::Read(5),
        Op::Write(5, 0x67),
        Op::Read(5),
        Op::Read(0x23),
        Op::Write(0x23, 0xe7),
    ];
    if m.trace != expected || m.bytes[6] != 0xb2 || m.bytes[2] != 0xfc {
        return TestResult::Fail(
            "PCI enable sequence differs from source or clobbers reserved fields",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/power",
    smoke_rtlwifi_8188ee_complete_enable_flow
);

fn smoke_rtlwifi_power_access_failure_stops_exact_row() -> TestResult {
    let success = Fake::new();
    run(&success, RTL8188EE_PWR_ON).unwrap();
    let expected = success.0.lock().trace.clone();
    for at in 0..expected.len() {
        let io = Fake::new();
        io.0.lock().fail = Some(at);
        if run(&io, RTL8188EE_PWR_ON) != Err(PwrSeqError::Access)
            || io.0.lock().trace != expected[..=at]
        {
            return TestResult::Fail("failed read/write dispatched later power rows");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/power",
    smoke_rtlwifi_power_access_failure_stops_exact_row
);

fn smoke_rtlwifi_power_filters_bases_and_requires_end() -> TestResult {
    let skip = WlanPwrCfg::new(
        0x77,
        PWR_CUT_A_MSK,
        PWR_FAB_TSMC_MSK,
        PWR_INTF_SDIO_MSK,
        PWR_BASEADDR_SDIO,
        PWR_CMD_WRITE,
        0xff,
        0,
    );
    let io = Fake::new();
    if run(&io, &[skip, pci_end()]).is_err() || !io.0.lock().trace.is_empty() {
        return TestResult::Fail("PCI parser executed SDIO row");
    }
    if run(&io, &[]) != Err(PwrSeqError::BadCmd)
        || run(
            &io,
            &[
                WlanPwrCfg::new(0, 0xff, 0xf, 4, PWR_BASEADDR_SDIO, PWR_CMD_WRITE, 1, 1),
                pci_end(),
            ],
        ) != Err(PwrSeqError::BadCmd)
        || run(
            &io,
            &[
                WlanPwrCfg::new(0, 0xff, 0xf, 4, 0, PWR_CMD_DELAY, 0, 2),
                pci_end(),
            ],
        ) != Err(PwrSeqError::BadCmd)
        || !io.0.lock().trace.is_empty()
    {
        return TestResult::Fail("invalid base/delay/missing-END succeeded or touched registers");
    }
    let delay = WlanPwrCfg::new(7, 0xff, 0xf, 4, 0, PWR_CMD_DELAY, 0, PWRSEQ_DELAY_MS);
    if run(&io, &[delay, pci_end()]).is_err() || io.0.lock().trace != [Op::Delay(7000)] {
        return TestResult::Fail("millisecond delay unit lost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/power",
    smoke_rtlwifi_power_filters_bases_and_requires_end
);

fn smoke_rtlwifi_8188ee_enable_unlocks_before_flow() -> TestResult {
    let io = Fake::new();
    if power_on_with(&io, super::super::regs::RTL_DEV_8188EE).is_err() {
        return TestResult::Fail("8188EE profile enable failed");
    }
    let m = io.0.lock();
    if m.trace[..5]
        != [
            Op::Read(0x7c),
            Op::Write(0x7c, 0xa4),
            Op::Read(5),
            Op::Write(5, 0x7e),
            Op::Write(0x1c, 0),
        ]
        || m.bytes[0x1c] != 0
        || m.bytes[5] != 0x66
        || m.bytes[0x23] != 0xe7
    {
        return TestResult::Fail(
            "reserved unlock/power order differs from Linux PCI initialization",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/power",
    smoke_rtlwifi_8188ee_enable_unlocks_before_flow
);
