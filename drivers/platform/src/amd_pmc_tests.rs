use super::*;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A PMC mailbox: the response register holds the last result, and a
/// message write replaces it with `answer` (0 is a PMC that never answers).
/// The clock advances 1 ms per read.
struct Fake {
    regs: [u32; 0x400],
    writes: Vec<(u32, u32)>,
    answer: u32,
    info: CpuInfo,
    now: u64,
}
impl Fake {
    fn new(info: CpuInfo, answer: u32) -> Self {
        let mut regs = [0; 0x400];
        regs[info.response as usize / 4] = RESULT_OK;
        Self {
            regs,
            writes: Vec::new(),
            answer,
            info,
            now: 0,
        }
    }
}
impl Mailbox for Fake {
    fn read32(&mut self, offset: u32) -> u32 {
        self.regs[offset as usize / 4]
    }
    fn write32(&mut self, offset: u32, value: u32) {
        self.writes.push((offset, value));
        self.regs[offset as usize / 4] = value;
        if offset == self.info.message {
            self.regs[self.info.response as usize / 4] = self.answer;
        }
    }
    fn now_ns(&mut self) -> u64 {
        self.now += 1_000_000;
        self.now
    }
}

/// `pmc_pci_ids`: Raphael (CB) and Phoenix (PS) take the 0x538/0x9bc/0x980
/// mailbox and `MSG_OS_HINT_RN`, as do Cezanne/Renoir, Van Gogh and
/// Rembrandt; Picasso its own hint; 1Ah M80h its own registers; the server
/// parts (SP, SHP) refuse; an unlisted root is unknown. The window base keeps
/// the low word's bits 31:20 and the high word's bits 15:0, plus 0x10000.
fn amd_pmc_cpu_table_and_window_follow_linux() -> TestResult {
    use cpu_id::*;
    let rn = CpuInfo {
        message: 0x538,
        argument: 0x9bc,
        response: 0x980,
        os_hint: 3,
    };
    if [CB, PS, CZN, VG, YC]
        .iter()
        .any(|&id| cpu_info(id) != Ok(rn))
        || cpu_info(PCO).map(|i| i.os_hint) != Ok(2)
        || cpu_info(M80H_ROOT).map(|i| (i.message, i.argument, i.response))
            != Ok((0xa10, 0xa18, 0xa14))
        || cpu_info(M20H_ROOT).map(|i| i.message) != Ok(0x938)
        || cpu_info(SP) != Err(PmcError::NoS0i3)
        || cpu_info(SHP) != Err(PmcError::NoS0i3)
        || cpu_info(0x1234) != Err(PmcError::UnknownCpu(0x1234))
    {
        return TestResult::Fail("pmc_pci_ids");
    }
    if window(0xfedc_1234, 0xabcd_0001) != 0x1_fed0_0000 + 0x1_0000 {
        return TestResult::Fail("the window's SMN masks");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmc",
    amd_pmc_cpu_table_and_window_follow_linux
);

/// `amd_pmc_send_cmd`: wait for a response, clear it, write the argument,
/// then the message, and decode the reply. Prepare sends the OS hint with 1.
/// Restore sends it with 0, then the log dump (except on Picasso). A PMC
/// that never answers times out within a bounded wait, and failure codes
/// map as Linux maps them.
fn amd_pmc_mailbox_follows_amd_pmc_send_cmd() -> TestResult {
    let rn = cpu_info(cpu_id::CB).unwrap();
    let mut mb = Fake::new(rn, RESULT_OK);
    if prepare(&mut mb, &rn).is_err() || mb.writes != [(0x980, 0), (0x9bc, 1), (0x538, 3)] {
        return TestResult::Fail("the prepare OS hint");
    }
    mb.writes.clear();
    if restore(&mut mb, &rn).is_err()
        || mb.writes
            != [
                (0x980, 0),
                (0x9bc, 0),
                (0x538, 3),
                (0x980, 0),
                (0x9bc, 0),
                (0x538, 8),
            ]
    {
        return TestResult::Fail("the restore OS hint and log dump");
    }
    let pco = cpu_info(cpu_id::PCO).unwrap();
    let mut mb = Fake::new(pco, RESULT_OK);
    if restore(&mut mb, &pco).is_err() || mb.writes.len() != 3 {
        return TestResult::Fail("Picasso dumped its log");
    }
    for (answer, want) in [
        (0xfc, PmcError::Busy),
        (0xfe, PmcError::Unknown),
        (0xfd, PmcError::Failed(0xfd)),
        (0xff, PmcError::Failed(0xff)),
        (0, PmcError::Timeout),
    ] {
        if prepare(&mut Fake::new(rn, answer), &rn) != Err(want) {
            return TestResult::Fail("a failure response");
        }
    }
    // A PMC still busy with an earlier message: nothing is written.
    let mut mb = Fake::new(rn, RESULT_OK);
    mb.regs[0x980 / 4] = 0;
    if prepare(&mut mb, &rn) != Err(PmcError::Timeout) || !mb.writes.is_empty() {
        return TestResult::Fail("sent over an unanswered message");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmc",
    amd_pmc_mailbox_follows_amd_pmc_send_cmd
);
