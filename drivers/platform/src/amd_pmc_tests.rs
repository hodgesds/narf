use super::*;
use crate::amd_pmc_quirks::{lookup, Dmi, Quirk};
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A PMC: the response register holds the last result, and a message
/// write replaces it with `answer` (0 never answers) and puts the reply
/// in the argument register. The clock advances 1 ms per read, plus any
/// delay. The metrics table is a word array.
struct Fake {
    regs: [u32; 0x400],
    writes: Vec<(u32, u32)>,
    answer: u32,
    /// Data replies by message.
    replies: Vec<(u32, u32)>,
    info: CpuInfo,
    now: u64,
    delayed_us: u64,
    table: Option<u64>,
    table_words: [u32; (METRICS_SIZE / 4) as usize],
    fch_clears: u32,
}
impl Fake {
    fn new(info: CpuInfo, answer: u32) -> Self {
        let mut regs = [0; 0x400];
        regs[info.response as usize / 4] = RESULT_OK;
        Self {
            regs,
            writes: Vec::new(),
            answer,
            replies: Vec::new(),
            info,
            now: 0,
            delayed_us: 0,
            table: None,
            table_words: [0; (METRICS_SIZE / 4) as usize],
            fch_clears: 0,
        }
    }
    /// (argument, message) pairs, in order.
    fn messages(&self) -> Vec<(u32, u32)> {
        let mut out = Vec::new();
        let mut arg = 0;
        for &(reg, value) in &self.writes {
            if reg == self.info.argument {
                arg = value;
            } else if reg == self.info.message {
                out.push((arg, value));
            }
        }
        out
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
            if let Some(&(_, reply)) = self.replies.iter().find(|(m, _)| *m == value) {
                self.regs[self.info.argument as usize / 4] = reply;
            }
        }
    }
    fn now_ns(&mut self) -> u64 {
        self.now += 1_000_000;
        self.now
    }
    fn delay_us(&mut self, us: u64) {
        self.delayed_us += us;
        self.now += us * 1000;
    }
    fn map_table(&mut self, phys: u64) -> bool {
        self.table = Some(phys);
        phys != 0
    }
    fn table_read32(&mut self, offset: u64) -> u32 {
        self.table
            .map_or(0, |_| self.table_words[offset as usize / 4])
    }
    fn table_zero(&mut self) {
        self.table_words = [0; (METRICS_SIZE / 4) as usize];
    }
    fn clear_fch_scratch_bit0(&mut self) {
        self.fch_clears += 1;
    }
}
fn state(cpu: u16) -> State {
    State::new(
        cpu,
        cpu_info(cpu).unwrap(),
        Quirk::default(),
        Options::default(),
    )
}
/// A PMC whose SMU reports `version` and keeps its table at 0x1_2340_0000.
fn pmc(cpu: u16, version: u32) -> (Fake, State) {
    let mut mb = Fake::new(cpu_info(cpu).unwrap(), RESULT_OK);
    mb.replies = alloc::vec![
        (SMU_MSG_GETSMUVERSION, version),
        (SMU_MSG_GET_SUP_CONSTRAINTS, 0x7ff),
        (SMU_MSG_LOG_GETDRAM_ADDR_LO, 0x2340_0000),
        (SMU_MSG_LOG_GETDRAM_ADDR_HI, 0x1),
    ];
    (mb, state(cpu))
}

/// `pmc_pci_ids`. Raphael (CB) and Phoenix (PS) take Rembrandt's
/// `amd_yc_cpu_info`: the 0x538/0x9bc/0x980 mailbox, `MSG_OS_HINT_RN` and
/// idle-mask scratch 0xd14. Cezanne's scratch is 0x94, and Picasso and
/// Van Gogh have none. 1Ah M80h has its own registers. The server parts (SP,
/// SHP) refuse, and an unlisted root is unknown. The window base keeps the
/// low word's bits 31:20 and the high word's bits 15:0, plus 0x10000.
fn amd_pmc_cpu_table_and_window_follow_linux() -> TestResult {
    use cpu_id::*;
    let yc = CpuInfo {
        message: 0x538,
        argument: 0x9bc,
        response: 0x980,
        os_hint: 3,
        scratch: Some(0xd14),
    };
    if [CB, PS, YC].iter().any(|&id| cpu_info(id) != Ok(yc))
        || cpu_info(CZN).map(|i| (i.os_hint, i.scratch)) != Ok((3, Some(0x94)))
        || cpu_info(VG).map(|i| (i.os_hint, i.scratch)) != Ok((3, None))
        || cpu_info(PCO).map(|i| (i.os_hint, i.scratch)) != Ok((2, None))
        || cpu_info(M80H_ROOT).map(|i| (i.message, i.argument, i.response, i.scratch))
            != Ok((0xa10, 0xa18, 0xa14, Some(0xf14)))
        || cpu_info(M20H_ROOT).map(|i| (i.message, i.scratch)) != Ok((0x938, Some(0xf14)))
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
/// then the message, and decode the reply. A data reply is the argument
/// register read after `DELAY_MIN_US`. A PMC that never answers times out
/// within a bounded wait, and failure codes map as Linux maps them.
fn amd_pmc_mailbox_follows_amd_pmc_send_cmd() -> TestResult {
    let rn = cpu_info(cpu_id::CB).unwrap();
    let mut mb = Fake::new(rn, RESULT_OK);
    if send(&mut mb, &rn, 1, 3).is_err() || mb.writes != [(0x980, 0), (0x9bc, 1), (0x538, 3)] {
        return TestResult::Fail("the message sequence");
    }
    mb.replies = alloc::vec![(SMU_MSG_GETSMUVERSION, 0x0040_3500)];
    if send_read(&mut mb, &rn, 0, SMU_MSG_GETSMUVERSION) != Ok(0x0040_3500) || mb.delayed_us != 2000
    {
        return TestResult::Fail("a data reply");
    }
    for (answer, want) in [
        (0xfc, PmcError::Busy),
        (0xfe, PmcError::Unknown),
        (0xfd, PmcError::Failed(0xfd)),
        (0xff, PmcError::Failed(0xff)),
        (0, PmcError::Timeout),
    ] {
        if send(&mut Fake::new(rn, answer), &rn, 1, 3) != Err(want) {
            return TestResult::Fail("a failure response");
        }
    }
    // A PMC still busy with an earlier message: nothing is written.
    let mut mb = Fake::new(rn, RESULT_OK);
    mb.regs[0x980 / 4] = 0;
    if send(&mut mb, &rn, 1, 3) != Err(PmcError::Timeout) || !mb.writes.is_empty() {
        return TestResult::Fail("sent over an unanswered message");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmc",
    amd_pmc_mailbox_follows_amd_pmc_send_cmd
);

/// `amd_pmc_s2idle_prepare`/`_restore`. Prepare fetches the active IPs and
/// the table address once, zeroes the table, resets and starts logging,
/// then sends the OS hint with 1. Restore sends the hint with 0, the log
/// dump, and reads the deepest-state metrics. Picasso has no SMU logging
/// and no dump.
fn amd_pmc_prepare_and_restore_follow_amd_pmc_s2idle() -> TestResult {
    let (mut mb, mut st) = pmc(cpu_id::CB, 0x004c_1a00);
    mb.table_words = [7; (METRICS_SIZE / 4) as usize];
    if prepare(&mut mb, &mut st).is_err()
        || mb.messages()
            != [
                (0, SMU_MSG_GET_SUP_CONSTRAINTS),
                (0, SMU_MSG_LOG_GETDRAM_ADDR_LO),
                (0, SMU_MSG_LOG_GETDRAM_ADDR_HI),
                (0, SMU_MSG_LOG_RESET),
                (0, SMU_MSG_LOG_START),
                (1, MSG_OS_HINT_RN),
            ]
        || mb.table != Some(0x1_2340_0000)
        || mb.table_words.iter().any(|&w| w != 0)
        || (st.active_ips, st.first_check) != (Some(0x7ff), true)
    {
        return TestResult::Fail("prepare");
    }
    // A second prepare reuses the table address and the IP list.
    mb.writes.clear();
    let _ = prepare(&mut mb, &mut st);
    if mb.messages()
        != [
            (0, SMU_MSG_LOG_RESET),
            (0, SMU_MSG_LOG_START),
            (1, MSG_OS_HINT_RN),
        ]
    {
        return TestResult::Fail("a second prepare re-fetched the table");
    }
    mb.writes.clear();
    mb.table_words[2] = 1; // s0i3_last_entry_status
    mb.table_words[12] = 5000; // timein_s0i3_lastcapture, low word
    let (hint, deepest) = restore(&mut mb, &mut st);
    if hint.is_err()
        || mb.messages() != [(0, MSG_OS_HINT_RN), (0, SMU_MSG_LOG_DUMP_DATA)]
        || deepest
            != Some(Metrics {
                s0i3_last_entry_status: 1,
                timein_s0i3_lastcapture: 5000,
            })
        || mb.fch_clears != 0
    {
        return TestResult::Fail("restore");
    }
    let (mut mb, mut st) = pmc(cpu_id::PCO, 0);
    let _ = prepare(&mut mb, &mut st);
    let (_, deepest) = restore(&mut mb, &mut st);
    if mb.messages() != [(1, MSG_OS_HINT_PCO), (0, MSG_OS_HINT_PCO)] || deepest.is_some() {
        return TestResult::Fail("Picasso logged or dumped");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmc",
    amd_pmc_prepare_and_restore_follow_amd_pmc_s2idle
);

/// `amd_pmc_s2idle_check`. The first check after a prepare finds the
/// freshly zeroed table: no delay. A wakeup that came out of S0i3 delays
/// 2.5 s before entering it again. The `need_suspend_delay` quirk delays
/// unless `delay_suspend=0` or `disable_workarounds`, and `delay_suspend=1`
/// always delays. The idle mask is the CPU's scratch register; Cezanne's
/// needs SMU 55.37.
fn amd_pmc_check_delays_as_linux_does() -> TestResult {
    let (mut mb, mut st) = pmc(cpu_id::CB, 0);
    let _ = prepare(&mut mb, &mut st);
    mb.regs[0xd14 / 4] = 0xabc;
    let first = check(&mut mb, &mut st);
    mb.table_words[2] = 1;
    let again = check(&mut mb, &mut st);
    if first
        != (Check {
            delayed: false,
            idle_mask: Some(0xabc),
        })
        || !again.delayed
        || mb.delayed_us < SUSPEND_DELAY_US
        || st.first_check
    {
        return TestResult::Fail("the intermediate-wakeup delay");
    }
    let quirk = Quirk {
        need_suspend_delay: true,
        ..Quirk::default()
    };
    for (delay_suspend, disable, have_quirk, want) in [
        (-1, false, true, true),
        (0, false, true, false),
        (-1, true, true, false),
        (1, true, true, true),
        (-1, false, false, false),
        (1, false, false, true),
    ] {
        let (mut mb, mut st) = pmc(cpu_id::CB, 0);
        st.quirk = if have_quirk { quirk } else { Quirk::default() };
        st.options = Options {
            delay_suspend,
            disable_workarounds: disable,
        };
        let _ = prepare(&mut mb, &mut st);
        if check(&mut mb, &mut st).delayed != want {
            return TestResult::Fail("amd_pmc_want_suspend_delay");
        }
    }
    // Cezanne: the idle mask needs SMU 55.37 or newer.
    for (version, want) in [
        (0x0037_2400, None),
        (0x0037_2500, Some(9)),
        (0x0037_2600, Some(9)),
        (0x0039_0000, Some(9)),
    ] {
        let (mut mb, mut st) = pmc(cpu_id::CZN, version);
        mb.regs[0x94 / 4] = 9;
        if idle_mask(&mut mb, &mut st).ok() != want {
            return TestResult::Fail("Cezanne's idle-mask version gate");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/amd_pmc",
    amd_pmc_check_delays_as_linux_does
);

/// `fwbug_list` matches every listed field by substring, in its order.
/// `s2idle_bug_mmio` clears the FCH PM scratch byte's bit 0 at restore.
/// Cezanne's prepare reads the SMU version for its RTC gate after the
/// logging setup, as Linux does, and sends the hint with 1, since no RTC
/// alarm is ever pending in NARF.
fn amd_pmc_quirks_follow_pmc_quirks() -> TestResult {
    let dmi = |sys: &str, product: &str, board_vendor: &str, board: &str, bios: &str| Dmi {
        sys_vendor: sys.into(),
        product_name: product.into(),
        board_vendor: board_vendor.into(),
        board_name: board.into(),
        bios_version: bios.into(),
    };
    let lenovo = |product: &str| dmi("LENOVO", product, "LENOVO", "LNVNB161216", "N2XET40W");
    let framework = |bios: &str| {
        dmi(
            "Framework",
            "Laptop 13 (AMD Ryzen 7040Series)",
            "Framework",
            "FRANMDCP07",
            bios,
        )
    };
    let quirk = |d: Dmi| lookup(&d).map(|(_, q)| q);
    if quirk(lenovo("20XKCTO1WW"))
        != Some(Quirk {
            s2idle_bug_mmio: true,
            spurious_8042: true,
            need_suspend_delay: false,
        })
        || quirk(lenovo("82YTABCD")).map(|q| (q.s2idle_bug_mmio, q.spurious_8042))
            != Some((true, false))
        || quirk(lenovo("82X70006US")).map(|q| q.need_suspend_delay) != Some(true)
        || quirk(framework("03.05")).map(|q| q.spurious_8042) != Some(true)
        || quirk(framework("03.04")).is_some()
        || quirk(dmi(
            "ASUSTeK COMPUTER INC.",
            "",
            "ASUSTeK COMPUTER INC.",
            "RC73YA",
            "",
        ))
        .map(|q| q.spurious_8042)
            != Some(true)
        || quirk(lenovo("21ZZ")).is_some()
    {
        return TestResult::Fail("fwbug_list");
    }
    let (mut mb, mut st) = pmc(cpu_id::CB, 0);
    st.quirk.s2idle_bug_mmio = true;
    let _ = restore(&mut mb, &mut st);
    if mb.fch_clears != 1 {
        return TestResult::Fail("the s2idle_bug_mmio restore quirk");
    }
    let (mut mb, mut st) = pmc(cpu_id::CZN, 0x0040_3500);
    if prepare(&mut mb, &mut st).is_err()
        || mb.messages()[mb.messages().len() - 2..]
            != [(0, SMU_MSG_GETSMUVERSION), (1, MSG_OS_HINT_RN)]
        || st.version != Some([0, 0x40, 0x35, 0])
    {
        return TestResult::Fail("Cezanne's RTC gate");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/platform/amd_pmc", amd_pmc_quirks_follow_pmc_quirks);
