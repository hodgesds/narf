//! Fixture tests for the BTCOEX glue (`btcoex.c` port).

use super::super::mci::Mci;
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Minimal register-map mock for the weight-register writes.
struct BtcoexFixture {
    regs: BTreeMap<u64, u32>,
    ops: Vec<(u64, u32)>,
}

impl BtcoexFixture {
    fn new() -> Self {
        Self {
            regs: BTreeMap::new(),
            ops: Vec::new(),
        }
    }

    fn last_write(&self, addr: u64) -> Option<u32> {
        self.ops
            .iter()
            .rev()
            .find(|(a, _)| *a == addr)
            .map(|(_, v)| *v)
    }
}

impl RegisterIo for BtcoexFixture {
    fn read32(&mut self, offset: u64) -> u32 {
        self.regs.get(&offset).copied().unwrap_or(0)
    }

    fn write32(&mut self, offset: u64, value: u32) {
        self.ops.push((offset, value));
        self.regs.insert(offset, value);
    }

    fn delay_us(&mut self, _us: u64) {}
}

fn btcoex_init_scheme() -> TestResult {
    // Coexistence disabled: no scheme.
    let mut btcoex = Btcoex::new(Chip::Ar9462);
    init_scheme(&mut btcoex, false, HW_CAP_MCI);
    if btcoex.scheme != Scheme::None {
        return TestResult::Fail("scheme was set with coexistence disabled");
    }
    // MCI capability: MCI scheme.
    init_scheme(&mut btcoex, true, HW_CAP_MCI);
    if btcoex.scheme != Scheme::Mci {
        return TestResult::Fail("MCI capability did not select the MCI scheme");
    }
    // No MCI capability on AR9003: 3WIRE with the 9300 pins.
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_scheme(&mut btcoex, true, 0);
    if btcoex.scheme != Scheme::ThreeWire {
        return TestResult::Fail("non-MCI AR9003 did not select 3WIRE");
    }
    if btcoex.wlanactive_gpio != 5 || btcoex.btactive_gpio != 4 || btcoex.btpriority_gpio != 8 {
        return TestResult::Fail("3WIRE GPIO pins are wrong");
    }
    // mci_is_enabled is btcoex_enabled && the MCI capability.
    if !mci_is_enabled(true, HW_CAP_MCI)
        || mci_is_enabled(false, HW_CAP_MCI)
        || mci_is_enabled(true, 0)
    {
        return TestResult::Fail("mci_is_enabled truth table is wrong");
    }
    // Scheme values (`btcoex.h::enum ath_btcoex_scheme`, Linux order).
    if Scheme::None as u8 != 0
        || Scheme::TwoWire as u8 != 1
        || Scheme::ThreeWire as u8 != 2
        || Scheme::Mci as u8 != 3
    {
        return TestResult::Fail("btcoex scheme values are wrong");
    }
    TestResult::Pass
}

fn btcoex_init_mci() -> TestResult {
    // AR9462 gets the 0x2201 config word.
    let mut btcoex = Btcoex::new(Chip::Ar9462);
    init_mci(&mut btcoex);
    if btcoex.mci.config != 0x2201 {
        return TestResult::Fail("AR9462 MCI config is not 0x2201");
    }
    // Other parts get 0xa4c1.
    for chip in [Chip::Ar9565, Chip::Ar9300, Chip::Ar9580, Chip::Ar9485] {
        let mut btcoex = Btcoex::new(chip);
        init_mci(&mut btcoex);
        if btcoex.mci.config != 0xa4c1 {
            return TestResult::Fail("non-AR9462 MCI config is not 0xa4c1");
        }
    }
    // The Linux defaults.
    let mci = &btcoex.mci;
    if mci.ready
        || mci.bt_state != super::super::mci::BtState::Sleep
        || mci.bt_ver_major != 3
        || mci.bt_ver_minor != 0
        || mci.bt_version_known
        || !mci.update_2g5g
        || !mci.is_2g
        || mci.wlan_channels_update
        || mci.wlan_channels != [0, 0xffff_ffff, 0xffff_ffff, 0x7fff_ffff]
        || !mci.query_bt
        || !mci.unhalt_bt_gpm
        || mci.halted_bt_gpm
        || mci.need_flush_btinfo
        || mci.wlan_cal_seq != 0
        || mci.wlan_cal_done != 0
    {
        return TestResult::Fail("init_mci defaults are wrong");
    }
    // init_mci leaves the buffer addresses, concur_tx and stomp_ftp
    // alone (Linux does not touch them either).
    let mut btcoex = Btcoex::new(Chip::Ar9462);
    btcoex.mci.gpm_addr = 0x1000;
    btcoex.mci.sched_addr = 0x2000;
    btcoex.mci.concur_tx = true;
    btcoex.mci.stomp_ftp = true;
    init_mci(&mut btcoex);
    if btcoex.mci.gpm_addr != 0x1000
        || btcoex.mci.sched_addr != 0x2000
        || !btcoex.mci.concur_tx
        || !btcoex.mci.stomp_ftp
    {
        return TestResult::Fail("init_mci reset fields it must leave alone");
    }
    // Mci::new starts zeroed; init_mci is what fills the defaults.
    let fresh = Mci::new(Chip::Ar9462);
    if fresh.config != 0 || fresh.bt_ver_major != 0 {
        return TestResult::Fail("Mci::new is not zeroed");
    }
    TestResult::Pass
}

fn btcoex_set_weight() -> TestResult {
    // Stomp values (`btcoex.h::enum ath_stomp_type`, Linux order).
    if StompType::All as u8 != 0
        || StompType::Low as u8 != 1
        || StompType::None as u8 != 2
        || StompType::LowFtp as u8 != 3
        || StompType::Audio as u8 != 4
    {
        return TestResult::Fail("stomp type values are wrong");
    }
    // AR9462 STOMP_ALL uses the MCI table.
    let mut btcoex = Btcoex::new(Chip::Ar9462);
    init_mci(&mut btcoex);
    set_weight(&mut btcoex, StompType::All);
    if btcoex.wlan_weight != [0x0101_7d01, 0x4141_4101, 0x4141_4101, 0x4141_4141] {
        return TestResult::Fail("AR9462 STOMP_ALL weights are wrong");
    }
    if btcoex.bt_weight != [0xcccc_4444; 4] {
        return TestResult::Fail("BT weights are not AR9300_BT_WGHT");
    }
    // STOMP_LOW promotes to LOW_FTP when FTP stomping is on.
    btcoex.mci.stomp_ftp = true;
    set_weight(&mut btcoex, StompType::Low);
    if btcoex.wlan_weight != [0x0101_7d01, 0x013b_0101, 0x3b3b_0101, 0x3b3b_013b] {
        return TestResult::Fail("STOMP_LOW did not promote to LOW_FTP");
    }
    btcoex.mci.stomp_ftp = false;
    set_weight(&mut btcoex, StompType::Low);
    if btcoex.wlan_weight != [0x0101_7d01, 0x3b3b_3b01, 0x3b3b_3b01, 0x3b3b_3b3b] {
        return TestResult::Fail("STOMP_LOW weights are wrong");
    }
    // Non-MCI parts use the AR9003 table; LOW_FTP/AUDIO rows are zero.
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_mci(&mut btcoex);
    set_weight(&mut btcoex, StompType::All);
    if btcoex.wlan_weight != [0xffff_fff0; 4] {
        return TestResult::Fail("AR9300 STOMP_ALL weights are wrong");
    }
    set_weight(&mut btcoex, StompType::LowFtp);
    if btcoex.wlan_weight != [0; 4] {
        return TestResult::Fail("AR9300 STOMP_LOW_FTP weights are not zero");
    }
    set_weight(&mut btcoex, StompType::Audio);
    if btcoex.wlan_weight != [0; 4] {
        return TestResult::Fail("AR9300 STOMP_AUDIO weights are not zero");
    }
    // Concurrent-TX priority overlays the top bytes of slots 1..3.
    // Linux applies the same tx_prio at every slot
    // (`btcoex.c::txprio_shift = {24, 16, 16, 0}`; no +1 anywhere),
    // so slot 2/3 take 0x5a in the 16-shift byte, not 0x5b.
    let mut btcoex = Btcoex::new(Chip::Ar9462);
    init_mci(&mut btcoex);
    btcoex.mci.concur_tx = true;
    set_concur_txprio(&mut btcoex, [0x5a, 0, 0, 0, 0]);
    set_weight(&mut btcoex, StompType::All);
    if btcoex.wlan_weight != [0x0101_7d01, 0x5a41_4101, 0x415a_4101, 0x415a_415a] {
        return TestResult::Fail("concurrent-TX priority overlay is wrong");
    }
    // Zero priority means no overlay even with concur_tx on.
    set_concur_txprio(&mut btcoex, [0; 5]);
    set_weight(&mut btcoex, StompType::All);
    if btcoex.wlan_weight != [0x0101_7d01, 0x4141_4101, 0x4141_4101, 0x4141_4141] {
        return TestResult::Fail("zero TX priority still overlaid the weights");
    }
    // bt_stomp is the STOMP_NONE entry point.
    bt_stomp(&mut btcoex, StompType::None);
    if btcoex.wlan_weight != [0x0101_7d01, 0x0101_0101, 0x0101_0101, 0x0101_0101] {
        return TestResult::Fail("bt_stomp(STOMP_NONE) weights are wrong");
    }
    TestResult::Pass
}

fn btcoex_enable_disable_mci() -> TestResult {
    // Enable programs the stomped weights and the quiet-ack bit.
    let mut io = BtcoexFixture::new();
    let mut btcoex = Btcoex::new(Chip::Ar9462);
    init_mci(&mut btcoex);
    bt_stomp(&mut btcoex, StompType::None);
    if enable_mci(&mut io, &mut btcoex).is_err() {
        return TestResult::Fail("enable_mci errored");
    }
    if !btcoex.enabled {
        return TestResult::Fail("enable_mci did not mark coexistence enabled");
    }
    let want = [0x0101_7d01, 0x0101_0101, 0x0101_0101, 0x0101_0101];
    let regs = [
        AR_BTCOEX_WL_WEIGHTS0,
        AR_BTCOEX_WL_WEIGHTS1,
        AR_BTCOEX_WL_WEIGHTS2,
        AR_BTCOEX_WL_WEIGHTS3,
    ];
    for (reg, w) in regs.iter().zip(want.iter()) {
        if io.last_write(*reg) != Some(*w) {
            return TestResult::Fail("enable_mci wrote the wrong weights");
        }
    }
    if io.last_write(AR_QUIET1) != Some(AR_QUIET1_QUIET_ACK_CTS_ENABLE) {
        return TestResult::Fail("enable_mci did not set QUIET_ACK_CTS_ENABLE");
    }
    // Disable re-stomps to NONE and re-programs the weights; the
    // caller owns `enabled`, as in Linux.
    let mut io = BtcoexFixture::new();
    let mut btcoex = Btcoex::new(Chip::Ar9462);
    init_mci(&mut btcoex);
    btcoex.enabled = true;
    bt_stomp(&mut btcoex, StompType::All);
    if disable_mci(&mut io, &mut btcoex).is_err() {
        return TestResult::Fail("disable_mci errored");
    }
    // Linux's `ath9k_hw_btcoex_disable_mci` does not touch `enabled`
    // (the caller `ath9k_hw_btcoex_disable` clears it first), so it
    // must still be set here.
    if !btcoex.enabled {
        return TestResult::Fail("disable_mci cleared enabled itself; the caller owns enabled");
    }
    for (reg, w) in regs.iter().zip(want.iter()) {
        if io.last_write(*reg) != Some(*w) {
            return TestResult::Fail("disable_mci did not stomp the weights");
        }
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_init_scheme);
kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_init_mci);
kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_set_weight);
kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_enable_disable_mci);
