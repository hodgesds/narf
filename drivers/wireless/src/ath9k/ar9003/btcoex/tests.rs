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

fn btcoex_init_btcoex_hw() -> TestResult {
    // Fresh non-SoC state, qnum 0: the slotted-mode image.
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_btcoex_hw(&mut btcoex, 0, false);
    if btcoex.bt_coex_mode != 0x0508_1b00 {
        return TestResult::Fail("non-SoC mode image is wrong");
    }
    if btcoex.bt_coex_mode2 != 0x0011_0032 {
        return TestResult::Fail("non-SoC mode2 image is wrong");
    }
    if btcoex.bt_coex_mode3 != 0 {
        return TestResult::Fail("non-SoC mode3 must stay zero");
    }
    // qnum lands in the QCU-threshold field.
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_btcoex_hw(&mut btcoex, 3, false);
    if btcoex.bt_coex_mode != 0x0508_7b00 {
        return TestResult::Fail("qnum did not land in the QCU-threshold field");
    }
    // SoC overrides: first slot 0x1d, time extend 0xa, mode3, mode2 bits.
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_btcoex_hw(&mut btcoex, 0, true);
    if btcoex.bt_coex_mode != 0x1d08_1b0a {
        return TestResult::Fail("SoC mode image is wrong");
    }
    if btcoex.bt_coex_mode2 != 0x8019_0032 {
        return TestResult::Fail("SoC mode2 image is wrong");
    }
    if btcoex.bt_coex_mode3 != 0x2020 {
        return TestResult::Fail("SoC mode3 image is wrong");
    }
    // Linux keeps a stale QCU-threshold: a preset mode with thresh 3
    // ORs through when qnum is 0.
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    btcoex.bt_coex_mode = 0x0000_6000;
    init_btcoex_hw(&mut btcoex, 0, false);
    if btcoex.bt_coex_mode != 0x0508_7b00 {
        return TestResult::Fail("stale QCU-threshold bits were not preserved");
    }
    // Mode2 accumulates: a preset stray bit survives.
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    btcoex.bt_coex_mode2 = 0x0000_0004;
    init_btcoex_hw(&mut btcoex, 0, false);
    if btcoex.bt_coex_mode2 != 0x0011_0036 {
        return TestResult::Fail("mode2 did not accumulate onto the preset bits");
    }
    TestResult::Pass
}

fn btcoex_init_2wire_3wire() -> TestResult {
    // 2WIRE on the 9300 pins (wlanactive 5, btactive 4, btpriority 8).
    // Seeds are chosen so each RMW/field both changes its bits and
    // preserves the rest (a zero seed would hide a wrong mask).
    let mut io = BtcoexFixture::new();
    io.regs.insert(AR_GPIO_INPUT_EN_VAL, 0x0000_efff);
    io.regs.insert(AR_GPIO_INPUT_MUX1, 0x00ff_00ff);
    io.regs.insert(AR_GPIO_OE_OUT, 0x0000_ffff);
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_scheme(&mut btcoex, true, 0);
    if init_2wire(&mut io, &btcoex, false).is_err() {
        return TestResult::Fail("init_2wire errored");
    }
    // Default BT-priority/BT-frequency bits cleared (0xefff -> 0xeff3),
    // BT-active baseband bit set (bit 12 was clear).
    if io.last_write(AR_GPIO_INPUT_EN_VAL) != Some(0x0000_fff3) {
        return TestResult::Fail("init_2wire input-enable bits are wrong");
    }
    // BT-active mux field 0xf -> 4, the rest of the register kept.
    if io.last_write(AR_GPIO_INPUT_MUX1) != Some(0x00f4_00ff) {
        return TestResult::Fail("init_2wire input mux is wrong");
    }
    // Pin 4 requested in: its 2-bit OE field cleared.
    if io.last_write(AR_GPIO_OE_OUT) != Some(0x0000_fcff) {
        return TestResult::Fail("init_2wire did not request the pin in");
    }
    // 3WIRE: both baseband bits set, both muxes, both pins in.
    let mut io = BtcoexFixture::new();
    io.regs.insert(AR_GPIO_INPUT_EN_VAL, 0x0001_0000);
    io.regs.insert(AR_GPIO_INPUT_MUX1, 0xff00_0000);
    io.regs.insert(AR_GPIO_OE_OUT, 0x0003_0300);
    if init_3wire(&mut io, &btcoex, false).is_err() {
        return TestResult::Fail("init_3wire errored");
    }
    if io.last_write(AR_GPIO_INPUT_EN_VAL) != Some(0x0001_1400) {
        return TestResult::Fail("init_3wire input-enable bits are wrong");
    }
    if io.last_write(AR_GPIO_INPUT_MUX1) != Some(0xff04_0800) {
        return TestResult::Fail("init_3wire input muxes are wrong");
    }
    if io.last_write(AR_GPIO_OE_OUT) != Some(0x0000_0000) {
        return TestResult::Fail("init_3wire did not request both pins in");
    }
    // SoC: no input-mux write, but the enable bits and request-ins
    // still happen.
    let mut io = BtcoexFixture::new();
    io.regs.insert(AR_GPIO_INPUT_EN_VAL, 0x0001_0000);
    io.regs.insert(AR_GPIO_INPUT_MUX1, 0x0000_1234);
    io.regs.insert(AR_GPIO_OE_OUT, 0x0003_0300);
    if init_3wire(&mut io, &btcoex, true).is_err() {
        return TestResult::Fail("SoC init_3wire errored");
    }
    if io.last_write(AR_GPIO_INPUT_MUX1).is_some() {
        return TestResult::Fail("SoC init_3wire wrote the input mux");
    }
    if io.last_write(AR_GPIO_INPUT_EN_VAL) != Some(0x0001_1400)
        || io.last_write(AR_GPIO_OE_OUT) != Some(0x0000_0000)
    {
        return TestResult::Fail("SoC init_3wire skipped the GPIO setup");
    }
    // deinit is a no-op on AR9003: pins and mode images untouched.
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_scheme(&mut btcoex, true, 0);
    init_btcoex_hw(&mut btcoex, 0, false);
    deinit(&btcoex);
    if btcoex.btactive_gpio != 4
        || btcoex.btpriority_gpio != 8
        || btcoex.wlanactive_gpio != 5
        || btcoex.bt_coex_mode != 0x0508_1b00
    {
        return TestResult::Fail("deinit changed state it must leave alone");
    }
    TestResult::Pass
}

fn btcoex_enable_2wire_3wire() -> TestResult {
    // 3WIRE: mode/weight programming, QUIET1, PCU_MISC, GPIO out.
    let mut io = BtcoexFixture::new();
    io.regs.insert(AR_PCU_MISC, 0xffff_0000);
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_scheme(&mut btcoex, true, 0);
    init_btcoex_hw(&mut btcoex, 0, false);
    bt_stomp(&mut btcoex, StompType::All);
    if enable_3wire(&mut io, &btcoex, false).is_err() {
        return TestResult::Fail("enable_3wire errored");
    }
    if io.last_write(AR_BT_COEX_MODE) != Some(0x0508_1b00) {
        return TestResult::Fail("enable_3wire did not program the mode image");
    }
    if io.last_write(AR_BT_COEX_MODE2) != Some(0x0011_0032) {
        return TestResult::Fail("enable_3wire did not program the mode2 image");
    }
    if io.last_write(AR_BT_COEX_MODE3).is_some() {
        return TestResult::Fail("non-SoC enable_3wire wrote mode3");
    }
    if io.last_write(AR_BT_COEX_WL_WEIGHTS0) != Some(0xffff_fff0)
        || io.last_write(AR_BT_COEX_WL_WEIGHTS1) != Some(0xffff_fff0)
    {
        return TestResult::Fail("enable_3wire did not program the WLAN weights");
    }
    for i in 0..4u32 {
        if io.last_write(ar_bt_coex_bt_weights(i)) != Some(0xcccc_4444) {
            return TestResult::Fail("enable_3wire did not program the BT weights");
        }
    }
    if io.last_write(AR_QUIET1) != Some(AR_QUIET1_QUIET_ACK_CTS_ENABLE) {
        return TestResult::Fail("enable_3wire did not set QUIET_ACK_CTS_ENABLE");
    }
    if io.last_write(AR_PCU_MISC) != Some(0xffef_0000) {
        return TestResult::Fail("enable_3wire did not clear BT_ANT_PREVENT_RX");
    }
    // WLAN-active (pin 5) out, muxed to RX_CLEAR_EXTERNAL (4 << 25).
    if io.last_write(AR_GPIO_OE_OUT) != Some(0x3 << 10) {
        return TestResult::Fail("enable_3wire did not request WLAN-active out");
    }
    if io.last_write(AR_GPIO_OUTPUT_MUX1) != Some(4 << 25) {
        return TestResult::Fail("enable_3wire muxed WLAN-active wrong");
    }
    // 2WIRE: GPIO out only (TX_FRAME mux), no mode/weight register.
    let mut io = BtcoexFixture::new();
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    btcoex.scheme = Scheme::TwoWire;
    btcoex.wlanactive_gpio = 5;
    if enable_2wire(&mut io, &btcoex).is_err() {
        return TestResult::Fail("enable_2wire errored");
    }
    if io.last_write(AR_GPIO_OUTPUT_MUX1) != Some(3 << 25) {
        return TestResult::Fail("enable_2wire muxed WLAN-active wrong");
    }
    if io.last_write(AR_BT_COEX_MODE).is_some() || io.last_write(AR_BT_COEX_WL_WEIGHTS0).is_some() {
        return TestResult::Fail("enable_2wire programmed mode/weight registers");
    }
    // SoC 3WIRE: the mode2 PHY-error-collision clear runs first, but
    // the image write that follows re-sets the bit (Linux quirk).
    let mut io = BtcoexFixture::new();
    io.regs.insert(AR_BT_COEX_MODE2, 0xffff_fffe);
    io.regs.insert(AR_PCU_MISC, 0xffff_0000);
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_scheme(&mut btcoex, true, 0);
    init_btcoex_hw(&mut btcoex, 0, true);
    bt_stomp(&mut btcoex, StompType::All);
    if enable_3wire(&mut io, &btcoex, true).is_err() {
        return TestResult::Fail("SoC enable_3wire errored");
    }
    if io.last_write(AR_BT_COEX_MODE3) != Some(0x2020) {
        return TestResult::Fail("SoC enable_3wire did not program mode3");
    }
    if io.last_write(AR_BT_COEX_MODE2) != Some(0x8019_0032) {
        return TestResult::Fail("SoC enable_3wire mode2 image is wrong");
    }
    let clear_pos = io
        .ops
        .iter()
        .position(|(a, v)| *a == AR_BT_COEX_MODE2 && *v == 0x7fff_fffe);
    let image_pos = io
        .ops
        .iter()
        .rposition(|(a, v)| *a == AR_BT_COEX_MODE2 && *v == 0x8019_0032);
    if clear_pos.is_none_or(|c| image_pos.is_none_or(|i| c >= i)) {
        return TestResult::Fail("SoC enable_3wire did not clear-then-image mode2");
    }
    TestResult::Pass
}

fn btcoex_enable_disable_dispatcher() -> TestResult {
    // NONE: enable is a no-op, enabled stays false, nothing written.
    let mut io = BtcoexFixture::new();
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_scheme(&mut btcoex, false, 0);
    if btcoex_enable(&mut io, &mut btcoex, false).is_err() {
        return TestResult::Fail("NONE btcoex_enable errored");
    }
    if btcoex.enabled || !io.ops.is_empty() {
        return TestResult::Fail("NONE btcoex_enable touched state");
    }
    // 3WIRE: enable programs the path, the PDPU pull-down, enabled.
    let mut io = BtcoexFixture::new();
    io.regs.insert(AR_GPIO_PDPU, 0x0000_ffff);
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_scheme(&mut btcoex, true, 0);
    init_btcoex_hw(&mut btcoex, 0, false);
    bt_stomp(&mut btcoex, StompType::None);
    if btcoex_enable(&mut io, &mut btcoex, false).is_err() {
        return TestResult::Fail("3WIRE btcoex_enable errored");
    }
    if !btcoex.enabled {
        return TestResult::Fail("3WIRE btcoex_enable did not mark enabled");
    }
    if io.last_write(AR_BT_COEX_MODE) != Some(0x0508_1b00) {
        return TestResult::Fail("3WIRE btcoex_enable skipped the 3WIRE path");
    }
    if io.last_write(AR_GPIO_PDPU) != Some(0x0000_feff) {
        return TestResult::Fail("3WIRE btcoex_enable PDPU pull-down is wrong");
    }
    // MCI: enable delegates to enable_mci (MCI weight regs, no PDPU).
    let mut io = BtcoexFixture::new();
    io.regs.insert(AR_GPIO_PDPU, 0x0000_ffff);
    let mut btcoex = Btcoex::new(Chip::Ar9462);
    init_scheme(&mut btcoex, true, HW_CAP_MCI);
    init_mci(&mut btcoex);
    bt_stomp(&mut btcoex, StompType::None);
    if btcoex_enable(&mut io, &mut btcoex, false).is_err() {
        return TestResult::Fail("MCI btcoex_enable errored");
    }
    if !btcoex.enabled {
        return TestResult::Fail("MCI btcoex_enable did not mark enabled");
    }
    if io.last_write(AR_BTCOEX_WL_WEIGHTS0) != Some(0x0101_7d01) {
        return TestResult::Fail("MCI btcoex_enable skipped the MCI path");
    }
    if io.last_write(AR_GPIO_PDPU).is_some() {
        return TestResult::Fail("MCI btcoex_enable programmed the PDPU pull-down");
    }
    // 2WIRE (set directly: init_scheme never selects it for AR9003):
    // enable runs the 2WIRE GPIO path plus the PDPU pull-down.
    let mut io = BtcoexFixture::new();
    io.regs.insert(AR_GPIO_PDPU, 0x0000_ffff);
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    btcoex.scheme = Scheme::TwoWire;
    btcoex.wlanactive_gpio = 5;
    btcoex.btactive_gpio = 4;
    if btcoex_enable(&mut io, &mut btcoex, false).is_err() {
        return TestResult::Fail("2WIRE btcoex_enable errored");
    }
    if !btcoex.enabled || io.last_write(AR_GPIO_OUTPUT_MUX1) != Some(3 << 25) {
        return TestResult::Fail("2WIRE btcoex_enable skipped the 2WIRE path");
    }
    if io.last_write(AR_GPIO_PDPU) != Some(0x0000_feff) {
        return TestResult::Fail("2WIRE btcoex_enable PDPU pull-down is wrong");
    }
    // 3WIRE disable: enabled cleared, mode parked, weights zeroed.
    let mut io = BtcoexFixture::new();
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    init_scheme(&mut btcoex, true, 0);
    btcoex.enabled = true;
    if btcoex_disable(&mut io, &mut btcoex).is_err() {
        return TestResult::Fail("3WIRE btcoex_disable errored");
    }
    if btcoex.enabled {
        return TestResult::Fail("3WIRE btcoex_disable did not clear enabled");
    }
    if io.last_write(AR_BT_COEX_MODE) != Some(0x0000_1c00) {
        return TestResult::Fail("3WIRE btcoex_disable did not park the mode");
    }
    if io.last_write(AR_BT_COEX_MODE2) != Some(0) {
        return TestResult::Fail("3WIRE btcoex_disable did not zero mode2");
    }
    if io.last_write(AR_BT_COEX_WL_WEIGHTS0) != Some(0)
        || io.last_write(AR_BT_COEX_WL_WEIGHTS1) != Some(0)
    {
        return TestResult::Fail("3WIRE btcoex_disable did not zero the WLAN weights");
    }
    for i in 0..4u32 {
        if io.last_write(ar_bt_coex_bt_weights(i)) != Some(0) {
            return TestResult::Fail("3WIRE btcoex_disable did not zero the BT weights");
        }
    }
    // WLAN-active re-muxed to a plain output (mux field 0, OE drive ALL).
    if io.last_write(AR_GPIO_OUTPUT_MUX1) != Some(0)
        || io.last_write(AR_GPIO_OE_OUT) != Some(0x3 << 10)
    {
        return TestResult::Fail("3WIRE btcoex_disable did not re-mux WLAN-active");
    }
    // MCI disable delegates to disable_mci (stomped weights, no mode).
    let mut io = BtcoexFixture::new();
    let mut btcoex = Btcoex::new(Chip::Ar9462);
    init_scheme(&mut btcoex, true, HW_CAP_MCI);
    init_mci(&mut btcoex);
    btcoex.enabled = true;
    bt_stomp(&mut btcoex, StompType::All);
    if btcoex_disable(&mut io, &mut btcoex).is_err() {
        return TestResult::Fail("MCI btcoex_disable errored");
    }
    if btcoex.enabled {
        return TestResult::Fail("MCI btcoex_disable did not clear enabled");
    }
    if io.last_write(AR_BTCOEX_WL_WEIGHTS0) != Some(0x0101_7d01) {
        return TestResult::Fail("MCI btcoex_disable skipped the MCI path");
    }
    if io.last_write(AR_BT_COEX_MODE).is_some() {
        return TestResult::Fail("MCI btcoex_disable touched the mode register");
    }
    // 2WIRE disable: only the GPIO re-mux, no mode/weight parking.
    let mut io = BtcoexFixture::new();
    let mut btcoex = Btcoex::new(Chip::Ar9300);
    btcoex.scheme = Scheme::TwoWire;
    btcoex.wlanactive_gpio = 5;
    btcoex.enabled = true;
    if btcoex_disable(&mut io, &mut btcoex).is_err() {
        return TestResult::Fail("2WIRE btcoex_disable errored");
    }
    if btcoex.enabled || io.last_write(AR_GPIO_OUTPUT_MUX1) != Some(0) {
        return TestResult::Fail("2WIRE btcoex_disable did not re-mux WLAN-active");
    }
    if io.last_write(AR_BT_COEX_MODE).is_some() {
        return TestResult::Fail("2WIRE btcoex_disable touched the mode register");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_init_scheme);
kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_init_mci);
kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_set_weight);
kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_enable_disable_mci);
kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_init_btcoex_hw);
kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_init_2wire_3wire);
kernel_test_in!("drivers/wireless/ath9k/ar9003", btcoex_enable_2wire_3wire);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    btcoex_enable_disable_dispatcher
);
