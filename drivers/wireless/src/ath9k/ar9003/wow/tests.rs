use super::super::Chip;
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const STA_MAC: [u8; 6] = [0x00, 0x03, 0x7f, 0x12, 0x34, 0x56];
const AP_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Read(u64),
    Write(u64, u32),
    Wait(u64, u32, u32, u64),
}

#[derive(Default)]
struct Model {
    registers: BTreeMap<u64, u32>,
    ops: Vec<Op>,
    revoked: bool,
}

impl RegisterIo for Model {
    fn authorized(&self) -> bool {
        !self.revoked
    }
    fn read32(&mut self, offset: u64) -> u32 {
        self.ops.push(Op::Read(offset));
        *self.registers.get(&offset).unwrap_or(&0)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.ops.push(Op::Write(offset, value));
        // AR_CR_RXD is a command bit: writing it must not clear the
        // AR_CR_RXE status bits, which reflect the Rx DMA engine state
        // and clear only when the engine actually stops (reg.h). The
        // seeded RXE value is what the wait_us stop decision reads.
        let stored = if offset == AR_CR {
            value | (self.registers.get(&offset).copied().unwrap_or(0) & AR_CR_RXE)
        } else {
            value
        };
        self.registers.insert(offset, stored);
    }
    fn wait_us(
        &mut self,
        offset: u64,
        mask: u32,
        expected: u32,
        timeout_us: u64,
    ) -> Result<u32, BringUpError> {
        // Single-shot, no scheduler spin: the Rx-DMA stop is decided by
        // the seeded register value.
        self.ops.push(Op::Wait(offset, mask, expected, timeout_us));
        let value = self.read32(offset);
        if value == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        if value & mask == expected {
            Ok(value)
        } else {
            Err(BringUpError::Timeout)
        }
    }
}

fn rev(chip: Chip, mac_rev: u8) -> Revision {
    Revision {
        chip,
        mac_rev,
        pcie: true,
    }
}

fn last_write(ops: &[Op], addr: u64) -> Option<u32> {
    ops.iter().rev().find_map(|op| match op {
        Op::Write(a, v) if *a == addr => Some(*v),
        _ => None,
    })
}

fn smoke_ath9k_wow_pci_table_is_ar9462_subsystem_only() -> TestResult {
    if WOW_SUBSYSTEMS.len() != 13 {
        return TestResult::Fail("WoW subsystem table is not the 13 pci.c entries");
    }
    // Verified entries named in #1912.
    for (subvendor, subdevice) in [(0x1a3b, 0x2110), (0x1043, 0x850e)] {
        if !wow_capable(0x0034, subvendor, subdevice) {
            return TestResult::Fail("named WoW subsystem entry not recognised");
        }
    }
    // Every table entry is WoW-capable on 0x0034, and only there.
    for &(subvendor, subdevice) in WOW_SUBSYSTEMS {
        if !wow_capable(0x0034, subvendor, subdevice)
            || wow_capable(0x0032, subvendor, subdevice)
            || driver_data(0x0034, subvendor, subdevice) != ATH9K_PCI_WOW
        {
            return TestResult::Fail("WoW table entry mis-scoped to its device");
        }
    }
    // No WoW driver_data for the other AR9003 parts, even with a listed
    // subsystem pair — the #1382 answer.
    for device in [0x0032, 0x0033, 0x0036, 0x0037, 0x0030] {
        if wow_capable(device, 0x1a3b, 0x2110) || driver_data(device, 0x1a3b, 0x2110) != 0 {
            return TestResult::Fail("non-AR9462 device claimed WoW capability");
        }
    }
    // Unknown subsystem on an AR9462: no WoW.
    if wow_capable(0x0034, 0x168c, 0xffff) || driver_data(0x0034, 0x168c, 0xffff) != 0 {
        return TestResult::Fail("unknown AR9462 subsystem claimed WoW capability");
    }
    if ATH9K_PCI_WOW != 0x0010 {
        return TestResult::Fail("ATH9K_PCI_WOW is not ath9k.h:955 0x0010");
    }
    if !init_capable(ATH9K_PCI_WOW, false) || !init_capable(0, true) || init_capable(0, false) {
        return TestResult::Fail("WoW init gating differs from ath9k_init_wow");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/wow",
    smoke_ath9k_wow_pci_table_is_ar9462_subsystem_only
);

fn smoke_ath9k_wow_patterns_and_support_follow_revision() -> TestResult {
    // hw.c: AR9462 2.0+/AR9565 1.1+ get the full 16 patterns.
    for (chip, mac_rev) in [(Chip::Ar9462, 2), (Chip::Ar9462, 3), (Chip::Ar9565, 2)] {
        let revision = rev(chip, mac_rev);
        if Wow::new(&revision, false).max_patterns != MAX_NUM_PATTERN as u8
            || WowlanSupport::for_revision(&revision) != WowlanSupport::Full
            || WowlanSupport::for_revision(&revision).n_patterns() != 14
        {
            return TestResult::Fail("newer AR9462/AR9565 revision lacks full WoW patterns");
        }
    }
    // Everything else gets the legacy 8.
    for (chip, mac_rev) in [
        (Chip::Ar9565, 0),
        (Chip::Ar9565, 1),
        (Chip::Ar9485, 1),
        (Chip::Ar9580, 4),
        (Chip::Ar9300, 0),
    ] {
        let revision = rev(chip, mac_rev);
        if Wow::new(&revision, false).max_patterns != MAX_NUM_PATTERN_LEGACY as u8
            || WowlanSupport::for_revision(&revision) != WowlanSupport::Legacy
            || WowlanSupport::for_revision(&revision).n_patterns() != MAX_NUM_USER_PATTERN as u8
            || WowlanSupport::for_revision(&revision).pattern_max_len() != MAX_PATTERN_SIZE
        {
            return TestResult::Fail("legacy revision got full WoW patterns");
        }
    }
    // Trigger mapping (wow.c::ath9k_wow_map_triggers).
    if map_triggers(&WowlanRequest {
        disconnect: true,
        magic_pkt: true,
        n_patterns: 1,
    }) != AH_WOW_LINK_CHANGE
        | AH_WOW_BEACON_MISS
        | AH_WOW_MAGIC_PATTERN_EN
        | AH_WOW_USER_PATTERN_EN
        || map_triggers(&WowlanRequest::default()) != 0
        || map_triggers(&WowlanRequest {
            disconnect: false,
            magic_pkt: true,
            n_patterns: 0,
        }) != AH_WOW_MAGIC_PATTERN_EN
    {
        return TestResult::Fail("WoW trigger mapping differs from wow.c");
    }
    // Disassociate/deauthenticate patterns (wow.c).
    let [disassoc, deauth] = disassoc_deauth_patterns(&AP_MAC);
    if disassoc.bytes[0] != 0xa0
        || deauth.bytes[0] != 0xc0
        || disassoc.len != 22
        || deauth.len != 22
        || disassoc.bytes[10..16] != AP_MAC
        || disassoc.bytes[16..22] != AP_MAC
        || deauth.bytes[10..16] != AP_MAC
        || disassoc.bytes[1..10] != [0; 9]
        || disassoc.mask[0] != 0xfe
        || disassoc.mask[1] != 0x03
        || disassoc.mask[2] != 0xc0
        || disassoc.mask[3..] != [0xff; 29]
        || deauth.mask != disassoc.mask
    {
        return TestResult::Fail("disassoc/deauth WoW pattern differs from wow.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/wow",
    smoke_ath9k_wow_patterns_and_support_follow_revision
);

fn smoke_ath9k_wow_apply_pattern_programs_slots_and_refuses_overflow() -> TestResult {
    let mut wow = Wow::new(&rev(Chip::Ar9462, 2), false);
    let mut model = Model::default();
    let [disassoc, _] = disassoc_deauth_patterns(&AP_MAC);
    if wow
        .apply_pattern(&mut model, &disassoc.bytes, &disassoc.mask, 0, disassoc.len)
        .is_err()
    {
        return TestResult::Fail("legacy WoW pattern 0 refused");
    }
    // Exact register trace for pattern 0: enable bit, 64 pattern words
    // at 0xe100, 8 mask words at 0xec00, LENGTH1 with len 22 at the top
    // byte (pattern 0 shift 24).
    let mut expected = vec![Op::Read(0x825c), Op::Write(0x825c, 0x1)];
    let words = [
        0x0000_00a0u32,
        0,
        0x1100_0000,
        0x5544_3322,
        0x3322_1100,
        0x0000_5544,
    ];
    for (i, word) in words.iter().enumerate() {
        expected.push(Op::Write(0xe100 + i as u64 * 4, *word));
    }
    for i in words.len()..64 {
        expected.push(Op::Write(0xe100 + i as u64 * 4, 0));
    }
    expected.push(Op::Write(0xec00, 0xffc0_03fe));
    for i in 1..8 {
        expected.push(Op::Write(0xec00 + i as u64 * 4, 0xffff_ffff));
    }
    expected.push(Op::Read(0x8360));
    expected.push(Op::Write(0x8360, 0x1600_0000));
    if model.ops != expected {
        return TestResult::Fail("WoW pattern 0 register trace differs from ar9003_wow.c");
    }
    if wow.event_mask != 0x100 || wow.event_mask2 != 0 {
        return TestResult::Fail("WoW pattern 0 did not set event mask bit 8");
    }
    // Extended slot 8 programs AR_MAC_PCU_WOW4, the second event mask
    // and LENGTH3 (pattern 8 shift 24). The mask base is
    // reg_wow.h::AR_WOW_TB_MASK(8) = 0xec00 + (8 << 5) = 0xed00.
    model.ops.clear();
    let pattern = [0xabu8; MAX_PATTERN_SIZE];
    let mask = [0x5au8; MAX_PATTERN_MASK_SIZE];
    if wow
        .apply_pattern(&mut model, &pattern, &mask, 8, 22)
        .is_err()
    {
        return TestResult::Fail("extended WoW pattern 8 refused");
    }
    if last_write(&model.ops, 0x8370) != Some(0x1)
        || last_write(&model.ops, 0xe900) != Some(0xabab_abab)
        || last_write(&model.ops, 0xed00) != Some(0x5a5a_5a5a)
        || last_write(&model.ops, 0x8380) != Some(0x1600_0000)
        || wow.event_mask2 != 0x100
    {
        return TestResult::Fail("WoW pattern 8 did not take the WOW4 path");
    }
    // Slot 15 programs LENGTH4 with shift 0.
    model.ops.clear();
    if wow
        .apply_pattern(&mut model, &pattern, &mask, 15, 22)
        .is_err()
        || last_write(&model.ops, 0x8384) != Some(22)
        || wow.event_mask2 != 0x8100
    {
        return TestResult::Fail("WoW pattern 15 did not take the LENGTH4 path");
    }
    // No free slot: Linux -ENOSPC.
    if wow.apply_pattern(&mut model, &pattern, &mask, 16, 22) != Err(BringUpError::BadState) {
        return TestResult::Fail("WoW pattern 16 past capacity was admitted");
    }
    let mut legacy = Wow::new(&rev(Chip::Ar9485, 1), false);
    if legacy.apply_pattern(&mut model, &pattern, &mask, 8, 22) != Err(BringUpError::BadState) {
        return TestResult::Fail("legacy WoW pattern 8 past capacity was admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/wow",
    smoke_ath9k_wow_apply_pattern_programs_slots_and_refuses_overflow
);

fn smoke_ath9k_wow_enable_ar9462_two_ghz() -> TestResult {
    let mut wow = Wow::new(&rev(Chip::Ar9462, 2), false);
    let mut model = Model::default();
    let triggers = AH_WOW_MAGIC_PATTERN_EN | AH_WOW_LINK_CHANGE | AH_WOW_BEACON_MISS;
    if wow
        .enable(
            &mut model,
            &rev(Chip::Ar9462, 2),
            triggers,
            &KeepAlive {
                tx_chainmask: 3,
                is_2ghz: true,
                sta_mac: STA_MAC,
                ap_mac: AP_MAC,
            },
        )
        .is_err()
    {
        return TestResult::Fail("AR9462 WoW enable refused");
    }
    let mut expected = vec![
        Op::Read(0x4014),
        Op::Write(0x4014, 0x1060_8000),
        Op::Read(0x4014),
        Op::Write(0x4014, 0x1040_8000),
        Op::Read(0x825c),
        Op::Write(0x825c, 0x2000_0000),
        Op::Read(0x8260),
        Op::Write(0x8260, 0x80922),
        Op::Write(0x8274, 0x4000_0000),
        Op::Write(0x8278, 0x7080),
        Op::Write(0x8288, 0xfa0),
    ];
    // Keep-alive descriptor words (tx_tries 0, CCK 1M, chainmask 3).
    let ctl = [0x003f_001c_u32, 0, 0xf0000, 0x1b, 0, 0, 0, 0xc, 0, 0, 0, 0];
    for (i, word) in ctl.iter().enumerate() {
        expected.push(Op::Write(0xe000 + i as u64 * 4, *word));
    }
    // AR9462 2.0 extra descriptor word, then the frame at word 13.
    expected.push(Op::Write(0xe030, 0));
    let data = [
        0x003d_0148_u32,
        0x3322_1100,
        0x0300_5544,
        0x5634_127f,
        0x3322_1100,
        0x5544,
    ];
    for (i, word) in data.iter().enumerate() {
        expected.push(Op::Write(0xe034 + i as u64 * 4, *word));
    }
    expected.extend([
        Op::Read(0x827c),
        Op::Write(0x827c, 0),
        Op::Read(0x8018),
        Op::Write(0x8018, 0x2000),
        Op::Read(0x8270),
        Op::Write(0x8270, 1),
        Op::Read(0x825c),
        Op::Write(0x825c, 0x2005_0000),
        Op::Write(0x8368, 0xffff),
        Op::Read(0x4014),
        Op::Write(0x4014, 0x1f40_8000),
        Op::Read(0x8004),
        Op::Write(0x8004, 0),
        Op::Read(0x18c08),
        Op::Write(0x18c08, 0x2000),
        Op::Read(0x4004),
        Op::Write(0x4004, 0x240000),
        Op::Read(0x83d0),
        Op::Write(0x83d0, 0),
        Op::Read(0x8004),
        Op::Write(0x8004, 0x40000),
        Op::Write(0x0008, 0x20),
        Op::Wait(0x0008, 0xc, 0, 100_000),
        Op::Read(0x0008),
        Op::Read(0x83d8),
        Op::Read(0x83a0),
        Op::Write(0x83a0, 0),
        Op::Write(0x704c, 2),
    ]);
    if model.ops != expected {
        return TestResult::Fail("AR9462 WoW enable trace differs from ar9003_wow.c");
    }
    if wow.event_mask != 0x320000 || wow.event_mask2 != 0 {
        return TestResult::Fail("AR9462 WoW enable did not accumulate the event mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/wow",
    smoke_ath9k_wow_enable_ar9462_two_ghz
);

fn smoke_ath9k_wow_enable_ar9485_five_ghz_no_triggers() -> TestResult {
    let mut wow = Wow::new(&rev(Chip::Ar9485, 1), false);
    let mut model = Model::default();
    if wow
        .enable(
            &mut model,
            &rev(Chip::Ar9485, 1),
            0,
            &KeepAlive {
                tx_chainmask: 1,
                is_2ghz: false,
                sta_mac: STA_MAC,
                ap_mac: AP_MAC,
            },
        )
        .is_err()
    {
        return TestResult::Fail("AR9485 WoW enable refused");
    }
    // No triggers: beacon timeout maxed, keep-alive never, no magic or
    // beacon-miss bits, keep-alive failure disabled.
    if last_write(&model.ops, 0x8274) != Some(0xffff_ffff)
        || last_write(&model.ops, 0x8278) != Some(0xffff_ffff)
        || last_write(&model.ops, 0x827c) != Some(0x2)
        || last_write(&model.ops, 0x8270) != Some(0)
        || last_write(&model.ops, 0x825c) != Some(0x2004_0000)
        || wow.event_mask != 0
    {
        return TestResult::Fail("trigger-less WoW enable programmed wake events");
    }
    // 5 GHz OFDM 6M, one chain, frame at word 12 (no extra descriptor).
    if last_write(&model.ops, 0xe00c) != Some(0xb)
        || last_write(&model.ops, 0xe01c) != Some(0x4)
        || last_write(&model.ops, 0xe030) != Some(0x003d_0148)
        || last_write(&model.ops, 0xe044) != Some(0x5544)
    {
        return TestResult::Fail("5 GHz keep-alive frame differs from ar9003_wow.c");
    }
    // No AR9462 D1D3_REAL rewrite: the final PM word keeps D1D3.
    if last_write(&model.ops, 0x4014) != Some(0x1f40_8000) {
        return TestResult::Fail("AR9485 PM control word differs from ar9003_wow.c");
    }
    // AR9485 TSF2 branch reads the NDP2 timer mode, not the gen-timer select.
    if !model.ops.contains(&Op::Read(0x81c0)) || model.ops.contains(&Op::Read(0x83d8)) {
        return TestResult::Fail("AR9485 WoW sleep took the wrong TSF2 branch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/wow",
    smoke_ath9k_wow_enable_ar9485_five_ghz_no_triggers
);

fn smoke_ath9k_wow_wakeup_decodes_and_clears() -> TestResult {
    let mut wow = Wow::new(&rev(Chip::Ar9462, 2), false);
    wow.event_mask = 0x320100;
    wow.event_mask2 = 0x100;
    let mut model = Model::default();
    model.registers.insert(0x825c, 0x0032_0300);
    model.registers.insert(0x8370, 0x100);
    model.registers.insert(0x4014, 0x1f40_8000);
    model.registers.insert(0x83a0, 0);
    let wakeup = match wow.wakeup(&mut model, &rev(Chip::Ar9462, 2)) {
        Ok(wakeup) => wakeup,
        Err(_) => return TestResult::Fail("WoW wakeup refused"),
    };
    // Bit 9 (pattern 1) is spurious: not in the enabled mask, so it is
    // dropped; magic + user pattern + keep-alive fail + beacon fail stay.
    if wakeup.status
        != AH_WOW_MAGIC_PATTERN_EN
            | AH_WOW_USER_PATTERN_EN
            | AH_WOW_LINK_CHANGE
            | AH_WOW_BEACON_MISS
        || !wakeup.tsf2_restart
        || !wakeup.restore_pcie_powersave
        || wow.event_mask != 0
        || wow.event_mask2 != 0
    {
        return TestResult::Fail("WoW wakeup decoded the wrong reason");
    }
    if last_write(&model.ops, 0x4014) != Some(0x1060_8000)
        || last_write(&model.ops, 0x825c) != Some(0x20300)
        || last_write(&model.ops, 0x8370) != Some(0x100)
        || last_write(&model.ops, 0x8018) != Some(0x700)
    {
        return TestResult::Fail("WoW wakeup did not clear events and restore RSSI_THR");
    }
    // WOW4-only wake: the second status register alone reports a user pattern.
    let mut wow = Wow::new(&rev(Chip::Ar9565, 2), false);
    wow.event_mask2 = 0x100;
    let mut model = Model::default();
    model.registers.insert(0x8370, 0x100);
    model.registers.insert(0x83a0, 1);
    let wakeup = match wow.wakeup(&mut model, &rev(Chip::Ar9565, 2)) {
        Ok(wakeup) => wakeup,
        Err(_) => return TestResult::Fail("WOW4-only wakeup refused"),
    };
    if wakeup.status != AH_WOW_USER_PATTERN_EN || wakeup.tsf2_restart {
        return TestResult::Fail("WOW4-only wakeup mis-decoded");
    }
    // AR9300 has no TSF2 branch: no DIRECT_CONNECT read at all.
    let mut wow = Wow::new(&rev(Chip::Ar9300, 0), false);
    let mut model = Model::default();
    let wakeup = match wow.wakeup(&mut model, &rev(Chip::Ar9300, 0)) {
        Ok(wakeup) => wakeup,
        Err(_) => return TestResult::Fail("AR9300 wakeup refused"),
    };
    if wakeup.tsf2_restart || model.ops.contains(&Op::Read(0x83a0)) {
        return TestResult::Fail("AR9300 wakeup took a TSF2 branch");
    }
    // A vanished device is refused, not decoded.
    let mut wow = Wow::new(&rev(Chip::Ar9462, 2), false);
    let mut model = Model::default();
    model.registers.insert(0x825c, u32::MAX);
    if wow.wakeup(&mut model, &rev(Chip::Ar9462, 2)) != Err(BringUpError::DeviceGone) {
        return TestResult::Fail("WoW wakeup decoded a vanished device");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/wow",
    smoke_ath9k_wow_wakeup_decodes_and_clears
);

fn smoke_ath9k_wow_sleep_rx_stop_timeout_aborts() -> TestResult {
    let mut wow = Wow::new(&rev(Chip::Ar9462, 2), false);
    let mut model = Model::default();
    model.registers.insert(0x0008, 0xc);
    if wow.enable(
        &mut model,
        &rev(Chip::Ar9462, 2),
        AH_WOW_MAGIC_PATTERN_EN,
        &KeepAlive {
            tx_chainmask: 3,
            is_2ghz: true,
            sta_mac: STA_MAC,
            ap_mac: AP_MAC,
        },
    ) != Err(BringUpError::Timeout)
    {
        return TestResult::Fail("WoW sleep entered with Rx DMA still running");
    }
    // The abort happens at the Rx-DMA wait: no TSF2 or force-wake write.
    if model.ops.contains(&Op::Write(0x704c, 2)) || model.ops.contains(&Op::Read(0x83d8)) {
        return TestResult::Fail("timed-out WoW sleep continued past the Rx stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/wow",
    smoke_ath9k_wow_sleep_rx_stop_timeout_aborts
);

fn smoke_ath9k_wow_mci_enabled_keeps_awake_and_skips_pwr_sav() -> TestResult {
    // The flag is stored exactly as constructed.
    if !Wow::new(&rev(Chip::Ar9462, 2), true).mci_enabled
        || Wow::new(&rev(Chip::Ar9462, 2), false).mci_enabled
    {
        return TestResult::Fail("Wow::new did not store the MCI flag");
    }
    // The probe site computes it from the landed capability:
    // `btcoex::mci_is_enabled` over `fill_cap_info` (§3.12). MCI parts
    // with the capability set, and only those, get the flag.
    use super::super::{btcoex, fill_cap_info, AR_ENT_OTP_49GHZ_DISABLE};
    if !btcoex::mci_is_enabled(true, fill_cap_info(Chip::Ar9462, 0))
        || !btcoex::mci_is_enabled(true, fill_cap_info(Chip::Ar9565, 0))
        || btcoex::mci_is_enabled(true, fill_cap_info(Chip::Ar9485, 0))
        || btcoex::mci_is_enabled(true, fill_cap_info(Chip::Ar9462, AR_ENT_OTP_49GHZ_DISABLE))
        || btcoex::mci_is_enabled(false, fill_cap_info(Chip::Ar9462, 0))
    {
        return TestResult::Fail("probe-time mci_enabled differs from fill_cap_info");
    }
    // `ar9003_wow.c::ath9k_hw_wow_enable` with MCI enabled (AR9462 2.0,
    // same triggers and keep-alive as the plain enable trace): the
    // `AR_RTC_KEEP_AWAKE` write (`reg.h` `0x7034`, value `0x2`) fires
    // twice — once in `enable` (line 445) and once in the WoW sleep
    // (line 61) — while `AR_STA_ID1_PWR_SAV` is never set.
    let keep_alive = KeepAlive {
        tx_chainmask: 3,
        is_2ghz: true,
        sta_mac: STA_MAC,
        ap_mac: AP_MAC,
    };
    let triggers = AH_WOW_MAGIC_PATTERN_EN | AH_WOW_LINK_CHANGE | AH_WOW_BEACON_MISS;
    let mut wow = Wow::new(&rev(Chip::Ar9462, 2), true);
    let mut model = Model::default();
    if wow
        .enable(&mut model, &rev(Chip::Ar9462, 2), triggers, &keep_alive)
        .is_err()
    {
        return TestResult::Fail("MCI WoW enable refused");
    }
    let keep_awake = model
        .ops
        .iter()
        .filter(|op| matches!(op, Op::Write(0x7034, 0x2)))
        .count();
    if keep_awake != 2 {
        return TestResult::Fail("MCI WoW enable did not write AR_RTC_KEEP_AWAKE twice");
    }
    if last_write(&model.ops, 0x8004) != Some(0) {
        return TestResult::Fail("MCI WoW enable set AR_STA_ID1_PWR_SAV");
    }
    // The force-wake write and the event mask are untouched by the MCI
    // branches.
    if !model.ops.contains(&Op::Write(0x704c, 2)) || wow.event_mask != 0x320000 {
        return TestResult::Fail("MCI WoW enable changed the non-MCI tail");
    }
    // Negative control: the same enable without MCI never touches
    // `AR_RTC_KEEP_AWAKE` and sets `PWR_SAV` (`0x40000`).
    let mut wow = Wow::new(&rev(Chip::Ar9462, 2), false);
    let mut model = Model::default();
    if wow
        .enable(&mut model, &rev(Chip::Ar9462, 2), triggers, &keep_alive)
        .is_err()
    {
        return TestResult::Fail("non-MCI WoW enable refused");
    }
    if model
        .ops
        .iter()
        .any(|op| matches!(op, Op::Write(0x7034, _)))
        || last_write(&model.ops, 0x8004) != Some(0x40000)
    {
        return TestResult::Fail("non-MCI WoW enable took an MCI branch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003/wow",
    smoke_ath9k_wow_mci_enabled_keeps_awake_and_skips_pwr_sav
);
