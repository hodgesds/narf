use super::eeprom::{restore, BlockHeader, Limits, Source, Store};
use super::ini::{RxGain, Tables, TxGain};
use super::templates::{AR9300_DEFAULT, AR9300_EEPROM_BYTES, AR9300_X112, TEMPLATES};
use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const SREV_9300_22: u32 = 0x001c_03ff;
const MAC: [u8; 6] = [0x00, 0x03, 0x7f, 0x12, 0x34, 0x56];

/// One compressed block: header, payload, little-endian additive checksum.
fn block(code: u8, reference: u8, payload: &[u8]) -> Vec<u8> {
    let length = payload.len();
    let mut out = vec![
        (code << 5) | (reference & 0x1f),
        (((reference & 0x20) << 2) as usize | ((length >> 4) & 0x7f)) as u8,
        (((length & 0xf) << 4) | 0x2) as u8,
        0x01,
    ];
    out.extend_from_slice(payload);
    let sum = payload
        .iter()
        .fold(0u16, |sum, &byte| sum.wrapping_add(u16::from(byte)));
    out.extend_from_slice(&sum.to_le_bytes());
    out
}

/// A `(offset, length, bytes)` run list writing `MAC` at `macAddr`.
fn mac_runs() -> Vec<u8> {
    let mut runs = vec![2, 6];
    runs.extend_from_slice(&MAC);
    runs
}

/// Byte-addressed non-volatile stores; a stream is laid out downward from
/// its base, as `ar9300_read_eeprom`/`ar9300_read_otp` read it.
struct Stores {
    eeprom: Vec<u8>,
    otp: Vec<u8>,
    eeprom_reads: usize,
}

impl Stores {
    fn blank() -> Self {
        Self {
            eeprom: vec![0xff; 16 * 1024],
            otp: vec![0; 4 * 1024],
            eeprom_reads: 0,
        }
    }
    fn place(bytes: &mut [u8], base: usize, stream: &[u8]) {
        for (i, &byte) in stream.iter().enumerate() {
            bytes[base - i] = byte;
        }
    }
}

impl Source for Stores {
    fn eeprom_word(&mut self, word: usize) -> Result<u16, identity::BringUpError> {
        self.eeprom_reads += 1;
        Ok(u16::from_le_bytes([
            self.eeprom[2 * word],
            self.eeprom[2 * word + 1],
        ]))
    }
    fn otp_word(&mut self, word: usize) -> Result<u32, identity::BringUpError> {
        let at = 4 * word;
        Ok(u32::from_le_bytes([
            self.otp[at],
            self.otp[at + 1],
            self.otp[at + 2],
            self.otp[at + 3],
        ]))
    }
}

use super::super::identity;
use super::super::identity::BringUpError;

fn expected_x112() -> [u8; AR9300_EEPROM_BYTES] {
    let mut image = AR9300_X112;
    image[2..8].copy_from_slice(&MAC);
    image
}

fn smoke_ath9k_ar9300_eeprom_restores_referenced_template_block() -> TestResult {
    let header = BlockHeader::unpack(&[0x65, 0x00, 0x82, 0x01]);
    if header
        != (BlockHeader {
            code: 3,
            reference: 5,
            length: 8,
            major: 2,
            minor: 1,
        })
    {
        return TestResult::Fail("ar9300_comp_hdr_unpack fields differ");
    }
    let mut stores = Stores::blank();
    Stores::place(&mut stores.eeprom, 0x3ff, &block(3, 5, &mac_runs()));
    let restored = match restore(&mut stores, Limits::for_chip(Chip::Ar9300)) {
        Ok(restored) => restored,
        Err(_) => return TestResult::Fail("valid x112-referenced block was refused"),
    };
    if *restored.image != expected_x112()
        || restored.store != Store::Eeprom
        || restored.base != 0x3ff
        || restored.blocks != 1
        || restored.template != 5
    {
        return TestResult::Fail("restored image is not x112 with the board MAC");
    }
    let identity = match eeprom::Identity::decode(Chip::Ar9300, &restored) {
        Ok(identity) => identity,
        Err(_) => return TestResult::Fail("restored identity refused"),
    };
    if identity.mac != MAC
        || identity.rx_chainmask != 7
        || identity.tx_chainmask != 7
        || identity.template_version != 5
        || identity.eeprom_version != 2
        || identity.regulatory_domains != [0, 0x1f]
        || identity.op_flags != 3
        || identity.tx_gain != 0
        || identity.rx_gain != 0
    {
        return TestResult::Fail("ath9k_hw_ar9300_get_eeprom identity fields differ");
    }
    // A second, reference-0 block overlays the first result.
    let mut stores = Stores::blank();
    let first = block(3, 5, &mac_runs());
    let second = block(3, 0, &[32, 1, 0x33]);
    let mut stream = first.clone();
    stream.extend_from_slice(&second);
    Stores::place(&mut stores.eeprom, 0x3ff, &stream);
    match restore(&mut stores, Limits::for_chip(Chip::Ar9300)) {
        Ok(restored) if restored.blocks == 2 && restored.image[32] == 0x33 => {}
        _ => return TestResult::Fail("reference-0 overlay block not applied in order"),
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_eeprom_restores_referenced_template_block
);

fn smoke_ath9k_ar9300_eeprom_otp_and_base_fallback_order() -> TestResult {
    // EEPROM blank at all three bases: OTP 0x3ff is tried next.
    let mut stores = Stores::blank();
    Stores::place(&mut stores.otp, 0x3ff, &block(3, 5, &mac_runs()));
    match restore(&mut stores, Limits::for_chip(Chip::Ar9300)) {
        Ok(restored) if restored.store == Store::Otp && *restored.image == expected_x112() => {}
        _ => return TestResult::Fail("OTP 0x3ff image not restored after blank EEPROM"),
    }
    // EEPROM at the 4K base wins over OTP.
    let mut stores = Stores::blank();
    Stores::place(&mut stores.eeprom, 0xfff, &block(3, 5, &mac_runs()));
    Stores::place(&mut stores.otp, 0x3ff, &block(3, 4, &mac_runs()));
    match restore(&mut stores, Limits::for_chip(Chip::Ar9300)) {
        Ok(restored) if restored.store == Store::Eeprom && restored.base == 0xfff => {}
        _ => return TestResult::Fail("EEPROM 0xfff base not preferred over OTP"),
    }
    // Nothing anywhere: refused, no default template image.
    let mut stores = Stores::blank();
    if restore(&mut stores, Limits::for_chip(Chip::Ar9300)) != Err(BringUpError::BadMagic) {
        return TestResult::Fail("blank stores did not refuse");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_eeprom_otp_and_base_fallback_order
);

fn smoke_ath9k_ar9300_eeprom_refuses_template_fallbacks() -> TestResult {
    let limits = Limits::for_chip(Chip::Ar9300);
    let restore_one = |stream: &[u8]| {
        let mut stores = Stores::blank();
        Stores::place(&mut stores.eeprom, 0x3ff, stream);
        restore(&mut stores, limits).map(|restored| *restored.image)
    };
    // Reference 0 on the default template, board id 2: Linux-defined base.
    let mut default = AR9300_DEFAULT;
    default[2..8].copy_from_slice(&MAC);
    if restore_one(&block(3, 0, &mac_runs())) != Ok(default) {
        return TestResult::Fail("reference-0 block on the default board id refused");
    }
    // Reference 0 but the board names x112: default bytes would stand in.
    let mut runs = vec![1, 7, 5];
    runs.extend_from_slice(&MAC);
    if restore_one(&block(3, 0, &runs)) != Err(BringUpError::BadIdentity) {
        return TestResult::Fail("default bytes accepted for a non-default board id");
    }
    // No board MAC: the template MAC would be used.
    if restore_one(&block(3, 5, &[32, 1, 0x77])) != Err(BringUpError::BadIdentity) {
        return TestResult::Fail("template MAC accepted");
    }
    // Bad checksum, unknown reference, unknown code, oversize run.
    let mut bad = block(3, 5, &mac_runs());
    let last = bad.len() - 1;
    bad[last] ^= 1;
    if restore_one(&bad) != Err(BringUpError::BadChecksum) {
        return TestResult::Fail("bad block checksum not refused");
    }
    if restore_one(&block(3, 9, &mac_runs())) != Err(BringUpError::BadVersion) {
        return TestResult::Fail("unknown reference template not refused");
    }
    if restore_one(&block(1, 5, &mac_runs())) != Err(BringUpError::BadVersion) {
        return TestResult::Fail("LZMA code not refused");
    }
    let mut runs = mac_runs();
    runs.extend_from_slice(&[0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0, 10]);
    runs.extend_from_slice(&[0; 10]);
    if restore_one(&block(3, 5, &runs)) != Err(BringUpError::BadLength) {
        return TestResult::Fail("run past the map not refused");
    }
    if restore_one(&block(3, 5, &[2, 6, 1])) != Err(BringUpError::BadLength) {
        return TestResult::Fail("run past the block not refused");
    }
    // An uncompressed block must be the whole map, which needs > 1023 bytes.
    if restore_one(&block(0, 0, &[0; 64])) != Err(BringUpError::BadLength) {
        return TestResult::Fail("short _CompressNone block not refused");
    }
    if TEMPLATES.iter().map(|t| t[1]).collect::<Vec<_>>() != [2, 5, 4, 3, 6] {
        return TestResult::Fail("template search order differs from Linux");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_eeprom_refuses_template_fallbacks
);

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Read(u64),
    Write(u64, u32),
    Delay(u64),
}

struct Chip9300 {
    regs: BTreeMap<u64, u32>,
    stores: Stores,
    selected_word: usize,
    selected_otp: usize,
    ops: Vec<Op>,
}

impl Chip9300 {
    fn new(srev: u32) -> Self {
        let mut regs = BTreeMap::new();
        regs.insert(AR_SREV, srev);
        regs.insert(AR_WA, 0x0000_0040);
        regs.insert(AR_RTC_STATUS, AR_RTC_STATUS_ON);
        regs.insert(AR_STA_ID1, AR_STA_ID1_PWR_SAV | 0x10);
        regs.insert(AR_PHY_CHIP_ID, 0x0000_00c0);
        let mut stores = Stores::blank();
        Stores::place(&mut stores.eeprom, 0x3ff, &block(3, 5, &mac_runs()));
        Self {
            regs,
            stores,
            selected_word: 0,
            selected_otp: 0,
            ops: Vec::new(),
        }
    }
}

impl RegisterIo for Chip9300 {
    fn read32(&mut self, offset: u64) -> u32 {
        self.ops.push(Op::Read(offset));
        // The EEPROM window (`AR5416_EEPROM_OFFSET + word * 4`, 8192
        // words for `AR9300_EEPROM_SIZE`) spans 0x2000..0xa000, which
        // also holds real registers (`AR_WA` 0x4004, `AR_SREV` 0x4020,
        // `AR_EEPROM_STATUS_DATA` 0x4084, the RTC block, `AR_STA_ID1`,
        // `AR_PHY_CHIP_ID`). A read of any other window word selects it; a
        // modelled register answers with its own value.
        if (0x2000..0x2000 + 4 * 8192).contains(&offset)
            && offset != 0x4084
            && !self.regs.contains_key(&offset)
        {
            self.selected_word = ((offset - 0x2000) / 4) as usize;
            return 0;
        }
        if (0x14000..0x14000 + 4 * 1024).contains(&offset) {
            self.selected_otp = ((offset - 0x14000) / 4) as usize;
            return 0;
        }
        match offset {
            0x4084 => self
                .stores
                .eeprom_word(self.selected_word)
                .map_or(u32::MAX, u32::from),
            0x15f18 => 0x4,
            0x15f1c => self.stores.otp_word(self.selected_otp).unwrap_or(u32::MAX),
            AR_CFG => {
                let cfg = self.regs.get(&AR_CFG).copied().unwrap_or(0);
                if cfg & AR_CFG_HALT_REQ != 0 {
                    cfg | AR_CFG_HALT_ACK
                } else {
                    cfg
                }
            }
            _ => self.regs.get(&offset).copied().unwrap_or(0),
        }
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.ops.push(Op::Write(offset, value));
        self.regs.insert(offset, value);
    }
    fn delay_us(&mut self, us: u64) {
        self.ops.push(Op::Delay(us));
    }
    fn wait_us(
        &mut self,
        offset: u64,
        mask: u32,
        expected: u32,
        _timeout_us: u64,
    ) -> Result<u32, BringUpError> {
        for _ in 0..4 {
            let value = self.read32(offset);
            if value == u32::MAX {
                return Err(BringUpError::DeviceGone);
            }
            if value & mask == expected {
                return Ok(value);
            }
        }
        Err(BringUpError::Timeout)
    }
}

fn smoke_ath9k_ar9300_identify_power_on_and_restore() -> TestResult {
    if Revision::decode(SREV_9300_22, Chip::Ar9300)
        != Some(Revision {
            chip: Chip::Ar9300,
            mac_rev: 3,
            pcie: true,
        })
        || !Revision::decode(SREV_9300_22, Chip::Ar9300).is_some_and(|r| r.ar9300_22())
        || Revision::decode(SREV_9300_22 | AR_SREV_TYPE2_HOST_MODE, Chip::Ar9300)
            .is_some_and(|r| r.pcie)
        || Revision::decode(0x000c_02ff, Chip::Ar9300).is_some()
        || Revision::decode(0x0000_00c2, Chip::Ar9300).is_some()
        || Chip::for_device(0x0030) != Some(Chip::Ar9300)
        || Chip::for_device(0x002b).is_some()
    {
        return TestResult::Fail("AR_SREV_9300 revision decode differs");
    }
    // Wrong silicon behind 0x0030: refused before any write.
    let mut io = Chip9300::new(0x000c_02ff);
    if identify(&mut io, 0x0030).err() != Some(BringUpError::UnsupportedRevision)
        || io.ops.iter().any(|op| matches!(op, Op::Write(..)))
    {
        return TestResult::Fail("AR9285 silicon not refused before the first write");
    }
    let mut io = Chip9300::new(SREV_9300_22);
    if identify(&mut io, 0x002b).is_ok() || !io.ops.is_empty() {
        return TestResult::Fail("non-AR9003 device ID not refused before access");
    }
    let mut io = Chip9300::new(SREV_9300_22);
    let identified = match identify(&mut io, 0x0030) {
        Ok(identified) => identified,
        Err(_) => return TestResult::Fail("AR9300 identification failed"),
    };
    let wa = 0x40 | AR_WA_D3_L1_DISABLE | AR_WA_ASPM_TIMER_BASED_DISABLE;
    if identified.powered.wa != wa
        || identified.powered.phy_rev != 0xc0
        || identified.identity.mac != MAC
        || *identified.restored.image != expected_x112()
    {
        return TestResult::Fail("AR9300 power-on facts or restored map differ");
    }
    let at = |op: Op| io.ops.iter().position(|o| *o == op);
    let first_wa = at(Op::Write(AR_WA, wa));
    let rtc_off = at(Op::Write(AR_RTC_RESET, 0));
    let rtc_on = at(Op::Write(AR_RTC_RESET, 1));
    let halt = at(Op::Write(AR_CFG, AR_CFG_HALT_REQ));
    let unhalt = io
        .ops
        .iter()
        .rposition(|o| *o == Op::Write(AR_CFG, AR_CFG_HALT_ACK));
    let warm = at(Op::Write(AR_RTC_RC, 1));
    let release = io.ops.iter().rposition(|o| *o == Op::Write(AR_RTC_RC, 0));
    let awake = at(Op::Write(AR_STA_ID1, 0x10));
    let eeprom = at(Op::Read(0x2000 + (0x3ff / 2) * 4));
    if !matches!((first_wa, rtc_off, rtc_on, halt, unhalt, warm, release, awake, eeprom),
        (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f), Some(g), Some(h), Some(i))
            if a < b && b < c && c < d && d < e && e < f && f < g && g < h && h < i)
    {
        return TestResult::Fail("AR9300 power-on/halt/warm-reset/awake/EEPROM order differs");
    }
    if io
        .ops
        .iter()
        .any(|op| matches!(op, Op::Write(AR_RC, v) if *v & 1 != 0))
        || !io.ops.contains(&Op::Delay(50))
        || !io.ops.contains(&Op::Delay(10))
    {
        return TestResult::Fail("AR9300 reset used AR_RC_AHB or AR9002 delays");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_identify_power_on_and_restore
);

fn smoke_ath9k_ar9003_mci_cap_gating() -> TestResult {
    // `hw.c::ath9k_hw_fill_cap_info`: AR9462/AR9565 carry MCI unless
    // the OTP 4.9 GHz disable is set; no other in-tree part does.
    if fill_cap_info(Chip::Ar9462, 0) != HW_CAP_MCI
        || fill_cap_info(Chip::Ar9565, 0) != HW_CAP_MCI
        || fill_cap_info(Chip::Ar9462, AR_ENT_OTP_49GHZ_DISABLE) != 0
        || fill_cap_info(Chip::Ar9565, AR_ENT_OTP_49GHZ_DISABLE) != 0
        || fill_cap_info(Chip::Ar9462, AR_ENT_OTP_49GHZ_DISABLE | 0x40) != 0
        || fill_cap_info(Chip::Ar9300, 0) != 0
        || fill_cap_info(Chip::Ar9580, 0) != 0
        || fill_cap_info(Chip::Ar9485, 0) != 0
    {
        return TestResult::Fail("MCI capability gating differs");
    }
    if HW_CAP_MCI != 1 << 15 {
        return TestResult::Fail("ATH9K_HW_CAP_MCI is not BIT(15)");
    }
    // `identify()` on 0x0030 reads `AR_ENT_OTP` (the fixture returns 0)
    // and reports no MCI capability for the AR9300.
    let mut io = Chip9300::new(SREV_9300_22);
    let identified = match identify(&mut io, 0x0030) {
        Ok(identified) => identified,
        Err(_) => return TestResult::Fail("AR9300 identification failed"),
    };
    if identified.ent_mode != 0 || identified.hw_caps != 0 {
        return TestResult::Fail("AR9300 identification reported MCI facts");
    }
    if !io.ops.contains(&Op::Read(AR_ENT_OTP)) {
        return TestResult::Fail("identify did not read AR_ENT_OTP");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9003_mci_cap_gating
);

/// FNV-1a over `(addr, value)` little-endian pairs, 2 GHz HT20 column.
fn fnv(tables: &[&[[u32; 2]]], modal: &[&[[u32; 5]]]) -> (u64, usize) {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut rows = 0;
    let mut feed = |addr: u32, value: u32| {
        for byte in addr.to_le_bytes().into_iter().chain(value.to_le_bytes()) {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        rows += 1;
    };
    for table in tables {
        for row in table.iter() {
            feed(row[0], row[1]);
        }
    }
    for table in modal {
        for row in table.iter() {
            feed(row[0], row[4]);
        }
    }
    (hash, rows)
}

/// A non-modal or a modal table, in programming order.
type Ordered = (&'static [[u32; 2]], Option<&'static [[u32; 5]]>);
/// `txrxgain`, revision, expected TX/RX tables and their oracles.
type GainCase<'a> = (u8, &'a Revision, TxGain, RxGain, (u64, usize), (u64, usize));

fn smoke_ath9k_ar9300_ini_selection_follows_txrxgain() -> TestResult {
    let mut stores = Stores::blank();
    Stores::place(&mut stores.eeprom, 0x3ff, &block(3, 5, &mac_runs()));
    let Ok(mut restored) = restore(&mut stores, Limits::for_chip(Chip::Ar9300)) else {
        return TestResult::Fail("restore failed");
    };
    let rev22 = Revision {
        chip: Chip::Ar9300,
        mac_rev: 3,
        pcie: true,
    };
    let rev20 = Revision {
        mac_rev: 2,
        ..rev22
    };
    let mut tables_for = |gain: u8, revision: &Revision| {
        restored.image[eeprom::field::TXRX_GAIN] = gain;
        let identity = eeprom::Identity::decode(Chip::Ar9300, &restored).ok()?;
        Some(Tables::ar9300(revision, &identity))
    };
    let Some(default) = tables_for(0x00, &rev22) else {
        return TestResult::Fail("identity refused");
    };
    // Oracle over the Linux order mac/bb/radio/soc core+post, rx, tx gain
    // (computed from the local ar9003_2p2_initvals.h).
    let hash = {
        let mut all = 0xcbf2_9ce4_8422_2325u64;
        let mut rows = 0usize;
        let order: [Ordered; 10] = [
            (default.mac_core, None),
            (&[], Some(default.mac_post)),
            (default.bb_core, None),
            (&[], Some(default.bb_post)),
            (default.radio_core, None),
            (&[], Some(default.radio_post)),
            (default.soc_pre, None),
            (&[], Some(default.soc_post)),
            (default.rx_gain, None),
            (&[], Some(default.tx_gain)),
        ];
        for (two, five) in order {
            let pairs: Vec<(u32, u32)> = match five {
                Some(table) => table.iter().map(|r| (r[0], r[4])).collect(),
                None => two.iter().map(|r| (r[0], r[1])).collect(),
            };
            for (addr, value) in pairs {
                for byte in addr.to_le_bytes().into_iter().chain(value.to_le_bytes()) {
                    all ^= u64::from(byte);
                    all = all.wrapping_mul(0x0000_0100_0000_01b3);
                }
                rows += 1;
            }
        }
        (all, rows)
    };
    if hash != (0xf9ef_63f2_7d44_8a14, 886)
        || default.tx_gain_kind != TxGain::LowestObDb
        || default.rx_gain_kind != RxGain::Common
        || default.pcie_serdes.len() != 3
        || default.pcie_serdes_low_power.len() != 3
        || default.fast_clock.len() != 9
        || default.cck_fir_japan_2484.len() != 3
        || default.dfs.len() != 3
    {
        return TestResult::Fail("AR9300 2p2 default INI selection differs from Linux");
    }
    let checks: [GainCase; 4] = [
        (
            0x51,
            &rev22,
            TxGain::Type5,
            RxGain::WithoutXlna,
            (0x7c44_5d0f_0e0a_af6f, 70),
            (0xbb9a_58a3_35ae_42e9, 256),
        ),
        (
            0x30,
            &rev22,
            TxGain::HighPower,
            RxGain::Common,
            (0x5806_46c6_4c21_cafe, 102),
            fnv(&[super::initvals::AR9300_COMMON_RX_GAIN_TABLE_2P2], &[]),
        ),
        // Type 5 needs AR_SREV_9300_22: 2.0 keeps lowest ob/db.
        (
            0x50,
            &rev20,
            TxGain::LowestObDb,
            RxGain::Common,
            fnv(
                &[],
                &[super::initvals::AR9300_MODES_LOWEST_OB_DB_TX_GAIN_TABLE_2P2],
            ),
            fnv(&[super::initvals::AR9300_COMMON_RX_GAIN_TABLE_2P2], &[]),
        ),
        // Modes 6/7/8+ and RX 2/3 have no AR9300 tables: defaults stay.
        (
            0x93,
            &rev22,
            TxGain::LowestObDb,
            RxGain::Common,
            fnv(
                &[],
                &[super::initvals::AR9300_MODES_LOWEST_OB_DB_TX_GAIN_TABLE_2P2],
            ),
            fnv(&[super::initvals::AR9300_COMMON_RX_GAIN_TABLE_2P2], &[]),
        ),
    ];
    for (gain, revision, tx, rx, tx_hash, rx_hash) in checks {
        let Some(tables) = tables_for(gain, revision) else {
            return TestResult::Fail("identity refused");
        };
        if tables.tx_gain_kind != tx
            || tables.rx_gain_kind != rx
            || fnv(&[], &[tables.tx_gain]) != tx_hash
            || fnv(&[tables.rx_gain], &[]) != rx_hash
        {
            return TestResult::Fail("txrxgain table selection differs from ar9003_hw.c");
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9300_ini_selection_follows_txrxgain
);

/// AR9580 1.0 `AR_SREV`: macVersion 0x1c0, macRev 4, PCIe.
const SREV_9580_10: u32 = 0x001c_04ff;

fn smoke_ath9k_ar9580_revision_split_and_ini_selection() -> TestResult {
    // AR_SREV_9580 is macRev >= 4 of the AR9300 macVersion; each device
    // ID accepts only its own side of that split.
    if Revision::decode(SREV_9580_10, Chip::Ar9580)
        != Some(Revision {
            chip: Chip::Ar9580,
            mac_rev: 4,
            pcie: true,
        })
        || Revision::decode(SREV_9580_10, Chip::Ar9300).is_some()
        || Revision::decode(0x001c_0fff, Chip::Ar9300).is_some()
        || Revision::decode(SREV_9300_22, Chip::Ar9580).is_some()
        || Revision::decode(0x001c_00ff, Chip::Ar9580).is_some()
        || Revision::decode(0x000c_02ff, Chip::Ar9580).is_some()
        || Revision::decode(SREV_9580_10, Chip::Ar9580).is_some_and(|r| r.ar9300_22())
        || !Revision::decode(SREV_9580_10, Chip::Ar9580).is_some_and(|r| r.ar9580())
        || Chip::for_device(0x0033) != Some(Chip::Ar9580)
        || Chip::Ar9580.chip_chainmask() != 7
        || Limits::for_chip(Chip::Ar9580) != Limits::for_chip(Chip::Ar9300)
    {
        return TestResult::Fail("AR_SREV_9580 revision split differs");
    }
    // AR9300 silicon behind 0x0033 is refused before any write.
    let mut io = Chip9300::new(SREV_9300_22);
    if identify(&mut io, 0x0033).err() != Some(BringUpError::UnsupportedRevision)
        || io.ops.iter().any(|op| matches!(op, Op::Write(..)))
    {
        return TestResult::Fail("AR9300 silicon not refused behind 0x0033");
    }
    let mut stores = Stores::blank();
    Stores::place(&mut stores.eeprom, 0x3ff, &block(3, 5, &mac_runs()));
    let Ok(mut restored) = restore(&mut stores, Limits::for_chip(Chip::Ar9580)) else {
        return TestResult::Fail("restore failed");
    };
    let Some(revision) = Revision::decode(SREV_9580_10, Chip::Ar9580) else {
        return TestResult::Fail("revision refused");
    };
    let mut tables_for = |gain: u8| {
        restored.image[eeprom::field::TXRX_GAIN] = gain;
        let identity = eeprom::Identity::decode(Chip::Ar9580, &restored).ok()?;
        Some(Tables::for_revision(
            &revision,
            &identity,
            serdes::PllPwrsave::resolve(Chip::Ar9580, 0, 0),
        ))
    };
    let Some(default) = tables_for(0x00) else {
        return TestResult::Fail("identity refused");
    };
    // FNV-1a oracle over the Linux order mac/bb/radio/soc core+post, rx,
    // tx gain at 2G HT20 (computed from the local ar9580_1p0_initvals.h
    // with its `#define` aliases resolved into ar9003_2p2_initvals.h).
    let all = {
        let mut rows: Vec<(u32, u32)> = Vec::new();
        let two = |t: &[[u32; 2]], rows: &mut Vec<(u32, u32)>| {
            rows.extend(t.iter().map(|r| (r[0], r[1])))
        };
        let five = |t: &[[u32; 5]], rows: &mut Vec<(u32, u32)>| {
            rows.extend(t.iter().map(|r| (r[0], r[4])))
        };
        two(default.mac_core, &mut rows);
        five(default.mac_post, &mut rows);
        two(default.bb_core, &mut rows);
        five(default.bb_post, &mut rows);
        two(default.radio_core, &mut rows);
        five(default.radio_post, &mut rows);
        two(default.soc_pre, &mut rows);
        five(default.soc_post, &mut rows);
        two(default.rx_gain, &mut rows);
        five(default.tx_gain, &mut rows);
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for (addr, value) in &rows {
            for byte in addr.to_le_bytes().into_iter().chain(value.to_le_bytes()) {
                h ^= u64::from(byte);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        (h, rows.len())
    };
    let ar9580 = |t: &[[u32; 5]], u: &[[u32; 5]]| core::ptr::eq(t, u);
    if all != (0xa7d3_dd7b_e1f6_d1d7, 886)
        || default.tx_gain_kind != TxGain::LowestObDb
        || default.rx_gain_kind != RxGain::Common
        || !default.pcie_serdes.is_empty()
        || !default.pcie_serdes_low_power.is_empty()
        || default.fast_clock.len() != 9
        || default.cck_fir_japan_2484.len() != 3
        || default.dfs.len() != 5
        || !core::ptr::eq(
            default.radio_core,
            super::initvals_ar9580::AR9580_1P0_RADIO_CORE,
        )
        || !core::ptr::eq(default.soc_pre, super::initvals::AR9300_2P2_SOC_PREAMBLE)
        || !ar9580(default.mac_post, super::initvals::AR9300_2P2_MAC_POSTAMBLE)
    {
        return TestResult::Fail("AR9580 1p0 default INI selection differs from Linux");
    }
    use super::initvals_ar9580 as t;
    // txrxgain, TX table + kind + 2G HT20 oracle, RX kind + oracle.
    type Case = (
        u8,
        &'static [[u32; 5]],
        TxGain,
        (u64, usize),
        RxGain,
        (u64, usize),
    );
    let rx_common = (0x7b24_6a38_6b1f_0fe4, 256);
    let rx_wo = (0xbb9a_58a3_35ae_42e9, 256);
    let low = (0x5806_46c6_4c21_cafe, 102);
    let checks: [Case; 9] = [
        (
            0x10,
            t::AR9580_1P0_HIGH_OB_DB_TX_GAIN_TABLE,
            TxGain::HighObDb,
            (0x69e7_697c_5259_738b, 102),
            RxGain::WithoutXlna,
            rx_wo,
        ),
        (
            0x20,
            t::AR9580_1P0_LOW_OB_DB_TX_GAIN_TABLE,
            TxGain::LowObDb,
            low,
            RxGain::Common,
            rx_common,
        ),
        (
            0x30,
            t::AR9580_1P0_HIGH_POWER_TX_GAIN_TABLE,
            TxGain::HighPower,
            (0x3be9_70bb_2c75_ee10, 103),
            RxGain::Common,
            rx_common,
        ),
        (
            0x40,
            t::AR9580_1P0_MIXED_OB_DB_TX_GAIN_TABLE,
            TxGain::MixedObDb,
            (0x69e7_697c_5259_738b, 102),
            RxGain::Common,
            rx_common,
        ),
        // Mode 5 is AR_SREV_9580's own (aliased) table, not AR_SREV_9300_22.
        (
            0x50,
            t::AR9580_1P0_TYPE5_TX_GAIN_TABLE,
            TxGain::Type5,
            (0x7c44_5d0f_0e0a_af6f, 70),
            RxGain::Common,
            rx_common,
        ),
        (
            0x60,
            t::AR9580_1P0_TYPE6_TX_GAIN_TABLE,
            TxGain::Type6,
            (0x7c44_5d0f_0e0a_af6f, 70),
            RxGain::Common,
            rx_common,
        ),
        // Mode 7 has no AR9580 table: the init_mode_regs low-ob/db default stays.
        (
            0x70,
            t::AR9580_1P0_LOW_OB_DB_TX_GAIN_TABLE,
            TxGain::LowObDb,
            low,
            RxGain::Common,
            rx_common,
        ),
        // Index >= 8 is mode 0; RX modes 2/3 keep the default.
        (
            0x82,
            t::AR9580_1P0_LOWEST_OB_DB_TX_GAIN_TABLE,
            TxGain::LowestObDb,
            (0x91a8_b9d6_9e9c_4b72, 102),
            RxGain::Common,
            rx_common,
        ),
        (
            0x03,
            t::AR9580_1P0_LOWEST_OB_DB_TX_GAIN_TABLE,
            TxGain::LowestObDb,
            (0x91a8_b9d6_9e9c_4b72, 102),
            RxGain::Common,
            rx_common,
        ),
    ];
    for (gain, table, tx, tx_hash, rx, rx_hash) in checks {
        let gain = if rx == RxGain::WithoutXlna {
            gain | 1
        } else {
            gain
        };
        let Some(tables) = tables_for(gain) else {
            return TestResult::Fail("identity refused");
        };
        if tables.tx_gain_kind != tx
            || !ar9580(tables.tx_gain, table)
            || tables.rx_gain_kind != rx
            || fnv(&[], &[tables.tx_gain]) != tx_hash
            || fnv(&[tables.rx_gain], &[]) != rx_hash
        {
            return TestResult::Fail("AR9580 txrxgain table selection differs from ar9003_hw.c");
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9580_revision_split_and_ini_selection
);

/// AR9462 2.0 `AR_SREV`: macVersion 0x280, macRev 2, PCIe.
/// 2.1 is macRev 3; 1.0 has no Linux tables.
const SREV_9462_20: u32 = 0x0028_02ff;
const SREV_9462_21: u32 = 0x0028_03ff;

fn smoke_ath9k_ar9462_revision_and_ini_selection() -> TestResult {
    // The AR9462 has its own macVersion, so no split against the AR9300
    // is needed; only shipped 2.0/2.1 silicon is accepted.
    if Revision::decode(SREV_9462_20, Chip::Ar9462)
        != Some(Revision {
            chip: Chip::Ar9462,
            mac_rev: 2,
            pcie: true,
        })
        || Revision::decode(SREV_9462_21, Chip::Ar9462)
            != Some(Revision {
                chip: Chip::Ar9462,
                mac_rev: 3,
                pcie: true,
            })
        || Revision::decode(SREV_9462_20, Chip::Ar9300).is_some()
        || Revision::decode(SREV_9462_20, Chip::Ar9580).is_some()
        || Revision::decode(SREV_9462_21, Chip::Ar9300).is_some()
        || Revision::decode(0x0028_01ff, Chip::Ar9462).is_some()
        || Revision::decode(0x0028_04ff, Chip::Ar9462).is_some()
        || Revision::decode(SREV_9300_22, Chip::Ar9462).is_some()
        || !Revision::decode(SREV_9462_21, Chip::Ar9462).is_some_and(|r| r.ar9462_21())
        || Revision::decode(SREV_9462_20, Chip::Ar9462).is_some_and(|r| r.ar9462_21())
        || Revision::decode(SREV_9462_20, Chip::Ar9462).is_some_and(|r| r.ar9300_22())
        || Revision::decode(SREV_9462_20, Chip::Ar9462).is_some_and(|r| r.ar9580())
        || Chip::for_device(0x0034) != Some(Chip::Ar9462)
        || Chip::Ar9462.mac_version() != 0x280
        || Chip::Ar9462.chip_chainmask() != 3
        || Limits::for_chip(Chip::Ar9462) != Limits::for_chip(Chip::Ar9300)
    {
        return TestResult::Fail("AR_SREV_9462 revision differs");
    }
    // AR9300 silicon behind 0x0034 is refused before any write.
    let mut io = Chip9300::new(SREV_9300_22);
    if identify(&mut io, 0x0034).err() != Some(BringUpError::UnsupportedRevision)
        || io.ops.iter().any(|op| matches!(op, Op::Write(..)))
    {
        return TestResult::Fail("AR9300 silicon not refused behind 0x0034");
    }
    let mut stores = Stores::blank();
    Stores::place(&mut stores.eeprom, 0x3ff, &block(3, 5, &mac_runs()));
    let Ok(mut restored) = restore(&mut stores, Limits::for_chip(Chip::Ar9462)) else {
        return TestResult::Fail("restore failed");
    };
    let rev20 = Revision {
        chip: Chip::Ar9462,
        mac_rev: 2,
        pcie: true,
    };
    let rev21 = Revision {
        mac_rev: 3,
        ..rev20
    };
    let mut tables_for = |gain: u8, revision: &Revision, pll: serdes::PllPwrsave| {
        // A genuine AR9462 board carries two-chain EEPROM masks; the
        // shared AR9300 template's three-chain mask (0x77) is foreign to
        // this chip and `Identity::decode` rightly refuses it.
        restored.image[eeprom::field::TXRX_MASK] = 0x33;
        restored.image[eeprom::field::TXRX_GAIN] = gain;
        let identity = eeprom::Identity::decode(Chip::Ar9462, &restored).ok()?;
        Some(Tables::for_revision(revision, &identity, pll))
    };
    // FNV-1a oracle over the Linux order mac/bb/radio/soc core+post,
    // sys2ant postamble, rx, tx gain at 2G HT20 (computed from the local
    // ar9462_2p0/2p1_initvals.h with their `#define` aliases resolved).
    let oracle = |tables: &Tables| {
        let mut rows: Vec<(u32, u32)> = Vec::new();
        let two = |t: &[[u32; 2]], rows: &mut Vec<(u32, u32)>| {
            rows.extend(t.iter().map(|r| (r[0], r[1])))
        };
        let five = |t: &[[u32; 5]], rows: &mut Vec<(u32, u32)>| {
            rows.extend(t.iter().map(|r| (r[0], r[4])))
        };
        two(tables.mac_core, &mut rows);
        five(tables.mac_post, &mut rows);
        two(tables.bb_core, &mut rows);
        five(tables.bb_post, &mut rows);
        two(tables.radio_core, &mut rows);
        five(tables.radio_post, &mut rows);
        five(tables.radio_post_sys2ant, &mut rows);
        two(tables.soc_pre, &mut rows);
        five(tables.soc_post, &mut rows);
        two(tables.rx_gain, &mut rows);
        five(tables.tx_gain, &mut rows);
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for (addr, value) in &rows {
            for byte in addr.to_le_bytes().into_iter().chain(value.to_le_bytes()) {
                h ^= u64::from(byte);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        (h, rows.len())
    };
    use super::initvals as i;
    use super::initvals_ar9462 as t;
    // `ath9k_hw_init_config` forces 7 for this chip.
    let pll9462 = serdes::PllPwrsave::resolve(Chip::Ar9462, 0, 0);
    let Some(default20) = tables_for(0x00, &rev20, pll9462) else {
        return TestResult::Fail("identity refused");
    };
    if oracle(&default20) != (0x6b83_5b40_4777_8dd5, 755)
        || default20.tx_gain_kind != TxGain::LowestObDb
        || default20.rx_gain_kind != RxGain::Common
        || !core::ptr::eq(
            default20.radio_post_sys2ant,
            t::AR9462_2P0_RADIO_POSTAMBLE_SYS2ANT,
        )
        || default20.radio_post_sys2ant.len() != 3
        || !default20.rxgain_bb_core.is_empty()
        || !default20.rxgain_bb_postamble.is_empty()
        || !default20.rxgain_xlna.is_empty()
        || default20.pcie_serdes.len() != 3
        || default20.pcie_serdes_low_power.len() != 3
        || default20.fast_clock.len() != 9
        || default20.cck_fir_japan_2484.len() != 3
        || !default20.dfs.is_empty()
    {
        return TestResult::Fail("AR9462 2p0 default INI selection differs from Linux");
    }
    // SerDes slots follow `pll_pwrsave`: the awake array only on
    // CONTROL+ON_D3, the low-power array only on CONTROL+ON_D0.
    // (`ath9k_hw_init_config` forces 7 for this chip, so the resolved
    // default sets both.)
    for (bits, awake, low) in [
        (7u8, 3usize, 3usize),
        (0, 0, 0),
        (1, 0, 0),
        (3, 3, 0),
        (5, 0, 3),
    ] {
        let Some(tables) = tables_for(0x00, &rev20, serdes::PllPwrsave::from_bits(bits)) else {
            return TestResult::Fail("identity refused");
        };
        if tables.pcie_serdes.len() != awake
            || tables.pcie_serdes_low_power.len() != low
            || (awake > 0
                && !core::ptr::eq(tables.pcie_serdes, t::AR9462_2P0_PCIEPHY_CLKREQ_DISABLE_L1))
            || (low > 0
                && !core::ptr::eq(
                    tables.pcie_serdes_low_power,
                    t::AR9462_2P0_PCIEPHY_CLKREQ_DISABLE_L1,
                ))
        {
            return TestResult::Fail("AR9462 SerDes selection differs from Linux");
        }
    }
    let Some(default21) = tables_for(0x00, &rev21, pll9462) else {
        return TestResult::Fail("identity refused");
    };
    if oracle(&default21) != (0xf5f2_6f37_ac39_d73d, 755)
        || !core::ptr::eq(default21.mac_core, t::AR9462_2P1_MAC_CORE)
        || !core::ptr::eq(default21.bb_post, t::AR9462_2P1_BASEBAND_POSTAMBLE)
        || !core::ptr::eq(default21.soc_pre, t::AR9462_2P1_SOC_PREAMBLE)
        || !core::ptr::eq(
            default21.radio_post_sys2ant,
            t::AR9462_2P1_RADIO_POSTAMBLE_SYS2ANT,
        )
    {
        return TestResult::Fail("AR9462 2p1 default INI selection differs from Linux");
    }
    // txrxgain: TX table + kind + 2G HT20 oracle, RX kind + oracle, and
    // the RX mode 2/3 override arrays (empty unless the mode selects them).
    type Case = (
        u8,
        &'static [[u32; 5]],
        TxGain,
        (u64, usize),
        RxGain,
        (u64, usize),
        (&'static [[u32; 2]], (u64, usize)),
        (&'static [[u32; 5]], (u64, usize)),
        (&'static [[u32; 5]], (u64, usize)),
    );
    let empty2: &'static [[u32; 2]] = &[];
    let empty5: &'static [[u32; 5]] = &[];
    let rx_common = (0x2274_57b8_a1e1_b8c3, 256);
    let rx_wo = (0xbb9a_58a3_35ae_42e9, 256);
    let rx_mixed = (0x2ede_ba7e_a1a8_ab2c, 256);
    let tx_low = (0xc725_5bf6_6eeb_8307, 65);
    let tx_9300 = (0x5806_46c6_4c21_cafe, 102);
    let mix_core = (
        t::AR9462_2P0_BASEBAND_CORE_MIX_RXGAIN,
        (0xff13_faa7_45bd_9db1, 1),
    );
    let mix_post = (
        t::AR9462_2P0_BASEBAND_POSTAMBLE_MIX_RXGAIN,
        (0x93b2_fa31_583a_fc69, 6),
    );
    let xlna = (
        t::AR9462_2P0_BASEBAND_POSTAMBLE_5G_XLNA,
        (0x1db8_1dcc_096c_a46b, 1),
    );
    let none = (empty2, (0xcbf2_9ce4_8422_2325, 0));
    let none5 = (empty5, (0xcbf2_9ce4_8422_2325, 0));
    let checks: [Case; 10] = [
        (
            0x11,
            t::AR9462_2P0_MODES_HIGH_OB_DB_TX_GAIN,
            TxGain::HighObDb,
            (0x189d_5b99_b888_b56b, 65),
            RxGain::WithoutXlna,
            rx_wo,
            none,
            none5,
            none5,
        ),
        // Modes 2/3 fall through to the AR9300 2p2 tables.
        (
            0x20,
            i::AR9300_MODES_LOW_OB_DB_TX_GAIN_TABLE_2P2,
            TxGain::LowObDb,
            tx_9300,
            RxGain::Common,
            rx_common,
            none,
            none5,
            none5,
        ),
        (
            0x30,
            i::AR9300_MODES_HIGH_POWER_TX_GAIN_TABLE_2P2,
            TxGain::HighPower,
            tx_9300,
            RxGain::Common,
            rx_common,
            none,
            none5,
            none5,
        ),
        (
            0x40,
            t::AR9462_2P0_MODES_MIX_OB_DB_TX_GAIN,
            TxGain::MixedObDb,
            (0xd925_af69_5551_4821, 59),
            RxGain::Common,
            rx_common,
            none,
            none5,
            none5,
        ),
        // Modes 5/6/7 and index >= 8 keep the mode-0 low-ob/db default.
        (
            0x50,
            t::AR9462_2P0_MODES_LOW_OB_DB_TX_GAIN,
            TxGain::LowestObDb,
            tx_low,
            RxGain::Common,
            rx_common,
            none,
            none5,
            none5,
        ),
        (
            0x70,
            t::AR9462_2P0_MODES_LOW_OB_DB_TX_GAIN,
            TxGain::LowestObDb,
            tx_low,
            RxGain::Common,
            rx_common,
            none,
            none5,
            none5,
        ),
        // RX mode 2: mixed table plus all three overrides.
        (
            0x02,
            t::AR9462_2P0_MODES_LOW_OB_DB_TX_GAIN,
            TxGain::LowestObDb,
            tx_low,
            RxGain::Mixed,
            rx_mixed,
            mix_core,
            mix_post,
            xlna,
        ),
        // RX mode 3: 5G-XLNA-only table (an alias of the mixed table)
        // plus only the XLNA array.
        (
            0x03,
            t::AR9462_2P0_MODES_LOW_OB_DB_TX_GAIN,
            TxGain::LowestObDb,
            tx_low,
            RxGain::FiveGXlnaOnly,
            rx_mixed,
            none,
            none5,
            xlna,
        ),
        // RX index >= 4 keeps the common default.
        (
            0x04,
            t::AR9462_2P0_MODES_LOW_OB_DB_TX_GAIN,
            TxGain::LowestObDb,
            tx_low,
            RxGain::Common,
            rx_common,
            none,
            none5,
            none5,
        ),
        // Index >= 8 is mode 0 on the TX side; the RX nibble still selects.
        (
            0x82,
            t::AR9462_2P0_MODES_LOW_OB_DB_TX_GAIN,
            TxGain::LowestObDb,
            tx_low,
            RxGain::Mixed,
            rx_mixed,
            mix_core,
            mix_post,
            xlna,
        ),
    ];
    for (
        gain,
        table,
        tx,
        tx_hash,
        rx,
        rx_hash,
        (core, core_hash),
        (post, post_hash),
        (x, x_hash),
    ) in checks
    {
        let Some(tables) = tables_for(gain, &rev20, pll9462) else {
            return TestResult::Fail("identity refused");
        };
        // Empty override arrays compare by emptiness: two distinct `&[]`
        // values have no guaranteed pointer identity.
        let same = |got: &[[u32; 2]], want: &[[u32; 2]]| {
            if want.is_empty() {
                got.is_empty()
            } else {
                core::ptr::eq(got, want)
            }
        };
        let same5 = |got: &[[u32; 5]], want: &[[u32; 5]]| {
            if want.is_empty() {
                got.is_empty()
            } else {
                core::ptr::eq(got, want)
            }
        };
        if tables.tx_gain_kind != tx
            || !core::ptr::eq(tables.tx_gain, table)
            || tables.rx_gain_kind != rx
            || fnv(&[], &[tables.tx_gain]) != tx_hash
            || fnv(&[tables.rx_gain], &[]) != rx_hash
            || !same(tables.rxgain_bb_core, core)
            || fnv(&[tables.rxgain_bb_core], &[]) != core_hash
            || !same5(tables.rxgain_bb_postamble, post)
            || fnv(&[], &[tables.rxgain_bb_postamble]) != post_hash
            || !same5(tables.rxgain_xlna, x)
            || fnv(&[], &[tables.rxgain_xlna]) != x_hash
        {
            return TestResult::Fail("AR9462 txrxgain table selection differs from ar9003_hw.c");
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9462_revision_and_ini_selection
);

/// AR9565 1.0 `AR_SREV`: macVersion 0x2c0, macRev 0, PCIe.
/// 1.0.1 is macRev 1; 1.1 is macRev 2.
const SREV_9565_10: u32 = 0x002c_00ff;
const SREV_9565_101: u32 = 0x002c_01ff;
const SREV_9565_11: u32 = 0x002c_02ff;

fn smoke_ath9k_ar9565_revision_and_ini_selection() -> TestResult {
    // The AR9565 has its own macVersion, so no split against the AR9300
    // is needed; Linux's branches cover every macRev, with the 1.1 set
    // from macRev 2 on.
    if Revision::decode(SREV_9565_10, Chip::Ar9565)
        != Some(Revision {
            chip: Chip::Ar9565,
            mac_rev: 0,
            pcie: true,
        })
        || Revision::decode(SREV_9565_101, Chip::Ar9565)
            != Some(Revision {
                chip: Chip::Ar9565,
                mac_rev: 1,
                pcie: true,
            })
        || Revision::decode(SREV_9565_11, Chip::Ar9565)
            != Some(Revision {
                chip: Chip::Ar9565,
                mac_rev: 2,
                pcie: true,
            })
        || Revision::decode(SREV_9565_10, Chip::Ar9300).is_some()
        || Revision::decode(SREV_9565_10, Chip::Ar9580).is_some()
        || Revision::decode(SREV_9565_10, Chip::Ar9462).is_some()
        || Revision::decode(SREV_9300_22, Chip::Ar9565).is_some()
        || !Revision::decode(SREV_9565_11, Chip::Ar9565).is_some_and(|r| r.ar9565_11_or_later())
        || Revision::decode(SREV_9565_101, Chip::Ar9565).is_some_and(|r| r.ar9565_11_or_later())
        || Revision::decode(SREV_9565_10, Chip::Ar9565).is_some_and(|r| r.ar9580())
        || Chip::for_device(0x0036) != Some(Chip::Ar9565)
        || Chip::Ar9565.mac_version() != 0x2c0
        || Chip::Ar9565.chip_chainmask() != 1
        || Limits::for_chip(Chip::Ar9565) != Limits::for_chip(Chip::Ar9300)
    {
        return TestResult::Fail("AR_SREV_9565 revision differs");
    }
    // AR9300 silicon behind 0x0036 is refused before any write.
    let mut io = Chip9300::new(SREV_9300_22);
    if identify(&mut io, 0x0036).err() != Some(BringUpError::UnsupportedRevision)
        || io.ops.iter().any(|op| matches!(op, Op::Write(..)))
    {
        return TestResult::Fail("AR9300 silicon not refused behind 0x0036");
    }
    let mut stores = Stores::blank();
    Stores::place(&mut stores.eeprom, 0x3ff, &block(3, 5, &mac_runs()));
    let Ok(mut restored) = restore(&mut stores, Limits::for_chip(Chip::Ar9565)) else {
        return TestResult::Fail("restore failed");
    };
    let rev10 = Revision {
        chip: Chip::Ar9565,
        mac_rev: 0,
        pcie: true,
    };
    let rev11 = Revision {
        mac_rev: 2,
        ..rev10
    };
    let mut tables_for = |gain: u8, revision: &Revision, pll: serdes::PllPwrsave| {
        // A genuine AR9565 board carries one-chain EEPROM masks; the
        // shared AR9300 template's three-chain mask (0x77) is foreign to
        // this chip and `Identity::decode` rightly refuses it.
        restored.image[eeprom::field::TXRX_MASK] = 0x11;
        restored.image[eeprom::field::TXRX_GAIN] = gain;
        let identity = eeprom::Identity::decode(Chip::Ar9565, &restored).ok()?;
        Some(Tables::for_revision(revision, &identity, pll))
    };
    // FNV-1a oracle over the Linux order mac/bb/radio/soc core+post,
    // sys2ant postamble, rx, tx gain at 2G HT20 (computed from the local
    // ar9565_1p0/1p1_initvals.h with their `#define` aliases resolved).
    let oracle = |tables: &Tables| {
        let mut rows: Vec<(u32, u32)> = Vec::new();
        let two = |t: &[[u32; 2]], rows: &mut Vec<(u32, u32)>| {
            rows.extend(t.iter().map(|r| (r[0], r[1])))
        };
        let five = |t: &[[u32; 5]], rows: &mut Vec<(u32, u32)>| {
            rows.extend(t.iter().map(|r| (r[0], r[4])))
        };
        two(tables.mac_core, &mut rows);
        five(tables.mac_post, &mut rows);
        two(tables.bb_core, &mut rows);
        five(tables.bb_post, &mut rows);
        two(tables.radio_core, &mut rows);
        five(tables.radio_post, &mut rows);
        five(tables.radio_post_sys2ant, &mut rows);
        two(tables.soc_pre, &mut rows);
        five(tables.soc_post, &mut rows);
        two(tables.rx_gain, &mut rows);
        five(tables.tx_gain, &mut rows);
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for (addr, value) in &rows {
            for byte in addr.to_le_bytes().into_iter().chain(value.to_le_bytes()) {
                h ^= u64::from(byte);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        (h, rows.len())
    };
    use super::initvals as i;
    use super::initvals_ar9565 as t;
    // `ath9k_hw_init_config` forces 7 for this chip.
    let pll9565 = serdes::PllPwrsave::resolve(Chip::Ar9565, 0, 0);
    let Some(default10) = tables_for(0x00, &rev10, pll9565) else {
        return TestResult::Fail("identity refused");
    };
    if oracle(&default10) != (0xacd9_a70b_8756_3d5a, 711)
        || default10.tx_gain_kind != TxGain::LowObDb
        || default10.rx_gain_kind != RxGain::Common
        || !core::ptr::eq(default10.radio_post, t::AR9565_1P0_RADIO_POSTAMBLE)
        || !default10.radio_post_sys2ant.is_empty()
        || !default10.rxgain_bb_core.is_empty()
        || !default10.rxgain_bb_postamble.is_empty()
        || !default10.rxgain_xlna.is_empty()
        || default10.pcie_serdes.len() != 3
        || default10.pcie_serdes_low_power.len() != 3
        || default10.fast_clock.len() != 9
        || default10.cck_fir_japan_2484.len() != 3
        || !default10.dfs.is_empty()
    {
        return TestResult::Fail("AR9565 1p0 default INI selection differs from Linux");
    }
    // SerDes slots follow `pll_pwrsave`: the awake array only on
    // CONTROL+ON_D3, the low-power array only on CONTROL+ON_D0.
    // (`ath9k_hw_init_config` forces 7 for this chip, so the resolved
    // default sets both; the 1.1 table is the 1.0 table by `#define`.)
    for (bits, awake, low) in [
        (7u8, 3usize, 3usize),
        (0, 0, 0),
        (1, 0, 0),
        (3, 3, 0),
        (5, 0, 3),
    ] {
        let Some(tables) = tables_for(0x00, &rev10, serdes::PllPwrsave::from_bits(bits)) else {
            return TestResult::Fail("identity refused");
        };
        if tables.pcie_serdes.len() != awake
            || tables.pcie_serdes_low_power.len() != low
            || (awake > 0
                && !core::ptr::eq(tables.pcie_serdes, t::AR9565_1P0_PCIEPHY_CLKREQ_DISABLE_L1))
            || (low > 0
                && !core::ptr::eq(
                    tables.pcie_serdes_low_power,
                    t::AR9565_1P0_PCIEPHY_CLKREQ_DISABLE_L1,
                ))
        {
            return TestResult::Fail("AR9565 SerDes selection differs from Linux");
        }
    }
    let Some(default11) = tables_for(0x00, &rev11, pll9565) else {
        return TestResult::Fail("identity refused");
    };
    if oracle(&default11) != (0x550e_5802_200a_6506, 711)
        || !core::ptr::eq(default11.radio_post, t::AR9565_1P1_RADIO_POSTAMBLE)
        || !core::ptr::eq(default11.mac_core, t::AR9565_1P0_MAC_CORE)
        || !core::ptr::eq(default11.bb_post, t::AR9565_1P0_BASEBAND_POSTAMBLE)
        || !core::ptr::eq(default11.soc_pre, t::AR9565_1P0_SOC_PREAMBLE)
    {
        return TestResult::Fail("AR9565 1p1 default INI selection differs from Linux");
    }
    // txrxgain: TX table + kind + 2G HT20 oracle, RX kind + oracle.
    // The gain byte is (tx_idx << 4) | rx_idx.
    type Case = (
        u8,
        &'static [[u32; 5]],
        TxGain,
        (u64, usize),
        RxGain,
        (u64, usize),
    );
    let rx_common = (0x5dc2_e629_164f_2062, 259);
    let rx_wo = (0x4ea8_8cea_b1fe_e449, 256);
    let tx_low = (0x92e5_d491_a50c_3306, 56);
    let tx_high = (0x670b_3dd6_e9b9_6069, 56);
    let tx_power = (0xac1c_0098_9858_ded3, 56);
    let tx_9300_mixed = (0x69e7_697c_5259_738b, 102);
    let checks: [Case; 8] = [
        (
            0x00,
            t::AR9565_1P0_MODES_LOW_OB_DB_TX_GAIN_TABLE,
            TxGain::LowObDb,
            tx_low,
            RxGain::Common,
            rx_common,
        ),
        (
            0x11,
            t::AR9565_1P0_MODES_HIGH_OB_DB_TX_GAIN_TABLE,
            TxGain::HighObDb,
            tx_high,
            RxGain::WithoutXlna,
            rx_wo,
        ),
        // Mode 2 is the low-ob/db table again; RX mode 2 is AR9462-only
        // and keeps the common default.
        (
            0x22,
            t::AR9565_1P0_MODES_LOW_OB_DB_TX_GAIN_TABLE,
            TxGain::LowObDb,
            tx_low,
            RxGain::Common,
            rx_common,
        ),
        // RX mode 3 is AR9462-only and keeps the common default.
        (
            0x33,
            t::AR9565_1P0_MODES_HIGH_POWER_TX_GAIN_TABLE,
            TxGain::HighPower,
            tx_power,
            RxGain::Common,
            rx_common,
        ),
        // Mode 4 falls through to the AR9300 2p2 mixed-ob/db table.
        (
            0x44,
            i::AR9300_MODES_MIXED_OB_DB_TX_GAIN_TABLE_2P2,
            TxGain::MixedObDb,
            tx_9300_mixed,
            RxGain::Common,
            rx_common,
        ),
        // Modes 5/6/7 have no 9565 arm and keep the mode-regs
        // lowest-ob/db value, which is the low-ob/db table by `#define`.
        (
            0x55,
            t::AR9565_1P0_MODES_LOW_OB_DB_TX_GAIN_TABLE,
            TxGain::LowObDb,
            tx_low,
            RxGain::Common,
            rx_common,
        ),
        (
            0x01,
            t::AR9565_1P0_MODES_LOW_OB_DB_TX_GAIN_TABLE,
            TxGain::LowObDb,
            tx_low,
            RxGain::WithoutXlna,
            rx_wo,
        ),
        (
            0x10,
            t::AR9565_1P0_MODES_HIGH_OB_DB_TX_GAIN_TABLE,
            TxGain::HighObDb,
            tx_high,
            RxGain::Common,
            rx_common,
        ),
    ];
    for (gain, table, tx, tx_hash, rx, rx_hash) in checks {
        let Some(tables) = tables_for(gain, &rev10, pll9565) else {
            return TestResult::Fail("identity refused");
        };
        if tables.tx_gain_kind != tx
            || !core::ptr::eq(tables.tx_gain, table)
            || tables.rx_gain_kind != rx
            || fnv(&[], &[tables.tx_gain]) != tx_hash
            || fnv(&[tables.rx_gain], &[]) != rx_hash
        {
            return TestResult::Fail("AR9565 txrxgain table selection differs from ar9003_hw.c");
        }
    }
    // The 1.1 oracle differs from 1.0 only in the radio postamble, so a
    // second full checks table would repeat the same selections; pin the
    // per-mode oracles for the modes whose tables differ instead.
    for (gain, want) in [
        (0x10, (0x2933_c147_64b7_9269, 711)),
        (0x30, (0x6e44_8409_1357_10d3, 711)),
        (0x40, (0x1a89_dc82_fb67_258b, 711)),
        (0x01, (0x2628_b5d3_2011_bf01, 711)),
    ] {
        let Some(tables) = tables_for(gain, &rev11, pll9565) else {
            return TestResult::Fail("identity refused");
        };
        if oracle(&tables) != want {
            return TestResult::Fail("AR9565 1p1 txrxgain oracle differs from Linux");
        }
    }
    TestResult::Pass
}

/// AR9485 1.1 `AR_SREV`: macVersion 0x240, macRev 1, PCIe. 1.0 has no
/// Linux tables; macRev >= 2 still selects the 1.1 set
/// (`AR_SREV_9485_11_OR_LATER`).
const SREV_9485_11: u32 = 0x0024_01ff;

fn smoke_ath9k_ar9485_revision_and_ini_selection() -> TestResult {
    // The AR9485 has its own macVersion, so no split against the AR9300
    // is needed; only 1.1-or-later silicon is accepted.
    if Revision::decode(SREV_9485_11, Chip::Ar9485)
        != Some(Revision {
            chip: Chip::Ar9485,
            mac_rev: 1,
            pcie: true,
        })
        || Revision::decode(0x0024_02ff, Chip::Ar9485)
            != Some(Revision {
                chip: Chip::Ar9485,
                mac_rev: 2,
                pcie: true,
            })
        || Revision::decode(SREV_9485_11, Chip::Ar9300).is_some()
        || Revision::decode(SREV_9485_11, Chip::Ar9580).is_some()
        || Revision::decode(0x0024_00ff, Chip::Ar9485).is_some()
        || Revision::decode(SREV_9300_22, Chip::Ar9485).is_some()
        || !Revision::decode(SREV_9485_11, Chip::Ar9485).is_some_and(|r| r.ar9485_11())
        || Revision::decode(SREV_9485_11, Chip::Ar9485).is_some_and(|r| r.ar9300_22())
        || Revision::decode(SREV_9485_11, Chip::Ar9485).is_some_and(|r| r.ar9580())
        || Chip::for_device(0x0032) != Some(Chip::Ar9485)
        || Chip::for_device(0x0037) != Some(Chip::Ar9485)
        || Chip::Ar9485.mac_version() != 0x240
        || Chip::Ar9485.chip_chainmask() != 1
        || Limits::for_chip(Chip::Ar9485)
            != (Limits {
                max_length: 1088,
                first_eeprom_base: eeprom::AR9300_BASE_ADDR_4K,
            })
        || Limits::for_chip(Chip::Ar9485) == Limits::for_chip(Chip::Ar9300)
    {
        return TestResult::Fail("AR_SREV_9485 revision differs");
    }
    // AR9300 silicon behind 0x0032/0x0037 is refused before any write.
    for device in [0x0032, 0x0037] {
        let mut io = Chip9300::new(SREV_9300_22);
        if identify(&mut io, device).err() != Some(BringUpError::UnsupportedRevision)
            || io.ops.iter().any(|op| matches!(op, Op::Write(..)))
        {
            return TestResult::Fail("AR9300 silicon not refused behind 0x0032/0x0037");
        }
    }
    let mut stores = Stores::blank();
    // The 9485 restore limits try the 4K base first.
    Stores::place(&mut stores.eeprom, 0xfff, &block(3, 5, &mac_runs()));
    let Ok(mut restored) = restore(&mut stores, Limits::for_chip(Chip::Ar9485)) else {
        return TestResult::Fail("restore failed");
    };
    let rev11 = Revision {
        chip: Chip::Ar9485,
        mac_rev: 1,
        pcie: true,
    };
    let rev12 = Revision {
        mac_rev: 2,
        ..rev11
    };
    let mut tables_for = |gain: u8, revision: &Revision, pll: serdes::PllPwrsave| {
        // A genuine AR9485 board carries single-chain EEPROM masks; the
        // shared AR9300 template's three-chain mask (0x77) is foreign to
        // this chip and `Identity::decode` rightly refuses it.
        restored.image[eeprom::field::TXRX_MASK] = 0x11;
        restored.image[eeprom::field::TXRX_GAIN] = gain;
        let identity = eeprom::Identity::decode(Chip::Ar9485, &restored).ok()?;
        Some(Tables::for_revision(revision, &identity, pll))
    };
    // FNV-1a oracle over the Linux order mac/bb/radio/soc core+post, BB
    // pre, allmodes radio postamble, rx, tx gain at 2G HT20 (computed
    // from the local ar9485_initvals.h with its `#define` aliases
    // resolved).
    let oracle = |tables: &Tables| {
        let mut rows: Vec<(u32, u32)> = Vec::new();
        let two = |t: &[[u32; 2]], rows: &mut Vec<(u32, u32)>| {
            rows.extend(t.iter().map(|r| (r[0], r[1])))
        };
        let five = |t: &[[u32; 5]], rows: &mut Vec<(u32, u32)>| {
            rows.extend(t.iter().map(|r| (r[0], r[4])))
        };
        two(tables.mac_core, &mut rows);
        five(tables.mac_post, &mut rows);
        two(tables.bb_pre, &mut rows);
        two(tables.bb_core, &mut rows);
        five(tables.bb_post, &mut rows);
        two(tables.radio_core, &mut rows);
        five(tables.radio_post, &mut rows);
        two(tables.radio_post_allmodes, &mut rows);
        two(tables.soc_pre, &mut rows);
        five(tables.soc_post, &mut rows);
        two(tables.rx_gain, &mut rows);
        five(tables.tx_gain, &mut rows);
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for (addr, value) in &rows {
            for byte in addr.to_le_bytes().into_iter().chain(value.to_le_bytes()) {
                h ^= u64::from(byte);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        (h, rows.len())
    };
    use super::initvals as i;
    use super::initvals_ar9485 as t;
    let pll9485 = serdes::PllPwrsave::resolve(Chip::Ar9485, 0, 0);
    let Some(default) = tables_for(0x00, &rev11, pll9485) else {
        return TestResult::Fail("identity refused");
    };
    if oracle(&default) != (0x9169_df72_650e_e951, 648)
        || default.tx_gain_kind != TxGain::LowestObDb
        || default.rx_gain_kind != RxGain::Common
        || !core::ptr::eq(default.mac_post, t::AR9485_1_1_MAC_POSTAMBLE)
        || !core::ptr::eq(default.bb_pre, t::AR9485_1_1)
        || !core::ptr::eq(default.radio_post_allmodes, t::AR9485_1_1_RADIO_POSTAMBLE)
        || !default.radio_post.is_empty()
        || !default.soc_post.is_empty()
        || default.pcie_serdes.len() != 3
        || default.pcie_serdes_low_power.len() != 3
        || !default.fast_clock.is_empty()
        || default.cck_fir_japan_2484.len() != 3
        || !default.dfs.is_empty()
    {
        return TestResult::Fail("AR9485 1.1 default INI selection differs from Linux");
    }
    // SerDes slots follow CONTROL alone: set selects the
    // `pll_on_cdr_on` table in both slots, clear the `clkreq` table in
    // both. (A default card resolves to 1, so today's code programs
    // the wrong — `clkreq` — table; a NO_PLL_PWRSAVE subsystem
    // resolves to 0 and keeps it.)
    for (bits, table, first) in [
        (
            1u8,
            t::AR9485_1_1_PLL_ON_CDR_ON_CLKREQ_DISABLE_L1,
            0x1801_265eu32,
        ),
        (0, t::AR9485_1_1_PCIE_PHY_CLKREQ_DISABLE_L1, 0x1801_3e5e),
    ] {
        let Some(tables) = tables_for(0x00, &rev11, serdes::PllPwrsave::from_bits(bits)) else {
            return TestResult::Fail("identity refused");
        };
        if !core::ptr::eq(tables.pcie_serdes, table)
            || !core::ptr::eq(tables.pcie_serdes_low_power, table)
            || tables.pcie_serdes.first().map(|r| r[1]) != Some(first)
        {
            return TestResult::Fail("AR9485 SerDes selection differs from Linux");
        }
    }
    // 1.2-or-later silicon selects the same 1.1 set.
    let Some(default12) = tables_for(0x00, &rev12, pll9485) else {
        return TestResult::Fail("identity refused");
    };
    if oracle(&default12) != (0x9169_df72_650e_e951, 648)
        || !core::ptr::eq(default12.mac_core, t::AR9485_1_1_MAC_CORE)
    {
        return TestResult::Fail("AR9485 later macRev INI selection differs from Linux");
    }
    // txrxgain: TX table + kind + 2G HT20 oracle, RX kind + oracle.
    // Modes 2/3 keep the wo-XLNA default (AR9462-only), mode 4 falls
    // through to the AR9300 2p2 mixed table, mode 7 sets nothing and
    // keeps the mode-0 lowest-ob/db default, index >= 4 on the RX side
    // keeps the common default, and TX index >= 8 is mode 0.
    type Case = (
        u8,
        &'static [[u32; 5]],
        TxGain,
        (u64, usize),
        RxGain,
        (u64, usize),
    );
    let tx_low = (0x35bf_2df9_5d5c_15dd, 90);
    let tx_9300 = (0x69e7_697c_5259_738b, 102);
    let rx_common = (0xd59f_ab09_f417_0cbc, 134);
    let rx_wo = (0x5bf7_0b75_f87d_b4c9, 134);
    let checks: [Case; 11] = [
        (
            0x11,
            t::AR9485MODES_HIGH_OB_DB_TX_GAIN_1_1,
            TxGain::HighObDb,
            (0x255a_fd8e_873d_a1af, 90),
            RxGain::WithoutXlna,
            rx_wo,
        ),
        (
            0x20,
            t::AR9485MODES_LOW_OB_DB_TX_GAIN_1_1,
            TxGain::LowObDb,
            tx_low,
            RxGain::Common,
            rx_common,
        ),
        (
            0x30,
            t::AR9485MODES_HIGH_POWER_TX_GAIN_1_1,
            TxGain::HighPower,
            (0x7535_90b0_183e_3088, 90),
            RxGain::Common,
            rx_common,
        ),
        // Mode 4 falls through to the AR9300 2p2 mixed table.
        (
            0x40,
            i::AR9300_MODES_MIXED_OB_DB_TX_GAIN_TABLE_2P2,
            TxGain::MixedObDb,
            tx_9300,
            RxGain::Common,
            rx_common,
        ),
        (
            0x50,
            t::AR9485MODES_GREEN_OB_DB_TX_GAIN_1_1,
            TxGain::GreenObDb,
            (0x2e40_c331_2b76_0d3c, 90),
            RxGain::Common,
            rx_common,
        ),
        (
            0x60,
            t::AR9485MODES_GREEN_SPUR_OB_DB_TX_GAIN_1_1,
            TxGain::GreenSpurObDb,
            (0xa743_5da3_a3e3_57c0, 90),
            RxGain::Common,
            rx_common,
        ),
        // Mode 7 sets nothing for non-9340: the mode-0 default stands.
        (
            0x70,
            t::AR9485MODES_LOW_OB_DB_TX_GAIN_1_1,
            TxGain::LowestObDb,
            tx_low,
            RxGain::Common,
            rx_common,
        ),
        // RX modes 2/3 are AR9462-only: the wo-XLNA default stands.
        (
            0x02,
            t::AR9485MODES_LOW_OB_DB_TX_GAIN_1_1,
            TxGain::LowestObDb,
            tx_low,
            RxGain::WithoutXlna,
            rx_wo,
        ),
        (
            0x03,
            t::AR9485MODES_LOW_OB_DB_TX_GAIN_1_1,
            TxGain::LowestObDb,
            tx_low,
            RxGain::WithoutXlna,
            rx_wo,
        ),
        // RX index >= 4 keeps the common default.
        (
            0x04,
            t::AR9485MODES_LOW_OB_DB_TX_GAIN_1_1,
            TxGain::LowestObDb,
            tx_low,
            RxGain::Common,
            rx_common,
        ),
        // TX index >= 8 is mode 0; the RX nibble still selects.
        (
            0x82,
            t::AR9485MODES_LOW_OB_DB_TX_GAIN_1_1,
            TxGain::LowestObDb,
            tx_low,
            RxGain::WithoutXlna,
            rx_wo,
        ),
    ];
    for (gain, table, tx, tx_hash, rx, rx_hash) in checks {
        let Some(tables) = tables_for(gain, &rev11, pll9485) else {
            return TestResult::Fail("identity refused");
        };
        if tables.tx_gain_kind != tx
            || !core::ptr::eq(tables.tx_gain, table)
            || tables.rx_gain_kind != rx
            || fnv(&[], &[tables.tx_gain]) != tx_hash
            || fnv(&[tables.rx_gain], &[]) != rx_hash
        {
            return TestResult::Fail("AR9485 txrxgain table selection differs from ar9003_hw.c");
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_revision_and_ini_selection
);

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9485_revision_and_ini_selection
);
