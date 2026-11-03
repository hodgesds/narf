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
        if (0x2000..0x2000 + 4 * 8192).contains(&offset) {
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
        Some(Tables::for_revision(&revision, &identity))
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
