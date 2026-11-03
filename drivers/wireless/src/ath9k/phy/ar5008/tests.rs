use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Io {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    gone: bool,
}
impl RegisterIo for Io {
    fn authorized(&self) -> bool {
        !self.gone
    }
    fn read32(&mut self, at: u64) -> u32 {
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write32(&mut self, at: u64, value: u32) {
        self.regs.insert(at, value);
        self.writes.push((at, value));
    }
}

/// AR9160 rev 1 (`AR_SREV_ID == 0xff` format, macVersion 0x40) and AR5416
/// PCI (legacy format, macVersion 0xd) at `rev`.
const SREV_9160_11: u32 = 0x0004_01ff;
fn srev_5416(rev: u32) -> u32 {
    0xd0 | rev
}

fn identity(minor: u16, rx: u8, tx: u8) -> Identity {
    Identity {
        revision: 1,
        mac: [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        eeprom_version: 0xe000 | minor,
        regulatory_domains: [0x64, 0],
        rx_chainmask: rx,
        tx_chainmask: tx,
        big_endian_fields: false,
    }
}

/// Synthetic dual-band def map: marker values, never board data.
fn image() -> Vec<u8> {
    let mut bytes = vec![0u8; MAP_DEF.bytes()];
    bytes[6] = 0x03; // AR5416_OPFLAGS_11A | _11G.
    for (base, tag) in [(MODAL_2G, 0x20u8), (MODAL_5G, 0x50u8)] {
        for chain in 0..3u32 {
            let at = base + chain as usize * 4;
            bytes[at..at + 4]
                .copy_from_slice(&((0x0001_1100 * (chain + 1)) | u32::from(tag)).to_le_bytes());
        }
        bytes[base + 12..base + 16].copy_from_slice(&(0x0c0c_3300 | u32::from(tag)).to_le_bytes());
        for (offset, value) in [
            (19, 0x2c),
            (20, 0x11),
            (21, 0x12),
            (22, 0x13),
            (23, 0x21),
            (24, 0x22),
            (25, 0x23),
            (26, 0xe2),
            (27, 0xd0),
            (31, 0x05),
            (32, 0x07),
            (33, 0x0e),
            (34, tag),
            (40, 0x3f),
            (41, 0x01),
            (42, 0x02),
            (43, 0x1e),
            (44, 0x03),
            (45, 0x04),
            (47, 0x05), // ob
            (48, 0x03), // db
            (49, 0x02), // xpaBiasLvl
            (52, 0x0e),
            (53, 0x0f),
            (55, 0x09),
            (56, 0x0a),
            (57, 0x0b),
            (58, 0x06),
            (59, 0x07),
            (60, 0x08),
        ] {
            bytes[base + offset] = value;
        }
        for spur in 0..5 {
            let at = base + SPUR_CHANS + spur * 4;
            bytes[at..at + 2].copy_from_slice(&0x8000u16.to_le_bytes());
        }
    }
    bytes
}

fn fnv(pairs: &[(u64, u32)]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for (reg, value) in pairs {
        for byte in (*reg as u32)
            .to_le_bytes()
            .into_iter()
            .chain(value.to_le_bytes())
        {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

/// The `process_ini` rows: everything after `AR_PHY_SEL_EXTERNAL_RADIO`
/// except the `AR_PHY_SEL_INTERNAL_ADDAC` switch.
fn ini(writes: &[(u64, u32)], rows: usize) -> Option<Vec<(u64, u32)>> {
    let first = writes.iter().position(|&w| w == (0x9830, 1))?;
    let out: Vec<_> = writes[first + 1..]
        .iter()
        .copied()
        .filter(|&(reg, _)| reg != 0x9830)
        .take(rows)
        .collect();
    (out.len() == rows).then_some(out)
}

fn run(
    srev: u32,
    device: u16,
    id: &Identity,
    map: &[u8],
    frequency: u16,
    addac: Option<&mut Addac>,
) -> (Io, Result<Prepared, BringUpError>) {
    let revision = Revision::decode(srev).unwrap();
    let mut own = Addac::new(&tables(&revision).unwrap());
    let addac = addac.unwrap_or(&mut own);
    let mut io = Io::default();
    let result = prepare(&mut io, &revision, id, map, device, frequency, addac);
    (io, result)
}

fn smoke_ath9k_ar5008_ini_follows_linux_revision_tables() -> TestResult {
    // Independent FNV-1a oracles over (address, value) LE32 pairs extracted
    // from Linux ar5008_initvals.h / ar9001_initvals.h by the
    // ar9002_hw_init_mode_regs rules. AR9160 1.1, 2 GHz, minor 7,
    // xpaBiasLvl 2: Addac_9160_1_1 with row 7 patched, modes column 4.
    let (io, result) = run(
        SREV_9160_11,
        DEVID_AR9160_PCI,
        &identity(7, 3, 3),
        &image(),
        2412,
        None,
    );
    let Ok(two) = result else {
        return TestResult::Fail("AR9160 2 GHz preparation refused");
    };
    if two.ini_writes != 534
        || ini_rows(&tables(&Revision::decode(SREV_9160_11).unwrap()).unwrap()) != 534
        || ini(&io.writes, 534).map(|w| fnv(&w)) != Some(0xa60d_0280_ec39_e1cc)
    {
        return TestResult::Fail("AR9160 INI differs from the Linux selection");
    }
    // AR5416 1.x (below 2.2), 5 GHz: ar5416Addac with CLKDRV row 31 zeroed,
    // no set_addac, modes column 1, BB_RfGain column 1.
    let (io, result) = run(
        srev_5416(1),
        DEVID_AR5416_PCI,
        &identity(7, 7, 7),
        &image(),
        5180,
        None,
    );
    if result.map(|p| p.ini_writes) != Ok(538)
        || ini(&io.writes, 538).map(|w| fnv(&w)) != Some(0x00ce_8e09_d3b8_e9f2)
    {
        return TestResult::Fail("AR5416 INI differs from the Linux selection");
    }
    if io.writes.first() != Some(&(0x24, 0)) || io.writes.last() != Some(&(0x8, 0x20)) {
        return TestResult::Fail("AR5008 preparation left interrupts or RX enabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar5008_ini_follows_linux_revision_tables
);

fn bank6_after(writes: &[(u64, u32)], marker: (u64, u32)) -> Option<Vec<(u64, u32)>> {
    let at = writes.iter().position(|&w| w == marker)?;
    writes.get(at + 1..at + 34).map(<[_]>::to_vec)
}

fn smoke_ath9k_ar5008_rf_banks_synth_and_force_bias() -> TestResult {
    // AR5416 2.2, 2412 MHz: Bank 6 2 GHz column with OB 5 / DB 3 swizzled
    // (bits 197/194), then ar5008_hw_force_bias rewrites Bank 6 with
    // rf_pwd_icsyndiv 1 at bit 181 column 3, then AR_PHY(0x37).
    let (io, result) = run(
        srev_5416(2),
        DEVID_AR5416_PCIE,
        &identity(7, 7, 7),
        &image(),
        2412,
        None,
    );
    if result.is_err() {
        return TestResult::Fail("AR5416 2 GHz preparation refused");
    }
    // Bank 3 (2 GHz column) immediately precedes Bank 6.
    if bank6_after(&io.writes, (0x98f0, 0x01c0_0018)).map(|w| fnv(&w))
        != Some(0x1d67_1124_0085_03c8)
    {
        return TestResult::Fail("AR5416 Bank 6 OB/DB swizzle differs from Linux");
    }
    let synth_at = io.writes.iter().rposition(|&w| w == (0x98dc, 0xd21));
    let bias = synth_at.and_then(|at| io.writes.get(at - 33..at)).map(fnv);
    if bias != Some(0xcbbf_9f10_2ed7_c138) {
        return TestResult::Fail("AR5416 force-bias Bank 6 rewrite or synth word wrong");
    }
    if io.regs.get(&0x7014) != Some(&0xeb) || io.regs.get(&0xa200) != Some(&6) {
        return TestResult::Fail("AR5416 2 GHz PLL or RF mode wrong");
    }
    // AR9160 5 GHz: Bank 6 5 GHz column with OB 6 / DB 1 at bits 203/200,
    // no force bias, PLL DIV 0x50, OFDM | RF5GHZ, synth for 5180 / 5745.
    let mut map = image();
    map[MODAL_5G + 47] = 6;
    map[MODAL_5G + 48] = 1;
    let (io, result) = run(
        SREV_9160_11,
        DEVID_AR9160_PCI,
        &identity(7, 3, 3),
        &map,
        5180,
        None,
    );
    if result.is_err()
        || bank6_after(&io.writes, (0x98f0, 0x0140_0018)).map(|w| fnv(&w))
            != Some(0x0c37_b488_09a5_c1ff)
        || io.writes.iter().filter(|w| w.0 == 0x98dc).count() != 1
        || io.regs.get(&0x98dc) != Some(&0x3229)
        || io.regs.get(&0x7014) != Some(&0x1450)
        || io.regs.get(&0xa200) != Some(&0)
    {
        return TestResult::Fail("AR9160 5 GHz banks, synth, PLL or RF mode wrong");
    }
    if synth(Chip::Ar9160, 5745) != Ok(0xbd29)
        || synth(Chip::Ar5416, 2437) != Ok(0x2321)
        || synth(Chip::Ar5416, 2413).is_ok()
    {
        return TestResult::Fail("ar5008_hw_set_channel synth words wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar5008_rf_banks_synth_and_force_bias
);

fn smoke_ath9k_ar5008_board_values_three_chain_swap() -> TestResult {
    // Masks 0x5: chain 1 at +0x2000, chain 2 at +0x1000, ALT_CHAIN set.
    let mut io = Io::default();
    let map = image();
    if set_board_values(&mut io, &identity(3, 5, 5), &map, false, false).is_err() {
        return TestResult::Fail("AR5416 board values refused");
    }
    let base = MODAL_2G;
    let get = |io: &Io, at| *io.regs.get(&at).unwrap_or(&0);
    if get(&io, 0x9964) != 0x3320
        || get(&io, 0x9960) != 0x0001_1120
        || get(&io, 0xb960) != 0x0002_2220
        || get(&io, 0xa960) != 0x0003_3320
        || get(&io, 0x9920) != ((0x3f << 5) | 0x1e)
        || get(&io, 0xb920) != ((0x01 << 5) | 0x03)
        // RXTX margin 0x21, BSW margin 6, BSW atten 9 on chain 0.
        || get(&io, 0xa20c) != ((0x21 << 18) | (6 << 10) | 9)
        || get(&io, 0x9848) != (0x11 << 12)
        || get(&io, 0x9850) != 0xd0e2
        || get(&io, 0x9864) != (0x20 << 12)
        || get(&io, 0x99bc) != (0x20 << 16)
        || get(&io, 0x9824) != 0x0f0e
        || map[base + 47] != 5
    {
        return TestResult::Fail("AR5416 board values differ from eeprom_def.c");
    }
    // Below minor 3 the default attenuation (2 GHz 23) is used, no BSW.
    let mut io = Io::default();
    if set_board_values(&mut io, &identity(2, 7, 7), &map, false, false).is_err()
        || get(&io, 0x9848) != (23 << 12)
        || get(&io, 0xa20c) != (0x21 << 18)
        || get(&io, 0xb960) != 0x0003_3320
    {
        return TestResult::Fail("AR5416 pre-minor-3 gain path wrong");
    }
    // Full preparation with masks 0x5 sets AR_PHY_SWAP_ALT_CHAIN.
    let (io, result) = run(
        srev_5416(2),
        DEVID_AR5416_PCI,
        &identity(7, 5, 5),
        &map,
        2437,
        None,
    );
    if result.is_err() || get(&io, 0xa268) & 0x40 == 0 || get(&io, 0x99a4) != 5 {
        return TestResult::Fail("AR5416 0x5 chain mask swap not programmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar5008_board_values_three_chain_swap
);

fn smoke_ath9k_ar9160_addac_bias_persists_across_bands() -> TestResult {
    let revision = Revision::decode(SREV_9160_11).unwrap();
    let tables = tables(&revision).unwrap();
    let pristine = Addac::new(&tables);
    let mut addac = pristine;
    let mut map = image();
    map[MODAL_5G + 49] = 0xff; // Use xpaBiasLvlFreq on 5 GHz.
                               // Bins: 5180 -> 76. Entry 0 bin 10 level 1, entry 1 bin 70 level 3,
                               // entry 2 bin 90 level 2 (above the center: stop).
    for (n, word) in [
        (0u16, 10u16 | (1 << 14)),
        (1, 70 | (3 << 14)),
        (2, 90 | (2 << 14)),
    ] {
        let at = MODAL_5G + XPA_BIAS_LVL_FREQ + 2 * n as usize;
        map[at..at + 2].copy_from_slice(&word.to_le_bytes());
    }
    let id = identity(7, 3, 3);
    let (_, two) = run(
        SREV_9160_11,
        DEVID_AR9160_PCI,
        &id,
        &map,
        2412,
        Some(&mut addac),
    );
    let (io, five) = run(
        SREV_9160_11,
        DEVID_AR9160_PCI,
        &id,
        &map,
        5180,
        Some(&mut addac),
    );
    let row = |i: usize| tables.addac[i][1];
    let rows = ini(&io.writes, 32);
    if two.is_err() || five.is_err() || rows.is_none() {
        return TestResult::Fail("AR9160 band change preparation refused");
    }
    let rows = rows.unwrap();
    if rows[7].1 != (row(7) & !0x18) | (2 << 3) || rows[6].1 != (row(6) & !0xc0) | (3 << 6) {
        return TestResult::Fail("AR9160 set_addac rows do not persist like iniAddac");
    }
    // Below minor 7 (and on AR5416) set_addac does nothing.
    let mut addac = pristine;
    let _ = run(
        SREV_9160_11,
        DEVID_AR9160_PCI,
        &identity(6, 3, 3),
        &map,
        2412,
        Some(&mut addac),
    );
    if addac != pristine {
        return TestResult::Fail("AR9160 set_addac ran below minor 7");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9160_addac_bias_persists_across_bands
);

fn smoke_ath9k_ar5008_preparation_refuses_wrong_inputs() -> TestResult {
    let id = identity(7, 7, 7);
    // Device / silicon mismatch, AR9280 silicon, unknown device.
    for (srev, device) in [
        (SREV_9160_11, DEVID_AR5416_PCI),
        (srev_5416(2), DEVID_AR9160_PCI),
        (0x0008_01ff, DEVID_AR9160_PCI),
        (srev_5416(2), 0x0029),
    ] {
        let (io, result) = run(srev, device, &id, &image(), 2412, None);
        if result != Err(BringUpError::UnsupportedRevision) || !io.writes.is_empty() {
            return TestResult::Fail("AR5008 preparation accepted a wrong part");
        }
    }
    // Band not enabled by opCapFlags, off-grid channel, open-loop map.
    let mut no_a = image();
    no_a[6] = 0x02;
    let mut open = image();
    open[36] = 1;
    for (map, minor, frequency, expected) in [
        (no_a, 7, 5180, BringUpError::Policy),
        (image(), 7, 2484, BringUpError::Policy),
        (open, 0x13, 2412, BringUpError::BadCalibration),
    ] {
        let (io, result) = run(
            srev_5416(2),
            DEVID_AR5416_PCI,
            &identity(minor, 7, 7),
            &map,
            frequency,
            None,
        );
        if result.map(|_| ()).map_err(|e| e == expected) != Err(true) || !io.writes.is_empty() {
            return TestResult::Fail("AR5008 preparation accepted a refused band or map");
        }
    }
    let revision = Revision::decode(srev_5416(2)).unwrap();
    let mut addac = Addac::new(&tables(&revision).unwrap());
    let mut io = Io {
        gone: true,
        ..Io::default()
    };
    if prepare(
        &mut io,
        &revision,
        &id,
        &image(),
        DEVID_AR5416_PCI,
        2412,
        &mut addac,
    ) != Err(BringUpError::DeviceGone)
        || !io.writes.is_empty()
    {
        return TestResult::Fail("AR5008 preparation wrote to a withdrawn device");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar5008_preparation_refuses_wrong_inputs
);
