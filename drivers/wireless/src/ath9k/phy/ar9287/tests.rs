use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Io {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    delays: Vec<u64>,
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
    fn delay_us(&mut self, us: u64) {
        self.delays.push(us);
    }
}

fn revision(srev: u32) -> Revision {
    Revision::decode(srev).unwrap()
}

fn identity(rx: u8, tx: u8) -> Identity {
    Identity {
        revision: 3,
        mac: [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        eeprom_version: 0xe003,
        regulatory_domains: [0x64, 0],
        rx_chainmask: rx,
        tx_chainmask: tx,
        big_endian_fields: false,
    }
}

/// Synthetic modal header: distinct marker values, never board data.
fn image(big: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; MAP_9287.bytes()];
    bytes[7] = u8::from(big);
    let dword = |v: u32| {
        if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    bytes[MODAL..MODAL + 4].copy_from_slice(&dword(0x0001_1111));
    bytes[MODAL + 4..MODAL + 8].copy_from_slice(&dword(0x0002_2222));
    bytes[MODAL + 8..MODAL + 12].copy_from_slice(&dword(0x0c0c_3333));
    for (offset, value) in [
        (14, 0x2c), // switchSettling
        (15, 0x11), // txRxAttenCh
        (16, 0x12),
        (17, 0x21), // rxTxMarginCh
        (18, 0x22),
        (19, 0xe2), // adcDesiredSize
        (20, 0x05), // txEndToXpaOff
        (21, 0x07), // txEndToRxOn
        (22, 0x0e), // txFrameToXpaOn
        (23, 0x40), // thresh62
        (28, 0x3f), // iqCalICh[0]
        (29, 0x01),
        (30, 0x1e), // iqCalQCh[0]
        (31, 0x02),
        (33, 0x02), // xpaBiasLvl
        (34, 0x0e), // txFrameToDataStart
        (35, 0x0f), // txFrameToPaOn
        (37, 0x09), // bswAtten
        (38, 0x0a),
        (39, 0x03), // bswMargin
        (40, 0x04),
        (41, 0x31), // swSettleHt40
        (43, 0x05), // db1
        (44, 0x04), // db2
        (45, 0x03), // ob_cck
        (46, 0x02), // ob_psk
        (47, 0x01), // ob_qam
        (48, 0x06), // ob_pal_off
    ] {
        bytes[MODAL + offset] = value;
    }
    // Empty spur list (AR_NO_SPUR terminator).
    bytes[SPUR_CHANS..SPUR_CHANS + 2].copy_from_slice(&if big {
        0x8000u16.to_be_bytes()
    } else {
        0x8000u16.to_le_bytes()
    });
    bytes
}

fn smoke_ath9k_ar9287_ini_follows_linux_mode_gain_common_order() -> TestResult {
    let mut io = Io::default();
    let prepared = match prepare(
        &mut io,
        &revision(0x0018_03ff),
        &identity(3, 3),
        &image(false),
        2412,
    ) {
        Ok(prepared) => prepared,
        Err(_) => return TestResult::Fail("AR9287 preparation refused"),
    };
    // Independent FNV-1a oracle over (address, value) LE32 pairs extracted
    // from Linux ar9002_initvals.h: AR9287 modes/rx gain/tx gain column 4,
    // then common column 1 (711 rows).
    let Some(first) = io.writes.iter().position(|&(reg, _)| reg == 0x9830) else {
        return TestResult::Fail("ADDAC shift selection missing");
    };
    let ini = &io.writes[first + 2..first + 2 + 711];
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for (reg, value) in ini {
        for byte in (*reg as u32)
            .to_le_bytes()
            .into_iter()
            .chain(value.to_le_bytes())
        {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    if prepared.ini_writes != 711 || hash != 0x99a6_476b_6878_6a82 {
        return TestResult::Fail("AR9287 INI differs from ar9002_initvals.h selection");
    }
    if io.writes.first() != Some(&(0x24, 0)) || io.writes.last() != Some(&(0x8, 0x20)) {
        return TestResult::Fail("AR9287 preparation left interrupts or RX enabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9287_ini_follows_linux_mode_gain_common_order
);

fn smoke_ath9k_ar9287_two_chain_masks_hwwar2_and_cck_fir() -> TestResult {
    let mut io = Io::default();
    io.regs.insert(0x8344, 0x0210_0040);
    if prepare(
        &mut io,
        &revision(0x0018_01ff),
        &identity(3, 1),
        &image(false),
        2437,
    )
    .is_err()
    {
        return TestResult::Fail("AR9287 1.1 preparation refused");
    }
    let wrote = |reg: u64, value: u32| io.writes.contains(&(reg, value));
    if !wrote(0x99a4, 3) || !wrote(0xa39c, 3) || !wrote(0x832c, 1) {
        return TestResult::Fail("AR9287 chain masks differ from ar5008_hw_init_chain_masks");
    }
    // MISC_MODE2 is an RMW over the post-INI register, not a zeroing write:
    // the COMMON table writes (0x8344, 0x01c81043) during process_ini
    // (initvals_ar9287.rs:266, = Linux ar9002_initvals.h:1946), and the
    // override RMW (channel.rs prepare_tune) clears HWWAR1/HWWAR2/KEYID and
    // sets CFP_IGNORE, yielding (0x01c81043 & !0x02100040) | 0x80.
    if io.regs.get(&0x8344) != Some(&0x01c8_1083) {
        return TestResult::Fail("AR9287 HWWAR1/HWWAR2/KEYID not cleared");
    }
    // `ar9287Modes_9287_1_1` / `ar9287Modes_rx_gain_9287_1_1` program
    // 0xa204 during process_ini (ar9002_initvals.h); what
    // `ar9002_hw_set_channel` (ar9002_phy.c:88-107) must not do on
    // AR_SREV_9287_11_OR_LATER is the AR_PHY_CCK_TX_CTRL_JAPAN RMW after
    // `ar5008_hw_set_rfmode` (the last 0xa200 write).
    let Some(rfmode) = io.writes.iter().rposition(|&(reg, _)| reg == 0xa200) else {
        return TestResult::Fail("AR9287 rfmode not programmed");
    };
    if io.writes[rfmode..].iter().any(|&(reg, _)| reg == 0xa204)
        || !AR9287_COMMON_NORMAL_CCK_FIR_COEFF_9287_1_1
            .iter()
            .all(|row| wrote(u64::from(row[0]), row[1]))
    {
        return TestResult::Fail("AR9287 CCK FIR path differs from ar9002_hw_set_channel");
    }
    if cck_fir(2484) != AR9287_COMMON_JAPAN_2484_CCK_FIR_COEFF_9287_1_1
        || cck_fir(2472) != AR9287_COMMON_NORMAL_CCK_FIR_COEFF_9287_1_1
    {
        return TestResult::Fail("channel-14 CCK spreading selection wrong");
    }
    // 2437 MHz: CHANSEL_2G with bMode|fracMode, top two synth bits kept.
    if !wrote(0x9874, 0x3000_0000 | (2437 * 0x10000 / 15)) {
        return TestResult::Fail("AR9287 synthesizer differs from ar9002_hw_set_channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9287_two_chain_masks_hwwar2_and_cck_fir
);

fn smoke_ath9k_ar9287_board_values_follow_eeprom_9287() -> TestResult {
    for big in [false, true] {
        let mut io = Io::default();
        io.regs.insert(0x7808, 0x0000_3fff);
        io.regs.insert(0x785c, 0x0000_2000);
        io.regs.insert(0x78b4, 0x0000_0001);
        if set_board_values(&mut io, &image(big), false).is_err() {
            return TestResult::Fail("AR9287 board values refused");
        }
        let reg = |at: u64| io.regs.get(&at).copied().unwrap_or(0);
        let rf2g3 = (5 << 29) | (4 << 26) | (3 << 23) | (2 << 20) | (1 << 17) | (6 << 14);
        if reg(0x9964) != 0x0c0c_3333
            || reg(0x9960) != 0x0001_1111
            || reg(0xa960) != 0x0002_2222
            || reg(0x9920) != (0x3f << 5) | 0x1e
            || reg(0xa920) != (1 << 5) | 2
            || reg(0xa20c) != (3 << 12) | 9
            || reg(0xb20c) != (4 << 12) | 0x0a
            || reg(0x9848) != (0x11 << 7) | (0x21 << 14)
            || reg(0xa848) != (0x12 << 7) | (0x22 << 14)
            || reg(0x9844) != 0x2c << 7
            || reg(0x9850) != 0xe2
            || reg(0x9834) != 0x0505_0e0e
            || reg(0x9828) != 0x07 << 16
            || reg(0x9864) != 0x40 << 12
            || reg(0x99b8) != 0x40
            || reg(0x7808) != rf2g3 | 0x3fff
            || reg(0x785c) != rf2g3 | 0x2000
            || reg(0x9824) != 0x0f0e
            || reg(0x78b4) != (2 << 30) | 1
        {
            return TestResult::Fail("AR9287 board value field placement wrong");
        }
        if io.delays.iter().filter(|&&us| us == 100).count() != 3 {
            return TestResult::Fail("AR9287 analog shift writes did not settle");
        }
    }
    let mut ht40 = Io::default();
    let _ = set_board_values(&mut ht40, &image(false), true);
    if ht40.regs.get(&0x9844) != Some(&(0x31 << 7)) {
        return TestResult::Fail("HT40 switch settling not selected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9287_board_values_follow_eeprom_9287
);

fn smoke_ath9k_ar9287_preparation_refuses_wrong_inputs() -> TestResult {
    let good = image(false);
    let cases: [(u32, usize, u16, BringUpError); 5] = [
        // AR9287 1.0 has no ar9002_hw_init_mode_regs tables.
        (
            0x0018_00ff,
            good.len(),
            2412,
            BringUpError::UnsupportedRevision,
        ),
        (
            0x000c_02ff,
            good.len(),
            2412,
            BringUpError::UnsupportedRevision,
        ),
        (0x0018_03ff, EEPROM_SHORT, 2412, BringUpError::BadLength),
        (0x0018_03ff, good.len(), 2484, BringUpError::Policy),
        (0x0018_03ff, good.len(), 5180, BringUpError::Policy),
    ];
    for (srev, len, frequency, expected) in cases {
        let mut io = Io::default();
        let result = prepare(
            &mut io,
            &revision(srev),
            &identity(3, 3),
            &good[..len],
            frequency,
        );
        if result != Err(expected) || !io.writes.is_empty() {
            return TestResult::Fail("invalid AR9287 preparation input reached registers");
        }
    }
    let mut gone = Io {
        gone: true,
        ..Io::default()
    };
    if prepare(
        &mut gone,
        &revision(0x0018_03ff),
        &identity(3, 3),
        &good,
        2412,
    ) != Err(BringUpError::DeviceGone)
        || !gone.writes.is_empty()
    {
        return TestResult::Fail("revoked AR9287 authority received writes");
    }
    TestResult::Pass
}
const EEPROM_SHORT: usize = 376;
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9287_preparation_refuses_wrong_inputs
);

fn smoke_ath9k_ar9287_13_enables_async_fifo_before_ini() -> TestResult {
    let mut io = Io::default();
    io.regs.insert(0x8358, 0x8000_0000);
    if prepare(
        &mut io,
        &revision(0x0018_03ff),
        &identity(3, 3),
        &image(false),
        2412,
    )
    .is_err()
    {
        return TestResult::Fail("AR9287 1.3 preparation refused");
    }
    let fifo: Vec<(usize, (u64, u32))> = io
        .writes
        .iter()
        .copied()
        .enumerate()
        .filter(|&(_, (reg, _))| reg == 0x8358 || reg == 0xa200)
        .take(4)
        .collect();
    let expected = [
        (0x8358, 0x8000_0400),
        (0xa200, 0x80),
        (0x8358, 0x400),
        (0x8358, 0x8000_0400),
    ];
    let Some(phy) = io.writes.iter().position(|w| *w == (0x9800, 7)) else {
        return TestResult::Fail("AR9287 preparation skipped AR_PHY(0)");
    };
    if fifo.iter().map(|f| f.1).ne(expected) || fifo.last().is_none_or(|f| f.0 > phy) {
        return TestResult::Fail("ar9002_hw_enable_async_fifo order differs");
    }
    // ar5008_hw_set_rfmode later rewrites AR_PHY_MODE without ASYNCFIFO.
    if io.regs.get(&0xa200) != Some(&4) {
        return TestResult::Fail("AR_PHY_MODE not rewritten by the channel path");
    }
    let mut old = Io::default();
    if prepare(
        &mut old,
        &revision(0x0018_01ff),
        &identity(3, 3),
        &image(false),
        2412,
    )
    .is_err()
        || old.writes.iter().any(|w| w.0 == 0x8358)
    {
        return TestResult::Fail("AR9287 1.1 enabled the 1.3 async FIFO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/phy",
    smoke_ath9k_ar9287_13_enables_async_fifo_before_ini
);
