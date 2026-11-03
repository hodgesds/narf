use super::super::chips::{MAP_9287, MAP_DEF};
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug, PartialEq, Eq)]
enum Op {
    Read(u64),
    Write(u64, u32),
    Delay(u64),
}

#[derive(Debug)]
struct Fake {
    words: Vec<u16>,
    registers: BTreeMap<u64, u32>,
    selected: usize,
    busy: bool,
    stalled: bool,
    ops: Vec<Op>,
}

fn checksum(image: &mut [u8; EEPROM_4K_BYTES]) {
    image[2..4].fill(0);
    let sum = image
        .chunks_exact(2)
        .fold(0u16, |sum, b| sum ^ u16::from_le_bytes([b[0], b[1]]));
    image[2..4].copy_from_slice(&(sum ^ 0xffff).to_le_bytes());
}

fn image(big: bool) -> [u8; EEPROM_4K_BYTES] {
    let mut bytes = [0; EEPROM_4K_BYTES];
    for (offset, value) in [
        (0, EEPROM_4K_BYTES as u16),
        (4, 0xe001),
        (8, 0x64),
        (10, 0x1f),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&if big {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        });
    }
    bytes[7] = u8::from(big);
    bytes[12..18].copy_from_slice(&[2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    bytes[18] = 1;
    bytes[19] = 1;
    bytes[374] = 0x42;
    checksum(&mut bytes);
    bytes
}

impl Fake {
    fn new() -> Self {
        let mut words = alloc::vec![0xffff; EEPROM_WINDOW_WORDS];
        words[0] = 0xa55a;
        for (index, bytes) in image(false).chunks_exact(2).enumerate() {
            words[EEPROM_BASE_WORD + index] = u16::from_le_bytes([bytes[0], bytes[1]]);
        }
        let mut registers = BTreeMap::new();
        registers.insert(AR_SREV, 0x000c02ff);
        registers.insert(AR_RTC_STATUS, 2);
        Self {
            words,
            registers,
            selected: 0,
            busy: false,
            stalled: false,
            ops: Vec::new(),
        }
    }
}

impl RegisterIo for Fake {
    fn read32(&mut self, offset: u64) -> u32 {
        self.ops.push(Op::Read(offset));
        if (EEPROM_WINDOW..EEPROM_WINDOW + 4 * EEPROM_WINDOW_WORDS as u64).contains(&offset) {
            self.selected = ((offset - EEPROM_WINDOW) / 4) as usize;
            self.busy = true;
            return 0;
        }
        if offset == EEPROM_STATUS {
            if self.busy || self.stalled {
                self.busy = false;
                return 0x10000 | 0xdead;
            }
            return self.words[self.selected] as u32;
        }
        self.registers.get(&offset).copied().unwrap_or(0)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        self.ops.push(Op::Write(offset, value));
        self.registers.insert(offset, value);
    }
    fn delay_us(&mut self, us: u64) {
        self.ops.push(Op::Delay(us));
    }
    fn wait(&mut self, offset: u64, mask: u32, expected: u32) -> Result<u32, BringUpError> {
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

fn smoke_ath9k_pcie_d3_workarounds_follow_reset_before_full_sleep() -> TestResult {
    let mut io = Fake::new();
    io.registers.insert(0x4014, 0x80023);
    io.registers.insert(0x4004, 0x00ca05cb);
    if disable_and_sleep_with_pcie(&mut io, Some(true)).is_err() {
        return TestResult::Fail("AR9285 ASPM-aware FULL_SLEEP failed");
    }
    let reset_done = io.ops.iter().rposition(|op| *op == Op::Write(AR_RC, 0));
    let pcie_off = io.ops.iter().position(|op| *op == Op::Write(0x4014, 0x23));
    let workaround = io
        .ops
        .iter()
        .position(|op| *op == Op::Write(0x4004, 0x00ca050b));
    let sleep = io.ops.iter().position(
        |op| matches!(op, Op::Write(AR_STA_ID1, value) if value & AR_STA_ID1_PWR_SAV != 0),
    );
    if !matches!((reset_done, pcie_off, workaround, sleep),
        (Some(reset), Some(off), Some(wa), Some(sleep)) if reset < off && off < wa && wa < sleep)
    {
        return TestResult::Fail("PCIe D3 workarounds were reset away or applied after FULL_SLEEP");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/pcie_pm",
    smoke_ath9k_pcie_d3_workarounds_follow_reset_before_full_sleep
);

fn smoke_ath9k_ar9285_reset_and_complete_eeprom() -> TestResult {
    let mut io = Fake::new();
    let (identity, calibration) = match identify(&mut io) {
        Ok(result) => result,
        Err(_) => return TestResult::Fail("AR9285 live identification helper failed"),
    };
    if identity.mac != [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
        || identity.revision != 2
        || identity.regulatory_domains != [0x64, 0x1f]
        || calibration != image(false)
    {
        return TestResult::Fail("AR9285 identity/calibration data corrupted");
    }
    let writes: Vec<_> = io
        .ops
        .iter()
        .filter_map(|op| {
            if let Op::Write(a, v) = op {
                Some((*a, *v))
            } else {
                None
            }
        })
        .collect();
    if writes
        != [
            (0x24, 0),
            (0x402c, 0),
            (0x704c, 3),
            (0x4000, 1),
            (0x7040, 0),
            (0x4000, 0),
            (0x7040, 1),
            (0x704c, 3),
            (0x4000, 1),
            (0x7000, 1),
            (0x7000, 0),
            (0x4000, 0),
        ]
        || !io.ops.contains(&Op::Delay(2))
        || !io.ops.contains(&Op::Delay(100))
    {
        return TestResult::Fail("AR9285 reset differs from Linux register sequence");
    }
    let triggers: Vec<_> = io
        .ops
        .iter()
        .filter_map(|op| {
            if let Op::Read(a) = op {
                if (0x2000..0x2400).contains(a) {
                    Some(*a)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    if triggers.len() != 189
        || triggers[0] != 0x2000
        || triggers[1] != 0x2100
        || triggers[188] != 0x23ec
    {
        return TestResult::Fail("AR9285 did not read exactly the complete 4K map");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k",
    smoke_ath9k_ar9285_reset_and_complete_eeprom
);

fn smoke_ath9k_eeprom_endian_and_magic() -> TestResult {
    let little = image(false);
    let expected = match decode_identity(2, 0xa55a, &mut little.clone()) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("LE EEPROM fixture rejected"),
    };
    let mut reversed = little;
    for word in reversed.chunks_exact_mut(2) {
        word.swap(0, 1);
    }
    if decode_identity(2, 0x5aa5, &mut reversed) != Ok(expected) || reversed != little {
        return TestResult::Fail("word-swapped EEPROM was not normalized");
    }
    let big = match decode_identity(2, 0xa55a, &mut image(true)) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("BE EEPROM fixture rejected"),
    };
    if big.mac != expected.mac
        || big.eeprom_version != expected.eeprom_version
        || big.regulatory_domains != expected.regulatory_domains
        || !big.big_endian_fields
    {
        return TestResult::Fail("BE scalar fields or MAC byte order decoded incorrectly");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k",
    smoke_ath9k_eeprom_endian_and_magic
);

fn smoke_ath9k_rejects_bad_eeprom_metadata() -> TestResult {
    let good = image(false);
    if decode_identity(0, 0xffff, &mut good.clone()) != Err(BringUpError::BadMagic) {
        return TestResult::Fail("bad EEPROM magic accepted");
    }
    for length in [0u16, 31, 33, 378, u16::MAX] {
        let mut data = good;
        data[..2].copy_from_slice(&length.to_le_bytes());
        if decode_identity(0, 0xa55a, &mut data) != Err(BringUpError::BadLength) {
            return TestResult::Fail("bad EEPROM length accepted");
        }
    }
    let mut bad_sum = good;
    bad_sum[374] ^= 1;
    if decode_identity(0, 0xa55a, &mut bad_sum) != Err(BringUpError::BadChecksum) {
        return TestResult::Fail("bad EEPROM checksum accepted");
    }
    let mut bad_version = good;
    bad_version[4..6].copy_from_slice(&0xd001u16.to_le_bytes());
    checksum(&mut bad_version);
    if decode_identity(0, 0xa55a, &mut bad_version) != Err(BringUpError::BadVersion) {
        return TestResult::Fail("wrong EEPROM version accepted");
    }
    for offset in [12usize, 18, 19] {
        let mut invalid = good;
        invalid[offset] = 3;
        checksum(&mut invalid);
        if decode_identity(0, 0xa55a, &mut invalid) != Err(BringUpError::BadIdentity) {
            return TestResult::Fail("multicast MAC or wrong chainmask accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k",
    smoke_ath9k_rejects_bad_eeprom_metadata
);

fn smoke_ath9k_rejects_absent_revision_and_busy_eeprom() -> TestResult {
    for (srev, expected) in [
        (u32::MAX, BringUpError::DeviceGone),
        (0x000802ff, BringUpError::UnsupportedRevision),
    ] {
        let mut io = Fake::new();
        io.registers.insert(AR_SREV, srev);
        if !matches!(identify(&mut io), Err(error) if error == expected)
            || io.ops.iter().any(|op| matches!(op, Op::Write(..)))
        {
            return TestResult::Fail("unsupported silicon received AR9285 writes");
        }
    }
    let mut io = Fake::new();
    io.stalled = true;
    if read_eeprom(&mut io, 64) != Err(BringUpError::Timeout) {
        return TestResult::Fail("busy EEPROM data was consumed as identity");
    }
    let count = io.ops.len();
    if read_eeprom(&mut io, 256) != Err(BringUpError::BadLength) || io.ops.len() != count {
        return TestResult::Fail("EEPROM word overflow reached MMIO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k",
    smoke_ath9k_rejects_absent_revision_and_busy_eeprom
);

fn smoke_ath9k_native_mmio_revocation_and_bounds() -> TestResult {
    use narf_bus::BusDeviceCap;
    use narf_capabilities::Cap;
    use narf_capabilities::Write;
    let cap = Cap::<BusDeviceCap, Write>::bootstrap();
    let mut words = [0x12345678u32, 0];
    let mmio = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 8,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let mut registers = Registers::new(mmio, cap);
    if registers.read32(0) != 0x12345678
        || registers.read32(1) != u32::MAX
        || registers.read32(8) != u32::MAX
    {
        return TestResult::Fail(
            "native AR9285 register reads ignored live authority or checked bounds",
        );
    }
    registers.write32(4, 0xaabbccdd);
    if words[1] != 0xaabbccdd {
        return TestResult::Fail("live native MMIO write did not execute");
    }
    cap.revoke();
    registers.mmio.virt = 0; // Any actual post-revocation access faults.
    if registers.authorized() || registers.read32(0) != u32::MAX {
        return TestResult::Fail("revoked AR9285 register access remained live");
    }
    registers.write32(4, 0xdeadbeef);
    if words[1] != 0xaabbccdd {
        return TestResult::Fail("revocation modified native register memory");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k",
    smoke_ath9k_native_mmio_revocation_and_bounds
);

fn smoke_ath9k_ar9285_suspend_disable_then_forced_full_sleep() -> TestResult {
    let mut io = Fake::new();
    io.registers.insert(AR_STA_ID1, 0x10);
    if disable_and_sleep(&mut io).is_err() {
        return TestResult::Fail("AR9285 suspend sequence failed");
    }
    let writes: Vec<_> = io
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Write(a, v) => Some((*a, *v)),
            _ => None,
        })
        .collect();
    // Cold reset first (IER off, RTC power-on, warm reset), then sleep.
    let tail = &writes[writes.len() - 4..];
    if writes.first() != Some(&(0x24, 0))
        || tail
            != [
                (AR_STA_ID1, 0x10 | AR_STA_ID1_PWR_SAV),
                (AR_RTC_FORCE_WAKE, 2),
                (AR_RC, 0x101),
                (AR_RTC_RESET, 0),
            ]
        || io.ops.last() != Some(&Op::Delay(2))
    {
        return TestResult::Fail("AR9285 FULL_SLEEP entry differs from ath9k_set_power_sleep");
    }
    let mut gone = Fake::new();
    gone.registers.insert(AR_SREV, u32::MAX);
    if disable_and_sleep(&mut gone) != Err(BringUpError::DeviceGone)
        || gone.ops.iter().any(|op| matches!(op, Op::Write(..)))
    {
        return TestResult::Fail("removed AR9285 received suspend writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/identity",
    smoke_ath9k_ar9285_suspend_disable_then_forced_full_sleep
);

/// A synthetic map image: base header only (never real board values).
fn chip_image(map: &EepromMap, length: u16, rx: u8, tx: u8) -> alloc::boxed::Box<[u8]> {
    let mut bytes = alloc::vec![0u8; map.bytes()].into_boxed_slice();
    bytes[..2].copy_from_slice(&length.to_le_bytes());
    bytes[4..6].copy_from_slice(&0xe003u16.to_le_bytes());
    bytes[8..10].copy_from_slice(&0x64u16.to_le_bytes());
    bytes[12..18].copy_from_slice(&[2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    bytes[18] = rx;
    bytes[19] = tx;
    let words = map.checksum_words(length as usize).unwrap_or(0);
    let sum = bytes[..words * 2]
        .chunks_exact(2)
        .fold(0u16, |sum, b| sum ^ u16::from_le_bytes([b[0], b[1]]));
    bytes[2..4].copy_from_slice(&(sum ^ 0xffff).to_le_bytes());
    bytes
}

fn smoke_ath9k_chip_revisions_follow_read_revisions() -> TestResult {
    let cases = [
        (0x000c_02ff, Some((Chip::Ar9285, 0xc0, 2))),
        (0x0018_03ff, Some((Chip::Ar9287, 0x180, 3))),
        (0x0018_01ff, Some((Chip::Ar9287, 0x180, 1))),
        (0x0008_02ff, Some((Chip::Ar9280, 0x80, 2))),
        (0x0004_01ff, Some((Chip::Ar9160, 0x40, 1))),
        (0x0000_00d2, Some((Chip::Ar5416, 0xd, 2))),
        (0x0000_00c1, Some((Chip::Ar5416, 0xc, 1))),
        // AR9300 (AR9003 EDMA) and AR9271 (USB) are not these PCI parts.
        (0x001c_02ff, None),
        (0x0014_01ff, None),
        (u32::MAX, None),
    ];
    for (srev, expected) in cases {
        let got = Revision::decode(srev).map(|r| (r.chip, r.mac_version, r.mac_rev));
        if got != expected {
            return TestResult::Fail("AR_SREV decode differs from ath9k_hw_read_revisions");
        }
    }
    let async_fifo = |srev| Revision::decode(srev).is_some_and(|r| r.ar9287_async_fifo());
    if !async_fifo(0x0018_03ff) || async_fifo(0x0018_02ff) || async_fifo(0x000c_03ff) {
        return TestResult::Fail("AR9287 1.3 async-FIFO gate wrong");
    }
    for (device, chip) in [
        (0x0023, Chip::Ar5416),
        (0x0024, Chip::Ar5416),
        (0x0027, Chip::Ar9160),
        (0x0029, Chip::Ar9280),
        (0x002a, Chip::Ar9280),
        (0x002b, Chip::Ar9285),
        (0x002c, Chip::Ar9285),
        (0x002d, Chip::Ar9287),
        (0x002e, Chip::Ar9287),
    ] {
        if Chip::for_device(device) != Some(chip) {
            return TestResult::Fail("PCI device inventory differs from hw.h");
        }
    }
    if Chip::for_device(0x0030).is_some() || Chip::for_device(0x0032).is_some() {
        return TestResult::Fail("AR9003 device mapped to an AR9002 profile");
    }
    if MAP_9287.bytes() != 726 || MAP_DEF.bytes() != 3256 || MAP_4K.bytes() != EEPROM_4K_BYTES {
        return TestResult::Fail("EEPROM map sizes differ from eeprom.h");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/identity",
    smoke_ath9k_chip_revisions_follow_read_revisions
);

fn smoke_ath9k_ar9287_map_decode_two_chain_masks() -> TestResult {
    // sizeof(struct ar9287_eeprom) = 727: Linux checksums min(727/2, 363).
    for (rx, tx) in [(1, 1), (3, 3), (2, 1), (3, 1)] {
        let mut image = chip_image(&MAP_9287, 727, rx, tx);
        match decode_map(&MAP_9287, 2, 3, 0xa55a, &mut image) {
            Ok(id) if id.rx_chainmask == rx && id.tx_chainmask == tx => {}
            _ => return TestResult::Fail("valid AR9287 map refused"),
        }
    }
    for (rx, tx) in [(0, 3), (4, 1), (3, 7)] {
        let mut image = chip_image(&MAP_9287, 727, rx, tx);
        if decode_map(&MAP_9287, 2, 3, 0xa55a, &mut image) != Err(BringUpError::BadIdentity) {
            return TestResult::Fail("AR9287 chain mask beyond two chains accepted");
        }
    }
    let mut short = chip_image(&MAP_9287, 727, 3, 3);
    short[0..2].copy_from_slice(&30u16.to_le_bytes());
    if decode_map(&MAP_9287, 2, 3, 0xa55a, &mut short) != Err(BringUpError::BadLength) {
        return TestResult::Fail("truncated AR9287 header accepted");
    }
    let mut bad = chip_image(&MAP_9287, 727, 3, 3);
    bad[700] ^= 1;
    if decode_map(&MAP_9287, 2, 3, 0xa55a, &mut bad) != Err(BringUpError::BadChecksum) {
        return TestResult::Fail("AR9287 checksum over full map ignored");
    }
    // The def map allows three chains, but AR9280 silicon has two.
    let mut def = chip_image(&MAP_DEF, 3256, 7, 7);
    if decode_map(&MAP_DEF, 3, 0, 0xa55a, &mut def.clone()).is_err()
        || decode_map(&MAP_DEF, 2, 0, 0xa55a, &mut def) != Err(BringUpError::BadIdentity)
    {
        return TestResult::Fail("def-map chain bound not per chip");
    }
    // AR9285 4k map keeps its strict even-length rule and single chain.
    let mut four = image(false);
    four[18] = 3;
    checksum(&mut four);
    if decode_identity(2, 0xa55a, &mut four) != Err(BringUpError::BadIdentity) {
        return TestResult::Fail("AR9285 accepted a two-chain mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/identity",
    smoke_ath9k_ar9287_map_decode_two_chain_masks
);

fn smoke_ath9k_ar9287_identify_reads_map_at_word_128() -> TestResult {
    let mut io = Fake::new();
    io.registers.insert(AR_SREV, 0x0018_03ff);
    let image = chip_image(&MAP_9287, 727, 3, 3);
    io.words.fill(0xffff);
    io.words[0] = 0xa55a;
    for (index, bytes) in image.chunks_exact(2).enumerate() {
        io.words[MAP_9287.start_word + index] = u16::from_le_bytes([bytes[0], bytes[1]]);
    }
    let (revision, identity, read) = match identify_chip(&mut io, Chip::Ar9287) {
        Ok(result) => result,
        Err(_) => return TestResult::Fail("AR9287 identification failed"),
    };
    if revision.chip != Chip::Ar9287
        || revision.mac_rev != 3
        || identity.rx_chainmask != 3
        || *read != *image
    {
        return TestResult::Fail("AR9287 identity/map corrupted");
    }
    let last = EEPROM_WINDOW + 4 * (MAP_9287.start_word + MAP_9287.words - 1) as u64;
    if !io.ops.contains(&Op::Read(last))
        || io.ops.contains(&Op::Read(last + 4))
        || io.ops.contains(&Op::Read(EEPROM_WINDOW + 4 * 64))
    {
        return TestResult::Fail("AR9287 map not read at AR9287_EEP_START_LOC");
    }
    // Device/silicon mismatch is refused before any write.
    let mut wrong = Fake::new();
    if identify_chip(&mut wrong, Chip::Ar9287) != Err(BringUpError::UnsupportedRevision)
        || wrong.ops.iter().any(|op| matches!(op, Op::Write(..)))
    {
        return TestResult::Fail("AR9285 silicon accepted as AR9287");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/identity",
    smoke_ath9k_ar9287_identify_reads_map_at_word_128
);

fn smoke_ath9k_ar9280_identify_reads_def_map_two_chains() -> TestResult {
    let mut io = Fake::new();
    io.registers.insert(AR_SREV, 0x0008_01ff);
    // sizeof(struct ar5416_eeprom_def) = 3256: checksum over all 1628 words.
    let image = chip_image(&MAP_DEF, 3256, 3, 3);
    io.words.fill(0xffff);
    io.words[0] = 0xa55a;
    for (index, bytes) in image.chunks_exact(2).enumerate() {
        io.words[MAP_DEF.start_word + index] = u16::from_le_bytes([bytes[0], bytes[1]]);
    }
    let (revision, identity, read) = match identify_chip(&mut io, Chip::Ar9280) {
        Ok(result) => result,
        Err(_) => return TestResult::Fail("AR9280 identification failed"),
    };
    if revision.chip != Chip::Ar9280
        || revision.mac_version != 0x80
        || identity.rx_chainmask != 3
        || identity.tx_chainmask != 3
        || *read != *image
    {
        return TestResult::Fail("AR9280 identity/map corrupted");
    }
    let last = EEPROM_WINDOW + 4 * (MAP_DEF.start_word + MAP_DEF.words - 1) as u64;
    if !io.ops.contains(&Op::Read(EEPROM_WINDOW + 4 * 64))
        || !io.ops.contains(&Op::Read(last))
        || io.ops.contains(&Op::Read(last + 4))
    {
        return TestResult::Fail("AR9280 def map not read at AR5416_EEP_START_LOC");
    }
    // The three-chain def map is limited by the two-chain silicon.
    let mut three = Fake::new();
    three.registers.insert(AR_SREV, 0x0008_01ff);
    let image = chip_image(&MAP_DEF, 3256, 7, 3);
    three.words.fill(0xffff);
    three.words[0] = 0xa55a;
    for (index, bytes) in image.chunks_exact(2).enumerate() {
        three.words[MAP_DEF.start_word + index] = u16::from_le_bytes([bytes[0], bytes[1]]);
    }
    if identify_chip(&mut three, Chip::Ar9280).map(|_| ()) != Err(BringUpError::BadIdentity) {
        return TestResult::Fail("AR9280 accepted a three-chain mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/identity",
    smoke_ath9k_ar9280_identify_reads_def_map_two_chains
);

fn ar5008_fake(srev: u32, opflags: u8, rx: u8, tx: u8, radio: u32, gpio: u32) -> Fake {
    let mut io = Fake::new();
    io.registers.insert(AR_SREV, srev);
    io.registers.insert(0x9c00, radio);
    io.registers.insert(0x4048, gpio);
    let mut image = chip_image(&MAP_DEF, 3256, rx, tx);
    // opCapFlags is outside the checksum fixup: keep the XOR at 0xffff.
    let old = u16::from_le_bytes([image[6], image[7]]);
    image[6] = opflags;
    let new = u16::from_le_bytes([image[6], image[7]]);
    let sum = u16::from_le_bytes([image[2], image[3]]) ^ old ^ new;
    image[2..4].copy_from_slice(&sum.to_le_bytes());
    io.words.fill(0xffff);
    io.words[0] = 0xa55a;
    for (index, bytes) in image.chunks_exact(2).enumerate() {
        io.words[MAP_DEF.start_word + index] = u16::from_le_bytes([bytes[0], bytes[1]]);
    }
    io
}

fn smoke_ath9k_ar5008_identify_radio_pcie_and_cb71_masks() -> TestResult {
    // PCI AR5416 2.2 (legacy SREV 0xd2), 2.4 GHz-only map: disablepcie,
    // AR2133 radio (raw 0xb0 -> 0xd0), CB71 GPIO 0 high -> RX 0x5.
    let mut io = ar5008_fake(0xd2, 0x02, 7, 7, 0xb000_0000, 1 << 14);
    let Ok((revision, identity, radio, _)) = identify_ar5008(&mut io, Chip::Ar5416, 0x0023) else {
        return TestResult::Fail("PCI AR5416 identification failed");
    };
    let serdes: Vec<_> = io
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Write(0x4040, v) => Some(*v),
            _ => None,
        })
        .collect();
    let radio_read = io.ops.iter().position(|op| *op == Op::Read(0x9c00));
    let serdes2 = io.ops.iter().position(|op| *op == Op::Write(0x4044, 0));
    let eeprom = io.ops.iter().position(|op| *op == Op::Read(EEPROM_WINDOW));
    if revision.mac_version != 0xd
        || radio.analog_rev != 0xd0
        || identity.rx_chainmask != 5
        || identity.tx_chainmask != 7
        || serdes.len() != 9
        || serdes[0] != 0x9248_fc00
        || serdes[8] != 0x000e_1007
        || !(serdes2 < radio_read && radio_read < eeprom)
    {
        return TestResult::Fail("PCI AR5416 SerDes, radio claim or CB71 mask wrong");
    }
    // GPIO 0 low -> 0x7; a dual-band PCI map keeps the EEPROM mask.
    let mut io = ar5008_fake(0xd2, 0x02, 3, 7, 0xb000_0000, 0);
    let low = identify_ar5008(&mut io, Chip::Ar5416, 0x0023).map(|r| r.1.rx_chainmask);
    let mut io = ar5008_fake(0xd2, 0x03, 3, 7, 0xb000_0000, 1 << 14);
    let dual = identify_ar5008(&mut io, Chip::Ar5416, 0x0023).map(|r| r.1.rx_chainmask);
    if low != Ok(7) || dual != Ok(3) {
        return TestResult::Fail("CB71 rule applied to the wrong board");
    }
    // AR5418 PCIe (0xc2): no SerDes writes, radio major 0 reads as AR5133.
    let mut io = ar5008_fake(0xc2, 0x03, 3, 3, 0, 1 << 14);
    let pcie = identify_ar5008(&mut io, Chip::Ar5416, 0x0024);
    if pcie.map(|r| (r.1.rx_chainmask, r.2.analog_rev)) != Ok((3, 0xc0))
        || io.ops.iter().any(|op| matches!(op, Op::Write(0x4040, _)))
    {
        return TestResult::Fail("AR5418 PCIe identification wrong");
    }
    // AR9160 with an unsupported radio major (0x10) never reads the map.
    let mut io = ar5008_fake(0x0004_01ff, 0x03, 3, 3, 0x8000_0000, 0);
    if identify_ar5008(&mut io, Chip::Ar9160, 0x0027).map(|_| ())
        != Err(BringUpError::UnsupportedRevision)
        || io.ops.contains(&Op::Read(EEPROM_WINDOW))
    {
        return TestResult::Fail("AR9160 accepted an unsupported radio");
    }
    // Silicon/device mismatch is refused before any write.
    let mut io = ar5008_fake(0xd2, 0x03, 3, 3, 0, 0);
    if identify_ar5008(&mut io, Chip::Ar9160, 0x0027).map(|_| ())
        != Err(BringUpError::UnsupportedRevision)
        || io.ops.iter().any(|op| matches!(op, Op::Write(..)))
    {
        return TestResult::Fail("AR5008 identification wrote to a mismatched part");
    }
    if fixup_chainmask(7, 0x8) != 7 || fixup_chainmask(7, 0xd) != 5 {
        return TestResult::Fail("fixup_chainmask differs from hw.c");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/identity",
    smoke_ath9k_ar5008_identify_radio_pcie_and_cb71_masks
);

fn smoke_ath9k_ar5416_full_sleep_keeps_rtc_out_of_reset() -> TestResult {
    let mut io = Fake::new();
    if sleep_ar5008_io(&mut io, Chip::Ar5416, false).is_err()
        || io.ops.iter().rev().find(|op| matches!(op, Op::Write(..)))
            != Some(&Op::Write(AR_RC, 0x101))
    {
        return TestResult::Fail("AR5416 FULL_SLEEP asserted the RTC reset");
    }
    let mut io = Fake::new();
    if sleep_ar5008_io(&mut io, Chip::Ar9160, false).is_err()
        || !matches!(
            io.ops.iter().rev().find(|op| matches!(op, Op::Write(..))),
            Some(Op::Write(AR_RTC_RESET, _))
        )
    {
        return TestResult::Fail("AR9160 FULL_SLEEP left the RTC running");
    }
    // An ASPM AR5418 adds the D3 `configpcipowersave(ah, true)` word
    // (AR_PCIE_PM_CTRL_ENA cleared at 0x4014, no SerDes rows) before
    // FULL_SLEEP; without ASPM nothing touches the PCIe block.
    let pcie = |io: &Fake, register: u64| {
        io.ops
            .iter()
            .any(|op| matches!(op, Op::Write(r, _) if *r == register))
    };
    let mut io = Fake::new();
    if sleep_ar5008_io(&mut io, Chip::Ar5416, true).is_err()
        || !pcie(&io, 0x4014)
        || pcie(&io, 0x4040)
        || io.ops.iter().rev().find(|op| matches!(op, Op::Write(..)))
            != Some(&Op::Write(AR_RC, 0x101))
    {
        return TestResult::Fail("ASPM AR5418 suspend lacks the D3 PCIe word");
    }
    let mut io = Fake::new();
    if sleep_ar5008_io(&mut io, Chip::Ar5416, false).is_err() || pcie(&io, 0x4014) {
        return TestResult::Fail("non-ASPM AR5416 suspend wrote the PCIe PM word");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/identity",
    smoke_ath9k_ar5416_full_sleep_keeps_rtc_out_of_reset
);
