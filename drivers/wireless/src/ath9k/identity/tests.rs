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
    words: [u16; 256],
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
        let mut words = [0xffff; 256];
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
        if (EEPROM_WINDOW..EEPROM_WINDOW + 1024).contains(&offset) {
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
