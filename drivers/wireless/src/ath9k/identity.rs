// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux ath9k `hw.c`, `pci.c::ath_pci_eeprom_read`, `eeprom.c` and
//! `eeprom_4k.c`: AR9285 reset and the complete factory calibration map.

use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Write};

use super::chips::{Chip, EepromMap, Revision, MAP_4K};

const AR_RC: u64 = 0x4000;
const AR_STA_ID1: u64 = 0x8004;
const AR_STA_ID1_PWR_SAV: u32 = 0x0004_0000;
const AR_SREV: u64 = 0x4020;
const AR_INTR_SYNC_CAUSE: u64 = 0x4028;
const AR_INTR_SYNC_ENABLE: u64 = 0x402c;
const AR_RTC_RC: u64 = 0x7000;
const AR_RTC_RESET: u64 = 0x7040;
const AR_RTC_STATUS: u64 = 0x7044;
const AR_RTC_FORCE_WAKE: u64 = 0x704c;
const EEPROM_WINDOW: u64 = 0x2000;
const EEPROM_STATUS: u64 = 0x407c;
const EEPROM_BUSY_PROTECTED: u32 = 0x0005_0000;
const EEPROM_BASE_WORD: usize = 64;
/// `sizeof(struct ar5416_eeprom_4k)` in Linux `ath9k/eeprom.h`.
pub const EEPROM_4K_BYTES: usize = 376;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BringUpError {
    DeviceGone,
    Timeout,
    UnsupportedRevision,
    BadMagic,
    BadLength,
    BadChecksum,
    BadVersion,
    BadIdentity,
    BadCalibration,
    Policy,
    BadState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub revision: u8,
    pub mac: [u8; 6],
    pub eeprom_version: u16,
    pub regulatory_domains: [u16; 2],
    pub rx_chainmask: u8,
    pub tx_chainmask: u8,
    pub big_endian_fields: bool,
}
impl Identity {
    /// Factory capability fact only; emission still needs calibration, policy
    /// and the distinct measured HT grant. Revalidate the exact retained image.
    pub(super) fn ht20(&self, image: &[u8; EEPROM_4K_BYTES]) -> bool {
        let length = if self.big_endian_fields {
            u16::from_be_bytes([image[0], image[1]])
        } else {
            u16::from_le_bytes([image[0], image[1]])
        };
        let mut copy = *image;
        length as usize == EEPROM_4K_BYTES
            && image[6] & 0x22 == 2
            && self.rx_chainmask == 1
            && self.tx_chainmask == 1
            && decode_identity(self.revision, 0xa55a, &mut copy) == Ok(*self)
    }
}

pub(super) trait RegisterIo {
    fn authorized(&self) -> bool {
        true
    }
    fn read32(&mut self, offset: u64) -> u32;
    fn write32(&mut self, offset: u64, value: u32);
    fn delay_us(&mut self, us: u64) {
        narf_scheduler::responsive_spin_until(|| false, narf_time::Deadline::after_us(us));
    }
    fn wait(&mut self, offset: u64, mask: u32, expected: u32) -> Result<u32, BringUpError> {
        let mut value = 0;
        let complete = narf_scheduler::responsive_spin_until(
            || {
                value = self.read32(offset);
                value == u32::MAX || value & mask == expected
            },
            narf_time::Deadline::after_us(100_000),
        );
        if value == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        if complete {
            Ok(value)
        } else {
            Err(BringUpError::Timeout)
        }
    }
}

/// Run the actual device access inside the current capability invocation.
pub(super) fn invoke<T>(
    cap: &Cap<BusDeviceCap, Write>,
    operation: impl FnOnce() -> T,
) -> Result<T, CapError> {
    struct RegistersOp<F>(F);
    impl<T, F: FnOnce() -> T> CapOp<BusDeviceCap, Write> for RegistersOp<F> {
        type Output = T;
        fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
            Ok(self.0())
        }
    }
    cap.invoke(RegistersOp(operation))
}
pub(super) struct Registers {
    mmio: MmioRegion,
    cap: Cap<BusDeviceCap, Write>,
}
impl Registers {
    pub fn new(mmio: MmioRegion, cap: Cap<BusDeviceCap, Write>) -> Self {
        Self { mmio, cap }
    }
}
impl RegisterIo for Registers {
    fn authorized(&self) -> bool {
        self.cap.invoke(NoopOp).is_ok()
    }
    fn read32(&mut self, offset: u64) -> u32 {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.mmio.len) {
            return u32::MAX;
        }
        invoke(&self.cap, || {
            // SAFETY: full dword bounds and alignment are checked above;
            // current exclusive authority gates the actual BAR access.
            unsafe { self.mmio.read32(offset) }
        })
        .unwrap_or(u32::MAX)
    }
    fn write32(&mut self, offset: u64, value: u32) {
        if offset & 3 != 0 || offset.checked_add(4).is_none_or(|end| end > self.mmio.len) {
            return;
        }
        let _ = invoke(&self.cap, || {
            // SAFETY: checked dword extent/alignment and live exclusive authority.
            unsafe { self.mmio.write32(offset, value) }
        });
    }
}

/// Read a multibyte EEPROM field from the raw, checksum-verified image.
/// Magic-driven word normalization and the EEPMISC field-byte order are
/// separate facts. Never rewrite the retained raw image or its source hash.
/// All callers use statically bounded offsets inside their chip's map.
pub(in crate::ath9k) fn eeprom_word(image: &[u8], offset: usize) -> u16 {
    let bytes = [image[offset], image[offset + 1]];
    if image[7] & 1 != 0 {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    }
}
pub(in crate::ath9k) fn eeprom_dword(image: &[u8], offset: usize) -> u32 {
    let bytes = [
        image[offset],
        image[offset + 1],
        image[offset + 2],
        image[offset + 3],
    ];
    if image[7] & 1 != 0 {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }
}

fn read_eeprom(io: &mut impl RegisterIo, word: usize) -> Result<u16, BringUpError> {
    read_eeprom_word(io, word, 256)
}

/// Words addressable through the 8 KiB `AR5416_EEPROM_OFFSET` window
/// (`ath_pci_eeprom_read`: `0x2000 + (off << AR5416_EEPROM_S)`); the largest
/// map (`eeprom_def.c`) ends at word 1692.
const EEPROM_WINDOW_WORDS: usize = 2048;

fn read_eeprom_word(
    io: &mut impl RegisterIo,
    word: usize,
    limit: usize,
) -> Result<u16, BringUpError> {
    if word >= limit {
        return Err(BringUpError::BadLength);
    }
    // The *read* at EEPROM_WINDOW triggers the requested EEPROM word.
    let _ = io.read32(EEPROM_WINDOW + word as u64 * 4);
    let status = io.wait(EEPROM_STATUS, EEPROM_BUSY_PROTECTED, 0)?;
    Ok(status as u16)
}

fn reset(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    if io.read32(AR_SREV) == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(0x24, 0); // AR_IER_DISABLE
    io.write32(AR_INTR_SYNC_ENABLE, 0);
    io.write32(AR_RTC_FORCE_WAKE, 3);
    io.write32(AR_RC, 1);
    io.write32(AR_RTC_RESET, 0);
    io.delay_us(2);
    io.write32(AR_RC, 0);
    io.write32(AR_RTC_RESET, 1);
    io.wait(AR_RTC_STATUS, 0xf, 2)?;
    // Power-on finishes with ath9k_hw_set_reset's warm-reset sequence.
    io.write32(AR_RTC_FORCE_WAKE, 3);
    let timeout = io.read32(AR_INTR_SYNC_CAUSE) & 0x3000;
    io.write32(AR_RC, if timeout != 0 { 0x101 } else { 1 });
    io.write32(AR_RTC_RC, 1);
    io.delay_us(100);
    io.write32(AR_RTC_RC, 0);
    io.wait(AR_RTC_RC, 3, 0)?;
    io.write32(AR_RC, 0);
    Ok(())
}

/// `pci.c::ath_pci_suspend`: `hw.c::ath9k_hw_disable` (AWAKE + cold
/// reset; the PLL is not reprogrammed because the chip sleeps immediately)
/// followed by the forced `hw.c::ath9k_set_power_sleep` FULL_SLEEP entry:
/// STA_ID1 PWR_SAV, RTC force-wake clear, AR_RC AHB|HOSTIF held in reset and
/// the active-low RTC reset asserted. Resume needs a full power-on reset.
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn disable_and_sleep(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    disable_and_sleep_with_pcie(io, None)
}

fn disable_and_sleep_with_pcie(
    io: &mut impl RegisterIo,
    pcie_xe2: Option<bool>,
) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    reset(io)?;
    if let Some(xe2) = pcie_xe2 {
        super::pcie_pm::configure(io, true, xe2, true)?;
    }
    let id1 = io.read32(AR_STA_ID1);
    let wake = io.read32(AR_RTC_FORCE_WAKE);
    let rtc = io.read32(AR_RTC_RESET);
    if [id1, wake, rtc].contains(&u32::MAX) {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_STA_ID1, id1 | AR_STA_ID1_PWR_SAV);
    io.write32(AR_RTC_FORCE_WAKE, wake & !1);
    io.write32(AR_RC, 0x101);
    io.write32(AR_RTC_RESET, rtc & !1);
    io.delay_us(2);
    Ok(())
}

pub(super) fn sleep(
    mmio: narf_bus::MmioRegion,
    cap: Cap<BusDeviceCap, Write>,
    pcie_xe2: Option<bool>,
) -> Result<(), BringUpError> {
    disable_and_sleep_with_pcie(&mut Registers::new(mmio, cap), pcie_xe2)
}

fn decode_identity(
    revision: u8,
    magic: u16,
    image: &mut [u8; EEPROM_4K_BYTES],
) -> Result<Identity, BringUpError> {
    decode_map(&MAP_4K, 1, revision, magic, image)
}

/// `eeprom.c::ath9k_hw_nvram_swap_data`, `ath9k_hw_nvram_validate_checksum`
/// and `ath9k_hw_nvram_check_version` over one family's map. The base
/// header layout (length, checksum, version, opCapFlags, eepMisc, regDmn,
/// macAddr, rxMask, txMask) is shared by `ar5416_eeprom_4k`, `ar9287_eeprom`
/// and `ar5416_eeprom_def`. Chain masks must be nonzero subsets of the
/// chip's `chains`.
pub(super) fn decode_map(
    map: &EepromMap,
    chains: u8,
    revision: u8,
    magic: u16,
    image: &mut [u8],
) -> Result<Identity, BringUpError> {
    if image.len() != map.bytes() {
        return Err(BringUpError::BadLength);
    }
    match magic {
        0xa55a => {}
        0x5aa5 => {
            for word in image.chunks_exact_mut(2) {
                word.swap(0, 1);
            }
        }
        _ => return Err(BringUpError::BadMagic),
    }
    let big = image[7] & 1 != 0;
    let word = |offset: usize| {
        let bytes = [image[offset], image[offset + 1]];
        if big {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        }
    };
    let words = map
        .checksum_words(word(0) as usize)
        .ok_or(BringUpError::BadLength)?;
    let sum = image[..words * 2].chunks_exact(2).fold(0u16, |sum, bytes| {
        sum ^ u16::from_le_bytes([bytes[0], bytes[1]])
    });
    if sum != 0xffff {
        return Err(BringUpError::BadChecksum);
    }
    let version = word(4);
    if version >> 12 != 14 || version & 0xfff < 1 {
        return Err(BringUpError::BadVersion);
    }
    let mut mac = [0; 6];
    mac.copy_from_slice(&image[12..18]);
    let chains = EepromMap {
        chains: chains.min(map.chains),
        ..*map
    };
    if mac == [0; 6]
        || mac[0] & 1 != 0
        || !chains.chainmask_valid(image[18])
        || !chains.chainmask_valid(image[19])
    {
        return Err(BringUpError::BadIdentity);
    }
    Ok(Identity {
        revision,
        mac,
        eeprom_version: version,
        regulatory_domains: [word(8), word(10)],
        rx_chainmask: image[18],
        tx_chainmask: image[19],
        big_endian_fields: big,
    })
}

/// Identify a non-AR9285 family through its own revision and map, after the
/// same AR5008/AR9002 PCI power-on + warm reset (`hw.c::ath9k_hw_set_reset`
/// takes no AR9003/AR9100 branch for these parts). The returned image is
/// the normalized, checksum-verified map; no device is admitted by this.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
pub(in crate::ath9k) fn identify_chip(
    io: &mut impl RegisterIo,
    expected: Chip,
) -> Result<(Revision, Identity, alloc::boxed::Box<[u8]>), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    let srev = io.read32(AR_SREV);
    if srev == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    let revision = match Revision::decode(srev) {
        Some(revision) if revision.chip == expected => revision,
        _ => return Err(BringUpError::UnsupportedRevision),
    };
    reset(io)?;
    let map = expected.eeprom_map();
    let magic = read_eeprom_word(io, 0, EEPROM_WINDOW_WORDS)?;
    let mut image = alloc::vec![0u8; map.bytes()].into_boxed_slice();
    for (i, bytes) in image.chunks_exact_mut(2).enumerate() {
        let value = read_eeprom_word(io, map.start_word + i, EEPROM_WINDOW_WORDS)?;
        bytes.copy_from_slice(&value.to_le_bytes());
    }
    let identity = decode_map(
        map,
        expected.max_chains(),
        revision.mac_rev,
        magic,
        &mut image,
    )?;
    Ok((revision, identity, image))
}

pub(in crate::ath9k) fn identify(
    io: &mut impl RegisterIo,
) -> Result<(Identity, [u8; EEPROM_4K_BYTES]), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    // Reject mismatched silicon before AR9285-specific writes.
    let srev = io.read32(AR_SREV);
    if srev == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    // `Chip::Ar9285` implies the `AR_SREV_ID == 0xff` format with macVersion
    // 0xc0; its macRev is `AR_SREV_REVISION2`.
    let revision = match Revision::decode(srev) {
        Some(revision) if revision.chip == Chip::Ar9285 => revision.mac_rev,
        _ => return Err(BringUpError::UnsupportedRevision),
    };
    reset(io)?;
    let magic = read_eeprom(io, 0)?;
    let mut image = [0; EEPROM_4K_BYTES];
    for (i, bytes) in image.chunks_exact_mut(2).enumerate() {
        bytes.copy_from_slice(&read_eeprom(io, EEPROM_BASE_WORD + i)?.to_le_bytes());
    }
    let identity = decode_identity(revision, magic, &mut image)?;
    Ok((identity, image))
}

pub(super) fn read(
    mmio: narf_bus::MmioRegion,
    cap: Cap<BusDeviceCap, Write>,
) -> Result<(Identity, [u8; EEPROM_4K_BYTES]), BringUpError> {
    identify(&mut Registers::new(mmio, cap))
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
