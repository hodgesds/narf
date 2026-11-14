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
    /// BT asked for its calibration window (`mci::start_reset`) or the
    /// reset handshake demands a recalibration
    /// (`mci::EndReset::RecalibrationNeeded`): nothing is terminal, the
    /// caller retries the generation reset.
    RecalibrationNeeded,
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
        self.wait_us(offset, mask, expected, 100_000)
    }
    /// `hw.c::ath9k_hw_wait` with an explicit timeout (µs).
    fn wait_us(
        &mut self,
        offset: u64,
        mask: u32,
        expected: u32,
        timeout_us: u64,
    ) -> Result<u32, BringUpError> {
        let mut value = 0;
        let complete = narf_scheduler::responsive_spin_until(
            || {
                value = self.read32(offset);
                value == u32::MAX || value & mask == expected
            },
            narf_time::Deadline::after_us(timeout_us),
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
    reset_with(io, false)
}

/// Power-on reset finished by `hw.c::ath9k_hw_set_reset`: WARM
/// (`AR_RTC_RC_MAC_WARM`), or with `cold` also `AR_RTC_RC_MAC_COLD`, the
/// type `ath9k_hw_chip_reset` always selects for a closed-loop AR9280.
fn reset_with(io: &mut impl RegisterIo, cold: bool) -> Result<(), BringUpError> {
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
    io.write32(AR_RTC_RC, if cold { 3 } else { 1 });
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
pub(super) fn disable_and_sleep(io: &mut impl RegisterIo) -> Result<(), BringUpError> {
    disable_and_sleep_with_pcie(io, None)
}

fn disable_and_sleep_with_pcie(
    io: &mut impl RegisterIo,
    pcie_xe2: Option<bool>,
) -> Result<(), BringUpError> {
    disable_and_sleep_with(io, false, true, |io| match pcie_xe2 {
        Some(xe2) => super::pcie_pm::configure(io, true, xe2, true),
        None => Ok(()),
    })
}

/// `disable_and_sleep` with the reset type (`cold`), whether
/// `ath9k_set_power_sleep` asserts the active-low RTC reset (`rtc_off`:
/// every part except AR5416/AR9271) and the D3
/// `ath9k_hw_configpcipowersave(ah, true)` step of the chip.
fn disable_and_sleep_with<R: RegisterIo>(
    io: &mut R,
    cold: bool,
    rtc_off: bool,
    pcie: impl FnOnce(&mut R) -> Result<(), BringUpError>,
) -> Result<(), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    reset_with(io, cold)?;
    pcie(io)?;
    let id1 = io.read32(AR_STA_ID1);
    let wake = io.read32(AR_RTC_FORCE_WAKE);
    let rtc = io.read32(AR_RTC_RESET);
    if [id1, wake, rtc].contains(&u32::MAX) {
        return Err(BringUpError::DeviceGone);
    }
    io.write32(AR_STA_ID1, id1 | AR_STA_ID1_PWR_SAV);
    io.write32(AR_RTC_FORCE_WAKE, wake & !1);
    io.write32(AR_RC, 0x101);
    if rtc_off {
        io.write32(AR_RTC_RESET, rtc & !1);
        io.delay_us(2);
    }
    Ok(())
}

/// AR5416/AR5418/AR9160 `ath_pci_suspend`: the `hw.c::ath9k_hw_disable`
/// COLD reset (unconditional, every chip), `ath9k_stop` →
/// `ath9k_hw_configpcipowersave(ah, true)`
/// (`pcie_pm::configure_ar5008(.., true)`: gated by `aspm_enabled`, so only
/// an ASPM PCIe AR5418 `0x0024` writes anything) and FULL_SLEEP, which on
/// AR5416 leaves the RTC out of reset (`ath9k_set_power_sleep`).
fn sleep_ar5008_io(io: &mut impl RegisterIo, chip: Chip, aspm: bool) -> Result<(), BringUpError> {
    disable_and_sleep_with(io, true, chip != Chip::Ar5416, |io| {
        super::pcie_pm::configure_ar5008(io, aspm, true)
    })
}

/// [`sleep_ar5008_io`] on the owner's BAR (`ar5008_owner::pm_suspend`).
pub(super) fn sleep_ar5008(
    mmio: narf_bus::MmioRegion,
    cap: Cap<BusDeviceCap, Write>,
    chip: Chip,
    aspm: bool,
) -> Result<(), BringUpError> {
    sleep_ar5008_io(&mut Registers::new(mmio, cap), chip, aspm)
}

pub(super) fn sleep(
    mmio: narf_bus::MmioRegion,
    cap: Cap<BusDeviceCap, Write>,
    pcie_xe2: Option<bool>,
) -> Result<(), BringUpError> {
    disable_and_sleep_with_pcie(&mut Registers::new(mmio, cap), pcie_xe2)
}

/// AR9280 `ath_pci_suspend`: COLD reset (`ath9k_hw_chip_reset`), the
/// AR9280 D3 PCIe word (`pcie_pm::configure_ar9280(.., true)`, ASPM parts
/// only) and FULL_SLEEP.
pub(super) fn sleep_ar9280(
    mmio: narf_bus::MmioRegion,
    cap: Cap<BusDeviceCap, Write>,
    aspm: bool,
) -> Result<(), BringUpError> {
    disable_and_sleep_with(&mut Registers::new(mmio, cap), true, true, |io| {
        super::pcie_pm::configure_ar9280(io, aspm, true)
    })
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
    // AR9280 (closed loop; open-loop maps are refused at preparation) takes
    // the COLD reset every `ath9k_hw_reset` gives it.
    reset_with(io, expected == Chip::Ar9280)?;
    read_map(io, expected, revision)
}

fn read_map(
    io: &mut impl RegisterIo,
    expected: Chip,
    revision: Revision,
) -> Result<(Revision, Identity, alloc::boxed::Box<[u8]>), BringUpError> {
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

/// An AR5008-PHY identification: revision, effective identity, radio and
/// the normalized map.
pub(in crate::ath9k) type Identified = (Revision, Identity, Radio, alloc::boxed::Box<[u8]>);

/// The AR5008-PHY identification facts beyond the map: the external radio
/// revision (`ah->hw_version.analog5GhzRev`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
pub(in crate::ath9k) struct Radio {
    pub analog_rev: u8,
}

/// `ar9002_hw.c::ar9002_hw_get_radiorev` + `ar9002_hw_rf_claim`: radio
/// major 0 reads as AR5133; AR5133/AR5122/AR2133/AR2122 are accepted, every
/// other major refused.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
pub(in crate::ath9k) fn claim_radio(io: &mut impl RegisterIo) -> Result<Radio, BringUpError> {
    io.write32(0x9800, 7); // AR_PHY(0).
    io.write32(0x98d8, 0x7058); // AR_PHY(0x36).
    for _ in 0..8 {
        io.write32(0x9880, 0x0001_0000); // AR_PHY(0x20).
    }
    let raw = io.read32(0x9c00); // AR_PHY(256).
    if raw == u32::MAX || !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    let value = (raw >> 24) & 0xff;
    let value = super::phy::ar5008::reverse_bits(((value & 0xf0) >> 4) | ((value & 0x0f) << 4), 8);
    match value & 0xf0 {
        0 => Ok(Radio { analog_rev: 0xc0 }),
        0xc0 | 0xd0 | 0xe0 | 0xf0 => Ok(Radio {
            analog_rev: value as u8,
        }),
        _ => Err(BringUpError::UnsupportedRevision),
    }
}

/// `hw.c::ath9k_hw_disablepcie`: AR5416 (macVersion 0xd/0xc) that is not
/// PCI Express. With the legacy `AR_SREV` format only macVersion 0xc
/// (AR5418) is `is_pciexpress`, so this is the PCI AR5416.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
fn disable_pcie(io: &mut impl RegisterIo) {
    for word in [
        0x9248_fc00,
        0x2492_4924,
        0x2800_0029,
        0x5716_0824,
        0x2598_0579,
        0x0000_0000,
        0x1aaa_be40,
        0xbe10_5554,
        0x000e_1007,
    ] {
        io.write32(0x4040, word); // AR_PCIE_SERDES.
    }
    io.write32(0x4044, 0); // AR_PCIE_SERDES2.
}

/// `hw.c::fixup_chainmask`: the mask within the chip's chains, or every
/// chain when nothing is left.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
pub(in crate::ath9k) fn fixup_chainmask(chip: u8, mask: u8) -> u8 {
    match mask & chip {
        0 => chip,
        fixed => fixed,
    }
}

/// AR5416/AR5418/AR9160 identification in `ath9k_hw_init` order: revision,
/// power-on + WARM reset, `ath9k_hw_disablepcie` (PCI AR5416),
/// `ar9002_hw_rf_claim`, the def map, then `ath9k_hw_fill_cap_info`'s chain
/// masks: the CB71 rule for the PCI AR5416 without `AR5416_OPFLAGS_11A`
/// (GPIO 0 input high: RX 0x5, else 0x7, from `AR_GPIO_IN_OUT`
/// `AR_GPIO_IN_VAL`) and `fixup_chainmask` against the three chains. The
/// retained map is unchanged; `Identity` carries the effective masks.
#[cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]
pub(in crate::ath9k) fn identify_ar5008(
    io: &mut impl RegisterIo,
    expected: Chip,
    device: u16,
) -> Result<Identified, BringUpError> {
    if !matches!(expected, Chip::Ar5416 | Chip::Ar9160)
        || Chip::for_device(device) != Some(expected)
    {
        return Err(BringUpError::UnsupportedRevision);
    }
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
    reset_with(io, false)?;
    if revision.mac_version == super::chips::AR_SREV_VERSION_5416_PCI {
        disable_pcie(io);
    }
    let radio = claim_radio(io)?;
    let (revision, mut identity, image) = read_map(io, expected, revision)?;
    let chip = 0x7;
    if device == 0x0023 && image[6] & 0x01 == 0 {
        let gpio = io.read32(0x4048);
        if gpio == u32::MAX {
            return Err(BringUpError::DeviceGone);
        }
        identity.rx_chainmask = if (gpio >> 14) & 1 != 0 { 0x5 } else { 0x7 };
    }
    identity.rx_chainmask = fixup_chainmask(chip, identity.rx_chainmask);
    identity.tx_chainmask = fixup_chainmask(chip, identity.tx_chainmask);
    Ok((revision, identity, radio, image))
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
