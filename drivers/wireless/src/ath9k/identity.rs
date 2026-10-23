// SPDX-License-Identifier: GPL-2.0-or-later
//! Linux ath9k `hw.c`, `pci.c::ath_pci_eeprom_read`, `eeprom.c` and
//! `eeprom_4k.c`: AR9285 reset and the complete factory calibration map.

use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Write};

const AR_RC: u64 = 0x4000;
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

fn read_eeprom(io: &mut impl RegisterIo, word: usize) -> Result<u16, BringUpError> {
    if word >= 256 {
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

fn decode_identity(
    revision: u8,
    magic: u16,
    image: &mut [u8; EEPROM_4K_BYTES],
) -> Result<Identity, BringUpError> {
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
    let length = word(0) as usize;
    if !(32..=EEPROM_4K_BYTES).contains(&length) || length & 1 != 0 {
        return Err(BringUpError::BadLength);
    }
    let sum = image[..length].chunks_exact(2).fold(0u16, |sum, bytes| {
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
    if mac == [0; 6] || mac[0] & 1 != 0 || image[18] != 1 || image[19] != 1 {
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

fn identify(io: &mut impl RegisterIo) -> Result<(Identity, [u8; EEPROM_4K_BYTES]), BringUpError> {
    if !io.authorized() {
        return Err(BringUpError::DeviceGone);
    }
    // Reject mismatched silicon before AR9285-specific writes.
    let srev = io.read32(AR_SREV);
    if srev == u32::MAX {
        return Err(BringUpError::DeviceGone);
    }
    if srev & 0xff != 0xff || (srev & 0xfffc0000) >> 12 != 0xc0 {
        return Err(BringUpError::UnsupportedRevision);
    }
    let revision = ((srev >> 8) & 0xf) as u8;
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
