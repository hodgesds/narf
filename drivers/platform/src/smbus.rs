//! Intel ICH SMBus controller — clean-room.
//!
//! Reference: **"Intel I/O Controller Hub 9 (ICH9) Family
//! Datasheet"** (or any later ICH/PCH datasheet — the SMBus
//! register layout is unchanged across the family). Section
//! references below (`§16.x`) point at the ICH9 datasheet.
//!
//! ## PCI identification
//!
//! SMBus is PCI **Class 0x0C / Subclass 0x05**. The ICH9 SMBus
//! function (`8086:2930`) is what QEMU's q35 chipset advertises;
//! ICH10 (`3A30`), C200/C600 (`1C22` / `1D22`), and the Cougar
//! Point family (`1E22`) all use the same register layout.
//!
//! ## Register layout (BAR4, IO space)
//!
//! | offset | name      | width | description                  |
//! |--------|-----------|-------|------------------------------|
//! | 0x00   | HST_STS   | u8    | Host Status                  |
//! | 0x02   | HST_CNT   | u8    | Host Control                 |
//! | 0x03   | HST_CMD   | u8    | Host Command (SMBus command) |
//! | 0x04   | XMIT_SLVA | u8    | Transmit Slave Address       |
//! | 0x05   | HST_D0    | u8    | Host Data 0                  |
//! | 0x06   | HST_D1    | u8    | Host Data 1                  |
//! | 0x07   | HOST_BLOCK_DB | u8 | Host Block Data Byte         |
//!
//! HST_CNT bits: bit 6 = START, bits[4:2] = SMB_CMD_PROTOCOL.
//!   000 = Quick     001 = Byte         010 = Byte Data
//!   011 = Word Data 100 = Process Call 101 = Block
//!
//! HST_STS bits: bit 0 = HOST_BUSY, bit 1 = INTR (success), bit 2 =
//!   DEV_ERR, bit 3 = BUS_ERR, bit 4 = FAILED. Write-1-to-clear.

extern crate alloc;

use narf_bus::{BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device ids we recognise ─────────────────────────────────────

pub const SMBUS_VENDOR: u16 = 0x8086;

/// QEMU q35 / real ICH9.
pub const SMBUS_ICH9_DEV:  u16 = 0x2930;
/// ICH10.
pub const SMBUS_ICH10_DEV: u16 = 0x3A30;
/// 5/6/7 series PCH (C200 / Cougar Point).
pub const SMBUS_PCH_DEV:   u16 = 0x1C22;
pub const SMBUS_PCH_DEV_2: u16 = 0x1E22;

// PCI class triple matching SMBus controllers.
pub const SMBUS_PCI_CLASS:    u8 = 0x0C;
pub const SMBUS_PCI_SUBCLASS: u8 = 0x05;

// ── Register offsets (BAR4 is IO; we read/write u8) ─────────────────

const SMB_HST_STS:   u16 = 0x00;
const SMB_HST_CNT:   u16 = 0x02;
const SMB_HST_CMD:   u16 = 0x03;
const SMB_XMIT_SLVA: u16 = 0x04;
const SMB_HST_D0:    u16 = 0x05;
const SMB_HST_D1:    u16 = 0x06;

// HST_STS bits.
const STS_HOST_BUSY: u8 = 1 << 0;
const STS_INTR:      u8 = 1 << 1;
const STS_DEV_ERR:   u8 = 1 << 2;
const STS_BUS_ERR:   u8 = 1 << 3;
const STS_FAILED:    u8 = 1 << 4;
const STS_ALL_ERRS:  u8 = STS_DEV_ERR | STS_BUS_ERR | STS_FAILED;

// HST_CNT bits.
const CNT_START:     u8 = 1 << 6;
const CNT_PROTO_BYTE_DATA: u8 = 0b010 << 2;
const CNT_PROTO_WORD_DATA: u8 = 0b011 << 2;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SmbusError {
    BarMissing,
    Busy,
    DeviceError,
    BusError,
    Failed,
    Timeout,
}

#[derive(Debug)]
pub struct Smbus {
    /// IO-space base address (BAR4).
    io_base: u16,
}

impl Smbus {
    /// Bring up the controller — no programming required, the
    /// SMBus host controller is always live; we just capture the
    /// IO base.
    ///
    /// # Safety
    /// Caller owns BAR4 exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap:   &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, SmbusError> {
        // SMBus uses IO-space BARs (PIO on x86_64). The
        // `narf-bus::map_bar` path expects MMIO — for SMBus we
        // dig into device.bars directly.
        let io_base = io_bar4(device).ok_or(SmbusError::BarMissing)?;
        Ok(Self { io_base })
    }

    /// Wait for HOST_BUSY to clear, then clear status latches.
    fn wait_idle(&self) -> Result<(), SmbusError> {
        for _ in 0..1_000_000u32 {
            // SAFETY: x86_64 PIO; SMBus IO window owned by us.
            let s = unsafe { pio_in8(self.io_base + SMB_HST_STS) };
            if s & STS_HOST_BUSY == 0 {
                // Clear any pending status (write-1-clear).
                // SAFETY: same.
                unsafe { pio_out8(self.io_base + SMB_HST_STS, 0xFF); }
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SmbusError::Busy)
    }

    /// Wait for INTR (success) or any error bit.
    fn wait_complete(&self) -> Result<(), SmbusError> {
        for _ in 0..10_000_000u32 {
            // SAFETY: x86_64 PIO.
            let s = unsafe { pio_in8(self.io_base + SMB_HST_STS) };
            if s & STS_BUS_ERR != 0 { return Err(SmbusError::BusError); }
            if s & STS_DEV_ERR != 0 { return Err(SmbusError::DeviceError); }
            if s & STS_FAILED  != 0 { return Err(SmbusError::Failed); }
            if s & STS_INTR    != 0 {
                // SAFETY: same — clear status.
                unsafe { pio_out8(self.io_base + SMB_HST_STS, STS_INTR | STS_ALL_ERRS); }
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(SmbusError::Timeout)
    }

    /// Read one byte at `cmd` from device at 7-bit `addr`.
    ///
    /// SMBus protocol "Read Byte Data" (§16.x): sends START, addr +
    /// R/W=W, cmd, repeated START, addr + R/W=R, reads one byte.
    pub fn read_byte_data(&self, addr: u8, cmd: u8) -> Result<u8, SmbusError> {
        self.wait_idle()?;
        // SAFETY: x86_64 PIO.
        unsafe {
            // bit 0 = read direction.
            pio_out8(self.io_base + SMB_XMIT_SLVA, (addr << 1) | 1);
            pio_out8(self.io_base + SMB_HST_CMD, cmd);
            pio_out8(self.io_base + SMB_HST_CNT, CNT_START | CNT_PROTO_BYTE_DATA);
        }
        self.wait_complete()?;
        // SAFETY: same.
        let v = unsafe { pio_in8(self.io_base + SMB_HST_D0) };
        Ok(v)
    }

    /// Write one byte `value` at `cmd` on device `addr`.
    pub fn write_byte_data(&self, addr: u8, cmd: u8, value: u8)
        -> Result<(), SmbusError>
    {
        self.wait_idle()?;
        // SAFETY: x86_64 PIO.
        unsafe {
            pio_out8(self.io_base + SMB_XMIT_SLVA, addr << 1);
            pio_out8(self.io_base + SMB_HST_CMD, cmd);
            pio_out8(self.io_base + SMB_HST_D0, value);
            pio_out8(self.io_base + SMB_HST_CNT, CNT_START | CNT_PROTO_BYTE_DATA);
        }
        self.wait_complete()?;
        Ok(())
    }

    /// Read a 16-bit word at `cmd` from device `addr`.
    pub fn read_word_data(&self, addr: u8, cmd: u8) -> Result<u16, SmbusError> {
        self.wait_idle()?;
        // SAFETY: x86_64 PIO.
        unsafe {
            pio_out8(self.io_base + SMB_XMIT_SLVA, (addr << 1) | 1);
            pio_out8(self.io_base + SMB_HST_CMD, cmd);
            pio_out8(self.io_base + SMB_HST_CNT, CNT_START | CNT_PROTO_WORD_DATA);
        }
        self.wait_complete()?;
        // SAFETY: same.
        let lo = unsafe { pio_in8(self.io_base + SMB_HST_D0) };
        // SAFETY: same.
        let hi = unsafe { pio_in8(self.io_base + SMB_HST_D1) };
        Ok(u16::from_le_bytes([lo, hi]))
    }
}

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Smbus>> =
    IrqSafeSpinLock::new(None);

pub fn probe(
    device: BusDevice,
    cap:    Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    // Class match catches all class-0x0C devices; verify subclass
    // is 0x05 (SMBus) before bringing up.
    let subclass = ((device.id.class >> 8) & 0xFF) as u8;
    if subclass != SMBUS_PCI_SUBCLASS {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    if CONTROLLER.lock().is_some() { return Ok(()); }
    narf_bus::pci::set_command(
        &cap, &device,
        narf_bus::pci::cmd::IO_SPACE
            | narf_bus::pci::cmd::INTX_DISABLE,
    ).map_err(|_| narf_bus::ProbeError::BadDevice)?;
    // SAFETY: caller-authority.
    let dev = match unsafe { Smbus::bring_up(&device, &cap) } {
        Ok(d)  => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };
    *CONTROLLER.lock() = Some(dev);
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name:    alloc::string::String::from("smbus"),
        kind:    narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain:  narf_drivers::BoundKind::Other.default_domain(),
    });
    Ok(())
}

pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "smbus-ich",
        kind: narf_bus::MatchKind::Class {
            class: SMBUS_PCI_CLASS, mask: 0xFF,
        },
        probe,
    });
}

pub fn is_probed() -> bool { CONTROLLER.lock().is_some() }

pub fn with_controller<R>(f: impl FnOnce(&Smbus) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(f)
}

// ── helpers ─────────────────────────────────────────────────────────

/// Extract the IO base address from BAR4. SMBus uses IO-space BARs;
/// the low bit of the BAR cfg-space dword is 1 (IO), bits[15:2] are
/// the address.
fn io_bar4(device: &BusDevice) -> Option<u16> {
    use narf_bus::BusKind;
    // Read BAR4 from the PCI cfg-space window.
    let cfg = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        _ => return None,
    };
    // SAFETY: identity-mapped cfg space; offset 0x10 + 4*4 = 0x20.
    let raw = unsafe { core::ptr::read_volatile((cfg.raw() + 0x20) as *const u32) };
    if raw & 1 == 0 { return None; }
    Some((raw & 0xFFFC) as u16)
}

#[cfg(target_arch = "x86_64")]
unsafe fn pio_in8(port: u16) -> u8 {
    let v: u8;
    // SAFETY: caller owns the IO window.
    unsafe {
        core::arch::asm!("in al, dx", out("al") v, in("dx") port, options(nomem, nostack));
    }
    v
}

#[cfg(target_arch = "x86_64")]
unsafe fn pio_out8(port: u16, v: u8) {
    // SAFETY: caller owns the IO window.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") v, options(nomem, nostack));
    }
}

#[cfg(not(target_arch = "x86_64"))]
unsafe fn pio_in8(_port: u16) -> u8 { 0 }
#[cfg(not(target_arch = "x86_64"))]
unsafe fn pio_out8(_port: u16, _v: u8) {}
