//! AMD FCH SPI controller — V1 (AMDI0061), V2 (AMDI0062), HID2 (AMDI0063).
//!
//! # Register map source
//!
//! Linux `drivers/spi/spi-amd.c` (GPL-2.0-or-later):
//!   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/spi/spi-amd.c
//!
//! Linux `drivers/spi/spi-amd-pci.c` (GPL-2.0-or-later):
//!   https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/spi/spi-amd-pci.c
//!
//! # PCI identity
//!
//! PCI vendor 0x1022 (AMD), device 0x1682 (FCH LPC bridge, Family 17h+).
//! MMIO base is read from PCI config offset 0xA0 (AMD_PCI_LPC_SPI_BASE_ADDR_REG),
//! masked to 0xFFFFFF00, then offset by +0x2000 for the HID2 SPI window
//! (AMD_HID2_PCI_BAR_OFFSET). MMIO window size is 0x200 bytes.
//!
//! V1 / V2 platforms expose the SPI controller via ACPI AMDI0061 / AMDI0062.
//!
//! # Register layout (byte-offset MMIO, 8-bit and 32-bit accesses)
//!
//! From Linux spi-amd.c:
//!
//! ```text
//! 0x00  AMD_SPI_CTRL0_REG    — EXEC_CMD (bit16), FIFO_CLEAR (bit20), BUSY (bit31),
//!                              opcode (bits 7:0 on V1), mode bits [21:20]
//! 0x1D  AMD_SPI_ALT_CS_REG   — chip-select select [1:0]
//! 0x20  AMD_SPI_ENA_REG      — SPI100 enable (bit0), ALT_SPD [23:20]
//! 0x45  AMD_SPI_OPCODE_REG   — opcode byte (V2/HID2)
//! 0x47  AMD_SPI_CMD_TRIGGER_REG — trigger byte (V2/HID2), TRIGGER_CMD = bit7
//! 0x48  AMD_SPI_TX_COUNT_REG — TX byte count (u8)
//! 0x4B  AMD_SPI_RX_COUNT_REG — RX byte count (u8)
//! 0x4C  AMD_SPI_STATUS_REG   — BUSY bit (bit31) on V2/HID2
//! 0x50  AMD_SPI_ADDR32CTRL_REG
//! 0x6C  AMD_SPI_SPEED_REG    — SPD7 [13:8]
//! 0x80  AMD_SPI_FIFO_BASE    — FIFO data port (70 bytes, byte-wide)
//! ```
//!
//! # Transfer flow (V1)
//!
//! 1. Wait for BUSY to clear (poll CTRL0 bit31).
//! 2. Clear FIFO pointer via FIFO_CLEAR in CTRL0.
//! 3. Set opcode in CTRL0[7:0].
//! 4. Write TX data into FIFO_BASE .. FIFO_BASE+tx_len.
//! 5. Write tx_count to TX_COUNT_REG, rx_count to RX_COUNT_REG.
//! 6. Set EXEC_CMD bit in CTRL0 to launch.
//! 7. If reading: wait for BUSY to clear, drain FIFO_BASE+tx_len.
//!
//! # FIFO chunking
//!
//! AMD_SPI_MAX_DATA = 64 bytes per transfer (V1/V2); HID2 allows DMA up
//! to 4096 bytes. This driver implements PIO chunking: transfers longer
//! than FIFO_DEPTH are split into back-to-back ops, each preceded by
//! a FIFO_CLEAR. The opcode byte of the first chunk is passed by the
//! caller as tx[0]; subsequent chunks use a NOP opcode (0x05 read-status
//! is safe, but we send the raw bytes so the caller controls the wire
//! protocol fully — chunked transfers assume the caller has designed
//! the packet to be splittable, e.g. a bulk FIFO read of a SPI-NAND).

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_memory::PhysAddr;

use crate::{SpiBus, SpiError, SpiMode};

// ── PCI identity ───────────────────────────────────────────────────
//
// From Linux spi-amd-pci.c:
//   #define AMD_PCI_DEVICE_ID_LPC_BRIDGE   0x1682
//   { PCI_DEVICE(PCI_VENDOR_ID_AMD, AMD_PCI_DEVICE_ID_LPC_BRIDGE) }

/// AMD PCI vendor ID.
pub const AMD_PCI_VENDOR: u16 = 0x1022;
/// AMD FCH LPC bridge / HID2 SPI PCI device ID. Family 17h+.
/// Source: Linux drivers/spi/spi-amd-pci.c AMD_PCI_DEVICE_ID_LPC_BRIDGE.
pub const AMD_FCH_SPI_PCI_DEVICE: u16 = 0x1682;

// ── ACPI HID list ──────────────────────────────────────────────────
//
// From Linux spi-amd.c spi_acpi_match[]:
//   { "AMDI0061", AMD_SPI_V1 }
//   { "AMDI0062", AMD_SPI_V2 }
//   { "AMDI0063", AMD_HID2_SPI }

const AMD_SPI_ACPI_HIDS: &[&str] = &["AMDI0061", "AMDI0062", "AMDI0063"];

// ── Register offsets (byte addresses) ─────────────────────────────
//
// All from Linux drivers/spi/spi-amd.c.

const AMD_SPI_CTRL0_REG: u64 = 0x00;
const AMD_SPI_ALT_CS_REG: u64 = 0x1D;
const AMD_SPI_ENA_REG: u64 = 0x20;
const AMD_SPI_OPCODE_REG: u64 = 0x45;
const AMD_SPI_CMD_TRIGGER_REG: u64 = 0x47;
const AMD_SPI_TX_COUNT_REG: u64 = 0x48;
const AMD_SPI_RX_COUNT_REG: u64 = 0x4B;
const AMD_SPI_STATUS_REG: u64 = 0x4C;
const AMD_SPI_SPEED_REG: u64 = 0x6C;
const AMD_SPI_FIFO_BASE: u64 = 0x80;

// ── CTRL0 bit definitions ──────────────────────────────────────────
//
// From Linux drivers/spi/spi-amd.c.

const AMD_SPI_EXEC_CMD: u32 = 1 << 16;
const AMD_SPI_FIFO_CLEAR: u32 = 1 << 20;
const AMD_SPI_BUSY: u32 = 1 << 31;
const AMD_SPI_OPCODE_MASK: u32 = 0xFF;

// ── V2 / HID2 trigger ─────────────────────────────────────────────
const AMD_SPI_TRIGGER_CMD: u8 = 1 << 7;

// ── ALT_CS bit mask ────────────────────────────────────────────────
const AMD_SPI_ALT_CS_MASK: u8 = 0x3;

// ── Speed register fields ──────────────────────────────────────────
const AMD_SPI_ALT_SPD_SHIFT: u32 = 20;
const AMD_SPI_ALT_SPD_MASK: u32 = 0xF << AMD_SPI_ALT_SPD_SHIFT;
const AMD_SPI_SPI100_MASK: u32 = 1;
const AMD_SPI_SPD7_SHIFT: u32 = 8;
const AMD_SPI_SPD7_MASK: u32 = 0x3F << AMD_SPI_SPD7_SHIFT;

// ── FIFO depth ─────────────────────────────────────────────────────
//
// AMD_SPI_MAX_DATA from Linux spi-amd.c.
pub const AMD_SPI_FIFO_DEPTH: usize = 64;

// ── Busy-wait budget ───────────────────────────────────────────────
const BUSY_WAIT_POLLS: u32 = 100_000;

// ── Speed table ────────────────────────────────────────────────────
//
// From Linux spi-amd.c amd_spi_freq[] + enum amd_spi_speed.
// Each entry is (max_hz, enable_val, spd7_val). A spd7_val of 0
// means the SPD7 register field is not needed for this speed.
//
// SPI100 enable bit (bit 0 of ENA_REG) is set when speed = 100 MHz.

const SPEED_TABLE: &[(u32, u32, u32)] = &[
    (100_000_000, 4, 0),   // F_100MHz
    (66_660_000, 0, 0),    // F_66_66MHz
    (50_000_000, 7, 0x04), // SPI_SPD7 + F_50MHz
    (33_330_000, 1, 0),    // F_33_33MHz
    (22_220_000, 2, 0),    // F_22_22MHz
    (16_660_000, 3, 0),    // F_16_66MHz
    (4_000_000, 7, 0x32),  // SPI_SPD7 + F_4MHz
    (3_170_000, 7, 0x3F),  // SPI_SPD7 + F_3_17MHz
    (800_000, 5, 0),       // F_800KHz
];

const AMD_SPI_MAX_HZ: u32 = 100_000_000;
const AMD_SPI_MIN_HZ: u32 = 800_000;

// ── Controller version ─────────────────────────────────────────────

/// AMD FCH SPI hardware version.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AmdSpiVersion {
    /// V1 — AMDI0061. Executes via CTRL0.EXEC_CMD.
    V1,
    /// V2 — AMDI0062. Uses separate opcode + trigger registers.
    V2,
    /// HID2 — AMDI0063. V2 register layout; DMA-capable but we use PIO.
    Hid2,
}

// ── Driver struct ──────────────────────────────────────────────────

/// One AMD FCH SPI controller instance.
pub struct AmdFchSpi {
    name: String,
    mmio_base: PhysAddr,
    mmio_len: u64,
    version: AmdSpiVersion,
    /// Cached current mode (CPOL/CPHA). Updated by `set_mode()`.
    mode: AtomicU32,
    /// Cached current chip-select. Updated by `set_cs()`.
    cs: AtomicU32,
    /// Cached current speed_hz. Updated by `set_freq()`.
    speed_hz: AtomicU32,
}

impl core::fmt::Debug for AmdFchSpi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AmdFchSpi")
            .field("name", &self.name)
            .field("mmio_base", &self.mmio_base)
            .field("version", &self.version)
            .finish()
    }
}

impl AmdFchSpi {
    /// Construct a controller. Used both by `probe_all` and by
    /// the smoke tests (synthetic MMIO buffer).
    pub fn new(name: String, mmio_base: PhysAddr, mmio_len: u64, version: AmdSpiVersion) -> Self {
        Self {
            name,
            mmio_base,
            mmio_len,
            version,
            mode: AtomicU32::new(SpiMode::Mode0 as u32),
            cs: AtomicU32::new(0),
            speed_hz: AtomicU32::new(AMD_SPI_MAX_HZ),
        }
    }

    // ── MMIO accessors ─────────────────────────────────────────────

    #[inline]
    unsafe fn read8(&self, off: u64) -> u8 {
        debug_assert!(off < self.mmio_len);
        // SAFETY: caller holds the bus lock; offset bounds-checked.
        unsafe { narf_arch::mmio::read8(self.mmio_base.raw() + off) }
    }

    #[inline]
    unsafe fn write8(&self, off: u64, val: u8) {
        debug_assert!(off < self.mmio_len);
        // SAFETY: same.
        unsafe { narf_arch::mmio::write8(self.mmio_base.raw() + off, val) }
    }

    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: same.
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    #[inline]
    unsafe fn write32(&self, off: u64, val: u32) {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: same.
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
    }

    // ── Private helpers ────────────────────────────────────────────

    /// Clear the FIFO data pointer so a new transfer starts at offset 0.
    /// From Linux amd_spi_clear_fifo_ptr().
    unsafe fn clear_fifo(&self) {
        // SAFETY: caller serialises.
        let ctrl0 = unsafe { self.read32(AMD_SPI_CTRL0_REG) };
        unsafe { self.write32(AMD_SPI_CTRL0_REG, ctrl0 | AMD_SPI_FIFO_CLEAR) };
    }

    /// Poll BUSY until clear, returning Timeout when the budget is
    /// exhausted. From Linux amd_spi_busy_wait().
    fn busy_wait(&self) -> Result<(), SpiError> {
        let status_reg = match self.version {
            AmdSpiVersion::V1 => AMD_SPI_CTRL0_REG,
            AmdSpiVersion::V2 | AmdSpiVersion::Hid2 => AMD_SPI_STATUS_REG,
        };
        for _ in 0..BUSY_WAIT_POLLS {
            // SAFETY: no concurrent transfers (callers hold the bus lock).
            let val = unsafe { self.read32(status_reg) };
            if val & AMD_SPI_BUSY == 0 {
                return Ok(());
            }
        }
        Err(SpiError::Timeout)
    }

    /// Set the opcode byte for the upcoming transfer.
    /// From Linux amd_spi_set_opcode().
    unsafe fn set_opcode(&self, opcode: u8) {
        match self.version {
            AmdSpiVersion::V1 => {
                // SAFETY: caller serialises.
                let ctrl0 = unsafe { self.read32(AMD_SPI_CTRL0_REG) };
                unsafe {
                    self.write32(
                        AMD_SPI_CTRL0_REG,
                        (ctrl0 & !AMD_SPI_OPCODE_MASK) | (opcode as u32),
                    )
                };
            }
            AmdSpiVersion::V2 | AmdSpiVersion::Hid2 => {
                // SAFETY: same.
                unsafe { self.write8(AMD_SPI_OPCODE_REG, opcode) };
            }
        }
    }

    /// Trigger command execution.
    /// From Linux amd_spi_execute_opcode().
    unsafe fn execute_opcode(&self) -> Result<(), SpiError> {
        self.busy_wait()?;
        match self.version {
            AmdSpiVersion::V1 => {
                // SAFETY: caller serialises.
                let ctrl0 = unsafe { self.read32(AMD_SPI_CTRL0_REG) };
                unsafe { self.write32(AMD_SPI_CTRL0_REG, ctrl0 | AMD_SPI_EXEC_CMD) };
            }
            AmdSpiVersion::V2 | AmdSpiVersion::Hid2 => {
                // SAFETY: same.
                let trig = unsafe { self.read8(AMD_SPI_CMD_TRIGGER_REG) };
                unsafe { self.write8(AMD_SPI_CMD_TRIGGER_REG, trig | AMD_SPI_TRIGGER_CMD) };
            }
        }
        Ok(())
    }

    /// Program the speed registers for the nearest frequency ≤ `hz`.
    /// From Linux amd_set_spi_freq().
    fn apply_freq(&self, hz: u32) -> Result<(), SpiError> {
        if !(AMD_SPI_MIN_HZ..=AMD_SPI_MAX_HZ).contains(&hz) {
            return Err(SpiError::FrequencyOutOfRange);
        }
        // Pick the highest speed that does not exceed `hz`.
        let (speed, enable_val, spd7_val) = SPEED_TABLE
            .iter()
            .find(|(cap, _, _)| hz >= *cap)
            .copied()
            .unwrap_or(*SPEED_TABLE.last().unwrap());

        // SAFETY: no concurrent transfer.
        unsafe {
            let ena = self.read32(AMD_SPI_ENA_REG);
            let alt_spd = (enable_val << AMD_SPI_ALT_SPD_SHIFT) & AMD_SPI_ALT_SPD_MASK;
            self.write32(AMD_SPI_ENA_REG, (ena & !AMD_SPI_ALT_SPD_MASK) | alt_spd);
            if speed == AMD_SPI_MAX_HZ {
                // Enable SPI100 path.
                let ena2 = self.read32(AMD_SPI_ENA_REG);
                self.write32(AMD_SPI_ENA_REG, ena2 | AMD_SPI_SPI100_MASK);
            }
            if spd7_val != 0 {
                let spd = self.read32(AMD_SPI_SPEED_REG);
                let new = (spd & !AMD_SPI_SPD7_MASK)
                    | ((spd7_val << AMD_SPI_SPD7_SHIFT) & AMD_SPI_SPD7_MASK);
                self.write32(AMD_SPI_SPEED_REG, new);
            }
        }
        self.speed_hz.store(speed, Ordering::Relaxed);
        Ok(())
    }

    /// Perform a single FIFO-sized chunk transfer.
    ///
    /// `tx_chunk` is clocked out (opcode = tx_chunk[0], body = rest).
    /// `rx_buf` receives the response bytes (may be empty for TX-only).
    /// Both must be ≤ `AMD_SPI_FIFO_DEPTH` bytes.
    ///
    /// Adapted from Linux amd_spi_fifo_xfer().
    fn fifo_xfer(&self, tx_chunk: &[u8], rx_buf: &mut [u8]) -> Result<(), SpiError> {
        debug_assert!(tx_chunk.len() <= AMD_SPI_FIFO_DEPTH);
        debug_assert!(rx_buf.len() <= AMD_SPI_FIFO_DEPTH);

        if tx_chunk.is_empty() && rx_buf.is_empty() {
            return Ok(());
        }

        let opcode = if tx_chunk.is_empty() {
            0x05 // READ_STATUS — benign NOP on the wire for RX-only
        } else {
            tx_chunk[0]
        };
        let tx_body = if tx_chunk.len() > 1 {
            &tx_chunk[1..]
        } else {
            &[]
        };
        let tx_len = tx_body.len() as u8;
        let rx_len = rx_buf.len() as u8;

        // SAFETY: no concurrent access; we hold the bus lock.
        unsafe {
            self.clear_fifo();
            self.set_opcode(opcode);

            // Write TX bytes into the FIFO.
            for (i, &b) in tx_body.iter().enumerate() {
                self.write8(AMD_SPI_FIFO_BASE + i as u64, b);
            }

            // Program byte counts.
            self.write8(AMD_SPI_TX_COUNT_REG, tx_len);
            self.write8(AMD_SPI_RX_COUNT_REG, rx_len);

            // Execute and wait for completion.
            self.execute_opcode()?;

            if rx_len > 0 {
                self.busy_wait()?;
                // Read RX bytes from FIFO immediately after TX body.
                let rx_fifo_off = AMD_SPI_FIFO_BASE + tx_len as u64;
                for (i, slot) in rx_buf.iter_mut().enumerate() {
                    *slot = self.read8(rx_fifo_off + i as u64);
                }
            }
        }
        Ok(())
    }
}

impl SpiBus for AmdFchSpi {
    fn transfer(&self, tx: &[u8], rx: &mut [u8]) -> Result<(), SpiError> {
        let len = tx.len().max(rx.len());
        if len == 0 {
            return Ok(());
        }
        // Chunk across FIFO depth. The first byte of each chunk is
        // the opcode; for chunks after the first we forward a
        // continuation byte. Client drivers that do not need opcode
        // framing should use chunks that fit in one FIFO op.
        let chunk_size = AMD_SPI_FIFO_DEPTH;
        let mut offset = 0usize;
        while offset < len {
            let end = (offset + chunk_size).min(len);
            let tx_chunk = if offset < tx.len() {
                &tx[offset..end.min(tx.len())]
            } else {
                &[]
            };
            let rx_slice = if offset < rx.len() {
                let rx_end = end.min(rx.len());
                &mut rx[offset..rx_end]
            } else {
                &mut []
            };
            self.fifo_xfer(tx_chunk, rx_slice)?;
            offset = end;
        }
        Ok(())
    }

    fn transfer_full_duplex(&self, tx: &mut [u8], rx: &mut [u8]) -> Result<(), SpiError> {
        if tx.len() != rx.len() {
            return Err(SpiError::BufferTooLarge);
        }
        // Full-duplex: transmit tx, receive into rx. Split into FIFO-sized
        // chunks. Each chunk's TX slice starts with the opcode byte.
        let len = tx.len();
        let mut offset = 0usize;
        while offset < len {
            let end = (offset + AMD_SPI_FIFO_DEPTH).min(len);
            let tx_chunk = &tx[offset..end];
            let rx_slice = &mut rx[offset..end];
            self.fifo_xfer(tx_chunk, rx_slice)?;
            offset = end;
        }
        Ok(())
    }

    fn set_mode(&self, mode: SpiMode) -> Result<(), SpiError> {
        self.mode.store(mode as u32, Ordering::Relaxed);
        Ok(())
    }

    fn set_freq(&self, hz: u32) -> Result<(), SpiError> {
        self.apply_freq(hz)
    }

    fn set_cs(&self, cs: u8) -> Result<(), SpiError> {
        if cs > AMD_SPI_ALT_CS_MASK {
            return Err(SpiError::InvalidCs);
        }
        // SAFETY: no concurrent transfer; atomic store + single byte write.
        unsafe {
            let cur = self.read8(AMD_SPI_ALT_CS_REG);
            self.write8(AMD_SPI_ALT_CS_REG, (cur & !AMD_SPI_ALT_CS_MASK) | cs);
        }
        self.cs.store(cs as u32, Ordering::Relaxed);
        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ── Discovery ──────────────────────────────────────────────────────

/// Walk the AML namespace for AMD SPI ACPI HIDs, decode _CRS, and
/// register each found controller. Returns the count registered.
pub fn probe_all() -> usize {
    use core::fmt::Write;
    let mut count = 0usize;
    for &hid in AMD_SPI_ACPI_HIDS {
        let version = match hid {
            "AMDI0061" => AmdSpiVersion::V1,
            "AMDI0062" => AmdSpiVersion::V2,
            "AMDI0063" => AmdSpiVersion::Hid2,
            _ => continue,
        };
        for node in narf_aml::find_all_devices_by_hid(hid) {
            let _ = writeln!(
                narf_console::Writer,
                "  amd-fch-spi: probing {} (HID={})",
                node.path,
                hid
            );
            if let Some(()) = probe_one(&node.path, version) {
                count += 1;
            }
        }
    }
    count
}

fn probe_one(path: &str, version: AmdSpiVersion) -> Option<()> {
    use core::fmt::Write;
    use narf_aml::resource::ResourceItem;

    let items = narf_aml::prt_crs::evaluate_crs_for(path).ok()?;
    let mut mmio: Option<(u64, u64)> = None;
    for item in items {
        match item {
            ResourceItem::Memory32Fixed { base, length, .. } if mmio.is_none() => {
                mmio = Some((base as u64, length as u64));
            }
            ResourceItem::Memory32 { min, length, .. } if mmio.is_none() => {
                mmio = Some((min as u64, length as u64));
            }
            _ => {}
        }
    }
    let (base, len) = match mmio {
        Some(m) => m,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  amd-fch-spi: {} _CRS had no memory range",
                path
            );
            return None;
        }
    };

    let drv = Arc::new(AmdFchSpi::new(
        path.to_string(),
        PhysAddr::new(base),
        len,
        version,
    ));
    crate::registry::register_unique(drv);
    let _ = writeln!(
        narf_console::Writer,
        "  amd-fch-spi: {} registered mmio={:#x}+{:#x} version={:?}",
        path,
        base,
        len,
        version
    );
    Some(())
}

/// Test-only: list the ACPI HIDs we recognise.
#[doc(hidden)]
pub fn recognised_hids() -> &'static [&'static str] {
    AMD_SPI_ACPI_HIDS
}

/// Test-only: construct a driver instance directly against a
/// caller-supplied MMIO base (synthetic buffer in tests).
#[doc(hidden)]
pub fn __new_for_test(name: String, mmio_base: PhysAddr, mmio_len: u64) -> AmdFchSpi {
    AmdFchSpi::new(name, mmio_base, mmio_len, AmdSpiVersion::V1)
}
