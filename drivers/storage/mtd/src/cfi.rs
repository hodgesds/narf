//! CFI NOR flash binding — the QEMU-virt CFI flash, bound from
//! DT (DT programme step 6).
//!
//! QEMU virt carries a `cfi-flash` node with two 64 MiB banks.
//! This driver speaks the CFI query protocol (JEDEC 68.01) to
//! identify each bank — command set, device size, erase-region
//! geometry come from the chip, not from constants — and
//! registers one MTD device per bank in the core registry.
//! Intel (0x0001) and AMD/Fujitsu (0x0002) command sets are
//! implemented for program + erase; other command sets identify
//! but refuse program/erase with `Unsupported`.
//!
//! Register access goes through the [`CfiIo`] seam: production
//! is a thin MMIO form over the ioremap'd bank window; the
//! smokes drive a modelled CFI chip (query table + command
//! state machine + busy polling) behind the same seam, so the
//! query/command sequences below are what execute against the
//! model, unchanged — the keystone-fixture discipline. The live
//! query sequence against QEMU's pflash model is exercised by
//! the aarch64 live smoke; CI is its first execution.
//!
//! One honesty note: this v1 assumes a single x16 device per
//! bank with no interleave (exactly what virt describes), and
//! uses the first erase region's block size as the device erase
//! geometry (virt's flash is uniform-region).

use alloc::string::String;
use alloc::sync::Arc;

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::ioremap::IoMapping;

use crate::{MtdDevice, MtdError};

/// Status-poll budget for program/erase completion.
const POLL_BUDGET: u32 = 1_000_000;

/// Register seam for one CFI bank (16-bit accesses at byte
/// offsets within the bank window).
pub trait CfiIo: Send + Sync + core::fmt::Debug {
    /// Read the 16-bit word at byte offset `off`.
    fn read16(&self, off: u64) -> u16;
    /// Write the 16-bit word at byte offset `off`.
    fn write16(&self, off: u64, val: u16);
}

/// Production [`CfiIo`]: volatile MMIO over the ioremap'd bank.
#[derive(Debug)]
pub struct MmioCfi {
    base_va: u64,
    /// Kept so the ioremap lives as long as the device.
    _mapping: Option<IoMapping>,
}

impl MmioCfi {
    /// Wrap an ioremap'd bank window.
    ///
    /// # Safety
    /// `mapping` must cover the bank window.
    pub unsafe fn new(mapping: IoMapping) -> Self {
        Self {
            base_va: mapping.va(),
            _mapping: Some(mapping),
        }
    }
}

impl CfiIo for MmioCfi {
    fn read16(&self, off: u64) -> u16 {
        // SAFETY: base_va covers the bank by the constructor
        // contract; off is within the identified device size.
        unsafe { core::ptr::read_volatile((self.base_va + off) as *const u16) }
    }

    fn write16(&self, off: u64, val: u16) {
        // SAFETY: same contract as read16.
        unsafe { core::ptr::write_volatile((self.base_va + off) as *mut u16, val) }
    }
}

// CFI query offsets, in device words (x16: byte offset = word x 2).
const QRY_WORD: u64 = 0x10;
const CMDSET_WORD: u64 = 0x13;
const SIZE_WORD: u64 = 0x27;
const REGION_TABLE_WORD: u64 = 0x2D;

const CMDSET_INTEL: u16 = 0x0001;
const CMDSET_AMD: u16 = 0x0002;

/// One identified CFI bank as an MTD device.
pub struct CfiFlash<I: CfiIo> {
    name: String,
    io: I,
    size: u64,
    erase_size: u32,
    cmdset: u16,
    lock: IrqSafeSpinLock<()>,
}

impl<I: CfiIo> core::fmt::Debug for CfiFlash<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CfiFlash")
            .field("name", &self.name)
            .field("size", &self.size)
            .field("cmdset", &self.cmdset)
            .finish_non_exhaustive()
    }
}

fn woff(word: u64) -> u64 {
    word * 2
}

impl<I: CfiIo> CfiFlash<I> {
    /// Run the CFI query against `io` and build the device.
    /// `window_len` bounds the bank: a chip claiming more than
    /// the window is clamped to it (the window is what the
    /// machine actually mapped).
    pub fn identify(name: String, io: I, window_len: u64) -> Result<Self, MtdError> {
        let dev = Self {
            name,
            io,
            size: 0,
            erase_size: 0,
            cmdset: 0,
            lock: IrqSafeSpinLock::new(()),
        };
        // Enter query mode: 0x98 at word 0x55.
        dev.io.write16(woff(0x55), 0x0098);
        let q = dev.io.read16(woff(QRY_WORD)) & 0xFF;
        let r = dev.io.read16(woff(QRY_WORD + 1)) & 0xFF;
        let y = dev.io.read16(woff(QRY_WORD + 2)) & 0xFF;
        if (q, r, y) != (0x51, 0x52, 0x59) {
            dev.reset_to_read_array();
            return Err(MtdError::BadGeometry);
        }
        let cmdset = dev.io.read16(woff(CMDSET_WORD));
        let size_pow = dev.io.read16(woff(SIZE_WORD)) & 0xFF;
        if !(16..=31).contains(&size_pow) {
            dev.reset_to_read_array();
            return Err(MtdError::BadGeometry);
        }
        let size = (1u64 << size_pow).min(window_len);
        // Erase-region geometry (JEDEC 68.01 §): the region
        // descriptor starts at word 0x2D as four bytes in the low
        // halves of consecutive words — (blocks - 1) LE16, then
        // (block size / 256) LE16. v1 uses the first region's
        // block size; the module docs name the uniform-region
        // assumption.
        let units = (dev.io.read16(woff(REGION_TABLE_WORD + 2)) & 0xFF)
            | ((dev.io.read16(woff(REGION_TABLE_WORD + 3)) & 0xFF) << 8);
        let block_size = units * 256;
        dev.reset_to_read_array();
        if block_size == 0 || block_size as u64 > size {
            return Err(MtdError::BadGeometry);
        }
        Ok(Self {
            size,
            erase_size: block_size,
            cmdset,
            ..dev
        })
    }

    /// The CFI primary command set (0x0001 Intel, 0x0002 AMD).
    pub fn cmdset(&self) -> u16 {
        self.cmdset
    }

    fn reset_to_read_array(&self) {
        // Intel wants 0xFF, AMD 0xF0; writing both is the common
        // robust form (each ignores the other's reset word once
        // back in read-array mode).
        self.io.write16(0, 0x00FF);
        self.io.write16(0, 0x00F0);
    }

    fn bounds(&self, off: u64, len: u64) -> Result<(), MtdError> {
        if off > self.size || len > self.size - off {
            return Err(MtdError::OutOfBounds);
        }
        Ok(())
    }

    // ── Intel command set ─────────────────────────────────────

    fn intel_poll_ready(&self) -> Result<(), MtdError> {
        self.io.write16(0, 0x0070); // read status
        for _ in 0..POLL_BUDGET {
            let status = self.io.read16(0);
            if status & 0x0080 != 0 {
                if status & 0x0030 != 0 {
                    self.io.write16(0, 0x0050); // clear status
                    self.reset_to_read_array();
                    return Err(MtdError::ProgramFailed);
                }
                self.io.write16(0, 0x0050);
                self.reset_to_read_array();
                return Ok(());
            }
            core::hint::spin_loop();
        }
        self.reset_to_read_array();
        Err(MtdError::ProgramFailed)
    }

    fn intel_program_word(&self, word_addr: u64, data: u16) -> Result<(), MtdError> {
        self.io.write16(woff(word_addr), 0x0040);
        self.io.write16(woff(word_addr), data);
        self.intel_poll_ready()
    }

    fn intel_erase_block(&self, block_word_addr: u64) -> Result<(), MtdError> {
        self.io.write16(woff(block_word_addr), 0x0020);
        self.io.write16(woff(block_word_addr), 0x00D0);
        self.intel_poll_ready().map_err(|_| MtdError::EraseFailed)
    }

    // ── AMD command set ───────────────────────────────────────

    fn amd_unlock(&self) {
        self.io.write16(woff(0x555), 0x00AA);
        self.io.write16(woff(0x2AA), 0x0055);
    }

    fn amd_poll_word(&self, word_addr: u64, data: u16, erase: bool) -> Result<(), MtdError> {
        for _ in 0..POLL_BUDGET {
            let v = self.io.read16(woff(word_addr));
            // DQ7 true-data poll: reads back the written data's
            // DQ7 once the operation completes.
            if (v ^ data) & 0x0080 == 0 {
                self.reset_to_read_array();
                return Ok(());
            }
            core::hint::spin_loop();
        }
        self.reset_to_read_array();
        Err(if erase {
            MtdError::EraseFailed
        } else {
            MtdError::ProgramFailed
        })
    }

    fn amd_program_word(&self, word_addr: u64, data: u16) -> Result<(), MtdError> {
        self.amd_unlock();
        self.io.write16(woff(0x555), 0x00A0);
        self.io.write16(woff(word_addr), data);
        self.amd_poll_word(word_addr, data, false)
    }

    fn amd_erase_block(&self, block_word_addr: u64) -> Result<(), MtdError> {
        self.amd_unlock();
        self.io.write16(woff(0x555), 0x0080);
        self.amd_unlock();
        self.io.write16(woff(block_word_addr), 0x0030);
        // Erase completion polls DQ7 at the block address: the
        // erased word reads all-ones.
        self.amd_poll_word(block_word_addr, 0xFFFF, true)
    }
}

impl<I: CfiIo> MtdDevice for CfiFlash<I> {
    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn erase_size(&self) -> u32 {
        self.erase_size
    }

    fn write_size(&self) -> u32 {
        2 // one x16 word
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> Result<(), MtdError> {
        self.bounds(off, buf.len() as u64)?;
        let _guard = self.lock.lock();
        // Read-array mode is the resting state (every command
        // path returns to it), so reads are direct.
        let mut i = 0usize;
        while i < buf.len() {
            let word = self.io.read16(off + i as u64);
            buf[i] = word as u8;
            if i + 1 < buf.len() {
                buf[i + 1] = (word >> 8) as u8;
            }
            i += 2;
        }
        Ok(())
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<(), MtdError> {
        self.bounds(off, buf.len() as u64)?;
        if !matches!(self.cmdset, CMDSET_INTEL | CMDSET_AMD) {
            return Err(MtdError::Unsupported);
        }
        let _guard = self.lock.lock();
        // Program word by word, read-modify-write so partial
        // words at either end (and any caller alignment) keep
        // their untouched byte: programming a byte with its
        // current value is a NOR no-op.
        let mut done = 0usize;
        while done < buf.len() {
            let addr = off + done as u64;
            let word_addr = addr / 2;
            let byte_in_word = (addr % 2) as usize;
            let cur = self.io.read16(word_addr * 2);
            let mut bytes = cur.to_le_bytes();
            let mut n = 0usize;
            while byte_in_word + n < 2 && done + n < buf.len() {
                bytes[byte_in_word + n] = buf[done + n];
                n += 1;
            }
            let word = u16::from_le_bytes(bytes);
            match self.cmdset {
                CMDSET_INTEL => self.intel_program_word(word_addr, word)?,
                _ => self.amd_program_word(word_addr, word)?,
            }
            done += n;
        }
        Ok(())
    }

    fn erase(&self, off: u64, len: u64) -> Result<(), MtdError> {
        let es = self.erase_size as u64;
        if off % es != 0 || len % es != 0 {
            return Err(MtdError::BadGeometry);
        }
        self.bounds(off, len)?;
        if !matches!(self.cmdset, CMDSET_INTEL | CMDSET_AMD) {
            return Err(MtdError::Unsupported);
        }
        let _guard = self.lock.lock();
        let mut block = off;
        while block < off + len {
            let word_addr = block / 2;
            match self.cmdset {
                CMDSET_INTEL => self.intel_erase_block(word_addr)?,
                _ => self.amd_erase_block(word_addr)?,
            }
            block += es;
        }
        Ok(())
    }
}

// ── DT binding ──────────────────────────────────────────────────

/// Register the CFI DT match entry with the bus match table.
/// Called from the storage facade's `register_initcalls` —
/// composition-time registration, census-neutral (bus registry
/// state, not an initcall).
pub fn register_dt_drivers() {
    narf_bus::register_dt_driver(narf_bus::DtMatch {
        name: "cfi-flash",
        compatible: "cfi-flash",
        probe: probe_dt,
    });
}

fn probe_dt(
    dev: narf_bus::BusDevice,
    _cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    use narf_bus::ProbeError;
    use narf_memory::ioremap::{ioremap, MmioAttrs};
    let narf_bus::BusKind::Platform(rec) = dev.kind else {
        return Err(ProbeError::NotForThisDriver);
    };
    if rec.reg_windows().is_empty() {
        return Err(ProbeError::BadDevice);
    }
    // The node's partitions (flash-global offsets), parsed once.
    let partitions_node = narf_bus::dt::dtb_blob().and_then(|blob| {
        let win0 = rec.reg_windows().first()?;
        narf_bus::dt::children_of(blob, rec.first_compatible(), win0.base.raw())
            .into_iter()
            .find(|c| c.compatible_contains("fixed-partitions"))
    });
    let mut bound_any = false;
    let mut bank_global_base = 0u64;
    for (bank, win) in rec.reg_windows().iter().enumerate() {
        // SAFETY: the window is the device's DT reg window;
        // ioremap maps it for the binding's lifetime (the mapping
        // rides inside the registered device).
        let mapping = unsafe { ioremap(win.base.raw(), win.len, MmioAttrs::Device) }
            .map_err(|_| ProbeError::Other("cfi-flash: ioremap of a bank window failed"))?;
        // SAFETY: the ioremap covers the bank window.
        let io = unsafe { MmioCfi::new(mapping) };
        let name = alloc::format!("cfi@{:#x}.bank{}", rec.reg_windows()[0].base.raw(), bank);
        let Ok(flash) = CfiFlash::identify(name, io, win.len) else {
            bank_global_base += win.len;
            continue; // a window that doesn't answer CFI is not a bank
        };
        let dev_arc: Arc<dyn MtdDevice> = Arc::new(flash);
        crate::registry::register_unique(dev_arc.clone());
        bound_any = true;
        // Attach this bank's slice of the node's partitions:
        // partition offsets are flash-global; a partition fully
        // inside this bank attaches, rebased to the bank.
        if let Some(node) = &partitions_node {
            for part in crate::parse_fixed_partitions(node) {
                if part.offset >= bank_global_base
                    && part.offset + part.size <= bank_global_base + dev_arc.size()
                {
                    let rebased = crate::Partition {
                        offset: part.offset - bank_global_base,
                        ..part
                    };
                    if rebased.offset % dev_arc.erase_size() as u64 == 0
                        && rebased.size % dev_arc.erase_size() as u64 == 0
                    {
                        crate::registry::register_unique(Arc::new(crate::PartitionDevice::new(
                            dev_arc.clone(),
                            rebased,
                        )));
                    }
                }
            }
        }
        bank_global_base += win.len;
    }
    if bound_any {
        Ok(())
    } else {
        Err(ProbeError::BadDevice)
    }
}
