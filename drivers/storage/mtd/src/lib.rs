//! MTD core — the memory-technology-device layer for raw flash
//! (DT programme step 6).
//!
//! Raw flash is not a block device: it erases in large blocks
//! to all-ones, programs with AND semantics (a program can only
//! clear bits; setting a bit needs an erase), and wears. This
//! core is deliberately only the device layer — a device record
//! with an erase geometry, read / program / erase operations,
//! a registry, and `fixed-partitions` handling. Flash
//! translation layers and flash filesystems sit above it; the
//! tree has none today (the embedded audit's storage-media.md
//! is the reference), and nothing here pretends otherwise.
//!
//! Bindings register devices here, so consumers resolve flash
//! through one registry regardless of the bus the flash hangs
//! off. The QEMU-virt CFI NOR binding and the SPI-NOR client
//! arrive as the following steps of the programme.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Errors of the MTD device layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MtdError {
    /// Offset/length outside the device (or partition).
    OutOfBounds,
    /// Write/erase attempted on a read-only device or partition.
    ReadOnly,
    /// A program operation did not verify (NOR status / AND
    /// semantics violation surfaced by the binding).
    ProgramFailed,
    /// An erase did not complete / verify.
    EraseFailed,
    /// Erase offset or length not aligned to the erase geometry,
    /// or a partition not aligned to the base device geometry.
    BadGeometry,
    /// The binding does not support the operation.
    Unsupported,
}

/// One raw-flash device. Implementors own the controller window
/// and serialise operations internally, like the other driver
/// registries' traits.
pub trait MtdDevice: Send + Sync + core::fmt::Debug {
    /// Registry-unique name (e.g. `cfi-flash@0.bank0`).
    fn name(&self) -> &str;
    /// Total size in bytes.
    fn size(&self) -> u64;
    /// Erase-block size in bytes.
    fn erase_size(&self) -> u32;
    /// Program granularity in bytes (1 for parallel NOR).
    fn write_size(&self) -> u32;
    /// Read `buf` from byte offset `off`.
    fn read(&self, off: u64, buf: &mut [u8]) -> Result<(), MtdError>;
    /// Program `buf` at byte offset `off`. NOR semantics: bits
    /// can only transition 1 → 0; callers erase first when they
    /// need 0 → 1. Bindings verify and report `ProgramFailed`
    /// when the device does.
    fn write(&self, off: u64, buf: &[u8]) -> Result<(), MtdError>;
    /// Erase the erase blocks covering [`off`, `off + len`).
    /// Both must be aligned to [`MtdDevice::erase_size`].
    fn erase(&self, off: u64, len: u64) -> Result<(), MtdError>;
}

// ── Registry ────────────────────────────────────────────────────

/// Process-global registry of MTD devices, keyed by name — the
/// same shape as the SPI/I2C/GPIO registries.
pub mod registry {
    use super::MtdDevice;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};
    use narf_lib::sync::IrqSafeSpinLock;

    pub static REGISTERED_COUNT: AtomicU32 = AtomicU32::new(0);

    static REGISTRY: IrqSafeSpinLock<Vec<Arc<dyn MtdDevice>>> = IrqSafeSpinLock::new(Vec::new());

    /// Register `dev` if no device with the same name exists;
    /// returns the registered (possibly pre-existing) device.
    pub fn register_unique(dev: Arc<dyn MtdDevice>) -> Arc<dyn MtdDevice> {
        let mut g = REGISTRY.lock();
        if let Some(existing) = g.iter().find(|d| d.name() == dev.name()) {
            return existing.clone();
        }
        g.push(dev.clone());
        REGISTERED_COUNT.store(g.len() as u32, Ordering::Release);
        dev
    }

    /// Find a device by name.
    pub fn find(name: &str) -> Option<Arc<dyn MtdDevice>> {
        REGISTRY.lock().iter().find(|d| d.name() == name).cloned()
    }

    /// Snapshot of all registered devices.
    pub fn list() -> Vec<Arc<dyn MtdDevice>> {
        REGISTRY.lock().clone()
    }

    /// Count of registered devices.
    pub fn count() -> u32 {
        REGISTERED_COUNT.load(Ordering::Acquire)
    }

    /// Test-only: drain the registry.
    #[doc(hidden)]
    pub fn __reset_for_test() {
        REGISTRY.lock().clear();
        REGISTERED_COUNT.store(0, Ordering::Release);
    }
}

// ── Partitions ──────────────────────────────────────────────────

/// One flash partition (DT `fixed-partitions` child).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Partition {
    /// Partition name (`label`, or the node name when unlabelled).
    pub name: String,
    /// Byte offset within the base device.
    pub offset: u64,
    /// Byte length.
    pub size: u64,
    /// `read-only` present in the node.
    pub read_only: bool,
}

/// Parse the children of a `fixed-partitions` node (as decoded
/// by `narf_bus::dt::children_of`) into partitions. Children
/// without a decodable `reg` are skipped; a zero-size child is
/// skipped as meaningless.
pub fn parse_fixed_partitions(fixed_partitions: &narf_bus::dt::DtChild) -> Vec<Partition> {
    let mut out = Vec::new();
    for child in &fixed_partitions.children {
        let Some((offset, size)) = child.reg else {
            continue;
        };
        if size == 0 {
            continue;
        }
        let name = child
            .prop_str("label")
            .map(String::from)
            .unwrap_or_else(|| child.name.clone());
        out.push(Partition {
            name,
            offset,
            size,
            read_only: child.prop_present("read-only"),
        });
    }
    out
}

/// An MTD device exposing one [`Partition`] of a base device —
/// the `/dev/mtdN`-partition shape: partitions are first-class
/// registry citizens with bounds and read-only enforced here,
/// not by each consumer.
#[derive(Debug)]
pub struct PartitionDevice {
    base: Arc<dyn MtdDevice>,
    partition: Partition,
    name: String,
}

impl PartitionDevice {
    /// Wrap `base`'s `partition`. The partition must be aligned
    /// to the base erase geometry and contained in the base —
    /// checked by [`attach_partitions`]; direct construction
    /// trusts the caller.
    pub fn new(base: Arc<dyn MtdDevice>, partition: Partition) -> Self {
        let name = alloc::format!("{}.{}", base.name(), partition.name);
        Self {
            base,
            partition,
            name,
        }
    }

    fn translate(&self, off: u64, len: u64) -> Result<u64, MtdError> {
        if off > self.partition.size || len > self.partition.size - off {
            return Err(MtdError::OutOfBounds);
        }
        Ok(self.partition.offset + off)
    }
}

impl MtdDevice for PartitionDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn size(&self) -> u64 {
        self.partition.size
    }

    fn erase_size(&self) -> u32 {
        self.base.erase_size()
    }

    fn write_size(&self) -> u32 {
        self.base.write_size()
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> Result<(), MtdError> {
        let base_off = self.translate(off, buf.len() as u64)?;
        self.base.read(base_off, buf)
    }

    fn write(&self, off: u64, buf: &[u8]) -> Result<(), MtdError> {
        if self.partition.read_only {
            return Err(MtdError::ReadOnly);
        }
        let base_off = self.translate(off, buf.len() as u64)?;
        self.base.write(base_off, buf)
    }

    fn erase(&self, off: u64, len: u64) -> Result<(), MtdError> {
        if self.partition.read_only {
            return Err(MtdError::ReadOnly);
        }
        let base_off = self.translate(off, len)?;
        self.base.erase(base_off, len)
    }
}

/// Register every partition of `base` described by a
/// `fixed-partitions` node as its own MTD device. A partition
/// not contained in the base, or not aligned to the base's
/// erase geometry, is skipped. Returns how many were attached.
pub fn attach_partitions(
    base: &Arc<dyn MtdDevice>,
    fixed_partitions: &narf_bus::dt::DtChild,
) -> usize {
    let mut n = 0;
    for part in parse_fixed_partitions(fixed_partitions) {
        if part.offset + part.size > base.size()
            || part.offset % base.erase_size() as u64 != 0
            || part.size % base.erase_size() as u64 != 0
        {
            continue;
        }
        registry::register_unique(Arc::new(PartitionDevice::new(base.clone(), part)));
        n += 1;
    }
    n
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
