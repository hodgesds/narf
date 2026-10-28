//! Register and delay seams.
//!
//! [`RegIo`] is a 32-bit register window (Linux `readl`/`writel` on an
//! `ioremap`ed resource, or a `regmap` over a syscon). [`MmioRegs`] is the
//! real implementation over `narf_memory::ioremap`; tests substitute the
//! recording fakes in `fixtures`.
//!
//! [`Delay`] is the only way a sequence in this crate waits. [`poll_reg`]
//! is Linux `readl_poll_timeout`: read, test, *sleep*, repeat until the
//! deadline, then test once more — never a busy spin on the register.

use core::future::Future;

/// A 32-bit register window addressed by byte offset.
pub trait RegIo {
    /// `readl(base + off)`.
    fn read32(&self, off: u32) -> u32;
    /// `writel(value, base + off)`.
    fn write32(&self, off: u32, value: u32);
    /// `regmap_update_bits`: read-modify-write of the bits in `mask`.
    fn update32(&self, off: u32, mask: u32, value: u32) {
        let v = (self.read32(off) & !mask) | (value & mask);
        self.write32(off, v);
    }
}

impl<T: RegIo + ?Sized> RegIo for &T {
    fn read32(&self, off: u32) -> u32 {
        (**self).read32(off)
    }
    fn write32(&self, off: u32, value: u32) {
        (**self).write32(off, value)
    }
}

/// Mapping failure for [`MmioRegs::map`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MapError {
    /// Zero length or a range that overflows.
    BadRange,
    /// `narf_memory::ioremap` refused the range.
    Ioremap,
}

/// A device register window mapped Device-nGnRE (`ioremap`).
#[derive(Copy, Clone, Debug)]
pub struct MmioRegs {
    virt: u64,
    len: u64,
}

impl MmioRegs {
    /// `devm_ioremap(phys, len)`.
    pub fn map(phys: u64, len: u64) -> Result<Self, MapError> {
        if len == 0 || phys.checked_add(len).is_none() {
            return Err(MapError::BadRange);
        }
        // SAFETY: `phys..phys+len` is a device resource described by the
        // firmware devicetree; ioremap installs a fresh Device mapping and
        // never aliases normal memory with a conflicting attribute (it
        // returns AttributeConflict instead).
        let m = unsafe {
            narf_memory::ioremap::ioremap(phys, len, narf_memory::ioremap::MmioAttrs::Device)
        }
        .map_err(|_| MapError::Ioremap)?;
        Ok(Self { virt: m.va(), len })
    }

    /// Wrap an already-mapped window.
    ///
    /// # Safety
    /// `virt..virt+len` must stay mapped (Device or Normal memory) for the
    /// lifetime of the returned value and be safe to access with 32-bit
    /// volatile loads/stores at 4-byte-aligned offsets.
    pub const unsafe fn from_raw(virt: u64, len: u64) -> Self {
        Self { virt, len }
    }

    /// Mapped length in bytes.
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// `true` for an empty window.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn in_range(&self, off: u32) -> bool {
        off & 3 == 0 && (off as u64) + 4 <= self.len
    }
}

impl RegIo for MmioRegs {
    /// Out-of-window reads return all-ones (a bus error pattern) instead
    /// of touching memory outside the mapping.
    fn read32(&self, off: u32) -> u32 {
        if !self.in_range(off) {
            return u32::MAX;
        }
        // SAFETY: in-range, aligned; mapping lifetime per constructor.
        unsafe { narf_arch::mmio::read32(self.virt + off as u64) }
    }
    /// Out-of-window writes are dropped.
    fn write32(&self, off: u32, value: u32) {
        if !self.in_range(off) {
            return;
        }
        // SAFETY: in-range, aligned; mapping lifetime per constructor.
        unsafe { narf_arch::mmio::write32(self.virt + off as u64, value) }
    }
}

/// The time source every wait in this crate goes through.
pub trait Delay {
    /// Sleep at least `us` microseconds (`usleep_range` / `msleep`).
    fn sleep_us(&self, us: u32) -> impl Future<Output = ()> + Send;
    /// Monotonic microseconds.
    fn now_us(&self) -> u64;
}

impl<T: Delay + ?Sized> Delay for &T {
    fn sleep_us(&self, us: u32) -> impl Future<Output = ()> + Send {
        (**self).sleep_us(us)
    }
    fn now_us(&self) -> u64 {
        (**self).now_us()
    }
}

/// [`Delay`] over the kernel timer wheel (`narf_time::SleepUntil`).
#[derive(Copy, Clone, Debug, Default)]
pub struct NarfDelay;

impl Delay for NarfDelay {
    fn sleep_us(&self, us: u32) -> impl Future<Output = ()> + Send {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(us as u64).as_instant())
    }
    fn now_us(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1_000
    }
}

/// Linux `readl_poll_timeout(addr, val, cond, sleep_us, timeout_us)`.
///
/// Reads `off`; returns `Ok(value)` once `cond(value)` holds. Between
/// reads it sleeps `sleep_us` through `delay`. After `timeout_us` it reads
/// once more (as Linux does) and returns `Err(last_value)` if the
/// condition still fails.
pub async fn poll_reg<R: RegIo + ?Sized, D: Delay + ?Sized>(
    io: &R,
    delay: &D,
    off: u32,
    cond: impl Fn(u32) -> bool,
    sleep_us: u32,
    timeout_us: u32,
) -> Result<u32, u32> {
    let deadline = delay.now_us().saturating_add(timeout_us as u64);
    loop {
        let v = io.read32(off);
        if cond(v) {
            return Ok(v);
        }
        if delay.now_us() >= deadline {
            let v = io.read32(off);
            return if cond(v) { Ok(v) } else { Err(v) };
        }
        delay.sleep_us(sleep_us.max(1)).await;
    }
}
