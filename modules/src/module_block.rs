//! Module-backed block devices: the kernel half of the `narf_blk_*` exports.
//!
//! A loadable storage driver registers one disk per namespace with
//! [`register`]. The disk joins the ordinary block registry
//! (`narf_block::register_block_device`), so `/dev/<name>`, partition
//! scanning and filesystems reach it like any built-in disk.
//!
//! Requests are synchronous, the same shape as the built-in polled drivers
//! (`NvmeBlockSync`, `AhciBlockSync`): [`BlockDeviceSync::read`] or `write`
//! calls the module's request callback through the module call gate (its
//! load-time domain, pinned `Live`) and returns once the callback does. The
//! module moves sector data with [`copy`], between the caller's buffer and
//! either one of its own DMA buffers (PCI drivers) or module memory it hands
//! the export (USB drivers, whose transfers already copy through module
//! memory). No kernel pointer is ever handed to module text.
//!
//! One request per disk is in flight at a time, and a request larger than
//! the module's `max_blocks` is split here. On unload, [`retire_owner`]
//! fails new requests, waits out the running one, and unregisters every
//! disk before the bus context and module text go away; [`retire_token`]
//! does the same for one device when the bus retires its context.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use narf_block::registry::{BlockCaps, BlockDeviceSync, BlockIoError};
use narf_lib::sync::IrqSafeSpinLock;

/// Module request callback. Runs in the module's domain, performs the whole
/// request, and returns 0 or a negative errno.
pub type RequestFn = extern "C" fn(cookie: u64, request: u64, op: u32, lba: u64, count: u32) -> i32;

/// Read `count` blocks at `lba`: the module copies them out with [`copy`].
pub const OP_READ: u32 = 0;
/// Write `count` blocks at `lba`: the module copies them in with [`copy`].
pub const OP_WRITE: u32 = 1;
/// Drain the device's volatile write cache (`lba` and `count` are 0).
pub const OP_FLUSH: u32 = 2;

/// Completed writes may sit in a volatile cache until [`OP_FLUSH`].
pub const FLAG_VOLATILE_CACHE: u32 = 1 << 0;
/// The medium refuses writes.
pub const FLAG_READ_ONLY: u32 = 1 << 1;
const KNOWN_FLAGS: u32 = FLAG_VOLATILE_CACHE | FLAG_READ_ONLY;

/// Largest single request a module may advertise (`max_blocks * lba_size`).
pub const MAX_REQUEST_BYTES: u64 = 1 << 20;
/// Disks one module may register.
pub const MAX_DISKS_PER_OWNER: usize = 8;
/// Longest disk name (`nvme12n34`, `mmcblk0`, ...).
pub const MAX_NAME: usize = 31;
/// How long unload waits for a running request before unregistering.
const RETIRE_WAIT_NS: u64 = 5_000_000_000;

const ENODEV: i32 = -19;
const EINVAL: i32 = -22;
const EBUSY: i32 = -16;
const EEXIST: i32 = -17;
const ENOSPC: i32 = -28;
const EROFS: i32 = -30;

struct Disk {
    owner: u64,
    token: u64,
    name: &'static str,
    lba_size: u32,
    capacity: u64,
    max_blocks: u32,
    flags: u32,
    request: RequestFn,
    cookie: u64,
    alive: AtomicBool,
    busy: AtomicBool,
}

/// One request while its callback runs. `buf`/`len` is the caller's buffer
/// for this chunk; it is valid exactly as long as the entry exists.
struct Active {
    id: u64,
    owner: u64,
    token: u64,
    write: bool,
    buf: usize,
    len: usize,
    copying: bool,
}

static DISKS: IrqSafeSpinLock<Vec<Arc<Disk>>> = IrqSafeSpinLock::new(Vec::new());
static ACTIVE: IrqSafeSpinLock<Vec<Active>> = IrqSafeSpinLock::new(Vec::new());
/// Interned disk names. The block registry keys on `&'static str`; reusing
/// the leaked string keeps load/unload cycles from leaking more.
static NAMES: IrqSafeSpinLock<Vec<&'static str>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

fn intern(name: &str) -> &'static str {
    let mut names = NAMES.lock();
    if let Some(existing) = names.iter().find(|n| **n == name) {
        return existing;
    }
    let leaked: &'static str = Box::leak(String::from(name).into_boxed_str());
    names.push(leaked);
    leaked
}

fn valid_name(name: &[u8]) -> Option<&str> {
    if name.is_empty() || name.len() > MAX_NAME || !name[0].is_ascii_lowercase() {
        return None;
    }
    if !name
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
    {
        return None;
    }
    core::str::from_utf8(name).ok()
}

/// Geometry and callback a module registers a disk with.
#[derive(Clone, Copy, Debug)]
pub struct DiskSpec {
    /// Bytes per logical block: a power of two in 512..=4096.
    pub lba_size: u32,
    /// Capacity in logical blocks.
    pub capacity: u64,
    /// Largest request the module accepts, in blocks.
    pub max_blocks: u32,
    /// `FLAG_*` bits.
    pub flags: u32,
    /// Called for every request.
    pub request: RequestFn,
    /// Passed back to `request` unchanged.
    pub cookie: u64,
}

/// Register a module-backed disk for the device behind `token`: a PCI
/// probe context or a USB one.
pub fn register(owner: u64, token: u64, name: &[u8], spec: DiskSpec) -> i32 {
    if !narf_bus::module_device_live(owner, token)
        && !narf_bus::module_usb::context_live(owner, token)
    {
        return ENODEV;
    }
    register_unchecked(owner, token, name, spec)
}

/// [`register`] without the bus-context check; the in-kernel smokes use it
/// with owner ids no module can have.
pub(crate) fn register_unchecked(owner: u64, token: u64, name: &[u8], spec: DiskSpec) -> i32 {
    let Some(name) = valid_name(name) else {
        return EINVAL;
    };
    let DiskSpec {
        lba_size,
        capacity,
        max_blocks,
        flags,
        ..
    } = spec;
    if !lba_size.is_power_of_two()
        || !(512..=4096).contains(&lba_size)
        || capacity == 0
        || max_blocks == 0
        || u64::from(max_blocks) * u64::from(lba_size) > MAX_REQUEST_BYTES
        || flags & !KNOWN_FLAGS != 0
    {
        return EINVAL;
    }
    let disk = {
        let mut disks = DISKS.lock();
        if disks.iter().filter(|d| d.owner == owner).count() >= MAX_DISKS_PER_OWNER {
            return ENOSPC;
        }
        if disks.iter().any(|d| d.name == name)
            || narf_block::block_devices().iter().any(|d| d.name == name)
        {
            return EEXIST;
        }
        let disk = Arc::new(Disk {
            owner,
            token,
            name: intern(name),
            lba_size,
            capacity,
            max_blocks,
            flags,
            request: spec.request,
            cookie: spec.cookie,
            alive: AtomicBool::new(true),
            busy: AtomicBool::new(false),
        });
        disks.push(Arc::clone(&disk));
        disk
    };
    // Outside the lock: registration may read the disk (disk policy), which
    // re-enters this module's request callback.
    narf_block::register_block_device(disk.name, Arc::new(ModuleDisk(Arc::clone(&disk))));
    0
}

/// The module side of one copy.
#[derive(Clone, Copy, Debug)]
pub enum Endpoint {
    /// One of the module's bus DMA buffers, at a byte offset.
    Dma { handle: u64, offset: u64 },
    /// Module memory the export was handed; `len` bytes long, readable for
    /// a read request and writable for a write request.
    Module(usize),
}

/// Copy one range of the running request. `to_request` = a read (module
/// side to the caller's buffer); otherwise a write (caller's buffer to the
/// module side). Only the module that owns the request, for the device it
/// registered the disk on, may copy, and only while the request callback
/// runs.
pub fn copy(
    owner: u64,
    token: u64,
    request: u64,
    endpoint: Endpoint,
    range: core::ops::Range<usize>,
    to_request: bool,
) -> i32 {
    let (req_off, len) = (range.start, range.end.saturating_sub(range.start));
    let (buf, write) = {
        let mut active = ACTIVE.lock();
        let Some(entry) = active
            .iter_mut()
            .find(|a| a.id == request && a.owner == owner && a.token == token)
        else {
            return EINVAL;
        };
        if entry.write == to_request || len == 0 || range.end > entry.len {
            return EINVAL;
        }
        if entry.copying {
            return EBUSY;
        }
        entry.copying = true;
        (entry.buf + req_off, entry.write)
    };
    let rc = if write {
        // SAFETY: `buf..buf+len` lies inside the caller's buffer for this
        // request (checked above). The caller is blocked inside the request
        // callback for as long as the entry exists, and `copying` excludes
        // a second concurrent copy, so this is the only access.
        let src = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
        match endpoint {
            Endpoint::Dma { handle, offset } => {
                narf_bus::module_dma_write(owner, token, handle, offset, src)
            }
            Endpoint::Module(dst) => {
                // SAFETY: the export's caller promises `len` writable bytes
                // of module memory at `dst`, disjoint from kernel buffers.
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst as *mut u8, len) };
                0
            }
        }
    } else {
        // SAFETY: as above; a read request's buffer is the caller's `&mut`.
        let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
        match endpoint {
            Endpoint::Dma { handle, offset } => {
                narf_bus::module_dma_read(owner, token, handle, offset, dst)
            }
            Endpoint::Module(src) => {
                // SAFETY: the export's caller promises `len` readable bytes of
                // module memory at `src`.
                unsafe { core::ptr::copy_nonoverlapping(src as *const u8, dst.as_mut_ptr(), len) };
                0
            }
        }
    };
    if let Some(entry) = ACTIVE.lock().iter_mut().find(|a| a.id == request) {
        entry.copying = false;
    }
    rc
}

/// Fail new requests on every disk `owner` registered, wait out a running
/// one, and unregister them. Called on unload before the bus context goes.
pub fn retire_owner(owner: u64) {
    retire_where(|d| d.owner == owner, "unload");
}

/// Retire the disks registered for one device context: the bus reports
/// every retired PCI or USB context here (unplug, reprobe, declined probe).
pub fn retire_token(owner: u64, token: u64) {
    retire_where(|d| d.owner == owner && d.token == token, "device removal");
}

fn retire_where(matches: impl Fn(&Disk) -> bool, why: &str) {
    let retired: Vec<Arc<Disk>> = {
        let mut disks = DISKS.lock();
        let mut retired = Vec::new();
        disks.retain(|d| {
            if matches(d) {
                retired.push(Arc::clone(d));
                false
            } else {
                true
            }
        });
        retired
    };
    for disk in &retired {
        disk.alive.store(false, Ordering::Release);
    }
    for disk in &retired {
        let idle = narf_scheduler::responsive_spin_until(
            || !disk.busy.load(Ordering::Acquire),
            narf_time::Deadline::after_ns(RETIRE_WAIT_NS),
        );
        if !idle {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  modules: {} still has a block request running at {why}",
                disk.name
            );
        }
        narf_block::unregister_block_device(disk.name);
    }
}

fn errno_to_io(rc: i32) -> BlockIoError {
    match rc {
        ENODEV => BlockIoError::DeviceRemoved,
        EROFS => BlockIoError::ReadOnly,
        _ => BlockIoError::DriverError,
    }
}

struct ModuleDisk(Arc<Disk>);

impl core::fmt::Debug for ModuleDisk {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModuleDisk")
            .field("name", &self.0.name)
            .field("owner", &self.0.owner)
            .finish()
    }
}

impl ModuleDisk {
    /// Run one request (at most `max_blocks`) through the module.
    fn submit(
        &self,
        op: u32,
        lba: u64,
        count: u32,
        buf: usize,
        len: usize,
    ) -> Result<(), BlockIoError> {
        let disk = &self.0;
        if !disk.alive.load(Ordering::Acquire) {
            return Err(BlockIoError::DeviceRemoved);
        }
        // A request issued from inside this module's own context (disk policy
        // reading the disk while the probe registers it) is already pinned and
        // in the module's domain, so it skips the gate. It still takes the
        // per-disk slot: no export a request callback can reach reads a disk,
        // so the slot is never held by the same call chain.
        let nested = crate::symbols::current_execution_id().0 == disk.owner;
        while disk
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        if !disk.alive.load(Ordering::Acquire) {
            disk.busy.store(false, Ordering::Release);
            return Err(BlockIoError::DeviceRemoved);
        }
        let id = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
        ACTIVE.lock().push(Active {
            id,
            owner: disk.owner,
            token: disk.token,
            write: op == OP_WRITE,
            buf,
            len,
            copying: false,
        });
        let (request, cookie) = (disk.request, disk.cookie);
        let rc = if nested {
            request(cookie, id, op, lba, count)
        } else {
            crate::call_in_module_context(disk.owner, || request(cookie, id, op, lba, count))
        };
        ACTIVE.lock().retain(|a| a.id != id);
        disk.busy.store(false, Ordering::Release);
        if rc == 0 {
            Ok(())
        } else {
            Err(errno_to_io(rc))
        }
    }

    fn transfer(
        &self,
        op: u32,
        lba: u64,
        n_blocks: u16,
        buf: usize,
        buf_len: usize,
    ) -> Result<(), BlockIoError> {
        let disk = &self.0;
        let n = u64::from(n_blocks);
        if n == 0 {
            return Ok(());
        }
        if lba.checked_add(n).is_none_or(|end| end > disk.capacity) {
            return Err(BlockIoError::OutOfRange);
        }
        let block = disk.lba_size as usize;
        if buf_len < n as usize * block {
            return Err(BlockIoError::BufferTooSmall);
        }
        let mut done = 0u64;
        while done < n {
            let count = (n - done).min(u64::from(disk.max_blocks));
            let off = done as usize * block;
            self.submit(
                op,
                lba + done,
                count as u32,
                buf + off,
                count as usize * block,
            )?;
            done += count;
        }
        Ok(())
    }
}

impl BlockDeviceSync for ModuleDisk {
    fn lba_size(&self) -> u32 {
        self.0.lba_size
    }

    fn capacity(&self) -> u64 {
        self.0.capacity
    }

    fn read(&self, lba: u64, n_blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
        self.transfer(OP_READ, lba, n_blocks, out.as_mut_ptr() as usize, out.len())
    }

    fn write(&self, lba: u64, n_blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
        if self.0.flags & FLAG_READ_ONLY != 0 {
            return Err(BlockIoError::ReadOnly);
        }
        self.transfer(OP_WRITE, lba, n_blocks, data.as_ptr() as usize, data.len())
    }

    fn is_read_only(&self) -> bool {
        self.0.flags & FLAG_READ_ONLY != 0
    }

    fn flush(&self) -> Result<(), BlockIoError> {
        if self.0.flags & FLAG_VOLATILE_CACHE == 0 {
            return Ok(());
        }
        self.submit(OP_FLUSH, 0, 0, 0, 0)
    }

    fn has_real_flush(&self) -> bool {
        self.0.flags & FLAG_VOLATILE_CACHE != 0
    }

    fn capabilities(&self) -> BlockCaps {
        BlockCaps {
            volatile_cache: self.0.flags & FLAG_VOLATILE_CACHE != 0,
            fua: false,
        }
    }
}

/// Disks `owner` has registered (test introspection).
pub fn __disk_count_for_test(owner: u64) -> usize {
    DISKS.lock().iter().filter(|d| d.owner == owner).count()
}

#[doc(hidden)]
#[path = "module_block_tests.rs"]
mod tests;
