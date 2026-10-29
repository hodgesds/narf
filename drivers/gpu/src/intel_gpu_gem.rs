//! Per-open Intel GEM storage. Host pages are owned by the object, not its
//! handle: CPU mappings, VM bindings and submitted jobs retain the same Arc.
//! Xe-LP and Xe-LPG integrated GPUs both use system-memory objects here.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use narf_filesystem::{FsError, MmapBacking};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::frame::{alloc_frame, free_frame, PhysFrame};

const PAGE: u64 = 4096;
const HANDLE_BASE: u32 = 0x4000_0000;
const MMAP_BASE: u64 = 0x1000_0000_0000;
const MAX_OBJECTS: usize = 4096;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static NEXT_MMAP: AtomicU64 = AtomicU64::new(MMAP_BASE);

#[derive(Debug)]
pub struct GemObject {
    frames: Vec<PhysFrame>,
    size: u64,
    offset: u64,
    /// Serializes kernel CPU copies; never forms references to mapped data.
    cpu: IrqSafeSpinLock<()>,
}

impl GemObject {
    fn allocate(size: u64, offset: u64) -> Result<Self, FsError> {
        // Charge the allocation's lifetime, including after GEM_CLOSE while a
        // VMA/VM/job still owns it. Closing handles cannot bypass this bound.
        let limit = ((narf_memory::frame::stats().total as u64 * PAGE) / 2).min(512 * 1024 * 1024);
        LIVE_BYTES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                live.checked_add(size).filter(|next| *next <= limit)
            })
            .map_err(|_| FsError::OutOfMemory)?;
        let mut object = Self {
            frames: Vec::new(),
            size,
            offset,
            cpu: IrqSafeSpinLock::new(()),
        };
        object
            .frames
            .try_reserve_exact((size / PAGE) as usize)
            .map_err(|_| FsError::OutOfMemory)?;
        for _ in 0..size / PAGE {
            let frame = alloc_frame().map_err(|_| FsError::OutOfMemory)?;
            // SAFETY: newly allocated private frame, not published until zeroed.
            unsafe {
                core::ptr::write_bytes(
                    frame.start_address().kernel_mut_ptr::<u8>(),
                    0,
                    PAGE as usize,
                )
            };
            object.frames.push(frame);
        }
        Ok(object)
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn pages(&self) -> impl Iterator<Item = u64> + '_ {
        self.frames.iter().map(|frame| frame.start_address().raw())
    }

    pub(crate) fn publish_for_device(&self) -> bool {
        crate::intel_gpu_gtt::publish_system_pages(self.frames.iter())
    }

    pub fn range(&self, offset: u64, len: usize) -> Result<(), FsError> {
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > self.size)
        {
            return Err(FsError::InvalidData);
        }
        Ok(())
    }

    /// Relative mapping used by PRIME exports as well as GEM mmap offsets.
    pub fn backing(self: &Arc<Self>, offset: u64, len: usize) -> Result<MmapBacking, FsError> {
        if len == 0 || offset % PAGE != 0 {
            return Err(FsError::InvalidData);
        }
        self.range(offset, len)?;
        let frames = self
            .pages()
            .skip((offset / PAGE) as usize)
            .take(len.div_ceil(PAGE as usize))
            .collect();
        Ok(MmapBacking {
            frames,
            lifetime: Some(self.clone()),
            memory_type: narf_memory::MemoryType::WriteBack,
        })
    }

    pub fn read(&self, offset: u64, bytes: &mut [u8]) -> Result<(), FsError> {
        self.range(offset, bytes.len())?;
        let _guard = self.cpu.lock();
        for (i, byte) in bytes.iter_mut().enumerate() {
            let at = offset + i as u64;
            let base = self.frames[(at / PAGE) as usize]
                .start_address()
                .kernel_ptr::<u8>();
            // SAFETY: range checked; raw volatile access also tolerates concurrent
            // device/user mappings without creating aliased Rust references.
            *byte = unsafe { core::ptr::read_volatile(base.add((at % PAGE) as usize)) };
        }
        Ok(())
    }

    pub fn write(&self, offset: u64, bytes: &[u8]) -> Result<(), FsError> {
        self.range(offset, bytes.len())?;
        let _guard = self.cpu.lock();
        for (i, byte) in bytes.iter().enumerate() {
            let at = offset + i as u64;
            let base = self.frames[(at / PAGE) as usize]
                .start_address()
                .kernel_mut_ptr::<u8>();
            // SAFETY: same owned, range-checked pages as read().
            unsafe { core::ptr::write_volatile(base.add((at % PAGE) as usize), *byte) };
        }
        Ok(())
    }
}

impl Drop for GemObject {
    fn drop(&mut self) {
        for frame in self.frames.drain(..) {
            free_frame(frame);
        }
        LIVE_BYTES.fetch_sub(self.size, Ordering::AcqRel);
    }
}

#[derive(Debug)]
struct Handles {
    next: u32,
    bytes: u64,
    objects: BTreeMap<u32, Arc<GemObject>>,
}

#[derive(Debug)]
pub struct GemState {
    handles: IrqSafeSpinLock<Handles>,
}

impl Default for GemState {
    fn default() -> Self {
        Self::new()
    }
}

impl GemState {
    pub const fn new() -> Self {
        Self {
            handles: IrqSafeSpinLock::new(Handles {
                next: HANDLE_BASE,
                bytes: 0,
                objects: BTreeMap::new(),
            }),
        }
    }

    /// Report before publishing. EFAULT consumes neither a handle nor pages.
    pub fn create(
        &self,
        size: u64,
        report: impl FnOnce(u32, u64) -> Result<(), FsError>,
    ) -> Result<u32, FsError> {
        let size = size.checked_add(PAGE - 1).ok_or(FsError::InvalidData)? & !(PAGE - 1);
        if size == 0 || size > MAX_FILE_BYTES {
            return Err(FsError::InvalidData);
        }
        let mut handles = self.handles.lock();
        if handles.objects.len() >= MAX_OBJECTS || handles.bytes + size > MAX_FILE_BYTES {
            return Err(FsError::OutOfMemory);
        }
        let next = handles.next.checked_add(1).ok_or(FsError::OutOfMemory)?;
        // Global uniqueness lets imported objects keep one stable mmap
        // offset without colliding with this open's pre-existing objects.
        let offset = NEXT_MMAP
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |offset| {
                offset
                    .checked_add(size + PAGE)
                    .filter(|next| *next < 1 << 63)
            })
            .map_err(|_| FsError::OutOfMemory)?;
        let object = Arc::new(GemObject::allocate(size, offset)?);
        let handle = handles.next;
        report(handle, size)?;
        handles.objects.insert(handle, object);
        handles.next = next;
        handles.bytes += size;
        Ok(handle)
    }

    pub fn object(&self, handle: u32) -> Result<Arc<GemObject>, FsError> {
        self.handles
            .lock()
            .objects
            .get(&handle)
            .cloned()
            .ok_or(FsError::NotFound)
    }

    /// Same-card PRIME import. Reimporting the same object on an open returns
    /// its existing handle. The object retains its own allocation/accounting.
    pub fn import(&self, object: &Arc<GemObject>) -> Result<u32, FsError> {
        let mut handles = self.handles.lock();
        if let Some((handle, _)) = handles
            .objects
            .iter()
            .find(|(_, entry)| Arc::ptr_eq(entry, object))
        {
            return Ok(*handle);
        }
        if handles.objects.len() >= MAX_OBJECTS || handles.bytes + object.size > MAX_FILE_BYTES {
            return Err(FsError::OutOfMemory);
        }
        let handle = handles.next;
        handles.next = handle.checked_add(1).ok_or(FsError::OutOfMemory)?;
        handles.objects.insert(handle, object.clone());
        handles.bytes += object.size;
        Ok(handle)
    }

    pub fn close(&self, handle: u32) -> Result<(), FsError> {
        let mut handles = self.handles.lock();
        let object = handles.objects.remove(&handle).ok_or(FsError::NotFound)?;
        handles.bytes -= object.size;
        // Other owners (VMA, VM, jobs) retain this backing independently.
        drop(handles);
        drop(object);
        Ok(())
    }

    pub fn mmap_offset(&self, handle: u32) -> Result<u64, FsError> {
        Ok(self.object(handle)?.offset)
    }

    pub fn mapping_object(
        &self,
        offset: u64,
        len: usize,
    ) -> Result<(Arc<GemObject>, u64), FsError> {
        if len == 0 || offset % PAGE != 0 {
            return Err(FsError::InvalidData);
        }
        let handles = self.handles.lock();
        let object = handles
            .objects
            .values()
            .find(|object| offset >= object.offset && offset < object.offset + object.size)
            .cloned()
            .ok_or(FsError::NotFound)?;
        let within = offset - object.offset;
        object.range(within, len)?;
        Ok((object, within))
    }

    pub fn mmap_backing(&self, offset: u64, len: usize) -> Result<MmapBacking, FsError> {
        let (object, within) = self.mapping_object(offset, len)?;
        object.backing(within, len)
    }
}
