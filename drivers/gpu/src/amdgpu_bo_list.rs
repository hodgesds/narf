//! `DRM_IOCTL_AMDGPU_BO_LIST` — `amdgpu_bo_list.c`.
//!
//! A BO list names the buffers a submission touches, created ahead of the
//! submission and passed as `drm_amdgpu_cs.in.bo_list_handle` — the pre-
//! `AMDGPU_CHUNK_ID_BO_HANDLES` interface (libdrm `amdgpu_bo_list_create`,
//! still exported). Mesa 26.2.4 sends the BO_HANDLES chunk instead; both
//! reach the same list here.
//!
//! A list holds its own reference to each buffer (`amdgpu_bo_ref`), so
//! closing a handle after listing it keeps the buffer alive for the list.
//! Entries are kept in priority order (`amdgpu_bo_list_entry_cmp`, a stable
//! sort on `min(priority, 32)`); with no eviction here the order only fixes
//! the order a submission visits its buffers.
//!
//! LINUX-GAP: userptr placement and GDS/GWS/OA resources are not part of a
//! list (neither buffer kind exists on this path).
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_gem::{GemObject, GemState};
use crate::amdgpu_uapi as uapi;
use crate::drm_ioctl_bridge::{copy_in, copy_out};
use crate::drm_uapi;

/// `AMDGPU_BO_LIST_MAX_PRIORITY`.
const MAX_PRIORITY: u32 = 32;
/// `AMDGPU_BO_LIST_MAX_ENTRIES`.
pub const MAX_ENTRIES: u32 = 128 * 1024;
/// `sizeof(struct drm_amdgpu_bo_list_entry)`: { bo_handle, bo_priority }.
const ENTRY_SIZE: u32 = 8;

/// One validated list: its buffers in priority order.
pub type BoList = Arc<Vec<Arc<GemObject>>>;

/// `amdgpu_bo_create_list_entry_array`: `bo_number` entries of
/// `bo_info_size` bytes each at `ptr`, each read as its first
/// `min(bo_info_size, 8)` bytes zero-extended. More than 128 Ki entries is
/// EINVAL; an unreadable entry EFAULT.
pub fn read_entries(
    bo_number: u32,
    bo_info_size: u32,
    ptr: u64,
) -> Result<Vec<(u32, u32)>, FsError> {
    if bo_number > MAX_ENTRIES {
        return Err(FsError::InvalidData);
    }
    let mut out = Vec::new();
    if bo_number == 0 {
        return Ok(out);
    }
    let parse = |e: &[u8]| {
        let mut full = [0u8; 8];
        full[..e.len()].copy_from_slice(e);
        (
            u32::from_le_bytes(full[0..4].try_into().unwrap()),
            u32::from_le_bytes(full[4..8].try_into().unwrap()),
        )
    };
    if bo_info_size == ENTRY_SIZE {
        // SAFETY: `ptr` is the caller's entry array; copy_in bounds the
        // length (at most 1 MiB here) and SMAP-brackets the read.
        let raw = unsafe { copy_in(ptr as usize, bo_number as usize * 8)? };
        out.extend(raw.chunks_exact(8).map(parse));
        return Ok(out);
    }
    let bytes = bo_info_size.min(ENTRY_SIZE) as usize;
    for i in 0..bo_number as u64 {
        let at = ptr.wrapping_add(i * u64::from(bo_info_size));
        let entry = if bytes == 0 {
            Vec::new()
        } else {
            // SAFETY: as above, one entry's leading bytes.
            unsafe { copy_in(at as usize, bytes)? }
        };
        out.push(parse(&entry));
    }
    Ok(out)
}

/// `amdgpu_bo_list_create`: every handle is one `gem` holds (ENOENT), in
/// priority order.
pub fn create(gem: &GemState, entries: &[(u32, u32)]) -> Result<BoList, FsError> {
    let mut list: Vec<(u32, Arc<GemObject>)> = Vec::with_capacity(entries.len());
    for &(handle, priority) in entries {
        let object = gem.lookup(handle).ok_or(FsError::NotFound)?;
        list.push((priority.min(MAX_PRIORITY), object));
    }
    list.sort_by_key(|(p, _)| *p);
    Ok(Arc::new(list.into_iter().map(|(_, o)| o).collect()))
}

/// Per-open BO lists (`fpriv->bo_list_handles`, an IDR from 1).
#[derive(Debug)]
pub struct BoListTable {
    lists: IrqSafeSpinLock<Vec<(u32, BoList)>>,
}

impl Default for BoListTable {
    fn default() -> Self {
        Self::new()
    }
}

impl BoListTable {
    pub const fn new() -> Self {
        BoListTable {
            lists: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    /// `amdgpu_bo_list_get` (ENOENT for an unknown handle).
    pub fn get(&self, handle: u32) -> Result<BoList, FsError> {
        self.lists
            .lock()
            .iter()
            .find(|(h, _)| *h == handle)
            .map(|(_, l)| l.clone())
            .ok_or(FsError::NotFound)
    }

    /// `idr_alloc(.., 1, 0)`: the lowest free handle from 1.
    fn insert(&self, list: BoList) -> u32 {
        let mut lists = self.lists.lock();
        let mut handle = 1;
        while lists.iter().any(|(h, _)| *h == handle) {
            handle += 1;
        }
        lists.push((handle, list));
        handle
    }

    /// `idr_replace`: ENOENT when `handle` names no list.
    fn replace(&self, handle: u32, list: BoList) -> Result<(), FsError> {
        let old = {
            let mut lists = self.lists.lock();
            let slot = lists
                .iter_mut()
                .find(|(h, _)| *h == handle)
                .ok_or(FsError::NotFound)?;
            core::mem::replace(&mut slot.1, list)
        };
        drop(old);
        Ok(())
    }

    /// `amdgpu_bo_list_destroy`: removing an unknown handle is not an error.
    fn remove(&self, handle: u32) {
        let old = {
            let mut lists = self.lists.lock();
            lists
                .iter()
                .position(|(h, _)| *h == handle)
                .map(|i| lists.swap_remove(i))
        };
        drop(old);
    }

    /// Live lists.
    pub fn len(&self) -> usize {
        self.lists.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// `amdgpu_bo_list_ioctl` for one open; `Unsupported` for any other ioctl.
///
/// `union drm_amdgpu_bo_list`: in { operation, list_handle, bo_number,
/// bo_info_size, bo_info_ptr } (24 bytes); out { list_handle }, with the
/// whole union cleared first.
pub fn dispatch(cmd: u32, arg: usize, table: &BoListTable, gem: &GemState) -> Result<u64, FsError> {
    if drm_uapi::ioc_nr(cmd) != drm_uapi::DRM_COMMAND_BASE + uapi::DRM_AMDGPU_BO_LIST {
        return Err(FsError::Unsupported);
    }
    // SAFETY: `arg` is the ioctl struct pointer; 24 bytes.
    let b = unsafe { copy_in(arg, 24)? };
    let word = |at: usize| u32::from_le_bytes(b[at..at + 4].try_into().unwrap());
    let (operation, mut handle) = (word(0), word(4));
    let ptr = u64::from_le_bytes(b[16..24].try_into().unwrap());
    // The entry array is read before the operation is examined, even for
    // DESTROY, as Linux does.
    let entries = read_entries(word(8), word(12), ptr)?;
    match operation {
        uapi::AMDGPU_BO_LIST_OP_CREATE => handle = table.insert(create(gem, &entries)?),
        uapi::AMDGPU_BO_LIST_OP_DESTROY => {
            table.remove(handle);
            handle = 0;
        }
        uapi::AMDGPU_BO_LIST_OP_UPDATE => table.replace(handle, create(gem, &entries)?)?,
        _ => return Err(FsError::InvalidData),
    }
    let mut out = [0u8; 24];
    out[0..4].copy_from_slice(&handle.to_le_bytes());
    // SAFETY: as above.
    unsafe { copy_out(arg, &out)? };
    Ok(0)
}
