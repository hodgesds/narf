//! Decompression workspaces (Linux `fs/btrfs/compression.c`
//! `btrfs_get_workspace` / `btrfs_put_workspace`).
//!
//! A zstd frame decoder and a zlib inflater are each several KiB of state. Built
//! on the stack for every compressed extent read, they gave `decompress` a
//! 19 KiB frame on every compressed read — from task stacks. Linux keeps such
//! state in per-algorithm workspace lists, allocated on demand and kept up to
//! one per online CPU; this is the same: a workspace is taken from the list (or
//! allocated, off the hot path, when the list is empty), used, and returned —
//! dropped instead when the list already holds one per CPU.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};

use narf_lib::sync::IrqSafeSpinLock;

/// One algorithm's idle workspaces.
pub(crate) struct Pool<T: 'static> {
    idle: IrqSafeSpinLock<Vec<Box<T>>>,
    make: fn() -> Box<T>,
}

impl<T: 'static> Pool<T> {
    pub(crate) const fn new(make: fn() -> Box<T>) -> Self {
        Self {
            idle: IrqSafeSpinLock::new(Vec::new()),
            make,
        }
    }

    /// A workspace for this caller's exclusive use until the guard drops.
    pub(crate) fn get(&'static self) -> Workspace<T> {
        let idle = self.idle.lock().pop();
        Workspace {
            pool: self,
            ws: Some(idle.unwrap_or_else(self.make)),
        }
    }

    /// Keep `ws` for the next caller, up to one per online CPU. The list's
    /// storage is only ever grown outside the lock, so the IRQ-masked section
    /// never allocates.
    fn put(&self, ws: Box<T>) {
        let keep = narf_lib::smp::online_bitmap().count_ones().max(1) as usize;
        {
            let mut idle = self.idle.lock();
            if idle.len() >= keep {
                drop(idle);
                drop(ws);
                return;
            }
            if idle.len() < idle.capacity() {
                idle.push(ws);
                return;
            }
        }
        let mut grown: Vec<Box<T>> = Vec::with_capacity(keep);
        let mut idle = self.idle.lock();
        if grown.capacity() > idle.capacity() {
            grown.append(&mut idle);
            core::mem::swap(&mut *idle, &mut grown);
        }
        let ws = if idle.len() < idle.capacity() {
            idle.push(ws);
            None
        } else {
            Some(ws)
        };
        drop(idle);
        drop((grown, ws));
    }
}

/// A workspace on loan from its [`Pool`]; returned on drop.
pub(crate) struct Workspace<T: 'static> {
    pool: &'static Pool<T>,
    ws: Option<Box<T>>,
}

impl<T> Deref for Workspace<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.ws.as_deref().expect("workspace present until drop")
    }
}

impl<T> DerefMut for Workspace<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.ws
            .as_deref_mut()
            .expect("workspace present until drop")
    }
}

impl<T> Drop for Workspace<T> {
    fn drop(&mut self) {
        if let Some(ws) = self.ws.take() {
            self.pool.put(ws);
        }
    }
}

/// Idle zstd frame decoders.
pub(crate) static ZSTD: Pool<ruzstd::decoding::FrameDecoder> = Pool::new(new_zstd);
/// Idle zlib inflaters.
pub(crate) static ZLIB: Pool<miniz_oxide::inflate::core::DecompressorOxide> = Pool::new(new_zlib);

// Allocation is out of line and cold: the decoder state is built once per
// workspace, not per read, so its stack temporary costs a frame only here.
#[cold]
#[inline(never)]
fn new_zstd() -> Box<ruzstd::decoding::FrameDecoder> {
    Box::new(ruzstd::decoding::FrameDecoder::new())
}

#[cold]
#[inline(never)]
fn new_zlib() -> Box<miniz_oxide::inflate::core::DecompressorOxide> {
    Box::default()
}
