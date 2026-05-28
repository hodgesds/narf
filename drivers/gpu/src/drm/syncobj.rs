//! Syncobj — stub, expanded in a follow-up commit.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyncError { NotFound, Timeout, Full }

pub trait DmaFence: Send + Sync + core::fmt::Debug {
    fn is_signalled(&self) -> bool;
    fn wait(&self, timeout_ns: u64) -> bool;
    fn signal(&self);
}

#[derive(Debug)]
pub struct BinaryFence { signalled: AtomicBool }

impl BinaryFence {
    pub fn new() -> Arc<Self> { Arc::new(BinaryFence { signalled: AtomicBool::new(false) }) }
    pub fn signalled() -> Arc<Self> { Arc::new(BinaryFence { signalled: AtomicBool::new(true) }) }
}

impl DmaFence for BinaryFence {
    fn is_signalled(&self) -> bool { self.signalled.load(Ordering::Acquire) }
    fn wait(&self, _timeout_ns: u64) -> bool { self.is_signalled() }
    fn signal(&self) { self.signalled.store(true, Ordering::Release); }
}

#[derive(Debug)]
pub struct SyncObj { pub id: u32, pub fence: Option<Arc<dyn DmaFence>> }

#[derive(Debug, Default)]
pub struct SyncObjTable { objs: Vec<SyncObj>, next: u32 }

impl SyncObjTable { pub fn new() -> Self { SyncObjTable { objs: Vec::new(), next: 1 } } }
