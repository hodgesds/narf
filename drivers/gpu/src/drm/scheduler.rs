//! GPU scheduler — stub, expanded in a follow-up commit.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};
use super::syncobj::DmaFence;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SchedError { NoContext, NotRunnable }

pub trait JobPayload: Send + core::fmt::Debug {
    fn execute(&mut self);
}

#[derive(Debug)]
pub struct JobFence { signalled: AtomicBool }
impl JobFence {
    pub fn pending() -> Arc<Self> { Arc::new(JobFence { signalled: AtomicBool::new(false) }) }
}
impl DmaFence for JobFence {
    fn is_signalled(&self) -> bool { self.signalled.load(Ordering::Acquire) }
    fn wait(&self, _timeout_ns: u64) -> bool { self.is_signalled() }
    fn signal(&self) { self.signalled.store(true, Ordering::Release); }
}

#[derive(Debug)]
pub struct Job {
    pub deps_in: Vec<Arc<dyn DmaFence>>,
    pub fence_out: Arc<JobFence>,
    pub payload: Box<dyn JobPayload>,
}

#[derive(Debug)]
pub struct SchedContext { pub id: u32, pub priority: u8, pub jobs: VecDeque<Job> }

#[derive(Debug, Default)]
pub struct Sched { pub contexts: Vec<SchedContext>, next_ctx_id: u32 }
impl Sched { pub fn new() -> Self { Sched { contexts: Vec::new(), next_ctx_id: 1 } } }
