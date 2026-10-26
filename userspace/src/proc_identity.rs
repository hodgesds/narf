//! Task-owned procfs identity, with immutable inherited image snapshots.
//!
//! The directory binds early loader/kernel-task publications to the same owner
//! later retained by `Task`. Registered tasks use that owner directly; clone
//! copies a fixed-size snapshot of references, never the argv/environment or
//! mapping paths. No identity lock nests another identity lock.

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone, Debug)]
pub(crate) struct ImageMapping {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub device: u64,
    pub inode: u64,
    pub pathname: String,
}

/// Preserve the existing fifteen-Unicode-character name limit without a heap
/// allocation. A Unicode scalar occupies at most four UTF-8 bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Comm {
    bytes: [u8; 60],
    len: usize,
}

impl Comm {
    pub fn new(name: &str) -> Self {
        let mut comm = Self {
            bytes: [0; 60],
            len: 0,
        };
        for ch in name.chars().take(15) {
            comm.len += ch.encode_utf8(&mut comm.bytes[comm.len..]).len();
        }
        comm
    }

    pub fn as_str(&self) -> &str {
        // Only complete UTF-8 scalars are appended by `new`.
        core::str::from_utf8(&self.bytes[..self.len]).expect("comm is UTF-8")
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Snapshot {
    pub comm: Option<Comm>,
    pub exe: Option<Arc<String>>,
    pub argv: Option<Arc<Vec<u8>>>,
    pub environ: Option<Arc<Vec<u8>>>,
    pub auxv: Option<Arc<Vec<u8>>>,
    pub mappings: Option<Arc<Vec<ImageMapping>>>,
}

pub(crate) struct Identity {
    state: IrqSafeSpinLock<Snapshot>,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity").finish_non_exhaustive()
    }
}

const SHARDS: usize = 32;
static OWNERS: [IrqSafeSpinLock<BTreeMap<u64, Arc<Identity>>>; SHARDS] =
    [const { IrqSafeSpinLock::new(BTreeMap::new()) }; SHARDS];

fn shard(tid: u64) -> usize {
    tid as usize & (SHARDS - 1)
}

/// Bind before publishing a Task. A concurrent early writer uses this same
/// directory operation, so no write can be lost during registration.
pub(crate) fn owner(tid: u64) -> Arc<Identity> {
    if let Some(owner) = OWNERS[shard(tid)].lock().get(&tid).cloned() {
        return owner;
    }
    let candidate = Arc::new(Identity {
        state: IrqSafeSpinLock::new(Snapshot::default()),
    });
    let mut owners = OWNERS[shard(tid)].lock();
    let owner = owners
        .entry(tid)
        .or_insert_with(|| candidate.clone())
        .clone();
    drop(owners);
    // A losing allocation, or the inserter's temporary reference, is dropped
    // after the directory lock.
    drop(candidate);
    owner
}

pub(crate) fn read<R>(tid: u64, read: impl FnOnce(&Snapshot) -> R) -> Option<R> {
    let mut read = Some(read);
    if let Some(value) = crate::task::with_task_local(tid, |task| {
        read.take().expect("one identity read")(&task.proc_identity.state.lock())
    }) {
        return Some(value);
    }
    let owner = OWNERS[shard(tid)].lock().get(&tid).cloned()?;
    let value = read.take().expect("unused identity read")(&owner.state.lock());
    Some(value)
}

pub(crate) fn update<R>(tid: u64, update: impl FnOnce(&mut Snapshot) -> R) -> R {
    let mut update = Some(update);
    if let Some(value) = crate::task::with_task_local(tid, |task| {
        update.take().expect("one identity update")(&mut task.proc_identity.state.lock())
    }) {
        return value;
    }
    let owner = owner(tid);
    let value = update.take().expect("unused identity update")(&mut owner.state.lock());
    value
}

/// Timer diagnostics borrow through both nonblocking guards, never cloning an
/// owner whose final drop could otherwise occur in IRQ context.
pub(crate) fn try_read<R>(tid: u64, read: impl FnOnce(&Snapshot) -> R) -> Option<R> {
    let owners = OWNERS[shard(tid)].try_lock()?;
    let owner = owners.get(&tid)?;
    let state = owner.state.try_lock()?;
    Some(read(&state))
}

pub(crate) fn inherit(parent: u64, child: u64) {
    let Some(inherited) = read(parent, Clone::clone) else {
        return;
    };
    let retired = update(child, |state| core::mem::replace(state, inherited));
    drop(retired);
}

pub(crate) fn clear(tid: u64) {
    // Unlike an update, cleanup must not create a missing owner.
    let retired = read_owner(tid, |owner| core::mem::take(&mut *owner.state.lock()));
    drop(retired);
    // Early loader/test rows have no Task to retire their directory binding.
    // Real task teardown retains the binding until `release_task`.
    if crate::task::task_get(tid).is_none() {
        let retired = OWNERS[shard(tid)].lock().remove(&tid);
        drop(retired);
    }
}

fn read_owner<R>(tid: u64, read: impl Fn(&Identity) -> R) -> Option<R> {
    if let Some(value) = crate::task::with_task_local(tid, |task| read(&task.proc_identity)) {
        return Some(value);
    }
    let owner = OWNERS[shard(tid)].lock().get(&tid).cloned()?;
    Some(read(&owner))
}

/// The removed registry reference is dropped after unlocking. Task still owns
/// this identity, and any already retained snapshot remains independently live.
pub(crate) fn retire(tid: u64, expected: &Arc<Identity>) {
    let retired = {
        let mut owners = OWNERS[shard(tid)].lock();
        if owners
            .get(&tid)
            .is_some_and(|owner| Arc::ptr_eq(owner, expected))
        {
            owners.remove(&tid)
        } else {
            None
        }
    };
    drop(retired);
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::abi_test_support::*;

    const PARENT: u64 = 0xd510_0001;
    const CHILD: u64 = 0xd510_0002;

    struct Cleanup;
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for tid in [PARENT, CHILD] {
                clear(tid);
                crate::task::release_task(tid);
            }
        }
    }

    fn smoke_proc_identity_shares_and_replaces_snapshots() -> TestResult {
        with_setup(|| {
            let _cleanup = Cleanup;
            let _parent = crate::task::Task::new_registered(PARENT, PARENT);
            let _child = crate::task::Task::new_registered(CHILD, CHILD);
            let bytes = Arc::new(alloc::vec![0x5a; 64 * 1024]);
            let exe = Arc::new(String::from("/bin/parent"));
            let mappings = Arc::new(alloc::vec![ImageMapping {
                start: 0x1000,
                end: 0x2000,
                file_offset: 0,
                device: 1,
                inode: 2,
                pathname: String::from("/bin/parent"),
            }]);
            update(PARENT, |state| {
                state.comm = Some(Comm::new("parent"));
                state.argv = Some(bytes.clone());
                state.environ = Some(bytes.clone());
                state.auxv = Some(bytes.clone());
                state.exe = Some(exe.clone());
                state.mappings = Some(mappings.clone());
            });
            inherit(PARENT, CHILD);
            let inherited = read(CHILD, Clone::clone).ok_or("child identity missing")?;
            for blob in [&inherited.argv, &inherited.environ, &inherited.auxv] {
                if !blob
                    .as_ref()
                    .is_some_and(|value| Arc::ptr_eq(value, &bytes))
                {
                    return Err("clone copied immutable bytes instead of sharing them");
                }
            }
            if !Arc::ptr_eq(inherited.exe.as_ref().ok_or("exe missing")?, &exe)
                || !Arc::ptr_eq(
                    inherited.mappings.as_ref().ok_or("maps missing")?,
                    &mappings,
                )
            {
                return Err("clone copied image provenance instead of sharing it");
            }
            crate::handlers::set_proc_argv_packed(CHILD, alloc::vec![1, 2, 0]);
            crate::handlers::set_proc_comm(CHILD, "child");
            if read(PARENT, |state| {
                state.comm.map(|comm| comm.as_str() == "parent")
            }) != Some(Some(true))
            {
                return Err("child rename changed parent comm");
            }
            if !read(PARENT, |state| {
                state
                    .argv
                    .as_ref()
                    .is_some_and(|value| Arc::ptr_eq(value, &bytes))
            })
            .unwrap_or(false)
            {
                return Err("child argv replacement changed parent snapshot");
            }
            if inherited.argv.as_ref().unwrap().as_slice() != bytes.as_slice() {
                return Err("retained pre-replacement snapshot changed");
            }
            clear(PARENT);
            if read(CHILD, |state| {
                state.comm.map(|comm| comm.as_str() == "child")
            }) != Some(Some(true))
            {
                return Err("parent cleanup cleared child identity");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "syscall_abi/proc_identity",
        smoke_proc_identity_shares_and_replaces_snapshots
    );

    fn smoke_proc_identity_clear_releases_bytes_before_task_drop() -> TestResult {
        with_setup(|| {
            let _cleanup = Cleanup;
            let parent = crate::task::Task::new_registered(PARENT, PARENT);
            let child = crate::task::Task::new_registered(CHILD, CHILD);
            let bytes = Arc::new(alloc::vec![7; 4096]);
            let weak = Arc::downgrade(&bytes);
            update(PARENT, |state| state.argv = Some(bytes));
            inherit(PARENT, CHILD);
            clear(PARENT);
            if weak.upgrade().is_none() {
                return Err("parent exit freed bytes still retained by child");
            }
            clear(CHILD);
            if weak.upgrade().is_some() {
                return Err("empty task identities retained exited image bytes");
            }
            if !Arc::ptr_eq(&owner(PARENT), &parent.proc_identity)
                || !Arc::ptr_eq(&owner(CHILD), &child.proc_identity)
            {
                return Err("cleanup detached a still-registered task binding");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "syscall_abi/proc_identity",
        smoke_proc_identity_clear_releases_bytes_before_task_drop
    );

    fn smoke_proc_identity_loader_binding_survives_registration() -> TestResult {
        with_setup(|| {
            let _cleanup = Cleanup;
            crate::handlers::set_proc_argv_packed(PARENT, alloc::vec![9, 0]);
            let early = owner(PARENT);
            let task = crate::task::Task::new_registered(PARENT, PARENT);
            if !Arc::ptr_eq(&early, &task.proc_identity) {
                return Err("task registration lost early loader publication");
            }
            crate::handlers::set_proc_comm(PARENT, "registered");
            if early
                .state
                .lock()
                .comm
                .map(|comm| comm.as_str() == "registered")
                != Some(true)
            {
                return Err("registered and early writers use different identity owners");
            }
            crate::task::release_task(PARENT);
            let fresh = owner(PARENT);
            retire(PARENT, &early);
            if !Arc::ptr_eq(&owner(PARENT), &fresh) {
                return Err("stale retirement removed a replacement directory binding");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "syscall_abi/proc_identity",
        smoke_proc_identity_loader_binding_survives_registration
    );

    fn smoke_proc_identity_oom_lookup_is_nonblocking() -> TestResult {
        with_setup(|| {
            let _cleanup = Cleanup;
            crate::handlers::set_proc_comm(PARENT, "oom-target");
            let identity = owner(PARENT);
            let mut buffer = [0; 16];
            {
                let _locked = identity.state.lock();
                if crate::handlers::proc_comm_of_task_into(PARENT, &mut buffer) != 0 {
                    return Err("OOM lookup entered an already-locked identity");
                }
            }
            {
                let _locked = OWNERS[shard(PARENT)].lock();
                if crate::handlers::proc_comm_of_task_into(PARENT, &mut buffer) != 0 {
                    return Err("OOM lookup entered an already-locked directory");
                }
            }
            let len = crate::handlers::proc_comm_of_task_into(PARENT, &mut buffer);
            if &buffer[..len] != b"oom-target" {
                return Err("uncontended OOM lookup lost the task name");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "syscall_abi/proc_identity",
        smoke_proc_identity_oom_lookup_is_nonblocking
    );

    fn smoke_proc_identity_comm_preserves_utf8_limit() -> TestResult {
        let name = "🦀".repeat(16);
        let comm = Comm::new(&name);
        if comm.as_str().chars().count() != 15 || comm.as_str().len() != 60 {
            return TestResult::Fail("inline comm changed the existing Unicode truncation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "syscall_abi/proc_identity",
        smoke_proc_identity_comm_preserves_utf8_limit
    );
}
