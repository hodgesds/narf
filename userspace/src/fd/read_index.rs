//! RCU lookup view of a shared descriptor table.
//!
//! The writer-owned FdTable keeps the strong file/description references.
//! Retired lookup records keep only Weak references, so an RCU grace period
//! cannot delay final-close effects. Readers upgrade under a pin, revalidate
//! both directory and slot identity, and leave the pin before using the file.

use super::{Description, FdEntry, FdTable, OpenFileDescription};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use narf_filesystem::FileOps;
use narf_lib::sync::{IrqSafeSpinLock, IrqSafeSpinLockGuard};

const COLD: u8 = 0;
const LIVE: u8 = 1;
const DISABLED: u8 = 2;

#[derive(Debug)]
pub(super) struct SharedTable {
    inner: IrqSafeSpinLock<FdTable>,
    view: Arc<ReadIndex>,
    cleanup_task: u64,
}

impl SharedTable {
    pub(super) fn new(mut table: FdTable, cleanup_task: u64) -> Self {
        let view = Arc::new(ReadIndex::new());
        table.read_view = Some(Arc::clone(&view));
        Self {
            inner: IrqSafeSpinLock::new(table),
            view,
            cleanup_task,
        }
    }

    pub(super) fn lock(&self) -> TableGuard<'_> {
        self.wrap(self.inner.lock())
    }

    pub(super) fn try_lock(&self) -> Option<TableGuard<'_>> {
        Some(self.wrap(self.inner.try_lock()?))
    }

    fn wrap<'a>(&'a self, guard: IrqSafeSpinLockGuard<'a, FdTable>) -> TableGuard<'a> {
        // RCU is forbidden in IRQ handlers. Poison before exposing a writer:
        // in-flight readers revalidate this monotone state, and future lookups
        // use the existing locked path. No RCU operation is needed here.
        if narf_lib::context::in_irq() {
            self.view.disable();
        }
        TableGuard {
            owner: self,
            inner: guard,
        }
    }

    fn prepare_view(&self) {
        if self.view.state.load(Ordering::Acquire) != COLD {
            return;
        }
        let table = self.lock();
        if self.view.state.load(Ordering::Acquire) == COLD {
            self.view.replace_directory(&table);
        }
    }
}

impl Drop for SharedTable {
    fn drop(&mut self) {
        // A lookup may retain this owner across the last task's detach. Put
        // final-close cleanup on the owner's lifetime, not try_unwrap success.
        let table =
            core::mem::replace(&mut self.inner, IrqSafeSpinLock::new(FdTable::new())).into_inner();
        let FdTable {
            slots,
            descriptions,
            reserved,
            ..
        } = table;
        drop(descriptions);
        drop(reserved);
        super::release_closed(
            self.cleanup_task,
            slots
                .into_iter()
                .filter_map(|slot| slot.map(|entry| entry.ops)),
        );
    }
}

#[derive(Debug)]
pub(super) struct TableGuard<'a> {
    owner: &'a SharedTable,
    inner: IrqSafeSpinLockGuard<'a, FdTable>,
}

impl core::ops::Deref for TableGuard<'_> {
    type Target = FdTable;
    fn deref(&self) -> &FdTable {
        &self.inner
    }
}

impl core::ops::DerefMut for TableGuard<'_> {
    fn deref_mut(&mut self) -> &mut FdTable {
        &mut self.inner
    }
}

impl Drop for TableGuard<'_> {
    fn drop(&mut self) {
        // with_table exposes a mutable whole table. A caller may replace it
        // rather than using its slot methods; conservatively retire the fast
        // path instead of allowing an old directory to describe the new one.
        if !self
            .inner
            .read_view
            .as_ref()
            .is_some_and(|view| Arc::ptr_eq(view, &self.owner.view))
        {
            self.owner.view.disable();
            self.inner.read_view = Some(Arc::clone(&self.owner.view));
        }
    }
}

/// Owned fdget result. No RCU borrow escapes into I/O or a park boundary.
pub(crate) struct ResolvedFd {
    pub ops: Arc<dyn FileOps>,
    pub description: Description,
    pub flags: u32,
}

impl core::fmt::Debug for ResolvedFd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResolvedFd")
            .field("flags", &self.flags)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

impl ResolvedFd {
    fn from_table(table: &FdTable, fd: u32) -> Option<Self> {
        Some(Self {
            ops: Arc::clone(&table.get(fd)?.ops),
            description: table.description(fd)?,
            flags: table.get(fd)?.flags,
        })
    }
}

#[derive(Debug)]
struct Slot {
    ops: Weak<dyn FileOps>,
    description: Weak<OpenFileDescription>,
    flags: u32,
}

impl Slot {
    fn new(entry: &FdEntry, description: &Description) -> Self {
        Self {
            ops: Arc::downgrade(&entry.ops),
            description: Arc::downgrade(description),
            flags: entry.flags,
        }
    }

    fn same_as(&self, other: &Self) -> bool {
        self.flags == other.flags
            && Weak::ptr_eq(&self.ops, &other.ops)
            && Weak::ptr_eq(&self.description, &other.description)
    }
}

#[derive(Debug)]
struct Directory {
    slots: Vec<narf_rcu::Atomic<Option<Slot>>>,
}

impl Directory {
    fn snapshot(table: &FdTable) -> Option<Self> {
        let mut slots = Vec::new();
        // Match the existing geometric fdtable extent. Growing once per new
        // numeric fd would turn monotonically increasing opens quadratic.
        slots.try_reserve_exact(table.max_fds).ok()?;
        for fd in 0..table.max_fds {
            let entry = table.slots.get(fd).and_then(Option::as_ref);
            let description = table.descriptions.get(fd).and_then(Option::as_ref);
            slots.push(match (entry, description) {
                (Some(entry), Some(description)) => {
                    narf_rcu::Atomic::try_new(Some(Slot::new(entry, description))).ok()?
                }
                _ => narf_rcu::Atomic::null(),
            });
        }
        Some(Self { slots })
    }
}

#[derive(Debug)]
pub(super) struct ReadIndex {
    state: AtomicU8,
    capacity: AtomicUsize,
    directory: narf_rcu::Atomic<Directory>,
}

impl ReadIndex {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(COLD),
            capacity: AtomicUsize::new(0),
            directory: narf_rcu::Atomic::null(),
        }
    }

    fn disable(&self) {
        self.state.store(DISABLED, Ordering::Release);
    }

    pub(super) fn publish(&self, table: &FdTable, fd: u32) {
        if self.state.load(Ordering::Acquire) != LIVE {
            return;
        }
        if fd as usize >= self.capacity.load(Ordering::Relaxed) {
            self.replace_directory(table);
        } else {
            self.publish_slot(
                fd,
                table.get(fd),
                table.descriptions.get(fd as usize).and_then(Option::as_ref),
            );
        }
    }

    fn replace_directory(&self, table: &FdTable) {
        let Some(directory) = Directory::snapshot(table) else {
            self.disable();
            return;
        };
        let capacity = directory.slots.len();
        let Ok(owned) = narf_rcu::Owned::try_new(directory) else {
            self.disable();
            return;
        };
        let guard = narf_rcu::pin();
        self.directory.store(owned, &guard);
        self.capacity.store(capacity, Ordering::Relaxed);
        self.state.store(LIVE, Ordering::Release);
    }

    pub(super) fn publish_slot(
        &self,
        fd: u32,
        entry: Option<&FdEntry>,
        description: Option<&Description>,
    ) {
        if self.state.load(Ordering::Acquire) != LIVE {
            return;
        }
        let replacement = entry
            .zip(description)
            .map(|(entry, description)| Slot::new(entry, description));
        let guard = narf_rcu::pin();
        let directory = self.directory.load(&guard);
        let Some(cell) = directory
            .as_ref()
            .and_then(|directory| directory.slots.get(fd as usize))
        else {
            self.disable();
            return;
        };
        let current = cell.load(&guard);
        let unchanged = match (
            current.as_ref().and_then(Option::as_ref),
            replacement.as_ref(),
        ) {
            (None, None) => true,
            (Some(old), Some(new)) => old.same_as(new),
            _ => false,
        };
        if unchanged {
            return;
        }
        if replacement.is_none() {
            // close/exit must make progress without allocating a tombstone.
            cell.clear(&guard);
            return;
        }
        drop(guard);
        let Ok(owned) = narf_rcu::Owned::try_new(replacement) else {
            self.disable();
            return;
        };
        // The fdtable writer gate excludes another publication. Repin after
        // allocation so no allocator path runs inside a read section.
        let guard = narf_rcu::pin();
        let directory = self.directory.load(&guard);
        if let Some(cell) = directory.as_ref().and_then(|d| d.slots.get(fd as usize)) {
            cell.store(owned, &guard);
        } else {
            self.disable();
        }
    }
}

fn candidate_is_current(
    view: &ReadIndex,
    directory: &Directory,
    cell: &narf_rcu::Atomic<Option<Slot>>,
    slot: &Option<Slot>,
    guard: &narf_rcu::ReadGuard<'_>,
) -> bool {
    view.directory
        .load(guard)
        .as_ref()
        .is_some_and(|current| core::ptr::eq(current, directory))
        && cell
            .load(guard)
            .as_ref()
            .is_some_and(|current| core::ptr::eq(current, slot))
}

pub(super) fn lookup(table: &Arc<SharedTable>, fd: u32) -> Option<ResolvedFd> {
    if narf_lib::context::in_irq() {
        return ResolvedFd::from_table(&table.lock(), fd);
    }
    table.prepare_view();
    loop {
        if table.view.state.load(Ordering::Acquire) != LIVE {
            return ResolvedFd::from_table(&table.lock(), fd);
        }
        // Declare speculative owned references outside the pin's scope. On a
        // retry their last drops may run close hooks, which must run unpinned.
        let mut ops = None;
        let mut description = None;
        let mut flags = 0;
        let mut retry = false;
        let mut absent = true;
        {
            let guard = narf_rcu::pin();
            let directory = table.view.directory.load(&guard);
            if let Some(directory) = directory.as_ref() {
                if let Some(cell) = directory.slots.get(fd as usize) {
                    let slot = cell.load(&guard);
                    if let Some(Some(entry)) = slot.as_ref() {
                        absent = false;
                        ops = entry.ops.upgrade();
                        description = entry.description.upgrade();
                        flags = entry.flags;
                        // Weak nodes remain allocated through the grace period;
                        // file owners do not. Failed upgrades retry publication,
                        // rather than spuriously returning EBADF during dup2.
                        retry = ops.is_none()
                            || description.is_none()
                            || !candidate_is_current(
                                &table.view,
                                directory,
                                cell,
                                slot.as_ref().unwrap(),
                                &guard,
                            );
                    }
                }
            }
        }
        if table.view.state.load(Ordering::Acquire) != LIVE {
            drop(ops);
            drop(description);
            return ResolvedFd::from_table(&table.lock(), fd);
        }
        if absent {
            return None;
        }
        if !retry {
            return Some(ResolvedFd {
                ops: ops.expect("validated file reference"),
                description: description.expect("validated description reference"),
                flags,
            });
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::abi_test_support::*;

    fn file() -> Arc<dyn FileOps> {
        Arc::new(crate::fd::ConsoleFile::new())
    }

    fn entry(ops: Arc<dyn FileOps>) -> FdEntry {
        FdEntry {
            ops,
            offset: 0,
            flags: 0,
            status_flags: 0,
        }
    }

    fn table(ops: Arc<dyn FileOps>) -> Arc<SharedTable> {
        let mut table = FdTable::new();
        table.set(4, entry(ops));
        Arc::new(SharedTable::new(table, 0))
    }

    fn smoke_fd_rcu_mutation_and_reuse() -> TestResult {
        let first = file();
        let table = table(Arc::clone(&first));
        if !Arc::ptr_eq(&lookup(&table, 4).unwrap().ops, &first) {
            return TestResult::Fail("initial lookup changed file identity");
        }
        {
            let mut writer = table.lock();
            writer.get_mut(4).unwrap().flags = crate::fd::FD_CLOEXEC;
        }
        if lookup(&table, 4).unwrap().flags != crate::fd::FD_CLOEXEC {
            return TestResult::Fail("mutable descriptor flags were not published");
        }
        let second = file();
        table.lock().set(4, entry(Arc::clone(&second)));
        let resolved = lookup(&table, 4).unwrap();
        if !Arc::ptr_eq(&resolved.ops, &second) || resolved.flags != 0 {
            return TestResult::Fail("reused slot retained the previous descriptor");
        }
        table.lock().take(4);
        if lookup(&table, 4).is_some() {
            return TestResult::Fail("closed descriptor remained visible");
        }
        TestResult::Pass
    }
    kernel_test_in!("syscall_abi/fd_rcu", smoke_fd_rcu_mutation_and_reuse);

    fn smoke_fd_rcu_metadata_does_not_delay_final_close() -> TestResult {
        let table = table(file());
        drop(lookup(&table, 4));
        let guard = narf_rcu::pin();
        let directory = table.view.directory.load(&guard);
        let slot = directory.as_ref().unwrap().slots[4].load(&guard);
        let old = slot.as_ref().unwrap().as_ref().unwrap();
        drop(table.lock().take(4));
        if old.ops.upgrade().is_some() || old.description.upgrade().is_some() {
            return TestResult::Fail("retired metadata delayed final file destruction");
        }
        if lookup(&table, 4).is_some() {
            return TestResult::Fail("closed descriptor upgraded through retired metadata");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "syscall_abi/fd_rcu",
        smoke_fd_rcu_metadata_does_not_delay_final_close
    );

    fn smoke_fd_rcu_revalidates_slot_and_directory() -> TestResult {
        let table = table(file());
        drop(lookup(&table, 4));
        let guard = narf_rcu::pin();
        let directory = table.view.directory.load(&guard);
        let directory = directory.as_ref().unwrap();
        let cell = &directory.slots[4];
        let old = cell.load(&guard);
        table.lock().set(4, entry(file()));
        if candidate_is_current(&table.view, directory, cell, old.as_ref().unwrap(), &guard) {
            return TestResult::Fail("lookup accepted a replaced descriptor slot");
        }
        let current = cell.load(&guard);
        if !candidate_is_current(
            &table.view,
            directory,
            cell,
            current.as_ref().unwrap(),
            &guard,
        ) {
            return TestResult::Fail("stable candidate failed validation");
        }
        table.lock().set(256, entry(file()));
        if candidate_is_current(
            &table.view,
            directory,
            cell,
            current.as_ref().unwrap(),
            &guard,
        ) {
            return TestResult::Fail("lookup accepted a retired descriptor directory");
        }
        if lookup(&table, 4).is_none() || lookup(&table, 256).is_none() {
            return TestResult::Fail("directory growth lost a descriptor");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "syscall_abi/fd_rcu",
        smoke_fd_rcu_revalidates_slot_and_directory
    );

    fn smoke_fd_rcu_irq_and_whole_table_replacement() -> TestResult {
        let owner = table(file());
        drop(lookup(&owner, 4));
        let irq_result = {
            let gate = IrqSafeSpinLock::new(());
            let _gate = gate.lock();
            narf_lib::context::enter_irq();
            owner.lock().get_mut(4).unwrap().flags = crate::fd::FD_CLOEXEC;
            let result = lookup(&owner, 4).unwrap().flags;
            narf_lib::context::exit_irq();
            result
        };
        if irq_result != crate::fd::FD_CLOEXEC
            || owner.view.state.load(Ordering::Acquire) != DISABLED
        {
            return TestResult::Fail("IRQ access did not use the coherent locked fallback");
        }
        let owner = table(file());
        drop(lookup(&owner, 4));
        let mut replacement = FdTable::new();
        replacement.set(5, entry(file()));
        *owner.lock() = replacement;
        if lookup(&owner, 4).is_some() || lookup(&owner, 5).is_none() {
            return TestResult::Fail("whole-table replacement left a stale read view");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "syscall_abi/fd_rcu",
        smoke_fd_rcu_irq_and_whole_table_replacement
    );

    fn smoke_fd_rcu_last_lookup_owner_releases_socket() -> TestResult {
        with_setup(|| {
            let first = call(Syscall::SocketOpen.raw(), a2(1, 1, 0)).ok_or("socket status")?;
            if first < 0 {
                return Err("first socket failed");
            }
            let path = b"\0fd-rcu-final-table-owner";
            let mut addr = [0u8; 64];
            addr[..2].copy_from_slice(&1u16.to_ne_bytes());
            addr[2..2 + path.len()].copy_from_slice(path);
            let bind = |fd| {
                call(
                    Syscall::SocketBind.raw(),
                    a2(fd, addr.as_ptr() as u64, (2 + path.len()) as u64),
                )
            };
            if bind(first as u64) != Some(0) {
                return Err("first bind failed");
            }
            drop(crate::fd::lookup(FAKE_TASK, first as u32));
            let owner = super::super::TABLES[super::super::table_shard(FAKE_TASK)]
                .tables
                .lock()
                .get(&FAKE_TASK)
                .cloned()
                .ok_or("missing shared table")?;
            crate::fd::detach(FAKE_TASK);
            let second =
                call(Syscall::SocketOpen.raw(), a2(1, 1, 0)).ok_or("second socket status")?;
            if second < 0 {
                return Err("second socket failed");
            }
            if bind(second as u64) != Some(-98) {
                return Err("temporary table owner did not retain binding");
            }
            drop(owner);
            if bind(second as u64) != Some(0) {
                return Err("last lookup owner failed to release binding");
            }
            crate::fd::detach(FAKE_TASK);
            if super::super::TABLES[super::super::table_shard(FAKE_TASK)]
                .tables
                .lock()
                .contains_key(&FAKE_TASK)
            {
                return Err("final-close cleanup resurrected the detached table");
            }
            Ok(())
        })
    }
    kernel_test_in!(
        "syscall_abi/fd_rcu",
        smoke_fd_rcu_last_lookup_owner_releases_socket
    );

    fn smoke_fd_rcu_fork_share_and_unshare() -> TestResult {
        with_setup(|| {
            let shared = FAKE_TASK + 1;
            let forked = FAKE_TASK + 2;
            let first = file();
            crate::fd::with_table(FAKE_TASK, |t| t.set(4, entry(Arc::clone(&first))));
            drop(crate::fd::lookup(FAKE_TASK, 4));
            crate::fd::share(FAKE_TASK, shared);
            drop(crate::fd::lookup(shared, 4));
            if crate::fd::ops_held_by_other_task(FAKE_TASK, &first) {
                return Err("shared binding was mistaken for an independent fd table");
            }
            crate::fd::fork(FAKE_TASK, forked);
            drop(crate::fd::lookup(forked, 4));
            if !crate::fd::ops_held_by_other_task(FAKE_TASK, &first) {
                return Err("forked table was skipped by the file alias check");
            }
            let second = file();
            crate::fd::with_table(FAKE_TASK, |t| t.set(4, entry(Arc::clone(&second))));
            if !Arc::ptr_eq(&crate::fd::lookup(shared, 4).unwrap().ops, &second)
                || !Arc::ptr_eq(&crate::fd::lookup(forked, 4).unwrap().ops, &first)
            {
                return Err("fork/shared table read views have incorrect ownership");
            }
            if !crate::fd::unshare_table(shared) {
                return Err("unshare did not copy the shared descriptor table");
            }
            if crate::fd::unshare_table(shared) {
                return Err("private descriptor table was copied again");
            }
            drop(crate::fd::lookup(shared, 4));
            crate::fd::with_table(FAKE_TASK, |t| t.close_range(4, 4, false));
            if crate::fd::lookup(FAKE_TASK, 4).is_some()
                || !Arc::ptr_eq(&crate::fd::lookup(shared, 4).unwrap().ops, &second)
            {
                return Err("parent close changed the unshared read view");
            }
            crate::fd::detach(shared);
            crate::fd::detach(forked);
            Ok(())
        })
    }
    kernel_test_in!("syscall_abi/fd_rcu", smoke_fd_rcu_fork_share_and_unshare);
}
