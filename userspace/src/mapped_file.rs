//! Lifetime tracking for `MAP_SHARED` file/device mappings.
//!
//! Address-space regions store physical frames but intentionally do not depend
//! on filesystem objects. Keep the backing open-file description alive here
//! until the last process mapping disappears, matching Linux's VMA-held file
//! reference without adding a filesystem dependency to the memory TCB.

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_filesystem::FileOps;
use narf_lib::sync::IrqSafeSpinLock;

struct MappingOwner {
    pid: u64,
    base: u64,
    len: u64,
    ops: Arc<dyn FileOps>,
}

static MAPPING_OWNERS: IrqSafeSpinLock<Vec<MappingOwner>> = IrqSafeSpinLock::new(Vec::new());

fn current_pid() -> u64 {
    let task = crate::handlers::current_task_id();
    crate::handlers::task_to_pid_raw(task).unwrap_or(task)
}

pub(crate) fn register_current(base: u64, len: u64, ops: Arc<dyn FileOps>) {
    register(current_pid(), base, len, ops);
}

fn register(pid: u64, base: u64, len: u64, ops: Arc<dyn FileOps>) {
    MAPPING_OWNERS.lock().push(MappingOwner {
        pid,
        base,
        len,
        ops,
    });
}

pub(crate) fn unmap_current(base: u64) {
    let pid = current_pid();
    MAPPING_OWNERS
        .lock()
        .retain(|mapping| mapping.pid != pid || mapping.base != base);
}

/// Mirror `AddressSpace::punch_fixed` splitting for owner references.
pub(crate) fn punch_current(base: u64, len: u64) {
    punch(current_pid(), base, len);
}

fn punch(pid: u64, base: u64, len: u64) {
    let Some(end) = base.checked_add(len) else {
        return;
    };
    let mut owners = MAPPING_OWNERS.lock();
    let old = core::mem::take(&mut *owners);
    for mut mapping in old {
        if mapping.pid != pid {
            owners.push(mapping);
            continue;
        }
        let Some(mapping_end) = mapping.base.checked_add(mapping.len) else {
            continue;
        };
        if mapping_end <= base || mapping.base >= end {
            owners.push(mapping);
            continue;
        }
        if mapping.base < base {
            let suffix = if mapping_end > end {
                Some(MappingOwner {
                    pid,
                    base: end,
                    len: mapping_end - end,
                    ops: Arc::clone(&mapping.ops),
                })
            } else {
                None
            };
            mapping.len = base - mapping.base;
            owners.push(mapping);
            if let Some(suffix) = suffix {
                owners.push(suffix);
            }
        } else if mapping_end > end {
            mapping.base = end;
            mapping.len = mapping_end - end;
            owners.push(mapping);
        }
    }
}

pub(crate) fn fork_process(parent_pid: u64, child_pid: u64) {
    let mut owners = MAPPING_OWNERS.lock();
    let inherited: Vec<_> = owners
        .iter()
        .filter(|mapping| mapping.pid == parent_pid)
        .map(|mapping| MappingOwner {
            pid: child_pid,
            base: mapping.base,
            len: mapping.len,
            ops: Arc::clone(&mapping.ops),
        })
        .collect();
    owners.extend(inherited);
}

pub(crate) fn process_exit(pid: u64, _tid: u64) {
    MAPPING_OWNERS.lock().retain(|mapping| mapping.pid != pid);
}

fn owner_count(pid: u64) -> usize {
    MAPPING_OWNERS
        .lock()
        .iter()
        .filter(|mapping| mapping.pid == pid)
        .count()
}

mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use narf_filesystem::{FsFuture, Mode, Stat};
    use narf_kernel_test::{kernel_test_in, TestResult};

    static DROPS: AtomicUsize = AtomicUsize::new(0);

    struct TestOwner;

    impl Drop for TestOwner {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl FileOps for TestOwner {
        fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async { Ok(0) })
        }

        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(buf.len()) })
        }

        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    fn smoke_mapped_file_owner_lifecycle() -> TestResult {
        const PARENT: u64 = u64::MAX - 20;
        const CHILD: u64 = u64::MAX - 19;
        process_exit(PARENT, PARENT);
        process_exit(CHILD, CHILD);
        DROPS.store(0, Ordering::Relaxed);

        let owner: Arc<dyn FileOps> = Arc::new(TestOwner);
        register(PARENT, 0x1000, 0x3000, Arc::clone(&owner));
        drop(owner);
        if DROPS.load(Ordering::Relaxed) != 0 || owner_count(PARENT) != 1 {
            return TestResult::Fail("mapping did not retain its file owner");
        }

        fork_process(PARENT, CHILD);
        if owner_count(CHILD) != 1 {
            return TestResult::Fail("fork did not inherit the mapping owner");
        }

        // Punch the middle page: parent retains prefix + suffix references.
        punch(PARENT, 0x2000, 0x1000);
        if owner_count(PARENT) != 2 {
            return TestResult::Fail("MAP_FIXED punch did not split the mapping owner");
        }
        process_exit(PARENT, PARENT);
        if DROPS.load(Ordering::Relaxed) != 0 || owner_count(CHILD) != 1 {
            return TestResult::Fail("parent exit released an inherited mapping owner");
        }
        process_exit(CHILD, CHILD);
        if DROPS.load(Ordering::Relaxed) != 1 {
            return TestResult::Fail("last mapping did not release its file owner");
        }
        TestResult::Pass
    }

    kernel_test_in!("userspace/perf", smoke_mapped_file_owner_lifecycle);
}
