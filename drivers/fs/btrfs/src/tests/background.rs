//! The filesystem's own background tasks (transaction timer, orphan reaper,
//! last-unmount commit) run like any other filesystem caller: on whichever
//! CPU is free. Linux runs `transaction_kthread` and `cleaner_kthread` as
//! unbound kthreads and its btrfs workqueues `WQ_UNBOUND`.

use super::*;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};
use core::task::{Context, Poll, Waker};
use narf_scheduler::affinity::{Affinity, CpuId};

static GO: AtomicBool = AtomicBool::new(false);
static GO_WAKER: narf_lib::sync::IrqSafeSpinLock<Option<Waker>> =
    narf_lib::sync::IrqSafeSpinLock::new(None);
/// 0 not started, 1 joined, 2 left, 3 could not join.
static HOLDER: AtomicU8 = AtomicU8::new(0);
static HOLDER_LEFT_ON: AtomicU32 = AtomicU32::new(u32::MAX);
/// 0 pending, 1 done, 2 deadline, 3 error.
static COMMIT: AtomicU8 = AtomicU8::new(0);
static JOIN: AtomicU8 = AtomicU8::new(0);

const DEADLINE_NS: u64 = 2_000_000_000;
const HOG_NS: u64 = 3_000_000_000;

/// Resolves once [`GO`] is set.
struct Go;

impl core::future::Future for Go {
    type Output = ();
    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if GO.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        *GO_WAKER.lock() = Some(cx.waker().clone());
        if GO.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn outcome<T, E>(r: Result<Result<T, E>, narf_time::Elapsed>) -> u8 {
    match r {
        Ok(Ok(_)) => 1,
        Err(_) => 2,
        Ok(Err(_)) => 3,
    }
}

fn wait_for(ns: u64, mut done: impl FnMut() -> bool) -> bool {
    let until = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(ns));
    while narf_time::now_cycles() < until {
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    done()
}

/// A background task of the filesystem, last run on the boot CPU, has joined
/// the running transaction and sleeps. The boot CPU then stops scheduling —
/// this test thread holds it for three seconds without polling anything,
/// the shape of a long non-yielding poll there. Another CPU wakes the task
/// and commits; a third starts a data operation behind the commit. Both must
/// finish within their deadlines: the woken task has to run elsewhere and
/// leave the transaction. A task held to the boot CPU keeps every commit and,
/// behind the waiting commit, every new operation on every CPU waiting.
fn background_join_off_a_stuck_boot_cpu() -> Result<(), &'static str> {
    let me = narf_lib::percpu::current_cpu() as u32;
    if narf_lib::smp::cpu_count() < 4 || me != CpuId::BOOT.0 {
        return Err("skip");
    }
    let dev = writable_sparse(FIXTURE_BGT_SPARSE);
    let vol = mount_writable(dev).map_err(|_| "fixture did not mount")?;
    // Something for the commit to do, so it has to close the transaction.
    {
        use narf_filesystem::FsInstance;
        let file = poll_once(vol.root().create("background"))
            .and_then(|r| r.ok())
            .ok_or("create failed")?;
        if !matches!(poll_once(file.write(0, &[0x5a; 4096])), Some(Ok(_))) {
            return Err("write failed");
        }
    }
    GO.store(false, Ordering::Release);
    HOLDER.store(0, Ordering::Release);
    HOLDER_LEFT_ON.store(u32::MAX, Ordering::Release);
    COMMIT.store(0, Ordering::Release);
    JOIN.store(0, Ordering::Release);

    let spec = crate::write::background_task_spec();
    let spec = narf_scheduler::TaskSpec {
        affinity: Affinity {
            allowed: spec.affinity.allowed,
            preferred: Some(CpuId(me)),
        },
        ..spec
    };
    let held = vol.clone();
    narf_scheduler::spawn_with_spec(
        async move {
            let Ok(op) = held.begin_data_op().await else {
                HOLDER.store(3, Ordering::Release);
                return;
            };
            HOLDER.store(1, Ordering::Release);
            Go.await;
            drop(op);
            HOLDER_LEFT_ON.store(narf_lib::percpu::current_cpu() as u32, Ordering::Release);
            HOLDER.store(2, Ordering::Release);
        },
        spec,
    );
    narf_scheduler::poll_one_round();
    if HOLDER.load(Ordering::Acquire) != 1 {
        return Err("the background task did not join the transaction on the boot CPU");
    }
    narf_scheduler::enable_work_stealing();
    // From here the boot CPU polls nothing until the hog ends.
    let hog_until = narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(HOG_NS));
    let committer = vol.clone();
    narf_scheduler::spawn_stackful_pinned(
        async move {
            GO.store(true, Ordering::Release);
            let waker = GO_WAKER.lock().take();
            if let Some(waker) = waker {
                waker.wake();
            }
            let deadline = narf_time::Deadline::after_ns(DEADLINE_NS);
            let r = narf_time::timeout(deadline, committer.sync_to_disk_exclusive()).await;
            COMMIT.store(outcome(r), Ordering::Release);
        },
        1,
    );
    let joiner = vol.clone();
    narf_scheduler::spawn_stackful_pinned(
        async move {
            // Behind the commit, once it has had time to close.
            narf_time::sleep_ms(100).await;
            let deadline = narf_time::Deadline::after_ns(DEADLINE_NS);
            let r = narf_time::timeout(deadline, joiner.begin_data_op()).await;
            JOIN.store(outcome(r), Ordering::Release);
        },
        2,
    );
    let settled = wait_for(HOG_NS, || {
        COMMIT.load(Ordering::Acquire) != 0 && JOIN.load(Ordering::Acquire) != 0
    });
    while narf_time::now_cycles() < hog_until && !settled {
        core::hint::spin_loop();
    }
    // Free the boot CPU: a task still held there finishes now.
    for _ in 0..64 {
        if HOLDER.load(Ordering::Acquire) >= 2 {
            break;
        }
        narf_scheduler::poll_one_round();
    }
    narf_scheduler::disable_work_stealing();
    let _ = wait_for(DEADLINE_NS, || {
        COMMIT.load(Ordering::Acquire) != 0 && JOIN.load(Ordering::Acquire) != 0
    });
    let left_on = HOLDER_LEFT_ON.load(Ordering::Acquire);
    match (COMMIT.load(Ordering::Acquire), JOIN.load(Ordering::Acquire)) {
        (1, 1) => {}
        (2, _) => return Err("a commit waited out its deadline behind a task held on a stuck CPU"),
        (_, 2) => {
            return Err("a new operation waited out its deadline behind a task held on a stuck CPU")
        }
        _ => return Err("the commit or the operation failed"),
    }
    if left_on == me {
        return Err("the woken background task left the transaction only on the stuck CPU");
    }
    if HOLDER.load(Ordering::Acquire) != 2 {
        return Err("the background task never left the transaction");
    }
    Ok(())
}

fn smoke_btrfs_background_join_off_a_stuck_boot_cpu() -> TestResult {
    match background_join_off_a_stuck_boot_cpu() {
        Ok(()) => TestResult::Pass,
        Err("skip") => TestResult::Skip("needs four CPUs, run from the boot CPU"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs/background",
    smoke_btrfs_background_join_off_a_stuck_boot_cpu
);
