//! Process-controlled VT handoff and wait regressions. Reference:
//! Linux drivers/tty/vt/vt_ioctl.c: change_console, vt_reldisp,
//! complete_change_console, VT_SETMODE and VT_WAITACTIVE.
use super::*;
use alloc::sync::Arc;
use alloc::task::Wake;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

static CALLER: AtomicU64 = AtomicU64::new(100);
static DEAD: AtomicU64 = AtomicU64::new(0);
static SIGNALS: IrqSafeSpinLock<Vec<(u64, u32)>> = IrqSafeSpinLock::new(Vec::new());

fn caller() -> u64 {
    CALLER.load(Ordering::Relaxed)
}
fn signal(task: u64, signum: u32) -> bool {
    if task == DEAD.load(Ordering::Relaxed) {
        return false;
    }
    SIGNALS.lock().push((task, signum));
    true
}
fn signals() -> Vec<(u64, u32)> {
    SIGNALS.lock().clone()
}

struct Hooks {
    current: usize,
    signal: usize,
}
impl Hooks {
    fn install() -> Self {
        let saved = Self {
            current: CURRENT_CONTROLLER.load(Ordering::Acquire),
            signal: SIGNAL_CONTROLLER.load(Ordering::Acquire),
        };
        __reset_for_test();
        SIGNALS.lock().clear();
        CALLER.store(100, Ordering::Relaxed);
        DEAD.store(0, Ordering::Relaxed);
        install_process_hooks(caller, signal);
        saved
    }
}
impl Drop for Hooks {
    fn drop(&mut self) {
        __reset_for_test();
        CURRENT_CONTROLLER.store(self.current, Ordering::Release);
        SIGNAL_CONTROLLER.store(self.signal, Ordering::Release);
    }
}
fn process_mode(relsig: i16, acqsig: i16) -> VtMode {
    VtMode {
        mode: VT_PROCESS,
        relsig,
        acqsig,
        ..VtMode::default()
    }
}
struct Counter(AtomicU64);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn smoke_vt_process_handoff_waits_for_release() -> TestResult {
    use crate::{DirOps, POLL_ERR};
    let _hooks = Hooks::install();
    if set_mode(1, process_mode(10, 11)).is_err() {
        return TestResult::Fail("old mode");
    }
    CALLER.store(200, Ordering::Relaxed);
    if set_mode(2, process_mode(12, 13)).is_err() {
        return TestResult::Fail("new mode");
    }
    // A different caller requesting activation must not become controller.
    CALLER.store(300, Ordering::Relaxed);
    crate::sysfs::populate_tty_class();
    let tty0 = crate::sysfs::get_root()
        .get_child("class")
        .unwrap()
        .get_child("tty")
        .unwrap()
        .get_child("tty0")
        .unwrap();
    let attr = crate::sysfs::SysKobjDir { kobj: tty0 }
        .lookup("active")
        .unwrap();
    let _ = narf_scheduler::block_on_spin(attr.read(0, &mut [0; 16]));
    let count = Arc::new(Counter(AtomicU64::new(0)));
    let waker = core::task::Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let mut wait = wait_active(2);
    if wait.as_mut().poll(&mut cx) != Poll::Pending {
        return TestResult::Fail("wait returned early");
    }
    if activate(2).is_err()
        || active_vt() != 1
        || signals() != [(100, 10)]
        || attr.poll_readiness() & POLL_ERR != 0
        || count.0.load(Ordering::Relaxed) != 0
    {
        return TestResult::Fail("VT_PROCESS must request release before publishing switch");
    }
    if release_display(1, 0).is_err() || active_vt() != 1 {
        return TestResult::Fail("release rejection");
    }
    if activate(2).is_err()
        || release_display(1, 1).is_err()
        || active_vt() != 2
        || signals() != [(100, 10), (100, 10), (200, 13)]
    {
        return TestResult::Fail("release/acquire signal order or controller identity");
    }
    if attr.poll_readiness() & POLL_ERR == 0
        || count.0.load(Ordering::Relaxed) != 1
        || wait.as_mut().poll(&mut cx) != Poll::Ready(Ok(()))
    {
        return TestResult::Fail("completed handoff did not notify and wake waiters");
    }
    if release_display(2, 2).is_err() || release_display(2, 1).is_ok() {
        return TestResult::Fail("acquisition acknowledgement validation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/vt/process",
    smoke_vt_process_handoff_waits_for_release
);

fn smoke_vt_dead_controllers_revert_to_auto() -> TestResult {
    let _hooks = Hooks::install();
    let _ = set_mode(1, process_mode(10, 11));
    DEAD.store(100, Ordering::Relaxed);
    if activate(2).is_err() || active_vt() != 2 || get_mode(1).mode != VT_AUTO {
        return TestResult::Fail("dead release controller blocked switch");
    }
    let _ = set_mode(3, process_mode(12, 13));
    if activate(3).is_err() || active_vt() != 3 || get_mode(3).mode != VT_AUTO {
        return TestResult::Fail("dead acquire controller retained VT_PROCESS");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/vt/process",
    smoke_vt_dead_controllers_revert_to_auto
);

fn smoke_vt_mode_replacement_cancels_pending_release() -> TestResult {
    let _hooks = Hooks::install();
    let _ = set_mode(1, process_mode(10, 11));
    let _ = activate(2);
    if set_mode(
        1,
        VtMode {
            mode: 9,
            ..VtMode::default()
        },
    )
    .is_ok()
        || set_mode(0, VtMode::default()).is_ok()
        || release_display(3, 1).is_ok()
    {
        return TestResult::Fail("invalid mode or unrelated release accepted");
    }
    let mut mode = process_mode(14, 15);
    mode.frsig = 99;
    let _ = set_mode(1, mode);
    if get_mode(1).frsig != 0 || release_display(1, 1).is_ok() || active_vt() != 1 {
        return TestResult::Fail("SETMODE did not clear ignored signal/pending switch");
    }
    if activate(3).is_err() || release_display(1, 1).is_err() || active_vt() != 3 {
        return TestResult::Fail("replacement controller could not complete fresh switch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/vt/process",
    smoke_vt_mode_replacement_cancels_pending_release
);

fn smoke_vt_wait_cancellation_and_ioctl() -> TestResult {
    use crate::{FsError, IoctlContext};
    struct ContextStub;
    impl IoctlContext for ContextStub {
        fn read(&self, _: u64, _: &mut [u8]) -> Result<(), FsError> {
            Err(FsError::BadAddress)
        }
        fn write(&self, _: u64, _: &[u8]) -> Result<(), FsError> {
            Err(FsError::BadAddress)
        }
        fn nonblocking(&self) -> bool {
            false
        }
    }
    let _hooks = Hooks::install();
    let count = Arc::new(Counter(AtomicU64::new(0)));
    let waker = core::task::Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let baseline = ACTIVE_CHANGED.waiter_count();
    let mut wait = wait_active(2);
    if wait.as_mut().poll(&mut cx) != Poll::Pending || ACTIVE_CHANGED.waiter_count() != baseline + 1
    {
        return TestResult::Fail("VT wait did not arm");
    }
    drop(wait);
    if ACTIVE_CHANGED.waiter_count() != baseline {
        return TestResult::Fail("cancelled VT wait leaked registration");
    }
    let tty = crate::devfs::console_tty_node(crate::TTY_ID_CONSOLE).unwrap();
    if tty.ioctl(crate::devfs_pty::VT_WAITACTIVE, 2) != Err(FsError::WouldBlock) {
        return TestResult::Fail("sync ioctl falsely reported inactive VT active");
    }
    let mut ioctl = tty.ioctl_user(crate::devfs_pty::VT_WAITACTIVE, 2, &ContextStub);
    if ioctl.as_mut().poll(&mut cx) != Poll::Pending {
        return TestResult::Fail("async ioctl returned early");
    }
    let _ = activate(2);
    if count.0.load(Ordering::Relaxed) != 1 || ioctl.as_mut().poll(&mut cx) != Poll::Ready(Ok(0)) {
        return TestResult::Fail("async ioctl did not wake after activation");
    }
    if narf_scheduler::block_on_spin(wait_active(0)) != Err(FsError::InvalidData) {
        return TestResult::Fail("invalid wait target accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "filesystem/vt/process",
    smoke_vt_wait_cancellation_and_ioctl
);
