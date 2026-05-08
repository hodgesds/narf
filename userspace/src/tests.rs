//! Per-crate kernel-test entries for `narf-userspace`.

use alloc::sync::Arc;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::AddressSpace;

use crate::syscall::{
    kernel_syscall_entry, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
};
use crate::{
    install_address_space_lookup, install_core_syscalls, install_global,
};

/// Static so the AS-lookup `fn` pointer can resolve it without a
/// closure capture.
#[cfg(target_arch = "x86_64")]
static PARENT_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

#[cfg(target_arch = "x86_64")]
fn lookup_parent_as() -> Option<Arc<AddressSpace>> {
    PARENT_AS.lock().clone()
}

/// Synthetic TrapContext used in handler-only tests (no ring-3
/// entry). Captures the args going in and the return going out.
struct StubCtx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
}

impl TrapContext for StubCtx {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, r: SyscallReturn) {
        self.ret = Some(r);
    }
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
}

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_shares_address_space() -> TestResult {
    // Direct exercise of `sys_clone` (Syscall::Clone = 56) without
    // entering ring 3. Wires the address-space lookup to a fixed
    // parent AS, dispatches a synthetic clone through
    // `kernel_syscall_entry`, then verifies:
    //
    //   1. The handler returned a non-zero tid.
    //   2. The new task is on the scheduler's ready queue with the
    //      SAME `Arc<AddressSpace>` as the parent (proves the
    //      thread-style "shared AS" guarantee).

    crate::syscall::__test_clear_global();
    narf_scheduler::init();

    let parent_as = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("AddressSpace::new_for_user"),
    };
    *PARENT_AS.lock() = Some(parent_as.clone());
    install_address_space_lookup(lookup_parent_as);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0x8000_0000_1000, // synthetic child entry
            arg1: 0x7fff_fff0_0000, // synthetic child stack top
            arg2: 0xC0FFEE,         // arg passed to child (RDI plumbing TBD)
            arg3: 0,                // inherit parent fs_base
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };

    // Syscall::Clone == 56; dispatch as the trap entry would.
    kernel_syscall_entry(56, &mut ctx);

    let ret = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("handler did not set return"),
    };
    if ret.status != SyscallReturn::OK {
        return TestResult::Fail("clone returned non-OK status");
    }
    if ret.value == 0 {
        return TestResult::Fail("clone returned tid=0");
    }
    let child_tid = narf_scheduler::TaskId(ret.value);
    let child_as = match narf_scheduler::address_space_of(child_tid) {
        Some(a) => a,
        None => return TestResult::Fail("child has no AS attached"),
    };
    if !Arc::ptr_eq(&child_as, &parent_as) {
        return TestResult::Fail("child AS is not the parent AS");
    }

    *PARENT_AS.lock() = None;
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_clone_shares_address_space);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_clone_rejects_zero_entry_or_stack() -> TestResult {
    // Defence-in-depth on the handler — entry==0 or stack==0 is
    // invalid input and must surface InvalidOp without spawning
    // a task. Does NOT require an AS lookup to be installed.

    crate::syscall::__test_clear_global();
    narf_scheduler::init();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    for (entry, stack) in [(0u64, 0x1000u64), (0x1000u64, 0u64), (0u64, 0u64)] {
        let mut ctx = StubCtx {
            args: SyscallArgs {
                arg0: entry,
                arg1: stack,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            },
            ret: None,
        };
        kernel_syscall_entry(56, &mut ctx);
        let r = match ctx.ret {
            Some(r) => r,
            None => return TestResult::Fail("no return set"),
        };
        if r.status == SyscallReturn::OK {
            return TestResult::Fail("zero entry/stack should not succeed");
        }
    }

    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_clone_rejects_zero_entry_or_stack);

// ── ported from verification ───────────────────────────────────────

fn smoke_userspace_install_core_syscalls_fills_table() -> TestResult {
    // `install_core_syscalls` drops Write/Read/Close/Mmap/Munmap/
    // ExitTask/Yield/Sleep handlers into a fresh table. Confirm
    // every slot has both a name and a handler after install.
    use crate::{install_core_syscalls, Syscall, SyscallTable};

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);

    let slots = [
        Syscall::Write,
        Syscall::Read,
        Syscall::Close,
        Syscall::Mmap,
        Syscall::Munmap,
        Syscall::ExitTask,
        Syscall::Yield,
        Syscall::Sleep,
    ];
    for s in slots {
        if t.name_of(s).is_none() {
            return TestResult::Fail("core syscall missing after install_core_syscalls");
        }
    }
    if t.len() < slots.len() {
        return TestResult::Fail("install_core_syscalls did not grow table to cover every slot");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_install_core_syscalls_fills_table);

fn smoke_userspace_syscall_table_roundtrip() -> TestResult {
    use crate::{Syscall, SyscallTable};

    // Pinned numbers.
    if Syscall::Submit.raw() != 100 || Syscall::Bootstrap.raw() != 101 {
        return TestResult::Fail("syscall numbers drifted");
    }
    if Syscall::from_raw(110) != Some(Syscall::OpenFile) {
        return TestResult::Fail("from_raw(110) did not match OpenFile");
    }
    if Syscall::from_raw(999).is_some() {
        return TestResult::Fail("from_raw(999) should be None");
    }

    let mut t = SyscallTable::new();
    t.register(Syscall::Submit, "submit");
    t.register(Syscall::Bootstrap, "bootstrap");
    if t.len() != 2 {
        return TestResult::Fail("register did not grow table");
    }
    if t.name_of(Syscall::Submit) != Some("submit") {
        return TestResult::Fail("name_of mismatch");
    }
    if t.name_of(Syscall::Yield).is_some() {
        return TestResult::Fail("unregistered syscall should return None");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_syscall_table_roundtrip);
