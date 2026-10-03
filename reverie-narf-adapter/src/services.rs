//! The per-entry [`KernelServices`] a hosted Tool callback runs against.

use alloc::vec;
use alloc::vec::Vec;

use narf_userspace::handlers::tool_view::{self, LinuxTaskIds};
use narf_userspace::syscall::{
    CreatedNativeTask, NativeSyscallOriginalError, NativeSyscallOutcome, NativeSyscallRequest,
    NativeSyscallTransition, SyscallArgs,
};
use reverie::syscalls::{libc, Errno, IoSlice, IoSliceMut, MemoryAccess};
use reverie::{Auxv, Pid};
use reverie_narf_core::{
    CreatedTask, CreatedTaskKind, KernelServices, NarfSyscallOutcome, NarfSyscallRequest,
    OriginalSyscallError,
};

/// x86_64 Linux user code and stack segment selectors, as a ptrace tracer
/// reads them for a 64-bit task.
const USER_CS: u64 = 0x33;
const USER_SS: u64 = 0x2b;

/// `-ENOSYS`, which Linux stores in `rax` at syscall entry.
const ENTRY_RAX: u64 = -38i64 as u64;

/// Maps one native outcome to the value the guest observes.
///
/// A normal return goes through [`narf_userspace::syscall::SyscallReturn::linux_abi_result`],
/// the same fold of Narf's typed status into a Linux-ABI value that the x86_64
/// syscall return path applies, so a Tool sees exactly the value the guest
/// would have seen without it.
pub fn map_native_outcome(outcome: NativeSyscallOutcome) -> NarfSyscallOutcome {
    match outcome {
        NativeSyscallOutcome::Returned(result) => {
            NarfSyscallOutcome::Returned(result.linux_abi_result())
        }
        NativeSyscallOutcome::ContextManaged => NarfSyscallOutcome::ContextManaged,
    }
}

fn args_of(values: [u64; 6]) -> SyscallArgs {
    SyscallArgs {
        arg0: values[0],
        arg1: values[1],
        arg2: values[2],
        arg3: values[3],
        arg4: values[4],
        arg5: values[5],
    }
}

fn pid(raw: u64) -> Pid {
    Pid::from_raw(raw as i32)
}

/// The current task's memory: the active user address space.
///
/// Valid while the task it was obtained for is the one running, which holds
/// for the whole callback. Every access goes through the kernel's checked
/// user-copy primitives, so a bad address is an `EFAULT`, never a kernel
/// access.
#[derive(Clone, Copy, Debug)]
pub struct NarfMemory {
    _private: (),
}

fn errno(raw: u64) -> Errno {
    Errno::new(raw as i32)
}

impl MemoryAccess for NarfMemory {
    fn read_vectored(&self, from: &[IoSlice], to: &mut [IoSliceMut]) -> Result<usize, Errno> {
        let capacity: usize = to.iter().map(|local| local.len()).sum();
        let mut gathered = vec![0u8; capacity];
        let mut filled = 0;
        // Remote slices name guest addresses; they are never dereferenced.
        for remote in from {
            let n = remote.len().min(capacity - filled);
            if n == 0 {
                break;
            }
            // SAFETY: this handle exists only inside a callback of the task
            // whose address space is active, and interceptor callbacks run in
            // task context, never in IRQ context.
            unsafe {
                tool_view::read_current_user(
                    &mut gathered[filled..filled + n],
                    remote.as_ptr() as u64,
                )
            }
            .map_err(errno)?;
            filled += n;
        }
        let mut copied = 0;
        for local in to.iter_mut() {
            let n = local.len().min(filled - copied);
            local[..n].copy_from_slice(&gathered[copied..copied + n]);
            copied += n;
        }
        Ok(copied)
    }

    fn write_vectored(&mut self, from: &[IoSlice], to: &mut [IoSliceMut]) -> Result<usize, Errno> {
        let mut source = Vec::new();
        for local in from {
            source.extend_from_slice(local);
        }
        let mut written = 0;
        for remote in to.iter() {
            let n = remote.len().min(source.len() - written);
            if n == 0 {
                break;
            }
            // SAFETY: as in `read_vectored`.
            unsafe {
                tool_view::write_current_user(remote.as_ptr() as u64, &source[written..written + n])
            }
            .map_err(errno)?;
            written += n;
        }
        Ok(written)
    }
}

/// [`KernelServices`] for one interceptor entry of one task.
///
/// It borrows the kernel-owned native transition the dispatcher lent to this
/// entry and reports the task the way a tracer in the root PID namespace sees
/// it under Linux.
pub struct NarfKernelServices<'a> {
    native: &'a mut dyn NativeSyscallTransition,
    task_id: u64,
    ids: LinuxTaskIds,
    raw_number: Option<u32>,
    created: Vec<(u64, Pid)>,
}

impl core::fmt::Debug for NarfKernelServices<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NarfKernelServices")
            .field("task_id", &self.task_id)
            .field("tid", &self.ids.tid)
            .field("pid", &self.ids.pid)
            .field("raw_number", &self.raw_number)
            .field("created", &self.created)
            .finish_non_exhaustive()
    }
}

// SAFETY: a `NarfKernelServices` lives on the trapping task's kernel stack for
// the duration of one interceptor call. The core lends it to the Tool's future
// only while it polls that future, synchronously, on that stack; a future the
// core keeps across a park holds no reference to it (reverie-narf-core's
// `FrameSlot` is cleared on every exit from the poll). So the borrowed
// transition is never reached from another CPU or after the call returns.
unsafe impl Send for NarfKernelServices<'_> {}
// SAFETY: as above; no shared reference escapes the single synchronous poll.
unsafe impl Sync for NarfKernelServices<'_> {}

impl<'a> NarfKernelServices<'a> {
    /// Services for scheduler task `task_id`, whose Linux identity is `ids`.
    ///
    /// `raw_number` is the intercepted syscall's wire number, or `None` for a
    /// lifecycle callback, which has no syscall.
    pub fn new(
        native: &'a mut dyn NativeSyscallTransition,
        task_id: u64,
        ids: LinuxTaskIds,
        raw_number: Option<u32>,
    ) -> Self {
        Self {
            native,
            task_id,
            ids,
            raw_number,
            created: Vec::new(),
        }
    }

    /// Scheduler task id of the task this entry belongs to.
    pub fn task_id(&self) -> u64 {
        self.task_id
    }

    /// The scheduler task ids and Linux thread IDs of the tasks this entry's
    /// transitions created, in creation order.
    pub fn take_created(&mut self) -> Vec<(u64, Pid)> {
        core::mem::take(&mut self.created)
    }

    fn created_task(&mut self, native: CreatedNativeTask) -> CreatedTask {
        let tid = pid(native.linux_tid);
        self.created.push((native.task_id, tid));
        CreatedTask {
            tid,
            pid: pid(native.linux_pid),
            kind: if native.thread {
                CreatedTaskKind::Thread
            } else {
                CreatedTaskKind::Process
            },
        }
    }
}

impl KernelServices for NarfKernelServices<'_> {
    type Memory = NarfMemory;

    fn tid(&self) -> Pid {
        pid(self.ids.tid)
    }

    fn pid(&self) -> Pid {
        pid(self.ids.pid)
    }

    fn ppid(&self) -> Option<Pid> {
        self.ids.ppid.map(pid)
    }

    fn auxv(&self) -> Auxv {
        Auxv::from_entries(
            tool_view::auxv_pairs(self.ids.pid)
                .into_iter()
                .map(|(key, value)| (key as libc::c_ulong, value as libc::c_ulong)),
        )
    }

    fn memory(&self) -> NarfMemory {
        NarfMemory { _private: () }
    }

    fn regs(&self) -> libc::user_regs_struct {
        let state = self.native.entry_user_state().unwrap_or_default();
        let (rax, orig_rax) = match self.raw_number {
            Some(number) => (ENTRY_RAX, u64::from(number)),
            None => (state.rax, u64::MAX),
        };
        libc::user_regs_struct {
            r15: state.r15,
            r14: state.r14,
            r13: state.r13,
            r12: state.r12,
            rbp: state.rbp,
            rbx: state.rbx,
            r11: state.r11,
            r10: state.r10,
            r9: state.r9,
            r8: state.r8,
            rax,
            rcx: state.rcx,
            rdx: state.rdx,
            rsi: state.rsi,
            rdi: state.rdi,
            orig_rax,
            rip: state.rip,
            cs: USER_CS,
            eflags: state.rflags,
            rsp: state.rsp,
            ss: USER_SS,
            fs_base: 0,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        }
    }

    fn execute_original(&mut self) -> Result<NarfSyscallOutcome, OriginalSyscallError> {
        self.native
            .execute_original()
            .map(map_native_outcome)
            .map_err(|error| match error {
                NativeSyscallOriginalError::AlreadyExecuted => {
                    OriginalSyscallError::AlreadyExecuted
                }
                NativeSyscallOriginalError::ContextManaged => OriginalSyscallError::ContextManaged,
            })
    }

    fn execute_injected(&mut self, request: NarfSyscallRequest) -> NarfSyscallOutcome {
        map_native_outcome(self.native.execute_injected(NativeSyscallRequest::new(
            request.number,
            args_of(request.args),
        )))
    }

    fn take_created_task(&mut self) -> Option<CreatedTask> {
        let native = self.native.take_created_task()?;
        Some(self.created_task(native))
    }

    fn daemonize(&mut self) -> Result<(), Errno> {
        // Narf has no daemonize transition yet; the core turns this into a
        // named fatal error rather than pretending the task detached.
        Err(Errno::ENOSYS)
    }
}
