//! narf-userspace — process model, ELF loader shapes, relibc hand-off.
//!
//! Spec: `userspace/specification/spec.md` (Stage-4 primary
//! crate). The real end-to-end Stage-4 exit gate ("run a standard
//! Rust binary compiled against relibc") needs:
//!
//! - An ELF64 loader that places PT_LOAD segments, resolves
//!   relocations (RX_64 / GLOB_DAT / JUMP_SLOT), and sets up the
//!   auxiliary vector + argv / envp on the new process's stack.
//! - An address-space abstraction distinct from the kernel's
//!   high-half: `memory/` needs per-process page tables with
//!   user-mode mappings.
//! - A relibc build linked against our `abi/` submission surface —
//!   relibc's entry points become `abi::submit(OpCode::…)`.
//! - A syscall trap that enters the kernel, consults the
//!   per-task cap table, and reflects the submission as a
//!   ring entry.
//!
//! What lands *here* at this Stage-4 first-pass stage:
//!
//! - `ProcessId` / `ThreadId` — monotonic identifiers.
//! - `ExecImage` — in-memory description of a loaded executable
//!   (file-type + entry point + segment list). The loader fills it
//!   in; the scheduler consumes it to spawn the first thread.
//! - `AuxVector` — the `AT_*` key/value table the dynamic loader
//!   expects on the stack.
//! - `Process` cap-type.
//!
//! No actual loader body yet — that's a separate substantial piece
//! of work that needs the address-space + syscall-entry pieces
//! above. The shapes here will drive those implementations.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod elf;
pub mod fd;
pub mod handlers;
pub mod interp;
pub mod loader;
pub mod pipe;
pub mod process;
pub mod syscall;
#[cfg(target_arch = "x86_64")]
pub mod tls;
pub mod user_task;

pub use interp::{lookup_interpreter, register_interpreter};

pub use fd::{FdEntry, FdTable, FD_CLOEXEC};

pub use handlers::StatBuf;
pub use pipe::{pipe_pair, PipeRead, PipeWrite};

pub use elf::{parse as parse_elf, ElfError};
pub use handlers::{
    abi_file_op_bridge, bootstrap_init, bootstrap_live_count, brk_init,
    clear_exit_landing, cwd_init, cwd_of, default_signal_delivery,
    default_sync_signal_delivery, install_address_space_lookup,
    install_core_syscalls, install_signal_delivery_hook,
    install_sync_signal_hook, install_task_id_lookup, set_exit_landing,
    shared_rings_for, sigaction_init, sigaction_lookup,
    signal_delivery_hook, signal_init, signal_mask_of, signal_pending_of,
    spawn_dispatcher_for, sync_signal_hook, take_kernel_ends,
    hostname_init, nice_init, rlimit_init, take_user_ends, uidgid_init,
    umask_init, vector_to_signum, SharedRingPair, TaskRings, UserRingEnds,
    BOOTSTRAP_SHARED_RING_DEPTH,
};
pub use user_task::{
    clear_current as clear_current_user_task, current_user_task,
    install_current as install_current_user_task, install_exit_hook,
    install_user_task_hooks, install_yield_hook, TaskState, UserExit,
    UserTaskCtx, UserTaskFuture, EXIT_REASON_EXITED, EXIT_REASON_YIELDED,
};
pub use loader::{
    apply_relocations, load_elf_bytes, load_elf_into_at, load_into,
    EntryPoint, LoadBytesError, LoadError,
};
pub use process::{
    init_sysv_stack, load_user_process, load_user_process_with,
    ProcessLoadError, SysVStackError, UserProcess,
    DEFAULT_USER_STACK_BASE, DEFAULT_USER_STACK_BYTES,
};
#[cfg(target_arch = "x86_64")]
pub use tls::{stage_tls, TlsError, TLS_REGION_BASE};
pub use syscall::{
    install_global, kernel_syscall_entry, kernel_syscall_entry_plain,
    FnHandler, RawFnHandler, RawSyscallHandler, Syscall, SyscallArgs,
    SyscallEntry, SyscallHandler, SyscallReturn, SyscallTable, TrapContext,
};

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_capabilities::{CapKind, CapType};

// ── Identifiers ─────────────────────────────────────────────────────

/// Monotonic process id. `0` is reserved (kernel itself).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(pub u64);

impl ProcessId {
    pub const KERNEL: ProcessId = ProcessId(0);
    #[inline] pub const fn raw(self) -> u64 { self.0 }
}

/// Monotonic thread id scoped per process.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub u64);

impl ThreadId {
    #[inline] pub const fn raw(self) -> u64 { self.0 }
}

static NEXT_PID: AtomicU64 = AtomicU64::new(1);

/// Allocate a fresh `ProcessId`. Wraps are structurally impossible on
/// a u64 at realistic exec rates.
#[inline]
pub fn alloc_pid() -> ProcessId {
    ProcessId(NEXT_PID.fetch_add(1, Ordering::Relaxed))
}

// ── Cap types ───────────────────────────────────────────────────────

/// `Cap<Process, R>` — authorises cross-process operations
/// (send-signal, wait, readmem — once those land). `Cap<Process,
/// Grant>` is mint-able by the spawner at exec time.
#[derive(Copy, Clone, Debug)]
pub struct Process;

impl CapType for Process {
    const KIND: CapKind = CapKind::Process;
}

// ── Exec image ──────────────────────────────────────────────────────

/// Kind of executable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ExecKind {
    Elf64Exec,
    Elf64Dyn,
}

/// A single loadable segment in the final address space.
#[derive(Copy, Clone, Debug)]
pub struct Segment {
    pub vaddr:      u64,
    pub file_off:   u64,
    pub file_size:  u64,
    pub mem_size:   u64,
    pub flags:      SegmentFlags,
}

/// Segment access flags. `repr(transparent)` over u32 — bits match
/// the ELF PF_* values so the loader doesn't need a translation
/// step.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SegmentFlags(pub u32);

impl SegmentFlags {
    pub const EXEC:  SegmentFlags = SegmentFlags(1 << 0);  // PF_X
    pub const WRITE: SegmentFlags = SegmentFlags(1 << 1);  // PF_W
    pub const READ:  SegmentFlags = SegmentFlags(1 << 2);  // PF_R

    #[inline] pub const fn contains(self, o: SegmentFlags) -> bool { self.0 & o.0 == o.0 }
}

impl core::ops::BitOr for SegmentFlags {
    type Output = SegmentFlags;
    fn bitor(self, rhs: SegmentFlags) -> Self { SegmentFlags(self.0 | rhs.0) }
}

/// Description of an ELF's PT_TLS segment — the template the
/// kernel uses to allocate a per-thread TLS block before
/// `iretq` to user mode. Field meanings match the ELF spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsTemplate {
    /// File-relative offset of the TLS image bytes (the
    /// initial-image part of the per-thread block).
    pub file_off:  u64,
    /// Bytes of initial image to copy into a fresh TLS block.
    pub file_size: u64,
    /// Total per-thread TLS block size; bytes past `file_size`
    /// are the BSS-style zero-fill.
    pub mem_size:  u64,
    /// Required alignment for the TLS block. Always a power of two.
    pub align:     u64,
    /// Linker-time vaddr of the TLS template within the binary.
    /// The dynamic loader uses this to compute thread-pointer
    /// offsets for the initial-exec model.
    pub vaddr:     u64,
}

/// One PT_DYNAMIC table entry — the file-format `Elf64_Dyn`
/// shape. Tags are signed (DT_* spec), values either pointer-typed
/// or scalar — we preserve the raw 64-bit bit pattern so
/// downstream consumers (the relocation processor) can re-interpret
/// per-tag without us baking in tag semantics here.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DynEntry {
    pub tag: i64,
    pub val: u64,
}

/// In-memory description of a loaded program.
#[derive(Clone, Debug)]
pub struct ExecImage {
    pub kind:       ExecKind,
    pub entry:      u64,
    pub interp:     Option<String>,
    pub segments:   Vec<Segment>,
    /// PT_DYNAMIC entries (DT_* tag/value pairs), empty for an ELF
    /// without a PT_DYNAMIC program header. The DT_NULL terminator
    /// is stripped — what's left is what the loader actually walks.
    pub dynamic:    Vec<DynEntry>,
    /// PT_TLS template if the ELF has one. The loader uses this in a
    /// follow-up round to allocate the per-thread TLS block and program
    /// `IA32_FS_BASE` for the initial-exec model. None means the binary
    /// does not use thread-local storage (or only has dynamic-TLS through
    /// the loader's own TCB, which is described via DT_* tags rather
    /// than PT_TLS).
    pub tls:        Option<TlsTemplate>,
    pub argv:       Vec<String>,
    pub envp:       Vec<String>,
    pub aux:        Vec<AuxEntry>,
}

impl ExecImage {
    pub fn empty(kind: ExecKind) -> Self {
        Self {
            kind, entry: 0, interp: None,
            segments: Vec::new(), dynamic: Vec::new(),
            tls: None,
            argv: Vec::new(), envp: Vec::new(),
            aux: Vec::new(),
        }
    }
}

// ── Auxiliary vector ────────────────────────────────────────────────
//
// The dynamic loader consumes `AT_*` entries right after argv/envp
// on the new stack. We carry the subset relibc needs at startup.

/// Auxiliary-vector entry — matches `<elf.h>` shapes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuxEntry {
    /// End of the aux vector. The loader stops reading here.
    Null,
    /// Program entry point.
    Entry(u64),
    /// Program-header table address.
    Phdr(u64),
    /// Size of a program-header entry.
    PhEnt(u32),
    /// Number of program-header entries.
    PhNum(u32),
    /// Base address of the interpreter.
    Base(u64),
    /// Executable's own file address.
    ExecFn(u64),
    /// System page size.
    Pagesz(u32),
    /// Hardware-feature bitmap (arch-dependent).
    Hwcap(u64),
    /// Address of a 16-byte random buffer relibc uses for
    /// stack-cookie / ASLR entropy.
    Random(u64),
    /// Secure-execution flag (set-uid / set-gid context).
    Secure(bool),
}

impl AuxEntry {
    /// Raw aux-vector tag — matches the `<elf.h>` `AT_*` numbers so
    /// the kernel and relibc agree on the wire tag.
    pub const fn tag(&self) -> u32 {
        match self {
            AuxEntry::Null       => 0,
            AuxEntry::Entry(_)   => 9,
            AuxEntry::Phdr(_)    => 3,
            AuxEntry::PhEnt(_)   => 4,
            AuxEntry::PhNum(_)   => 5,
            AuxEntry::Base(_)    => 7,
            AuxEntry::ExecFn(_)  => 31,
            AuxEntry::Pagesz(_)  => 6,
            AuxEntry::Hwcap(_)   => 16,
            AuxEntry::Random(_)  => 25,
            AuxEntry::Secure(_)  => 23,
        }
    }
}
