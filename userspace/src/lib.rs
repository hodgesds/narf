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
#![feature(allocator_api)]
#![feature(generic_const_exprs)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![allow(incomplete_features)] // generic_const_exprs

extern crate alloc;

#[cfg(feature = "container")]
pub mod container;
pub mod linux_compat;

pub mod anon_reclaim;
pub(crate) mod bpf_iter;
pub mod coredump;
pub mod elf;
pub mod ephemeral_port;
pub mod epoll;
pub mod errno;
pub mod fd;
pub mod handlers;
pub mod hwcap;
pub mod init;
pub mod interp;
pub mod io_mux;
pub mod keyring;
pub mod landlock;
pub mod loader;
pub mod lsm;
mod mapped_file;
pub mod migrate;
pub mod mount_api;
pub mod mqueue;
#[cfg(feature = "container")]
pub mod namespaces;
pub mod network_daemon;
pub mod oom;
pub mod perf_event;
pub mod pid_idr;
#[cfg(feature = "container")]
pub mod pid_ns;
pub mod pidfd;
pub mod pipe;
pub mod poll;
pub mod posix_timer;
pub mod process;
pub mod ptrace;
pub mod select;
pub mod socket;
pub mod syscall;
pub mod sysvipc;
pub mod task;

/// `/proc/sys/kernel/{sem,msgmax,msgmnb,msgmni,shmmax,shmall,shmmni,
/// shm_rmid_forced}` — read one key of the calling task's IPC namespace
/// limits. Procfs passes the key index so it holds one hook pair, not eight.
pub fn proc_ipc_limit_read(key: u8) -> alloc::string::String {
    match sysvipc::IpcSysctl::from_index(key) {
        Some(key) => sysvipc::sysctl_read(key),
        None => alloc::string::String::new(),
    }
}

/// Apply a write to one IPC limit key, with the errno Linux's `ctl_table`
/// handler would report for a malformed or out-of-range value.
pub fn proc_ipc_limit_write(key: u8, value: &str) -> Result<(), narf_filesystem::FsError> {
    let Some(key) = sysvipc::IpcSysctl::from_index(key) else {
        return Err(narf_filesystem::FsError::InvalidData);
    };
    sysvipc::sysctl_write(key, value).map_err(|_| narf_filesystem::FsError::InvalidData)
}

/// `/proc/sysvipc/{sem,msg,shm}` rows for the reader's IPC namespace
/// (`0` = sem, `1` = msg, `2` = shm). One entry point so procfs holds one
/// hook rather than three.
pub fn proc_sysvipc_table(kind: u8) -> alloc::string::String {
    match kind {
        0 => sysvipc::proc_sysvipc_sem(),
        1 => sysvipc::proc_sysvipc_msg(),
        2 => handlers::proc_sysvipc_shm(),
        _ => alloc::string::String::new(),
    }
}

// TLS staging is arch-neutral now: `tls::block_displacement_from_tp` encodes
// the variant (block below the thread pointer on x86_64, above the reserved
// TCB words on aarch64) and `stage_tls` lays the block out accordingly.
pub mod tls;
pub mod user_task;
pub mod vdso;
pub mod xdp_socket;

mod abi_aio_tests;
mod abi_async_tests;
mod abi_bpf_btf_tests;
mod abi_bpf_tests;
mod abi_creds_tests;
mod abi_drm_prime_tests;
mod abi_fdio2_tests;
mod abi_fdio_tests;
mod abi_filemap_tests;
mod abi_fsx2_tests;
mod abi_fsx_tests;
mod abi_futex_tests;
mod abi_inode_identity_tests;
mod abi_ioerrno_tests;
mod abi_ipc_tests;
mod abi_mem2_tests;
mod abi_mem_tests;
mod abi_misc_tests;
mod abi_packet_tests;
mod abi_path_tests;
mod abi_pathx_tests;
mod abi_perf_tests;
mod abi_pid_alloc_tests;
mod abi_pidns_tests;
mod abi_proc2_tests;
mod abi_proc_tests;
mod abi_remount_tests;
mod abi_sched_tests;
mod abi_signal_tests;
mod abi_socket_errno_tests;
mod abi_socket_tests;
mod abi_sound_tests;
mod abi_test_support;
mod abi_tests;
mod abi_thp_tests;
mod abi_tid_lookup_tests;
mod abi_time_tests;
mod abi_uaccess_tests;
mod abi_udev_protocol_tests;
mod abi_udp_tests;
mod abi_vconsole_tests;
mod mount_e2e_tests;
mod process_e2e_tests;
mod shell_e2e_tests;
mod tests;

pub use interp::{lookup_interpreter, register_interpreter};

pub use fd::{FdEntry, FdTable, FD_CLOEXEC};

pub use handlers::StatBuf;
pub use pipe::{pipe_pair, PipeRead, PipeWrite};

/// Retire file-backed VMA ownership after memory has invalidated the last
/// translations belonging to an address space.
pub fn drop_mapped_file_address_space(address_space_id: u64) {
    mapped_file::drop_address_space(address_space_id);
    // `mseal` seals are keyed by the same identity. An entry that outlived
    // its address space would seal whatever a later one happened to map at
    // the same addresses.
    handlers::drop_address_space_seals(address_space_id);
    // `mbind` range policies are keyed by the same identity, for the same
    // reason: they belong to the mm, so they are retired when it dies rather
    // than when whichever thread called `mbind` exits.
    handlers::drop_address_space_mbind_ranges(address_space_id);
    // The NUMA scan cursor is address-space state for the same reason the
    // range policies are, so it dies with the address space too.
    handlers::drop_address_space_numa_cursor(address_space_id);
}

/// Filesystem truncation bridge installed during common boot init.
pub use mapped_file::truncate_file_mappings;

pub use elf::{parse as parse_elf, ElfError};
pub use handlers::{
    abi_file_op_bridge, active_user_as, address_space_lookup, bootstrap_init, bootstrap_live_count,
    clear_exit_landing, clear_mempolicy_for_fault, cwd_init, cwd_of, default_signal_delivery,
    default_sync_signal_delivery, delegate_stack_admin_to_generic_socket,
    delegate_stack_admin_to_route_socket, exit_landing, hostname_init, init_per_task_state,
    install_address_space_for_task_lookup, install_address_space_lookup,
    install_all_address_spaces_lookup, install_core_syscalls, install_signal_delivery_hook,
    install_sync_signal_hook, install_task_id_lookup, nice_init, pgid_init, prctl_init,
    publish_mempolicy_for_fault, release_external_shared_frame, restore_address_space_lookup,
    retain_external_shared_frame, rlimit_init, sched_param_init, set_exit_landing,
    shared_rings_for, sid_init, sigaction_init, sigaction_lookup, signal_delivery_hook,
    signal_init, signal_mask_of, signal_pending_of, spawn_dispatcher_for, sync_signal_hook,
    take_kernel_ends, take_user_ends, uidgid_init, umask_init, vector_to_signum, SharedRingPair,
    SyncFaultInfo, TaskRings, UserRingEnds, BOOTSTRAP_SHARED_RING_DEPTH,
};
pub use loader::{
    apply_relocations, load_elf_bytes, load_elf_into_at, load_into, EntryPoint, LoadBytesError,
    LoadError,
};
pub use process::{
    init_sysv_stack, load_user_process, load_user_process_with, load_user_process_with_root,
    load_user_process_with_root_file, ProcessLoadError, SysVStackError, UserProcess,
    DEFAULT_USER_STACK_BASE, DEFAULT_USER_STACK_BYTES, DEFAULT_USER_STACK_RESERVED,
    DEFAULT_USER_STACK_TOP,
};
pub use syscall::{
    install_global, kernel_syscall_entry, kernel_syscall_entry_plain,
    kernel_syscall_entry_plain_with_state, syscall_number, syscall_pack, syscall_version,
    FnHandler, RawFnHandler, RawSyscallHandler, SigDeliveryParams, Syscall, SyscallArgs,
    SyscallEntry, SyscallHandler, SyscallReturn, SyscallTable, TrapContext, SA_NODEFER, SA_ONSTACK,
    SA_RESETHAND, SA_RESTART, SA_SIGINFO, SYS_NUMBER_MASK, SYS_VERSION_MASK, SYS_VERSION_SHIFT,
};
pub use tls::{stage_tls, TlsError, TLS_REGION_BASE};
pub use user_task::{
    clear_current as clear_current_user_task, current_user_task,
    install_current as install_current_user_task, install_exit_hook, install_user_task_hooks,
    install_yield_hook, TaskState, UserExit, UserTaskCtx, UserTaskFuture, EXIT_REASON_EXITED,
    EXIT_REASON_YIELDED,
};

use alloc::string::String;
use alloc::vec::Vec;

use narf_capabilities::{CapKind, CapType};

use narf_lib::sync::IrqSafeSpinLock;

// ── Identifiers ─────────────────────────────────────────────────────

/// Linux-visible process id. Allocated cyclically and reused after wrap;
/// `0` is reserved for the kernel.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(pub u64);

impl ProcessId {
    pub const KERNEL: ProcessId = ProcessId(0);
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Monotonic thread id scoped per process.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThreadId(pub u64);

impl ThreadId {
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

// ── PID allocation (root pid namespace) ─────────────────────────────
//
// Linux allocates pids cyclically per namespace (`kernel/pid.c::alloc_pid`
// → `idr_alloc_cyclic`), see [`pid_idr`]. This is the root namespace's
// number space — the outer `ProcessId` every task has. Child pid namespaces
// (`pid_ns`, `container` feature) each keep their own [`pid_idr::PidIdr`].
//
// On `release_pid` the id leaves the in-use set — wired by `on_child_exit`
// in handlers.rs so a `wait4`-reaped child's pid becomes allocatable again,
// but only once the cyclic search comes back round to it.

/// Linux `PID_MAX_DEFAULT` (`include/linux/threads.h`): the boot value of
/// `/proc/sys/kernel/pid_max`. The live bound is [`pid_max`].
pub const PID_MAX: u64 = 32768;

/// Linux `PID_MAX_LIMIT` on 64-bit: the ceiling `pid_max` may be raised to.
pub const PID_MAX_LIMIT: u64 = 4 * 1024 * 1024;

pub use pid_idr::RESERVED_PIDS;

/// The live `pid_max` — `/proc/sys/kernel/pid_max`, an EXCLUSIVE bound: the
/// largest allocatable pid is `pid_max() - 1`, as on Linux.
///
/// LINUX-GAP: Linux (6.14+) keeps `pid_max` per pid namespace
/// (`pidns->pid_max`, inherited from the parent at creation, and the sysctl
/// resolves the caller's namespace). NARF's sysctl is a single global, so
/// every namespace allocates against it. Linux also scales the boot default
/// to `max(PID_MAX_DEFAULT, PIDS_PER_CPU_DEFAULT * num_possible_cpus())`;
/// NARF keeps PID_MAX_DEFAULT, which is the same value up to 32 CPUs.
#[inline]
pub fn pid_max() -> u64 {
    u64::from(narf_filesystem::procfs::sys_kernel::pid_max())
}

/// The root namespace's pid numbers.
static PID_IDR: IrqSafeSpinLock<pid_idr::PidIdr> = IrqSafeSpinLock::new(pid_idr::PidIdr::new());

/// Allocate a fresh `ProcessId` — `alloc_pid`'s cyclic search in the root
/// namespace. Returns `ProcessId(0)` (kernel reserved) when every pid in
/// `[pid_min, pid_max)` is in use — callers report that as -EAGAIN, which is
/// what Linux's `alloc_pid` returns for `idr_alloc_cyclic`'s -ENOSPC.
#[inline]
pub fn alloc_pid() -> ProcessId {
    let pid_max = pid_max();
    match PID_IDR.lock().alloc_cyclic(pid_max) {
        Some(nr) => ProcessId(nr),
        None => ProcessId::KERNEL,
    }
}

/// Reserve a caller-selected PID for clone3(2) `set_tid`.
///
/// Linux (`alloc_pid`): `if (tid < 1 || tid >= pid_max) -EINVAL`, then an
/// exact `idr_alloc(tid, tid + 1)` whose -ENOSPC is reported as -EEXIST. The
/// exact allocation does not move the cyclic cursor.
pub(crate) fn alloc_pid_specific(raw: u64) -> Result<ProcessId, u64> {
    const EEXIST: u64 = 17;
    const EINVAL: u64 = 22;
    if raw == 0 || raw >= pid_max() {
        return Err(EINVAL);
    }
    if PID_IDR.lock().alloc_exact(raw) {
        Ok(ProcessId(raw))
    } else {
        Err(EEXIST)
    }
}

/// Return `pid` to the root namespace (`free_pid` → `idr_remove`).
/// Releasing an id that is not allocated is a no-op; `0` (kernel) and ids
/// beyond `PID_MAX_LIMIT` were never allocatable.
#[inline]
pub fn release_pid(pid: ProcessId) {
    let raw = pid.raw();
    if raw == 0 || raw >= PID_MAX_LIMIT {
        return;
    }
    // Invalidate every pid-KEYED cache before the number becomes
    // re-mintable. `pidfd`'s table is one: it maps pid → shared exit
    // state, and a row left behind hands the next occupant of this pid a
    // state that already says `exited`. See `pidfd::forget_pid`.
    pidfd::forget_pid(raw);
    PID_IDR.lock().remove(raw);
}

/// `/proc/sys/kernel/ns_last_pid` for the root namespace:
/// `idr_get_cursor() - 1`.
pub fn root_ns_last_pid() -> i64 {
    PID_IDR.lock().last_pid()
}

/// `ns_last_pid` write for the root namespace: `idr_set_cursor(last + 1)`.
pub fn set_root_ns_last_pid(last: u64) {
    PID_IDR.lock().set_cursor(last + 1);
}

/// Diagnostic: number of root-namespace pids currently allocated.
pub fn pid_pool_in_use_count() -> usize {
    PID_IDR.lock().in_use()
}

/// `/proc/sys/kernel/ns_last_pid` read, resolved in the caller's ACTIVE pid
/// namespace (`task_active_pid_ns(current)` in `pid_ns_ctl_handler`).
pub fn ns_last_pid_for_current() -> i64 {
    #[cfg(feature = "container")]
    {
        let task = handlers::current_task_id();
        if let Some(ns) = pid_ns::ns_of(task) {
            return ns.last_pid();
        }
    }
    root_ns_last_pid()
}

/// `/proc/sys/kernel/ns_last_pid` write — `pid_ns_ctl_handler`:
///
/// ```c
/// if (write && !checkpoint_restore_ns_capable(pid_ns->user_ns))
///         return -EPERM;
/// next = idr_get_cursor(&pid_ns->idr) - 1;
/// tmp.data = &next;
/// tmp.extra2 = &pid_ns->pid_max;
/// ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
/// if (!ret && write)
///         idr_set_cursor(&pid_ns->idr, next + 1);
/// ```
///
/// The capability check comes first, so an unprivileged write is EPERM
/// whatever it says; the value is then `proc_dointvec_minmax` over
/// `[0, pid_max]` (EINVAL outside it).
pub fn set_ns_last_pid_for_current(v: &str) -> Result<(), narf_filesystem::FsError> {
    let task = handlers::current_task_id();
    #[cfg(feature = "container")]
    let ns = pid_ns::current_pid_ns(task);
    #[cfg(feature = "container")]
    let allowed = {
        let owner = ns.owner_user_ns();
        handlers::task_ns_capable(task, &owner, handlers::CAP_SYS_ADMIN)
            || handlers::task_ns_capable(task, &owner, handlers::CAP_CHECKPOINT_RESTORE)
    };
    #[cfg(not(feature = "container"))]
    let allowed = handlers::task_capable(task, handlers::CAP_SYS_ADMIN)
        || handlers::task_capable(task, handlers::CAP_CHECKPOINT_RESTORE);
    if !allowed {
        return Err(narf_filesystem::FsError::OperationNotPermitted);
    }
    let last =
        narf_filesystem::procfs::sys_kernel::parse_dointvec_minmax(v, 0, pid_max() as i64)? as u64;
    #[cfg(feature = "container")]
    ns.set_last_pid(last);
    #[cfg(not(feature = "container"))]
    set_root_ns_last_pid(last);
    Ok(())
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
    pub vaddr: u64,
    pub file_off: u64,
    pub file_size: u64,
    pub mem_size: u64,
    pub flags: SegmentFlags,
}

/// Segment access flags. `repr(transparent)` over u32 — bits match
/// the ELF PF_* values so the loader doesn't need a translation
/// step.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SegmentFlags(pub u32);

impl SegmentFlags {
    pub const EXEC: SegmentFlags = SegmentFlags(1 << 0); // PF_X
    pub const WRITE: SegmentFlags = SegmentFlags(1 << 1); // PF_W
    pub const READ: SegmentFlags = SegmentFlags(1 << 2); // PF_R

    #[inline]
    pub const fn contains(self, o: SegmentFlags) -> bool {
        self.0 & o.0 == o.0
    }
}

impl core::ops::BitOr for SegmentFlags {
    type Output = SegmentFlags;
    fn bitor(self, rhs: SegmentFlags) -> Self {
        SegmentFlags(self.0 | rhs.0)
    }
}

/// Description of an ELF's PT_TLS segment — the template the
/// kernel uses to allocate a per-thread TLS block before
/// `iretq` to user mode. Field meanings match the ELF spec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsTemplate {
    /// File-relative offset of the TLS image bytes (the
    /// initial-image part of the per-thread block).
    pub file_off: u64,
    /// Bytes of initial image to copy into a fresh TLS block.
    pub file_size: u64,
    /// Total per-thread TLS block size; bytes past `file_size`
    /// are the BSS-style zero-fill.
    pub mem_size: u64,
    /// Required alignment for the TLS block. Always a power of two.
    pub align: u64,
    /// Linker-time vaddr of the TLS template within the binary.
    /// The dynamic loader uses this to compute thread-pointer
    /// offsets for the initial-exec model.
    pub vaddr: u64,
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
/// Hardware-security features a binary declares it was built for, from its
/// `PT_GNU_PROPERTY` note (`NT_GNU_PROPERTY_TYPE_0`).
///
/// These are opt-INs: the toolchain emits them only when every input object
/// carried the matching property, because enforcement breaks code that was not
/// compiled for it. Branch Target Identification faults an indirect branch to
/// an instruction that is not a `BTI` landing pad, so enabling it on a binary
/// built without the landing pads kills it on its first PLT call; the same
/// applies to x86 IBT. A kernel therefore cannot turn these on by policy — it
/// has to read what the binary asked for, which is what this carries.
///
/// Linux reaches the same place through `arch_parse_elf_property` recording
/// into `struct arch_elf_state`, then `arch_elf_adjust_prot` applying it to the
/// binary's executable mappings.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ElfProperties {
    /// aarch64 `GNU_PROPERTY_AARCH64_FEATURE_1_BTI`: the binary's indirect
    /// branch targets carry `BTI` landing pads, so its executable pages may be
    /// mapped with the guarded (`GP`) attribute.
    pub aarch64_bti: bool,
    /// aarch64 `..._FEATURE_1_PAC`: built with pointer authentication.
    /// Recorded for `/proc` and for a future PAC enablement pass; the kernel
    /// does not gate anything on it today.
    pub aarch64_pac: bool,
    /// aarch64 `..._FEATURE_1_MTE`: built for Memory Tagging.
    pub aarch64_mte: bool,
    /// x86 `GNU_PROPERTY_X86_FEATURE_1_IBT`: built for Indirect Branch
    /// Tracking (part of CET).
    pub x86_ibt: bool,
    /// x86 `GNU_PROPERTY_X86_FEATURE_1_SHSTK`: built for the shadow stack.
    pub x86_shstk: bool,
}

#[derive(Clone, Debug)]
pub struct ExecImage {
    pub kind: ExecKind,
    pub entry: u64,
    pub interp: Option<String>,
    pub segments: Vec<Segment>,
    /// PT_DYNAMIC entries (DT_* tag/value pairs), empty for an ELF
    /// without a PT_DYNAMIC program header. The DT_NULL terminator
    /// is stripped — what's left is what the loader actually walks.
    pub dynamic: Vec<DynEntry>,
    /// PT_TLS template if the ELF has one. The loader uses this in a
    /// follow-up round to allocate the per-thread TLS block and program
    /// `IA32_FS_BASE` for the initial-exec model. None means the binary
    /// does not use thread-local storage (or only has dynamic-TLS through
    /// the loader's own TCB, which is described via DT_* tags rather
    /// than PT_TLS).
    pub tls: Option<TlsTemplate>,
    pub stack_flags: Option<SegmentFlags>,
    /// Link-time virtual address of the program-header table, taken
    /// from the `PT_PHDR` program header when the ELF carries one.
    /// `None` when there is no `PT_PHDR` (rare — hand-written or
    /// fully-static ELFs may omit it). The loader biases this by the
    /// load base to compute `AT_PHDR`, which is the authoritative,
    /// PT_LOAD-order-independent source a self-relocating ET_DYN
    /// (static-PIE glibc / musl `rcrt1`) reads to derive its load
    /// bias (`l_addr = AT_PHDR - PT_PHDR.p_vaddr`). See the AT_PHDR
    /// construction in `process::load_user_process_with`.
    pub phdr_vaddr: Option<u64>,
    /// Parsed `PT_GNU_PROPERTY` contents. All-false when the binary carries no
    /// property note, which is the common case for anything not built with the
    /// relevant `-z` flags.
    pub properties: ElfProperties,
    /// The largest power-of-two `p_align` across the image's `PT_LOAD` headers,
    /// never below the page size.
    ///
    /// A toolchain asks for 2 MiB here when it wants the segment eligible for a
    /// huge mapping; honouring it is what lets program text land on a boundary
    /// the hardware can back with one entry. Linux computes the same value in
    /// `maximum_alignment()` and aligns the ET_DYN base to it, skipping
    /// non-power-of-two values as malformed.
    pub max_align: u64,
    pub argv: Vec<String>,
    pub envp: Vec<String>,
    pub aux: Vec<AuxEntry>,
}

impl ExecImage {
    pub fn empty(kind: ExecKind) -> Self {
        Self {
            kind,
            entry: 0,
            interp: None,
            segments: Vec::new(),
            dynamic: Vec::new(),
            tls: None,
            stack_flags: None,
            phdr_vaddr: None,
            properties: ElfProperties::default(),
            // An empty image declares no alignment beyond the page size.
            max_align: 4096,
            argv: Vec::new(),
            envp: Vec::new(),
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
    /// Real user ID (`AT_UID` = 11).
    Uid(u32),
    /// Effective user ID (`AT_EUID` = 12).
    Euid(u32),
    /// Real group ID (`AT_GID` = 13).
    Gid(u32),
    /// Effective group ID (`AT_EGID` = 14).
    Egid(u32),
    /// Base address of the vDSO ELF header (`AT_SYSINFO_EHDR` = 33). libc
    /// parses the vDSO from here to resolve `__vdso_*` / `__kernel_*`.
    SysInfoEhdr(u64),
    /// AT_CLKTCK — `times()` tick rate. glibc's `sysconf(_SC_CLK_TCK)`
    /// reads this; without it libc falls back to a compiled-in 100, which
    /// is right today only by coincidence.
    Clktck(u64),
    /// AT_FLAGS — Linux always emits this (as 0 on x86_64/aarch64).
    Flags(u64),
    /// AT_HWCAP2 — second CPU-capability word. 0 until NARF advertises
    /// any of the bits it gates.
    Hwcap2(u64),
    /// AT_MINSIGSTKSZ — the smallest usable `sigaltstack` size, which
    /// glibc uses for its dynamic MINSIGSTKSZ/SIGSTKSZ.
    MinSigStkSz(u64),
}

impl AuxEntry {
    /// Raw aux-vector tag — matches the `<elf.h>` `AT_*` numbers so
    /// the kernel and relibc agree on the wire tag.
    pub const fn tag(&self) -> u32 {
        match self {
            AuxEntry::Null => 0,
            AuxEntry::Entry(_) => 9,
            AuxEntry::Phdr(_) => 3,
            AuxEntry::PhEnt(_) => 4,
            AuxEntry::PhNum(_) => 5,
            AuxEntry::Base(_) => 7,
            AuxEntry::ExecFn(_) => 31,
            AuxEntry::Pagesz(_) => 6,
            AuxEntry::Hwcap(_) => 16,
            AuxEntry::Random(_) => 25,
            AuxEntry::Secure(_) => 23,
            AuxEntry::Uid(_) => 11,
            AuxEntry::Euid(_) => 12,
            AuxEntry::Gid(_) => 13,
            AuxEntry::Egid(_) => 14,
            AuxEntry::SysInfoEhdr(_) => 33,
            AuxEntry::Flags(_) => 8,
            AuxEntry::Clktck(_) => 17,
            AuxEntry::Hwcap2(_) => 26,
            AuxEntry::MinSigStkSz(_) => 51,
        }
    }
}
