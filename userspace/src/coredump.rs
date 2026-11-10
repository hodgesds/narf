//! Userspace ELF coredump generator.

use crate::handlers::{poll_blocking, resolve_cwd_path, resolve_parent_dir_async};
#[cfg(target_arch = "x86_64")]
use crate::user_task::with_user_task_ctx;
use crate::user_task::UserState;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use narf_filesystem::{FileOps, FsError};
use narf_memory::PhysAddr;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct Elf64_Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct Elf64_Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
struct Elf64_Nhdr {
    n_namesz: u32,
    n_descsz: u32,
    n_type: u32,
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct user_regs_struct {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct user_regs_struct {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct user_regs_struct {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

fn align_up(val: u64) -> u64 {
    (val + 4095) & !4095
}

fn metadata_offsets(headers: usize, notes: usize) -> (u64, u64, u64) {
    // ELF permits notes before the program-header table. A real greeter
    // dump stopped during that table (822/853 headers), losing every
    // register and identity note. Keep those at the beginning instead.
    let note_offset = core::mem::size_of::<Elf64_Ehdr>() as u64;
    let phoff = (note_offset + notes as u64 + 7) & !7;
    let end = phoff + core::mem::size_of::<Elf64_Phdr>() as u64 * headers as u64;
    (phoff, note_offset, align_up(end))
}

unsafe fn slice_from_ref<T>(val: &T) -> &[u8] {
    // SAFETY: caller must ensure val is safe to read.
    unsafe { core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>()) }
}

#[derive(Debug, PartialEq, Eq)]
enum DumpWriteError {
    Killed,
    Filesystem(FsError),
    Unavailable,
}

type OwnedDumpWrite = Pin<Box<dyn Future<Output = Result<usize, FsError>> + Send>>;

fn dump_interrupted(task: u64) -> bool {
    // Linux fs/coredump.c::dump_interrupted: SIGKILL aborts a core dump.
    crate::handlers::task_fatal_signal_pending(task)
}

fn drain_dump_write(write: OwnedDumpWrite) {
    // A pending filesystem write may own DMA or transaction resources. Keep
    // its owned file and buffer alive until terminal completion; this task
    // never refers to the dying process's address space or borrowed memory.
    narf_scheduler::spawn(async move {
        let _ = write.await;
    });
}

/// One already-authorized file write, with a SIGKILL wake independent of
/// filesystem progress. At most this one operation survives cancellation.
struct DumpWrite {
    task: u64,
    write: Option<OwnedDumpWrite>,
    started: bool,
    drain: fn(OwnedDumpWrite),
}

impl Future for DumpWrite {
    type Output = Result<usize, DumpWriteError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        // Register before checking SIGKILL or polling I/O. A never-waking
        // filesystem future must not strand the process during shutdown.
        crate::handlers::register_signal_waker(this.task, cx.waker().clone());
        if dump_interrupted(this.task) {
            return Poll::Ready(Err(DumpWriteError::Killed));
        }
        this.started = true;
        match this
            .write
            .as_mut()
            .expect("live core write")
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(result) => {
                this.write = None;
                Poll::Ready(result.map_err(DumpWriteError::Filesystem))
            }
            Poll::Pending if dump_interrupted(this.task) => {
                Poll::Ready(Err(DumpWriteError::Killed))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DumpWrite {
    fn drop(&mut self) {
        crate::handlers::drop_signal_waker(self.task);
        if let Some(write) = self.write.take() {
            if self.started {
                // Called after poll returns, without a registry/driver lock.
                // Re-polling in the drain task installs its own I/O waker.
                (self.drain)(write);
            }
        }
    }
}

/// Emit `buf` at `offset`, clipped to the RLIMIT_CORE ceiling.
///
/// `fs/coredump.c::__dump_emit` stops writing once `cprm->written + nr`
/// would exceed `cprm->limit`, so an over-large dump is TRUNCATED rather
/// than abandoned — a partial core still identifies the faulting frame,
/// which is the whole reason to set a non-zero limit instead of zero. This
/// writer addresses the file by absolute offset rather than sequentially,
/// so the equivalent test is on the end of the range.
fn write_at(
    task: u64,
    file: Arc<dyn FileOps>,
    limit: u64,
    offset: u64,
    buf: &[u8],
) -> Result<(), DumpWriteError> {
    if offset >= limit {
        return Ok(());
    }
    let room = (limit - offset) as usize;
    let buf = if buf.len() > room { &buf[..room] } else { buf };
    let mut written = 0;
    while written < buf.len() {
        if dump_interrupted(task) {
            return Err(DumpWriteError::Killed);
        }
        // Bound even the metadata operation. Payload is copied before the
        // async write so cancellation can release the process's RAM safely.
        let chunk = &buf[written..buf.len().min(written + 64 * 1024)];
        let bytes = chunk.to_vec();
        let target = file.clone();
        let at = offset + written as u64;
        let write = DumpWrite {
            task,
            write: Some(Box::pin(async move { target.write(at, &bytes).await })),
            started: false,
            drain: drain_dump_write,
        };
        let n = match poll_blocking(write) {
            Some(result) => result?,
            None => return Err(DumpWriteError::Unavailable),
        };
        if n == 0 || n > chunk.len() {
            return Err(DumpWriteError::Filesystem(FsError::InvalidData));
        }
        written += n;
    }
    Ok(())
}

fn write_metadata(
    task: u64,
    file: Arc<dyn FileOps>,
    limit: u64,
    ehdr: &Elf64_Ehdr,
    phdrs: &[Elf64_Phdr],
    notes: &[u8],
) -> Result<(), DumpWriteError> {
    let stride = core::mem::size_of::<Elf64_Phdr>();
    let end = ehdr.e_phoff as usize + core::mem::size_of_val(phdrs);
    let mut bytes = alloc::vec![0; end];
    // SAFETY: these initialized ELF records have their declared C layouts.
    let header = unsafe { slice_from_ref(ehdr) };
    bytes[..header.len()].copy_from_slice(header);
    let note_at = phdrs[0].p_offset as usize;
    bytes[note_at..note_at + notes.len()].copy_from_slice(notes);
    for (i, phdr) in phdrs.iter().enumerate() {
        let start = ehdr.e_phoff as usize + i * stride;
        // SAFETY: same initialized ELF record layout.
        bytes[start..start + stride].copy_from_slice(unsafe { slice_from_ref(phdr) });
    }
    // Sequential bounded writes rather than a small write per VMA.
    // A short/interrupted write retains the notes before the large table.
    write_at(task, file, limit, 0, &bytes)
}

/// `struct elf_prpsinfo` — the note that tells a debugger *which* process this
/// core belongs to. Without it `gdb` opens a core with registers and memory but
/// no program name or command line.
#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) struct ElfPrpsinfo {
    pr_state: u8,
    pr_sname: u8,
    pr_zomb: u8,
    pr_nice: i8,
    pr_flag: u64,
    pr_uid: u32,
    pr_gid: u32,
    pr_pid: i32,
    pr_ppid: i32,
    pr_pgrp: i32,
    pr_sid: i32,
    /// Short name, `comm`-style, NUL-padded.
    pr_fname: [u8; 16],
    /// The command line, space-separated and NUL-padded — Linux fills this
    /// from the first 80 bytes of the process's argv area.
    pr_psargs: [u8; 80],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct ElfSiginfo {
    pub(crate) si_signo: i32,
    pub(crate) si_code: i32,
    pub(crate) si_errno: i32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct ElfTimeval {
    pub(crate) tv_sec: i64,
    pub(crate) tv_usec: i64,
}

/// Linux `struct elf_prstatus` for `NT_PRSTATUS` (note type 1).
/// 336 bytes on x86_64, with `pr_reg` at offset 112.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub(crate) struct ElfPrstatus {
    pub(crate) pr_info: ElfSiginfo,
    pub(crate) pr_cursig: i16,
    pub(crate) _pad0: [u8; 2],
    pub(crate) pr_sigpend: u64,
    pub(crate) pr_sighold: u64,
    pub(crate) pr_pid: i32,
    pub(crate) pr_ppid: i32,
    pub(crate) pr_pgrp: i32,
    pub(crate) pr_sid: i32,
    pub(crate) pr_utime: ElfTimeval,
    pub(crate) pr_stime: ElfTimeval,
    pub(crate) pr_cutime: ElfTimeval,
    pub(crate) pr_cstime: ElfTimeval,
    pub(crate) pr_reg: user_regs_struct,
    pub(crate) pr_fpvalid: i32,
    pub(crate) _pad1: i32,
}

impl Default for ElfPrstatus {
    fn default() -> Self {
        Self {
            pr_info: ElfSiginfo::default(),
            pr_cursig: 0,
            _pad0: [0; 2],
            pr_sigpend: 0,
            pr_sighold: 0,
            pr_pid: 0,
            pr_ppid: 0,
            pr_pgrp: 0,
            pr_sid: 0,
            pr_utime: ElfTimeval::default(),
            pr_stime: ElfTimeval::default(),
            pr_cutime: ElfTimeval::default(),
            pr_cstime: ElfTimeval::default(),
            pr_reg: user_regs_struct::default(),
            pr_fpvalid: 1,
            _pad1: 0,
        }
    }
}

impl Default for ElfPrpsinfo {
    fn default() -> Self {
        Self {
            pr_state: 0,
            pr_sname: 0,
            pr_zomb: 0,
            pr_nice: 0,
            pr_flag: 0,
            pr_uid: 0,
            pr_gid: 0,
            pr_pid: 0,
            pr_ppid: 0,
            pr_pgrp: 0,
            pr_sid: 0,
            pr_fname: [0; 16],
            pr_psargs: [0; 80],
        }
    }
}

/// Test-only: a prpsinfo carrying just a pid and a short name, so the note
/// format can be exercised without the /proc plumbing.
#[doc(hidden)]
pub(crate) fn __test_prpsinfo(pid: i32, name: &[u8]) -> ElfPrpsinfo {
    let mut info = ElfPrpsinfo {
        pr_pid: pid,
        ..ElfPrpsinfo::default()
    };
    let take = core::cmp::min(name.len(), info.pr_fname.len() - 1);
    info.pr_fname[..take].copy_from_slice(&name[..take]);
    info
}

/// Append one ELF note: header, name padded to 4, descriptor padded to 4.
///
/// `n_namesz` counts the terminating NUL (a "CORE" note declares 5), and both
/// the name and the descriptor are padded to a 4-byte boundary. Getting this
/// wrong does not fail loudly — a debugger walking the segment simply lands
/// mid-header on the next note and stops reading, silently dropping every note
/// after the malformed one.
fn push_note(buf: &mut Vec<u8>, name: &[u8], n_type: u32, desc: &[u8]) {
    let namesz = name.len() as u32 + 1;
    let nhdr = Elf64_Nhdr {
        n_namesz: namesz,
        n_descsz: desc.len() as u32,
        n_type,
    };
    // SAFETY: `nhdr` is a live local of exactly this size with no padding
    // beyond its three u32 fields.
    buf.extend_from_slice(unsafe { slice_from_ref(&nhdr) });
    buf.extend_from_slice(name);
    buf.push(0);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    buf.extend_from_slice(desc);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

/// Build the whole `PT_NOTE` payload.
///
/// Linux's `elf_core_dump` writes NT_PRSTATUS, NT_PRPSINFO, NT_SIGINFO,
/// NT_AUXV, NT_FILE and the FP register sets. This kernel wrote only
/// NT_PRSTATUS, which gives a debugger registers and memory but no idea what
/// program it is looking at. NT_PRPSINFO and NT_AUXV are added here because
/// both have a source already: `comm`/argv from the /proc bookkeeping, and the
/// auxv the process was started with.
///
/// Still missing, and deliberately not faked: NT_FILE, which needs a path per
/// file-backed mapping and the VMA layer keeps none (only the executable's own
/// path is retained), and NT_FPREGSET, which needs the task's FPU save area
/// exposed here. Emitting either with invented contents would be worse than
/// omitting it — a debugger trusts NT_FILE to locate shared objects.
pub(crate) fn build_note_segment(
    regs: &user_regs_struct,
    prpsinfo: &ElfPrpsinfo,
    auxv: &[u8],
) -> Vec<u8> {
    build_note_segment_with_signal(regs, 0, prpsinfo, auxv)
}

pub(crate) fn build_note_segment_with_signal(
    regs: &user_regs_struct,
    signum: u32,
    prpsinfo: &ElfPrpsinfo,
    auxv: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::new();
    let prstatus = ElfPrstatus {
        pr_info: ElfSiginfo {
            si_signo: signum as i32,
            si_code: 0,
            si_errno: 0,
        },
        pr_cursig: signum as i16,
        _pad0: [0; 2],
        pr_sigpend: 0,
        pr_sighold: 0,
        pr_pid: prpsinfo.pr_pid,
        pr_ppid: prpsinfo.pr_ppid,
        pr_pgrp: prpsinfo.pr_pgrp,
        pr_sid: prpsinfo.pr_sid,
        pr_utime: ElfTimeval::default(),
        pr_stime: ElfTimeval::default(),
        pr_cutime: ElfTimeval::default(),
        pr_cstime: ElfTimeval::default(),
        pr_reg: *regs,
        pr_fpvalid: 1,
        _pad1: 0,
    };
    // SAFETY: `prstatus` is a live local of exactly this size (336 bytes on x86_64).
    push_note(&mut buf, b"CORE", 1, unsafe { slice_from_ref(&prstatus) });
    // SAFETY: `prpsinfo` is a live reference to a `#[repr(C)]` struct of
    // exactly this size, read as bytes for the note descriptor.
    push_note(&mut buf, b"CORE", 3, unsafe { slice_from_ref(prpsinfo) });
    if !auxv.is_empty() {
        push_note(&mut buf, b"CORE", 6, auxv);
    }
    buf
}

/// Bytes of `r` written to the core: Linux `vma_dump_size` dumps nothing for
/// `VM_IO`/`VM_PFNMAP` mappings. Here those are the device mappings a region
/// marks with a non-write-back memory type (DRM GEM VRAM BAR frames, which
/// may lie far above the kernel direct map, e.g. a ReBAR at 992 GiB). Their
/// PT_LOAD keeps `p_memsz` with `p_filesz = 0`.
/// File-backed private read-only mappings (executable and library .text) are
/// also omitted from file payload (`p_filesz = 0`), matching Linux's coredump
/// filter and ensuring stacks and writable heaps fit within RLIMIT_CORE.
fn dump_len(r: &narf_memory::address_space::Region) -> u64 {
    let device = narf_memory::memtype::region_may_request(r.perms)
        && r.perms.memory_type() != narf_memory::MemoryType::WriteBack;
    // Device mappings, file-backed private read-only mappings, and
    // unmaterialized regions all dump nothing (see the doc comment above).
    if device
        || (r
            .perms
            .contains(narf_memory::address_space::RegionPerms::FILE_DEMAND)
            && !r
                .perms
                .contains(narf_memory::address_space::RegionPerms::WRITE))
        || r.phys.is_empty()
    {
        0
    } else {
        // Dump up to the highest backed page, bounded by r.len.
        // Trimming unmaterialized tails avoids writing tens of megabytes of zeroes
        // for sparse thread arenas (e.g. 64 MB thread arenas with only a few pages resident)
        // and keeps the crash dump from exhausting RLIMIT_CORE before thread stacks are written.
        r.phys
            .indexed()
            .rfind(|(_, phys)| phys.raw() != 0)
            .map_or(0, |(idx, _)| {
                ((idx as u64) + 1).saturating_mul(4096).min(r.len)
            })
    }
}

pub fn write_coredump(task: u64, signum: u32, state: &UserState) {
    // Fatal path only: publish the cause before any optional dump-file I/O
    // can fail or stall. This also covers RLIMIT_CORE=0. Do not put this
    // diagnostic on the normal trap/syscall path.
    let pid = crate::handlers::task_to_pid_raw(task).unwrap_or(task);
    let exe = crate::handlers::proc_exe_path(pid);
    use core::fmt::Write;
    #[cfg(target_arch = "x86_64")]
    let _ = writeln!(
        narf_console::Writer,
        "coredump: fatal pid={pid} tid={task} exe={} signal={signum} rip={:#x} rsp={:#x} rbp={:#x} rax={:#x} rdi={:#x} rsi={:#x} rdx={:#x}",
        exe.as_deref().unwrap_or("?"), state.rip, state.rsp, state.rbp,
        state.rax, state.rdi, state.rsi, state.rdx
    );
    #[cfg(not(target_arch = "x86_64"))]
    let _ = writeln!(
        narf_console::Writer,
        "coredump: fatal pid={pid} tid={task} exe={} signal={signum} pc={:#x} sp={:#x} lr={:#x} x0={:#x} x1={:#x}",
        exe.as_deref().unwrap_or("?"), state.pc, state.sp, state.x[30],
        state.x[0], state.x[1]
    );
    // `fs/coredump.c`: `cprm.limit = rlimit(RLIMIT_CORE)`, then
    // `if (cprm->limit < binfmt->min_coredump) return false;` — and
    // binfmt_elf sets `min_coredump = ELF_EXEC_PAGESIZE`. So a limit under
    // one page produces NO core file at all, which is the case that matters
    // here: NARF's default RLIMIT_CORE soft limit is already 0, deliberately
    // matching Linux, and nothing consulted it — so this kernel wrote a core
    // dump on every fatal signal where a stock Linux writes none.
    //
    // The check comes before the file is touched. Linux never opens the core
    // file in this case, and the unlink below would otherwise delete a core
    // from an earlier crash on its way to writing nothing.
    const ELF_MIN_COREDUMP: u64 = 4096;
    let limit = crate::handlers::coredump_limit(task);
    if limit < ELF_MIN_COREDUMP {
        return;
    }
    if dump_interrupted(task) {
        return;
    }

    // Resolve address space
    let as_ref = match narf_scheduler::address_space_of_live(narf_scheduler::TaskId(task)) {
        Some(a) => a,
        None => return,
    };
    let regions = as_ref.regions_snapshot();

    // Core file path: core
    let path = resolve_cwd_path(task, "core");

    // Open/Create core file
    let (parent, leaf) = match resolve_parent_dir_async(&path) {
        Some(x) => x,
        None => return,
    };
    if dump_interrupted(task) {
        return;
    }

    // Try unlinking first to clear any old core dump file
    let _ = poll_blocking(parent.unlink(&leaf));
    if dump_interrupted(task) {
        return;
    }

    let file = match poll_blocking(parent.create(&leaf)) {
        Some(Ok(f)) => f,
        _ => return,
    };

    // Get register state
    #[cfg(target_arch = "x86_64")]
    let user_regs = {
        let fs_base = with_user_task_ctx(task, |uctx| {
            uctx.pending_fs_base
                .load(core::sync::atomic::Ordering::Acquire)
        })
        .unwrap_or(0);
        user_regs_struct {
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
            rax: state.rax,
            rcx: state.rcx,
            rdx: state.rdx,
            rsi: state.rsi,
            rdi: state.rdi,
            orig_rax: state.rax,
            rip: state.rip,
            cs: 0x2b,
            eflags: state.rflags,
            rsp: state.rsp,
            ss: 0x23,
            fs_base,
            gs_base: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
        }
    };
    #[cfg(target_arch = "aarch64")]
    let user_regs = user_regs_struct {
        regs: state.x,
        sp: state.sp,
        pc: state.pc,
        pstate: state.spsr,
    };
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let user_regs = user_regs_struct {
        regs: state.x,
        sp: state.sp,
        pc: state.pc,
        pstate: state.spsr,
    };

    let num_phdrs = 1 + regions.len();
    let mut ehdr = Elf64_Ehdr {
        e_ident: [0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        e_type: 4, // ET_CORE
        e_machine: 0,
        e_version: 1,
        e_entry: 0,
        e_phoff: 64,
        e_shoff: 0,
        e_flags: 0,
        e_ehsize: 64,
        e_phentsize: 56,
        e_phnum: num_phdrs as u16,
        e_shentsize: 0,
        e_shnum: 0,
        e_shstrndx: 0,
    };

    #[cfg(target_arch = "x86_64")]
    {
        ehdr.e_machine = 62; // EM_X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        ehdr.e_machine = 183; // EM_AARCH64
    }

    let mut phdrs = Vec::new();
    // Process identity for NT_PRPSINFO, from the same /proc bookkeeping that
    // serves `comm` and `cmdline`.
    let mut prpsinfo = ElfPrpsinfo {
        pr_pid: pid as i32,
        ..ElfPrpsinfo::default()
    };
    if let Some(comm) = crate::handlers::proc_comm_of(pid) {
        let bytes = comm.as_bytes();
        let take = core::cmp::min(bytes.len(), prpsinfo.pr_fname.len() - 1);
        prpsinfo.pr_fname[..take].copy_from_slice(&bytes[..take]);
    }
    {
        // `cmdline` is NUL-separated; `pr_psargs` is the space-separated form.
        let argv = crate::handlers::proc_argv_of(pid);
        let mut at = 0usize;
        for (i, part) in argv
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .enumerate()
        {
            if i > 0 && at < prpsinfo.pr_psargs.len() - 1 {
                prpsinfo.pr_psargs[at] = b' ';
                at += 1;
            }
            let room = prpsinfo.pr_psargs.len() - 1 - at;
            let take = core::cmp::min(part.len(), room);
            prpsinfo.pr_psargs[at..at + take].copy_from_slice(&part[..take]);
            at += take;
            if at >= prpsinfo.pr_psargs.len() - 1 {
                break;
            }
        }
    }
    let auxv = crate::handlers::proc_auxv_of(pid);
    let note_buf = build_note_segment_with_signal(&user_regs, signum, &prpsinfo, &auxv);
    let note_size = note_buf.len() as u64;
    let (phoff, note_offset, data_offset) = metadata_offsets(num_phdrs, note_buf.len());
    ehdr.e_phoff = phoff;

    phdrs.push(Elf64_Phdr {
        p_type: 4, // PT_NOTE
        p_flags: 0,
        p_offset: note_offset,
        p_vaddr: 0,
        p_paddr: 0,
        p_filesz: note_size,
        p_memsz: note_size,
        p_align: 0,
    });

    let mut current_offset = data_offset;

    for r in &regions {
        let mut flags = 0;
        if (r.perms.0 & narf_memory::address_space::RegionPerms::READ.0) != 0 {
            flags |= 4;
        }
        if (r.perms.0 & narf_memory::address_space::RegionPerms::WRITE.0) != 0 {
            flags |= 2;
        }
        if (r.perms.0 & narf_memory::address_space::RegionPerms::EXEC.0) != 0 {
            flags |= 1;
        }

        phdrs.push(Elf64_Phdr {
            p_type: 1, // PT_LOAD
            p_flags: flags,
            p_offset: current_offset,
            p_vaddr: r.base.as_u64(),
            p_paddr: 0,
            p_filesz: dump_len(r),
            p_memsz: r.len,
            p_align: 4096,
        });
        current_offset = align_up(current_offset + dump_len(r));
    }

    if let Err(error) = write_metadata(task, file.clone(), limit, &ehdr, &phdrs, &note_buf) {
        let _ = writeln!(
            narf_console::Writer,
            "coredump: pid={pid} metadata write failed: {error:?}"
        );
        return;
    }

    // Write segment data
    for (i, r) in regions.iter().enumerate() {
        let ph = &phdrs[i + 1];
        if ph.p_filesz == 0 {
            continue;
        }
        let mut offset = ph.p_offset;
        let mut bytes_left = ph.p_filesz;
        let mut page_idx = 0;

        while bytes_left > 0 {
            if offset >= limit {
                return;
            }
            let chunk_len = core::cmp::min(bytes_left, 4096);
            let phys = r.phys.get(page_idx).copied().unwrap_or(PhysAddr::new(0));

            // Only System RAM is covered by the kernel direct map; any other
            // frame (device memory that slipped past `dump_len`) is written
            // as zeros instead of dereferenced.
            if phys != PhysAddr::new(0) && narf_memory::frame::is_system_ram(phys) {
                // SAFETY: phys is a System RAM frame, covered by the direct map.
                let ptr = phys.kernel_ptr::<u8>();
                // SAFETY: reading chunk_len <= 4096 from page is safe.
                let slice = unsafe { core::slice::from_raw_parts(ptr, chunk_len as usize) };
                if write_at(task, file.clone(), limit, offset, slice).is_err() {
                    return;
                }
            } else {
                let zeros = [0u8; 4096];
                if write_at(
                    task,
                    file.clone(),
                    limit,
                    offset,
                    &zeros[..chunk_len as usize],
                )
                .is_err()
                {
                    return;
                }
            }

            offset += chunk_len;
            bytes_left -= chunk_len;
            page_idx += 1;
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "coredump_tests.rs"]
mod tests;
