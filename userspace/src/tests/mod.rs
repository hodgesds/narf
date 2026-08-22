//! Per-crate kernel-test entries for `narf-userspace`.

pub(crate) use alloc::sync::Arc;

pub(crate) use narf_kernel_test::{kernel_test_in, TestResult};
pub(crate) use narf_lib::sync::IrqSafeSpinLock;
pub(crate) use narf_memory::AddressSpace;

pub(crate) use crate::syscall::{
    kernel_syscall_entry, Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
};
#[cfg_attr(not(target_arch = "x86_64"), allow(unused_imports))]
pub(crate) use crate::{install_address_space_lookup, install_core_syscalls, install_global};

/// Static so the AS-lookup `fn` pointer can resolve it without a
/// closure capture.
static PARENT_AS: IrqSafeSpinLock<Option<Arc<AddressSpace>>> = IrqSafeSpinLock::new(None);

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
    fn user_rsp(&self) -> u64 {
        0
    }
    fn rip(&self) -> u64 {
        0
    }
    fn set_rip(&mut self, _rip: u64) {}
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
}

#[allow(unused_imports)]
pub(crate) use core::sync::atomic::{AtomicU32, AtomicU64, Ordering as AtomicOrd};

mod console_tty;
mod elf_loader;
mod epoll_poll;
mod fd_io;
mod mem_uaccess;
mod misc;
mod namespaces;
mod process;
mod signals;
mod sockets;
mod time;

// ── Shared non-test helpers (moved verbatim from the flat module) ──

#[allow(dead_code)] // TODO(narf): used only on x86_64 today
fn build_unresolved_named_elf(strtab: &[u8]) -> alloc::vec::Vec<u8> {
    const SEG_VA: u64 = 0x0000_0080_0000_1000;
    const SEG_FOFF: u64 = 0x1000;
    const RELOC_OFF_IN_SEG: u64 = 0x80;
    const RELA_OFF_IN_SEG: u64 = 0x180;
    const SYMTAB_OFF_IN_SEG: u64 = 0x1C0;
    const STRTAB_OFF_IN_SEG: u64 = 0x240;
    const DYN_OFF_IN_SEG: u64 = 0x300;

    const FSIZE: usize = 0x2000;
    let mut b = alloc::vec![0u8; FSIZE];
    b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x111).to_le_bytes());
    b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // e_phnum

    let mut ph = 64usize;
    b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
    b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());

    ph = 64 + 56;
    let dyn_foff = SEG_FOFF + DYN_OFF_IN_SEG;
    let dyn_va = SEG_VA + DYN_OFF_IN_SEG;
    // Six 16-byte entries: DT_RELA, DT_RELASZ, DT_RELAENT, DT_SYMTAB,
    // DT_STRTAB, DT_NULL → 96 bytes.
    let dyn_size: u64 = 96;
    b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
    b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
    b[ph + 0x08..ph + 0x10].copy_from_slice(&dyn_foff.to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&dyn_va.to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&dyn_va.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&dyn_size.to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&dyn_size.to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());

    let reloc_va = SEG_VA + RELOC_OFF_IN_SEG;
    let rela_foff = (SEG_FOFF + RELA_OFF_IN_SEG) as usize;
    let r_info: u64 = (1u64 << 32) | 1u64; // sym_idx=1, R_X86_64_64
    b[rela_foff..rela_foff + 8].copy_from_slice(&reloc_va.to_le_bytes());
    b[rela_foff + 8..rela_foff + 16].copy_from_slice(&r_info.to_le_bytes());
    b[rela_foff + 16..rela_foff + 24].copy_from_slice(&0u64.to_le_bytes());

    // Symbol table: entry 0 is the canonical zero placeholder; entry 1
    // is undefined (st_value=0, st_shndx=0) but with st_name=1 — the
    // loader must follow that into DT_STRTAB.
    let sym_foff = (SEG_FOFF + SYMTAB_OFF_IN_SEG) as usize;
    let s1 = sym_foff + 24;
    b[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes()); // st_name
                                                        // st_info, st_other, st_shndx, st_value, st_size all stay zero.

    // String table: caller-supplied content. Convention: leading NUL
    // followed by NUL-terminated names. Caller provides the whole
    // blob already.
    let strtab_foff = (SEG_FOFF + STRTAB_OFF_IN_SEG) as usize;
    b[strtab_foff..strtab_foff + strtab.len()].copy_from_slice(strtab);

    // Dynamic array.
    let rela_va = SEG_VA + RELA_OFF_IN_SEG;
    let symtab_va = SEG_VA + SYMTAB_OFF_IN_SEG;
    let strtab_va = SEG_VA + STRTAB_OFF_IN_SEG;
    let mut p = dyn_foff as usize;
    b[p..p + 8].copy_from_slice(&7i64.to_le_bytes()); // DT_RELA
    b[p + 8..p + 16].copy_from_slice(&rela_va.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&8i64.to_le_bytes()); // DT_RELASZ
    b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&9i64.to_le_bytes()); // DT_RELAENT
    b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&6i64.to_le_bytes()); // DT_SYMTAB
    b[p + 8..p + 16].copy_from_slice(&symtab_va.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&5i64.to_le_bytes()); // DT_STRTAB
    b[p + 8..p + 16].copy_from_slice(&strtab_va.to_le_bytes());
    p += 16;
    b[p..p + 8].copy_from_slice(&0i64.to_le_bytes()); // DT_NULL
    b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());

    b
}

#[cfg(target_arch = "x86_64")]
fn build_minimal_elf_for_execve() -> alloc::vec::Vec<u8> {
    // Same ELF shape used by smoke_userspace_load_user_process_*:
    // one PT_LOAD R|X segment, entry at 0x80_0000_1111.
    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(64 + 56 + 0x1000);
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type ET_EXEC
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine x86_64
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
    bytes.extend_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes()); // e_entry
    bytes.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    bytes.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                                  // PT_LOAD program header.
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type PT_LOAD
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags R|X
    bytes.extend_from_slice(&(64u64 + 56).to_le_bytes()); // p_offset
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
    bytes.resize(64 + 56 + 0x1000, 0);
    bytes
}

/// Minimal ET_EXEC ELF whose `PT_INTERP` names `interp_name`. One R|X
/// PT_LOAD at 0x80_0000_1000 (entry +0x111), interp string stored after
/// the phdr table. Used by the PT_INTERP-unresolvable regression tests:
/// a dynamic binary must NEVER load without its interpreter (silent
/// fallback ran `_start` against an unrelocated GOT → #PF rip=0).
#[cfg(target_arch = "x86_64")]
fn build_pt_interp_elf(interp_name: &str) -> alloc::vec::Vec<u8> {
    const FSIZE: usize = 0x2000;
    let mut b = alloc::vec![0u8; FSIZE];
    b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // e_type ET_EXEC
    b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // e_machine x86_64
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // e_version
    b[0x18..0x20].copy_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes()); // e_entry
    b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
                                                        // Interp string (NUL-terminated) right after the phdr table.
    let interp_off = 64 + 2 * 56;
    let name_bytes = interp_name.as_bytes();
    assert!(interp_off + name_bytes.len() + 1 < 0x1000);
    b[interp_off..interp_off + name_bytes.len()].copy_from_slice(name_bytes);
    // Phdr 0 — PT_INTERP.
    let mut ph = 64usize;
    b[ph..ph + 0x04].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
    b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
    b[ph + 0x08..ph + 0x10].copy_from_slice(&(interp_off as u64).to_le_bytes());
    let ilen = (name_bytes.len() + 1) as u64; // include the NUL
    b[ph + 0x20..ph + 0x28].copy_from_slice(&ilen.to_le_bytes()); // p_filesz
    b[ph + 0x28..ph + 0x30].copy_from_slice(&ilen.to_le_bytes()); // p_memsz
    b[ph + 0x30..ph + 0x38].copy_from_slice(&1u64.to_le_bytes()); // p_align
                                                                  // Phdr 1 — PT_LOAD R|X, file off 0x1000 → vaddr 0x80_0000_1000.
    ph = 64 + 56;
    b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
    b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    b[ph + 0x18..ph + 0x20].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
    b
}

struct SigGapCtx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
}
impl TrapContext for SigGapCtx {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, r: SyscallReturn) {
        self.ret = Some(r);
    }
    fn user_rsp(&self) -> u64 {
        0
    }
    fn rip(&self) -> u64 {
        0
    }
    fn set_rip(&mut self, _rip: u64) {}
    fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
        false
    }
}

struct ReadyFile(AtomicU32);

impl core::fmt::Debug for ReadyFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ReadyFile({})", self.0.load(AtomicOrd::Relaxed))
    }
}

impl narf_filesystem::FileOps for ReadyFile {
    fn read<'a>(&'a self, _off: u64, _buf: &'a mut [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        alloc::boxed::Box::pin(async move { Ok(0) })
    }
    fn write<'a>(&'a self, _off: u64, buf: &'a [u8]) -> narf_filesystem::FsFuture<'a, usize> {
        let n = buf.len();
        alloc::boxed::Box::pin(async move { Ok(n) })
    }
    fn stat(&self) -> narf_filesystem::Stat {
        narf_filesystem::Stat {
            size: 0,
            blocks: 0,
            mode: narf_filesystem::Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
    fn poll_readiness(&self) -> u32 {
        self.0.load(AtomicOrd::Relaxed)
    }
}

/// Install `ReadyFile` at a fresh fd under `task_id`.
/// Returns the fd number.
fn install_ready_file(task_id: u64, mask: u32) -> u32 {
    crate::fd::with_table(task_id, |t| {
        t.open(crate::fd::FdEntry {
            ops: Arc::new(ReadyFile(AtomicU32::new(mask))),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .unwrap()
}

/// Common test setup: reset global state, install task-id lookup, build
/// syscall table. Returns task id.
fn setup_poll_test() -> u64 {
    crate::syscall::__test_clear_global();
    crate::fd::__test_reset();
    crate::handlers::init_per_task_state();
    crate::epoll::__test_reset();

    const TASK: u64 = 0xFACE_CAFE;
    static POLL_TASK: AtomicU64 = AtomicU64::new(TASK);
    fn task_lu() -> u64 {
        POLL_TASK.load(AtomicOrd::Relaxed)
    }
    crate::install_task_id_lookup(task_lu);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    TASK
}

// ── Helper: fire a syscall via StubCtx ───────────────────────────────

fn call(syscall: Syscall, args: SyscallArgs) -> SyscallReturn {
    let mut ctx = StubCtx { args, ret: None };
    kernel_syscall_entry(syscall.raw(), &mut ctx);
    ctx.ret.unwrap_or(SyscallReturn::invalid_op())
}

fn build_sockaddr_in(ip: u32, port: u16) -> crate::socket::SockAddr {
    crate::socket::make_sockaddr_in(ip, port)
}
