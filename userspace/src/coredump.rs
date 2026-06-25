//! Userspace ELF coredump generator.

use crate::handlers::{poll_blocking, resolve_cwd_path, resolve_parent_dir_async};
use crate::user_task::{with_user_task_ctx, UserState};
use alloc::vec::Vec;
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

unsafe fn slice_from_ref<T>(val: &T) -> &[u8] {
    // SAFETY: caller must ensure val is safe to read.
    unsafe { core::slice::from_raw_parts(val as *const T as *const u8, core::mem::size_of::<T>()) }
}

fn write_at(file: &dyn FileOps, offset: u64, buf: &[u8]) -> Result<(), FsError> {
    let mut written = 0;
    while written < buf.len() {
        let chunk = &buf[written..];
        let n = match poll_blocking(file.write(offset + written as u64, chunk)) {
            Some(Ok(x)) => x,
            Some(Err(e)) => return Err(e),
            None => return Err(FsError::InvalidData),
        };
        if n == 0 {
            break;
        }
        written += n;
    }
    Ok(())
}

pub fn write_coredump(task: u64, _signum: u32, state: &UserState) {
    // Resolve address space
    let as_ref = match narf_scheduler::address_space_of(narf_scheduler::TaskId(task)) {
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

    // Try unlinking first to clear any old core dump file
    let _ = poll_blocking(parent.unlink(&leaf));

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
    let note_offset = 64 + num_phdrs as u64 * 56;
    let note_desc_size = core::mem::size_of::<user_regs_struct>() as u64;
    let note_size = 12 + 8 + note_desc_size; // Elf64_Nhdr + name("CORE\0\0\0") + desc

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

    let mut current_offset = align_up(note_offset + note_size);

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
            p_filesz: r.len,
            p_memsz: r.len,
            p_align: 4096,
        });
        current_offset = align_up(current_offset + r.len);
    }

    // Write Elf64_Ehdr
    // SAFETY: ehdr is valid reference, size matches.
    let ehdr_slice = unsafe { slice_from_ref(&ehdr) };
    if write_at(file.as_ref(), 0, ehdr_slice).is_err() {
        return;
    }

    // Write Elf64_Phdrs
    for (i, ph) in phdrs.iter().enumerate() {
        // SAFETY: ph is valid reference, size matches.
        let ph_slice = unsafe { slice_from_ref(ph) };
        if write_at(file.as_ref(), 64 + i as u64 * 56, ph_slice).is_err() {
            return;
        }
    }

    // Write Note
    let mut note_buf = Vec::new();
    let nhdr = Elf64_Nhdr {
        n_namesz: 5,
        n_descsz: note_desc_size as u32,
        n_type: 1, // NT_PRSTATUS
    };
    // SAFETY: nhdr is valid reference, size matches.
    let nhdr_slice = unsafe { slice_from_ref(&nhdr) };
    note_buf.extend_from_slice(nhdr_slice);
    note_buf.extend_from_slice(b"CORE\0\0\0");
    // SAFETY: user_regs is valid reference, size matches.
    let regs_slice = unsafe { slice_from_ref(&user_regs) };
    note_buf.extend_from_slice(regs_slice);

    if write_at(file.as_ref(), note_offset, &note_buf).is_err() {
        return;
    }

    // Write segment data
    for (i, r) in regions.iter().enumerate() {
        let ph = &phdrs[i + 1];
        let mut offset = ph.p_offset;
        let mut bytes_left = r.len;
        let mut page_idx = 0;

        while bytes_left > 0 {
            let chunk_len = core::cmp::min(bytes_left, 4096);
            let phys = r.phys.get(page_idx).copied().unwrap_or(PhysAddr::new(0));

            if phys != PhysAddr::new(0) {
                // SAFETY: phys is valid page frame mapped in kernel.
                let ptr = phys.kernel_ptr::<u8>();
                // SAFETY: reading chunk_len <= 4096 from page is safe.
                let slice = unsafe { core::slice::from_raw_parts(ptr, chunk_len as usize) };
                if write_at(file.as_ref(), offset, slice).is_err() {
                    return;
                }
            } else {
                let zeros = [0u8; 4096];
                if write_at(file.as_ref(), offset, &zeros[..chunk_len as usize]).is_err() {
                    return;
                }
            }

            offset += chunk_len;
            bytes_left -= chunk_len;
            page_idx += 1;
        }
    }
}
