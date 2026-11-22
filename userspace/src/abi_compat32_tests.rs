//! IA-32 compat ABI (Linux `CONFIG_IA32_EMULATION`) conformance.
//!
//! Linux runs an i386 program on x86_64 through `fs/compat_binfmt_elf.c`
//! (`binfmt_elf.c` built for ELFCLASS32) and routes its `int 0x80` syscalls
//! through `arch/x86/entry/syscalls/syscall_32.tbl`. These cases cover the
//! userspace half of that: parsing an i386 ELF32 image, laying out its 32-bit
//! address space and startup stack, and the i386 syscall table's argument
//! and structure conversions.
//!
//! Every fixture is a hand-assembled byte image built here. No case enters
//! ring 3 — that needs the compat-mode user entry (CS 0x23) in `frame/`.
#![cfg(target_arch = "x86_64")]
#![allow(dead_code)] // fixture constants are shared across the test groups

use crate::abi_test_support::*;
use alloc::vec::Vec;

// ── ELF32 wire constants (elf.h) ─────────────────────────────────────

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_386: u16 = 3;
const EM_486: u16 = 6;
const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;

const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

/// `sizeof(Elf32_Ehdr)` / `sizeof(Elf32_Phdr)`.
const EHDR32: usize = 52;
const PHDR32: usize = 32;

/// One `Elf32_Phdr`, in the order the fixture builder writes its fields.
#[derive(Copy, Clone)]
struct Ph32 {
    p_type: u32,
    offset: u32,
    vaddr: u32,
    filesz: u32,
    memsz: u32,
    flags: u32,
    align: u32,
}

fn put16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// A `size`-byte ELF32 little-endian image: `Elf32_Ehdr` at 0, the program
/// header table straight after it at offset 52, everything else zero.
fn elf32(e_type: u16, machine: u16, entry: u32, phdrs: &[Ph32], size: usize) -> Vec<u8> {
    let mut b = alloc::vec![0u8; size];
    // e_ident: ELFMAG, ELFCLASS32, ELFDATA2LSB, EV_CURRENT, ELFOSABI_SYSV.
    b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put16(&mut b, 0x10, e_type);
    put16(&mut b, 0x12, machine);
    put32(&mut b, 0x14, 1); // e_version
    put32(&mut b, 0x18, entry);
    put32(&mut b, 0x1C, EHDR32 as u32); // e_phoff
    put32(&mut b, 0x20, 0); // e_shoff
    put32(&mut b, 0x24, 0); // e_flags
    put16(&mut b, 0x28, EHDR32 as u16); // e_ehsize
    put16(&mut b, 0x2A, PHDR32 as u16); // e_phentsize
    put16(&mut b, 0x2C, phdrs.len() as u16); // e_phnum
    for (i, ph) in phdrs.iter().enumerate() {
        let o = EHDR32 + i * PHDR32;
        put32(&mut b, o, ph.p_type);
        put32(&mut b, o + 0x04, ph.offset);
        put32(&mut b, o + 0x08, ph.vaddr);
        put32(&mut b, o + 0x0C, ph.vaddr); // p_paddr
        put32(&mut b, o + 0x10, ph.filesz);
        put32(&mut b, o + 0x14, ph.memsz);
        put32(&mut b, o + 0x18, ph.flags);
        put32(&mut b, o + 0x1C, ph.align);
    }
    b
}

// ── The static i386 fixture ──────────────────────────────────────────
//
// The classic i386 link layout: text at 0x08048000 with the headers in its
// first page, data on the next page, `_start` at text + 0x100. The program
// is `write(1, "hello i386\n", 11); exit_group(0)` through `int 0x80`, the
// phase-1 exit criterion once the compat-mode entry runs it.

const STATIC_TEXT_VA: u32 = 0x0804_8000;
const STATIC_DATA_VA: u32 = 0x0804_9000;
const STATIC_ENTRY: u32 = STATIC_TEXT_VA + 0x100;
const STATIC_MSG_OFF: usize = 0x140;
/// File-backed bytes of the data segment. Two eagerly-loaded pages the
/// table tests use as user scratch memory.
const STATIC_DATA_FILE: u32 = 0x2000;
/// The data segment's memory size: one page of `.bss` past the file image.
const STATIC_DATA_MEM: u32 = 0x3000;
const HELLO: &[u8] = b"hello i386\n";

/// `write(1, msg, len); exit_group(0); jmp $`, i386 encoding.
fn hello_i386_code(msg: u32, len: u32) -> Vec<u8> {
    let mut c = Vec::new();
    c.push(0xB8); // mov eax, imm32
    c.extend_from_slice(&4u32.to_le_bytes()); // __NR_write
    c.push(0xBB); // mov ebx, imm32
    c.extend_from_slice(&1u32.to_le_bytes()); // fd 1
    c.push(0xB9); // mov ecx, imm32
    c.extend_from_slice(&msg.to_le_bytes());
    c.push(0xBA); // mov edx, imm32
    c.extend_from_slice(&len.to_le_bytes());
    c.extend_from_slice(&[0xCD, 0x80]); // int 0x80
    c.push(0xB8); // mov eax, imm32
    c.extend_from_slice(&252u32.to_le_bytes()); // __NR_exit_group
    c.extend_from_slice(&[0x31, 0xDB]); // xor ebx, ebx
    c.extend_from_slice(&[0xCD, 0x80]); // int 0x80
    c.extend_from_slice(&[0xEB, 0xFE]); // jmp $
    c
}

/// The static i386 executable: PT_PHDR, text, data(+bss), PT_GNU_STACK RW.
fn i386_static_image() -> Vec<u8> {
    let phdrs = [
        Ph32 {
            p_type: PT_PHDR,
            offset: EHDR32 as u32,
            vaddr: STATIC_TEXT_VA + EHDR32 as u32,
            filesz: 4 * PHDR32 as u32,
            memsz: 4 * PHDR32 as u32,
            flags: PF_R,
            align: 4,
        },
        Ph32 {
            p_type: PT_LOAD,
            offset: 0,
            vaddr: STATIC_TEXT_VA,
            filesz: 0x1000,
            memsz: 0x1000,
            flags: PF_R | PF_X,
            align: 0x1000,
        },
        Ph32 {
            p_type: PT_LOAD,
            offset: 0x1000,
            vaddr: STATIC_DATA_VA,
            filesz: STATIC_DATA_FILE,
            memsz: STATIC_DATA_MEM,
            flags: PF_R | PF_W,
            align: 0x1000,
        },
        Ph32 {
            p_type: PT_GNU_STACK,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            flags: PF_R | PF_W,
            align: 16,
        },
    ];
    let mut b = elf32(ET_EXEC, EM_386, STATIC_ENTRY, &phdrs, 0x3000);
    let code = hello_i386_code(STATIC_TEXT_VA + STATIC_MSG_OFF as u32, HELLO.len() as u32);
    b[0x100..0x100 + code.len()].copy_from_slice(&code);
    b[STATIC_MSG_OFF..STATIC_MSG_OFF + HELLO.len()].copy_from_slice(HELLO);
    b
}

// ── ELF32 parsing ────────────────────────────────────────────────────

/// An i386 ET_EXEC carrying every program-header type the loader reads:
/// PT_PHDR, PT_INTERP, two PT_LOADs, PT_DYNAMIC (`Elf32_Dyn`, 8 bytes per
/// entry), PT_TLS and PT_GNU_STACK.
fn i386_parse_fixture(machine: u16) -> Vec<u8> {
    const INTERP: &[u8] = b"/lib/ld-linux.so.2\0";
    let phdrs = [
        Ph32 {
            p_type: PT_PHDR,
            offset: EHDR32 as u32,
            vaddr: STATIC_TEXT_VA + EHDR32 as u32,
            filesz: 7 * PHDR32 as u32,
            memsz: 7 * PHDR32 as u32,
            flags: PF_R,
            align: 4,
        },
        Ph32 {
            p_type: PT_INTERP,
            offset: 0x200,
            vaddr: STATIC_TEXT_VA + 0x200,
            filesz: INTERP.len() as u32,
            memsz: INTERP.len() as u32,
            flags: PF_R,
            align: 1,
        },
        Ph32 {
            p_type: PT_LOAD,
            offset: 0,
            vaddr: STATIC_TEXT_VA,
            filesz: 0x1000,
            memsz: 0x1000,
            flags: PF_R | PF_X,
            align: 0x1000,
        },
        Ph32 {
            p_type: PT_LOAD,
            offset: 0x1000,
            vaddr: STATIC_DATA_VA,
            filesz: 0x1000,
            memsz: 0x2000,
            flags: PF_R | PF_W,
            align: 0x1000,
        },
        Ph32 {
            p_type: PT_DYNAMIC,
            offset: 0x1000,
            vaddr: STATIC_DATA_VA,
            filesz: 3 * 8,
            memsz: 3 * 8,
            flags: PF_R | PF_W,
            align: 4,
        },
        Ph32 {
            p_type: PT_TLS,
            offset: 0x1100,
            vaddr: STATIC_DATA_VA + 0x100,
            filesz: 0x10,
            memsz: 0x20,
            flags: PF_R,
            align: 4,
        },
        Ph32 {
            p_type: PT_GNU_STACK,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            flags: PF_R | PF_W,
            align: 16,
        },
    ];
    let mut b = elf32(ET_EXEC, machine, STATIC_ENTRY, &phdrs, 0x2000);
    b[0x200..0x200 + INTERP.len()].copy_from_slice(INTERP);
    // Elf32_Dyn { Sword d_tag; Word d_val; }: DT_NEEDED, DT_STRTAB, DT_NULL.
    put32(&mut b, 0x1000, 1);
    put32(&mut b, 0x1004, 0x10);
    put32(&mut b, 0x1008, 5);
    put32(&mut b, 0x100C, STATIC_TEXT_VA + 0x300);
    put32(&mut b, 0x1010, 0);
    put32(&mut b, 0x1014, 0);
    b
}

/// `compat_elf_check_arch` (`arch/x86/include/asm/elf.h`): an ELFCLASS32
/// image naming EM_386 or EM_486 is an IA-32 program, and `binfmt_elf`
/// built for Elf32 reads its 52-byte header and 32-byte program headers.
/// NARF answered every ELFCLASS32 image with ENOEXEC, which is what Steam's
/// `ldd` of `ubuntu12_32/steamui.so` reported as a missing libc.so.6.
fn smoke_compat32_elf32_i386_image_parses() -> TestResult {
    use crate::{parse_elf, ElfError, SegmentFlags};

    for machine in [EM_386, EM_486] {
        let image = match parse_elf(&i386_parse_fixture(machine)) {
            Ok(image) => image,
            Err(_) => return TestResult::Fail("an i386 ELF32 executable did not parse"),
        };
        if image.entry != u64::from(STATIC_ENTRY) {
            return TestResult::Fail("e_entry was not read from the Elf32_Ehdr");
        }
        if image.segments.len() != 2 {
            return TestResult::Fail("ELF32 PT_LOAD count is wrong");
        }
        let text = &image.segments[0];
        let data = &image.segments[1];
        if text.vaddr != u64::from(STATIC_TEXT_VA)
            || text.file_off != 0
            || text.file_size != 0x1000
            || text.mem_size != 0x1000
            || !text.flags.contains(SegmentFlags::READ | SegmentFlags::EXEC)
            || text.flags.contains(SegmentFlags::WRITE)
        {
            return TestResult::Fail("ELF32 text PT_LOAD fields mis-decoded");
        }
        if data.vaddr != u64::from(STATIC_DATA_VA)
            || data.file_off != 0x1000
            || data.file_size != 0x1000
            || data.mem_size != 0x2000
            || !data
                .flags
                .contains(SegmentFlags::READ | SegmentFlags::WRITE)
            || data.flags.contains(SegmentFlags::EXEC)
        {
            return TestResult::Fail("ELF32 data PT_LOAD fields (p_flags sits at +24) mis-decoded");
        }
        if image.interp.as_deref() != Some("/lib/ld-linux.so.2") {
            return TestResult::Fail("ELF32 PT_INTERP not captured");
        }
        if image.phdr_vaddr != Some(u64::from(STATIC_TEXT_VA) + EHDR32 as u64) {
            return TestResult::Fail("ELF32 PT_PHDR p_vaddr not captured");
        }
        if image.dynamic.len() != 2
            || image.dynamic[0].tag != 1
            || image.dynamic[0].val != 0x10
            || image.dynamic[1].tag != 5
            || image.dynamic[1].val != u64::from(STATIC_TEXT_VA) + 0x300
        {
            return TestResult::Fail("Elf32_Dyn entries (8 bytes each) mis-decoded");
        }
        match &image.tls {
            Some(tls)
                if tls.file_off == 0x1100
                    && tls.file_size == 0x10
                    && tls.mem_size == 0x20
                    && tls.align == 4
                    && tls.vaddr == u64::from(STATIC_DATA_VA) + 0x100 => {}
            _ => return TestResult::Fail("ELF32 PT_TLS template mis-decoded"),
        }
        match image.stack_flags {
            Some(flags) if !flags.contains(SegmentFlags::EXEC) => {}
            _ => return TestResult::Fail("ELF32 PT_GNU_STACK lost or reads executable"),
        }
        if image.max_align != 0x1000 {
            return TestResult::Fail("ELF32 PT_LOAD alignment not folded into max_align");
        }
    }

    // ELFCLASS32 + EM_X86_64 is x32, which NARF (like a kernel built
    // without CONFIG_X86_X32_ABI) does not run.
    match parse_elf(&i386_parse_fixture(EM_X86_64)) {
        Err(ElfError::Not64Bit) => {}
        _ => return TestResult::Fail("an x32 (ELFCLASS32 EM_X86_64) image must not parse"),
    }
    // The 32-bit program-header stride is exactly sizeof(Elf32_Phdr).
    let mut bad_stride = i386_parse_fixture(EM_386);
    put16(&mut bad_stride, 0x2A, 56);
    match parse_elf(&bad_stride) {
        Err(ElfError::BadPhoff) => {}
        _ => return TestResult::Fail("ELF32 with e_phentsize != 32 must be BadPhoff"),
    }
    // PT_DYNAMIC must be a whole number of 8-byte Elf32_Dyn entries.
    let mut bad_dyn = i386_parse_fixture(EM_386);
    put32(&mut bad_dyn, EHDR32 + 4 * PHDR32 + 0x10, 12);
    match parse_elf(&bad_dyn) {
        Err(ElfError::DynamicOutOfBounds) => {}
        _ => return TestResult::Fail("ELF32 PT_DYNAMIC of 12 bytes must be rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("userspace/compat32", smoke_compat32_elf32_i386_image_parses);

/// The ELF64 parser keeps `elf_check_arch`: an ELFCLASS64 header naming
/// EM_386 is not an x86_64 program.
fn smoke_compat32_elf64_naming_i386_is_wrong_machine() -> TestResult {
    use crate::{parse_elf, ElfError};
    let mut b = alloc::vec![0u8; 64 + 56];
    b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    b[0x10..0x12].copy_from_slice(&ET_EXEC.to_le_bytes());
    b[0x12..0x14].copy_from_slice(&EM_386.to_le_bytes());
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    b[0x18..0x20].copy_from_slice(&0x401000u64.to_le_bytes());
    b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    b[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
    let ph = 64usize;
    b[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    b[ph + 4..ph + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    b[ph + 0x10..ph + 0x18].copy_from_slice(&0x401000u64.to_le_bytes());
    b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
    b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
    b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
    match parse_elf(&b) {
        Err(ElfError::WrongMachine) => TestResult::Pass,
        _ => TestResult::Fail("an ELF64 image naming EM_386 must be WrongMachine"),
    }
}
kernel_test_in!(
    "userspace/compat32",
    smoke_compat32_elf64_naming_i386_is_wrong_machine
);

// ── 32-bit address-space layout and startup stack ────────────────────

/// `IA32_PAGE_OFFSET` / `TASK_SIZE_32`: the end of an IA-32 task's
/// address space (`arch/x86/include/asm/page_64_types.h`).
const TASK_SIZE_32: u64 = 0xFFFF_E000;
/// `TASK_UNMAPPED_BASE` for a 32-bit task: `PAGE_ALIGN(TASK_SIZE_32 / 3)`.
const COMPAT_MMAP_BASE: u64 = 0x5555_5000;
/// RLIMIT_STACK-sized stack reservation under `TASK_SIZE_32`.
const COMPAT_STACK_RESERVED: u64 = 8 * 1024 * 1024;

const AT_PHDR: u32 = 3;
const AT_PHENT: u32 = 4;
const AT_PHNUM: u32 = 5;
const AT_PAGESZ: u32 = 6;
const AT_BASE: u32 = 7;
const AT_ENTRY: u32 = 9;
const AT_PLATFORM: u32 = 15;
const AT_HWCAP: u32 = 16;
const AT_SECURE: u32 = 23;
const AT_RANDOM: u32 = 25;
const AT_SYSINFO: u32 = 32;
const AT_SYSINFO_EHDR: u32 = 33;

/// Read `out.len()` bytes of `aspace` at user `va` through its page tables
/// (no CR3 switch). `false` when any byte is not materialized.
fn user_read(aspace: &narf_memory::AddressSpace, va: u64, out: &mut [u8]) -> bool {
    for (i, byte) in out.iter_mut().enumerate() {
        let v = va + i as u64;
        // SAFETY: `aspace.root` is the live root the loader built; the walk
        // only reads page-table entries for the page-aligned address.
        let page = unsafe {
            narf_memory::x86_64::paging::translate(
                aspace.root,
                narf_memory::VirtAddr::new(v & !0xFFF),
            )
        };
        let Some(page) = page else {
            return false;
        };
        // SAFETY: `page` is the frame backing that user page, reached
        // through the kernel direct map; the in-page offset stays inside it.
        *byte =
            unsafe { *narf_memory::PhysAddr::new(page.as_u64() | (v & 0xFFF)).kernel_ptr::<u8>() };
    }
    true
}

fn user_u32(aspace: &narf_memory::AddressSpace, va: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    if user_read(aspace, va, &mut b) {
        Some(u32::from_le_bytes(b))
    } else {
        None
    }
}

/// The NUL-terminated string at `va` (without its NUL), at most 256 bytes.
fn user_cstr(aspace: &narf_memory::AddressSpace, va: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for i in 0..256u64 {
        let mut b = [0u8; 1];
        if !user_read(aspace, va + i, &mut b) {
            return None;
        }
        if b[0] == 0 {
            return Some(out);
        }
        out.push(b[0]);
    }
    None
}

/// The startup stack an IA-32 program's `_start` reads at `esp`:
/// `argc`, then 32-bit `argv[]`, `envp[]` and `Elf32_auxv_t` pairs.
struct Stack32 {
    argc: u32,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    auxv: Vec<(u32, u32)>,
}

impl Stack32 {
    fn aux(&self, tag: u32) -> Option<u32> {
        self.auxv.iter().find(|(t, _)| *t == tag).map(|&(_, v)| v)
    }
}

/// Walk the 32-bit startup block at `esp`. Every pointer is 4 bytes wide
/// (`elf_addr_t` is `Elf32_Addr` in `compat_binfmt_elf.c`).
fn read_stack32(aspace: &narf_memory::AddressSpace, esp: u64) -> Option<Stack32> {
    let argc = user_u32(aspace, esp)?;
    let mut cursor = esp + 4;
    let mut argv = Vec::new();
    for _ in 0..argc {
        let p = user_u32(aspace, cursor)?;
        argv.push(user_cstr(aspace, u64::from(p))?);
        cursor += 4;
    }
    if user_u32(aspace, cursor)? != 0 {
        return None; // argv[argc] must be NULL
    }
    cursor += 4;
    let mut envp = Vec::new();
    loop {
        let p = user_u32(aspace, cursor)?;
        cursor += 4;
        if p == 0 {
            break;
        }
        envp.push(user_cstr(aspace, u64::from(p))?);
        if envp.len() > 64 {
            return None;
        }
    }
    let mut auxv = Vec::new();
    loop {
        let tag = user_u32(aspace, cursor)?;
        let val = user_u32(aspace, cursor + 4)?;
        cursor += 8;
        if tag == 0 {
            break;
        }
        auxv.push((tag, val));
        if auxv.len() > 64 {
            return None;
        }
    }
    Some(Stack32 {
        argc,
        argv,
        envp,
        auxv,
    })
}

/// Load `bytes` the way exec does (fresh pid, argv/envp), or say why not.
fn load_i386(
    bytes: &[u8],
    argv: &[&str],
    envp: &[&str],
) -> Result<crate::UserProcess, &'static str> {
    // SAFETY: the kernel-test harness keeps paging live and the frame
    // allocator initialised, which is the loader's whole contract.
    unsafe { crate::load_user_process_with(bytes, argv, envp, &[]) }
        .map_err(|_| "an i386 ELF32 image failed to load")
}

/// Give a loaded process's pid and address space back.
fn unload(proc: crate::UserProcess) {
    let pid = proc.pid;
    drop(proc);
    crate::release_pid(pid);
}

/// `load_elf_binary` for an ELFCLASS32 image (`compat_binfmt_elf.c`):
///
///   * the image maps where an ET_EXEC asks, below `TASK_SIZE_32`;
///   * `STACK_TOP` is `TASK_SIZE_LOW` = `IA32_PAGE_OFFSET`, so `esp` sits in
///     the RLIMIT_STACK window under 0xFFFFe000, 16-byte aligned
///     (`STACK_ROUND`);
///   * `create_elf_tables` writes `elf_addr_t` = `Elf32_Addr` words: a 4-byte
///     `argc`, 4-byte `argv`/`envp` pointers and 8-byte `Elf32_auxv_t`;
///   * the auxv carries AT_PHENT = sizeof(Elf32_Phdr), AT_PLATFORM =
///     `COMPAT_ELF_PLATFORM` ("i686") and no AT_SYSINFO/AT_SYSINFO_EHDR while
///     there is no vDSO32 (`ARCH_DLINFO_IA32` with `vdso32_enabled == 0`);
///   * the thread starts with FS/GS bases of zero (`compat_start_thread`):
///     an i386 libc sets its TLS up with `set_thread_area`.
fn smoke_compat32_static_image_loads_in_a_32bit_layout() -> TestResult {
    let bytes = i386_static_image();
    let proc = match load_i386(&bytes, &["hello", "two"], &["A=1"]) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    let outcome = (|| -> Result<(), &'static str> {
        if proc.entry.0.as_u64() != u64::from(STATIC_ENTRY) {
            return Err("ET_EXEC entry moved: an i386 ET_EXEC loads at its own vaddrs");
        }
        let mut first = [0u8; 1];
        if !user_read(&proc.address_space, u64::from(STATIC_ENTRY), &mut first) || first[0] != 0xB8
        {
            return Err("i386 text is not mapped at 0x08048000");
        }
        let esp = proc.stack_top.as_u64();
        if esp >= TASK_SIZE_32 || esp < TASK_SIZE_32 - COMPAT_STACK_RESERVED {
            return Err("startup esp is not in the stack window under TASK_SIZE_32");
        }
        if esp & 0xF != 0 {
            return Err("startup esp is not 16-byte aligned");
        }
        let stack = read_stack32(&proc.address_space, esp)
            .ok_or("the startup block is not a 32-bit argc/argv/envp/auxv layout")?;
        if stack.argc != 2 || stack.argv[0] != b"hello" || stack.argv[1] != b"two" {
            return Err("32-bit argv does not read back");
        }
        if stack.envp.len() != 1 || stack.envp[0] != b"A=1" {
            return Err("32-bit envp does not read back");
        }
        if stack.aux(AT_PHDR) != Some(STATIC_TEXT_VA + EHDR32 as u32)
            || stack.aux(AT_PHENT) != Some(PHDR32 as u32)
            || stack.aux(AT_PHNUM) != Some(4)
        {
            return Err("AT_PHDR/AT_PHENT/AT_PHNUM do not describe the Elf32_Phdr table");
        }
        if stack.aux(AT_PAGESZ) != Some(4096)
            || stack.aux(AT_ENTRY) != Some(STATIC_ENTRY)
            || stack.aux(AT_BASE) != Some(0)
        {
            return Err("AT_PAGESZ/AT_ENTRY/AT_BASE wrong for a static i386 image");
        }
        if stack.aux(AT_HWCAP).is_none() || stack.aux(AT_SECURE) != Some(0) {
            return Err("AT_HWCAP/AT_SECURE missing from the 32-bit auxv");
        }
        match stack.aux(AT_PLATFORM) {
            Some(p)
                if user_cstr(&proc.address_space, u64::from(p)).as_deref()
                    == Some(&b"i686"[..]) => {}
            _ => return Err("AT_PLATFORM must name COMPAT_ELF_PLATFORM \"i686\""),
        }
        match stack.aux(AT_RANDOM) {
            Some(r) if u64::from(r) > esp && u64::from(r) + 16 <= TASK_SIZE_32 => {}
            _ => return Err("AT_RANDOM must point at 16 bytes on the 32-bit stack"),
        }
        if stack.aux(AT_SYSINFO_EHDR).is_some() || stack.aux(AT_SYSINFO).is_some() {
            return Err("no vDSO32 exists: AT_SYSINFO(_EHDR) must be absent, not the 64-bit vDSO");
        }
        if proc.fs_base.is_some() || proc.gs_base != 0 {
            return Err("an i386 task must start with FS and GS bases of zero");
        }
        Ok(())
    })();
    unload(proc);
    match outcome {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}
kernel_test_in!(
    "userspace/compat32",
    smoke_compat32_static_image_loads_in_a_32bit_layout
);

/// The compat process's address space, for the AS-lookup `fn` pointer.
static COMPAT_AS: narf_lib::sync::IrqSafeSpinLock<
    Option<alloc::sync::Arc<narf_memory::AddressSpace>>,
> = narf_lib::sync::IrqSafeSpinLock::new(None);

fn compat_as_lookup() -> Option<alloc::sync::Arc<narf_memory::AddressSpace>> {
    COMPAT_AS.lock().clone()
}

/// Make `proc`'s address space the harness task's current one.
fn install_compat_as(proc: &crate::UserProcess) {
    *COMPAT_AS.lock() = Some(alloc::sync::Arc::clone(&proc.address_space));
    crate::handlers::install_address_space_lookup(compat_as_lookup);
}

fn clear_compat_as() {
    *COMPAT_AS.lock() = None;
}

/// `arch_pick_mmap_layout` / `arch_get_unmapped_area` and `load_elf_binary`'s
/// brk for an IA-32 task: every mapping the kernel chooses lands below
/// `TASK_SIZE_32`, mmap from the compat mmap base (`mmap_compat_base`; NARF
/// uses the bottom-up `mmap_compat_legacy_base` layout), and the program
/// break starts after the image's `.bss` (`mm->start_brk = ELF_PAGEALIGN
/// (elf_brk)`, randomized by `arch_randomize_brk`), not in NARF's 64-bit
/// heap arena. A fixed mapping anywhere in the 32-bit window above
/// `mmap_min_addr` is legal.
fn smoke_compat32_mmap_and_brk_stay_below_task_size_32() -> TestResult {
    const PROT_RW: u64 = 0x3;
    const MAP_PRIVATE_ANON: u64 = 0x02 | 0x20;
    const MAP_FIXED: u64 = 0x10;
    let bytes = i386_static_image();
    let proc = match load_i386(&bytes, &["hello"], &[]) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    let outcome = with_setup_strict(|| {
        install_compat_as(&proc);
        let reserved = proc.address_space.reserve_mmap_va(0x1000);
        if reserved < COMPAT_MMAP_BASE || reserved + 0x1000 > TASK_SIZE_32 {
            return Err("the mmap cursor of an i386 address space is outside the 32-bit window");
        }
        let anon = call(
            Syscall::Mmap.raw(),
            SyscallArgs {
                arg0: 0,
                arg1: 0x2000,
                arg2: PROT_RW,
                arg3: MAP_PRIVATE_ANON,
                arg4: u64::MAX,
                arg5: 0,
            },
        )
        .ok_or("mmap returned a non-Linux status")?;
        if anon < 0 || anon as u64 + 0x2000 > TASK_SIZE_32 || (anon as u64) < COMPAT_MMAP_BASE {
            return Err("an anonymous mmap in an i386 address space landed above TASK_SIZE_32");
        }
        let fixed_va = 0x1000_0000u64;
        let fixed = call(
            Syscall::Mmap.raw(),
            SyscallArgs {
                arg0: fixed_va,
                arg1: 0x1000,
                arg2: PROT_RW,
                arg3: MAP_PRIVATE_ANON | MAP_FIXED,
                arg4: u64::MAX,
                arg5: 0,
            },
        );
        if fixed != Some(fixed_va as i64) {
            return Err("MAP_FIXED inside the 32-bit window was refused");
        }
        let brk0 = call(Syscall::Brk.raw(), a0(0)).ok_or("brk returned a non-Linux status")?;
        let image_end = u64::from(STATIC_DATA_VA) + u64::from(STATIC_DATA_MEM);
        if (brk0 as u64) < image_end || brk0 as u64 >= COMPAT_MMAP_BASE {
            return Err("an i386 program break must start after .bss and below the mmap base");
        }
        let grown = call(Syscall::Brk.raw(), a0(brk0 as u64 + 0x3000));
        if grown != Some(brk0 + 0x3000) {
            return Err("brk could not grow the i386 heap");
        }
        Ok(())
    });
    clear_compat_as();
    unload(proc);
    outcome
}
kernel_test_in!(
    "userspace/compat32",
    smoke_compat32_mmap_and_brk_stay_below_task_size_32
);

/// A one-page-text ET_DYN i386 object with an optional PT_INTERP, and a
/// PT_DYNAMIC whose `DT_REL` table holds one `R_386_RELATIVE` against a slot
/// carrying `rel_addend` when that is `Some`.
fn i386_dyn_image(entry: u32, interp: Option<&[u8]>, rel_addend: Option<u32>) -> Vec<u8> {
    let mut phdrs = Vec::new();
    let nph = 4 + u32::from(interp.is_some());
    phdrs.push(Ph32 {
        p_type: PT_PHDR,
        offset: EHDR32 as u32,
        vaddr: EHDR32 as u32,
        filesz: nph * PHDR32 as u32,
        memsz: nph * PHDR32 as u32,
        flags: PF_R,
        align: 4,
    });
    if let Some(name) = interp {
        phdrs.push(Ph32 {
            p_type: PT_INTERP,
            offset: 0x200,
            vaddr: 0x200,
            filesz: name.len() as u32,
            memsz: name.len() as u32,
            flags: PF_R,
            align: 1,
        });
    }
    phdrs.push(Ph32 {
        p_type: PT_LOAD,
        offset: 0,
        vaddr: 0,
        filesz: 0x1000,
        memsz: 0x1000,
        flags: PF_R | PF_X,
        align: 0x1000,
    });
    phdrs.push(Ph32 {
        p_type: PT_LOAD,
        offset: 0x1000,
        vaddr: 0x1000,
        filesz: 0x1000,
        memsz: 0x1000,
        flags: PF_R | PF_W,
        align: 0x1000,
    });
    phdrs.push(Ph32 {
        p_type: PT_DYNAMIC,
        offset: 0x1000,
        vaddr: 0x1000,
        filesz: 4 * 8,
        memsz: 4 * 8,
        flags: PF_R | PF_W,
        align: 4,
    });
    let mut b = elf32(ET_DYN, EM_386, entry, &phdrs, 0x2000);
    if let Some(name) = interp {
        b[0x200..0x200 + name.len()].copy_from_slice(name);
    }
    // Elf32_Dyn: DT_REL = 0x1100, DT_RELSZ, DT_RELENT = 8, then DT_NULL.
    put32(&mut b, 0x1000, 17);
    put32(&mut b, 0x1004, 0x1100);
    put32(&mut b, 0x1008, 18);
    put32(&mut b, 0x100C, if rel_addend.is_some() { 8 } else { 0 });
    put32(&mut b, 0x1010, 19);
    put32(&mut b, 0x1014, 8);
    // One Elf32_Rel { r_offset = 0x1200, r_info = R_386_RELATIVE (8) } whose
    // implicit addend sits in the slot itself.
    if let Some(addend) = rel_addend {
        put32(&mut b, 0x1100, 0x1200);
        put32(&mut b, 0x1104, 8);
        put32(&mut b, 0x1200, addend);
    }
    b
}

/// `load_elf_binary` for an i386 PIE naming an i386 interpreter:
///
///   * the PIE loads at `ELF_ET_DYN_BASE` = 0x400000 for `mmap_is_ia32()`
///     (plus `arch_mmap_rnd`), the interpreter in the compat mmap region
///     (`load_elf_interp` maps it through `get_unmapped_area`);
///   * AT_BASE is the interpreter's load address and AT_ENTRY the program's;
///   * the kernel applies no relocation to an i386 object: `ld.so`
///     relocates itself, and `Elf32_Rel` has implicit addends, so a kernel
///     pass would add the bias twice;
///   * the interpreter must itself be an IA-32 image (`elf_check_arch` on
///     `interp_elf_ex`, else `-ELIBBAD`); a 64-bit one is refused.
fn smoke_compat32_pie_and_interpreter_load_in_the_compat_window() -> TestResult {
    const NAME: &str = "/lib/ld-compat32-test.so.2";
    const PROG_ENTRY: u32 = 0x100;
    const INTERP_ENTRY: u32 = 0x80;
    const REL_ADDEND: u32 = 0x0000_1234;
    let interp: &'static [u8] = alloc::boxed::Box::leak(
        i386_dyn_image(INTERP_ENTRY, None, Some(REL_ADDEND)).into_boxed_slice(),
    );
    crate::register_interpreter(NAME, interp);
    let mut path = Vec::from(NAME.as_bytes());
    path.push(0);
    let prog = i386_dyn_image(PROG_ENTRY, Some(&path), None);
    let proc = match load_i386(&prog, &["prog"], &[]) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    let outcome = (|| -> Result<(), &'static str> {
        let stack = read_stack32(&proc.address_space, proc.stack_top.as_u64())
            .ok_or("the startup block is not a 32-bit layout")?;
        let base = u64::from(stack.aux(AT_BASE).ok_or("AT_BASE missing")?);
        if base < COMPAT_MMAP_BASE || base + 0x2000 > TASK_SIZE_32 {
            return Err("the i386 interpreter is not in the compat mmap window");
        }
        if proc.entry.0.as_u64() != base + u64::from(INTERP_ENTRY) {
            return Err("the first entry is not the interpreter's entry at AT_BASE");
        }
        let bias = proc.program_bias;
        if !(0x40_0000..=0x40_0000 + 0x0100_1000).contains(&bias) || bias & 0xFFF != 0 {
            return Err("an i386 PIE must load at ELF_ET_DYN_BASE (0x400000) plus rnd");
        }
        if stack.aux(AT_ENTRY).map(u64::from) != Some(bias + u64::from(PROG_ENTRY))
            || stack.aux(AT_PHDR).map(u64::from) != Some(bias + EHDR32 as u64)
        {
            return Err("AT_ENTRY/AT_PHDR not biased by the PIE's load base");
        }
        if user_u32(&proc.address_space, base + 0x1200) != Some(REL_ADDEND) {
            return Err("the kernel relocated an i386 interpreter's Elf32_Rel slot");
        }
        Ok(())
    })();
    unload(proc);
    if let Err(msg) = outcome {
        return TestResult::Fail(msg);
    }

    // An i386 program whose PT_INTERP names a 64-bit object.
    const NAME64: &str = "/lib/ld-compat32-test-64.so";
    let mut interp64 = alloc::vec![0u8; 0x1000];
    interp64[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    interp64[0x10..0x12].copy_from_slice(&ET_DYN.to_le_bytes());
    interp64[0x12..0x14].copy_from_slice(&EM_X86_64.to_le_bytes());
    interp64[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    interp64[0x18..0x20].copy_from_slice(&0x80u64.to_le_bytes());
    interp64[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
    interp64[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    interp64[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
    interp64[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
    let ph = 64usize;
    interp64[ph..ph + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
    interp64[ph + 4..ph + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    interp64[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
    interp64[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
    interp64[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
    let interp64: &'static [u8] = alloc::boxed::Box::leak(interp64.into_boxed_slice());
    crate::register_interpreter(NAME64, interp64);
    let mut path64 = Vec::from(NAME64.as_bytes());
    path64.push(0);
    let mixed = i386_dyn_image(PROG_ENTRY, Some(&path64), None);
    match load_i386(&mixed, &["prog"], &[]) {
        Ok(p) => {
            unload(p);
            TestResult::Fail("an i386 program loaded a 64-bit interpreter")
        }
        Err(_) => TestResult::Pass,
    }
}
kernel_test_in!(
    "userspace/compat32",
    smoke_compat32_pie_and_interpreter_load_in_the_compat_window
);

/// Mixed exec, 64-bit to i386: a 64-bit task's `execve` of an i386 image
/// goes through `compat_binfmt_elf` instead of failing with ENOEXEC
/// ("exec format error", Steam's `ldd` of `steamui.so`). The harness has no
/// user-task context, so a load that succeeds ends in the kernel-test bail
/// (-ENOSYS) rather than in ring 3; -ENOEXEC means the image was refused.
fn smoke_compat32_execve_of_an_i386_image_is_not_enoexec() -> TestResult {
    let image = i386_static_image();
    with_memfs(
        "/compat32-exec",
        "compat32-exec",
        &[("hello", image.as_slice())],
        || {
            let path = b"/compat32-exec/hello\0";
            match call(Syscall::Execve.raw(), a2(path.as_ptr() as u64, 0, 0)) {
                Some(ENOSYS) => Ok(()),
                Some(ENOEXEC) => Err("execve of an i386 ELF32 image is still ENOEXEC"),
                _ => Err("execve of an i386 image neither loaded nor reported ENOEXEC"),
            }
        },
    )
}
kernel_test_in!(
    "userspace/compat32",
    smoke_compat32_execve_of_an_i386_image_is_not_enoexec
);

// ── The i386 syscall table ───────────────────────────────────────────

/// The `int 0x80` gate's view of an i386 call, as `frame` builds it: six
/// 32-bit registers zero-extended into `args()`, `in_ia32_syscall()` true.
struct Ia32Ctx {
    args: SyscallArgs,
    ret: Option<SyscallReturn>,
}

impl TrapContext for Ia32Ctx {
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
    fn in_ia32_syscall(&self) -> bool {
        true
    }
    fn in_compat_mode(&self) -> bool {
        true
    }
}

/// Issue i386 syscall `nr` through the i386 table with ebx..ebp = `regs`
/// (each truncated to 32 bits, as the registers are) and return eax,
/// sign-extended the way an i386 libc reads a negative errno.
fn call32(nr: u32, regs: [u64; 6]) -> i64 {
    let reg = |i: usize| u64::from(regs[i] as u32);
    let mut ctx = Ia32Ctx {
        args: SyscallArgs {
            arg0: reg(0),
            arg1: reg(1),
            arg2: reg(2),
            arg3: reg(3),
            arg4: reg(4),
            arg5: reg(5),
        },
        ret: None,
    };
    let _ = crate::compat32::table::dispatch(nr, &mut ctx);
    match ctx.ret {
        Some(r) => i64::from(r.value as u32 as i32),
        None => i64::MIN,
    }
}

/// Run `body` with `proc`'s address space live on this CPU, as it is for a
/// syscall that task makes; the previous root comes back afterwards.
fn with_live_as(
    proc: &crate::UserProcess,
    body: impl FnOnce() -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    // SAFETY: CPL0 read of CR3; the value is restored below.
    let saved = unsafe { narf_arch::x86_64::cr::read_cr3() };
    if proc.address_space.activate().is_err() {
        return Err("activating the i386 address space failed");
    }
    let outcome = body();
    // SAFETY: `saved` is the root this CPU ran on before `activate`.
    unsafe { narf_arch::x86_64::cr::write_cr3(saved) };
    outcome
}

/// Store `bytes` at user `va` of the live address space.
fn put_user(va: u64, bytes: &[u8]) -> Result<(), &'static str> {
    // SAFETY: the caller's address space is live (`with_live_as`) and `va`
    // lies in its eagerly-backed data segment; the copy validates the range.
    unsafe { crate::handlers::copy_to_user(va, bytes) }.map_err(|_| "user store failed")
}

/// Load `len` bytes from user `va` of the live address space.
fn get_user(va: u64, len: usize) -> Result<Vec<u8>, &'static str> {
    let mut out = alloc::vec![0u8; len];
    // SAFETY: as `put_user`.
    unsafe { crate::handlers::copy_from_user(&mut out, va) }.map_err(|_| "user load failed")?;
    Ok(out)
}

fn get_u32(va: u64) -> Result<u32, &'static str> {
    let b = get_user(va, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// i386 calls with no structure to convert reach the native handler with
/// the same answer: the identity family (`getpid` 20, `gettid` 224,
/// `getppid` 64 and the `*32` uid/gid calls 199-202), `set_tid_address`
/// (258), and `sys_ni_syscall`'s -ENOSYS for a number the table lacks.
fn smoke_compat32_table_identity_calls_match_native() -> TestResult {
    with_setup_strict(|| {
        for (nr, native) in [
            (20u32, Syscall::GetPid),
            (224, Syscall::Gettid),
            (64, Syscall::GetPpid),
            (199, Syscall::GetUid),
            (200, Syscall::GetGid),
            (201, Syscall::Geteuid),
            (202, Syscall::Getegid),
        ] {
            let want = call(native.raw(), a0(0)).ok_or("native identity call failed")?;
            if call32(nr, [0; 6]) != want {
                return Err("an i386 identity call does not match its native handler");
            }
        }
        let tid = call(Syscall::Gettid.raw(), a0(0)).ok_or("native gettid failed")?;
        if call32(258, [0; 6]) != tid {
            return Err("i386 set_tid_address(NULL) must return the caller's tid");
        }
        // 17 is i386 `break`, `sys_ni_syscall` on every kernel.
        for nr in [17u32, 0x7FFF] {
            if call32(nr, [0; 6]) != ENOSYS {
                return Err("an i386 number without an entry must be -ENOSYS");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "userspace/compat32",
    smoke_compat32_table_identity_calls_match_native
);

/// The i386 I/O calls through 32-bit pointers in an IA-32 address space:
///
///   * `pipe` (42), `write` (4), `read` (3), `close` (6) pass through;
///   * `writev` (146) / `readv` (145) read 8-byte `struct compat_iovec`
///     (`import_iovec` under `in_compat_syscall()`), not 16-byte iovecs;
///   * `open` (5) and `openat` (295) with `AT_FDCWD`, which arrives as the
///     32-bit register 0xFFFFFF9C and is an `int` (sign-extended by the
///     `__ia32_sys_openat` wrapper);
///   * `ioctl` (54): `compat_sys_ioctl` serves the commands whose argument
///     is layout-compatible (FIONREAD, the termios family) through the
///     native path, answers EBADF for a dead descriptor first, and ENOTTY
///     for a command with no compat translation (DRM_IOCTL_VERSION here).
fn smoke_compat32_table_io_takes_32bit_pointers_and_iovecs() -> TestResult {
    const O_RDONLY: u64 = 0;
    const FIONREAD: u64 = 0x541B;
    const TCGETS: u64 = 0x5401;
    const DRM_IOCTL_VERSION: u64 = 0xC040_6400;
    let image = i386_static_image();
    let proc = match load_i386(&image, &["io"], &[]) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    let outcome = with_memfs("/compat32-io", "compat32-io", &[("f", b"abc")], || {
        install_compat_as(&proc);
        with_live_as(&proc, || {
            let base = u64::from(STATIC_DATA_VA);
            put_user(base, b"hello")?;
            if call32(42, [base + 0x100, 0, 0, 0, 0, 0]) != 0 {
                return Err("i386 pipe(int[2]) failed");
            }
            let rfd = u64::from(get_u32(base + 0x100)?);
            let wfd = u64::from(get_u32(base + 0x104)?);
            if call32(4, [wfd, base, 5, 0, 0, 0]) != 5 {
                return Err("i386 write through a 32-bit pointer failed");
            }
            if call32(54, [rfd, FIONREAD, base + 0x180, 0, 0, 0]) != 0
                || get_u32(base + 0x180)? != 5
            {
                return Err("i386 ioctl(FIONREAD) did not reach the pipe");
            }
            if call32(54, [rfd, TCGETS, base + 0x400, 0, 0, 0]) != ENOTTY {
                return Err("i386 ioctl(TCGETS) on a pipe must be the tty layer's ENOTTY");
            }
            if call32(54, [rfd, DRM_IOCTL_VERSION, base + 0x400, 0, 0, 0]) != ENOTTY {
                return Err("an ioctl with no compat translation must be ENOTTY");
            }
            if call32(54, [999, TCGETS, base + 0x400, 0, 0, 0]) != EBADF {
                return Err("i386 ioctl on a dead fd must be EBADF");
            }
            if call32(3, [rfd, base + 0x200, 16, 0, 0, 0]) != 5
                || get_user(base + 0x200, 5)? != b"hello"
            {
                return Err("i386 read through a 32-bit pointer failed");
            }
            // struct compat_iovec { compat_uptr_t iov_base; compat_size_t iov_len; }
            let mut iov = Vec::new();
            for word in [base as u32, 2, base as u32 + 2, 3] {
                iov.extend_from_slice(&word.to_le_bytes());
            }
            put_user(base + 0x300, &iov)?;
            if call32(146, [wfd, base + 0x300, 2, 0, 0, 0]) != 5 {
                return Err("i386 writev did not read 8-byte compat_iovecs");
            }
            let mut iov = Vec::new();
            for word in [base as u32 + 0x500, 5] {
                iov.extend_from_slice(&word.to_le_bytes());
            }
            put_user(base + 0x320, &iov)?;
            if call32(145, [rfd, base + 0x320, 1, 0, 0, 0]) != 5
                || get_user(base + 0x500, 5)? != b"hello"
            {
                return Err("i386 readv did not fill a compat_iovec");
            }
            if call32(6, [rfd, 0, 0, 0, 0, 0]) != 0 || call32(6, [wfd, 0, 0, 0, 0, 0]) != 0 {
                return Err("i386 close failed");
            }
            put_user(base + 0x600, b"/compat32-io/f\0")?;
            for fd in [
                call32(5, [base + 0x600, O_RDONLY, 0, 0, 0, 0]),
                call32(295, [0xFFFF_FF9C, base + 0x600, O_RDONLY, 0, 0, 0]),
            ] {
                if fd < 0 {
                    return Err("i386 open/openat(AT_FDCWD) of an existing file failed");
                }
                if call32(3, [fd as u64, base + 0x700, 8, 0, 0, 0]) != 3
                    || get_user(base + 0x700, 3)? != b"abc"
                {
                    return Err("reading the opened file through the i386 table failed");
                }
                let _ = call32(6, [fd as u64, 0, 0, 0, 0, 0]);
            }
            Ok(())
        })
    });
    clear_compat_as();
    unload(proc);
    outcome
}
kernel_test_in!(
    "userspace/compat32",
    smoke_compat32_table_io_takes_32bit_pointers_and_iovecs
);

/// The i386 memory calls keep an IA-32 task inside `TASK_SIZE_32`:
///
///   * `mmap2` (192) takes its offset in 4096-byte pages (`sys_mmap_pgoff`)
///     and returns an address below 0xFFFFe000;
///   * the old `mmap` (90) reads `struct mmap_arg_struct32` (six 32-bit
///     words) and refuses an offset that is not page-aligned with EINVAL
///     and an unreadable struct with EFAULT (`compat_sys_ia32_mmap`);
///   * a `MAP_FIXED` range ending above `TASK_SIZE_32` is ENOMEM
///     (`__get_unmapped_area`: `addr > TASK_SIZE - len`);
///   * `munmap` (91), `mprotect` (125) and `brk` (45) pass through.
fn smoke_compat32_table_memory_calls_stay_below_task_size_32() -> TestResult {
    const PROT_R: u64 = 0x1;
    const PROT_RW: u64 = 0x3;
    const MAP_PRIVATE_ANON: u64 = 0x02 | 0x20;
    const MAP_FIXED: u64 = 0x10;
    const FD_NONE: u64 = 0xFFFF_FFFF;
    let image = i386_static_image();
    let proc = match load_i386(&image, &["mem"], &[]) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    let outcome = with_setup_strict(|| {
        install_compat_as(&proc);
        with_live_as(&proc, || {
            let in_window = |addr: i64, len: u64| {
                addr >= 0 && (addr as u64) >= COMPAT_MMAP_BASE && addr as u64 + len <= TASK_SIZE_32
            };
            let anon = call32(192, [0, 0x2000, PROT_RW, MAP_PRIVATE_ANON, FD_NONE, 0]);
            if !in_window(anon, 0x2000) {
                return Err("i386 mmap2 must return an address inside the 32-bit window");
            }
            let base = u64::from(STATIC_DATA_VA);
            // struct mmap_arg_struct32 { addr, len, prot, flags, fd, offset }
            let mut arg = Vec::new();
            for word in [
                0u32,
                0x1000,
                PROT_RW as u32,
                MAP_PRIVATE_ANON as u32,
                u32::MAX,
                0,
            ] {
                arg.extend_from_slice(&word.to_le_bytes());
            }
            put_user(base, &arg)?;
            let old = call32(90, [base, 0, 0, 0, 0, 0]);
            if !in_window(old, 0x1000) {
                return Err("i386 old mmap(mmap_arg_struct32 *) failed or left the window");
            }
            put_user(base + 20, &0x800u32.to_le_bytes())?;
            if call32(90, [base, 0, 0, 0, 0, 0]) != EINVAL {
                return Err("old mmap with an unaligned offset must be EINVAL");
            }
            if call32(90, [0xFFFF_F000, 0, 0, 0, 0, 0]) != EFAULT {
                return Err("old mmap with an unreadable struct must be EFAULT");
            }
            if call32(
                192,
                [
                    TASK_SIZE_32 - 0x1000,
                    0x2000,
                    PROT_RW,
                    MAP_PRIVATE_ANON | MAP_FIXED,
                    FD_NONE,
                    0,
                ],
            ) != ENOMEM
            {
                return Err("a MAP_FIXED range past TASK_SIZE_32 must be ENOMEM");
            }
            if call32(125, [anon as u64, 0x1000, PROT_R, 0, 0, 0]) != 0 {
                return Err("i386 mprotect failed");
            }
            if call32(91, [anon as u64, 0x2000, 0, 0, 0, 0]) != 0
                || call32(91, [old as u64, 0x1000, 0, 0, 0, 0]) != 0
            {
                return Err("i386 munmap failed");
            }
            let brk = call32(45, [0; 6]);
            if brk <= 0 || brk as u64 >= COMPAT_MMAP_BASE {
                return Err("i386 brk(0) must report the 32-bit program break");
            }
            Ok(())
        })
    });
    clear_compat_as();
    unload(proc);
    outcome
}
kernel_test_in!(
    "userspace/compat32",
    smoke_compat32_table_memory_calls_stay_below_task_size_32
);

/// Time and identity structures through the i386 table:
///
///   * `clock_gettime` (265) is `clock_gettime32`, writing an 8-byte
///     `struct old_timespec32` and nothing past it;
///     `clock_gettime64` (403) writes the 16-byte `__kernel_timespec`;
///   * `uname` (122, `newuname`) reports `machine` "x86_64" to a compat task,
///     and "i686" only once its personality is PER_LINUX32
///     (`override_architecture`, `COMPAT_UTS_MACHINE`).
fn smoke_compat32_table_time_and_uname_layouts() -> TestResult {
    const CLOCK_MONOTONIC: u64 = 1;
    const PER_LINUX32: u64 = 0x0008;
    const UTS_FIELD: u64 = 65;
    let image = i386_static_image();
    let proc = match load_i386(&image, &["time"], &[]) {
        Ok(p) => p,
        Err(e) => return TestResult::Fail(e),
    };
    let outcome = with_setup_strict(|| {
        install_compat_as(&proc);
        with_live_as(&proc, || {
            let base = u64::from(STATIC_DATA_VA);
            put_user(base, &[0xAA; 32])?;
            if call32(265, [CLOCK_MONOTONIC, base, 0, 0, 0, 0]) != 0 {
                return Err("i386 clock_gettime (time32) failed");
            }
            let ts = get_user(base, 16)?;
            let nsec = u32::from_le_bytes([ts[4], ts[5], ts[6], ts[7]]);
            if nsec >= 1_000_000_000 || ts[8..16].iter().any(|&b| b != 0xAA) {
                return Err("clock_gettime32 must write exactly an 8-byte old_timespec32");
            }
            put_user(base, &[0xAA; 32])?;
            if call32(403, [CLOCK_MONOTONIC, base, 0, 0, 0, 0]) != 0 {
                return Err("i386 clock_gettime64 failed");
            }
            let ts = get_user(base, 24)?;
            let nsec = u64::from_le_bytes(ts[8..16].try_into().unwrap_or([0xFF; 8]));
            if ts[4..8] != [0, 0, 0, 0] || nsec >= 1_000_000_000 || ts[16..24] != [0xAA; 8] {
                return Err("clock_gettime64 must write a 16-byte __kernel_timespec");
            }
            let machine = |p: u64| get_user(p + 4 * UTS_FIELD, 7);
            if call32(122, [base + 0x100, 0, 0, 0, 0, 0]) != 0 {
                return Err("i386 uname failed");
            }
            if machine(base + 0x100)? != b"x86_64\0" {
                return Err("a compat task without PER_LINUX32 must see machine x86_64");
            }
            if call32(136, [PER_LINUX32, 0, 0, 0, 0, 0]) < 0 {
                return Err("i386 personality(PER_LINUX32) failed");
            }
            let uname = call32(122, [base + 0x100, 0, 0, 0, 0, 0]);
            let _ = call32(136, [0, 0, 0, 0, 0, 0]);
            if uname != 0 || machine(base + 0x100)?[..5] != *b"i686\0" {
                return Err("PER_LINUX32 must report COMPAT_UTS_MACHINE \"i686\"");
            }
            Ok(())
        })
    });
    clear_compat_as();
    unload(proc);
    outcome
}
kernel_test_in!(
    "userspace/compat32",
    smoke_compat32_table_time_and_uname_layouts
);
