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
