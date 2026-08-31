//! `elf_loader` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

// execve's /proc/self/fd/N magic-symlink parse: glibc fexecve and systemd
// 257's sd-executor spawn execve("/proc/self/fd/<N>") after opening the
// binary O_PATH; execve must recognize that path and resolve the fd. Only a
// bare fd (no trailing sub-path) under /proc/self/fd or /proc/<pid>/fd counts.
#[cfg(target_arch = "x86_64")]
fn smoke_userspace_parse_proc_self_fd() -> TestResult {
    use crate::handlers::parse_proc_self_fd as p;
    if p("/proc/self/fd/3") != Some(3) {
        return TestResult::Fail("/proc/self/fd/3 should parse to 3");
    }
    if p("/proc/1234/fd/7") != Some(7) {
        return TestResult::Fail("/proc/<pid>/fd/7 should parse to 7");
    }
    if p("/proc/self/fd/3/foo").is_some() {
        return TestResult::Fail("a trailing sub-path must not parse");
    }
    if p("/proc/self/fd/").is_some() || p("/proc/self/fd/x").is_some() {
        return TestResult::Fail("empty/non-numeric fd must not parse");
    }
    if p("/usr/lib/systemd/systemd-executor").is_some() {
        return TestResult::Fail("an ordinary path must not parse as a proc-fd");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_parse_proc_self_fd);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_user_process_builds_runnable_image() -> TestResult {
    // Build a minimal ELF64 with a 1-page R|X PT_LOAD, hand it to
    // `load_user_process`, confirm the returned UserProcess has a
    // fresh pid, a materialised AS with both the code segment and
    // a mapped user stack at DEFAULT_USER_STACK_BASE.
    use crate::{load_user_process, DEFAULT_USER_STACK_TOP};
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(64 + 56 + 0x1000);
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
    bytes.extend_from_slice(&64u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&64u16.to_le_bytes());
    bytes.extend_from_slice(&56u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&(64u64 + 56).to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.resize(64 + 56 + 0x1000, 0);

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process(&bytes) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process failed"),
    };

    if proc.pid.raw() == 0 {
        return TestResult::Fail("pid should be non-zero");
    }
    if proc.entry.0 != VirtAddr::new(0x0000_0080_0000_1111) {
        return TestResult::Fail("entry mis-decoded");
    }
    if proc.stack_top.as_u64() != DEFAULT_USER_STACK_TOP {
        return TestResult::Fail("stack_top mis-computed");
    }

    // AS should have the code segment + stack + stack-guard. On
    // x86_64 the loader also stages a synthetic TLS region (one
    // page) for every binary that lacks PT_TLS, so the count is 4
    // there. The stack-guard (1-page PROT_NONE region one page
    // below the stack base) was added after the original test was
    // written and bumped the count from 3 → 4.
    let expected_regions: usize = if cfg!(target_arch = "x86_64") { 4 } else { 3 };
    if proc.address_space.region_count() != expected_regions {
        return TestResult::Fail("address space carried unexpected region count");
    }

    // Code segment PTE installed.
    // SAFETY: `proc.address_space.root` is the live root the loader just built,
    // identity-reachable as `translate` requires; this only walks its tables for
    // the code segment vaddr.
    // SAFETY: Valid memory or trusted environment
    let code_phys = unsafe {
        paging::translate(
            proc.address_space.root,
            VirtAddr::new(0x0000_0080_0000_1000),
        )
    };
    if code_phys.is_none() {
        return TestResult::Fail("code segment not materialized");
    }

    // Stack PTE installed — check the top committed page. Only the top
    // DEFAULT_USER_STACK_BYTES of the reserved region are eagerly backed;
    // the low pages (including DEFAULT_USER_STACK_BASE) are lazy/demand-
    // zero and have no PTE until first access.
    // SAFETY: same live loader-built root as above; only walks its tables for the
    // top committed stack vaddr.
    // SAFETY: Valid memory or trusted environment
    let stack_phys = unsafe {
        paging::translate(
            proc.address_space.root,
            VirtAddr::new(DEFAULT_USER_STACK_TOP - 0x1000),
        )
    };
    if stack_phys.is_none() {
        return TestResult::Fail("stack region not materialized");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_load_user_process_builds_runnable_image
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_user_process_with_argv() -> TestResult {
    // Same shape as the no-args runnable-image test, but exercises
    // `load_user_process_with`: pass argv/envp/aux, then verify
    // the new RSP is inside the stack region and that walking the
    // argv pointer-array yields the right strings.
    use crate::{
        load_user_process_with, AuxEntry, DEFAULT_USER_STACK_BASE, DEFAULT_USER_STACK_TOP,
    };
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(64 + 56 + 0x1000);
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
    bytes.extend_from_slice(&64u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&64u16.to_le_bytes());
    bytes.extend_from_slice(&56u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&(64u64 + 56).to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.resize(64 + 56 + 0x1000, 0);

    let argv = ["one", "two"];
    let envp = ["A=1"];
    let aux = [AuxEntry::Pagesz(4096)];

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &argv, &envp, &aux) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };

    let stack_top = DEFAULT_USER_STACK_TOP;
    let new_rsp = proc.stack_top.as_u64();
    if new_rsp >= stack_top || new_rsp < DEFAULT_USER_STACK_BASE {
        return TestResult::Fail("rsp not inside stack region");
    }
    if (new_rsp & 0xF) != 0 {
        return TestResult::Fail("rsp not 16-byte aligned");
    }

    // Per-byte read goes through translate again so we honour the
    // user-vaddr offset within the page (translate itself returns
    // page-aligned phys).
    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: Valid memory or trusted environment
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
        // SAFETY: `p` is the phys frame `translate` just resolved for this page;
        // OR-ing the in-page offset stays within that identity-mapped frame, and the
        // `u64` read is aligned because callers pass 8-byte-aligned `vaddr`s.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { *((p.as_u64() | (vaddr & 0xFFF)) as *const u64) })
    };
    let argc = match read_u64(new_rsp) {
        Some(v) => v,
        None => return TestResult::Fail("rsp not materialised"),
    };
    if argc != 2 {
        if argc == 0 {
            return TestResult::Fail("argc reads back as 0");
        }
        return TestResult::Fail("argc not 2 (non-zero)");
    }
    let argv0 = read_u64(new_rsp + 8).unwrap();
    let argv1 = read_u64(new_rsp + 16).unwrap();
    let argv_term = read_u64(new_rsp + 24).unwrap();
    if argv_term != 0 {
        return TestResult::Fail("argv NULL terminator missing");
    }
    // Resolve argv[0] / argv[1] via the same translate path.
    let resolve = |v: u64, want: &str| -> bool {
        // SAFETY: `proc.address_space.root` is the live top-level page-table frame
        // for this test process; `translate` only reads that hierarchy and the
        // page-aligned `VirtAddr` is a plain table walk with no aliasing.
        // SAFETY: Valid memory or trusted environment
        let p = match unsafe {
            paging::translate(proc.address_space.root, VirtAddr::new(v & !0xFFF))
        } {
            Some(p) => p.as_u64() | (v & 0xFFF),
            None => return false,
        };
        let want_b = want.as_bytes();
        for (i, &b) in want_b.iter().enumerate() {
            // SAFETY: `p` is the physical/identity-mapped address that `translate`
            // returned for this user `VirtAddr`, so it points at the mapped page;
            // `i < want_b.len()` keeps the read within the resolved string buffer.
            // SAFETY: Valid memory or trusted environment
            if unsafe { *((p + i as u64) as *const u8) } != b {
                return false;
            }
        }
        // SAFETY: same mapped page as above; `want_b.len()` is the byte just past
        // the compared bytes, still within the page checked by `translate`.
        // SAFETY: Valid memory or trusted environment
        unsafe { *((p + want_b.len() as u64) as *const u8) == 0 }
    };
    if !resolve(argv0, "one") {
        return TestResult::Fail("argv[0] != \"one\"");
    }
    if !resolve(argv1, "two") {
        return TestResult::Fail("argv[1] != \"two\"");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_load_user_process_with_argv);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_user_process_with_interp() -> TestResult {
    // PT_INTERP follow-through. Build two minimal ELFs:
    //
    //   - program: 2 PT_LOAD segments (RX code + RW data) + 1
    //     PT_INTERP pointing at the literal "ld-narf\0".
    //   - interp:  1 PT_LOAD segment (RX code).
    //
    // Register the interpreter under "ld-narf", call
    // load_user_process_with, and verify:
    //   - proc.entry resolves to the *interpreter's* entry +
    //     INTERP_BIAS (the program's entry is forwarded via
    //     AT_ENTRY).
    //   - Both bias=0 (program) and bias=INTERP_BIAS (interp)
    //     vaddr ranges materialise.
    //   - region_count() == 4 (program code + program data +
    //     interp code + stack).
    //   - The aux vector on the stack carries AT_PAGESZ, AT_ENTRY,
    //     AT_BASE with the expected values.
    use crate::{interp::__test_clear_interpreters, load_user_process_with, register_interpreter};
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    const INTERP_BIAS: u64 = 0x0000_4000_0000_0000;
    const PROG_CODE_VA: u64 = 0x0000_0080_0000_1000;
    const PROG_DATA_VA: u64 = 0x0000_0080_0000_2000;
    const PROG_ENTRY: u64 = 0x0000_0080_0000_1111;
    const INTERP_CODE_VA: u64 = 0x0000_0000_0000_1000;
    const INTERP_ENTRY: u64 = 0x0000_0000_0000_1234;

    // Build a 3-phdr program ELF. Phdr 0 = PT_INTERP naming the
    // string at offset 64+3*56=232; phdrs 1 & 2 = PT_LOAD code/data
    // backed by file pages at offset 0x1000 / 0x2000.
    fn write_program() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x3000;
        let mut b = alloc::vec![0u8; FSIZE];
        // ELF ident + e_type/e_machine/e_version.
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&PROG_ENTRY.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        b[0x30..0x34].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x38..0x3A].copy_from_slice(&3u16.to_le_bytes()); // e_phnum
                                                            // Phdr 0 — PT_INTERP pointing at the "ld-narf\0" string.
        let interp_str = b"ld-narf\0";
        let interp_off = 64 + 3 * 56;
        b[interp_off..interp_off + interp_str.len()].copy_from_slice(interp_str);
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&3u32.to_le_bytes()); // PT_INTERP
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&(interp_off as u64).to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&0u64.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&0u64.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&(interp_str.len() as u64).to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&(interp_str.len() as u64).to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&1u64.to_le_bytes());
        // Phdr 1 — PT_LOAD code (RX) at PROG_CODE_VA, file off 0x1000.
        ph = 64 + 56;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&PROG_CODE_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&PROG_CODE_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        // Phdr 2 — PT_LOAD data (RW) at PROG_DATA_VA, file off 0x2000.
        ph = 64 + 2 * 56;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x2000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&PROG_DATA_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&PROG_DATA_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        b
    }

    // Single PT_LOAD interpreter ELF. ET_EXEC keeps the parser
    // happy; entry sits inside the loaded page.
    fn write_interp() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x2000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&INTERP_ENTRY.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&INTERP_CODE_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&INTERP_CODE_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        b
    }

    __test_clear_interpreters();

    let prog_bytes = write_program();
    // Leak the interp bytes — the registry stores `&'static [u8]`
    // for the lifetime of the kernel. Tests run once per boot so a
    // small leak is fine; production code's interpreter bytes come
    // from `.rodata` of an init image.
    let interp_bytes = alloc::boxed::Box::leak(write_interp().into_boxed_slice());
    register_interpreter("ld-narf", interp_bytes);

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `prog_bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&prog_bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };

    // Entry must point at the interpreter (program entry + INTERP_BIAS
    // for the interp's vaddr — its INTERP_ENTRY plus the bias).
    if proc.entry.0 != VirtAddr::new(INTERP_ENTRY + INTERP_BIAS) {
        return TestResult::Fail("entry should be interpreter entry + bias");
    }

    // Program code + program data + interp + stack + stack-guard
    // (+ TLS region on x86_64). The stack-guard PROT_NONE region
    // was added after this test was written and bumps the expected
    // count by 1.
    let expected_regions: usize = if cfg!(target_arch = "x86_64") { 6 } else { 5 };
    if proc.address_space.region_count() != expected_regions {
        return TestResult::Fail("unexpected region count after PT_INTERP load");
    }
    if proc.loaded_mappings.len() != 4 {
        return TestResult::Fail("loader did not retain every perf-visible VMA");
    }
    let code = &proc.loaded_mappings[0];
    let data = &proc.loaded_mappings[1];
    let interp = &proc.loaded_mappings[2];
    let stack = &proc.loaded_mappings[3];
    if (code.addr, code.len, code.pgoff, code.prot, &code.filename)
        != (PROG_CODE_VA, 0x1000, 0x1000, 5, &None)
        || (data.addr, data.len, data.pgoff, data.prot, &data.filename)
            != (PROG_DATA_VA, 0x1000, 0x2000, 3, &None)
        || (interp.addr, interp.len, interp.pgoff, interp.prot)
            != (INTERP_CODE_VA + INTERP_BIAS, 0x1000, 0x1000, 5)
        || interp.filename.as_deref() != Some("ld-narf")
        || stack.addr != crate::process::DEFAULT_USER_STACK_BASE
        || stack.len != crate::process::DEFAULT_USER_STACK_RESERVED
        || stack.filename.as_deref() != Some("[stack]")
    {
        return TestResult::Fail("retained loader VMA metadata is not exact");
    }

    // Both program and interpreter pages must be materialised.
    // SAFETY: `proc.address_space.root` is the live loader-built root, identity-
    // reachable as `translate` requires; only walks its tables for `PROG_CODE_VA`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { paging::translate(proc.address_space.root, VirtAddr::new(PROG_CODE_VA)) }.is_none()
    {
        return TestResult::Fail("program code not materialised");
    }
    // SAFETY: same live loader-built root; only walks its tables for `PROG_DATA_VA`.
    if unsafe { paging::translate(proc.address_space.root, VirtAddr::new(PROG_DATA_VA)) }.is_none()
    {
        return TestResult::Fail("program data not materialised");
    }
    // SAFETY: same live loader-built root; only walks its tables for the
    // bias-relocated interpreter code vaddr.
    // SAFETY: Valid memory or trusted environment
    if unsafe {
        paging::translate(
            proc.address_space.root,
            VirtAddr::new(INTERP_CODE_VA + INTERP_BIAS),
        )
    }
    .is_none()
    {
        return TestResult::Fail("interpreter code not materialised at bias");
    }

    // Walk the aux vector on the stack: argc=0, argv NULL, envp
    // NULL, then aux pairs. Match by AT_* tag.
    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: Valid memory or trusted environment
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
        // SAFETY: `p` is the phys frame `translate` just resolved for this page;
        // OR-ing the in-page offset stays within that identity-mapped frame, and the
        // `u64` read is aligned because callers pass 8-byte-aligned `vaddr`s.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { *((p.as_u64() | (vaddr & 0xFFF)) as *const u64) })
    };
    let rsp = proc.stack_top.as_u64();
    let argc = read_u64(rsp).unwrap_or(0xDEAD);
    if argc != 0 {
        return TestResult::Fail("argc should be 0 in this test");
    }
    let argv_null = read_u64(rsp + 8).unwrap_or(0xDEAD);
    if argv_null != 0 {
        return TestResult::Fail("argv NULL terminator missing");
    }
    let envp_null = read_u64(rsp + 16).unwrap_or(0xDEAD);
    if envp_null != 0 {
        return TestResult::Fail("envp NULL terminator missing");
    }

    // Aux pairs start at rsp+24. Walk until AT_NULL (key=0); we
    // expect to find AT_PAGESZ(6), AT_ENTRY(9), AT_BASE(7).
    let mut at_pagesz: Option<u64> = None;
    let mut at_entry: Option<u64> = None;
    let mut at_base: Option<u64> = None;
    let mut p = rsp + 24;
    for _ in 0..16 {
        let key = read_u64(p).unwrap_or(0xDEAD);
        let val = read_u64(p + 8).unwrap_or(0xDEAD);
        match key {
            0 => break,
            6 => at_pagesz = Some(val),
            9 => at_entry = Some(val),
            7 => at_base = Some(val),
            _ => {}
        }
        p += 16;
    }
    if at_pagesz != Some(4096) {
        return TestResult::Fail("AT_PAGESZ missing or wrong");
    }
    if at_entry != Some(PROG_ENTRY) {
        return TestResult::Fail("AT_ENTRY should be the program entry");
    }
    if at_base != Some(INTERP_BIAS) {
        return TestResult::Fail("AT_BASE should be the interp bias");
    }

    __test_clear_interpreters();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_load_user_process_with_interp);

// Regression: a PT_INTERP binary whose interpreter cannot be resolved
// (not registered in-memory, not readable through the VFS) must FAIL to
// load with `ProcessLoadError::InterpUnavailable`. The old behaviour
// silently fell through to the program's own entry — starting glibc's
// `_start` against an unrelocated GOT, whose first indirect call lands
// on a zeroed slot (#PF faultva=0 rip=0, pf-errcode 0x15). That silent
// fallback intermittently killed freshly fork+exec'd processes whenever
// the interp read transiently failed under contended block I/O.
#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_pt_interp_unresolvable_fails() -> TestResult {
    use crate::{interp::__test_clear_interpreters, load_user_process_with, ProcessLoadError};

    __test_clear_interpreters();
    // Absolute path so the VFS fallback is exercised too — nothing is
    // mounted there, so both resolution sources miss.
    let prog = build_pt_interp_elf("/nonexistent/ld-narf-missing.so");

    // SAFETY: test harness runs with the low 4 GiB identity-mapped and
    // the frame allocator initialised (loader `# Safety` contract);
    // `prog` outlives the call.
    match unsafe { load_user_process_with(&prog, &[], &[], &[]) } {
        Err(ProcessLoadError::InterpUnavailable) => TestResult::Pass,
        Err(_) => TestResult::Fail("wrong error; expected InterpUnavailable"),
        Ok(_) => TestResult::Fail("PT_INTERP binary must not load without its interpreter"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_load_pt_interp_unresolvable_fails
);

fn smoke_userspace_parse_pt_tls() -> TestResult {
    // PT_TLS parsing. Hand-build a minimal ELF with one PT_LOAD (so the
    // parser sees a "loadable" image) and one PT_TLS pointing at known
    // bytes, then assert `parse_elf` populates `image.tls` with those
    // exact field values. Parse-only — load/staging is a follow-up.
    use crate::{parse_elf, ElfError};

    const TLS_FILE_OFF: u64 = 0x2000;
    const TLS_FILE_SIZE: u64 = 0x40;
    const TLS_MEM_SIZE: u64 = 0x80; // 0x40 BSS-zero past file image
    const TLS_ALIGN: u64 = 16;
    const TLS_VADDR: u64 = 0x0000_0080_0000_3000;

    fn write_one_tls() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x3000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        b[0x30..0x34].copy_from_slice(&0u32.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // 2 phdrs
                                                            // Phdr 0 — PT_LOAD code (RX) at file off 0x1000.
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes()); // PF_R|PF_X
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        // Phdr 1 — PT_TLS at file off 0x2000.
        ph = 64 + 56;
        b[ph..ph + 0x04].copy_from_slice(&7u32.to_le_bytes()); // PT_TLS
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&TLS_FILE_OFF.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&TLS_FILE_SIZE.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&TLS_MEM_SIZE.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&TLS_ALIGN.to_le_bytes());
        b
    }

    let bytes = write_one_tls();
    let image = match parse_elf(&bytes) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("parse_elf failed on PT_TLS image"),
    };
    let tls = match image.tls {
        Some(t) => t,
        None => return TestResult::Fail("image.tls should be Some for PT_TLS ELF"),
    };
    if tls.file_off != TLS_FILE_OFF {
        return TestResult::Fail("tls.file_off mismatch");
    }
    if tls.file_size != TLS_FILE_SIZE {
        return TestResult::Fail("tls.file_size mismatch");
    }
    if tls.mem_size != TLS_MEM_SIZE {
        return TestResult::Fail("tls.mem_size mismatch");
    }
    if tls.align != TLS_ALIGN {
        return TestResult::Fail("tls.align mismatch");
    }
    if tls.vaddr != TLS_VADDR {
        return TestResult::Fail("tls.vaddr mismatch");
    }

    // Negative path: a second PT_TLS must be rejected. Cheaper to
    // build a fresh 3-phdr image inline than to try patching the
    // single-TLS bytes above.
    fn write_two_tls() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x3000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&3u16.to_le_bytes());
        // Phdr 0 — PT_LOAD.
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&5u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());
        // Phdr 1 — first PT_TLS.
        ph = 64 + 56;
        b[ph..ph + 0x04].copy_from_slice(&7u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x2000u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&TLS_VADDR.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&16u64.to_le_bytes());
        // Phdr 2 — second PT_TLS (illegal).
        ph = 64 + 2 * 56;
        b[ph..ph + 0x04].copy_from_slice(&7u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&0x2040u64.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&(TLS_VADDR + 0x100).to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&(TLS_VADDR + 0x100).to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x40u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&16u64.to_le_bytes());
        b
    }

    match parse_elf(&write_two_tls()) {
        Err(ElfError::MultiplePtTls) => TestResult::Pass,
        Err(_) => TestResult::Fail("two PT_TLS produced wrong error variant"),
        Ok(_) => TestResult::Fail("two PT_TLS should have been rejected"),
    }
}
kernel_test_in!("userspace", smoke_userspace_parse_pt_tls);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_apply_relative_relocations() -> TestResult {
    // PT_DYNAMIC walk-through. Build a minimal ELF with one PT_LOAD
    // covering [0x80_0000_1000, 0x80_0000_2000), one PT_DYNAMIC
    // pointing at a 5-entry dynamic array inside the segment, and a
    // single Elf64_Rela whose r_offset names a slot inside the same
    // segment. After load, the R_X86_64_RELATIVE relocation should
    // have written its addend into the slot — proving DT_RELA
    // walking + r_offset → user-vaddr translation + page-table-
    // backed write all work end-to-end.
    use crate::load_user_process_with;
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    const SEG_VA: u64 = 0x0000_0080_0000_1000;
    const SEG_FOFF: u64 = 0x1000;
    // r_offset inside the segment (byte 0x80 from base — well clear
    // of both the rela array and the dynamic array we lay out below).
    const RELOC_OFF_IN_SEG: u64 = 0x80;
    const RELOC_VA: u64 = SEG_VA + RELOC_OFF_IN_SEG;
    const ADDEND: u64 = 0x12345678;
    // Where the rela entry lives inside the segment (file + vaddr).
    const RELA_OFF_IN_SEG: u64 = 0x100;
    // Where the dynamic array lives inside the segment.
    const DYN_OFF_IN_SEG: u64 = 0x200;

    fn build() -> alloc::vec::Vec<u8> {
        // Total file size: 0x2000 — first 0x1000 = ELF header + phdrs
        // (zero-padded), second 0x1000 = the PT_LOAD page.
        const FSIZE: usize = 0x2000;
        let mut b = alloc::vec![0u8; FSIZE];
        // ELF header.
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
        b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x111).to_le_bytes()); // entry inside seg
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[0x28..0x30].copy_from_slice(&0u64.to_le_bytes()); // e_shoff
        b[0x30..0x34].copy_from_slice(&0u32.to_le_bytes()); // e_flags
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
                                                            // Phdr 0 — PT_LOAD covering the page at file_off 0x1000 →
                                                            // vaddr SEG_VA, with R+W perms (so the relocation can patch
                                                            // the slot — kernel writes through identity-map so PF_W is
                                                            // for completeness only).
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
        b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes()); // filesz
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes()); // memsz
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes()); // align
                                                                           // Phdr 1 — PT_DYNAMIC. Its file region is the dynamic array
                                                                           // we lay down at DYN_OFF_IN_SEG (5 × 16 bytes = 80).
        ph = 64 + 56;
        let dyn_foff = SEG_FOFF + DYN_OFF_IN_SEG;
        let dyn_va = SEG_VA + DYN_OFF_IN_SEG;
        b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&dyn_foff.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&80u64.to_le_bytes()); // 5 × 16
        b[ph + 0x28..ph + 0x30].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());

        // Lay out the Elf64_Rela entry at SEG_FOFF + RELA_OFF_IN_SEG.
        // r_offset = RELOC_VA, r_info = (sym=0 << 32) | type=8, addend=ADDEND.
        let rela_foff = (SEG_FOFF + RELA_OFF_IN_SEG) as usize;
        b[rela_foff..rela_foff + 8].copy_from_slice(&RELOC_VA.to_le_bytes());
        b[rela_foff + 8..rela_foff + 16].copy_from_slice(&8u64.to_le_bytes());
        b[rela_foff + 16..rela_foff + 24].copy_from_slice(&ADDEND.to_le_bytes());

        // Lay out the dynamic array. Tags use the standard DT_* wire
        // numbers — DT_RELA=7, DT_RELASZ=8, DT_RELAENT=9, DT_RELACOUNT=
        // 0x6FFFFFF9, DT_NULL=0.
        let rela_va = SEG_VA + RELA_OFF_IN_SEG;
        let dyn_foff_us = dyn_foff as usize;
        let mut p = dyn_foff_us;
        // DT_RELA = rela array vaddr.
        b[p..p + 8].copy_from_slice(&7i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&rela_va.to_le_bytes());
        p += 16;
        // DT_RELASZ = 24.
        b[p..p + 8].copy_from_slice(&8i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        // DT_RELAENT = 24.
        b[p..p + 8].copy_from_slice(&9i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        // DT_RELACOUNT = 1.
        b[p..p + 8].copy_from_slice(&0x6FFFFFF9i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&1u64.to_le_bytes());
        p += 16;
        // DT_NULL terminator.
        b[p..p + 8].copy_from_slice(&0i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());

        b
    }

    let bytes = build();
    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };
    let image = crate::parse_elf(&bytes).unwrap();
    // SAFETY: `proc` was just built by `load_user_process_with` from the same
    // `bytes`, so its `address_space` is mapped and matches `image` (parsed from
    // those bytes); `bytes`/`image` outlive the call. The test harness keeps the
    // low 4 GiB identity-mapped, satisfying the loader's `# Safety` contract.
    unsafe {
        crate::loader::apply_relocations(&bytes, &image, &proc.address_space, 0, false).unwrap()
    };

    // Read back the slot through the AS — same translate-and-cast
    // pattern the other smokes use.
    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: Valid memory or trusted environment
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
        // SAFETY: `p` is the phys frame `translate` just resolved for this page;
        // OR-ing the in-page offset stays within that identity-mapped frame, and the
        // `u64` read is aligned because callers pass 8-byte-aligned `vaddr`s.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { *((p.as_u64() | (vaddr & 0xFFF)) as *const u64) })
    };
    let got = match read_u64(RELOC_VA) {
        Some(v) => v,
        None => return TestResult::Fail("relocation site not materialised"),
    };
    if got != ADDEND {
        return TestResult::Fail("R_X86_64_RELATIVE didn't write the addend");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_apply_relative_relocations);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_relr_decode() -> TestResult {
    // DT_RELR bitmap decode + read-modify-write semantics. Modern
    // glibc/ld-linux (Debian 13, "-z pack-relative-relocs") emit their
    // RELATIVE relocations here; the loader was blind to the table, so
    // an interpreter loaded that way ran with un-biased pointers and
    // #GP'd. This exercises the pure `for_each_relr_target` decoder:
    //   entry 0 (even)  → address 0x1000: relocate the slot there.
    //   entry 1 (odd)   → bitmap over the 63 slots after 0x1008; bits
    //                     1, 3, 63 set → slots 0, 2, 62.
    //   entry 2 (even)  → address 0x2000: relocate that slot.
    // The bitmap word: bit 0 is the tag, bit N (N≥1) marks the slot at
    // cursor + (N−1)*8.
    use crate::loader::for_each_relr_target;

    const BITMAP: u64 = 1 | (1u64 << 1) | (1u64 << 3) | (1u64 << 63);
    let mut table = alloc::vec::Vec::<u8>::new();
    table.extend_from_slice(&0x1000u64.to_le_bytes()); // address entry
    table.extend_from_slice(&BITMAP.to_le_bytes()); // bitmap entry
    table.extend_from_slice(&0x2000u64.to_le_bytes()); // address entry

    // Expected relocated slots, in table order.
    let expected: [u64; 5] = [
        0x1000,          // entry 0
        0x1008,          // bitmap bit 1 → slot 0
        0x1018,          // bitmap bit 3 → slot 2
        0x1008 + 62 * 8, // bitmap bit 63 → slot 62 (0x11F8)
        0x2000,          // entry 2
    ];

    let mut visited = alloc::vec::Vec::<u64>::new();
    for_each_relr_target(&table, |va| visited.push(va));
    if visited.as_slice() != expected {
        return TestResult::Fail("RELR decode visited the wrong slot sequence");
    }

    // Read-modify-write check: each named slot holds a link-time value;
    // applying bias must add it exactly once. Model memory as a map
    // from slot vaddr → value and replay the walk with a bias.
    const BIAS: u64 = 0x0000_0080_0000_0000;
    let seeds: [(u64, u64); 5] = [
        (0x1000, 0x11),
        (0x1008, 0x22),
        (0x1018, 0x33),
        (0x1008 + 62 * 8, 0x44),
        (0x2000, 0x55),
    ];
    let mut mem = alloc::vec::Vec::<(u64, u64)>::from(seeds);
    for_each_relr_target(&table, |va| {
        if let Some(slot) = mem.iter_mut().find(|(a, _)| *a == va) {
            slot.1 = slot.1.wrapping_add(BIAS);
        }
    });
    for (i, (_, v)) in mem.iter().enumerate() {
        if *v != seeds[i].1.wrapping_add(BIAS) {
            return TestResult::Fail("RELR RMW didn't add bias exactly once per slot");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_relr_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_apply_relr_relocations() -> TestResult {
    // End-to-end DT_RELR: build an ET_DYN with a PT_LOAD, a PT_DYNAMIC
    // naming a RELR table, and seeded slots; load it (bias =
    // PROGRAM_DYN_BASE), run `apply_relocations`, and read the slots
    // back. Each RELR-covered slot must hold `link_time_value + bias`
    // EXACTLY ONCE (RELR is read-modify-write, so a double-apply would
    // show `+ 2*bias` — the non-canonical corruption that broke glibc
    // ld.so). A slot the bitmap does NOT mark must be untouched.
    use crate::load_user_process_with;
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    const BIAS: u64 = 0x0000_0080_0000_0000; // PROGRAM_DYN_BASE (ET_DYN load bias)
    const SEG_VA: u64 = 0x1000; // link-time p_vaddr (small — ET_DYN)
    const SEG_FOFF: u64 = 0x1000;
    // Seeded slots (link-time vaddrs) + their pre-relocation values.
    const A_VA: u64 = SEG_VA + 0x80; // via RELR address entry
    const B_VA: u64 = SEG_VA + 0x88; // via bitmap bit 1 (slot 0)
    const C_VA: u64 = SEG_VA + 0x98; // via bitmap bit 3 (slot 2)
    const U_VA: u64 = SEG_VA + 0x90; // between B and C, bit 2 unset → untouched
    const A_VAL: u64 = 0x1111;
    const B_VAL: u64 = 0x2222;
    const C_VAL: u64 = 0x3333;
    const U_VAL: u64 = 0x4444;
    const RELR_VA: u64 = SEG_VA + 0x100;
    const DYN_VA: u64 = SEG_VA + 0x200;

    fn build() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x2000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
        b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x111).to_le_bytes()); // entry inside seg
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
                                                            // Phdr 0 — PT_LOAD (R+W) at SEG_VA, file page 0x1000.
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
        b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes()); // filesz
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes()); // memsz
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes()); // align
                                                                           // Phdr 1 — PT_DYNAMIC over the dynamic array (4 × 16 = 64).
        ph = 64 + 56;
        let dyn_foff = SEG_FOFF + (DYN_VA - SEG_VA);
        b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&dyn_foff.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&DYN_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&DYN_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&64u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&64u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());

        // Seed the four slots with their link-time values.
        let put = |b: &mut [u8], va: u64, val: u64| {
            let off = (SEG_FOFF + (va - SEG_VA)) as usize;
            b[off..off + 8].copy_from_slice(&val.to_le_bytes());
        };
        put(&mut b, A_VA, A_VAL);
        put(&mut b, B_VA, B_VAL);
        put(&mut b, C_VA, C_VAL);
        put(&mut b, U_VA, U_VAL);

        // RELR table: [address(A_VA), bitmap]. After the address entry
        // the cursor sits at A_VA+8 == B_VA; bitmap bit 1 → B_VA (slot 0),
        // bit 3 → C_VA (slot 2). Bit 2 (U_VA) is left unset.
        let relr_foff = (SEG_FOFF + (RELR_VA - SEG_VA)) as usize;
        b[relr_foff..relr_foff + 8].copy_from_slice(&A_VA.to_le_bytes());
        let bitmap: u64 = 1 | (1u64 << 1) | (1u64 << 3);
        b[relr_foff + 8..relr_foff + 16].copy_from_slice(&bitmap.to_le_bytes());

        // Dynamic array: DT_RELR=0x24, DT_RELRSZ=0x23, DT_RELRENT=0x25, DT_NULL.
        let mut p = dyn_foff as usize;
        let ent = |b: &mut [u8], p: &mut usize, tag: i64, val: u64| {
            b[*p..*p + 8].copy_from_slice(&tag.to_le_bytes());
            b[*p + 8..*p + 16].copy_from_slice(&val.to_le_bytes());
            *p += 16;
        };
        ent(&mut b, &mut p, 0x24, RELR_VA); // DT_RELR
        ent(&mut b, &mut p, 0x23, 16); // DT_RELRSZ (2 entries)
        ent(&mut b, &mut p, 0x25, 8); // DT_RELRENT
        ent(&mut b, &mut p, 0, 0); // DT_NULL
        b
    }

    let bytes = build();
    // SAFETY: harness keeps the low 4 GiB identity-mapped + frame allocator up;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };
    let image = crate::parse_elf(&bytes).unwrap();
    // SAFETY: `proc` was just built from `bytes`; its AS is mapped and matches
    // `image`. BIAS is the ET_DYN load bias the loader applied.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        crate::loader::apply_relocations(&bytes, &image, &proc.address_space, BIAS, true).unwrap()
    };

    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root; the walk reads table entries for the page-aligned `vaddr`.
            // SAFETY: Valid memory or trusted environment
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
        // SAFETY: `p` is the phys frame just resolved; OR-ing the in-page offset
        // stays within it and the `u64` read is 8-aligned by construction.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { *((p.as_u64() | (vaddr & 0xFFF)) as *const u64) })
    };

    // Each covered slot must be link_time_value + BIAS, applied once.
    for (va, val) in [(A_VA, A_VAL), (B_VA, B_VAL), (C_VA, C_VAL)] {
        match read_u64(va + BIAS) {
            Some(got) if got == val.wrapping_add(BIAS) => {}
            Some(_) => return TestResult::Fail("RELR slot not link_time+bias (double-apply?)"),
            None => return TestResult::Fail("RELR slot not materialised"),
        }
    }
    // The unmarked slot must be untouched.
    match read_u64(U_VA + BIAS) {
        Some(got) if got == U_VAL => TestResult::Pass,
        Some(_) => TestResult::Fail("RELR relocated a slot the bitmap did not mark"),
        None => TestResult::Fail("RELR untouched-slot not materialised"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_apply_relr_relocations);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_apply_symbol_relocations() -> TestResult {
    // Symbol-resolved relocation walk-through. Mirrors the
    // RELATIVE-only smoke above, but the dynamic array also names a
    // DT_SYMTAB pointing at a 2-entry symbol table; the rela entry's
    // r_info encodes (sym_idx=1, type=R_X86_64_64). Sym 1 is defined
    // (st_value=0x80_0000_1100, st_shndx=1), so the patch site at
    // r_offset should end up holding `st_value + r_addend`.
    use crate::load_user_process_with;
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    const SEG_VA: u64 = 0x0000_0080_0000_1000;
    const SEG_FOFF: u64 = 0x1000;
    const RELOC_OFF_IN_SEG: u64 = 0x80;
    const RELOC_VA: u64 = SEG_VA + RELOC_OFF_IN_SEG;
    const SYM_VALUE: u64 = SEG_VA + 0x100;
    const ADDEND: u64 = 0x42;
    const RELA_OFF_IN_SEG: u64 = 0x180;
    const SYMTAB_OFF_IN_SEG: u64 = 0x1C0;
    const DYN_OFF_IN_SEG: u64 = 0x300;

    fn build() -> alloc::vec::Vec<u8> {
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

        // Phdr 0: PT_LOAD covering the page.
        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes()); // PF_R|PF_W
        b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());

        // Phdr 1: PT_DYNAMIC. 5 dynamic entries × 16 = 80 bytes.
        ph = 64 + 56;
        let dyn_foff = SEG_FOFF + DYN_OFF_IN_SEG;
        let dyn_va = SEG_VA + DYN_OFF_IN_SEG;
        b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        b[ph + 0x08..ph + 0x10].copy_from_slice(&dyn_foff.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());

        // Elf64_Rela @ RELA_OFF_IN_SEG: r_offset, r_info, r_addend.
        // r_info = (sym_idx 1 << 32) | type R_X86_64_64 (1).
        let rela_foff = (SEG_FOFF + RELA_OFF_IN_SEG) as usize;
        let r_info: u64 = (1u64 << 32) | 1u64;
        b[rela_foff..rela_foff + 8].copy_from_slice(&RELOC_VA.to_le_bytes());
        b[rela_foff + 8..rela_foff + 16].copy_from_slice(&r_info.to_le_bytes());
        b[rela_foff + 16..rela_foff + 24].copy_from_slice(&ADDEND.to_le_bytes());

        // Symbol table @ SYMTAB_OFF_IN_SEG. Two 24-byte entries.
        // Entry 0: all-zero (the canonical STN_UNDEF placeholder).
        // Entry 1: defined symbol — st_value=SYM_VALUE, st_shndx=1.
        let sym_foff = (SEG_FOFF + SYMTAB_OFF_IN_SEG) as usize;
        // Entry 0 is already zeroed by the vec init.
        let s1 = sym_foff + 24;
        // st_name(4) | st_info(1) | st_other(1) | st_shndx(2) | st_value(8) | st_size(8).
        b[s1..s1 + 4].copy_from_slice(&0u32.to_le_bytes()); // st_name
        b[s1 + 4] = 0; // st_info
        b[s1 + 5] = 0; // st_other
        b[s1 + 6..s1 + 8].copy_from_slice(&1u16.to_le_bytes()); // st_shndx (defined)
        b[s1 + 8..s1 + 16].copy_from_slice(&SYM_VALUE.to_le_bytes()); // st_value
        b[s1 + 16..s1 + 24].copy_from_slice(&0u64.to_le_bytes()); // st_size

        // Dynamic array.
        let rela_va = SEG_VA + RELA_OFF_IN_SEG;
        let symtab_va = SEG_VA + SYMTAB_OFF_IN_SEG;
        let mut p = dyn_foff as usize;
        // DT_RELA = 7.
        b[p..p + 8].copy_from_slice(&7i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&rela_va.to_le_bytes());
        p += 16;
        // DT_RELASZ = 8 → 24 bytes (one entry).
        b[p..p + 8].copy_from_slice(&8i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        // DT_RELAENT = 9 → 24.
        b[p..p + 8].copy_from_slice(&9i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        // DT_SYMTAB = 6 → symtab_va.
        b[p..p + 8].copy_from_slice(&6i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&symtab_va.to_le_bytes());
        p += 16;
        // DT_NULL.
        b[p..p + 8].copy_from_slice(&0i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());

        b
    }

    let bytes = build();
    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };
    let image = crate::parse_elf(&bytes).unwrap();
    // SAFETY: `proc` was just built by `load_user_process_with` from the same
    // `bytes`, so its `address_space` is mapped and matches `image` (parsed from
    // those bytes); `bytes`/`image` outlive the call. The test harness keeps the
    // low 4 GiB identity-mapped, satisfying the loader's `# Safety` contract.
    unsafe {
        crate::loader::apply_relocations(&bytes, &image, &proc.address_space, 0, false).unwrap()
    };

    let read_u64 = |vaddr: u64| -> Option<u64> {
        let p =
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: `proc.address_space.root` is this test process's live page-table
            // root, identity-reachable as `translate` requires; the walk only reads
            // table entries for the page-aligned `vaddr`.
            // SAFETY: Valid memory or trusted environment
            unsafe { paging::translate(proc.address_space.root, VirtAddr::new(vaddr & !0xFFF)) }?;
        // SAFETY: `p` is the phys frame `translate` just resolved for this page;
        // OR-ing the in-page offset stays within that identity-mapped frame, and the
        // `u64` read is aligned because callers pass 8-byte-aligned `vaddr`s.
        // SAFETY: Valid memory or trusted environment
        Some(unsafe { *((p.as_u64() | (vaddr & 0xFFF)) as *const u64) })
    };
    let got = match read_u64(RELOC_VA) {
        Some(v) => v,
        None => return TestResult::Fail("relocation site not materialised"),
    };
    if got != SYM_VALUE.wrapping_add(ADDEND) {
        return TestResult::Fail("R_X86_64_64 didn't write S+A");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_apply_symbol_relocations);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_unresolved_symbol_errors() -> TestResult {
    // Same shape as `smoke_userspace_apply_symbol_relocations` but
    // sym_idx 1 is SHN_UNDEF (st_value=0, st_shndx=0). The loader
    // must surface `LoadBytesError::UnresolvedSymbol { idx: 1, .. }`
    // rather than silently writing zero. This image has no DT_STRTAB
    // and a zero `st_name`, so the captured name buffer is all-zero —
    // the dedicated `_carries_name` smoke covers the populated path.
    use crate::{load_user_process_with, LoadBytesError};

    const SEG_VA: u64 = 0x0000_0080_0000_1000;
    const SEG_FOFF: u64 = 0x1000;
    const RELOC_OFF_IN_SEG: u64 = 0x80;
    const RELOC_VA: u64 = SEG_VA + RELOC_OFF_IN_SEG;
    const RELA_OFF_IN_SEG: u64 = 0x180;
    const SYMTAB_OFF_IN_SEG: u64 = 0x1C0;
    const DYN_OFF_IN_SEG: u64 = 0x300;

    fn build() -> alloc::vec::Vec<u8> {
        const FSIZE: usize = 0x2000;
        let mut b = alloc::vec![0u8; FSIZE];
        b[..16].copy_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        b[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
        b[0x12..0x14].copy_from_slice(&0x3Eu16.to_le_bytes());
        b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        b[0x18..0x20].copy_from_slice(&(SEG_VA + 0x111).to_le_bytes());
        b[0x20..0x28].copy_from_slice(&64u64.to_le_bytes());
        b[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes());
        b[0x38..0x3A].copy_from_slice(&2u16.to_le_bytes());

        let mut ph = 64usize;
        b[ph..ph + 0x04].copy_from_slice(&1u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&6u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&SEG_FOFF.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&SEG_VA.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&0x1000u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&0x1000u64.to_le_bytes());

        ph = 64 + 56;
        let dyn_foff = SEG_FOFF + DYN_OFF_IN_SEG;
        let dyn_va = SEG_VA + DYN_OFF_IN_SEG;
        b[ph..ph + 0x04].copy_from_slice(&2u32.to_le_bytes());
        b[ph + 0x04..ph + 0x08].copy_from_slice(&4u32.to_le_bytes());
        b[ph + 0x08..ph + 0x10].copy_from_slice(&dyn_foff.to_le_bytes());
        b[ph + 0x10..ph + 0x18].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x18..ph + 0x20].copy_from_slice(&dyn_va.to_le_bytes());
        b[ph + 0x20..ph + 0x28].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x28..ph + 0x30].copy_from_slice(&80u64.to_le_bytes());
        b[ph + 0x30..ph + 0x38].copy_from_slice(&8u64.to_le_bytes());

        let rela_foff = (SEG_FOFF + RELA_OFF_IN_SEG) as usize;
        let r_info: u64 = (1u64 << 32) | 1u64;
        b[rela_foff..rela_foff + 8].copy_from_slice(&RELOC_VA.to_le_bytes());
        b[rela_foff + 8..rela_foff + 16].copy_from_slice(&r_info.to_le_bytes());
        b[rela_foff + 16..rela_foff + 24].copy_from_slice(&0u64.to_le_bytes());

        // Symbol table — entry 1 is an undefined symbol (st_value=0,
        // st_shndx=SHN_UNDEF=0). The vec is already zero, so leave
        // both entries at their zero defaults.
        let _sym_foff = (SEG_FOFF + SYMTAB_OFF_IN_SEG) as usize;

        let rela_va = SEG_VA + RELA_OFF_IN_SEG;
        let symtab_va = SEG_VA + SYMTAB_OFF_IN_SEG;
        let mut p = dyn_foff as usize;
        b[p..p + 8].copy_from_slice(&7i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&rela_va.to_le_bytes());
        p += 16;
        b[p..p + 8].copy_from_slice(&8i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        b[p..p + 8].copy_from_slice(&9i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&24u64.to_le_bytes());
        p += 16;
        b[p..p + 8].copy_from_slice(&6i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&symtab_va.to_le_bytes());
        p += 16;
        b[p..p + 8].copy_from_slice(&0i64.to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes());

        b
    }

    let bytes = build();
    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };
    let image = crate::parse_elf(&bytes).unwrap();
    // SAFETY: `proc` was just built by `load_user_process_with` from the same
    // `bytes`, so its `address_space` is mapped and matches `image` (parsed from
    // those bytes); `bytes`/`image` outlive the call. The test harness keeps the
    // low 4 GiB identity-mapped, satisfying the loader's `# Safety` contract.
    match unsafe { crate::loader::apply_relocations(&bytes, &image, &proc.address_space, 0, false) }
    {
        Err(LoadBytesError::UnresolvedSymbol { idx: 1, name }) => {
            // No DT_STRTAB + st_name=0 → name buffer must be empty.
            if name == [0u8; 32] {
                TestResult::Pass
            } else {
                TestResult::Fail("UnresolvedSymbol.name should be empty without DT_STRTAB")
            }
        }
        Err(_) => TestResult::Fail(
            "expected UnresolvedSymbol{idx:1,..}, got different error from apply_relocations",
        ),
        Ok(_) => TestResult::Fail("expected UnresolvedSymbol error, got Ok"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_unresolved_symbol_errors);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_unresolved_symbol_carries_name() -> TestResult {
    // The loader walks DT_STRTAB and surfaces the symbol name
    // alongside the index. With strtab "\0printf\0exit\0" and
    // st_name=1, the name buffer must read "printf" + NUL-pad.
    use crate::{load_user_process_with, LoadBytesError};

    let strtab = b"\0printf\0exit\0";
    let bytes = build_unresolved_named_elf(strtab);
    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };
    let image = crate::parse_elf(&bytes).unwrap();
    // SAFETY: `proc` was just built by `load_user_process_with` from the same
    // `bytes`, so its `address_space` is mapped and matches `image` (parsed from
    // those bytes); `bytes`/`image` outlive the call. The test harness keeps the
    // low 4 GiB identity-mapped, satisfying the loader's `# Safety` contract.
    match unsafe { crate::loader::apply_relocations(&bytes, &image, &proc.address_space, 0, false) }
    {
        Err(LoadBytesError::UnresolvedSymbol { idx: 1, name }) => {
            if &name[..6] != b"printf" {
                return TestResult::Fail("name buffer doesn't start with \"printf\"");
            }
            if name[6] != 0 {
                return TestResult::Fail("name buffer not NUL-terminated after \"printf\"");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail(
            "expected UnresolvedSymbol{idx:1,..}, got different error from apply_relocations",
        ),
        Ok(_) => TestResult::Fail("expected UnresolvedSymbol error, got Ok"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_unresolved_symbol_carries_name);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_unresolved_symbol_name_truncates() -> TestResult {
    // A 50-byte name must truncate to 32 bytes with no NUL byte
    // anywhere in the buffer — documents the truncation contract
    // explicitly so future churn doesn't silently regress it.
    use crate::{load_user_process_with, LoadBytesError};

    // 50-byte name, leading NUL + name + trailing NUL (preserves
    // SysV's strtab[0] convention).
    let long: &[u8] = b"verylongsymbolnamethatdefinitelyexceeds_thirty_two";
    assert!(long.len() == 50);
    let mut strtab = alloc::vec::Vec::with_capacity(1 + long.len() + 1);
    strtab.push(0u8);
    strtab.extend_from_slice(long);
    strtab.push(0u8);
    let bytes = build_unresolved_named_elf(&strtab);

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed"),
    };
    let image = crate::parse_elf(&bytes).unwrap();
    // SAFETY: `proc` was just built by `load_user_process_with` from the same
    // `bytes`, so its `address_space` is mapped and matches `image` (parsed from
    // those bytes); `bytes`/`image` outlive the call. The test harness keeps the
    // low 4 GiB identity-mapped, satisfying the loader's `# Safety` contract.
    match unsafe { crate::loader::apply_relocations(&bytes, &image, &proc.address_space, 0, false) }
    {
        Err(LoadBytesError::UnresolvedSymbol { idx: 1, name }) => {
            // First 32 bytes must equal the source's first 32 bytes,
            // and *all* 32 must be non-zero (we truncated mid-name,
            // so no terminator was reached inside the buffer).
            if name[..32] != long[..32] {
                return TestResult::Fail("truncated name doesn't match source prefix");
            }
            if name.contains(&0) {
                return TestResult::Fail("truncated name should have no NUL inside the buffer");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail(
            "expected UnresolvedSymbol{idx:1,..}, got different error from apply_relocations",
        ),
        Ok(_) => TestResult::Fail("expected UnresolvedSymbol error, got Ok"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_unresolved_symbol_name_truncates
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_init_sysv_stack_layout() -> TestResult {
    // Verify `init_sysv_stack` lays out the System V x86_64 startup
    // contract: argc at [rsp], then argv pointers + NULL, then envp
    // pointers + NULL, then aux pairs ending in AT_NULL. Strings the
    // pointers name live in the upper portion of the stack.
    //
    // The helper walks the AS per page via translate, so the test
    // builds a real one-page user mapping rather than a fake
    // contiguous slab.
    use crate::{init_sysv_stack, AuxEntry};
    use narf_memory::{x86_64::paging, AddressSpace, Region, RegionPerms, VirtAddr};

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let as_ = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("new_for_user"),
    };
    let frame = match narf_memory::alloc_frame() {
        Ok(f) => f.start_address(),
        Err(_) => return TestResult::Fail("alloc_frame"),
    };
    // SAFETY: `frame` is a freshly allocated 4 KiB frame, identity-mapped so
    // `frame.raw()` is a writable kernel pointer; zeroing exactly its 4096 bytes
    // stays in bounds and the frame is not aliased yet.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096);
    }

    // PML4[1]; PML4[0] is the kernel's identity-map (1 GiB huge
    // pages), where map_4kb can't carve a 4K mapping.
    let user_base: u64 = 0x0000_0080_0000_0000;
    let stack_top = user_base + 4096;
    if as_
        .map_region(Region {
            base: VirtAddr::new(user_base),
            len: 4096,
            perms: RegionPerms::READ | RegionPerms::WRITE,
            phys: alloc::vec![frame],
        })
        .is_err()
    {
        return TestResult::Fail("map_region");
    }
    // SAFETY: `as_` was built via `new_for_user`, so its `root` is a valid user
    // root, satisfying `materialize`'s `# Safety` precondition.
    // SAFETY: Valid memory or trusted environment
    if unsafe { as_.materialize() }.is_err() {
        return TestResult::Fail("materialize");
    }

    let argv = ["argv0", "alpha"];
    let envp = ["KEY=val", "LANG=C"];
    let aux = [AuxEntry::Pagesz(4096), AuxEntry::Random(0x1234_5678)];
    // SAFETY: the single page `[user_base, stack_top)` was just mapped READ|WRITE
    // and materialised above, and the low-4-GiB identity map is live, meeting
    // `init_sysv_stack`'s `# Safety` contract.
    // SAFETY: Valid memory or trusted environment
    let rsp_v = match unsafe { init_sysv_stack(&as_, stack_top, 4096, &argv, &envp, &aux) } {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("init_sysv_stack overflowed unexpectedly"),
    };

    if (rsp_v & 0xF) != 0 {
        return TestResult::Fail("rsp not 16-byte aligned");
    }

    // Read back via translate so we exercise the same path the
    // helper used for writes (and so a future per-page-phys
    // refactor still yields identical output).
    let read_u64 = |vaddr: u64| -> u64 {
        // SAFETY: `as_.root` is the live user root for this test, identity-reachable
        // as `translate` requires; only walks its tables for the page-aligned vaddr.
        // SAFETY: Valid memory or trusted environment
        let p = unsafe { paging::translate(as_.root, VirtAddr::new(vaddr & !0xFFF)) }
            .map(|p| p.as_u64() | (vaddr & 0xFFF))
            .unwrap();
        // SAFETY: `p` is the identity-mapped phys for that mapped stack page; the
        // helper writes 8-byte-aligned words there, so this `u64` read is aligned
        // and in-bounds.
        // SAFETY: Valid memory or trusted environment
        unsafe { *(p as *const u64) }
    };

    if read_u64(rsp_v) != 2 {
        return TestResult::Fail("argc != 2");
    }
    let argv_p0 = read_u64(rsp_v + 8);
    let argv_p1 = read_u64(rsp_v + 16);
    if read_u64(rsp_v + 24) != 0 {
        return TestResult::Fail("argv NULL term");
    }
    let envp_p0 = read_u64(rsp_v + 32);
    let envp_p1 = read_u64(rsp_v + 40);
    if read_u64(rsp_v + 48) != 0 {
        return TestResult::Fail("envp NULL term");
    }
    if read_u64(rsp_v + 56) != 6 || read_u64(rsp_v + 64) != 4096 {
        return TestResult::Fail("aux[0] (PAGESZ)");
    }
    if read_u64(rsp_v + 72) != 25 || read_u64(rsp_v + 80) != 0x1234_5678 {
        return TestResult::Fail("aux[1] (RANDOM)");
    }
    if read_u64(rsp_v + 88) != 0 || read_u64(rsp_v + 96) != 0 {
        return TestResult::Fail("aux AT_NULL");
    }

    // Linux-compatible startup strings form one ascending, contiguous
    // argv-then-envp area. Avahi's process-title setup depends on this exact
    // relationship when it computes the writable span from argv[0] through
    // the end of the final environment string.
    if argv_p1 != argv_p0 + argv[0].len() as u64 + 1 {
        return TestResult::Fail("argv strings not ascending and contiguous");
    }
    if envp_p0 != argv_p1 + argv[1].len() as u64 + 1 {
        return TestResult::Fail("envp does not immediately follow argv");
    }
    if envp_p1 != envp_p0 + envp[0].len() as u64 + 1 {
        return TestResult::Fail("envp strings not ascending and contiguous");
    }
    let Some(title_span) = (envp_p1 + envp[1].len() as u64).checked_sub(argv_p0) else {
        return TestResult::Fail("Avahi-style process-title span underflowed");
    };
    if title_span == 0 || title_span >= 4096 {
        return TestResult::Fail("Avahi-style process-title span is out of bounds");
    }

    let check_str = |user_p: u64, expected: &str| -> bool {
        if user_p < user_base || user_p >= stack_top {
            return false;
        }
        // SAFETY: `as_.root` is the live top-level page-table frame for this test
        // address space; `translate` only walks that hierarchy for the page-aligned
        // `VirtAddr`, reading table entries with no aliasing.
        // SAFETY: Valid memory or trusted environment
        let kp = match unsafe { paging::translate(as_.root, VirtAddr::new(user_p & !0xFFF)) } {
            Some(p) => p.as_u64() | (user_p & 0xFFF),
            None => return false,
        };
        let ebytes = expected.as_bytes();
        for (i, &b) in ebytes.iter().enumerate() {
            // SAFETY: `kp` is the kernel-mapped address `translate` returned for this
            // user page; `i < ebytes.len()` keeps the read inside that mapped page.
            // SAFETY: Valid memory or trusted environment
            if unsafe { *((kp + i as u64) as *const u8) } != b {
                return false;
            }
        }
        // SAFETY: same mapped page as above; reading the terminating byte at
        // `ebytes.len()`, still within the page resolved by `translate`.
        // SAFETY: Valid memory or trusted environment
        unsafe { *((kp + ebytes.len() as u64) as *const u8) == 0 }
    };
    if !check_str(argv_p0, "argv0") {
        return TestResult::Fail("argv[0]");
    }
    if !check_str(argv_p1, "alpha") {
        return TestResult::Fail("argv[1]");
    }
    if !check_str(envp_p0, "KEY=val") {
        return TestResult::Fail("envp[0]");
    }
    if !check_str(envp_p1, "LANG=C") {
        return TestResult::Fail("envp[1]");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_init_sysv_stack_layout);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_elf_bytes_end_to_end() -> TestResult {
    // End-to-end: hand-build a minimal ELF64 with a 1-page PT_LOAD
    // carrying 7 bytes of "payload", call load_elf_bytes, then walk
    // the returned AddressSpace via translate() to confirm the
    // backing phys frame is mapped AND the payload bytes are in
    // the frame.
    use crate::load_elf_bytes;
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    // Build ELF bytes: header (64) + 1 PHDR (56) + 0x1000 payload
    // area. Payload-area size is chosen so file_size == mem_size ==
    // 0x1000, which means `load_elf_bytes` copies the full page.
    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(64 + 56 + 0x1000);
    // e_ident
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
                                                  // Entry = 0x0000_0080_0000_1111 (some user vaddr inside PML4[1]).
    bytes.extend_from_slice(&0x0000_0080_0000_1111u64.to_le_bytes());
    bytes.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    bytes.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                                  // Program header — R|X 1-page segment.
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    bytes.extend_from_slice(&(64u64 + 56).to_le_bytes()); // p_offset = past PHDR
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&0x0000_0080_0000_1000u64.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
                                                       // 4 KiB of payload. First 7 bytes distinct so we can verify.
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x69, 0x01]);
    bytes.resize(64 + 56 + 0x1000, 0);

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let (as_arc, entry) = match unsafe { load_elf_bytes(&bytes) } {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("load_elf_bytes failed on minimal ELF"),
    };

    if entry.0 != VirtAddr::new(0x0000_0080_0000_1111) {
        return TestResult::Fail("entry point mis-decoded");
    }
    if as_arc.region_count() != 1 {
        return TestResult::Fail("load_elf_bytes did not install one region");
    }

    // Walk the AS PML4 to find the PTE for the segment base, then
    // read back the first 7 bytes via the phys address.
    // SAFETY: `as_arc.root` is the live root `load_elf_bytes` just built, identity-
    // reachable as `translate` requires; only walks its tables for the segment base.
    // SAFETY: Valid memory or trusted environment
    let phys = match unsafe { paging::translate(as_arc.root, VirtAddr::new(0x0000_0080_0000_1000)) }
    {
        Some(p) => p,
        None => return TestResult::Fail("translate found no mapping for segment base"),
    };
    // Read back via identity map.
    // SAFETY: `phys` is the identity-mapped frame `translate` resolved for the
    // segment base; the loader copied the segment there, so reading the leading
    // 7 bytes is in-bounds, and a `[u8; 7]` has alignment 1.
    // SAFETY: Valid memory or trusted environment
    let payload: [u8; 7] = unsafe { core::ptr::read_volatile(phys.kernel_ptr::<[u8; 7]>()) };
    if payload != [0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x69, 0x01] {
        return TestResult::Fail("segment payload bytes did not land in the mapped frame");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_load_elf_bytes_end_to_end);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_load_multi_segment() -> TestResult {
    // Multi-PT_LOAD: hand-build an ELF with TWO PT_LOAD segments at
    // non-adjacent vaddrs (.text at 0x80_0000_1000 R+X, .data at
    // 0x80_0000_5000 R+W) and verify load_user_process_with materialises
    // each segment to its own scattered phys backing. The freelist
    // allocator returns frames in arbitrary order — by the time the
    // second segment's pages are allocated, the freelist will not be
    // contiguous with the first segment's. The old single-base Region
    // shape silently miscompiled this layout (page 2 of segment 1 would
    // alias whatever frame happened to sit at phys+0x1000 in the
    // freelist, not the actual second-page allocation).
    use crate::load_user_process_with;
    use narf_memory::x86_64::paging;
    use narf_memory::VirtAddr;

    // Two segments, two pages each, with a 3-page hole between them so
    // the runtime vaddrs are clearly disjoint.
    const TEXT_VADDR: u64 = 0x0000_0080_0000_1000;
    const DATA_VADDR: u64 = 0x0000_0080_0000_5000;
    const TEXT_PAGES: usize = 2;
    const DATA_PAGES: usize = 2;
    const TEXT_FILESZ: u64 = (TEXT_PAGES as u64) * 0x1000;
    const DATA_FILESZ: u64 = (DATA_PAGES as u64) * 0x1000;

    // ELF layout: header (64) + 2 PHDRs (56 each) + .text bytes + .data bytes.
    let phoff: u64 = 64;
    let text_off: u64 = phoff + 2 * 56;
    let data_off: u64 = text_off + TEXT_FILESZ;
    let total: usize = (data_off + DATA_FILESZ) as usize;

    let mut bytes: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(total);
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
    bytes.extend_from_slice(&(TEXT_VADDR + 0x111).to_le_bytes()); // entry
    bytes.extend_from_slice(&phoff.to_le_bytes()); // e_phoff
    bytes.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                                  // .text PT_LOAD — R|X
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    bytes.extend_from_slice(&text_off.to_le_bytes()); // p_offset
    bytes.extend_from_slice(&TEXT_VADDR.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&TEXT_VADDR.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&TEXT_FILESZ.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&TEXT_FILESZ.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
                                                       // .data PT_LOAD — R|W
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type
    bytes.extend_from_slice(&6u32.to_le_bytes()); // p_flags = R|W
    bytes.extend_from_slice(&data_off.to_le_bytes()); // p_offset
    bytes.extend_from_slice(&DATA_VADDR.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&DATA_VADDR.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&DATA_FILESZ.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&DATA_FILESZ.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
                                                       // Pad to file size, then plant per-page sentinel bytes so we can
                                                       // read them back through the AS to confirm the right phys was used
                                                       // per page.
    bytes.resize(total, 0);
    bytes[text_off as usize] = 0x11; // .text page 0 byte 0
    bytes[text_off as usize + 0x1000] = 0x12; // .text page 1 byte 0
    bytes[data_off as usize] = 0x21; // .data page 0 byte 0
    bytes[data_off as usize + 0x1000] = 0x22; // .data page 1 byte 0

    // SAFETY: the test harness keeps the low 4 GiB identity-mapped and the
    // frame allocator initialised, satisfying the loader's `# Safety` contract;
    // `bytes` lives for the whole call.
    // SAFETY: Valid memory or trusted environment
    let proc = match unsafe { load_user_process_with(&bytes, &[], &[], &[]) } {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("load_user_process_with failed on multi-segment ELF"),
    };
    let root = proc.address_space.root;

    // For each page of each segment, translate the user vaddr and read
    // the sentinel back through the identity map. If materialize were
    // still doing single-base + i*0x1000, page-1 reads would be wrong
    // — they'd land at base+0x1000 in physical space, which (after
    // any prior allocations stir the freelist) is not the page-1
    // allocation.
    let checks: [(u64, u8); 4] = [
        (TEXT_VADDR, 0x11),
        (TEXT_VADDR + 0x1000, 0x12),
        (DATA_VADDR, 0x21),
        (DATA_VADDR + 0x1000, 0x22),
    ];
    for &(va, want) in checks.iter() {
        // SAFETY: `root` is the live loader-built root, identity-reachable as
        // `translate` requires; only walks its tables for this segment-page vaddr.
        // SAFETY: Valid memory or trusted environment
        let phys = match unsafe { paging::translate(root, VirtAddr::new(va)) } {
            Some(p) => p,
            None => return TestResult::Fail("translate returned None for a mapped page"),
        };
        // SAFETY: `phys` is the identity-mapped frame `translate` resolved; the
        // loader stored the per-page sentinel byte there, so a 1-byte read is valid.
        // SAFETY: Valid memory or trusted environment
        let got: u8 = unsafe { core::ptr::read_volatile(phys.kernel_ptr::<u8>()) };
        if got != want {
            return TestResult::Fail("per-page sentinel mismatch — scatter list not honoured");
        }
    }

    // Round-trip: write a sentinel into .data page 1 via the kernel's
    // identity view of the translated phys, re-translate, and confirm
    // the read sees the write. This validates that each page in a
    // multi-page R+W segment is independently mapped — not aliased.
    // SAFETY: `root` is the live loader-built root, identity-reachable as
    // `translate` requires; only walks its tables for the .data page-1 vaddr.
    // SAFETY: Valid memory or trusted environment
    let data_p1_phys = unsafe { paging::translate(root, VirtAddr::new(DATA_VADDR + 0x1000)) }
        .expect("data page 1 mapped");
    // SAFETY: `data_p1_phys` is the identity-mapped frame for that mapped R+W page;
    // it is 4 KiB-aligned so a `u32` write at offset 0 is aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    unsafe {
        core::ptr::write_volatile(data_p1_phys.kernel_mut_ptr::<u32>(), 0xCAFEBABE);
    }
    // SAFETY: re-translating the same vaddr yields the identity-mapped phys of the
    // page just written; reading the `u32` back at offset 0 is aligned and in-bounds.
    // SAFETY: Valid memory or trusted environment
    let echo: u32 = unsafe {
        let p = paging::translate(root, VirtAddr::new(DATA_VADDR + 0x1000)).expect("re-translate");
        core::ptr::read_volatile(p.kernel_ptr::<u32>())
    };
    if echo != 0xCAFEBABE {
        return TestResult::Fail("kernel-side write/read via translate did not round-trip");
    }

    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_load_multi_segment);

fn smoke_userspace_loader_into_address_space() -> TestResult {
    use crate::{load_into, ExecImage, ExecKind, LoadError, Segment, SegmentFlags};
    use narf_memory::{AddressSpace, PhysAddr, RegionPerms, VirtAddr};

    // Empty image must refuse.
    let empty = ExecImage::empty(ExecKind::Elf64Exec);
    let pool: alloc::vec::Vec<PhysAddr> = alloc::vec::Vec::new();
    let a = AddressSpace::empty();
    match load_into(&empty, pool.into_iter(), &a) {
        Err(LoadError::NoSegments) => {}
        _ => return TestResult::Fail("empty image should refuse"),
    }

    // Build an image with two segments.
    let rx = SegmentFlags::READ | SegmentFlags::EXEC;
    let rw = SegmentFlags::READ | SegmentFlags::WRITE;
    let mut img = ExecImage::empty(ExecKind::Elf64Exec);
    img.entry = 0x4000;
    img.segments.push(Segment {
        vaddr: 0x4000,
        file_off: 0,
        file_size: 0x1000,
        mem_size: 0x2000,
        flags: rx,
    });
    img.segments.push(Segment {
        vaddr: 0x7000,
        file_off: 0x1000,
        file_size: 0x800,
        mem_size: 0x1000,
        flags: rw,
    });

    // Pool: 2 pages for segment 1 + 1 page for segment 2 = 3 frames.
    let pool = alloc::vec![
        PhysAddr::new(0x10_0000),
        PhysAddr::new(0x10_1000),
        PhysAddr::new(0x20_0000),
    ];
    let a2 = AddressSpace::empty();
    let ep = match load_into(&img, pool.into_iter(), &a2) {
        Ok(ep) => ep,
        Err(_) => return TestResult::Fail("loader failed on valid image"),
    };
    if ep.0 != VirtAddr::new(0x4000) {
        return TestResult::Fail("loader returned wrong entry point");
    }
    if a2.region_count() != 2 {
        return TestResult::Fail("loader did not install both segments");
    }
    // First region: RX, first pool frame.
    let r1 = a2.lookup(VirtAddr::new(0x4000)).expect("mapped");
    if r1.perms != (RegionPerms::READ | RegionPerms::EXEC) {
        return TestResult::Fail("first segment perms wrong");
    }
    if r1.phys.first().copied() != Some(PhysAddr::new(0x10_0000)) {
        return TestResult::Fail("first segment did not pick first pool frame");
    }
    if r1.phys.get(1).copied() != Some(PhysAddr::new(0x10_1000)) {
        return TestResult::Fail("first segment did not pick second pool frame for page 2");
    }
    if r1.len != 0x2000 {
        return TestResult::Fail("first segment len did not round up mem_size");
    }
    // Second region: RW, third pool frame (first two went to seg 1).
    let r2 = a2.lookup(VirtAddr::new(0x7000)).expect("mapped");
    if r2.phys.first().copied() != Some(PhysAddr::new(0x20_0000)) {
        return TestResult::Fail("second segment picked wrong frame from pool");
    }

    // Insufficient pool → NoPhysFrames.
    let tiny = alloc::vec![PhysAddr::new(0x30_0000)];
    let a3 = AddressSpace::empty();
    match load_into(&img, tiny.into_iter(), &a3) {
        Err(LoadError::NoPhysFrames) => {}
        _ => return TestResult::Fail("insufficient pool should surface NoPhysFrames"),
    }

    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_loader_into_address_space);

fn smoke_userspace_parse_minimal_elf64() -> TestResult {
    use crate::{parse_elf, ElfError, ExecKind, SegmentFlags};

    // Hand-crafted minimal ELF64 LE header + 1 PT_LOAD program
    // header. 64-byte ELF header, 56-byte program header, no
    // section table. PT_LOAD covers virt 0x400000 of 0x1000 bytes,
    // flags RX.
    let mut bytes = alloc::vec::Vec::with_capacity(64 + 56);
    // e_ident: 7F 'E' 'L' 'F', class 2 (64-bit), data 1 (LSB),
    // version 1, OS/ABI 0, abi-version 0, 7 bytes pad.
    bytes.extend_from_slice(&[0x7F, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    bytes.extend_from_slice(&0x3Eu16.to_le_bytes()); // e_machine = EM_X86_64 (ignored here)
    bytes.extend_from_slice(&1u32.to_le_bytes()); // e_version
    bytes.extend_from_slice(&0x401000u64.to_le_bytes()); // e_entry
    bytes.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
    bytes.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
    bytes.extend_from_slice(&0u32.to_le_bytes()); // e_flags
    bytes.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
    bytes.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
    bytes.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shentsize
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
    bytes.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
                                                  // Program header: PT_LOAD, flags=PF_R|PF_X (5).
    bytes.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    bytes.extend_from_slice(&5u32.to_le_bytes()); // p_flags = R|X
    bytes.extend_from_slice(&0u64.to_le_bytes()); // p_offset
    bytes.extend_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
    bytes.extend_from_slice(&0x400000u64.to_le_bytes()); // p_paddr
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
    bytes.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    let image = match parse_elf(&bytes) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("minimal ELF64 failed to parse"),
    };
    if image.kind != ExecKind::Elf64Exec {
        return TestResult::Fail("ET_EXEC not mapped to Elf64Exec");
    }
    if image.entry != 0x401000 {
        return TestResult::Fail("entry point mis-parsed");
    }
    if image.segments.len() != 1 {
        return TestResult::Fail("segment count off");
    }
    let s = &image.segments[0];
    if s.vaddr != 0x400000 || s.file_size != 0x1000 || s.mem_size != 0x1000 {
        return TestResult::Fail("segment fields mis-parsed");
    }
    if !s.flags.contains(SegmentFlags::READ) || !s.flags.contains(SegmentFlags::EXEC) {
        return TestResult::Fail("segment flags lost R|X");
    }
    if s.flags.contains(SegmentFlags::WRITE) {
        return TestResult::Fail("W bit appeared spuriously");
    }

    // Refusal paths.
    match parse_elf(&bytes[..32]) {
        Err(ElfError::TooShort) => {}
        _ => return TestResult::Fail("short slice should surface TooShort"),
    }
    let mut bad = bytes.clone();
    bad[0] = 0; // wreck ELF magic
    match parse_elf(&bad) {
        Err(ElfError::BadMagic) => {}
        _ => return TestResult::Fail("bad magic should surface BadMagic"),
    }
    let mut bad32 = bytes.clone();
    bad32[4] = 1; // ELFCLASS32
    match parse_elf(&bad32) {
        Err(ElfError::Not64Bit) => {}
        _ => return TestResult::Fail("32-bit ELF should be rejected"),
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_parse_minimal_elf64);

// ── execve smokes ───────────────────────────────────────────────
//
// `sys_execve` (Syscall::Execve = 179) replaces the current process
// image. Full end-to-end requires a polling user-task ctx (so the
// EXECVE longjmp + ExecRequest pickup can fire); the no-ctx path
// returns `invalid_op()` after the load completes, which is exactly
// what we need to validate the load-side without entering ring 3.

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_rejects_short_elf() -> TestResult {
    // execve(2) takes (path, argv, envp) on the Linux ABI: arg0 is the pathname
    // pointer. A non-null but unmapped/invalid pointer faults in copy_user_cstr
    // → EFAULT, before argv is even looked at.
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: 0xDEAD_BEEFu64, // any non-null pointer
            arg1: 32,             // < 64 — too short
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    if r != SyscallReturn::ok((-14i64) as u64) {
        return TestResult::Fail("bad execve pathname pointer should return -EFAULT");
    }
    crate::syscall::__test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_execve_rejects_short_elf);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_loads_elf_then_bails_without_user_ctx() -> TestResult {
    // End-to-end the load side via the Linux ABI: stage a valid minimal ELF
    // in a MemFs and execve its PATH (not an inline pointer — execve takes
    // (path, argv, envp)). The handler resolves + reads the file, runs
    // `load_user_process_with` to completion, updates /proc/[pid]/{argv,comm},
    // then discovers there's no active user-task ctx (kernel-test stub) and
    // bails with `invalid_op()`. Confirms resolve→read→load→publish on clean
    // input. (Reaching invalid_op — not -ENOENT — proves the path resolved
    // and the image actually loaded.)
    crate::syscall::__test_clear_global();
    // The path pointer is a kernel test address; opt into accepting it so
    // execve reaches the load+bail instead of the EFAULT user-pointer guard.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    let mount = {
        use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
        let auth = bootstrap_mount_authority();
        registry()
            .mount(
                &auth,
                "/execve-load",
                MemFs::with_seeds("execve-load", &[("init", elf.as_slice())]),
            )
            .ok()
    };

    let path = b"/execve-load/init\0";
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0, // argv = NULL → empty (POSIX)
            arg2: 0, // envp = NULL → empty
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = ctx.ret;
    if let Some(h) = &mount {
        let _ = narf_filesystem::registry().unmount(h, "/execve-load");
    }
    crate::syscall::__test_clear_global();
    // load completed but no user ctx → bail with invalid_op.
    match r {
        Some(r) if r == SyscallReturn::invalid_op() => TestResult::Pass,
        _ => TestResult::Fail("expected invalid_op fallback after load when no user ctx"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_loads_elf_then_bails_without_user_ctx
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_rejects_inline_elf_pointer() -> TestResult {
    // Legacy-ABI guard. execve was (elf_ptr, elf_len); it is now Linux
    // (path, argv, envp). Passing the ELF *bytes* as arg0 means the handler
    // reads the ELF magic as a path string ("\x7fELF…", not absolute), which
    // cannot resolve — so execve must REJECT it, never silently load the
    // inline image as if the old ABI were still in effect.
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: elf.as_ptr() as u64,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let r = match ctx.ret {
        Some(r) => r,
        None => return TestResult::Fail("no return"),
    };
    crate::syscall::__test_clear_global();
    if r.status != SyscallReturn::OK || (r.value as i64) < 0 {
        TestResult::Pass
    } else {
        TestResult::Fail("execve must reject the ELF bytes passed as a path (legacy ABI)")
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_rejects_inline_elf_pointer
);

// ── Wave-67 — PID + mount namespaces ───────────────────────────────

/// CLONE_NEWPID via the namespace module directly: the task gets
/// bound as inner pid 1, and `self_inner_pid` returns 1 even though
/// the outer pid is whatever the root pool minted.
#[cfg(feature = "container")]
fn smoke_unshare_pid_ns_sees_self_as_pid_one() -> TestResult {
    crate::pid_ns::__test_reset();
    let fake_task: u64 = 0xABCD_1234;
    let fake_outer: u64 = 4242;
    let ns = crate::pid_ns::unshare_pid_ns(fake_task, fake_outer);
    if ns.outer_to_inner(fake_outer) != Some(1) {
        return TestResult::Fail("first bind should be inner pid 1");
    }
    if crate::pid_ns::self_inner_pid(fake_task, fake_outer) != 1 {
        return TestResult::Fail("self_inner_pid != 1 after unshare");
    }
    // Outer pid still resolvable for kernel-side delivery.
    if ns.inner_to_outer(1) != Some(fake_outer) {
        return TestResult::Fail("inner→outer translation broken");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_unshare_pid_ns_sees_self_as_pid_one);

// ── execve leak regression tests ─────────────────────────────────────
//
// Root causes pinned here (found via the Fedora-KDE 5-minute kernel-heap
// OOM: "memory allocation of N bytes failed" under fork+exec churn):
//
//   1. `load_user_process_with` minted a fresh pid for EVERY load — but
//      execve replaces an image inside an existing process, so the minted
//      pid was discarded and never released: one pid-pool entry leaked
//      per exec.
//   2. The execve commit paths DIVERGE (own-stack `enter_user_mode_at_top`
//      inline; longjmp-model via the EXECVE hook). Divergence abandons the
//      syscall frames, so destructors of live locals never run — the new
//      image's `UserProcess` (including a strong `Arc<AddressSpace>` that
//      kept the whole post-exec AS alive FOREVER, surviving process exit),
//      the ELF buffer, and the argv/envp copies all leaked per exec.

/// Net pids currently allocated: ids minted past the watermark minus
/// ids sitting in the free pool.
#[cfg(target_arch = "x86_64")]
fn net_allocated_pids() -> u64 {
    (crate::pid_pool_watermark() - 1) - crate::pid_pool_free_count() as u64
}

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_does_not_leak_pid() -> TestResult {
    // Drive the real execve handler over a valid staged ELF (same fixture
    // as smoke_userspace_execve_loads_elf_then_bails_without_user_ctx: the
    // load completes, then the handler bails for want of a user ctx). The
    // pid pool must be EXACTLY as it was: exec replaces an image, it does
    // not create a process. Pre-fix the loader minted (and leaked) one pid
    // per exec — under a desktop boot's service churn that marched the pool
    // toward PID_MAX exhaustion.
    //
    // The path pointer below is a kernel address; scope the kernel-buffer
    // opt-in so the copy-in validators accept it and the handler really
    // reaches the loader (without it the path copy can bail first and the
    // pid assertion would vacuously pass).
    let _kbuf = crate::handlers::kernel_buffers_guard();
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    let mount = {
        use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
        let auth = bootstrap_mount_authority();
        registry()
            .mount(
                &auth,
                "/execve-pid-leak",
                MemFs::with_seeds("execve-pid-leak", &[("init", elf.as_slice())]),
            )
            .ok()
    };

    let before = net_allocated_pids();

    let path = b"/execve-pid-leak/init\0";
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
    let after = net_allocated_pids();

    if let Some(h) = &mount {
        let _ = narf_filesystem::registry().unmount(h, "/execve-pid-leak");
    }
    crate::syscall::__test_clear_global();

    if ctx.ret != Some(SyscallReturn::invalid_op()) {
        return TestResult::Fail("execve fixture drifted: expected the no-user-ctx bail");
    }
    if after != before {
        return TestResult::Fail("execve leaked a pid (net allocated pids changed across exec)");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_execve_does_not_leak_pid);

#[cfg(target_arch = "x86_64")]
struct ExecJmpCell(core::cell::UnsafeCell<narf_scheduler::JmpBuf>);
#[cfg(target_arch = "x86_64")]
// SAFETY: written by exactly one test, single-threaded kernel-test runner.
unsafe impl Sync for ExecJmpCell {}
#[cfg(target_arch = "x86_64")]
static EXEC_LEAK_JMP: ExecJmpCell =
    ExecJmpCell(core::cell::UnsafeCell::new(narf_scheduler::JmpBuf {
        rbx: 0,
        rbp: 0,
        r12: 0,
        r13: 0,
        r14: 0,
        r15: 0,
        rsp: 0,
        rip: 0,
    }));

/// Stand-in for the production execve hook: longjmp straight back into
/// the test, abandoning the execve syscall frames exactly the way the
/// real hook abandons them into the polling routine.
#[cfg(target_arch = "x86_64")]
unsafe fn exec_leak_test_hook(_uctx: *mut crate::user_task::UserTaskCtx) -> ! {
    // SAFETY: the jmp buf was filled by the setjmp in the test body below,
    // whose frame is still live (it is waiting for this longjmp).
    unsafe { narf_scheduler::longjmp(EXEC_LEAK_JMP.0.get(), 1) }
}

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_execve_divergence_frees_address_space() -> TestResult {
    // The execve commit path never returns to its caller — it longjmps (or
    // iretqs) away, abandoning the syscall frames, so anything still owned
    // by a local at that point leaks forever. This test runs the REAL
    // handler with a longjmp hook (production shape) and then checks the
    // one observable that matters: after the staged ExecRequest is consumed
    // and dropped, the freshly-loaded address space must be GONE — live
    // user-PML4 count back at baseline. Pre-fix the abandoned frame held a
    // strong Arc<AddressSpace> (inside the leaked UserProcess), so every
    // exec left one dead AS (PML4 tree + every mapped frame) behind — the
    // Fedora-KDE 5-minute kernel-heap OOM.
    use crate::user_task::{clear_current, install_current, UserTaskCtx};

    // The path pointer below is a kernel address; with a user ctx installed
    // the copy-in validators enforce the user half, so scope the kernel-
    // buffer opt-in the way every syscall-driving e2e fixture does.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let elf = build_minimal_elf_for_execve();
    let mount = {
        use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
        let auth = bootstrap_mount_authority();
        registry()
            .mount(
                &auth,
                "/execve-as-leak",
                MemFs::with_seeds("execve-as-leak", &[("init", elf.as_slice())]),
            )
            .ok()
    };

    // A live user ctx (so execve reaches the hook) + the longjmp hook.
    let uctx: *mut UserTaskCtx =
        alloc::boxed::Box::into_raw(alloc::boxed::Box::new(UserTaskCtx::new()));
    crate::user_task::install_execve_hook(exec_leak_test_hook);

    let baseline = narf_memory::paging::user_pml4_live();

    let path = b"/execve-as-leak/init\0";
    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    // IRQs masked across install_current → execve → longjmp: the `CURRENT`
    // uctx cell is per-CPU, and a timer preemption between the install and
    // the handler's read can migrate this test task to another CPU, where
    // the cell is empty — execve then takes the no-user-ctx bail instead of
    // the hook. (The production poll path installs and reads on one CPU
    // with the same no-preempt guarantee.)
    let reached_hook = narf_lib::sync::without_interrupts(|| {
        install_current(uctx);
        // SAFETY: EXEC_LEAK_JMP is a valid JmpBuf; the hook longjmps back here.
        let resumed = unsafe { narf_scheduler::setjmp(EXEC_LEAK_JMP.0.get()) };
        if resumed == 0 {
            kernel_syscall_entry(Syscall::Execve.raw(), &mut ctx);
            // The hook must have fired (and longjmp'd past this line).
            return false;
        }
        true
    });
    if !reached_hook {
        crate::user_task::__test_clear_execve_hook();
        clear_current();
        // SAFETY: uctx came from Box::into_raw above; nothing else owns it.
        drop(unsafe { alloc::boxed::Box::from_raw(uctx) });
        if let Some(h) = &mount {
            let _ = narf_filesystem::registry().unmount(h, "/execve-as-leak");
        }
        crate::syscall::__test_clear_global();
        return TestResult::Fail("execve never reached the exec hook (fixture drifted)");
    }

    // Back from the longjmp: consume the staged ExecRequest the way the
    // polling routine would, then drop it — the LAST intended reference
    // to the new image's address space.
    // SAFETY: uctx is still owned by this test; execve published the
    // request pointer with Box::into_raw.
    let req_ptr = unsafe {
        (*uctx)
            .pending_exec
            .swap(core::ptr::null_mut(), AtomicOrd::AcqRel)
    };
    let had_req = !req_ptr.is_null();
    if had_req {
        // SAFETY: non-null pending_exec is always a Box::into_raw'd ExecRequest.
        drop(unsafe { alloc::boxed::Box::from_raw(req_ptr) });
    }

    crate::user_task::__test_clear_execve_hook();
    clear_current();
    // SAFETY: uctx came from Box::into_raw above; nothing else owns it.
    drop(unsafe { alloc::boxed::Box::from_raw(uctx) });
    if let Some(h) = &mount {
        let _ = narf_filesystem::registry().unmount(h, "/execve-as-leak");
    }
    crate::syscall::__test_clear_global();

    if !had_req {
        return TestResult::Fail("execve staged no ExecRequest before the hook");
    }
    let after = narf_memory::paging::user_pml4_live();
    if after != baseline {
        return TestResult::Fail(
            "execve divergence leaked the new address space (user PML4 live count did not return to baseline)",
        );
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_execve_divergence_frees_address_space
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_loader_stamps_caller_pid() -> TestResult {
    // The rooted loader takes the ProcessId from its caller: exec passes the
    // calling process's EXISTING pid, spawn paths mint a fresh one. The
    // loader itself must neither mint nor release anything.
    use crate::{load_user_process_with_root, ProcessId};

    let elf = build_minimal_elf_for_execve();
    let before = net_allocated_pids();
    // SAFETY: kernel-test environment has the identity map + frame allocator.
    let proc =
        match unsafe { load_user_process_with_root(&elf, &[], &[], &[], None, ProcessId(4242)) } {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("rooted load failed on the minimal ELF"),
        };
    let stamped = proc.pid.raw();
    drop(proc);
    let after = net_allocated_pids();
    if stamped != 4242 {
        return TestResult::Fail("loader did not stamp the caller-supplied pid");
    }
    if after != before {
        return TestResult::Fail(
            "rooted loader touched the pid pool (must neither mint nor release)",
        );
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_loader_stamps_caller_pid);
