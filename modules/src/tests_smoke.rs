//! Module-loader smoke tests.
//!
//! These run under `cargo xtask test`'s in-tree QEMU smoke suite.
//! They synthesize minimal Elf64 byte sequences in memory so we can
//! exercise the parser, the relocator, the manifest, the symbol
//! table, the lifecycle state machine, and the /proc + /sys
//! adapters without needing a real .ko build pipeline.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_capabilities::CapKind;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::elf::header::{
    Elf64Header, EM_AARCH64, EM_X86_64, ET_REL, SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS,
    SHT_PROGBITS, SHT_RELA, SHT_STRTAB, SHT_SYMTAB,
};
use crate::elf::{
    apply_aarch64, apply_x86_64, parse_header, parse_section, section_name, RelocError,
};
use crate::lifecycle::ModuleState;
use crate::manifest::{Manifest, ManifestError};

// ───────────────────────────────────────────────────────────────────
// Tiny Elf64 builder. Section layout:
//   sec 0: SHN_UNDEF (zero header)
//   sec 1: .shstrtab
//   sec 2: .strtab
//   sec 3: .symtab
//   sec 4: .modinfo
//   sec 5: .text (always-present, holds optional init/exit bytes)
//   sec 6: .rela.text (optional)
//   sec 7: .narf_kparams (optional)
// ───────────────────────────────────────────────────────────────────

#[derive(Default)]
struct ElfBuilder {
    machine: u16,
    modinfo: Vec<u8>,
    text: Vec<u8>,
    // (name, value_offset_in_text, st_info, st_shndx)
    locals: Vec<(String, u64, u8, u16)>,
    // (name, info_byte)
    undefs: Vec<(String, u8)>,
    // (target_section_idx, r_offset, sym_idx, ty, addend)
    relas: Vec<(u32, u64, u32, u32, i64)>,
    kparams: Vec<u8>,
}

impl ElfBuilder {
    fn new_x86_64() -> Self {
        Self {
            machine: EM_X86_64,
            ..Default::default()
        }
    }
    fn new_aarch64() -> Self {
        Self {
            machine: EM_AARCH64,
            ..Default::default()
        }
    }
    fn modinfo(mut self, raw: &[u8]) -> Self {
        self.modinfo = raw.to_vec();
        self
    }
    fn text(mut self, raw: &[u8]) -> Self {
        self.text = raw.to_vec();
        self
    }
    fn local_sym(mut self, name: &str, off: u64, info: u8, shndx: u16) -> Self {
        self.locals.push((name.into(), off, info, shndx));
        self
    }
    fn undef_sym(mut self, name: &str, info: u8) -> Self {
        self.undefs.push((name.into(), info));
        self
    }
    fn add_rela(
        mut self,
        target_section_idx: u32,
        r_offset: u64,
        sym_idx: u32,
        ty: u32,
        addend: i64,
    ) -> Self {
        self.relas
            .push((target_section_idx, r_offset, sym_idx, ty, addend));
        self
    }
    fn kparams(mut self, raw: &[u8]) -> Self {
        self.kparams = raw.to_vec();
        self
    }

    fn build(self) -> Vec<u8> {
        // We'll write the header (64), then sections, then section
        // header table at the end.
        let mut out = vec![0u8; 64];

        // ─ Section content cursor ────────────────────────────────────
        // Layout offsets in the file:
        //   0..64           — header
        //   64..             — section content
        // After all section content is appended, we record the offset
        // at which the section header table starts.

        // .shstrtab content (interleaved NUL terminator).
        let mut shstrtab = Vec::<u8>::new();
        shstrtab.push(0);
        let off_name_shstrtab = shstrtab.len();
        shstrtab.extend_from_slice(b".shstrtab\0");
        let off_name_strtab = shstrtab.len();
        shstrtab.extend_from_slice(b".strtab\0");
        let off_name_symtab = shstrtab.len();
        shstrtab.extend_from_slice(b".symtab\0");
        let off_name_modinfo = shstrtab.len();
        shstrtab.extend_from_slice(b".modinfo\0");
        let off_name_text = shstrtab.len();
        shstrtab.extend_from_slice(b".text\0");
        let off_name_relatext = shstrtab.len();
        shstrtab.extend_from_slice(b".rela.text\0");
        let off_name_kparams = shstrtab.len();
        shstrtab.extend_from_slice(b".narf_kparams\0");

        // .strtab content. Index 0 is the empty name; we append every
        // symbol name with a NUL terminator and remember its offset.
        let mut strtab = Vec::<u8>::new();
        strtab.push(0);
        let mut sym_name_offs: Vec<u32> = Vec::new();
        // Index 0 of symtab is reserved/empty.
        sym_name_offs.push(0);

        // Build the symbol table content.
        let mut symtab = Vec::<u8>::new();
        // Empty entry.
        symtab.extend_from_slice(&[0u8; 24]);
        // Local definitions land first, then UND.
        let text_section_index: u16 = 5; // see header layout
        for (name, off_in_text, info, shndx) in &self.locals {
            let name_off = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            sym_name_offs.push(name_off);
            push_sym(&mut symtab, name_off, *info, *shndx, *off_in_text, 0);
            let _ = text_section_index;
        }
        for (name, info) in &self.undefs {
            let name_off = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            sym_name_offs.push(name_off);
            push_sym(&mut symtab, name_off, *info, 0, 0, 0);
        }

        // Build the rela.text section.
        let mut rela = Vec::<u8>::new();
        for (_target, r_offset, sym_idx, ty, addend) in &self.relas {
            let info = ((*sym_idx as u64) << 32) | (*ty as u64);
            rela.extend_from_slice(&r_offset.to_le_bytes());
            rela.extend_from_slice(&info.to_le_bytes());
            rela.extend_from_slice(&(*addend as u64).to_le_bytes());
        }

        // Append section contents in order so we can record offsets.
        let off_shstrtab = out.len();
        out.extend_from_slice(&shstrtab);
        let off_strtab = out.len();
        out.extend_from_slice(&strtab);
        let off_symtab = out.len();
        out.extend_from_slice(&symtab);
        let off_modinfo = out.len();
        out.extend_from_slice(&self.modinfo);
        let off_text = out.len();
        out.extend_from_slice(&self.text);
        let off_rela = out.len();
        out.extend_from_slice(&rela);
        let off_kparams = out.len();
        out.extend_from_slice(&self.kparams);

        // Align to 8 before section header table.
        while out.len() % 8 != 0 {
            out.push(0);
        }
        let off_sht = out.len();

        // ─ Section header table ──────────────────────────────────────
        // sec 0: SHN_UNDEF
        push_shdr(&mut out, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        // sec 1: .shstrtab
        push_shdr(
            &mut out,
            off_name_shstrtab as u32,
            SHT_STRTAB,
            0,
            0,
            off_shstrtab as u64,
            shstrtab.len() as u64,
            0,
            0,
            1,
            0,
        );
        // sec 2: .strtab
        push_shdr(
            &mut out,
            off_name_strtab as u32,
            SHT_STRTAB,
            0,
            0,
            off_strtab as u64,
            strtab.len() as u64,
            0,
            0,
            1,
            0,
        );
        // sec 3: .symtab. sh_link = strtab idx (2), sh_entsize = 24.
        push_shdr(
            &mut out,
            off_name_symtab as u32,
            SHT_SYMTAB,
            0,
            0,
            off_symtab as u64,
            symtab.len() as u64,
            2,
            (1 + self.locals.len()) as u32,
            8,
            24,
        );
        // sec 4: .modinfo (PROGBITS, ALLOC).
        push_shdr(
            &mut out,
            off_name_modinfo as u32,
            SHT_PROGBITS,
            SHF_ALLOC,
            0,
            off_modinfo as u64,
            self.modinfo.len() as u64,
            0,
            0,
            1,
            0,
        );
        // sec 5: .text (PROGBITS, ALLOC+EXEC).
        push_shdr(
            &mut out,
            off_name_text as u32,
            SHT_PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            0,
            off_text as u64,
            self.text.len() as u64,
            0,
            0,
            16,
            0,
        );
        // sec 6: .rela.text. sh_link = symtab idx (3), sh_info = .text idx (5).
        push_shdr(
            &mut out,
            off_name_relatext as u32,
            SHT_RELA,
            0,
            0,
            off_rela as u64,
            rela.len() as u64,
            3,
            5,
            8,
            24,
        );
        // sec 7: .narf_kparams (PROGBITS, ALLOC).
        push_shdr(
            &mut out,
            off_name_kparams as u32,
            SHT_PROGBITS,
            SHF_ALLOC,
            0,
            off_kparams as u64,
            self.kparams.len() as u64,
            0,
            0,
            1,
            0,
        );

        let shnum: u16 = 8;
        let shentsize: u16 = 64;
        let shstrndx: u16 = 1;

        write_header(
            &mut out,
            ET_REL,
            self.machine,
            off_sht as u64,
            shentsize,
            shnum,
            shstrndx,
        );
        out
    }
}

fn write_header(
    out: &mut [u8],
    e_type: u16,
    e_machine: u16,
    e_shoff: u64,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
) {
    out[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    out[4] = 2; // ELFCLASS64
    out[5] = 1; // ELFDATA2LSB
    out[6] = 1; // EV_CURRENT
                // e_type
    out[0x10..0x12].copy_from_slice(&e_type.to_le_bytes());
    // e_machine
    out[0x12..0x14].copy_from_slice(&e_machine.to_le_bytes());
    // e_version
    out[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    // e_shoff
    out[0x28..0x30].copy_from_slice(&e_shoff.to_le_bytes());
    // e_ehsize
    out[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
    // e_phentsize / e_phnum left zero (relocatable)
    out[0x3A..0x3C].copy_from_slice(&e_shentsize.to_le_bytes());
    out[0x3C..0x3E].copy_from_slice(&e_shnum.to_le_bytes());
    out[0x3E..0x40].copy_from_slice(&e_shstrndx.to_le_bytes());
}

fn push_sym(buf: &mut Vec<u8>, name: u32, info: u8, shndx: u16, value: u64, size: u64) {
    buf.extend_from_slice(&name.to_le_bytes());
    buf.push(info);
    buf.push(0); // st_other
    buf.extend_from_slice(&shndx.to_le_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
    buf.extend_from_slice(&size.to_le_bytes());
}

#[allow(clippy::too_many_arguments)]
fn push_shdr(
    out: &mut Vec<u8>,
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
) {
    out.extend_from_slice(&sh_name.to_le_bytes());
    out.extend_from_slice(&sh_type.to_le_bytes());
    out.extend_from_slice(&sh_flags.to_le_bytes());
    out.extend_from_slice(&sh_addr.to_le_bytes());
    out.extend_from_slice(&sh_offset.to_le_bytes());
    out.extend_from_slice(&sh_size.to_le_bytes());
    out.extend_from_slice(&sh_link.to_le_bytes());
    out.extend_from_slice(&sh_info.to_le_bytes());
    out.extend_from_slice(&sh_addralign.to_le_bytes());
    out.extend_from_slice(&sh_entsize.to_le_bytes());
}

// ───────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────

fn modinfo_text(name: &str, abi: u32) -> Vec<u8> {
    let s = format!(
        "name={}\nversion=0.1.0\nlicense=GPL-2.0-or-later\nauthor=test\ndescription=t\ntarget_domain=scratch\nkernel_abi=0x{:08x}\n",
        name, abi
    );
    s.into_bytes()
}

fn smoke_elf_parse_valid_header() -> TestResult {
    let bytes = ElfBuilder::new_x86_64()
        .modinfo(&modinfo_text("a", 0xCAFE))
        .text(&[0x90u8; 16])
        .local_sym("narf_module_init", 0, (1 << 4) | 2, 5)
        .build();
    match parse_header(&bytes) {
        Ok(h) => {
            if h.e_machine == EM_X86_64 && h.e_type == ET_REL {
                TestResult::Pass
            } else {
                TestResult::Fail("parsed but fields wrong")
            }
        }
        Err(_) => TestResult::Fail("parse_header rejected a valid ELF"),
    }
}
kernel_test_in!("modules/elf", smoke_elf_parse_valid_header);

fn smoke_elf_rejects_class32() -> TestResult {
    let mut bytes = ElfBuilder::new_x86_64()
        .modinfo(&modinfo_text("a", 0))
        .text(&[0u8; 4])
        .local_sym("narf_module_init", 0, (1 << 4) | 2, 5)
        .build();
    bytes[4] = 1; // ELFCLASS32
    match parse_header(&bytes) {
        Err(crate::elf::HeaderError::InvalidClass) => TestResult::Pass,
        _ => TestResult::Fail("32-bit ELF should be rejected"),
    }
}
kernel_test_in!("modules/elf", smoke_elf_rejects_class32);

fn smoke_elf_rejects_missing_modinfo() -> TestResult {
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::symbols::set_kernel_abi(0);
    let bytes = ElfBuilder::new_x86_64()
        .modinfo(b"") // empty .modinfo
        .text(&[0xC3u8])
        .local_sym("narf_module_init", 0, (1 << 4) | 2, 5)
        .build();
    match crate::loader::load_image(&bytes) {
        Err(crate::loader::LoadError::Manifest(ManifestError::Missing)) => TestResult::Pass,
        Err(crate::loader::LoadError::Manifest(_)) => TestResult::Pass,
        other => {
            let _ = other;
            TestResult::Fail("missing .modinfo should fail manifest parse")
        }
    }
}
kernel_test_in!("modules/elf", smoke_elf_rejects_missing_modinfo);

fn smoke_manifest_parse_well_formed() -> TestResult {
    let raw = b"name=hello\nversion=0.2.0\nlicense=GPL-2.0-or-later\nauthor=Test\ndescription=A test module\ntarget_domain=net\nkernel_abi=0x12345678\nrequired_caps=NetIface:Write,DmaBuffer:Invoke\n";
    let m = match Manifest::parse(raw, 0x12345678) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("manifest parse"),
    };
    if m.name != "hello" || m.version != "0.2.0" || m.target_domain != "net" {
        return TestResult::Fail("manifest fields wrong");
    }
    if m.required_caps.len() != 2 {
        return TestResult::Fail("required_caps not parsed");
    }
    let has_net = m
        .required_caps
        .iter()
        .any(|rc| rc.kind == CapKind::NetIface && rc.right == 0b0_0010);
    let has_dma = m
        .required_caps
        .iter()
        .any(|rc| rc.kind == CapKind::DmaBuffer && rc.right == 0b1_0000);
    if !has_net || !has_dma {
        return TestResult::Fail("required_caps content wrong");
    }
    TestResult::Pass
}
kernel_test_in!("modules/manifest", smoke_manifest_parse_well_formed);

fn smoke_manifest_rejects_abi_mismatch() -> TestResult {
    let raw = b"name=q\nversion=0.1\nlicense=g\nauthor=a\ndescription=d\nkernel_abi=0xDEADBEEF\ntarget_domain=scratch\n";
    match Manifest::parse(raw, 0x12345678) {
        Err(ManifestError::AbiMismatch { .. }) => TestResult::Pass,
        _ => TestResult::Fail("abi mismatch must be rejected"),
    }
}
kernel_test_in!("modules/manifest", smoke_manifest_rejects_abi_mismatch);

fn smoke_kernel_symbol_lookup_round_trip() -> TestResult {
    crate::symbols::__reset_for_test();
    crate::symbols::export("narf_io_alloc_coherent", 0xDEAD_BEEF_CAFEusize, 0xABCD);
    let mf = Manifest::default();
    match crate::symbols::resolve("narf_io_alloc_coherent", None, &mf) {
        Ok(r) if r.addr == 0xDEAD_BEEF_CAFEusize => TestResult::Pass,
        _ => TestResult::Fail("ksymtab lookup failed"),
    }
}
kernel_test_in!("modules/symbols", smoke_kernel_symbol_lookup_round_trip);

fn smoke_x86_pc32_roundtrip() -> TestResult {
    // text bytes laid out as: 32-bit zero at offset 0 will be patched.
    let mut buf = vec![0u8; 16];
    // Place buffer "at" 0x1000, symbol at 0x2010, addend = -4 (call-site convention).
    let target_addr = 0x1000u64;
    let sym = 0x2010u64;
    let addend = -4i64;
    apply_x86_64(
        &mut buf,
        0,
        target_addr,
        sym,
        addend,
        crate::elf::reloc::R_X86_64_PC32,
    )
    .expect("pc32 apply");
    let decoded = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as i32;
    let want = (sym as i64 + addend - target_addr as i64) as i32;
    if decoded == want {
        TestResult::Pass
    } else {
        TestResult::Fail("PC32 round-trip math")
    }
}
kernel_test_in!("modules/reloc", smoke_x86_pc32_roundtrip);

fn smoke_x86_plt32_overflow_caught() -> TestResult {
    let mut buf = vec![0u8; 8];
    // sym address 5 GiB above target — outside i32 range.
    let r = apply_x86_64(
        &mut buf,
        0,
        0u64,
        0x1_4000_0000u64,
        0,
        crate::elf::reloc::R_X86_64_PLT32,
    );
    match r {
        Err(RelocError::Overflow) => TestResult::Pass,
        _ => TestResult::Fail("PLT32 overflow should be caught"),
    }
}
kernel_test_in!("modules/reloc", smoke_x86_plt32_overflow_caught);

fn smoke_aarch64_call26_encoding() -> TestResult {
    let mut buf = vec![0u8; 8];
    // 4-byte aligned branch from 0x1000 to 0x1004 → displacement = 4
    // imm = 4 >> 2 = 1.
    apply_aarch64(
        &mut buf,
        0,
        0x1000u64,
        0x1004u64,
        0,
        crate::elf::reloc::R_AARCH64_CALL26,
    )
    .expect("call26 apply");
    let cur = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if (cur & 0x03FF_FFFF) == 1 {
        TestResult::Pass
    } else {
        TestResult::Fail("CALL26 imm bits wrong")
    }
}
kernel_test_in!("modules/reloc", smoke_aarch64_call26_encoding);

fn smoke_cap_typed_export_blocks_missing_cap() -> TestResult {
    crate::symbols::__reset_for_test();
    crate::symbols::export_with_cap(
        "block_write_admit",
        0x1234usize,
        0x9999,
        CapKind::BlockDevice,
    );
    // Manifest without required_caps mentioning BlockDevice.
    let mf = Manifest::default();
    match crate::symbols::resolve("block_write_admit", None, &mf) {
        Err(crate::symbols::ResolveError::CapMissing(CapKind::BlockDevice)) => TestResult::Pass,
        _ => TestResult::Fail("cap-gated export should reject"),
    }
}
kernel_test_in!("modules/symbols", smoke_cap_typed_export_blocks_missing_cap);

fn smoke_domain_placement_resolves_text_domain() -> TestResult {
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    let id = crate::domain::resolve("net").expect("net domain present");
    if id == narf_lib::id::DomainId::DRIVER_0 {
        TestResult::Pass
    } else {
        TestResult::Fail("net should map to DRIVER_0")
    }
}
kernel_test_in!(
    "modules/domain",
    smoke_domain_placement_resolves_text_domain
);

fn smoke_lifecycle_loading_to_live() -> TestResult {
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::symbols::set_kernel_abi(0xAAAA);
    let m = arc_test_module("lc_live", 0xAAAA);
    // SAFETY: `arc_test_module` sets `init_addr` to `noop_init`, a real
    // `extern "C" fn() -> i32`, and the module is freshly built in state
    // `Loading`, satisfying `invoke_init`'s contract.
    // SAFETY: Valid memory or trusted environment
    let r = unsafe { crate::loader::invoke_init(&m) };
    if r.is_err() {
        return TestResult::Fail("invoke_init failed");
    }
    let state = *m.state.lock();
    if state == ModuleState::Live {
        TestResult::Pass
    } else {
        TestResult::Fail("module didn't reach Live")
    }
}
kernel_test_in!("modules/lifecycle", smoke_lifecycle_loading_to_live);

fn smoke_lifecycle_rmmod_clean_unload() -> TestResult {
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::symbols::set_kernel_abi(0xBEEF);
    let m = arc_test_module("lc_unload", 0xBEEF);
    // SAFETY: freshly built module in state `Loading` with `init_addr` =
    // `noop_init` (a real `extern "C"` fn), satisfying `invoke_init`.
    // SAFETY: Valid memory or trusted environment
    unsafe { crate::loader::invoke_init(&m) }.expect("init");
    // SAFETY: the module is now `Live` (init succeeded above) with refcount
    // zero, and `exit_addr` = `noop_exit` (a real `extern "C"` fn), so
    // `invoke_exit`'s Live-state contract is met.
    // SAFETY: Valid memory or trusted environment
    let r = unsafe { crate::loader::invoke_exit(&m) };
    if r.is_err() {
        return TestResult::Fail("invoke_exit failed");
    }
    let state = *m.state.lock();
    if state == ModuleState::Dead {
        TestResult::Pass
    } else {
        TestResult::Fail("module didn't reach Dead")
    }
}
kernel_test_in!("modules/lifecycle", smoke_lifecycle_rmmod_clean_unload);

fn smoke_lifecycle_rmmod_blocks_on_refcount() -> TestResult {
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::symbols::set_kernel_abi(0xCC);
    let m = arc_test_module("lc_busy", 0xCC);
    // SAFETY: freshly built module in state `Loading` with `init_addr` =
    // `noop_init` (a real `extern "C"` fn), satisfying `invoke_init`.
    // SAFETY: Valid memory or trusted environment
    unsafe { crate::loader::invoke_init(&m) }.expect("init");
    // Hold a ref so exit will refuse.
    m.refcount.get();
    // SAFETY: the module is `Live` (init succeeded) and `exit_addr` =
    // `noop_exit`; `invoke_exit` short-circuits on the non-zero refcount
    // before calling exit, but its Live-state contract is met regardless.
    // SAFETY: Valid memory or trusted environment
    let r = unsafe { crate::loader::invoke_exit(&m) };
    match r {
        Err(crate::lifecycle::LifecycleError::Busy(1)) => TestResult::Pass,
        _ => TestResult::Fail("exit must block on refcount > 0"),
    }
}
kernel_test_in!(
    "modules/lifecycle",
    smoke_lifecycle_rmmod_blocks_on_refcount
);

#[cfg(feature = "linux-compat")]
fn smoke_proc_modules_format() -> TestResult {
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::symbols::set_kernel_abi(0xD0);
    let m = arc_test_module("pm_fmt", 0xD0);
    crate::registry::insert(m.clone());
    let line = crate::proc_modules::render_one(&m);
    if line.contains("pm_fmt") && line.contains("0x") && line.contains("Loading") {
        TestResult::Pass
    } else {
        TestResult::Fail("/proc/modules line missing fields")
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("modules/procfs", smoke_proc_modules_format);

#[cfg(feature = "linux-compat")]
fn smoke_sysfs_refcnt_reads_count() -> TestResult {
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::symbols::set_kernel_abi(0xE0);
    let m = arc_test_module("sf_ref", 0xE0);
    crate::registry::insert(m.clone());
    let kobj = crate::sysfs_module::install_module(&m);
    m.refcount.get();
    m.refcount.get();
    let out = kobj.attr_show("refcnt").unwrap_or_default();
    if out.trim() == "2" {
        TestResult::Pass
    } else {
        TestResult::Fail("/sys refcnt didn't reflect counter")
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("modules/sysfs", smoke_sysfs_refcnt_reads_count);

#[cfg(feature = "linux-compat")]
fn smoke_param_sysfs_rw_round_trip() -> TestResult {
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::symbols::set_kernel_abi(0xF0);
    let m = arc_test_module_with_params("sf_param", 0xF0, b"debug=1\nname=hi\n");
    crate::registry::insert(m.clone());
    let kobj = crate::sysfs_module::install_module(&m);
    let params_kobj = kobj.get_child("parameters").expect("parameters dir");
    let initial = params_kobj.attr_show("debug").unwrap_or_default();
    if initial.trim() != "1" {
        return TestResult::Fail("initial param read mismatch");
    }
    let st = params_kobj.attr_store("debug", b"7");
    if st.is_none() {
        return TestResult::Fail("debug should be writable");
    }
    let after = params_kobj.attr_show("debug").unwrap_or_default();
    if after.trim() != "7" {
        return TestResult::Fail("write didn't persist");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("modules/params", smoke_param_sysfs_rw_round_trip);

fn smoke_two_modules_dep_refcount() -> TestResult {
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::symbols::set_kernel_abi(0xFF);
    // Module A loads + registers an exported symbol.
    let a = arc_test_module("a_dep", 0xFF);
    crate::registry::insert(a.clone());
    // Simulate B holding a reference to A via the refcount.
    a.refcount.get();
    // SAFETY: module `a` is in state `Loading`/`Live` with `exit_addr` =
    // `noop_exit` (a real `extern "C"` fn); `invoke_exit` returns Busy on
    // the held refcount before invoking exit, meeting its state contract.
    // SAFETY: Valid memory or trusted environment
    let unload = unsafe { crate::loader::invoke_exit(&a) };
    match unload {
        Err(crate::lifecycle::LifecycleError::Busy(1)) => {
            // Drop B's reference and retry — must succeed now.
            a.refcount.put();
            // SAFETY: refcount is now zero and `exit_addr` = `noop_exit`
            // (a real `extern "C"` fn); the module is still Live, so
            // `invoke_exit` may now run the exit routine soundly.
            // SAFETY: Valid memory or trusted environment
            match unsafe { crate::loader::invoke_exit(&a) } {
                Ok(_) => TestResult::Pass,
                Err(_) => TestResult::Fail("second rmmod after refcount=0 failed"),
            }
        }
        _ => TestResult::Fail("first rmmod with refcount=1 should have been Busy"),
    }
}
kernel_test_in!("modules/lifecycle", smoke_two_modules_dep_refcount);

fn smoke_signature_default_accepts() -> TestResult {
    crate::sign::install_verifier(alloc::boxed::Box::new(crate::sign::AcceptAll));
    match crate::sign::verify(&[0u8; 32]) {
        crate::sign::VerifyDecision::Allow => TestResult::Pass,
        _ => TestResult::Fail("default verifier should allow"),
    }
}
kernel_test_in!("modules/sign", smoke_signature_default_accepts);

fn smoke_signature_install_rejecter() -> TestResult {
    #[derive(Debug)]
    struct AlwaysReject;
    impl crate::sign::ModuleVerifier for AlwaysReject {
        fn verify(&self, _: &[u8]) -> crate::sign::VerifyDecision {
            crate::sign::VerifyDecision::Reject("test")
        }
    }
    crate::sign::install_verifier(alloc::boxed::Box::new(AlwaysReject));
    let outcome = crate::sign::verify(&[0u8; 4]);
    // Restore default for downstream tests.
    crate::sign::install_verifier(alloc::boxed::Box::new(crate::sign::AcceptAll));
    match outcome {
        crate::sign::VerifyDecision::Reject(_) => TestResult::Pass,
        _ => TestResult::Fail("rejecter should fire"),
    }
}
kernel_test_in!("modules/sign", smoke_signature_install_rejecter);

// ───────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────

/// Build a tiny module manually (not via the ELF loader) so lifecycle
/// tests don't need a real init function pointer.
fn arc_test_module(name: &str, abi: u32) -> Arc<crate::loader::Module> {
    let raw = format!(
        "name={}\nversion=0.1\nlicense=GPL-2.0-or-later\nauthor=t\ndescription=d\nkernel_abi=0x{:08x}\ntarget_domain=scratch\n",
        name, abi
    );
    let mf = Manifest::parse(raw.as_bytes(), abi).expect("manifest");
    Arc::new(crate::loader::Module {
        id: crate::symbols::alloc_module_id(),
        manifest: mf,
        domain: narf_lib::id::DomainId::SCRATCH,
        image_size: 0,
        placements: Vec::new(),
        init_addr: noop_init as usize,
        exit_addr: Some(noop_exit as usize),
        params: Vec::new(),
        refcount: crate::refcount::RefCount::new(),
        state: narf_lib::sync::IrqSafeSpinLock::new(crate::lifecycle::ModuleState::Loading),
    })
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn arc_test_module_with_params(
    name: &str,
    abi: u32,
    params_bytes: &[u8],
) -> Arc<crate::loader::Module> {
    let m = arc_test_module(name, abi);
    let slots = crate::params::parse_section(params_bytes);
    // We can't mutate the Arc<Module>'s `params` Vec directly because
    // it's behind Arc; rebuild a fresh Arc with the same fields.
    let new = crate::loader::Module {
        id: crate::symbols::alloc_module_id(),
        manifest: m.manifest.clone(),
        domain: m.domain,
        image_size: m.image_size,
        placements: Vec::new(),
        init_addr: m.init_addr,
        exit_addr: m.exit_addr,
        params: slots,
        refcount: crate::refcount::RefCount::new(),
        state: narf_lib::sync::IrqSafeSpinLock::new(crate::lifecycle::ModuleState::Loading),
    };
    Arc::new(new)
}

extern "C" fn noop_init() -> i32 {
    0
}
extern "C" fn noop_exit() {}

// Avoid unused-import warnings for the elf builder + types used only
// in one branch.
#[allow(dead_code)]
fn _ensure_builder_compiles() -> Vec<u8> {
    ElfBuilder::new_aarch64()
        .modinfo(&modinfo_text("x", 0))
        .text(&[0u8; 4])
        .local_sym("narf_module_init", 0, (1 << 4) | 2, 5)
        .undef_sym("printk", 1u8 << 4)
        .add_rela(5, 0, 2, 1, 0)
        .kparams(b"a=b\n")
        .build()
}

// Suppress dead-code warnings on imports only used in the test build.
#[allow(dead_code)]
fn _force_elf_imports(_h: Elf64Header) {
    let _ = (SHT_PROGBITS, SHT_NOBITS, SHT_RELA, SHT_SYMTAB, SHT_STRTAB);
    let _ = (SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE);
    let _ = parse_section;
    let _ = section_name;
}
