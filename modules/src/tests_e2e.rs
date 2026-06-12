//! End-to-end loadable-kernel-module smoke tests.
//!
//! The 21 unit smokes in `tests_smoke.rs` cover individual loader
//! stages — ELF parse, relocator math, manifest parsing, lifecycle
//! state transitions, /proc/modules formatting, /sys/module attrs.
//! What none of them do is exercise the **whole** flow: drive a
//! synthetic relocatable ELF through `sys_init_module`, see init
//! fire, look up the module from the registry, inspect `/proc/modules`
//! and `/sys/module/<name>/`, hold a refcount, attempt unload, drop
//! the refcount, and confirm clean teardown end-to-end.
//!
//! These smokes do exactly that. They synthesize a small ELF in
//! memory rather than relying on a cross-compiled `.ko`: the
//! payload value is exercising the LOADER, not the toolchain, and
//! in-memory synthesis keeps the QEMU smoke runner self-contained.
//! The reference `narf-test-module` crate at
//! `modules/test-module/` mirrors the same shape so out-of-tree
//! authors have a working starting point.
//!
//! Linux refs for the equivalent test path:
//!   * `tools/testing/selftests/kmod/kmod.sh` — the userspace driver
//!     for end-to-end module load/unload.
//!   * `lib/test_modload.c` — kernel-side regression module that
//!     gets loaded by the kmod selftests.
//!   * `kernel/module/main.c::do_init_module` (`main.c:2845`) — the
//!     transition under test (Loading → Live).
//!
//! Lifecycle-symbol trick: each test points `narf_module_init` /
//! `narf_module_exit` at *kernel-resident* Rust functions via
//! `SHN_ABS` symbols. The loader's `find_lifecycle_symbols` honours
//! ABS verbatim (see `loader::resolve_local_address`); this lets us
//! observe init/exit firing through `AtomicBool` flags without
//! copying machine code into a heap-allocated `.text` placement
//! (which would also need the heap to be RWX).

#![allow(clippy::too_many_arguments)]

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_capabilities::CapKind;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::elf::header::{
    EM_X86_64, ET_REL, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS, SHT_STRTAB, SHT_SYMTAB,
};
use crate::elf::symbols::{SHN_ABS, STB_GLOBAL, STT_FUNC};
use crate::syscalls::{sys_delete_module, sys_init_module, ModuleSyscallError};

// ── Observable side-effects ─────────────────────────────────────────
//
// The synthetic ELF's `narf_module_init` and `narf_module_exit`
// symbols are ABS pointers to these kernel-resident functions. The
// loader calls them; they set the flags we then check.

static INIT_RAN: AtomicBool = AtomicBool::new(false);
static EXIT_RAN: AtomicBool = AtomicBool::new(false);

/// Magic value the exported `test_module_alive` symbol returns.
/// Mirrors the constant in `narf-test-module`'s reference crate.
const TEST_MODULE_ALIVE_MAGIC: u32 = 0xDEAD_C0DE;

/// Kernel-resident `narf_module_init` for the smoke ELF.
extern "C" fn smoke_init() -> i32 {
    INIT_RAN.store(true, Ordering::Release);
    0
}

/// Kernel-resident `narf_module_exit` for the smoke ELF.
extern "C" fn smoke_exit() {
    EXIT_RAN.store(true, Ordering::Release);
}

/// Kernel-resident `test_module_alive`. The module's KSYMTAB-style
/// export points at this; smoke 2 calls it through the looked-up
/// address.
extern "C" fn smoke_alive() -> u32 {
    TEST_MODULE_ALIVE_MAGIC
}

/// Per-test ABI hash. Bumped per call so a previous test's leaked
/// state can't accidentally match.
static ABI_COUNTER: AtomicU32 = AtomicU32::new(0xE2E0_0000);

fn fresh_abi() -> u32 {
    ABI_COUNTER.fetch_add(1, Ordering::Relaxed)
}

/// Reset crate state every smoke so leftovers from earlier suites
/// (the 21 unit smokes touch the same statics) can't bleed in.
fn fresh_state(abi: u32) {
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::symbols::set_kernel_abi(abi);
    // Force-default the signature verifier in case a prior test left
    // an AlwaysReject installed.
    crate::sign::install_verifier(alloc::boxed::Box::new(crate::sign::AcceptAll));
    INIT_RAN.store(false, Ordering::Release);
    EXIT_RAN.store(false, Ordering::Release);
}

// ── ELF builder ─────────────────────────────────────────────────────
//
// Tighter than `tests_smoke::ElfBuilder`: this one targets the
// loader's full pipeline (not just the parser). Section layout:
//   sec 0: SHN_UNDEF
//   sec 1: .shstrtab
//   sec 2: .strtab
//   sec 3: .symtab
//   sec 4: .modinfo (PROGBITS, ALLOC)
//   sec 5: .text    (PROGBITS, ALLOC|EXEC) — dummy bytes
//
// Symbol table (idx 0 reserved, then ABS lifecycle):
//   1: narf_module_init   (ABS, st_value = init_addr)
//   2: narf_module_exit   (ABS, st_value = exit_addr)
//
// No relocations — the loader's `apply_all_relas` walks the SHT
// looking for `SHT_RELA` and finds none.

#[derive(Debug, Default)]
struct SmokeElfSpec {
    modinfo: Vec<u8>,
    /// Address `narf_module_init` resolves to (ABS symbol).
    init_addr: u64,
    /// Address `narf_module_exit` resolves to (ABS symbol). 0 = no
    /// exit symbol.
    exit_addr: u64,
}

fn build_smoke_elf(spec: &SmokeElfSpec) -> Vec<u8> {
    let mut out = alloc::vec![0u8; 64];

    // .shstrtab: name offsets recorded as we push.
    let mut shstr = Vec::<u8>::new();
    shstr.push(0);
    let n_shstrtab = shstr.len() as u32;
    shstr.extend_from_slice(b".shstrtab\0");
    let n_strtab = shstr.len() as u32;
    shstr.extend_from_slice(b".strtab\0");
    let n_symtab = shstr.len() as u32;
    shstr.extend_from_slice(b".symtab\0");
    let n_modinfo = shstr.len() as u32;
    shstr.extend_from_slice(b".modinfo\0");
    let n_text = shstr.len() as u32;
    shstr.extend_from_slice(b".text\0");

    // .strtab + .symtab.
    let mut strtab = Vec::<u8>::new();
    strtab.push(0);
    let mut symtab = Vec::<u8>::new();
    push_sym(&mut symtab, 0, 0, 0, 0, 0); // idx 0 reserved

    // idx 1: narf_module_init (ABS, GLOBAL, FUNC).
    let off_init = strtab.len() as u32;
    strtab.extend_from_slice(b"narf_module_init\0");
    push_sym(
        &mut symtab,
        off_init,
        (STB_GLOBAL << 4) | STT_FUNC,
        SHN_ABS,
        spec.init_addr,
        0,
    );

    // idx 2: narf_module_exit (ABS, GLOBAL, FUNC) — only if requested.
    if spec.exit_addr != 0 {
        let off_exit = strtab.len() as u32;
        strtab.extend_from_slice(b"narf_module_exit\0");
        push_sym(
            &mut symtab,
            off_exit,
            (STB_GLOBAL << 4) | STT_FUNC,
            SHN_ABS,
            spec.exit_addr,
            0,
        );
    }

    // Section contents — pre-record offsets.
    let off_shstrtab = out.len();
    out.extend_from_slice(&shstr);
    let off_strtab = out.len();
    out.extend_from_slice(&strtab);
    let off_symtab = out.len();
    out.extend_from_slice(&symtab);
    let off_modinfo = out.len();
    out.extend_from_slice(&spec.modinfo);
    let off_text = out.len();
    // A single nop so .text is non-empty (loader allocates a buffer
    // and uses bytes.as_ptr() as target_addr; we want a stable addr).
    out.push(0x90);
    let text_len: u64 = 1;

    while out.len() % 8 != 0 {
        out.push(0);
    }
    let off_sht = out.len();

    // sec 0: SHN_UNDEF.
    push_shdr(&mut out, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    // sec 1: .shstrtab.
    push_shdr(
        &mut out,
        n_shstrtab,
        SHT_STRTAB,
        0,
        0,
        off_shstrtab as u64,
        shstr.len() as u64,
        0,
        0,
        1,
        0,
    );
    // sec 2: .strtab.
    push_shdr(
        &mut out,
        n_strtab,
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
    // sec 3: .symtab. sh_link = .strtab idx (2). sh_info = first
    // non-local index; we mark every symbol GLOBAL so sh_info = 1.
    push_shdr(
        &mut out,
        n_symtab,
        SHT_SYMTAB,
        0,
        0,
        off_symtab as u64,
        symtab.len() as u64,
        2,
        1,
        8,
        24,
    );
    // sec 4: .modinfo.
    push_shdr(
        &mut out,
        n_modinfo,
        SHT_PROGBITS,
        SHF_ALLOC,
        0,
        off_modinfo as u64,
        spec.modinfo.len() as u64,
        0,
        0,
        1,
        0,
    );
    // sec 5: .text.
    push_shdr(
        &mut out,
        n_text,
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        0,
        off_text as u64,
        text_len,
        0,
        0,
        16,
        0,
    );

    let shnum: u16 = 6;
    let shentsize: u16 = 64;
    let shstrndx: u16 = 1;
    write_header(
        &mut out,
        ET_REL,
        EM_X86_64,
        off_sht as u64,
        shentsize,
        shnum,
        shstrndx,
    );
    out
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
    out[0x10..0x12].copy_from_slice(&e_type.to_le_bytes());
    out[0x12..0x14].copy_from_slice(&e_machine.to_le_bytes());
    out[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    out[0x28..0x30].copy_from_slice(&e_shoff.to_le_bytes());
    out[0x34..0x36].copy_from_slice(&64u16.to_le_bytes());
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

fn build_modinfo(name: &str, abi: u32, required_caps: Option<&str>) -> Vec<u8> {
    let mut s = format!(
        "name={}\nversion=0.1.0\nlicense=GPL-2.0-or-later\nauthor=narf-test\ndescription=loader e2e\ntarget_domain=scratch\nkernel_abi=0x{:08x}\n",
        name, abi,
    );
    if let Some(rc) = required_caps {
        s.push_str(&format!("required_caps={}\n", rc));
    }
    s.into_bytes()
}

/// Build the standard test ELF used by most smokes.
fn standard_test_elf(name: &str, abi: u32) -> Vec<u8> {
    build_smoke_elf(&SmokeElfSpec {
        modinfo: build_modinfo(name, abi, None),
        init_addr: smoke_init as usize as u64,
        exit_addr: smoke_exit as usize as u64,
    })
}

// ── Smoke 1: load → live ────────────────────────────────────────────

#[cfg(feature = "linux-compat")]
fn e2e_load_to_live() -> TestResult {
    let abi = fresh_abi();
    fresh_state(abi);
    let elf = standard_test_elf("e2e_load_to_live", abi);

    let m = match sys_init_module(&elf) {
        Ok(m) => m,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("sys_init_module returned non-zero");
        }
    };

    if !INIT_RAN.load(Ordering::Acquire) {
        return TestResult::Fail("INIT_RAN flag never set");
    }
    if !crate::registry::contains("e2e_load_to_live") {
        return TestResult::Fail("module missing from registry");
    }
    if *m.state.lock() != crate::lifecycle::ModuleState::Live {
        return TestResult::Fail("state did not reach Live");
    }

    // /proc/modules line check.
    let snapshot = crate::registry::snapshot();
    let proc = crate::proc_modules::render_all(&snapshot);
    if !proc.contains("e2e_load_to_live") {
        return TestResult::Fail("/proc/modules missing test module line");
    }

    // /sys/module/<name>/refcnt + version.
    let kobj = crate::sysfs_module::install_module(&m);
    if kobj.attr_show("refcnt").as_deref().map(str::trim) != Some("0") {
        return TestResult::Fail("/sys refcnt should read 0");
    }
    if kobj.attr_show("version").as_deref().map(str::trim) != Some("0.1.0") {
        return TestResult::Fail("/sys version should read 0.1.0");
    }

    // Cleanup so the next smoke starts clean.
    let _ = sys_delete_module("e2e_load_to_live");
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("modules/e2e", e2e_load_to_live);

// ── Smoke 2: module-published export visible ────────────────────────
//
// The synthetic ELF doesn't carry a `.narf_ksymtab` section (the
// loader doesn't parse one yet). To make the exported symbol
// observable end-to-end we have the init function publish it into
// the kernel's KSYMTAB — the same path Linux drivers take via
// EXPORT_SYMBOL: the export is materialised when init runs, and a
// later module looking it up via `resolve` sees it.

extern "C" fn smoke_init_with_export() -> i32 {
    INIT_RAN.store(true, Ordering::Release);
    crate::symbols::export("test_module_alive", smoke_alive as usize, 0xABCD_1234);
    0
}

fn e2e_symbol_export_visible() -> TestResult {
    let abi = fresh_abi();
    fresh_state(abi);
    let elf = build_smoke_elf(&SmokeElfSpec {
        modinfo: build_modinfo("e2e_export", abi, None),
        init_addr: smoke_init_with_export as usize as u64,
        exit_addr: smoke_exit as usize as u64,
    });

    if sys_init_module(&elf).is_err() {
        return TestResult::Fail("sys_init_module failed");
    }

    let manifest = crate::manifest::Manifest::default();
    let resolved = match crate::symbols::resolve("test_module_alive", None, &manifest) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("test_module_alive not in ksymtab"),
    };

    // Call through the looked-up address and verify the magic
    // round-trips. SAFETY: we just registered this address ourselves
    // pointing at `smoke_alive`, which is a kernel-resident extern
    // "C" fn returning u32.
    // SAFETY: Valid memory or trusted environment
    let f: extern "C" fn() -> u32 = unsafe { core::mem::transmute(resolved.addr) };
    if f() != TEST_MODULE_ALIVE_MAGIC {
        return TestResult::Fail("looked-up export returned wrong magic");
    }

    let _ = sys_delete_module("e2e_export");
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_symbol_export_visible);

// ── Smoke 3: refcount holds unload ──────────────────────────────────

fn e2e_refcount_blocks_unload() -> TestResult {
    let abi = fresh_abi();
    fresh_state(abi);
    let elf = standard_test_elf("e2e_busy", abi);

    let m = match sys_init_module(&elf) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("load failed"),
    };

    // try_module_get — bump refcount.
    m.refcount.get();
    match sys_delete_module("e2e_busy") {
        Err(ModuleSyscallError::ExitFailed(crate::lifecycle::LifecycleError::Busy(1))) => {}
        _ => return TestResult::Fail("delete with refcount=1 should fail Busy"),
    }
    if *m.state.lock() != crate::lifecycle::ModuleState::Live {
        return TestResult::Fail("module dropped out of Live on failed delete");
    }

    // module_put — drop refcount, retry.
    m.refcount.put();
    if sys_delete_module("e2e_busy").is_err() {
        return TestResult::Fail("second delete after refcount=0 failed");
    }
    if !EXIT_RAN.load(Ordering::Acquire) {
        return TestResult::Fail("EXIT_RAN never set");
    }
    if crate::registry::contains("e2e_busy") {
        return TestResult::Fail("module still in registry after delete");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_refcount_blocks_unload);

// ── Smoke 4: unload → /proc/modules + /sys/module + KSYMTAB cleanup ──
//
// Verifies the full unload sequence including the KSYMTAB sweep
// introduced in DESIGN.md §6.  The module registers a symbol during
// its init (attributed to module.id via the CURRENT_INIT_MODULE_ID
// context); after unload that entry must be gone.  Re-loading the
// same module re-registers the symbol under a new ModuleId — the
// idempotency test confirms the ownership model survives multiple
// load/unload cycles.

/// Init function for smoke 4: registers "e2e_cleanup_alive" while
/// the init-attribution context is set to this module's id.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
extern "C" fn smoke_init_cleanup() -> i32 {
    INIT_RAN.store(true, Ordering::Release);
    crate::symbols::export("e2e_cleanup_alive", smoke_alive as usize, 0x4242);
    0
}

#[cfg(feature = "linux-compat")]
fn e2e_unload_cleans_proc_and_sys() -> TestResult {
    let abi = fresh_abi();
    fresh_state(abi);
    let elf = build_smoke_elf(&SmokeElfSpec {
        modinfo: build_modinfo("e2e_cleanup", abi, None),
        init_addr: smoke_init_cleanup as usize as u64,
        exit_addr: smoke_exit as usize as u64,
    });

    let m = match sys_init_module(&elf) {
        Ok(m) => m,
        Err(_) => return TestResult::Fail("load failed"),
    };
    let _kobj = crate::sysfs_module::install_module(&m);

    // Symbol must be visible before unload.
    let manifest = crate::manifest::Manifest::default();
    if crate::symbols::resolve("e2e_cleanup_alive", None, &manifest).is_err() {
        return TestResult::Fail("e2e_cleanup_alive not in ksymtab before unload");
    }

    if sys_delete_module("e2e_cleanup").is_err() {
        return TestResult::Fail("delete returned error");
    }

    // /proc/modules and registry must be empty.
    let snapshot = crate::registry::snapshot();
    let proc = crate::proc_modules::render_all(&snapshot);
    if proc.contains("e2e_cleanup") {
        return TestResult::Fail("/proc/modules still lists module after delete");
    }
    if crate::registry::contains("e2e_cleanup") {
        return TestResult::Fail("registry still lists module after delete");
    }

    // DESIGN.md §6: the KSYMTAB entry registered during init must have
    // been swept by sys_delete_module → unregister_exports_of(module.id).
    match crate::symbols::resolve("e2e_cleanup_alive", None, &manifest) {
        Err(crate::symbols::ResolveError::Unknown) => {}
        Ok(_) => {
            return TestResult::Fail(
                "e2e_cleanup_alive still in ksymtab after unload (use-after-free risk)",
            )
        }
        Err(_) => return TestResult::Fail("unexpected resolve error after unload"),
    }

    // Idempotency: reload the module — the symbol reappears under a new
    // ModuleId and is visible again.
    INIT_RAN.store(false, Ordering::Release);
    EXIT_RAN.store(false, Ordering::Release);
    let abi2 = fresh_abi();
    crate::symbols::set_kernel_abi(abi2);
    let elf2 = build_smoke_elf(&SmokeElfSpec {
        modinfo: build_modinfo("e2e_cleanup", abi2, None),
        init_addr: smoke_init_cleanup as usize as u64,
        exit_addr: smoke_exit as usize as u64,
    });
    if sys_init_module(&elf2).is_err() {
        return TestResult::Fail("re-load failed");
    }
    if crate::symbols::resolve("e2e_cleanup_alive", None, &manifest).is_err() {
        return TestResult::Fail("e2e_cleanup_alive not visible after re-load");
    }
    // Clean up.
    let _ = sys_delete_module("e2e_cleanup");

    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("modules/e2e", e2e_unload_cleans_proc_and_sys);

// ── Smoke 5: load-load same module → reject ─────────────────────────

fn e2e_double_load_rejected() -> TestResult {
    let abi = fresh_abi();
    fresh_state(abi);
    let elf = standard_test_elf("e2e_dup", abi);

    if sys_init_module(&elf).is_err() {
        return TestResult::Fail("first load failed");
    }
    let second = sys_init_module(&elf);
    match &second {
        Err(ModuleSyscallError::Load(crate::loader::LoadError::AlreadyLoaded(name)))
            if name == "e2e_dup" => {}
        Err(_) => {
            return TestResult::Fail("second load: wrong error variant");
        }
        Ok(_) => return TestResult::Fail("second load: should have been rejected"),
    }
    // Confirm AlreadyLoaded surfaces as -EEXIST on the syscall wire.
    if let Err(e) = &second {
        if e.to_errno() != -17 {
            return TestResult::Fail("AlreadyLoaded should map to -EEXIST (-17)");
        }
    }

    let _ = sys_delete_module("e2e_dup");
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_double_load_rejected);

// ── Smoke 6: bad manifest → reject ──────────────────────────────────

fn e2e_bad_manifest_rejected() -> TestResult {
    let abi = fresh_abi();
    fresh_state(abi);
    // The ELF declares kernel_abi != the running kernel's. The
    // manifest parser raises AbiMismatch.
    let bad_modinfo = build_modinfo("e2e_bad_abi", 0xFFFF_FFFF, None);
    let elf = build_smoke_elf(&SmokeElfSpec {
        modinfo: bad_modinfo,
        init_addr: smoke_init as usize as u64,
        exit_addr: smoke_exit as usize as u64,
    });

    match sys_init_module(&elf) {
        Err(ModuleSyscallError::Load(crate::loader::LoadError::Manifest(
            crate::manifest::ManifestError::AbiMismatch { .. },
        ))) => {}
        Err(_) => return TestResult::Fail("wrong load-error variant"),
        Ok(_) => return TestResult::Fail("bad manifest should have been rejected"),
    }
    if crate::registry::contains("e2e_bad_abi") {
        return TestResult::Fail("rejected module still in registry");
    }
    if INIT_RAN.load(Ordering::Acquire) {
        return TestResult::Fail("init must not have run for a rejected load");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_bad_manifest_rejected);

// ── Smoke 7: cap-typed export gate ──────────────────────────────────
//
// A kernel export declared with a `required_cap` is unresolvable
// unless the module's manifest declares that CapKind in
// `required_caps`. We register a cap-gated kernel export, then load
// a module that consumes it via a relocation — without the cap
// declaration the relocator returns CapMissing.
//
// Building a real R_X86_64_PC32 relocation inline would re-implement
// the existing relocation smoke (`smoke_x86_pc32_roundtrip`). The
// LOADER-level equivalent we can drive end-to-end is: register the
// cap-gated export, then ask the resolver — the same call site the
// relocator hits — and verify CapMissing. This is the same gate the
// relocator uses on every undefined-symbol lookup (relocator.rs:107).

fn e2e_cap_gate_blocks_undeclared() -> TestResult {
    let abi = fresh_abi();
    fresh_state(abi);
    crate::symbols::export_with_cap(
        "narf_block_register_block_device",
        0xDEAD_BEEFusize,
        0x9999,
        CapKind::BlockDevice,
    );

    // Manifest that *doesn't* declare BlockDevice.
    let mf_no = crate::manifest::Manifest {
        name: "e2e_cap_no".to_string(),
        ..Default::default()
    };
    let r = crate::symbols::resolve("narf_block_register_block_device", None, &mf_no);
    match r {
        Err(crate::symbols::ResolveError::CapMissing(CapKind::BlockDevice)) => {}
        _ => return TestResult::Fail("undeclared cap should produce CapMissing"),
    }

    // Same export + manifest that DOES declare the cap → resolves.
    let mf_yes = crate::manifest::Manifest {
        name: "e2e_cap_yes".to_string(),
        required_caps: alloc::vec![crate::manifest::RequiredCap {
            kind: CapKind::BlockDevice,
            right: 0b0_0010, // Write
        }],
        ..Default::default()
    };
    let r2 = crate::symbols::resolve("narf_block_register_block_device", None, &mf_yes);
    if r2.is_err() {
        return TestResult::Fail("declared cap should resolve");
    }

    // Drive the full syscall path too: a module whose manifest
    // declares the cap loads, one that doesn't declare it would
    // only fail at relocation time (no rela in the synthetic ELF
    // so this just confirms the symbol-table side of the gate).
    let elf = build_smoke_elf(&SmokeElfSpec {
        modinfo: build_modinfo("e2e_cap_load", abi, Some("BlockDevice:Write")),
        init_addr: smoke_init as usize as u64,
        exit_addr: smoke_exit as usize as u64,
    });
    if sys_init_module(&elf).is_err() {
        return TestResult::Fail("module with declared cap should load");
    }
    let _ = sys_delete_module("e2e_cap_load");

    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_cap_gate_blocks_undeclared);

// ── Helper kept around so the test harness sees a use of `String`
// even on toolchains that elide unused imports during macro expansion.
#[allow(dead_code)]
fn _force_imports() -> String {
    "ok".to_string()
}
