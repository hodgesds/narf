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
//! The focused smokes synthesize small ELF images in memory. The final smoke
//! also loads the rustc-built `narf-test-module.ko` staged by cargo narf, so the
//! compiler/linker's genuine relocation output is exercised on both arches.
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

use crate::elf::header::{ET_REL, SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS, SHT_STRTAB, SHT_SYMTAB};
use crate::elf::symbols::{SHN_ABS, STB_GLOBAL, STT_FUNC};
use crate::syscalls::{
    sys_delete_module, sys_init_module, sys_init_module_with_params, ModuleSyscallError,
};

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
        native_machine(),
        off_sht as u64,
        shentsize,
        shnum,
        shstrndx,
    );
    out
}

/// `e_machine` for the running architecture.
///
/// `load_image` rejects a foreign machine before anything else, so an image
/// hardcoded to x86_64 would fail every one of these end-to-end smokes on an
/// aarch64 kernel.
fn native_machine() -> u16 {
    #[cfg(target_arch = "aarch64")]
    {
        crate::elf::EM_AARCH64
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        crate::elf::EM_X86_64
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
kernel_test_in!("modules/e2e", e2e_load_to_live);

/// The load-authority holder, rather than the module author, selects the
/// effective isolation frame. The manifest remains an author hint and FRAME
/// itself remains reserved for statically linked TCB code.
fn e2e_load_time_domain_override() -> TestResult {
    let abi = fresh_abi();
    fresh_state(abi);
    let elf = standard_test_elf("e2e_domain_override", abi);

    let module = match sys_init_module_with_params(&elf, "domain=driver3") {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("valid load-time domain override was rejected"),
    };
    if module.manifest.target_domain != "scratch" {
        return TestResult::Fail("load-time override mutated the signed manifest hint");
    }
    if module.domain != narf_lib::id::DomainId::DRIVER_3 {
        return TestResult::Fail("load-time override did not select DRIVER_3");
    }
    drop(module);
    if sys_delete_module("e2e_domain_override").is_err() {
        return TestResult::Fail("domain-override module failed to unload");
    }

    // Even a later alias registration cannot make FRAME a legal runtime
    // target for separately loaded text.
    crate::domain::register_domain("frame-test", narf_lib::id::DomainId::FRAME);
    match sys_init_module_with_params(&elf, "domain=frame-test") {
        Err(ModuleSyscallError::Load(crate::loader::LoadError::DomainOverride(
            crate::domain::DomainError::FrameReserved,
        ))) => TestResult::Pass,
        _ => TestResult::Fail("runtime module was allowed into the FRAME domain"),
    }
}
kernel_test_in!("modules/e2e", e2e_load_time_domain_override);

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

// ── Smoke 8: rustc-built `.ko` load → execute → unload ─────────────────

fn e2e_real_rust_module_loads_raw_and_compressed() -> TestResult {
    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("no staged initramfs for real module smoke");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/narf_test_module.ko")
    else {
        return TestResult::Skip("narf_test_module.ko was not staged");
    };

    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::sign::install_verifier(alloc::boxed::Box::new(crate::sign::Ed25519Verifier));
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);

    // cargo narf also stages its own compressed artifact. It still carries the
    // zero ABI placeholder, so a successful decode must reach the manifest
    // and fail specifically with AbiMismatch. This cross-checks cargo narf's small
    // host encoder against the kernel's independent bounded LZ4 decoder.
    let Some((_, staged_compressed)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/narf_test_module.ko.lz4")
    else {
        return TestResult::Skip("narf_test_module.ko.lz4 was not staged");
    };
    match crate::loader::load_image(staged_compressed) {
        Err(crate::loader::LoadError::Manifest(crate::manifest::ManifestError::AbiMismatch {
            ..
        })) => {}
        Err(crate::loader::LoadError::Compression(_)) => {
            return TestResult::Fail("xtask-compressed module did not decode in kernel");
        }
        _ => return TestResult::Fail("xtask-compressed fixture did not reach ABI validation"),
    }

    // cargo narf cannot know the live export-table hash while compiling the test
    // fixture, so it stages the fixed-width zero placeholder. Stamp the test
    // copy in memory exactly as `cargo narf build build-module --kernel-abi` does.
    let mut image = staged.to_vec();
    const PLACEHOLDER: &[u8] = b"kernel_abi=0x00000000";
    let Some(value_at) = image
        .windows(PLACEHOLDER.len())
        .position(|window| window == PLACEHOLDER)
        .map(|start| start + b"kernel_abi=0x".len())
    else {
        return TestResult::Fail("real module has no ABI placeholder");
    };
    let stamped = format!("{abi:08x}");
    image[value_at..value_at + 8].copy_from_slice(stamped.as_bytes());

    let module = match sys_init_module(&image) {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("rustc-built module failed to load or execute init"),
    };
    if module.name() != "test_module" {
        return TestResult::Fail("rustc-built module manifest name mismatch");
    }
    if module.domain != narf_lib::id::DomainId::SCRATCH {
        return TestResult::Fail("target_domain was not enforced as SCRATCH");
    }
    if *module.state.lock() != crate::lifecycle::ModuleState::Live {
        return TestResult::Fail("rustc-built module did not reach Live");
    }
    if module.base_addr() == 0 || module.total_size() == 0 {
        return TestResult::Fail("rustc-built module was not mapped");
    }
    if !crate::registry::contains("test_module") {
        return TestResult::Fail("rustc-built module missing from registry");
    }
    drop(module);
    if sys_delete_module("test_module").is_err() {
        return TestResult::Fail("rustc-built module exit/unload failed");
    }
    if crate::registry::contains("test_module") {
        return TestResult::Fail("rustc-built module remained registered after unload");
    }

    // Exercise the same genuine rustc/linker output through the compressed
    // path. Compress only after stamping the live ABI: the envelope is the
    // exact payload a production signer authenticates.
    let mut compressed =
        alloc::vec![0u8; narf_memory::compress::lz4_max_compressed_len(image.len())];
    let compressed_len = match narf_memory::compress::lz4_encode(&image, &mut compressed) {
        Ok(len) => len,
        Err(_) => return TestResult::Fail("real module LZ4 compression failed"),
    };
    compressed.truncate(compressed_len);
    let envelope = match crate::compression::envelope_lz4(image.len(), &compressed) {
        Ok(envelope) => envelope,
        Err(_) => return TestResult::Fail("real module compression envelope failed"),
    };
    let module = match sys_init_module(&envelope) {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("compressed rustc-built module failed to load"),
    };
    if module.domain != narf_lib::id::DomainId::SCRATCH
        || *module.state.lock() != crate::lifecycle::ModuleState::Live
        || module.image_size != envelope.len()
    {
        return TestResult::Fail("compressed module lost domain, state, or stored-size metadata");
    }
    drop(module);
    if sys_delete_module("test_module").is_err() {
        return TestResult::Fail("compressed rustc-built module failed to unload");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_real_rust_module_loads_raw_and_compressed);

// ── Smoke 8b: a module built on `narf-module-rt` (alloc + async) ───────

/// Load the rustc-built `narf-module-rt-smoke` `.ko`. Unlike the reference
/// test module, its object carries out-of-line `core`/`alloc` code and the
/// runtime crate, linked in from the staticlib archive and section-GC'd by
/// `cargo narf build build-module`; this is the proof that such an object relocates and
/// runs. Its `narf_module_init` allocates through its `#[global_allocator]`,
/// formats with `alloc::format!`, and drives two futures on its own executor
/// (a 3 ms sleep under an async mutex and a waiter on that mutex), returning
/// a negative errno if any of those misbehaves — so a successful load is the
/// assertion.
fn e2e_runtime_module_allocates_and_runs_futures() -> TestResult {
    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("no staged initramfs for runtime module smoke");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/narf_module_rt_smoke.ko")
    else {
        return TestResult::Skip("narf_module_rt_smoke.ko was not staged");
    };

    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::sign::install_verifier(alloc::boxed::Box::new(crate::sign::Ed25519Verifier));
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);

    let mut image = staged.to_vec();
    const PLACEHOLDER: &[u8] = b"kernel_abi=0x00000000";
    let Some(value_at) = image
        .windows(PLACEHOLDER.len())
        .position(|window| window == PLACEHOLDER)
        .map(|start| start + b"kernel_abi=0x".len())
    else {
        return TestResult::Fail("runtime module has no ABI placeholder");
    };
    let stamped = format!("{abi:08x}");
    image[value_at..value_at + 8].copy_from_slice(stamped.as_bytes());

    let module = match sys_init_module(&image) {
        Ok(module) => module,
        Err(_) => {
            return TestResult::Fail(
                "runtime module failed to load, or its init reported a heap/executor fault",
            )
        }
    };
    if module.name() != "module_rt_smoke"
        || *module.state.lock() != crate::lifecycle::ModuleState::Live
    {
        return TestResult::Fail("runtime module did not reach Live under its manifest name");
    }
    drop(module);
    if sys_delete_module("module_rt_smoke").is_err() {
        return TestResult::Fail("runtime module exit/unload failed");
    }
    if crate::registry::contains("module_rt_smoke") {
        return TestResult::Fail("runtime module remained registered after unload");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_runtime_module_allocates_and_runs_futures);

/// Load parameters reach a module's init through `narf_module_param`. The
/// runtime smoke declares `greeting=default` and `expect=default` in its
/// `.narf_kparams` and fails init unless they are equal: overriding both in
/// the load string must load, overriding only one must fail init — and the
/// `domain=` placement option must not be taken for a parameter.
fn e2e_runtime_module_reads_load_parameters() -> TestResult {
    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("no staged initramfs for runtime module smoke");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/narf_module_rt_smoke.ko")
    else {
        return TestResult::Skip("narf_module_rt_smoke.ko was not staged");
    };
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::sign::install_verifier(alloc::boxed::Box::new(crate::sign::Ed25519Verifier));
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("runtime module has no ABI placeholder");
    };

    match crate::syscalls::sys_init_module_with_params(
        &image,
        "domain=scratch greeting=hello expect=hello",
    ) {
        Ok(module) => {
            let slot = crate::params::find(&module.params, "greeting").map(|p| p.read());
            drop(module);
            let _ = sys_delete_module("module_rt_smoke");
            if slot.as_deref() != Some("hello") {
                return TestResult::Fail("load-string parameter did not reach the module's slot");
            }
        }
        Err(_) => {
            return TestResult::Fail("module rejected matching load-string parameters");
        }
    }
    match crate::syscalls::sys_init_module_with_params(&image, "greeting=hello") {
        Err(ModuleSyscallError::InitFailed(_)) => {}
        Ok(_) => {
            let _ = sys_delete_module("module_rt_smoke");
            return TestResult::Fail("init accepted a parameter override it could not see");
        }
        Err(_) => return TestResult::Fail("runtime module failed to load before init"),
    }
    if crate::registry::contains("module_rt_smoke") {
        return TestResult::Fail("failed init left the module registered");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_runtime_module_reads_load_parameters);

// ── Smoke 9: a real dual-build driver `.ko` loads and DRIVES the device ──

/// The capstone of the loadable-driver work: load the rustc-built
/// `narf-drivers-net-e1000` `.ko` (the same crate the kernel links as a
/// built-in) and prove it (a) registers through the `narf_register_pci_driver`
/// KSYMTAB export, and (b) actually **drives the real QEMU e1000** through the
/// device-datapath C-ABI — the module's `probe_c` enables the device, maps
/// BAR0, and reads STATUS + the MAC off the silicon, all via exports, holding
/// only an opaque device token + BAR handle.
///
/// On a VM without an e1000 the datapath half is skipped but the registration +
/// bogus-token-rejection halves still run. `MODULE_THUNKS`
/// (`__module_thunk_for_test`) is collision-free: only a *module* registration
/// populates it, so the built-in e1000's `PciProbeFn` can't be mistaken for it.
fn e2e_driver_module_drives_device() -> TestResult {
    const E1000_VENDOR: u16 = 0x8086;
    const E1000_DEV_82540EM: u16 = 0x100E;

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("no staged initramfs for driver module smoke");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/narf_drivers_net_e1000.ko")
    else {
        return TestResult::Skip("narf_drivers_net_e1000.ko was not staged");
    };

    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::sign::install_verifier(alloc::boxed::Box::new(crate::sign::AcceptAll));
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    // Start the bus match table clean so probe_all sees only this module.
    narf_bus::driver_match::__reset_for_test();

    // Stamp the live ABI over cargo narf's zero placeholder, as the loader expects.
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("driver module has no ABI placeholder");
    };

    // The module advertises `target_domain=net` (DRIVER_0), but the holder of
    // module-load authority places this instance in DRIVER_2. A built-in
    // e1000 keeps its compile-time registration path and never consumes this
    // loader parameter.
    let module = match sys_init_module_with_params(&image, "domain=driver2") {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("driver module failed to load or run init"),
    };
    if module.name() != "e1000" {
        return TestResult::Fail("driver module manifest name mismatch");
    }
    if module.domain != narf_lib::id::DomainId::DRIVER_2 {
        return TestResult::Fail("load-time domain did not override target_domain=net");
    }
    if *module.state.lock() != crate::lifecycle::ModuleState::Live {
        return TestResult::Fail("driver module did not reach Live");
    }

    // narf_module_init ran register() -> narf_register_pci_driver, so the bus
    // recorded the module's probe thunk for (vendor, device).
    match narf_bus::driver_match::__module_thunk_for_test(E1000_VENDOR, E1000_DEV_82540EM) {
        Some(thunk) => {
            // A bogus token (no device context) must be rejected, not claimed.
            if thunk(0, 0) == 0 {
                return TestResult::Fail("module probe_c claimed success for an unknown device");
            }
        }
        None => return TestResult::Fail("driver module did not register its PCI match"),
    }

    // Drive the real device: run the PCI probe so the trampoline installs the
    // datapath context and calls probe_c, which enables + MMIO-reads the e1000.
    #[cfg(target_arch = "x86_64")]
    {
        use narf_bus::{bootstrap_registry_authority, devices, probe_all_pci, BusKind};
        // SAFETY: ECAM_DEFAULT_BASE is the q35 MMCONFIG window the harness maps;
        // `init` only walks that ECAM region and is idempotent on re-entry.
        let _ = unsafe { narf_bus::init(narf_bus::x86_64::ECAM_DEFAULT_BASE) };
        let e1000_count = devices()
            .iter()
            .filter(|d| {
                matches!(&d.kind, BusKind::Pcie { .. })
                    && d.id.vendor == E1000_VENDOR
                    && d.id.device == E1000_DEV_82540EM
            })
            .count();
        if e1000_count != 0 {
            let authority = bootstrap_registry_authority();
            match probe_all_pci(&authority) {
                // Only the module's match is registered (we reset the table), so
                // a bind means the module's probe_c drove the device and returned 0.
                Ok(n) if n >= 1 => {}
                Ok(_) => {
                    narf_bus::driver_match::__reset_for_test();
                    return TestResult::Fail(
                        "probe_all bound 0 — module probe_c did not drive the e1000",
                    );
                }
                Err(_) => {
                    narf_bus::driver_match::__reset_for_test();
                    return TestResult::Fail("probe_all_pci failed");
                }
            }
            // Two descriptor rings + 8 TX buffers + 256 RX buffers. The
            // Stage-2 scratch allocation was freed before ring bring-up.
            if narf_bus::driver_match::__module_dma_buffer_count_for_test(module.id.0)
                != 266 * e1000_count
            {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail(
                    "module probe did not retain the expected DMA rings/buffers",
                );
            }
            // The poller calls module text only from executor context through
            // the lifecycle/domain gate. Its first poll is immediate; later
            // polls remain live as the legacy-IRQ fallback for this NIC.
            let _ = narf_scheduler::poll_one_round();
            if narf_bus::driver_match::__module_callback_invocation_count_for_test(module.id.0) == 0
            {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail("module task-context poll callback did not run");
            }
            if narf_bus::driver_match::__module_callback_failure_count_for_test(module.id.0) != 0 {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail("module task-context poll callback returned an error");
            }
            if narf_bus::driver_match::__module_dma_buffer_count_for_test(module.id.0)
                != 266 * e1000_count
            {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail("poll callback changed the persistent DMA buffer set");
            }
            if narf_bus::driver_match::__module_netif_count_for_test(module.id.0) != e1000_count {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail(
                    "module did not register one interface per matching PCI function",
                );
            }

            // Send a real ARP request through the registered interface. The
            // in-tree context trampoline enters module text, the module posts
            // a TX descriptor, and waits through the bounded DMA primitive
            // until QEMU reports hardware completion. RX is exercised
            // separately below because this test boot has already bound the
            // same physical device to the built-in driver.
            let Some(source_mac) = narf_bus::driver_match::__module_netif_mac_for_test(module.id.0)
            else {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail("module network interface lost its hardware MAC");
            };
            let mut arp = [0u8; 42];
            arp[..6].fill(0xff);
            arp[6..12].copy_from_slice(&source_mac);
            arp[12..14].copy_from_slice(&[0x08, 0x06]);
            arp[14..22].copy_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
            arp[22..28].copy_from_slice(&source_mac);
            arp[28..32].copy_from_slice(&[10, 0, 2, 15]);
            arp[38..42].copy_from_slice(&[10, 0, 2, 2]);
            if !narf_bus::driver_match::__module_netif_send_for_test(module.id.0, &arp) {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail("module network interface failed ARP transmit");
            }
            let (tx, tx_err, _) =
                narf_bus::driver_match::__module_netif_stats_for_test(module.id.0);
            if tx != 1 || tx_err != 0 {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail("module TX callback accounting mismatch");
            }
            // This guest boot already bound the built-in e1000 before the
            // module smoke runs. A production module-only build has exclusive
            // device ownership; rebinding the live test NIC leaves the old
            // driver's background state attached. Keep the real TX/completion
            // proof above, then emulate one device RX completion in the
            // module-owned coherent ring so the RX copy, callback gate, stack
            // delivery, and descriptor-rearm path are deterministic.
            let mut reply = [0u8; 64];
            reply[..6].copy_from_slice(&source_mac);
            reply[6..12].copy_from_slice(&[0x52, 0x55, 10, 0, 2, 2]);
            reply[12..14].copy_from_slice(&[0x08, 0x06]);
            reply[14..22].copy_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02]);
            reply[22..28].copy_from_slice(&[0x52, 0x55, 10, 0, 2, 2]);
            reply[28..32].copy_from_slice(&[10, 0, 2, 2]);
            reply[32..38].copy_from_slice(&source_mac);
            reply[38..42].copy_from_slice(&[10, 0, 2, 15]);

            // Handle 1 was the freed Stage-2 scratch buffer and must never be
            // reused. The persistent layout is therefore TX ring = 2, RX ring
            // = 3, eight TX buffers = 4..11, RX[0] = 12.
            let owner = module.id.0;
            let mut rx_desc = [0u8; 16];
            if !narf_bus::driver_match::__module_dma_read_for_test(owner, 3, 0, &mut rx_desc)
                || !narf_bus::driver_match::__module_dma_write_for_test(owner, 12, 0, &reply)
            {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail("could not stage module RX descriptor completion");
            }
            rx_desc[8..10].copy_from_slice(&(reply.len() as u16).to_le_bytes());
            rx_desc[12] = 0x03; // legacy RX DD | EOP
            rx_desc[13] = 0;
            if !narf_bus::driver_match::__module_dma_write_for_test(owner, 3, 0, &rx_desc) {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail("could not publish module RX descriptor completion");
            }

            let callbacks_before_rx =
                narf_bus::driver_match::__module_callback_invocation_count_for_test(owner);
            let received = narf_scheduler::responsive_spin_until(
                || {
                    // Kernel tests run outside the executor's main loop. Pump
                    // it explicitly so the module's periodic RX callback can
                    // observe the asynchronous reply from QEMU's SLIRP peer.
                    let _ = narf_scheduler::poll_one_round();
                    narf_bus::driver_match::__module_netif_stats_for_test(owner).2 > 0
                },
                narf_time::Deadline::after_ms(100),
            );
            if !received {
                let callbacks_after_rx =
                    narf_bus::driver_match::__module_callback_invocation_count_for_test(
                        module.id.0,
                    );
                narf_bus::driver_match::__reset_for_test();
                if callbacks_after_rx <= callbacks_before_rx {
                    return TestResult::Fail("module periodic RX callback was not rescheduled");
                }
                return TestResult::Fail("module RX ring did not receive the ARP reply");
            }
            let mut rearmed = [0u8; 16];
            if !narf_bus::driver_match::__module_dma_read_for_test(owner, 3, 0, &mut rearmed)
                || rearmed[12] != 0
            {
                narf_bus::driver_match::__reset_for_test();
                return TestResult::Fail("module RX callback did not rearm its descriptor");
            }

            // Both identical cards live in one module image. Sending on either
            // ifindex must modify only that device's retained TX descriptor ring.
            let instances = narf_bus::driver_match::__module_netif_instances_for_test(owner);
            for &(target, _) in &instances {
                let mut before = Vec::new();
                for &(token, _) in &instances {
                    let mut ring = [0u8; 128];
                    if narf_bus::module_dma_read(owner, token, 2, 0, &mut ring) != 0 {
                        return TestResult::Fail("module multi-device TX ring snapshot failed");
                    }
                    before.push(ring);
                }
                let mut frame = [0u8; 64];
                frame[..6].fill(0xff);
                frame[6..12].copy_from_slice(&source_mac);
                frame[12..14].copy_from_slice(&[0x88, 0xb5]);
                if !narf_bus::driver_match::__module_netif_send_for_device_for_test(
                    owner, target, &frame,
                ) {
                    return TestResult::Fail("per-device module TX callback failed");
                }
                for (&(token, _), previous) in instances.iter().zip(before) {
                    let mut after = [0u8; 128];
                    if narf_bus::module_dma_read(owner, token, 2, 0, &mut after) != 0
                        || (after != previous) != (token == target)
                    {
                        return TestResult::Fail("module TX callback crossed device contexts");
                    }
                }
            }
        }
    }

    // Unload itself must tear down the registration + cap-bearing datapath
    // context before freeing module text; a test-only registry reset here
    // would hide a dangling callback.
    let owner = module.id.0;
    drop(module);
    if sys_delete_module("e1000").is_err() {
        return TestResult::Fail("driver module failed to unload");
    }
    if narf_bus::driver_match::__module_thunk_for_test(E1000_VENDOR, E1000_DEV_82540EM).is_some() {
        return TestResult::Fail("driver module unload left a PCI probe callback");
    }
    if narf_bus::driver_match::__module_device_context_count_for_test(owner) != 0 {
        return TestResult::Fail("driver module unload left a device context");
    }
    narf_bus::driver_match::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_driver_module_drives_device);

// ── Safe unload ─────────────────────────────────────────────────────
//
// Module text runs only in `init`, in `exit`, and inside module call-gate
// calls. Unload must start only from Live with no call in flight, and only
// once, or it can unmap text a CPU is still running.

/// `exit` runs of the counting smoke modules.
static EXIT_COUNT: AtomicU32 = AtomicU32::new(0);
/// What a self-unloading `init` observed: 1 = refused as still Loading.
static INIT_UNLOAD_SEEN: AtomicU32 = AtomicU32::new(0);
const UNLOAD_IN_INIT: &str = "e2e_unload_in_init";

extern "C" fn counting_exit() {
    EXIT_COUNT.fetch_add(1, Ordering::AcqRel);
}

/// An `init` that tries to unload its own module while it is still running.
extern "C" fn self_unloading_init() -> i32 {
    let seen = match sys_delete_module(UNLOAD_IN_INIT) {
        Err(ModuleSyscallError::ExitFailed(crate::lifecycle::LifecycleError::BadState {
            from: crate::lifecycle::ModuleState::Loading,
            ..
        })) => 1,
        _ => 2,
    };
    INIT_UNLOAD_SEEN.store(seen, Ordering::Release);
    0
}

fn counting_elf(name: &str, abi: u32, init: extern "C" fn() -> i32) -> Vec<u8> {
    build_smoke_elf(&SmokeElfSpec {
        modinfo: build_modinfo(name, abi, None),
        init_addr: init as usize as u64,
        exit_addr: counting_exit as usize as u64,
    })
}

/// An unload attempted while `init` is still running is refused: init holds
/// no reference, so only the Loading state stands between it and an unmap.
fn e2e_unload_refused_while_initialising() -> TestResult {
    let abi = fresh_abi();
    fresh_state(abi);
    EXIT_COUNT.store(0, Ordering::Release);
    INIT_UNLOAD_SEEN.store(0, Ordering::Release);
    let elf = counting_elf(UNLOAD_IN_INIT, abi, self_unloading_init);
    let Ok(module) = sys_init_module(&elf) else {
        return TestResult::Fail("self-unloading module failed to load");
    };
    let seen = INIT_UNLOAD_SEEN.load(Ordering::Acquire);
    let live = *module.state.lock() == crate::lifecycle::ModuleState::Live;
    let exits_during_init = EXIT_COUNT.load(Ordering::Acquire);
    drop(module);
    let unloaded = sys_delete_module(UNLOAD_IN_INIT).is_ok();
    if seen != 1 {
        return TestResult::Fail("an unload during init was not refused as still Loading");
    }
    if exits_during_init != 0 || !live {
        return TestResult::Fail("an unload during init ran exit or left the module not Live");
    }
    if !unloaded || EXIT_COUNT.load(Ordering::Acquire) != 1 {
        return TestResult::Fail("the module did not unload cleanly once init had finished");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_unload_refused_while_initialising);

/// Unload runs `exit` exactly once: a second unload while one owns the module
/// is -EBUSY, an unload from inside a call into the module is -EBUSY and
/// leaves it Live, and an unload after the module is gone is NotFound.
fn e2e_unload_runs_exit_once() -> TestResult {
    const NAME: &str = "e2e_unload_once";
    let abi = fresh_abi();
    fresh_state(abi);
    EXIT_COUNT.store(0, Ordering::Release);
    let elf = counting_elf(NAME, abi, smoke_init);
    let Ok(module) = sys_init_module(&elf) else {
        return TestResult::Fail("counting module failed to load");
    };

    // Another unload already owns the module.
    *module.state.lock() = crate::lifecycle::ModuleState::Going;
    let concurrent = sys_delete_module(NAME);
    *module.state.lock() = crate::lifecycle::ModuleState::Live;
    let concurrent_ok = matches!(
        &concurrent,
        Err(ModuleSyscallError::ExitFailed(
            crate::lifecycle::LifecycleError::BadState {
                from: crate::lifecycle::ModuleState::Going,
                ..
            }
        ))
    ) && concurrent.as_ref().err().map(ModuleSyscallError::to_errno)
        == Some(-16);

    // An unload from inside a gate call: the call holds a reference.
    let id = module.id.0;
    let inside = crate::call_in_module_context(id, || match sys_delete_module(NAME) {
        Err(ModuleSyscallError::ExitFailed(crate::lifecycle::LifecycleError::Busy(_))) => 0,
        _ => -1,
    });
    let still_live = *module.state.lock() == crate::lifecycle::ModuleState::Live
        && crate::registry::contains(NAME);
    let exits_before = EXIT_COUNT.load(Ordering::Acquire);
    drop(module);

    let first = sys_delete_module(NAME).is_ok();
    let second = sys_delete_module(NAME);
    let exits = EXIT_COUNT.load(Ordering::Acquire);
    if !concurrent_ok {
        return TestResult::Fail("an unload while another owned the module was not -EBUSY");
    }
    if inside != 0 || !still_live {
        return TestResult::Fail("an unload from inside a module call was not refused cleanly");
    }
    if exits_before != 0 {
        return TestResult::Fail("a refused unload ran the module's exit");
    }
    if !first || !matches!(second, Err(ModuleSyscallError::NotFound)) || exits != 1 {
        return TestResult::Fail("unload did not run exit exactly once");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_unload_runs_exit_once);

/// A real driving module survives a refused unload, then unloads, reloads
/// and drives its device again: e1000.ko against QEMU's 82540EM.
fn e2e_driver_module_unload_and_reload() -> TestResult {
    const E1000_VENDOR: u16 = 0x8086;
    const E1000_DEV_82540EM: u16 = 0x100E;
    const MATCH_NAME: &str = "e1000-82540em";

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("no staged initramfs for driver module smoke");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/narf_drivers_net_e1000.ko")
    else {
        return TestResult::Skip("narf_drivers_net_e1000.ko was not staged");
    };
    crate::registry::__reset_for_test();
    crate::symbols::__reset_for_test();
    crate::domain::__reset_for_test();
    crate::domain::install_standard_domains();
    crate::sign::install_verifier(alloc::boxed::Box::new(crate::sign::AcceptAll));
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    narf_bus::driver_match::__reset_for_test();
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("driver module has no ABI placeholder");
    };

    // How many QEMU 82540EMs this guest has. aarch64 has none: the lifecycle
    // part of the test still runs, the device part does not.
    #[cfg(target_arch = "x86_64")]
    let nics = {
        // SAFETY: ECAM_DEFAULT_BASE is the q35 MMCONFIG window the harness
        // maps; `init` only walks that ECAM region and is idempotent.
        let _ = unsafe { narf_bus::init(narf_bus::x86_64::ECAM_DEFAULT_BASE) };
        narf_bus::devices()
            .iter()
            .filter(|d| {
                matches!(&d.kind, narf_bus::BusKind::Pcie { .. })
                    && d.id.vendor == E1000_VENDOR
                    && d.id.device == E1000_DEV_82540EM
            })
            .count()
    };
    #[cfg(not(target_arch = "x86_64"))]
    let nics = 0usize;

    // Load, bind every 82540EM, and run the poller once. Returns the owner.
    let bring_up = |round: &'static str| -> Result<u64, &'static str> {
        let module = sys_init_module_with_params(&image, "domain=driver2").map_err(|_| round)?;
        let owner = module.id.0;
        if nics != 0 {
            let authority = narf_bus::bootstrap_registry_authority();
            match narf_bus::probe_all_pci(&authority) {
                Ok(n) if n as usize >= nics => {}
                _ => return Err("probe_all did not bind the module to every 82540EM"),
            }
            let _ = narf_scheduler::poll_one_round();
            if narf_bus::driver_match::__module_netif_count_for_test(owner) != nics
                || narf_bus::driver_match::__module_callback_invocation_count_for_test(owner) == 0
            {
                return Err("the module did not drive the NIC (interface or poller missing)");
            }
        }
        Ok(owner)
    };

    let owner = match bring_up("e1000.ko failed to load") {
        Ok(owner) => owner,
        Err(why) => {
            narf_bus::driver_match::__reset_for_test();
            return TestResult::Fail(why);
        }
    };

    // A refused unload (from inside a call into the module) must not break
    // it: its poller keeps running and its interface stays up.
    let refused = crate::call_in_module_context(owner, || match sys_delete_module("e1000") {
        Err(ModuleSyscallError::ExitFailed(crate::lifecycle::LifecycleError::Busy(_))) => 0,
        _ => -1,
    });
    let callbacks = narf_bus::driver_match::__module_callback_invocation_count_for_test(owner);
    let still_driving = nics == 0
        || narf_scheduler::responsive_spin_until(
            || {
                let _ = narf_scheduler::poll_one_round();
                narf_bus::driver_match::__module_callback_invocation_count_for_test(owner)
                    > callbacks
            },
            narf_time::Deadline::after_ms(100),
        );
    if refused != 0 || !still_driving {
        narf_bus::driver_match::__reset_for_test();
        return TestResult::Fail("a refused unload stopped the module driving its device");
    }

    // Unload for real: matches, bindings, contexts and interfaces all go.
    let unloaded = |owner: u64| {
        sys_delete_module("e1000").is_ok()
            && narf_bus::driver_match::__module_thunk_for_test(E1000_VENDOR, E1000_DEV_82540EM)
                .is_none()
            && narf_bus::driver_match::__module_device_context_count_for_test(owner) == 0
            && narf_bus::driver_match::__module_netif_count_for_test(owner) == 0
            && narf_bus::driver_match::__bound_count_for_test(MATCH_NAME) == 0
            && !crate::registry::contains("e1000")
    };
    if !unloaded(owner) {
        narf_bus::driver_match::__reset_for_test();
        return TestResult::Fail("unload left a match, binding, context or interface behind");
    }

    // Reload the same image: it must bind and drive the device again.
    let owner = match bring_up("e1000.ko failed to reload") {
        Ok(owner) => owner,
        Err(why) => {
            narf_bus::driver_match::__reset_for_test();
            return TestResult::Fail(why);
        }
    };
    let clean = unloaded(owner);
    narf_bus::driver_match::__reset_for_test();
    if !clean {
        return TestResult::Fail("the reloaded module did not unload cleanly");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e", e2e_driver_module_unload_and_reload);

/// Copy a staged fixture with `abi` written over its `kernel_abi=` placeholder.
///
/// The large driver fixtures are staged as `NRFCMOD` LZ4 envelopes
/// (`*.ko.lz4`) to keep the resident initramfs small; those are decoded first
/// and the raw ELF is stamped, since the placeholder lives inside the
/// compressed bytes. `None` when an envelope does not decode or the image has
/// no placeholder.
fn stamp_fixture_abi(staged: &[u8], abi: u32) -> Option<Vec<u8>> {
    const PLACEHOLDER: &[u8] = b"kernel_abi=0x00000000";
    let mut image = if crate::compression::is_compressed(staged) {
        crate::compression::decompress(staged).ok()?
    } else {
        staged.to_vec()
    };
    let start = image
        .windows(PLACEHOLDER.len())
        .position(|w| w == PLACEHOLDER)?
        + b"kernel_abi=0x".len();
    image[start..start + 8].copy_from_slice(format!("{abi:08x}").as_bytes());
    Some(image)
}

/// The PCI identity table `intel_gpu.ko` registers from. The module crate
/// includes this same file, so the expected row count follows the table.
#[path = "../../drivers/gpu/src/intel_gpu_pci_ids.rs"]
#[allow(dead_code, unused_imports)]
mod intel_gpu_pci_ids;

fn e2e_intel_gpu_module_registration() -> TestResult {
    use narf_bus::driver_match::{
        __module_device_context_count_for_test, __module_thunk_for_test, count, registered,
    };
    use narf_bus::{BusAddr, BusDevice, BusDeviceCap, BusKind, DeviceId, PcieAddr, ProbeError};
    use narf_capabilities::{Cap, Write};

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("kernel booted without a test initramfs");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/test-fixtures/intel_gpu.ko.lz4")
    else {
        return TestResult::Fail("Intel GPU module fixture absent from staged initramfs");
    };
    fresh_state(0);
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("Intel GPU module has no ABI placeholder");
    };
    let before = count();
    // Exercise a late registration conflict. Failed init must withdraw its
    // earlier rows, leave the other owner in place, and permit a clean retry.
    const OWNER: u64 = u64::MAX - 1;
    extern "C" fn decline(_: u64, _: u64) -> i32 {
        -19
    }
    // SAFETY: the static C callback remains valid until the test removes it.
    if unsafe {
        narf_bus::register_module_pci_driver(
            OWNER,
            "intel-gpu-fixture",
            0x8086,
            0xd74b,
            decline as usize,
        )
    } != 0
    {
        return TestResult::Fail("could not install conflicting Nova Lake PCI match");
    }
    let conflict = sys_init_module(&image);
    let rolled_back = matches!(
        conflict,
        Err(ModuleSyscallError::InitFailed(
            crate::lifecycle::LifecycleError::InitFailed(-16)
        ))
    ) && count() == before + 1
        && __module_thunk_for_test(0x8086, 0xd74b).is_some();
    narf_bus::unregister_module_pci_drivers(OWNER);
    if !rolled_back {
        let _ = sys_delete_module("intel_gpu");
        return TestResult::Fail("failed Intel module init did not roll back on EBUSY");
    }

    let Ok(module) = sys_init_module(&image) else {
        return TestResult::Fail(
            "could not load the Intel GPU module after resolving the conflict",
        );
    };
    let representatives = [
        0x9a49, 0x4c80, 0x46b3, 0x7d55, 0x7d41, 0x6420, 0xb080, 0xfd80, 0xd740, 0x4905, 0x56a0,
        0xe202, 0x56c0, 0x674c, 0x6750, 0xd750, 0xd75f, 0xb0a1, 0xd74a, 0xd74b,
    ];
    let identity_ok =
        module.name() == "intel_gpu" && module.domain == narf_lib::id::DomainId::DRIVER_2;
    let expected_rows = intel_gpu_pci_ids::pci_matches().count();
    let installed_rows = count().saturating_sub(before);
    let ids_ok = representatives
        .iter()
        .all(|&id| __module_thunk_for_test(0x8086, id).is_some())
        && [0xb0a2, 0xd746, 0xd74c, 0xd758, 0x6751, 0xffff]
            .iter()
            .all(|&id| __module_thunk_for_test(0x8086, id).is_none());
    // Exercise the real module callback via the bus trampoline. A declined
    // Meteor Lake probe must let arbitration continue with a fresh cap.
    let addr = PcieAddr::new(0x7f34, 0, 2, 0);
    let device = BusDevice {
        addr: BusAddr::Pcie(addr),
        id: DeviceId {
            vendor: 0x8086,
            device: 0x7d55,
            class: 0x030000,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
        kind: BusKind::Pcie {
            addr,
            // The registration probe declines from its device token alone.
            cfg_phys: narf_memory::PhysAddr::new(0),
        },
    };
    let declined = registered()
        .iter()
        .find(|m| m.name == "intel-gpu-module" && m.kind.matches(&device))
        .is_some_and(|m| {
            let cap = Cap::<BusDeviceCap, Write>::bootstrap();
            matches!((m.probe)(device, cap), Err(ProbeError::NotForThisDriver))
                && cap.check_live().is_err()
                && __module_device_context_count_for_test(module.id.0) == 0
        });
    drop(module);
    if sys_delete_module("intel_gpu").is_err() {
        return TestResult::Fail("could not unload the Intel GPU module");
    }
    if !identity_ok {
        return TestResult::Fail("Intel module name or graphics domain mismatch");
    }
    if installed_rows != expected_rows {
        narf_console::write_str(&format!(
            "intel-gpu: module installed {installed_rows} PCI matches, table has {expected_rows}\n"
        ));
        return TestResult::Fail("Intel module did not register every table row");
    }
    if !ids_ok {
        return TestResult::Fail("Intel module PCI match set differs from the table");
    }
    if !declined {
        return TestResult::Fail("Intel module probe did not decline and release its context");
    }
    if count() != before
        || representatives
            .iter()
            .any(|&id| __module_thunk_for_test(0x8086, id).is_some())
    {
        return TestResult::Fail("Intel module unload left a PCI match");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/intel-gpu", e2e_intel_gpu_module_registration);

/// The real ath11k `.ko` (`narf-drivers-wireless-ath11k --features module`:
/// the whole WCN6855 station driver — MHI, QMI, CE, WMI, DP, MAC and its
/// supplicant — over `narf-module-rt` and the KABI). The compiler's
/// relocations for several MiB of driver, `core`/`alloc` and protocol code
/// resolve and init runs; the module claims exactly the WCN6855 id (not the
/// built-in-only QCA6390 / QCN9074), declares the autoconnect parameters and
/// takes a load argument, refuses a probe with no device context before any
/// device access, and unloads leaving no match behind. QEMU has no WCN6855,
/// so bring-up itself is proven on hardware.
fn e2e_ath11k_module_registration() -> TestResult {
    use narf_bus::driver_match::{__module_thunk_for_test, count};
    const QCOM: u16 = 0x17cb;
    const WCN6855: u16 = 0x1103;

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("kernel booted without a test initramfs");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/test-fixtures/ath11k.ko.lz4")
    else {
        return TestResult::Fail("ath11k module fixture absent from staged initramfs");
    };
    fresh_state(0);
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("ath11k module has no ABI placeholder");
    };
    let before = count();
    let module = match sys_init_module_with_params(&image, "ssid=narf-e2e") {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("ath11k.ko failed to load or run init"),
    };
    let live = *module.state.lock() == crate::lifecycle::ModuleState::Live;
    let declared = ["ssid", "psk", "passphrase", "scan"]
        .iter()
        .all(|name| crate::params::find(&module.params, name).is_some());
    let applied = crate::params::find(&module.params, "ssid")
        .is_some_and(|s| s.read() == "narf-e2e")
        && crate::params::find(&module.params, "passphrase").is_some_and(|s| s.read().is_empty());
    let claims = module.name() == "ath11k"
        && count() == before + 1
        && __module_thunk_for_test(QCOM, WCN6855).is_some()
        && __module_thunk_for_test(QCOM, 0x1101).is_none()
        && __module_thunk_for_test(QCOM, 0x1104).is_none();
    // A bogus token (no device context): the identity read fails first.
    let refused = __module_thunk_for_test(QCOM, WCN6855).is_some_and(|thunk| thunk(0, 0) != 0);
    drop(module);
    if sys_delete_module("ath11k").is_err() {
        return TestResult::Fail("could not unload ath11k.ko");
    }
    if !live || !declared || !applied {
        return TestResult::Fail("ath11k.ko not Live, or its parameters missing or not applied");
    }
    if !claims {
        return TestResult::Fail("ath11k.ko did not claim exactly the WCN6855 PCI id");
    }
    if !refused {
        return TestResult::Fail("ath11k.ko probe accepted a token with no device context");
    }
    if count() != before || __module_thunk_for_test(QCOM, WCN6855).is_some() {
        return TestResult::Fail("ath11k.ko unload left a PCI match");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/ath11k", e2e_ath11k_module_registration);

// ── mt76.ko ────────────────────────────────────────────────────────────

/// The real mt76 `.ko` (`narf-drivers-wireless-mt76 --features module`: the
/// MT7921/MT7922 driver — PCI binding, WFDMA rings, MCU, firmware download,
/// the station join with its supplicant and the packet path — over
/// `narf-module-rt` and the KABI). Its relocations resolve and init runs to
/// Live; the `debug` parameter is declared and a load argument applies; it
/// claims exactly the eight PCI ids the built-in table names (MT7925 and
/// its 0717 alias included; the chip-id gate still refuses MT7925 silicon,
/// as built in); a probe with no device context is refused before any
/// device access; unload leaves no match behind. QEMU emulates no MediaTek Wi-Fi,
/// so bring-up itself is proven on hardware.
fn e2e_mt76_module_registration() -> TestResult {
    use narf_bus::driver_match::{__module_thunk_for_test, count};
    const MTK: u16 = 0x14c3;
    const ITTIM: u16 = 0x0e8d;
    const IDS: [(u16, u16); 8] = [
        (MTK, 0x7961),
        (MTK, 0x7922),
        (MTK, 0x0608),
        (MTK, 0x0616),
        (MTK, 0x7920),
        (MTK, 0x7925),
        (MTK, 0x0717),
        (ITTIM, 0x7922),
    ];

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("kernel booted without a test initramfs");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/test-fixtures/mt76.ko.lz4")
    else {
        return TestResult::Fail("mt76 module fixture absent from staged initramfs");
    };
    fresh_state(0);
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("mt76 module has no ABI placeholder");
    };
    let before = count();
    let module = match sys_init_module_with_params(&image, "debug=1") {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("mt76.ko failed to load or run init"),
    };
    let live = *module.state.lock() == crate::lifecycle::ModuleState::Live;
    let applied = crate::params::find(&module.params, "debug").is_some_and(|s| s.read() == "1");
    let claims = module.name() == "mt76"
        && count() == before + IDS.len()
        && IDS
            .iter()
            .all(|&(vendor, device)| __module_thunk_for_test(vendor, device).is_some())
        // The ITTIM vendor id only carries the MT7922 SKU.
        && __module_thunk_for_test(ITTIM, 0x7925).is_none();
    // A bogus token (no device context): the identity read fails first.
    let refused = __module_thunk_for_test(MTK, 0x7922).is_some_and(|thunk| thunk(0, 0) != 0);
    drop(module);
    if sys_delete_module("mt76").is_err() {
        return TestResult::Fail("could not unload mt76.ko");
    }
    if !live || !applied {
        return TestResult::Fail("mt76.ko not Live, or its debug parameter missing or not applied");
    }
    if !claims {
        return TestResult::Fail("mt76.ko did not claim exactly the CONNAC2 PCI ids");
    }
    if !refused {
        return TestResult::Fail("mt76.ko probe accepted a token with no device context");
    }
    if count() != before
        || IDS
            .iter()
            .any(|&(vendor, device)| __module_thunk_for_test(vendor, device).is_some())
    {
        return TestResult::Fail("mt76.ko unload left a PCI match");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/mt76", e2e_mt76_module_registration);

/// The real ath10k `.ko` (`narf-drivers-wireless-ath10k --features module`:
/// the whole PCIe driver — BMI, firmware/board/OTP download, CE, HTC, WMI,
/// HTT and the station radio with its in-driver supplicant — over
/// `narf-module-rt` and the shared KABI, including `narf_pci_command`,
/// `narf_pcie_state` and `narf_wireless_regdomain`). Its relocations
/// resolve and init runs; it claims
/// every ath10k PCIe id the built-in driver binds and not AR9462 (ath9k's),
/// refuses a probe with no device context before any device access, and
/// unloads leaving no match behind. QEMU has no Atheros Wi-Fi, so bring-up
/// itself is proven on hardware.
fn e2e_ath10k_module_registration() -> TestResult {
    use narf_bus::driver_match::{__module_thunk_for_test, count};
    const ATHEROS: u16 = 0x168c;
    const CLAIMED: [(u16, u16); 9] = [
        (ATHEROS, 0x003c), // QCA988X
        (0x0777, 0x11ac),  // QCA988X (Ubiquiti)
        (ATHEROS, 0x0050), // QCA9887
        (ATHEROS, 0x003e), // QCA6174
        (ATHEROS, 0x0041), // QCA6164
        (ATHEROS, 0x0040), // QCA99X0
        (ATHEROS, 0x0056), // QCA9888
        (ATHEROS, 0x0046), // QCA9984
        (ATHEROS, 0x0042), // QCA9377
    ];
    const AR9462: u16 = 0x0034;

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("kernel booted without a test initramfs");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/test-fixtures/ath10k.ko.lz4")
    else {
        return TestResult::Fail("ath10k module fixture absent from staged initramfs");
    };
    fresh_state(0);
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("ath10k module has no ABI placeholder");
    };
    let before = count();
    let module = match sys_init_module(&image) {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("ath10k.ko failed to load or run init"),
    };
    let live = *module.state.lock() == crate::lifecycle::ModuleState::Live;
    let claims = module.name() == "ath10k"
        && count() == before + CLAIMED.len()
        && CLAIMED
            .iter()
            .all(|&(vendor, device)| __module_thunk_for_test(vendor, device).is_some())
        && __module_thunk_for_test(ATHEROS, AR9462).is_none();
    // A bogus token (no device context): the identity read fails first.
    let (vendor, device) = CLAIMED[0];
    let refused = __module_thunk_for_test(vendor, device).is_some_and(|thunk| thunk(0, 0) != 0);
    drop(module);
    if sys_delete_module("ath10k").is_err() {
        return TestResult::Fail("could not unload ath10k.ko");
    }
    if !live {
        return TestResult::Fail("ath10k.ko did not reach Live");
    }
    if !claims {
        return TestResult::Fail("ath10k.ko did not claim exactly the ath10k PCIe ids");
    }
    if !refused {
        return TestResult::Fail("ath10k.ko probe accepted a token with no device context");
    }
    if count() != before
        || CLAIMED
            .iter()
            .any(|&(vendor, device)| __module_thunk_for_test(vendor, device).is_some())
    {
        return TestResult::Fail("ath10k.ko unload left a PCI match");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/ath10k", e2e_ath10k_module_registration);

/// The real ath9k `.ko` (`narf-drivers-wireless-ath9k --features module`:
/// every chip owner — AR5008, AR9280, AR9285, AR9287 and the AR9300 family:
/// identity/EEPROM, board admission, INI/PLL/RF, calibration, MAC, packet
/// DMA and the station with its WPA2 supplicant — over `narf-module-rt` and
/// the KABI, including the softMAC exports `narf_pci_command`,
/// `narf_pcie_state`, `narf_pci_config_read32` and
/// `narf_wireless_regdomain`). The relocations resolve and init runs; the
/// module claims exactly the built-in driver's fifteen Atheros ids, under
/// its own match name `ath9k-module`, and none
/// of ath10k's; a probe with no device context is refused before any
/// device access; and unload (whose exit runs the owners' removal with
/// nothing bound) leaves no match behind. QEMU has no Atheros Wi-Fi, so
/// bring-up itself is proven on hardware.
fn e2e_ath9k_module_registration() -> TestResult {
    use narf_bus::driver_match::{__module_thunk_for_test, count, registered};
    const ATHEROS: u16 = 0x168c;
    /// AR5416/AR5418/AR9160, AR9280 PCI/PCIe, AR9285, AR2427, AR9287
    /// PCI/PCIe, AR9380, AR9485, AR9580, AR9462, AR9565, AR9462/AR1111.
    const CLAIMED: [u16; 15] = [
        0x0023, 0x0024, 0x0027, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x0030, 0x0032,
        0x0033, 0x0034, 0x0036, 0x0037,
    ];
    /// QCA988X and QCA9887: ath10k's, never ath9k's.
    const BUILT_IN: [u16; 2] = [0x003c, 0x0050];

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("kernel booted without a test initramfs");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/test-fixtures/ath9k.ko.lz4")
    else {
        return TestResult::Fail("ath9k module fixture absent from staged initramfs");
    };
    fresh_state(0);
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("ath9k module has no ABI placeholder");
    };
    let before = count();
    let module = match sys_init_module(&image) {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("ath9k.ko failed to load or run init"),
    };
    let live = *module.state.lock() == crate::lifecycle::ModuleState::Live;
    // Under its own match name: a built-in per-chip name would replace the
    // built-in entry instead of adding one (whether the built-in driver has
    // registered by now depends on the tests that ran before this one).
    let own_matches = registered()
        .iter()
        .filter(|m| m.name == "ath9k-module")
        .count();
    let claims = module.name() == "ath9k"
        && own_matches == CLAIMED.len()
        && count() == before + CLAIMED.len()
        && CLAIMED
            .iter()
            .all(|&id| __module_thunk_for_test(ATHEROS, id).is_some())
        && BUILT_IN
            .iter()
            .all(|&id| __module_thunk_for_test(ATHEROS, id).is_none());
    // A bogus token (no device context): the identity read fails first.
    let refused = CLAIMED
        .iter()
        .all(|&id| __module_thunk_for_test(ATHEROS, id).is_some_and(|thunk| thunk(0, 0) != 0));
    drop(module);
    if sys_delete_module("ath9k").is_err() {
        return TestResult::Fail("could not unload ath9k.ko");
    }
    if !live {
        return TestResult::Fail("ath9k.ko not Live after init");
    }
    if !claims {
        return TestResult::Fail("ath9k.ko did not claim exactly the built-in ath9k PCI ids");
    }
    if !refused {
        return TestResult::Fail("ath9k.ko probe accepted a token with no device context");
    }
    if count() != before
        || CLAIMED
            .iter()
            .any(|&id| __module_thunk_for_test(ATHEROS, id).is_some())
    {
        return TestResult::Fail("ath9k.ko unload left a PCI match");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/ath9k", e2e_ath9k_module_registration);

/// The real brcmfmac `.ko` (`narf-drivers-wireless-brcm --features module`,
/// module name `brcm`: the brcmfmac chip discovery, CR4/CA7 firmware
/// download, msgbuf common rings and the shared FullMAC station over
/// `narf-module-rt` and the KABI, including `narf_pci_config_write32` and
/// `narf_wireless_regdomain`). The relocations resolve and init runs; the
/// module declares the autoconnect parameters and takes a load argument; it
/// takes its regulatory domain from the kernel (it imports
/// `narf_wireless_regdomain` and names no `wireless-regulatory.bin` of its
/// own); it claims every Broadcom FullMAC PCIe id of the built-in table
/// under its own match name (so the built-in entries survive), refuses a
/// probe with no device context before any device access, and unloads
/// leaving no match behind. QEMU has no Broadcom Wi-Fi, so bring-up itself
/// is proven on hardware.
fn e2e_brcmfmac_module_registration() -> TestResult {
    use narf_bus::driver_match::{__module_thunk_for_test, count};
    const BROADCOM: u16 = 0x14e4;
    // `brcmfmac::pcie_ids::ALL_DEV_IDS` (Linux `brcmf_pcie_devid_table`).
    const IDS: [u16; 26] = [
        0x43A3, 0x43DF, 0x4354, 0x43DC, 0x43EC, 0x43D3, 0x43D9, 0xAA31, 0x43E9, 0x43EF, 0x43BA,
        0x43BB, 0x43BC, 0x4464, 0x43CA, 0x43CB, 0x43CC, 0x43C3, 0x43C4, 0x43C5, 0x440D, 0x4415,
        0x449D, 0x4488, 0x4425, 0x4433,
    ];

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("kernel booted without a test initramfs");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/test-fixtures/brcmfmac.ko.lz4")
    else {
        return TestResult::Fail("brcmfmac module fixture absent from staged initramfs");
    };
    fresh_state(0);
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("brcmfmac module has no ABI placeholder");
    };
    // The regulatory domain is the kernel's: the import is in the symbol
    // table (and must resolve for init to run), the signed policy file is
    // not opened by name. Searched in the decompressed image: the staged
    // fixture is LZ4.
    let names = |needle: &[u8]| image.windows(needle.len()).any(|w| w == needle);
    if !names(b"narf_wireless_regdomain\0") || names(b"wireless-regulatory.bin") {
        return TestResult::Fail(
            "brcmfmac.ko does not take its regulatory domain from narf_wireless_regdomain",
        );
    }
    let before = count();
    let module = match sys_init_module_with_params(&image, "ssid=narf-e2e") {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("brcmfmac.ko failed to load or run init"),
    };
    let live = *module.state.lock() == crate::lifecycle::ModuleState::Live;
    let declared = ["ssid", "psk", "passphrase"]
        .iter()
        .all(|name| crate::params::find(&module.params, name).is_some());
    let applied = crate::params::find(&module.params, "ssid")
        .is_some_and(|s| s.read() == "narf-e2e")
        && crate::params::find(&module.params, "passphrase").is_some_and(|s| s.read().is_empty());
    let claims = module.name() == "brcm"
        && count() == before + IDS.len()
        && IDS
            .iter()
            .all(|&id| __module_thunk_for_test(BROADCOM, id).is_some())
        // Not a Broadcom FullMAC PCIe id: the SoftMAC BCM4313.
        && __module_thunk_for_test(BROADCOM, 0x4727).is_none();
    // A bogus token (no device context): the identity read fails first.
    let refused = __module_thunk_for_test(BROADCOM, 0x43BA).is_some_and(|thunk| thunk(0, 0) != 0);
    drop(module);
    if sys_delete_module("brcm").is_err() {
        return TestResult::Fail("could not unload brcmfmac.ko");
    }
    if !live || !declared || !applied {
        return TestResult::Fail("brcmfmac.ko not Live, or its parameters missing or not applied");
    }
    if !claims {
        return TestResult::Fail("brcmfmac.ko did not claim exactly the FullMAC PCIe id table");
    }
    if !refused {
        return TestResult::Fail("brcmfmac.ko probe accepted a token with no device context");
    }
    if count() != before
        || IDS
            .iter()
            .any(|&id| __module_thunk_for_test(BROADCOM, id).is_some())
    {
        return TestResult::Fail("brcmfmac.ko unload left a PCI match");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/brcmfmac", e2e_brcmfmac_module_registration);

/// The real rtw `.ko` (`narf-drivers-wireless-rtw --features module`: the
/// rtw88 driver source — USB transport, firmware, MAC/PHY/RF, calibration,
/// the station shell and its in-driver SME — over `narf-module-rt`, the
/// kernel-free protocol crates and the KABI). Relocations resolve and init
/// runs; the station parameters are declared and a load argument applies;
/// the module claims the RTL8821CU / RTL8822BU USB ids on their
/// vendor-specific interface (and not a Realtek id rtw88 does not drive, nor
/// the same id on another interface class), keeps the rtw88 / rtw89 PCIe
/// ids registration-only; a USB probe with no device context is refused
/// before any device access; unload leaves no USB or PCI match behind. QEMU
/// has no Realtek Wi-Fi device, so bring-up itself is proven on hardware.
fn e2e_rtw88_module_registration() -> TestResult {
    use narf_bus::driver_match::{__module_thunk_for_test, count};
    use narf_drivers_usb::class_registry::{__module_probe_for_test, module_match_count};
    const REALTEK: u16 = 0x10ec;
    /// RTL8821CU (0bda:c811), RTL8822BU (0bda:b812), and RTL8188EU
    /// (0bda:8179, rtl8xxxu's) — the last is not rtw88's.
    const RTL8821CU: (u16, u16) = (0x0bda, 0xc811);
    const RTL8822BU: (u16, u16) = (0x0bda, 0xb812);
    const RTL8188EU: (u16, u16) = (0x0bda, 0x8179);
    /// The id tables' entry counts (`rtw88::usb::RTL8821CU_IDS`,
    /// `RTL8822BU_IDS`).
    const USB_IDS: usize = 15 + 35;
    /// A configuration descriptor with one interface of class
    /// `class`/`class`/`class`.
    fn config(class: u8) -> [u8; 18] {
        [
            9, 2, 18, 0, 1, 1, 0, 0x80, 50, // configuration
            9, 4, 0, 0, 0, class, class, class, 0, // interface 0
        ]
    }

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("kernel booted without a test initramfs");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/test-fixtures/rtw88.ko.lz4")
    else {
        return TestResult::Fail("rtw88 module fixture absent from staged initramfs");
    };
    fresh_state(0);
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("rtw88 module has no ABI placeholder");
    };
    let (pci_before, usb_before) = (count(), module_match_count());
    let module = match sys_init_module_with_params(&image, "ssid=narf-e2e") {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("rtw88.ko failed to load or run init"),
    };
    let live = *module.state.lock() == crate::lifecycle::ModuleState::Live;
    let declared = ["ssid", "psk", "passphrase", "scan"]
        .iter()
        .all(|name| crate::params::find(&module.params, name).is_some());
    let applied = crate::params::find(&module.params, "ssid")
        .is_some_and(|s| s.read() == "narf-e2e")
        && crate::params::find(&module.params, "psk").is_some_and(|s| s.read().is_empty());
    let vendor = config(0xff);
    let probe_8821cu = __module_probe_for_test(RTL8821CU.0, RTL8821CU.1, &vendor);
    let usb_claims = module.name() == "rtw"
        && module_match_count() == usb_before + USB_IDS
        && probe_8821cu.is_some_and(|(name, _)| name == "rtw8821cu")
        && __module_probe_for_test(RTL8822BU.0, RTL8822BU.1, &vendor)
            .is_some_and(|(name, _)| name == "rtw8822bu")
        && __module_probe_for_test(RTL8188EU.0, RTL8188EU.1, &vendor).is_none()
        && __module_probe_for_test(RTL8821CU.0, RTL8821CU.1, &config(0x08)).is_none();
    let pci_claims = count() > pci_before
        && __module_thunk_for_test(REALTEK, 0xc821).is_some()
        && __module_thunk_for_test(REALTEK, 0x8852).is_some();
    // A bogus token (no USB context): the configuration read fails first.
    let refused = probe_8821cu.is_some_and(|(_, probe)| probe(0, 0) != 0);
    drop(module);
    if sys_delete_module("rtw").is_err() {
        return TestResult::Fail("could not unload rtw88.ko");
    }
    if !live || !declared || !applied {
        return TestResult::Fail("rtw88.ko not Live, or its parameters missing or not applied");
    }
    if !usb_claims {
        return TestResult::Fail("rtw88.ko did not claim exactly the RTL8821CU/RTL8822BU USB ids");
    }
    if !pci_claims {
        return TestResult::Fail("rtw88.ko did not register the rtw88/rtw89 PCIe ids");
    }
    if !refused {
        return TestResult::Fail("rtw88.ko probe accepted a token with no USB context");
    }
    if module_match_count() != usb_before
        || count() != pci_before
        || __module_probe_for_test(RTL8821CU.0, RTL8821CU.1, &vendor).is_some()
    {
        return TestResult::Fail("rtw88.ko unload left a USB or PCI match");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/rtw88", e2e_rtw88_module_registration);

// ── rtl.ko (legacy Realtek rtlwifi PCIe + rtl8xxxu USB) ───────────────

/// The id tables `rtl.ko` registers from. The module crate uses this same
/// file, so the expected rows follow the table.
#[path = "../../drivers/wireless/rtl/src/module_ids.rs"]
#[allow(dead_code)]
mod rtl_module_ids;

/// A USB probe that must never run: the test registers it under a foreign
/// owner only to observe which USB matches `rtl.ko` holds (`-EBUSY`).
extern "C" fn rtl_e2e_foreign_usb_probe(_dev: u64, _reserved: u64) -> i32 {
    -19
}

/// An owner id no loaded module has.
const RTL_E2E_FOREIGN_OWNER: u64 = u64::MAX - 0x7274_6c00;

/// Register `(vid, pid)` under [`RTL_E2E_FOREIGN_OWNER`]: `-EBUSY` while
/// another module holds the match, `-ENODEV` with no USB stack, 0 (then
/// withdrawn again) when the match is free.
fn rtl_e2e_foreign_usb_claim(vid: u16, pid: u16) -> i32 {
    use narf_bus::module_usb::{
        register_module_usb_driver, unregister_module_usb_drivers, ModuleUsbMatch,
        MATCH_VENDOR_PRODUCT,
    };
    let Ok(m) = ModuleUsbMatch::from_flags(MATCH_VENDOR_PRODUCT, vid, pid, 0, 0, 0) else {
        return -22;
    };
    // SAFETY: the probe is kernel text that stays mapped; the match is
    // withdrawn below before this function returns.
    let rc = unsafe {
        register_module_usb_driver(
            RTL_E2E_FOREIGN_OWNER,
            "rtl-e2e-foreign",
            m,
            rtl_e2e_foreign_usb_probe as usize,
        )
    };
    unregister_module_usb_drivers(RTL_E2E_FOREIGN_OWNER);
    rc
}

/// The real `rtl.ko` (`narf-drivers-wireless-rtl --features module`: the
/// whole rtlwifi PCIe driver — identification, firmware, native preparation
/// and the station with its `wlan%d`/wiphy — plus rtl8xxxu, over
/// `narf-module-rt` and the KABI). Relocations for ~6.8 MB of driver,
/// `core`/`alloc` and protocol code resolve and
/// init runs to Live; the module claims exactly the rtlwifi PCI table (not
/// rtw88's RTL8822BE) and, where the kernel has a USB stack, every rtl8xxxu
/// VID/PID (not rtw88's RTL8821CU); a probe with no device context is
/// refused before any device access; unload leaves no match. QEMU emulates
/// no Realtek Wi-Fi device, so bring-up itself is proven on hardware.
fn e2e_rtl_module_registration() -> TestResult {
    use narf_bus::driver_match::{__module_thunk_for_test, count};
    use rtl_module_ids::{PCI_DEVICES, PCI_VENDOR, USB_IDS};

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("kernel booted without a test initramfs");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/test-fixtures/rtl.ko.lz4")
    else {
        return TestResult::Fail("rtl module fixture absent from staged initramfs");
    };
    fresh_state(0);
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("rtl module has no ABI placeholder");
    };
    let before = count();
    // The match a foreign owner can take before load decides whether this
    // kernel has a USB stack to check against.
    let usb_stack = rtl_e2e_foreign_usb_claim(USB_IDS[0].0, USB_IDS[0].1) != -19;
    let module = match sys_init_module_with_params(&image, "ssid=narf-e2e") {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("rtl.ko failed to load or run init"),
    };
    let live = *module.state.lock() == crate::lifecycle::ModuleState::Live;
    // The USB station's parameter-driven SME.
    let params = ["ssid", "psk", "passphrase"]
        .iter()
        .all(|name| crate::params::find(&module.params, name).is_some())
        && crate::params::find(&module.params, "ssid").is_some_and(|s| s.read() == "narf-e2e")
        && crate::params::find(&module.params, "psk").is_some_and(|s| s.read().is_empty());
    let installed = count().saturating_sub(before);
    let pci_claims = module.name() == "rtl"
        && installed == PCI_DEVICES.len()
        && PCI_DEVICES
            .iter()
            .all(|&did| __module_thunk_for_test(PCI_VENDOR, did).is_some())
        // RTL8822BE belongs to rtw88.
        && __module_thunk_for_test(PCI_VENDOR, 0xB822).is_none();
    // A bogus token (no device context): the identity read fails first.
    let refused = PCI_DEVICES
        .iter()
        .filter_map(|&did| __module_thunk_for_test(PCI_VENDOR, did))
        .all(|thunk| thunk(0, 0) != 0);
    let usb_claims = !usb_stack
        || (USB_IDS
            .iter()
            .all(|&(vid, pid)| rtl_e2e_foreign_usb_claim(vid, pid) == -16)
            // RTL8821CU belongs to rtw88.
            && rtl_e2e_foreign_usb_claim(0x0BDA, 0xC811) == 0);
    drop(module);
    if sys_delete_module("rtl").is_err() {
        return TestResult::Fail("could not unload rtl.ko");
    }
    if !live {
        return TestResult::Fail("rtl.ko not Live after init");
    }
    if !params {
        return TestResult::Fail("rtl.ko parameters missing or the load argument not applied");
    }
    if !pci_claims {
        narf_console::write_str(&format!(
            "rtl: module installed {installed} PCI matches, table has {}\n",
            PCI_DEVICES.len()
        ));
        return TestResult::Fail("rtl.ko did not claim exactly the rtlwifi PCI table");
    }
    if !refused {
        return TestResult::Fail("rtl.ko probe accepted a token with no device context");
    }
    if !usb_claims {
        return TestResult::Fail("rtl.ko did not hold exactly the rtl8xxxu USB table");
    }
    if count() != before
        || PCI_DEVICES
            .iter()
            .any(|&did| __module_thunk_for_test(PCI_VENDOR, did).is_some())
    {
        return TestResult::Fail("rtl.ko unload left a PCI match");
    }
    if usb_stack
        && USB_IDS
            .iter()
            .any(|&(vid, pid)| rtl_e2e_foreign_usb_claim(vid, pid) != 0)
    {
        return TestResult::Fail("rtl.ko unload left a USB match");
    }
    if !usb_stack {
        narf_console::write_str("rtl: no USB stack in this kernel; USB claims not checked\n");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/rtl", e2e_rtl_module_registration);

// ── iwlwifi.ko ──────────────────────────────────────────────────────────

/// The real iwlwifi `.ko` (`narf-drivers-wireless-iwlwifi --features
/// module`: the driver's PCIe transport, firmware loader, MLD station path and
/// in-driver supplicant over `narf-module-rt` and the KABI). The relocations
/// for the driver, `core`/`alloc` and the protocol crates resolve and init
/// runs; the module claims exactly the 28 ids of the built-in table (Gen2
/// Qu/QuZ/CC and Gen3 Ty, So, Ma, Bz and Sc) and no other Intel id; a probe
/// with no device context is refused before any device access; and unload
/// leaves no match. QEMU has no Intel Wi-Fi device, so bring-up itself is
/// proven on hardware.
fn e2e_iwlwifi_module_registration() -> TestResult {
    use narf_bus::driver_match::{__module_thunk_for_test, count};
    const INTEL: u16 = 0x8086;
    const CLAIMED: [u16; 28] = [
        0x2723, 0x02f0, 0x06f0, 0x34f0, 0x3df0, 0x4df0, 0x43f0, 0xa0f0, 0x7df0, 0x2725, 0x51f0,
        0x51f1, 0x54f0, 0x7a70, 0x7af0, 0x7f70, 0x2729, 0x7e40, 0x272b, 0x7740, 0x4d40, 0xa840,
        0x6e70, 0x9327, 0xd240, 0xd340, 0xe340, 0xe440,
    ];
    // Intel Wi-Fi ids the built-in table does not match either (9260, 9560,
    // AX101): nothing claims them.
    const UNCLAIMED: [u16; 3] = [0x2526, 0x9df0, 0xa0f1];

    let Some(initramfs) = narf_initramfs::staged() else {
        return TestResult::Skip("kernel booted without a test initramfs");
    };
    let Some((_, staged)) = initramfs
        .iter_files()
        .find(|(name, _)| *name == "lib/modules/test-fixtures/iwlwifi.ko.lz4")
    else {
        return TestResult::Fail("iwlwifi module fixture absent from staged initramfs");
    };
    fresh_state(0);
    let abi = crate::symbols::compute_abi_hash();
    crate::symbols::set_kernel_abi(abi);
    let Some(image) = stamp_fixture_abi(staged, abi) else {
        return TestResult::Fail("iwlwifi module has no ABI placeholder");
    };
    let before = count();
    let module = match sys_init_module_with_params(&image, "") {
        Ok(module) => module,
        Err(_) => return TestResult::Fail("iwlwifi.ko failed to load or run init"),
    };
    let live = *module.state.lock() == crate::lifecycle::ModuleState::Live;
    let claims = module.name() == "iwlwifi"
        && count() == before + CLAIMED.len()
        && CLAIMED
            .iter()
            .all(|&did| __module_thunk_for_test(INTEL, did).is_some())
        && UNCLAIMED
            .iter()
            .all(|&did| __module_thunk_for_test(INTEL, did).is_none());
    // A bogus token (no device context): the identity read fails first.
    let refused = CLAIMED
        .iter()
        .all(|&did| __module_thunk_for_test(INTEL, did).is_some_and(|thunk| thunk(0, 0) != 0));
    drop(module);
    if sys_delete_module("iwlwifi").is_err() {
        return TestResult::Fail("could not unload iwlwifi.ko");
    }
    if !live {
        return TestResult::Fail("iwlwifi.ko did not reach Live");
    }
    if !claims {
        return TestResult::Fail("iwlwifi.ko did not claim exactly the built-in table's PCI ids");
    }
    if !refused {
        return TestResult::Fail("iwlwifi.ko probe accepted a token with no device context");
    }
    if count() != before
        || CLAIMED
            .iter()
            .any(|&did| __module_thunk_for_test(INTEL, did).is_some())
    {
        return TestResult::Fail("iwlwifi.ko unload left a PCI match");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/iwlwifi", e2e_iwlwifi_module_registration);

// ── Helper kept around so the test harness sees a use of `String`
// even on toolchains that elide unused imports during macro expansion.
#[allow(dead_code)]
fn _force_imports() -> String {
    "ok".to_string()
}

// The physical packet paths are exercised by the driver crates' host KABI
// models. QEMU does not emulate these NICs: this test instead loads the actual
// ET_REL artifacts, resolves their imports, invokes probe rejection and unloads.
fn e2e_wired_module_images() -> TestResult {
    use narf_bus::driver_match::{__module_thunk_for_test, count};
    for (name, vendor, ids) in [
        ("realtek", 0x10ec, [0x8125, 0x3000]),
        ("mlx4", 0x15b3, [0x1003, 0x1007]),
    ] {
        let Some(initramfs) = narf_initramfs::staged() else {
            return TestResult::Fail("wired module initramfs missing");
        };
        let path = format!("lib/modules/test-fixtures/{name}.ko.lz4");
        let Some((_, staged)) = initramfs.iter_files().find(|(p, _)| *p == path) else {
            return TestResult::Fail("wired module fixture missing");
        };
        fresh_state(0);
        let abi = crate::symbols::compute_abi_hash();
        crate::symbols::set_kernel_abi(abi);
        let Some(image) = stamp_fixture_abi(staged, abi) else {
            return TestResult::Fail("wired module ABI stamp missing");
        };
        let before = count();
        let Ok(module) = sys_init_module_with_params(&image, "domain=driver2") else {
            return TestResult::Fail("wired module relocation or init failed");
        };
        let live =
            module.name() == name && *module.state.lock() == crate::lifecycle::ModuleState::Live;
        let claims = count() == before + 2
            && ids.iter().all(|&id| {
                __module_thunk_for_test(vendor, id).is_some_and(|probe| probe(0, 0) == -19)
            });
        drop(module);
        if sys_delete_module(name).is_err() {
            return TestResult::Fail("wired module unload failed");
        }
        if !live || !claims || count() != before {
            return TestResult::Fail("wired module identity, probes or cleanup failed");
        }
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e/wired", e2e_wired_module_images);

fn e2e_module_carrier_ownership() -> TestResult {
    use narf_bus::driver_match::*;
    const OWNER: u64 = 0xffff_fff0;
    const TOKEN: u64 = 0xffff_fff1;
    let Some((name, index)) = __install_module_netif_for_test(OWNER, TOKEN, [2, 4, 6, 8, 10, 12])
    else {
        return TestResult::Fail("carrier fixture unavailable");
    };
    let results = [
        module_netif_set_link(OWNER + 1, TOKEN, index, true) == -19,
        module_netif_set_link(OWNER, TOKEN, index + 1, true) == -22,
        module_netif_set_link(OWNER, TOKEN, index, true) == 0,
        module_netif_set_link(OWNER, TOKEN, index, false) == 0,
    ];
    let _ = name;
    __remove_module_device_for_test(TOKEN);
    if results.iter().all(|&ok| ok) {
        TestResult::Pass
    } else {
        TestResult::Fail("carrier update did not enforce device/interface owner")
    }
}
kernel_test_in!("modules/e2e/wired", e2e_module_carrier_ownership);
