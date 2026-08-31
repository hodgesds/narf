//! Loading a REAL, rustc-built `.ko`.
//!
//! Every other module test synthesizes its ELF in memory. That exercises the
//! loader's parsing, layout and lifecycle, but never the compiler's actual
//! relocation output — and the two can disagree. They already did once: rustc
//! emits one `.modinfo` section per `#[link_section]` static (seven for the
//! reference module), and a loader that read only the first saw a manifest
//! consisting of `name=` alone. No synthesized-ELF test could have caught it,
//! because every one of them writes a single hand-built `.modinfo`.
//!
//! `cargo xtask image` stages `modules/test-module` into the initramfs at
//! `/lib/modules/narf_test_module.ko`. This is what a module's whole life
//! looks like end to end:
//!
//!   * a genuine undefined symbol (`narf_printk`) resolved through KSYMTAB,
//!     reached by `R_X86_64_PLT32` on x86_64 and by `R_AARCH64_CALL26` on
//!     aarch64 — which is out of range and needs a PLT veneer;
//!   * the image mapped, relocated, sealed W^X, and *executed* when
//!     `narf_module_init` runs;
//!   * unload running `exit` and releasing the image — checked by loading it
//!     a second time, which needs the VA and frames back.
//!
//! Skips rather than fails when the file is absent: the module is a test
//! fixture, and a build without it should not turn this red.

use super::*;

/// Read the staged `.ko` out of the initramfs, or `None` if it was not built
/// into this image.
fn read_test_module() -> Option<alloc::vec::Vec<u8>> {
    crate::process::read_path_from_vfs("/lib/modules/narf_test_module.ko")
}

/// Stamp the running kernel's ABI hash into a module image's `.modinfo`.
///
/// A module's `kernel_abi=` has to match the kernel it loads into, and that
/// hash is derived from the kernel's export table at runtime — so it is not
/// knowable when the module is compiled. `cargo xtask build-module` takes a
/// `--kernel-abi` for exactly this, but a value baked in at image-build time
/// would have to come from a kernel booted earlier, which makes a test run a
/// two-phase build.
///
/// Patching the in-memory copy here asks the same question without that: the
/// field is fixed-width hex, so this is an eight-byte overwrite that moves no
/// offsets. What is under test is the loader — relocation, mapping, symbol
/// resolution, execution — and the ABI-hash mechanism itself has its own
/// smokes (`modules/kabi`).
fn stamp_abi(image: &mut [u8], hash: u32) -> bool {
    const KEY: &[u8] = b"kernel_abi=0x";
    let Some(at) = image
        .windows(KEY.len())
        .position(|w| w == KEY)
        .map(|p| p + KEY.len())
    else {
        return false;
    };
    if at + 8 > image.len() {
        return false;
    }
    // `{:08x}` — the same form the manifest parser reads.
    let mut buf = [0u8; 8];
    for (i, b) in buf.iter_mut().enumerate() {
        let nibble = (hash >> (28 - i * 4)) & 0xF;
        *b = match nibble {
            0..=9 => b'0' + nibble as u8,
            _ => b'a' + (nibble as u8 - 10),
        };
    }
    image[at..at + 8].copy_from_slice(&buf);
    true
}

/// The end-to-end case: load a real `.ko`, confirm it ran, then unload it.
fn smoke_module_load_real_ko_round_trip() -> TestResult {
    let Some(mut image) = read_test_module() else {
        return TestResult::Skip(
            "/lib/modules/narf_test_module.ko absent — image built without the test module",
        );
    };
    if image.len() < 64 {
        return TestResult::Fail("staged .ko is too small to be an ELF");
    }
    if !stamp_abi(&mut image, narf_modules::symbols::kernel_abi()) {
        return TestResult::Fail("staged .ko has no kernel_abi= field to stamp");
    }

    // A previous run of this smoke may have left the module registered.
    let _ = narf_modules::syscalls::sys_delete_module("test_module");

    let module = match narf_modules::syscalls::sys_init_module(&image) {
        Ok(m) => m,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("sys_init_module rejected a real rustc-built .ko");
        }
    };

    // `narf_module_init` returning 0 is what promotes Loading → Live, so this
    // is the assertion that the relocated, sealed image actually EXECUTED.
    // `Live` carries most of this test's weight, because reaching it is only
    // possible if the whole pipeline worked:
    //
    //   * `narf_printk` was an UNDEFINED symbol in the object, so the load
    //     could only get this far by resolving it against the live KSYMTAB —
    //     an unresolved name fails the load outright;
    //   * the relocation patching that call site was applied against the
    //     image's final address (a veneer on aarch64, where the target is
    //     beyond `CALL26`'s reach);
    //   * the image was mapped, sealed RX, and `narf_module_init` EXECUTED
    //     from it — a mis-patched call would fault here, not return;
    //   * init returned 0, which is what promotes Loading → Live.
    let live = *module.state.lock() == narf_modules::ModuleState::Live;
    let named = module.name() == "test_module";
    let listed = narf_modules::registry::contains("test_module");

    let unloaded = narf_modules::syscalls::sys_delete_module("test_module").is_ok();
    let gone = !narf_modules::registry::contains("test_module");

    // Load it a second time. This is the assertion with teeth for the unload
    // path: a second load has to obtain module VA and frames, so anything
    // `sys_delete_module` failed to release — the window bitmap run, the
    // backing frames, the name in the registry — surfaces here rather than
    // as exhaustion in some later boot.
    let reloaded = narf_modules::syscalls::sys_init_module(&image);
    let relive = reloaded
        .as_ref()
        .map(|m| *m.state.lock() == narf_modules::ModuleState::Live)
        .unwrap_or(false);
    let _ = narf_modules::syscalls::sys_delete_module("test_module");

    if !live {
        return TestResult::Fail("module loaded but never reached Live — init did not run");
    }
    if !named {
        return TestResult::Fail("manifest name is wrong — .modinfo was misparsed");
    }
    if !listed {
        return TestResult::Fail("a Live module is missing from the registry");
    }
    if !unloaded {
        return TestResult::Fail("sys_delete_module refused an idle module");
    }
    if !gone {
        return TestResult::Fail("unload left the module in the registry");
    }
    if !relive {
        return TestResult::Fail("reload after unload failed — unload did not release something");
    }
    TestResult::Pass
}
kernel_test_in!("modules/e2e", smoke_module_load_real_ko_round_trip);

/// The staged object must be what the loader expects before any of the above
/// means anything: a relocatable ELF for THIS architecture, carrying the
/// undefined `narf_printk` reference that makes it a real relocation test.
/// If the build ever silently produced a shape the loader tolerates but that
/// exercises nothing, this says so rather than the round-trip passing
/// vacuously.
fn smoke_module_staged_ko_is_relocatable_for_this_arch() -> TestResult {
    let Some(image) = read_test_module() else {
        return TestResult::Skip("/lib/modules/narf_test_module.ko absent");
    };
    if image.len() < 64 || &image[0..4] != b"\x7fELF" {
        return TestResult::Fail("staged .ko is not an ELF");
    }
    // e_type == ET_REL (1); e_machine must match the running arch.
    let e_type = u16::from_le_bytes([image[16], image[17]]);
    let e_machine = u16::from_le_bytes([image[18], image[19]]);
    #[cfg(target_arch = "x86_64")]
    const WANT_MACHINE: u16 = 62; // EM_X86_64
    #[cfg(target_arch = "aarch64")]
    const WANT_MACHINE: u16 = 183; // EM_AARCH64
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const WANT_MACHINE: u16 = 0;

    if e_type != 1 {
        return TestResult::Fail("staged .ko is not ET_REL — `ld -r` did not run");
    }
    if e_machine != WANT_MACHINE {
        return TestResult::Fail("staged .ko was built for a different architecture");
    }
    // The `.modinfo` merge `ld -r` performs is what makes the manifest
    // readable as one blob; a raw `.o` carries one section per line.
    if !image
        .windows(b"kernel_abi=0x".len())
        .any(|w| w == b"kernel_abi=0x")
    {
        return TestResult::Fail("staged .ko carries no kernel_abi= line");
    }
    if !image
        .windows(b"narf_printk".len())
        .any(|w| w == b"narf_printk")
    {
        return TestResult::Fail(
            "staged .ko does not reference narf_printk — nothing to relocate against",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "modules/e2e",
    smoke_module_staged_ko_is_relocatable_for_this_arch
);
