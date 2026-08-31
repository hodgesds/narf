//! NARF loadable kernel modules.
//!
//! Runtime-loadable Rust modules: parse a relocatable ELF64,
//! resolve undefined symbols against the kernel's exported symbol
//! table (cap-gated), apply per-arch relocations, call the module's
//! `narf_module_init`, and register the module in a per-name registry
//! that backs `/proc/modules` and `/sys/module/<name>/`.
//!
//! NARF deviates from Linux in three load-bearing ways:
//!   1. **Cap-typed exports.** A kernel export may declare a
//!      `required_cap`; the relocator refuses to resolve the symbol
//!      unless the module's manifest declares the same cap. Linux's
//!      `EXPORT_SYMBOL_GPL` is the closest analogue but it's a coarse
//!      bool, not a per-cap predicate.
//!   2. **Domain placement.** Every module declares `target_domain`;
//!      the loader maps its text + data into that PKS-isolated
//!      driver-domain region. A buggy module can scribble only its
//!      own domain.
//!   3. **Versioned ABI hash.** Every exported symbol carries a CRC;
//!      every module carries a `kernel_abi=` line. Mismatches are
//!      caught at load time, not at first call.
//!
//! Linux refs read during design:
//!   * `kernel/module/main.c::load_module` — overall pipeline.
//!   * `kernel/module/main.c::find_symbol` — kernel symbol resolution.
//!   * `kernel/module/main.c::do_init_module` — init invocation +
//!     state transition.
//!   * `kernel/module/procfs.c::m_show` — /proc/modules format.
//!   * `kernel/module/sysfs.c::mod_sysfs_setup` — /sys/module layout.
//!   * `arch/x86/kernel/module.c::apply_relocate_add` — x86_64 relocs.
//!   * `arch/arm64/kernel/module.c::apply_relocate_add` — aarch64 relocs.
//!
//! See `DESIGN.md` and `MODULE_AUTHORING.md` in this crate's root.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod domain;
pub mod elf;
pub mod kabi;
pub mod lifecycle;
pub mod loader;
pub mod manifest;
pub mod params;
pub mod plt;
pub mod proc_modules;
pub mod refcount;
pub mod relocator;
pub mod sign;
pub mod symbols;
pub mod syscalls;
pub mod sysfs_module;

#[cfg(test)]
mod tests;

#[doc(hidden)]
mod tests_smoke;

#[doc(hidden)]
mod tests_e2e;

pub use lifecycle::ModuleState;
pub use loader::{load_image, Module};

/// Per-name registry of loaded modules. Acts as the single source
/// of truth for `/proc/modules` + `/sys/module/`.
pub mod registry {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use narf_lib::sync::IrqSafeSpinLock;

    use crate::loader::Module;

    static MODULES: IrqSafeSpinLock<Vec<Arc<Module>>> = IrqSafeSpinLock::new(Vec::new());

    /// True iff a module with `name` is registered.
    pub fn contains(name: &str) -> bool {
        MODULES.lock().iter().any(|m| m.name() == name)
    }

    /// Look up a module by name.
    pub fn lookup(name: &str) -> Option<Arc<Module>> {
        MODULES.lock().iter().find(|m| m.name() == name).cloned()
    }

    /// Insert a module. Caller verifies non-duplication beforehand.
    pub fn insert(module: Arc<Module>) {
        MODULES.lock().push(module);
    }

    /// Remove a module by name. Returns true iff one was removed.
    pub fn remove(name: &str) -> bool {
        let mut g = MODULES.lock();
        let before = g.len();
        g.retain(|m| m.name() != name);
        g.len() < before
    }

    /// Snapshot the current registry.
    pub fn snapshot() -> Vec<Arc<Module>> {
        MODULES.lock().clone()
    }

    /// Number of loaded modules.
    pub fn len() -> usize {
        MODULES.lock().len()
    }

    /// Test helper.
    #[doc(hidden)]
    pub fn __reset_for_test() {
        MODULES.lock().clear();
    }
}

/// Wire the modules subsystem into the kernel at boot. Called from
/// `frame/src/bare_main.rs`.
///
/// Order within `modules-abi` matters: the ABI hash is *derived from* the
/// export table, so the exports have to be registered first. That is the
/// point of deriving it rather than accepting one — the hash cannot drift
/// from the surface it describes, because there is nowhere for it to drift
/// to. `/sys/module/<name>/` entries are installed per-module on load.
///
/// Split across two stages. The ABI surface, the domain table and the
/// signature verifier are `Subsys`: they are pure registration, and every one
/// of them has to be in place before the first `init_module(2)` — which,
/// arriving from userspace, cannot happen until long after `Late`.
///
/// `/proc/modules` waits for `Fs`, after `procfs-mount`. `register_proc`
/// records into a registry that `ProcFs` consults per lookup, so the order is
/// not load-bearing, but installing a `/proc` entry before `/proc` exists
/// reads as a bug even when it works.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};

    narf_init::register(Stage::Subsys, "modules-abi", || {
        domain::install_standard_domains();
        kabi::register_all();
        symbols::set_kernel_abi(symbols::compute_abi_hash());
        sign::install_verifier(alloc::boxed::Box::new(sign::AcceptAll));
        InitResult::Ok
    });

    narf_init::register(Stage::Fs, "modules-procfs", || {
        proc_modules::install_proc_modules();
        InitResult::Ok
    });
}
