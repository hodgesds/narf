//! NARF loadable kernel modules.
//!
//! Runtime-loadable Rust modules: authenticate and optionally decompress a
//! bounded module envelope, parse a relocatable ELF64,
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

pub mod compression;
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
pub use loader::{load_image, load_image_with_domain, Module};

fn canonical_initramfs_name(name: &str) -> &str {
    let name = name.strip_prefix("./").unwrap_or(name);
    name.strip_prefix('/').unwrap_or(name)
}

fn autoload_params(requested_path: &str) -> Result<alloc::string::String, &'static str> {
    let mut selected = None;
    if let Some(mappings) = narf_boot::args().value("modules_domains") {
        for mapping in mappings.split(',').filter(|mapping| !mapping.is_empty()) {
            let Some((path, domain)) = mapping.split_once('=') else {
                return Err("invalid modules_domains mapping");
            };
            if path.is_empty() || domain.is_empty() {
                return Err("invalid modules_domains mapping");
            }
            if canonical_initramfs_name(path) == requested_path
                && selected.replace(domain).is_some()
            {
                return Err("duplicate modules_domains mapping");
            }
        }
    }
    Ok(selected
        .or_else(|| narf_boot::args().value("modules_domain"))
        .map(|domain| alloc::format!("domain={domain}"))
        .unwrap_or_default())
}

/// Load the comma-separated initramfs paths named by `modules_load=`.
///
/// This runs after the KABI table is finalized but before `Stage::Device`, so
/// a driver module can register its PCI match before the ordinary bus probe.
/// `modules_domains=path=domain,...` selects placement per module;
/// `modules_domain=` remains the fallback applied to every unmatched module.
/// The loader still rejects `FRAME` and enforces the module signature, ABI
/// hash, and capability manifest normally. All values come from the
/// bootloader-supplied command line.
fn autoload_initramfs_modules() -> narf_init::InitResult {
    use core::fmt::Write as _;

    let Some(requested) = narf_boot::args().value("modules_load") else {
        return narf_init::InitResult::NotPresent;
    };
    let Some(initramfs) = narf_initramfs::staged() else {
        return narf_init::InitResult::Error("modules_load requires an initramfs");
    };
    let mut loaded = 0usize;

    for requested_path in requested.split(',').filter(|path| !path.is_empty()) {
        let requested_path = canonical_initramfs_name(requested_path);
        let params = match autoload_params(requested_path) {
            Ok(params) => params,
            Err(error) => return narf_init::InitResult::Error(error),
        };
        let Some((_, bytes)) = initramfs
            .iter_files()
            .find(|(name, _)| canonical_initramfs_name(name) == requested_path)
        else {
            let _ = writeln!(
                narf_console::Writer,
                "  modules: autoload path not found: {requested_path}"
            );
            return narf_init::InitResult::Error("module autoload path not found");
        };
        match syscalls::sys_init_module_with_params(bytes, &params) {
            Ok(module) => {
                loaded += 1;
                let _ = writeln!(
                    narf_console::Writer,
                    "  modules: autoloaded {} from {} in {:?}",
                    module.name(),
                    requested_path,
                    module.domain,
                );
            }
            Err(error) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "  modules: autoload failed for {}: {:?}",
                    requested_path,
                    error,
                );
                return narf_init::InitResult::Error("module autoload failed");
            }
        }
    }

    if loaded == 0 {
        narf_init::InitResult::NotPresent
    } else {
        narf_init::InitResult::Ok
    }
}

/// Enter a loaded module's effective isolation frame before the bus invokes
/// its separately compiled probe callback. The bus stores only the opaque
/// module id and delegates placement policy back here.
fn call_in_module_context(owner: u64, call: impl FnOnce() -> i32) -> i32 {
    if owner == symbols::KERNEL_MODULE_ID.0 {
        return call();
    }
    let Some(module) = registry::lookup_by_id(symbols::ModuleId(owner)) else {
        return -19; // -ENODEV: owner disappeared or was never registered.
    };
    // Pin while holding the lifecycle lock. This makes "Live -> Going" and
    // "admit a new callback" mutually exclusive: unload either observes the
    // reference and returns Busy, or the callback observes Going and refuses
    // to enter module text.
    let state = module.state.lock();
    if *state != lifecycle::ModuleState::Live {
        return -19;
    }
    module.refcount.get();
    drop(state);
    let previous_owner = symbols::swap_execution_context(module.id);
    let scope = domain::enter(module.domain);
    let rc = call();
    domain::exit(scope);
    symbols::swap_execution_context(previous_owner);
    module.refcount.put();
    rc
}

fn module_pci_probe_call_gate(
    owner: u64,
    probe: narf_bus::ModuleProbeFn,
    dev_token: u64,
    reserved: u64,
) -> i32 {
    call_in_module_context(owner, || probe(dev_token, reserved))
}

fn module_callback_call_gate(owner: u64, callback: narf_bus::ModuleCallbackFn, cookie: u64) -> i32 {
    call_in_module_context(owner, || callback(cookie))
}

fn module_tx_call_gate(owner: u64, callback: narf_bus::ModuleTxFn, frame: &[u8]) -> i32 {
    call_in_module_context(owner, || callback(frame.as_ptr(), frame.len()))
}

fn install_bus_call_gate() {
    narf_bus::set_module_probe_call_gate(module_pci_probe_call_gate);
    narf_bus::set_module_callback_call_gate(module_callback_call_gate);
    narf_bus::set_module_tx_call_gate(module_tx_call_gate);
}

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

    /// Look up a module by its `ModuleId`. Used to resolve dependency edges,
    /// which are recorded by id rather than by name — a name can be reused
    /// across a load/unload cycle, an id never is.
    pub fn lookup_by_id(id: crate::symbols::ModuleId) -> Option<Arc<Module>> {
        MODULES.lock().iter().find(|m| m.id == id).cloned()
    }

    /// Insert a module unless one of that name is already registered.
    /// Returns false if one was.
    ///
    /// Atomic against a concurrent insert of the same name, which a
    /// `contains` check followed by `insert` is not: two `init_module` calls
    /// racing on the same name could both observe "absent" and both push.
    pub fn insert_unique(module: Arc<Module>) -> bool {
        let mut g = MODULES.lock();
        if g.iter().any(|m| m.name() == module.name()) {
            return false;
        }
        g.push(module);
        true
    }

    /// Modules holding a reference on `id`, by name. Backs the holders column
    /// of `/proc/modules`, which Linux fills the same way
    /// (`kernel/module/procfs.c::m_show`).
    pub fn holders_of(id: crate::symbols::ModuleId) -> Vec<alloc::string::String> {
        MODULES
            .lock()
            .iter()
            .filter(|m| m.deps.contains(&id))
            .map(|m| alloc::string::String::from(m.name()))
            .collect()
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
        install_bus_call_gate();
        kabi::register_all();
        symbols::set_kernel_abi(symbols::compute_abi_hash());
        sign::install_build_trusted_signers();
        sign::install_verifier(alloc::boxed::Box::new(sign::Ed25519Verifier));
        InitResult::Ok
    });

    narf_init::register(
        Stage::Subsys,
        "modules-initramfs-autoload",
        autoload_initramfs_modules,
    );

    narf_init::register(Stage::Fs, "modules-sysfs", || {
        proc_modules::install_proc_modules();
        // `/sys/kernel/abi_hash` — the value a module author has to put in
        // their `kernel_abi=` line. Registered here rather than with the ABI
        // surface at `Subsys` because it needs `/sys` to exist.
        sysfs_module::install_abi_hash();
        InitResult::Ok
    });
}
