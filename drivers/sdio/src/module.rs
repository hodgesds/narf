//! Loadable-module SDIO function-driver host.
//!
//! The SDIO-stack side of `narf_bus::module_sdio`: it installs one permanent
//! [`Host`] so the `narf_register_sdio_driver` kernel-ABI export can register a
//! `.ko`'s function-driver match. `bus` cannot reach the SDIO registry
//! directly, mirroring how `narf-drivers-usb` backs `narf_bus::module_usb`.
//!
//! A [`FunctionDriver::probe`] is a bare `fn(NativeCard)` with no owner
//! context, so every module match registers the same [`trampoline`]; it
//! resolves the owning module from the card's `(vendor, device)` on the
//! matched function and dispatches through the module probe call gate
//! ([`narf_bus::module_sdio::call_module_sdio_probe`]), exactly as the PCI
//! `module_probe_trampoline` does. Registration-only: no SDIO datapath export
//! accepts the token yet, so the probe runs but returns `-ENOSYS`.

use alloc::vec::Vec;

use narf_bus::module_sdio::{self, Host, ModuleSdioMatch};
use narf_bus::ModuleProbeFn;
use narf_lib::sync::IrqSafeSpinLock;

use crate::native::{self, FunctionDriver, NativeCard};

struct SdioThunk {
    owner: u64,
    m: ModuleSdioMatch,
    /// The interned name the match registered its `FunctionDriver` under.
    name: &'static str,
    probe: ModuleProbeFn,
}

static THUNKS: IrqSafeSpinLock<Vec<SdioThunk>> = IrqSafeSpinLock::new(Vec::new());

/// `module_sdio::Host::register`. Dedups on the full `(vendor, device,
/// function)` match so a re-registration replaces the thunk rather than growing
/// the table; `-EBUSY` if another module already owns that match or the native
/// registry rejected the driver (duplicate name / table full).
fn do_register(owner: u64, name: &'static str, m: ModuleSdioMatch, probe: ModuleProbeFn) -> i32 {
    {
        let mut g = THUNKS.lock();
        if let Some(pos) = g.iter().position(|t| t.m == m) {
            if g[pos].owner != owner {
                return -16; // -EBUSY
            }
            g[pos].owner = owner;
            g[pos].name = name;
            g[pos].probe = probe;
            return 0;
        }
        g.push(SdioThunk {
            owner,
            m,
            name,
            probe,
        });
    }
    if native::register_function_driver(FunctionDriver {
        name,
        vendor: m.vendor,
        device: m.device,
        function: m.function,
        probe: trampoline,
    }) {
        0
    } else {
        // Roll the thunk back so the table reflects what actually registered.
        THUNKS.lock().retain(|t| t.m != m);
        -16
    }
}

/// `module_sdio::Host::unregister`: drop every match the module owns, and the
/// native function drivers registered for them, before its text is unmapped.
fn do_unregister(owner: u64) {
    let names: Vec<&'static str> = {
        let mut g = THUNKS.lock();
        let names = g
            .iter()
            .filter(|t| t.owner == owner)
            .map(|t| t.name)
            .collect();
        g.retain(|t| t.owner != owner);
        names
    };
    for name in names {
        native::unregister_function_driver(name);
    }
}

/// The shared `FunctionDriver` probe for every module match. Resolve the owning
/// module from the card and dispatch its thunk through the module call gate.
fn trampoline(card: NativeCard) {
    let found = {
        let g = THUNKS.lock();
        g.iter()
            .find(|t| {
                card.function(t.m.function)
                    .is_some_and(|f| f.vendor == t.m.vendor && f.device == t.m.device)
            })
            .map(|t| (t.owner, t.probe))
    };
    if let Some((owner, probe)) = found {
        // No SDIO datapath export accepts the token yet; the probe returns
        // -ENOSYS. A 0 token is the opaque registration-only placeholder.
        let _ = module_sdio::call_module_sdio_probe(owner, probe, 0);
    }
}

static HOST: Host = Host {
    register: do_register,
    unregister: do_unregister,
};

/// Install the SDIO module host. Idempotent (the `compare_exchange` in
/// `module_sdio::register` makes a repeat a no-op), so it is safe to call from
/// every SDIO-stack bring-up path.
pub fn install() {
    let _ = module_sdio::register(&HOST);
}

#[cfg(feature = "kernel-test")]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    extern "C" fn probe_ok(_dev_token: u64, _reserved: u64) -> i32 {
        0
    }

    /// Registering a module SDIO match installs a native function driver, and
    /// unregistering the owner removes it; a re-registration with a different
    /// owner is refused.
    fn smoke_sdio_module_host_register_and_unregister() -> TestResult {
        install();
        module_sdio::__reset_host_for_test();
        install();
        THUNKS.lock().clear();

        let m = ModuleSdioMatch::new(0x02d0, 0x4345, 1).expect("valid match");
        let probe: ModuleProbeFn = probe_ok;
        if do_register(7, "sdio-mod-test", m, probe) != 0 {
            return TestResult::Fail("first registration should succeed");
        }
        if !native::registered_function_driver("sdio-mod-test") {
            return TestResult::Fail("native function driver was not installed");
        }
        // Same owner re-registers the same match: replace, still 0.
        if do_register(7, "sdio-mod-test", m, probe) != 0 {
            return TestResult::Fail("re-registration by the owner should succeed");
        }
        // A different owner claiming the same match is refused.
        if do_register(8, "sdio-mod-test-2", m, probe) != -16 {
            return TestResult::Fail("a foreign owner must not steal the match");
        }
        do_unregister(7);
        if native::registered_function_driver("sdio-mod-test") {
            return TestResult::Fail("unregister did not remove the function driver");
        }
        THUNKS.lock().clear();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/sdio/module",
        smoke_sdio_module_host_register_and_unregister
    );
}
