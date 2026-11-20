//! Devicetree driver registration for loadable modules.
//!
//! The DT analogue of [`crate::register_module_pci_driver`]. Unlike USB/SDIO,
//! the Devicetree match registry ([`crate::dt_match`]) lives in `bus` itself,
//! so this registers a [`DtMatch`] directly — no registry-side `Host`.
//!
//! A [`DtProbeFn`](crate::dt_match::DtProbeFn) is `fn(blob, path)` with no
//! owner context, so every module match registers the same
//! [`module_dt_probe_trampoline`]; it resolves the owning module from the
//! matched node's `compatible` at `path` and dispatches through the module
//! probe call gate, exactly as the PCI `module_probe_trampoline` resolves by
//! `(vendor, device)`. Registration-only: no DT datapath export accepts the
//! token yet, so a module probe matches a node but returns `-ENOSYS`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::driver_match::{call_module_probe, intern_name, ModuleProbeFn, ProbeError};
use crate::dt_match::{self, DtMatch};

struct DtThunk {
    owner: u64,
    /// The interned name the match registered its `DtMatch` under.
    name: &'static str,
    /// The single `compatible` string this match claims.
    compatible: &'static str,
    probe: ModuleProbeFn,
}

static THUNKS: IrqSafeSpinLock<Vec<DtThunk>> = IrqSafeSpinLock::new(Vec::new());

/// Build the `/a/b/c` path string of a walk node, matching `probe_blob`.
fn path_string(path: &narf_firmware_fdt::Path<'_>) -> String {
    let mut p = String::new();
    for i in 0..path.depth() as usize {
        p.push('/');
        p.push_str(path.segment(i).unwrap_or(""));
    }
    if p.is_empty() {
        p.push('/');
    }
    p
}

/// Resolve the module that owns the node at `path`: read its `compatible` and
/// find the thunk whose claimed string is among them.
fn resolve(blob: &'static [u8], path: &str) -> Option<(u64, ModuleProbeFn)> {
    let mut found: Option<(u64, ModuleProbeFn)> = None;
    narf_firmware_fdt::walk_with_cells(blob, |p, props, _| {
        if found.is_some() || path_string(p) != path {
            return;
        }
        let Some((_, value)) = props.into_iter().find(|(n, _)| *n == "compatible") else {
            return;
        };
        let thunks = THUNKS.lock();
        narf_firmware_fdt::for_each_compatible_string(value, |c| {
            if found.is_none() {
                if let Some(t) = thunks.iter().find(|t| t.compatible == c) {
                    found = Some((t.owner, t.probe));
                }
            }
        });
    });
    found
}

/// The shared `DtProbeFn` for every module match: resolve the owner from the
/// node and dispatch its thunk. `0` => bound; `-19` => declined (retry a
/// later walk); anything else (e.g. the registration-only `-ENOSYS`) is a
/// generic probe failure that leaves the node unbound.
fn module_dt_probe_trampoline(blob: &'static [u8], path: &str) -> Result<(), ProbeError> {
    let Some((owner, probe)) = resolve(blob, path) else {
        return Err(ProbeError::NotForThisDriver);
    };
    // No DT datapath export accepts the token yet; 0 is the opaque
    // registration-only placeholder.
    match call_module_probe(owner, probe, 0, 0) {
        0 => Ok(()),
        -19 => Err(ProbeError::NotForThisDriver),
        _ => Err(ProbeError::Other("module DT probe failed")),
    }
}

/// Register a module's DT match. Reached from the `narf_register_dt_driver`
/// export. `-EINVAL` for a null probe; `-EBUSY` when another module already
/// claims the same `compatible`. Dedups on `compatible` so a re-registration
/// replaces the thunk rather than growing the table.
///
/// # Safety
/// `probe` must be a valid [`ModuleProbeFn`] address that stays mapped for as
/// long as the match is registered (the loader unregisters it before unmap).
pub unsafe fn register_module_dt_driver(
    owner: u64,
    name: &str,
    compatible: &str,
    probe: usize,
) -> i32 {
    if probe == 0 {
        return -22;
    }
    // SAFETY: the caller promises `probe` is a valid `ModuleProbeFn` address.
    let thunk: ModuleProbeFn = unsafe { core::mem::transmute(probe) };
    let name = intern_name(name);
    let compatible = intern_name(compatible);
    {
        let mut g = THUNKS.lock();
        if let Some(pos) = g.iter().position(|t| t.compatible == compatible) {
            if g[pos].owner != owner {
                return -16; // -EBUSY
            }
            g[pos].owner = owner;
            g[pos].name = name;
            g[pos].probe = thunk;
            return 0;
        }
        g.push(DtThunk {
            owner,
            name,
            compatible,
            probe: thunk,
        });
    }
    // `DtMatch.compatible` is a `&'static [&'static str]`; leak a one-element
    // table from the interned string (leaked for the driver's lifetime, like
    // the interned name).
    let compat: &'static [&'static str] = Box::leak(Box::new([compatible]));
    dt_match::register(DtMatch {
        name,
        compatible: compat,
        probe: module_dt_probe_trampoline,
    });
    0
}

/// Remove every DT match owned by one loadable module. The caller runs the
/// module's exit hook first and calls this before unmapping module text.
pub fn unregister_module_dt_drivers(owner: u64) {
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
        dt_match::unregister(name);
    }
}

#[doc(hidden)]
/// Test-only: forget every registered module DT match.
pub fn __reset_for_test() {
    THUNKS.lock().clear();
}
