//! Devicetree platform-driver match registry.
//!
//! The DT analogue of [`crate::driver_match`]: Linux's
//! `platform_driver_register` with an `of_match_table`, and the
//! `of_platform_populate` → `platform_match` → `of_match_device` walk
//! that binds a driver to each enabled node.
//!
//! A driver registers a [`DtMatch`] (its `compatible` table and a probe
//! fn) at `Stage::Subsys`. [`probe_blob`] walks a flattened Devicetree
//! once: for every enabled node (`status` absent, `"okay"` or `"ok"`)
//! it tries the node's own `compatible` strings in order — most
//! specific first, as `of_match_device` scores them — against every
//! registered table, and calls the first match's probe with the blob
//! and the node's full path. A node binds at most once: the binding is
//! recorded by path, so repeated walks (one per DT driver's
//! `Stage::Device` initcall, or a later re-walk) never re-probe it.
//! [`probe_all`] walks the boot blob ([`crate::boot_dtb`]).
//!
//! No capability is minted: a DT node is not a `BusDevice` in the
//! registry, and the probe owns the node's resources by reading them
//! from the blob (`reg`, `interrupts`, phandles) the way a Linux
//! platform driver does.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::driver_match::ProbeError;

/// Probe for one matched node: the whole blob (phandle targets live
/// elsewhere in it) and the node's full path (`/soc@0/wifi@c000000`).
pub type DtProbeFn = fn(blob: &'static [u8], path: &str) -> Result<(), ProbeError>;

/// One DT driver: `struct platform_driver` + its `of_match_table`.
#[derive(Copy, Clone)]
pub struct DtMatch {
    /// Driver name; the registration key.
    pub name: &'static str,
    /// The `of_device_id.compatible` strings this driver claims.
    pub compatible: &'static [&'static str],
    pub probe: DtProbeFn,
}

impl core::fmt::Debug for DtMatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DtMatch")
            .field("name", &self.name)
            .field("compatible", &self.compatible)
            .finish_non_exhaustive()
    }
}

static REGISTRY: IrqSafeSpinLock<Vec<DtMatch>> = IrqSafeSpinLock::new(Vec::new());
/// `(node path, driver name)` of every node a probe bound.
static BOUND: IrqSafeSpinLock<Vec<(String, &'static str)>> = IrqSafeSpinLock::new(Vec::new());

/// Register (or replace, keyed by `name`) a DT driver.
pub fn register(m: DtMatch) {
    let mut g = REGISTRY.lock();
    if let Some(pos) = g.iter().position(|e| e.name == m.name) {
        g[pos] = m;
    } else {
        g.push(m);
    }
}

/// Drop the driver registered under `name` and its bindings
/// (`platform_driver_unregister`; the probe's resources are the
/// driver's to release).
pub fn unregister(name: &str) {
    REGISTRY.lock().retain(|e| e.name != name);
    BOUND.lock().retain(|(_, n)| *n != name);
}

/// Snapshot of the registered DT drivers.
pub fn registered() -> Vec<DtMatch> {
    REGISTRY.lock().clone()
}

/// Snapshot of `(node path, driver name)` bindings.
pub fn bound() -> Vec<(String, &'static str)> {
    BOUND.lock().clone()
}

/// The registered driver claiming a node whose `compatible` property is
/// `value` (NUL-separated, most specific first).
fn best_match(drivers: &[DtMatch], value: &[u8]) -> Option<DtMatch> {
    let mut hit = None;
    narf_firmware_fdt::for_each_compatible_string(value, |c| {
        if hit.is_some() {
            return;
        }
        hit = drivers.iter().find(|d| d.compatible.contains(&c)).copied();
    });
    hit
}

/// Walk `blob` and probe every enabled, not yet bound node a registered
/// driver claims. Returns how many nodes this walk bound. A probe error
/// leaves the node unbound (a later walk retries it, like Linux's
/// deferred probe).
pub fn probe_blob(blob: &'static [u8]) -> usize {
    let drivers = registered();
    if drivers.is_empty() {
        return 0;
    }
    // Collect first: probes run outside the FDT walk and the locks.
    let mut todo: Vec<(String, DtMatch)> = Vec::new();
    narf_firmware_fdt::walk_with_cells(blob, |path, props, _| {
        if narf_firmware_fdt::node_status(props) != narf_firmware_fdt::Status::Okay {
            return;
        }
        let Some(m) = props
            .into_iter()
            .find(|(n, _)| *n == "compatible")
            .and_then(|(_, v)| best_match(&drivers, v))
        else {
            return;
        };
        let mut p = String::new();
        for i in 0..path.depth() as usize {
            p.push('/');
            p.push_str(path.segment(i).unwrap_or(""));
        }
        if p.is_empty() {
            p.push('/');
        }
        todo.push((p, m));
    });
    let mut n = 0;
    for (path, m) in todo {
        if BOUND.lock().iter().any(|(p, _)| *p == path) {
            continue;
        }
        if (m.probe)(blob, &path).is_ok() {
            BOUND.lock().push((path, m.name));
            n += 1;
        }
    }
    n
}

/// [`probe_blob`] over the boot Devicetree. `0` without one (x86_64, a
/// DTB-less boot).
pub fn probe_all() -> usize {
    const MAX_DTB_SIZE: usize = 2 * 1024 * 1024;
    let Some(phys) = crate::boot_dtb() else {
        return 0;
    };
    // SAFETY: the boot path reserved the firmware DTB in RAM covered by
    // the kernel direct map; `discover` validates the header and bounds
    // the slice by the blob's own `totalsize` (capped here).
    match unsafe { narf_firmware_fdt::discover(phys.raw() as usize, MAX_DTB_SIZE) } {
        Some(blob) => probe_blob(blob),
        None => 0,
    }
}
