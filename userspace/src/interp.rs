//! PT_INTERP interpreter registry.
//!
//! The ELF parser already extracts the interpreter path from
//! `PT_INTERP` (e.g. "/lib/ld-linux-x86-64.so.2", or for narf the
//! capability-bootstrap "ld-narf"). The loader uses this registry
//! to resolve that path to a byte slice it can map alongside the
//! program.
//!
//! In a fully-fledged system the path would name a file the loader
//! pulls through the filesystem layer; until that hand-off is wired
//! up, boot code (or tests) `register_interpreter`s a static slice
//! up front and the loader looks it up by exact-path match.
//!
//! Re-exported by name from `narf_userspace`. The lock pattern
//! mirrors the per-task bootstrap registry in `handlers.rs` so the
//! IRQ-discipline assumptions are uniform across the crate.

use alloc::collections::BTreeMap;

use narf_lib::sync::IrqSafeSpinLock;

static REGISTRY: IrqSafeSpinLock<Option<BTreeMap<&'static str, &'static [u8]>>>
    = IrqSafeSpinLock::new(None);

/// Register an interpreter ELF blob under `name`. A second call
/// with the same `name` overwrites the prior entry — boot code is
/// expected to call this once per interpreter image.
pub fn register_interpreter(name: &'static str, bytes: &'static [u8]) {
    let mut g = REGISTRY.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert(name, bytes);
}

/// Look up a registered interpreter by name. Returns `None` when
/// nothing matches `name`.
pub fn lookup_interpreter(name: &str) -> Option<&'static [u8]> {
    let g = REGISTRY.lock();
    g.as_ref()?.get(name).copied()
}

/// Test hook: drop every registered interpreter so test ordering
/// doesn't leak state across cases. Production code never calls
/// this.
#[doc(hidden)]
pub fn __test_clear_interpreters() { *REGISTRY.lock() = None; }
