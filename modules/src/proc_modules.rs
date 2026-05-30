//! /proc/modules adapter.
//!
//! Linux ref: `linux/kernel/module/procfs.c::m_show` (`procfs.c:74`)
//! and the format documented at `procfs.c:106`:
//!
//! ```text
//! <name> <size> <refcount> <holder1,holder2,> <state> 0x<addr> [(<taint>)]
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::loader::Module;

/// Render one module's `/proc/modules` line. No trailing newline.
pub fn render_one(module: &Module) -> String {
    let state_str = module.state.lock().as_str();
    let state_label = match state_str {
        "Live" => "Live",
        "Loading" => "Loading",
        "Going" => "Unloading",
        "Dead" => "Unloading",
        other => other,
    };
    let holders = "-"; // dependency tracking placeholder
    format!(
        "{} {} {} {} {} 0x{:016x}",
        module.name(),
        module.total_size(),
        module.refcount.snapshot(),
        holders,
        state_label,
        module.base_addr(),
    )
}

/// Render every loaded module in the supplied list (the caller
/// snapshots the registry first). One module per line, no trailing
/// blank line.
pub fn render_all(mods: &[Arc<Module>]) -> String {
    let mut out = String::new();
    for m in mods {
        out.push_str(&render_one(m));
        out.push('\n');
    }
    out
}

/// `ProcFile` adapter for `/proc/modules`. Pulls the registry
/// snapshot on every read.
#[derive(Debug)]
pub struct ProcModulesFile {
    snapshot: fn() -> Vec<Arc<Module>>,
}

impl ProcModulesFile {
    pub const fn new(snapshot: fn() -> Vec<Arc<Module>>) -> Self {
        Self { snapshot }
    }
}

impl narf_filesystem::procfs::ProcFile for ProcModulesFile {
    fn read(&self) -> Vec<u8> {
        let mods = (self.snapshot)();
        render_all(&mods).into_bytes()
    }
}

/// Install `/proc/modules` against `narf-filesystem`'s procfs
/// registry. Called once at boot once the kernel is ready to surface
/// the file.
pub fn install_proc_modules() {
    use crate::registry;
    let f = Arc::new(ProcModulesFile::new(registry::snapshot));
    narf_filesystem::procfs::register_proc("modules", f);
}

/// Utility: surface a tainted-flag string (placeholder — NARF
/// doesn't taint today). Mirrors Linux's `module_flags` (`main.c:3892`).
pub fn taint_string(_module: &Module) -> String {
    String::new().to_string()
}
