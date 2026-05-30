//! Module parameters.
//!
//! Linux ref: `linux/include/linux/moduleparam.h` (`MODULE_PARM_DESC`,
//! `module_param`) and `linux/kernel/params.c::param_set_*`.
//!
//! NARF reads parameters from the `.narf_kparams` ELF section (one
//! `name=value` per line) at load time, and exposes a writable
//! mirror under `/sys/module/<name>/parameters/<param>` so an
//! operator can tune the value at runtime.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

/// One module parameter slot. Stored as raw bytes; the module is
/// responsible for parsing into whatever Rust type it expects.
#[derive(Debug)]
pub struct ParamSlot {
    pub name: String,
    /// Current text value (most recent write wins).
    pub value: IrqSafeSpinLock<String>,
}

impl ParamSlot {
    pub fn new(name: impl Into<String>, initial: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: IrqSafeSpinLock::new(initial.into()),
        }
    }

    pub fn read(&self) -> String {
        self.value.lock().clone()
    }

    pub fn write(&self, s: &str) {
        *self.value.lock() = s.to_string();
    }
}

/// Parse a `.narf_kparams` section's bytes into a Vec of slots.
/// Format: one `key=value` per line; blank and `#`-prefixed lines
/// are ignored.
pub fn parse_section(bytes: &[u8]) -> Vec<ParamSlot> {
    let mut out = Vec::new();
    let s = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return out,
    };
    for raw in s.split(|c| c == '\n' || c == 0 as char) {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            out.push(ParamSlot::new(k.trim(), v.trim()));
        }
    }
    out
}

/// Find a parameter slot by name in a slice. Linear scan; the per-
/// module slot list is tiny.
pub fn find<'a>(params: &'a [ParamSlot], name: &str) -> Option<&'a ParamSlot> {
    params.iter().find(|p| p.name == name)
}
