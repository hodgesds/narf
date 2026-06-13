//! `misc` controller — scalar resources keyed by name.
//!
//! A generic controller for resources that are neither memory-like nor
//! cpu-like (e.g. AMD SEV ASIDs, SGX EPC). Each resource is a named
//! scalar with a global `capacity`; cgroups set a per-key `max` and
//! account `current`. With no resources registered every file is empty
//! — the faithful v2 behaviour when the kernel exposes no misc keys.
//!
//! Linux ref: `kernel/cgroup/misc.c`,
//! `Documentation/admin-guide/cgroup-v2.rst` §"Misc".
//!
//! Interface files:
//!   * `misc.current` (ro) — `<key> <usage>` lines
//!   * `misc.max`     (rw) — `<key> <max>` lines; write `"key max"` to unset
//!   * `misc.events`  (ro) — `<key>.max <n>` lines

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &["misc.current", "misc.max", "misc.events"];

/// Global registry of misc resource keys → capacity. Populated by the
/// platform when it exposes a misc resource; empty otherwise.
static CAPACITY: IrqSafeSpinLock<BTreeMap<&'static str, u64>> =
    IrqSafeSpinLock::new(BTreeMap::new());

/// Register a misc resource and its total capacity (e.g.
/// `register_misc_resource("sev", 509)`). Call at boot.
pub fn register_misc_resource(key: &'static str, capacity: u64) {
    CAPACITY.lock().insert(key, capacity);
}

#[derive(Debug)]
pub struct MiscController;

impl Controller for MiscController {
    fn name(&self) -> &'static str {
        "misc"
    }

    fn new_state(&self, _parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        Arc::new(MiscState {
            max: IrqSafeSpinLock::new(BTreeMap::new()),
            current: IrqSafeSpinLock::new(BTreeMap::new()),
        })
    }
}

#[derive(Debug)]
pub struct MiscState {
    /// Per-key `max`. Absent key ⇒ "max" (capacity).
    max: IrqSafeSpinLock<BTreeMap<&'static str, u64>>,
    /// Per-key current usage.
    current: IrqSafeSpinLock<BTreeMap<&'static str, u64>>,
}

impl ControllerState for MiscState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        match file {
            "misc.current" => {
                let cur = self.current.lock();
                let mut s = String::new();
                for (k, v) in cur.iter() {
                    s.push_str(&format_line(k, *v));
                }
                s
            }
            "misc.max" => {
                let max = self.max.lock();
                let mut s = String::new();
                for (k, v) in max.iter() {
                    s.push_str(&format_line(k, *v));
                }
                s
            }
            "misc.events" => String::new(),
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        if file != "misc.max" {
            return Err(FsError::ReadOnly);
        }
        let text = core::str::from_utf8(buf).map_err(|_| FsError::InvalidData)?;
        // "<key> <max>" — one resource per write line.
        let mut parts = text.split_whitespace();
        let key = parts.next().ok_or(FsError::InvalidData)?;
        let val = parts.next().ok_or(FsError::InvalidData)?;
        // Resolve to a registered &'static key.
        let canon = {
            let cap = CAPACITY.lock();
            *cap.keys()
                .find(|k| **k == key)
                .ok_or(FsError::InvalidData)?
        };
        if val == "max" {
            self.max.lock().remove(canon);
        } else {
            let n = val.parse::<u64>().map_err(|_| FsError::InvalidData)?;
            self.max.lock().insert(canon, n);
        }
        Ok(())
    }

    fn writable(&self, file: &str) -> bool {
        file == "misc.max"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn format_line(key: &str, val: u64) -> String {
    let mut s = String::new();
    s.push_str(key);
    s.push(' ');
    s.push_str(&val.to_string());
    s.push('\n');
    s
}

/// Snapshot of registered misc resource keys (for diagnostics/tests).
#[doc(hidden)]
pub fn registered_keys() -> Vec<&'static str> {
    CAPACITY.lock().keys().copied().collect()
}
