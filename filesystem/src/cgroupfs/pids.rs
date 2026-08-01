//! `pids` controller — limit the number of processes in a subtree.
//!
//! The simplest real v2 controller: a counter plus a limit. The core
//! charges every ancestor on attach/detach, so each level's `current`
//! is the number of processes in that cgroup's subtree, and `max`
//! caps it.
//!
//! Linux ref: `kernel/cgroup/pids.c`,
//! `Documentation/admin-guide/cgroup-v2.rst` §"PID".
//!
//! Interface files:
//!   * `pids.current` (ro) — processes currently in the subtree
//!   * `pids.peak`    (ro) — high-water mark of `pids.current`
//!   * `pids.max`     (rw) — limit; `"max"` for unlimited
//!   * `pids.events`  (ro) — `max <n>`: times a fork/attach was denied
//!   * `pids.events.local` (ro) — the non-hierarchical event view

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &[
    "pids.current",
    "pids.peak",
    "pids.max",
    "pids.events",
    "pids.events.local",
];

#[derive(Debug)]
pub struct PidsController;

impl Controller for PidsController {
    fn name(&self) -> &'static str {
        "pids"
    }

    fn new_state(&self, _parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        Arc::new(PidsState {
            current: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            limit: IrqSafeSpinLock::new(None),
            events_max: AtomicU64::new(0),
        })
    }
}

#[derive(Debug)]
pub struct PidsState {
    current: AtomicU64,
    peak: AtomicU64,
    /// `pids.max`; `None` = "max" (unlimited).
    limit: IrqSafeSpinLock<Option<u64>>,
    /// `pids.events` `max` counter.
    events_max: AtomicU64,
}

impl ControllerState for PidsState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        match file {
            "pids.current" => format!("{}\n", self.current.load(Ordering::Acquire)),
            "pids.peak" => format!("{}\n", self.peak.load(Ordering::Acquire)),
            "pids.max" => match *self.limit.lock() {
                None => "max\n".into(),
                Some(n) => format!("{n}\n"),
            },
            "pids.events" | "pids.events.local" => {
                format!("max {}\n", self.events_max.load(Ordering::Acquire))
            }
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        match file {
            "pids.max" => {
                let text = core::str::from_utf8(buf)
                    .map_err(|_| FsError::InvalidData)?
                    .trim();
                let v = if text == "max" {
                    None
                } else {
                    Some(text.parse::<u64>().map_err(|_| FsError::InvalidData)?)
                };
                *self.limit.lock() = v;
                Ok(())
            }
            _ => Err(FsError::ReadOnly),
        }
    }

    fn writable(&self, file: &str) -> bool {
        file == "pids.max"
    }

    fn can_attach(&self, _pid: u64) -> Result<(), FsError> {
        let limit = *self.limit.lock();
        if let Some(max) = limit {
            if self.current.load(Ordering::Acquire) + 1 > max {
                self.events_max.fetch_add(1, Ordering::Relaxed);
                // v2 maps a pids.max breach on migration to EBUSY.
                return Err(FsError::Busy);
            }
        }
        Ok(())
    }

    fn on_attach(&self, _pid: u64) {
        let now = self.current.fetch_add(1, Ordering::AcqRel) + 1;
        self.peak.fetch_max(now, Ordering::AcqRel);
    }

    fn on_detach(&self, _pid: u64) {
        // Saturating: never underflow if a detach races a fresh state.
        let mut cur = self.current.load(Ordering::Acquire);
        while cur > 0 {
            match self.current.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
