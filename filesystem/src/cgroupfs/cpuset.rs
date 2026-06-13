//! `cpuset` controller — pin a cgroup to a set of CPUs / memory nodes.
//!
//! SCAFFOLD: stores `cpuset.cpus` / `cpuset.mems` and reports the
//! requested set as effective (no parent-intersection yet) and accepts
//! writes. Applying affinity to member tasks via `narf-scheduler`
//! affinity hooks and computing `*.effective` as the parent-intersected
//! mask land in the controller pass.
//!
//! Linux ref: `kernel/cgroup/cpuset.c`,
//! `Documentation/admin-guide/cgroup-v2.rst` §"Cpuset".

use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &[
    "cpuset.cpus",
    "cpuset.cpus.effective",
    "cpuset.mems",
    "cpuset.mems.effective",
    "cpuset.cpus.partition",
];

#[derive(Debug)]
pub struct CpuSetController;

impl Controller for CpuSetController {
    fn name(&self) -> &'static str {
        "cpuset"
    }

    fn new_state(&self, _parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        Arc::new(CpuSetState {
            cpus: IrqSafeSpinLock::new(String::new()),
            mems: IrqSafeSpinLock::new(String::new()),
            partition: IrqSafeSpinLock::new(String::from("member")),
        })
    }
}

#[derive(Debug)]
pub struct CpuSetState {
    /// Requested cpu list, e.g. "0-3" (empty = inherit parent).
    cpus: IrqSafeSpinLock<String>,
    mems: IrqSafeSpinLock<String>,
    partition: IrqSafeSpinLock<String>,
}

impl ControllerState for CpuSetState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        let line = |s: &str| {
            let mut o = String::from(s);
            o.push('\n');
            o
        };
        match file {
            "cpuset.cpus" => line(&self.cpus.lock()),
            // SCAFFOLD: effective == requested until parent-intersection
            // is wired.
            "cpuset.cpus.effective" => line(&self.cpus.lock()),
            "cpuset.mems" => line(&self.mems.lock()),
            "cpuset.mems.effective" => line(&self.mems.lock()),
            "cpuset.cpus.partition" => line(&self.partition.lock()),
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        let text = core::str::from_utf8(buf)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        match file {
            "cpuset.cpus" => {
                *self.cpus.lock() = String::from(text);
                Ok(())
            }
            "cpuset.mems" => {
                *self.mems.lock() = String::from(text);
                Ok(())
            }
            "cpuset.cpus.partition" => {
                *self.partition.lock() = String::from(text);
                Ok(())
            }
            _ => Err(FsError::ReadOnly),
        }
    }

    fn writable(&self, file: &str) -> bool {
        matches!(
            file,
            "cpuset.cpus" | "cpuset.mems" | "cpuset.cpus.partition"
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
