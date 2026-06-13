//! `cpu` controller — CPU weight + bandwidth.
//!
//! SCAFFOLD: presents the v2 cpu interface with default weight and
//! unlimited bandwidth, and accepts writes. Mapping weight→scheduler
//! priority and `cpu.max` quota/period→bandwidth throttling (via hooks
//! installed into `narf-scheduler`) lands in the controller pass.
//!
//! Linux ref: `kernel/sched/core.c` (cgroup hooks),
//! `Documentation/admin-guide/cgroup-v2.rst` §"CPU".

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &[
    "cpu.stat",
    "cpu.weight",
    "cpu.weight.nice",
    "cpu.max",
    "cpu.max.burst",
    "cpu.idle",
];

#[derive(Debug)]
pub struct CpuController;

impl Controller for CpuController {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn new_state(&self, _parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        Arc::new(CpuState {
            weight: IrqSafeSpinLock::new(100),
            // `cpu.max`: (quota, period); None quota = "max".
            quota: IrqSafeSpinLock::new(None),
            period: IrqSafeSpinLock::new(100_000),
            burst: IrqSafeSpinLock::new(0),
            idle: IrqSafeSpinLock::new(0),
        })
    }
}

#[derive(Debug)]
pub struct CpuState {
    weight: IrqSafeSpinLock<u64>,
    quota: IrqSafeSpinLock<Option<u64>>,
    period: IrqSafeSpinLock<u64>,
    burst: IrqSafeSpinLock<u64>,
    idle: IrqSafeSpinLock<u64>,
}

/// `cpu.weight` (1..=10000) ↔ nice (-20..=19). Linux's mapping.
fn weight_to_nice(weight: u64) -> i64 {
    // weight = 1024 >> nice-ish; use Linux's table midpoint approx.
    // Default weight 100 ↔ nice 0.
    let w = weight.clamp(1, 10000) as i64;
    // Coarse inverse of the kernel's sched_prio_to_weight table.
    (((10000 - w) * 39) / 9999) - 20
}

impl ControllerState for CpuState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        match file {
            "cpu.stat" => {
                "usage_usec 0\nuser_usec 0\nsystem_usec 0\nnr_periods 0\nnr_throttled 0\nthrottled_usec 0\n".into()
            }
            "cpu.weight" => format!("{}\n", *self.weight.lock()),
            "cpu.weight.nice" => format!("{}\n", weight_to_nice(*self.weight.lock())),
            "cpu.max" => {
                let q = self.quota.lock();
                let p = *self.period.lock();
                match *q {
                    None => format!("max {p}\n"),
                    Some(quota) => format!("{quota} {p}\n"),
                }
            }
            "cpu.max.burst" => format!("{}\n", *self.burst.lock()),
            "cpu.idle" => format!("{}\n", *self.idle.lock()),
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        let text = core::str::from_utf8(buf)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        match file {
            "cpu.weight" => {
                let w = text.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                if !(1..=10000).contains(&w) {
                    return Err(FsError::InvalidData);
                }
                *self.weight.lock() = w;
                Ok(())
            }
            "cpu.max" => {
                // "<quota|max> [period]"
                let mut parts = text.split_whitespace();
                let quota = parts.next().ok_or(FsError::InvalidData)?;
                if let Some(p) = parts.next() {
                    *self.period.lock() = p.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                }
                *self.quota.lock() = if quota == "max" {
                    None
                } else {
                    Some(quota.parse::<u64>().map_err(|_| FsError::InvalidData)?)
                };
                Ok(())
            }
            "cpu.max.burst" => {
                *self.burst.lock() = text.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                Ok(())
            }
            "cpu.idle" => {
                *self.idle.lock() = text.parse::<u64>().map_err(|_| FsError::InvalidData)?;
                Ok(())
            }
            _ => Err(FsError::ReadOnly),
        }
    }

    fn writable(&self, file: &str) -> bool {
        matches!(
            file,
            "cpu.weight" | "cpu.weight.nice" | "cpu.max" | "cpu.max.burst" | "cpu.idle"
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
