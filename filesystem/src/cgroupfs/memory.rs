//! `memory` controller — memory accounting + limits.
//!
//! SCAFFOLD: presents the full v2 memory interface with zero usage and
//! accepts limit writes. Real charge/uncharge accounting (wired to the
//! page/frame allocator via a hook installed into `narf-memory`) and
//! `memory.max`/OOM enforcement land in the controller-implementation
//! pass.
//!
//! Linux ref: `mm/memcontrol.c`,
//! `Documentation/admin-guide/cgroup-v2.rst` §"Memory".

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &[
    "memory.current",
    "memory.peak",
    "memory.min",
    "memory.low",
    "memory.high",
    "memory.max",
    "memory.events",
    "memory.events.local",
    "memory.stat",
    "memory.swap.current",
    "memory.swap.max",
];

#[derive(Debug)]
pub struct MemoryController;

impl Controller for MemoryController {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn new_state(&self, _parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        Arc::new(MemoryState {
            current: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            swap_current: AtomicU64::new(0),
            min: IrqSafeSpinLock::new(0),
            low: IrqSafeSpinLock::new(0),
            high: IrqSafeSpinLock::new(None),
            max: IrqSafeSpinLock::new(None),
            swap_max: IrqSafeSpinLock::new(None),
        })
    }
}

#[derive(Debug)]
pub struct MemoryState {
    current: AtomicU64,
    peak: AtomicU64,
    swap_current: AtomicU64,
    min: IrqSafeSpinLock<u64>,
    low: IrqSafeSpinLock<u64>,
    /// `None` = "max".
    high: IrqSafeSpinLock<Option<u64>>,
    max: IrqSafeSpinLock<Option<u64>>,
    swap_max: IrqSafeSpinLock<Option<u64>>,
}

fn max_line(v: &Option<u64>) -> String {
    match v {
        None => "max\n".into(),
        Some(n) => format!("{n}\n"),
    }
}

fn parse_limit(buf: &[u8]) -> Result<Option<u64>, FsError> {
    let t = core::str::from_utf8(buf)
        .map_err(|_| FsError::InvalidData)?
        .trim();
    if t == "max" {
        Ok(None)
    } else {
        t.parse::<u64>().map(Some).map_err(|_| FsError::InvalidData)
    }
}

fn parse_u64(buf: &[u8]) -> Result<u64, FsError> {
    core::str::from_utf8(buf)
        .map_err(|_| FsError::InvalidData)?
        .trim()
        .parse::<u64>()
        .map_err(|_| FsError::InvalidData)
}

impl ControllerState for MemoryState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        match file {
            "memory.current" => format!("{}\n", self.current.load(Ordering::Acquire)),
            "memory.peak" => format!("{}\n", self.peak.load(Ordering::Acquire)),
            "memory.min" => format!("{}\n", *self.min.lock()),
            "memory.low" => format!("{}\n", *self.low.lock()),
            "memory.high" => max_line(&self.high.lock()),
            "memory.max" => max_line(&self.max.lock()),
            "memory.swap.current" => format!("{}\n", self.swap_current.load(Ordering::Acquire)),
            "memory.swap.max" => max_line(&self.swap_max.lock()),
            "memory.events" => "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n".into(),
            "memory.events.local" => {
                "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n".into()
            }
            "memory.stat" => "anon 0\nfile 0\nkernel 0\nslab 0\nsock 0\n".into(),
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        match file {
            "memory.min" => {
                *self.min.lock() = parse_u64(buf)?;
                Ok(())
            }
            "memory.low" => {
                *self.low.lock() = parse_u64(buf)?;
                Ok(())
            }
            "memory.high" => {
                *self.high.lock() = parse_limit(buf)?;
                Ok(())
            }
            "memory.max" => {
                *self.max.lock() = parse_limit(buf)?;
                Ok(())
            }
            "memory.swap.max" => {
                *self.swap_max.lock() = parse_limit(buf)?;
                Ok(())
            }
            _ => Err(FsError::ReadOnly),
        }
    }

    fn writable(&self, file: &str) -> bool {
        matches!(
            file,
            "memory.min" | "memory.low" | "memory.high" | "memory.max" | "memory.swap.max"
        )
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
