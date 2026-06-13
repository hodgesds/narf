//! `io` controller — block-I/O weight + throttling.
//!
//! SCAFFOLD: presents the v2 io interface (empty per-device stats,
//! default weight) and accepts `io.max` / `io.weight` writes. Wiring
//! per-device accounting + bps/iops throttling to the block layer
//! (`narf-block` submit hook, attributing requests to the submitting
//! task's cgroup) lands in the controller pass.
//!
//! Linux ref: `block/blk-cgroup.c`,
//! `Documentation/admin-guide/cgroup-v2.rst` §"IO".

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use core::any::Any;

use narf_lib::sync::IrqSafeSpinLock;

use super::controller::{Controller, ControllerState};
use crate::FsError;

const FILES: &[&str] = &["io.stat", "io.max", "io.weight"];

#[derive(Debug)]
pub struct IoController;

impl Controller for IoController {
    fn name(&self) -> &'static str {
        "io"
    }

    fn new_state(&self, _parent: Option<Arc<dyn ControllerState>>) -> Arc<dyn ControllerState> {
        Arc::new(IoState {
            weight: IrqSafeSpinLock::new(100),
        })
    }
}

#[derive(Debug)]
pub struct IoState {
    /// Default per-cgroup weight (1..=10000).
    weight: IrqSafeSpinLock<u64>,
}

impl ControllerState for IoState {
    fn files(&self) -> &'static [&'static str] {
        FILES
    }

    fn read(&self, file: &str) -> String {
        match file {
            // No per-device stats tracked yet.
            "io.stat" => String::new(),
            "io.max" => String::new(),
            "io.weight" => format!("default {}\n", *self.weight.lock()),
            _ => String::new(),
        }
    }

    fn write(&self, file: &str, buf: &[u8]) -> Result<(), FsError> {
        let text = core::str::from_utf8(buf)
            .map_err(|_| FsError::InvalidData)?
            .trim();
        match file {
            "io.weight" => {
                // Accept "default <n>" or bare "<n>".
                let n = text
                    .split_whitespace()
                    .last()
                    .ok_or(FsError::InvalidData)?
                    .parse::<u64>()
                    .map_err(|_| FsError::InvalidData)?;
                if !(1..=10000).contains(&n) {
                    return Err(FsError::InvalidData);
                }
                *self.weight.lock() = n;
                Ok(())
            }
            // SCAFFOLD: accept io.max writes (per-device limits) without
            // enforcing yet.
            "io.max" => Ok(()),
            _ => Err(FsError::ReadOnly),
        }
    }

    fn writable(&self, file: &str) -> bool {
        matches!(file, "io.max" | "io.weight")
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}
