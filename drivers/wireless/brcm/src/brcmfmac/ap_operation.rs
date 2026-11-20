// SPDX-License-Identifier: GPL-2.0-or-later
//! Dropping an AP control requests terminal cleanup; it does not release a
//! native ID/mapping or leave a forever-busy live BSS after its waiter vanished.
use super::{ap::Session, ap_scope::Epoch};
use crate::cyw43439::runtime::Error;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

pub(super) struct Operation {
    cancelled: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    role: Epoch,
    copy: Epoch,
    armed: bool,
}
impl Operation {
    pub(super) fn finish(mut self) {
        self.armed = false;
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled.store(true, Ordering::Release);
            self.running.store(false, Ordering::Release);
            self.copy.close();
            self.role.close();
        }
    }
}
impl Session {
    pub(super) fn operation(&mut self) -> Result<Operation, Error> {
        self.current()?;
        if self.busy {
            return Err(Error::Busy);
        }
        self.busy = true;
        Ok(Operation {
            cancelled: self.cancelled.clone(),
            running: self.running.clone(),
            role: self.base.role.clone(),
            copy: self.base.copy.clone(),
            armed: true,
        })
    }
}
