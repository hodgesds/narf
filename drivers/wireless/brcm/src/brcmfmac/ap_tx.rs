// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual AP transport completion ownership. Msgbuf retires matching native
//! DMA IDs; SDPCM PIO finishes the actual copied host buffer. Neither receipt
//! independently proves an over-air ACK or firmware MAC/FIFO quiescence.
use super::{ap_scope::Capture, runtime::TxReceipt};
use crate::cyw43439::runtime::Error;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicU16, AtomicU8, Ordering};

pub(super) struct Terminal {
    state: AtomicU8,
    status: AtomicU16,
}
impl Terminal {
    pub(super) fn complete(&self, receipt: TxReceipt) {
        self.status.store(receipt.status, Ordering::Relaxed);
        // Only Adapter::progress, after Runtime consumed the exact original
        // request/flow terminal and retired its DMA, can publish this receipt.
        self.state.store(1, Ordering::Release);
    }
}
/// Private native ownership comes from an actual published ID, never a wire
/// cookie. Dropping this waiter drops no DMA and provides no completion credit.
/// The retained adapter continues to own its original TX ID and timeout.
pub struct Ticket {
    id: u32,
    terminal: Arc<Terminal>,
    original: Capture,
}
impl core::fmt::Debug for Ticket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FullmacApTxTicket")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}
impl Ticket {
    pub(super) fn new(id: u32, original: Capture) -> (Self, Weak<Terminal>) {
        let terminal = Arc::new(Terminal {
            state: AtomicU8::new(0),
            status: AtomicU16::new(0),
        });
        let owned = Arc::downgrade(&terminal);
        (
            Self {
                id,
                terminal,
                original,
            },
            owned,
        )
    }
    /// Producer is the actual synchronous native SDPCM PIO owner, only
    /// after every source-qualified split transfer completed. This host
    /// operation ID is not a fabricated firmware TXSTATUS/DMA ID or ACK.
    pub(crate) fn pio_copied(id: u32, original: Capture) -> Self {
        Self {
            id,
            terminal: Arc::new(Terminal {
                state: AtomicU8::new(2),
                status: AtomicU16::new(0),
            }),
            original,
        }
    }
    /// A terminal result says nothing about ACK. Unsupported ACK reporting
    /// remains unadvertised even when this actual DMA terminal succeeds.
    pub(crate) fn terminal(&self) -> Result<bool, Error> {
        self.original.current().map_err(|_| Error::Authority)?;
        if self.terminal.state.load(Ordering::Acquire) == 0 {
            return Ok(false);
        }
        let status = self.terminal.status.load(Ordering::Relaxed);
        if status == 0 {
            Ok(true)
        } else {
            Err(Error::Firmware(u32::from(status)))
        }
    }
}
pub(super) struct Owner {
    pub(super) original: Capture,
}
impl Owner {
    pub(super) fn admits(&self, original: &Capture) -> Result<(), Error> {
        if !self.original.same_role(original) {
            return Err(Error::Authority);
        }
        self.original.role_current().map_err(|_| Error::Authority)?;
        original.current().map_err(|_| Error::Authority)
    }
}
