//! The module build's loader record (`firmware_source.rs` built in).
//!
//! Built in, the BMI/mission owner retains the exact firmware-registry
//! capabilities of every executable and board input it consumed, plus its
//! PCI grant, and every later native publication runs inside a live
//! invocation of all of them: revoking any one input stops the radio.
//!
//! A module holds no capability. Its firmware arrives as copies through
//! `narf_firmware_open`/`_read`, gated by the module's `Firmware` manifest
//! cap when they are read, and its PCI grant is checked by the kernel on
//! every device export. So this record keeps what can still be kept — the
//! bounded set of consumed names, the image/board flags, the seal (no input
//! after the calibrated download) — and its `invoke` runs an operation only
//! once sealed, while the probed device is still bound. Revocation of an
//! input after it was read is not observable from a `.ko`.
use alloc::{string::String, sync::Arc, vec::Vec};

use crate::ath10k::platform::pci::{BusDeviceCap, Cap, Write};
use crate::ath10k::platform::IrqSafeSpinLock;

const MAX_SOURCES: usize = 8;

/// Why a source operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SourceError {
    /// Not sealed, sealed twice, rebound, or the bounded log is full.
    BadFormat,
    /// No device is bound any more.
    AuthorityRevoked,
    OutOfMemory,
}

pub(super) fn invoke<T>(
    source: Option<&Source>,
    operation: impl FnOnce() -> T,
) -> Result<T, SourceError> {
    match source {
        Some(s) => s.invoke(operation),
        None => {
            let _ = operation;
            Err(SourceError::AuthorityRevoked)
        }
    }
}

struct Records {
    names: Vec<String>,
    image: bool,
    board: bool,
    sealed: bool,
    pci: bool,
}

#[derive(Clone)]
pub(super) struct Source {
    records: Arc<IrqSafeSpinLock<Records>>,
}

impl core::fmt::Debug for Source {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ath10kModuleSource").finish_non_exhaustive()
    }
}

impl Source {
    pub fn new() -> Self {
        Self {
            records: Arc::new(IrqSafeSpinLock::new(Records {
                names: Vec::new(),
                image: false,
                board: false,
                sealed: false,
                pci: false,
            })),
        }
    }

    /// Bind the transport's PCI grant, once, before sealing.
    pub fn bind_pci(&self, cap: Cap<BusDeviceCap, Write>) -> Result<(), SourceError> {
        cap.invoke(crate::ath10k::platform::pci::NoopOp)
            .map_err(|_| SourceError::AuthorityRevoked)?;
        let mut r = self.records.lock();
        if r.sealed || r.pci {
            return Err(SourceError::BadFormat);
        }
        r.pci = true;
        Ok(())
    }

    /// Record one consumed input (an identical re-read is not another).
    pub fn retain(&self, name: &str, image: bool, board: bool) -> Result<(), SourceError> {
        let mut r = self.records.lock();
        if r.sealed {
            return Err(SourceError::BadFormat);
        }
        if !r.names.iter().any(|old| old == name) {
            if r.names.len() == MAX_SOURCES {
                return Err(SourceError::BadFormat);
            }
            let mut owned = String::new();
            owned
                .try_reserve_exact(name.len())
                .map_err(|_| SourceError::OutOfMemory)?;
            owned.push_str(name);
            r.names
                .try_reserve(1)
                .map_err(|_| SourceError::OutOfMemory)?;
            r.names.push(owned);
        }
        r.image |= image;
        r.board |= board;
        Ok(())
    }

    pub fn seal(&self) -> Result<(), SourceError> {
        {
            let mut r = self.records.lock();
            if r.sealed || !r.image || !r.board {
                return Err(SourceError::BadFormat);
            }
            r.sealed = true;
        }
        self.check()
    }

    pub fn check(&self) -> Result<(), SourceError> {
        self.invoke(|| ())
    }

    pub fn invoke<T>(&self, operation: impl FnOnce() -> T) -> Result<T, SourceError> {
        if !self.records.lock().sealed {
            return Err(SourceError::BadFormat);
        }
        self.invoke_boot(operation)
    }

    pub fn invoke_boot<T>(&self, operation: impl FnOnce() -> T) -> Result<T, SourceError> {
        // The lock is dropped before running anything: a publication may
        // re-enter this source.
        if crate::ath10k::platform::device() == 0 {
            return Err(SourceError::AuthorityRevoked);
        }
        Ok(operation())
    }
}
