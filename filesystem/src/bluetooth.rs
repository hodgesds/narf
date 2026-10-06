//! Cross-crate broker for the Bluetooth management (mgmt) handler.
//!
//! `narf-bluetooth` owns the mgmt (`HCI_CHANNEL_CONTROL`) protocol logic, but
//! it cannot be a dependency of the userspace socket layer (that would cycle
//! through `narf-audio`). This crate sits below both, so — like the uevent
//! wake hook — `narf-bluetooth` installs its handler here at boot and the
//! socket layer calls it through a function pointer.

use core::sync::atomic::{AtomicUsize, Ordering};

extern crate alloc;
use alloc::vec::Vec;

/// Handler shape: one mgmt command frame in, zero or more reply frames out.
pub type MgmtHandler = fn(&[u8]) -> Vec<Vec<u8>>;

// Stored as `MgmtHandler as usize`; 0 means "not installed".
static MGMT_HANDLER: AtomicUsize = AtomicUsize::new(0);

/// Install the mgmt command handler (`narf_bluetooth::mgmt::handle`). Called
/// once during Bluetooth bring-up.
pub fn install_mgmt_handler(f: MgmtHandler) {
    MGMT_HANDLER.store(f as usize, Ordering::Release);
}

/// Dispatch a mgmt command frame to the installed handler, returning its
/// reply frames. `None` if no Bluetooth stack has registered a handler.
pub fn mgmt_handle(command: &[u8]) -> Option<Vec<Vec<u8>>> {
    let h = MGMT_HANDLER.load(Ordering::Acquire);
    if h == 0 {
        return None;
    }
    // SAFETY: only ever stored as `MgmtHandler as usize` by install_mgmt_handler.
    let f: MgmtHandler = unsafe { core::mem::transmute::<usize, MgmtHandler>(h) };
    Some(f(command))
}
