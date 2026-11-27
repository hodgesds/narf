//! The most recent refused read-write mount, whatever the filesystem.
//!
//! A filesystem's write gate (btrfs `rw_gate`, ext4 `sb_state`) mounts a
//! filesystem it will not write read-only, or fails a read-write request
//! outright. Under `narf.disks=root-rw` the boot then stops with a banner,
//! and the banner has to say why. The refused mount usually returned an
//! error and left no instance to ask, so each gate records its line here.

use alloc::string::String;

use narf_lib::sync::IrqSafeSpinLock;

static LAST: IrqSafeSpinLock<Option<String>> = IrqSafeSpinLock::new(None);

/// Remember `line`, the gate's full log line (it names the filesystem and
/// the reason).
pub fn record(line: &str) {
    *LAST.lock() = Some(String::from(line));
}

/// The most recent refusal line, if any.
pub fn last() -> Option<String> {
    LAST.lock().clone()
}

#[doc(hidden)]
pub fn __clear_for_test() {
    *LAST.lock() = None;
}
