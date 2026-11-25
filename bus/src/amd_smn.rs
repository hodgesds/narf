//! AMD System Management Network (SMN) access through the root complex.
//!
//! The SMN is the SoC's internal register space (SMU, thermal, data
//! fabric). The host reaches it through an index/data pair in the root
//! complex's (`00:00.0`) config space: write the SMN address to `0x60`,
//! read the value at `0x64`. The pair is one shared resource, so every
//! user goes through [`read`], which holds one global lock across the
//! whole transaction — Linux `amd_smn_read` and its `smn_mutex`
//! (arch/x86/kernel/amd_node.c).
//!
//! An all-ones result is how the bridge reports a failed access; it is
//! returned as `None` (Linux `amd_smn_read` returns `-ENODEV` for it).

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

/// Config-space offset of the SMN index register.
pub const SMN_INDEX: u64 = 0x60;
/// Config-space offset of the SMN data register.
pub const SMN_DATA: u64 = 0x64;

/// Serialises the index/data pair. No allocation, callback or wait
/// happens while it is held.
static SMN_LOCK: IrqSafeSpinLock<()> = IrqSafeSpinLock::new(());

/// Read SMN address `address` through the root complex whose config
/// window starts at `root_cfg`. `None` when the window is not mapped or
/// unaligned, or the read returns all-ones.
pub fn read(root_cfg: PhysAddr, address: u32) -> Option<u32> {
    if root_cfg.raw() & 0xfff != 0 {
        return None;
    }
    let index = crate::ecam::ptr_for(root_cfg, SMN_INDEX)? as *mut u32;
    let data = crate::ecam::ptr_for(root_cfg, SMN_DATA)? as *const u32;
    // The whole data word must be mapped before it is dereferenced.
    crate::ecam::ptr_for(root_cfg, SMN_DATA + 3)?;
    let value = {
        let _guard = SMN_LOCK.lock();
        // SAFETY: both aligned words lie within the root complex's live
        // ECAM mapping; SMN_LOCK serialises the index/data transaction
        // against every other SMN user.
        unsafe {
            core::ptr::write_volatile(index, address);
            core::ptr::read_volatile(data)
        }
    };
    (value != u32::MAX).then_some(value)
}
