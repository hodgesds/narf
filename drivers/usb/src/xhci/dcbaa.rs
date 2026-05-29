//! Device Context Base Address Array (xHCI 1.2 §6.1).
//!
//! The DCBAA is a 256-entry array of 64-bit physical pointers. Entry
//! 0 is the Scratchpad Buffer Array Base (when scratchpad buffers are
//! required); entries 1..=MaxSlots point at each slot's Device Context.
//!
//! The array sits at the physical address programmed into DCBAAP. The
//! controller does NOT modify the DCBAA — software writes the device-
//! context address into `dcbaa[slot_id]` BEFORE issuing Address Device
//! so the controller can read the slot's context at command time.

#![allow(dead_code)]

/// DCBAA must hold up to 256 64-bit entries (xHCI §6.1).
pub const DCBAA_ENTRIES: usize = 256;
/// Byte size of the DCBAA.
pub const DCBAA_BYTES: usize = DCBAA_ENTRIES * 8;
/// DCBAAP requires 64-byte alignment (xHCI §6.1).
pub const DCBAA_ALIGN: usize = 64;

/// Encode one DCBAA entry. The encoded value is the 64-byte-aligned
/// physical address of the device context (or scratchpad-buffer-array
/// base for entry 0). xHCI §6.1 requires bits[5:0] zero.
pub const fn encode_entry(dev_ctx_phys: u64) -> u64 {
    dev_ctx_phys & !0x3F
}

/// Encode an entire DCBAA. `slot_ctx_phys[slot_id]` provides the
/// device-context address for each slot (or 0 if the slot is unused).
/// `scratchpad_pa` goes into entry 0.
pub fn encode_array(slot_ctx_phys: &[u64; DCBAA_ENTRIES], scratchpad_pa: u64) -> [u64; DCBAA_ENTRIES] {
    let mut out = [0u64; DCBAA_ENTRIES];
    out[0] = encode_entry(scratchpad_pa);
    let mut i = 1;
    while i < DCBAA_ENTRIES {
        out[i] = encode_entry(slot_ctx_phys[i]);
        i += 1;
    }
    out
}

/// Layout shape verifier — sanity check that the DCBAA is the expected
/// size and meets alignment.
pub const fn is_aligned(phys: u64) -> bool {
    (phys & ((DCBAA_ALIGN as u64) - 1)) == 0
}
