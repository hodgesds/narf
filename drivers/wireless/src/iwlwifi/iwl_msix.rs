//! iwlwifi MSI-X cause routing.
//!
//! gen2 and gen3 iwlwifi chips expose up to 32 MSI-X vectors, each
//! tied to a logical "cause" — TX done on queue N, RX queue N
//! writeback, FW ALIVE, FW error, etc. The driver writes one byte
//! per cause into the MSI-X cause map; the byte names the vector
//! the cause should fire on.
//!
//! For the bring-up data path we coalesce most causes onto a small
//! number of vectors:
//!
//!   vector 0  → ALIVE + FH_RX (default RX queue)
//!   vector 1  → FH_TX (default TX queue completions)
//!   vector 2  → SW_ERR / HW_ERR / fatal causes
//!
//! Linux's `pcie/rx.c::iwl_pcie_init_msix_handler` uses up to one
//! vector per RX queue when many queues are configured; in the
//! single-queue bring-up case it collapses to the layout above.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `drivers/net/wireless/intel/iwlwifi/iwl-csr.h` —
//!   CSR_MSIX_* register offsets.
//! - `drivers/net/wireless/intel/iwlwifi/pcie/internal.h` —
//!   `iwl_pcie_isr_t`, MSIX_HW_INT_CAUSES / MSIX_FH_INT_CAUSES.
//! - `drivers/net/wireless/intel/iwlwifi/pcie/rx.c` —
//!   `iwl_pcie_init_msix_handler`.

#![allow(dead_code)]

use super::regs;
use super::transport::IwlMmio;

// ── MSI-X CSR offsets (BAR0-relative) ──────────────────────────────
// Sourced from `iwl-csr.h`.

/// MSI-X FH (Flow Handler) interrupt cause masks.
pub const CSR_MSIX_FH_INT_CAUSES_AD: u32 = 0x0800;
/// MSI-X FH interrupt mask.
pub const CSR_MSIX_FH_INT_MASK_AD: u32 = 0x0804;
/// MSI-X HW (hardware) interrupt cause masks.
pub const CSR_MSIX_HW_INT_CAUSES_AD: u32 = 0x0808;
/// MSI-X HW interrupt mask.
pub const CSR_MSIX_HW_INT_MASK_AD: u32 = 0x080C;
/// Per-cause to-vector lookup base. Each cause is one byte; the byte
/// names the MSI-X vector to fire. Causes are at fixed indices.
pub const CSR_MSIX_IVAR_AD_REG: u32 = 0x0880;
/// PCIe DMA channel cause IVAR table (32 bytes covering causes
/// 0..32). Identical layout to the FH/HW IVAR but split per
/// per-device sub-table.
pub const CSR_MSIX_PENDING_PBA: u32 = 0x0810;
/// Acknowledgment of automask. Writing the bit re-arms the vector.
pub const CSR_MSIX_AUTOMASK_ST_AD: u32 = 0x0814;
/// Vector enable: setting bit N un-masks vector N.
pub const CSR_MSIX_RFH_INT_PERIODIC: u32 = 0x0848;

// ── Cause identifiers ──────────────────────────────────────────────
//
// Indices into the MSIX_IVAR table. Sourced from Linux's
// `MSIX_FH_INT_CAUSES_Q*` / `MSIX_HW_INT_CAUSES_REG_*` enums.

/// FH causes: RX queue 0 packet ready.
pub const CAUSE_FH_RX_Q0: u8 = 0;
/// FH causes: RX queue 1 packet ready.
pub const CAUSE_FH_RX_Q1: u8 = 1;
/// FH causes: TX done (legacy non-MQ path).
pub const CAUSE_FH_TX: u8 = 27;

/// HW cause: firmware ALIVE.
pub const CAUSE_HW_ALIVE: u8 = 0;
/// HW cause: wakeup from sleep.
pub const CAUSE_HW_WAKEUP: u8 = 1;
/// HW cause: RF-kill switch.
pub const CAUSE_HW_RF_KILL: u8 = 7;
/// HW cause: CT-kill (thermal).
pub const CAUSE_HW_CT_KILL: u8 = 6;
/// HW cause: software error.
pub const CAUSE_HW_SW_ERR: u8 = 25;
/// HW cause: scheduler interrupt.
pub const CAUSE_HW_SCD: u8 = 26;
/// HW cause: periodic RX poll.
pub const CAUSE_HW_RX_PERIODIC: u8 = 28;
/// HW cause: hardware fatal error.
pub const CAUSE_HW_HW_ERR: u8 = 29;

// ── Vector assignment ──────────────────────────────────────────────

/// Vectors used by the bring-up data path. Vector 0 carries ALIVE
/// and the default RX queue; vector 1 carries TX completions;
/// vector 2 carries fatal-error causes.
pub const VECTOR_RX_ALIVE: u8 = 0;
pub const VECTOR_TX: u8 = 1;
pub const VECTOR_ERR: u8 = 2;

/// Mapping from cause index to vector. Used to drive `set_ivar`
/// during bring-up.
#[allow(missing_debug_implementations)] // TODO(narf): no Debug impl yet
pub struct CauseMap {
    pub cause: u8,
    pub vector: u8,
}

/// Canonical bring-up cause table for single-queue operation.
pub const DEFAULT_CAUSE_TABLE: &[CauseMap] = &[
    // FH causes — written into IVAR_AD_REG[0..32].
    CauseMap {
        cause: CAUSE_FH_RX_Q0,
        vector: VECTOR_RX_ALIVE,
    },
    CauseMap {
        cause: CAUSE_FH_TX,
        vector: VECTOR_TX,
    },
];

/// HW causes table (separate sub-table; offsets above IVAR_AD_REG).
pub const DEFAULT_HW_CAUSE_TABLE: &[CauseMap] = &[
    CauseMap {
        cause: CAUSE_HW_ALIVE,
        vector: VECTOR_RX_ALIVE,
    },
    CauseMap {
        cause: CAUSE_HW_WAKEUP,
        vector: VECTOR_RX_ALIVE,
    },
    CauseMap {
        cause: CAUSE_HW_RF_KILL,
        vector: VECTOR_ERR,
    },
    CauseMap {
        cause: CAUSE_HW_CT_KILL,
        vector: VECTOR_ERR,
    },
    CauseMap {
        cause: CAUSE_HW_SW_ERR,
        vector: VECTOR_ERR,
    },
    CauseMap {
        cause: CAUSE_HW_HW_ERR,
        vector: VECTOR_ERR,
    },
];

// ── Programming helpers ────────────────────────────────────────────

/// Write one IVAR byte. The IVAR table is byte-addressable but the
/// MMIO surface is 32-bit; we read-modify-write the containing dword.
///
/// `table_base` is `CSR_MSIX_IVAR_AD_REG` (FH causes) or
/// `CSR_MSIX_IVAR_AD_REG + 0x20` (HW causes).
pub fn set_ivar<M: IwlMmio>(mmio: &mut M, table_base: u32, cause: u8, vector: u8) {
    let dword_off = table_base + (cause as u32 & !0x3);
    let shift = (cause as u32 & 0x3) * 8;
    let cur = mmio.read(dword_off);
    let masked = cur & !(0xFFu32 << shift);
    // Linux sets bit 7 ("MSIX_IVAR_VALID") to mark the byte live.
    let val = (vector as u32 | 0x80) << shift;
    mmio.write(dword_off, masked | val);
}

/// Program the default cause-to-vector map and clear cause masks so
/// every wired cause is delivered to its assigned vector.
///
/// Caller is responsible for actually allocating + arming the MSI-X
/// vectors at the PCI capability level (see `bus::msix`); this
/// function only programs the iwlwifi-side BAR0 cause table.
pub fn program_default_causes<M: IwlMmio>(mmio: &mut M) {
    // FH causes — IVAR sub-table starts at CSR_MSIX_IVAR_AD_REG.
    for cm in DEFAULT_CAUSE_TABLE {
        set_ivar(mmio, CSR_MSIX_IVAR_AD_REG, cm.cause, cm.vector);
    }
    // HW causes — sub-table starts at IVAR_AD_REG + 0x20.
    for cm in DEFAULT_HW_CAUSE_TABLE {
        set_ivar(mmio, CSR_MSIX_IVAR_AD_REG + 0x20, cm.cause, cm.vector);
    }

    // Clear both cause masks so all wired causes deliver. Linux uses
    // ~0u32 + selective masking later for queues we don't drive.
    let mut fh_mask = !0u32;
    for cm in DEFAULT_CAUSE_TABLE {
        fh_mask &= !(1u32 << cm.cause);
    }
    let mut hw_mask = !0u32;
    for cm in DEFAULT_HW_CAUSE_TABLE {
        hw_mask &= !(1u32 << cm.cause);
    }
    mmio.write(CSR_MSIX_FH_INT_MASK_AD, fh_mask);
    mmio.write(CSR_MSIX_HW_INT_MASK_AD, hw_mask);
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct MockMmio {
        writes: alloc::vec::Vec<(u32, u32)>,
        regs: alloc::collections::BTreeMap<u32, u32>,
    }
    impl MockMmio {
        fn new() -> Self {
            Self {
                writes: alloc::vec::Vec::new(),
                regs: alloc::collections::BTreeMap::new(),
            }
        }
    }
    impl IwlMmio for MockMmio {
        fn read(&mut self, off: u32) -> u32 {
            *self.regs.get(&off).unwrap_or(&0)
        }
        fn write(&mut self, off: u32, val: u32) {
            self.regs.insert(off, val);
            self.writes.push((off, val));
        }
    }

    // set_ivar packs the right byte into the right dword position
    // with the VALID bit set.
    fn smoke_iwlwifi_msix_set_ivar_byte_packing() -> TestResult {
        let mut mmio = MockMmio::new();
        // Cause 1 → vector 5. cause&3 = 1 → shift = 8.
        // VALID(0x80) | 5 = 0x85, shifted left 8 = 0x8500.
        set_ivar(&mut mmio, CSR_MSIX_IVAR_AD_REG, 1, 5);
        let val = mmio.read(CSR_MSIX_IVAR_AD_REG);
        if val != 0x0000_8500 {
            return TestResult::Fail("cause 1 IVAR packing wrong");
        }

        // Now program cause 3 → vector 2 in the same dword.
        // cause&3 = 3 → shift = 24. VALID|2 = 0x82, shifted = 0x8200_0000.
        set_ivar(&mut mmio, CSR_MSIX_IVAR_AD_REG, 3, 2);
        let val = mmio.read(CSR_MSIX_IVAR_AD_REG);
        if val != 0x8200_8500 {
            return TestResult::Fail("two-byte IVAR merge wrong");
        }
        TestResult::Pass
    }

    // Default cause table programs masks that leave the wired
    // causes un-masked (bit cleared).
    fn smoke_iwlwifi_msix_default_program_masks() -> TestResult {
        let mut mmio = MockMmio::new();
        program_default_causes(&mut mmio);

        let fh_mask = mmio.read(CSR_MSIX_FH_INT_MASK_AD);
        // FH_RX_Q0 (bit 0) and FH_TX (bit 27) must be CLEARED.
        if fh_mask & (1u32 << CAUSE_FH_RX_Q0) != 0 {
            return TestResult::Fail("FH_RX_Q0 should be unmasked");
        }
        if fh_mask & (1u32 << CAUSE_FH_TX) != 0 {
            return TestResult::Fail("FH_TX should be unmasked");
        }

        let hw_mask = mmio.read(CSR_MSIX_HW_INT_MASK_AD);
        if hw_mask & (1u32 << CAUSE_HW_ALIVE) != 0 {
            return TestResult::Fail("HW_ALIVE should be unmasked");
        }
        if hw_mask & (1u32 << CAUSE_HW_SW_ERR) != 0 {
            return TestResult::Fail("HW_SW_ERR should be unmasked");
        }
        TestResult::Pass
    }

    // Each cause in the default table maps to a known vector.
    fn smoke_iwlwifi_msix_cause_table_assignments() -> TestResult {
        let mut rx_seen = false;
        let mut tx_seen = false;
        for cm in DEFAULT_CAUSE_TABLE {
            if cm.cause == CAUSE_FH_RX_Q0 && cm.vector == VECTOR_RX_ALIVE {
                rx_seen = true;
            }
            if cm.cause == CAUSE_FH_TX && cm.vector == VECTOR_TX {
                tx_seen = true;
            }
        }
        if !rx_seen || !tx_seen {
            return TestResult::Fail("cause table missing entries");
        }
        let mut alive_seen = false;
        let mut err_seen = false;
        for cm in DEFAULT_HW_CAUSE_TABLE {
            if cm.cause == CAUSE_HW_ALIVE && cm.vector == VECTOR_RX_ALIVE {
                alive_seen = true;
            }
            if cm.cause == CAUSE_HW_SW_ERR && cm.vector == VECTOR_ERR {
                err_seen = true;
            }
        }
        if !alive_seen || !err_seen {
            return TestResult::Fail("HW cause table missing entries");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi/msix",
        smoke_iwlwifi_msix_set_ivar_byte_packing
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/msix",
        smoke_iwlwifi_msix_default_program_masks
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/msix",
        smoke_iwlwifi_msix_cause_table_assignments
    );

    extern crate alloc;
}

// Re-export the regs alias to silence unused-import lints when not
// in test mode.
#[allow(unused_imports)]
use regs as _regs;
