//! iwlwifi register-offset constants.
//!
//! All offsets relative to the device's BAR0 mapping (CSRs) or
//! the PRPH/FH register spaces accessed *through* CSRs via the
//! HBUS_TARG_* indirect-access registers.
//!
//! Sourced from Linux `drivers/net/wireless/intel/iwlwifi/iwl-csr.h`,
//! `iwl-prph.h`, and `iwl-fh.h` (kernel 6.10+).

#![allow(dead_code)]

// ── CSR — directly-mapped registers (BAR0 + offset) ────────────────

/// Hardware interface configuration. Encodes the platform's
/// power-saving + bus-arbitration model. Set early in `apm_init`.
pub const CSR_HW_IF_CONFIG_REG: u32 = 0x000;
/// Interrupt coalescing — number of interrupts per ms before
/// the device starts batching.
pub const CSR_INT_COALESCING: u32 = 0x004;
/// Pending interrupt status. Read-and-clear by writing the bits
/// back to it. Driver's MSI handler reads this first.
pub const CSR_INT: u32 = 0x008;
/// Interrupt-mask register. Bit set = enabled.
pub const CSR_INT_MASK: u32 = 0x00C;
/// Flow-handler interrupt status. Read on every IRQ to find which
/// DMA channel completed.
pub const CSR_FH_INT_STATUS: u32 = 0x010;
/// GPIO input register — reads platform-wired switches (RF-kill
/// switch lives here).
pub const CSR_GPIO_IN: u32 = 0x018;
/// Reset. Setting bit 7 holds the device in reset; clearing it
/// (after firmware load) starts the embedded CPU.
pub const CSR_RESET: u32 = 0x020;
/// General-purpose control. Carries the `MAC_INIT` request +
/// `MAC_CLOCK_READY` ack handshake, and the `NIC_SLEEP`
/// power-saving bit.
pub const CSR_GP_CNTRL: u32 = 0x024;
/// Hardware revision. Used to identify the silicon variant.
pub const CSR_HW_REV: u32 = 0x028;
/// Function-scratch — driver-private 32-bit scratch the device
/// preserves across resets.
pub const CSR_FUNC_SCRATCH: u32 = 0x02C;
/// EEPROM register window.
pub const CSR_EEPROM_REG: u32 = 0x02C;
/// GP1 — driver→firmware general-purpose. Driver writes things
/// like RFKILL state here. The CPU reads it from inside the
/// firmware.
pub const CSR_UCODE_DRV_GP1: u32 = 0x054;
/// GP2 — firmware→driver general-purpose. Mostly used for legacy
/// status bits.
pub const CSR_UCODE_DRV_GP2: u32 = 0x060;
/// Last "active" status word the host wrote. Driver sets to
/// `0xFFFFFFFF` after a gen2 load completes (see `transport.rs`).
pub const CSR_GIO_REG: u32 = 0x03C;

/// CSR_RESET bits.
pub mod csr_reset {
    /// "Hold device in reset". Set during `apm_init`, cleared at
    /// the end of load to start the firmware.
    pub const NEVO_RESET: u32 = 1 << 0;
    /// Force NMI. Used by the watchdog path to dump error logs.
    pub const FORCE_NMI: u32 = 1 << 1;
    /// Software-controlled reset. Sticky until cleared.
    pub const SW_RESET: u32 = 1 << 7;
    /// Master disable. Asserted while reprogramming the FH.
    pub const MASTER_DISABLED: u32 = 1 << 8;
    /// "Stop the device". Set when the driver is unbinding.
    pub const STOP_MASTER: u32 = 1 << 9;
}

/// CSR_GP_CNTRL bits.
pub mod csr_gp_cntrl {
    /// Host requests the MAC come out of sleep. Driver sets this
    /// in `apm_init`, then polls `MAC_CLOCK_READY`.
    pub const MAC_INIT: u32 = 1 << 2;
    /// Device acknowledges the wake — clock is up.
    pub const MAC_CLOCK_READY: u32 = 1 << 0;
    /// Request the MAC enter sleep.
    pub const NIC_SLEEP: u32 = 1 << 1;
    /// MAC access disabled (driver should not poke the device).
    pub const MAC_ACCESS_DISABLED: u32 = 1 << 4;
}

/// CSR_HW_IF_CONFIG_REG bits.
pub mod csr_hw_if_config {
    /// EEPROM ownership requested by the host.
    pub const EEPROM_OWN: u32 = 1 << 21;
    /// PCIe link is in L0 (active).
    pub const NIC_READY: u32 = 1 << 22;
    /// "I/O fusion pending" — set during ALIVE rendezvous.
    pub const IOFUSION_PENDING: u32 = 1 << 23;
    /// Persistence bit so device retains state across resets.
    pub const PERSISTENCE: u32 = 1 << 25;
}

/// CSR_INT bits (subset).
pub mod csr_int {
    pub const ALIVE: u32 = 1 << 0;
    pub const WAKEUP: u32 = 1 << 1;
    pub const SW_RX: u32 = 1 << 3;
    pub const CT_KILL: u32 = 1 << 6;
    pub const RF_KILL: u32 = 1 << 7;
    pub const SW_ERR: u32 = 1 << 25;
    pub const SCD: u32 = 1 << 26;
    pub const FH_TX: u32 = 1 << 27;
    pub const RX_PERIODIC: u32 = 1 << 28;
    pub const HW_ERR: u32 = 1 << 29;
    pub const FH_RX: u32 = 1 << 31;
}

/// `CSR_INI_SET_MASK` — the mask the driver writes after
/// `apm_init` to enable the structurally-essential interrupts.
pub const CSR_INI_SET_MASK: u32 = csr_int::HW_ERR
    | csr_int::SW_ERR
    | csr_int::RF_KILL
    | csr_int::CT_KILL
    | csr_int::SW_RX
    | csr_int::WAKEUP
    | csr_int::ALIVE
    | csr_int::FH_RX;

// ── gen2 (AX200/AX201) — flow-handler DMA paths ────────────────────

/// Service-channel base. The "service" channel is the one the
/// driver uses for direct-DMA firmware section loads (other FH
/// channels carry runtime TX traffic and aren't used during boot).
pub const FH_SRVC_CHNL: u32 = 9;
/// FH service-channel register-base offset.
pub const FH_MEM_LOWER_BOUND_GEN2: u32 = 0x1000;

/// `FH_TCSR_CHNL_TX_CONFIG_REG(SRVC)` — channel config / pause
/// register. Driver pauses the channel before reprogramming.
pub const FH_TCSR_CHNL_TX_CONFIG_REG_SRVC: u32 =
    FH_MEM_LOWER_BOUND_GEN2 + 0x100 + FH_SRVC_CHNL * 0x20;
/// `FH_TCSR_CHNL_TX_BUF_STS_REG(SRVC)` — validate/kick. Writing
/// the "valid" bit kicks the DMA.
pub const FH_TCSR_CHNL_TX_BUF_STS_REG_SRVC: u32 =
    FH_MEM_LOWER_BOUND_GEN2 + 0x108 + FH_SRVC_CHNL * 0x20;
/// `FH_SRVC_CHNL_SRAM_ADDR_REG(SRVC)` — destination address
/// (device-internal SRAM) for the next DMA.
pub const FH_SRVC_CHNL_SRAM_ADDR_REG_SRVC: u32 =
    FH_MEM_LOWER_BOUND_GEN2 + 0x180 + FH_SRVC_CHNL * 0x4;
/// `FH_TFDIB_CTRL0_REG(SRVC)` — host phys, low 32 bits.
pub const FH_TFDIB_CTRL0_REG_SRVC: u32 =
    FH_MEM_LOWER_BOUND_GEN2 + 0x900 + FH_SRVC_CHNL * 0x8;
/// `FH_TFDIB_CTRL1_REG(SRVC)` — host phys high 32 bits (low
/// nibble) packed with the byte count.
pub const FH_TFDIB_CTRL1_REG_SRVC: u32 =
    FH_MEM_LOWER_BOUND_GEN2 + 0x904 + FH_SRVC_CHNL * 0x8;

/// CTRL1 packing helper: 4 high bits of phys go into bits 28-31
/// of CTRL1; byte count lives in bits 0-19.
pub const fn fh_tfdib_ctrl1(phys_hi_nibble: u32, byte_count: u32) -> u32 {
    ((phys_hi_nibble & 0xF) << 28) | (byte_count & 0x000F_FFFF)
}

/// Bit the driver sets in `CSR_GIO_REG` after a gen2 firmware
/// load completes. Tells the device "the host is done staging,
/// you can start consuming." Stored at the same offset as
/// `CSR_GIO_REG`.
pub const FH_UCODE_LOAD_STATUS_GEN2: u32 = 0xFFFF_FFFF;

// ── gen3 (AX210+) — context-info-v2 / IML CSRs ─────────────────────

/// Bottom 32 bits of the context-info-v2 dma-coherent block phys.
pub const CSR_CTXT_INFO_ADDR: u32 = 0x118;
/// Bottom 32 bits of the IML (image-loader) dma-coherent phys.
pub const CSR_IML_DATA_ADDR: u32 = 0x120;
/// IML byte length.
pub const CSR_IML_SIZE_ADDR: u32 = 0x128;
/// Context-info boot control. Set bit `CSR_AUTO_FUNC_BOOT_ENA`
/// to kick the device's IML.
pub const CSR_CTXT_INFO_BOOT_CTRL: u32 = 0x150;
/// Bit set in `CSR_CTXT_INFO_BOOT_CTRL` to start IML boot.
pub const CSR_AUTO_FUNC_BOOT_ENA: u32 = 1 << 1;

/// Doorbell register the SMU / WFPM uses for cross-CPU signalling.
/// The driver writes `DOORBELL_TO_ISR6_NMI_BIT` here to force an
/// NMI for crash diagnostics.
pub const UREG_DOORBELL_TO_ISR6: u32 = 0x0AAC_C040;
pub const DOORBELL_TO_ISR6_NMI_BIT: u32 = 1 << 0;

// ── PRPH — indirect access through HBUS_TARG_* registers ──────────

/// HBUS target window — the driver writes an address here, then
/// reads/writes data through `HBUS_TARG_PRPH_DATA`. Allows
/// 32-bit-wide PRPH ops without per-register CSR mappings.
pub const HBUS_TARG_PRPH_WADDR: u32 = 0x0044_C000;
pub const HBUS_TARG_PRPH_WDAT: u32 = 0x0044_C004;
pub const HBUS_TARG_PRPH_RADDR: u32 = 0x0044_C008;
pub const HBUS_TARG_PRPH_RDAT: u32 = 0x0044_C00C;

/// PRPH register: "release CPU from reset". Cleared during
/// firmware load, set when the section loader is done.
pub const PRPH_RELEASE_CPU_RESET: u32 = 0x0030_0C;
pub const PRPH_RELEASE_CPU_RESET_BIT: u32 = 1 << 31;
/// PRPH register: ucode load status. Driver writes
/// `FH_UCODE_LOAD_STATUS_GEN2` here on gen2 to signal "host done."
pub const PRPH_UREG_UCODE_LOAD_STATUS: u32 = 0x0034_0;
/// PRPH register: OTP cfg1 — fused RF-chip identity. Read by
/// gen3 probe to decide which `rf_*` to match against.
pub const PRPH_WFPM_OTP_CFG1_ADDR: u32 = 0x0094_0;

/// `LMPM_CHICK` register — toggled when the DMA destination
/// falls into extended SRAM (0x40000–0x57FFF). The chick bit
/// gives the channel access to the extended bank.
pub const PRPH_LMPM_CHICK: u32 = 0x0A_01F4;
pub const PRPH_LMPM_CHICK_EXT_ADDR_LSB: u32 = 1 << 27;

// ── Address-range constants for `LMPM_CHICK` decision ──────────────

/// Sections whose dest_offset falls in this range need the chick
/// bit toggled (extended-SRAM bank).
pub const EXT_SRAM_LO: u32 = 0x0004_0000;
pub const EXT_SRAM_HI: u32 = 0x0005_7FFF;

#[inline]
pub const fn dest_needs_chick(dest_offset: u32) -> bool {
    dest_offset >= EXT_SRAM_LO && dest_offset <= EXT_SRAM_HI
}

// ── ALIVE notification ─────────────────────────────────────────────

/// `IWL_ALIVE_STATUS_OK` — the magic value the firmware writes
/// to the status field of its ALIVE notification to say
/// "I'm alive and ready." Anything else means abort.
pub const IWL_ALIVE_STATUS_OK: u32 = 0xCAFE;

/// ALIVE notification timeout. Linux uses `2 * HZ`; HZ here is
/// nominally 1000, so 2 seconds.
pub const IWL_ALIVE_TIMEOUT_MS: u64 = 2000;

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Service-channel register offsets — sanity-check that the
    /// five FH SRVC registers all decode to distinct values and
    /// match the formulas declared above. Absolute-value parity
    /// with Linux's `iwl-fh.h` (which uses *multiple* FH base
    /// constants — `FH_TCSR_LOWER_BOUND`, `FH_MEM_TFDIB_LOWER_
    /// BOUND` etc.) is pending a real-HW audit; the test here
    /// catches regressions in the formula constants without
    /// asserting exact byte offsets we haven't verified against
    /// silicon.
    fn smoke_iwlwifi_fh_srvc_offsets_distinct_and_consistent() -> TestResult {
        // Compute expectations from the same formulas the code uses.
        let expected_tx_cfg = FH_MEM_LOWER_BOUND_GEN2 + 0x100 + FH_SRVC_CHNL * 0x20;
        let expected_tx_sts = FH_MEM_LOWER_BOUND_GEN2 + 0x108 + FH_SRVC_CHNL * 0x20;
        let expected_sram = FH_MEM_LOWER_BOUND_GEN2 + 0x180 + FH_SRVC_CHNL * 0x4;
        let expected_ctrl0 = FH_MEM_LOWER_BOUND_GEN2 + 0x900 + FH_SRVC_CHNL * 0x8;
        let expected_ctrl1 = FH_MEM_LOWER_BOUND_GEN2 + 0x904 + FH_SRVC_CHNL * 0x8;

        if FH_TCSR_CHNL_TX_CONFIG_REG_SRVC != expected_tx_cfg {
            return TestResult::Fail("TX_CONFIG_REG formula drifted");
        }
        if FH_TCSR_CHNL_TX_BUF_STS_REG_SRVC != expected_tx_sts {
            return TestResult::Fail("TX_BUF_STS_REG formula drifted");
        }
        if FH_SRVC_CHNL_SRAM_ADDR_REG_SRVC != expected_sram {
            return TestResult::Fail("SRAM_ADDR_REG formula drifted");
        }
        if FH_TFDIB_CTRL0_REG_SRVC != expected_ctrl0 {
            return TestResult::Fail("TFDIB_CTRL0_REG formula drifted");
        }
        if FH_TFDIB_CTRL1_REG_SRVC != expected_ctrl1 {
            return TestResult::Fail("TFDIB_CTRL1_REG formula drifted");
        }

        // No two FH SRVC registers should share an offset.
        let all = [
            FH_TCSR_CHNL_TX_CONFIG_REG_SRVC,
            FH_TCSR_CHNL_TX_BUF_STS_REG_SRVC,
            FH_SRVC_CHNL_SRAM_ADDR_REG_SRVC,
            FH_TFDIB_CTRL0_REG_SRVC,
            FH_TFDIB_CTRL1_REG_SRVC,
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                if a == b {
                    return TestResult::Fail("two FH SRVC offsets collided");
                }
            }
        }

        TestResult::Pass
    }

    /// CTRL1 packing layout: high nibble = phys[35:32], low 20
    /// bits = byte count.
    fn smoke_iwlwifi_fh_ctrl1_packing() -> TestResult {
        let v = fh_tfdib_ctrl1(0xA, 0x1234);
        // Expected: 0xA in bits 28..32 + 0x1234 in bits 0..20.
        if v != 0xA000_1234 {
            return TestResult::Fail("CTRL1 packing wrong");
        }
        TestResult::Pass
    }

    /// Extended SRAM range detection — sections at 0x40000..=
    /// 0x57FFF need the LMPM chick bit toggled.
    fn smoke_iwlwifi_ext_sram_chick_decision() -> TestResult {
        if dest_needs_chick(0) {
            return TestResult::Fail("0 should not need chick");
        }
        if dest_needs_chick(0x3FFFF) {
            return TestResult::Fail("boundary-below should not need chick");
        }
        if !dest_needs_chick(0x40000) {
            return TestResult::Fail("low end of ext-SRAM");
        }
        if !dest_needs_chick(0x57FFF) {
            return TestResult::Fail("high end of ext-SRAM");
        }
        if dest_needs_chick(0x58000) {
            return TestResult::Fail("boundary-above should not need chick");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi/regs",
        smoke_iwlwifi_fh_srvc_offsets_distinct_and_consistent
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/regs",
        smoke_iwlwifi_fh_ctrl1_packing
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/regs",
        smoke_iwlwifi_ext_sram_chick_decision
    );
}
