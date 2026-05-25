//! Intel iwlwifi — APM (Active Power Management) bring-up.
//!
//! Adapted from Linux `drivers/net/wireless/intel/iwlwifi/pcie/gen1_2/
//! trans.c::iwl_pcie_apm_init` + `iwl_trans_pcie_sw_reset` +
//! `iwl_pcie_gen1_2_activate_nic`. GPL-2.0-or-later.
//!
//! Sequence is:
//!
//! 1. SW reset — assert `CSR_RESET_REG_FLAG_SW_RESET` (bit 7) on
//!    pre-Bz parts (or `CSR_GP_CNTRL_REG_FLAG_SW_RESET` on Bz+).
//! 2. APM init — set the chicken-bits (L0s exit timer disabled on
//!    pre-8000, L1A→L0s disable always), set HAP_WAKE in
//!    `CSR_HW_IF_CONFIG_REG`, configure PLL if the part needs it.
//! 3. Activate NIC — set `INIT_DONE` in `CSR_GP_CNTRL` and poll for
//!    `MAC_CLOCK_READY` (pre-Bz) or `MAC_STATUS` (Bz+).
//! 4. APMG clock — write `APMG_CLK_VAL_DMA_CLK_RQT` to
//!    `APMG_CLK_EN_REG` via PRPH (skipped on parts where
//!    `apmg_not_supported = true`, i.e. AX210+).
//!
//! Stage-2 lands the *sequence definition* + the wall-clock budgets,
//! but does NOT run it from probe yet — the BAR mapping path that
//! drives this lives in `probe.rs` (built next).

#![allow(dead_code)]

use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::MmioRegion;

use super::csr;
use super::prph;

/// Per-step wall-clock deadlines mirroring Linux's `usleep_range` +
/// `iwl_poll_bits` timeouts.
///
/// - SW reset settle (pre-Bz): `usleep_range(5000, 6000)` ≈ 6 ms.
/// - SW reset settle (Bz+): `usleep_range(10000, 20000)` ≈ 20 ms.
/// - MAC_CLOCK_READY poll: `iwl_poll_bits(..., 25000)` ≈ 25 ms.
pub const APM_SW_RESET_PRE_BZ_MS: u64 = 6;
pub const APM_SW_RESET_BZ_MS: u64 = 20;
pub const APM_ACTIVATE_NIC_TIMEOUT_MS: u64 = 25;

/// Which Bz-vs-not control flow this part follows. Bz+ moves the
/// SW-reset bit out of `CSR_RESET` into `CSR_GP_CNTRL` and uses
/// MAC_STATUS instead of MAC_CLOCK_READY for the wake-poll. NARF's
/// Stage-2 targets are AX-class (pre-Bz), so the helper defaults to
/// `Family::Pre` for AX200/AX201/AX210/AX211/AX411.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Family {
    /// AX200/AX201/AX210/AX211/AX411 — `device_family < BZ`.
    Pre,
    /// Bz (Be200) and later — uses `CSR_GP_CNTRL`'s SW_RESET bit.
    Bz,
}

impl Family {
    /// Most AX-class parts. Bz+ family lookup is a Stage-3 problem
    /// once we resolve `CSR_HW_REV` against the family table.
    pub const fn default_for_ax() -> Self {
        Self::Pre
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ApmError {
    /// `MAC_CLOCK_READY` (or `MAC_STATUS`) didn't set within
    /// `APM_ACTIVATE_NIC_TIMEOUT_MS`.
    ActivateTimeout,
    /// Device says it's owned by ME (Management Engine) — driver
    /// can't take it without doing the prepare-card-hw dance first.
    /// Stage-2 surfaces the error; the recovery path lands later.
    OwnedByMe,
}

/// Step 1: SW reset.
///
/// # Safety
/// `mmio` must be the device's BAR0 mapping, owned exclusively.
pub unsafe fn sw_reset(mmio: &MmioRegion, family: Family) -> Result<(), ApmError> {
    // SAFETY: caller-owned BAR0.
    unsafe {
        match family {
            Family::Pre => {
                let cur = mmio.read32(csr::CSR_RESET as u64);
                mmio.write32(
                    csr::CSR_RESET as u64,
                    cur | csr::CSR_RESET_REG_FLAG_SW_RESET,
                );
            }
            Family::Bz => {
                let cur = mmio.read32(csr::CSR_GP_CNTRL as u64);
                mmio.write32(
                    csr::CSR_GP_CNTRL as u64,
                    cur | csr::CSR_GP_CNTRL_REG_FLAG_SW_RESET,
                );
            }
        }
    }
    compiler_fence(Ordering::SeqCst);

    let ms = match family {
        Family::Pre => APM_SW_RESET_PRE_BZ_MS,
        Family::Bz => APM_SW_RESET_BZ_MS,
    };
    // responsive_spin_until ticks sleep_pumps so cursor / serial /
    // audio drain stay alive across the wait. The body returns true
    // immediately on the first tick — we just want a wall-clock delay.
    let deadline = narf_time::Deadline::after_ms(ms);
    let _ = narf_scheduler::responsive_spin_until(|| deadline.expired(), deadline);
    Ok(())
}

/// Step 2: APM init (the "wake up the NIC" preamble).
///
/// # Safety
/// `mmio` must be the device's BAR0 mapping; exclusively owned.
pub unsafe fn apm_init(mmio: &MmioRegion, family: Family) -> Result<(), ApmError> {
    // SAFETY: caller-owned BAR0.
    unsafe {
        // Disable L0s exit timer (pre-8000 chicken bit). We're past
        // the 8000-family on every AX part, so this is a no-op set in
        // practice — kept for parity with the upstream sequence.
        let cur = mmio.read32(csr::CSR_GIO_CHICKEN_BITS as u64);
        mmio.write32(
            csr::CSR_GIO_CHICKEN_BITS as u64,
            cur | csr::CSR_GIO_CHICKEN_BITS_REG_BIT_L1A_NO_L0S_RX,
        );

        // Set FH wait threshold to max (HW-error stress workaround).
        // The value `CSR_DBG_HPET_MEM_REG_VAL` is `0xFFFF_0000`.
        let dbg = mmio.read32(csr::CSR_DBG_HPET_MEM_REG as u64);
        mmio.write32(csr::CSR_DBG_HPET_MEM_REG as u64, dbg | 0xFFFF_0000);

        // Enable HAP_WAKE — wakes PCIe link from L1a → L0s.
        let cfg = mmio.read32(csr::CSR_HW_IF_CONFIG_REG as u64);
        mmio.write32(
            csr::CSR_HW_IF_CONFIG_REG as u64,
            cfg | csr::CSR_HW_IF_CONFIG_REG_HAP_WAKE,
        );

        // Disable L0s in GIO_REG — load-bearing on every modern part.
        let gio = mmio.read32(csr::CSR_GIO_REG as u64);
        mmio.write32(
            csr::CSR_GIO_REG as u64,
            gio | csr::CSR_GIO_REG_VAL_L0S_DISABLED,
        );
    }

    // SAFETY: caller-owned BAR0; activate_nic does its own MMIO.
    unsafe { activate_nic(mmio, family) }?;

    // SAFETY: at this point MAC is awake, PRPH is usable.
    unsafe {
        // Step 4: APMG clock enable. Linux gates this on
        // `apmg_not_supported` — AX210+ skips it. Stage-2 takes the
        // pre-AX210 path; AX210 parts skip via the family check at
        // probe time.
        if matches!(family, Family::Pre) {
            prph::write_prph(
                mmio,
                prph::PrphMask::Mask20,
                prph::APMG_CLK_EN_REG,
                prph::APMG_CLK_VAL_DMA_CLK_RQT,
            );
            // Linux udelay(20) — the DMA clock needs ~20 µs to settle.
            // 1 ms wall-clock here covers responsive_spin_until granularity.
            let dl = narf_time::Deadline::after_ms(1);
            let _ = narf_scheduler::responsive_spin_until(|| dl.expired(), dl);
            prph::set_bits_prph(
                mmio,
                prph::PrphMask::Mask20,
                prph::APMG_PCIDEV_STT_REG,
                prph::APMG_PCIDEV_STT_VAL_L1_ACT_DIS,
            );
            // Clear pending RFKILL interrupt in APMG, if any.
            prph::write_prph(
                mmio,
                prph::PrphMask::Mask20,
                prph::APMG_RTC_INT_STT_REG,
                prph::APMG_RTC_INT_STT_RFKILL,
            );
        }
    }

    Ok(())
}

/// Step 3: activate the NIC. Sets `INIT_DONE` (or Bz+'s
/// `MAC_INIT` + `BZ_MAC_ACCESS_REQ`) and polls for `MAC_CLOCK_READY`
/// (or Bz+'s `MAC_STATUS`).
///
/// # Safety
/// Caller owns the BAR0 mapping.
pub unsafe fn activate_nic(mmio: &MmioRegion, family: Family) -> Result<(), ApmError> {
    let poll_mask = match family {
        Family::Pre => {
            // SAFETY: caller-owned.
            unsafe {
                let cur = mmio.read32(csr::CSR_GP_CNTRL as u64);
                mmio.write32(
                    csr::CSR_GP_CNTRL as u64,
                    cur | csr::CSR_GP_CNTRL_REG_FLAG_INIT_DONE,
                );
            }
            csr::CSR_GP_CNTRL_REG_FLAG_MAC_CLOCK_READY
        }
        Family::Bz => {
            // SAFETY: caller-owned.
            unsafe {
                let cur = mmio.read32(csr::CSR_GP_CNTRL as u64);
                mmio.write32(
                    csr::CSR_GP_CNTRL as u64,
                    cur | csr::CSR_GP_CNTRL_REG_FLAG_BZ_MAC_ACCESS_REQ
                        | csr::CSR_GP_CNTRL_REG_FLAG_MAC_INIT,
                );
            }
            csr::CSR_GP_CNTRL_REG_FLAG_MAC_STATUS
        }
    };
    compiler_fence(Ordering::SeqCst);

    let deadline = narf_time::Deadline::after_ms(APM_ACTIVATE_NIC_TIMEOUT_MS);
    let ready = narf_scheduler::responsive_spin_until(
        || {
            // SAFETY: caller-owned BAR0.
            let v = unsafe { mmio.read32(csr::CSR_GP_CNTRL as u64) };
            (v & poll_mask) == poll_mask
        },
        deadline,
    );
    if !ready {
        return Err(ApmError::ActivateTimeout);
    }
    Ok(())
}
