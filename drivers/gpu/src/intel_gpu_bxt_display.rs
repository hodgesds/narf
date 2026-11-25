//! Broxton / Gemini Lake display power for one port.
//!
//! MIT Linux v6.12 `display/intel_display_power_map.c` (`bxt_power_wells`,
//! `glk_power_wells`) and `display/intel_display_power_well.c`
//! (`bxt_dpio_cmn_power_well_ops`, `hsw_power_well_ops`), `i915_reg.h`
//! (`HSW_PWR_WELL_CTL2`, `GLK_PW_CTL_IDX_AUX_*`).
//!
//! A port's lanes and AUX channel belong to its PHY's `dpio-common` well,
//! whose enable is `bxt_dpio_phy_init`; Gemini Lake adds a separate AUX
//! well per port. Pipe A and the eDP transcoder are in power well 1, which
//! the DMC keeps on; pipes B and C take power well 2. Nothing here has run
//! on silicon.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_bxt_phy::{self as phy, PhyError, Port};

/// `HSW_PWR_WELL_CTL2`: the driver request register, `REQ(i)` at bit
/// `2i + 1` and `STATE(i)` at bit `2i`.
const PWR_WELL_CTL2: u64 = 0x45404;

/// `GLK_PW_CTL_IDX_AUX_A` / `_B` / `_C`.
pub(crate) const fn glk_aux_well(port: Port) -> u32 {
    match port {
        Port::A => 8,
        Port::B => 9,
        Port::C => 10,
    }
}

/// Why a port could not be powered.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PowerError {
    Phy(PhyError),
    /// A power well's state did not follow its request within 1 ms.
    WellTimeout(u32),
}

/// `hsw_power_well_enable` for a well without fuses: set the request and
/// wait 1 ms for the state.
fn request_well(io: &(impl MmioWindow + ?Sized), idx: u32) -> Result<(), PowerError> {
    let state = 1 << (2 * idx);
    let request = 2 << (2 * idx);
    let cur = io.read32(PWR_WELL_CTL2);
    if cur & request == 0 {
        io.write32(PWR_WELL_CTL2, cur | request);
    }
    let done = narf_scheduler::responsive_spin_until(
        || io.read32(PWR_WELL_CTL2) & state != 0 || !io.display_access_ok(),
        narf_time::Deadline::after_us(1_000),
    );
    if done && io.display_access_ok() {
        Ok(())
    } else {
        Err(PowerError::WellTimeout(idx))
    }
}

/// Power `port`'s lanes and AUX channel: its PHY's `dpio-common` well and,
/// on Gemini Lake, its AUX well. An enabled, verified PHY is not
/// reprogrammed.
pub(crate) fn power_port(
    io: &(impl MmioWindow + ?Sized),
    glk: bool,
    port: Port,
) -> Result<(), PowerError> {
    let (phy_id, _) = phy::port_to_phy_channel(glk, port);
    phy::init(io, glk, phy_id).map_err(PowerError::Phy)?;
    if glk {
        request_well(io, glk_aux_well(port))?;
    }
    Ok(())
}

/// `PCH_PPS_BASE`, where the shared panel power sequencer addresses its
/// registers.
const PCH_PPS_BASE: u64 = 0xc7200;
/// `PPS_BASE`: Gen9 LP has no PCH, so instance 0 of its power sequencer is
/// in the display engine (`bxt_power_sequencer_idx` defaults to 0).
const BXT_PPS_BASE: u64 = 0x61200;

/// A window that moves the panel power sequencer's PCH registers
/// (`PP_STATUS`, `PP_CONTROL`, `PP_ON_DELAYS`, `PP_OFF_DELAYS`) to Gen9 LP's
/// display-engine instance, and passes everything else through. With
/// `relocate` clear it passes everything through.
pub(crate) struct PpsWindow<'a, M: MmioWindow + ?Sized> {
    inner: &'a M,
    relocate: bool,
}

impl<'a, M: MmioWindow + ?Sized> PpsWindow<'a, M> {
    pub(crate) fn new(inner: &'a M, relocate: bool) -> Self {
        Self { inner, relocate }
    }

    fn map(&self, reg: u64) -> u64 {
        if self.relocate && (PCH_PPS_BASE..PCH_PPS_BASE + 0x10).contains(&reg) {
            reg - PCH_PPS_BASE + BXT_PPS_BASE
        } else {
            reg
        }
    }
}

impl<M: MmioWindow + ?Sized> MmioWindow for PpsWindow<'_, M> {
    fn read32(&self, reg: u64) -> u32 {
        self.inner.read32(self.map(reg))
    }
    fn write32(&self, reg: u64, value: u32) {
        self.inner.write32(self.map(reg), value)
    }
    fn display_access_ok(&self) -> bool {
        self.inner.display_access_ok()
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Power wells grant their request at once; PHYs power and calibrate as
    /// soon as the PUNIT bit is set.
    #[derive(Default)]
    struct Regs(RefCell<BTreeMap<u64, u32>>);
    impl MmioWindow for Regs {
        fn read32(&self, reg: u64) -> u32 {
            *self.0.borrow().get(&reg).unwrap_or(&0)
        }
        fn write32(&self, reg: u64, value: u32) {
            let mut value = value;
            if reg == PWR_WELL_CTL2 {
                // Every requested well reports its state.
                value |= (value & 0xaaaa_aaaa) >> 1;
            }
            self.0.borrow_mut().insert(reg, value);
            if reg == phy::DISP_PWRON {
                for (p, info) in phy::phys(true).iter().chain(phy::phys(false)) {
                    if value & info.pwron_mask != 0 {
                        self.0.borrow_mut().insert(phy::cl1cm_dw0(*p), 1 << 16);
                        self.0
                            .borrow_mut()
                            .insert(phy::cl1cm_dw0(*p) + 0x18c, 1 << 22);
                    }
                }
            }
        }
    }

    /// Gemini Lake port A: PHY1 up and the AUX_A well (index 8) granted;
    /// Broxton port C: PHY0 up with no AUX well request.
    fn smoke_bxt_display_power_port() -> TestResult {
        let glk = Regs::default();
        if power_port(&glk, true, Port::A).is_err()
            || !phy::is_enabled(&glk, true, phy::Phy::Phy1)
            || glk.read32(PWR_WELL_CTL2) & (3 << 16) != 3 << 16
        {
            return TestResult::Fail("Gemini Lake port A power");
        }
        let bxt = Regs::default();
        if power_port(&bxt, false, Port::C).is_err()
            || !phy::is_enabled(&bxt, false, phy::Phy::Phy0)
            || bxt.read32(PWR_WELL_CTL2) != 0
        {
            return TestResult::Fail("Broxton port C power");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_bxt_display",
        smoke_bxt_display_power_port
    );

    /// The sequencer's PCH registers land at 0x61200 on Gen9 LP; other
    /// registers, and every register without relocation, pass through.
    fn smoke_bxt_display_pps_window() -> TestResult {
        let regs = Regs::default();
        let lp = PpsWindow::new(&regs, true);
        lp.write32(crate::intel_gpu_edp::PP_STATUS + 4, 0x67);
        lp.write32(0x45404, 2);
        let pch = PpsWindow::new(&regs, false);
        pch.write32(crate::intel_gpu_edp::PP_STATUS, 9);
        if regs.read32(0x61204) != 0x67
            || regs.read32(0xc7204) != 0
            || regs.read32(0xc7200) != 9
            || lp.read32(crate::intel_gpu_edp::PP_STATUS + 4) != 0x67
        {
            return TestResult::Fail("PPS relocation");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_bxt_display",
        smoke_bxt_display_pps_window
    );
}
