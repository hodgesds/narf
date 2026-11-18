//! Nova Lake-S display-35 output-resource planning.
//!
//! This module is deliberately pure: it binds the source-qualified LT ports
//! to their connector roles, pipes, power dependencies, AUX channel and HPD
//! source without reading or writing MMIO.  It therefore does not widen
//! [`crate::intel_gpu_xe2lpd::DisplayIp`] and cannot enable the disconnected
//! LT-PHY transport.
//!
//! Linux 7.0-rc7 sources:
//! - `intel_display_device.c::XE_LPDP_FEATURES` (Pipes/Transcoders A-D),
//! - `intel_display_power_map.c::xe3lpd_power_wells` (PW1, PW2, PW_A-D,
//!   PICA_TC and per-channel AUX wells),
//! - `intel_display_power_well.c::xelpdp_aux_power_well_enable` (LT AUX
//!   request/status handshake),
//! - `intel_lt_phy_regs.h` (the A/B/USBC1/USBC2 LT register ranges), and
//! - `intel_ddi.c` / `intel_hotplug_irq.c` (D2D, Type-C and HPD ownership).

// The complete plan is intentionally disconnected until a Display-35 live
// resource transaction exists; keeping it crate-private prevents accidental
// production authority in the meantime.
#![allow(dead_code)]

use crate::intel_gpu_aux::{
    MmioWindow, XELPDP_AUX_CH_CTL_POWER_REQUEST, XELPDP_AUX_CH_CTL_POWER_STATUS,
};
use crate::intel_gpu_lt_phy::LtPort;
use crate::intel_gpu_pipes::{Pipe, Transcoder};
use crate::intel_gpu_xe2lpd::{self as xe2lpd, IpError};

/// `PWR_WELL_CTL2` indices used by Xe3 LPD and Xe3P LPD.
const PW_1_INDEX: u8 = 0;
const PW_2_INDEX: u8 = 1;
const PW_A_INDEX: u8 = 5;

/// A connector shape admitted by the disconnected Nova resource owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NovaOutput {
    /// The firmware-lit internal panel on LT port A and Pipe A.
    Edp,
    /// Native DisplayPort on combo LT port B.
    DisplayPort,
    /// HDMI 2.0 TMDS on combo LT port B. FRL remains unsupported.
    HdmiTmds,
    /// DisplayPort alternate mode on TC1 or TC2.
    UsbCDpAlt,
}

/// Exact hotplug source retained by a future output owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NovaHpd {
    A,
    B,
    Tc1,
    Tc2,
}

/// Why no Nova output-resource plan was produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NovaPlanRefusal {
    /// Port and connector role do not match the qualified topology.
    PortRole,
    /// Pipe A belongs to eDP; external outputs use Pipes B-D.
    PipeRole,
}

/// Failure while realizing a disconnected Nova resource dependency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NovaResourceError {
    /// The MMIO owner is not the exact Nova/LT platform view.
    ProfileMismatch,
    /// Access was lost or the D2D state transition timed out.
    D2d(IpError),
}

/// LT AUX power-well handshake retained by DP/eDP outputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NovaAux {
    /// `XELPDP_DP_AUX_CH_CTL` for this exact LT port.
    pub(crate) ctl: u64,
    pub(crate) request_mask: u32,
    pub(crate) status_mask: u32,
}

/// Pure ownership contract for one Nova output.
///
/// A future live route must acquire these dependencies before enabling the LT
/// PHY and must release them in reverse order after a proven local stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NovaResourcePlan {
    pub(crate) port: LtPort,
    pub(crate) pipe: Pipe,
    pub(crate) transcoder: Transcoder,
    pub(crate) output: NovaOutput,
    /// DP/eDP AUX ownership. Native HDMI uses GMBUS/DDC instead.
    pub(crate) aux: Option<NovaAux>,
    /// Native HDMI requires a VBT-qualified GMBUS/DDC route.
    pub(crate) gmbus_ddc: bool,
    pub(crate) hpd: NovaHpd,
    /// The owner must hold display DC-off across every programming step.
    pub(crate) dc_off: bool,
    /// PW1, optional PW2, and the pipe's PW_A-D request bits.
    pub(crate) power_well_request_mask: u32,
    /// PW1, optional PW2, and the pipe's PW_A-D state bits.
    pub(crate) power_well_state_mask: u32,
    /// TC1/TC2 lane and AUX domains also require PICA_TC.
    pub(crate) pica_tc: bool,
    /// TC1/TC2 DP-alt needs TCSS ownership; combo ports do not.
    pub(crate) typec_phy: Option<u8>,
    /// Display >= 20 keeps the D2D request with the active port buffer.
    pub(crate) d2d: bool,
}

const fn well_request(index: u8) -> u32 {
    0x2 << (index * 2)
}

const fn well_state(index: u8) -> u32 {
    0x1 << (index * 2)
}

const fn pipe_well_index(pipe: Pipe) -> u8 {
    PW_A_INDEX + pipe as u8
}

const fn needs_pw2(port: LtPort, pipe: Pipe) -> bool {
    // Xe3 changed the hierarchy: TC lane domains and Pipes C/D are under
    // PW2, while Pipe B is directly under PW1 through its own well.
    matches!(port, LtPort::Tc1 | LtPort::Tc2) || matches!(pipe, Pipe::C | Pipe::D)
}

impl NovaResourcePlan {
    /// Build the exact disconnected ownership plan. No register is touched.
    pub(crate) const fn new(
        port: LtPort,
        pipe: Pipe,
        output: NovaOutput,
    ) -> Result<Self, NovaPlanRefusal> {
        let (hpd, typec_phy) = match (port, output) {
            (LtPort::A, NovaOutput::Edp) if matches!(pipe, Pipe::A) => (NovaHpd::A, None),
            (LtPort::B, NovaOutput::DisplayPort | NovaOutput::HdmiTmds)
                if !matches!(pipe, Pipe::A) =>
            {
                (NovaHpd::B, None)
            }
            (LtPort::Tc1, NovaOutput::UsbCDpAlt) if !matches!(pipe, Pipe::A) => {
                (NovaHpd::Tc1, Some(0))
            }
            (LtPort::Tc2, NovaOutput::UsbCDpAlt) if !matches!(pipe, Pipe::A) => {
                (NovaHpd::Tc2, Some(1))
            }
            (LtPort::A, NovaOutput::Edp)
            | (LtPort::B, NovaOutput::DisplayPort | NovaOutput::HdmiTmds)
            | (LtPort::Tc1 | LtPort::Tc2, NovaOutput::UsbCDpAlt) => {
                return Err(NovaPlanRefusal::PipeRole);
            }
            _ => return Err(NovaPlanRefusal::PortRole),
        };

        let mut power_well_request_mask =
            well_request(PW_1_INDEX) | well_request(pipe_well_index(pipe));
        let mut power_well_state_mask = well_state(PW_1_INDEX) | well_state(pipe_well_index(pipe));
        if needs_pw2(port, pipe) {
            power_well_request_mask |= well_request(PW_2_INDEX);
            power_well_state_mask |= well_state(PW_2_INDEX);
        }

        let aux = if matches!(output, NovaOutput::HdmiTmds) {
            None
        } else {
            Some(NovaAux {
                ctl: port.aux_ctl(),
                request_mask: XELPDP_AUX_CH_CTL_POWER_REQUEST,
                status_mask: XELPDP_AUX_CH_CTL_POWER_STATUS,
            })
        };

        Ok(Self {
            port,
            pipe,
            transcoder: pipe.transcoder(),
            output,
            aux,
            gmbus_ddc: matches!(output, NovaOutput::HdmiTmds),
            hpd,
            dc_off: true,
            power_well_request_mask,
            power_well_state_mask,
            pica_tc: typec_phy.is_some(),
            typec_phy,
            d2d: true,
        })
    }

    /// Acquire Display >= 20's D2D link through `DDI_BUF_CTL`. The exact LT
    /// platform fact is required before the first read or write.
    pub(crate) fn enable_d2d(
        self,
        io: &(impl MmioWindow + ?Sized),
    ) -> Result<(), NovaResourceError> {
        if !io.has_lt_phy() {
            return Err(NovaResourceError::ProfileMismatch);
        }
        xe2lpd::enable_d2d_xe2_plus(io, self.port.xelpg()).map_err(NovaResourceError::D2d)
    }

    /// Release the exact Nova D2D link and observe its state clear.
    pub(crate) fn disable_d2d(
        self,
        io: &(impl MmioWindow + ?Sized),
    ) -> Result<(), NovaResourceError> {
        if !io.has_lt_phy() {
            return Err(NovaResourceError::ProfileMismatch);
        }
        xe2lpd::disable_d2d_xe2_plus(io, self.port.xelpg()).map_err(NovaResourceError::D2d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_and_combo_plans_keep_their_port_roles() {
        let panel = NovaResourcePlan::new(LtPort::A, Pipe::A, NovaOutput::Edp).unwrap();
        assert_eq!(panel.transcoder, Transcoder::A);
        assert_eq!(
            panel.aux,
            Some(NovaAux {
                ctl: 0x6_4010,
                request_mask: 1 << 19,
                status_mask: 1 << 18,
            })
        );
        assert_eq!(panel.hpd, NovaHpd::A);
        assert_eq!(panel.power_well_request_mask, (0x2 << 0) | (0x2 << 10));
        assert_eq!(panel.power_well_state_mask, (0x1 << 0) | (0x1 << 10));
        assert!(!panel.pica_tc);
        assert_eq!(panel.typec_phy, None);
        assert!(panel.dc_off && panel.d2d);
        assert!(!panel.gmbus_ddc);

        let combo = NovaResourcePlan::new(LtPort::B, Pipe::B, NovaOutput::HdmiTmds).unwrap();
        assert_eq!(combo.transcoder, Transcoder::B);
        assert_eq!(combo.aux, None);
        assert_eq!(combo.hpd, NovaHpd::B);
        assert_eq!(combo.power_well_request_mask, (0x2 << 0) | (0x2 << 12));
        assert!(!combo.pica_tc);
        assert!(combo.gmbus_ddc && combo.dc_off);
    }

    #[test]
    fn both_usb_c_dp_ports_retain_pw2_pica_aux_and_hpd() {
        for (port, pipe, tc, aux, hpd, pipe_shift) in [
            (LtPort::Tc1, Pipe::B, 0, 0x16_f210, NovaHpd::Tc1, 12),
            (LtPort::Tc2, Pipe::D, 1, 0x16_f410, NovaHpd::Tc2, 16),
        ] {
            let plan = NovaResourcePlan::new(port, pipe, NovaOutput::UsbCDpAlt).unwrap();
            assert_eq!(plan.typec_phy, Some(tc));
            assert!(plan.pica_tc && plan.dc_off && plan.d2d);
            assert!(!plan.gmbus_ddc);
            assert_eq!(
                plan.aux,
                Some(NovaAux {
                    ctl: aux,
                    request_mask: 1 << 19,
                    status_mask: 1 << 18,
                })
            );
            assert_eq!(plan.hpd, hpd);
            assert_eq!(
                plan.power_well_request_mask,
                (0x2 << 0) | (0x2 << 2) | (0x2 << pipe_shift)
            );
        }
    }

    #[test]
    fn invalid_port_and_pipe_combinations_fail_closed() {
        assert_eq!(
            NovaResourcePlan::new(LtPort::A, Pipe::B, NovaOutput::Edp),
            Err(NovaPlanRefusal::PipeRole)
        );
        assert_eq!(
            NovaResourcePlan::new(LtPort::Tc1, Pipe::A, NovaOutput::UsbCDpAlt),
            Err(NovaPlanRefusal::PipeRole)
        );
        assert_eq!(
            NovaResourcePlan::new(LtPort::Tc2, Pipe::C, NovaOutput::HdmiTmds),
            Err(NovaPlanRefusal::PortRole)
        );
        assert_eq!(
            NovaResourcePlan::new(LtPort::B, Pipe::C, NovaOutput::UsbCDpAlt),
            Err(NovaPlanRefusal::PortRole)
        );
    }

    #[test]
    fn combo_pipe_c_inherits_pw2_from_the_xe3_hierarchy() {
        let plan = NovaResourcePlan::new(LtPort::B, Pipe::C, NovaOutput::DisplayPort).unwrap();
        assert_eq!(
            plan.power_well_request_mask,
            (0x2 << 0) | (0x2 << 2) | (0x2 << 14)
        );
    }
}

#[cfg(feature = "kernel-test")]
mod kernel_tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct D2dFake {
        reg: u64,
        value: Cell<u32>,
        writes: RefCell<Vec<u32>>,
        lt: bool,
        acknowledge: bool,
    }

    impl D2dFake {
        fn new(port: LtPort, lt: bool, acknowledge: bool) -> Self {
            Self {
                reg: port.xelpg().ddi_buf_ctl(),
                value: Cell::new(0),
                writes: RefCell::new(Vec::new()),
                lt,
                acknowledge,
            }
        }
    }

    impl MmioWindow for D2dFake {
        fn has_lt_phy(&self) -> bool {
            self.lt
        }
        fn read32(&self, off: u64) -> u32 {
            if off != self.reg {
                return 0;
            }
            let value = self.value.get();
            value
                | if self.acknowledge && value & xe2lpd::DDI_BUF_D2D_LINK_ENABLE != 0 {
                    xe2lpd::DDI_BUF_D2D_LINK_STATE
                } else {
                    0
                }
        }
        fn write32(&self, off: u64, value: u32) {
            if off == self.reg {
                self.writes.borrow_mut().push(value);
                self.value.set(value & !xe2lpd::DDI_BUF_D2D_LINK_STATE);
            }
        }
    }

    fn smoke_nvl_resource_plan_owns_display20_d2d() -> TestResult {
        let plan = match NovaResourcePlan::new(LtPort::Tc2, Pipe::D, NovaOutput::UsbCDpAlt) {
            Ok(plan) => plan,
            Err(_) => return TestResult::Fail("Nova TC2/Pipe-D plan must be admitted"),
        };
        let io = D2dFake::new(LtPort::Tc2, true, true);
        if plan.enable_d2d(&io).is_err()
            || io.value.get() & xe2lpd::DDI_BUF_D2D_LINK_ENABLE == 0
            || plan.disable_d2d(&io).is_err()
            || io.value.get() & xe2lpd::DDI_BUF_D2D_LINK_ENABLE != 0
            || io.writes.borrow().len() != 2
        {
            return TestResult::Fail("Nova must observe DDI_BUF_CTL D2D up and down");
        }

        let crossed = D2dFake::new(LtPort::Tc2, false, true);
        if plan.enable_d2d(&crossed) != Err(NovaResourceError::ProfileMismatch)
            || !crossed.writes.borrow().is_empty()
        {
            return TestResult::Fail("Nova D2D must refuse a non-LT view before MMIO");
        }

        let stuck = D2dFake::new(LtPort::Tc2, true, false);
        if !matches!(
            plan.enable_d2d(&stuck),
            Err(NovaResourceError::D2d(IpError::NoDevice))
        ) {
            return TestResult::Fail("Nova D2D missing state must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_nvl_resources",
        smoke_nvl_resource_plan_owns_display20_d2d
    );
}
