//! Nova Lake-S display-35 output-resource planning.
//!
//! The plan is deliberately pure: it binds source-qualified LT ports to their
//! connector roles, pipes, power dependencies, AUX channel and HPD source.
//! Disconnected methods can realize individual, bounded prerequisites, but
//! the module does not widen [`crate::intel_gpu_xe2lpd::DisplayIp`] and cannot
//! enable a display route or the LT-PHY transport.
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

use core::sync::atomic::{compiler_fence, Ordering};

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
/// Main display power-well request sources.
const PWR_WELL_CTL1: u64 = 0x4_5400;
const PWR_WELL_CTL2: u64 = 0x4_5404;
const PWR_WELL_CTL3: u64 = 0x4_5408;
const PWR_WELL_CTL4: u64 = 0x4_540c;
const SKL_FUSE_STATUS: u64 = 0x4_2000;
const POWER_WELL_TIMEOUT_NS: u64 = 1_000_000;

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
    /// Display MMIO authority disappeared during the resource transaction.
    AccessLost,
    /// A main power well did not report its state within Linux's bound.
    PowerWellTimeout(u8),
    /// A power gate did not report its fuse-distribution state.
    PowerGateFuseTimeout(u8),
    /// Access was lost or the D2D state transition timed out.
    D2d(IpError),
}

/// Main-well requests newly acquired by one disconnected Nova transaction.
///
/// Pre-existing DRIVER requests are observed but never released by this
/// token. A future live owner must still serialize/refcount leases globally.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "main-well requests remain held until the lease is released"]
pub(crate) struct NovaMainWellLease {
    owned_request_mask: u32,
}

impl NovaMainWellLease {
    /// DRIVER request bits this exact transaction raised.
    pub(crate) const fn owned_request_mask(&self) -> u32 {
        self.owned_request_mask
    }

    /// Release newly acquired wells in reverse dependency order. A BIOS,
    /// KVMR or debug request is allowed to keep the hardware state raised.
    pub(crate) fn release(self, io: &(impl MmioWindow + ?Sized)) -> Result<(), NovaResourceError> {
        require_nova(io)?;
        release_owned(io, self.owned_request_mask)
    }
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

const fn fuse_status_mask(index: u8) -> u32 {
    // `pw_idx_to_pg`: ICL PW1 index 0 maps to PG1, and
    // `SKL_FUSE_PG_DIST_STATUS(pg)` is bit 27-pg.
    1 << (26 - index)
}

fn require_nova(io: &(impl MmioWindow + ?Sized)) -> Result<(), NovaResourceError> {
    if io.has_lt_phy() {
        Ok(())
    } else {
        Err(NovaResourceError::ProfileMismatch)
    }
}

fn read_checked(io: &(impl MmioWindow + ?Sized), off: u64) -> Result<u32, NovaResourceError> {
    if !io.display_access_ok() {
        return Err(NovaResourceError::AccessLost);
    }
    let value = io.read32(off);
    if value == u32::MAX || !io.display_access_ok() {
        Err(NovaResourceError::AccessLost)
    } else {
        Ok(value)
    }
}

fn wait_mask(
    io: &(impl MmioWindow + ?Sized),
    off: u64,
    mask: u32,
    expected: u32,
) -> Result<bool, NovaResourceError> {
    let budget = narf_time::wall::ns_to_cycles(POWER_WELL_TIMEOUT_NS);
    let start = narf_time::now_cycles();
    loop {
        // Match read_poll_timeout: the read that can satisfy the condition
        // still occurs after the deadline sample.
        let expired = narf_time::now_cycles().wrapping_sub(start) > budget;
        if read_checked(io, off)? & mask == expected {
            return Ok(true);
        }
        if expired {
            return Ok(false);
        }
        core::hint::spin_loop();
    }
}

fn wait_fuse(
    io: &(impl MmioWindow + ?Sized),
    gate: u8,
    mask: u32,
) -> Result<(), NovaResourceError> {
    if wait_mask(io, SKL_FUSE_STATUS, mask, mask)? {
        Ok(())
    } else {
        Err(NovaResourceError::PowerGateFuseTimeout(gate))
    }
}

fn enable_well(io: &(impl MmioWindow + ?Sized), index: u8) -> Result<bool, NovaResourceError> {
    if index == PW_1_INDEX {
        // PW1 additionally requires the HW-controlled PG0 fuse first.
        wait_fuse(io, 0, 1 << 27)?;
    }
    let request = well_request(index);
    let state = well_state(index);
    let current = read_checked(io, PWR_WELL_CTL2)?;
    let acquired = current & request == 0;
    if acquired {
        io.write32(PWR_WELL_CTL2, current | request);
        compiler_fence(Ordering::SeqCst);
    }
    let enabled = wait_mask(io, PWR_WELL_CTL2, state, state);
    if !matches!(enabled, Ok(true)) {
        if acquired {
            let _ = disable_well(io, index);
        }
        return match enabled {
            Ok(false) => Err(NovaResourceError::PowerWellTimeout(index)),
            Err(error) => Err(error),
            Ok(true) => unreachable!(),
        };
    }
    if let Err(error) = wait_fuse(io, index + 1, fuse_status_mask(index)) {
        if acquired {
            let _ = disable_well(io, index);
        }
        return Err(error);
    }
    Ok(acquired)
}

fn foreign_requesters(
    io: &(impl MmioWindow + ?Sized),
    request: u32,
) -> Result<bool, NovaResourceError> {
    for off in [PWR_WELL_CTL1, PWR_WELL_CTL3, PWR_WELL_CTL4] {
        if read_checked(io, off)? & request != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn disable_well(io: &(impl MmioWindow + ?Sized), index: u8) -> Result<(), NovaResourceError> {
    let request = well_request(index);
    let state = well_state(index);
    let current = read_checked(io, PWR_WELL_CTL2)?;
    io.write32(PWR_WELL_CTL2, current & !request);
    compiler_fence(Ordering::SeqCst);
    if foreign_requesters(io, request)? {
        return Ok(());
    }
    if wait_mask(io, PWR_WELL_CTL2, state, 0)? {
        Ok(())
    } else {
        Err(NovaResourceError::PowerWellTimeout(index))
    }
}

fn release_owned(
    io: &(impl MmioWindow + ?Sized),
    owned_request_mask: u32,
) -> Result<(), NovaResourceError> {
    for index in (PW_1_INDEX..=PW_A_INDEX + Pipe::D as u8).rev() {
        if owned_request_mask & well_request(index) != 0 {
            disable_well(io, index)?;
        }
    }
    Ok(())
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

    /// Acquire PW1, optional PW2 and the selected pipe well in source order.
    /// Only requests absent on entry are retained by the returned lease.
    pub(crate) fn acquire_main_wells(
        self,
        io: &(impl MmioWindow + ?Sized),
    ) -> Result<NovaMainWellLease, NovaResourceError> {
        require_nova(io)?;
        let mut owned = 0;
        let indices = [
            Some(PW_1_INDEX),
            needs_pw2(self.port, self.pipe).then_some(PW_2_INDEX),
            Some(pipe_well_index(self.pipe)),
        ];
        for index in indices.into_iter().flatten() {
            match enable_well(io, index) {
                Ok(true) => owned |= well_request(index),
                Ok(false) => {}
                Err(error) => {
                    let _ = release_owned(io, owned);
                    return Err(error);
                }
            }
        }
        Ok(NovaMainWellLease {
            owned_request_mask: owned,
        })
    }

    /// Acquire Display >= 20's D2D link through `DDI_BUF_CTL`. The exact LT
    /// platform fact is required before the first read or write.
    pub(crate) fn enable_d2d(
        self,
        io: &(impl MmioWindow + ?Sized),
    ) -> Result<(), NovaResourceError> {
        require_nova(io)?;
        xe2lpd::enable_d2d_xe2_plus(io, self.port.xelpg()).map_err(NovaResourceError::D2d)
    }

    /// Release the exact Nova D2D link and observe its state clear.
    pub(crate) fn disable_d2d(
        self,
        io: &(impl MmioWindow + ?Sized),
    ) -> Result<(), NovaResourceError> {
        require_nova(io)?;
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

    struct MainWellFake {
        driver: Cell<u32>,
        bios: Cell<u32>,
        kvmr: Cell<u32>,
        debug: Cell<u32>,
        acknowledged_requests: Cell<u32>,
        fuse_status: Cell<u32>,
        writes: RefCell<Vec<u32>>,
        lt: bool,
    }

    impl MainWellFake {
        fn new(lt: bool) -> Self {
            Self {
                driver: Cell::new(0),
                bios: Cell::new(0),
                kvmr: Cell::new(0),
                debug: Cell::new(0),
                acknowledged_requests: Cell::new(request_bits(u32::MAX)),
                // PG0 plus every gate selected by the supported indices.
                fuse_status: Cell::new(0x0fff_ffff),
                writes: RefCell::new(Vec::new()),
                lt,
            }
        }

        fn state_bits(&self) -> u32 {
            let requests = self.driver.get() | self.bios.get() | self.kvmr.get() | self.debug.get();
            let acknowledged = requests & self.acknowledged_requests.get();
            let mut states = 0;
            for index in PW_1_INDEX..=PW_A_INDEX + Pipe::D as u8 {
                if acknowledged & well_request(index) != 0 {
                    states |= well_state(index);
                }
            }
            states
        }
    }

    fn request_bits(value: u32) -> u32 {
        let mut requests = 0;
        for index in PW_1_INDEX..=PW_A_INDEX + Pipe::D as u8 {
            requests |= value & well_request(index);
        }
        requests
    }

    impl MmioWindow for MainWellFake {
        fn has_lt_phy(&self) -> bool {
            self.lt
        }
        fn read32(&self, off: u64) -> u32 {
            match off {
                PWR_WELL_CTL1 => self.bios.get(),
                PWR_WELL_CTL2 => self.driver.get() | self.state_bits(),
                PWR_WELL_CTL3 => self.kvmr.get(),
                PWR_WELL_CTL4 => self.debug.get(),
                SKL_FUSE_STATUS => self.fuse_status.get(),
                _ => 0,
            }
        }
        fn write32(&self, off: u64, value: u32) {
            if off == PWR_WELL_CTL2 {
                let requests = request_bits(value);
                self.driver.set(requests);
                self.writes.borrow_mut().push(requests);
            }
        }
    }

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

    fn smoke_nvl_main_well_lease_orders_and_rolls_back() -> TestResult {
        let plan = match NovaResourcePlan::new(LtPort::Tc2, Pipe::D, NovaOutput::UsbCDpAlt) {
            Ok(plan) => plan,
            Err(_) => return TestResult::Fail("Nova TC2/Pipe-D plan must be admitted"),
        };
        let io = MainWellFake::new(true);
        let lease = match plan.acquire_main_wells(&io) {
            Ok(lease) => lease,
            Err(_) => return TestResult::Fail("Nova main wells must grant in source order"),
        };
        let all = well_request(PW_1_INDEX)
            | well_request(PW_2_INDEX)
            | well_request(pipe_well_index(Pipe::D));
        let expected_up = [
            well_request(PW_1_INDEX),
            well_request(PW_1_INDEX) | well_request(PW_2_INDEX),
            all,
        ];
        if lease.owned_request_mask() != all
            || io.writes.borrow().as_slice() != expected_up
            || lease.release(&io).is_err()
            || io.driver.get() != 0
            || io.writes.borrow().len() != 6
        {
            return TestResult::Fail("Nova main-well lease must own and reverse its requests");
        }

        let shared = MainWellFake::new(true);
        shared.driver.set(well_request(PW_1_INDEX));
        let panel = match NovaResourcePlan::new(LtPort::A, Pipe::A, NovaOutput::Edp) {
            Ok(plan) => plan,
            Err(_) => return TestResult::Fail("Nova panel plan must be admitted"),
        };
        let lease = match panel.acquire_main_wells(&shared) {
            Ok(lease) => lease,
            Err(_) => return TestResult::Fail("pre-owned PW1 must satisfy the panel plan"),
        };
        if lease.owned_request_mask() != well_request(pipe_well_index(Pipe::A))
            || lease.release(&shared).is_err()
            || shared.driver.get() != well_request(PW_1_INDEX)
        {
            return TestResult::Fail("a lease must not release a pre-existing DRIVER request");
        }

        let foreign = MainWellFake::new(true);
        let lease = match panel.acquire_main_wells(&foreign) {
            Ok(lease) => lease,
            Err(_) => return TestResult::Fail("Nova panel wells must grant"),
        };
        foreign.bios.set(well_request(pipe_well_index(Pipe::A)));
        if lease.release(&foreign).is_err()
            || foreign.driver.get() != 0
            || foreign.bios.get() != well_request(pipe_well_index(Pipe::A))
        {
            return TestResult::Fail("BIOS power-well requests must survive DRIVER release");
        }

        let stuck = MainWellFake::new(true);
        stuck
            .acknowledged_requests
            .set(stuck.acknowledged_requests.get() & !well_request(PW_2_INDEX));
        if plan.acquire_main_wells(&stuck) != Err(NovaResourceError::PowerWellTimeout(PW_2_INDEX))
            || stuck.driver.get() != 0
            || stuck
                .writes
                .borrow()
                .iter()
                .any(|value| value & well_request(pipe_well_index(Pipe::D)) != 0)
        {
            return TestResult::Fail("a partial Nova well grant must roll back before Pipe D");
        }

        let unfused = MainWellFake::new(true);
        unfused
            .fuse_status
            .set(unfused.fuse_status.get() & !fuse_status_mask(PW_2_INDEX));
        if plan.acquire_main_wells(&unfused)
            != Err(NovaResourceError::PowerGateFuseTimeout(PW_2_INDEX + 1))
            || unfused.driver.get() != 0
        {
            return TestResult::Fail("a missing Nova gate fuse must fail closed and roll back");
        }

        let crossed = MainWellFake::new(false);
        if plan.acquire_main_wells(&crossed) != Err(NovaResourceError::ProfileMismatch)
            || !crossed.writes.borrow().is_empty()
        {
            return TestResult::Fail("Nova wells must refuse a non-LT view before MMIO");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_nvl_resources",
        smoke_nvl_main_well_lease_orders_and_rolls_back
    );

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
