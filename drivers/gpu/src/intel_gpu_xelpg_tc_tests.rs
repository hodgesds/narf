//! Native register-model fixtures for MTL Type-C ownership and AUX power.
extern crate alloc;

use super::*;
use crate::intel_gpu_xelpg::tests::FakePhy;
use crate::intel_gpu_xelpg_hpd::{port_hotplug_ctl, sde_tc_hotplug};
use alloc::vec::Vec;
use core::cell::Cell;
use narf_kernel_test::{kernel_test_in, TestResult};

/// How `TCSS_DDI_STATUS.READY` behaves in the model.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ready {
    /// Never ready (IOM never hands the PHY over).
    Never,
    /// Ready while the TCSS power request is raised.
    FollowsPower,
}

/// The C20 Type-C port model: `FakePhy` with its TCSS power-state mirror,
/// plus PICA/SDE live levels, the IOM ready flag and the FIA pin
/// assignment. `drop_dp_alt_after` withdraws the DP-alt live bit after a
/// number of PICA ISR reads (a cable pulled mid-connect).
#[derive(Debug)]
pub struct TcFake {
    pub phy: FakePhy,
    pub ready: Cell<Ready>,
    pub pica_isr: Cell<u32>,
    pub sde_isr: Cell<u32>,
    pub pin: Cell<u8>,
    pub drop_dp_alt_after: Cell<Option<u32>>,
    pub access: Cell<bool>,
    reads: Cell<u32>,
}

impl TcFake {
    pub fn new(port: XeLpgPort) -> Self {
        let phy = FakePhy::new(port);
        phy.model_tcss.set(true);
        phy.model_d2d.set(true);
        phy.model_ddi_idle.set(true);
        Self {
            phy,
            ready: Cell::new(Ready::FollowsPower),
            pica_isr: Cell::new(0),
            sde_isr: Cell::new(0),
            pin: Cell::new(PIN_ASSIGNMENT_C),
            drop_dp_alt_after: Cell::new(None),
            access: Cell::new(true),
            reads: Cell::new(0),
        }
    }
    pub fn tc(&self) -> u8 {
        self.phy.port.tc_index().unwrap()
    }
    pub fn buf(&self) -> u32 {
        self.phy.read32(self.phy.port.buf_ctl1())
    }
    pub fn buf_writes(&self) -> Vec<u32> {
        self.phy.writes_to(self.phy.port.buf_ctl1())
    }
}

impl MmioWindow for TcFake {
    fn display_access_ok(&self) -> bool {
        self.access.get()
    }
    fn read32(&self, off: u64) -> u32 {
        if !self.access.get() {
            return u32::MAX;
        }
        let tc = self.tc();
        if off == PICA_ISR {
            let n = self.reads.get() + 1;
            self.reads.set(n);
            if let Some(limit) = self.drop_dp_alt_after.get() {
                if n > limit {
                    self.pica_isr
                        .set(self.pica_isr.get() & !pica_dp_alt_hotplug(tc));
                }
            }
            return self.pica_isr.get();
        }
        if off == SDE_ISR {
            return self.sde_isr.get();
        }
        if off == tcss_ddi_status(tc) {
            let powered = self.phy.read32(self.phy.port.buf_ctl1()) & TCSS_POWER_REQUEST != 0;
            return match self.ready.get() {
                Ready::FollowsPower if powered => TCSS_DDI_STATUS_READY,
                _ => 0,
            };
        }
        if off == port_tx_dflexpa1(tc) {
            return (self.pin.get() as u32) << pin_assignment_shift(tc);
        }
        self.phy.read32(off)
    }
    fn write32(&self, off: u64, value: u32) {
        if self.access.get() {
            self.phy.write32(off, value);
        }
    }
}

fn smoke_mtl_tc_register_map_all_four_ports() -> TestResult {
    let rows = [
        (
            XeLpgPort::Tc1,
            0x16_1500u64,
            0x16_3880u64,
            0u32,
            0x16_F270u64,
        ),
        (XeLpgPort::Tc2, 0x16_1504, 0x16_3880, 4, 0x16_F470),
        (XeLpgPort::Tc3, 0x16_1508, 0x16_E880, 0, 0x16_F670),
        (XeLpgPort::Tc4, 0x16_150C, 0x16_E880, 4, 0x16_F870),
    ];
    for (port, status, pa1, shift, hotplug) in rows {
        let tc = match port.tc_index() {
            Some(tc) => tc,
            None => return TestResult::Fail("TC port without a tc index"),
        };
        if tcss_ddi_status(tc) != status
            || port_tx_dflexpa1(tc) != pa1
            || pin_assignment_shift(tc) != shift
            || port_hotplug_ctl(tc) != hotplug
            || pica_dp_alt_hotplug(tc) != 1 << (16 + tc)
            || pica_tbt_hotplug(tc) != 1 << tc
            || sde_tc_hotplug(tc) != 1 << (24 + tc)
        {
            return TestResult::Fail("Type-C register map differs from the source");
        }
    }
    if XeLpgPort::B.tc_index().is_some() || XeLpgPort::A.tc_index().is_some() {
        return TestResult::Fail("combo ports have no Type-C index");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_tc",
    smoke_mtl_tc_register_map_all_four_ports
);

fn smoke_mtl_tc_dp_alt_connect_takes_ownership_and_disconnect_releases() -> TestResult {
    let io = TcFake::new(XeLpgPort::Tc2);
    io.pica_isr.set(pica_dp_alt_hotplug(1));
    io.pin.set(PIN_ASSIGNMENT_E);
    let conn = match connect(&io, XeLpgPort::Tc2, false, 1) {
        Ok(conn) => conn,
        Err(_) => return TestResult::Fail("DP-alt pin E connect must succeed"),
    };
    if conn.mode != TcMode::DpAlt
        || conn.max_lanes != 4
        || conn.tc != 1
        || conn.pin_assignment != PIN_ASSIGNMENT_E
    {
        return TestResult::Fail("connection facts wrong");
    }
    let buf = io.buf();
    if buf & (TCSS_POWER_REQUEST | TCSS_POWER_STATE | TC_PHY_OWNERSHIP)
        != TCSS_POWER_REQUEST | TCSS_POWER_STATE | TC_PHY_OWNERSHIP
    {
        return TestResult::Fail("connect must power the TCSS and own the PHY");
    }
    // Power request strictly precedes ownership (enable_tcss_power, then
    // take_ownership).
    let writes = io.buf_writes();
    let power = writes.iter().position(|w| w & TCSS_POWER_REQUEST != 0);
    let owned = writes.iter().position(|w| w & TC_PHY_OWNERSHIP != 0);
    match (power, owned) {
        (Some(p), Some(o)) if p < o => {}
        _ => return TestResult::Fail("TCSS power must be requested before ownership"),
    }
    if connection_intact(&io, &conn) != Ok(true)
        || current_mode(&io, XeLpgPort::Tc2, false) != Ok(TcMode::DpAlt)
    {
        return TestResult::Fail("owned connection must read back as DP-alt");
    }
    if disconnect(&io, &conn).is_err() {
        return TestResult::Fail("disconnect must succeed");
    }
    if io.buf() & (TCSS_POWER_REQUEST | TCSS_POWER_STATE | TC_PHY_OWNERSHIP) != 0 {
        return TestResult::Fail("disconnect must release ownership and TCSS power");
    }
    // Ownership is released before the power request drops.
    let writes = io.buf_writes();
    let n = writes.len();
    if n < 2
        || writes[n - 2] & TC_PHY_OWNERSHIP != 0
        || writes[n - 2] & TCSS_POWER_REQUEST == 0
        || writes[n - 1] & TCSS_POWER_REQUEST != 0
    {
        return TestResult::Fail("disconnect order must be ownership, then power");
    }
    // Not owned any more: the live DP-alt sink reads as TBT-owned.
    if current_mode(&io, XeLpgPort::Tc2, false) != Ok(TcMode::TbtAlt) {
        return TestResult::Fail("unowned PHY with live DP-alt must read TBT-alt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_tc",
    smoke_mtl_tc_dp_alt_connect_takes_ownership_and_disconnect_releases
);

fn smoke_mtl_tc_failed_ready_releases_power_without_ownership() -> TestResult {
    let io = TcFake::new(XeLpgPort::Tc1);
    io.pica_isr.set(pica_dp_alt_hotplug(0));
    io.ready.set(Ready::Never);
    if connect(&io, XeLpgPort::Tc1, false, 1) != Err(TcError::PhyNotReady) {
        return TestResult::Fail("an IOM that never hands over must refuse PhyNotReady");
    }
    if io.buf() & (TCSS_POWER_REQUEST | TC_PHY_OWNERSHIP) != 0
        || io.buf_writes().iter().any(|w| w & TC_PHY_OWNERSHIP != 0)
    {
        return TestResult::Fail("failed power-up must release the request, never own");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_tc",
    smoke_mtl_tc_failed_ready_releases_power_without_ownership
);

fn smoke_mtl_tc_tcss_power_stuck_times_out_and_rolls_back() -> TestResult {
    let io = TcFake::new(XeLpgPort::Tc3);
    io.pica_isr.set(pica_dp_alt_hotplug(2));
    io.phy.tcss_power_stuck.set(true);
    if connect(&io, XeLpgPort::Tc3, false, 1) != Err(TcError::TcssPowerTimeout) {
        return TestResult::Fail("unacknowledged TCSS power must refuse TcssPowerTimeout");
    }
    if io.buf() & (TCSS_POWER_REQUEST | TC_PHY_OWNERSHIP) != 0 {
        return TestResult::Fail("power timeout must drop the request without ownership");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_tc",
    smoke_mtl_tc_tcss_power_stuck_times_out_and_rolls_back
);

fn smoke_mtl_tc_pin_d_lanes_and_sudden_disconnect_roll_back() -> TestResult {
    // Pin assignment D: two DP lanes, PHY lane 1 owned by USB.
    let io = TcFake::new(XeLpgPort::Tc4);
    io.pica_isr.set(pica_dp_alt_hotplug(3));
    io.pin.set(PIN_ASSIGNMENT_D);
    let conn = match connect(&io, XeLpgPort::Tc4, false, 2) {
        Ok(conn) if conn.max_lanes == 2 => conn,
        _ => return TestResult::Fail("pin assignment D must admit two DP lanes"),
    };
    if disconnect(&io, &conn).is_err() || io.buf() & TC_PHY_OWNERSHIP != 0 {
        return TestResult::Fail("pin D disconnect must release ownership");
    }
    if connect(&io, XeLpgPort::Tc4, false, 4)
        != Err(TcError::InsufficientLanes {
            max: 2,
            required: 4,
        })
    {
        return TestResult::Fail("pin D must still refuse four DP lanes");
    }
    // No pin assignment: zero lanes cannot carry even one required lane.
    let none = TcFake::new(XeLpgPort::Tc4);
    none.pica_isr.set(pica_dp_alt_hotplug(3));
    none.pin.set(PIN_ASSIGNMENT_NONE);
    if connect(&none, XeLpgPort::Tc4, false, 1)
        != Err(TcError::InsufficientLanes {
            max: 0,
            required: 1,
        })
        || none.buf() & TC_PHY_OWNERSHIP != 0
    {
        return TestResult::Fail("pin NONE must refuse InsufficientLanes and release");
    }
    // Cable pulled between target-mode selection and verification.
    let pulled = TcFake::new(XeLpgPort::Tc1);
    pulled.pica_isr.set(pica_dp_alt_hotplug(0));
    pulled.drop_dp_alt_after.set(Some(1));
    if connect(&pulled, XeLpgPort::Tc1, false, 1) != Err(TcError::SuddenDisconnect)
        || pulled.buf() & TC_PHY_OWNERSHIP != 0
    {
        return TestResult::Fail("mid-connect unplug must refuse SuddenDisconnect and release");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_tc",
    smoke_mtl_tc_pin_d_lanes_and_sudden_disconnect_roll_back
);

fn smoke_mtl_tc_tbt_combo_and_access_refusals() -> TestResult {
    // A live TBT-alt route is observed without taking its PHY from USB4.
    let io = TcFake::new(XeLpgPort::Tc2);
    io.pica_isr.set(pica_tbt_hotplug(1));
    let conn = match connect(&io, XeLpgPort::Tc2, false, 1) {
        Ok(conn) if conn.mode == TcMode::TbtAlt => conn,
        _ => return TestResult::Fail("live TBT-alt must connect without taking the PHY"),
    };
    if !io.buf_writes().is_empty()
        || connection_intact(&io, &conn) != Ok(true)
        || disconnect(&io, &conn).is_err()
        || !io.buf_writes().is_empty()
    {
        return TestResult::Fail("TBT lifecycle must preserve fabric PHY ownership");
    }
    io.pica_isr.set(0);
    if connection_intact(&io, &conn) != Ok(false) {
        return TestResult::Fail("lost fabric HPD must invalidate TBT connection");
    }
    // Nothing connected on a Type-C port: default mode is TBT, refused.
    let empty = TcFake::new(XeLpgPort::Tc2);
    if connect(&empty, XeLpgPort::Tc2, false, 1) != Err(TcError::TunnelUnavailable)
        || !empty.buf_writes().is_empty()
    {
        return TestResult::Fail("empty Type-C port must refuse without writes");
    }
    // Combo ports are not Type-C: refuse before MMIO.
    struct NoAccess;
    impl MmioWindow for NoAccess {
        fn read32(&self, _: u64) -> u32 {
            panic!("combo port TC read");
        }
        fn write32(&self, _: u64, _: u32) {
            panic!("combo port TC write");
        }
    }
    for port in [XeLpgPort::A, XeLpgPort::B] {
        if connect(&NoAccess, port, false, 1) != Err(TcError::NotTypeC)
            || current_mode(&NoAccess, port, false) != Err(TcError::NotTypeC)
        {
            return TestResult::Fail("combo ports must refuse NotTypeC before MMIO");
        }
    }
    // Lost authority is a typed failure, never a mode.
    let lost = TcFake::new(XeLpgPort::Tc1);
    lost.pica_isr.set(pica_dp_alt_hotplug(0));
    lost.access.set(false);
    if connect(&lost, XeLpgPort::Tc1, false, 1) != Err(TcError::AccessLost)
        || live_status_mask(&lost, 0, false) != Err(TcError::AccessLost)
    {
        return TestResult::Fail("lost access must surface as AccessLost");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_tc",
    smoke_mtl_tc_tbt_combo_and_access_refusals
);

fn smoke_mtl_tc_legacy_declaration_fixup_and_lane_table() -> TestResult {
    // tc_port_fixup_legacy_flag: a single invalid live mode flips the flag.
    let legacy = TcMode::Legacy as u32;
    let dp_alt = TcMode::DpAlt as u32;
    if !fixup_legacy_flag(false, 1 << legacy)
        || !fixup_legacy_flag(true, 1 << legacy)
        || fixup_legacy_flag(true, 1 << dp_alt)
        || !fixup_legacy_flag(true, 0)
        || fixup_legacy_flag(false, 0b110)
    {
        return TestResult::Fail("legacy flag fixup differs from the source");
    }
    if TcMode::from_live_mask(0b1110) != TcMode::Legacy
        || TcMode::from_live_mask(0b0110) != TcMode::DpAlt
        || TcMode::from_live_mask(0) != TcMode::Disconnected
    {
        return TestResult::Fail("hpd_mask_to_tc_mode must pick the highest mode");
    }
    // mtl_get_max_lane_count.
    let table = [
        (PIN_ASSIGNMENT_NONE, 0u8),
        (PIN_ASSIGNMENT_C, 4),
        (PIN_ASSIGNMENT_D, 2),
        (PIN_ASSIGNMENT_E, 4),
        (1, 2),
        (6, 2),
    ];
    for (pin, lanes) in table {
        if max_lane_count(TcMode::DpAlt, pin) != lanes || max_lane_count(TcMode::Legacy, pin) != 4 {
            return TestResult::Fail("lane-count table differs from mtl_get_max_lane_count");
        }
    }
    // A declared legacy port connects through the SDE live bit with four
    // lanes regardless of the FIA pin field.
    let io = TcFake::new(XeLpgPort::Tc3);
    io.sde_isr.set(sde_tc_hotplug(2));
    io.pin.set(PIN_ASSIGNMENT_NONE);
    match connect(&io, XeLpgPort::Tc3, true, 4) {
        Ok(conn) if conn.mode == TcMode::Legacy && conn.max_lanes == 4 && conn.legacy_port => {}
        _ => return TestResult::Fail("declared legacy port must connect in legacy mode"),
    }
    // Undeclared: the same SDE bit is invisible, so the TBT default refuses.
    let undeclared = TcFake::new(XeLpgPort::Tc3);
    undeclared.sde_isr.set(sde_tc_hotplug(2));
    if connect(&undeclared, XeLpgPort::Tc3, false, 4) != Err(TcError::TunnelUnavailable) {
        return TestResult::Fail("undeclared legacy wiring must stay unadvertised");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_tc",
    smoke_mtl_tc_legacy_declaration_fixup_and_lane_table
);

fn smoke_mtl_tc_aux_power_well_request_and_busy_refusal() -> TestResult {
    for port in [XeLpgPort::B, XeLpgPort::Tc4] {
        let io = TcFake::new(XeLpgPort::Tc4);
        // The model is per port; drive the AUX CTL of `port` directly.
        if aux_power_enable(&io.phy, port).is_err()
            || aux_power_requested(&io.phy, port) != Ok(true)
        {
            return TestResult::Fail("AUX power request must be raised");
        }
        if io.phy.writes_to(port.aux_ctl()) != [XELPDP_AUX_CH_CTL_POWER_REQUEST] {
            return TestResult::Fail("AUX power enable must be one request write");
        }
        if aux_power_disable(&io.phy, port).is_err()
            || aux_power_requested(&io.phy, port) != Ok(false)
        {
            return TestResult::Fail("AUX power request must be released");
        }
    }
    // A foreign in-flight transaction is never re-triggered.
    let busy = TcFake::new(XeLpgPort::Tc1);
    busy.phy
        .write32(XeLpgPort::Tc1.aux_ctl(), AUX_CTL_SEND_BUSY);
    let before = busy.phy.writes.borrow().len();
    if aux_power_enable(&busy, XeLpgPort::Tc1) != Err(TcError::AuxBusy)
        || busy.phy.writes.borrow().len() != before
    {
        return TestResult::Fail("busy AUX must refuse without writing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_tc",
    smoke_mtl_tc_aux_power_well_request_and_busy_refusal
);
