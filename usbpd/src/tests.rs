//! Smoke tests for narf-usbpd.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::message::{
    decode_message, encode_message, CtrlMsg, DataMsg, DataRole, FixedRdo, Header, PowerRole,
    SourcePdo, SpecRev,
};
use crate::tcpc::{CcState, CcStatus, PortRole, Tcpc, TcpcError};
use crate::tcpm::{SinkPort, SinkState, StepOutcome};

// ── Header round-trip ──────────────────────────────────────────────

fn smoke_header_round_trip() -> TestResult {
    let h = Header::data(
        DataMsg::Request,
        DataRole::Ufp,
        PowerRole::Sink,
        SpecRev::R3_0,
        4,
        1,
    );
    let raw = h.encode();
    let back = Header::decode(raw);
    if back != h {
        return TestResult::Fail("Header round-trip mismatch");
    }
    // Spec rev field at bits 6..7.
    if (raw >> 6) & 0x3 != 0b10 {
        return TestResult::Fail("SpecRev::R3_0 should encode to 0b10");
    }
    // Power role at bit 8 = 0 for Sink.
    if (raw >> 8) & 0x1 != 0 {
        return TestResult::Fail("PowerRole::Sink should encode bit 8 = 0");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_header_round_trip);

fn smoke_fixed_pdo_round_trip() -> TestResult {
    // 5V / 3A — the canonical USB-PD baseline (§6.4.1.3.1).
    let pdo = SourcePdo::Fixed {
        voltage_mv: 5000,
        max_current_ma: 3000,
    };
    let raw = pdo.encode();
    // Type field = 00.
    if (raw >> 30) & 0x3 != 0b00 {
        return TestResult::Fail("Fixed PDO type-field drift");
    }
    let back = SourcePdo::decode(raw);
    if back != pdo {
        return TestResult::Fail("Fixed PDO round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_fixed_pdo_round_trip);

fn smoke_pps_pdo_round_trip() -> TestResult {
    let pdo = SourcePdo::Augmented {
        max_voltage_mv: 21000,
        min_voltage_mv: 3300,
        max_current_ma: 5000,
    };
    let raw = pdo.encode();
    if (raw >> 30) & 0x3 != 0b11 {
        return TestResult::Fail("Augmented PDO type-field drift");
    }
    let back = SourcePdo::decode(raw);
    // PPS uses 100 mV / 50 mA quantisation; 3300 mV is exact, but
    // 21000 mV is also exact (210 * 100). Currents use 50 mA steps:
    // 5000 / 50 = 100 — fits.
    if back != pdo {
        return TestResult::Fail("PPS PDO round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_pps_pdo_round_trip);

fn smoke_fixed_rdo_round_trip() -> TestResult {
    let rdo = FixedRdo {
        object_position: 1,
        op_current_ma: 3000,
        max_op_current_ma: 3000,
        give_back: false,
        usb_comms: true,
        no_usb_suspend: true,
        cap_mismatch: false,
    };
    let raw = rdo.encode();
    let back = FixedRdo::decode(raw);
    if back != rdo {
        return TestResult::Fail("Fixed RDO round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_fixed_rdo_round_trip);

fn smoke_message_codec_pack_layout() -> TestResult {
    // Build a Source_Capabilities frame with a single Fixed 5V/3A PDO
    // and verify the wire layout: 2-byte LE header followed by 4-byte
    // LE PDO.
    let h = Header::data(
        DataMsg::SourceCapabilities,
        DataRole::Dfp,
        PowerRole::Source,
        SpecRev::R3_0,
        0,
        1,
    );
    let pdo = SourcePdo::Fixed {
        voltage_mv: 5000,
        max_current_ma: 3000,
    };
    let frame = encode_message(h, &[pdo.encode()]);
    if frame.len() != 6 {
        return TestResult::Fail("Source_Cap frame should be 2 + 4 = 6 bytes");
    }
    let (back_h, back_pdos) = match decode_message(&frame) {
        Some(p) => p,
        None => return TestResult::Fail("decode_message returned None"),
    };
    if back_h != h {
        return TestResult::Fail("decode header drift");
    }
    if back_pdos.len() != 1 || SourcePdo::decode(back_pdos[0]) != pdo {
        return TestResult::Fail("decode PDO drift");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_message_codec_pack_layout);

// ── TCPC fake + sink state machine ─────────────────────────────────

#[derive(Debug)]
struct FakeTcpc {
    role: IrqSafeSpinLock<PortRole>,
    cc: IrqSafeSpinLock<CcStatus>,
    tx: IrqSafeSpinLock<Vec<Vec<u8>>>,
    rx: IrqSafeSpinLock<Vec<Vec<u8>>>,
}

impl FakeTcpc {
    fn new() -> Self {
        Self {
            role: IrqSafeSpinLock::new(PortRole::Drp),
            cc: IrqSafeSpinLock::new(CcStatus {
                cc1: CcState::Open,
                cc2: CcState::Open,
            }),
            tx: IrqSafeSpinLock::new(Vec::new()),
            rx: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    fn set_cc(&self, cc1: CcState, cc2: CcState) {
        *self.cc.lock() = CcStatus { cc1, cc2 };
    }

    fn enqueue_rx(&self, frame: Vec<u8>) {
        self.rx.lock().push(frame);
    }

    fn sent_frames(&self) -> Vec<Vec<u8>> {
        self.tx.lock().clone()
    }
}

impl Tcpc for FakeTcpc {
    fn name(&self) -> &'static str {
        "fake-tcpc"
    }

    fn set_role(&self, r: PortRole) -> Result<(), TcpcError> {
        *self.role.lock() = r;
        Ok(())
    }

    fn cc_status(&self) -> Result<CcStatus, TcpcError> {
        Ok(*self.cc.lock())
    }

    fn transmit(&self, msg: &[u8]) -> Result<(), TcpcError> {
        self.tx.lock().push(msg.to_vec());
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, TcpcError> {
        let mut q = self.rx.lock();
        if q.is_empty() {
            return Err(TcpcError::NoMessage);
        }
        Ok(q.remove(0))
    }
}

fn ctrl_frame(msg: CtrlMsg, message_id: u8) -> Vec<u8> {
    let h = Header::control(
        msg,
        DataRole::Dfp,
        PowerRole::Source,
        SpecRev::R3_0,
        message_id,
    );
    encode_message(h, &[])
}

fn source_caps_frame(pdos: &[SourcePdo], message_id: u8) -> Vec<u8> {
    let h = Header::data(
        DataMsg::SourceCapabilities,
        DataRole::Dfp,
        PowerRole::Source,
        SpecRev::R3_0,
        message_id,
        pdos.len() as u8,
    );
    let objs: Vec<u32> = pdos.iter().map(|p| p.encode()).collect();
    encode_message(h, &objs)
}

fn smoke_sink_state_machine_5v3a_contract() -> TestResult {
    use crate::bootstrap_usbpd_authority;

    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc.clone()));
    let cap = bootstrap_usbpd_authority();

    // 1. Unattached → AttachWait when CC1 sees Rp@3A.
    tcpc.set_cc(CcState::Rp3A0, CcState::Open);
    let _ = port.step(&cap).expect("unattached step");
    if port.state() != SinkState::AttachWait {
        return TestResult::Fail("did not advance to AttachWait");
    }
    // 2. AttachWait → Attached.
    let _ = port.step(&cap).expect("attach-wait step");
    if port.state() != SinkState::Attached {
        return TestResult::Fail("did not advance to Attached");
    }
    // 3. Attached → Startup → Discovery → WaitCaps via empty steps.
    let _ = port.step(&cap).unwrap(); // Attached → Startup
    let _ = port.step(&cap).unwrap(); // Startup → Discovery
    let _ = port.step(&cap).unwrap(); // Discovery → WaitCaps
    if port.state() != SinkState::WaitCaps {
        return TestResult::Fail("did not reach WaitCaps");
    }
    // 4. Source_Capabilities arrives.
    let pdos = [SourcePdo::Fixed {
        voltage_mv: 5000,
        max_current_ma: 3000,
    }];
    tcpc.enqueue_rx(source_caps_frame(&pdos, 0));
    let _ = port.step(&cap).unwrap(); // WaitCaps → EvaluateCaps
    if port.state() != SinkState::EvaluateCaps {
        return TestResult::Fail("WaitCaps did not advance on Source_Caps");
    }
    // 5. EvaluateCaps → SelectCapability (synchronous policy pick).
    let _ = port.step(&cap).unwrap();
    if port.state() != SinkState::SelectCapability {
        return TestResult::Fail("EvaluateCaps did not advance");
    }
    // 6. SelectCapability emits the Request, advances to TransitionSink.
    let _ = port.step(&cap).unwrap();
    if port.state() != SinkState::TransitionSink {
        return TestResult::Fail("SelectCapability did not transmit Request");
    }
    let sent = tcpc.sent_frames();
    if sent.len() != 1 {
        return TestResult::Fail("expected exactly one Request frame on the wire");
    }
    let (sent_h, sent_objs) = match decode_message(&sent[0]) {
        Some(p) => p,
        None => return TestResult::Fail("Request frame failed to decode"),
    };
    if DataMsg::from_u8(sent_h.msg_type) != Some(DataMsg::Request) {
        return TestResult::Fail("Request msg-type drift");
    }
    let rdo = FixedRdo::decode(sent_objs[0]);
    if rdo.object_position != 1 || rdo.op_current_ma != 3000 {
        return TestResult::Fail("RDO did not select PDO #1 @ 3A");
    }
    // 7. Source replies Accept then PS_RDY.
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::Accept, 1));
    let _ = port.step(&cap).unwrap();
    if port.state() != SinkState::TransitionSink {
        return TestResult::Fail("Accept should keep us in TransitionSink");
    }
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::PsRdy, 2));
    let outcome = port.step(&cap).unwrap();
    let contract = match outcome {
        StepOutcome::Ready { contract } => contract,
        _ => return TestResult::Fail("PS_RDY did not produce a Ready outcome"),
    };
    if contract.voltage_mv != 5000 || contract.op_current_ma != 3000 {
        return TestResult::Fail("Contract did not lock 5V/3A");
    }
    if port.state() != SinkState::Ready {
        return TestResult::Fail("did not transition to Ready");
    }
    if port.contract() != Some(contract) {
        return TestResult::Fail("contract() snapshot mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/tcpm", smoke_sink_state_machine_5v3a_contract);

fn smoke_sink_rejects_empty_source_caps() -> TestResult {
    use crate::bootstrap_usbpd_authority;
    use crate::tcpm::SinkError;

    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc.clone()));
    let cap = bootstrap_usbpd_authority();

    tcpc.set_cc(CcState::Rp3A0, CcState::Open);
    // Walk to WaitCaps.
    let _ = port.step(&cap).unwrap(); // Unattached → AttachWait
    let _ = port.step(&cap).unwrap(); // AttachWait → Attached
    let _ = port.step(&cap).unwrap(); // Attached → Startup
    let _ = port.step(&cap).unwrap(); // Startup → Discovery
    let _ = port.step(&cap).unwrap(); // Discovery → WaitCaps

    // Source advertises 0 PDOs. Build a Source_Capabilities header
    // with num_data_objects = 0 (illegal but defensible to detect).
    let frame = source_caps_frame(&[], 0);
    tcpc.enqueue_rx(frame);
    match port.step(&cap) {
        // Empty caps means Source_Capabilities with num_data_objects=0,
        // which we interpret as a protocol error and bounce back to
        // Unattached. The state-machine test verifies that path.
        Ok(_) => {
            if port.state() == SinkState::Unattached {
                return TestResult::Pass;
            }
            return TestResult::Fail("empty Source_Caps should drop to Unattached");
        }
        Err(SinkError::NoPdos) => return TestResult::Pass,
        Err(_) => return TestResult::Fail("unexpected error variant"),
    }
}
kernel_test_in!("usbpd/tcpm", smoke_sink_rejects_empty_source_caps);

fn smoke_cap_revocation_blocks_step() -> TestResult {
    use crate::bootstrap_usbpd_authority;
    use crate::tcpm::SinkError;

    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc));
    let cap = bootstrap_usbpd_authority();
    cap.revoke();
    match port.step(&cap) {
        Err(SinkError::AuthorityRevoked) => TestResult::Pass,
        _ => TestResult::Fail("step accepted a revoked cap"),
    }
}
kernel_test_in!("usbpd/tcpm", smoke_cap_revocation_blocks_step);

fn smoke_cc_status_attached_logic() -> TestResult {
    let s_open = CcStatus {
        cc1: CcState::Open,
        cc2: CcState::Open,
    };
    if s_open.attached() {
        return TestResult::Fail("(Open, Open) should not be attached");
    }
    let s_ra_only = CcStatus {
        cc1: CcState::Ra,
        cc2: CcState::Open,
    };
    if s_ra_only.attached() {
        return TestResult::Fail("(Ra, Open) is a powered cable, not an attached partner");
    }
    let s_rp = CcStatus {
        cc1: CcState::Rp3A0,
        cc2: CcState::Open,
    };
    if !s_rp.attached() {
        return TestResult::Fail("(Rp3A0, Open) should report attached");
    }
    let _ = vec![1u8, 2]; // anchor alloc::vec import
    TestResult::Pass
}
kernel_test_in!("usbpd/tcpc", smoke_cc_status_attached_logic);

// ── VDM + DisplayPort Alt Mode ──────────────────────────────────────

fn smoke_vdm_header_round_trip() -> TestResult {
    use crate::vdm::{CommandType, VdmCommand, VdmHeader, SVID_DISPLAYPORT};
    let h = VdmHeader::structured(
        SVID_DISPLAYPORT,
        VdmCommand::DiscoverModes,
        CommandType::Req,
    );
    let raw = h.encode();
    // Top 16 bits must be the SVID.
    if (raw >> 16) as u16 != SVID_DISPLAYPORT {
        return TestResult::Fail("SVID not at MSBs of VDM header");
    }
    // Bit 15 = VDM Type = 1 (Structured).
    if (raw >> 15) & 0x1 != 1 {
        return TestResult::Fail("Structured VDM Type bit drift");
    }
    let back = VdmHeader::decode(raw);
    if back != h {
        return TestResult::Fail("VDM header round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/vdm", smoke_vdm_header_round_trip);

fn smoke_dp_status_vdo_round_trip() -> TestResult {
    use crate::vdm::DpStatusVdo;
    let s = DpStatusVdo {
        port_connected: 0b10, // UFP_D connected
        power_low: false,
        enabled: true,
        multi_function: true,
        usb_configured: false,
        exit_dp_mode: false,
        hpd_state: true,
        hpd_irq: false,
    };
    let raw = s.encode();
    let back = DpStatusVdo::decode(raw);
    if back != s {
        return TestResult::Fail("DP_Status VDO round-trip mismatch");
    }
    if (raw >> 7) & 0x1 != 1 {
        return TestResult::Fail("HPD State bit position drift");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/vdm", smoke_dp_status_vdo_round_trip);

fn smoke_dp_configure_vdo_round_trip() -> TestResult {
    use crate::vdm::{DpConfigureVdo, DpPinAssignment};
    let cfg = DpConfigureVdo::dfp_source(DpPinAssignment::D);
    let raw = cfg.encode();
    let back = DpConfigureVdo::decode(raw);
    if back != cfg {
        return TestResult::Fail("DP Configure VDO round-trip mismatch");
    }
    if back.dp_config != 1 {
        return TestResult::Fail("DFP_D config code drift (want 1)");
    }
    if back.dfp_d_pin != DpPinAssignment::D as u8 {
        return TestResult::Fail("Pin assignment D not set in DFP_D field");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/vdm", smoke_dp_configure_vdo_round_trip);

fn smoke_dp_alt_mode_discovery_full_walk() -> TestResult {
    use crate::vdm::{
        build_discover_identity_req, AltModeState, AltStepOutcome, CommandType, DpAltModeDriver,
        DpCapabilitiesVdo, DpStatusVdo, VdmCommand, VdmHeader, SVID_DISPLAYPORT, SVID_PD,
    };

    let mut drv = DpAltModeDriver::new();
    let kick = drv.start();
    match kick {
        AltStepOutcome::Transmit(v) if v == build_discover_identity_req() => {}
        _ => return TestResult::Fail("start() should kick Discover Identity"),
    }
    if drv.state != AltModeState::DiscoveringIdentity {
        return TestResult::Fail("state didn't move to DiscoveringIdentity");
    }

    // Identity ACK — single header, no VDOs needed for our walker.
    let id_ack = alloc::vec![VdmHeader::structured(
        SVID_PD,
        VdmCommand::DiscoverIdentity,
        CommandType::Ack
    )
    .encode()];
    match drv.feed_response(&id_ack) {
        AltStepOutcome::Transmit(_) => {}
        _ => return TestResult::Fail("Identity ACK should kick Discover SVIDs"),
    }
    if drv.state != AltModeState::DiscoveringSvids {
        return TestResult::Fail("state didn't move to DiscoveringSvids");
    }

    // SVIDs ACK — header + a VDO listing DisplayPort SVID in the high half.
    let svid_pack = ((SVID_DISPLAYPORT as u32) << 16) | 0x0000;
    let svids_ack = alloc::vec![
        VdmHeader::structured(SVID_PD, VdmCommand::DiscoverSvids, CommandType::Ack).encode(),
        svid_pack,
    ];
    match drv.feed_response(&svids_ack) {
        AltStepOutcome::Transmit(_) => {}
        _ => return TestResult::Fail("SVIDs ACK should kick Discover Modes"),
    }
    if drv.state != AltModeState::DiscoveringModes {
        return TestResult::Fail("state didn't move to DiscoveringModes");
    }

    // Modes ACK — header + a Capabilities VDO advertising pin D for DFP_D.
    let caps = (DpCapabilitiesVdo(0).0)
        | 0x3 // both UFP_D + DFP_D capable
        | (0x1 << 2) // HBR3 signalling
        | ((1u32 << 3) << 8); // DFP_D pin assignment D
    let modes_ack = alloc::vec![
        VdmHeader::structured(SVID_DISPLAYPORT, VdmCommand::DiscoverModes, CommandType::Ack)
            .encode(),
        caps,
    ];
    match drv.feed_response(&modes_ack) {
        AltStepOutcome::Transmit(_) => {}
        _ => return TestResult::Fail("Modes ACK should kick EnterMode"),
    }
    if drv.state != AltModeState::EnteringMode {
        return TestResult::Fail("state didn't move to EnteringMode");
    }

    // EnterMode ACK — header only.
    let enter_ack = alloc::vec![VdmHeader::structured(
        SVID_DISPLAYPORT,
        VdmCommand::EnterMode,
        CommandType::Ack
    )
    .encode()];
    match drv.feed_response(&enter_ack) {
        AltStepOutcome::Transmit(_) => {}
        _ => return TestResult::Fail("EnterMode ACK should kick Configure"),
    }
    if drv.state != AltModeState::ConfiguringDp {
        return TestResult::Fail("state didn't move to ConfiguringDp");
    }

    // Configure ACK arrives as Attention with the live DP_Status as
    // a VDO (per VESA DP Alt 2.0).
    let status = DpStatusVdo {
        port_connected: 0b10,
        power_low: false,
        enabled: true,
        multi_function: false,
        usb_configured: false,
        exit_dp_mode: false,
        hpd_state: true,
        hpd_irq: false,
    };
    let cfg_ack = alloc::vec![
        VdmHeader::structured(SVID_DISPLAYPORT, VdmCommand::Attention, CommandType::Ack).encode(),
        status.encode(),
    ];
    match drv.feed_response(&cfg_ack) {
        AltStepOutcome::Active(_) => {}
        _ => return TestResult::Fail("Configure ACK should produce Active outcome"),
    }
    if drv.state != AltModeState::Active {
        return TestResult::Fail("state didn't move to Active");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/vdm", smoke_dp_alt_mode_discovery_full_walk);

fn smoke_dp_alt_mode_nak_aborts() -> TestResult {
    use crate::vdm::{
        AltModeState, AltStepOutcome, CommandType, DpAltModeDriver, VdmCommand, VdmHeader, SVID_PD,
    };
    let mut drv = DpAltModeDriver::new();
    let _ = drv.start();
    let nak = alloc::vec![VdmHeader::structured(
        SVID_PD,
        VdmCommand::DiscoverIdentity,
        CommandType::Nak
    )
    .encode()];
    match drv.feed_response(&nak) {
        AltStepOutcome::Failed => {}
        _ => return TestResult::Fail("NAK should fail discovery"),
    }
    if drv.state != AltModeState::Failed {
        return TestResult::Fail("state didn't move to Failed on NAK");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/vdm", smoke_dp_alt_mode_nak_aborts);

fn smoke_port_registry_round_trip() -> TestResult {
    use crate::tcpm;
    tcpm::__test_reset();
    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc));
    tcpm::register(port.clone());
    let snap = tcpm::ports();
    if snap.len() != 1 {
        return TestResult::Fail("registry did not capture the port");
    }
    tcpm::__test_reset();
    if !tcpm::ports().is_empty() {
        return TestResult::Fail("__test_reset did not drain registry");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/tcpm", smoke_port_registry_round_trip);

// ── SOP'/SOP'' cable VDM smokes ────────────────────────────────────

fn smoke_sop_prime_target_constants() -> TestResult {
    use crate::sop_prime::{
        SOP_TARGET_CABLE_PLUG_FAR, SOP_TARGET_CABLE_PLUG_NEAR, SOP_TARGET_PORT_PARTNER,
    };
    if SOP_TARGET_PORT_PARTNER != 0 {
        return TestResult::Fail("SOP target = 0");
    }
    if SOP_TARGET_CABLE_PLUG_NEAR != 1 {
        return TestResult::Fail("SOP' target = 1");
    }
    if SOP_TARGET_CABLE_PLUG_FAR != 2 {
        return TestResult::Fail("SOP'' target = 2");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/sop-prime", smoke_sop_prime_target_constants);

fn smoke_sop_prime_id_header_round_trip() -> TestResult {
    use crate::sop_prime::{
        IdHeaderVdo, CABLE_PLUG_TYPE_PASSIVE_CABLE, CONNECTOR_PLUG,
    };
    let v = IdHeaderVdo {
        usb_host_capable: false,
        usb_device_capable: false,
        ufp_product_type: CABLE_PLUG_TYPE_PASSIVE_CABLE,
        modal_operation: false,
        dfp_product_type: 0,
        connector_type: CONNECTOR_PLUG,
        vendor_id: 0x05AC, // Apple as a known test VID
    };
    let raw = v.encode();
    let back = IdHeaderVdo::decode(raw);
    if back != v {
        return TestResult::Fail("ID Header VDO round-trip");
    }
    if (raw & 0xFFFF) != 0x05AC {
        return TestResult::Fail("VID lives in low 16 bits");
    }
    if (raw >> 27) & 0x07 != CABLE_PLUG_TYPE_PASSIVE_CABLE as u32 {
        return TestResult::Fail("UFP product type at bits 29..27");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/sop-prime", smoke_sop_prime_id_header_round_trip);

fn smoke_sop_prime_passive_cable_vdo_round_trip() -> TestResult {
    use crate::sop_prime::{
        PassiveCableVdo, USB_SS_SIGNALING_GEN2, VBUS_CURRENT_5A,
    };
    let v = PassiveCableVdo {
        hw_version: 1,
        firmware_version: 2,
        vdo_version: 1,
        plug_type: 0x02,
        epr_mode_capable: true,
        cable_latency: 4,
        cable_termination: 1,
        max_vbus_voltage: 1,
        vbus_current: VBUS_CURRENT_5A,
        usb_ss_signaling: USB_SS_SIGNALING_GEN2,
    };
    let raw = v.encode();
    let back = PassiveCableVdo::decode(raw);
    if back != v {
        return TestResult::Fail("Passive Cable VDO round-trip");
    }
    if (raw & 0x07) != USB_SS_SIGNALING_GEN2 as u32 {
        return TestResult::Fail("USB SS signaling lives in low 3 bits");
    }
    if (raw & (1 << 16)) == 0 {
        return TestResult::Fail("EPR Mode bit position");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/sop-prime", smoke_sop_prime_passive_cable_vdo_round_trip);

fn smoke_sop_prime_active_cable_vdo1_round_trip() -> TestResult {
    use crate::sop_prime::{ActiveCableVdo1, USB_SS_SIGNALING_GEN3};
    let v = ActiveCableVdo1 {
        hw_version: 0,
        firmware_version: 0,
        vdo_version: 1,
        plug_type: 0x02,
        epr_mode_capable: false,
        cable_latency: 7,
        cable_termination: 1,
        max_vbus_voltage: 2,
        sbu_supported: true,
        sbu_type: 1,
        vbus_current: 2,
        vbus_through_cable: true,
        sop_double_prime_supported: true,
        usb_ss_signaling: USB_SS_SIGNALING_GEN3,
    };
    let raw = v.encode();
    let back = ActiveCableVdo1::decode(raw);
    if back != v {
        return TestResult::Fail("Active Cable VDO1 round-trip");
    }
    if (raw & (1 << 3)) == 0 {
        return TestResult::Fail("SOP'' supported bit = 1<<3");
    }
    if (raw & (1 << 4)) == 0 {
        return TestResult::Fail("VBUS through cable bit = 1<<4");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/sop-prime", smoke_sop_prime_active_cable_vdo1_round_trip);

fn smoke_sop_prime_discover_identity_request() -> TestResult {
    use crate::sop_prime::{discover_identity_request_objects, SOP_TARGET_CABLE_PLUG_NEAR};
    let objs = discover_identity_request_objects(SOP_TARGET_CABLE_PLUG_NEAR);
    if objs.len() != 1 {
        return TestResult::Fail("Discover Identity request = 1 DWORD (header only)");
    }
    let h = objs[0];
    // SVID=0xFF00 in upper 16 bits.
    if (h >> 16) != 0xFF00 {
        return TestResult::Fail("Standard SVID 0xFF00 not at top 16 bits");
    }
    // VDM Type bit 15 set (structured).
    if h & (1 << 15) == 0 {
        return TestResult::Fail("Structured VDM bit not set");
    }
    // Command field (low 5 bits) = 1 (Discover Identity).
    if h & 0x1F != 1 {
        return TestResult::Fail("Discover Identity command code = 1");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/sop-prime", smoke_sop_prime_discover_identity_request);
