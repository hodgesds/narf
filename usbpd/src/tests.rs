//! Smoke tests for narf-usbpd.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::message::{
    decode_message, encode_message, AvsRdo, CtrlMsg, DataMsg, DataRole, EprEnterFailedReason,
    EprModeAction, EprModeDataObject, FixedRdo, Header, PowerRole, ProgrammableRdo, SourcePdo,
    SpecRev,
};
use crate::tcpc::{CcState, CcStatus, PortRole, Tcpc, TcpcError};
use crate::tcpm::{SinkPort, SinkState, SinkSwapPolicy, StepOutcome};

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
        epr_mode_capable: false,
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
        epr_mode_capable: false,
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
        epr_mode_capable: false,
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

// ── EPR wire types (§6.4.1.2.5.2, §6.4.2 table 6.27, §6.4.10) ─────

fn smoke_epr_avs_apdo_byte_exact() -> TestResult {
    // EPR AVS APDO, source, 48 V max / 15 V min / 240 W PDP, peak 00.
    // Hand-built from table 6.14: bits 31..30 = 11, 29..28 = 01,
    // 27..26 = 00, 25..17 = 480 (48 V in 100 mV steps), bit 16 = 0,
    // 15..8 = 150 (15 V), 7..0 = 240 (PDP in watts).
    let pdo = SourcePdo::EprAvs {
        max_voltage_mv: 48000,
        min_voltage_mv: 15000,
        pdp_w: 240,
        peak_current: 0,
    };
    let raw = pdo.encode();
    if raw != 0xD3C0_96F0 {
        return TestResult::Fail("EPR AVS APDO word drift from table 6.14 layout");
    }
    let back = SourcePdo::decode(raw);
    if back != pdo {
        return TestResult::Fail("EPR AVS APDO round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_epr_avs_apdo_byte_exact);

fn smoke_apdo_subtype_split_is_not_masked() -> TestResult {
    // Masking-defeating: an SPR PPS word (sub-type 00) and an EPR
    // AVS word (sub-type 01) share type bits 31..30 = 11 but must
    // decode to different variants. The old code decoded every APDO
    // as SPR PPS, which would read an EPR AVS word's 9-bit max
    // voltage truncated and its PDP watts as a 50 mA current.
    let pps = SourcePdo::Augmented {
        max_voltage_mv: 21000,
        min_voltage_mv: 3300,
        max_current_ma: 5000,
    };
    let pps_raw = pps.encode();
    if (pps_raw >> 28) & 0x3 != 0b00 {
        return TestResult::Fail("SPR PPS sub-type bits drift");
    }
    if !matches!(SourcePdo::decode(pps_raw), SourcePdo::Augmented { .. }) {
        return TestResult::Fail("SPR PPS word decoded as non-Augmented");
    }
    let avs = SourcePdo::EprAvs {
        max_voltage_mv: 48000,
        min_voltage_mv: 15000,
        pdp_w: 240,
        peak_current: 0,
    };
    let avs_raw = avs.encode();
    if (avs_raw >> 28) & 0x3 != 0b01 {
        return TestResult::Fail("EPR AVS sub-type bits drift");
    }
    match SourcePdo::decode(avs_raw) {
        SourcePdo::EprAvs {
            max_voltage_mv,
            min_voltage_mv,
            pdp_w,
            ..
        } => {
            if max_voltage_mv != 48000 || min_voltage_mv != 15000 || pdp_w != 240 {
                return TestResult::Fail("EPR AVS fields drift after decode");
            }
        }
        _ => return TestResult::Fail("EPR AVS word decoded as non-EprAvs"),
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_apdo_subtype_split_is_not_masked);

fn smoke_avs_rdo_byte_exact_and_quantisation() -> TestResult {
    // AVS RDO, position 9 (EPR), 28 V @ 5 A, usb-comms + no-suspend
    // + EPR-capable set. Hand-built from table 6.27: bits 31..28 =
    // 1001, bit 25 = 1, bit 24 = 1, bit 22 = 1, bits 20..9 = 1120
    // (28 V in 25 mV units, low bits zero), bits 6..0 = 100 (5 A).
    let rdo = AvsRdo {
        object_position: 9,
        voltage_mv: 28000,
        op_current_ma: 5000,
        usb_comms: true,
        no_usb_suspend: true,
        cap_mismatch: false,
        epr_mode_capable: true,
    };
    let raw = rdo.encode();
    if raw != 0x9348_C064 {
        return TestResult::Fail("AVS RDO word drift from table 6.27 layout");
    }
    let back = AvsRdo::decode(raw);
    if back != rdo {
        return TestResult::Fail("AVS RDO round-trip mismatch");
    }
    // Voltage floors to the 100 mV step: 28130 mV encodes as 28100.
    let floored = AvsRdo {
        voltage_mv: 28130,
        ..rdo
    };
    if AvsRdo::decode(floored.encode()).voltage_mv != 28100 {
        return TestResult::Fail("AVS RDO voltage should floor to 100 mV");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_avs_rdo_byte_exact_and_quantisation);

fn smoke_epr_mode_data_object_codec() -> TestResult {
    // Table 6.51: bits 31..24 Action, bits 23..16 Data, bits 15..0 zero.
    let enter = EprModeDataObject::enter(240);
    if enter.encode() != 0x01F0_0000 {
        return TestResult::Fail("EPR_Mode Enter word drift");
    }
    if enter.operational_pdp_w() != Some(240) {
        return TestResult::Fail("Enter PDP accessor drift");
    }
    let failed = EprModeDataObject::enter_failed(EprEnterFailedReason::CableNotEprCapable);
    if failed.encode() != 0x0401_0000 {
        return TestResult::Fail("EPR_Mode Enter Failed word drift");
    }
    if failed.failed_reason() != Some(EprEnterFailedReason::CableNotEprCapable) {
        return TestResult::Fail("Enter Failed reason accessor drift");
    }
    let exit = EprModeDataObject::exit();
    if exit.encode() != 0x0500_0000 || exit.action != EprModeAction::Exit {
        return TestResult::Fail("EPR_Mode Exit word drift");
    }
    if EprModeDataObject::decode(0x0600_0000).is_some() {
        return TestResult::Fail("reserved EPR_Mode action 0x06 should not decode");
    }
    let back = EprModeDataObject::decode(enter.encode()).expect("decode Enter");
    if back != enter {
        return TestResult::Fail("EPRMDO round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_epr_mode_data_object_codec);

fn smoke_epr_mode_capable_bits_and_positions() -> TestResult {
    // Fixed PDO bit 23 (table 6.9) and RDO bit 22 (§6.4.2.7).
    let pdo = SourcePdo::Fixed {
        voltage_mv: 5000,
        max_current_ma: 3000,
        epr_mode_capable: true,
    };
    let raw = pdo.encode();
    if (raw >> 23) & 0x1 != 1 {
        return TestResult::Fail("Fixed PDO EPR Mode Capable bit 23 not set");
    }
    if !matches!(
        SourcePdo::decode(raw),
        SourcePdo::Fixed {
            epr_mode_capable: true,
            ..
        }
    ) {
        return TestResult::Fail("Fixed PDO EPR bit lost on decode");
    }
    // Object positions 8..=11 must survive the RDO codec — the old
    // 3-bit mask wrapped position 9 to 1.
    let rdo = FixedRdo {
        object_position: 9,
        op_current_ma: 5000,
        max_op_current_ma: 5000,
        give_back: false,
        usb_comms: true,
        no_usb_suspend: true,
        cap_mismatch: false,
        epr_mode_capable: true,
    };
    let raw = rdo.encode();
    if (raw >> 28) & 0xF != 9 || (raw >> 22) & 0x1 != 1 {
        return TestResult::Fail("Fixed RDO position 9 / EPR bit drift");
    }
    if FixedRdo::decode(raw) != rdo {
        return TestResult::Fail("Fixed RDO position-9 round-trip mismatch");
    }
    // Programmable RDO carries the same bit and width.
    let prdo = ProgrammableRdo {
        object_position: 2,
        voltage_mv: 9000,
        op_current_ma: 2000,
        usb_comms: true,
        no_usb_suspend: true,
        cap_mismatch: false,
        epr_mode_capable: true,
    };
    let raw = prdo.encode();
    if (raw >> 22) & 0x1 != 1 || ProgrammableRdo::decode(raw) != prdo {
        return TestResult::Fail("Programmable RDO EPR bit drift");
    }
    // Data message types: EPR_Request 0x09, EPR_Mode 0x0A.
    if DataMsg::from_u8(0x09) != Some(DataMsg::EprRequest)
        || DataMsg::from_u8(0x0A) != Some(DataMsg::EprMode)
    {
        return TestResult::Fail("EPR data message types drift");
    }
    // An EPR_Request frame is header + RDO + PDO copy = 10 bytes.
    let h = Header::data(
        DataMsg::EprRequest,
        DataRole::Ufp,
        PowerRole::Sink,
        SpecRev::R3_0,
        0,
        2,
    );
    let frame = encode_message(h, &[rdo.encode(), pdo.encode()]);
    if frame.len() != 10 {
        return TestResult::Fail("EPR_Request frame should be 2 + 8 = 10 bytes");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_epr_mode_capable_bits_and_positions);

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

    fn role(&self) -> PortRole {
        *self.role.lock()
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
        epr_mode_capable: false,
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

/// #1193: after `reset()`, a sink that held a contract must report
/// no contract and must run a *fresh* negotiation on re-attach —
/// the new partner's capabilities, not the stale ones, decide the
/// new contract.
fn smoke_sink_reset_clears_contract_and_renegotiates() -> TestResult {
    use crate::bootstrap_usbpd_authority;

    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc.clone()));
    let cap = bootstrap_usbpd_authority();

    // First negotiation: 5 V / 3 A partner, walked to Ready.
    tcpc.set_cc(CcState::Rp3A0, CcState::Open);
    let pdos_a = [SourcePdo::Fixed {
        voltage_mv: 5000,
        max_current_ma: 3000,
        epr_mode_capable: false,
    }];
    for _ in 0..5 {
        let _ = port.step(&cap).unwrap();
    }
    tcpc.enqueue_rx(source_caps_frame(&pdos_a, 0));
    let _ = port.step(&cap).unwrap(); // WaitCaps → EvaluateCaps
    let _ = port.step(&cap).unwrap(); // EvaluateCaps → SelectCapability
    let _ = port.step(&cap).unwrap(); // SelectCapability → TransitionSink (Request sent)
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::Accept, 1));
    let _ = port.step(&cap).unwrap();
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::PsRdy, 2));
    let _ = port.step(&cap).unwrap();
    if port.state() != SinkState::Ready || port.contract().map(|c| c.op_current_ma) != Some(3000) {
        return TestResult::Fail("first negotiation did not lock 5V/3A");
    }

    // Detach: the driving task resets the engine.
    port.reset();
    if port.state() != SinkState::Unattached {
        return TestResult::Fail("reset did not return to Unattached");
    }
    if port.contract().is_some() {
        return TestResult::Fail("reset left a stale contract visible");
    }

    // Re-attach to a *different* partner: 5 V / 1 A. The fresh
    // negotiation must request 1 A — if the stale caps/contract
    // leaked through, the Request would still ask for 3 A.
    let pdos_b = [SourcePdo::Fixed {
        voltage_mv: 5000,
        max_current_ma: 1000,
        epr_mode_capable: false,
    }];
    for _ in 0..5 {
        let _ = port.step(&cap).unwrap();
    }
    if port.state() != SinkState::WaitCaps {
        return TestResult::Fail("renegotiation did not reach WaitCaps");
    }
    tcpc.enqueue_rx(source_caps_frame(&pdos_b, 0));
    let _ = port.step(&cap).unwrap();
    let _ = port.step(&cap).unwrap();
    let _ = port.step(&cap).unwrap(); // Request sent
    let sent = tcpc.sent_frames();
    let (_, objs) = match decode_message(sent.last().expect("a Request was sent")) {
        Some(p) => p,
        None => return TestResult::Fail("renegotiation Request failed to decode"),
    };
    let rdo = FixedRdo::decode(objs[0]);
    if rdo.object_position != 1 || rdo.op_current_ma != 1000 {
        return TestResult::Fail("renegotiation Request did not follow the new caps (1A)");
    }
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::Accept, 1));
    let _ = port.step(&cap).unwrap();
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::PsRdy, 2));
    let _ = port.step(&cap).unwrap();
    if port.state() != SinkState::Ready || port.contract().map(|c| c.op_current_ma) != Some(1000) {
        return TestResult::Fail("renegotiation did not lock 5V/1A");
    }
    TestResult::Pass
}
kernel_test_in!(
    "usbpd/tcpm",
    smoke_sink_reset_clears_contract_and_renegotiates
);

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
            TestResult::Fail("empty Source_Caps should drop to Unattached")
        }
        Err(SinkError::NoPdos) => TestResult::Pass,
        Err(_) => TestResult::Fail("unexpected error variant"),
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
    let id_ack =
        alloc::vec![
            VdmHeader::structured(SVID_PD, VdmCommand::DiscoverIdentity, CommandType::Ack).encode()
        ];
    match drv.feed_response(&id_ack) {
        AltStepOutcome::Transmit(_) => {}
        _ => return TestResult::Fail("Identity ACK should kick Discover SVIDs"),
    }
    if drv.state != AltModeState::DiscoveringSvids {
        return TestResult::Fail("state didn't move to DiscoveringSvids");
    }

    // SVIDs ACK — header + a VDO listing DisplayPort SVID in the high half.
    let svid_pack = (SVID_DISPLAYPORT as u32) << 16;
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
        VdmHeader::structured(
            SVID_DISPLAYPORT,
            VdmCommand::DiscoverModes,
            CommandType::Ack
        )
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
    let nak =
        alloc::vec![
            VdmHeader::structured(SVID_PD, VdmCommand::DiscoverIdentity, CommandType::Nak).encode()
        ];
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
    use crate::sop_prime::{IdHeaderVdo, CABLE_PLUG_TYPE_PASSIVE_CABLE, CONNECTOR_PLUG};
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
    use crate::sop_prime::{PassiveCableVdo, USB_SS_SIGNALING_GEN2, VBUS_CURRENT_5A};
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
kernel_test_in!(
    "usbpd/sop-prime",
    smoke_sop_prime_passive_cable_vdo_round_trip
);

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
kernel_test_in!(
    "usbpd/sop-prime",
    smoke_sop_prime_active_cable_vdo1_round_trip
);

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

// ── Enter_USB (EUDO, §6.4.9) + USB4 entry driver ────────────────

use crate::message::{CableCurrent, CableSpeed, CableType, EnterUsbDataObject, UsbMode};
use crate::vdm::{
    build_usb4_identity_ack, Usb4EntryDriver, Usb4EntryOutcome, Usb4EntryState, VdmHeader,
};

/// Fixture entry parameters: USB4 mode, USB4-DRD host, USB4 Gen3
/// passive 3 A cable, PCIe + DP + TBT3 tunneling, host present.
/// The values are fixture assumptions (a real host supplies its own
/// capabilities and the SOP' cable parameters); the test pins that
/// the codec and the exchange carry exactly these values.
fn fixture_eudo() -> EnterUsbDataObject {
    EnterUsbDataObject {
        usb_mode: UsbMode::Usb4,
        usb4_drd: true,
        usb3_drd: false,
        cable_speed: CableSpeed::Usb4Gen3,
        cable_type: CableType::Passive,
        cable_current: CableCurrent::Current3A,
        pcie_support: true,
        dp_support: true,
        tbt_support: true,
        host_present: true,
    }
}

fn smoke_enter_usb_message_byte_pin() -> TestResult {
    let eudo = fixture_eudo();
    // Byte-pin the EUDO against the §6.4.9 field layout, computed
    // by hand: mode 2<<28 | drd 1<<26 | speed 3<<21 | current 2<<17
    // | pcie 1<<16 | dp 1<<15 | tbt 1<<14 | host 1<<13.
    if eudo.encode() != 0x2465_E000 {
        return TestResult::Fail("EUDO encode drift from §6.4.9 layout");
    }
    // Byte-pin the full EnterUsb frame: 2-byte LE header
    // (msg 0x08, DFP, R3.0, Source, id 0, 1 object = 0x11A8)
    // followed by the 4-byte LE EUDO.
    let h = Header::data(
        DataMsg::EnterUsb,
        DataRole::Dfp,
        PowerRole::Source,
        SpecRev::R3_0,
        0,
        1,
    );
    let frame = encode_message(h, &[eudo.encode()]);
    if frame.as_slice() != [0xA8, 0x11, 0x00, 0xE0, 0x65, 0x24] {
        return TestResult::Fail("EnterUsb frame bytes drift from spec-shaped frame");
    }
    let (back_h, back_objs) = match decode_message(&frame) {
        Some(p) => p,
        None => return TestResult::Fail("decode_message returned None"),
    };
    if DataMsg::from_u8(back_h.msg_type) != Some(DataMsg::EnterUsb) {
        return TestResult::Fail("EnterUsb must decode to DataMsg::EnterUsb");
    }
    if back_objs.len() != 1 || EnterUsbDataObject::decode(back_objs[0]) != Some(eudo) {
        return TestResult::Fail("EUDO round-trip drift");
    }
    // The remaining undecodable data types stay undecodable; only
    // 0x08 was fixed by this lane.
    if DataMsg::from_u8(0x05).is_some() || DataMsg::from_u8(0x07).is_some() {
        return TestResult::Fail("BatteryStatus/GetCountryInfo must still decode to None");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_enter_usb_message_byte_pin);

fn smoke_enter_usb_eudo_reserved_bits() -> TestResult {
    let eudo = fixture_eudo();
    let clean = eudo.encode();
    // Masking-defeating case: reserved bits (31, 27, 24, 12:0) set
    // must decode to the same EUDO, and re-encode must zero them.
    let tainted = clean | (1 << 31) | (1 << 27) | (1 << 24) | 0x1FFF;
    if EnterUsbDataObject::decode(tainted) != Some(eudo) {
        return TestResult::Fail("reserved EUDO bits must be ignored on decode");
    }
    if EnterUsbDataObject::decode(tainted).unwrap().encode() != clean {
        return TestResult::Fail("encode must zero reserved EUDO bits");
    }
    // Reserved field values must be rejected: mode 3, current 1,
    // speed 4 (no USB mode / current / speed with that value).
    let mode_reserved = (clean & !(0x7 << 28)) | (3 << 28);
    if EnterUsbDataObject::decode(mode_reserved).is_some() {
        return TestResult::Fail("EUDO mode 3 (reserved) must fail decode");
    }
    let current_reserved = (clean & !(0x3 << 17)) | (1 << 17);
    if EnterUsbDataObject::decode(current_reserved).is_some() {
        return TestResult::Fail("EUDO current 1 (reserved) must fail decode");
    }
    let speed_reserved = (clean & !(0x7 << 21)) | (4 << 21);
    if EnterUsbDataObject::decode(speed_reserved).is_some() {
        return TestResult::Fail("EUDO speed 4 (reserved) must fail decode");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/message", smoke_enter_usb_eudo_reserved_bits);

fn smoke_usb4_entry_driver_walk() -> TestResult {
    let eudo = fixture_eudo();
    let mut sm = Usb4EntryDriver::new(eudo);
    let first = sm.start();
    let req = match first {
        Usb4EntryOutcome::TransmitVdm(v) => v,
        _ => return TestResult::Fail("start must transmit Discover Identity"),
    };
    if sm.state != Usb4EntryState::DiscoveringIdentity {
        return TestResult::Fail("start must land in DiscoveringIdentity");
    }
    if req.len() != 1 {
        return TestResult::Fail("Discover Identity REQ is a single VDO");
    }
    let rh = VdmHeader::decode(req[0]);
    if rh.svid != 0xFF00 || rh.command != 1 {
        return TestResult::Fail("REQ must be SVID 0xFF00, DiscoverIdentity");
    }
    // USB4-capable ACK → EnterUsb transmission, then Active.
    let ack = build_usb4_identity_ack(0x8087);
    match sm.feed_response(&ack) {
        Usb4EntryOutcome::TransmitEnterUsb(sent) => {
            if sent != eudo {
                return TestResult::Fail("EnterUsb must carry the configured params");
            }
        }
        _ => return TestResult::Fail("USB4-capable ACK must yield EnterUsb"),
    }
    if sm.state != Usb4EntryState::EnteringUsb {
        return TestResult::Fail("ACK must land in EnteringUsb");
    }
    sm.mark_entered();
    if sm.state != Usb4EntryState::Active {
        return TestResult::Fail("mark_entered must land in Active");
    }
    // Negative: ACK without the USB4 capability bit → Failed, and
    // no EnterUsb is offered.
    let mut sm2 = Usb4EntryDriver::new(eudo);
    let _ = sm2.start();
    let mut ack_no_usb4 = build_usb4_identity_ack(0x8087);
    ack_no_usb4[4] = 0;
    if !matches!(sm2.feed_response(&ack_no_usb4), Usb4EntryOutcome::Failed)
        || sm2.state != Usb4EntryState::Failed
    {
        return TestResult::Fail("non-USB4 ACK must fail without EnterUsb");
    }
    // Negative: a REQ (not ACK) and an empty response both fail.
    let mut sm3 = Usb4EntryDriver::new(eudo);
    let req_frame = match sm3.start() {
        Usb4EntryOutcome::TransmitVdm(v) => v,
        _ => return TestResult::Fail("start must transmit"),
    };
    if !matches!(sm3.feed_response(&req_frame), Usb4EntryOutcome::Failed) {
        return TestResult::Fail("REQ fed as response must fail");
    }
    let mut sm4 = Usb4EntryDriver::new(eudo);
    let _ = sm4.start();
    if !matches!(sm4.feed_response(&[]), Usb4EntryOutcome::Failed) {
        return TestResult::Fail("empty response must fail");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/vdm", smoke_usb4_entry_driver_walk);

// ── Sink-side role swaps (#1217) ───────────────────────────────────

/// Drive a fresh sink port to `Ready` with a 5 V / 3 A contract, the
/// same walk as `smoke_sink_state_machine_5v3a_contract` but as a
/// reusable helper for the swap tests.
fn drive_sink_to_ready(
    tcpc: &Arc<FakeTcpc>,
    port: &Arc<SinkPort>,
    cap: &narf_capabilities::Cap<crate::UsbPd, narf_capabilities::Grant>,
) -> Result<crate::tcpm::Contract, &'static str> {
    tcpc.set_cc(CcState::Rp3A0, CcState::Open);
    let _ = port.step(cap).map_err(|_| "unattached step")?;
    let _ = port.step(cap).map_err(|_| "attach-wait step")?;
    let _ = port.step(cap).map_err(|_| "attached step")?;
    let _ = port.step(cap).map_err(|_| "startup step")?;
    let _ = port.step(cap).map_err(|_| "discovery step")?;
    if port.state() != SinkState::WaitCaps {
        return Err("did not reach WaitCaps");
    }
    let pdos = [SourcePdo::Fixed {
        voltage_mv: 5000,
        max_current_ma: 3000,
        epr_mode_capable: false,
    }];
    tcpc.enqueue_rx(source_caps_frame(&pdos, 0));
    let _ = port.step(cap).map_err(|_| "wait-caps step")?;
    let _ = port.step(cap).map_err(|_| "evaluate-caps step")?;
    let _ = port.step(cap).map_err(|_| "select-capability step")?;
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::Accept, 1));
    let _ = port.step(cap).map_err(|_| "transition accept step")?;
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::PsRdy, 2));
    match port.step(cap).map_err(|_| "transition ps-rdy step")? {
        StepOutcome::Ready { contract } => Ok(contract),
        _ => Err("PS_RDY did not produce a Ready outcome"),
    }
}

/// Last sent control message type, decoded (masking-defeating: the
/// test asserts on the decoded wire type, not on our own builder).
fn last_sent_ctrl(tcpc: &FakeTcpc) -> Option<CtrlMsg> {
    let sent = tcpc.sent_frames();
    let (h, _) = decode_message(sent.last()?)?;
    CtrlMsg::from_u8(h.msg_type)
}

fn last_sent_header(tcpc: &FakeTcpc) -> Option<Header> {
    let sent = tcpc.sent_frames();
    let (h, _) = decode_message(sent.last()?)?;
    Some(h)
}

fn smoke_sink_pr_swap_responder_accepts_and_becomes_source() -> TestResult {
    use crate::bootstrap_usbpd_authority;

    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc.clone()));
    let cap = bootstrap_usbpd_authority();
    if drive_sink_to_ready(&tcpc, &port, &cap).is_err() {
        return TestResult::Fail("setup: did not reach Ready");
    }
    port.set_swap_policy(SinkSwapPolicy {
        accept_pr_swap: true,
        ..SinkSwapPolicy::default()
    });
    // Partner initiates PR_Swap; we Accept and wait for its PS_RDY.
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::PrSwap, 3));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("PR_Swap step errored"),
    };
    if outcome != StepOutcome::Advanced(SinkState::PrSwapWaitOff) {
        return TestResult::Fail("PR_Swap did not advance to PrSwapWaitOff");
    }
    if last_sent_ctrl(&tcpc) != Some(CtrlMsg::Accept) {
        return TestResult::Fail("expected Accept in reply to PR_Swap");
    }
    if last_sent_header(&tcpc).map(|h| h.power_role) != Some(PowerRole::Sink) {
        return TestResult::Fail("Accept must still carry power role Sink");
    }
    // Partner turns its rail off and sends PS_RDY; we turn ours on
    // (PS_RDY), flip CC role, drop the contract, and report the swap.
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::PsRdy, 4));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("PrSwapWaitOff step errored"),
    };
    if outcome != StepOutcome::RoleSwappedToSource {
        return TestResult::Fail("partner PS_RDY did not complete the swap");
    }
    // Wire order pins the sequence: Request, Accept, PS_RDY.
    let types: Vec<Option<CtrlMsg>> = tcpc
        .sent_frames()
        .iter()
        .filter_map(|f| decode_message(f).map(|(h, _)| CtrlMsg::from_u8(h.msg_type)))
        .collect();
    // The Request is a data message (None here); the two control
    // frames must be Accept then PsRdy, in that order.
    let ctrls: Vec<CtrlMsg> = types.into_iter().flatten().collect();
    if ctrls != [CtrlMsg::Accept, CtrlMsg::PsRdy] {
        return TestResult::Fail("expected Accept then PS_RDY on the wire");
    }
    if tcpc.role() != PortRole::Source {
        return TestResult::Fail("CC role did not flip to Source");
    }
    if port.state() != SinkState::Unattached {
        return TestResult::Fail("sink engine did not park in Unattached");
    }
    if port.contract().is_some() {
        return TestResult::Fail("contract survived the role swap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "usbpd/tcpm",
    smoke_sink_pr_swap_responder_accepts_and_becomes_source
);

fn smoke_sink_pr_swap_responder_rejects_by_policy() -> TestResult {
    use crate::bootstrap_usbpd_authority;

    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc.clone()));
    let cap = bootstrap_usbpd_authority();
    if drive_sink_to_ready(&tcpc, &port, &cap).is_err() {
        return TestResult::Fail("setup: did not reach Ready");
    }
    // Default policy rejects every swap.
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::PrSwap, 3));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("PR_Swap step errored"),
    };
    if outcome != StepOutcome::Advanced(SinkState::Ready) {
        return TestResult::Fail("rejected PR_Swap did not return to Ready");
    }
    if last_sent_ctrl(&tcpc) != Some(CtrlMsg::Reject) {
        return TestResult::Fail("expected Reject in reply to PR_Swap");
    }
    if port.state() != SinkState::Ready || port.contract().is_none() {
        return TestResult::Fail("rejected swap disturbed Ready/contract");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/tcpm", smoke_sink_pr_swap_responder_rejects_by_policy);

fn smoke_sink_dr_swap_flips_data_role() -> TestResult {
    use crate::bootstrap_usbpd_authority;

    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc.clone()));
    let cap = bootstrap_usbpd_authority();
    if drive_sink_to_ready(&tcpc, &port, &cap).is_err() {
        return TestResult::Fail("setup: did not reach Ready");
    }
    port.set_swap_policy(SinkSwapPolicy {
        accept_dr_swap: true,
        ..SinkSwapPolicy::default()
    });
    if port.is_dfp() {
        return TestResult::Fail("sink must start as UFP");
    }
    // First swap: UFP -> DFP.
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::DrSwap, 3));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("DR_Swap step errored"),
    };
    if outcome != StepOutcome::Advanced(SinkState::DrSwapChange) {
        return TestResult::Fail("DR_Swap did not advance to DrSwapChange");
    }
    if last_sent_ctrl(&tcpc) != Some(CtrlMsg::Accept) {
        return TestResult::Fail("expected Accept in reply to DR_Swap");
    }
    // The Accept still carries the pre-flip role (UFP); the flip
    // happens in DrSwapChange.
    if last_sent_header(&tcpc).map(|h| h.data_role) != Some(DataRole::Ufp) {
        return TestResult::Fail("Accept must carry the pre-flip data role");
    }
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("DrSwapChange step errored"),
    };
    if outcome != (StepOutcome::DataRoleSwapped { now_dfp: true }) {
        return TestResult::Fail("DR_Swap did not report DFP");
    }
    if !port.is_dfp() || port.state() != SinkState::Ready {
        return TestResult::Fail("data role did not flip to DFP");
    }
    // Second swap: DFP -> UFP.
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::DrSwap, 4));
    if port.step(&cap).is_err() {
        return TestResult::Fail("second DR_Swap step");
    }
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("second DrSwapChange step errored"),
    };
    if outcome != (StepOutcome::DataRoleSwapped { now_dfp: false }) {
        return TestResult::Fail("second DR_Swap did not report UFP");
    }
    if port.is_dfp() {
        return TestResult::Fail("data role did not flip back to UFP");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/tcpm", smoke_sink_dr_swap_flips_data_role);

fn smoke_sink_vconn_swap_start_and_turn_off() -> TestResult {
    use crate::bootstrap_usbpd_authority;

    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc.clone()));
    let cap = bootstrap_usbpd_authority();
    if drive_sink_to_ready(&tcpc, &port, &cap).is_err() {
        return TestResult::Fail("setup: did not reach Ready");
    }
    port.set_swap_policy(SinkSwapPolicy {
        accept_vconn_swap: true,
        ..SinkSwapPolicy::default()
    });
    if port.is_vconn_supplier() {
        return TestResult::Fail("sink must start as VConn consumer");
    }
    // Become supplier: Accept -> Start -> PS_RDY + flag.
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::VconnSwap, 3));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("VconnSwap step errored"),
    };
    if outcome != StepOutcome::Advanced(SinkState::VconnSwapStart) {
        return TestResult::Fail("VconnSwap did not advance to VconnSwapStart");
    }
    if last_sent_ctrl(&tcpc) != Some(CtrlMsg::Accept) {
        return TestResult::Fail("expected Accept in reply to VconnSwap");
    }
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("VconnSwapStart step errored"),
    };
    if outcome
        != (StepOutcome::VconnSwapped {
            now_supplying: true,
        })
    {
        return TestResult::Fail("VconnSwapStart did not report supplier");
    }
    if !port.is_vconn_supplier() || port.state() != SinkState::Ready {
        return TestResult::Fail("VConn supplier flag did not set");
    }
    if last_sent_ctrl(&tcpc) != Some(CtrlMsg::PsRdy) {
        return TestResult::Fail("expected PS_RDY after becoming supplier");
    }
    // Release: Accept -> TurnOff -> wait PS_RDY -> flag cleared.
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::VconnSwap, 4));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("second VconnSwap step errored"),
    };
    if outcome != StepOutcome::Advanced(SinkState::VconnSwapTurnOff) {
        return TestResult::Fail("second VconnSwap did not advance to TurnOff");
    }
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::PsRdy, 5));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("VconnSwapTurnOff step errored"),
    };
    if outcome
        != (StepOutcome::VconnSwapped {
            now_supplying: false,
        })
    {
        return TestResult::Fail("VconnSwapTurnOff did not report consumer");
    }
    if port.is_vconn_supplier() || port.state() != SinkState::Ready {
        return TestResult::Fail("VConn supplier flag did not clear");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/tcpm", smoke_sink_vconn_swap_start_and_turn_off);

fn smoke_sink_swap_initiate_paths() -> TestResult {
    use crate::bootstrap_usbpd_authority;

    let tcpc = Arc::new(FakeTcpc::new());
    let port = Arc::new(SinkPort::new(tcpc.clone()));
    let cap = bootstrap_usbpd_authority();
    // Initiation is illegal before Ready.
    if port.initiate_pr_swap() || port.initiate_dr_swap() || port.initiate_vconn_swap() {
        return TestResult::Fail("initiation must fail outside Ready");
    }
    if drive_sink_to_ready(&tcpc, &port, &cap).is_err() {
        return TestResult::Fail("setup: did not reach Ready");
    }
    // PR initiator, partner rejects: back to Ready, still a sink.
    if !port.initiate_pr_swap() || port.state() != SinkState::PrSwapSend {
        return TestResult::Fail("initiate_pr_swap did not enter PrSwapSend");
    }
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("PrSwapSend step errored"),
    };
    if outcome != StepOutcome::Advanced(SinkState::PrSwapWaitReply) {
        return TestResult::Fail("PrSwapSend did not advance to WaitReply");
    }
    if last_sent_ctrl(&tcpc) != Some(CtrlMsg::PrSwap) {
        return TestResult::Fail("expected PR_Swap on the wire");
    }
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::Reject, 3));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("PrSwapWaitReply step errored"),
    };
    if outcome != StepOutcome::Advanced(SinkState::Ready) {
        return TestResult::Fail("rejected PR_Swap did not return to Ready");
    }
    if tcpc.role() != PortRole::Sink {
        return TestResult::Fail("rejected swap changed the CC role");
    }
    // DR initiator, partner accepts: flip to DFP.
    if !port.initiate_dr_swap() {
        return TestResult::Fail("initiate_dr_swap failed in Ready");
    }
    if port.step(&cap).is_err() {
        return TestResult::Fail("DrSwapSend step");
    }
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::Accept, 4));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("DrSwapWaitReply step errored"),
    };
    if outcome != StepOutcome::Advanced(SinkState::DrSwapChange) {
        return TestResult::Fail("accepted DR_Swap did not reach DrSwapChange");
    }
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("DrSwapChange step errored"),
    };
    if outcome != (StepOutcome::DataRoleSwapped { now_dfp: true }) {
        return TestResult::Fail("initiated DR_Swap did not report DFP");
    }
    // VConn initiator, partner accepts: become supplier.
    if !port.initiate_vconn_swap() {
        return TestResult::Fail("initiate_vconn_swap failed in Ready");
    }
    if port.step(&cap).is_err() {
        return TestResult::Fail("VconnSwapSend step");
    }
    tcpc.enqueue_rx(ctrl_frame(CtrlMsg::Accept, 5));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("VconnSwapWaitReply step errored"),
    };
    if outcome != StepOutcome::Advanced(SinkState::VconnSwapStart) {
        return TestResult::Fail("accepted VconnSwap did not reach Start");
    }
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("VconnSwapStart step errored"),
    };
    if outcome
        != (StepOutcome::VconnSwapped {
            now_supplying: true,
        })
    {
        return TestResult::Fail("initiated VconnSwap did not report supplier");
    }
    TestResult::Pass
}
kernel_test_in!("usbpd/tcpm", smoke_sink_swap_initiate_paths);
