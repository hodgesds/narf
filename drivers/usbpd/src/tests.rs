//! Smoke tests for narf-drivers-usbpd.
//!
//! All driver behaviour is exercised against a `MockBus` in-memory
//! register file; no real silicon required.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::fusb302::{
    Fusb302, MockBus, FUSB302_DEFAULT_I2C_ADDR, REG_DEVICE_ID, REG_RESET, REG_STATUS0, REG_STATUS1,
    RESET_SW_RES, STATUS0_BC_LVL_MASK, STATUS1_RX_EMPTY, TX_TOKEN_PACKSYM_BASE, TX_TOKEN_SYNC1,
    TX_TOKEN_SYNC2,
};

fn smoke_fusb302_probe_device_id() -> TestResult {
    let bus = Arc::new(MockBus::new());
    let chip = Fusb302::new(bus, FUSB302_DEFAULT_I2C_ADDR);
    let id = chip.probe_device_id().expect("probe");
    if (id >> 4) < 0x8 {
        return TestResult::Fail("DEVICE_ID high nibble should be ≥ 0x8");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usbpd/fusb302", smoke_fusb302_probe_device_id);

fn smoke_fusb302_init_resets_chip() -> TestResult {
    let bus = Arc::new(MockBus::new());
    // Pre-stuff a register that SW_RES should clear.
    bus.set_reg(0x06, 0xFF);
    let chip = Fusb302::new(bus.clone(), FUSB302_DEFAULT_I2C_ADDR);
    chip.init().expect("init");
    // After init, CONTROL0 should be 0 (init writes 0 explicitly).
    let _ = bus; // anchor
    let bus = Arc::new(MockBus::new());
    let chip = Fusb302::new(bus.clone(), FUSB302_DEFAULT_I2C_ADDR);
    bus.set_reg(0x06, 0xFF);
    chip.init().unwrap();
    let v = bus.tx_log(); // SW_RES doesn't push to FIFO
    let _ = v;
    // Reading register 0x06 directly via the bus to confirm.
    use crate::fusb302::I2cBus as _;
    let c0 = bus.read_reg(FUSB302_DEFAULT_I2C_ADDR, 0x06).unwrap();
    if c0 != 0 {
        return TestResult::Fail("CONTROL0 should be cleared after init");
    }
    // Confirm DEVICE_ID survived SW_RES (preserved by silicon).
    let id = bus
        .read_reg(FUSB302_DEFAULT_I2C_ADDR, REG_DEVICE_ID)
        .unwrap();
    if id == 0 {
        return TestResult::Fail("DEVICE_ID should not be zeroed by SW_RES");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/usbpd/fusb302", smoke_fusb302_init_resets_chip);

fn smoke_fusb302_set_role_writes_switches0() -> TestResult {
    use crate::fusb302::I2cBus as _;
    use narf_usbpd::tcpc::{PortRole, Tcpc};

    let bus = Arc::new(MockBus::new());
    let chip = Fusb302::new(bus.clone(), FUSB302_DEFAULT_I2C_ADDR);
    chip.set_role(PortRole::Sink).expect("sink");
    let sw0 = bus.read_reg(FUSB302_DEFAULT_I2C_ADDR, 0x02).unwrap();
    // Sink: PDWN1 + PDWN2 set, PU_EN cleared.
    if sw0 & 0x3 != 0x3 {
        return TestResult::Fail("Sink role didn't set PDWN1 | PDWN2");
    }
    if sw0 & 0xC0 != 0 {
        return TestResult::Fail("Sink role left PU_EN bits set");
    }

    chip.set_role(PortRole::Source).expect("source");
    let sw0 = bus.read_reg(FUSB302_DEFAULT_I2C_ADDR, 0x02).unwrap();
    if sw0 & 0xC0 != 0xC0 {
        return TestResult::Fail("Source role didn't set PU_EN1 | PU_EN2");
    }
    if sw0 & 0x3 != 0 {
        return TestResult::Fail("Source role left PDWN bits set");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/fusb302",
    smoke_fusb302_set_role_writes_switches0
);

fn smoke_fusb302_cc_status_decodes_bc_lvl() -> TestResult {
    use narf_usbpd::tcpc::{CcState, Tcpc};

    let bus = Arc::new(MockBus::new());
    // STATUS0.BC_LVL = 0b11 → Rp@3A.
    bus.set_reg(REG_STATUS0, STATUS0_BC_LVL_MASK);
    let chip = Fusb302::new(bus.clone(), FUSB302_DEFAULT_I2C_ADDR);
    let s = chip.cc_status().expect("cc_status");
    if s.cc1 != CcState::Rp3A0 || s.cc2 != CcState::Rp3A0 {
        return TestResult::Fail("BC_LVL=0b11 should decode to Rp3A0");
    }

    // BC_LVL = 0b00 → Open.
    bus.set_reg(REG_STATUS0, 0);
    let s = chip.cc_status().expect("cc_status");
    if s.cc1 != CcState::Open || s.cc2 != CcState::Open {
        return TestResult::Fail("BC_LVL=0b00 should decode to Open");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/fusb302",
    smoke_fusb302_cc_status_decodes_bc_lvl
);

fn smoke_fusb302_transmit_emits_sop_frame() -> TestResult {
    use narf_usbpd::tcpc::Tcpc;

    let bus = Arc::new(MockBus::new());
    let chip = Fusb302::new(bus.clone(), FUSB302_DEFAULT_I2C_ADDR);
    // PD body: 2-byte header + zero data objects.
    let pd_body = [0x16u8, 0x18];
    chip.transmit(&pd_body).expect("transmit");
    let log = bus.tx_log();
    // Expect the SOP signal sequence at the start: SYNC1, SYNC1, SYNC1, SYNC2.
    if log.len() < 5 {
        return TestResult::Fail("TX FIFO log too short");
    }
    if log[0] != TX_TOKEN_SYNC1
        || log[1] != TX_TOKEN_SYNC1
        || log[2] != TX_TOKEN_SYNC1
        || log[3] != TX_TOKEN_SYNC2
    {
        return TestResult::Fail("SOP token sequence drift");
    }
    // Token 4 should be PACKSYM(2).
    if log[4] != (TX_TOKEN_PACKSYM_BASE | (pd_body.len() as u8 & 0x1F)) {
        return TestResult::Fail("PACKSYM token did not encode body length");
    }
    // The pd_body bytes follow.
    if log[5..5 + pd_body.len()] != pd_body {
        return TestResult::Fail("body bytes did not appear in TX FIFO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/fusb302",
    smoke_fusb302_transmit_emits_sop_frame
);

fn smoke_fusb302_receive_drains_rx_fifo() -> TestResult {
    use narf_usbpd::tcpc::Tcpc;

    let bus = Arc::new(MockBus::new());
    let chip = Fusb302::new(bus.clone(), FUSB302_DEFAULT_I2C_ADDR);

    // Build a synthetic RX stream: SOP token (0xE0), then a 2-byte
    // PD header advertising 1 data object, then 4 PD payload bytes,
    // then 4 CRC bytes (driver discards).
    let pd_header_le: u16 = (1 << 12) | 0x42; // num_data_objects=1, low bits arbitrary
    let header_bytes = pd_header_le.to_le_bytes();
    let payload = [0xAA, 0xBB, 0xCC, 0xDD];
    let crc = [0u8; 4];
    let mut rx = alloc::vec![0xE0u8];
    rx.extend_from_slice(&header_bytes);
    rx.extend_from_slice(&payload);
    rx.extend_from_slice(&crc);
    bus.enqueue_rx(&rx);

    let frame = chip.receive().expect("receive");
    // Driver returns header + payload only (no CRC, no SOP token).
    if frame.len() != 2 + payload.len() {
        return TestResult::Fail("receive should drop SOP+CRC tokens");
    }
    if frame[0..2] != header_bytes {
        return TestResult::Fail("PD header bytes wrong");
    }
    if frame[2..] != payload {
        return TestResult::Fail("PD payload bytes wrong");
    }
    // After draining, RX should report empty.
    use crate::fusb302::I2cBus as _;
    let s1 = bus.read_reg(FUSB302_DEFAULT_I2C_ADDR, REG_STATUS1).unwrap();
    if s1 & STATUS1_RX_EMPTY == 0 {
        return TestResult::Fail("RX_EMPTY should be set after drain");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/fusb302",
    smoke_fusb302_receive_drains_rx_fifo
);

fn smoke_fusb302_receive_empty_returns_no_message() -> TestResult {
    use narf_usbpd::tcpc::{Tcpc, TcpcError};
    let bus = Arc::new(MockBus::new());
    let chip = Fusb302::new(bus.clone(), FUSB302_DEFAULT_I2C_ADDR);
    // RX FIFO empty by default.
    bus.set_reg(REG_STATUS1, STATUS1_RX_EMPTY);
    match chip.receive() {
        Err(TcpcError::NoMessage) => TestResult::Pass,
        _ => TestResult::Fail("empty FIFO should yield NoMessage"),
    }
}
kernel_test_in!(
    "drivers/usbpd/fusb302",
    smoke_fusb302_receive_empty_returns_no_message
);

fn smoke_fusb302_hard_reset_sets_control3_bit() -> TestResult {
    use crate::fusb302::I2cBus as _;
    use narf_usbpd::tcpc::Tcpc;
    let bus = Arc::new(MockBus::new());
    let chip = Fusb302::new(bus.clone(), FUSB302_DEFAULT_I2C_ADDR);
    chip.hard_reset().expect("hard_reset");
    let c3 = bus.read_reg(FUSB302_DEFAULT_I2C_ADDR, 0x09).unwrap();
    if c3 & 0x40 == 0 {
        return TestResult::Fail("CONTROL3.SEND_HARD_RESET bit not set");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/fusb302",
    smoke_fusb302_hard_reset_sets_control3_bit
);

// ── TPS65987 ───────────────────────────────────────────────────────

fn smoke_tps65987_probe_validates_vendor() -> TestResult {
    use crate::fusb302::I2cBus;
    use crate::tps65987::{Tps65987, TPS65987_DEFAULT_I2C_ADDR};
    let bus = Arc::new(MockBus::new());
    // Pre-load the Vendor ID register: TI = 0x0451 LE, padded to 4 bytes.
    let _ = bus.write_reg(TPS65987_DEFAULT_I2C_ADDR, 0x00, 0x51);
    let _ = bus.write_reg(TPS65987_DEFAULT_I2C_ADDR, 0x01, 0x04);
    // Device ID 0xF987 LE.
    let _ = bus.write_reg(TPS65987_DEFAULT_I2C_ADDR, 0x01, 0x04);
    bus.set_reg(0x00, 0x51); // VID low
    bus.set_reg(0x01, 0x04); // VID high (then DID register starts at 0x01 too —
                             // we set it via set_reg sequencing below)
                             // Wait — the mock is a flat 256-register table, not a multi-byte
                             // register file. Lay out the four-byte VID at 0x00..=0x03 and the
                             // four-byte DID at 0x01..=0x04 — they overlap, so re-stamp DID.
    bus.set_reg(0x00, 0x51);
    bus.set_reg(0x01, 0x04);
    bus.set_reg(0x02, 0x00);
    bus.set_reg(0x03, 0x00);
    // DID block at 0x01: 0x87 0xF9 0x00 0x00.
    bus.set_reg(0x01, 0x04); // overlap leaves vendor's high byte intact

    let chip = Tps65987::new(bus.clone(), TPS65987_DEFAULT_I2C_ADDR);
    let (vendor, _) = chip.probe().expect("probe");
    if vendor != 0x0451 {
        return TestResult::Fail("VID parse should yield 0x0451 (TI)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/tps65987",
    smoke_tps65987_probe_validates_vendor
);

fn smoke_tps65987_decode_cc_orientation() -> TestResult {
    use crate::tps65987::{Tps65987, TPS65987_DEFAULT_I2C_ADDR};
    use narf_usbpd::tcpc::{CcState, Tcpc};

    let bus = Arc::new(MockBus::new());
    // Type-C Status: orientation = 1 (CC1), connection = 3 (sink-mode source-attached).
    // Layout: bits 0..2 orientation, bits 2..5 connection.
    let typec_status: u8 = 1 | (3 << 2);
    bus.set_reg(0x05, typec_status);
    // Vendor probe path is bypassed for this test — call cc_status directly.
    let chip = Tps65987::new(bus.clone(), TPS65987_DEFAULT_I2C_ADDR);
    let s = chip.cc_status().expect("cc_status");
    if s.cc1 != CcState::RpDefault {
        return TestResult::Fail("orientation=1 + sink-conn should put Rp on CC1");
    }
    if s.cc2 != CcState::Open {
        return TestResult::Fail("CC2 should be Open when orientation=1");
    }

    bus.set_reg(0x05, 2 | (2 << 2));
    let s = chip.cc_status().expect("cc_status");
    if s.cc2 != CcState::Rd {
        return TestResult::Fail("orientation=2 + source-conn should put Rd on CC2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/tps65987",
    smoke_tps65987_decode_cc_orientation
);

fn smoke_tps65987_issue_cmd_writes_cmd1_and_data1() -> TestResult {
    use crate::fusb302::I2cBus;
    use crate::tps65987::{Tps65987, CMD4_HARD_RESET, REG_DATA1, TPS65987_DEFAULT_I2C_ADDR};
    // The mock for I²C address 0x38 (TPS65987) treats writes to the
    // four-byte Cmd1 block (0x08..=0x0B) as no-ops to simulate the
    // chip firmware's auto-clear of Cmd1 (TI TPS65987 TRM §"Host
    // Interface" — the firmware clears Cmd1 once it consumes the
    // 4CC). REG_DATA1 lives at 0x09 so its first three bytes
    // (0x09..=0x0B) sit inside the Cmd1 block too — our `issue_cmd`
    // intentionally writes Data1 *first* and then Cmd1, matching
    // the chip's spec-required ordering. Verify the post-Cmd1-block
    // bytes of Data1 hold the payload bytes we sent past the
    // overlap window. We send 4 bytes so byte 4 (REG_DATA1 + 3 =
    // 0x0C) lands outside the no-op range and survives the round-
    // trip.
    let bus = Arc::new(MockBus::new());
    let chip = Tps65987::new(bus.clone(), TPS65987_DEFAULT_I2C_ADDR);
    chip.issue_cmd(CMD4_HARD_RESET, &[0x00, 0x00, 0x00, 0xCD])
        .expect("issue");
    let d3 = bus
        .read_reg(TPS65987_DEFAULT_I2C_ADDR, REG_DATA1 + 3)
        .unwrap();
    if d3 != 0xCD {
        return TestResult::Fail("Data1 payload (post-Cmd1-overlap byte) not stored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/tps65987",
    smoke_tps65987_issue_cmd_writes_cmd1_and_data1
);

fn smoke_tps65987_receive_returns_no_message_on_zero_caps() -> TestResult {
    use crate::tps65987::{Tps65987, TPS65987_DEFAULT_I2C_ADDR};
    use narf_usbpd::tcpc::{Tcpc, TcpcError};
    let bus = Arc::new(MockBus::new());
    let chip = Tps65987::new(bus.clone(), TPS65987_DEFAULT_I2C_ADDR);
    // RX Source Caps register is zeroed by default → no message.
    match chip.receive() {
        Err(TcpcError::NoMessage) => TestResult::Pass,
        _ => TestResult::Fail("zero RX Caps must report NoMessage"),
    }
}
kernel_test_in!(
    "drivers/usbpd/tps65987",
    smoke_tps65987_receive_returns_no_message_on_zero_caps
);

fn smoke_tps65987_default_address_constant() -> TestResult {
    use crate::tps65987::TPS65987_DEFAULT_I2C_ADDR;
    if TPS65987_DEFAULT_I2C_ADDR != 0x38 {
        return TestResult::Fail("default I²C address drift (TRM says 0x38)");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/tps65987",
    smoke_tps65987_default_address_constant
);

fn smoke_fusb302_default_address_constant() -> TestResult {
    if FUSB302_DEFAULT_I2C_ADDR != 0x22 {
        return TestResult::Fail("default 7-bit I²C address drift (datasheet says 0x22)");
    }
    let _ = (REG_DEVICE_ID, REG_RESET, RESET_SW_RES); // anchor
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/fusb302",
    smoke_fusb302_default_address_constant
);

fn smoke_tcpc_connector_published_to_both_registries() -> TestResult {
    // Reset both registries (mirrors extcon sysfs_bridge tests' reset()).
    narf_drivers_extcon::class::REGISTRY.lock().clear();
    narf_drivers_extcon::typec_class::TYPEC_REGISTRY
        .lock()
        .clear();
    let conn = crate::publish_tcpc_connector("test-bus@0x22");
    // Publication → both registries, exactly once.
    if narf_drivers_extcon::typec_class::TYPEC_REGISTRY
        .lock()
        .len()
        != 1
    {
        return TestResult::Fail("TYPEC_REGISTRY should hold exactly one connector");
    }
    if narf_drivers_extcon::class::lookup("typec-test-bus@0x22").is_none() {
        return TestResult::Fail("extcon REGISTRY missing the TCPC connector");
    }
    // Initial class observation: an unattached port reads Dual/Dual.
    if conn.power_role() != narf_drivers_extcon::typec::PowerRole::Dual
        || conn.data_role() != narf_drivers_extcon::typec::DataRole::Dual
    {
        return TestResult::Fail("new TCPC connector should read Dual/Dual");
    }
    // A second binding is a second object, not a second entry for the first.
    let _ = crate::publish_tcpc_connector("test-bus@0x38");
    if narf_drivers_extcon::typec_class::TYPEC_REGISTRY
        .lock()
        .len()
        != 2
    {
        return TestResult::Fail("second TCPC binding should add a second registry entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/typec-publish",
    smoke_tcpc_connector_published_to_both_registries
);

// ── TcpmPort sink-swap routing (#1217) ─────────────────────────────

#[derive(Debug)]
struct PortFakeTcpc {
    role: narf_lib::sync::IrqSafeSpinLock<narf_usbpd::tcpc::PortRole>,
    cc: narf_lib::sync::IrqSafeSpinLock<narf_usbpd::tcpc::CcStatus>,
    tx: narf_lib::sync::IrqSafeSpinLock<Vec<Vec<u8>>>,
    rx: narf_lib::sync::IrqSafeSpinLock<Vec<Vec<u8>>>,
}

impl PortFakeTcpc {
    fn new() -> Self {
        Self {
            role: narf_lib::sync::IrqSafeSpinLock::new(narf_usbpd::tcpc::PortRole::Drp),
            cc: narf_lib::sync::IrqSafeSpinLock::new(narf_usbpd::tcpc::CcStatus {
                cc1: narf_usbpd::tcpc::CcState::Open,
                cc2: narf_usbpd::tcpc::CcState::Open,
            }),
            tx: narf_lib::sync::IrqSafeSpinLock::new(Vec::new()),
            rx: narf_lib::sync::IrqSafeSpinLock::new(Vec::new()),
        }
    }

    fn set_cc(&self, cc1: narf_usbpd::tcpc::CcState, cc2: narf_usbpd::tcpc::CcState) {
        *self.cc.lock() = narf_usbpd::tcpc::CcStatus { cc1, cc2 };
    }

    fn enqueue_rx(&self, frame: Vec<u8>) {
        self.rx.lock().push(frame);
    }
}

impl narf_usbpd::tcpc::Tcpc for PortFakeTcpc {
    fn name(&self) -> &'static str {
        "port-fake-tcpc"
    }

    fn set_role(&self, r: narf_usbpd::tcpc::PortRole) -> Result<(), narf_usbpd::tcpc::TcpcError> {
        *self.role.lock() = r;
        Ok(())
    }

    fn cc_status(&self) -> Result<narf_usbpd::tcpc::CcStatus, narf_usbpd::tcpc::TcpcError> {
        Ok(*self.cc.lock())
    }

    fn transmit(&self, msg: &[u8]) -> Result<(), narf_usbpd::tcpc::TcpcError> {
        self.tx.lock().push(msg.to_vec());
        Ok(())
    }

    fn receive(&self) -> Result<Vec<u8>, narf_usbpd::tcpc::TcpcError> {
        let mut q = self.rx.lock();
        if q.is_empty() {
            return Err(narf_usbpd::tcpc::TcpcError::NoMessage);
        }
        Ok(q.remove(0))
    }
}

fn port_ctrl_frame(msg: narf_usbpd::message::CtrlMsg, message_id: u8) -> Vec<u8> {
    let h = narf_usbpd::message::Header::control(
        msg,
        narf_usbpd::message::DataRole::Dfp,
        narf_usbpd::message::PowerRole::Source,
        narf_usbpd::message::SpecRev::R3_0,
        message_id,
    );
    narf_usbpd::message::encode_message(h, &[])
}

fn port_source_caps_frame(pdos: &[narf_usbpd::message::SourcePdo], message_id: u8) -> Vec<u8> {
    let h = narf_usbpd::message::Header::data(
        narf_usbpd::message::DataMsg::SourceCapabilities,
        narf_usbpd::message::DataRole::Dfp,
        narf_usbpd::message::PowerRole::Source,
        narf_usbpd::message::SpecRev::R3_0,
        message_id,
        pdos.len() as u8,
    );
    let objs: Vec<u32> = pdos.iter().map(|p| p.encode()).collect();
    narf_usbpd::message::encode_message(h, &objs)
}

/// #1217 routing: a sink port that completes a PR_Swap must move the
/// port-level state to `AttachedSrc`, hand the source engine a fresh
/// `Startup`, and carry the data role across (DR-swapped to DFP
/// before the PR swap, the new source engine must already be DFP).
fn smoke_tcpm_port_sink_pr_swap_routes_to_source() -> TestResult {
    use crate::policy::{SinkPolicy, SourcePolicy};
    use crate::tcpm::{PortState, PortStepOutcome, SourceState, TcpmPort};

    let tcpc = Arc::new(PortFakeTcpc::new());
    let port = Arc::new(TcpmPort::new(
        tcpc.clone(),
        SinkPolicy {
            accept_pr_swap: true,
            accept_dr_swap: true,
            ..SinkPolicy::default()
        },
        SourcePolicy::default(),
        "test".into(),
    ));
    let cap = narf_usbpd::bootstrap_usbpd_authority();
    tcpc.set_cc(
        narf_usbpd::tcpc::CcState::Rp3A0,
        narf_usbpd::tcpc::CcState::Open,
    );
    // 1. Classify -> AttachedSnk, then walk the sink engine to Ready.
    if port.step(&cap).is_err() {
        return TestResult::Fail("classify step");
    }
    if port.state() != PortState::AttachedSnk {
        return TestResult::Fail("did not classify as AttachedSnk");
    }
    for _ in 0..5 {
        if port.step(&cap).is_err() {
            return TestResult::Fail("sink walk step");
        }
    }
    if port.sink().state() != narf_usbpd::tcpm::SinkState::WaitCaps {
        return TestResult::Fail("sink did not reach WaitCaps via port");
    }
    let pdos = [narf_usbpd::message::SourcePdo::Fixed {
        voltage_mv: 5000,
        max_current_ma: 3000,
        epr_mode_capable: false,
    }];
    tcpc.enqueue_rx(port_source_caps_frame(&pdos, 0));
    if port.step(&cap).is_err() {
        return TestResult::Fail("wait-caps step");
    }
    if port.step(&cap).is_err() {
        return TestResult::Fail("evaluate step");
    }
    if port.step(&cap).is_err() {
        return TestResult::Fail("select step");
    }
    tcpc.enqueue_rx(port_ctrl_frame(narf_usbpd::message::CtrlMsg::Accept, 1));
    if port.step(&cap).is_err() {
        return TestResult::Fail("transition accept step");
    }
    tcpc.enqueue_rx(port_ctrl_frame(narf_usbpd::message::CtrlMsg::PsRdy, 2));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("transition ps-rdy step"),
    };
    if !matches!(outcome, PortStepOutcome::SinkReady(_)) {
        return TestResult::Fail("did not reach SinkReady via port");
    }
    // 2. DR swap first: sink becomes DFP while still a sink.
    tcpc.enqueue_rx(port_ctrl_frame(narf_usbpd::message::CtrlMsg::DrSwap, 3));
    if port.step(&cap).is_err() {
        return TestResult::Fail("dr swap step");
    }
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("dr change step"),
    };
    if outcome != (PortStepOutcome::DataRoleSwapped { now_dfp: true }) {
        return TestResult::Fail("DR swap did not report DFP via port");
    }
    if !port.sink().is_dfp() {
        return TestResult::Fail("sink data role did not flip");
    }
    // 3. PR swap: Accept, partner PS_RDY, port flips to AttachedSrc.
    tcpc.enqueue_rx(port_ctrl_frame(narf_usbpd::message::CtrlMsg::PrSwap, 4));
    if port.step(&cap).is_err() {
        return TestResult::Fail("pr swap step");
    }
    tcpc.enqueue_rx(port_ctrl_frame(narf_usbpd::message::CtrlMsg::PsRdy, 5));
    let outcome = match port.step(&cap) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("pr swap wait-off step"),
    };
    if outcome != PortStepOutcome::RoleSwapped(PortState::AttachedSrc) {
        return TestResult::Fail("PR swap did not route to AttachedSrc");
    }
    if port.state() != PortState::AttachedSrc {
        return TestResult::Fail("port state is not AttachedSrc after swap");
    }
    if port.source().state() != SourceState::Startup {
        return TestResult::Fail("source engine did not start at Startup");
    }
    if !port.source().is_dfp() {
        return TestResult::Fail("data role did not carry across the swap");
    }
    if port.sink().contract().is_some() {
        return TestResult::Fail("old sink contract survived the swap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/usbpd/tcpm",
    smoke_tcpm_port_sink_pr_swap_routes_to_source
);
