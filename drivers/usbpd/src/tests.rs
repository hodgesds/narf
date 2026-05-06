//! Smoke tests for narf-drivers-usbpd.
//!
//! All driver behaviour is exercised against a `MockBus` in-memory
//! register file; no real silicon required.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::sync::Arc;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::fusb302::{
    Fusb302, MockBus, FUSB302_DEFAULT_I2C_ADDR, REG_DEVICE_ID, REG_RESET, REG_STATUS0,
    REG_STATUS1, RESET_SW_RES, STATUS0_BC_LVL_MASK, STATUS1_RX_EMPTY, TX_TOKEN_PACKSYM_BASE,
    TX_TOKEN_SYNC1, TX_TOKEN_SYNC2,
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
    let id = bus.read_reg(FUSB302_DEFAULT_I2C_ADDR, REG_DEVICE_ID).unwrap();
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
kernel_test_in!("drivers/usbpd/fusb302", smoke_fusb302_set_role_writes_switches0);

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
    if &log[5..5 + pd_body.len()] != pd_body {
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
    if &frame[0..2] != header_bytes {
        return TestResult::Fail("PD header bytes wrong");
    }
    if &frame[2..] != payload {
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
    use crate::fusb302::I2cBus as _;
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
