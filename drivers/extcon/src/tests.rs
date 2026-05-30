//! Smoke tests for narf-drivers-extcon.
//!
//! All tests run in-process against in-memory state; no hardware
//! required.

#![cfg(any(test, feature = "kernel-test"))]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use narf_usbpd::tcpc::{CcState, CcStatus};
use narf_usbpd::vdm::DpConfigureVdo;

use crate::cable::Cable;
use crate::class::{self, ExtconDevice as _, ExtconEventSink};
use crate::typec::{
    altmode::{
        dp_lane_count, encode_dp_configure, encode_dp_enter_mode, AltMode, DpPinAssign,
        SVID_DISPLAYPORT,
    },
    mux::{MuxSetting, NullMux, SsRouting, TypecMux},
    orientation_from_cc, Orientation, TypecConnector,
};

// ── 1: Extcon class register + state report ───────────────────────

fn smoke_extcon_register_and_state() -> TestResult {
    let conn = Arc::new(TypecConnector::new("extcon-test-0"));
    // Initially no cables attached.
    if conn.cable_state(Cable::Usb) {
        return TestResult::Fail("USB should not be attached initially");
    }
    // Register in the global registry.
    class::register(conn.clone());
    let count = class::device_count();
    if count == 0 {
        return TestResult::Fail("registry should be non-empty after register");
    }
    // Look it up by name.
    let found = class::lookup("extcon-test-0");
    if found.is_none() {
        return TestResult::Fail("lookup by name should succeed");
    }
    let dev = found.unwrap();
    if dev.name() != "extcon-test-0" {
        return TestResult::Fail("looked-up device name mismatch");
    }
    // Verify supported_cables is non-empty.
    if dev.supported_cables().is_empty() {
        return TestResult::Fail("supported_cables should be non-empty");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/extcon", smoke_extcon_register_and_state);

// ── 2: Cable state change → subscribers notified ─────────────────

struct RecordingSink {
    events: narf_lib::sync::IrqSafeSpinLock<Vec<(alloc::string::String, Cable, bool)>>,
}

impl RecordingSink {
    fn new() -> Self {
        Self { events: narf_lib::sync::IrqSafeSpinLock::new(Vec::new()) }
    }
    fn event_count(&self) -> usize {
        self.events.lock().len()
    }
    fn last_event(&self) -> Option<(alloc::string::String, Cable, bool)> {
        self.events.lock().last().cloned()
    }
}

impl core::fmt::Debug for RecordingSink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecordingSink").finish_non_exhaustive()
    }
}

impl ExtconEventSink for RecordingSink {
    fn on_cable_change(&self, device: &str, cable: Cable, attached: bool) {
        self.events.lock().push((device.into(), cable, attached));
    }
}

fn smoke_cable_change_notifies_subscribers() -> TestResult {
    let conn = Arc::new(TypecConnector::new("extcon-test-1"));
    let sink = Arc::new(RecordingSink::new());
    conn.subscribe(sink.clone());

    if sink.event_count() != 0 {
        return TestResult::Fail("no events before any change");
    }

    // Attach headphone.
    conn.update_cable_state(Cable::Headphone, true);
    if sink.event_count() != 1 {
        return TestResult::Fail("expected 1 event after headphone attach");
    }
    let (dev, cable, att) = sink.last_event().unwrap();
    if dev != "extcon-test-1" {
        return TestResult::Fail("wrong device name in event");
    }
    if cable != Cable::Headphone {
        return TestResult::Fail("wrong cable in event");
    }
    if !att {
        return TestResult::Fail("attached should be true");
    }

    // Detach headphone.
    conn.update_cable_state(Cable::Headphone, false);
    if sink.event_count() != 2 {
        return TestResult::Fail("expected 2 events after headphone detach");
    }
    let (_, _, att2) = sink.last_event().unwrap();
    if att2 {
        return TestResult::Fail("attached should be false on detach");
    }

    // Redundant update (same state) must NOT fire an event.
    conn.update_cable_state(Cable::Headphone, false);
    if sink.event_count() != 2 {
        return TestResult::Fail("redundant update must not fire event");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/extcon", smoke_cable_change_notifies_subscribers);

// ── 3: Orientation decode from CC1 pull-up ───────────────────────

fn smoke_orientation_from_cc1() -> TestResult {
    // CC1 active (Rp3A0), CC2 open → Normal orientation.
    let cc = CcStatus { cc1: CcState::Rp3A0, cc2: CcState::Open };
    if orientation_from_cc(cc) != Orientation::Normal {
        return TestResult::Fail("CC1 active should give Normal orientation");
    }

    // CC2 active, CC1 open → Reversed.
    let cc2 = CcStatus { cc1: CcState::Open, cc2: CcState::Rp1A5 };
    if orientation_from_cc(cc2) != Orientation::Reversed {
        return TestResult::Fail("CC2 active should give Reversed orientation");
    }

    // Both open → Unknown.
    let cc3 = CcStatus { cc1: CcState::Open, cc2: CcState::Open };
    if orientation_from_cc(cc3) != Orientation::Unknown {
        return TestResult::Fail("both open should give Unknown orientation");
    }

    // TypecConnector::update_cc propagates to connector state.
    let conn = TypecConnector::new("extcon-test-cc");
    conn.update_cc(cc);
    if conn.orientation() != Orientation::Normal {
        return TestResult::Fail("update_cc should update connector orientation");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/extcon", smoke_orientation_from_cc1);

// ── 4: DP Alt Mode Enter encode (Enter Mode SOP, SVID 0xFF01) ────

fn smoke_dp_altmode_enter_encode() -> TestResult {
    let vdos = encode_dp_enter_mode(1);
    if vdos.is_empty() {
        return TestResult::Fail("Enter Mode VDMs should not be empty");
    }
    // VDO[0] is the VDM header.
    let hdr = narf_usbpd::vdm::VdmHeader::decode(vdos[0]);
    if hdr.svid != SVID_DISPLAYPORT {
        return TestResult::Fail("Enter Mode header should have SVID 0xFF01");
    }
    // VdmCommand::EnterMode = 4 (USB-PD §6.4.4.1 Table 6-29).
    if hdr.command != 4u8 {
        return TestResult::Fail("VDM command should be EnterMode (4)");
    }
    // Object position must be 1.
    if hdr.object_position != 1 {
        return TestResult::Fail("object_position should be 1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/extcon", smoke_dp_altmode_enter_encode);

// ── 5: DP Status Update decode ───────────────────────────────────

fn smoke_dp_status_update_decode() -> TestResult {
    use narf_usbpd::vdm::DpStatusVdo;
    // VESA DP Alt 2.0 Table 5-2 / USB-PD §6.4.4.3.1:
    //   bits 1..0 = Port Connected (0=not, 1=DFP_D, 2=UFP_D, 3=both)
    //   bit 3 = Enabled
    //   bit 5 = USB Configured
    //
    // Build: Port Connected = UFP_D (0b10), Enabled (bit 3) set.
    let raw: u32 = 0b10 | (1 << 3);
    let status = DpStatusVdo::decode(raw);
    // Port Connected should be 2 (UFP_D).
    if status.port_connected != 2 {
        return TestResult::Fail("port_connected should be 2 (UFP_D)");
    }
    if !status.enabled {
        return TestResult::Fail("enabled bit should be set");
    }
    // USB Configured bit (bit 5) is clear.
    if status.usb_configured {
        return TestResult::Fail("usb_configured should be clear");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/extcon", smoke_dp_status_update_decode);

// ── 6: Pin assignment C (4 lanes DP) encode ──────────────────────

fn smoke_pin_assignment_c_encode() -> TestResult {
    // Encode a DP Configure for pin assignment C (4-lane).
    let vdos = encode_dp_configure(1, DpPinAssign::C);
    if vdos.is_empty() {
        return TestResult::Fail("DP Configure VDMs should not be empty");
    }
    // At least 2 VDOs: VDM header + DpConfigureVdo.
    if vdos.len() < 2 {
        return TestResult::Fail("expected at least 2 VDOs (header + config)");
    }
    // Decode the DpConfigureVdo.
    let cfg = DpConfigureVdo::decode(vdos[1]);
    // dp_config should be DFP_D (1) per dfp_source().
    if cfg.dp_config != 1 {
        return TestResult::Fail("DpConfigureVdo dp_config should be DFP_D (1)");
    }
    // dfp_d_pin encodes the selected pin assignment.
    // dfp_source(C) stores DpPinAssign::C as a byte in dfp_d_pin.
    if cfg.dfp_d_pin != (DpPinAssign::C as u8) {
        return TestResult::Fail("dfp_d_pin should encode DpPinAssign::C");
    }
    // Lane count for C must be 4.
    if dp_lane_count(DpPinAssign::C) != 4 {
        return TestResult::Fail("DpPinAssign::C should give 4 DP lanes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/extcon", smoke_pin_assignment_c_encode);

// ── 7: Mux: orient=Reversed + pin=C → Dp4Lane + Reversed ─────────

fn smoke_mux_reversed_pin_c() -> TestResult {
    let setting = MuxSetting::dp(Orientation::Reversed, DpPinAssign::C);
    if setting.orientation != Orientation::Reversed {
        return TestResult::Fail("mux orientation should be Reversed");
    }
    if setting.ss != SsRouting::Dp4Lane {
        return TestResult::Fail("pin C should route to Dp4Lane");
    }

    // Attach a NullMux to a connector and verify configure is accepted.
    let conn = Arc::new(TypecConnector::new("extcon-test-mux"));
    let mux: Arc<dyn TypecMux> = Arc::new(NullMux);
    conn.set_mux(mux);

    // Update CC → Reversed.
    let cc = CcStatus { cc1: CcState::Open, cc2: CcState::Rp3A0 };
    conn.update_cc(cc);
    if conn.orientation() != Orientation::Reversed {
        return TestResult::Fail("connector should report Reversed after update_cc");
    }

    // Enter DP Alt Mode with pin C — mux should be re-programmed.
    conn.set_alt_mode(AltMode::DisplayPort(DpPinAssign::C), true);
    if !conn.cable_state(Cable::Dp) {
        return TestResult::Fail("Cable::Dp should be attached after DP Alt Mode enter");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/extcon", smoke_mux_reversed_pin_c);

// ── 8: Headphone insertion → Cable::Headphone state high ─────────

fn smoke_headphone_cable_state() -> TestResult {
    let conn = Arc::new(TypecConnector::new("extcon-test-hp"));
    let sink = Arc::new(RecordingSink::new());
    conn.subscribe(sink.clone());

    // Initially not attached.
    if conn.cable_state(Cable::Headphone) {
        return TestResult::Fail("Headphone should not be attached initially");
    }

    // Insert headphone.
    conn.update_cable_state(Cable::Headphone, true);
    if !conn.cable_state(Cable::Headphone) {
        return TestResult::Fail("Headphone should be attached after update");
    }
    if sink.event_count() == 0 {
        return TestResult::Fail("subscriber should have been called");
    }
    let (_, cable, att) = sink.last_event().unwrap();
    if cable != Cable::Headphone {
        return TestResult::Fail("event should carry Cable::Headphone");
    }
    if !att {
        return TestResult::Fail("event should show attached=true");
    }

    // Remove headphone.
    conn.update_cable_state(Cable::Headphone, false);
    if conn.cable_state(Cable::Headphone) {
        return TestResult::Fail("Headphone should not be attached after removal");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/extcon", smoke_headphone_cable_state);
