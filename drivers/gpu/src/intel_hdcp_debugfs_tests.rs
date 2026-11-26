//! HDCP debugfs fixtures (`drivers/gpu/intel_hdcp`). The names and texts
//! are laid out from Linux 7.4-rc4: `drm_connector_enum_list` and
//! `drm_connector_init` ("%s-%d", from 1), `intel_hdcp_sink_capability_show`
//! with `__intel_hdcp_info`, `str_yes_no` and `kstrtobool`.

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// The connector directory names, the sink capability text and the
/// `i915_force_hdcp14` write grammar.
fn smoke_intel_hdcp_debugfs_names_texts_and_bool_grammar() -> TestResult {
    if connector_name(ConnectorType::DisplayPort, 0).as_deref() != Some("DP-1")
        || connector_name(ConnectorType::HdmiA, 1).as_deref() != Some("HDMI-A-2")
        || connector_name(ConnectorType::HdmiB, 0).as_deref() != Some("HDMI-B-1")
        || connector_name(ConnectorType::Edp, 0).is_some()
        || connector_name(ConnectorType::Unknown, 0).is_some()
    {
        return TestResult::Fail("connector debugfs names");
    }
    if sink_capability_text("DP-1", 42, true, true) != "DP-1:42 HDCP version: HDCP1.4 HDCP2.2 \n"
        || sink_capability_text("HDMI-A-1", 7, true, false) != "HDMI-A-1:7 HDCP version: HDCP1.4 \n"
        || sink_capability_text("DP-2", 9, false, true) != "DP-2:9 HDCP version: HDCP2.2 \n"
        || sink_capability_text("DP-1", 42, false, false) != "DP-1:42 HDCP version: None\n"
    {
        return TestResult::Fail("intel_hdcp_sink_capability_show text");
    }
    for (input, want) in [
        (&b"1\n"[..], Some(true)),
        (b"y", Some(true)),
        (b"Yes", Some(true)),
        (b"T", Some(true)),
        (b"on", Some(true)),
        (b"ON\n", Some(true)),
        (b"0", Some(false)),
        (b"no", Some(false)),
        (b"F", Some(false)),
        (b"off", Some(false)),
        (b"oF", Some(false)),
        (b"o", None),
        (b"ox", None),
        (b"2", None),
        (b"", None),
    ] {
        if kstrtobool(input) != want {
            return TestResult::Fail("kstrtobool");
        }
    }
    let mut buf = [0u8; 8];
    if copy_at(b"yes\n", 0, &mut buf) != 4
        || &buf[..4] != b"yes\n"
        || copy_at(b"yes\n", 2, &mut buf) != 2
        || &buf[..2] != b"s\n"
        || copy_at(b"yes\n", 9, &mut buf) != 0
    {
        return TestResult::Fail("read offsets");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_hdcp",
    smoke_intel_hdcp_debugfs_names_texts_and_bool_grammar
);

/// The service side of the files: a capability query on a connector
/// without a route is answered -ENODEV by the next pass, as
/// `intel_hdcp_sink_capability_show` is without a connected encoder; with
/// a route the pass runs the query as the connector's operation (here with
/// no display behind it, so it ends -ENODEV too) and a later query takes a
/// new ticket. `i915_force_hdcp14` reads -ENODEV without a route, keeps a
/// written value across the route's binding, and reads it back. Errnos map
/// to Linux's: ENODEV, ETIMEDOUT.
fn smoke_intel_hdcp_debugfs_capability_and_force_through_the_service() -> TestResult {
    const CARD: u32 = 0xfff3;
    const CONNECTOR: u32 = 71;
    live::__attach_slot_for_test(CARD, CONNECTOR);
    let finish = |result| {
        live::__detach_card_for_test(CARD);
        result
    };
    // No such connector: ENODEV at once.
    if live::ask_capability(CARD, CONNECTOR + 1) != Err(HdcpError::NoRoute) {
        return finish(TestResult::Fail("query on a connector without HDCP"));
    }
    let Ok(ticket) = live::ask_capability(CARD, CONNECTOR) else {
        return finish(TestResult::Fail("capability query refused"));
    };
    // A second reader shares the pending query.
    if live::ask_capability(CARD, CONNECTOR) != Ok(ticket)
        || live::capability_answer(CARD, CONNECTOR, ticket).is_some()
    {
        return finish(TestResult::Fail("pending query not shared"));
    }
    live::__service_slot_for_test(CARD, CONNECTOR, Ok(None));
    if live::capability_answer(CARD, CONNECTOR, ticket) != Some(Err(HdcpError::NoRoute)) {
        return finish(TestResult::Fail("routeless query not answered ENODEV"));
    }
    if live::force_hdcp14(CARD, CONNECTOR) != Err(HdcpError::NoRoute)
        || live::set_force_hdcp14(CARD, CONNECTOR, true) != Ok(())
    {
        return finish(TestResult::Fail("force_hdcp14 without a route"));
    }
    // A route: bound on one pass, the query runs on the next.
    let route = live::RouteDesc {
        key: live::gen12_key(crate::intel_gpu_ddi::Ddi::B),
        protocol: crate::intel_hdcp::Protocol::Dp,
        transcoder: 1,
        link: live::RouteLink::Dp(crate::intel_hdcp_shim::AuxPort::Gen12(
            crate::intel_gpu_ddi::Ddi::B,
        )),
        display_ver: 12,
        hw: crate::intel_hdcp::HdcpHw::TRANSCODER,
        hdcp2: true,
        rekey: crate::intel_hdcp::LineRekey::None,
        cp_irq: false,
        mst: live::MstStreams::default(),
    };
    let Ok(ticket) = live::ask_capability(CARD, CONNECTOR) else {
        return finish(TestResult::Fail("second capability query refused"));
    };
    for _ in 0..3 {
        live::__service_slot_for_test(CARD, CONNECTOR, Ok(Some(route)));
    }
    if live::capability_answer(CARD, CONNECTOR, ticket) != Some(Err(HdcpError::NoRoute))
        || live::capability_answer(CARD, CONNECTOR, ticket.wrapping_sub(1))
            != Some(Err(HdcpError::Timeout))
    {
        return finish(TestResult::Fail("routed query not run by the service"));
    }
    if live::force_hdcp14(CARD, CONNECTOR) != Ok(true)
        || live::set_force_hdcp14(CARD, CONNECTOR, false) != Ok(())
        || live::force_hdcp14(CARD, CONNECTOR) != Ok(false)
    {
        return finish(TestResult::Fail("force_hdcp14 across the route"));
    }
    if fs_error(HdcpError::NoRoute) != FsError::NoDevice
        || fs_error(HdcpError::Timeout) != FsError::TimedOut
    {
        return finish(TestResult::Fail("errno mapping"));
    }
    finish(TestResult::Pass)
}
kernel_test_in!(
    "drivers/gpu/intel_hdcp",
    smoke_intel_hdcp_debugfs_capability_and_force_through_the_service
);
