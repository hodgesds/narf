use super::*;
use crate::drm::ioctl::{dispatch, mode_to_wire, DrmIoctlResult};
use crate::drm::render_node::DrmFileCtx;
use narf_kernel_test::{kernel_test_in, TestResult};

/// CEA 1920x1080@60: 148.5 MHz, 2200x1125, positive syncs.
fn cea_1080p() -> Timing {
    Timing {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        h_front_porch: 88,
        h_sync_width: 44,
        v_active: 1080,
        v_total: 1125,
        v_front_porch: 4,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}
fn geometry(m: &DrmModeModeInfo) -> [u32; 12] {
    [
        m.clock,
        m.hdisplay.into(),
        m.hsync_start.into(),
        m.hsync_end.into(),
        m.htotal.into(),
        m.vdisplay.into(),
        m.vsync_start.into(),
        m.vsync_end.into(),
        m.vtotal.into(),
        m.vrefresh,
        m.flags,
        m.r#type,
    ]
}

fn navi48_kms_reports_exact_sink_timing() -> TestResult {
    let w = timing_wire(&cea_1080p());
    if geometry(&w)
        != [
            148_500, 1920, 2008, 2052, 2200, 1080, 1084, 1089, 1125, 60, 5, 0x48,
        ]
        || &w.name[..10] != b"1920x1080\0"
    {
        return TestResult::Fail("1080p wire timing");
    }
    // Negative syncs and a non-integer refresh round to the nearest hertz.
    let t = Timing {
        pixel_clock_khz: 148_352,
        h_sync_positive: false,
        v_sync_positive: false,
        ..cea_1080p()
    };
    let w = timing_wire(&t);
    if w.flags != NHSYNC | NVSYNC || w.vrefresh != 60 {
        return TestResult::Fail("negative syncs / 59.94 Hz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_reports_exact_sink_timing
);

fn navi48_kms_publishes_connector_edid_and_refuses_other_modes() -> TestResult {
    let mut edid = [0u8; 128];
    edid[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    edid[127] = 0x5a;
    let t = cea_1080p();
    let wire = timing_wire(&t);
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    apply(&mut card, Some((&edid, &t, ConnectorType::DisplayPort)));
    apply(&mut card, Some((&edid, &t, ConnectorType::DisplayPort))); // idempotent topology
    if (card.crtcs.len(), card.encoders.len(), card.connectors.len()) != (1, 1, 1) {
        return TestResult::Fail("topology duplicated");
    }
    let c = &card.connectors[0];
    let mode = Mode {
        width: 1920,
        height: 1080,
        refresh_hz: 60,
        bpp: 32,
    };
    if c.status != ConnectorStatus::Connected
        || c.connector_type != ConnectorType::DisplayPort
        || c.modes != [mode]
        || card.crtcs[0].mode != Some(mode)
        || card.native_output(CONNECTOR).and_then(|n| n.edid) != Some(edid)
        || geometry(&card.mode_wire(&mode)) != geometry(&wire)
    {
        return TestResult::Fail("lit connector");
    }
    // GETCONNECTOR returns the real timing, not the synthesized one.
    let mut arg = [0u8; 80];
    arg[48..52].copy_from_slice(&CONNECTOR.to_le_bytes());
    match dispatch(&mut card, 0xA7, &arg, &DrmFileCtx::primary_master()) {
        Ok(DrmIoctlResult::GetConnector(_, modes))
            if modes.len() == 1 && geometry(&modes[0]) == geometry(&wire) => {}
        _ => return TestResult::Fail("GETCONNECTOR timing"),
    }
    // Only the published timing may be set; the synthesized one may not.
    if !card.accepts_mode(&wire) || card.accepts_mode(&mode_to_wire(&mode)) {
        return TestResult::Fail("SETCRTC mode gate");
    }
    // Unplugged: disconnected, no modes or EDID, and no mode accepted.
    card.crtcs[0].primary_fb = Some(7);
    apply(&mut card, None);
    let c = &card.connectors[0];
    if c.status != ConnectorStatus::Disconnected
        || !c.modes.is_empty()
        || card.crtcs[0].mode.is_some()
        || card.crtcs[0].enabled
        || card.crtcs[0].primary_fb.is_some()
        || card
            .native_output(CONNECTOR)
            .is_none_or(|n| n.edid.is_some())
        || card.accepts_mode(&wire)
    {
        return TestResult::Fail("unplugged connector");
    }
    // Cards without native outputs keep accepting any mode.
    if !Card::new("bochs", "", (1, 0, 0)).accepts_mode(&mode_to_wire(&mode)) {
        return TestResult::Fail("non-native card gated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_publishes_connector_edid_and_refuses_other_modes
);

fn navi48_kms_reports_hdmi_connectors_and_keeps_the_type_when_unplugged() -> TestResult {
    let edid = [0u8; 128];
    let t = cea_1080p();
    let mut card = Card::new("amdgpu", "AMD GPU", (3, 0, 0));
    apply(&mut card, Some((&edid, &t, ConnectorType::HdmiA)));
    if card.connectors[0].connector_type != ConnectorType::HdmiA
        || card.connectors[0].status != ConnectorStatus::Connected
    {
        return TestResult::Fail("HDMI connector");
    }
    apply(&mut card, None);
    if card.connectors[0].connector_type != ConnectorType::HdmiA
        || card.connectors[0].status != ConnectorStatus::Disconnected
    {
        return TestResult::Fail("unplugged HDMI connector");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-kms",
    navi48_kms_reports_hdmi_connectors_and_keeps_the_type_when_unplugged
);
