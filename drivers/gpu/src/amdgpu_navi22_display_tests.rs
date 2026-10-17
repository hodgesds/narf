use super::*;
use crate::amdgpu_dcn30_ddc::tests::{engine, set_hpd, Fake, Sink as Model};
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
fn path(connector: Kind, transmitter: u8, aux: Option<u8>, hpd: u8) -> Path {
    Path {
        connector,
        connector_instance: 1,
        transmitter,
        aux,
        hpd,
        device_tag: 0,
        max_speed_mhz: 0,
    }
}
/// The MSI RX 6750 XT shape: three DP and one HDMI, one DDC/HPD each.
fn board() -> Vec<Path> {
    vec![
        path(Kind::DisplayPort, 0, Some(0), 1),
        path(Kind::DisplayPort, 1, Some(1), 2),
        path(Kind::DisplayPort, 2, Some(2), 3),
        path(Kind::HdmiTypeA, 3, Some(3), 4),
    ]
}
fn fix(edid: &mut [u8]) {
    for block in edid.chunks_exact_mut(128) {
        let sum = block[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        block[127] = 0u8.wrapping_sub(sum);
    }
}
/// A 1080p60 base block and a CTA extension, optionally with an HDMI VSDB.
fn edid(blocks: usize, hdmi: bool) -> Vec<u8> {
    let mut e = vec![0u8; 128 * blocks];
    e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    e[18] = 1;
    e[19] = 4;
    // 148.5 MHz, 1920+280 x 1080+45, sync 88/44, 4/5, +h +v.
    e[54..72].copy_from_slice(&[
        0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c, 0x45, 0x00, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[126] = (blocks - 1) as u8;
    for b in 1..blocks {
        let ext = &mut e[b * 128..][..128];
        ext[0] = 0x02;
        ext[1] = 3;
        ext[2] = 4;
        ext[5] = b as u8;
        if hdmi && b == 1 {
            ext[2] = 10;
            ext[4..10].copy_from_slice(&[0x65, 0x03, 0x0c, 0x00, 0x10, 0x00]);
        }
    }
    fix(&mut e);
    e
}

fn navi22_display_binds_board_routes_without_ambiguity() -> TestResult {
    let Ok(bound) = connectors(&board()) else {
        return TestResult::Fail("board refused");
    };
    if bound.len() != 4
        || bound[3].signal != Signal::Hdmi
        || bound[3].line != 3
        || bound[3].hpd != Some(3)
        || bound[0].hpd != Some(0)
    {
        return TestResult::Fail("connector derivation");
    }
    let mut shared = board();
    shared[3].aux = Some(1);
    let mut shared_hpd = board();
    shared_hpd[2].hpd = 2;
    if connectors(&shared) != Err(Error::Invalid) || connectors(&shared_hpd) != Err(Error::Invalid)
    {
        return TestResult::Fail("shared DDC/HPD admitted");
    }
    // Unusable or foreign paths are skipped, not guessed.
    let mut odd = board();
    odd.push(path(Kind::Other(0x13), 4, Some(4), 5));
    odd[0].aux = None;
    match connectors(&odd) {
        Ok(c) if c.len() == 3 && c[0].line == 1 => {}
        _ => return TestResult::Fail("skip rules"),
    }
    if connectors(&[path(Kind::EmbeddedDisplayPort, 0, Some(0), 1)]) != Err(Error::Unsupported) {
        return TestResult::Fail("no usable connector");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-display",
    navi22_display_binds_board_routes_without_ambiguity
);

fn navi22_display_detects_hdmi_and_dp_sinks() -> TestResult {
    let mut fake = Fake::new();
    fake.ddc[3] = Some(Model::new(edid(2, true)));
    fake.aux[1] = Some(Model::new(edid(2, false)));
    set_hpd(&mut fake, 3, true);
    set_hpd(&mut fake, 1, true);
    let Ok(mut detector) = Detector::new_with(engine(fake), &board()) else {
        return TestResult::Fail("detector");
    };
    let Ok(reports) = run(detector.detect_all()) else {
        return TestResult::Fail("probe failed");
    };
    if reports.len() != 4
        || reports[0].detection != Detection::Disconnected
        || reports[2].detection != Detection::Disconnected
    {
        return TestResult::Fail("disconnected DP ports");
    }
    let Detection::Connected(hdmi) = &reports[3].detection else {
        return TestResult::Fail("HDMI sink not detected");
    };
    if hdmi.edid != edid(2, true)
        || !hdmi.hdmi
        || hdmi.dpcd.is_some()
        || hdmi
            .preferred
            .map(|t| (t.h_active, t.v_active, t.pixel_clock_khz))
            != Some((1920, 1080, 148_500))
    {
        return TestResult::Fail("HDMI EDID");
    }
    let Detection::Connected(dp) = &reports[1].detection else {
        return TestResult::Fail("DP sink not detected");
    };
    if dp.hdmi || dp.dpcd.map(|c| c[0]) != Some(0x12) || dp.edid.len() != 256 {
        return TestResult::Fail("DP sink");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-display",
    navi22_display_detects_hdmi_and_dp_sinks
);

fn navi22_display_edid_segments_and_failures() -> TestResult {
    // Blocks 2.. sit behind the E-DDC segment pointer, on both engines.
    for mode in [Mode::I2c, Mode::Aux] {
        let mut fake = Fake::new();
        let expected = edid(4, true);
        fake.ddc[0] = Some(Model::new(expected.clone()));
        fake.aux[0] = Some(Model::new(expected.clone()));
        let mut e = engine(fake);
        crate::amdgpu_dcn30_ddc::bind(&mut e, 0, Some(0), Signal::DisplayPort).unwrap();
        if run(read_edid(&mut e, 0, mode)).as_deref() != Ok(&expected[..]) {
            return TestResult::Fail("four-block EDID");
        }
    }
    // A block that never checksums is a sink failure, not a connect.
    let mut fake = Fake::new();
    let mut bad = edid(2, true);
    bad[200] ^= 1;
    fake.ddc[3] = Some(Model::new(bad));
    set_hpd(&mut fake, 3, true);
    let mut detector = Detector::new_with(engine(fake), &board()).unwrap();
    if run(detector.detect(3))
        != Ok(Detection::Failed(Error::Edid(
            narf_edid::EdidError::BadChecksum,
        )))
    {
        return TestResult::Fail("bad checksum");
    }
    // A wrong header, and HPD asserted with nothing answering DDC.
    let mut fake = Fake::new();
    let mut header = edid(1, false);
    header[0] = 1;
    fix(&mut header);
    fake.ddc[3] = Some(Model::new(header));
    set_hpd(&mut fake, 3, true);
    set_hpd(&mut fake, 0, true);
    let mut detector = Detector::new_with(engine(fake), &board()).unwrap();
    if run(detector.detect(3))
        != Ok(Detection::Failed(Error::Edid(
            narf_edid::EdidError::BadHeader,
        )))
        || run(detector.detect(0))
            != Ok(Detection::Failed(Error::Ddc(
                crate::amdgpu_dcn30_ddc::Error::Timeout,
            )))
        || run(detector.detect(9)) != Err(Error::Invalid)
    {
        return TestResult::Fail("sink failures");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-display",
    navi22_display_edid_segments_and_failures
);
