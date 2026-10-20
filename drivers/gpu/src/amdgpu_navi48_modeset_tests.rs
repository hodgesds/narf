use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn completed_modeset(pipe: u8) -> Modeset {
    let paths = [path(inventory::Connector::DisplayPort, pipe)];
    let ports = [port(paths[0], dpcd(0x14, 4), edid_1080p())];
    let selection = select(&paths, &ports, 8, None).unwrap();
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 456_000,
        fclk_khz: [300_000, 800_000],
        dcfclk_khz: [200_000, 600_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 1_000_000,
        dppclk_max_khz: 1_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let plan = admit_displays(&soc, &[selection]).unwrap()[0];
    Modeset {
        selection,
        pipe,
        plan,
        scanout: otg::ScanoutRunning {
            pipe,
            odm: None,
            stream: pipe,
            plan,
            address: 0x8_0000_0000 + u64::from(pipe) * 0x1000000,
            frame_before: 2,
            frame_after: 3,
        },
        modes: [None; MAX_MODES],
    }
}

fn navi48_completed_modesets_survive_configuration_and_publication_cancellation() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Waker},
    };
    for during_startup in [false, true] {
        let first = completed_modeset(0);
        let second = completed_modeset(2);
        let mut retained = RetainedModesets::new();
        let mut journal = super::super::teardown::Teardowns::new();
        {
            let mut future = core::pin::pin!(async {
                // A caller's temporary configuration disappears on cancellation.
                let mut local = Vec::new();
                for m in [first, second] {
                    retained.retain(m);
                    local.push(m);
                }
                if during_startup {
                    journal
                        .begin_activation(3, None, &second.selection)
                        .unwrap();
                }
                // Later native startup, or asynchronous platform adoption.
                core::future::pending::<()>().await;
                local
            });
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(retained.check_stopped(), Err(otg::Error::Busy.into()));
        let mut recovered = [None; 4];
        assert_eq!(retained.restore(&mut recovered), Ok(0b0101));
        assert_eq!(recovered, [Some(first), None, Some(second), None]);
        assert_eq!(retained.restore(&mut recovered), Ok(0));
        // Handle recovery must not clear a cancelled native startup's quarantine.
        if during_startup {
            assert_eq!(journal.check_idle(), Err(otg::Error::Busy.into()));
        } else {
            assert_eq!(journal.check_idle(), Ok(()));
        }
        // Forget only the completed teardown's pipe; a sibling still blocks
        // configuration preparation and stays available after another restore.
        retained.stopped(0);
        assert_eq!(retained.check_stopped(), Err(otg::Error::Busy.into()));
        let mut again = [None; 4];
        assert_eq!(retained.restore(&mut again), Ok(0b0100));
        assert_eq!(again[2], Some(second));
        retained.stopped(2);
        assert_eq!(retained.check_stopped(), Ok(()));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_completed_modesets_survive_configuration_and_publication_cancellation
);

fn navi48_modeset_restore_refuses_conflicting_incarnations_before_changes() -> TestResult {
    let first = completed_modeset(0);
    let last = completed_modeset(3);
    let mut retained = RetainedModesets::new();
    retained.retain(first);
    retained.retain(last);
    let mut old = last;
    old.scanout.address += 4096;
    let mut caller = [None, None, None, Some(old)];
    let before = caller;
    assert_eq!(retained.restore(&mut caller), Err(otg::Error::Busy.into()));
    assert_eq!(
        caller, before,
        "partially restored before detecting a conflict"
    );
    // Updated admission and retraining witnesses replace the retained record.
    let mut updated = last;
    updated.modes[0] = Some(last.selection.timing);
    updated.scanout.frame_before = 10;
    updated.scanout.frame_after = 11;
    retained.retain(updated);
    let mut caller = [None; 4];
    assert_eq!(retained.restore(&mut caller), Ok(0b1001));
    assert_eq!(caller[3], Some(updated));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_restore_refuses_conflicting_incarnations_before_changes
);

/// One-block EDID 1.4 whose preferred mode is CEA 1920x1080@60 (148.5 MHz).
fn edid_1080p() -> Vec<u8> {
    let mut e = alloc::vec![0u8; 128];
    e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    e[8..10].copy_from_slice(&[0x10, 0xac]);
    (e[18], e[19], e[20]) = (1, 4, 0xa5);
    e[54..72].copy_from_slice(&[
        0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c, 0x45, 0, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[127] = narf_edid::compute_checksum(&e);
    e
}
fn path(connector: inventory::Connector, transmitter: u8) -> inventory::Path {
    inventory::Path {
        connector,
        connector_instance: transmitter + 1,
        transmitter,
        aux: Some(transmitter),
        hpd: transmitter + 1,
        device_tag: 0,
        max_speed_mhz: 0,
    }
}
/// DPCD with MAX_LINK_RATE and MAX_LANE_COUNT (enhanced framing set).
fn dpcd(rate: u8, lanes: u8) -> Option<[u8; 16]> {
    let mut d = [0u8; 16];
    (d[0], d[1], d[2]) = (0x14, rate, 0x80 | lanes);
    Some(d)
}
fn port(path: inventory::Path, dpcd: Option<[u8; 16]>, edid: Vec<u8>) -> display::Port {
    display::Port {
        path,
        sink: Ok(display::Sink {
            dpcd,
            edid,
            lttpr: None,
            uhbr: 0,
            lttpr_uhbr: None,
            fec: false,
            dsc: None,
            verified_link: None,
        }),
    }
}

fn navi48_modeset_selects_first_answering_dp_sink_by_board_path() -> TestResult {
    use inventory::Connector::{DisplayPort as Dp, HdmiTypeA as Hdmi};
    let paths = [path(Hdmi, 0), path(Dp, 1), path(Dp, 2), path(Dp, 3)];
    let ports = [
        port(paths[0], None, edid_1080p()),
        display::Port {
            path: paths[1],
            sink: Err(display::Error::InvalidDpcd),
        },
        port(paths[2], None, edid_1080p()),
        port(paths[3], dpcd(0x14, 4), edid_1080p()),
    ];
    let Ok(s) = select(&paths, &ports, 8, None) else {
        return TestResult::Fail("no selection");
    };
    let t = s.timing;
    if s.port != 3
        || (s.lanes, s.rate) != (4, DpRate::Legacy(LinkRate::Hbr2))
        || (
            t.pixel_clock_khz,
            t.h_active,
            t.h_total,
            t.v_active,
            t.v_total,
        ) != (148_500, 1920, 2200, 1080, 1125)
        || !(t.h_sync_positive && t.v_sync_positive)
        || s.edid[..] != edid_1080p()[..]
    {
        return TestResult::Fail("selection");
    }
    // A sink without a usable preferred mode or with unknown link caps is
    // skipped; none left means no sink.
    let mut bad = edid_1080p();
    bad[127] ^= 1;
    let ports = [
        port(paths[3], dpcd(0x14, 4), bad),
        port(paths[2], dpcd(0x15, 4), edid_1080p()),
        port(paths[1], dpcd(0x14, 3), edid_1080p()),
    ];
    if select(&paths, &ports, 8, None) != Err(ModesetError::NoSink) {
        return TestResult::Fail("unusable sinks selected");
    }
    // A port missing from the board inventory is never addressed.
    let stray = path(Dp, 4);
    if select(&paths, &[port(stray, dpcd(0x14, 4), edid_1080p())], 8, None)
        != Err(ModesetError::NoSink)
    {
        return TestResult::Fail("unrouted port selected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_selects_first_answering_dp_sink_by_board_path
);

fn navi48_modeset_requires_link_payload_and_aligns_pitch() -> TestResult {
    use inventory::Connector::DisplayPort as Dp;
    let paths = [path(Dp, 0), path(Dp, 1)];
    // 148.5 MHz * 24 bpp needs 3.564 Gb/s of payload: 1-lane RBR is short,
    // 2-lane HBR (4.32) suffices. A short first sink falls through.
    let short = [port(paths[0], dpcd(0x06, 1), edid_1080p())];
    if select(&paths, &short, 8, None) != Err(ModesetError::Link) {
        return TestResult::Fail("short link accepted");
    }
    let ports = [
        port(paths[0], dpcd(0x06, 1), edid_1080p()),
        port(paths[1], dpcd(0x0a, 2), edid_1080p()),
    ];
    let Ok(s) = select(&paths, &ports, 8, None) else {
        return TestResult::Fail("fitting sink rejected");
    };
    if s.port != 1
        || !link_fits(&s.timing, 2, LinkRate::Hbr)
        || link_fits(&s.timing, 1, LinkRate::Hbr)
    {
        return TestResult::Fail("payload ceiling");
    }
    let mut odd = s.timing;
    odd.h_active = 1366;
    if mode(s.timing).pitch != 1920 || mode(odd).pitch != 1408 {
        return TestResult::Fail("pitch alignment");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_requires_link_payload_and_aligns_pitch
);

fn navi48_modeset_link_fallback_ladder_skips_short_links() -> TestResult {
    use inventory::Connector::DisplayPort as Dp;
    let paths = [path(Dp, 0)];
    let Ok(s) = select(
        &paths,
        &[port(paths[0], dpcd(0x14, 4), edid_1080p())],
        8,
        None,
    ) else {
        return TestResult::Fail("selection");
    };
    use LinkRate::{Hbr, Hbr2, Rbr};
    let ladder = link_candidates(&s.timing, 4, Hbr2);
    if ladder
        != [
            (4, Hbr2),
            (4, Hbr),
            (4, Rbr),
            (2, Hbr2),
            (2, Hbr),
            (1, Hbr2),
        ]
    {
        return TestResult::Fail("fallback order");
    }
    // The maximum link always leads; a sink that only carries the mode at
    // its maximum has a single candidate.
    if link_candidates(&s.timing, 1, Hbr2) != [(1, Hbr2)]
        || !link_candidates(&s.timing, 1, Hbr).is_empty()
    {
        return TestResult::Fail("short ladders");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_link_fallback_ladder_skips_short_links
);

/// `base` with one CTA-861 extension, carrying the HDMI Licensing VSDB when
/// `hdmi` (else a DVI sink with a bare extension).
fn with_cta(mut base: Vec<u8>, hdmi: bool) -> Vec<u8> {
    base[126] = 1;
    base[127] = 0;
    base[127] = narf_edid::compute_checksum(&base);
    let mut ext = alloc::vec![0u8; 128];
    (ext[0], ext[1], ext[3]) = (0x02, 3, 0);
    if hdmi {
        ext[4..10].copy_from_slice(&[3 << 5 | 5, 0x03, 0x0c, 0x00, 0x10, 0x00]);
        ext[2] = 10;
    } else {
        ext[2] = 4;
    }
    let sum = ext[..127].iter().fold(0u8, |s, b| s.wrapping_add(*b));
    ext[127] = 0u8.wrapping_sub(sum);
    base.extend_from_slice(&ext);
    base
}
/// CEA 3840x2160@60 (594 MHz) as the preferred mode.
fn edid_2160p() -> Vec<u8> {
    let mut e = edid_1080p();
    e[54..72].copy_from_slice(&[
        0x08, 0xe8, 0x00, 0x30, 0xf2, 0x70, 0x5a, 0x80, 0xb0, 0x58, 0x8a, 0, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[127] = 0;
    e[127] = narf_edid::compute_checksum(&e);
    e
}

fn navi48_modeset_selects_hdmi_sinks_only_without_dp_and_below_340_mhz() -> TestResult {
    use inventory::Connector::{DisplayPort as Dp, HdmiTypeA as Hdmi};
    if !hdmi_caps_hdmi(&with_cta(edid_1080p(), true))
        || hdmi_caps_hdmi(&with_cta(edid_1080p(), false))
        || hdmi_caps_hdmi(&edid_1080p())
    {
        return TestResult::Fail("HDMI VSDB detection");
    }
    let paths = [path(Hdmi, 0), path(Hdmi, 1), path(Dp, 2)];
    // A DVI sink on an HDMI connector is never driven with HDMI packets.
    let ports = [
        port(paths[0], None, with_cta(edid_1080p(), false)),
        port(paths[1], None, with_cta(edid_1080p(), true)),
        display::Port {
            path: paths[2],
            sink: Err(display::Error::InvalidDpcd),
        },
    ];
    match select(&paths, &ports, 8, None) {
        Ok(s) if s.port == 1 && s.hdmi && s.lanes == 0 && s.timing.pixel_clock_khz == 148_500 => {}
        _ => return TestResult::Fail("HDMI selection"),
    }
    // An answering DP sink wins over HDMI, as before; like nearly every real
    // monitor it carries an extension block after its base block.
    let ports = [
        port(paths[1], None, with_cta(edid_1080p(), true)),
        port(paths[2], dpcd(0x14, 4), with_cta(edid_1080p(), false)),
    ];
    if !matches!(select(&paths, &ports, 8, None), Ok(s) if s.port == 2 && !s.hdmi) {
        return TestResult::Fail("DP preferred");
    }
    // 594 MHz needs SCDC scrambling, which this path does not do.
    let ports = [port(paths[1], None, with_cta(edid_2160p(), true))];
    if select(&paths, &ports, 8, None) != Err(ModesetError::Link) {
        return TestResult::Fail("over 340 MHz");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_selects_hdmi_sinks_only_without_dp_and_below_340_mhz
);

/// `base` with one CTA extension holding the given data blocks (each with its
/// header byte).
fn with_blocks(mut base: Vec<u8>, blocks: &[&[u8]]) -> Vec<u8> {
    base[126] = 1;
    base[127] = 0;
    base[127] = narf_edid::compute_checksum(&base);
    let mut ext = alloc::vec![0u8; 128];
    (ext[0], ext[1]) = (0x02, 3);
    let mut at = 4;
    for b in blocks {
        ext[at..at + b.len()].copy_from_slice(b);
        at += b.len();
    }
    ext[2] = at as u8;
    let sum = ext[..127].iter().fold(0u8, |s, b| s.wrapping_add(*b));
    ext[127] = 0u8.wrapping_sub(sum);
    base.extend_from_slice(&ext);
    base
}
const VSDB: &[u8] = &[3 << 5 | 5, 0x03, 0x0c, 0x00, 0x10, 0x00];
/// HDMI VSDB declaring Max_TMDS_Clock 225 MHz (45 * 5).
const VSDB_225: &[u8] = &[3 << 5 | 7, 0x03, 0x0c, 0x00, 0x10, 0x00, 0, 45];
/// HF-VSDB: version 1, 600 MHz, SCDC_Present.
const HF_VSDB: &[u8] = &[3 << 5 | 7, 0xd8, 0x5d, 0xc4, 1, 120, 0x80, 0];
/// HF-SCDB (extended tag 0x79): reserved x2, version 1, 600 MHz, SCDC_Present.
const HF_SCDB: &[u8] = &[7 << 5 | 7, 0x79, 0, 0, 1, 120, 0x80, 0];

fn navi48_modeset_reads_hdmi_caps_and_admits_scrambled_modes_only_with_scdc() -> TestResult {
    let caps = |blocks: &[&[u8]]| hdmi_caps(&with_blocks(edid_1080p(), blocks));
    let full = HdmiCaps {
        hdmi: true,
        vsdb_max_khz: 0,
        forum_max_khz: 600_000,
        scdc: true,
        dc30: false,
        dc36: false,
        ..Default::default()
    };
    if caps(&[VSDB, HF_VSDB]) != full
        || caps(&[VSDB, HF_SCDB]) != full
        || caps(&[VSDB_225]).vsdb_max_khz != 225_000
        || caps(&[HF_VSDB]).hdmi
        // DRM ignores truncated HF blocks.
        || caps(&[VSDB, &[3 << 5 | 6, 0xd8, 0x5d, 0xc4, 1, 120, 0x80]]).scdc
        || caps(&[VSDB, &[7 << 5 | 6, 0x79, 0, 0, 1, 120, 0x80]]).scdc
    {
        return TestResult::Fail("caps parse");
    }
    for (c, khz, fits) in [
        (full, 340_000, true),
        (full, 594_000, true),
        (full, 600_001, false),
        (caps(&[VSDB]), 594_000, false), // no SCDC: never scrambled
        (caps(&[VSDB_225]), 148_500, true),
        (caps(&[VSDB_225]), 240_000, false),
        (
            HdmiCaps {
                forum_max_khz: 340_000,
                ..full
            },
            594_000,
            false,
        ),
    ] {
        if hdmi_fits(c, khz) != fits {
            return TestResult::Fail("fits rule");
        }
    }
    use inventory::Connector::HdmiTypeA as Hdmi;
    let paths = [path(Hdmi, 0)];
    let ports = [port(
        paths[0],
        None,
        with_blocks(edid_2160p(), &[VSDB, HF_VSDB]),
    )];
    match select(&paths, &ports, 8, None) {
        Ok(s) if s.hdmi && s.scdc && s.timing.pixel_clock_khz == 594_000 => {}
        _ => return TestResult::Fail("4K60 HDMI 2.0 selection"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_reads_hdmi_caps_and_admits_scrambled_modes_only_with_scdc
);

/// The AVI fields drm_hdmi_avi_infoframe_from_display_mode and amdgpu's
/// set_avi_info_frame derive: the CTA VIC at 60 or 59.94 Hz with its aspect,
/// HDMI 1.4b 4K VICs left to the vendor InfoFrame on HDMI sinks, VICs above
/// 64 only for HDMI 2.0 sinks or ones listing them, full range only with QS.
fn navi48_modeset_derives_hdmi_avi_like_linux() -> TestResult {
    let t = |khz, h: [u32; 4], v: [u32; 4], positive| Timing {
        pixel_clock_khz: khz,
        h_active: h[0],
        h_front_porch: h[1] - h[0],
        h_sync_width: h[2] - h[1],
        h_total: h[3],
        v_active: v[0],
        v_front_porch: v[1] - v[0],
        v_sync_width: v[2] - v[1],
        v_total: v[3],
        h_sync_positive: positive,
        v_sync_positive: positive,
    };
    let p1080 = |khz| {
        t(
            khz,
            [1920, 2008, 2052, 2200],
            [1080, 1084, 1089, 1125],
            true,
        )
    };
    let uhd30 = t(
        297_000,
        [3840, 4016, 4104, 4400],
        [2160, 2168, 2178, 2250],
        true,
    );
    let vga = t(25_175, [640, 656, 752, 800], [480, 490, 492, 525], false);
    let caps = |blocks: &[&[u8]]| hdmi_caps(&with_blocks(edid_1080p(), blocks));
    let plain = caps(&[VSDB]);
    let avi = |vic, aspect, qs| otg::Avi {
        vic,
        aspect,
        qs,
        hdmi_vic: 0,
    };
    if hdmi_avi(plain, &p1080(148_500)) != avi(16, 2, false)
        || hdmi_avi(plain, &p1080(148_352)) != avi(16, 2, false)
        || hdmi_avi(plain, &p1080(148_000)) != avi(0, 0, false)
        || hdmi_avi(plain, &vga) != avi(1, 1, false)
        // Inverted sync polarity is not the CTA mode.
        || hdmi_avi(plain, &t(25_175, [640, 656, 752, 800], [480, 490, 492, 525], true))
            != avi(0, 0, false)
    {
        return TestResult::Fail("CTA VIC match");
    }
    // HDMI 1.4b VIC 1 on an HDMI sink: no AVI VIC, its 16:9 aspect kept,
    // and the HDMI VIC for the vendor InfoFrame.
    if hdmi_avi(plain, &uhd30)
        != (otg::Avi {
            hdmi_vic: 1,
            ..avi(0, 2, false)
        })
    {
        return TestResult::Fail("HDMI VIC in AVI");
    }
    // VIC 95 without a VSDB: dropped for an HDMI 1.4 sink unless listed.
    let no_vsdb = HdmiCaps::default();
    let listed = caps(&[&[2 << 5 | 1, 95]]);
    let hdmi2 = HdmiCaps {
        scdc: true,
        ..no_vsdb
    };
    let y420 = caps(&[&[7 << 5 | 1, 15]]);
    if hdmi_avi(no_vsdb, &uhd30) != avi(0, 2, false)
        || hdmi_avi(listed, &uhd30) != avi(95, 2, false)
        || hdmi_avi(hdmi2, &uhd30) != avi(95, 2, false)
        || !y420.ycbcr420
        || hdmi_avi(y420, &uhd30) != avi(95, 2, false)
    {
        return TestResult::Fail("HDMI 2.0 VIC range");
    }
    let qs = caps(&[VSDB, &[7 << 5 | 2, 0, 0x40]]);
    if !qs.qs || caps(&[VSDB, &[7 << 5 | 2, 0, 0x80]]).qs {
        return TestResult::Fail("VCDB QS");
    }
    if hdmi_avi(qs, &p1080(148_500)) != avi(16, 2, true) {
        return TestResult::Fail("QS not carried");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi48",
    navi48_modeset_derives_hdmi_avi_like_linux
);

/// "Broadcast RGB" as amdgpu_dm_get_output_color_space reads it for RGB:
/// only Limited selects limited range; Automatic stays full.
fn navi48_modeset_broadcast_rgb_selects_limited_only_when_asked() -> TestResult {
    if limited_range(BROADCAST_RGB_AUTO)
        || limited_range(BROADCAST_RGB_FULL)
        || !limited_range(BROADCAST_RGB_LIMITED)
    {
        return TestResult::Fail("output range");
    }
    let before = broadcast_rgb();
    set_broadcast_rgb(7);
    let ignored = broadcast_rgb() == before;
    set_broadcast_rgb(BROADCAST_RGB_LIMITED);
    let set = broadcast_rgb() == BROADCAST_RGB_LIMITED;
    set_broadcast_rgb(before);
    if !ignored || !set {
        return TestResult::Fail("setting");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi48",
    navi48_modeset_broadcast_rgb_selects_limited_only_when_asked
);

fn hdmi_caps_hdmi(edid: &[u8]) -> bool {
    hdmi_caps(edid).hdmi
}

/// HDMI VSDB with DC_30bit | DC_36bit and Max_TMDS_Clock 300 MHz (60 * 5).
const VSDB_DC: &[u8] = &[3 << 5 | 7, 0x03, 0x0c, 0x00, 0x10, 0x00, 0x30, 60];

fn navi48_modeset_picks_the_deepest_hdmi_depth_that_fits() -> TestResult {
    use otg::ColorDepth::{Bpc10, Bpc12, Bpc8};
    let caps = hdmi_caps(&with_blocks(edid_1080p(), &[VSDB_DC]));
    if !(caps.dc30 && caps.dc36 && caps.vsdb_max_khz == 300_000) {
        return TestResult::Fail("DC bits");
    }
    for (pixel, max, depth) in [
        (148_500, 8, Some(Bpc8)),   // DRM's default max bpc
        (148_500, 12, Some(Bpc12)), // 222.75 MHz TMDS
        (148_500, 10, Some(Bpc10)), // 185.625 MHz
        (220_000, 12, Some(Bpc10)), // 12 bpc 330 MHz > 300: step down
        (297_000, 12, Some(Bpc8)),  // 10 bpc 371.25 MHz > 300
        (310_000, 12, None),        // past the VSDB maximum even at 8
    ] {
        if hdmi_depth(caps, pixel, max) != depth {
            return TestResult::Fail("depth choice");
        }
    }
    // Undeclared depths are never used.
    let plain = hdmi_caps(&with_blocks(edid_1080p(), &[VSDB]));
    if hdmi_depth(plain, 148_500, 12) != Some(Bpc8) {
        return TestResult::Fail("undeclared deep colour");
    }
    use inventory::Connector::HdmiTypeA as Hdmi;
    let paths = [path(Hdmi, 0)];
    let ports = [port(paths[0], None, with_blocks(edid_1080p(), &[VSDB_DC]))];
    if !matches!(select(&paths, &ports, 12, None), Ok(s) if s.depth == Bpc12)
        || !matches!(select(&paths, &ports, 8, None), Ok(s) if s.depth == Bpc8)
    {
        return TestResult::Fail("selected depth");
    }
    set_max_bpc(11);
    if max_bpc() != 8 {
        return TestResult::Fail("invalid max bpc accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_picks_the_deepest_hdmi_depth_that_fits
);

fn navi48_modeset_reads_sink_audio_like_amdgpu_dm() -> TestResult {
    let mut base = edid_1080p();
    base[8..12].copy_from_slice(&[0x2d, 0x4c, 0x99, 0x0f]);
    // Monitor name descriptor "Living TV\n".
    base[72..90].copy_from_slice(&[
        0, 0, 0, 0xfc, 0, b'L', b'i', b'v', b'i', b'n', b'g', b' ', b'T', b'V', 0x0a, 0x20, 0x20,
        0x20,
    ]);
    // LPCM 2ch 32/44.1/48 kHz 16/20/24-bit, AC-3 6ch; speakers FL/FR LFE FC;
    // HDMI VSDB with progressive latencies 40/20.
    const AUDIO: &[u8] = &[1 << 5 | 6, 0x09, 0x07, 0x07, 0x15, 0x07, 0x50];
    const SPEAKERS: &[u8] = &[4 << 5 | 3, 0x07, 0, 0];
    const VSDB_LAT: &[u8] = &[
        3 << 5 | 10,
        0x03,
        0x0c,
        0x00,
        0x10,
        0x00,
        0,
        0,
        0x80,
        40,
        20,
    ];
    let edid = with_blocks(base.clone(), &[AUDIO, SPEAKERS, VSDB_LAT]);
    let Some(info) = sink_audio_info(&edid) else {
        return TestResult::Fail("no audio");
    };
    if info.manufacturer_id != 0x4c2d
        || info.product_id != 0x0f99
        || &info.name[..10] != b"Living TV\0"
        || info.speakers != 0x07
        || info.mode_count != 2
        || info.modes[0]
            != (otg::AudioMode {
                format: 1,
                channels: 2,
                rates: 0x07,
                byte2: 0x07,
            })
        || info.modes[1]
            != (otg::AudioMode {
                format: 2,
                channels: 6,
                rates: 0x07,
                byte2: 0x50,
            })
        || (info.video_latency, info.audio_latency) != (40, 20)
    {
        return TestResult::Fail("audio info");
    }
    // No speaker block: FL/FR + FC. No SADs: no audio endpoint at all.
    let plain = sink_audio_info(&with_blocks(base.clone(), &[AUDIO])).unwrap();
    if plain.speakers != 5 || sink_audio_info(&with_blocks(base.clone(), &[VSDB])).is_some() {
        return TestResult::Fail("defaults");
    }
    // A DP SST sink's audio comes from the same EDID blocks.
    let paths = [path(inventory::Connector::DisplayPort, 0)];
    let dp = |edid: Vec<u8>| select(&paths, &[port(paths[0], dpcd(0x14, 4), edid)], 8, None);
    match (dp(edid), dp(with_blocks(base, &[VSDB]))) {
        (Ok(a), Ok(b)) if !a.hdmi && a.audio == Some(info) && b.audio.is_none() => {}
        _ => return TestResult::Fail("DP sink audio"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_reads_sink_audio_like_amdgpu_dm
);

/// 1080p preferred, 2160p as the second base-block descriptor and 720p as a
/// CTA extension DTD.
fn edid_three_modes(hdmi: bool) -> Vec<u8> {
    let mut e = edid_1080p();
    e[72..90].copy_from_slice(&[
        0x08, 0xe8, 0x00, 0x30, 0xf2, 0x70, 0x5a, 0x80, 0xb0, 0x58, 0x8a, 0, 0, 0, 0, 0, 0, 0x1e,
    ]);
    let mut e = with_cta(e, hdmi);
    let at = 128 + usize::from(e[130]);
    e[at..at + 18].copy_from_slice(&[
        0x01, 0x1d, 0x00, 0x72, 0x51, 0xd0, 0x1e, 0x20, 0x6e, 0x28, 0x55, 0, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[255] = 0;
    let sum = e[128..255].iter().fold(0u8, |s, b| s.wrapping_add(*b));
    e[255] = 0u8.wrapping_sub(sum);
    e
}

fn navi48_dark_sst_modes_use_link_and_joint_display_admission() -> TestResult {
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [500_000, 2_000_000],
        dcfclk_khz: [300_000, 1_200_000],
        socclk_khz: 600_000,
        dispclk_max_khz: 1_500_000,
        dppclk_max_khz: 1_500_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let paths = [path(inventory::Connector::DisplayPort, 0)];
    let mut device = port(paths[0], dpcd(0x14, 4), edid_three_modes(false));
    let widths = |m: Vec<Timing>| m.iter().map(|t| t.h_active).collect::<Vec<_>>();
    assert_eq!(
        widths(sst::dark_modes(&soc, &paths, &device, 8, &[])),
        [1920, 3840, 1280]
    );
    let one = select(&paths, core::slice::from_ref(&device), 8, None).unwrap();
    assert!(sst::dark_modes(&soc, &paths, &device, 8, &[one; 4]).is_empty());
    assert!(sst::dark_modes(
        &dml::Soc {
            dispclk_max_khz: 30_000,
            ..soc
        },
        &paths,
        &device,
        8,
        &[]
    )
    .is_empty());
    // The preferred mode does not fit this link. Its dark connector must
    // still offer the 720p alternative, without relabelling preferred as 720p.
    device.sink.as_mut().unwrap().dpcd = dpcd(0x06, 2);
    assert_eq!(
        select(&paths, core::slice::from_ref(&device), 8, None),
        Err(ModesetError::Link)
    );
    let modes = sst::dark_modes(&soc, &paths, &device, 8, &[]);
    assert_eq!(widths(modes.clone()), [1280]);
    assert_eq!(
        select(&paths, core::slice::from_ref(&device), 8, Some(modes[0]))
            .unwrap()
            .timing,
        modes[0]
    );
    device.sink.as_mut().unwrap().dpcd = dpcd(0x06, 1);
    assert!(sst::dark_modes(&soc, &paths, &device, 8, &[]).is_empty());
    device.sink = Err(display::Error::InvalidDpcd);
    assert!(sst::dark_modes(&soc, &paths, &device, 8, &[]).is_empty());
    let hdmi = [path(inventory::Connector::HdmiTypeA, 0)];
    let device = port(hdmi[0], None, edid_three_modes(true));
    assert_eq!(
        widths(sst::dark_modes(&soc, &hdmi, &device, 8, &[])),
        [1920, 1280]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_dark_sst_modes_use_link_and_joint_display_admission
);

fn navi48_modeset_offers_edid_modes_and_selects_a_wanted_one() -> TestResult {
    use inventory::Connector::{DisplayPort as Dp, HdmiTypeA as Hdmi};
    let edid = edid_three_modes(false);
    let modes = edid_timings(&edid);
    if modes.iter().map(|t| t.h_active).collect::<Vec<_>>() != [1920, 3840, 1280] {
        return TestResult::Fail("EDID detailed timings in order");
    }
    let (p1080, p2160, p720) = (modes[0], modes[1], modes[2]);
    // Four HBR lanes carry 1080p and 720p, not 2160p.
    let paths = [path(Dp, 0)];
    let ports = [port(paths[0], dpcd(0x0a, 4), edid.clone())];
    let pick = |want| select(&paths, &ports, 8, want).map(|s| s.timing);
    let mut unlisted = p720;
    unlisted.h_front_porch += 2;
    if pick(Some(p720)) != Ok(p720)
        || pick(None) != Ok(p1080)
        || pick(Some(p2160)) != Ok(p1080)
        || pick(Some(unlisted)) != Ok(p1080)
    {
        return TestResult::Fail("DP wanted mode");
    }
    // HDMI without SCDC: 2160p (594 MHz) does not fit, 720p does.
    let edid = edid_three_modes(true);
    let paths = [path(Hdmi, 0)];
    let ports = [port(paths[0], None, edid)];
    let pick = |want| select(&paths, &ports, 8, want).map(|s| s.timing);
    if pick(Some(p720)) != Ok(p720) || pick(Some(p2160)) != Ok(p1080) {
        return TestResult::Fail("HDMI wanted mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_offers_edid_modes_and_selects_a_wanted_one
);

fn navi48_modeset_lists_standard_established_and_vic_modes_like_linux() -> TestResult {
    let mut e = edid_1080p();
    e[35] = 0x20; // established 640x480@60
    e[38..40].copy_from_slice(&[0x81, 0x80]); // standard 1280x1024@60
    for slot in (40..54).step_by(2) {
        e[slot..slot + 2].copy_from_slice(&[1, 1]);
    }
    e[127] = 0;
    e[127] = narf_edid::compute_checksum(&e);
    let mut e = with_cta(e, false);
    // A video data block: VIC 16 (1080p60, a duplicate of the DTD), VIC 4
    // (720p60), VIC 5 (1080i, interlaced) and VIC 6 (pixel-repeated 480i).
    e[132..137].copy_from_slice(&[2 << 5 | 4, 0x80 | 16, 4, 5, 6]);
    e[130] = 9;
    e[255] = 0;
    let sum = e[128..255].iter().fold(0u8, |s, b| s.wrapping_add(*b));
    e[255] = 0u8.wrapping_sub(sum);
    let sizes: Vec<(u32, u32, u32)> = edid_timings(&e)
        .iter()
        .map(|t| (t.h_active, t.v_active, t.pixel_clock_khz))
        .collect();
    if sizes
        != [
            (1920, 1080, 148_500),
            (1280, 1024, 108_000),
            (640, 480, 25_175),
            (1280, 720, 74_250),
        ]
    {
        return TestResult::Fail("mode list order and filtering");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_lists_standard_established_and_vic_modes_like_linux
);

fn navi48_modeset_bounds_the_link_by_a_repeater_chain() -> TestResult {
    use inventory::Connector::DisplayPort as Dp;
    let paths = [path(Dp, 0)];
    let mut p = port(paths[0], dpcd(0x14, 4), edid_1080p());
    if let Ok(sink) = p.sink.as_mut() {
        sink.lttpr = Some((0x0a, 4)); // the repeater stops at HBR
    }
    match select(&paths, &[p], 8, None) {
        Ok(s) if (s.lanes, s.rate) == (4, DpRate::Legacy(LinkRate::Hbr)) => TestResult::Pass,
        _ => TestResult::Fail("LTTPR-bounded link"),
    }
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_bounds_the_link_by_a_repeater_chain
);

/// Every lightable sink becomes a display: DP ports in board order, then
/// HDMI, each with its own wanted mode, at most four; a configuration the
/// pipeline cannot carry drops displays from the end.
fn navi48_modeset_selects_every_sink_and_admits_what_fits() -> TestResult {
    use inventory::Connector::{DisplayPort as Dp, HdmiTypeA as Hdmi};
    let paths = [
        path(Hdmi, 0),
        path(Dp, 1),
        path(Hdmi, 2),
        path(Dp, 3),
        path(Dp, 4),
        path(Dp, 5),
    ];
    let ports = [
        port(paths[0], None, edid_three_modes(true)),
        port(paths[1], dpcd(0x14, 4), edid_1080p()),
        // A DVI sink on an HDMI connector is not lit at all.
        port(paths[2], None, with_cta(edid_1080p(), false)),
        port(paths[3], dpcd(0x14, 4), edid_three_modes(false)),
        display::Port {
            path: paths[4],
            sink: Err(display::Error::InvalidDpcd),
        },
        port(paths[5], dpcd(0x14, 4), edid_1080p()),
    ];
    let wanted = edid_timings(&edid_three_modes(false))[1];
    let Ok(all) = select_all(&paths, &ports, 8, &|port| (port == 3).then_some(wanted)) else {
        return TestResult::Fail("no selection");
    };
    let order: Vec<(usize, bool)> = all.iter().map(|s| (s.port, s.hdmi)).collect();
    if order != [(1, false), (3, false), (5, false), (0, true)] {
        return TestResult::Fail("display order");
    }
    // Only port 3 was asked for another mode; the others take their preferred.
    if all[1].timing != wanted || all[0].timing.h_active != 1920 || all[3].timing == wanted {
        return TestResult::Fail("per-port wanted mode");
    }
    if select(&paths, &ports, 8, None).map(|s| s.port) != Ok(1) {
        return TestResult::Fail("one display is the first of all");
    }
    // A fifth sink stays dark.
    let mut more = ports.to_vec();
    more.push(port(path(Dp, 6), dpcd(0x14, 4), edid_1080p()));
    let mut paths6 = paths.to_vec();
    paths6.push(path(Dp, 6));
    if select_all(&paths6, &more, 8, &|_| None).map(|a| a.len()) != Ok(MAX_DISPLAYS) {
        return TestResult::Fail("more than four displays");
    }
    // A slow board carries 1080p60 but not 2160p120 beside it: the second
    // display stays dark; alone, the 2160p120 one is refused outright (it
    // would need a 3:1 ODM split of the 500-MHz DISPCLK).
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 456_000,
        fclk_khz: [300_000, 800_000],
        dcfclk_khz: [200_000, 600_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 500_000,
        dppclk_max_khz: 500_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let mut fast = all[0];
    fast.timing = Timing {
        pixel_clock_khz: 1_188_000,
        h_active: 3840,
        h_total: 4400,
        h_front_porch: 176,
        h_sync_width: 88,
        v_active: 2160,
        v_total: 2250,
        v_front_porch: 8,
        v_sync_width: 10,
        h_sync_positive: true,
        v_sync_positive: true,
    };
    match admit_displays(&soc, &[all[0], fast]) {
        Ok(plans) if plans.len() == 1 && plans[0].mode == mode(all[0].timing) => {}
        _ => return TestResult::Fail("configuration not cut to what fits"),
    }
    if admit_displays(&soc, &[fast, all[0]]).is_ok() {
        return TestResult::Fail("first display beyond the board admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_selects_every_sink_and_admits_what_fits
);

/// An HDMI 2.0 sink limited to 300 MHz TMDS: VICs 16 (1080p60), 97 (2160p60)
/// and 95 (2160p30) in its Video Data Block, 97 also as 4:2:0 (Y420CMDB),
/// and 96 (2160p50) only as 4:2:0 (Y420VDB).
fn edid_y420() -> Vec<u8> {
    const VSDB_300: &[u8] = &[3 << 5 | 7, 0x03, 0x0c, 0x00, 0x10, 0x00, 0, 60];
    with_blocks(
        edid_1080p(),
        &[
            &[2 << 5 | 3, 16, 97, 95],
            VSDB_300,
            &[7 << 5 | 2, 15, 0b010],
            &[7 << 5 | 2, 14, 96],
        ],
    )
}

/// amdgpu's encoding choice on HDMI: RGB where it fits, 4:2:0 for a mode
/// the sink takes only so, and 4:2:0 for one RGB cannot carry that the
/// sink also takes so; 4:2:0-only modes join the mode list.
fn navi48_modeset_picks_ycbcr420_like_amdgpu() -> TestResult {
    let edid = edid_y420();
    let caps = hdmi_caps(&edid);
    let bit = |map: [u64; 4], vic: u8| map[usize::from(vic / 64)] & 1 << (vic % 64) != 0;
    if !caps.ycbcr420
        || !bit(caps.y420_only, 96)
        || bit(caps.y420_only, 97)
        || !bit(caps.y420_also, 97)
        || bit(caps.y420_also, 16)
        || bit(caps.y420_also, 95)
    {
        return TestResult::Fail("Y420VDB / Y420CMDB parsing");
    }
    // An empty map covers every SVD.
    let all = hdmi_caps(&with_blocks(
        edid_1080p(),
        &[&[2 << 5 | 2, 16, 97], &[7 << 5 | 1, 15]],
    ));
    if !bit(all.y420_also, 16) || !bit(all.y420_also, 97) {
        return TestResult::Fail("empty Y420CMDB map");
    }
    let timings = edid_timings(&edid);
    let by = |khz: u32, w: u32, total: u32| {
        timings
            .iter()
            .copied()
            .find(|t| (t.pixel_clock_khz, t.h_active, t.h_total) == (khz, w, total))
    };
    let (Some(p1080), Some(p2160_60), Some(p2160_30), Some(p2160_50)) = (
        by(148_500, 1920, 2200),
        by(594_000, 3840, 4400),
        by(297_000, 3840, 4400),
        by(594_000, 3840, 5280),
    ) else {
        return TestResult::Fail("4:2:0-only mode missing from the mode list");
    };
    use otg::ColorDepth::Bpc8;
    if hdmi_format(caps, &p1080, 8) != Some((Bpc8, false))
        || hdmi_format(caps, &p2160_30, 8) != Some((Bpc8, false))
        || hdmi_format(caps, &p2160_60, 8) != Some((Bpc8, true))
        || hdmi_format(caps, &p2160_50, 8) != Some((Bpc8, true))
    {
        return TestResult::Fail("encoding choice");
    }
    // Without the CMDB, 2160p60 does not fit at all.
    let rgb_only = HdmiCaps {
        y420_also: [0; 4],
        ..caps
    };
    if hdmi_format(rgb_only, &p2160_60, 8).is_some() {
        return TestResult::Fail("4:2:0 without the sink taking it");
    }
    // A wanted 2160p60 lights as 4:2:0, with its CTA VIC.
    let paths = [path(inventory::Connector::HdmiTypeA, 0)];
    let ports = [port(paths[0], None, edid.clone())];
    match select(&paths, &ports, 8, Some(p2160_60)) {
        Ok(s) if s.ycbcr420 && s.hdmi && s.depth == Bpc8 && s.avi.vic == 97 => {}
        _ => return TestResult::Fail("4:2:0 selection"),
    }
    if !selection_mode(&select(&paths, &ports, 8, Some(p2160_60)).unwrap()).ycbcr420
        || select(&paths, &ports, 8, None).is_ok_and(|s| s.ycbcr420)
    {
        return TestResult::Fail("4:2:0 admission mode");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_picks_ycbcr420_like_amdgpu
);

/// UHBR as Linux decides it: the board's connector speed, the sink's 0x2215
/// rates and a revision 1.4 repeater chain's bound the rates (UHBR13.5 only
/// where listed); 128b/132b bandwidth is 96.41% of the raw rate; streams
/// carry pixel-to-symbol padding; UHBR is used only past every 8b/10b
/// setting, upward; fallback walks the bandwidth-ordered table.
fn navi48_modeset_decides_uhbr_like_linux() -> TestResult {
    use otg::UhbrRate::{Uhbr10 as U10, Uhbr13_5 as U13, Uhbr20 as U20};
    let caps_of = |speed: u32, uhbr: u8, lttpr_uhbr: Option<u8>| {
        let mut p = path(inventory::Connector::DisplayPort, 0);
        p.max_speed_mhz = speed;
        let sink = display::Sink {
            dpcd: dpcd(0x1e, 4),
            edid: Vec::new(),
            lttpr: None,
            uhbr,
            lttpr_uhbr,
            fec: false,
            dsc: None,
            verified_link: None,
        };
        dp_caps(&p, &sink).unwrap().uhbr
    };
    if caps_of(20_000, 7, None) != 0b111
        || caps_of(20_000, 7, Some(1)) != 0b001
        || caps_of(20_000, 7, Some(0)) != 0
        || caps_of(20_000, 3, None) != 0b101
        || caps_of(20_000, 7, Some(3)) != 0b101
        || caps_of(13_500, 7, None) != 0b011
        || caps_of(13_500, 3, None) != 0b001
        || caps_of(8_100, 7, None) != 0
        || caps_of(0, 7, None) != 0
        || caps_of(20_000, 0, None) != 0
    {
        return TestResult::Fail("UHBR caps");
    }
    if uhbr_kbps(4, U10) != 38_564_000
        || uhbr_kbps(4, U13) != 52_061_400
        || uhbr_kbps(4, U20) != 77_128_000
        || uhbr_kbps(1, U10) != 9_641_000
    {
        return TestResult::Fail("128b/132b bandwidth");
    }
    let timing = |khz: u32, h_active: u32| Timing {
        pixel_clock_khz: khz,
        h_active,
        h_total: h_active + 560,
        h_front_porch: 176,
        h_sync_width: 88,
        v_active: 2160,
        v_total: 2250,
        v_front_porch: 8,
        v_sync_width: 10,
        h_sync_positive: true,
        v_sync_positive: true,
    };
    // 3840 x 24 bits fill 720 symbols exactly; 1366 x 24 needs 256.125.
    let uhd60 = timing(594_000, 3840);
    let odd = timing(85_500, 1366);
    if stream_kbps(&uhd60, true) != 14_256_000
        || stream_kbps(&odd, false) != 2_052_000
        || stream_kbps(&odd, true) != (2_052_000u64 * 257 * 128).div_ceil(1366 * 24)
    {
        return TestResult::Fail("stream bandwidth");
    }
    let caps = |uhbr: u8| DpCaps {
        lanes: 4,
        rate: LinkRate::Hbr3,
        uhbr,
        fec: false,
        dsc: None,
    };
    let uhd120 = timing(1_188_000, 3840);
    let uhd8k = timing(2_376_000, 7680);
    use DpRate::{Legacy, Uhbr};
    if dp_link(&uhd60, caps(7)) != Some((4, Legacy(LinkRate::Hbr3)))
        || dp_link(&uhd120, caps(7)) != Some((4, Uhbr(U10)))
        || dp_link(&uhd8k, caps(7)) != Some((4, Uhbr(U20)))
        || dp_link(&uhd8k, caps(3)).is_some()
        || dp_link(&uhd120, caps(0)).is_some()
    {
        return TestResult::Fail("upward link decision");
    }
    // Two lanes: 2 x UHBR13.5 (26,030,700 kbps) falls short, 2 x UHBR20
    // carries it; four lanes stop at 4 x UHBR10 first.
    let two = DpCaps {
        lanes: 2,
        ..caps(7)
    };
    if dp_link(&uhd120, two) != Some((2, Uhbr(U20))) {
        return TestResult::Fail("lanes before rate");
    }
    // FEC: 4 x HBR2 carries 17,280,000 kbps, 16,761,600 with FEC's 3%.
    let edge = timing(710_000, 3840);
    let fec = DpCaps {
        rate: LinkRate::Hbr2,
        fec: true,
        dsc: None,
        ..caps(0)
    };
    if dp_link(&edge, DpCaps { fec: false, ..fec }) != Some((4, Legacy(LinkRate::Hbr2)))
        || dp_link(&edge, fec).is_some()
        || !dp_fits(&timing(698_400, 3840), fec, 4, Legacy(LinkRate::Hbr2))
        || dp_fits(&timing(698_401, 3840), fec, 4, Legacy(LinkRate::Hbr2))
    {
        return TestResult::Fail("8b/10b FEC bandwidth");
    }
    if dp_candidates(&uhd120, caps(7), 4, Uhbr(U10)) != [(4, Uhbr(U10))] {
        return TestResult::Fail("fallback that cannot carry the mode");
    }
    let ladder = dp_candidates(&uhd60, caps(0b101), 4, Uhbr(U20));
    // 128b/132b settings only: the timing is staged for HPO output.
    let want = [
        (4, Uhbr(U20)),
        (2, Uhbr(U20)),
        (4, Uhbr(U10)),
        (1, Uhbr(U20)),
        (2, Uhbr(U10)),
    ];
    if ladder != want {
        return TestResult::Fail("bandwidth-ordered fallback");
    }
    // 4K60 on a one-lane sink needs 128b/132b (1 x UHBR20), with LPCM.
    let mut p = path(inventory::Connector::DisplayPort, 0);
    p.max_speed_mhz = 20_000;
    let paths = [p];
    let mut sink = display::Sink {
        dpcd: dpcd(0x1e, 1),
        edid: edid_uhbr(),
        lttpr: None,
        uhbr: 7,
        lttpr_uhbr: None,
        fec: false,
        dsc: None,
        verified_link: None,
    };
    let port = display::Port {
        path: p,
        sink: Ok(sink.clone()),
    };
    match select(&paths, &[port], 8, None) {
        Ok(s)
            if s.uhbr()
                && s.rate == Uhbr(U20)
                && s.lanes == 1
                && s.audio == sink_audio_info(&edid_uhbr()) => {}
        other => panic!("UHBR selection {other:?}"),
    }
    // Without a board connector-speed record it does not light at all.
    sink.uhbr = 7;
    let bare = path(inventory::Connector::DisplayPort, 0);
    let port = display::Port {
        path: bare,
        sink: Ok(sink),
    };
    if select(&[bare], &[port], 8, None).is_ok() {
        return TestResult::Fail("UHBR without the board's speed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_decides_uhbr_like_linux
);

/// A sink whose preferred mode is 3840x2160@60 (594 MHz), with audio.
fn edid_uhbr() -> Vec<u8> {
    let mut e = edid_1080p();
    e[54..72].copy_from_slice(&[
        0x08, 0xe8, 0x00, 0x30, 0xf2, 0x70, 0x5a, 0x80, 0xb0, 0x58, 0x8a, 0, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[127] = 0;
    e[127] = narf_edid::compute_checksum(&e);
    const AUDIO: &[u8] = &[1 << 5 | 3, 0x09, 0x07, 0x07];
    with_blocks(e, &[AUDIO])
}

/// HDMI FRL as amdgpu decides it: off unless enabled (dcfeaturemask
/// 0x400); the sink's HF Max_FRL_Rate bounded by DCN401's forced 4 x 12G
/// and requiring SCDC; get_audio_check's packet type and layout; the
/// lowest rate code carrying the mode by Linux's capacity check, if the
/// cap carries it at all.
fn navi48_modeset_decides_frl_like_linux() -> TestResult {
    // HF-VSDB: version 1, 600 MHz, SCDC_Present, Max_FRL_Rate 6 (4 x 12G).
    const HF_FRL: &[u8] = &[3 << 5 | 7, 0xd8, 0x5d, 0xc4, 1, 120, 0x80, 0x60];
    let caps = hdmi_caps(&with_blocks(edid_1080p(), &[VSDB, HF_FRL]));
    if caps.max_frl_rate != 6 || !caps.scdc {
        return TestResult::Fail("Max_FRL_Rate");
    }
    set_frl(false);
    if frl_cap(caps).is_some() {
        return TestResult::Fail("FRL used while disabled");
    }
    set_frl(true);
    let cap = frl_cap(caps);
    let three = frl_cap(HdmiCaps {
        max_frl_rate: 2,
        ..caps
    });
    let no_scdc = frl_cap(HdmiCaps {
        scdc: false,
        ..caps
    });
    set_frl(false);
    if cap.map(|r| (r.code(), r.lanes(), r.gbps())) != Some((6, 4, 12))
        || three.map(|r| (r.lanes(), r.character_khz())) != Some((3, 333_333))
        || no_scdc.is_some()
    {
        return TestResult::Fail("FRL cap");
    }
    let mut info = otg::AudioInfo {
        manufacturer_id: 0,
        product_id: 0,
        name: [0; 18],
        speakers: 5,
        modes: [otg::AudioMode::default(); 16],
        mode_count: 2,
        video_latency: 0,
        audio_latency: 0,
    };
    info.modes[0] = otg::AudioMode {
        format: 1,
        channels: 2,
        rates: 0x07,
        byte2: 7,
    };
    info.modes[1] = otg::AudioMode {
        format: 1,
        channels: 8,
        rates: 0x7f,
        byte2: 7,
    };
    let a = |i: Option<otg::AudioInfo>, v| {
        let a = frl_audio(i, v);
        (a.packet_type, a.max_rate_hz, a.layout)
    };
    if a(None, 2160) != (2, 0, 0)
        || a(Some(info), 2160) != (2, 192_000, 1)
        || a(Some(info), 480) != (2, 192_000, 0)
    {
        return TestResult::Fail("FRL audio check");
    }
    let t = |khz: u32, w: u32, total: u32| Timing {
        pixel_clock_khz: khz,
        h_active: w,
        h_total: total,
        h_front_porch: 176,
        h_sync_width: 88,
        v_active: 2160,
        v_total: 2250,
        v_front_porch: 8,
        v_sync_width: 10,
        h_sync_positive: true,
        v_sync_positive: true,
    };
    let quiet = frl_audio(None, 2160);
    let cap = FrlRate::new(6).unwrap();
    let uhd120 = t(1_188_000, 3840, 4400);
    let uhd8k = t(2_376_000, 7680, 9000);
    if frl_link(&uhd120, 8, false, cap, quiet).map(FrlRate::code) != Some(4)
        || frl_link(&uhd120, 10, false, cap, quiet).map(FrlRate::code) != Some(5)
        || frl_link(&uhd8k, 8, false, cap, quiet).is_some()
        || frl_link(&uhd120, 8, false, FrlRate::new(3).unwrap(), quiet).is_some()
    {
        return TestResult::Fail("FRL rate decision");
    }
    // TMDS whenever it carries the mode; FRL only beyond it, RGB at the
    // deepest declared depth that some rate carries.
    let deep = HdmiCaps {
        dc30: true,
        dc36: false,
        ..caps
    };
    let out = |t: &Timing, bpc, cap| {
        hdmi_output(deep, t, bpc, cap, None).map(|(d, y, r)| (d, y, r.map(FrlRate::code)))
    };
    let uhd60 = t(594_000, 3840, 4400);
    if out(&uhd60, 10, Some(cap)) != Some((otg::ColorDepth::Bpc8, false, None))
        || out(&uhd120, 10, Some(cap)) != Some((otg::ColorDepth::Bpc10, false, Some(5)))
        || out(&uhd120, 8, Some(cap)) != Some((otg::ColorDepth::Bpc8, false, Some(4)))
        || out(&uhd120, 10, None).is_some()
        || out(&uhd8k, 12, Some(cap)).is_some()
    {
        return TestResult::Fail("HDMI output choice");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_decides_frl_like_linux
);

/// DSC as amdgpu_dm's SST policy uses it here: a 4K60 sink on two HBR2
/// lanes (8,380,800 kbps with FEC) cannot take the 14,256,000 kbps stream,
/// so it is compressed to the highest bpp that link carries, on the
/// maximum 8b/10b link, with its audio; an 8b/10b sink without DSC or
/// without FEC gets no DSC (128b/132b sinks:
/// `navi48_modeset_decides_uhbr_dsc_like_linux`), and a stream that fits
/// needs none.
fn navi48_modeset_decides_dsc_like_linux() -> TestResult {
    use crate::amdgpu_dsc::{compute_config, DscSinkCaps, DscTiming, Encoding, LinkEncoding};
    let p = path(inventory::Connector::DisplayPort, 0);
    // DSC 1.2, slices 1/2/4, 13-bit line buffer, RGB, 8/10/12 bpc,
    // 1000 MP/s per slice, 5120-pixel slices, 1/16 bpp.
    const DSC: [u8; 16] = [
        1, 0x21, 0, 0x0b, 0x0b, 4, 1, 0, 0, 0x13, 0x0e, 0xee, 16, 0, 0, 0,
    ];
    let sink = |dsc: Option<[u8; 16]>, fec: bool, lanes: u8| display::Sink {
        dpcd: dpcd(0x14, lanes),
        edid: edid_uhbr(),
        lttpr: None,
        uhbr: 0,
        lttpr_uhbr: None,
        fec,
        dsc,
        verified_link: None,
    };
    let pick = |s: display::Sink| {
        select(
            &[p],
            &[display::Port {
                path: p,
                sink: Ok(s),
            }],
            8,
            None,
        )
    };
    let Ok(s) = pick(sink(Some(DSC), true, 2)) else {
        return TestResult::Fail("DSC sink not selected");
    };
    let t = DscTiming {
        pix_clk_100hz: s.timing.pixel_clock_khz * 10,
        h_active: s.timing.h_active,
        h_total: s.timing.h_total,
        v_active: s.timing.v_active,
        v_total: s.timing.v_total,
        bpc: 8,
        encoding: Encoding::Rgb,
    };
    let want = compute_config(
        &DscSinkCaps::parse(&DSC, &[0; 3]).unwrap(),
        2_000_000,
        8_380_800,
        &t,
        LinkEncoding::Dp8b10b,
        false,
    );
    if want.is_none()
        || s.dsc != want
        || (s.lanes, s.rate) != (2, DpRate::Legacy(LinkRate::Hbr2))
        || s.audio != sink_audio_info(&edid_uhbr())
        || s.audio.is_none()
        || selection_mode(&s).dsc.map(|d| (d.slices, d.bpp_x16))
            != want.map(|c| (c.slices_h, c.bpp_x16))
    {
        return TestResult::Fail("DSC selection");
    }
    // Four lanes carry 4K60 uncompressed; no DSC sink, no FEC: no mode.
    if pick(sink(Some(DSC), true, 4)).map(|s| s.dsc.is_none()) != Ok(true)
        || pick(sink(None, true, 2)).is_ok()
        || pick(sink(Some(DSC), false, 2)).is_ok()
    {
        return TestResult::Fail("DSC only when needed and possible");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_decides_dsc_like_linux
);

fn limited_bpp_dsc_selection() -> Selection {
    let p = path(inventory::Connector::DisplayPort, 0);
    let mut device = port(p, dpcd(0x1e, 2), edid_uhbr());
    let sink = device.sink.as_mut().unwrap();
    sink.fec = true;
    // Same DSC capabilities as above, with the sink capped at 8 bpp.
    sink.dsc = Some([
        1, 0x21, 0, 0x0b, 0x0b, 4, 1, 128, 0, 0x13, 0x0e, 0xee, 16, 0, 0, 0,
    ]);
    select(&[p], &[device], 8, None).unwrap()
}

fn navi48_dsc_fallback_keeps_the_admitted_pps_and_filters_link_capacity() -> TestResult {
    use DpRate::Legacy;
    use LinkRate::{Hbr2, Hbr3};
    let mut s = limited_bpp_dsc_selection();
    let cfg = s.dsc.unwrap();
    assert_eq!(cfg.bpp_x16, 128);
    assert_eq!(
        selected_dp_candidates(&s),
        [(2, Legacy(Hbr3)), (2, Legacy(Hbr2)), (1, Legacy(Hbr3))]
    );
    assert_eq!(s.dsc, Some(cfg), "fallback changed the staged PPS");
    s.lanes = 1;
    assert_eq!(selected_dp_candidates(&s), [(1, Legacy(Hbr3))]);
    s.caps.fec = false;
    assert!(selected_dp_candidates(&s).is_empty());
    s.caps.fec = true;
    s.rate = Legacy(Hbr2);
    assert!(selected_dp_candidates(&s).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_dsc_fallback_keeps_the_admitted_pps_and_filters_link_capacity
);

fn navi48_dp_alternatives_keep_dsc_admission_and_bound_the_fallback_link() -> TestResult {
    let mut s = limited_bpp_dsc_selection();
    let faster = Timing {
        pixel_clock_khz: s.timing.pixel_clock_khz * 2,
        ..s.timing
    };
    let offered = dp_offered_mode(faster, &s, 2_000_000).unwrap();
    assert_eq!(offered.dsc.unwrap().bpp_x16, 128);
    assert!(
        dp_offered_mode(faster, &s, 1_000).is_none(),
        "used nominal rather than board DISPCLK"
    );
    s.lanes = 1; // Trained HBR3, 6.2856 Gbit/s after FEC.
    assert!(dp_offered_mode(s.timing, &s, 2_000_000)
        .unwrap()
        .dsc
        .is_some());
    assert!(dp_offered_mode(faster, &s, 2_000_000).is_none());
    let mut m = completed_modeset(0);
    m.selection.lanes = 1;
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [500_000, 2_000_000],
        dcfclk_khz: [300_000, 1_200_000],
        socclk_khz: 600_000,
        dispclk_max_khz: 1_500_000,
        dppclk_max_khz: 1_500_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let previous = edid_timings(&edid_three_modes(false));
    let refreshed = admitted_modes(&soc, &[m], 0, previous, |t| {
        dp_offered_mode(t, &m.selection, soc.dispclk_max_khz)
    });
    assert_eq!(
        refreshed
            .into_iter()
            .flatten()
            .map(|t| t.h_active)
            .collect::<Vec<_>>(),
        [1920, 1280]
    );
    // Even an empty old list retains the actual running timing as a historical
    // witness; alternatives still need fresh admission.
    let refreshed = admitted_modes(&soc, &[m], 0, [], |_| None);
    assert_eq!(refreshed[0], Some(m.selection.timing));
    assert_eq!(refreshed.into_iter().flatten().count(), 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_dp_alternatives_keep_dsc_admission_and_bound_the_fallback_link
);

/// MST streams as amdgpu_dm's MST atomic check admits them on an HBR2 x4
/// link (40 PBN per slot): each device takes the timing asked of it, or
/// its first EDID timing whose payload fits the slots the earlier ones
/// left of 63 and its port's available PBN; a device nothing fits stays
/// dark.
fn navi48_modeset_selects_mst_streams_like_amdgpu_dm() -> TestResult {
    use crate::dp_mst_mgr::Sink;
    let caps = DpCaps {
        lanes: 4,
        rate: LinkRate::Hbr2,
        uhbr: 0,
        fec: false,
        dsc: None,
    };
    let sink = |port| Sink { branch: 0, port };
    let devices = [
        (sink(1), edid_2160p(), u16::MAX),
        (sink(2), edid_three_modes(false), u16::MAX),
        (sink(3), edid_2160p(), u16::MAX),
    ];
    let uhd = edid_timings(&edid_2160p())[0];
    let want = |_| Some(uhd);
    let s = super::super::select_mst(2, caps, &devices, &want);
    let pbn_div = crate::dp_mst::pbn_div(17_280_000);
    let shown: Vec<(u32, u8)> = s
        .iter()
        .map(|s| (s.timing.h_active, s.mst.map_or(0, |m| m.slots)))
        .collect();
    // 2160p takes 54 slots; neither 2160p nor 1080p (14) fits beside it,
    // 720p (7) does; the third device's only mode does not.
    if pbn_div != 40 << 12 || shown != [(3840, 54), (1280, 7)] {
        panic!("MST streams {shown:?}");
    }
    let m = s[0].mst.unwrap();
    if m.sink != sink(1)
        || u32::from(m.pbn) != crate::dp_mst::calc_pbn_mode(594_000, 384)
        || m.rate != otg::vc_rate(594_000 * 24, 17_280_000).unwrap()
        || s[0].port != 2
        || s[0].lanes != 4
        || s[0].audio.is_some()
    {
        return TestResult::Fail("MST stream");
    }
    // A port's available PBN bounds its device: 1080p rather than 2160p.
    let one = [(sink(1), edid_three_modes(false), 600)];
    let s = super::super::select_mst(0, caps, &one, &want);
    if s.len() != 1 || s[0].timing.h_active != 1920 {
        return TestResult::Fail("available PBN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_selects_mst_streams_like_amdgpu_dm
);

fn navi48_mst_keeps_sink_output_assignments() -> TestResult {
    use crate::dp_mst_mgr::Sink;
    let caps = DpCaps {
        lanes: 4,
        rate: LinkRate::Hbr2,
        uhbr: 0,
        fec: false,
        dsc: None,
    };
    let sink = |port| Sink { branch: 0, port };
    let mut devices = [
        (sink(1), edid_2160p(), u16::MAX),
        (sink(2), Vec::new(), u16::MAX), // EDID read failed: keep the gap.
        (sink(3), edid_three_modes(false), u16::MAX),
    ];
    let timing = edid_timings(&devices[2].1)[1];
    let pipes = [None, Some(1), Some(2)];
    let choose = |devices: &[_], pipes: &[_]| {
        super::super::mst::select_mst_outputs(
            2,
            caps,
            devices,
            &|k| (k == 2).then_some(timing),
            pipes,
            &|_, _| u16::MAX,
        )
    };
    let picked = choose(&devices, &pipes);
    if picked.len() != 1
        || picked[0].1 != 2
        || picked[0].0.mst.unwrap().sink != sink(3)
        || picked[0].0.timing != timing
    {
        return TestResult::Fail("disabled or unreadable sink shifted the output");
    }
    // An enabled sink with no fitting timing must not consume another
    // sink's pipe or requested mode either.
    devices[0].2 = 1;
    let picked = choose(&devices, &[Some(0), Some(1), Some(2)]);
    if picked.len() != 1 || picked[0].1 != 2 || picked[0].0.timing != timing {
        return TestResult::Fail("unadmitted sink shifted the output");
    }
    if !choose(&devices, &[None, None, None]).is_empty() {
        return TestResult::Fail("disabled CRTCs were selected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_mst_keeps_sink_output_assignments
);

fn navi48_mst_admits_dark_connector_modes() -> TestResult {
    use super::super::mst::dark_mst_modes;
    let caps = DpCaps {
        lanes: 4,
        rate: LinkRate::Hbr2,
        uhbr: 0,
        fec: false,
        dsc: None,
    };
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [500_000, 2_000_000],
        dcfclk_khz: [300_000, 1_200_000],
        socclk_khz: 600_000,
        dispclk_max_khz: 1_500_000,
        dppclk_max_khz: 1_500_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let edid = edid_three_modes(false);
    let widths = |m: Vec<Timing>| m.iter().map(|t| t.h_active).collect::<Vec<_>>();
    // Enumeration works before any stream has ever been selected or lit.
    let all = dark_mst_modes(&soc, caps, &edid, u16::MAX, &[]);
    assert_eq!(widths(all.clone()), [1920, 3840, 1280]);
    assert_eq!(
        widths(dark_mst_modes(&soc, caps, &edid, 600, &[])),
        [1920, 1280]
    );
    assert!(dark_mst_modes(&soc, caps, &edid, 1, &[]).is_empty());
    assert!(dark_mst_modes(&soc, caps, &edid, 0, &[]).is_empty());
    assert!(dark_mst_modes(&soc, caps, &[], u16::MAX, &[]).is_empty());
    // Too slow even for 720p split across two ODM pipes.
    let slow = dml::Soc {
        dispclk_max_khz: 30_000,
        ..soc
    };
    assert!(dark_mst_modes(&slow, caps, &edid, u16::MAX, &[]).is_empty());

    let sink = crate::dp_mst_mgr::Sink { branch: 0, port: 1 };
    let mut lit = super::super::select_mst(0, caps, &[(sink, edid_2160p(), u16::MAX)], &|_| None);
    // A running 4K60 stream owns 54 slots; only 720p fits in the remaining 9.
    assert_eq!(
        widths(dark_mst_modes(&soc, caps, &edid, u16::MAX, &lit)),
        [1280]
    );
    lit[0].mst.as_mut().unwrap().slots = 63;
    assert!(dark_mst_modes(&soc, caps, &edid, u16::MAX, &lit).is_empty());
    // Even spare link slots cannot admit a fifth display engine stream.
    let one = super::super::select_mst(0, caps, &[(sink, edid_1080p(), u16::MAX)], &|_| None)[0];
    assert!(dark_mst_modes(&soc, caps, &edid, u16::MAX, &[one; 4]).is_empty());
    // Board SST/HDMI streams in the same configuration use no MST slots but
    // do take display engine pipes in the joint admission.
    let mut board = one;
    board.mst = None;
    board.port = 1;
    assert_eq!(
        widths(dark_mst_modes(&soc, caps, &edid, u16::MAX, &[board])),
        [1920, 3840, 1280]
    );
    assert!(dark_mst_modes(&soc, caps, &edid, u16::MAX, &[board, board, one, one]).is_empty());
    lit[0].mst.as_mut().unwrap().slots = 54;
    assert_eq!(
        widths(dark_mst_modes(
            &soc,
            caps,
            &edid,
            u16::MAX,
            &[board, lit[0]]
        )),
        [1280]
    );
    // Advertising a timing does not enable the connector. A later explicit
    // request retains its fixed pipe and gets full configuration admission.
    let devices = [(sink, edid, u16::MAX)];
    assert!(super::super::mst::select_mst_outputs(
        0,
        caps,
        &devices,
        &|_| None,
        &[None],
        &|_, _| u16::MAX
    )
    .is_empty());
    let enabled = super::super::mst::select_mst_outputs(
        0,
        caps,
        &devices,
        &|_| Some(all[1]),
        &[Some(3)],
        &|_, _| u16::MAX,
    );
    assert_eq!((enabled[0].0.timing, enabled[0].1), (all[1], 3));
    assert!(admit_displays(&soc, &[enabled[0].0]).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_mst_admits_dark_connector_modes
);

fn navi48_mst_selection_obeys_shared_path_budget() -> TestResult {
    let caps = DpCaps {
        lanes: 4,
        rate: LinkRate::Hbr2,
        uhbr: 0,
        fec: false,
        dsc: None,
    };
    let devices = [
        (
            crate::dp_mst_mgr::Sink { branch: 1, port: 1 },
            edid_three_modes(false),
            u16::MAX,
        ),
        (
            crate::dp_mst_mgr::Sink { branch: 1, port: 2 },
            edid_three_modes(false),
            u16::MAX,
        ),
    ];
    // Both end ports can carry 1080p, but their common upstream hop cannot
    // carry two such streams. The second keeps its pipe and takes 720p.
    let budget = |_, selected: &[Selection]| {
        900u16.saturating_sub(selected.iter().filter_map(|s| s.mst).map(|m| m.pbn).sum())
    };
    let picked = super::super::mst::select_mst_outputs(
        0,
        caps,
        &devices,
        &|_| None,
        &[Some(1), Some(3)],
        &budget,
    );
    assert_eq!(
        picked
            .iter()
            .map(|(s, p)| (s.timing.h_active, *p))
            .collect::<Vec<_>>(),
        [(1920, 1), (1280, 3)]
    );
    assert!(super::super::mst::select_mst_outputs(
        0,
        caps,
        &devices,
        &|_| None,
        &[Some(1), Some(3)],
        &|_, _| 0,
    )
    .is_empty());
    let zero = [(devices[0].0, devices[0].1.clone(), 0)];
    assert!(super::super::select_mst(0, caps, &zero, &|_| None).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_mst_selection_obeys_shared_path_budget
);

/// FRL fallback must obey the sink's Y420VDB, including when
/// the mode fits the FRL wire rate but cannot fit TMDS at half pixel rate.
fn navi48_frl_fallback_respects_y420_only_modes() -> TestResult {
    let edid = edid_y420();
    let caps = HdmiCaps {
        max_frl_rate: 6,
        scdc: true,
        ..hdmi_caps(&edid)
    };
    let t = edid_timings(&edid)
        .into_iter()
        .find(|t| (t.pixel_clock_khz, t.h_active, t.h_total) == (594_000, 3840, 5280))
        .unwrap(); // CTA VIC 96, listed only as 4:2:0.
    let frl = Some(FrlRate::new(6).unwrap());
    if hdmi_output(caps, &t, 8, frl, None) != Some((otg::ColorDepth::Bpc8, true, None)) {
        return TestResult::Fail("lost supported TMDS 4:2:0");
    }
    let limited = HdmiCaps {
        vsdb_max_khz: 165_000,
        forum_max_khz: 0,
        ..caps
    };
    for depth in [8, 10, 12] {
        if !matches!(
            hdmi_output(limited, &t, depth, frl, None),
            Some((otg::ColorDepth::Bpc8, true, Some(_)))
        ) {
            return TestResult::Fail("FRL did not preserve 4:2:0-only encoding");
        }
    }
    // The same rate/timing remains usable when RGB is allowed (including
    // sinks that advertise 4:2:0 as an additional encoding).
    for also in [[0; 4], caps.y420_only] {
        let rgb = HdmiCaps {
            y420_only: [0; 4],
            y420_also: also,
            ..limited
        };
        if !matches!(
            hdmi_output(rgb, &t, 8, frl, None),
            Some((otg::ColorDepth::Bpc8, false, Some(_)))
        ) {
            return TestResult::Fail("lost supported RGB FRL");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_frl_fallback_respects_y420_only_modes
);

/// HF 4:2:0 deep-color flags are independent of the RGB VSDB flags.
/// FRL capacity/rate selection preserves the chosen encoding and depth.
fn navi48_frl_420_caps_rates_and_selection() -> TestResult {
    use otg::ColorDepth::{Bpc10, Bpc12, Bpc8};
    let hf = [3 << 5 | 7, 0xd8, 0x5d, 0xc4, 1, 68, 0x80, 0x33];
    let y420 = [7 << 5 | 2, 14, 118]; // 3840x2160p120, 4:2:0-only.
    let edid = with_blocks(edid_1080p(), &[VSDB, &hf, &y420]);
    let caps = hdmi_caps(&edid);
    assert!(caps.dc30_420 && caps.dc36_420);
    assert!(!caps.dc30 && !caps.dc36);
    assert_eq!(caps.max_frl_rate, 3);
    // HF-SCDB places the same byte after its reserved/version/rate/flags.
    let scdb = [7 << 5 | 7, 0x79, 0, 0, 1, 68, 0x80, 0x31];
    let sc = hdmi_caps(&with_blocks(edid_1080p(), &[VSDB, &scdb, &y420]));
    assert!(sc.dc30_420 && !sc.dc36_420);
    let t = edid_timings(&edid)
        .into_iter()
        .find(|t| t.pixel_clock_khz == 1_188_000)
        .unwrap();
    let cap = FrlRate::new(3).unwrap();
    let quiet = frl_audio(None, t.v_active);
    // Linux reference vectors: 8 bpc uses 3x6G; 10/12 require 4x6G.
    for (bpc, depth, code) in [(8, Bpc8, 2), (10, Bpc10, 3), (12, Bpc12, 3)] {
        assert_eq!(
            frl_link(&t, bpc, true, cap, quiet).map(FrlRate::code),
            Some(code)
        );
        assert_eq!(
            hdmi_output(caps, &t, bpc, Some(cap), None),
            Some((depth, true, FrlRate::new(code)))
        );
        for candidate in 1..=cap.code() {
            assert_eq!(
                frl_carries(&t, bpc, true, FrlRate::new(candidate).unwrap(), quiet).is_some(),
                candidate >= code
            );
        }
    }
    assert!(hdmi_output(caps, &t, 12, None, None).is_none());
    assert!(hdmi_output(caps, &t, 12, FrlRate::new(1), None).is_none());
    for bpc in [0, 6, 16] {
        assert!(frl_carries(&t, bpc, true, cap, quiet).is_none());
    }
    for invalid in [
        Timing { h_active: 0, ..t },
        Timing {
            h_active: t.h_active + 1,
            ..t
        },
        Timing {
            h_total: t.h_total + 1,
            ..t
        },
        Timing {
            h_total: t.h_active - 1,
            ..t
        },
        Timing {
            pixel_clock_khz: 0,
            ..t
        },
        Timing {
            pixel_clock_khz: u32::MAX,
            ..t
        },
    ] {
        assert!(frl_carries(&invalid, 8, true, cap, quiet).is_none());
    }
    let eight_only = HdmiCaps {
        dc30_420: false,
        dc36_420: false,
        dc30: true,
        dc36: true,
        ..caps
    };
    assert_eq!(
        hdmi_output(eight_only, &t, 12, Some(cap), None),
        Some((Bpc8, true, FrlRate::new(2)))
    );
    assert_eq!(
        hdmi_output(sc, &t, 12, Some(cap), None),
        Some((Bpc10, true, Some(cap)))
    );
    let also = HdmiCaps {
        y420_only: [0; 4],
        y420_also: caps.y420_only,
        ..caps
    };
    assert_eq!(
        hdmi_output(also, &t, 8, Some(cap), None),
        Some((Bpc8, true, FrlRate::new(2)))
    );
    // RGB wins once it fits, even when deeper 4:2:0 would fit too.
    assert_eq!(
        hdmi_output(also, &t, 12, FrlRate::new(6), None),
        Some((Bpc8, false, FrlRate::new(4)))
    );
    let rgb = HdmiCaps {
        y420_also: [0; 4],
        ..also
    };
    assert!(hdmi_output(rgb, &t, 12, Some(cap), None).is_none());
    // The format survives complete connector selection and native admission.
    let paths = [path(inventory::Connector::HdmiTypeA, 0)];
    let ports = [port(paths[0], None, edid)];
    let enabled = frl_enabled();
    set_frl(true);
    let chosen = select(&paths, &ports, 12, Some(t));
    set_frl(enabled);
    let s = chosen.unwrap();
    assert!(s.hdmi && s.ycbcr420 && s.audio.is_none());
    assert_eq!(s.depth, Bpc12);
    assert_eq!(s.frl, Some(cap));
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [500_000, 2_000_000],
        dcfclk_khz: [300_000, 1_200_000],
        socclk_khz: 600_000,
        dispclk_max_khz: 1_500_000,
        dppclk_max_khz: 1_500_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let plan = dml::admit(&soc, &selection_mode(&s)).unwrap();
    assert!(plan.mode.ycbcr420);
    assert_eq!(timing_request(0, &plan, &s).signal, otg::Signal::HdmiFrl);
    assert!(timing_request(0, &plan, &s).ycbcr420);
    assert_eq!(
        pipe_clock_request(0, &plan, &s).pixel,
        dccg::PixelClock::HdmiFrl {
            pixel_hz: 1_188_000_000
        }
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_frl_420_caps_rates_and_selection
);

/// Linux dml1_frl_cap_chk: at 359.5 MHz, 1920 active + 280 blank,
/// 3x3G carries video/ACR alone (one packet, borrow blank), but rejects
/// 192 kHz layout 1 (-4). 3x6G carries it (two packets, no borrow).
fn navi48_frl_selection_reserves_audio_bandwidth() -> TestResult {
    const AUDIO: &[u8] = &[1 << 5 | 6, 0x0f, 0x7f, 7, 0x15, 7, 0x50];
    const HF: &[u8] = &[3 << 5 | 7, 0xd8, 0x5d, 0xc4, 1, 33, 0x80, 0x20];
    let mut base = edid_1080p();
    base[54..56].copy_from_slice(&35950u16.to_le_bytes());
    let edid = with_blocks(base, &[VSDB, HF, AUDIO]);
    let t = preferred(&edid).unwrap();
    let caps = hdmi_caps(&edid);
    let raw = sink_audio_info(&edid).unwrap();
    let rate = |audio, cap| {
        hdmi_output(caps, &t, 8, FrlRate::new(cap), audio)
            .and_then(|(_, _, r)| r.map(FrlRate::code))
    };
    assert_eq!(rate(None, 1), Some(1));
    assert_eq!(rate(Some(raw), 1), None);
    assert_eq!(rate(Some(raw), 2), Some(2));
    let paths = [path(inventory::Connector::HdmiTypeA, 0)];
    let enabled = frl_enabled();
    set_frl(true);
    let chosen = select(&paths, &[port(paths[0], None, edid)], 8, None);
    set_frl(enabled);
    let s = chosen.unwrap();
    assert_eq!(s.frl, FrlRate::new(2));
    let a = s.audio.unwrap();
    // AC-3 passes through beside LPCM; its 48-kHz six channels do not change
    // the reservation the 192-kHz eight-channel LPCM already sets.
    assert_eq!(a.mode_count, 2);
    assert_eq!(a.modes[0], raw.modes[0]);
    assert_eq!(a.modes[1], raw.modes[1]);
    assert_eq!(frl_audio(Some(a), t.v_active).max_rate_hz, 192_000);
    assert_eq!(frl_audio(Some(a), t.v_active).layout, 1);
    assert_eq!(
        frl_carries(&t, 8, false, s.frl.unwrap(), frl_audio(Some(a), t.v_active)),
        Some(crate::amdgpu_frl_cap::FrlCap::Ok {
            audio_packets_line: 2,
            borrow: crate::amdgpu_frl_cap::FrlBorrow::None,
        })
    );
    // A compressed-only sink remains usable as silent FRL video.
    let mut nonpcm = raw;
    nonpcm.modes[0] = raw.modes[1];
    nonpcm.mode_count = 1;
    assert_eq!(rate(Some(nonpcm), 1), Some(1));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_frl_selection_reserves_audio_bandwidth
);

fn navi48_mst_selection_keeps_only_remote_lpcm_that_fits() -> TestResult {
    use crate::dp_mst_mgr::Sink;
    // Stereo and 8ch LPCM at every sample rate, plus AC-3 (not exposed).
    const AUDIO: &[u8] = &[0x29, 0x09, 0x7f, 7, 0x0f, 0x7f, 7, 0x15, 7, 0x50];
    let caps = DpCaps {
        lanes: 4,
        rate: LinkRate::Hbr2,
        uhbr: 0,
        fec: false,
        dsc: None,
    };
    for blocks in [&[AUDIO][..], &[][..]] {
        for narrow in [false, true] {
            let mut base = edid_1080p();
            if narrow {
                // The remote sink offers a 32-pixel horizontal blank with
                // 8-pixel front porch/sync; its LPCM rates must be filtered.
                base[57] = 32;
                base[58] &= 0xf0;
                base[62] = 8;
                base[63] = 8;
                base[65] &= 0x0f;
            }
            let edid = with_blocks(base, blocks);
            let timing = edid_timings(&edid)[0];
            let devices = [(Sink { branch: 0, port: 1 }, edid.clone(), u16::MAX)];
            let s = super::super::select_mst(0, caps, &devices, &|_| Some(timing));
            assert_eq!(s.len(), 1);
            assert_eq!(s[0].timing, timing);
            let expected = sink_audio_info(&edid).and_then(|a| {
                otg::mst_audio_info(
                    a,
                    &timing,
                    8,
                    otg::DpPhySettings {
                        lanes: 4,
                        rate: LinkRate::Hbr2,
                        mst: true,
                    },
                )
            });
            assert_eq!(s[0].audio, expected);
            if !blocks.is_empty() {
                let a = s[0].audio.unwrap();
                let modes = &a.modes[..usize::from(a.mode_count)];
                // LPCM is required; compressed SADs pass through unfiltered.
                assert!(modes.iter().any(|m| m.format == 1));
                let raw = sink_audio_info(&edid).unwrap();
                for m in modes.iter().filter(|m| m.format != 1) {
                    assert!(raw.modes.contains(m));
                }
                if narrow {
                    let lpcm: Vec<_> = modes.iter().filter(|m| m.format == 1).collect();
                    assert!(lpcm.len() < 2 || lpcm[..2].iter().any(|m| m.rates != 0x7f));
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_mst_selection_keeps_only_remote_lpcm_that_fits
);

/// dp_verify_link_cap after the staged DSC/PPS fits no link that trains:
/// the rest of the 8b/10b ladder is trained without a stream, the first
/// setting that trains (else one RBR lane) bounds the sink's caps, and
/// selecting again computes new DSC geometry for that link, as Linux's
/// next detection and dc_dsc_compute_config do. The cap lasts while the same
/// sink stays on the port.
fn navi48_dsc_link_verification_reselects_compressed_geometry() -> TestResult {
    use crate::amdgpu_dsc::{compute_config, DscSinkCaps, LinkEncoding};
    use LinkRate::{Hbr, Hbr2, Hbr3, Rbr};
    const DSC: [u8; 16] = [
        1, 0x21, 0, 0x0b, 0x0b, 4, 1, 0, 0, 0x13, 0x0e, 0xee, 16, 0, 0, 0,
    ];
    let p = path(inventory::Connector::DisplayPort, 0);
    let sink = || display::Sink {
        dpcd: dpcd(0x1e, 2),
        edid: edid_uhbr(),
        lttpr: None,
        uhbr: 0,
        lttpr_uhbr: None,
        fec: true,
        dsc: Some(DSC),
        verified_link: None,
    };
    let ports = || {
        alloc::vec![display::Port {
            path: p,
            sink: Ok(sink()),
        }]
    };
    let first = select(&[p], &ports(), 8, None).unwrap();
    let wide = first.dsc.unwrap();
    assert_eq!((first.lanes, first.rate), (2, DpRate::Legacy(Hbr3)));
    // The highest bpp 2 x HBR3 carries: no slower link carries that PPS.
    let tried = selected_dp_candidates(&first);
    assert_eq!(tried, [(2, DpRate::Legacy(Hbr3))]);
    assert_eq!(
        verify_ladder(first.caps, &tried),
        [
            (2, Hbr2),
            (2, Hbr),
            (2, Rbr),
            (1, Hbr3),
            (1, Hbr2),
            (1, Hbr),
            (1, Rbr)
        ]
    );
    assert_eq!(verified_link(first.caps, Some((2, Hbr2))), Some((2, Hbr2)));
    assert_eq!(verified_link(first.caps, None), Some((1, Rbr)));
    let floor = DpCaps {
        lanes: 1,
        rate: Rbr,
        ..first.caps
    };
    assert_eq!(verified_link(floor, None), None, "no lower link to select");

    // The port keeps 2 x HBR2: selection compresses harder for it.
    let s = sink();
    let identity = VerifiedLink {
        path: p,
        dpcd: s.dpcd.unwrap(),
        edid: s.edid[..128].try_into().unwrap(),
        lanes: 2,
        rate: Hbr2,
    };
    let mut links = alloc::vec![identity];
    let mut scanned = ports();
    apply_verified_links(&mut links, &mut scanned);
    assert_eq!(links, [identity]);
    assert_eq!(
        scanned[0].sink.as_ref().unwrap().verified_link,
        Some((0x14, 2))
    );
    let again = select(&[p], &scanned, 8, None).unwrap();
    assert_eq!((again.caps.lanes, again.caps.rate), (2, Hbr2));
    assert_eq!((again.lanes, again.rate), (2, DpRate::Legacy(Hbr2)));
    let narrow = again.dsc.unwrap();
    let want = compute_config(
        &DscSinkCaps::parse(&DSC, &[0; 3]).unwrap(),
        NOMINAL_DISPCLK_KHZ,
        legacy_kbps(2, Hbr2, true) as u32,
        &dsc_timing(&again.timing),
        LinkEncoding::Dp8b10b,
        false,
    );
    assert_eq!(Some(narrow), want);
    assert!(narrow.bpp_x16 < wide.bpp_x16, "bpp was not lowered");
    assert_eq!(again.timing, first.timing);
    assert_eq!(selected_dp_candidates(&again)[0], (2, DpRate::Legacy(Hbr2)));
    // A verified link also removes 128b/132b.
    let mut uhbr = sink();
    uhbr.uhbr = 1;
    uhbr.verified_link = Some((0x14, 2));
    assert_eq!(dp_caps(&p, &uhbr).map(|c| (c.uhbr, c.lanes)), Some((0, 2)));

    // Another sink, a changed EDID, no answer or no sink: the cap is gone.
    for change in 0..4 {
        let mut links = alloc::vec![identity];
        let mut scanned = ports();
        match change {
            0 => scanned[0].sink.as_mut().unwrap().dpcd = dpcd(0x1e, 4),
            1 => scanned[0].sink.as_mut().unwrap().edid[8] ^= 1,
            2 => scanned[0].sink = Err(display::Error::Busy),
            _ => scanned.clear(),
        }
        apply_verified_links(&mut links, &mut scanned);
        assert!(links.is_empty());
        if let Some(Ok(s)) = scanned.first().map(|p| &p.sink) {
            assert_eq!(s.verified_link, None);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_dsc_link_verification_reselects_compressed_geometry
);

/// A two-pipe plan takes the highest pipe no display of the configuration
/// is on and no earlier ODM display took; one-pipe plans take none.
fn navi48_odm_plans_take_the_highest_free_pipes() -> TestResult {
    let one = completed_modeset(0).plan;
    let two = dml::Plan { pipes: 2, ..one };
    let got = |plans: &[dml::Plan], pipes: &[u8]| odm_pipes(plans, pipes).ok();
    if got(&[two], &[0]) != Some(alloc::vec![Some(3)])
        || got(&[two], &[3]) != Some(alloc::vec![Some(2)])
        || got(&[one, two, one], &[0, 3, 1]) != Some(alloc::vec![None, Some(2), None])
        || got(&[one, two, two], &[0, 3, 1]).is_some()
        || got(&[two, two], &[0, 2]) != Some(alloc::vec![Some(3), Some(1)])
        || got(&[one, one], &[0, 1]) != Some(alloc::vec![None, None])
    {
        return TestResult::Fail("ODM pipe allocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_odm_plans_take_the_highest_free_pipes
);

/// An MST branch that codes 128b/132b trains at its verified cap, the best
/// UHBR rate on every lane (decide_mst_link_settings, then
/// mst_decide_link_encoding_format): each 2160p60 stream takes 12 of the
/// link's 64 slots (dm_mst_get_pbn_divider at 4 x UHBR20), its source rate
/// is the HPO one, and its LPCM is filtered as Linux budgets 128b/132b SST
/// (the whole link, the timing's blank). The same branch without UHBR fits
/// one such stream on 4 x HBR2.
fn navi48_mst_selection_trains_uhbr_when_the_branch_codes_it() -> TestResult {
    use crate::dp_mst_mgr::Sink;
    let mut caps = DpCaps {
        lanes: 4,
        rate: LinkRate::Hbr2,
        uhbr: 0b101,
        fec: false,
        dsc: None,
    };
    // Stereo and 8ch LPCM at every sample rate.
    const AUDIO: &[u8] = &[0x26, 0x09, 0x7f, 7, 0x0f, 0x7f, 7];
    let edid = with_blocks(edid_2160p(), &[AUDIO]);
    let devices = [
        (Sink { branch: 0, port: 1 }, edid.clone(), u16::MAX),
        (Sink { branch: 0, port: 2 }, edid.clone(), u16::MAX),
    ];
    let s = super::super::select_mst(0, caps, &devices, &|_| None);
    let settings = otg::UhbrSettings {
        lanes: 4,
        rate: otg::UhbrRate::Uhbr20,
        mst: true,
    };
    let (vc, _) = otg::uhbr_mst_rate(&s[0].timing, 8, settings).unwrap();
    let audio =
        sink_audio_info(&edid).and_then(|a| otg::uhbr_audio_info(a, &s[0].timing, 8, settings));
    if s.len() != 2
        || s.iter().any(|s| {
            s.rate != DpRate::Uhbr(otg::UhbrRate::Uhbr20)
                || s.lanes != 4
                || s.timing.h_active != 3840
                || audio.is_none()
                || s.audio != audio
                || s.mst.map(|m| (m.slots, m.rate)) != Some((12, (vc >> 25, vc & 0x1ff_ffff)))
        })
    {
        panic!("UHBR MST selections {s:?}");
    }
    // 64 slots: five such streams would fit the link, as 63 would not.
    let t = s[0].timing;
    let slots = super::super::mst::mst_slots(&t, 4, s[0].rate, false)
        .unwrap()
        .1;
    if super::super::mst::mst_total_slots(s[0].rate) != 64 || slots * 5 > 64 {
        return TestResult::Fail("UHBR MST slot budget");
    }
    caps.uhbr = 0;
    let legacy = super::super::select_mst(0, caps, &devices, &|_| None);
    if legacy.iter().filter(|s| s.timing.h_active == 3840).count() != 1
        || legacy
            .iter()
            .any(|s| s.rate != DpRate::Legacy(LinkRate::Hbr2))
    {
        panic!("8b/10b MST selections {legacy:?}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_mst_selection_trains_uhbr_when_the_branch_codes_it
);

/// A 1080p60 EDID 1.4 with continuous frequency and a 48-75 Hz "range
/// limits only" descriptor.
fn edid_vrr_48_75() -> Vec<u8> {
    let mut e = edid_1080p();
    e[24] |= 1;
    e[90..108].copy_from_slice(&[0, 0, 0, 0xfd, 0, 48, 75, 30, 90, 17, 1, 0, 0, 0, 0, 0, 0, 0]);
    e[127] = 0;
    e[127] = narf_edid::compute_checksum(&e);
    e
}

/// amdgpu_dm_update_freesync_caps on the selected DP SST sink: the EDID
/// range when DPCD 0x007 bit 6 allows invalid MSA timing; the mode is then
/// vrr_supported and VRR_ENABLED runs it at mod_freesync's totals (1125 to
/// ceil(1406.25) = 1407 for 48 Hz). HDMI sinks are not VRR-capable here.
fn navi48_modeset_dp_selection_carries_the_freesync_range() -> TestResult {
    use inventory::Connector::{DisplayPort as Dp, HdmiTypeA as Hdmi};
    let p = path(Dp, 0);
    let mut caps = dpcd(0x14, 4);
    let s = select(&[p], &[port(p, caps, edid_vrr_48_75())], 8, None).unwrap();
    if s.vrr.is_some() || s.vrr_supported() || s.drr().is_some() {
        return TestResult::Fail("MSA_TIMING_PAR_IGNORED clear");
    }
    caps.as_mut().unwrap()[7] = 0x40;
    let s = select(&[p], &[port(p, caps, edid_vrr_48_75())], 8, None).unwrap();
    let range = crate::amdgpu_freesync::VrrRange {
        min_hz: 48,
        max_hz: 75,
    };
    if s.vrr != Some(range)
        || !s.vrr_supported()
        || s.drr()
            != Some(crate::amdgpu_freesync::Drr {
                v_total_min: 1125,
                v_total_max: 1407,
            })
    {
        return TestResult::Fail("capable DP sink");
    }
    // A sink without the range descriptor is not capable either.
    let s = select(&[p], &[port(p, caps, edid_1080p())], 8, None).unwrap();
    if s.vrr.is_some() {
        return TestResult::Fail("no range");
    }
    // A mode outside the range keeps the sink capable but the mode fixed.
    let mut outside = s;
    outside.vrr = Some(crate::amdgpu_freesync::VrrRange {
        min_hz: 61,
        max_hz: 144,
    });
    if outside.vrr_supported() || outside.drr().is_some() {
        return TestResult::Fail("mode outside the range");
    }
    let h = path(Hdmi, 1);
    let hdmi = select(
        &[h],
        &[port(h, None, with_cta(edid_vrr_48_75(), true))],
        8,
        None,
    );
    if hdmi.map(|s| s.vrr) != Ok(None) {
        return TestResult::Fail("HDMI");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_dp_selection_carries_the_freesync_range
);

/// DSC 1.2 decoder caps: slices 1/2/4, 13-bit line buffer, RGB, 8/10/12
/// bpc, 1000 MP/s per slice, 5120-pixel slices, 1/16 bpp.
const UHBR_DSC: [u8; 16] = [
    1, 0x21, 0, 0x0b, 0x0b, 4, 1, 0, 0, 0x13, 0x0e, 0xee, 16, 0, 0, 0,
];
/// CVT-RB2-like timings past one 4 x UHBR10 link uncompressed.
fn big_timing(khz: u32, h_active: u32, v_active: u32, v_total: u32) -> Timing {
    Timing {
        pixel_clock_khz: khz,
        h_active,
        h_total: h_active + 80,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active,
        v_total,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: false,
    }
}
fn uhd8k60() -> Timing {
    big_timing(2_039_793, 7680, 4320, 4381)
}
fn uhd240() -> Timing {
    big_timing(2_151_590, 3840, 2160, 2287)
}
fn uhd144() -> Timing {
    big_timing(1_254_282, 3840, 2160, 2222)
}

/// DSC over 128b/132b as amdgpu_dm's SST policy and dc pick it. The DSC
/// target is dc_link_bandwidth_kbps at the sink's maximum link
/// (dc_link_get_link_cap): 4 x UHBR10 on a UHBR10 sink, so the 128b/132b
/// encoding (its padded uncompressed stream decides whether DSC is
/// needed), not 4 x HBR3 with FEC. Uncompressed UHBR wins whenever any
/// rate the sink reaches carries the mode (8K60 and 4K240 run uncompressed
/// on 4 x UHBR13.5). The compressed stream then takes the lowest setting
/// upward its bandwidth needs. Configurations, compressed bandwidths and
/// link targets match Linux's dc_dsc_compute_config built on the host
/// (tests/dcn401_dsc harness): 8K60 4 slices at 16 bpp, 32,905,857 kbps;
/// 4K240 4 slices at 16 bpp, 34,987,489 kbps; 4K144 on two UHBR10 lanes
/// 2 slices at 243/16 bpp, 19,213,233 kbps; 8K60 on 4 x HBR3 with FEC 4
/// slices at 195/16 bpp, 25,129,147 kbps (two DSCs under ODM 2:1).
fn navi48_modeset_decides_uhbr_dsc_like_linux() -> TestResult {
    use crate::amdgpu_dsc::{compute_config, dsc_kbps, DscSinkCaps, LinkEncoding};
    use otg::UhbrRate::{Uhbr10 as U10, Uhbr13_5 as U13, Uhbr20 as U20};
    use DpRate::{Legacy, Uhbr};
    let sink = DscSinkCaps::parse(&UHBR_DSC, &[0; 3]).unwrap();
    let caps = |lanes: u8, uhbr: u8, fec: bool, dsc: bool| DpCaps {
        lanes,
        rate: LinkRate::Hbr3,
        uhbr,
        fec,
        dsc: dsc.then_some(sink),
    };
    // (timing, caps, link, Some((slices, bpp_x16, kbps, target)) for DSC).
    type Want = Option<(u32, u32, u32, u64, LinkEncoding)>;
    type Case = (Timing, DpCaps, Option<(u8, DpRate)>, Want);
    let cases: [Case; 11] = [
        (
            uhd8k60(),
            caps(4, 0b001, true, true),
            Some((4, Uhbr(U10))),
            Some((4, 256, 32_905_857, 38_564_000, LinkEncoding::Dp128b132b)),
        ),
        (
            uhd8k60(),
            caps(4, 0b011, true, true),
            Some((4, Uhbr(U13))),
            None,
        ),
        (
            uhd8k60(),
            caps(4, 0b101, true, true),
            Some((4, Uhbr(U20))),
            None,
        ),
        (
            uhd240(),
            caps(4, 0b001, true, true),
            Some((4, Uhbr(U10))),
            Some((4, 256, 34_987_489, 38_564_000, LinkEncoding::Dp128b132b)),
        ),
        (
            uhd240(),
            caps(4, 0b111, true, true),
            Some((4, Uhbr(U13))),
            None,
        ),
        (
            uhd144(),
            caps(2, 0b001, true, true),
            Some((2, Uhbr(U10))),
            Some((2, 243, 19_213_233, 19_282_000, LinkEncoding::Dp128b132b)),
        ),
        (
            uhd144(),
            caps(4, 0b001, true, true),
            Some((4, Uhbr(U10))),
            None,
        ),
        // FEC is inherent in 128b/132b: no 8b/10b FEC cap is needed.
        (
            uhd8k60(),
            caps(4, 0b001, false, true),
            Some((4, Uhbr(U10))),
            Some((4, 256, 32_905_857, 38_564_000, LinkEncoding::Dp128b132b)),
        ),
        // An 8b/10b-only sink compresses for 4 x HBR3 with FEC; 8K takes
        // two DSCs (ODM 2:1, two slices each).
        (
            uhd8k60(),
            caps(4, 0, true, true),
            Some((4, Legacy(LinkRate::Hbr3))),
            Some((4, 195, 25_129_147, 25_142_400, LinkEncoding::Dp8b10b)),
        ),
        // No DSC decoder, or 8b/10b DSC without FEC: no link.
        (uhd8k60(), caps(4, 0b001, true, false), None, None),
        (uhd8k60(), caps(4, 0, false, true), None, None),
    ];
    for (i, (t, c, link, want)) in cases.into_iter().enumerate() {
        let uncompressed = dp_link(&t, c);
        let cfg = dp_dsc(&t, c, NOMINAL_DISPCLK_KHZ);
        let got = uncompressed.or_else(|| cfg.and_then(|cfg| dsc_link(&t, cfg, c)));
        assert_eq!(got, link, "case {i}: link");
        let Some((slices, bpp, kbps, target, encoding)) = want else {
            assert!(uncompressed.is_some() || got.is_none(), "case {i}: DSC");
            continue;
        };
        assert!(uncompressed.is_none(), "case {i}: carried uncompressed");
        let cfg = cfg.unwrap();
        let linux = compute_config(
            &sink,
            NOMINAL_DISPCLK_KHZ,
            target as u32,
            &dsc_timing(&t),
            encoding,
            false,
        );
        assert_eq!(Some(cfg), linux, "case {i}: dc_dsc_compute_config");
        assert_eq!((cfg.slices_h, cfg.bpp_x16), (slices, bpp), "case {i}");
        assert_eq!(dsc_kbps(&dsc_timing(&t), cfg.bpp_x16, cfg.slices_h), kbps);
        // The admission shape: the DSCs DML gives the stream.
        let pipes = dml::dsc_pipes(&t, cfg.slices_h, NOMINAL_DISPCLK_KHZ);
        assert_eq!(
            pipes,
            if t.h_active > 5760 || t.pixel_clock_khz > 1_992_428 {
                2
            } else {
                1
            }
        );
    }
    // A UHBR sink never compresses onto 8b/10b: 16 bpp is two thirds of
    // 24, and 8b/10b with FEC at any lane count carries less than two
    // thirds of UHBR10 at that count. Sweep 4K and 8K pixel clocks.
    for lanes in [1, 2, 4] {
        for h_active in [3840, 7680] {
            for khz in (300_000..2_600_000).step_by(25_000) {
                let t = big_timing(khz, h_active, 2160, 2222);
                let c = caps(lanes, 0b111, true, true);
                if dp_link(&t, c).is_some() {
                    continue;
                }
                if let Some(cfg) = dp_dsc(&t, c, NOMINAL_DISPCLK_KHZ) {
                    match dsc_link(&t, cfg, c) {
                        Some((_, Uhbr(_))) => {}
                        other => panic!("{lanes} lanes {h_active} at {khz}: {other:?}"),
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_decides_uhbr_dsc_like_linux
);

/// A one-lane UHBR10 sink (DSC decoder, board connector at UHBR10) and its
/// EDID's 4K60 (14,256,000 kbps): neither 1 x HBR3 nor 1 x UHBR10
/// (9,641,000 kbps) carries it, so select compresses it for 1 x UHBR10,
/// on 1 x UHBR10, through HPO, without audio. refine_dsc redoes it with
/// the board's DISPCLK, admission takes it, the timing request is HPO DP
/// with the DSC, and fallback keeps the PPS: Linux's table through the
/// 128b/132b settings that carry the compressed stream.
fn navi48_modeset_selects_dsc_over_uhbr() -> TestResult {
    use crate::amdgpu_dsc::{compute_config, DscSinkCaps, LinkEncoding};
    use otg::UhbrRate::{Uhbr10 as U10, Uhbr13_5 as U13, Uhbr20 as U20};
    use DpRate::Uhbr;
    let mut p = path(inventory::Connector::DisplayPort, 0);
    p.max_speed_mhz = 10_000;
    let sink = display::Sink {
        dpcd: dpcd(0x1e, 1),
        edid: edid_uhbr(),
        lttpr: None,
        uhbr: 1,
        lttpr_uhbr: None,
        fec: true,
        dsc: Some(UHBR_DSC),
        verified_link: None,
    };
    let port = display::Port {
        path: p,
        sink: Ok(sink),
    };
    let mut s = match select(&[p], &[port], 8, None) {
        Ok(s) => s,
        Err(e) => panic!("UHBR DSC selection {e:?}"),
    };
    let want = compute_config(
        &DscSinkCaps::parse(&UHBR_DSC, &[0; 3]).unwrap(),
        NOMINAL_DISPCLK_KHZ,
        9_641_000,
        &dsc_timing(&s.timing),
        LinkEncoding::Dp128b132b,
        false,
    );
    if !s.uhbr()
        || (s.lanes, s.rate) != (1, Uhbr(U10))
        || s.dsc.is_none()
        || s.dsc != want
        || s.audio.is_some()
        || s.timing.pixel_clock_khz != 594_000
    {
        panic!("UHBR DSC selection {s:?}");
    }
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [500_000, 2_000_000],
        dcfclk_khz: [300_000, 1_200_000],
        socclk_khz: 600_000,
        dispclk_max_khz: 1_500_000,
        dppclk_max_khz: 1_500_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let selected = s;
    refine_dsc(&soc, core::slice::from_mut(&mut s)).unwrap();
    if (s.lanes, s.rate) != (1, Uhbr(U10)) || s.dsc.is_none() {
        return TestResult::Fail("refined UHBR DSC");
    }
    let plans = match admit_displays(&soc, &[s]) {
        Ok(p) => p,
        Err(e) => panic!("UHBR DSC admission {e:?}"),
    };
    let request = timing_request(0, &plans[0], &s);
    if request.signal != otg::Signal::HpoDisplayPort || request.dsc != s.dsc {
        return TestResult::Fail("HPO timing request");
    }
    assert_eq!(selected_dp_candidates(&s), [(1, Uhbr(U10))]);
    // From a 4 x UHBR20 setting the compressed stream fits every
    // 128b/132b row of Linux's table; uncompressed, the one-lane rows
    // below UHBR20 would not.
    let wide = Selection {
        lanes: 4,
        rate: Uhbr(U20),
        caps: DpCaps {
            lanes: 4,
            uhbr: 0b111,
            ..s.caps
        },
        ..selected
    };
    let ladder = selected_dp_candidates(&wide);
    assert_eq!(
        ladder,
        [
            (4, Uhbr(U20)),
            (4, Uhbr(U13)),
            (2, Uhbr(U20)),
            (4, Uhbr(U10)),
            (2, Uhbr(U13)),
            (1, Uhbr(U20)),
            (2, Uhbr(U10)),
            (1, Uhbr(U13)),
            (1, Uhbr(U10)),
        ]
    );
    assert!(!dp_candidates(&wide.timing, wide.caps, 4, Uhbr(U20)).contains(&(1, Uhbr(U13))));
    // Alternatives are offered with their own DSC for the same maximum
    // link: 4K90 compresses harder.
    let offered = dp_offered_mode(s.timing, &s, soc.dispclk_max_khz).and_then(|m| m.dsc);
    let faster = Timing {
        pixel_clock_khz: 891_000,
        ..s.timing
    };
    let harder = dp_offered_mode(faster, &s, soc.dispclk_max_khz).and_then(|m| m.dsc);
    match (offered, harder) {
        (Some(a), Some(b)) if b.bpp_x16 < a.bpp_x16 => {}
        other => panic!("offered DSC {other:?}"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_selects_dsc_over_uhbr
);
