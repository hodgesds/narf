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
        crtc: pipe,
        plan,
        scanout: otg::ScanoutRunning {
            pipe,
            odm: otg::SplitPipes::NONE,
            mpc: otg::SplitPipes::NONE,
            stream: pipe,
            plan,
            address: 0x8_0000_0000 + u64::from(pipe) * 0x1000000,
            overlays: [None; crate::amdgpu_dcn401_otg::MAX_OVERLAYS],
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
    // Modeset records are large: keep them on the heap (the aarch64
    // kernel-test stack is 64 KiB).
    for during_startup in [false, true] {
        let first = alloc::boxed::Box::new(completed_modeset(0));
        let second = alloc::boxed::Box::new(completed_modeset(2));
        let mut retained = alloc::boxed::Box::new(RetainedModesets::new());
        let mut journal = super::super::teardown::Teardowns::new();
        {
            let mut future = alloc::boxed::Box::pin(async {
                // A caller's temporary configuration disappears on cancellation.
                let mut local = Vec::new();
                for m in [&first, &second] {
                    retained.retain(**m);
                    local.push(alloc::boxed::Box::new(**m));
                }
                if during_startup {
                    journal
                        .begin_activation(3, otg::SplitPipes::NONE, &second.selection)
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
        let mut recovered: alloc::boxed::Box<[Option<Modeset>; 4]> =
            alloc::boxed::Box::new([None; 4]);
        assert_eq!(retained.restore(&mut recovered), Ok(0b0101));
        assert!(recovered[0] == Some(*first) && recovered[1].is_none());
        assert!(recovered[2] == Some(*second) && recovered[3].is_none());
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
        let mut again: alloc::boxed::Box<[Option<Modeset>; 4]> = alloc::boxed::Box::new([None; 4]);
        assert_eq!(retained.restore(&mut again), Ok(0b0100));
        assert!(again[2] == Some(*second));
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
    // Modeset records are large: keep them on the heap (the aarch64
    // kernel-test stack is 64 KiB).
    let first = alloc::boxed::Box::new(completed_modeset(0));
    let last = alloc::boxed::Box::new(completed_modeset(3));
    let mut retained = alloc::boxed::Box::new(RetainedModesets::new());
    retained.retain(*first);
    retained.retain(*last);
    let mut old = last.clone();
    old.scanout.address += 4096;
    let mut caller: alloc::boxed::Box<[Option<Modeset>; 4]> = alloc::boxed::Box::new([None; 4]);
    caller[3] = Some(*old);
    let before = caller.clone();
    assert_eq!(retained.restore(&mut caller), Err(otg::Error::Busy.into()));
    assert_eq!(
        caller, before,
        "partially restored before detecting a conflict"
    );
    // Updated admission and retraining witnesses replace the retained record.
    let mut updated = last.clone();
    updated.modes[0] = Some(last.selection.timing);
    updated.scanout.frame_before = 10;
    updated.scanout.frame_after = 11;
    retained.retain(*updated);
    *caller = [None; 4];
    assert_eq!(retained.restore(&mut caller), Ok(0b1001));
    assert_eq!(caller[3], Some(*updated));
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
            dprx_feature: 0,
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

/// Each plane format's admission shape: its bytes per pixel and a pitch of
/// whole 256-byte requests (128, 64 or 32 pixels), the selection's plane
/// format, and the per-pipe format a lighting takes (XRGB8888 by default).
fn navi48_modeset_admits_the_plane_format_of_each_pipe() -> TestResult {
    use otg::SurfaceFormat as F;
    let paths = [path(inventory::Connector::DisplayPort, 0)];
    let ports = [port(paths[0], dpcd(0x14, 4), edid_1080p())];
    let Ok(mut s) = select(&paths, &ports, 8, None) else {
        return TestResult::Fail("sink rejected");
    };
    if s.format != F::Xrgb8888 || selection_mode(&s) != mode(s.timing) {
        return TestResult::Fail("default plane");
    }
    let mut odd = s.timing;
    odd.h_active = 1366;
    for (format, bytes, pitch, odd_pitch) in [
        (F::Rgb565, 2, 1920, 1408),
        (F::Xbgr2101010, 4, 1920, 1408),
        (F::Abgr16161616f, 8, 1920, 1376),
    ] {
        s.format = format;
        let m = selection_mode(&s);
        if m.bytes_per_pixel != bytes
            || m.pitch != pitch
            || plane_mode(odd, format).pitch != odd_pitch
            || (dml::Mode {
                bytes_per_pixel: 4,
                pitch: 1920,
                ..m
            }) != mode(s.timing)
        {
            return TestResult::Fail("plane admission shape");
        }
    }
    let before = plane_format(2);
    set_plane_format(2, F::Argb16161616f);
    set_plane_format(7, F::Rgb565);
    let (two, three) = (plane_format(2), plane_format(3));
    set_plane_format(2, before);
    if two != F::Argb16161616f || three != F::Xrgb8888 || plane_format(9) != F::Xrgb8888 {
        return TestResult::Fail("per-pipe plane format");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_admits_the_plane_format_of_each_pipe
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
    // A slow board carries 1080p60 but not 2160p240 beside it: the second
    // display stays dark; alone, the 2160p240 one is refused outright.
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
    // 2160p120 takes a 3:1 ODM split of the 500-MHz DISPCLK: with the
    // 1080p60 display beside it, all four pipes.
    match admit_displays(&soc, &[all[0], fast]) {
        Ok(plans) if plans.len() == 2 && plans[1].pipes == 3 && plans[0].pipes == 1 => {}
        _ => return TestResult::Fail("3:1 stream beside a single-pipe one"),
    }
    // 2160p240 would need more than four pipes' DISPCLK.
    fast.timing.pixel_clock_khz = 2_376_000;
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
            dprx_feature: 0,
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
        || !dp_fits_bpc(&timing(698_400, 3840), fec, 4, Legacy(LinkRate::Hbr2), 8)
        || dp_fits_bpc(&timing(698_401, 3840), fec, 4, Legacy(LinkRate::Hbr2), 8)
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
        dprx_feature: 0,
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
        dprx_feature: 0,
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
        &|_, _| { u16::MAX }
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
    let budget = |_, selected: &[(crate::dp_mst_mgr::Sink, u16)]| {
        900u16.saturating_sub(selected.iter().map(|a| a.1).sum())
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
            hc_active: 0,
            hc_blank: 0,
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
        dprx_feature: 0,
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
        &dsc_timing(&again.timing, 8),
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

/// A configuration lit with no display running, as DC acquires its pipes:
/// every stream's OTG master first, in CRTC order, the lowest free pipe
/// (whatever the CRTC's index), then each n-pipe plan's n - 1 further OPP
/// heads, the lowest pipes still free, left to right in that order;
/// one-pipe plans take none, and a configuration short of pipes is refused.
/// (Linux's acquire_otg_master_pipe_for_stream and dcn32_acquire_free_pipe_
/// as_secondary_opp_head take pipes from the bottom; NARF used to take ODM
/// pipes from the top.)
fn navi48_odm_plans_take_pipes_as_dc_acquires_them() -> TestResult {
    let one = completed_modeset(0).plan;
    let two = dml::Plan { pipes: 2, ..one };
    let three = dml::Plan { pipes: 3, ..one };
    let four = dml::Plan { pipes: 4, ..one };
    let s = |p: &[u8]| otg::SplitPipes::new(p).unwrap();
    let none = otg::SplitPipes::NONE;
    let got = |plans: &[dml::Plan], crtcs: &[u8]| {
        plan_pipes(plans, crtcs)
            .ok()
            .map(|d| d.iter().map(|&(head, d)| (head, d.odm)).collect::<Vec<_>>())
    };
    if got(&[two], &[0]) != Some(alloc::vec![(0, s(&[1]))])
        || got(&[two], &[3]) != Some(alloc::vec![(0, s(&[1]))])
        || got(&[one, two, one], &[0, 1, 3])
            != Some(alloc::vec![(0, none), (1, s(&[3])), (2, none)])
        || got(&[one, two, two], &[0, 1, 3]).is_some()
        || got(&[two, two], &[0, 2]) != Some(alloc::vec![(0, s(&[2])), (1, s(&[3]))])
        || got(&[one, one], &[0, 1]) != Some(alloc::vec![(0, none), (1, none)])
        || got(&[three], &[0]) != Some(alloc::vec![(0, s(&[1, 2]))])
        || got(&[four], &[1]) != Some(alloc::vec![(0, s(&[1, 2, 3]))])
        || got(&[three, one], &[0, 1]) != Some(alloc::vec![(0, s(&[2, 3])), (1, none)])
        || got(&[one, three], &[0, 2]) != Some(alloc::vec![(0, none), (1, s(&[2, 3]))])
        || got(&[four, one], &[0, 1]).is_some()
        || got(&[three, two], &[0, 1]).is_some()
    {
        return TestResult::Fail("ODM pipe allocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_odm_plans_take_pipes_as_dc_acquires_them
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
    let slots = super::super::mst::mst_slots(&t, 8, 4, s[0].rate, false)
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
        let cfg = dp_dsc(&t, c, NOMINAL_DISPCLK_KHZ, 8);
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
            &dsc_timing(&t, 8),
            encoding,
            false,
        );
        assert_eq!(Some(cfg), linux, "case {i}: dc_dsc_compute_config");
        assert_eq!((cfg.slices_h, cfg.bpp_x16), (slices, bpp), "case {i}");
        assert_eq!(
            dsc_kbps(&dsc_timing(&t, 8), cfg.bpp_x16, cfg.slices_h),
            kbps
        );
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
                if let Some(cfg) = dp_dsc(&t, c, NOMINAL_DISPCLK_KHZ, 8) {
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

const DEPTH_VECTORS: &str = include_str!("../tests/dcn401_dsc/depth_vectors.txt");

/// An EDID 1.4 base block whose digital input declares `bpc` (0:
/// undefined), for `dp_depths`.
fn edid_with_bpc(bpc: u8) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[18] = 1;
    e[19] = 4;
    let code = match bpc {
        6 => 1,
        8 => 2,
        10 => 3,
        12 => 4,
        14 => 5,
        16 => 6,
        _ => 0,
    };
    e[20] = 0x80 | code << 4;
    e
}

/// One depth_vectors.txt line through `dp_sst_stream`, printed as
/// depth_harness.c prints Linux's choice.
fn run_depth_vector(input: &str) -> Option<alloc::string::String> {
    use core::fmt::Write;
    let w: Vec<&str> = input.split_whitespace().collect();
    let mut dpcd = [0u8; 16];
    for (i, b) in dpcd.iter_mut().enumerate() {
        *b = u8::from_str_radix(w.first()?.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    let n: Vec<u32> = w[1..]
        .iter()
        .map(|v| v.parse().ok())
        .collect::<Option<_>>()?;
    let (dispclk, pix, ha, ht, va, vt) = (n[0], n[1], n[2], n[3], n[4], n[5]);
    let (edid_bpc, requested, lanes, rate) = (n[6] as u8, n[7] as u8, n[8] as u8, n[9]);
    let t = Timing {
        pixel_clock_khz: pix / 10,
        h_active: ha,
        h_total: ht,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: va,
        v_total: vt,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: false,
    };
    // The sink's maximum link: an 8b/10b rate with FEC, or 128b/132b up
    // to the given UHBR rate (the HBR3 8b/10b link below it).
    let (legacy, uhbr) = match rate {
        1000 => (LinkRate::Hbr3, 0b001),
        1350 => (LinkRate::Hbr3, 0b011),
        2000 => (LinkRate::Hbr3, 0b111),
        r => (LinkRate::from_dpcd_byte(r as u8)?, 0),
    };
    let caps = DpCaps {
        lanes,
        rate: legacy,
        uhbr,
        fec: true,
        dsc: crate::amdgpu_dsc::DscSinkCaps::parse(&dpcd, &[0; 3]),
    };
    let depths = dp_depths(&edid_with_bpc(edid_bpc), requested);
    let mut out = alloc::string::String::new();
    match dp_sst_stream(&t, caps, &depths, dispclk) {
        None => out.push_str("FAIL"),
        Some(s) => {
            let bpc = depth_bpc(s.depth);
            match s.dsc {
                None => write!(out, "{bpc} -").ok()?,
                Some(c) => write!(
                    out,
                    "{bpc} {} {} {} {}",
                    c.slices_h,
                    c.slices_v,
                    c.bpp_x16,
                    crate::amdgpu_dsc::dsc_kbps(&dsc_timing(&t, c.bpc), c.bpp_x16, c.slices_h)
                )
                .ok()?,
            }
            if s.dsc.is_some_and(|c| c.bpc != bpc) {
                return None;
            }
        }
    }
    Some(out)
}

/// Every depth_vectors.txt line: amdgpu_dm_create_validate_stream_for_sink's
/// DP SST depth search as Linux built on the host runs it (depth_harness.c:
/// the requested and EDID depths, uncompressed or DSC at each, the first
/// that fits the maximum link), through `dp_sst_stream` and `dp_depths`.
fn navi48_dp_sst_depth_search_matches_linux_vectors() -> TestResult {
    let mut checked = 0;
    for line in DEPTH_VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("malformed depth vector");
        };
        match run_depth_vector(input) {
            Some(got) if got == want => checked += 1,
            Some(got) => panic!("depth vector {input}\n want {want}\n  got {got}"),
            None => return TestResult::Fail("depth vector input"),
        }
    }
    if checked < 1000 {
        return TestResult::Fail("too few depth vectors");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_dp_sst_depth_search_matches_linux_vectors
);

/// A one-lane UHBR10 sink (DSC decoder, board connector at UHBR10) and its
/// EDID's 4K60 (14,256,000 kbps): neither 1 x HBR3 nor 1 x UHBR10
/// (9,641,000 kbps) carries it, so select compresses it for 1 x UHBR10,
/// on 1 x UHBR10, through HPO, with its LPCM budgeted at the compressed
/// bits per pixel (build_audio_output's dsc_cfg). refine_dsc redoes it with
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
        dprx_feature: 0,
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
        &dsc_timing(&s.timing, 8),
        LinkEncoding::Dp128b132b,
        false,
    );
    if !s.uhbr()
        || (s.lanes, s.rate) != (1, Uhbr(U10))
        || s.dsc.is_none()
        || s.dsc != want
        || s.timing.pixel_clock_khz != 594_000
    {
        panic!("UHBR DSC selection {s:?}");
    }
    let settings = otg::UhbrSettings {
        lanes: 1,
        rate: U10,
        mst: false,
    };
    let audio = sink_audio_info(&edid_uhbr())
        .and_then(|a| otg::uhbr_audio_info_with(a, &s.timing, 8, settings, s.dsc.as_ref()));
    if audio.is_none() || s.audio != audio {
        panic!("UHBR DSC audio {:?} want {audio:?}", s.audio);
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

/// A selection's output color space, blank request and HDR packet follow
/// amdgpu_dm_get_output_color_space and amdgpu_dm_fill_hdr_info_packet;
/// the DP sink's VSC colorimetry follows its DPCD revision and DPRX bit.
fn navi48_selection_maps_colorspace_and_hdr_like_amdgpu_dm() -> TestResult {
    use crate::amdgpu_hdr::DcColorSpace as C;
    let s = limited_bpp_dsc_selection();
    if s.colorspace != 0 || s.hdr.is_some() || s.hdr_packet().is_some() {
        return TestResult::Fail("defaults");
    }
    for (colorspace, limited, ycbcr420, cs) in [
        (0, false, false, C::Srgb),
        (0, true, false, C::SrgbLimited),
        (0, false, true, C::Ycbcr709),
        (9, false, false, C::Rgb2020Full),
        (9, true, false, C::Rgb2020Limited),
        (10, false, true, C::Ycbcr2020Limited),
        (7, false, false, C::AdobeRgb),
        (2, false, false, C::Ycbcr709),
    ] {
        let sel = Selection {
            colorspace,
            limited,
            ycbcr420,
            ..s
        };
        let b = sel.blank_request(2);
        if sel.color_space() != cs
            || b.colorspace != cs
            || b.limited != matches!(cs, C::SrgbLimited | C::Rgb2020Limited)
            || b.ycbcr420 != ycbcr420
        {
            return TestResult::Fail("output color space");
        }
    }
    let mut blob = [0u8; 32];
    blob[4] = 2;
    let meta = crate::amdgpu_hdr::HdrOutputMetadata::from_blob(&blob).unwrap();
    let dp = Selection {
        hdr: Some(meta),
        ..s
    };
    let hdmi = Selection { hdmi: true, ..dp };
    if dp.hdr_packet().map(|p| p.hb) != Some([0, 0x87, 0x1d, 0x4c])
        || hdmi.hdr_packet().map(|p| p.hb) != Some([0x87, 1, 0x1a, 0])
    {
        return TestResult::Fail("HDR packet type");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_selection_maps_colorspace_and_hdr_like_amdgpu_dm
);

/// DRM's planes reach DML and staging as DC hands them over: the scaled
/// primary's and each overlay's surface request (layout on the stream,
/// format, pipe) and, from them, the admission mode's plane list (SPL's
/// viewport, ratios and taps). The full-frame primary alone keeps the
/// single-plane mode. Overlays take free pipes from the top (one per
/// segment of an ODM stream); a configuration short of pipes is refused.
fn navi48_planes_reach_admission_and_staging() -> TestResult {
    use crate::amdgpu_dcn401_spl::{Rect, Rotation};
    let base = completed_modeset(0).selection;
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let geometry = |w: u32, h: u32, dst: Rect, format: otg::SurfaceFormat| PlaneGeometry {
        src_x: 0,
        src_y: 0,
        width: w,
        height: h,
        dst,
        rotation: Rotation::R0,
        blend: otg::Blend::default_for(format),
        surface: otg::PlaneSurface::LINEAR,
        fb_size: (w, h),
        client: false,
    };
    let video = OverlayPlane {
        geometry: geometry(
            1280,
            720,
            Rect::new(100, 100, 640, 360),
            otg::SurfaceFormat::Argb8888,
        ),
        format: otg::SurfaceFormat::Argb8888,
        underlay: false,
        plane: 0,
    };
    let s = Selection {
        planes: PlaneSetup {
            primary: Some(geometry(
                1280,
                720,
                Rect::new(0, 0, 1920, 1080),
                base.format,
            )),
            overlays: [Some(video), None, None],
        },
        ..base
    };
    let pp = |pipe: u8, odm: &[u8]| {
        Some(PlanePipes {
            pipe,
            odm: otg::SplitPipes::new(odm).unwrap(),
            mpc: otg::SplitPipes::NONE,
        })
    };
    let on3 = DisplayPipes {
        overlays: [pp(3, &[]), None, None],
        ..DisplayPipes::default()
    };
    let (primary, overlays) = plane_requests(&s, 0, &on3);
    let Some(overlay) = overlays[0] else {
        return TestResult::Fail("overlay request");
    };
    let full = Rect::new(0, 0, 1920, 1080);
    if (primary.width, primary.height) != (1280, 720)
        || primary.plane.map(|l| (l.dst, l.stream_width, l.underlay)) != Some((full, 1920, false))
        || (overlay.pipe, overlay.odm, overlay.format)
            != (3, otg::SplitPipes::NONE, otg::SurfaceFormat::Argb8888)
        || overlay.plane.map(|l| l.dst) != Some(Rect::new(100, 100, 640, 360))
        || overlay.check().is_err()
        || primary.check().is_err()
    {
        return TestResult::Fail("surface requests");
    }
    let mode = selection_mode(&s);
    let planes: alloc::vec::Vec<dml::Plane> = mode.plane_list().collect();
    if planes != [primary.dml_plane(), overlay.dml_plane()]
        || planes[0].h_ratio != (1280 << 19) / 1920
        || planes[1].v_ratio != 2 << 19
    {
        return TestResult::Fail("admission planes");
    }
    if selection_mode(&base).planes != [None; dml::MAX_PLANES] {
        return TestResult::Fail("full-frame primary alone");
    }
    let Ok(plans) = admit_displays(&soc, &[s]) else {
        return TestResult::Fail("scaled primary with an overlay refused");
    };
    let one = plans[0];
    if one.plane(1).is_none() || one.plane(2).is_some() {
        return TestResult::Fail("planned planes");
    }
    let two = dml::Plan { pipes: 2, ..one };
    // As DC acquires them with no display running: the OTG masters, then
    // each stream's planes in DC order (the primary on its OPP heads, the
    // overlays top first, each on the lowest free pipe), then DML's ODM
    // slices, which copy each slice's tree onto pipes still free. (NARF
    // used to take overlay pipes from the top.)
    let got = |sel: &[Selection], plans: &[dml::Plan], crtcs: &[u8]| {
        display_pipes(sel, plans, crtcs).ok().map(|d| {
            d.iter()
                .map(|&(head, d)| (head, d.odm, d.overlays))
                .collect::<alloc::vec::Vec<_>>()
        })
    };
    let three = Selection {
        planes: PlaneSetup {
            overlays: [Some(video); 3],
            ..s.planes
        },
        ..s
    };
    let none = otg::SplitPipes::NONE;
    if got(&[s, s], &[one, one], &[0, 1])
        != Some(alloc::vec![
            (0, none, [pp(2, &[]), None, None]),
            (1, none, [pp(3, &[]), None, None])
        ])
        || got(&[s], &[two], &[0])
            != Some(alloc::vec![(
                0,
                otg::SplitPipes::one(2),
                [pp(1, &[3]), None, None]
            )])
        || got(&[three], &[one], &[0])
            != Some(alloc::vec![(0, none, [pp(3, &[]), pp(2, &[]), pp(1, &[])])])
        || got(&[three, base], &[one, one], &[0, 1]).is_some()
        || got(&[s, s], &[two, one], &[0, 1]).is_some()
    {
        return TestResult::Fail("overlay pipes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_planes_reach_admission_and_staging
);

/// amdgpu_dm's rotation 90/270 through to DML21: a portrait 1080x1920
/// framebuffer in 64KB tiles with DCC turned onto the 1080p stream as the
/// primary (and as an overlay window beside an unrotated primary) is
/// admitted, its plane scanned vertically with SPL's surface-space
/// viewport and unity ratios; the same plane linear is DML's Unsupported
/// (SourceFormatPixelAndScanSupport).
#[inline(never)]
fn navi48_rotated_planes_reach_admission() -> TestResult {
    use crate::amdgpu_dcn401_spl::{Rect, Rotation};
    let base = completed_modeset(0).selection;
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let tiled = otg::PlaneSurface {
        tiling: otg::Tiling {
            swizzle: otg::Swizzle::S64K2D,
            dcc: Some(otg::DccBlock::B128),
        },
        ..otg::PlaneSurface::LINEAR
    };
    let portrait = |dst: Rect, rotation, surface| PlaneGeometry {
        src_x: 0,
        src_y: 0,
        width: 1080,
        height: 1920,
        dst,
        rotation,
        blend: otg::Blend::default_for(base.format),
        surface,
        fb_size: (1080, 1920),
        client: false,
    };
    let full = Rect::new(0, 0, 1920, 1080);
    for rotation in [Rotation::R90, Rotation::R270] {
        let primary = Selection {
            planes: PlaneSetup {
                primary: Some(portrait(full, rotation, tiled)),
                ..PlaneSetup::NONE
            },
            ..base
        };
        let window = Selection {
            planes: PlaneSetup {
                overlays: [
                    Some(OverlayPlane {
                        geometry: portrait(Rect::new(960, 0, 960, 540), rotation, tiled),
                        format: base.format,
                        underlay: false,
                        plane: 0,
                    }),
                    None,
                    None,
                ],
                ..PlaneSetup::NONE
            },
            ..base
        };
        let mode = selection_mode(&primary);
        let Some(p) = mode.planes[0] else {
            return TestResult::Fail("rotated primary not a DML plane");
        };
        if !p.vertical_scan
            || (u32::from(p.viewport_width), u32::from(p.viewport_height)) != (1080, 1920)
            || (p.h_ratio, p.v_ratio) != (1 << 19, 1 << 19)
        {
            return TestResult::Fail("rotated primary DML plane");
        }
        if admit_displays(&soc, &[primary]).is_err() {
            return TestResult::Fail("rotated tiled primary refused");
        }
        match admit_displays(&soc, &[window]) {
            Ok(plans) if plans[0].plane(1).is_some() => {}
            _ => return TestResult::Fail("rotated tiled overlay refused"),
        }
        let linear = Selection {
            planes: PlaneSetup {
                primary: Some(portrait(full, rotation, otg::PlaneSurface::LINEAR)),
                ..PlaneSetup::NONE
            },
            ..base
        };
        if !matches!(
            admit_displays(&soc, &[linear]),
            Err(dml::Error::Unsupported)
        ) {
            return TestResult::Fail("rotated linear primary admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_rotated_planes_reach_admission
);

/// An HDMI 2.1 sink's HF-VSDB with its DSC fields: 600 MHz, SCDC,
/// Max_FRL_Rate 6, DSC 1.2 with 10 bpc, DSC_Max_FRL_Rate 6, DSC_MaxSlices
/// code 4 (eight slices at 340 MP/s) and 20 KiB of chunk buffer.
const HF_DSC: &[u8] = &[
    3 << 5 | 13,
    0xd8,
    0x5d,
    0xc4,
    1,
    120,
    0x80,
    0x60,
    0,
    0,
    0,
    0x81,
    0x64,
    19,
];
/// The 7680x4320@60 CTA mode (VIC 199) as narf's timing model takes it.
fn cta8k60() -> Timing {
    crate::amdgpu_dcn_display::timing_from_edid(
        &narf_edid::modes::cea_mode(199).unwrap().detailed(),
    )
    .unwrap()
}
fn dsc_soc() -> dml::Soc {
    dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    }
}

/// amdgpu_dm's HDMI FRL DSC policy on DCN401: the HF DSC fields as DRM
/// parses them; a stream compresses only when its raw bandwidth exceeds the
/// verified FRL link's, at each encoding and depth Linux tries in turn
/// (RGB before 4:2:0, the deepest depth first, compressed RGB only
/// natively), with dc_dsc_compute_config
/// against the sink's DSC_Max_FRL_Rate and the lowest rate the compressed
/// capacity check passes. The 8K60 CTA mode takes HDMI 2.1's eight slices
/// and VIC 199's preset 159/16 bpp, and (as Linux's dml1 tables give it)
/// 4 x 6G with the primary format's 3182/140 tribytes, borrowing from
/// blank; checked against the host build in tests/dcn401_frl.
fn navi48_hdmi_frl_dsc_policy_matches_linux() -> TestResult {
    use crate::amdgpu_dsc::{FrlDscLink, HdmiDscCaps};
    use crate::amdgpu_frl_cap::FrlBorrow;
    let vdb: &[u8] = &[2 << 5 | 2, 199, 118];
    let edid = with_blocks(edid_1080p(), &[VSDB, HF_DSC, vdb]);
    let caps = hdmi_caps(&edid);
    let want = HdmiDscCaps {
        bpc10: true,
        bpc12: false,
        all_bpp: false,
        native_420: false,
        max_slices: 4,
        max_frl_rate: 6,
        total_chunk_kbytes: 19,
    };
    if caps.dsc != Some(want) || caps.max_frl_rate != 6 {
        return TestResult::Fail("HF DSC fields");
    }
    let t = cta8k60();
    let enabled = frl_enabled();
    set_frl(true);
    let cap = frl_cap(caps);
    let stream = |caps: HdmiCaps, t: &Timing, bpc: u8, cap: Option<FrlRate>| {
        hdmi_stream(caps, t, bpc, cap, None, 2_000_000)
    };
    let got = stream(caps, &t, 8, cap).unwrap();
    let cfg = got.dsc.unwrap();
    if got.depth != otg::ColorDepth::Bpc8
        || got.ycbcr420
        || got.frl.map(FrlRate::code) != Some(3)
        || (cfg.slices_h, cfg.slices_v, cfg.bpp_x16) != (8, 40, 159)
        || cfg.frl
            != Some(FrlDscLink {
                all_bpp: false,
                max_rate: 6,
            })
    {
        panic!("8K60 FRL DSC: {got:?}");
    }
    let quiet = frl_audio(None, t.v_active);
    let dsc = FrlDscStream {
        cfg,
        vic: crate::amdgpu_dsc::Vic { cta: 199, hdmi: 0 },
    };
    // The trained link's encoder parameters: from 4 x 6G up the same
    // primary-format targets; below it the tribyte borrow is too large.
    for code in 3..=6 {
        assert_eq!(
            frl_video_params(&t, 8, false, Some(dsc), FrlRate::new(code).unwrap(), quiet),
            Some((1, FrlBorrow::FromBlank, 3182, 140)),
            "rate {code}"
        );
    }
    assert!(frl_dsc_carries(&t, dsc, FrlRate::new(2).unwrap(), quiet).is_none());
    // The 4K120 CTA mode fits the link raw: uncompressed, even so.
    let uhd120 = crate::amdgpu_dcn_display::timing_from_edid(
        &narf_edid::modes::cea_mode(118).unwrap().detailed(),
    )
    .unwrap();
    let raw = stream(caps, &uhd120, 8, cap).unwrap();
    // Deeper output compresses from 10 bpc (the decoder's DSC_10bpc), as
    // Linux tries it before 8; without DSC_10bpc 10-bpc DSC cannot form
    // and 8 bpc compresses.
    let deep = HdmiCaps { dc30: true, ..caps };
    let deep_dsc8 = HdmiCaps {
        dsc: Some(HdmiDscCaps {
            bpc10: false,
            ..want
        }),
        ..deep
    };
    let no_rate = HdmiCaps {
        dsc: Some(HdmiDscCaps {
            max_frl_rate: 0,
            ..want
        }),
        ..caps
    };
    let no_dsc = HdmiCaps { dsc: None, ..caps };
    let also_420 = HdmiCaps {
        y420_also: [0, 0, 0, 1 << (199 - 192)],
        ..caps
    };
    let slow = HdmiCaps {
        max_frl_rate: 2,
        ..caps
    };
    let results = (
        raw.dsc,
        raw.frl.map(FrlRate::code),
        stream(deep, &t, 10, cap).map(|s| (s.depth, s.dsc.map(|c| c.bpc), s.frl)),
        stream(no_rate, &t, 8, cap),
        stream(no_dsc, &t, 8, cap),
        stream(also_420, &t, 8, cap).map(|s| (s.ycbcr420, s.dsc.is_some())),
        stream(
            HdmiCaps {
                dsc: None,
                ..also_420
            },
            &t,
            8,
            cap,
        )
        .map(|s| (s.ycbcr420, s.dsc.is_some(), s.frl.map(FrlRate::code))),
        stream(slow, &t, 8, frl_cap(slow)),
    );
    let deep8 = stream(deep_dsc8, &t, 10, cap).map(|s| (s.depth, s.dsc.map(|c| c.bpc)));
    set_frl(false);
    let off = stream(caps, &t, 8, frl_cap(caps));
    set_frl(enabled);
    assert_eq!(results.0, None);
    assert_eq!(results.1, Some(4));
    let deep10 = crate::amdgpu_dsc::compute_frl_config(
        &crate::amdgpu_dsc::DscSinkCaps::from_hdmi(&want),
        2_000_000,
        6,
        &frl_dsc_timing(&t, 10),
        dsc.vic,
    )
    .unwrap();
    assert_eq!(deep10.bpc, 10);
    assert_eq!(
        results.2,
        Some((
            otg::ColorDepth::Bpc10,
            Some(10),
            frl_dsc_link(&t, FrlDscStream { cfg: deep10, ..dsc }, cap.unwrap(), quiet)
        ))
    );
    assert_eq!(deep8, Some((otg::ColorDepth::Bpc8, Some(8))));
    // No DSC rate (update_dsc_caps) or decoder: 8K60 RGB does not fit.
    assert_eq!(results.3, None);
    assert_eq!(results.4, None);
    // RGB is tried (and compressed) before 4:2:0, as Linux orders them;
    // without a decoder the 4:2:0 stream is carried raw.
    assert_eq!(results.5, Some((false, true)));
    assert_eq!(results.6, Some((true, false, Some(4))));
    // A 3 x 6G sink: the DSC stream fails its capacity check at the cap.
    assert_eq!(results.7, None);
    assert_eq!(off, None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_hdmi_frl_dsc_policy_matches_linux
);

/// A compressed FRL selection: the configuration's one FRL display keeps
/// the HF decoder for `refine_dsc`, stages an FRL timing with its DSC, and
/// DML admits it on two pipes (DSC per ODM segment).
fn navi48_hdmi_frl_dsc_selection_admits_on_two_pipes() -> TestResult {
    let vdb: &[u8] = &[2 << 5 | 1, 199];
    let edid = with_blocks(edid_1080p(), &[VSDB, HF_DSC, vdb]);
    let paths = [path(inventory::Connector::HdmiTypeA, 0)];
    let t = cta8k60();
    let enabled = frl_enabled();
    set_frl(true);
    let chosen = select(&paths, &[port(paths[0], None, edid)], 8, Some(t));
    set_frl(enabled);
    let mut s = chosen.unwrap();
    let cfg = s.dsc.unwrap();
    if s.timing != t
        || s.frl.map(FrlRate::code) != Some(3)
        || s.caps.dsc.is_none_or(|c| !c.is_frl)
        || s.avi.vic != 199
        || FrlDscStream::of(&s).map(|d| d.vic.cta_equivalent()) != Some(199)
    {
        panic!("FRL DSC selection: {s:?}");
    }
    let soc = dsc_soc();
    let before = s;
    refine_dsc(&soc, core::slice::from_mut(&mut s)).unwrap();
    assert_eq!(s, before);
    let plan = admit_displays(&soc, &[s]).unwrap()[0];
    assert_eq!(plan.pipes, 2);
    assert_eq!(
        plan.mode.dsc,
        Some(dml::Dsc {
            slices: cfg.slices_h,
            bpp_x16: cfg.bpp_x16
        })
    );
    let r = timing_request(0, &plan, &s);
    assert_eq!((r.signal, r.dsc), (otg::Signal::HdmiFrl, Some(cfg)));
    // A board whose DISPCLK cannot split 8K across two pipes takes four
    // (ODM 4:1: eight slices are not the twelve 3:1 needs), each DSC on
    // two slices of its quarter of the line.
    let small = dml::Soc {
        dispclk_max_khz: 1_000_000,
        ..soc
    };
    refine_dsc(&small, core::slice::from_mut(&mut s)).unwrap();
    let plan = admit_displays(&small, &[s]).unwrap()[0];
    assert_eq!(plan.pipes, 4);
    assert_eq!(
        dml::dsc_shape(&t, cfg.slices_h, small.dispclk_max_khz),
        Some(4)
    );
    // One whose DISPCLK four pipes cannot cover refuses it.
    let tiny = dml::Soc {
        dispclk_max_khz: 500_000,
        ..soc
    };
    let refused = refine_dsc(&tiny, core::slice::from_mut(&mut s)).is_err()
        || admit_displays(&tiny, &[s]).is_err();
    assert!(refused, "8K60 on four 500 MHz pipes");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_hdmi_frl_dsc_selection_admits_on_two_pipes
);

/// A tiled, 4:2:0 or client (GEM, scanned out in place) plane's surface is
/// its whole framebuffer with the source rectangle placed in it (DC scans
/// the framebuffer's viewport); a linear RGB dumb plane's is its source
/// rectangle.
fn navi48_modeset_stages_whole_framebuffers_for_tiled_and_yuv_planes() -> TestResult {
    use crate::amdgpu_dcn401_spl::{Rect, Rotation};
    let timing = Timing {
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
    };
    let geometry = |format: otg::SurfaceFormat, surface: otg::PlaneSurface, client| PlaneGeometry {
        src_x: 320,
        src_y: 180,
        width: 640,
        height: 360,
        dst: Rect::new(100, 50, 960, 540),
        rotation: Rotation::R0,
        blend: otg::Blend::default_for(format),
        surface,
        fb_size: (1280, 720),
        client,
    };
    let tiled = otg::PlaneSurface {
        tiling: otg::Tiling {
            swizzle: otg::Swizzle::S64K2D,
            dcc: None,
        },
        ..otg::PlaneSurface::LINEAR
    };
    for (format, surface, client, whole) in [
        (
            otg::SurfaceFormat::Nv12,
            otg::PlaneSurface::LINEAR,
            false,
            true,
        ),
        (otg::SurfaceFormat::Xrgb8888, tiled, false, true),
        (
            otg::SurfaceFormat::Xrgb8888,
            otg::PlaneSurface::LINEAR,
            false,
            false,
        ),
        // A linear GEM plane: the crop is in the viewport, so a source
        // rectangle at any byte shows (amdgpu_dm_plane_fill_plane_buffer_
        // attributes fetches from the buffer's start).
        (
            otg::SurfaceFormat::Xrgb8888,
            otg::PlaneSurface::LINEAR,
            true,
            true,
        ),
    ] {
        let setup = PlaneSetup {
            overlays: [
                Some(OverlayPlane {
                    geometry: geometry(format, surface, client),
                    format,
                    underlay: false,
                    plane: 0,
                }),
                None,
                None,
            ],
            ..PlaneSetup::NONE
        };
        let (_, overlays) = stream_planes(
            &timing,
            false,
            otg::SurfaceFormat::Xrgb8888,
            &setup,
            (0, otg::SplitPipes::NONE, otg::SplitPipes::NONE),
            &[
                Some(PlanePipes {
                    pipe: 1,
                    odm: otg::SplitPipes::NONE,
                    mpc: otg::SplitPipes::NONE,
                }),
                None,
                None,
            ],
        );
        let r = overlays[0].unwrap();
        let src = r.plane.unwrap().src;
        let want = if whole {
            ((1280, 720), Rect::new(320, 180, 640, 360))
        } else {
            ((640, 360), Rect::new(0, 0, 640, 360))
        };
        if ((r.width, r.height), src) != want || r.surface != surface || r.check().is_err() {
            return TestResult::Fail("plane surface");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_stages_whole_framebuffers_for_tiled_and_yuv_planes
);

/// Every further pipe DML's split needs, as DC acquires it with no display
/// running: the OTG masters in CRTC order, each stream's planes (an
/// overlay on the lowest free pipe), then DML's counts stream by stream
/// (map_dc_pipes_with_callbacks): each plane's MPC slices right after its
/// own pipes in its tree, then the stream's ODM slices with a copy of the
/// tree, each on the lowest free pipe. More than the four pipes is DML's
/// `Pipes`; a configuration DML admits always fits. (NARF used to take
/// every further pipe from the top, ODM segments first.)
fn navi48_split_pipes_follow_dml() -> TestResult {
    let one = completed_modeset(0).plan;
    let s = |p: &[u8]| otg::SplitPipes::new(p).unwrap();
    let none = otg::SplitPipes::NONE;
    // A primary MPC-combined on two DPPs, in ODM bypass.
    let mut mpc = one;
    if let Some(p) = mpc.planes[0].as_mut() {
        p.dpps = 2;
    }
    // A stream with one overlay plane; `ovl_mpc`'s overlay is MPC-combined.
    let mut ovl = one;
    let full = dml::Plane::full(&one.mode.timing, one.mode.pitch, 4);
    ovl.mode.planes = [Some(full), Some(full), None, None];
    ovl.planes[1] = ovl.planes[0];
    let mut ovl_mpc = ovl;
    if let Some(p) = ovl_mpc.planes[1].as_mut() {
        p.dpps = 2;
    }
    let three = dml::Plan { pipes: 3, ..ovl };
    let pp = |pipe: u8, odm: &[u8], mpc: &[u8]| {
        Some(PlanePipes {
            pipe,
            odm: s(odm),
            mpc: s(mpc),
        })
    };
    let got = |plans: &[dml::Plan], crtcs: &[u8]| plan_pipes(plans, crtcs).ok();
    let d = |head, odm, mpc, overlays| (head, DisplayPipes { odm, mpc, overlays });
    if got(&[mpc], &[0]) != Some(alloc::vec![d(0, none, s(&[1]), [None; 3])])
        || got(&[mpc, mpc], &[0, 1])
            != Some(alloc::vec![
                d(0, none, s(&[2]), [None; 3]),
                d(1, none, s(&[3]), [None; 3])
            ])
        // CRTC 1 alone takes pipe 0; its overlay's slice follows the
        // overlay in the tree.
        || got(&[ovl_mpc], &[1])
            != Some(alloc::vec![d(0, none, none, [pp(1, &[], &[2]), None, None])])
        || got(&[mpc, ovl], &[0, 1])
            != Some(alloc::vec![
                d(0, none, s(&[3]), [None; 3]),
                d(1, none, none, [pp(2, &[], &[]), None, None])
            ])
        // A 3:1 stream's segments and its overlay's: four pipes cannot
        // hold them.
        || got(&[three], &[0]).is_some()
        // The overlay is added on one pipe, then the ODM slice copies the
        // tree: the second OPP head, then the overlay's segment.
        || got(&[dml::Plan { pipes: 2, ..ovl }], &[0])
            != Some(alloc::vec![d(0, s(&[2]), none, [pp(1, &[3], &[]), None, None])])
        || got(&[mpc, mpc, one], &[0, 1, 2]).is_some()
    {
        return TestResult::Fail("split pipe allocation");
    }
    // The same through the selections' overlays.
    let base = completed_modeset(0).selection;
    if display_pipes(&[base], &[mpc], &[0]).ok()
        != Some(alloc::vec![d(0, none, s(&[1]), [None; 3])])
    {
        return TestResult::Fail("display pipes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/navi48-modeset", navi48_split_pipes_follow_dml);

/// On harvested boards (pipe 0, pipe 1, pipes 1 and 2 fused) every plan
/// takes pipe indices of the pool only (the pool's count is Linux's
/// pipe_count and max_streams): OTG masters, ODM segments and MPC slices
/// from the pool's lowest free pipe up whatever the CRTC, a split past the
/// pool refused, a stream routed past the published CRTCs refused, and KMS
/// publishing one CRTC per pool pipe. (NARF used to take the further pipes
/// from the pool's top down, with CRTC k's stream on pipe k.)
fn navi48_plans_take_only_the_pools_pipes_on_harvested_boards() -> TestResult {
    use crate::amdgpu_rdna4::{self as rdna4, PipePool};
    let one = completed_modeset(0).plan;
    let two = dml::Plan { pipes: 2, ..one };
    let three = dml::Plan { pipes: 3, ..one };
    let four = dml::Plan { pipes: 4, ..one };
    let mut mpc = one;
    if let Some(p) = mpc.planes[0].as_mut() {
        p.dpps = 2;
    }
    let s = |p: &[u8]| otg::SplitPipes::new(p).unwrap();
    let none = otg::SplitPipes::NONE;
    let mut result = TestResult::Pass;
    for fuses in [0x1, 0x2, 0x6] {
        rdna4::publish_pipe_pool(PipePool::from_fuses(fuses));
        let count = rdna4::pipe_pool().count();
        let top = count - 1;
        let got = |plans: &[dml::Plan], crtcs: &[u8]| {
            plan_pipes(plans, crtcs)
                .ok()
                .map(|d| d.iter().map(|&(head, d)| (head, d.odm)).collect::<Vec<_>>())
        };
        let mpc_got = plan_pipes(&[mpc], &[top])
            .ok()
            .map(|d| (d[0].0, d[0].1.mpc));
        let selection = completed_modeset(0).selection;
        let ok = got(&[two], &[0]) == Some(alloc::vec![(0, s(&[1]))])
            && got(&[two], &[top]) == Some(alloc::vec![(0, s(&[1]))])
            && got(&[one, one], &[0, top]) == Some(alloc::vec![(0, none), (1, none)])
            && got(&[four], &[0]).is_none()
            && (count < 3 || got(&[three], &[0]) == Some(alloc::vec![(0, s(&[1, 2]))]))
            && (count > 2 || got(&[three], &[0]).is_none())
            && mpc_got == Some((0, s(&[1])))
            && route_streams(alloc::vec![(selection, count)], &[]).is_err()
            && route_streams(alloc::vec![(selection, top)], &[]).is_ok()
            && crate::amdgpu_navi48_kms::crtc_count() == usize::from(count)
            && crate::amdgpu_navi48_kms::crtc_display(crate::amdgpu_navi48_kms::crtc_id(
                usize::from(top),
            )) == Some(top)
            && crate::amdgpu_navi48_kms::crtc_display(crate::amdgpu_navi48_kms::crtc_id(
                usize::from(count),
            ))
            .is_none();
        if !ok {
            result = TestResult::Fail("plans beyond the harvested pool");
            break;
        }
    }
    rdna4::publish_pipe_pool(PipePool::FULL);
    result
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_plans_take_only_the_pools_pipes_on_harvested_boards
);

/// The streams of `plans` on `crtcs`, their planes those the plans were
/// admitted with.
fn streams_of<'a>(plans: &'a [dml::Plan], crtcs: &[u8]) -> Vec<StreamPipes<'a>> {
    plans
        .iter()
        .zip(crtcs)
        .map(|(plan, &crtc)| StreamPipes::of_plan(crtc, plan))
        .collect()
}

/// The running displays a lighting of `plans` on `crtcs` with no display
/// running leaves.
fn lit_on(plans: &[dml::Plan], crtcs: &[u8]) -> Option<Vec<Modeset>> {
    let got = plan_pipes(plans, crtcs).ok()?;
    Some(
        got.iter()
            .zip(plans)
            .zip(crtcs)
            .map(|((&(head, d), plan), &crtc)| {
                let mut m = completed_modeset(head);
                m.crtc = crtc;
                m.plan = *plan;
                m.scanout.odm = d.odm;
                m.scanout.mpc = d.mpc;
                m.scanout.overlays = d.overlays.map(|o| {
                    o.map(|o| otg::OverlayScanout {
                        pipe: o.pipe,
                        odm: o.odm,
                        mpc: o.mpc,
                        address: 0x8_1000_0000,
                        underlay: false,
                    })
                });
                m
            })
            .collect(),
    )
}

/// The running state as DC left it (`dc_state` of the lit displays) holds
/// each stream's pipes where the acquisition put them: lighting the same
/// configuration again over it (a relight, one commit) gives every stream
/// and plane its pipes back (former OTG masters first, then each slice's
/// and tree's own pipes); CRTCs whose streams ran crosswise take the former
/// OTG masters lowest first in CRTC order; a stream lit beside the running
/// ones takes the lowest pipe they leave free and never a running split.
/// Harvested pools acquire the same way over their own pipe indices.
fn navi48_relight_and_beside_reacquire_dcs_pipes() -> TestResult {
    // Plans are kilobytes: keep them on the heap (the aarch64 kernel-test
    // stack is 64 KiB).
    let one = completed_modeset(0).plan;
    let none = otg::SplitPipes::NONE;
    let mut base: Vec<dml::Plan> = alloc::vec![one; 4];
    // A primary MPC-combined on two DPPs; a stream with one overlay; ODM 2:1.
    let (mpc, ovl, odm) = (1, 2, 3);
    if let Some(p) = base[mpc].planes[0].as_mut() {
        p.dpps = 2;
    }
    let full = dml::Plane::full(&one.mode.timing, one.mode.pitch, 4);
    base[ovl].mode.planes = [Some(full), Some(full), None, None];
    base[ovl].planes[1] = base[ovl].planes[0];
    base[odm].pipes = 2;
    let pick = |ids: &[usize]| -> Vec<dml::Plan> { ids.iter().map(|&i| base[i]).collect() };
    let configs: [(&[usize], &[u8]); 5] = [
        (&[0, 0, 0], &[0, 1, 3]),
        (&[mpc, ovl], &[0, 2]),
        (&[odm, ovl], &[1, 3]),
        (&[ovl, ovl], &[0, 1]),
        (&[mpc, 0, 0], &[0, 1, 2]),
    ];
    for (ids, crtcs) in configs {
        let plans = pick(ids);
        let Some(running) = lit_on(&plans, crtcs) else {
            return TestResult::Fail("configuration");
        };
        let first = plan_pipes(&plans, crtcs).ok();
        let again = light_pipes(&dc_state(&running), &streams_of(&plans, crtcs)).ok();
        if first.is_none() || again != first {
            return TestResult::Fail("relight keeps every pipe");
        }
    }
    // CRTC 0's stream ran on pipe 1 and CRTC 1's on pipe 0: relit together,
    // CRTC 0 takes former OTG master 0, CRTC 1 former OTG master 1.
    let mut a = completed_modeset(1);
    a.crtc = 0;
    let mut b = completed_modeset(0);
    b.crtc = 1;
    let relit = light_pipes(&dc_state(&[a, b]), &streams_of(&pick(&[0, 0]), &[0, 1]))
        .ok()
        .map(|d| d.iter().map(|&(h, _)| h).collect::<Vec<_>>());
    if relit != Some(alloc::vec![0, 1]) {
        return TestResult::Fail("former OTG masters in CRTC order");
    }
    // Beside: CRTC 0 runs on pipes 0 and 1 (ODM); CRTC 2 lit beside it
    // takes pipe 2, its overlay pipe 3.
    let Some(running) = lit_on(&pick(&[odm]), &[0]) else {
        return TestResult::Fail("ODM display");
    };
    let overlay = PlanePipes {
        pipe: 3,
        odm: none,
        mpc: none,
    };
    let beside = beside_pipes(&dc_state(&running), &streams_of(&pick(&[ovl]), &[2]));
    if beside
        != Some(alloc::vec![(
            2,
            DisplayPipes {
                overlays: [Some(overlay), None, None],
                ..DisplayPipes::default()
            }
        )])
    {
        return TestResult::Fail("beside the running display");
    }
    // A running stream's MPC split is not taken by a stream beside it:
    // no pipe is left.
    let Some(running) = lit_on(&pick(&[mpc, 0, 0]), &[0, 1, 2]) else {
        return TestResult::Fail("split display");
    };
    if beside_pipes(&dc_state(&running), &streams_of(&pick(&[0]), &[3])).is_some() {
        return TestResult::Fail("a running split taken");
    }
    // Harvested pools: the pool's indices, the same rules.
    use crate::amdgpu_rdna4::{self as rdna4, PipePool};
    let mut result = TestResult::Pass;
    for fuses in [0x1, 0x2, 0x6] {
        rdna4::publish_pipe_pool(PipePool::from_fuses(fuses));
        let count = rdna4::pipe_pool().count();
        let beside = |running: &[Modeset]| {
            beside_pipes(&dc_state(running), &streams_of(&pick(&[0]), &[0])).map(|d| d[0].0)
        };
        let ok = lit_on(&pick(&[odm]), &[count - 1]).is_some_and(|running| {
            running[0].pipe == 0
                && running[0].scanout.odm == otg::SplitPipes::one(1)
                && if count > 2 {
                    beside(&running) == Some(2)
                } else {
                    beside(&running).is_none()
                }
        });
        if !ok {
            result = TestResult::Fail("harvested pool");
            break;
        }
    }
    rdna4::publish_pipe_pool(PipePool::FULL);
    result
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_relight_and_beside_reacquire_dcs_pipes
);

/// MPC combine of the surfaces Linux DML21 also splits, from amdgpu_dm's
/// planes to the pipes: on a 4K CVT-RB stream (533.25 MHz, ODM bypass), an
/// 8K framebuffer in 64KB tiles, a portrait 8K one in 256KB tiles with DCC
/// turned 270 degrees, and portrait 8K NV12 (64KB tiles, turned 90) and
/// P010 (256KB tiles, turned 270) frames, each scaled 2:1 as the primary,
/// are admitted with the plane on two DPPs (no single DPP takes the swath:
/// the tiled and vertical 4:2:0 limits), take the lowest free pipe as
/// their second slice (DC's acquisition with no display running; NARF used
/// to take the top one), and stage as a request naming it. A 4K tiled
/// plane at 1:1 keeps one DPP.
#[inline(never)]
fn navi48_split_tiled_rotated_and_video_planes_reach_pipes() -> TestResult {
    use crate::amdgpu_dcn401_spl::{Rect, Rotation};
    let mut base = completed_modeset(0).selection;
    base.timing = Timing {
        pixel_clock_khz: 533_250,
        h_active: 3840,
        h_total: 4000,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 2160,
        v_total: 2222,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: false,
    };
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let surface = |swizzle, dcc| otg::PlaneSurface {
        tiling: otg::Tiling { swizzle, dcc },
        ..otg::PlaneSurface::LINEAR
    };
    let geometry = |(w, h): (u32, u32), rotation, surface, format| PlaneGeometry {
        src_x: 0,
        src_y: 0,
        width: w,
        height: h,
        dst: Rect::new(0, 0, 3840, 2160),
        rotation,
        blend: otg::Blend::default_for(format),
        surface,
        fb_size: (w, h),
        client: false,
    };
    let tiled = surface(otg::Swizzle::S64K2D, None);
    let dcc = surface(otg::Swizzle::S256K2D, Some(otg::DccBlock::B64));
    let (rgb, nv12, p010) = (
        otg::SurfaceFormat::Xrgb8888,
        otg::SurfaceFormat::Nv12,
        otg::SurfaceFormat::P010,
    );
    let cases = [
        (rgb, geometry((7680, 4320), Rotation::R0, tiled, rgb), 2),
        (rgb, geometry((4320, 7680), Rotation::R270, dcc, rgb), 2),
        (nv12, geometry((4320, 7680), Rotation::R90, tiled, nv12), 2),
        (
            p010,
            geometry(
                (4320, 7680),
                Rotation::R270,
                surface(otg::Swizzle::S256K2D, None),
                p010,
            ),
            2,
        ),
        (rgb, geometry((3840, 2160), Rotation::R0, tiled, rgb), 1),
    ];
    const NAMES: [&str; 5] = [
        "8K tiled plane DPPs",
        "turned 8K DCC plane DPPs",
        "turned 8K NV12 plane DPPs",
        "turned 8K P010 plane DPPs",
        "1:1 tiled plane DPPs",
    ];
    for (k, (format, g, dpps)) in cases.into_iter().enumerate() {
        let sel = Selection {
            format,
            planes: PlaneSetup {
                primary: Some(g),
                ..PlaneSetup::NONE
            },
            ..base
        };
        let Ok(plans) = admit_displays(&soc, &[sel]) else {
            return TestResult::Fail("split plane refused");
        };
        if plans[0].pipes != 1 || plans[0].plane(0).map(|p| p.dpps) != Some(dpps) {
            return TestResult::Fail(NAMES[k]);
        }
        let Ok(pipes) = display_pipes(&[sel], &plans, &[0]) else {
            return TestResult::Fail("split plane pipes");
        };
        let want = if dpps == 2 {
            otg::SplitPipes::one(1)
        } else {
            otg::SplitPipes::NONE
        };
        let (head, pipes) = pipes[0];
        let (primary, _) = plane_requests(&sel, head, &pipes);
        if head != 0
            || pipes.mpc != want
            || primary.mpc != want
            || primary.check().is_err()
            || Some(primary.dml_plane()) != plans[0].mode.planes[0]
        {
            return TestResult::Fail("split plane request");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_split_tiled_rotated_and_video_planes_reach_pipes
);

/// DP SST deep color as amdgpu_dm decides it: the sink's EDID 1.4 color
/// depth (display_info.bpc, 8 when undefined) bounded by the requested
/// maximum (max_requested_bpc, even), then create_validate_stream_for_sink's
/// steps of 2 while the link cannot carry the stream; 1080p60 at 10 bpc
/// (4,455,000 kbps) fits 2 x HBR2 but not 1 x HBR2, which then lights it
/// at 8 bpc. The training candidates and UHBR budget use the chosen depth.
fn navi48_modeset_dp_deep_color_like_amdgpu_dm() -> TestResult {
    let with_bpc = |code: u8| {
        let mut e = edid_1080p();
        e[20] = 0x80 | code << 4 | 5;
        e[127] = narf_edid::compute_checksum(&e);
        e
    };
    assert_eq!(edid_bpc(&with_bpc(3)), 10);
    assert_eq!(edid_bpc(&with_bpc(4)), 12);
    assert_eq!(edid_bpc(&with_bpc(0)), 0);
    assert_eq!(edid_bpc(&edid_1080p()), 8);
    let mut old = with_bpc(3);
    old[19] = 3;
    assert_eq!(edid_bpc(&old), 0);
    use otg::ColorDepth::{Bpc10, Bpc12, Bpc8};
    assert_eq!(dp_depths(&with_bpc(4), 12), [Bpc12, Bpc10, Bpc8]);
    assert_eq!(dp_depths(&with_bpc(4), 11), [Bpc10, Bpc8]);
    assert_eq!(dp_depths(&with_bpc(3), 12), [Bpc10, Bpc8]);
    assert_eq!(dp_depths(&with_bpc(0), 12), [Bpc8]);
    assert_eq!(dp_depths(&with_bpc(1), 12), [Bpc8]);
    let paths = [path(inventory::Connector::DisplayPort, 0)];
    let pick = |edid: Vec<u8>, rate: u8, lanes: u8, max: u8| {
        select(
            &paths,
            &[port(paths[0], dpcd(rate, lanes), edid)],
            max,
            None,
        )
        .unwrap()
    };
    let s = pick(with_bpc(3), 0x14, 2, 10);
    if s.depth != Bpc10 || (s.lanes, s.rate) != (2, DpRate::Legacy(LinkRate::Hbr2)) {
        panic!("10 bpc on 2 x HBR2: {:?} {} {:?}", s.depth, s.lanes, s.rate);
    }
    assert_eq!(s.blank_request(0).depth, Bpc10);
    // Every fallback candidate carries 30-bit pixels.
    for (l, r) in selected_dp_candidates(&s) {
        assert!(dp_fits_bpc(&s.timing, s.caps, l, r, 10), "{l} {r:?}");
    }
    assert!(!selected_dp_candidates(&s).contains(&(1, DpRate::Legacy(LinkRate::Hbr2))));
    assert_eq!(pick(with_bpc(3), 0x14, 1, 10).depth, Bpc8);
    assert_eq!(pick(with_bpc(3), 0x14, 2, 8).depth, Bpc8);
    assert_eq!(pick(with_bpc(4), 0x1e, 4, 12).depth, Bpc12);
    assert_eq!(pick(edid_1080p(), 0x1e, 4, 12).depth, Bpc8);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_dp_deep_color_like_amdgpu_dm
);

/// A connector's "max bpc" (max_requested_bpc) caps its own stream as
/// amdgpu_dm_create_validate_stream_for_sink's bpc mask does, within
/// `amdgpu.max_bpc`: on 4 x HBR3, a 10-bpc sink lights at 10 bpc when its
/// connector asks for 10 (or 16), at 8 when it asks for 8 or 9; a 12-bpc
/// sink's 10 asks it down to 10 and 11 rounds down to 10; another port's
/// connector is unaffected; with 16 the stream still steps down to what
/// the link carries (1080p60 at 12 bpc, 5,346,000 kbps, does not fit 1 x
/// HBR2's 4,320,000 kbps, nor does 10 bpc, 4,455,000: 8 bpc). HDMI takes
/// the same cap.
fn navi48_modeset_connector_max_bpc_caps_its_stream() -> TestResult {
    use otg::ColorDepth::{Bpc10, Bpc12, Bpc8};
    let with_bpc = |code: u8| {
        let mut e = edid_1080p();
        e[20] = 0x80 | code << 4 | 5;
        e[127] = narf_edid::compute_checksum(&e);
        e
    };
    let before = max_bpc();
    set_max_bpc(12);
    let paths = [
        path(inventory::Connector::DisplayPort, 0),
        path(inventory::Connector::DisplayPort, 1),
        path(inventory::Connector::HdmiTypeA, 2),
    ];
    let pick = |n: usize, edid: Vec<u8>, rate: u8, lanes: u8, requested: u8| {
        set_requested_bpc(n, None, requested);
        let ports = [port(paths[n], dpcd(rate, lanes), edid)];
        let s = select_all(&paths, &ports, max_bpc(), &|_| None).map(|s| s[0].depth);
        set_requested_bpc(n, None, MAX_REQUESTED_BPC);
        s.ok()
    };
    let got = [
        pick(0, with_bpc(3), 0x1e, 4, 10),
        pick(0, with_bpc(3), 0x1e, 4, 16),
        pick(0, with_bpc(3), 0x1e, 4, 8),
        pick(0, with_bpc(3), 0x1e, 4, 9),
        pick(0, with_bpc(4), 0x1e, 4, 10),
        pick(0, with_bpc(4), 0x1e, 4, 11),
        pick(0, with_bpc(4), 0x1e, 4, 16),
        pick(0, with_bpc(4), 0x14, 1, 16),
    ];
    // Port 1's connector asks for 8; port 0's stream does not see it.
    set_requested_bpc(1, None, 8);
    let ports = [
        port(paths[0], dpcd(0x1e, 4), with_bpc(4)),
        port(paths[1], dpcd(0x1e, 4), with_bpc(4)),
    ];
    let both = select_all(&paths, &ports, max_bpc(), &|_| None)
        .map(|s| s.iter().map(|s| (s.port, s.depth)).collect::<Vec<_>>());
    set_requested_bpc(1, None, MAX_REQUESTED_BPC);
    // amdgpu.max_bpc still bounds every connector.
    set_max_bpc(8);
    let module = pick(0, with_bpc(4), 0x1e, 4, 16);
    set_max_bpc(12);
    // HDMI: 1080p60 RGB 12 bpc (222.75 MHz TMDS) unless its connector
    // asks for less.
    let hdmi = |requested: u8| {
        set_requested_bpc(2, None, requested);
        let ports = [port(paths[2], None, with_blocks(edid_1080p(), &[VSDB_DC]))];
        let s = select_all(&paths, &ports, max_bpc(), &|_| None).map(|s| s[0].depth);
        set_requested_bpc(2, None, MAX_REQUESTED_BPC);
        s.ok()
    };
    let hdmi = [hdmi(16), hdmi(10), hdmi(8)];
    set_max_bpc(before);
    let want = [
        Some(Bpc10),
        Some(Bpc10),
        Some(Bpc8),
        Some(Bpc8),
        Some(Bpc10),
        Some(Bpc10),
        Some(Bpc12),
        Some(Bpc8),
    ];
    if got != want {
        panic!("DP SST depths {got:?} want {want:?}");
    }
    if both.ok() != Some(alloc::vec![(0, Bpc12), (1, Bpc8)]) {
        return TestResult::Fail("per-connector cap");
    }
    if module != Some(Bpc8) {
        return TestResult::Fail("amdgpu.max_bpc bound");
    }
    if hdmi != [Some(Bpc12), Some(Bpc10), Some(Bpc8)] {
        panic!("HDMI depths {hdmi:?}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_connector_max_bpc_caps_its_stream
);

/// The board inputs of the live plane tests.
fn live_soc() -> dml::Soc {
    dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    }
}
/// A 640x360 ARGB8888 overlay, DRM plane `plane`, at x.
fn live_overlay(plane: u32, x: i32) -> OverlayPlane {
    use crate::amdgpu_dcn401_spl::{Rect, Rotation};
    OverlayPlane {
        geometry: PlaneGeometry {
            src_x: 0,
            src_y: 0,
            width: 640,
            height: 360,
            dst: Rect::new(x, 100, 640, 360),
            rotation: Rotation::R0,
            blend: otg::Blend::default_for(otg::SurfaceFormat::Argb8888),
            surface: otg::PlaneSurface::LINEAR,
            fb_size: (640, 360),
            client: false,
        },
        format: otg::SurfaceFormat::Argb8888,
        underlay: false,
        plane,
    }
}
/// The full-frame primary with `overlays`, bottom first.
fn live_setup(overlays: &[OverlayPlane]) -> PlaneSetup {
    let mut s = PlaneSetup::NONE;
    for (o, p) in s.overlays.iter_mut().zip(overlays) {
        *o = Some(*p);
    }
    s
}
/// Display `m`'s plan with the planes `setup`, on the heap.
#[inline(never)]
fn live_plan(m: &Modeset, setup: &PlaneSetup) -> alloc::boxed::Box<dml::Plan> {
    let mut s = m.selection;
    s.planes = *setup;
    alloc::boxed::Box::new(admit_displays(&live_soc(), &[s]).unwrap()[0])
}
/// `completed_modeset(pipe)` on the heap.
#[inline(never)]
fn live_modeset(pipe: u8) -> alloc::boxed::Box<Modeset> {
    alloc::boxed::Box::new(completed_modeset(pipe))
}
/// Display `m`'s planes `setup` under `plan` beside `others`, the planes
/// recreated when amdgpu_dm would (`live_pipes` on their `dc_state`).
#[inline(never)]
fn live_on(
    m: &Modeset,
    others: &[&Modeset],
    setup: &PlaneSetup,
    plan: &dml::Plan,
) -> Option<DisplayPipes> {
    let mut running: Vec<Modeset> = Vec::with_capacity(1 + others.len());
    running.push(*m);
    for o in others {
        running.push(**o);
    }
    let mut s = m.selection;
    s.planes = *setup;
    let reset =
        super::planes::planes_reset(m.selection.format, &m.selection.planes, s.format, setup);
    live_pipes(
        &dc_state(&running),
        &StreamPipes::of(m.crtc, &s, plan),
        reset,
    )
}
fn live_one(pipe: u8) -> PlanePipes {
    PlanePipes {
        pipe,
        odm: otg::SplitPipes::NONE,
        mpc: otg::SplitPipes::NONE,
    }
}
fn live_overlay_pipes(r: Option<DisplayPipes>) -> Option<[Option<u8>; otg::MAX_OVERLAYS]> {
    r.map(|d| d.overlays.map(|p| p.map(|p| p.pipe)))
}

/// The pipes a running display's new planes take without a modeset, as DC
/// acquires them on the running state (`live_pipes`): a plane added or
/// removed makes amdgpu_dm recreate every plane of the CRTC
/// (should_reset_plane, `planes::planes_reset`), and each recreated overlay
/// takes, top first, the first free pipe of its OPP head's current blending
/// tree (dcn32_find_optimal_free_pipe_as_secondary_dpp_pipe), else one the
/// running state leaves free, so a kept overlay comes back to its pipe
/// wherever it moves in the stack and a new one takes a removed one's; a
/// plane only moved keeps its pipes; another ODM split is a modeset. (NARF
/// used to give a new overlay the top free pipe and keep every other
/// plane's.)
fn navi48_live_plane_pipes_follow_dc() -> TestResult {
    let mut m = live_modeset(0);
    let other1 = live_modeset(1);
    let other3 = live_modeset(3);
    let a = live_overlay(0x44, 100);
    let with_a = live_setup(&[a]);
    let plan_a = live_plan(&m, &with_a);
    // A new overlay: the lowest free pipe, past another display's.
    if live_overlay_pipes(live_on(&m, &[], &with_a, &plan_a)) != Some([Some(1), None, None])
        || live_overlay_pipes(live_on(&m, &[&other1], &with_a, &plan_a))
            != Some([Some(2), None, None])
    {
        return TestResult::Fail("new overlay pipe");
    }
    // Running with A on pipe 2 (another display on 3): B is added below A;
    // A, recreated first (top first), takes its tree's pipe 2 back
    // although its stack position moved, and B the free pipe 1.
    m.selection.planes = with_a;
    m.plan = *plan_a;
    m.scanout.overlays[0] = Some(otg::OverlayScanout {
        pipe: 2,
        odm: otg::SplitPipes::NONE,
        mpc: otg::SplitPipes::NONE,
        address: 0x8_1000_0000,
        underlay: false,
    });
    let b = live_overlay(0x45, 900);
    let with_ba = live_setup(&[b, a]);
    let plan_ba = live_plan(&m, &with_ba);
    let Some(got) = live_on(&m, &[&other3], &with_ba, &plan_ba) else {
        return TestResult::Fail("two overlays");
    };
    if got.mpc != otg::SplitPipes::NONE
        || got.overlays != [Some(live_one(1)), Some(live_one(2)), None]
    {
        return TestResult::Fail("recreated overlay comes back to its pipe");
    }
    // A removed and C added: C takes the tree's pipe A held, and is
    // another plane than the one there: it takes a fresh surface with its
    // own first frame however alike A's surface is (`moved_planes`).
    let with_c = live_setup(&[live_overlay(0x46, 400)]);
    let plan_c = live_plan(&m, &with_c);
    let pipes_c = live_overlay_pipes(live_on(&m, &[&other3], &with_c, &plan_c));
    if pipes_c != Some([Some(2), None, None]) {
        return TestResult::Fail("freed pipe reused");
    }
    let old_pipes = [Some(2), None, None];
    if super::planes::moved_planes(&with_a, &old_pipes, &with_c, &old_pipes) != 1 << 2
        || super::planes::moved_planes(&with_a, &old_pipes, &with_a, &old_pipes) != 0
        || super::planes::moved_planes(&with_a, &old_pipes, &with_ba, &[Some(1), Some(2), None])
            != 0
    {
        return TestResult::Fail("plane moved onto another's pipe");
    }
    // A only moved: no plane is recreated and it keeps its pipe.
    let moved = live_setup(&[live_overlay(0x44, 300)]);
    let format = m.selection.format;
    if super::planes::planes_reset(format, &with_a, format, &moved)
        || !super::planes::planes_reset(format, &with_a, format, &with_c)
        || live_overlay_pipes(live_on(&m, &[&other3], &moved, &plan_a))
            != Some([Some(2), None, None])
    {
        return TestResult::Fail("moved overlay");
    }
    // Another ODM split moves the stream: a modeset.
    let mut odm = plan_a;
    odm.pipes = 2;
    if live_on(&m, &[], &with_a, &odm).is_some() {
        return TestResult::Fail("ODM change");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_live_plane_pipes_follow_dc
);

/// `live_pipes` beside a split primary and other displays: a primary
/// MPC-combined on pipes 0 and 1 gaining an overlay gives the overlay the
/// tree's first pipe (1) and moves its slice to the next free one (2), as
/// Linux swaps them; with displays on pipes 1, 2 and 3 a new overlay has no
/// pipe (another display's are never taken): a modeset.
fn navi48_live_plane_pipes_swap_a_split_and_spare_other_displays() -> TestResult {
    let with_a = live_setup(&[live_overlay(0x44, 100)]);
    let mut split = live_modeset(0);
    if let Some(p) = split.plan.planes[0].as_mut() {
        p.dpps = 2;
    }
    split.scanout.mpc = otg::SplitPipes::one(1);
    let mut plan_split = live_plan(&split, &with_a);
    if let Some(p) = plan_split.planes[0].as_mut() {
        p.dpps = 2;
    }
    let Some(got) = live_on(&split, &[], &with_a, &plan_split) else {
        return TestResult::Fail("overlay beside a split primary");
    };
    if got.mpc != otg::SplitPipes::one(2) || got.overlays != [Some(live_one(1)), None, None] {
        return TestResult::Fail("split primary's slice swapped");
    }
    drop(split);
    let lone = live_modeset(0);
    let plan_a = live_plan(&lone, &with_a);
    let (o1, o2, o3) = (live_modeset(1), live_modeset(2), live_modeset(3));
    if live_on(&lone, &[&o1, &o2, &o3], &with_a, &plan_a).is_some() {
        return TestResult::Fail("other displays' pipes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_live_plane_pipes_swap_a_split_and_spare_other_displays
);

/// DSC at the deepest depth, as create_validate_stream_for_sink tries each
/// depth with apply_dsc_policy_for_stream: a 10-bpc 4K60 sink on 4 x HBR2
/// with FEC (16,761,600 kbps) would take 8-bpc RGB raw (14,256,000) but
/// not 10-bpc (17,820,000), so with max_bpc 10 it is compressed from 10 bpc
/// (dc_dsc_compute_config at that depth) rather than sent raw at 8. A
/// decoder without 10-bpc input, or max_bpc 8, keeps it raw at 8.
/// refine_dsc keeps the depth, the timing request compresses at it and the
/// blank request feeds the DSC that depth.
fn navi48_modeset_compresses_dp_sst_at_10_bpc_like_amdgpu_dm() -> TestResult {
    use crate::amdgpu_dsc::{compute_config, DscSinkCaps, LinkEncoding};
    // DSC 1.2, slices 1/2/4, 13-bit line buffer, RGB, 1000 MP/s per
    // slice, 5120-pixel slices, 1/16 bpp; 8, 10 and 12 bpc input.
    const DSC: [u8; 16] = [
        1, 0x21, 0, 0x0b, 0x0b, 4, 1, 0, 0, 0x13, 0x0e, 0xee, 16, 0, 0, 0,
    ];
    let mut edid = edid_uhbr();
    edid[20] = 0x80 | 3 << 4 | 5; // 10 bpc, DisplayPort
    edid[127] = 0;
    edid[127] = narf_edid::compute_checksum(&edid[..128]);
    let p = path(inventory::Connector::DisplayPort, 0);
    let pick = |dsc: [u8; 16], max: u8| {
        let mut device = port(p, dpcd(0x14, 4), edid.clone());
        let sink = device.sink.as_mut().unwrap();
        sink.fec = true;
        sink.dsc = Some(dsc);
        select(&[p], &[device], max, None).unwrap()
    };
    let mut s = pick(DSC, 10);
    let link = legacy_kbps(4, LinkRate::Hbr2, true);
    assert_eq!(link, 16_761_600);
    assert!(stream_kbps_bpc(&s.timing, false, 8) <= link);
    assert!(stream_kbps_bpc(&s.timing, false, 10) > link);
    let want = compute_config(
        &DscSinkCaps::parse(&DSC, &[0; 3]).unwrap(),
        NOMINAL_DISPCLK_KHZ,
        link as u32,
        &dsc_timing(&s.timing, 10),
        LinkEncoding::Dp8b10b,
        false,
    );
    if s.depth != otg::ColorDepth::Bpc10
        || want.is_none_or(|c| c.bpc != 10)
        || s.dsc != want
        || (s.lanes, s.rate) != (4, DpRate::Legacy(LinkRate::Hbr2))
    {
        panic!(
            "10-bpc DSC: {:?} {:?} {} {:?}",
            s.depth, s.dsc, s.lanes, s.rate
        );
    }
    let soc = dsc_soc();
    refine_dsc(&soc, core::slice::from_mut(&mut s)).unwrap();
    let plans = admit_displays(&soc, &[s]).unwrap();
    let request = timing_request(0, &plans[0], &s);
    if s.depth != otg::ColorDepth::Bpc10
        || request.dsc.map(|c| c.bpc) != Some(10)
        || s.blank_request(0).depth != otg::ColorDepth::Bpc10
    {
        return TestResult::Fail("10-bpc DSC through refine and the requests");
    }
    // 8-bpc-only input (DP_DSC_DEC_COLOR_DEPTH_CAP 8 bpc) or max_bpc 8:
    // 10-bpc DSC fails validation and 8 bpc goes raw.
    let mut eight = DSC;
    eight[10] = 0x02;
    for s in [pick(eight, 10), pick(DSC, 8)] {
        if s.depth != otg::ColorDepth::Bpc8 || s.dsc.is_some() {
            panic!("8-bpc fallback: {:?} {:?}", s.depth, s.dsc);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_compresses_dp_sst_at_10_bpc_like_amdgpu_dm
);

/// MST on two DP ports at once, as amdgpu_dm keeps a topology manager per
/// DP connector: each port's end devices are selected against that port's
/// own link (two 2160p streams of 54 slots each, which one 63-slot link
/// could never carry together), each port's dark devices count only that
/// port's slots, and the configuration joins both ports' streams in pipe
/// order with joint DML admission; one pipe named on both ports is refused.
fn navi48_mst_two_ports_select_on_their_own_links() -> TestResult {
    use crate::dp_mst_mgr::Sink;
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
    // Both branches report the same Sink indices: only the port tells
    // their streams apart.
    let sink = |port| Sink { branch: 0, port };
    let devices = [
        (sink(1), edid_2160p(), u16::MAX),
        (sink(2), edid_three_modes(false), u16::MAX),
    ];
    let uhd = edid_timings(&edid_2160p())[0];
    let budget = |_, _: &[(Sink, u16)]| u16::MAX;
    let pick = |port, pipes: &[Option<u8>]| {
        super::super::mst::select_mst_outputs(port, caps, &devices, &|_| Some(uhd), pipes, &budget)
    };
    let a = pick(0, &[Some(0), Some(2)]);
    let b = pick(2, &[Some(1), Some(3)]);
    let shape = |s: &[(Selection, u8)]| -> Vec<(usize, u32, u8, u8)> {
        s.iter()
            .map(|(s, p)| (s.port, s.timing.h_active, s.mst.unwrap().slots, *p))
            .collect()
    };
    assert_eq!(shape(&a), [(0, 3840, 54, 0), (0, 1280, 7, 2)]);
    assert_eq!(shape(&b), [(2, 3840, 54, 1), (2, 1280, 7, 3)]);
    let streams = route_streams(Vec::new(), &[a.as_slice(), b.as_slice()]).unwrap();
    assert_eq!(
        streams
            .iter()
            .map(|(s, p)| (s.port, *p))
            .collect::<Vec<_>>(),
        [(0, 0), (2, 1), (0, 2), (2, 3)]
    );
    // The two 2160p streams together pass DML; four stay the pipes' limit.
    let selections: Vec<Selection> = streams.iter().map(|(s, _)| *s).collect();
    assert_eq!(
        admit_displays(&soc, &selections[..2]).map(|p| p.len()),
        Ok(2)
    );
    assert!(admit_displays(&soc, &selections).is_ok_and(|p| p.len() <= MAX_DISPLAYS));
    // A pipe on both ports, or a board sink's pipe again, is refused.
    let clash = pick(2, &[Some(0), None]);
    assert!(route_streams(Vec::new(), &[a.as_slice(), clash.as_slice()]).is_err());
    let mut board = a[1].0;
    board.mst = None;
    board.port = 1;
    assert!(route_streams(alloc::vec![(board, 2)], &[a.as_slice()]).is_err());
    assert!(route_streams(alloc::vec![(board, 1)], &[a.as_slice()]).is_ok());
    // A dark device on port 0 sees port 0's 54 + 7 slots taken, not port
    // 2's: only 720p could still be added there (9 slots left would not
    // even carry 1080p), and with port 2's streams alone every mode fits
    // port 0's slots.
    let widths = |m: Vec<Timing>| m.iter().map(|t| t.h_active).collect::<Vec<_>>();
    let edid = edid_three_modes(false);
    let lit_b: Vec<Selection> = b.iter().map(|(s, _)| *s).collect();
    let offered = |lit: &[Selection]| {
        widths(super::super::mst::dark_mst_modes_with(
            &soc,
            0,
            caps,
            &edid,
            u16::MAX,
            lit,
            None,
        ))
    };
    assert_eq!(offered(&lit_b[..1]), [1920, 3840, 1280]);
    assert_eq!(offered(&[a[0].0, lit_b[0]]), [1280]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_mst_two_ports_select_on_their_own_links
);

/// A new end device beside a port's running MST stream on a link without
/// DSC decoders: the running stream keeps its payload as Linux keeps it
/// (drm_dp_atomic_find_time_slots runs only for the changed connector), so
/// the new one takes what it leaves: 9 of 63 slots beside a 2160p stream
/// (720p, not the 1080p the device would get alone), its hop PBN beside the
/// running payload's, and no payload past amdgpu_dm's four per manager.
/// The running device is never selected again.
fn navi48_mst_selects_new_streams_beside_running_ones() -> TestResult {
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
    ];
    let unlimited = |_: Sink, _: &[(Sink, u16)]| u16::MAX;
    let beside = |pipes: &[Option<u8>], lit: &[Selection], budget: &super::super::mst::Budget| {
        super::super::mst::select_mst_outputs_beside(
            0,
            caps,
            &devices,
            &|_| None,
            pipes,
            budget,
            None,
            lit,
        )
    };
    let lit: Vec<Selection> = beside(&[Some(0), None], &[], &unlimited)
        .unwrap()
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    assert_eq!(lit[0].mst.unwrap().slots, 54);
    let alone = beside(&[None, Some(1)], &[], &unlimited).unwrap();
    assert_eq!(alone[0].0.timing.h_active, 1920);
    let added = beside(&[Some(0), Some(1)], &lit, &unlimited).unwrap();
    let shown: Vec<_> = added
        .iter()
        .map(|(s, p)| (s.timing.h_active, s.mst.unwrap().slots, *p))
        .collect();
    assert_eq!(shown, [(1280, 7, 1)]);
    // A hop shared with the running payload: what it leaves bounds the new.
    let pbn = lit[0].mst.unwrap().pbn;
    let shared = |s: Sink, allocated: &[(Sink, u16)]| {
        let used: u16 = allocated.iter().map(|a| a.1).sum();
        if s == sink(2) {
            (pbn + 100).saturating_sub(used)
        } else {
            u16::MAX
        }
    };
    assert_eq!(beside(&[None, Some(1)], &lit, &shared), Some(Vec::new()));
    // Four payloads on the manager already: nothing more.
    let mut four = lit.clone();
    for k in 0..3 {
        let mut s = lit[0];
        s.mst.as_mut().unwrap().slots = 1;
        s.mst.as_mut().unwrap().sink = sink(8 + k);
        four.push(s);
    }
    four[0].mst.as_mut().unwrap().slots = 1;
    assert_eq!(
        beside(&[None, Some(1)], &four, &unlimited),
        Some(Vec::new())
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_mst_selects_new_streams_beside_running_ones
);
