use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

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
        sink: Ok(display::Sink { dpcd, edid }),
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
        || (s.lanes, s.rate) != (4, LinkRate::Hbr2)
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

fn navi48_modeset_reads_hdmi_audio_like_amdgpu_dm() -> TestResult {
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
    let Some(info) = hdmi_audio_info(&edid) else {
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
    let plain = hdmi_audio_info(&with_blocks(base.clone(), &[AUDIO])).unwrap();
    if plain.speakers != 5 || hdmi_audio_info(&with_blocks(base, &[VSDB])).is_some() {
        return TestResult::Fail("defaults");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-modeset",
    navi48_modeset_reads_hdmi_audio_like_amdgpu_dm
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
