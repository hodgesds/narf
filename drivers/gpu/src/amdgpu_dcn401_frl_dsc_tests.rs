//! HDMI FRL DSC on the HPO FRL stream encoder: the CVTEM packets against
//! Linux's hpo_enc401_hdmi_set_dsc_config, and link_set_dsc_on_stream's
//! order after FRL training and at retirement.
use super::*;
use crate::amdgpu_dcn401_otg::frl::video::cvtem_packets;
use crate::amdgpu_dsc::{DscConfig, FrlDscLink};
use crate::amdgpu_frl_cap::FrlBorrow;

const CVTEM_VECTORS: &str = include_str!("../tests/dcn401_dsc/cvtem_vectors.txt");

/// Every PPS of the FRL DSC vectors, as Linux's hpo_enc401_hdmi_set_dsc_config
/// sends it (cvtem_harness.c): seven packet writes, stale buffer bytes and
/// all.
fn dcn401_frl_cvtem_packets_match_linux() -> TestResult {
    let mut checked = 0;
    for line in CVTEM_VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let (input, want) = line.split_once(" =").expect("vector format");
        let w: alloc::vec::Vec<&str> = input.split_whitespace().collect();
        let n: alloc::vec::Vec<u32> = w[..6].iter().map(|v| v.parse().unwrap()).collect();
        let mut pps = [0u8; 128];
        for (i, b) in pps.iter_mut().enumerate() {
            *b = u8::from_str_radix(&w[6][2 * i..2 * i + 2], 16).unwrap();
        }
        let t = Timing {
            h_active: n[0],
            h_total: n[1],
            h_front_porch: n[2],
            h_sync_width: n[3],
            ..request(1).timing
        };
        let cfg = DscConfig {
            slices_h: n[4],
            slices_v: 1,
            bpp_x16: n[5],
            block_pred: true,
            linebuf_depth: 13,
            version_minor: 2,
            ycbcr422_simple: false,
            frl: Some(FrlDscLink {
                all_bpp: false,
                max_rate: 6,
            }),
            bpc: 8,
        };
        let mut got = alloc::string::String::new();
        for (index, packet) in cvtem_packets(&t, &cfg, &pps) {
            got.push_str(&alloc::format!(" {index}:"));
            for b in packet {
                got.push_str(&alloc::format!("{b:02x}"));
            }
        }
        if got != want {
            panic!("CVTEM {input}\n want{want}\n  got{got}");
        }
        checked += 1;
    }
    if checked < 800 {
        return TestResult::Fail("too few vectors");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_cvtem_packets_match_linux
);

/// A 1080p FRL timing compressed to 8 bpp in two slices.
fn frl_cfg() -> DscConfig {
    DscConfig {
        slices_h: 2,
        slices_v: 10,
        bpp_x16: 128,
        block_pred: true,
        linebuf_depth: 13,
        version_minor: 2,
        ycbcr422_simple: false,
        frl: Some(FrlDscLink {
            all_bpp: false,
            max_rate: 6,
        }),
        bpc: 8,
    }
}

/// The index of the first write to `at` (with `value` under `mask`) after
/// write `from`.
fn write_at(e: &Engine<FrlIo>, from: usize, at: u64, mask: u32, value: u32) -> Option<usize> {
    e.io.inner.writes[from..]
        .iter()
        .position(|&(a, v)| a == at && v & mask == value)
        .map(|i| from + i)
}

/// After FRL training a compressed timing's DSC is started with its video,
/// as link_set_dsc_on_stream does in link_set_dpms_on_post_enable_link: the
/// stream attribute (zero GCP depth, borrow mode and tribyte targets), the
/// DSC engine fed from OPP 1, HDMI_DSC_MODE and the FIFO's compressed
/// format, the CVTEM PPS in generic packets 5-10 (5 again with New
/// cleared), the OPTC's DSC mode with OTG_V_SYNC_MODE, then the InfoFrames
/// and the encoder. A staged FRL timing does not compress before that.
/// Video stop leaves the DSC; retirement turns the OPTC's DSC off, then the
/// HPO DSC mode, then the DSC engine.
fn dcn401_frl_dsc_starts_after_training_and_stops_in_order() -> TestResult {
    let (phy, pipe) = (2u8, 1u8);
    let rate = crate::amdgpu_navi48_boot::FrlRate::new(6).unwrap();
    let cfg = frl_cfg();
    let dsc_at = |r: u64| BASE + (0x3000 + u64::from(pipe) * 0x5c + r) * 4;
    let r = |e: &Engine<FrlIo>, at: u64| e.io.inner.regs.get(&at).copied().unwrap_or(0);
    // A 10-bpc stream compresses at its own depth: the DSC's input depth
    // and the PPS say 10, and the stream attribute still sends no GCP
    // depth.
    let deep = DscConfig { bpc: 10, ..cfg };
    let (mut e, _fw, request, c) =
        prepared_frl_video_dsc(false, ColorDepth::Bpc10, rate, Some(deep));
    if let Err(err) = run(e.start_frl_video(path(phy), request, c)) {
        panic!("10-bpc FRL DSC video: {err:?}");
    }
    let regs = dsc_hw::dsc_registers(&e.status.blanks[1].unwrap().timing.request, &deep).unwrap();
    if regs.pps.bits_per_component != 10
        || r(&e, dsc_at(5)) >> 16 & 0xf != 10
        || r(&e, frl(0x8e0)) & 0x303_0301 != 1 << 24
    {
        return TestResult::Fail("10-bpc FRL DSC input");
    }
    let (mut e, mut fw, mut request, c) =
        prepared_frl_video_dsc(false, ColorDepth::Bpc8, rate, Some(cfg));
    let forward = BASE + (0x1a64 + u64::from(pipe)) * 4;
    let format = e.layout.odm(pipe, 0x1acc);
    let vsync = e.layout.otg(pipe, 0x1b3a);
    // Staged, not compressing: no DSC clocked or forwarded, OPTC DSC off.
    if r(&e, dsc_at(0)) & 1 != 0 || r(&e, forward) & 1 != 0 || r(&e, format) & 0x30 != 0 {
        return TestResult::Fail("FRL DSC before training");
    }
    // Uncompressed-only fields on a compressed stream are its own.
    request.borrow = FrlBorrow::FromActive;
    request.hc_active = 1234;
    request.hc_blank = 180;
    let before = e.io.inner.writes.len();
    if let Err(err) = run(e.start_frl_video(path(phy), request, c)) {
        panic!("FRL DSC video: {err:?}");
    }
    let regs = dsc_hw::dsc_registers(&e.status.blanks[1].unwrap().timing.request, &cfg).unwrap();
    let hpo = |e: &Engine<FrlIo>, reg: u64| r(e, frl(reg));
    if hpo(&e, 0x8e0) & 0x303_0301 != 1 << 24 // DSC 4:4:4, no GCP depth
        || hpo(&e, 0x8d6) & 0x11100 != 0x100
        || hpo(&e, 0x908) & 3 != 1
        || hpo(&e, 0x901) != 1234 | 180 << 16
        || hpo(&e, 0x8e6) & 0x3330_0000 != 0x3330_0000
        || hpo(&e, 0x8e7) & 0x333 != 0x333
        || hpo(&e, 0x8eb) >> 16 & 0x7fff != 2
        || hpo(&e, 0x8ee) & 0x7fff != 2
        || r(&e, dsc_at(0)) & 1 != 1
        || r(&e, forward) & 0x71 != 1 | u32::from(pipe) << 4
        || r(&e, format) & 0x30 != 0x10
        || r(&e, e.layout.odm(pipe, 0x1acd)) != regs.bytes_per_pixel
        || r(&e, vsync) & 0x100 != 0x100
        || e.status.frl_dsc != Some(pipe)
    {
        return TestResult::Fail("FRL DSC programming");
    }
    // Write order: attribute, DSC engine, HPO DSC mode, CVTEM, OPTC DSC,
    // AVI InfoFrame (packet 0), encoder enable.
    let attribute = write_at(&e, before, frl(0x900), 0, 0).unwrap();
    let engine = write_at(&e, attribute, dsc_at(0), 1, 1).unwrap();
    let mode = write_at(&e, engine, frl(0x8e0), 0x300_0000, 1 << 24).unwrap();
    let access = |e: &Engine<FrlIo>, from: usize, index: u32| {
        write_at(e, from, frl(0x931), 0xff, index * 9).unwrap()
    };
    let first = access(&e, mode, 5);
    let optc = write_at(&e, first, format, 0x30, 0x10).unwrap();
    let avi = access(&e, optc, 0);
    let enable = write_at(&e, avi, frl(0x8df), 0x10, 0x10).unwrap();
    if !(attribute < engine
        && engine < mode
        && mode < first
        && first < optc
        && optc < avi
        && avi < enable)
    {
        return TestResult::Fail("FRL DSC order");
    }
    // The seven CVTEM packet writes, word for word.
    let pps = crate::amdgpu_dsc::pack_pps(&regs.pps);
    let t = e.status.blanks[1].unwrap().timing.request.timing;
    let mut at = mode;
    for (index, packet) in cvtem_packets(&t, &cfg, &pps) {
        at = access(&e, at, index);
        let words: alloc::vec::Vec<u32> = e.io.inner.writes[at..]
            .iter()
            .filter(|w| w.0 == frl(0x932))
            .take(9)
            .map(|w| w.1)
            .collect();
        let want: alloc::vec::Vec<u32> = packet
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .collect();
        if words != want {
            return TestResult::Fail("CVTEM packet words");
        }
        at += 1;
    }
    e.frl_video_verify_running(&e.status.frl_video_running.unwrap())
        .unwrap();
    // Drift in a DSC field or a CVTEM packet's schedule is caught live.
    for (reg, bit) in [(0x8e0, 1 << 24), (0x8d6, 0x100), (0x8e7, 0x200)] {
        *e.io.inner.regs.get_mut(&frl(reg)).unwrap() ^= bit;
        assert_eq!(
            e.frl_video_verify_running(&e.status.frl_video_running.unwrap()),
            Err(Error::Readback(frl(reg)))
        );
        *e.io.inner.regs.get_mut(&frl(reg)).unwrap() ^= bit;
    }
    // Video stop: packets off; the DSC stays until the timing retires.
    run(e.stop_frl_video(path(phy))).unwrap();
    if hpo(&e, 0x8e6) != 0 || hpo(&e, 0x8e7) != 0 || r(&e, dsc_at(0)) & 1 != 1 {
        return TestResult::Fail("FRL DSC video stop");
    }
    run(e.stop_frl_link(&mut fw, path(phy))).unwrap();
    let before = e.io.inner.writes.len();
    e.io.inner.retiring = [true; 4];
    run(e.retire(pipe)).unwrap();
    let optc_off = write_at(&e, before, format, 0x30, 0).unwrap();
    let vsync_off = write_at(&e, before, vsync, 0x100, 0).unwrap();
    let hpo_off = write_at(&e, before, frl(0x8d6), 0x10100, 0).unwrap();
    let mode_off = write_at(&e, before, frl(0x8e0), 0x300_0000, 0).unwrap();
    let disconnect = write_at(&e, before, forward, 1, 0).unwrap();
    let disable = write_at(&e, before, dsc_at(0), 1, 0).unwrap();
    if !(optc_off < vsync_off
        && vsync_off < hpo_off
        && hpo_off < mode_off
        && mode_off < disconnect
        && disconnect < disable)
        || e.status.frl_dsc.is_some()
        || hpo(&e, 0x8e0) & 0x300_0000 != 0
        || hpo(&e, 0x8d6) & 0x10100 != 0
    {
        return TestResult::Fail("FRL DSC retirement order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_dsc_starts_after_training_and_stops_in_order
);

/// An uncompressed FRL stream takes no tribyte targets or active
/// borrowing; a DSC configuration must say whether it is HDMI FRL's.
fn dcn401_frl_dsc_requests_are_validated() -> TestResult {
    let rate = crate::amdgpu_navi48_boot::FrlRate::new(6).unwrap();
    for bad in [
        |r: &mut FrlVideoRequest| r.hc_active = 1,
        |r: &mut FrlVideoRequest| r.hc_blank = 1,
        |r: &mut FrlVideoRequest| r.borrow = FrlBorrow::FromActive,
    ] {
        let (mut e, _fw, mut request, c) = prepared_frl_video_rate(false, ColorDepth::Bpc8, rate);
        bad(&mut request);
        assert_eq!(
            run(e.start_frl_video(path(2), request, c)),
            Err(Error::Invalid)
        );
    }
    // A DP DSC configuration on an FRL timing, or an FRL one on DP.
    let mut req = request(1);
    req.signal = Signal::HdmiFrl;
    req.dsc = Some(DscConfig {
        frl: None,
        ..frl_cfg()
    });
    assert_eq!(
        dsc_hw::dsc_registers(&req, &req.dsc.unwrap()),
        Err(Error::Unsupported)
    );
    req.signal = Signal::DisplayPort;
    assert_eq!(
        dsc_hw::dsc_registers(&req, &frl_cfg()),
        Err(Error::Unsupported)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_dsc_requests_are_validated
);
