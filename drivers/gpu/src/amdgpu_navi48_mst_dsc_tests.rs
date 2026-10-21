use super::*;
use crate::amdgpu_dsc::LinkEncoding;
use crate::dp_mst_mgr::tests::Hub;
use alloc::collections::BTreeMap;
use narf_kernel_test::{kernel_test_in, TestResult};

fn run<T>(f: impl core::future::Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

/// DSC 1.2 decoder caps (0x060..0x06f): 1-12 slices, 8-12 bpc RGB/YCbCr,
/// 1/16 bpp increments.
const DECODER: [u8; 16] = [
    0x01, 0x21, 0x0b, 0x0f, 0x7f, 0x03, 0x01, 0x00, 0x00, 0x1f, 0x0e, 0x88, 0x10, 0x00, 0x00, 0x00,
];
const ROOT_SINK: Sink = Sink { branch: 0, port: 1 };
const CHILD_SINK: Sink = Sink { branch: 1, port: 1 };
const CHILD_PORT: Sink = Sink { branch: 0, port: 2 };

fn decoder(fec: bool) -> BTreeMap<u32, u8> {
    let mut d: BTreeMap<u32, u8> = (0..16).map(|i| (0x60 + i, DECODER[i as usize])).collect();
    d.insert(0x90, u8::from(fec));
    d
}

fn probed(hub: &mut Hub) -> (Manager, Topology) {
    let mut mgr = Manager::new();
    let topology = run(mgr.probe(hub)).unwrap();
    hub.requests.clear();
    (mgr, topology)
}

/// drm_dp_mst_dsc_aux_for_port: an end device with DSC and FEC decodes in
/// its own DPCD; one without FEC, or behind a hub that answers no remote
/// DPCD, has no DSC; a Synaptics primary branch with a DPCD 1.4 decoder and
/// a non-VGA downstream port decodes for its ports (DSC without virtual
/// DPCD).
fn navi48_mst_dsc_aux_for_port_like_drm() -> TestResult {
    let mut hub = Hub::new();
    let (mut mgr, topology) = probed(&mut hub);
    if run(dsc_aux_for_port(&mut mgr, &mut hub, &topology, ROOT_SINK)).is_some() {
        return TestResult::Fail("no remote DPCD");
    }
    hub.remote.insert((1, 1), decoder(false));
    if run(dsc_aux_for_port(&mut mgr, &mut hub, &topology, ROOT_SINK)).is_some() {
        return TestResult::Fail("DSC without FEC");
    }
    hub.remote.insert((1, 1), decoder(true));
    hub.remote.insert((2, 1), decoder(true));
    // The child's DSC is found only once its upstream port's DPCD
    // (drm_dp_read_desc through it) answers.
    if run(dsc_aux_for_port(&mut mgr, &mut hub, &topology, CHILD_SINK)).is_some() {
        return TestResult::Fail("unreadable upstream branch");
    }
    hub.remote.insert((1, 2), BTreeMap::new());
    for sink in [ROOT_SINK, CHILD_SINK] {
        if run(dsc_aux_for_port(&mut mgr, &mut hub, &topology, sink))
            != Some((DscAux::Port(sink), None))
        {
            return TestResult::Fail("end device decoder");
        }
    }
    // A Synaptics primary branch decodes for its own ports.
    for (i, b) in [0x90, 0xcc, 0x24].into_iter().enumerate() {
        hub.dpcd.insert(0x500 + i as u32, b);
    }
    hub.dpcd.insert(0x60, 1);
    hub.dpcd.insert(0, 0x14);
    hub.dpcd.insert(5, 1 | 2 << 1);
    if run(dsc_aux_for_port(&mut mgr, &mut hub, &topology, ROOT_SINK)) != Some((DscAux::Root, None))
    {
        return TestResult::Fail("Synaptics root decoder");
    }
    // A VGA downstream port leaves decoding to the end device.
    hub.dpcd.insert(5, 1 | 1 << 1);
    if run(dsc_aux_for_port(&mut mgr, &mut hub, &topology, ROOT_SINK))
        != Some((DscAux::Port(ROOT_SINK), None))
    {
        return TestResult::Fail("Synaptics VGA branch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_aux_for_port_like_drm
);

/// A DPCD 1.4 DP-to-DP peer (a two-port branch with an SST sink) has
/// virtual DPCD: an end device that decodes with FEC behind a passthrough
/// peer is enabled through itself and the peer (passthrough first on
/// enable, decoder first on disable, as dm_helpers_dp_write_dsc_enable),
/// otherwise the peer's virtual DPCD decodes.
fn navi48_mst_dsc_virtual_dpcd_passthrough_order() -> TestResult {
    let mut hub = Hub::new();
    hub.port_rev = 0x14;
    let (mut mgr, mut topology) = probed(&mut hub);
    if is_virtual_dpcd(&topology, CHILD_PORT) {
        return TestResult::Fail("three-port branch is not DP-to-DP");
    }
    topology.branches[1].ports.retain(|p| p.info.port != 2);
    if !is_virtual_dpcd(&topology, CHILD_PORT) || is_virtual_dpcd(&topology, ROOT_SINK) {
        return TestResult::Fail("DP-to-DP peer");
    }
    hub.remote.insert((2, 1), decoder(true));
    let mut peer = decoder(true);
    peer.insert(0x60, 1);
    hub.remote.insert((1, 2), peer);
    let at = run(dsc_aux_for_port(&mut mgr, &mut hub, &topology, CHILD_SINK));
    if at != Some((DscAux::Port(CHILD_PORT), None)) {
        panic!("no passthrough {at:?}");
    }
    hub.remote.get_mut(&(1, 2)).unwrap().insert(0x60, 3);
    let at = run(dsc_aux_for_port(&mut mgr, &mut hub, &topology, CHILD_SINK));
    if at != Some((DscAux::Port(CHILD_SINK), Some(CHILD_PORT))) {
        panic!("passthrough {at:?}");
    }
    hub.remote
        .get_mut(&(2, 1))
        .unwrap()
        .extend([(0x100, 0x14), (0x101, 0x84), (0x108, 1)]);
    let Some(dsc) = run(read_dsc(&mut mgr, &mut hub, &topology, CHILD_SINK)) else {
        return TestResult::Fail("read_dsc");
    };
    // HBR2 x4 at 8b/10b FEC efficiency.
    if dsc.end_link_kbps != 5_400_000 * 4 / 10_000 * 7760
        || dsc.aux != DscAux::Port(CHILD_SINK)
        || dsc.passthrough != Some(CHILD_PORT)
        || dsc.caps.max_slice_width != 5120
    {
        panic!("decoder {dsc:?}");
    }
    hub.remote_writes.clear();
    run(set_rx(&mut mgr, &mut hub, &topology, &dsc, true)).unwrap();
    if !run(rx_enabled(&mut mgr, &mut hub, &topology, &dsc)).unwrap() {
        return TestResult::Fail("decoder enabled");
    }
    run(set_rx(&mut mgr, &mut hub, &topology, &dsc, false)).unwrap();
    let writes: Vec<_> = hub
        .remote_writes
        .iter()
        .map(|(lct, port, at, b)| (*lct, *port, *at, b[0]))
        .collect();
    if writes
        != [
            (1, 2, 0x160, 2),
            (2, 1, 0x160, 1),
            (2, 1, 0x160, 0),
            (1, 2, 0x160, 0),
        ]
    {
        panic!("DSC_ENABLE order {writes:?}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_virtual_dpcd_passthrough_order
);

const fn timing(khz: u32, ha: u32, ht: u32, va: u32, vt: u32) -> Timing {
    Timing {
        pixel_clock_khz: khz,
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
    }
}
/// 3840x2160@144 CVT-RBv2 and 1920x1080@60.
const UHD144: Timing = timing(1_254_282, 3840, 3920, 2160, 2222);
const FHD60: Timing = timing(148_500, 1920, 2200, 1080, 1125);
const HBR3X4: DscLink = DscLink {
    encoding: LinkEncoding::Dp8b10b,
    kbps: 25_142_400,
    slots: 63,
    max_dispclk_khz: 2_000_000,
};

fn caps() -> Option<DscSinkCaps> {
    DscSinkCaps::parse(&DECODER, &[0; 3])
}

/// compute_mst_dsc_configs_for_link on the native pipeline: two 4K144
/// sinks behind one HBR3 x4 branch need DSC and share the link fairly
/// (within one bpp of each other, inside the link's 63 slots); a 4K144 decoder beside a 1080p60
/// sink without DSC is the only compressed stream; two 4K144 sinks of
/// which only one decodes do not fit; and a fit that needs no compression
/// leaves both streams uncompressed.
fn navi48_mst_dsc_fairness_policy_matrix() -> TestResult {
    let fits = |a: &[(Sink, u16)]| a.iter().all(|&(_, pbn)| pbn <= 2560);
    let s = |port, timing, dsc| DscStream {
        sink: Sink { branch: 0, port },
        timing,
        dsc,
        bpc: 8,
    };
    let two = [s(1, UHD144, caps()), s(2, UHD144, caps())];
    let Some(p) = compute(&two, &HBR3X4, &fits) else {
        return TestResult::Fail("two 4K144 DSC sinks");
    };
    let (Some(a), Some(b)) = (p[0].dsc, p[1].dsc) else {
        return TestResult::Fail("both compressed");
    };
    // Linux spreads the leftover slack smallest-first, so the shares
    // need not be equal.
    if a.bpp_x16.min(b.bpp_x16) < 8 * 16
        || a.bpp_x16.abs_diff(b.bpp_x16) > 16
        || p.iter().map(|p| u32::from(p.slots)).sum::<u32>() > 63
    {
        panic!("fair share {p:?}");
    }
    let mixed = [s(1, UHD144, caps()), s(2, FHD60, None)];
    let Some(p) = compute(&mixed, &HBR3X4, &fits) else {
        return TestResult::Fail("one compressed stream");
    };
    if p[0].dsc.is_none() || p[1].dsc.is_some() {
        panic!("single compressed {p:?}");
    }
    let one = [s(1, UHD144, caps()), s(2, UHD144, None)];
    if compute(&one, &HBR3X4, &fits).is_some() {
        return TestResult::Fail("raw 4K144 beside a compressed one");
    }
    let small = [s(1, FHD60, caps()), s(2, FHD60, caps())];
    match compute(&small, &HBR3X4, &fits) {
        Some(p) if p.iter().all(|p| p.dsc.is_none()) => {}
        other => panic!("uncompressed fit {other:?}"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_fairness_policy_matrix
);

/// dm_dp_mst_is_port_support_mode: a mode the port's full PBN carries is
/// supported; 4K144 needs a decoder whose compressed minimum fits the link,
/// and a last link (non-Synaptics) too slow for it raw refuses it.
fn navi48_mst_dsc_port_support_mode_like_amdgpu_dm() -> TestResult {
    let mut hub = Hub::new();
    let (_, topology) = probed(&mut hub);
    let mut dsc = MstDsc {
        caps: caps().unwrap(),
        aux: DscAux::Port(ROOT_SINK),
        passthrough: None,
        end_link_kbps: 0,
        branch_oui: 0,
    };
    if !port_supports_mode(&FHD60, 8, &topology, ROOT_SINK, None, &HBR3X4)
        || port_supports_mode(&UHD144, 8, &topology, ROOT_SINK, None, &HBR3X4)
        || !port_supports_mode(&UHD144, 8, &topology, ROOT_SINK, Some(&dsc), &HBR3X4)
    {
        return TestResult::Fail("decoder admission");
    }
    // An HBR2 x4 last link cannot carry 4K144 raw.
    dsc.end_link_kbps = 5_400_000 * 4 / 10_000 * 7760;
    if port_supports_mode(&UHD144, 8, &topology, ROOT_SINK, Some(&dsc), &HBR3X4) {
        return TestResult::Fail("slow last link");
    }
    dsc.branch_oui = OUI_SYNAPTICS;
    if !port_supports_mode(&UHD144, 8, &topology, ROOT_SINK, Some(&dsc), &HBR3X4) {
        return TestResult::Fail("Synaptics last link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_port_support_mode_like_amdgpu_dm
);

/// compute_mst_dsc_configs_for_link across a daisy chain: the child's and
/// the grandchild's 4K144 decoders both sit behind the primary branch's
/// port 2, so the fairness search admits them only while their joint PBN
/// fits that hop (drm_dp_mst_atomic_check's per-port bandwidth, here the
/// topology's path budget), beside an uncompressed 1080p60 on the
/// primary's own sink. A tighter shared hop lowers both streams' bpp
/// together and keeps them within one bpp of each other; one too small for
/// both at the minimum bpp refuses the pair.
fn navi48_mst_dsc_fairness_spans_cascaded_branches() -> TestResult {
    use super::super::topology::path_budget;
    let mut hub = Hub::new();
    hub.grandchild_present = true;
    let grand = Sink { branch: 2, port: 1 };
    let solve = |hub: &mut Hub| {
        let (_, topology) = probed(hub);
        let fits = |alloc: &[(Sink, u16)]| {
            alloc.iter().enumerate().all(|(i, &(sink, pbn))| {
                let others: Vec<_> = alloc
                    .iter()
                    .enumerate()
                    .filter(|&(j, _)| j != i)
                    .map(|(_, &a)| a)
                    .collect();
                path_budget(&topology, sink, &others).is_some_and(|free| pbn <= free)
            })
        };
        let streams = [
            DscStream {
                sink: ROOT_SINK,
                timing: FHD60,
                dsc: None,
                bpc: 8,
            },
            DscStream {
                sink: CHILD_SINK,
                timing: UHD144,
                dsc: caps(),
                bpc: 8,
            },
            DscStream {
                sink: grand,
                timing: UHD144,
                dsc: caps(),
                bpc: 8,
            },
        ];
        // 4 x UHBR10: two raw 4K144 streams do not fit, compressed they do.
        let link = DscLink {
            encoding: LinkEncoding::Dp128b132b,
            kbps: 38_564_000,
            slots: 64,
            max_dispclk_khz: 2_000_000,
        };
        compute(&streams, &link, &fits)
    };
    hub.resources.insert((1, 2), (6000, 6000));
    let wide = solve(&mut hub).expect("roomy shared hop");
    hub.resources.insert((1, 2), (3300, 3300));
    let tight = solve(&mut hub).expect("tight shared hop");
    for p in [&wide, &tight] {
        assert!(p[0].dsc.is_none(), "{p:?}");
        let (Some(a), Some(b)) = (p[1].dsc, p[2].dsc) else {
            panic!("both chained decoders compress {p:?}");
        };
        assert!(a.bpp_x16.abs_diff(b.bpp_x16) <= 16, "{p:?}");
        assert!(p.iter().map(|p| u32::from(p.slots)).sum::<u32>() <= 64);
    }
    assert!(u32::from(tight[1].pbn) + u32::from(tight[2].pbn) <= 3300);
    let bpp = |p: &[DscPayload]| p[1].dsc.unwrap().bpp_x16 + p[2].dsc.unwrap().bpp_x16;
    assert!(bpp(&tight) < bpp(&wide), "{tight:?} vs {wide:?}");
    hub.resources.insert((1, 2), (2000, 2000));
    assert!(solve(&mut hub).is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_fairness_spans_cascaded_branches
);

/// An EDID 1.4 block whose digital input declares `code` (3: 10 bpc) and
/// whose detailed timing is 3840x2160@60 (594 MHz).
fn uhd60_edid(code: u8) -> Vec<u8> {
    let mut e = alloc::vec![0u8; 128];
    e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    e[8..10].copy_from_slice(&[0x10, 0xac]);
    (e[18], e[19], e[20]) = (1, 4, 0x80 | code << 4 | 5);
    e[54..72].copy_from_slice(&[
        0x08, 0xe8, 0x00, 0x30, 0xf2, 0x70, 0x5a, 0x80, 0xb0, 0x58, 0x8a, 0, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[127] = narf_edid::compute_checksum(&e);
    e
}

/// An MST stream at its deepest depth, as amdgpu_dm validates each depth
/// with dm_dp_mst_is_port_support_mode and the link's fairness search: a
/// 10-bpc 4K60 sink behind a 2 x HBR2 branch link (8,380,800 kbps with
/// FEC) is compressed from 10 bpc when max_bpc is 10, its PBN and DSC the
/// fairness search's for a 10-bpc stream; at max_bpc 8, or with a decoder
/// that takes only 8-bpc input, it is compressed from 8 bpc.
fn navi48_mst_dsc_streams_take_the_deepest_depth() -> TestResult {
    let mut hub = Hub::new();
    let (_, topology) = probed(&mut hub);
    let caps = modeset::DpCaps {
        lanes: 2,
        rate: crate::dp_link_training::LinkRate::Hbr2,
        uhbr: 0,
        fec: true,
        dsc: None,
    };
    let devices = [(ROOT_SINK, uhd60_edid(3), u16::MAX)];
    let budget = |_: Sink, _: &[(Sink, u16)]| u16::MAX;
    let pick = |decoder: [u8; 16], max_bpc: u8| {
        let mst = MstDsc {
            caps: DscSinkCaps::parse(&decoder, &[0; 3]).unwrap(),
            aux: DscAux::Port(ROOT_SINK),
            passthrough: None,
            end_link_kbps: 0,
            branch_oui: 0,
        };
        let dsc_of = |s: Sink| (s == ROOT_SINK).then_some(mst);
        let max_bpc = |_: Sink| max_bpc;
        let ctx = MstDscContext {
            topology: &topology,
            dsc_of: &dsc_of,
            max_dispclk_khz: 2_000_000,
            max_bpc: &max_bpc,
        };
        super::super::select_mst_dsc(0, caps, &devices, &|_| None, &budget, &ctx, &[]).unwrap()
    };
    let link = super::super::dsc_link(caps, 2_000_000).unwrap();
    let want = |decoder: [u8; 16], bpc: u8| {
        let stream = DscStream {
            sink: ROOT_SINK,
            timing: modeset::edid_timings(&devices[0].1)[0],
            dsc: DscSinkCaps::parse(&decoder, &[0; 3]),
            bpc,
        };
        compute(&[stream], &link, &|_| true).unwrap()[0]
    };
    let mut eight = DECODER;
    eight[10] = 0x02;
    for (decoder, max_bpc, bpc, depth) in [
        (DECODER, 10, 10, otg::ColorDepth::Bpc10),
        (DECODER, 8, 8, otg::ColorDepth::Bpc8),
        (eight, 10, 8, otg::ColorDepth::Bpc8),
    ] {
        let s = pick(decoder, max_bpc);
        let w = want(decoder, bpc);
        let [s] = s.as_slice() else {
            panic!("one stream at max_bpc {max_bpc}: {s:?}");
        };
        if s.depth != depth
            || s.dsc.map(|c| c.bpc) != Some(bpc)
            || s.dsc != w.dsc
            || s.mst.map(|m| (m.pbn, m.slots)) != Some((w.pbn, w.slots))
        {
            panic!("{bpc}-bpc MST DSC: {s:?} want {w:?}");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_streams_take_the_deepest_depth
);

/// Uncompressed MST deep color on a link without DSC decoders, as
/// amdgpu_dm runs it: a 10-bpc 4K60 sink behind a 4 x HBR3 branch link
/// (25,920,000 kbps) streams at 10 bpc when its connector asks for 10 or
/// 16, its payload dm_encoder_helper_atomic_check's drm_dp_calc_pbn_mode
/// (594,000 kHz, 30 bpp) = 2656 PBN in DIV_ROUND_UP(2656 << 12, 245,760) =
/// 45 slots and its VC rate 17,820,000 kbps' PBN 2640 over 60 PBN per slot
/// = exactly 44 slots per MTP; at 8 it streams at 8 bpc in 2125 PBN (36
/// slots). Behind a port of 2400 full PBN (16,102,800 kbps end to end) the
/// 10-bpc stream (17,820,000 kbps) steps down to 8 bpc
/// (dm_dp_mst_is_port_support_mode) but its PBN stays sized for the
/// requested 10 bpc, which the port cannot hold: the mode is refused until
/// the connector asks for 8.
fn navi48_mst_raw_streams_run_deep_color() -> TestResult {
    let caps = modeset::DpCaps {
        lanes: 4,
        rate: crate::dp_link_training::LinkRate::Hbr3,
        uhbr: 0,
        fec: false,
        dsc: None,
    };
    let edid = uhd60_edid(3);
    let pick = |full: u16, max: u8| {
        let mut hub = Hub::new();
        hub.resources.insert((1, 1), (full, full - 10));
        let (_, topology) = probed(&mut hub);
        assert_eq!(topology.port(ROOT_SINK).map(|p| p.full_pbn), Some(full));
        let devices = [(ROOT_SINK, edid.clone(), full - 10)];
        let budget = |_: Sink, _: &[(Sink, u16)]| u16::MAX;
        let dsc_of = |_: Sink| -> Option<MstDsc> { None };
        let max_bpc = |_: Sink| max;
        let ctx = MstDscContext {
            topology: &topology,
            dsc_of: &dsc_of,
            max_dispclk_khz: 2_000_000,
            max_bpc: &max_bpc,
        };
        let t = modeset::edid_timings(&edid)[0];
        let raw = super::super::raw_mst_stream(&t, &edid, caps, Some((ROOT_SINK, &ctx)));
        let lit = super::super::select_mst_outputs_with(
            0,
            caps,
            &devices,
            &|_| None,
            &[Some(0)],
            &budget,
            Some(&ctx),
        );
        let lit = lit.first().map(|(s, _)| {
            (
                s.depth,
                s.timing,
                s.mst.map(|m| (m.pbn, m.slots, m.pbn_bpc, m.rate)),
            )
        });
        (t, raw, lit)
    };
    use otg::ColorDepth::{Bpc10, Bpc8};
    let raw = |bpc, pbn_bpc, pbn, slots| {
        Some(super::super::RawMstStream {
            bpc,
            pbn_bpc,
            pbn,
            slots,
        })
    };
    let (t, r, lit) = pick(4000, 10);
    if t.pixel_clock_khz != 594_000
        || r != raw(10, 10, 2656, 45)
        || lit != Some((Bpc10, t, Some((2656, 45, 10, (44, 0)))))
    {
        panic!("10-bpc MST stream: {r:?} {lit:?}");
    }
    if pick(4000, 16).2 != lit {
        return TestResult::Fail("max bpc 16");
    }
    let rate8 = super::super::mst_vc_rate(&t, 8, 4, DpRate::Legacy(caps.rate), false);
    let (_, r, lit) = pick(4000, 8);
    if r != raw(8, 8, 2125, 36) || lit != Some((Bpc8, t, Some((2125, 36, 8, rate8.unwrap())))) {
        panic!("8-bpc MST stream: {r:?} {lit:?}");
    }
    // Stepped down, its PBN still the requested depth's.
    let (_, r, lit) = pick(2400, 10);
    if r != raw(8, 10, 2656, 45) || lit.is_some() {
        panic!("stepped-down MST stream: {r:?} {lit:?}");
    }
    let (_, r, lit) = pick(2400, 8);
    if r != raw(8, 8, 2125, 36) || lit.map(|l| l.0) != Some(Bpc8) {
        panic!("8 bpc behind a narrow port: {r:?} {lit:?}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_raw_streams_run_deep_color
);

const RAW_VECTORS: &str = include_str!("../tests/dcn401_dsc/mst_raw_vectors.txt");

/// mst_raw_vectors.txt (mst_harness.c built with RAW_DEPTH): Linux's
/// uncompressed MST stream depth (create_validate_stream_for_sink's mask
/// with dm_dp_mst_is_port_support_mode) and its PBN and slots
/// (dm_encoder_helper_atomic_check's drm_dp_calc_pbn_mode at
/// convert_color_depth_from_display_info of max_requested_bpc), through
/// `raw_mst_choice`; a stream no depth carries, or whose slots exceed the
/// link's, is none.
fn navi48_mst_raw_depth_matches_linux_vectors() -> TestResult {
    let (mut checked, mut carried, mut stepped) = (0, 0, 0);
    for line in RAW_VECTORS
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let Some((input, want)) = line.split_once(" = ") else {
            return TestResult::Fail("vector line");
        };
        let i: Vec<u32> = input
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        let w: Vec<u32> = want
            .split_whitespace()
            .filter_map(|v| v.parse().ok())
            .collect();
        let ([enc, kbps, edid_bpc, requested, pix, ha, ht, va, vt, full], [bpc, pbn, slots]) =
            (i.as_slice(), w.as_slice())
        else {
            return TestResult::Fail("vector fields");
        };
        let code = match edid_bpc {
            0 => 0,
            8 => 2,
            10 => 3,
            12 => 4,
            14 => 5,
            16 => 6,
            _ => return TestResult::Fail("vector EDID depth"),
        };
        let link = DscLink {
            encoding: if *enc == 1 {
                LinkEncoding::Dp128b132b
            } else {
                LinkEncoding::Dp8b10b
            },
            kbps: *kbps,
            slots: if *enc == 1 { 64 } else { 63 },
            max_dispclk_khz: 2_000_000,
        };
        let t = timing(pix / 10, *ha, *ht, *va, *vt);
        let got = super::super::raw_mst_choice(
            &t,
            &uhd60_edid(code),
            *requested as u8,
            *full as u16,
            &link,
        );
        let expect = (*bpc != 0 && *slots <= u32::from(link.slots)).then_some((*bpc, *pbn, *slots));
        if got.map(|r| (u32::from(r.bpc), u32::from(r.pbn), u32::from(r.slots))) != expect {
            panic!("{input}: {got:?} want {expect:?}");
        }
        checked += 1;
        if let Some(r) = got {
            carried += 1;
            stepped += usize::from(r.bpc < r.pbn_bpc);
        }
    }
    if checked < 1400 || carried < 500 || stepped < 20 {
        panic!("raw vector coverage: {checked} {carried} {stepped}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_raw_depth_matches_linux_vectors
);

/// `uhd60_edid` with a 1920x1080@60 (148.5 MHz) detailed timing instead.
fn fhd60_edid() -> Vec<u8> {
    let mut e = uhd60_edid(3);
    e[54..72].copy_from_slice(&[
        0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c, 0x45, 0, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[127] = 0;
    e[127] = narf_edid::compute_checksum(&e);
    e
}

/// A stream added or removed on a link whose end devices decode DSC, as
/// amdgpu_dm handles it: the link's fairness search runs again over every
/// stream, the running ones first (is_dsc_need_re_compute,
/// compute_mst_dsc_configs_for_link), and Linux modesets each stream whose
/// configuration that changes. A 1080p60 beside an uncompressed 4K60 on 4
/// x HBR3 leaves the 4K stream as it runs: the new stream is selected
/// alone. A second 4K60 on 4 x HBR2 would compress the running one: the
/// addition is refused for a relight. Removing one of two compressed 4K
/// streams changes the other (it would run uncompressed alone), so the
/// removal relights; with both still running nothing changes.
fn navi48_mst_dsc_beside_running_streams_like_amdgpu_dm() -> TestResult {
    let mut hub = Hub::new();
    let (_, topology) = probed(&mut hub);
    let mst = MstDsc {
        caps: DscSinkCaps::parse(&DECODER, &[0; 3]).unwrap(),
        aux: DscAux::Port(ROOT_SINK),
        passthrough: None,
        end_link_kbps: 0,
        branch_oui: 0,
    };
    let dsc_of = |s: Sink| (s == ROOT_SINK || s == CHILD_SINK).then_some(mst);
    let max_bpc = |_: Sink| 8;
    let ctx = MstDscContext {
        topology: &topology,
        dsc_of: &dsc_of,
        max_dispclk_khz: 2_000_000,
        max_bpc: &max_bpc,
    };
    let budget = |_: Sink, _: &[(Sink, u16)]| u16::MAX;
    let caps = |rate| modeset::DpCaps {
        lanes: 4,
        rate,
        uhbr: 0,
        fec: true,
        dsc: None,
    };
    let select = |caps,
                  devices: &[(Sink, Vec<u8>, u16)],
                  pipes: &[Option<u8>],
                  lit: &[modeset::Selection]| {
        super::super::select_mst_outputs_beside(
            0,
            caps,
            devices,
            &|_| None,
            pipes,
            &budget,
            Some(&ctx),
            lit,
        )
    };
    use crate::dp_link_training::LinkRate::{Hbr2, Hbr3};
    // 4 x HBR3: the 4K60 runs uncompressed; a 1080p60 fits beside it.
    let small = [
        (ROOT_SINK, uhd60_edid(3), u16::MAX),
        (CHILD_SINK, fhd60_edid(), u16::MAX),
    ];
    let lit: Vec<modeset::Selection> = select(caps(Hbr3), &small, &[Some(0), None], &[])
        .unwrap()
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    assert!(lit.len() == 1 && lit[0].dsc.is_none(), "{lit:?}");
    let added = select(caps(Hbr3), &small, &[None, Some(1)], &lit).expect("kept");
    let [(b, 1)] = added.as_slice() else {
        panic!("one new stream {added:?}");
    };
    assert_eq!(b.mst.map(|m| m.sink), Some(CHILD_SINK));
    assert!(b.dsc.is_none());
    // The running stream is not selected again, even when asked.
    let again = select(caps(Hbr3), &small, &[Some(0), Some(1)], &lit).unwrap();
    assert_eq!(again.iter().map(|a| a.1).collect::<Vec<_>>(), [1]);
    // 4 x HBR2: two 4K60 streams fit only compressed.
    let big = [
        (ROOT_SINK, uhd60_edid(3), u16::MAX),
        (CHILD_SINK, uhd60_edid(3), u16::MAX),
    ];
    let alone: Vec<modeset::Selection> = select(caps(Hbr2), &big, &[Some(0), None], &[])
        .unwrap()
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    assert!(alone.len() == 1 && alone[0].dsc.is_none(), "{alone:?}");
    assert_eq!(
        select(caps(Hbr2), &big, &[None, Some(1)], &alone),
        Err(super::super::BesideRefusal::DscFairness)
    );
    let joint: Vec<modeset::Selection> = select(caps(Hbr2), &big, &[Some(0), Some(1)], &[])
        .unwrap()
        .into_iter()
        .map(|(s, _)| s)
        .collect();
    assert!(
        joint.len() == 2 && joint.iter().all(|s| s.dsc.is_some()),
        "{joint:?}"
    );
    assert_eq!(
        select(caps(Hbr2), &big, &[None, None], &joint),
        Ok(Vec::new())
    );
    assert_eq!(
        select(caps(Hbr2), &big, &[None, None], &joint[..1]),
        Err(super::super::BesideRefusal::DscFairness)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_beside_running_streams_like_amdgpu_dm
);

/// `uhd60_edid` with a 2560x1440@60 (241.5 MHz) detailed timing instead.
fn qhd60_edid() -> Vec<u8> {
    let mut e = uhd60_edid(3);
    e[54..72].copy_from_slice(&[
        0x56, 0x5e, 0x00, 0xa0, 0xa0, 0xa0, 0x29, 0x50, 0x30, 0x20, 0x35, 0, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[127] = 0;
    e[127] = narf_edid::compute_checksum(&e);
    e
}

/// The affected-stream search and the lighting after it walk one order:
/// for every assignment of 4K60/1440p60/1080p60 EDIDs to three cascaded
/// end devices, the first two or all three decoding DSC, every set of
/// running streams and every set joining them on 2 x HBR3 and 4 x HBR,
/// HBR2 and HBR3, the streams `affected_mst_streams`
/// keeps run on when the others (the affected and the joining) light
/// beside them (`select_mst_outputs_beside`), which then reproduces the
/// search's configuration for each: the partial relight never falls back
/// to a full one because the two searched the link's streams in
/// different orders. (Searching the running streams first, as the lighting
/// did, refuses 2 x HBR3 4K60, 4K60, 1440p60 with decoders on the first
/// two, the last two running and the first joining: the search modesets
/// the third, the lighting then changes the second.)
fn navi48_mst_dsc_affected_relight_keeps_the_search_order() -> TestResult {
    let mut hub = Hub::new();
    hub.grandchild_present = true;
    let (_, topology) = probed(&mut hub);
    let sinks = topology.sinks();
    assert_eq!(sinks.len(), 3);
    let mst = MstDsc {
        caps: DscSinkCaps::parse(&DECODER, &[0; 3]).unwrap(),
        aux: DscAux::Port(ROOT_SINK),
        passthrough: None,
        end_link_kbps: 0,
        branch_oui: 0,
    };
    let max_bpc = |_: Sink| 8;
    let budget = |_: Sink, _: &[(Sink, u16)]| u16::MAX;
    use crate::dp_link_training::LinkRate::{Hbr, Hbr2, Hbr3};
    let edids = [uhd60_edid(3), qhd60_edid(), fhd60_edid()];
    let mut partial = 0;
    // Decoders on the first two devices, or all three.
    for decoders in [0b011usize, 0b111] {
        let dsc_of = |s: Sink| {
            sinks
                .iter()
                .position(|&x| x == s)
                .filter(|&k| decoders >> k & 1 != 0)
                .map(|_| mst)
        };
        let ctx = MstDscContext {
            topology: &topology,
            dsc_of: &dsc_of,
            max_dispclk_khz: 2_000_000,
            max_bpc: &max_bpc,
        };
        for (lanes, rate) in [(2, Hbr3), (4, Hbr), (4, Hbr2), (4, Hbr3)] {
            let caps = modeset::DpCaps {
                lanes,
                rate,
                uhbr: 0,
                fec: true,
                dsc: None,
            };
            for pick in 0..27usize {
                let devices: Vec<(Sink, Vec<u8>, u16)> = sinks
                    .iter()
                    .enumerate()
                    .map(|(k, &sink)| {
                        let e = (pick / [1, 3, 9][k]) % 3;
                        (sink, edids[e].clone(), u16::MAX)
                    })
                    .collect();
                for running_set in 1..8usize {
                    // Device k's CRTC is k.
                    let crtcs: Vec<Option<u8>> = (0..3)
                        .map(|k| (running_set >> k & 1 != 0).then_some(k as u8))
                        .collect();
                    let Ok(running) = super::super::select_mst_outputs_beside(
                        0,
                        caps,
                        &devices,
                        &|_| None,
                        &crtcs,
                        &budget,
                        Some(&ctx),
                        &[],
                    ) else {
                        continue;
                    };
                    for joining_set in (0..8usize).filter(|j| j & running_set == 0) {
                        let joining: Vec<Option<u8>> = (0..3)
                            .map(|k| (joining_set >> k & 1 != 0).then_some(k as u8))
                            .collect();
                        let Some(affected) = super::super::affected_mst_streams(
                            0,
                            caps,
                            &devices,
                            &running,
                            &joining,
                            &|_| None,
                            &budget,
                            Some(&ctx),
                        ) else {
                            continue;
                        };
                        // The affected streams torn down; they and the joining
                        // devices light beside the rest, each at its timing.
                        let kept: Vec<modeset::Selection> = running
                            .iter()
                            .filter(|(_, c)| affected & 1 << c == 0)
                            .map(|(s, _)| *s)
                            .collect();
                        let relit: Vec<Option<u8>> = (0..3)
                            .map(|k| {
                                let c = k as u8;
                                (joining[k].is_some() || affected & 1 << c != 0).then_some(c)
                            })
                            .collect();
                        let timing_of = |k: usize| {
                            running
                                .iter()
                                .find(|(s, _)| s.mst.map(|m| m.sink) == Some(devices[k].0))
                                .map(|(s, _)| s.timing)
                        };
                        let lit = super::super::select_mst_outputs_beside(
                            0,
                            caps,
                            &devices,
                            &timing_of,
                            &relit,
                            &budget,
                            Some(&ctx),
                            &kept,
                        );
                        let Ok(lit) = lit else {
                            panic!(
                            "dec {decoders:#b} {lanes} x {rate:?} edids {pick} running {running_set:#b} \
                             joining {joining_set:#b} affected {affected:#b}: {lit:?}"
                        );
                        };
                        partial += usize::from(affected != 0 && !kept.is_empty());
                        // What lit for an affected stream is its search result.
                        let search = super::super::select_mst_outputs_beside(
                            0,
                            caps,
                            &devices,
                            &|k| timing_of(k),
                            &(0..3)
                                .map(|k| {
                                    (relit[k].is_some() || timing_of(k).is_some())
                                        .then_some(k as u8)
                                })
                                .collect::<Vec<_>>(),
                            &budget,
                            Some(&ctx),
                            &[],
                        )
                        .unwrap();
                        for (s, c) in &lit {
                            let found = search.iter().find(|(n, _)| n.mst == s.mst);
                            assert!(
                                found.is_some_and(|f| f.1 == *c),
                                "{:?} {:?}",
                                s.mst,
                                search.iter().map(|x| x.0.mst).collect::<Vec<_>>()
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(partial > 0, "no partial relight exercised");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_affected_relight_keeps_the_search_order
);

/// The streams a change on a DSC link modesets, as amdgpu_dm finds them
/// (drm_dp_mst_add_affected_dsc_crtcs puts the topology's streams in the
/// commit, pre_validate_dsc keeps each the search leaves unchanged): a
/// 1080p60 beside an uncompressed 4K60 on 4 x HBR3 affects nothing; a
/// second 4K60 on 4 x HBR2 compresses the running one, so only that one
/// is modeset, and lighting both from the full search then keeps the
/// result (the running set is what the search picks for it); removing one
/// of two compressed 4K60 streams modesets the other. A link without
/// decoders never modesets running streams.
fn navi48_mst_dsc_affected_streams_like_amdgpu_dm() -> TestResult {
    let mut hub = Hub::new();
    let (_, topology) = probed(&mut hub);
    let mst = MstDsc {
        caps: DscSinkCaps::parse(&DECODER, &[0; 3]).unwrap(),
        aux: DscAux::Port(ROOT_SINK),
        passthrough: None,
        end_link_kbps: 0,
        branch_oui: 0,
    };
    let dsc_of = |s: Sink| (s == ROOT_SINK || s == CHILD_SINK).then_some(mst);
    let none = |_: Sink| None;
    let max_bpc = |_: Sink| 8;
    let ctx = MstDscContext {
        topology: &topology,
        dsc_of: &dsc_of,
        max_dispclk_khz: 2_000_000,
        max_bpc: &max_bpc,
    };
    let plain = MstDscContext {
        dsc_of: &none,
        ..ctx
    };
    let budget = |_: Sink, _: &[(Sink, u16)]| u16::MAX;
    let caps = |rate| modeset::DpCaps {
        lanes: 4,
        rate,
        uhbr: 0,
        fec: true,
        dsc: None,
    };
    let select = |caps, devices: &[(Sink, Vec<u8>, u16)], pipes: &[Option<u8>]| {
        super::super::select_mst_outputs_beside(
            0,
            caps,
            devices,
            &|_| None,
            pipes,
            &budget,
            Some(&ctx),
            &[],
        )
        .unwrap()
    };
    let affected = |caps,
                    devices: &[(Sink, Vec<u8>, u16)],
                    running: &[(modeset::Selection, u8)],
                    joining: &[Option<u8>],
                    ctx: &MstDscContext| {
        super::super::affected_mst_streams(
            0,
            caps,
            devices,
            running,
            joining,
            &|_| None,
            &budget,
            Some(ctx),
        )
    };
    use crate::dp_link_training::LinkRate::{Hbr2, Hbr3};
    let small = [
        (ROOT_SINK, uhd60_edid(3), u16::MAX),
        (CHILD_SINK, fhd60_edid(), u16::MAX),
    ];
    let lit = select(caps(Hbr3), &small, &[Some(0), None]);
    if affected(caps(Hbr3), &small, &lit, &[None, Some(1)], &ctx) != Some(0) {
        return TestResult::Fail("1080p beside an uncompressed 4K");
    }
    let big = [
        (ROOT_SINK, uhd60_edid(3), u16::MAX),
        (CHILD_SINK, uhd60_edid(3), u16::MAX),
    ];
    // The running 4K60 on pipe 2 runs uncompressed alone.
    let alone: Vec<_> = select(caps(Hbr2), &big, &[Some(2), None]);
    if alone.len() != 1 || alone[0].0.dsc.is_some() || alone[0].1 != 2 {
        return TestResult::Fail("one 4K alone");
    }
    if affected(caps(Hbr2), &big, &alone, &[None, Some(1)], &ctx) != Some(1 << 2) {
        return TestResult::Fail("a second 4K compresses the running one");
    }
    // Both lit from the search: nothing changes; one leaving modesets the
    // other (it would run uncompressed alone).
    let joint = select(caps(Hbr2), &big, &[Some(2), Some(1)]);
    if joint.len() != 2 || joint.iter().any(|(s, _)| s.dsc.is_none()) {
        return TestResult::Fail("both compressed");
    }
    if affected(caps(Hbr2), &big, &joint, &[None, None], &ctx) != Some(0) {
        return TestResult::Fail("both running");
    }
    let left: Vec<_> = joint.iter().copied().filter(|&(_, p)| p == 2).collect();
    if affected(caps(Hbr2), &big, &left, &[None, None], &ctx) != Some(1 << 2) {
        return TestResult::Fail("one leaving");
    }
    // No decoder on the link: running payloads stay (only the changed
    // connectors' time slots are found again).
    if affected(caps(Hbr2), &big, &alone, &[None, Some(1)], &plain) != Some(0) {
        return TestResult::Fail("a link without decoders");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_affected_streams_like_amdgpu_dm
);
