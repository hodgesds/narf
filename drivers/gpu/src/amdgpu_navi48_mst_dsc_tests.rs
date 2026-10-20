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
    if !port_supports_mode(&FHD60, &topology, ROOT_SINK, None, &HBR3X4)
        || port_supports_mode(&UHD144, &topology, ROOT_SINK, None, &HBR3X4)
        || !port_supports_mode(&UHD144, &topology, ROOT_SINK, Some(&dsc), &HBR3X4)
    {
        return TestResult::Fail("decoder admission");
    }
    // An HBR2 x4 last link cannot carry 4K144 raw.
    dsc.end_link_kbps = 5_400_000 * 4 / 10_000 * 7760;
    if port_supports_mode(&UHD144, &topology, ROOT_SINK, Some(&dsc), &HBR3X4) {
        return TestResult::Fail("slow last link");
    }
    dsc.branch_oui = OUI_SYNAPTICS;
    if !port_supports_mode(&UHD144, &topology, ROOT_SINK, Some(&dsc), &HBR3X4) {
        return TestResult::Fail("Synaptics last link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mst",
    navi48_mst_dsc_port_support_mode_like_amdgpu_dm
);
