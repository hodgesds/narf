//! SAGV/QGV tests. Bandwidth values are worked by hand from Linux b90c984d
//! intel_bw.c (tgl_get_bw_info with mtl_sa_info, mtl_find_qgv_points).
use super::*;
use crate::intel_gpu_modeset::Mode;
use crate::intel_gpu_pmdemand::Params;
use crate::intel_gpu_xelpg_live::tests::{programmed, Live};
use crate::intel_gpu_xelpg_live::{commit_live, plan, Step};
use crate::intel_gpu_xelpg_resources::{commit, compute, PipeRequest, ResourceError, State};
use crate::intel_gpu_xelpg_wm::{Latency, Tiling};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Two LPDDR5 points on eight channels: tRP=tRCD=30, tRDPRE=15, tRAS=68.
fn qgv(dclk_raw: [u32; 2]) -> Qgv {
    let hw = Live::new();
    hw.set(MEM_SS_INFO_GLOBAL, (2 << 8) | (8 << 4) | 2);
    for (i, raw) in dclk_raw.into_iter().enumerate() {
        let base = QGV_POINT_BASE + i as u64 * 8;
        hw.set(base, (30 << 24) | (30 << 16) | raw);
        hw.set(base + 4, (68 << 8) | 15);
    }
    Qgv::read(&hw).unwrap().unwrap()
}

fn latency(q: Option<Qgv>) -> Latency {
    Latency {
        qgv: q,
        ..Latency::adjust([6, 8, 10, 12, 14, 16], 20)
    }
}

fn panel(mode: &Mode) -> crate::intel_gpu_xelpg_resources::Request {
    crate::intel_gpu_display_resources::request(mode, Tiling::Linear, 0)
}

fn smoke_xelpg_bw_qgv_decode_and_derated_points() -> TestResult {
    let q = qgv([120, 192]);
    assert_eq!(
        (q.t_bl, q.max_numchannels, q.channel_width, q.deinterleave),
        (16, 8, 16, 4)
    );
    assert_eq!((q.num_channels, q.num_points), (8, 2));
    assert_eq!(
        q.points[0],
        QgvPoint {
            dclk: 2000,
            t_rp: 30,
            t_rcd: 30,
            t_rdpre: 15,
            t_ras: 68,
            t_rc: 98
        }
    );
    // Group0: clpchgroup 16, ct = max(98, 30+30+15*16+15) = 315.
    // maxdebw = min(38000, 8*2*3200*60/100 = 30720).
    let g = bw_info(&q).unwrap();
    assert_eq!(g[0].deratedbw[..2], [23406, 30720]);
    assert_eq!(g[0].peakbw[..2], [32000, 51200]);
    assert!(g.iter().all(|g| g.num_planes == 0));
    assert_eq!(max_bw_index(&g, 2, 1, 0), Some(0));
    assert_eq!(max_bw_index(&g, 2, 1, 2), None);
    // The least-headroom point that still carries the rate; 100 MB/s units.
    assert_eq!(qgv_peak_bw(&q, 260, 1), Some(320));
    assert_eq!(qgv_peak_bw(&q, 25_000, 1), Some(512));
    assert_eq!(qgv_peak_bw(&q, 40_000, 1), None);
    // Not describable or not controllable: SAGV stays masked.
    let hw = Live::new();
    hw.set(MEM_SS_INFO_GLOBAL, (2 << 8) | (8 << 4) | 4); // DDR3
    assert_eq!(Qgv::read(&hw), Ok(None));
    hw.set(MEM_SS_INFO_GLOBAL, (1 << 8) | (8 << 4) | 2); // one point
    assert_eq!(Qgv::read(&hw), Ok(None));
    hw.set(MEM_SS_INFO_GLOBAL, u32::MAX);
    assert!(Qgv::read(&hw).is_err());
    assert!(hw.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_bw",
    smoke_xelpg_bw_qgv_decode_and_derated_points
);

fn smoke_xelpg_bw_sagv_enables_only_with_headroom() -> TestResult {
    let q = qgv([120, 192]);
    let vesa = Mode::VESA_1024X768_60;
    // Every plane keeps its SAGV watermark: QCLK_GV_BW = 32000/100.
    let s = compute(&panel(&vesa), &latency(Some(q))).unwrap();
    assert_eq!(s.pmdemand.qclk_gv_bw, 320);
    assert!(s.dbuf.pipes[0].wm[0].sagv.enable);
    // Without SAGV control the decision stays masked.
    let s = compute(&panel(&vesa), &latency(None)).unwrap();
    assert_eq!(s.pmdemand.qclk_gv_bw, 0xffff);
    // A 3-line vblank cannot hide the 20 us block: the pipe rejects SAGV.
    let mut short = vesa;
    short.v_total = 771;
    let s = compute(&panel(&short), &latency(Some(q))).unwrap();
    assert!(!s.dbuf.pipes[0].wm[0].sagv.enable);
    assert_eq!(s.pmdemand.qclk_gv_bw, 0xffff);
    // SAGV allowed but 594 MB/s exceeds every derated point (199/316).
    let slow = qgv([1, 2]);
    let fhd = Mode {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        v_active: 1080,
        v_total: 1125,
        ..vesa
    };
    assert_eq!(
        compute(&panel(&fhd), &latency(Some(slow))),
        Err(ResourceError::BandwidthExceeded)
    );
    // The same QGV table carries the 260 MB/s panel at its top point.
    assert_eq!(
        compute(&panel(&vesa), &latency(Some(slow)))
            .unwrap()
            .pmdemand
            .qclk_gv_bw,
        5
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_bw",
    smoke_xelpg_bw_sagv_enables_only_with_headroom
);

fn qclk_writes(hw: &Live) -> alloc::vec::Vec<(usize, u32)> {
    hw.writes
        .borrow()
        .iter()
        .enumerate()
        .filter(|(_, (r, _))| *r == 0x45230)
        .map(|(i, (_, v))| (i, v >> 16))
        .collect()
}

fn two_pipes(q: Qgv) -> State {
    let mut request = panel(&Mode::VESA_1024X768_60);
    // An external pipe whose 3-line vblank rejects SAGV.
    let mut b: PipeRequest = request.pipes[0].unwrap();
    b.pixel_rate_khz = 74_250;
    b.hdisplay = 1280;
    b.htotal = 1650;
    b.vdisplay = 720;
    b.vtotal = 723;
    b.port_clock_khz = 270_000;
    b.combo_phy = Some(1);
    b.planes[0] = b.planes[0].map(|mut p| {
        p.width = 1280;
        p.height = 720;
        p
    });
    request.pipes[1] = Some(b);
    compute(&request, &latency(Some(q))).unwrap()
}

fn smoke_xelpg_bw_sagv_transitions_all_off_live_and_restore() -> TestResult {
    let q = qgv([120, 192]);
    let a = compute(&panel(&Mode::VESA_1024X768_60), &latency(Some(q))).unwrap();
    // All pipes off, SAGV masked before: pre keeps 0xffff (max), the post
    // request enables SAGV only after every plane register.
    let hw = Live::new();
    hw.set(0x45230, 0xffff_0000);
    commit(&hw, &a).unwrap();
    let w = qclk_writes(&hw);
    assert_eq!(w.first().map(|w| w.1), Some(0xffff));
    assert_eq!(w.last().map(|w| w.1), Some(320));
    assert!(w.last().unwrap().0 > hw.last(0x7327c));
    assert_eq!(Params::decode(hw.get(0x45230), hw.get(0x45234)), a.pmdemand);
    // A failed commit restores the masked demand.
    let hw = Live::new();
    hw.set(0x45230, 0xffff_0000);
    hw.set(0x45234, 308 << 20);
    hw.drop_write.set(0x7027c);
    assert_eq!(commit(&hw, &a), Err(ResourceError::Readback));
    assert_eq!((hw.get(0x45230), hw.get(0x45234)), (0xffff_0000, 308 << 20));
    // Live: adding a SAGV-rejecting pipe masks SAGV before the panel's
    // DDB moves; removing it re-enables SAGV only after the panel regrew.
    let ab = two_pipes(q);
    assert_eq!(ab.pmdemand.qclk_gv_bw, 0xffff);
    assert_eq!(plan(&a, &ab, 0x1).unwrap()[0], Step::PmDemandPre);
    let hw = programmed(&a, &[0]);
    commit_live(&hw, &a, &ab, 0x1).unwrap();
    let w = qclk_writes(&hw);
    assert_eq!(w.first().map(|w| w.1), Some(0xffff));
    assert!(w.first().unwrap().0 < hw.first(0x7027c));
    assert_eq!(hw.get(0x45230) >> 16, 0xffff);
    hw.writes.borrow_mut().clear();
    commit_live(&hw, &ab, &a, 0x1).unwrap();
    let w = qclk_writes(&hw);
    // Pre-plane max(0xffff, 320) equals the held request, so nothing is
    // re-initiated before the planes; SAGV is unmasked only afterwards.
    let moved = hw.last(0x7027c);
    assert!(w.iter().all(|&(i, v)| v == 0xffff || i > moved));
    assert_eq!(w.last().map(|w| w.1), Some(320));
    assert!(w.last().unwrap().0 > hw.last(0x7027c));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_bw",
    smoke_xelpg_bw_sagv_transitions_all_off_live_and_restore
);
