//! Display-30 (Xe3_LPD) native fixtures. Expected values are worked by hand
//! from Linux b90c984d (intel_display_device.c, intel_display_power_map.c,
//! intel_cdclk.c, intel_pmdemand.c, skl_watermark.c, skl_universal_plane.c,
//! intel_bw.c, intel_vrr.c, skl_prefill.c, skl_scaler.c, intel_dp.c,
//! intel_cx0_phy.c, intel_cx0_phy_regs.h, intel_dp_aux_regs.h, intel_dmc.c
//! and xe_device_wa_oob.rules); register literals are repeated
//! independently of the production constants. The models supply only
//! hardware acknowledgements.
use super::*;
use crate::intel_gpu::Generation;
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError, PixelFormat};
use crate::intel_gpu_pmdemand::{Demand, Layout, Params};
use crate::intel_gpu_xelpg_cdclk::{self as cdclk, Current, Step};
use crate::intel_gpu_xelpg_resources as res;
use crate::intel_gpu_xelpg_wm::{self as wm, Latency, Surface, Tiling};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

/// A plain register file: reads return the stored value (0 when unset) and
/// are counted, writes are logged and stored. `pll` mirrors
/// `BXT_DE_PLL_ENABLE`'s lock from its enable and the frequency-request ACK
/// from a pending request.
#[derive(Debug, Default)]
struct Regs {
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    reads: Cell<usize>,
}

impl Regs {
    fn with(values: &[(u64, u32)]) -> Self {
        let regs = Self::default();
        for &(r, v) in values {
            regs.values.borrow_mut().insert(r, v);
        }
        regs
    }
    fn set(&self, r: u64, v: u32) {
        self.values.borrow_mut().insert(r, v);
    }
    fn written(&self, r: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == r)
            .map(|(_, v)| *v)
            .collect()
    }
    fn position(&self, r: u64) -> usize {
        self.writes
            .borrow()
            .iter()
            .position(|(o, _)| *o == r)
            .expect("written")
    }
}

impl MmioWindow for Regs {
    fn read32(&self, r: u64) -> u32 {
        self.reads.set(self.reads.get() + 1);
        let v = *self.values.borrow().get(&r).unwrap_or(&0);
        if r == 0x46070 {
            // LOCK follows ENABLE; FREQ_REQ_ACK follows FREQ_REQ.
            return v | ((v >> 1) & (1 << 30)) | ((v >> 1) & (1 << 22));
        }
        v
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        self.values.borrow_mut().insert(r, v);
    }
}

// ── Identification and route ─────────────────────────────────────

fn smoke_xe3lpd_gmd_decode_admits_30_00_only_through_decode_all() -> TestResult {
    use crate::intel_gpu_xe2lpd::IpError;
    // gmdid_display_map: 30.00 is xe2_lpd_display (Panther Lake), 30.02
    // wcl_display (Wildcat Lake, not in the device table).
    assert_eq!(DisplayIp::decode_all(30 << 22), Ok(DisplayIp::Xe3Lpd));
    assert_eq!(DisplayIp::decode_all((30 << 22) | 5), Ok(DisplayIp::Xe3Lpd));
    assert_eq!(
        DisplayIp::decode_all((30 << 22) | (2 << 14)),
        Err(IpError::Unqualified { ver: 30, rel: 2 })
    );
    // The Meteor/Lunar Lake entries keep refusing 30.00.
    assert_eq!(
        DisplayIp::decode(30 << 22),
        Err(IpError::Unqualified { ver: 30, rel: 0 })
    );
    for gmd in [
        14 << 22,
        20 << 22,
        0,
        35 << 22,
        (14 << 22) | (1 << 14),
        (20 << 22) | (1 << 14),
    ] {
        assert_eq!(
            DisplayIp::decode_all(gmd),
            DisplayIp::decode(gmd),
            "{gmd:#x}"
        );
    }
    let io = Regs::with(&[(0x510a0, 30 << 22)]);
    assert_eq!(DisplayIp::read_all(&io), Ok(DisplayIp::Xe3Lpd));
    assert_eq!(
        DisplayIp::read(&io),
        Err(IpError::Unqualified { ver: 30, rel: 0 })
    );
    let io = Regs::with(&[(0x510a0, u32::MAX)]);
    assert_eq!(DisplayIp::read_all(&io), Err(IpError::NoDevice));
    // Display-30 properties of xe2_lpd_display and the display >= 20
    // branches it shares.
    let ip = DisplayIp::Xe3Lpd;
    assert_eq!(ip.ver(), 30);
    assert_eq!(ip.fbc_instances(), 4);
    assert!(ip.xe2_plus() && DisplayIp::Xe2Lpd.xe2_plus() && !DisplayIp::Xelpdp.xe2_plus());
    assert!(!ip.has_no_dpt_chicken());
    // get_allowed_dc_mask: max_dc 2 (DC6) with DC9 on display >= 20.
    assert_eq!(ip.allowed_dc_mask(), (1 << 3) | 2);
    assert_eq!(ip.dmc_firmware(), ("i915/xe3lpd_dmc.bin", 0x8000));
    // intel_enable_transcoder: display >= 14 clears INSERT_SF_AT_EOL; only
    // display 14 sets FEC_BS_JITTER.
    assert_eq!(ip.chicken_trans(), (1 << 4, 0));
    // mtl_ddi_enable_d2d, display >= 20: DDI_BUF_CTL bits 29/28.
    assert_eq!(
        ip.d2d(crate::intel_gpu_xelpg::XeLpgPort::A),
        (0x64000, 1 << 29, 1 << 28)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_gmd_decode_admits_30_00_only_through_decode_all
);

fn lit_ptl() -> Regs {
    Regs::with(&[
        (0x510a0, 30 << 22),
        (0x51000, 0),
        (0x16fe68, 0),
        (0x70008, 3 << 30),
    ])
}

fn smoke_xe3lpd_route_is_read_only_and_keeps_headless_otherwise() -> TestResult {
    use crate::intel_gpu_xe2lpd::IpError;
    let io = lit_ptl();
    assert_eq!(
        display_route(Generation::PantherLake, true, &io),
        Ok(DisplayIp::Xe3Lpd)
    );
    for other in [
        Generation::LunarLake,
        Generation::MeteorLake,
        Generation::TigerLake,
    ] {
        assert_eq!(
            display_route(other, true, &io),
            Err(RouteRefusal::NotPantherLake)
        );
    }
    // Without the option nothing is read.
    let io = lit_ptl();
    assert_eq!(
        display_route(Generation::PantherLake, false, &io),
        Err(RouteRefusal::NotRequested)
    );
    assert_eq!(io.reads.get(), 0);
    for (r, v, refusal) in [
        (0x510a0, 0, RouteRefusal::Ip(IpError::Absent)),
        (
            0x510a0,
            20 << 22,
            RouteRefusal::Ip(IpError::Unqualified { ver: 20, rel: 0 }),
        ),
        (
            0x510a0,
            14 << 22,
            RouteRefusal::Ip(IpError::Unqualified { ver: 14, rel: 0 }),
        ),
        (
            0x510a0,
            (30 << 22) | (2 << 14),
            RouteRefusal::Ip(IpError::Unqualified { ver: 30, rel: 2 }),
        ),
        (0x510a0, u32::MAX, RouteRefusal::Ip(IpError::NoDevice)),
        (0x51000, 1 << 30, RouteRefusal::PipeAFused),
        (0x16fe68, 1 << 31, RouteRefusal::EdpOnTypeC),
        (0x16fe68, u32::MAX, RouteRefusal::Ip(IpError::NoDevice)),
        (0x70008, 0, RouteRefusal::PipeADark),
        (0x70008, 1 << 31, RouteRefusal::PipeADark),
    ] {
        let io = lit_ptl();
        io.set(r, v);
        assert_eq!(
            display_route(Generation::PantherLake, true, &io),
            Err(refusal),
            "{r:#x}={v:#x}"
        );
        assert!(io.writes.borrow().is_empty(), "refusal wrote");
    }
    // A fused-out pipe B/C/D or other PICA config bits do not refuse.
    let io = lit_ptl();
    io.set(0x51000, 1 << 28);
    io.set(0x16fe68, 0x7fff_ffff);
    assert_eq!(
        display_route(Generation::PantherLake, true, &io),
        Ok(DisplayIp::Xe3Lpd)
    );
    assert!(io.writes.borrow().is_empty());
    // The strict opt-in grammar; the Lunar Lake option does not request it.
    use narf_boot::args::KernelCmdline;
    assert!(requested(KernelCmdline::new("narf.intel.ptl_display=1")));
    assert!(requested(KernelCmdline::new(
        "quiet narf.intel.ptl_display=1 root=/dev/sda"
    )));
    for line in [
        "",
        "narf.intel.ptl_display",
        "narf.intel.ptl_display=0",
        "narf.intel.ptl_display=01",
        "-- narf.intel.ptl_display=1",
        "narf.intel.ptl_display=1 narf.intel.ptl_display=1",
        "narf.intel.lnl_display=1",
    ] {
        assert!(!requested(KernelCmdline::new(line)), "{line}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_route_is_read_only_and_keeps_headless_otherwise
);

fn smoke_xe3lpd_wa_15015404425_follows_media_step() -> TestResult {
    // xe_step_gmdid_get: STEP_A0 + revid (5:0); B0 is revid 4.
    for (gmd, active) in [
        ((30 << 22), true),
        ((30 << 22) | 3, true),
        ((30 << 22) | 4, false),
        ((30 << 22) | (2 << 14) | 8, false),
        (0, true),
        (u32::MAX, true),
    ] {
        assert_eq!(wa_15015404425(gmd), active, "{gmd:#x}");
    }
    let io = Regs::with(&[(0x380d8c, (30 << 22) | 1)]);
    assert!(wa_15015404425_active(&io));
    io.set(0x380d8c, (30 << 22) | 5);
    assert!(!wa_15015404425_active(&io));
    assert!(io.writes.borrow().is_empty());
    // The view's flush: four dummy writes to 0x130030 precede every read
    // only when the workaround applies.
    let io = Regs::with(&[(0x510a0, 30 << 22)]);
    let flushed = View::new(&io, true);
    assert_eq!(flushed.read32(0x510a0), 30 << 22);
    assert_eq!(io.written(0x130030), [0, 0, 0, 0]);
    let plain = View::new(&io, false);
    io.writes.borrow_mut().clear();
    assert_eq!(plain.read32(0x510a0), 30 << 22);
    assert!(io.writes.borrow().is_empty());
    assert!(plain.cx0_xe3() && !io.cx0_xe3());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_wa_15015404425_follows_media_step
);

// ── Power wells ──────────────────────────────────────────────────

fn smoke_xe3lpd_power_well_map() -> TestResult {
    // PGB hangs off PG1 on display 30, off PG2 before.
    assert_eq!(parent(DisplayIp::Xe3Lpd, Well::PwB), Some(Well::Pw1));
    assert_eq!(parent(DisplayIp::Xe2Lpd, Well::PwB), Some(Well::Pw2));
    assert_eq!(parent(DisplayIp::Xelpdp, Well::PwB), Some(Well::Pw2));
    for ip in [DisplayIp::Xelpdp, DisplayIp::Xe2Lpd, DisplayIp::Xe3Lpd] {
        assert_eq!(parent(ip, Well::Pw1), None);
        assert_eq!(parent(ip, Well::Pw2), Some(Well::Pw1));
        assert_eq!(parent(ip, Well::PwA), Some(Well::Pw1));
        assert_eq!(parent(ip, Well::PwC), Some(Well::Pw2));
        assert_eq!(parent(ip, Well::PwD), Some(Well::Pw2));
    }
    // The Pipe-A eDP chain is PW_1 (idx 0) then PW_A (idx 5) everywhere.
    assert_eq!(PIPE_A_EDP_WELLS.map(Well::idx), [0, 5]);
    assert_eq!(
        [Well::Pw2, Well::PwB, Well::PwC, Well::PwD].map(Well::idx),
        [1, 6, 7, 8]
    );
    // DC_off also covers the PW_2 domains and AUDIO_PLAYBACK on display 30.
    let xe3 = dc_off_domains(DisplayIp::Xe3Lpd);
    let xe2 = dc_off_domains(DisplayIp::Xe2Lpd);
    for d in xe2 {
        assert!(xe3.contains(d), "{d:?}");
    }
    for d in [Domain::Vga, Domain::DdiLanesTc, Domain::AudioPlayback] {
        assert!(xe3.contains(&d) && !xe2.contains(&d), "{d:?}");
    }
    assert!(!xe3.contains(&Domain::PipeB) && !xe2.contains(&Domain::PipeB));
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_xe3lpd", smoke_xe3lpd_power_well_map);

// ── CDCLK ────────────────────────────────────────────────────────

fn rung(khz: u32) -> cdclk::Rung {
    cdclk::table(DisplayIp::Xe3Lpd)
        .iter()
        .copied()
        .find(|r| r.cdclk_khz == khz)
        .unwrap()
}

fn smoke_xe3lpd_cdclk_table_ctl_voltage_and_ceiling() -> TestResult {
    let table = cdclk::table(DisplayIp::Xe3Lpd);
    assert_eq!(table.len(), 29);
    // cdclk = ratio * 38.4 MHz * popcount(waveform) / 32, every rung.
    for r in table {
        assert_eq!(
            r.ratio * 38_400 * r.waveform.count_ones() / 32,
            r.cdclk_khz,
            "{r:?}"
        );
    }
    // Squashed rungs at ratio 16 up to 307.2 MHz, crawl-only above.
    assert_eq!(rung(153_600).waveform, 0xaaaa);
    assert_eq!((rung(307_200).ratio, rung(307_200).waveform), (16, 0xffff));
    assert_eq!((rung(326_400).ratio, rung(326_400).waveform), (17, 0xffff));
    assert!(table
        .iter()
        .filter(|r| r.cdclk_khz > 307_200)
        .all(|r| r.waveform == 0xffff && r.ratio == r.cdclk_khz / 19_200));
    assert_eq!(
        table.last().map(|r| (r.cdclk_khz, r.ratio)),
        Some((691_200, 36))
    );
    assert_eq!(
        cdclk::calc_cdclk_ip(DisplayIp::Xe3Lpd, 652_801).map(|r| r.cdclk_khz),
        Some(672_000)
    );
    assert_eq!(cdclk::calc_cdclk_ip(DisplayIp::Xe3Lpd, 691_201), None);
    assert_eq!(cdclk::max_cdclk_khz(DisplayIp::Xe3Lpd), 691_200);
    assert_eq!(cdclk::max_cdclk_khz(DisplayIp::Xe2Lpd), 652_800);
    // bxt_cdclk_ctl, display >= 30: DIV_SEL_1, no CD2X pipe field, the
    // MDCLK source select. Display 20 keeps CD2X_PIPE_NONE.
    assert_eq!(
        cdclk::ctl_value_ip(DisplayIp::Xe3Lpd, rung(691_200)),
        1 << 25
    );
    assert_eq!(
        cdclk::ctl_value_ip(DisplayIp::Xe2Lpd, rung(307_200)),
        0x0238_0000
    );
    // xe3lpd_calc_voltage_level is always 0; rplu levels stay on 20.
    for khz in [153_600, 480_000, 691_200] {
        assert_eq!(cdclk::voltage_level_ip(DisplayIp::Xe3Lpd, khz), 0);
    }
    assert_eq!(cdclk::voltage_level_ip(DisplayIp::Xe2Lpd, 652_800), 3);
    // bxt_get_cdclk + bxt_sanitize_cdclk on display 30: a CD2X pipe field
    // left by firmware is ignored, a decimal field is not.
    let io = Regs::with(&[
        (0x46070, 0x8000_0022),
        (0x46008, 0x8f00_ffff),
        (0x46000, 0x0238_0000),
    ]);
    let current = Current::read_ip(&io, DisplayIp::Xe3Lpd).unwrap();
    assert_eq!(current.known, Some(rung(652_800)));
    io.set(0x46000, 0x0200_0517);
    assert_eq!(
        Current::read_ip(&io, DisplayIp::Xe3Lpd).unwrap().known,
        None
    );
    assert!(io.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_cdclk_table_ctl_voltage_and_ceiling
);

fn known(khz: u32) -> Current {
    let r = rung(khz);
    Current {
        known: Some(r),
        pll: 0xc000_0000 | r.ratio,
        squash: cdclk::squash_value(r.waveform),
        ctl: 1 << 25,
        actual_khz: khz,
    }
}

fn smoke_xe3lpd_cdclk_plan_crawl_squash_and_wa_13012396614() -> TestResult {
    let unknown = Current {
        known: None,
        pll: 0x8000_0022,
        squash: 0,
        ctl: 0x0200_0517,
        actual_khz: 652_800,
    };
    // Unknown clock: no wa_15010685871 squash-off, Wa_13012396614 selects
    // CD2XCLK before the PLL disable.
    assert_eq!(
        cdclk::plan_ip(DisplayIp::Xe3Lpd, &unknown, rung(153_600)),
        vec![
            Step::MdclkCd2x,
            Step::PllDisable,
            Step::PllEnable { ratio: 16 },
            Step::Squash { waveform: 0xaaaa },
            Step::Ctl { value: 1 << 25 },
        ]
    );
    // Display 20 is unchanged: squash off first, no MDCLK step.
    let xe2 = crate::intel_gpu_xe2lpd::CDCLK_TABLE[0];
    assert_eq!(
        cdclk::plan_ip(DisplayIp::Xe2Lpd, &unknown, xe2),
        vec![
            Step::SquashOff,
            Step::PllDisable,
            Step::PllEnable { ratio: 16 },
            Step::Squash { waveform: 0xaaaa },
            Step::Ctl { value: 0x0238_0000 },
        ]
    );
    // Crawl-only between unsquashed rungs.
    assert_eq!(
        cdclk::plan_ip(DisplayIp::Xe3Lpd, &known(652_800), rung(384_000)),
        vec![
            Step::Crawl { ratio: 20 },
            Step::Squash { waveform: 0xffff },
            Step::Ctl { value: 1 << 25 },
        ]
    );
    // Lowering across VCO and waveform: crawl first with the old waveform to
    // the 307.2 MHz midpoint, then squash.
    assert_eq!(
        cdclk::plan_ip(DisplayIp::Xe3Lpd, &known(691_200), rung(153_600)),
        vec![
            Step::Crawl { ratio: 16 },
            Step::Squash { waveform: 0xffff },
            Step::Ctl { value: 1 << 25 },
            Step::Squash { waveform: 0xaaaa },
            Step::Ctl { value: 1 << 25 },
        ]
    );
    // Raising: squash first at the old VCO, then crawl.
    assert_eq!(
        cdclk::plan_ip(DisplayIp::Xe3Lpd, &known(153_600), rung(691_200)),
        vec![
            Step::Squash { waveform: 0xffff },
            Step::Ctl { value: 1 << 25 },
            Step::Crawl { ratio: 36 },
            Step::Squash { waveform: 0xffff },
            Step::Ctl { value: 1 << 25 },
        ]
    );
    assert!(cdclk::plan_ip(DisplayIp::Xe3Lpd, &known(480_000), rung(480_000)).is_empty());

    // The register order of Wa_13012396614 against an unknown 652.8 MHz
    // clock: CDCLK_CTL loses the MDCLK select before the PLL is disabled,
    // squash is never cleared first.
    let io = Regs::with(&[(0x46070, 0x8000_0022), (0x46000, 0x0200_0517)]);
    let old = Current::read_ip(&io, DisplayIp::Xe3Lpd).unwrap();
    assert_eq!(old.known, None);
    cdclk::program_ip(&io, DisplayIp::Xe3Lpd, &old, rung(153_600)).unwrap();
    assert_eq!(io.written(0x46000), [0x0000_0517, 0x0200_0000]);
    assert_eq!(io.written(0x46070), [0x22, 0x10, 0x8000_0010]);
    assert_eq!(io.written(0x46008), [0x8f00_aaaa]);
    assert!(io.position(0x46000) < io.position(0x46070));
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&io),
        153_600
    );
    // MDCLK ratio programming is display 20's: DIV_ROUND_UP(vco, cdclk).
    assert_eq!(crate::intel_gpu_xe2lpd::mdclk_cdclk_ratio(rung(153_600)), 4);
    assert_eq!(crate::intel_gpu_xe2lpd::mdclk_cdclk_ratio(rung(691_200)), 2);
    assert_eq!(crate::intel_gpu_xe2lpd::mdclk_cdclk_ratio(rung(326_400)), 2);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_cdclk_plan_crawl_squash_and_wa_13012396614
);

// ── PM demand ────────────────────────────────────────────────────

fn smoke_xe3lpd_pmdemand_xe3_layout() -> TestResult {
    let demand = Demand {
        qgv_peak_bw: None,
        enabled_slices: 0b1111,
        active_pipes: 0b1111,
        voltage_level: 1,
        cdclk_khz: 691_200,
        max_port_clock_khz: 810_000,
        combo_phys: 1,
    };
    let pre = demand.params();
    let xe3 = demand.params_for(Layout::Xe3);
    assert_eq!(demand.params_for(Layout::PreXe3), pre);
    assert_eq!((pre.active_pipes, pre.active_dbufs, pre.scalers), (3, 3, 7));
    // min(active pipes, INTEL_NUM_PIPES); no DBUF slices, no scalers.
    assert_eq!((xe3.active_pipes, xe3.active_dbufs, xe3.scalers), (4, 0, 0));
    assert_eq!(
        Params {
            active_pipes: 0,
            active_dbufs: 0,
            scalers: 0,
            ..xe3
        },
        Params {
            active_pipes: 0,
            active_dbufs: 0,
            scalers: 0,
            ..pre
        }
    );
    // REQUEST0: QCLK_GV_BW 31:16, VOLTAGE 14:12, QCLK_GV_INDEX 11:8,
    // XE3_PIPES 7:4, PHYS 2:0. REQUEST1: CDCLK 30:20, DDICLK 18:8,
    // [SCALERS 6:4 untouched], PLLS 2:0.
    assert_eq!(xe3.apply_for(Layout::Xe3, 0, 0), (0xffff_1041, 0x2b43_2a02));
    assert_eq!(pre.apply(0, 0), (0xffff_10f1, 0x2b43_2a72));
    let (r0, r1) = xe3.apply_for(Layout::Xe3, 0x8, 0x70);
    assert_eq!((r0 & 0x8, r1 & 0x70), (0x8, 0x70));
    assert_eq!(
        Params::decode_for(Layout::Xe3, 0xffff_1041, 0x2b43_2a02),
        xe3
    );
    // The 4-bit field reads every pipe; the pre-Xe3 decode would split it.
    let all = Params::decode_for(Layout::Xe3, 0xf0, 0);
    assert_eq!((all.active_pipes, all.active_dbufs), (15, 0));
    let split = Params::decode(0xf0, 0);
    assert_eq!((split.active_pipes, split.active_dbufs), (3, 3));
    assert_eq!(Layout::for_ip(DisplayIp::Xe3Lpd), Layout::Xe3);
    assert_eq!(Layout::for_ip(DisplayIp::Xe2Lpd), Layout::PreXe3);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_pmdemand_xe3_layout
);

// ── Watermarks, DDB and bandwidth ────────────────────────────────

fn vesa() -> wm::Timing {
    wm::Timing {
        pixel_rate_khz: 65_000,
        htotal: 1344,
        vtotal: 806,
        vblank_start: 768,
    }
}

fn smoke_xe3lpd_wm_no_added_block_and_unpanned_tile4() -> TestResult {
    // A 30 µs level 0 selects method2 (latency >= linetime 21 µs): two
    // lines of 9 blocks. Display 14 adds a block, display 30 does not.
    let latency = Latency::adjust([30, 40, 50, 60, 70, 80], 0);
    let linear = Surface {
        width: 1024,
        cpp: 4,
        tiling: Tiling::Linear,
    };
    let d14 = wm::plane(vesa(), linear, &latency).unwrap();
    let d30 = wm::plane_ip(DisplayIp::Xe3Lpd, vesa(), linear, &latency).unwrap();
    let d20 = wm::plane_ip(DisplayIp::Xe2Lpd, vesa(), linear, &latency).unwrap();
    assert_eq!(d20, d14, "display 20 keeps the display-14 arithmetic");
    let l14 = d14.levels[0];
    let l30 = d30.levels[0];
    assert_eq!((l14.blocks, l14.lines, l14.min_ddb_alloc), (19, 2, 22));
    assert_eq!((l30.blocks, l30.lines, l30.min_ddb_alloc), (18, 2, 21));
    // Tile4: 32 blocks per four lines, plus one before display 30 (8.25 vs
    // 8 blocks per line); the Y-tile minimum (four lines) is selected.
    let tile4 = Surface {
        tiling: Tiling::Tile4,
        ..linear
    };
    let t14 = wm::plane(vesa(), tile4, &latency).unwrap().levels[0];
    let t30 = wm::plane_ip(DisplayIp::Xe3Lpd, vesa(), tile4, &latency)
        .unwrap()
        .levels[0];
    assert_eq!((t14.blocks, t14.lines, t14.min_ddb_alloc), (34, 4, 67));
    assert_eq!((t30.blocks, t30.lines, t30.min_ddb_alloc), (32, 4, 65));
    // The cursor allocation follows the same rule.
    let c14 = wm::cursor_allocation(vesa(), &latency, 1).unwrap();
    let c30 = wm::cursor_allocation_ip(DisplayIp::Xe3Lpd, vesa(), &latency, 1).unwrap();
    assert!(c30 <= c14);
    // skl_wm0_prefill_lines_worst: XBGR16161616F Tile4, panned, at the
    // scaled width/rate: 7 lines at 3072 px / 1382.401 MHz.
    let worst = wm::wm0_prefill_lines_worst_xe3(
        1_382_401,
        1344,
        3072,
        &Latency::adjust([6, 8, 10, 12, 14, 16], 0),
    )
    .unwrap();
    assert_eq!(worst, 7 << 16);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_wm_no_added_block_and_unpanned_tile4
);

fn panel_request() -> res::Request {
    crate::intel_gpu_display_resources::request(&Mode::VESA_1024X768_60, Tiling::Linear, 0)
}

fn std_latency() -> Latency {
    Latency::adjust([6, 8, 10, 12, 14, 16], 0)
}

fn smoke_xe3lpd_resources_auto_min_alloc_and_min_buf_cfg() -> TestResult {
    let vblank = [Some(806 - 36), None, None, None];
    let xe3 = res::compute_ip_vblank(DisplayIp::Xe3Lpd, &panel_request(), &std_latency(), vblank)
        .unwrap();
    let xe2 = res::compute_ip(DisplayIp::Xe2Lpd, &panel_request(), &std_latency()).unwrap();
    assert_eq!(xe3.ip, DisplayIp::Xe3Lpd);
    assert_eq!(xe3.vblank_start, vblank);
    assert_eq!(xe3.cdclk.cdclk_khz, 153_600);
    // Voltage index 0 (xe3lpd_calc_voltage_level, HBR3 port: 1 from the
    // DDI) and the Xe3 PM-demand layout.
    assert_eq!(xe3.voltage_level, 1);
    assert_eq!(
        (
            xe3.pmdemand.active_pipes,
            xe3.pmdemand.active_dbufs,
            xe3.pmdemand.scalers
        ),
        (1, 0, 0)
    );
    // The display-20 MDCLK-ratio DBUF/MBUS/DBOX images.
    assert_eq!(xe3.dbuf_ctl(0, 0, xe3.dbuf.enabled_slices), 0x8007_0000);
    assert_eq!(xe3.mbus_ctl_select(None), 0xdc00_6000);
    assert_eq!(xe3.dbox(0), 0x0103_0a4c);
    let regs = xe3.plane_registers().unwrap();
    let get = |r: u64| regs.iter().find(|(o, _)| *o == r).map(|(_, v)| *v);
    let alloc = &xe3.dbuf.pipes[0];
    let primary = alloc.wm[0];
    // PLANE_WM(A, 1, 0) and PLANE_WM_SAGV(A, 1): level 0 carries
    // PLANE_WM_AUTO_MIN_ALLOC_EN (29); without SAGV control the SAGV level
    // was rejected and zeroed, so it does not.
    assert_eq!(get(0x70240).unwrap() & (1 << 29), 1 << 29);
    assert!(get(0x70240).unwrap() & (1 << 31) != 0);
    assert_eq!(get(0x70244).unwrap() & (1 << 29), 0);
    assert_eq!(get(0x70258).unwrap() & (1 << 29), 0);
    // PLANE_MIN_BUF_CFG(A, 1): min = level-0 min_ddb_alloc (28:16),
    // interim = SAGV min_ddb_alloc (0), PLANE_AUTO_MIN_DBUF_EN (31).
    assert_eq!(
        get(0x70274),
        Some((1 << 31) | (u32::from(primary.levels[0].min_ddb_alloc) << 16))
    );
    // Disabled planes and inactive pipes: zero.
    assert_eq!(get(0x70374), Some(0));
    assert_eq!(get(0x71274), Some(0));
    // The cursor never carries the bit.
    assert_eq!(get(0x70140).unwrap() & (1 << 29), 0);
    // Display 20 writes no PLANE_MIN_BUF_CFG and no auto bit.
    let regs20 = xe2.plane_registers().unwrap();
    assert!(regs20
        .iter()
        .all(|(r, _)| r & 0xfff != 0x274 && r & 0xfff != 0x374));
    assert!(regs20.iter().all(|(_, v)| v & (1 << 29) == 0));
    // With SAGV allowed, the interim allocation is the SAGV level's.
    let mut sagv = std_latency();
    sagv.sagv_block_us = 20;
    let state = res::compute_ip_vblank(DisplayIp::Xe3Lpd, &panel_request(), &sagv, vblank).unwrap();
    let primary = state.dbuf.pipes[0].wm[0];
    assert!(primary.sagv.min_ddb_alloc != 0);
    assert_eq!(
        res::min_ddb_value(&primary),
        Some(
            (1 << 31)
                | (u32::from(primary.levels[0].min_ddb_alloc) << 16)
                | u32::from(primary.sagv.min_ddb_alloc)
        )
    );
    let image = res::plane_wm_image_ip(DisplayIp::Xe3Lpd, 0, 0, &primary).unwrap();
    assert_eq!(image[6].0, 0x70258);
    assert_eq!(image[6].1 & (1 << 29), 1 << 29);
    // A vblank start outside [vdisplay, vtotal) is refused.
    assert_eq!(
        res::compute_ip_vblank(
            DisplayIp::Xe3Lpd,
            &panel_request(),
            &std_latency(),
            [Some(767), None, None, None]
        ),
        Err(res::ResourceError::Unsupported)
    );
    // Above 652.8 MHz only display 30 has a rung.
    let mut request = panel_request();
    request.min_cdclk_khz = 672_000;
    assert_eq!(
        res::compute_ip_vblank(DisplayIp::Xe3Lpd, &request, &std_latency(), vblank)
            .unwrap()
            .cdclk
            .cdclk_khz,
        672_000
    );
    assert_eq!(
        res::compute_ip(DisplayIp::Xe2Lpd, &request, &std_latency()),
        Err(res::ResourceError::CdclkUnsatisfiable)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd_resources",
    smoke_xe3lpd_resources_auto_min_alloc_and_min_buf_cfg
);

fn smoke_xe3lpd_bandwidth_sa_info_limit() -> TestResult {
    use crate::intel_gpu_xelpg_bw::{qgv_peak_bw, qgv_peak_bw_ip, Qgv, QgvPoint};
    // A fast 8-channel LPDDR5 point whose derated bandwidth sits above the
    // 38 GB/s display-14 limit and below xe3lpd_sa_info's 65 GB/s.
    let mut points = [QgvPoint::default(); 8];
    points[0] = QgvPoint {
        dclk: 4800,
        t_rp: 20,
        t_rcd: 20,
        t_rdpre: 10,
        t_ras: 40,
        t_rc: 60,
    };
    points[1] = QgvPoint {
        dclk: 1600,
        ..points[0]
    };
    let qgv = Qgv {
        t_bl: 16,
        max_numchannels: 8,
        channel_width: 16,
        deinterleave: 4,
        num_channels: 8,
        num_points: 2,
        points,
    };
    // Point 0's derated bandwidth is 61016 MB/s, clamped to 38000 (display
    // 14/20) or to the 60% peak limit 46080 (display 30, 65 GB/s); its peak
    // is 76800 MB/s (QCLK_GV_BW 768). A 40 GB/s load fits only on display 30.
    assert_eq!(qgv_peak_bw(&qgv, 40_000, 1), None);
    assert_eq!(
        qgv_peak_bw_ip(DisplayIp::Xe3Lpd, &qgv, 40_000, 1),
        Some(768)
    );
    assert_eq!(qgv_peak_bw_ip(DisplayIp::Xe3Lpd, &qgv, 50_000, 1), None);
    assert_eq!(
        qgv_peak_bw_ip(DisplayIp::Xe2Lpd, &qgv, 30_000, 1),
        qgv_peak_bw(&qgv, 30_000, 1)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd_resources",
    smoke_xe3lpd_bandwidth_sa_info_limit
);

// ── VRR timing generator ─────────────────────────────────────────

fn smoke_xe3lpd_vrr_guardband() -> TestResult {
    let mode = Mode::VESA_1024X768_60;
    // Two scalers, no DSC: the worst-case prefill is 12.7 lines, the
    // adaptive-sync SDP term vtotal - vsync_start + 1 = 36 wins under the
    // 38-line cap.
    assert_eq!(vrr_guardband(&mode, &std_latency(), false, 2), Some(36));
    assert_eq!(vrr_guardband(&mode, &std_latency(), false, 1), Some(36));
    assert_eq!(vrr_guardband(&mode, &std_latency(), false, 0), Some(36));
    // A 500 µs package-C latency makes the prefill (36.09 lines) win.
    let slow = Latency::adjust([6, 8, 10, 12, 14, 500], 0);
    assert_eq!(vrr_guardband(&mode, &slow, false, 2), Some(37));
    // 600 µs and DSC each exceed the vblank: capped at vtotal - vdisplay.
    let slower = Latency::adjust([6, 8, 10, 12, 14, 600], 0);
    assert_eq!(vrr_guardband(&mode, &slower, false, 2), Some(38));
    assert_eq!(vrr_guardband(&mode, &std_latency(), true, 2), Some(38));
    // The SAGV block time counts like a latency.
    let mut sagv = std_latency();
    sagv.sagv_block_us = 500;
    assert_eq!(vrr_guardband(&mode, &sagv, false, 2), Some(37));
    // No front porch: the SDP term exceeds the vblank.
    let tight = Mode {
        v_sync_start: 768,
        ..mode
    };
    assert_eq!(vrr_guardband(&tight, &std_latency(), false, 2), Some(38));
    // Undescribable modes refuse.
    assert_eq!(
        vrr_guardband(
            &Mode {
                v_total: 768,
                ..mode
            },
            &std_latency(),
            false,
            2
        ),
        None
    );
    assert_eq!(
        vrr_guardband(
            &Mode {
                pixel_clock_khz: 0,
                ..mode
            },
            &std_latency(),
            false,
            2
        ),
        None
    );
    // num_scalers: XE2LPD_DE_CAP's single-scaler fuse.
    assert_eq!(num_scalers(&Regs::with(&[(0x41100, 0)])), Ok(2));
    assert_eq!(num_scalers(&Regs::with(&[(0x41100, 1 << 26)])), Ok(1));

    // The fixed-refresh timings and the generator's enable/disable.
    let io = Regs::default();
    program_vrr_timings(&io, &mode).unwrap();
    assert_eq!(io.written(0x60434), [805]);
    assert_eq!(io.written(0x60424), [805]);
    assert_eq!(io.written(0x60438), [805]);
    // TRANS_VRR_VSYNC: end 806 - 777 = 29 (28:16), start 806 - 771 = 35.
    assert_eq!(io.written(0x60078), [(29 << 16) | 35]);
    assert_eq!(io.written(0x60204), [35]);
    assert!(io.written(0x60420).is_empty(), "no TRANS_VRR_CTL here");
    assert_eq!(trans_vtotal(&mode), 767);
    tg_enable(&io, 36).unwrap();
    assert_eq!(io.written(0x60a70), [1 << 31]);
    assert_eq!(io.written(0x60420), [(1 << 31) | (1 << 29) | 36]);
    assert!(io.position(0x60a70) < io.position(0x60420));
    // Disable: flip line and the old guardband stay, VRR_EN_LIVE clears,
    // then TRANS_PUSH is cleared.
    let io = Regs::with(&[(0x60420, (1 << 31) | (1 << 29) | 38)]);
    tg_disable(&io).unwrap();
    assert_eq!(io.written(0x60420), [(1 << 29) | 38]);
    assert_eq!(io.written(0x60a70), [0]);
    // A generator that never ran (no flip line) is left alone.
    let io = Regs::default();
    tg_disable(&io).unwrap();
    assert!(io.writes.borrow().is_empty());
    // A live status that never clears is a failure, with PUSH untouched.
    let io = Regs::with(&[(0x60420, (1 << 31) | (1 << 29) | 38), (0x6042c, 1 << 27)]);
    assert!(tg_disable(&io).is_err());
    assert!(io.written(0x60a70).is_empty());
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_xe3lpd", smoke_xe3lpd_vrr_guardband);

// ── PHY ──────────────────────────────────────────────────────────

fn smoke_xe3lpd_phy_pica_relocation_and_dialect() -> TestResult {
    use crate::intel_gpu_xelpg::{PhyKind, XeLpgPort};
    // __xe2lpd_port_idx(PORT_A) = 7, (PORT_B) = 8: the TC1 layout at
    // +4 * 0x200 and +5 * 0x200.
    for (mtl, pica) in [
        (0x64004u64, 0x16fa00u64), // PORT_BUF_CTL1
        (0x64008, 0x16fa04),       // PORT_BUF_CTL2
        (0x6400c, 0x16fa08),       // PORT_BUF_CTL3
        (0x64010, 0x16fa10),       // DP_AUX_CH_CTL
        (0x64014, 0x16fa14),       // DP_AUX_CH_DATA1
        (0x64024, 0x16fa24),       // DP_AUX_CH_DATA5
        (0x64040, 0x16fa40),       // M2P_MSGBUS_CTL ln0
        (0x64044, 0x16fa44),       // ln1
        (0x64048, 0x16fa48),       // P2M_MSGBUS_STATUS ln0
        (0x6404c, 0x16fa4c),       // ln1
        (0x640d8, 0x16fa58),       // PORT_MSGBUS_TIMER ln0
        (0x640dc, 0x16fa5c),       // ln1
        (0x640e0, 0x16fa60),       // PORT_CLOCK_CTL
        (0x64104, 0x16fc00),
        (0x64110, 0x16fc10),
        (0x64140, 0x16fc40),
        (0x641d8, 0x16fc58),
        (0x641e0, 0x16fc60),
    ] {
        assert_eq!(pica_port_reg(mtl), Some(pica), "{mtl:#x}");
    }
    // DDI_BUF_CTL, DDI_CLK_VALFREQ and everything else stay put.
    for off in [
        0x64000u64, 0x64030, 0x64100, 0x64130, 0x64028, 0x64002, 0x60540, 0x16f240, 0x45404,
    ] {
        assert_eq!(pica_port_reg(off), None, "{off:#x}");
    }
    let io = Regs::with(&[(0x16fa00, 0x1234)]);
    let view = View::new(&io, false);
    assert_eq!(view.read32(0x64004), 0x1234);
    view.write32(0x640e0, 7);
    view.write32(0x64000, 9);
    assert_eq!(io.written(0x16fa60), [7]);
    assert_eq!(io.written(0x64000), [9]);
    assert!(io.written(0x640e0).is_empty());
    // intel_encoder_is_c10phy on Panther Lake: PHY A only.
    assert_eq!(phy_kind(XeLpgPort::A), PhyKind::C10);
    for port in [XeLpgPort::B, XeLpgPort::Tc1, XeLpgPort::Tc4] {
        assert_eq!(phy_kind(port), PhyKind::C20);
    }
    // cx0_power_control_disable_val, display >= 30.
    assert_eq!(power_control_disable_val(PhyKind::C10, true), 0x9);
    assert_eq!(power_control_disable_val(PhyKind::C10, false), 0x9);
    assert_eq!(power_control_disable_val(PhyKind::C20, true), 0x9);
    assert_eq!(power_control_disable_val(PhyKind::C20, false), 0xc);
    // need_pipedmc_load_mmio, display 30: pipes C/D only.
    assert_eq!(
        [0, 1, 2, 3].map(need_pipedmc_load_mmio),
        [false, false, true, true]
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_phy_pica_relocation_and_dialect
);

// ── Owned modeset ────────────────────────────────────────────────

/// The display-14 modeset model (`intel_gpu_modeset_xelpg::tests::MtlFake`)
/// presenting display 30: `GMD_ID_DISPLAY` 30.00, DDI A's PHY and AUX
/// registers only at their PICA offsets (mapped back to the model's
/// display-14 ones by an independent table; an access at the display-14
/// offset is recorded as a stray and reads all-ones), the D2D link state in
/// `DDI_BUF_CTL` and the display-20/30 resource registers.
#[derive(Debug)]
struct Ptl {
    mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake,
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    strays: RefCell<Vec<u64>>,
}

/// The PICA offset of DDI A's relocated register, as the display-14 PHY
/// code names it (`__xe2lpd_port_idx`: TC1 layout + 4 * 0x200).
fn from_pica(r: u64) -> Option<u64> {
    match r {
        0x16fa00..=0x16fa08 => Some(r - 0x16fa00 + 0x64004),
        0x16fa10..=0x16fa24 | 0x16fa40..=0x16fa4c => Some(r - 0x16fa00 + 0x64000),
        0x16fa58 | 0x16fa5c => Some(r - 0x16fa58 + 0x640d8),
        0x16fa60 => Some(0x640e0),
        _ => None,
    }
}

/// DDI A's display-14 PHY/AUX offsets, which display 30 must never touch.
fn display14_phy(r: u64) -> bool {
    matches!(r, 0x64004..=0x64024 | 0x64040..=0x6404c | 0x640d8 | 0x640dc | 0x640e0)
}

impl Ptl {
    fn new() -> Self {
        Self {
            mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake::new(
                crate::intel_gpu_xelpg::XeLpgPort::A,
            ),
            values: RefCell::new(
                [
                    (0x510a0, 30 << 22),
                    (0x45780, 6 | (8 << 16)),
                    (0x45784, 10 | (12 << 16)),
                    (0x45788, 14 | (16 << 16)),
                ]
                .into_iter()
                .collect(),
            ),
            writes: RefCell::new(Vec::new()),
            strays: RefCell::new(Vec::new()),
        }
    }
    fn resource(r: u64) -> bool {
        matches!(
            r,
            0x510a0
                | 0x41100
                | 0x46460
                | 0x45230
                | 0x45234
                | 0x46440
                | 0x46438
                | 0x4438c
                | 0x7003c
                | 0x44464
                | 0x44468
                | 0x4446c
                | 0x45780
                | 0x45784
                | 0x45788
                | 0x45008
                | 0x44fe8
                | 0x44300
                | 0x44304
                | 0x45004
                | 0x71008
                | 0x72008
                | 0x73008
                | 0x43288
                | 0x432c8
        ) || ((0x70000..0x75000).contains(&r)
            && r & 0xfff >= 0x140
            && r & 0xfff <= 0x87c
            && r & 0xff < 0x80)
    }
    fn get(&self, r: u64) -> u32 {
        self.read32(r)
    }
    fn written(&self, r: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == r)
            .map(|(_, v)| *v)
            .collect()
    }
    fn first(&self, r: u64) -> usize {
        self.writes
            .borrow()
            .iter()
            .position(|(o, _)| *o == r)
            .expect("written")
    }
    fn last(&self, r: u64) -> usize {
        self.writes
            .borrow()
            .iter()
            .rposition(|(o, _)| *o == r)
            .expect("written")
    }
    fn fb() -> Framebuffer {
        Framebuffer {
            phys_addr: 0x100_0000,
            stride_bytes: 4096,
            format: PixelFormat::Xrgb8888,
        }
    }
    fn run(&self) -> Result<Mode, ModesetError> {
        modeset(
            &View::new(self, false),
            &Self::fb(),
            Some(&Mode::VESA_1024X768_60),
        )
    }
}

impl MmioWindow for Ptl {
    fn read32(&self, r: u64) -> u32 {
        if display14_phy(r) {
            self.strays.borrow_mut().push(r);
            return u32::MAX;
        }
        if let Some(r) = from_pica(r) {
            return self.mode.read32(r);
        }
        if Self::resource(r) {
            *self.values.borrow().get(&r).unwrap_or(&0)
        } else if r == 0x46070 {
            let v = self.mode.read32(r);
            v | ((v >> 1) & (1 << 22))
        } else if r == 0x64000 {
            let v = self.mode.read32(r);
            v | ((v >> 1) & (1 << 28))
        } else {
            self.mode.read32(r)
        }
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        if display14_phy(r) {
            self.strays.borrow_mut().push(r);
            return;
        }
        if let Some(r) = from_pica(r) {
            return self.mode.write32(r, v);
        }
        if Self::resource(r) {
            let mut value = v;
            if r == 0x45234 && v & (1 << 31) != 0 {
                value &= !(1 << 31)
            }
            if [0x45008, 0x44fe8, 0x44300, 0x44304].contains(&r) && v & (1 << 31) != 0 {
                value |= 1 << 30
            }
            self.values.borrow_mut().insert(r, value);
        } else {
            self.mode.write32(r, v)
        }
    }
}

fn smoke_xe3lpd_owned_modeset_lights_pipe_a_with_display30_resources() -> TestResult {
    let io = Ptl::new();
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    assert!(io.strays.borrow().is_empty(), "{:x?}", io.strays.borrow());
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::owned_panel_mode(),
        Some(Mode::VESA_1024X768_60)
    );
    // The PHY ran at the PICA offsets: message bus, port clock, AUX.
    assert!(!io.written(0x16fa40).is_empty());
    assert!(!io.written(0x16fa60).is_empty());
    assert_eq!(io.written(0x16fa10).first(), Some(&(1 << 19)));
    // __intel_cx0_{read,write}_once on display 30: no settle reset.
    for ctl in [0x16fa40, 0x16fa44] {
        assert!(io.written(ctl).iter().all(|v| *v != 1 << 15), "{ctl:#x}");
    }
    // DDI_CLK_VALFREQ and DDI_BUF_CTL stay at their _MMIO_PORT offsets.
    assert_eq!(io.written(0x64030), [162_000, 540_000]);
    assert!(io.written(0x64000).iter().any(|v| v & (1 << 29) != 0));
    // CDCLK from an off PLL: Wa_13012396614 clears the MDCLK select before
    // the (redundant) PLL disable, no wa_15010685871 squash-off, the
    // display-30 bottom rung, CTL without a CD2X pipe field.
    assert_eq!(io.written(0x46000), [0, 0x0200_0000]);
    assert_eq!(io.written(0x46070), [0, 0x10, 0x8000_0010]);
    assert_eq!(io.written(0x46008), [0x8f00_aaaa]);
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&io),
        153_600
    );
    // The MDCLK ratio after the raise; MBUS joined with throttle 3.
    assert!(io.last(0x46000) < io.first(0x4438c));
    assert_eq!(io.get(0x4438c), 0xdc00_6000);
    // PM demand in the Xe3 layout: one pipe in 7:4, no DBUF count, voltage
    // index 1 (HBR3 port), CDCLK 154 MHz; SCALERS (6:4 of REQUEST1) never
    // written.
    let req0 = io.get(0x45230);
    let req1 = io.get(0x45234);
    assert_eq!((req0 >> 4) & 0xf, 1);
    assert_eq!((req0 >> 12) & 7, 1);
    assert_eq!((req1 >> 20) & 0x7ff, 154);
    assert_eq!(req1 & 0x70, 0);
    // The primary's level 0 carries the auto minimum allocation bit and
    // PLANE_MIN_BUF_CFG its minimum DDB.
    assert_eq!(
        io.get(0x70240) & ((1 << 31) | (1 << 29)),
        (1 << 31) | (1 << 29)
    );
    let min_buf = io.get(0x70274);
    assert_eq!(min_buf & (1 << 31), 1 << 31);
    assert!((min_buf >> 16) & 0x1fff != 0);
    // VRR timing generator at fixed refresh, guardband 36: SCL 0, VTOTAL
    // without its vtotal field, MIN_HBLANK 0, VMIN/VMAX/FLIPLINE 805,
    // VRR_VSYNC and EMP_AS_SDP_TL, then PUSH and VRR_CTL before TRANSCONF.
    assert_eq!(io.written(0x6007c), [0]);
    assert_eq!(io.written(0x6000c), [767]);
    assert_eq!(io.written(0x600ac), [0]);
    for r in [0x60434, 0x60424, 0x60438] {
        assert_eq!(io.written(r), [805], "{r:#x}");
    }
    assert_eq!(io.written(0x60078), [(29 << 16) | 35]);
    assert_eq!(io.written(0x60204), [35]);
    assert_eq!(io.written(0x60a70), [1 << 31]);
    assert_eq!(io.written(0x60420), [(1 << 31) | (1 << 29) | 36]);
    assert!(io.first(0x60420) < io.last(0x70008));
    assert!(io.first(0x60a70) < io.first(0x60420));
    // intel_enable_transcoder: clear INSERT_SF_AT_EOL only.
    assert_eq!(io.written(0x604e0), [0]);
    // intel_program_dpkgc_latency (Wa_22020432604 covers display 30).
    assert_eq!(io.written(0x46460), [21]);
    // The KMS owners' single-pipe profile proves the same layout.
    let before = io.writes.borrow().len();
    let profile = crate::intel_gpu_display_resources::Profile::capture(
        &View::new(&io, false),
        &Mode::VESA_1024X768_60,
    )
    .unwrap();
    assert_eq!(profile.ip, DisplayIp::Xe3Lpd);
    assert!(profile.primary.levels[0].enable);
    // A diverged PLANE_MIN_BUF_CFG no longer proves it.
    io.values.borrow_mut().insert(0x70274, 0);
    assert!(crate::intel_gpu_display_resources::Profile::capture(
        &View::new(&io, false),
        &Mode::VESA_1024X768_60
    )
    .is_err());
    io.values.borrow_mut().insert(0x70274, min_buf);
    assert_eq!(io.writes.borrow().len(), before, "captures never write");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd_modeset",
    smoke_xe3lpd_owned_modeset_lights_pipe_a_with_display30_resources
);

fn smoke_xe3lpd_owned_modeset_stops_a_live_vrr_generator() -> TestResult {
    // Firmware ran the timing generator with a 30-line guardband: after the
    // transcoder stops, VRR_CTL keeps the flip line and that guardband,
    // PUSH clears, and the new generator starts with 36 lines.
    let io = Ptl::new();
    io.mode.write32(0x60420, (1 << 31) | (1 << 29) | 30);
    io.mode.write32(0x60a70, 1 << 31);
    io.writes.borrow_mut().clear();
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    assert_eq!(
        io.written(0x60420),
        [(1 << 29) | 30, (1 << 31) | (1 << 29) | 36]
    );
    assert_eq!(io.written(0x60a70), [0, 1 << 31]);
    // The generator stops after TRANSCONF is cleared and before the port
    // PLL request drops.
    let stop = io.first(0x60420);
    assert!(io.first(0x70008) < stop);
    let pll = io
        .writes
        .borrow()
        .iter()
        .position(|(r, _)| *r == 0x16fa60)
        .unwrap();
    assert!(stop < pll);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd_modeset",
    smoke_xe3lpd_owned_modeset_stops_a_live_vrr_generator
);

fn smoke_xe3lpd_entry_refuses_without_display30_read_only() -> TestResult {
    for gmd in [14 << 22, 20 << 22, 0, (30 << 22) | (2 << 14)] {
        let io = Ptl::new();
        io.values.borrow_mut().insert(0x510a0, gmd);
        assert_eq!(io.run(), Err(ModesetError::UnsupportedGeneration));
        assert!(io.writes.borrow().is_empty(), "{gmd:#x}");
    }
    // The entry needs the display-30 view (the PICA dialect).
    let io = Ptl::new();
    assert_eq!(
        modeset(&io, &Ptl::fb(), Some(&Mode::VESA_1024X768_60)),
        Err(ModesetError::UnsupportedGeneration)
    );
    assert!(io.writes.borrow().is_empty());
    // The generation-level dispatch keeps refusing Panther Lake.
    assert_eq!(
        crate::intel_gpu_modeset::modeset_display(
            &View::new(&io, false),
            Generation::PantherLake,
            &Ptl::fb(),
            Some(&Mode::VESA_1024X768_60)
        ),
        Err(ModesetError::UnsupportedGeneration)
    );
    assert!(io.writes.borrow().is_empty());
    // Takeover needs a lit Pipe A and reads only.
    assert_eq!(takeover(&View::new(&io, false)), None);
    assert!(io.writes.borrow().is_empty());
    // An unaligned or a DSC-fused display keeps refusing a compressing
    // stream before any write is not reachable here: the model's sink has
    // no DSC, so a removed-DSC fuse changes nothing.
    let io = Ptl::new();
    io.values.borrow_mut().insert(0x41100, 1 << 28);
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd_modeset",
    smoke_xe3lpd_entry_refuses_without_display30_read_only
);

/// Every access of a window, in order: `(write, register)`.
struct Trace<'a>(&'a Ptl, RefCell<Vec<(bool, u64)>>);

impl MmioWindow for Trace<'_> {
    fn read32(&self, r: u64) -> u32 {
        self.1.borrow_mut().push((false, r));
        self.0.read32(r)
    }
    fn write32(&self, r: u64, v: u32) {
        self.1.borrow_mut().push((true, r));
        self.0.write32(r, v)
    }
}

/// The route's probe-time window: with Wa_15015404425 active every read
/// follows the four dummy writes; past media B0 none does. Both light the
/// panel through the PICA offsets and open the backlight gate last.
fn smoke_xe3lpd_probe_window_flush_follows_media_step() -> TestResult {
    for flush in [true, false] {
        let io = Ptl::new();
        io.mode.write32(0xc7200, 0x8000_0000);
        let trace = Trace(&io, RefCell::new(Vec::new()));
        let lit = probe_window(&trace, &trace, flush, |mmio| {
            modeset(mmio, &Ptl::fb(), Some(&Mode::VESA_1024X768_60)).ok()
        });
        assert_eq!(lit, Ok(Some(Mode::VESA_1024X768_60)), "{flush}");
        assert!(io.strays.borrow().is_empty());
        let events = trace.1.borrow();
        let dummies = events.iter().filter(|e| **e == (true, 0x130030)).count();
        let reads = events.iter().filter(|e| !e.0).count();
        if flush {
            assert_eq!(dummies, 4 * reads);
            for (i, &(write, _)) in events.iter().enumerate() {
                if !write {
                    assert!(i >= 4 && events[i - 4..i].iter().all(|e| *e == (true, 0x130030)));
                }
            }
        } else {
            assert_eq!(dummies, 0);
        }
        assert_eq!(events.last(), Some(&(true, 0xc7204)));
        assert_ne!(io.mode.read32(0xc7204) & (1 << 2), 0, "EDP_BLC_ENABLE");
    }
    // Pipe A dark: the takeover refuses and the gate stays closed.
    let io = Ptl::new();
    io.mode.write32(0xc7200, 0x8000_0000);
    assert_eq!(
        probe_window(&io, &io, false, |mmio| takeover(mmio)),
        Ok(None)
    );
    assert_eq!(io.mode.read32(0xc7204) & (1 << 2), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd_modeset",
    smoke_xe3lpd_probe_window_flush_follows_media_step
);

// ── Display 30 Cursor, DSB and Double-Buffered LUTs ──────────────

#[cfg(target_arch = "x86_64")]
fn display30_resources(
    platform: &crate::intel_gpu_kms::tests::MockPlatform,
) -> crate::intel_gpu_dsb::Timing {
    let timing = platform.dsb_timing();
    let rung = CDCLK_TABLE[8];
    assert_eq!(
        (rung.cdclk_khz, rung.ratio, rung.waveform),
        (307_200, 16, 0xffff)
    );
    for (r, v) in [
        (0x510a0, 30 << 22),
        (0x480c, 0x3c),
        (0x70008, 0),
        (0x70180, 0),
        (0x46070, 0xc000_0010),
        (0x46008, 0x8f00_ffff),
        (
            0x46000,
            crate::intel_gpu_xelpg_cdclk::ctl_value_ip(DisplayIp::Xe3Lpd, rung),
        ),
    ] {
        platform.set(r, v);
    }
    let mode = crate::intel_gpu_modeset::Mode {
        pixel_clock_khz: timing.clock,
        h_active: timing.width,
        h_sync_start: timing.width + 10,
        h_sync_end: timing.width + 20,
        h_total: timing.htotal,
        v_active: timing.height,
        v_sync_start: timing.height + 5,
        v_sync_end: timing.height + 10,
        v_total: timing.vtotal,
        ..crate::intel_gpu_modeset::Mode::VESA_1024X768_60
    };
    crate::intel_gpu_display_resources::initialize(platform, &mode, 307_200)
        .unwrap()
        .expect("display 30 resource profile");
    platform.set(0x70008, 3 << 30);
    platform.set(0x70180, 0x8400_0000);
    timing
}

#[cfg(target_arch = "x86_64")]
fn smoke_xe3lpd_cursor_and_dsb_pages_map_xe3_pat3() -> TestResult {
    use crate::intel_gpu_gtt::{PteFormat, GGTT_ARRAY_BASE};
    use crate::intel_gpu_kms::{tests::MockPlatform, Platform};
    use crate::intel_gpu_scanout_io::{display_pat_programmed_ip, display_pte_ip};
    use narf_filesystem::FsError;

    let platform = MockPlatform::new().with_display_ip(DisplayIp::Xe3Lpd);
    let timing = platform.dsb_timing();

    // Verify display_pte_ip and display_pat_programmed_ip for Panther Lake.
    assert_eq!(
        display_pte_ip(Generation::PantherLake, Some(DisplayIp::Xe3Lpd)),
        Some((PteFormat::Xe2, 3))
    );
    assert_eq!(display_pte_ip(Generation::PantherLake, None), None);
    assert!(!display_pat_programmed_ip(
        &platform,
        Generation::PantherLake,
        Some(DisplayIp::Xe3Lpd)
    ));
    platform.set(0x480c, 0x3c);
    assert!(display_pat_programmed_ip(
        &platform,
        Generation::PantherLake,
        Some(DisplayIp::Xe3Lpd)
    ));

    // Reserve DSB and arm.
    let mut dsb = crate::intel_gpu_dsb::Owner::reserve_for(
        platform.clone(),
        0x100_0000,
        Generation::PantherLake,
    )
    .unwrap();
    dsb.arm(timing, &[(0x49028, 0)], None, platform.now())
        .unwrap();

    // Verify 4 DSB pages mapped with Xe2 PTE at PAT index 3.
    let pages = platform.dsb_mappings();
    assert_eq!(pages.len(), 8);
    for (r, v) in pages {
        if r % 8 == 0 {
            assert_eq!(v & 1, 1, "DSB PTE valid {r:#x}");
        } else {
            assert_eq!((v >> 20) & 3, 3, "DSB PTE PAT index 3 {r:#x}");
        }
    }

    // Reserve Cursor and stage an image.
    let gem = crate::intel_gpu_gem::GemState::new();
    let handle = gem.create(16384, |_, _| Ok(())).unwrap();
    let image = gem.object(handle).unwrap();
    let mut cursor = crate::intel_gpu_cursor::Owner::new_for(
        platform.clone(),
        0x100_0000,
        timing,
        Generation::PantherLake,
    )
    .unwrap();
    let regs = cursor
        .stage_with(|_| Vec::new(), Some(&image), true, Some((0, 0)))
        .unwrap();
    let base = regs.iter().find(|(r, _)| *r == 0x70084).unwrap().1;
    assert_ne!(base, 0);

    // Verify 8 cursor pages mapped with Xe2 PTE at PAT index 3.
    for page in 0..8u64 {
        let r = GGTT_ARRAY_BASE + (u64::from(base) / 4096 + page) * 8;
        assert_eq!(platform.read32(r) & 1, 1, "cursor page {page} valid");
        assert_eq!(
            (platform.read32(r + 4) >> 20) & 3,
            3,
            "cursor page {page} PAT index 3"
        );
    }
    cursor.cancel_unarmed();

    // Refusal without PAT3.
    let unprog = MockPlatform::new().with_display_ip(DisplayIp::Xe3Lpd);
    assert!(matches!(
        crate::intel_gpu_dsb::Owner::reserve_for(
            unprog.clone(),
            0x100_0000,
            Generation::PantherLake
        ),
        Err(FsError::NoDevice)
    ));
    assert!(matches!(
        crate::intel_gpu_cursor::Owner::new_for(
            unprog.clone(),
            0x100_0000,
            timing,
            Generation::PantherLake
        ),
        Err(FsError::NoDevice)
    ));

    // Refusal when headless (display_ip is None).
    let headless = MockPlatform::new();
    headless.set(0x480c, 0x3c);
    assert!(matches!(
        crate::intel_gpu_dsb::Owner::reserve_for(
            headless.clone(),
            0x100_0000,
            Generation::PantherLake
        ),
        Err(FsError::Unsupported)
    ));
    assert!(matches!(
        crate::intel_gpu_cursor::Owner::new_for(
            headless.clone(),
            0x100_0000,
            timing,
            Generation::PantherLake
        ),
        Err(FsError::Unsupported)
    ));

    TestResult::Pass
}

#[cfg(target_arch = "x86_64")]
fn smoke_xe3lpd_double_buffered_luts_and_color_arm() -> TestResult {
    use crate::intel_gpu_color::{
        has_double_buffered_lut, has_double_buffered_lut_ip, DegammaLut, Lut, GAMMA, MODE,
    };
    use crate::intel_gpu_kms::{tests::MockPlatform, Platform};

    assert!(has_double_buffered_lut(Generation::PantherLake));
    assert!(has_double_buffered_lut_ip(DisplayIp::Xe3Lpd));
    assert!(!has_double_buffered_lut(Generation::MeteorLake));
    assert!(!has_double_buffered_lut(Generation::LunarLake));

    let platform = MockPlatform::new().with_display_ip(DisplayIp::Xe3Lpd);
    platform.set(0x480c, 0x3c);
    let timing = platform.dsb_timing();

    // Capture initial color state.
    let mut owner =
        crate::intel_gpu_color::Owner::capture(&platform, Generation::PantherLake).unwrap();
    assert!(owner.double_buffered_lut());

    // Reserve DSB.
    let mut dsb = crate::intel_gpu_dsb::Owner::reserve_for(
        platform.clone(),
        0x100_0000,
        Generation::PantherLake,
    )
    .unwrap();

    // Create 129-entry degamma and 1024-entry gamma LUTs.
    let degamma_raw: Vec<u8> = (0..129u16)
        .flat_map(|i| {
            let ch = (i as u64 * 65535 / 128) as u16;
            let mut b = [0u8; 8];
            b[..2].copy_from_slice(&ch.to_le_bytes());
            b[2..4].copy_from_slice(&ch.to_le_bytes());
            b[4..6].copy_from_slice(&ch.to_le_bytes());
            b
        })
        .collect();
    let degamma =
        DegammaLut::decode_profile(&degamma_raw, crate::intel_gpu_color::Profile::Mtl).unwrap();

    let gamma_raw: Vec<u8> = (0..1024u16)
        .flat_map(|i| {
            let ch = (i as u64 * 65535 / 1023) as u16;
            let mut b = [0u8; 8];
            b[..2].copy_from_slice(&ch.to_le_bytes());
            b[2..4].copy_from_slice(&ch.to_le_bytes());
            b[4..6].copy_from_slice(&ch.to_le_bytes());
            b
        })
        .collect();
    let lut = Lut::decode_profile(&gamma_raw, crate::intel_gpu_color::Profile::Mtl).unwrap();

    // Prepare stages and arm DSB.
    let update = owner
        .prepare_stages(&platform, None, Some(lut.clone()), Some(degamma.clone()))
        .unwrap();
    assert!(update.registers.iter().any(|(r, _)| *r == GAMMA));
    assert!(update.registers.iter().any(|(r, _)| *r == MODE));

    dsb.arm_color(
        timing,
        &update.registers,
        update.lut(),
        update.degamma(),
        platform.now(),
    )
    .unwrap();

    // Complete DSB poll.
    while dsb.armed() && !dsb.poll(platform.now()).unwrap() {
        platform.step();
    }

    TestResult::Pass
}

#[cfg(target_arch = "x86_64")]
fn smoke_xe3lpd_cursor_staging_and_dsb_arm() -> TestResult {
    use crate::intel_gpu_kms::{tests::MockPlatform, Platform};

    let platform = MockPlatform::new().with_display_ip(DisplayIp::Xe3Lpd);
    let timing = display30_resources(&platform);
    let profile =
        crate::intel_gpu_display_resources::Profile::capture_timing(&platform, timing).unwrap();

    let gem = crate::intel_gpu_gem::GemState::new();
    let handle = gem.create(16384, |_, _| Ok(())).unwrap();
    let image = gem.object(handle).unwrap();

    let mut cursor = crate::intel_gpu_cursor::Owner::new_for(
        platform.clone(),
        0x100_0000,
        timing,
        Generation::PantherLake,
    )
    .unwrap();

    // Stage cursor at (10, 20).
    let regs = cursor
        .stage_with(
            |e| profile.cursor_registers(e),
            Some(&image),
            true,
            Some((10, 20)),
        )
        .unwrap();

    // Check CUR_CTL = 0x27 (MCURSOR_MODE_64_ARGB_AX).
    let ctl = regs.iter().find(|(r, _)| *r == 0x70080).unwrap().1;
    assert_eq!(ctl, 0x27);

    // Check CUR_POS = 10 | (20 << 16).
    let pos = regs.iter().find(|(r, _)| *r == 0x70088).unwrap().1;
    assert_eq!(pos, 10 | (20 << 16));

    // Check CUR_BASE is non-zero.
    let base = regs.iter().find(|(r, _)| *r == 0x70084).unwrap().1;
    assert_ne!(base, 0);

    // Arm through DSB.
    let mut dsb = crate::intel_gpu_dsb::Owner::reserve_for(
        platform.clone(),
        0x100_0000,
        Generation::PantherLake,
    )
    .unwrap();
    dsb.arm(timing, &regs, None, platform.now()).unwrap();

    while dsb.armed() && !dsb.poll(platform.now()).unwrap() {
        platform.step();
    }
    cursor.complete().unwrap();
    dsb.shutdown().unwrap();

    // Verify cursor register latching.
    assert_eq!(platform.read32(0x70080), 0x27);
    assert_eq!(platform.read32(0x70088), 10 | (20 << 16));
    assert_eq!(platform.read32(0x70084), base);

    // Stage cursor hidden (image = None).
    let hide_regs = cursor
        .stage_with(|e| profile.cursor_registers(e), None, true, None)
        .unwrap();
    let hide_ctl = hide_regs.iter().find(|(r, _)| *r == 0x70080).unwrap().1;
    assert_eq!(hide_ctl, 0);

    dsb.arm(timing, &hide_regs, None, platform.now()).unwrap();
    while dsb.armed() && !dsb.poll(platform.now()).unwrap() {
        platform.step();
    }
    cursor.complete().unwrap();
    dsb.shutdown().unwrap();
    assert_eq!(platform.read32(0x70080), 0);

    TestResult::Pass
}

#[cfg(target_arch = "x86_64")]
fn smoke_xe3lpd_gt_scanout_create_flag_follows_display_profile() -> TestResult {
    use crate::intel_gpu_gt::GtPlatform;
    use narf_filesystem::FsError;
    let info = |platform, display: Option<bool>| crate::intel_gpu_render::DeviceInfo {
        device_id: 0xb080,
        platform,
        memory_bytes: 0x8000_0000,
        hwconfig: None,
        topology: None,
        vram: None,
        backend: display.map(|display| {
            alloc::sync::Arc::new(crate::intel_gpu_xe2lpd::gt_tests::ProfileBackend(display))
                as alloc::sync::Arc<dyn crate::intel_gpu_user::UserBackend>
        }),
    };
    let ptl = GtPlatform::from_pci(0x8086, 0xb080).unwrap();
    let gem = crate::intel_gpu_gem::GemState::new();
    let display = info(ptl, Some(true));
    let handle = crate::intel_gpu_xe2lpd::gt_tests::xe_gem_create(&display, &gem, 2, 2).unwrap();
    let object = gem.object(handle).unwrap();
    assert!(object.scanout() && object.is_wc());
    assert_eq!(
        crate::intel_gpu_xe2lpd::gt_tests::xe_gem_create(&display, &gem, 2, 1),
        Err(FsError::InvalidData)
    );
    assert_eq!(
        crate::intel_gpu_xe2lpd::gt_tests::xe_gem_create(&info(ptl, Some(false)), &gem, 2, 2),
        Err(FsError::InvalidData)
    );
    TestResult::Pass
}

#[cfg(target_arch = "x86_64")]
fn smoke_xe3lpd_kms_tile4_and_x_flips_through_owned_dpt() -> TestResult {
    use crate::intel_gpu_gtt::{GEM_SCANOUT_GTT_END, GEM_SCANOUT_GTT_START, GGTT_ARRAY_BASE};
    use crate::intel_gpu_kms::tests::MockPlatform;
    use crate::intel_gpu_scanout::{Geometry, Layout, View};

    let platform = MockPlatform::new().with_display_ip(DisplayIp::Xe3Lpd);
    let timing = display30_resources(&platform);
    let geometry = crate::intel_gpu_kms::tests::geometry();
    crate::intel_gpu_kms::tile4_profile(&platform, geometry, timing).unwrap();
    let device = platform.panther();
    let fb = crate::intel_gpu_kms::tests::object(true).unwrap();
    let frames: Vec<u64> = fb.pages().collect();
    assert_eq!(frames.len(), 2);
    let view = View {
        layout: Layout::Tile4,
        ..View::default()
    };
    {
        let mut session = crate::intel_gpu_kms::tests::complete(device.session()).unwrap();
        crate::intel_gpu_kms::tests::complete(session.present_color(
            fb.clone(),
            geometry,
            view,
            None,
            Default::default(),
            timing,
        ))
        .unwrap();
    }
    assert_eq!(platform.read32(0x70180), 0x8400_1400);
    assert_eq!(platform.read32(0x70188), 2);
    let surface = platform.read32(0x701ac);
    assert_eq!(platform.read32(0x7019c), surface);
    assert_eq!(surface % (2 << 20), 0);
    assert!((GEM_SCANOUT_GTT_START..GEM_SCANOUT_GTT_END).contains(&u64::from(surface)));
    let pte = GGTT_ARRAY_BASE + u64::from(surface) / 4096 * 8;
    let (low, high) = (platform.read32(pte), platform.read32(pte + 4));
    assert_eq!(low & 1, 1);
    assert_eq!((high >> 20) & 3, 3);
    assert_eq!(platform.read32(pte + 8), 0);
    let table = (u64::from(low) | (u64::from(high) << 32)) & crate::intel_gpu_gtt::PTE_PHYS_MASK;
    let entry = |index: u64| -> u64 {
        // SAFETY: the presenter retains this DPT page, mapped by the PTE
        // just read, for the surface's lifetime.
        unsafe {
            narf_memory::PhysAddr::new(table + index * 8)
                .kernel_ptr::<u64>()
                .read_volatile()
        }
    };
    for (index, phys) in frames.iter().enumerate() {
        assert_eq!(entry(index as u64), phys | 1 | (3 << 52), "entry {index}");
    }
    for index in 2..512 {
        assert_eq!(entry(index), 0, "padding {index}");
    }
    assert!(platform.all_writes().iter().all(|&(r, _)| r != 0x7026c));

    // X-tiled flip through DPT at 512 pitch.
    let platform_x = MockPlatform::new().with_display_ip(DisplayIp::Xe3Lpd);
    let timing_x = display30_resources(&platform_x);
    let geom_x = Geometry {
        width: 64,
        height: 32,
        pitch: 512,
    };
    let device_x = platform_x.panther_pitch(512);
    let fb_x = crate::intel_gpu_kms::tests::object_sized(true, 16384).unwrap();
    let view_x = View {
        layout: Layout::X,
        ..View::default()
    };
    {
        let mut session = crate::intel_gpu_kms::tests::complete(device_x.session()).unwrap();
        crate::intel_gpu_kms::tests::complete(session.present_color(
            fb_x.clone(),
            geom_x,
            view_x,
            None,
            Default::default(),
            timing_x,
        ))
        .unwrap();
    }
    assert_eq!(platform_x.read32(0x70180), 0x8400_0400);
    assert_eq!(platform_x.read32(0x70188), 1);
    let surface_x = platform_x.read32(0x701ac);
    assert_eq!(platform_x.read32(0x7019c), surface_x);
    assert_eq!(surface_x % (2 << 20), 0);
    let pte_x = GGTT_ARRAY_BASE + u64::from(surface_x) / 4096 * 8;
    let (low_x, high_x) = (platform_x.read32(pte_x), platform_x.read32(pte_x + 4));
    assert_eq!(low_x & 1, 1);
    assert_eq!((high_x >> 20) & 3, 3);

    TestResult::Pass
}

#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_cursor_and_dsb_pages_map_xe3_pat3
);
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_double_buffered_luts_and_color_arm
);
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_cursor_staging_and_dsb_arm
);
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_gt_scanout_create_flag_follows_display_profile
);
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe3lpd",
    smoke_xe3lpd_kms_tile4_and_x_flips_through_owned_dpt
);
