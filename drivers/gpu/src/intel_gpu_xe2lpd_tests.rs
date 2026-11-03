//! Display-20 (Xe2_LPD) native fixtures. Expected values are worked by hand
//! from Linux b90c984d (intel_display_device.c, intel_cdclk.c,
//! skl_watermark.c, intel_ddi.c, intel_display.c, intel_dmc.c,
//! intel_display_power_well.c); register literals are repeated independently
//! of the production constants. The models supply only hardware ACKs.
use super::*;
use crate::intel_gpu_modeset::{Framebuffer, Mode, ModesetError, PixelFormat};
use crate::intel_gpu_xelpg_cdclk::{self as cdclk, Current, Step};
use crate::intel_gpu_xelpg_resources as res;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

/// A plain register file: reads return the stored value (0 when unset),
/// writes are logged and stored. `mirror` makes a status bit follow its
/// request bit (register, request, status).
#[derive(Debug, Default)]
struct Regs {
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    mirror: Cell<Option<(u64, u32, u32)>>,
    unstable: Cell<u64>,
    flip: Cell<bool>,
}

impl Regs {
    fn with(values: &[(u64, u32)]) -> Self {
        let regs = Self::default();
        regs.unstable.set(u64::MAX);
        for &(r, v) in values {
            regs.values.borrow_mut().insert(r, v);
        }
        regs
    }
    fn get(&self, r: u64) -> u32 {
        *self.values.borrow().get(&r).unwrap_or(&0)
    }
    fn written(&self, r: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(o, _)| *o == r)
            .map(|(_, v)| *v)
            .collect()
    }
}

impl MmioWindow for Regs {
    fn read32(&self, r: u64) -> u32 {
        let mut v = self.get(r);
        if r == self.unstable.get() {
            self.flip.set(!self.flip.get());
            v ^= u32::from(self.flip.get());
        }
        if let Some((reg, request, status)) = self.mirror.get() {
            if reg == r && v & request != 0 {
                v |= status;
            }
        }
        v
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        self.values.borrow_mut().insert(r, v);
    }
}

// ── Identification and admission ─────────────────────────────────

fn smoke_xe2lpd_gmd_decode_and_typed_refusals() -> TestResult {
    // gmdid_display_map: 14.00 xe_lpdp, 20.00 xe2_lpd; the rest are other
    // descriptors; a zero GMD is "Device doesn't have display".
    assert_eq!(DisplayIp::decode(14 << 22), Ok(DisplayIp::Xelpdp));
    assert_eq!(DisplayIp::decode((20 << 22) | 3), Ok(DisplayIp::Xe2Lpd));
    assert_eq!(DisplayIp::decode(0), Err(IpError::Absent));
    for (gmd, ver, rel) in [
        ((14 << 22) | (1 << 14), 14, 1),
        (30 << 22, 30, 0),
        ((30 << 22) | (2 << 14), 30, 2),
        (35 << 22, 35, 0),
        ((20 << 22) | (1 << 14), 20, 1),
        (13 << 22, 13, 0),
    ] {
        assert_eq!(
            DisplayIp::decode(gmd),
            Err(IpError::Unqualified { ver, rel }),
            "{gmd:#x}"
        );
    }
    // Two equal reads are required; all-ones is lost access.
    let io = Regs::with(&[(0x510a0, 20 << 22)]);
    assert_eq!(DisplayIp::read(&io), Ok(DisplayIp::Xe2Lpd));
    io.unstable.set(0x510a0);
    assert_eq!(DisplayIp::read(&io), Err(IpError::NoDevice));
    let io = Regs::with(&[(0x510a0, u32::MAX)]);
    assert_eq!(DisplayIp::read(&io), Err(IpError::NoDevice));
    assert!(io.writes.borrow().is_empty());
    use crate::intel_gpu::Generation;
    assert_eq!(
        DisplayIp::for_generation(Generation::MeteorLake),
        Some(DisplayIp::Xelpdp)
    );
    assert_eq!(
        DisplayIp::for_generation(Generation::LunarLake),
        Some(DisplayIp::Xe2Lpd)
    );
    for generation in [
        Generation::TigerLake,
        Generation::AlderLake,
        Generation::PantherLake,
    ] {
        assert_eq!(DisplayIp::for_generation(generation), None);
    }
    assert_eq!((DisplayIp::Xelpdp.ver(), DisplayIp::Xe2Lpd.ver()), (14, 20));
    // XE2LPD_DE_CAP: DSC field 29:28 == 1 removed, scaler 27:26 == 1 single.
    assert_eq!(
        DeCap::decode(1 << 28),
        DeCap {
            dsc_removed: true,
            single_scaler: false
        }
    );
    assert_eq!(
        DeCap::decode((2 << 28) | (1 << 26)),
        DeCap {
            dsc_removed: false,
            single_scaler: true
        }
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd",
    smoke_xe2lpd_gmd_decode_and_typed_refusals
);

fn smoke_xe2lpd_route_is_read_only_and_keeps_headless_otherwise() -> TestResult {
    use crate::intel_gpu::Generation;
    let lit = || Regs::with(&[(0x510a0, 20 << 22), (0x51000, 0), (0x70008, 3 << 30)]);
    let io = lit();
    assert_eq!(
        display_route(Generation::LunarLake, true, &io),
        Ok(DisplayIp::Xe2Lpd)
    );
    assert_eq!(
        display_route(Generation::MeteorLake, true, &io),
        Err(RouteRefusal::NotLunarLake)
    );
    assert_eq!(
        display_route(Generation::PantherLake, true, &io),
        Err(RouteRefusal::NotLunarLake)
    );
    assert_eq!(
        display_route(Generation::LunarLake, false, &io),
        Err(RouteRefusal::NotRequested)
    );
    assert!(io.writes.borrow().is_empty());
    for (r, v, refusal) in [
        (0x510a0, 0, RouteRefusal::Ip(IpError::Absent)),
        (
            0x510a0,
            14 << 22,
            RouteRefusal::Ip(IpError::Unqualified { ver: 14, rel: 0 }),
        ),
        (
            0x510a0,
            30 << 22,
            RouteRefusal::Ip(IpError::Unqualified { ver: 30, rel: 0 }),
        ),
        (0x51000, 1 << 30, RouteRefusal::PipeAFused),
        (0x70008, 0, RouteRefusal::PipeADark),
        (0x70008, 1 << 31, RouteRefusal::PipeADark),
        (0x70008, u32::MAX, RouteRefusal::Ip(IpError::NoDevice)),
    ] {
        let io = lit();
        io.values.borrow_mut().insert(r, v);
        assert_eq!(
            display_route(Generation::LunarLake, true, &io),
            Err(refusal),
            "{r:#x}={v:#x}"
        );
        assert!(io.writes.borrow().is_empty(), "refusal wrote");
    }
    // The opt-in grammar is the strict Intel destructive-option grammar.
    use narf_boot::args::KernelCmdline;
    assert!(requested(KernelCmdline::new("narf.intel.lnl_display=1")));
    assert!(requested(KernelCmdline::new(
        "quiet narf.intel.lnl_display=1 root=/dev/sda"
    )));
    for line in [
        "",
        "narf.intel.lnl_display",
        "narf.intel.lnl_display=0",
        "narf.intel.lnl_display=01",
        "-- narf.intel.lnl_display=1",
        "narf.intel.lnl_display=1 narf.intel.lnl_display=1",
    ] {
        assert!(!requested(KernelCmdline::new(line)), "{line}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd",
    smoke_xe2lpd_route_is_read_only_and_keeps_headless_otherwise
);

fn smoke_xe2lpd_source_facts() -> TestResult {
    // get_allowed_dc_mask: DC9 | DC3CO | UPTO_DC6 on 14, DC9 | UPTO_DC6 on 20.
    assert_eq!(DisplayIp::Xelpdp.allowed_dc_mask(), 0x4000_000a);
    assert_eq!(DisplayIp::Xe2Lpd.allowed_dc_mask(), 0x0000_000a);
    assert_eq!(
        DisplayIp::Xe2Lpd.dmc_firmware(),
        ("i915/xe2lpd_dmc.bin", 0x8000)
    );
    assert_eq!(
        DisplayIp::Xelpdp.dmc_firmware(),
        (crate::intel_gpu_dmc::MTL_DMC_FIRMWARE, 0x7000)
    );
    assert_eq!(
        (
            DisplayIp::Xelpdp.fbc_instances(),
            DisplayIp::Xe2Lpd.fbc_instances()
        ),
        (2, 4)
    );
    assert!(DisplayIp::Xelpdp.has_no_dpt_chicken() && !DisplayIp::Xe2Lpd.has_no_dpt_chicken());
    // intel_enable_transcoder: clear INSERT_SF_AT_EOL (bit 4); only display
    // 14 sets FEC_BS_JITTER (bit 15).
    assert_eq!(DisplayIp::Xelpdp.chicken_trans(), (1 << 4, 1 << 15));
    assert_eq!(DisplayIp::Xe2Lpd.chicken_trans(), (1 << 4, 0));
    // mtl_ddi_enable_d2d: PORT_BUF_CTL1 on 14, DDI_BUF_CTL on 20 (bits 29/28).
    use crate::intel_gpu_xelpg::XeLpgPort;
    assert_eq!(
        DisplayIp::Xelpdp.d2d(XeLpgPort::A),
        (0x64004, 1 << 29, 1 << 28)
    );
    assert_eq!(
        DisplayIp::Xe2Lpd.d2d(XeLpgPort::A),
        (0x64000, 1 << 29, 1 << 28)
    );
    assert_eq!(DisplayIp::Xe2Lpd.d2d(XeLpgPort::B).0, 0x64100);
    assert_eq!(DisplayIp::Xe2Lpd.d2d(XeLpgPort::Tc1).0, 0x64300);
    assert_eq!(DisplayIp::Xe2Lpd.d2d(XeLpgPort::Tc4).0, 0x64600);
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_xe2lpd", smoke_xe2lpd_source_facts);

// ── CDCLK, MDCLK ratio and DBUF/MBUS values ──────────────────────

fn rung(khz: u32) -> cdclk::Rung {
    cdclk::table(DisplayIp::Xe2Lpd)
        .iter()
        .copied()
        .find(|r| r.cdclk_khz == khz)
        .expect("xe2lpd rung")
}

fn smoke_xe2lpd_cdclk_table_decode_and_ctl() -> TestResult {
    let table = cdclk::table(DisplayIp::Xe2Lpd);
    assert_eq!(table.len(), 21);
    assert_eq!(
        (table[0].cdclk_khz, table[0].ratio, table[0].waveform),
        (153_600, 16, 0xaaaa)
    );
    assert_eq!(
        (table[20].cdclk_khz, table[20].ratio, table[20].waveform),
        (652_800, 34, 0xffff)
    );
    assert_eq!(cdclk::table(DisplayIp::Xelpdp), &cdclk::TABLE[..]);
    // Every rung decodes back from PLL ratio + full-window squash
    // (bxt_get_cdclk), so the table is self-consistent.
    for r in table {
        let io = Regs::with(&[
            (0x46070, 0xc000_0000 | r.ratio),
            (0x46008, cdclk::squash_value(r.waveform)),
            (0x46000, cdclk::ctl_value_ip(DisplayIp::Xe2Lpd, *r)),
        ]);
        assert_eq!(
            crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&io),
            r.cdclk_khz,
            "{}",
            r.cdclk_khz
        );
        let current = Current::read_ip(&io, DisplayIp::Xe2Lpd).unwrap();
        assert_eq!(current.known, Some(*r));
        // The display-14 sanitize does not recognise a display-20 clock.
        assert_ne!(Current::read(&io).unwrap().known, Some(*r));
    }
    assert_eq!(
        cdclk::calc_cdclk_ip(DisplayIp::Xe2Lpd, 1)
            .unwrap()
            .cdclk_khz,
        153_600
    );
    assert_eq!(
        cdclk::calc_cdclk_ip(DisplayIp::Xe2Lpd, 330_001)
            .unwrap()
            .cdclk_khz,
        360_000
    );
    assert_eq!(cdclk::calc_cdclk_ip(DisplayIp::Xe2Lpd, 652_801), None);
    // bxt_cdclk_ctl, display >= 20: CD2X_PIPE_NONE | MDCLK_SOURCE_SEL_CDCLK_PLL,
    // no decimal field; display 14 keeps CD2X_PIPE_NONE | decimal.
    assert_eq!(
        cdclk::ctl_value_ip(DisplayIp::Xe2Lpd, rung(652_800)),
        0x0238_0000
    );
    let mtl = cdclk::TABLE[5];
    assert_eq!(
        cdclk::ctl_value_ip(DisplayIp::Xelpdp, mtl),
        cdclk::ctl_value(mtl)
    );
    assert_eq!(cdclk::ctl_value(mtl), (7 << 19) | 1304);
    // A decimal-field CTL is "unknown" on display 20 (bxt_sanitize_cdclk).
    let io = Regs::with(&[
        (0x46070, 0xc000_0022),
        (0x46008, 0x8f00_ffff),
        (0x46000, (7 << 19) | 1304),
    ]);
    assert_eq!(
        Current::read_ip(&io, DisplayIp::Xe2Lpd).unwrap().known,
        None
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd",
    smoke_xe2lpd_cdclk_table_decode_and_ctl
);

fn known(khz: u32) -> Current {
    let r = rung(khz);
    Current {
        known: Some(r),
        pll: 0xc000_0000 | r.ratio,
        squash: cdclk::squash_value(r.waveform),
        ctl: cdclk::ctl_value_ip(DisplayIp::Xe2Lpd, r),
        actual_khz: khz,
    }
}

fn smoke_xe2lpd_cdclk_plan_squash_crawl_midpoints() -> TestResult {
    let ctl = 0x0238_0000;
    // Raising 153.6 -> 480 MHz: VCO and waveform both change, so
    // cdclk_compute_crawl_and_squash_midpoint squashes first at the old
    // VCO (307.2 MHz, ratio 16, 0xffff), then crawls.
    assert_eq!(
        cdclk::plan_ip(DisplayIp::Xe2Lpd, &known(153_600), rung(480_000)),
        vec![
            Step::Squash { waveform: 0xffff },
            Step::Ctl { value: ctl },
            Step::Crawl { ratio: 25 },
            Step::Squash { waveform: 0xffff },
            Step::Ctl { value: ctl },
        ]
    );
    // Lowering 480 -> 153.6 MHz: crawl first with the old waveform.
    assert_eq!(
        cdclk::plan_ip(DisplayIp::Xe2Lpd, &known(480_000), rung(153_600)),
        vec![
            Step::Crawl { ratio: 16 },
            Step::Squash { waveform: 0xffff },
            Step::Ctl { value: ctl },
            Step::Squash { waveform: 0xaaaa },
            Step::Ctl { value: ctl },
        ]
    );
    // Same VCO: squash only.
    assert_eq!(
        cdclk::plan_ip(DisplayIp::Xe2Lpd, &known(307_200), rung(211_200)),
        vec![Step::Squash { waveform: 0xdbb6 }, Step::Ctl { value: ctl },]
    );
    // An unknown clock takes pll_enable_wa_needed (20.00) and the full
    // disable/enable.
    let unknown = Current {
        known: None,
        pll: 0,
        squash: 0,
        ctl: 0,
        actual_khz: 0,
    };
    assert_eq!(
        cdclk::plan_ip(DisplayIp::Xe2Lpd, &unknown, rung(330_000)),
        vec![
            Step::SquashOff,
            Step::PllDisable,
            Step::PllEnable { ratio: 25 },
            Step::Squash { waveform: 0xdbb6 },
            Step::Ctl { value: ctl },
        ]
    );
    assert!(cdclk::plan_ip(DisplayIp::Xe2Lpd, &known(652_800), rung(652_800)).is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd",
    smoke_xe2lpd_cdclk_plan_squash_crawl_midpoints
);

fn smoke_xe2lpd_mdclk_ratio_dbuf_mbus_and_dbox() -> TestResult {
    // intel_mdclk_cdclk_ratio: DIV_ROUND_UP(vco, cdclk) with the MDCLK on
    // the CDCLK PLL.
    for (khz, ratio) in [
        (153_600, 4),
        (172_800, 4),
        (288_000, 3),
        (307_200, 2),
        (330_000, 3),
        (480_000, 2),
        (487_200, 3),
        (556_800, 2),
        (571_200, 3),
        (652_800, 2),
    ] {
        assert_eq!(mdclk_cdclk_ratio(rung(khz)), ratio, "{khz}");
    }
    // Every rung fits the 3-bit tracker even when joined (ratio <= 4).
    assert!(cdclk::table(DisplayIp::Xe2Lpd)
        .iter()
        .all(|r| mdclk_cdclk_ratio(*r) * 2 - 1 <= 7));
    assert_eq!(mbus_throttle(4), 3 << 13);
    assert_eq!(mbus_throttle(2), 1 << 13);
    assert_eq!(dbuf_min_tracker(4, true), 7 << 16);
    assert_eq!(dbuf_min_tracker(3, false), 2 << 16);
    assert_eq!(dbuf_min_tracker(2, true), 3 << 16);
    // DBUF_CTL: request per slice, tracker state service (23:19) kept,
    // POWER_STATE never written back.
    assert_eq!(
        dbuf_ctl(0, 0x00f8_0000 | (1 << 30), 1, 2, true),
        0x80fb_0000
    );
    assert_eq!(dbuf_ctl(1, 0x8007_0000, 1, 4, false), 0x0003_0000);
    // pipe_mbus_dbox_ctl without the 14.00 BW credits (15:14).
    assert_eq!(dbox(true), 0x0103_0a4c);
    assert_eq!(dbox(false), 0x0103_0a48);
    // Read-modify-write of the throttle and every slice's minimum tracker.
    let io = Regs::with(&[
        (0x4438c, 0xdc00_0000 | (1 << 13) | 1),
        (0x45008, 0xc041_0000),
        (0x44fe8, 0xc041_0000),
        (0x44300, 0x0041_0000),
        (0x44304, 0x0041_0000),
    ]);
    program_mdclk_ratio(&io, rung(153_600), true).unwrap();
    assert_eq!(io.get(0x4438c), 0xdc00_0000 | (3 << 13) | 1);
    assert_eq!(io.written(0x45008), [0x8047_0000]);
    assert_eq!(io.written(0x44300), [0x0047_0000]);
    let io = Regs::with(&[(0x4438c, u32::MAX)]);
    assert_eq!(
        program_mdclk_ratio(&io, rung(153_600), true),
        Err(IpError::NoDevice)
    );
    assert!(io.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd",
    smoke_xe2lpd_mdclk_ratio_dbuf_mbus_and_dbox
);

fn smoke_xe2lpd_pkgc_latency() -> TestResult {
    use crate::intel_gpu_xelpg_wm::Latency;
    let latency = Latency::adjust([6, 8, 10, 12, 14, 16], 0);
    // 1024x768@60: linetime ceil(1344 * 8000 / 65000) = 166 (1/8 us) ->
    // 21 us; skl_watermark_max_latency(1) = 16 us -> roundup(16, 21) = 21.
    assert_eq!(pkgc_latency(&latency, &[166]), Some(21));
    // 1920x1080@60 (148.5 MHz, htotal 2200): 119 -> 15 us; roundup(16) = 30.
    assert_eq!(pkgc_latency(&latency, &[119]), Some(30));
    // The largest pipeline time across pipes.
    assert_eq!(pkgc_latency(&latency, &[119, 166]), Some(21));
    // No pipe, or no latency: the all-ones field.
    assert_eq!(pkgc_latency(&latency, &[]), Some(0x1fff));
    let none = Latency::adjust([6, 0, 0, 0, 0, 0], 0);
    assert_eq!(pkgc_latency(&none, &[166]), Some(0x1fff));
    // Level 0 never counts (initial_wm_level 1).
    let only_l1 = Latency::adjust([30, 9, 0, 0, 0, 0], 0);
    assert_eq!(pkgc_latency(&only_l1, &[8]), Some(30));
    // A rounded value past the 13-bit field is refused.
    let huge = Latency::adjust([1, 8191, 0, 0, 0, 0], 0);
    assert_eq!(pkgc_latency(&huge, &[16]), None);
    let io = Regs::with(&[]);
    program_pkgc_latency(&io, 21).unwrap();
    assert_eq!(io.written(0x46460), [21]);
    assert_eq!(program_pkgc_latency(&io, 0x2000), Err(IpError::NoDevice));
    assert_eq!(io.written(0x46460), [21]);
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_xe2lpd", smoke_xe2lpd_pkgc_latency);

fn smoke_xe2lpd_pica_well_and_d2d_link() -> TestResult {
    use crate::intel_gpu_xelpg::XeLpgPort;
    // xe2lpd_pica_power_well_enable/disable: request bit 31, status bit 30.
    let io = Regs::with(&[]);
    io.mirror.set(Some((0x16fe04, 1 << 31, 1 << 30)));
    assert_eq!(pica_enable(&io), Ok(()));
    assert_eq!(pica_disable(&io), Ok(()));
    assert_eq!(io.written(0x16fe04), [1 << 31, 0]);
    let dead = Regs::with(&[]);
    assert_eq!(pica_enable(&dead), Err(IpError::NoDevice), "no status");
    // D2D on display 20 is DDI_BUF_CTL; PORT_BUF_CTL1 is untouched.
    let io = Regs::with(&[(0x64000, 1 << 31)]);
    io.mirror.set(Some((0x64000, 1 << 29, 1 << 28)));
    assert_eq!(enable_d2d(&io, DisplayIp::Xe2Lpd, XeLpgPort::A), Ok(()));
    assert_eq!(io.written(0x64000), [(1 << 31) | (1 << 29)]);
    assert!(io.written(0x64004).is_empty());
    let io = Regs::with(&[(0x64004, 1 << 24)]);
    io.mirror.set(Some((0x64004, 1 << 29, 1 << 28)));
    assert_eq!(enable_d2d(&io, DisplayIp::Xelpdp, XeLpgPort::A), Ok(()));
    assert_eq!(io.written(0x64004), [(1 << 24) | (1 << 29)]);
    let stuck = Regs::with(&[(0x64300, 0)]);
    assert_eq!(
        enable_d2d(&stuck, DisplayIp::Xe2Lpd, XeLpgPort::Tc1),
        Err(IpError::NoDevice)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd",
    smoke_xe2lpd_pica_well_and_d2d_link
);

// ── Resource transaction ─────────────────────────────────────────

fn panel_request(min_cdclk_khz: u32) -> res::Request {
    let mut request = crate::intel_gpu_display_resources::request(
        &Mode::VESA_1024X768_60,
        crate::intel_gpu_xelpg_wm::Tiling::Linear,
        0,
    );
    request.min_cdclk_khz = min_cdclk_khz;
    request
}

fn latency() -> crate::intel_gpu_xelpg_wm::Latency {
    crate::intel_gpu_xelpg_wm::Latency::adjust([6, 8, 10, 12, 14, 16], 0)
}

fn smoke_xe2lpd_resources_compute_dispatch_keeps_display14() -> TestResult {
    let lnl = res::compute_ip(DisplayIp::Xe2Lpd, &panel_request(0), &latency()).unwrap();
    let mtl = res::compute(&panel_request(0), &latency()).unwrap();
    // Same watermarks, DDB and PM-demand arithmetic; the display-20 table
    // has a lower bottom rung.
    assert_eq!(lnl.dbuf, mtl.dbuf);
    assert_eq!((lnl.ip, mtl.ip), (DisplayIp::Xe2Lpd, DisplayIp::Xelpdp));
    assert_eq!(lnl.cdclk.cdclk_khz, 153_600);
    assert_eq!(mtl.cdclk.cdclk_khz, 172_800);
    assert!(lnl.dbuf.joined);
    // Display 20: ratio 4 joined -> tracker 7, throttle 3, no BW credits.
    assert_eq!(lnl.dbuf_ctl(0, 0, lnl.dbuf.enabled_slices), 0x8007_0000);
    assert_eq!(lnl.dbuf_ctl_mask(), 0xc007_0000);
    assert_eq!(lnl.mbus_ctl_select(None), 0xdc00_6000);
    assert_eq!(lnl.mbus_ctl_mask(), 0xdc00_e000);
    assert_eq!(lnl.dbox(0), 0x0103_0a4c);
    // Display 14 is exactly its Dbuf image.
    for slice in 0..4 {
        assert_eq!(
            mtl.dbuf_ctl(slice, 0x1234, 0xf),
            mtl.dbuf.dbuf_ctl(slice, 0x1234, 0xf)
        );
    }
    assert_eq!(mtl.dbuf_ctl_mask(), 0xc0ff_0000);
    assert_eq!(mtl.mbus_ctl_select(None), mtl.dbuf.mbus_ctl());
    assert_eq!(
        mtl.mbus_ctl_mask(),
        crate::intel_gpu_xelpg_dbuf::MBUS_CTL_MASK
    );
    assert_eq!(mtl.dbox(0), mtl.dbuf.dbox(0));
    assert_eq!(mtl.dbox(0), 0x0103_ca4c);
    // A floor past the table is unsatisfiable on both.
    assert_eq!(
        res::compute_ip(DisplayIp::Xe2Lpd, &panel_request(652_801), &latency()),
        Err(res::ResourceError::CdclkUnsatisfiable)
    );
    // FBC C/D count only on display 20.
    let io = Regs::with(&[(0x43288, 1 << 31)]);
    assert_eq!(
        res::require_idle_ip(&io, DisplayIp::Xe2Lpd),
        Err(res::ResourceError::Busy)
    );
    assert_eq!(res::require_idle_ip(&io, DisplayIp::Xelpdp), Ok(()));
    let io = Regs::with(&[(0x432c8, 1 << 31)]);
    assert_eq!(
        res::require_idle_ip(&io, DisplayIp::Xe2Lpd),
        Err(res::ResourceError::Busy)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_resources",
    smoke_xe2lpd_resources_compute_dispatch_keeps_display14
);

/// The production modeset/resource conversation model of the display-14
/// fixtures (`intel_gpu_display_resources_tests`), presenting display 20:
/// `GMD_ID_DISPLAY` 20.00, the D2D link state in `DDI_BUF_CTL` and the
/// display-20 resource registers.
#[derive(Debug)]
struct Lnl {
    mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake,
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    drop_write: Cell<u64>,
}

impl Lnl {
    fn new() -> Self {
        Self {
            mode: crate::intel_gpu_modeset_xelpg::tests::MtlFake::new(
                crate::intel_gpu_xelpg::XeLpgPort::A,
            ),
            values: RefCell::new(
                [
                    (0x510a0, 20 << 22),
                    (0x45780, 6 | (8 << 16)),
                    (0x45784, 10 | (12 << 16)),
                    (0x45788, 14 | (16 << 16)),
                ]
                .into_iter()
                .collect(),
            ),
            writes: RefCell::new(Vec::new()),
            drop_write: Cell::new(u64::MAX),
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
        modeset(self, &Self::fb(), Some(&Mode::VESA_1024X768_60))
    }
    /// Firmware left a known 652.8 MHz display-20 clock with its ratio-2
    /// MBUS throttle and unjoined minimum trackers.
    fn firmware_clock(&self) {
        self.mode.write32(0x46070, 0x8000_0022);
        self.mode.write32(0x46008, 0x8f00_ffff);
        self.mode.write32(0x46000, 0x0200_0000);
        let mut values = self.values.borrow_mut();
        values.insert(0x4438c, 1 << 13);
        for r in [0x45008, 0x44fe8, 0x44300, 0x44304] {
            values.insert(r, 1 << 16);
        }
        values.insert(0x45230, 3 << 12);
        values.insert(0x45234, 653 << 20);
        drop(values);
        self.writes.borrow_mut().clear();
    }
}

impl MmioWindow for Lnl {
    fn read32(&self, r: u64) -> u32 {
        if Self::resource(r) {
            *self.values.borrow().get(&r).unwrap_or(&0)
        } else if r == 0x46070 {
            // BXT_DE_PLL_FREQ_REQ_ACK follows a pending FREQ_REQ (crawl).
            let v = self.mode.read32(r);
            v | ((v >> 1) & (1 << 22))
        } else if r == 0x64000 {
            // XE2LPD_DDI_BUF_D2D_LINK_STATE follows its enable.
            let v = self.mode.read32(r);
            v | ((v >> 1) & (1 << 28))
        } else {
            self.mode.read32(r)
        }
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        if self.drop_write.get() == r {
            return;
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

fn smoke_xe2lpd_owned_modeset_lights_pipe_a_with_display20_resources() -> TestResult {
    let io = Lnl::new();
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::owned_panel_mode(),
        Some(Mode::VESA_1024X768_60),
        "the owned display-20 layout records the panel"
    );
    // CDCLK: the display-20 bottom rung from an off PLL (full enable), the
    // MDCLK source select instead of a decimal field.
    assert_eq!(io.written(0x46070), [0, 0x10, 0x8000_0010]);
    assert_eq!(io.written(0x46008), [0, 0x8f00_aaaa]);
    assert_eq!(io.written(0x46000), [0x0238_0000]);
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&io),
        153_600
    );
    // Raising from an unknown clock: the ratio follows the clock.
    assert!(io.last(0x46000) < io.first(0x4438c));
    // MBUS joined with throttle 3 (ratio 4), DBUF trackers 7, no BW credits.
    assert_eq!(io.get(0x4438c), 0xdc00_6000);
    for r in [0x45008, 0x44fe8, 0x44300, 0x44304] {
        assert_eq!(io.get(r) & 0xc0ff_0000, 0xc007_0000, "{r:#x}");
    }
    assert_eq!(io.get(0x7003c), 0x0103_0a4c);
    // No PLANE_CHICKEN no-DPT and no 14.00 stepping workaround.
    assert!(io.written(0x7026c).is_empty());
    assert!(io.written(0x46438).is_empty());
    // D2D through DDI_BUF_CTL; PORT_BUF_CTL1 never carries a D2D request.
    assert!(io.written(0x64000).iter().any(|v| v & (1 << 29) != 0));
    assert!(io.written(0x64004).iter().all(|v| v & (1 << 29) == 0));
    // intel_enable_transcoder on display 20: clear INSERT_SF_AT_EOL only.
    assert_eq!(io.written(0x604e0), [0]);
    assert!(io.last(0x604e0) < io.last(0x70008));
    // intel_program_dpkgc_latency after the enables: roundup(16, 21).
    assert_eq!(io.written(0x46460), [21]);
    assert!(io.last(0x70008) < io.first(0x46460));
    // The KMS owners' single-pipe profile proves the same layout.
    let profile =
        crate::intel_gpu_display_resources::Profile::capture(&io, &Mode::VESA_1024X768_60).unwrap();
    assert!(profile.primary.levels[0].enable && profile.cursor.levels[0].enable);
    // A tiled primary is not a display-20 profile (no no-DPT chicken).
    let before = io.writes.borrow().len();
    let linear = io.mode.read32(0x70180);
    io.mode.write32(0x70180, linear | 0x400);
    assert!(
        crate::intel_gpu_display_resources::Profile::capture(&io, &Mode::VESA_1024X768_60).is_err()
    );
    io.mode.write32(0x70180, linear);
    io.writes.borrow_mut().truncate(before);
    // A diverged throttle no longer proves the layout.
    let mbus = io.get(0x4438c);
    io.values.borrow_mut().insert(0x4438c, mbus & !(7 << 13));
    assert!(
        crate::intel_gpu_display_resources::Profile::capture(&io, &Mode::VESA_1024X768_60).is_err()
    );
    io.values.borrow_mut().insert(0x4438c, mbus);
    assert_eq!(io.writes.borrow().len(), before, "captures never write");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_modeset",
    smoke_xe2lpd_owned_modeset_lights_pipe_a_with_display20_resources
);

fn smoke_xe2lpd_owned_modeset_lowers_known_clock_ratio_first() -> TestResult {
    let io = Lnl::new();
    io.firmware_clock();
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    // 652.8 -> 153.6 MHz: crawl to ratio 16 with the old waveform, then
    // squash; CTL keeps the MDCLK select.
    assert_eq!(io.written(0x46070), [0x8000_0010, 0x8080_0010, 0x8000_0010]);
    assert_eq!(io.written(0x46008), [0x8f00_ffff, 0x8f00_aaaa]);
    assert_eq!(io.written(0x46000), [0x0238_0000, 0x0238_0000]);
    // bxt_set_cdclk lowering: the MDCLK ratio goes in before the clock.
    assert!(io.first(0x4438c) < io.first(0x46070));
    assert_eq!(io.written(0x4438c)[0], 3 << 13);
    assert_eq!(io.get(0x4438c), 0xdc00_6000);
    // PM demand covers the old clock until the new one is programmed.
    assert!(io.first(0x45234) < io.first(0x46070));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_modeset",
    smoke_xe2lpd_owned_modeset_lowers_known_clock_ratio_first
);

fn smoke_xe2lpd_owned_modeset_failure_restores_clock_and_ratio() -> TestResult {
    // A refused plane DDB write after the lowered clock restores the
    // original 652.8 MHz clock and, after it (raising), the ratio fields.
    let io = Lnl::new();
    io.firmware_clock();
    io.drop_write.set(0x7027c);
    assert_eq!(io.run(), Err(ModesetError::DisplayResourceUnavailable));
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&io),
        652_800
    );
    assert_eq!(io.mode.read32(0x46000), 0x0200_0000);
    assert_eq!(io.get(0x4438c), 1 << 13);
    for r in [0x45008, 0x44fe8, 0x44300, 0x44304] {
        assert_eq!(io.get(r) & !(1 << 30), 1 << 16, "{r:#x}");
    }
    assert_eq!(io.get(0x45234), 653 << 20);
    assert!(io.last(0x46070) < io.last(0x4438c));
    assert_eq!(io.read32(0x70008) & 0xc000_0000, 0);
    assert!(io.written(0x46460).is_empty(), "no PKG_C on a dark pipe");
    // A fresh retry succeeds.
    io.drop_write.set(u64::MAX);
    assert_eq!(io.run(), Ok(Mode::VESA_1024X768_60));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_modeset",
    smoke_xe2lpd_owned_modeset_failure_restores_clock_and_ratio
);

fn smoke_xe2lpd_raising_floor_programs_ratio_after_clock() -> TestResult {
    // A caller CDCLK floor (force_min_cdclk) raises a known 153.6 MHz clock
    // to 480 MHz: squash at the old VCO, crawl, then the ratio (2).
    let io = Lnl::new();
    io.mode.write32(0x46070, 0x8000_0010);
    io.mode.write32(0x46008, 0x8f00_aaaa);
    io.mode.write32(0x46000, 0x0238_0000);
    io.writes.borrow_mut().clear();
    let profile =
        crate::intel_gpu_display_resources::initialize(&io, &Mode::VESA_1024X768_60, 480_000)
            .unwrap();
    assert!(profile.is_some());
    assert_eq!(io.written(0x46008), [0x8f00_ffff, 0x8f00_ffff]);
    assert_eq!(io.written(0x46070), [0x8000_0019, 0x8080_0019, 0x8000_0019]);
    assert!(io.last(0x46000) < io.first(0x4438c));
    assert_eq!(io.get(0x4438c) & (7 << 13), 1 << 13);
    assert_eq!(io.get(0x45008) & (7 << 16), 3 << 16);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_modeset",
    smoke_xe2lpd_raising_floor_programs_ratio_after_clock
);

fn smoke_xe2lpd_entry_refuses_without_display20_read_only() -> TestResult {
    use crate::intel_gpu::Generation;
    for gmd in [14 << 22, 30 << 22, 0, (20 << 22) | (1 << 14)] {
        let io = Lnl::new();
        io.values.borrow_mut().insert(0x510a0, gmd);
        assert_eq!(io.run(), Err(ModesetError::UnsupportedGeneration));
        assert!(io.writes.borrow().is_empty(), "{gmd:#x}");
    }
    // The generation-level restore dispatch still refuses Lunar Lake: only
    // the per-device admission reaches display 20.
    let io = Lnl::new();
    assert_eq!(
        crate::intel_gpu_modeset::modeset_display(
            &io,
            Generation::LunarLake,
            &Lnl::fb(),
            Some(&Mode::VESA_1024X768_60)
        ),
        Err(ModesetError::UnsupportedGeneration)
    );
    assert!(io.writes.borrow().is_empty());
    // Takeover needs a lit Pipe A and reads only.
    assert_eq!(takeover(&io), None);
    assert!(io.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_modeset",
    smoke_xe2lpd_entry_refuses_without_display20_read_only
);

/// Every access of a window, in order: `(write, register)`.
struct Trace<'a>(&'a Lnl, RefCell<Vec<(bool, u64)>>);

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

impl Trace<'_> {
    /// Whether every read follows four writes of 0 to `DUMMY_REG_OFFSET`
    /// (0x130030); the number of reads.
    fn flushed_reads(&self) -> Option<usize> {
        let events = self.1.borrow();
        let mut reads = 0;
        for (i, &(write, _)) in events.iter().enumerate() {
            if !write {
                if i < 4 || events[i - 4..i].iter().any(|&e| e != (true, 0x130030)) {
                    return None;
                }
                reads += 1;
            }
        }
        Some(reads)
    }
}

/// Wa_15015404425 on the route's probe-time window (`probe_window`): every
/// read of the panel power sequencer, the display-20 modeset and the
/// backlight gate follows xe_mmio.c::mmio_flush_pending_writes' four dummy
/// writes, with the gate opened only once the panel is lit. A refused
/// takeover lights nothing and leaves the gate closed.
fn smoke_xe2lpd_probe_window_flushes_every_read() -> TestResult {
    // GOP left the panel powered: PP_STATUS.PP_ON (bit 31).
    let io = Lnl::new();
    io.mode.write32(0xc7200, 0x8000_0000);
    let trace = Trace(&io, RefCell::new(Vec::new()));
    let lit = probe_window(&trace, &trace, |mmio| {
        modeset(mmio, &Lnl::fb(), Some(&Mode::VESA_1024X768_60)).ok()
    });
    assert_eq!(lit, Ok(Some(Mode::VESA_1024X768_60)));
    assert!(trace.flushed_reads().is_some_and(|reads| reads > 0));
    {
        let events = trace.1.borrow();
        // The sequencer (PP_STATUS) and the modeset (GMD_ID_DISPLAY,
        // TRANSCONF_A) both read through the flush.
        for r in [0xc7200, 0x510a0, 0x70008] {
            assert!(events.contains(&(false, r)), "{r:#x}");
        }
        // The backlight gate (PP_CONTROL) is the window's last write.
        assert_eq!(events.last(), Some(&(true, 0xc7204)));
    }
    assert_ne!(io.mode.read32(0xc7204) & (1 << 2), 0, "EDP_BLC_ENABLE");

    // Pipe A dark: the takeover refuses and the gate stays closed.
    let io = Lnl::new();
    io.mode.write32(0xc7200, 0x8000_0000);
    let trace = Trace(&io, RefCell::new(Vec::new()));
    assert_eq!(
        probe_window(&trace, &trace, |mmio| takeover(mmio)),
        Ok(None)
    );
    assert!(trace.flushed_reads().is_some_and(|reads| reads > 0));
    assert_eq!(io.mode.read32(0xc7204) & (1 << 2), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xe2lpd_modeset",
    smoke_xe2lpd_probe_window_flushes_every_read
);
