//! Display-14 resource transaction tests. Expected values are worked by
//! hand from Linux b90c984d skl_watermark.c / intel_cdclk.c /
//! intel_pmdemand.c; register literals are repeated independently of the
//! production constants. The register model supplies only hardware ACKs.
use super::*;
use crate::intel_gpu_pmdemand::{Demand, Params};
use crate::intel_gpu_xelpg_cdclk::{plan, Current, Rung, Step};
use crate::intel_gpu_xelpg_dbuf::{dbuf_slices, mbus_joined, Entry};
use crate::intel_gpu_xelpg_wm::Level;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Register file with source ACK behavior: PM demand REQ_ENABLE self-clears,
/// DBUF POWER_STATE follows POWER_REQUEST, the CDCLK PLL reports LOCK while
/// enabled and FREQ_REQ_ACK while a frequency request is pending.
#[derive(Debug, Default)]
struct Hw {
    regs: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    drop_write: Cell<u64>,
    no_ack: Cell<bool>,
    no_crawl_ack: Cell<bool>,
    no_lock: Cell<bool>,
    timeout_err: Cell<bool>,
    nth: Cell<(u64, u32)>,
    seen: Cell<u32>,
    uncovered: Cell<u32>,
}

impl Hw {
    fn new() -> Self {
        let hw = Self::default();
        hw.drop_write.set(u64::MAX);
        hw
    }
    fn set(&self, r: u64, v: u32) {
        self.regs.borrow_mut().insert(r, v);
    }
    fn get(&self, r: u64) -> u32 {
        *self.regs.borrow().get(&r).unwrap_or(&0)
    }
    /// Drop only the `n`th write to `r` (1-based).
    fn drop_nth(&self, r: u64, n: u32) {
        self.nth.set((r, n));
    }
    fn dropped(&self, r: u64) -> bool {
        let (reg, n) = self.nth.get();
        if r != reg {
            return false;
        }
        self.seen.set(self.seen.get() + 1);
        self.seen.get() == n
    }
    /// After every CDCLK register write the requested PM demand must cover
    /// the clock the hardware now runs (frequency and voltage level).
    fn monitor(&self, r: u64) {
        if ![0x46070, 0x46008, 0x46000].contains(&r) {
            return;
        }
        let khz = crate::intel_gpu_modeset_xelpg::cdclk_current_khz(self);
        let held = crate::intel_gpu_pmdemand::Params::decode(self.get(0x45230), self.get(0x45234));
        if khz != 0
            && (u32::from(held.cdclk_freq_mhz) * 1000 < khz
                || held.voltage_index < crate::intel_gpu_xelpg_cdclk::voltage_level(khz))
        {
            self.uncovered.set(self.uncovered.get() + 1);
        }
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
            .expect("register written")
    }
    fn last(&self, r: u64) -> usize {
        self.writes
            .borrow()
            .iter()
            .rposition(|(o, _)| *o == r)
            .expect("register written")
    }
}

impl MmioWindow for Hw {
    fn read32(&self, r: u64) -> u32 {
        let v = self.get(r);
        if r == 0x46070 {
            let mut v = v;
            if v & (1 << 31) != 0 && !self.no_lock.get() {
                v |= 1 << 30;
            }
            if v & (1 << 23) != 0 && !self.no_crawl_ack.get() {
                v |= 1 << 22;
            }
            return v;
        }
        v
    }
    fn write32(&self, r: u64, v: u32) {
        self.writes.borrow_mut().push((r, v));
        if r == self.drop_write.get() || self.dropped(r) {
            return;
        }
        let mut stored = v;
        if r == 0x45234 && v & (1 << 31) != 0 && !self.no_ack.get() {
            stored &= !(1 << 31);
            if self.timeout_err.get() {
                let iir = self.get(0x44468);
                self.set(0x44468, iir | (1 << 27));
            }
        }
        if [0x45008, 0x44fe8, 0x44300, 0x44304].contains(&r) {
            stored = if v & (1 << 31) != 0 {
                v | (1 << 30)
            } else {
                v & !(1 << 30)
            };
        }
        if r == 0x46070 {
            stored &= !((1 << 30) | (1 << 22));
        }
        self.set(r, stored);
        self.monitor(r);
    }
}

fn latency() -> Latency {
    Latency::adjust([6, 8, 10, 12, 14, 16], 0)
}

fn plane(width: u16, height: u16) -> Option<PlaneRequest> {
    Some(PlaneRequest {
        width,
        height,
        cpp: 4,
        tiling: Tiling::Linear,
    })
}

fn pipe(
    pixel: u32,
    (h, ht): (u16, u16),
    (v, vt): (u16, u16),
    port: u32,
    phy: u8,
) -> Option<PipeRequest> {
    let mut planes = [None; PLANES];
    planes[0] = plane(h, v);
    Some(PipeRequest {
        pixel_rate_khz: pixel,
        hdisplay: h,
        htotal: ht,
        vdisplay: v,
        vtotal: vt,
        planes,
        cursor_visible: false,
        port_clock_khz: port,
        combo_phy: Some(phy),
        dsc: None,
        src_w: None,
        src_h: None,
        scaler: None,
        bigjoiner_slave: None,
    })
}

fn two_pipes() -> Request {
    let mut pipes = [None; PIPES];
    pipes[0] = pipe(148_500, (1920, 2200), (1080, 1125), 540_000, 0);
    pipes[1] = pipe(74_250, (1280, 1650), (720, 750), 270_000, 1);
    Request {
        pipes,
        min_cdclk_khz: 0,
    }
}

fn smoke_xelpg_wm_latency_adjust_read_and_sagv_block() -> TestResult {
    // sanitize_wm_latency: levels after the first zero (level >= 1) clear.
    assert_eq!(
        Latency::adjust([6, 9, 0, 18, 24, 31], 0).levels,
        [6, 9, 0, 0, 0, 0]
    );
    // make_wm_latency_monotonic.
    assert_eq!(
        Latency::adjust([9, 4, 13, 18, 24, 31], 0).levels,
        [9, 9, 13, 18, 24, 31]
    );
    // WaWmMemoryReadLatency: display >= 14 adds 6us, not Gen12's 3us.
    assert_eq!(
        Latency::adjust([0, 5, 9, 0, 0, 0], 0).levels,
        [6, 11, 15, 0, 0, 0]
    );
    // mtl_read_wm_latency: 13-bit even/odd fields; QCLK_SAGV is 12:0.
    let hw = Hw::new();
    hw.set(0x45780, 0xe000_0000 | (8 << 16) | 0x2000 | 6);
    hw.set(0x45784, 10 | (12 << 16));
    hw.set(0x45788, 14 | (16 << 16));
    hw.set(0x4578c, 0xffff_e000 | 20);
    // tgl_get_bw_info: exactly one QGV point (SAGV disabled in the BIOS)
    // is I915_SAGV_NOT_CONTROLLED, and intel_sagv_init then zeroes the
    // block time, so no SAGV watermark is computed. One LPDDR5 point on
    // eight channels.
    hw.set(0x45700, (1 << 8) | (8 << 4) | 2);
    hw.set(0x45710, (30 << 24) | (30 << 16) | 192);
    hw.set(0x45714, (68 << 8) | 15);
    let l = Latency::read(&hw).unwrap();
    assert_eq!(l.levels, [6, 8, 10, 12, 14, 16]);
    assert_eq!((l.sagv_block_us, l.qgv), (0, None));
    // Zero enabled QGV points is NARF policy, not Linux: tgl_get_bw_info
    // sets I915_SAGV_ENABLED for any count other than one, so Linux keeps
    // the 20 us block time and mtl_find_qgv_points returns -EINVAL for
    // every state that can enable SAGV (no point carries its data rate).
    // NARF treats it as uncontrolled: SAGV stays masked (QCLK_GV_BW
    // 0xffff) with no SAGV watermark, costing power, never admission.
    hw.set(0x45700, (8 << 4) | 2);
    let l = Latency::read(&hw).unwrap();
    assert_eq!((l.sagv_block_us, l.qgv), (0, None));
    // Two LPDDR5 QGV points on eight channels: SAGV is controllable.
    hw.set(0x45700, (2 << 8) | (8 << 4) | 2);
    hw.set(0x45710, (30 << 24) | (30 << 16) | 120);
    hw.set(0x45714, (68 << 8) | 15);
    hw.set(0x45718, (30 << 24) | (30 << 16) | 192);
    hw.set(0x4571c, (68 << 8) | 15);
    let l = Latency::read(&hw).unwrap();
    assert_eq!(l.sagv_block_us, 20);
    assert_eq!(l.qgv.unwrap().points[1].dclk, 3200);
    hw.set(0x45784, u32::MAX);
    assert_eq!(Latency::read(&hw), Err(FsError::NoDevice));
    assert!(
        hw.writes.borrow().is_empty(),
        "latency readout is read-only"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_wm_latency_adjust_read_and_sagv_block
);

fn smoke_xelpg_wm_display14_levels_tile4_sagv_and_255_lines() -> TestResult {
    // 64-wide XRGB at 1 GHz, htotal 16000: linetime 16us, latency 15 takes
    // method1 = 117.1875 + 1 -> blocks 120, lines ceil(118.1875/2) = 60.
    // Display >= 13 allows 255 lines; the Gen12 transcription caps at 31.
    let t = wm::Timing {
        pixel_rate_khz: 1_000_000,
        htotal: 16_000,
        vtotal: 2000,
        vblank_start: 1000,
    };
    let lat = Latency {
        levels: [15, 0, 0, 0, 0, 0],
        sagv_block_us: 0,
        qgv: None,
    };
    let s = Surface {
        width: 64,
        cpp: 4,
        tiling: Tiling::Linear,
    };
    let w = wm::plane(t, s, &lat).unwrap();
    assert_eq!(
        w.levels[0],
        Level {
            enable: true,
            blocks: 120,
            lines: 60,
            min_ddb_alloc: 133
        }
    );
    assert_eq!(w.levels[0].encode(0x1fff), Some(0x800f_0078));
    // Latency 0 levels are rejected with an unusable minimum.
    assert!(!w.levels[1].enable && w.levels[1].min_ddb_alloc == u16::MAX);
    let gen12 = crate::intel_gpu_wm::compute_plane_watermarks(
        &crate::intel_gpu_wm::WmParams {
            pixel_rate_khz: 1_000_000,
            htotal: 16_000,
            width_px: 64,
            cpp: 4,
        },
        &[15, 0, 0, 0, 0, 0],
        0,
    );
    assert!(!gen12.levels[0].enable, "Gen12 results stay unchanged");
    // Tile4 64x XRGB, 1034 kHz/htotal 224: y_tile_minimum 3.0 dominates;
    // blocks 4, lines 4, transition max(3, 6) + 15 = 21.
    let t = wm::Timing {
        pixel_rate_khz: 1034,
        htotal: 224,
        vtotal: 77,
        vblank_start: 32,
    };
    let tile4 = Surface {
        width: 64,
        cpp: 4,
        tiling: Tiling::Tile4,
    };
    let w = wm::plane(t, tile4, &latency()).unwrap();
    for l in w.levels {
        assert_eq!(l.encode(0x1fff), Some(0x8001_0004));
        assert_eq!(l.min_ddb_alloc, 7);
    }
    assert_eq!(w.trans.encode(0x1fff), Some(0x8000_0015));
    assert!(!w.sagv.enable && !w.sagv_trans.enable);
    // X-tiled uses the linear arithmetic on display >= 10.
    let x = Surface {
        tiling: Tiling::X,
        ..s
    };
    assert_eq!(
        wm::plane(t, x, &latency()).unwrap(),
        wm::plane(t, s, &latency()).unwrap()
    );
    // tgl_compute_sagv_wm: 1024 linear at 65 MHz, block 20us + level0 6us
    // >= linetime 21us -> method2 2 lines * 9 blocks: 19 blocks, 2 lines.
    let t = wm::Timing {
        pixel_rate_khz: 65_000,
        htotal: 1344,
        vtotal: 806,
        vblank_start: 768,
    };
    let lat = Latency::adjust([6, 8, 10, 12, 14, 16], 20);
    let s = Surface {
        width: 1024,
        cpp: 4,
        tiling: Tiling::Linear,
    };
    let w = wm::plane(t, s, &lat).unwrap();
    assert_eq!(
        w.sagv,
        Level {
            enable: true,
            blocks: 19,
            lines: 2,
            min_ddb_alloc: 22
        }
    );
    assert_eq!(w.levels[0].blocks, 9);
    assert_eq!(w.trans.blocks, 23);
    assert_eq!(w.sagv_trans.blocks, 33);
    // Inputs Linux would wrap in u32 are refused, not emulated.
    let huge = Latency {
        levels: [8000, 0, 0, 0, 0, 0],
        sagv_block_us: 0,
        qgv: None,
    };
    let t = wm::Timing {
        pixel_rate_khz: 1_305_600,
        htotal: 16_000,
        vtotal: 2000,
        vblank_start: 1000,
    };
    assert_eq!(
        wm::plane(
            t,
            Surface {
                width: 64,
                cpp: 8,
                tiling: Tiling::Linear
            },
            &huge
        ),
        Err(WmError::Unsupported)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_wm_display14_levels_tile4_sagv_and_255_lines
);

fn smoke_xelpg_wm_cursor_allocation_and_vblank_prefill_limit() -> TestResult {
    let t = wm::Timing {
        pixel_rate_khz: 148_500,
        htotal: 2200,
        vtotal: 1125,
        vblank_start: 1080,
    };
    // skl_cursor_allocation at the 256-pixel cursor_width: level5 needs 22.
    assert_eq!(wm::cursor_allocation(t, &latency(), 1), Ok(32));
    assert_eq!(wm::cursor_allocation(t, &latency(), 2), Ok(22));
    let t = wm::Timing {
        pixel_rate_khz: 74_250,
        htotal: 1650,
        vtotal: 750,
        vblank_start: 720,
    };
    assert_eq!(wm::cursor_allocation(t, &latency(), 3), Ok(15));
    // 1024x768@65MHz with a 3-line vblank: fixed 1.97 lines + adjusted wm0
    // (cursor 3 lines) + latency lines leaves level1 as the deepest level.
    let lat = Latency::adjust([6, 8, 10, 12, 14, 16], 20);
    let t = wm::Timing {
        pixel_rate_khz: 65_000,
        htotal: 1344,
        vtotal: 771,
        vblank_start: 768,
    };
    let s = Surface {
        width: 1024,
        cpp: 4,
        tiling: Tiling::Linear,
    };
    let mut primary = wm::plane(t, s, &lat).unwrap();
    let mut cursor = wm::plane(
        t,
        Surface {
            width: 64,
            cpp: 4,
            tiling: Tiling::Linear,
        },
        &lat,
    )
    .unwrap();
    assert_eq!(cursor.levels[0].lines, 3);
    let before = primary;
    wm::check_vblank(t, &lat, &mut [&mut primary, &mut cursor]).unwrap();
    assert!(primary.levels[0].enable && primary.levels[1].enable);
    for l in 2..6 {
        assert!(!primary.levels[l].enable && !cursor.levels[l].enable);
        // Linux clears only the enable bit; the register keeps blocks/lines.
        assert_eq!(primary.levels[l].blocks, before.levels[l].blocks);
        assert_eq!(
            primary.levels[l].min_ddb_alloc,
            before.levels[l].min_ddb_alloc
        );
    }
    assert!(!primary.sagv.enable && primary.sagv.blocks == before.sagv.blocks);
    assert_eq!(
        primary.levels[2].encode(0x1fff),
        Some((u32::from(before.levels[2].lines) << 14) | u32::from(before.levels[2].blocks))
    );
    // Two lines cannot even hold level0 prefill: a typed refusal.
    let t = wm::Timing { vtotal: 770, ..t };
    let mut primary = wm::plane(t, s, &lat).unwrap();
    assert_eq!(
        wm::check_vblank(t, &lat, &mut [&mut primary]),
        Err(WmError::VblankTooShort)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_wm_cursor_allocation_and_vblank_prefill_limit
);

fn smoke_xelpg_dbuf_slices_join_dbox_and_tracker() -> TestResult {
    const AB: u8 = 0x3;
    const CD: u8 = 0xc;
    assert!(mbus_joined(0x1) && mbus_joined(0x2));
    for active in [0x3, 0x4, 0x8, 0xf, 0x5] {
        assert!(!mbus_joined(active));
    }
    assert_eq!(dbuf_slices(0, 0x1, true), 0xf);
    assert_eq!(dbuf_slices(0, 0x1, false), AB);
    assert_eq!(dbuf_slices(1, 0x2, true), 0xf);
    let all: Vec<u8> = (0..4).map(|p| dbuf_slices(p, 0xf, false)).collect();
    assert_eq!(all, [AB, CD, CD, AB]);
    assert_eq!(dbuf_slices(2, 0x6, false), CD);
    assert_eq!(dbuf_slices(3, 0x9, false), AB);
    // A pipe outside the active set has no slices.
    assert_eq!(dbuf_slices(2, 0x3, false), 0);
    let joined = Dbuf {
        active_pipes: 0x1,
        joined: true,
        ..Default::default()
    };
    // pipe_mbus_dbox_ctl, display 14.00: I2, B2B 16/1/regulate, A12, B10, BW8.
    assert_eq!(joined.dbox(0), 0x0103_ca4c);
    assert_eq!(joined.mbus_ctl(), 0xdc00_0000);
    assert_eq!(joined.dbuf_ctl(1, 0x4000_0007, 0xf), 0x8043_0007);
    let ab = Dbuf {
        active_pipes: 0x3,
        joined: false,
        ..Default::default()
    };
    assert_eq!(ab.dbox(0), 0x0103_ca48);
    assert_eq!(ab.dbox(1), 0x0103_ca48);
    assert_eq!(ab.mbus_ctl(), 0x1c00_0000);
    // Unjoined MDCLK ratio2 -> min tracker1; unused slices drop REQUEST.
    assert_eq!(ab.dbuf_ctl(2, 0xc000_0000, 0x3), 0x0041_0000);
    let ad = Dbuf {
        active_pipes: 0x9,
        joined: false,
        ..Default::default()
    };
    // Two pipes share the A/D bank: 4 bandwidth credits each.
    assert_eq!(ad.dbox(0), 0x0103_8a48);
    assert_eq!(ad.dbox(3), 0x0103_8a48);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_dbuf_slices_join_dbox_and_tracker
);

fn synthetic(min: [u16; 6]) -> PlaneWm {
    let mut w = PlaneWm::default();
    for (l, m) in min.into_iter().enumerate() {
        w.levels[l] = Level {
            enable: true,
            blocks: m - 2,
            lines: l as u16 + 1,
            min_ddb_alloc: m,
        };
    }
    w
}

fn synthetic_pipe(hdisplay: u16, planes: &[([u16; 6], u64)], cursor: [u16; 6]) -> PipeInput {
    let mut p = [None; PLANES];
    for (i, (min, rate)) in planes.iter().enumerate() {
        p[i] = Some(PlaneInput {
            wm: synthetic(*min),
            rel_data_rate: *rate,
            data_rate: 1000,
        });
    }
    PipeInput {
        hdisplay,
        planes: p,
        cursor_alloc: 32,
        cursor_wm: synthetic(cursor),
    }
}

fn smoke_xelpg_ddb_multi_pipe_weights_plane_split_and_level_limit() -> TestResult {
    // Two planes, relative rates 2:1: level5 fits; leftovers split 2666/1333.
    let mut pipes = [None; PIPES];
    pipes[0] = Some(synthetic_pipe(
        1000,
        &[([10, 20, 30, 40, 50, 60], 200), ([5; 6], 100)],
        [8; 6],
    ));
    let d = dbuf::compute(&pipes).unwrap();
    let a = d.pipes[0];
    assert!(d.joined && d.enabled_slices == 0xf && a.level == 5);
    assert_eq!(
        a.cursor,
        Entry {
            start: 4064,
            end: 4096
        }
    );
    assert_eq!(
        a.planes[0],
        Entry {
            start: 0,
            end: 2726
        }
    );
    assert_eq!(
        a.planes[1],
        Entry {
            start: 2726,
            end: 4064
        }
    );
    // Level search falls to 3 (3900 of 4064); higher levels exceed their
    // plane's final DDB, are cleared and take level-n-1 blocks/lines.
    pipes[0] = Some(synthetic_pipe(
        1000,
        &[
            ([1000, 1500, 2000, 2500, 3000, 3500], 200),
            ([500, 800, 1100, 1400, 1700, 2000], 100),
        ],
        [8, 8, 8, 8, 8, 40],
    ));
    let a = dbuf::compute(&pipes).unwrap().pipes[0];
    assert_eq!(a.level, 3);
    assert_eq!(
        a.planes[0],
        Entry {
            start: 0,
            end: 2610
        }
    );
    assert_eq!(
        a.planes[1],
        Entry {
            start: 2610,
            end: 4064
        }
    );
    for l in [4, 5] {
        let w = a.wm[0].levels[l];
        assert!(!w.enable && w.min_ddb_alloc == 0);
        assert_eq!((w.blocks, w.lines), (2498, 4));
    }
    // The cursor's level5 exceeds its 32 blocks: cleared and copied.
    let c = a.cursor_wm.levels[5];
    assert!(!c.enable && c.blocks == 6 && c.lines == 5);
    // Level0 alone exceeds the DDB: typed refusal.
    pipes[0] = Some(synthetic_pipe(
        1000,
        &[([3000; 6], 1), ([2000; 6], 1)],
        [8; 6],
    ));
    assert_eq!(dbuf::compute(&pipes), Err(DdbError::Exhausted));
    // A + D share S1/S2 by hdisplay weight 1920:1280.
    let mut pipes = [None; PIPES];
    pipes[0] = Some(synthetic_pipe(1920, &[([10; 6], 1)], [8; 6]));
    pipes[3] = Some(synthetic_pipe(1280, &[([10; 6], 1)], [8; 6]));
    let d = dbuf::compute(&pipes).unwrap();
    assert!(!d.joined && d.slices[0] == 0x3 && d.slices[3] == 0x3);
    assert_eq!(d.enabled_slices, 0x3);
    assert_eq!(
        d.pipes[0].ddb,
        Entry {
            start: 0,
            end: 1228
        }
    );
    assert_eq!(
        d.pipes[3].ddb,
        Entry {
            start: 1228,
            end: 2048
        }
    );
    assert_eq!(
        d.pipes[3].cursor,
        Entry {
            start: 2016,
            end: 2048
        }
    );
    // Four pipes: B/C in S3/S4 are MBUS-relative from 0; absolutes are
    // disjoint across the whole 4096-block DBUF.
    let mut pipes = [None; PIPES];
    for (p, h) in [(0, 1920), (1, 1280), (2, 1280), (3, 640)] {
        pipes[p] = Some(synthetic_pipe(h, &[([10; 6], 1)], [8; 6]));
    }
    let d = dbuf::compute(&pipes).unwrap();
    assert_eq!(
        d.pipes[1].ddb,
        Entry {
            start: 0,
            end: 1024
        }
    );
    assert_eq!(
        d.pipes[2].ddb,
        Entry {
            start: 1024,
            end: 2048
        }
    );
    assert_eq!(
        d.pipes[1].absolute,
        Entry {
            start: 2048,
            end: 3072
        }
    );
    assert_eq!(
        d.pipes[2].absolute,
        Entry {
            start: 3072,
            end: 4096
        }
    );
    assert_eq!(
        d.pipes[0].absolute,
        Entry {
            start: 0,
            end: 1536
        }
    );
    assert_eq!(
        d.pipes[3].absolute,
        Entry {
            start: 1536,
            end: 2048
        }
    );
    assert_eq!(dbuf::compute(&[None; PIPES]), Err(DdbError::Unsupported));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_ddb_multi_pipe_weights_plane_split_and_level_limit
);

fn known(cdclk_khz: u32) -> Current {
    let rung = crate::intel_gpu_xelpg_cdclk::TABLE
        .into_iter()
        .find(|r| r.cdclk_khz == cdclk_khz)
        .unwrap();
    Current {
        known: Some(rung),
        pll: 0xc000_0000 | rung.ratio,
        squash: cdclk::squash_value(rung.waveform),
        ctl: cdclk::ctl_value(rung),
        actual_khz: cdclk_khz,
    }
}

fn rung(cdclk_khz: u32) -> Rung {
    cdclk::calc_cdclk(cdclk_khz).unwrap()
}

fn smoke_xelpg_cdclk_compute_classify_and_crawl_squash_plans() -> TestResult {
    assert_eq!(cdclk::calc_cdclk(1).unwrap().cdclk_khz, 172_800);
    assert_eq!(cdclk::calc_cdclk(192_001).unwrap().cdclk_khz, 307_200);
    assert_eq!(cdclk::calc_cdclk(652_801), None);
    for (khz, level) in [
        (307_200, 0),
        (312_000, 0),
        (480_000, 1),
        (556_800, 2),
        (652_800, 3),
    ] {
        assert_eq!(cdclk::voltage_level(khz), level);
    }
    assert_eq!(cdclk::port_min_voltage_level(594_000), 0);
    assert_eq!(cdclk::port_min_voltage_level(810_000), 1);
    let ctl = |khz: u32| cdclk::ctl_value(rung(khz));
    // Lowering 652.8 -> 172.8: crawl first with the old waveform to the
    // 307.2 midpoint, then squash.
    assert_eq!(
        plan(&known(652_800), rung(172_800)),
        vec![
            Step::Crawl { ratio: 16 },
            Step::Squash { waveform: 0 },
            Step::Ctl {
                value: ctl(307_200)
            },
            Step::Squash { waveform: 0xad5a },
            Step::Ctl {
                value: ctl(172_800)
            },
        ]
    );
    // Raising: squash first at the old VCO, then crawl.
    assert_eq!(
        plan(&known(172_800), rung(652_800)),
        vec![
            Step::Squash { waveform: 0 },
            Step::Ctl {
                value: ctl(307_200)
            },
            Step::Crawl { ratio: 34 },
            Step::Squash { waveform: 0 },
            Step::Ctl {
                value: ctl(652_800)
            },
        ]
    );
    assert_eq!(
        plan(&known(480_000), rung(652_800)),
        vec![
            Step::Crawl { ratio: 34 },
            Step::Squash { waveform: 0 },
            Step::Ctl {
                value: ctl(652_800)
            },
        ]
    );
    assert_eq!(
        plan(&known(307_200), rung(192_000)),
        vec![
            Step::Squash { waveform: 0xb6b6 },
            Step::Ctl {
                value: ctl(192_000)
            },
        ]
    );
    assert!(plan(&known(480_000), rung(480_000)).is_empty());
    let unknown = Current {
        known: None,
        ..known(652_800)
    };
    assert_eq!(
        plan(&unknown, rung(307_200)),
        vec![
            Step::SquashOff,
            Step::PllDisable,
            Step::PllEnable { ratio: 16 },
            Step::Squash { waveform: 0 },
            Step::Ctl {
                value: ctl(307_200)
            },
        ]
    );
    assert_eq!(ctl(172_800), (7 << 19) | 344);
    assert_eq!(ctl(652_800), (7 << 19) | 1304);
    // bxt_sanitize_cdclk classification of real register values.
    let hw = Hw::new();
    hw.set(0x46070, 0x8000_0022);
    hw.set(0x46000, 1304); // CD2X pipe A field is ignored
    assert_eq!(Current::read(&hw).unwrap().known, Some(rung(652_800)));
    hw.set(0x46000, 0); // wrong decimal
    assert_eq!(Current::read(&hw).unwrap().known, None);
    hw.set(0x46000, (1 << 22) | 1304); // CD2X divider is not DIV_SEL_1
    assert_eq!(Current::read(&hw).unwrap().known, None);
    hw.set(0x46070, 0); // PLL off is unknown (vco = ~0)
    assert_eq!(Current::read(&hw).unwrap().known, None);
    hw.set(0x46070, 0x8000_0022);
    hw.no_lock.set(true);
    assert_eq!(Current::read(&hw), Err(CdclkError::Unlocked));
    assert!(hw.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_cdclk_compute_classify_and_crawl_squash_plans
);

fn smoke_xelpg_cdclk_program_crawl_lowering_and_ack_timeout() -> TestResult {
    let hw = Hw::new();
    hw.set(0x46070, 0x8000_0022);
    hw.set(0x46000, (7 << 19) | 1304);
    let old = Current::read(&hw).unwrap();
    cdclk::program(&hw, &old, rung(172_800)).unwrap();
    // adlp_cdclk_pll_crawl: ratio with ENABLE, FREQ_REQ, then drop FREQ_REQ.
    assert_eq!(hw.written(0x46070), [0x8000_0010, 0x8080_0010, 0x8000_0010]);
    assert_eq!(hw.written(0x46008), [0, 0x8f00_ad5a]);
    assert_eq!(hw.written(0x46000), [(7 << 19) | 612, (7 << 19) | 344]);
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&hw),
        172_800
    );
    // No FREQ_REQ_ACK: bounded typed timeout, no CTL programming after it.
    let hw = Hw::new();
    hw.set(0x46070, 0x8000_0022);
    hw.set(0x46000, (7 << 19) | 1304);
    hw.no_crawl_ack.set(true);
    let old = Current::read(&hw).unwrap();
    assert_eq!(
        cdclk::program(&hw, &old, rung(172_800)),
        Err(CdclkError::Timeout)
    );
    assert!(hw.written(0x46000).is_empty());
    // Restoration returns the known original through the source sequence.
    hw.no_crawl_ack.set(false);
    cdclk::restore(&hw, &old).unwrap();
    assert_eq!(hw.get(0x46070) & 0x8000_00ff, 0x8000_0022);
    assert_eq!(hw.get(0x46000), (7 << 19) | 1304);
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&hw),
        652_800
    );
    // Unknown, PLL off: wa_15010685871 squash-off, RMW disable, enable.
    let hw = Hw::new();
    let old = Current::read(&hw).unwrap();
    cdclk::program(&hw, &old, rung(192_000)).unwrap();
    assert_eq!(hw.written(0x46070), [0, 16, 0x8000_0010]);
    assert_eq!(hw.written(0x46008), [0, 0x8f00_b6b6]);
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&hw),
        192_000
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_cdclk_program_crawl_lowering_and_ack_timeout
);

fn smoke_xelpg_pmdemand_params_pre_post_and_refusals() -> TestResult {
    let new = Demand {
        qgv_peak_bw: None,
        enabled_slices: 0xf,
        active_pipes: 0xf,
        voltage_level: 1,
        cdclk_khz: 172_800,
        max_port_clock_khz: 810_000,
        combo_phys: 0x3,
    }
    .params();
    assert_eq!(
        new,
        Params {
            qclk_gv_bw: 0xffff,
            voltage_index: 1,
            qclk_gv_index: 0,
            active_pipes: 3,
            active_dbufs: 3,
            active_phys: 2,
            plls: 3,
            cdclk_freq_mhz: 173,
            ddiclk_max: 810,
            scalers: 7,
        }
    );
    let (r0, r1) = new.apply(0x0000_8008, 0x8000_0008);
    assert_eq!(r0, 0xffff_10f2 | 0x8008);
    assert_eq!(r1, 0x8000_0008 | (173 << 20) | (810 << 8) | (7 << 4) | 3);
    assert_eq!(Params::decode(r0, r1), new);
    // Pre-plane keeps the higher firmware clock/voltage; post lowers.
    let hw = Hw::new();
    let old = Params {
        voltage_index: 3,
        cdclk_freq_mhz: 653,
        ..Default::default()
    };
    let (o0, o1) = old.apply(0, 0);
    hw.set(0x45230, o0);
    hw.set(0x45234, o1);
    assert_eq!(pmdemand::program(&hw, &new, Some(&old)), Ok(true));
    assert_eq!((hw.get(0x45230) >> 12) & 7, 3);
    assert_eq!((hw.get(0x45234) >> 20) & 2047, 653);
    assert_eq!(pmdemand::program(&hw, &new, None), Ok(true));
    assert_eq!(Params::decode(hw.get(0x45230), hw.get(0x45234)), new);
    // Unchanged values initiate no request.
    let count = hw.writes.borrow().len();
    assert_eq!(pmdemand::program(&hw, &new, None), Ok(false));
    assert_eq!(hw.writes.borrow().len(), count);
    // A missing response is a bounded timeout and leaves REQ_ENABLE set.
    let hw = Hw::new();
    hw.no_ack.set(true);
    assert_eq!(pmdemand::program(&hw, &new, None), Err(FsError::TimedOut));
    assert_ne!(hw.get(0x45234) & (1 << 31), 0);
    assert_eq!(pmdemand::current(&hw), Err(FsError::TimedOut));
    // A latched response timeout refuses success.
    let hw = Hw::new();
    hw.timeout_err.set(true);
    assert_eq!(pmdemand::program(&hw, &new, None), Err(FsError::NoDevice));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_pmdemand_params_pre_post_and_refusals
);

fn smoke_xelpg_resources_compute_two_pipe_state_and_refusals() -> TestResult {
    let state = compute(&two_pipes(), &latency()).unwrap();
    let d = &state.dbuf;
    assert!(!d.joined && d.active_pipes == 0x3 && d.enabled_slices == 0xf);
    assert_eq!((d.slices[0], d.slices[1]), (0x3, 0xc));
    assert_eq!(
        d.pipes[0].absolute,
        Entry {
            start: 0,
            end: 2048
        }
    );
    assert_eq!(
        d.pipes[1].ddb,
        Entry {
            start: 0,
            end: 2048
        }
    );
    assert_eq!(
        d.pipes[1].absolute,
        Entry {
            start: 2048,
            end: 4096
        }
    );
    // num_active 2: cursor sizes are the level5 minimums, not 32.
    assert_eq!(
        d.pipes[0].cursor,
        Entry {
            start: 2026,
            end: 2048
        }
    );
    assert_eq!(
        d.pipes[1].cursor,
        Entry {
            start: 2033,
            end: 2048
        }
    );
    assert_eq!(
        d.pipes[0].planes[0],
        Entry {
            start: 0,
            end: 2026
        }
    );
    assert_eq!(
        d.pipes[1].planes[0],
        Entry {
            start: 0,
            end: 2033
        }
    );
    assert!(d.pipes[0].wm[0].levels.iter().all(|l| l.enable));
    // Pixel-rate minimum 74.25 MHz selects the lowest rung; no port above
    // 594 MHz keeps voltage level 0.
    assert_eq!(state.cdclk.cdclk_khz, 172_800);
    assert_eq!(state.voltage_level, 0);
    assert_eq!(
        state.pmdemand,
        Params {
            qclk_gv_bw: 0xffff,
            voltage_index: 0,
            qclk_gv_index: 0,
            active_pipes: 2,
            active_dbufs: 3,
            active_phys: 2,
            plls: 3,
            cdclk_freq_mhz: 173,
            ddiclk_max: 540,
            scalers: 7,
        }
    );
    // Hidden cursors keep their DDB but program zero WMs.
    let regs = state.plane_registers().unwrap();
    let value = |r: u64| regs.iter().find(|(o, _)| *o == r).unwrap().1;
    assert_eq!(value(0x70140), 0);
    assert_eq!(value(0x7017c), (2047 << 16) | 2026);
    assert_eq!(value(0x7117c), (2047 << 16) | 2033);
    assert_eq!(value(0x7027c), 2025 << 16);
    assert_eq!(value(0x7227c), 0, "inactive pipe C stays zero");
    // A caller floor raises the rung and its voltage.
    let mut floor = two_pipes();
    floor.min_cdclk_khz = 500_000;
    let s = compute(&floor, &latency()).unwrap();
    assert_eq!((s.cdclk.cdclk_khz, s.voltage_level), (556_800, 2));
    floor.min_cdclk_khz = 700_000;
    assert_eq!(
        compute(&floor, &latency()),
        Err(ResourceError::CdclkUnsatisfiable)
    );
    // Typed refusals, all before any register access.
    let empty = Request {
        pipes: [None; PIPES],
        min_cdclk_khz: 0,
    };
    assert_eq!(compute(&empty, &latency()), Err(ResourceError::Unsupported));
    let mut wide = two_pipes();
    wide.pipes[1].as_mut().unwrap().planes[0] = plane(1281, 720);
    assert_eq!(compute(&wide, &latency()), Err(ResourceError::Unsupported));
    let mut short = two_pipes();
    short.pipes[0].as_mut().unwrap().vtotal = 1081;
    assert_eq!(
        compute(&short, &latency()),
        Err(ResourceError::VblankTooShort)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_resources_compute_two_pipe_state_and_refusals
);

const GLOBAL: [u64; 14] = [
    0x45230, 0x45234, 0x46070, 0x46008, 0x46000, 0x45008, 0x44fe8, 0x44300, 0x44304, 0x4438c,
    0x7003c, 0x7103c, 0x7203c, 0x7303c,
];

fn firmware(hw: &Hw) {
    // Known 307.2 MHz clock, joined single-pipe layout and some plane state.
    hw.set(0x46070, 0x8000_0010);
    hw.set(0x46000, 612);
    hw.set(0x45230, 0xffff_1071);
    hw.set(0x45234, (308 << 20) | (810 << 8) | (7 << 4) | 2);
    for r in [0x45008, 0x44fe8, 0x44300, 0x44304] {
        hw.set(r, 0xc043_0000);
    }
    hw.set(0x4438c, 0xdc00_0000 | 5);
    hw.set(0x7003c, 0x0103_ca4c);
    hw.set(0x70240, 0x8000_4003);
    hw.set(0x7027c, 2047 << 16);
    hw.set(0x7117c, 0x1234);
}

fn smoke_xelpg_resources_commit_two_pipes_in_source_order() -> TestResult {
    let hw = Hw::new();
    firmware(&hw);
    let state = compute(&two_pipes(), &latency()).unwrap();
    commit(&hw, &state).unwrap();
    // PM demand pre-plane, then CDCLK, DBUF, MBUS/DBOX, plane WM/DDB.
    let req = hw.first(0x45234);
    let clk = hw.first(0x46008);
    let slices = hw.first(0x45008);
    let mbus = hw.first(0x4438c);
    let planes = hw.first(0x70240);
    assert!(req < clk && clk < slices && slices < mbus && mbus < planes);
    // 307.2 -> 172.8 at the same VCO is a squash-only change.
    assert!(hw.written(0x46070).is_empty());
    assert_eq!(hw.get(0x46008), 0x8f00_ad5a);
    assert_eq!(hw.get(0x46000), (7 << 19) | 344);
    // Post-plane PM demand lowers to the new requirement after planes.
    assert!(hw.last(0x45234) > hw.last(0x7327c));
    assert_eq!(
        Params::decode(hw.get(0x45230), hw.get(0x45234)),
        state.pmdemand
    );
    // Unjoined MBUS keeps unrelated bits; both active DBOXes programmed.
    assert_eq!(hw.get(0x4438c), 0x1c00_0005);
    assert_eq!(hw.get(0x7003c), 0x0103_ca48);
    assert_eq!(hw.get(0x7103c), 0x0103_ca48);
    assert!(hw.written(0x7203c).is_empty() && hw.written(0x7303c).is_empty());
    for r in [0x45008, 0x44fe8, 0x44300, 0x44304] {
        assert_eq!(hw.get(r), 0xc041_0000);
    }
    for (r, v) in state.plane_registers().unwrap() {
        assert_eq!(hw.get(r), v, "plane register {r:#x}");
    }
    // Busy refusal: a live pipe stops the commit before any write.
    let hw = Hw::new();
    firmware(&hw);
    hw.set(0x72008, 1 << 31);
    assert_eq!(commit(&hw, &state), Err(ResourceError::Busy));
    assert!(hw.writes.borrow().is_empty());
    let hw = Hw::new();
    hw.set(0x71b08, 1);
    assert_eq!(commit(&hw, &state), Err(ResourceError::Busy));
    assert!(hw.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_resources_commit_two_pipes_in_source_order
);

fn smoke_xelpg_resources_commit_failure_restores_every_register() -> TestResult {
    let state = compute(&two_pipes(), &latency()).unwrap();
    let image: Vec<u64> = state
        .plane_registers()
        .unwrap()
        .into_iter()
        .map(|(r, _)| r)
        .chain(GLOBAL)
        .collect();
    // Plane-stage failure: everything back to firmware values.
    let hw = Hw::new();
    firmware(&hw);
    let before: Vec<u32> = image.iter().map(|&r| hw.read32(r)).collect();
    hw.drop_write.set(0x7127c);
    assert_eq!(commit(&hw, &state), Err(ResourceError::Readback));
    for (&r, &v) in image.iter().zip(&before) {
        assert_eq!(hw.read32(r), v, "restored {r:#x}");
    }
    assert!(!hw.written(0x70240).is_empty(), "the stage was reached");
    // CDCLK-stage failure (CTL refuses): the squash already landed, so the
    // clock is unknown and is relocked to the original 307.2 MHz before
    // its PM demand is restored.
    let hw = Hw::new();
    firmware(&hw);
    hw.drop_write.set(0x46000);
    assert_eq!(
        commit(&hw, &state),
        Err(ResourceError::Clock(CdclkError::Readback))
    );
    assert_eq!(hw.get(0x46008), 0);
    assert_eq!(hw.get(0x46070) & 0x8000_00ff, 0x8000_0010);
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&hw),
        307_200
    );
    assert_eq!(hw.get(0x45230), 0xffff_1071);
    assert_eq!(hw.get(0x45234), (308 << 20) | (810 << 8) | (7 << 4) | 2);
    assert!(hw.written(0x4438c).is_empty() && hw.written(0x70240).is_empty());
    // PM demand never acknowledges: nothing else is programmed and the
    // restore cannot lower the demand under a pending request.
    let hw = Hw::new();
    firmware(&hw);
    hw.no_ack.set(true);
    assert_eq!(commit(&hw, &state), Err(ResourceError::Timeout));
    for r in [0x46008, 0x46070, 0x46000, 0x45008, 0x4438c, 0x70240] {
        assert!(hw.written(r).is_empty(), "no programming after {r:#x}");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_resources_commit_failure_restores_every_register
);

fn smoke_xelpg_resources_failed_post_demand_restore_keeps_clock_covered() -> TestResult {
    // Firmware runs a known 652.8 MHz clock with its PM demand; the new
    // single-pipe state lowers CDCLK to 172.8 MHz.
    let hw = Hw::new();
    hw.set(0x46070, 0x8000_0022);
    hw.set(0x46000, (7 << 19) | 1304);
    hw.set(0x45230, 3 << 12);
    hw.set(0x45234, 653 << 20);
    let mut pipes = [None; PIPES];
    pipes[0] = pipe(65_000, (1024, 1344), (768, 806), 810_000, 0);
    let request = Request {
        pipes,
        min_cdclk_khz: 0,
    };
    let state = compute(&request, &latency()).unwrap();
    assert_eq!(state.cdclk.cdclk_khz, 172_800);
    // The post-plane request's REQUEST0 write is refused after REQUEST1
    // already carries 173 MHz/voltage 1: readback fails at the last step.
    hw.drop_nth(0x45230, 2);
    assert_eq!(commit(&hw, &state), Err(ResourceError::NoDevice));
    // Restoration re-raised max(original, new) before the clock went back
    // up, so no CDCLK write ever ran above the requested demand.
    assert_eq!(hw.uncovered.get(), 0, "PM demand covered every clock");
    assert_eq!(
        crate::intel_gpu_modeset_xelpg::cdclk_current_khz(&hw),
        652_800
    );
    assert_eq!(hw.get(0x46000), (7 << 19) | 1304);
    assert_eq!((hw.get(0x45230), hw.get(0x45234)), (3 << 12, 653 << 20));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_resources_failed_post_demand_restore_keeps_clock_covered
);

fn smoke_xelpg_resources_dsc_pipe_adds_vdsc_cdclk_and_prefill() -> TestResult {
    // intel_crtc_min_cdclk takes intel_vdsc_min_cdclk: a 2880x1800@120
    // eDP compressing on one engine needs its whole pixel rate with the
    // slice bubbles (vdsc_min_cdclk(650016, 2960, 1, 1) = 653091 kHz,
    // past the 652.8 MHz maximum), on two engines with four slices
    // 331157 kHz, above the 325008 kHz pixel minimum: the 480 MHz rung.
    use crate::intel_gpu_xelpg_dsc::{vdsc_min_cdclk, DscTerm};
    if vdsc_min_cdclk(650_016, 2960, 1, 1) != 653_091
        || vdsc_min_cdclk(650_016, 2960, 4, 2) != 331_157
    {
        return TestResult::Fail("intel_vdsc_min_cdclk adds 14 pixels per slice");
    }
    let mut request = Request {
        pipes: [None; PIPES],
        min_cdclk_khz: 0,
    };
    request.pipes[0] = pipe(650_016, (2880, 2960), (1800, 1830), 810_000, 0);
    let plain = match compute(&request, &latency()) {
        Ok(state) => state,
        Err(_) => return TestResult::Fail("the uncompressed panel must compute"),
    };
    if let Some(p) = request.pipes[0].as_mut() {
        p.dsc = Some(DscTerm {
            min_cdclk_khz: 331_157,
        });
    }
    let dsc = match compute(&request, &latency()) {
        Ok(state) => state,
        Err(_) => return TestResult::Fail("the compressed panel must compute"),
    };
    if plain.cdclk.cdclk_khz != 480_000 || dsc.cdclk.cdclk_khz != 480_000 {
        return TestResult::Fail("both fit the 480 MHz rung");
    }
    if let Some(p) = request.pipes[0].as_mut() {
        p.dsc = Some(DscTerm {
            min_cdclk_khz: 653_091,
        });
    }
    if compute(&request, &latency()) != Err(ResourceError::CdclkUnsatisfiable) {
        return TestResult::Fail("a VDSC minimum past 652.8 MHz must refuse");
    }
    if let Some(p) = request.pipes[0].as_mut() {
        p.dsc = Some(DscTerm {
            min_cdclk_khz: 500_000,
        });
    }
    match compute(&request, &latency()) {
        Ok(state) if state.cdclk.cdclk_khz == 556_800 && state.requests == request.pipes => {}
        _ => return TestResult::Fail("the VDSC term raises CDCLK and stays in the request"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_resources_dsc_pipe_adds_vdsc_cdclk_and_prefill
);

fn smoke_xelpg_resources_bigjoiner_and_panel_fitter_allocation() -> TestResult {
    let mut request = Request {
        pipes: [None; PIPES],
        min_cdclk_khz: 0,
    };
    // 1. Panel fitter custom source sizing
    request.pipes[0] = pipe(148_500, (1920, 2200), (1080, 1125), 540_000, 0);
    if let Some(p) = request.pipes[0].as_mut() {
        p.src_w = Some(1280);
        p.src_h = Some(720);
    }
    let fit_state = match compute(&request, &latency()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("panel fitter request must compute"),
    };
    if fit_state.requests[0].unwrap().src_w != Some(1280) {
        return TestResult::Fail("src_w not preserved in state");
    }

    // Source size exceeding display size is rejected
    if let Some(p) = request.pipes[0].as_mut() {
        p.src_w = Some(2560);
    }
    if compute(&request, &latency()) != Err(ResourceError::Unsupported) {
        return TestResult::Fail("src_w > hdisplay must be rejected");
    }

    // 2. Bigjoiner resource allocation
    request.pipes[0] = pipe(148_500, (1920, 2200), (1080, 1125), 540_000, 0);
    if let Some(p) = request.pipes[0].as_mut() {
        p.bigjoiner_slave = Some(crate::intel_gpu_pipes::Pipe::B);
    }
    let joiner_state = match compute(&request, &latency()) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("bigjoiner request must compute"),
    };
    // Both pipe A and pipe B must be marked active in DBUF
    if joiner_state.dbuf.active_pipes != (1 << 0) | (1 << 1) {
        return TestResult::Fail("bigjoiner slave must be active in DBUF");
    }

    // Conflict: requesting pipe B directly while it's also a slave pipe must fail
    request.pipes[1] = pipe(74_250, (1280, 1650), (720, 750), 270_000, 1);
    if compute(&request, &latency()) != Err(ResourceError::Unsupported) {
        return TestResult::Fail("slave pipe conflict must be rejected");
    }

    // Master pipe cannot join with itself
    request.pipes[1] = None;
    if let Some(p) = request.pipes[0].as_mut() {
        p.bigjoiner_slave = Some(crate::intel_gpu_pipes::Pipe::A);
    }
    if compute(&request, &latency()) != Err(ResourceError::Unsupported) {
        return TestResult::Fail("self-joining must be rejected");
    }

    // 3. Pipe scaler window bounds check
    request.pipes[0] = pipe(148_500, (1920, 2200), (1080, 1125), 540_000, 0);
    if let Some(p) = request.pipes[0].as_mut() {
        p.scaler = Some(crate::intel_gpu_xelpg_scaler::PipeScaler {
            id: 0,
            window: crate::intel_gpu_xelpg_scaler::Window {
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
            },
            hscale: 0x10000,
            vscale: 0x10000,
            filter: crate::intel_gpu_xelpg_scaler::Filter::Default,
        });
    }
    if compute(&request, &latency()).is_err() {
        return TestResult::Fail("valid pipe scaler window must compute");
    }

    // Scaler window exceeding hdisplay/vdisplay must be rejected
    if let Some(p) = request.pipes[0].as_mut() {
        p.scaler = Some(crate::intel_gpu_xelpg_scaler::PipeScaler {
            id: 0,
            window: crate::intel_gpu_xelpg_scaler::Window {
                x: 100,
                y: 0,
                width: 1920,
                height: 1080,
            },
            hscale: 0x10000,
            vscale: 0x10000,
            filter: crate::intel_gpu_xelpg_scaler::Filter::Default,
        });
    }
    if compute(&request, &latency()) != Err(ResourceError::Unsupported) {
        return TestResult::Fail("scaler window exceeding hdisplay must be rejected");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_resources",
    smoke_xelpg_resources_bigjoiner_and_panel_fitter_allocation
);
