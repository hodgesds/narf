//! Register models under pipe harvesting. `Renamed` sits between an owner
//! and a model written for the unfused board: each access the owner makes
//! to a pipe block's hardware instance reaches the model at its pipe
//! index's instance (`PipePool::pipe`), and each instance a register field
//! names is renamed the same way (pipe index to the model, hardware
//! instance back to the owner). An owner that addresses the pool's
//! instances therefore drives the model exactly as on the full board, and
//! any access to a fused instance, or a field naming one, panics. A run
//! under `under(fuses, ..)` is the same test on the harvested board. Models
//! that address registers through the owner's own layout (so already at
//! the pool's instances) use `guard` or `guard_raw` instead, which only
//! refuse fused instances.
//!
//! The blocks and fields are written out from dcn_4_1_0_offset.h /
//! sh_mask.h, not borrowed from the driver.
use super::*;
use crate::amdgpu_rdna4::{self as rdna4, PipePool};
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};

/// Every per-pipe register block an owner reaches: (bank, first and last
/// dword of instance 0, instance stride, whether a fused instance's may be
/// read). Bank 1 is DCCG, 2 the DCN core, 3 the MPC. Only DCHUBBUB's DET
/// sizes are read for every instance, fused ones included, as Linux's
/// dcn401_init_crb and dcn401_program_compbuf_segments read DET0-3; no
/// fused instance is ever written.
const BLOCKS: [(u8, u64, u64, u64, bool); 21] = [
    (2, 0xcc5, 0xdc8, 0x16b, false), // DPP_TOP, CNVC_CFG/CUR, DSCL, CM (dpp->inst)
    (2, 0x5e5, 0x68d, 0xdc, false),  // HUBP, HUBPREQ, HUBPRET, CURSOR0 (hubp->inst)
    (2, 0x183c, 0x1895, 0x5a, false), // FMT, DPG, OPPBUF, OPP_PIPE(_CRC) (opp->inst)
    (2, 0x1aca, 0x1ad2, 0x10, false), // ODM: OPTC input and data source (tg->inst)
    (2, 0x1b2a, 0x1ba1, 0x80, false), // OTG (tg->inst)
    (2, 0x156, 0x156, 1, false),     // OTG_INTERRUPT_DEST
    (2, 0x530, 0x530, 1, false),     // VTG_CONTROL
    (2, 0x80, 0x81, 2, false),       // DOMAIN0-3_PG_CONFIG/STATUS (hubp->inst)
    (2, 0x4bb, 0x4bb, 1, true),      // DCHUBBUB_DET0-3_CTRL (hubp->inst)
    (2, 0x528, 0x529, 2, false),     // SURFACE_CHECK
    (3, 0x0, 0xe, 0x15, false),      // MPCC (mpcc_inst = dpp->inst)
    (3, 0x7e, 0xd5, 0x5e, false),    // MPCC_OGAM
    (3, 0x453, 0x4fb, 0xb0, false),  // MPCC_MCM
    (3, 0x2f2, 0x2f5, 4, false),     // MPC_OUT mux and denorm (opp->inst)
    (3, 0x30b, 0x317, 0xd, false),   // MPC_OUT output CSC
    (3, 0x2c1, 0x2c5, 5, false),     // per-OPP VUPDATE lock sets (cursor lock)
    (3, 0x2d5, 0x2d6, 2, false),     // HUBP 3DLUT fast load
    (3, 0xe7a, 0xea1, 0x41, false),  // ABM (abm_regs[inst])
    (1, 0x80, 0x83, 4, false),       // OTG_PIXEL_RATE_CNTL, DP_DTO, PHYPLL rate
    (1, 0x99, 0x99, 1, false),       // DPPCLK0-3_DTO_PARAM (dpp->inst)
    (1, 0xb0, 0xb0, 1, false),       // DCCG_VSYNC_OTG0-3_LATCH_VALUE
];

/// A field naming one pipe block's instance: (bank, dword of instance 0,
/// stride and count of the register's instances, shift, width). Values of
/// all ones are "none".
const FIELDS: [(u8, u64, u64, u64, u32, u32); 15] = [
    (3, 0x0, 0x15, 4, 0, 4),     // MPCC_TOP_SEL: DPP
    (3, 0x1, 0x15, 4, 0, 4),     // MPCC_BOT_SEL: MPCC
    (3, 0x2, 0x15, 4, 0, 4),     // MPCC_OPP_ID: OPP
    (3, 0x5, 0x15, 4, 0, 4),     // MPCC_UPDATE_LOCK_SEL: OPP
    (3, 0x2f2, 4, 4, 0, 4),      // MPC_OUT_MUX: MPCC
    (2, 0x1acb, 0x10, 4, 16, 4), // OPTC_SEG0_SRC_SEL: OPP
    (2, 0x1acb, 0x10, 4, 20, 4), // OPTC_SEG1_SRC_SEL
    (2, 0x1acb, 0x10, 4, 24, 4), // OPTC_SEG2_SRC_SEL
    (2, 0x1acb, 0x10, 4, 28, 4), // OPTC_SEG3_SRC_SEL
    (2, 0x5f4, 0xdc, 4, 4, 4),   // HUBP_VTG_SEL: OTG
    (2, 0x2093, 0x124, 5, 0, 3), // DIG_SOURCE_SELECT: OTG
    (2, 0x2093, 0x124, 5, 4, 3), // DIG_STEREOSYNC_SELECT: OTG
    (2, 0x3624, 0xd4, 4, 0, 3),  // HPO DP_STREAM_ENC_INPUT_MUX pixel source: OTG
    (2, 0x1a64, 1, 4, 4, 3),     // DSCRM_DSC_OPP_PIPE_SOURCE: OPP
    (1, 0xab, 0, 1, 0, 3),       // DCCG_AUDIO_DTO0_SOURCE_SEL: OTG
];
/// Registers with one bit per instance: (bank, dword, first bit).
const BITS: [(u8, u64, u32); 1] = [
    (3, 0x30a, 0), // MPC_OUT_CSC_COEF_FORMAT: MPC_OCSC0-3_COEF_FORMAT
];

/// The owner's view of a model built for the full board, on `pool`.
pub(crate) struct Renamed<I> {
    pub(crate) model: I,
    pool: PipePool,
    banks: [u64; 4],
    /// The NBIF registers owners read (HDP flush and its ack), which the otg
    /// test descriptor places in the MPC bank's range: never renamed.
    nbif: [u64; 2],
}
impl<I> Renamed<I> {
    /// `model` behind `layout`'s pool, with the otg test descriptor's banks
    /// (DCCG bank 1 from `layout`).
    pub(crate) fn new(model: I, layout: Layout) -> Self {
        Self {
            model,
            pool: layout.pool,
            banks: [0, layout.dio_clock - 0xa0 * 4, BASE, MPC_BASE],
            nbif: [layout.nbio + 0x12d * 4, layout.nbio + 0xc3 * 4],
        }
    }
    /// The pipe index's instance of block register `at` (a read of a fused
    /// instance's readable register: the slot `PipePool::hw` gives it past
    /// the pool), or `at` itself.
    fn rename_addr(&self, at: u64, write: bool) -> u64 {
        if self.nbif.contains(&at) {
            return at;
        }
        for (bank, first, last, stride, readable) in BLOCKS {
            let base = self.banks[usize::from(bank)];
            for inst in 0..4u8 {
                let lo = base + (first + u64::from(inst) * stride) * 4;
                let hi = base + (last + u64::from(inst) * stride) * 4;
                if (lo..=hi).contains(&at) {
                    let pipe = match self.pool.pipe(inst) {
                        Some(pipe) => pipe,
                        None if readable && !write => {
                            (0..4u8).find(|&p| self.pool.hw(p) == inst).unwrap()
                        }
                        None => panic!("fused pipe instance {inst} touched at {at:#x}"),
                    };
                    return at - lo + base + (first + u64::from(pipe) * stride) * 4;
                }
            }
        }
        at
    }
    /// The owner's address of model register `at`: its pipe's instance.
    pub(crate) fn owner_addr(&self, at: u64) -> u64 {
        if self.nbif.contains(&at) {
            return at;
        }
        for (bank, first, last, stride, _) in BLOCKS {
            let base = self.banks[usize::from(bank)];
            for pipe in 0..4u8 {
                let lo = base + (first + u64::from(pipe) * stride) * 4;
                let hi = base + (last + u64::from(pipe) * stride) * 4;
                if (lo..=hi).contains(&at) {
                    let inst = self.pool.hw(pipe);
                    return at - lo + base + (first + u64::from(inst) * stride) * 4;
                }
            }
        }
        at
    }
    /// `value` of register `at` (pipe-index address) with every instance
    /// field mapped by `map`.
    fn fields(&self, at: u64, mut value: u32, map: impl Fn(u8) -> u8) -> u32 {
        if self.nbif.contains(&at) {
            return value;
        }
        for (bank, first, stride, count, shift, width) in FIELDS {
            let base = self.banks[usize::from(bank)];
            if !(0..count).any(|i| at == base + (first + i * stride) * 4) {
                continue;
            }
            let mask = (1u32 << width) - 1;
            let field = (value >> shift & mask) as u8;
            if u32::from(field) != mask {
                value = value & !(mask << shift) | u32::from(map(field)) << shift;
            }
        }
        for (bank, reg, bit) in BITS {
            if at == self.banks[usize::from(bank)] + reg * 4 {
                let bits = (value >> bit & 0xf) as u8;
                let mapped = (0..4u8)
                    .filter(|&i| bits & 1 << i != 0)
                    .fold(0u8, |m, i| m | 1 << map(i));
                value = value & !(0xf << bit) | u32::from(mapped) << bit;
            }
        }
        value
    }
}
impl<I> Deref for Renamed<I> {
    type Target = I;
    fn deref(&self) -> &I {
        &self.model
    }
}
impl<I> DerefMut for Renamed<I> {
    fn deref_mut(&mut self) -> &mut I {
        &mut self.model
    }
}
impl<I: Io> Io for Renamed<I> {
    fn read(&mut self, at: u64) -> u32 {
        let at = self.rename_addr(at, false);
        let value = self.model.read(at);
        let pool = self.pool;
        self.fields(at, value, |p| pool.hw(p))
    }
    fn write(&mut self, at: u64, value: u32) {
        let at = self.rename_addr(at, true);
        let pool = self.pool;
        let value = self.fields(at, value, |inst| {
            pool.pipe(inst)
                .unwrap_or_else(|| panic!("field names fused pipe instance {inst} at {at:#x}"))
        });
        self.model.write(at, value)
    }
    fn pause_wait(&self) -> bool {
        self.model.pause_wait()
    }
    fn wait_poll_limit(&self) -> Option<u32> {
        self.model.wait_poll_limit()
    }
}

/// For a model that addresses registers with the owner's own `layout`
/// (so it already sees the pool's instances): panic on an access to a
/// fused instance, or on a write whose instance field names one.
pub(crate) fn guard(layout: Layout, at: u64, written: Option<u32>) {
    let checker = Renamed::new((), layout);
    checker.rename_addr(at, written.is_some());
    if let Some(value) = written {
        let pool = layout.pool;
        checker.fields(at, value, |inst| {
            assert!(
                pool.pipe(inst).is_some(),
                "field names fused pipe instance {inst} at {at:#x}"
            );
            inst
        });
    }
}

/// The otg test descriptor's DCCG bank and NBIF base, as `engine` resolves
/// them (for `guard_raw`, which has no layout).
static BANK1: AtomicU64 = AtomicU64::new(0);
static NBIO: AtomicU64 = AtomicU64::new(0);
/// Record `layout`'s banks for `guard_raw`; returns it.
pub(crate) fn note_layout(layout: Layout) -> Layout {
    BANK1.store(layout.dio_clock - 0xa0 * 4, Ordering::Relaxed);
    NBIO.store(layout.nbio, Ordering::Relaxed);
    layout
}
/// `guard` for a model addressed by the owner itself, on the published
/// pool and the descriptor's banks.
pub(crate) fn guard_raw(at: u64, written: Option<u32>) {
    let nbio = NBIO.load(Ordering::Relaxed);
    let checker = Renamed {
        model: (),
        pool: rdna4::pipe_pool(),
        banks: [0, BANK1.load(Ordering::Relaxed), BASE, MPC_BASE],
        nbif: [nbio + 0x12d * 4, nbio + 0xc3 * 4],
    };
    checker.rename_addr(at, written.is_some());
    if let Some(value) = written {
        let pool = checker.pool;
        checker.fields(at, value, |inst| {
            assert!(
                pool.pipe(inst).is_some(),
                "field names fused pipe instance {inst} at {at:#x}"
            );
            inst
        });
    }
}

/// `layout` (resolved on the full pool) as an owner resolves it on the
/// published pool: its pool, and no idle witness on a fused OTG
/// (clocks::Layout::idle_registers).
pub(crate) fn harvested_layout(layout: Layout) -> Layout {
    let pool = rdna4::pipe_pool();
    let mut idle = layout.idle;
    for entry in idle.iter_mut() {
        for inst in (0..4u8).filter(|&i| pool.pipe(i).is_none()) {
            let otg = |r: u64| BASE + (r + u64::from(inst) * 0x80) * 4;
            if entry.0 == otg(0x1b43) || entry.0 == otg(0x1b84) {
                *entry = (0, 0);
            }
        }
    }
    Layout {
        pool,
        idle,
        ..layout
    }
}

/// `f` with the full pool published (a model staged for the full board,
/// which `Renamed` then shows the harvested owner), then the caller's pool.
pub(crate) fn on_full_pool<T>(f: impl FnOnce() -> T) -> T {
    let pool = rdna4::pipe_pool();
    rdna4::publish_pipe_pool(PipePool::FULL);
    let out = f();
    rdna4::publish_pipe_pool(pool);
    out
}

/// The harvested boards the model tests run again on: pipe 0 fused, pipe 1
/// fused, and pipes 1 and 2 fused.
pub(crate) const HARVESTED: [u32; 3] = [0x1, 0x2, 0x6];

/// Run `test` with the pool `CC_DC_PIPE_DIS = fuses` leaves published (every
/// owner and `Renamed` built inside it takes that pool), then restore the
/// full pool.
pub(crate) fn under(fuses: u32, test: impl FnOnce() -> TestResult) -> TestResult {
    rdna4::publish_pipe_pool(PipePool::from_fuses(fuses));
    let result = test();
    rdna4::publish_pipe_pool(PipePool::FULL);
    result
}
/// `test` on every harvested board whose pool has at least `pipes` pipes.
pub(crate) fn harvested(pipes: u8, test: impl Fn() -> TestResult) -> TestResult {
    for fuses in HARVESTED {
        if PipePool::from_fuses(fuses).count() < pipes {
            continue;
        }
        let result = under(fuses, &test);
        if result != TestResult::Pass {
            return result;
        }
    }
    TestResult::Pass
}

/// dcn20_acquire_dsc and dsc401_enable on harvested boards (pipe 0, pipe 1,
/// pipes 1 and 2 fused): pipe p compresses on DSC p (the pool keeps every
/// DSC) fed from p's OPP instance (DSCRM_DSC_OPP_PIPE_SOURCE), no other
/// DSC forwards, and no pipe block of a fused instance is touched; stopping
/// the DSC turns its forwarding off again.
fn dcn401_dsc_follows_the_pipe_index_from_its_opp_instance_on_harvested_boards() -> TestResult {
    harvested(1, || {
        let pool = rdna4::pipe_pool();
        let cfg = crate::amdgpu_dsc::DscConfig {
            slices_h: 2,
            slices_v: 10,
            bpp_x16: 128,
            block_pred: true,
            linebuf_depth: 11,
            version_minor: 2,
            ycbcr422_simple: false,
            frl: None,
            bpc: 8,
        };
        let forward = |k: u8| BASE + (0x1a64 + u64::from(k)) * 4;
        for pipe in pool.pipes() {
            let mut e = engine();
            let l = e.layout;
            let mut r = request(pipe);
            r.dsc = Some(cfg);
            if run(e.start_dsc(&r, &cfg)).is_err() {
                return TestResult::Fail("DSC start on a pool pipe");
            }
            for &(at, value) in &e.io.writes {
                guard(l, at, Some(value));
            }
            let fwd = |e: &Engine<Fake>, k: u8| e.io.regs.get(&forward(k)).copied().unwrap_or(0);
            if fwd(&e, pipe) & 0x71 != 1 | u32::from(pool.hw(pipe)) << 4
                || (0..4u8).any(|k| k != pipe && fwd(&e, k) & 1 != 0)
                || e.dsc_running(&r, &cfg).is_err()
            {
                return TestResult::Fail("DSC of the pipe index from the OPP instance");
            }
            if run(e.stop_dsc(pipe)).is_err() || fwd(&e, pipe) & 1 != 0 {
                return TestResult::Fail("DSC stop");
            }
        }
        TestResult::Pass
    })
}
narf_kernel_test::kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dsc_follows_the_pipe_index_from_its_opp_instance_on_harvested_boards
);

/// The timing (OTG/ODM/VTG/OPTC source) and ODM 2:1 with split DSC on
/// harvested boards (pipe 0, pipe 1, pipes 1 and 2 fused): every register
/// at the pipe's instance, the OPTC segments and line memories naming OPP
/// instances, each segment's DSC its pipe's; the register model refuses
/// any fused instance (Fake::guarded).
fn dcn401_otg_timing_and_odm_on_harvested_boards() -> TestResult {
    harvested(2, || {
        let top = rdna4::pipe_pool().count() - 1;
        for result in [
            super::dcn401_otg_native_timing_all_pipes_and_signal_muxes(),
            super::odm_split_dsc_on(0, top),
            super::odm_split_dsc_on(top, 0),
        ] {
            if result != TestResult::Pass {
                return result;
            }
        }
        TestResult::Pass
    })
}
narf_kernel_test::kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_timing_and_odm_on_harvested_boards
);
