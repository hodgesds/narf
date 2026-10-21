use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

pub(super) const BASE: u64 = 0x10000;
#[path = "amdgpu_dcn401_dp_phy_tests.rs"]
mod dp_phy;
const MPC_BASE: u64 = 0x30000;
pub(super) struct Fake {
    pub(super) regs: BTreeMap<u64, u32>,
    pub(super) writes: Vec<(u64, u32)>,
    // input clock, OTG clock, retire master/busy, OPP clock, enable master,
    // DPG latch, FMT latch, frame progress
    stall: u16,
    poll_limit: Option<u32>,
    retiring: [bool; 4],
    delay: [u8; 4],
    pub(super) reject: Option<usize>,
    gone: Option<usize>,
    revoke: Option<(usize, Cap<BusDeviceCap, Write>)>,
    after_enable: Option<(u64, u32)>,
    after_write: Option<(usize, u64, u32)>,
    disconnecting: bool,
    forbidden_hubps: u8,
    plane_delay: [u8; 4],
    dp_written: u8,
    dp_delay: [u8; 8],
    dp_stall: u16,
    encoder_written: u8,
    encoder_delay: [u8; 8],
    encoder_stall: u8,
    /// Accesses are the owner's own (not renamed): refuse a fused
    /// instance's (harvest::guard_raw).
    pub(super) guarded: bool,
}
impl Io for Fake {
    fn wait_poll_limit(&self) -> Option<u32> {
        self.poll_limit
    }
    fn read(&mut self, at: u64) -> u32 {
        if self.guarded {
            harvest::guard_raw(at, None);
        }
        if self.gone == Some(self.writes.len()) {
            return u32::MAX;
        }
        // DSC domains' PGFSM follows DOMAIN_POWER_GATE at once.
        for k in 0..4u64 {
            if at == BASE + (0x8a + 2 * k) * 4 {
                let gated = self
                    .regs
                    .get(&(BASE + (0x89 + 2 * k) * 4))
                    .copied()
                    .unwrap_or(0)
                    & 1;
                return if gated != 0 { 0x8000_0000 } else { 0 };
            }
        }
        for p in 0..4 {
            for (slot, reg, stride, enable, on) in [
                (p, 0x2094, 0x124, 0x10, 0x2c00),
                (p + 4, 0x3623, 0xd4, 1, 0x11110),
            ] {
                if at == BASE + (reg + p * stride) * 4
                    && self.encoder_written & (1 << slot) != 0
                    && self.encoder_stall & (1 << slot) == 0
                    && self.regs.get(&at).copied().unwrap_or(0) & enable == 0
                {
                    if self.encoder_delay[slot as usize] == 0 {
                        *self.regs.entry(at).or_default() &= !on;
                    } else {
                        self.encoder_delay[slot as usize] -= 1;
                    }
                }
            }
            for (slot, reg, stride, status) in
                [(p, 0x2122, 0x124, 0x10000), (p + 4, 0x3685, 0xd4, 0x100)]
            {
                if at == BASE + (reg + p * stride) * 4
                    && self.dp_written & (1 << slot) != 0
                    && self.regs.get(&at).copied().unwrap_or(0) & 1 == 0
                    && self.dp_stall & (1 << slot) == 0
                {
                    if self.dp_delay[slot as usize] == 0 {
                        *self.regs.entry(at).or_default() &= !status;
                    } else {
                        self.dp_delay[slot as usize] -= 1;
                    }
                }
            }
            if at == BASE + (0x2123 + p * 0x124) * 4
                && self.regs.get(&at).copied().unwrap_or(0) & 2 != 0
                && self.dp_stall & (1 << (p + 8)) == 0
            {
                *self.regs.entry(at).or_default() |= 4;
            }
            assert!(
                self.forbidden_hubps & (1 << p) == 0
                    || !(BASE + (0x5e5 + p * 0xdc) * 4..=BASE + (0x68d + p * 0xdc) * 4)
                        .contains(&at)
            );
            let top = MPC_BASE + p * 0x15 * 4;
            let disconnected = self.disconnecting
                && [0, 1, 2, 5]
                    .iter()
                    .all(|r| self.regs.get(&(top + r * 4)).copied().unwrap_or(0) & 0xf == 0xf);
            if disconnected && at == top + 0xe * 4 && self.stall & 512 == 0 {
                if self.plane_delay[p as usize] == 0 {
                    self.regs.insert(at, 1);
                } else {
                    self.plane_delay[p as usize] -= 1;
                }
            }
            if disconnected
                && at == BASE + (0x5f4 + p * 0xdc) * 4
                && self.stall & 1024 == 0
                && !(self.stall & 2048 != 0 && self.regs.get(&at).copied().unwrap_or(0) & 1 != 0)
                && self
                    .regs
                    .get(&(BASE + (0x679 + p * 0xdc) * 4))
                    .copied()
                    .unwrap_or(0)
                    & 1
                    == 0
            {
                *self.regs.entry(at).or_default() |= 2;
            }
            let ctrl = BASE + (0x1b43 + 0x80 * p) * 4;
            let clock = BASE + (0x1b84 + 0x80 * p) * 4;
            let input = BASE + (0x1ad0 + 0x10 * p) * 4;
            let opp = BASE + (0x188c + 0x5a * p) * 4;
            let old = *self.regs.get(&at).unwrap_or(&0);
            if at == input && old & 3 == 3 && self.stall & 1 == 0 {
                self.regs.insert(at, old | 4);
            }
            if at == clock && old & 3 == 3 && self.stall & 2 == 0 {
                self.regs.insert(at, old | 0x100);
            }
            if at == opp && old & 1 == 1 && self.stall & 16 == 0 {
                self.regs.insert(at, old | 2);
            }
            if self.regs.get(&ctrl).copied().unwrap_or(0) & 1 != 0 {
                if at == ctrl && self.stall & 32 == 0 {
                    self.regs.insert(at, old | 0x10000);
                }
                if at == BASE + (0x185b + 0x5a * p) * 4 && self.stall & 64 == 0 {
                    self.regs.insert(at, old & !1);
                }
                if at == BASE + (0x1840 + 0x5a * p) * 4 && self.stall & 128 == 0 {
                    self.regs.insert(at, old & !0x1000000);
                }
                if at == BASE + (0x1b4d + 0x80 * p) * 4 && self.stall & 256 == 0 {
                    self.regs.insert(at, old.wrapping_add(1) & 0xffffff);
                }
            }
            if self.retiring[p as usize] && (at == ctrl || at == clock) {
                if self.delay[p as usize] != 0 {
                    self.delay[p as usize] -= 1;
                } else if (at == ctrl && self.stall & 4 == 0)
                    || (at == clock && self.stall & 8 == 0)
                {
                    *self.regs.entry(at).or_default() &= !0x10000;
                }
            }
        }
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, value: u32) {
        if self.guarded {
            harvest::guard_raw(at, Some(value));
        }
        assert!(
            (BASE + 0x475 * 4..=BASE + 0x47a * 4).contains(&at)
                || (BASE + 0x530 * 4..=BASE + 0x1d1f * 4).contains(&at)
                || (BASE + 0x4ba * 4..=BASE + 0x4be * 4).contains(&at)
                || at == BASE + 0x4c4 * 4
                || at == BASE + 0x485 * 4 // SDPIF_REQUEST_RATE_LIMIT
                || (BASE + 0x4fc * 4..=BASE + 0x523 * 4).contains(&at) // arbiter/watermarks
                || (0x162a0 * 4..=0x162a3 * 4).contains(&at)
                || (0x16240 * 4..=0x16243 * 4).contains(&at) // PHYPLL deep-colour resync
                || (0x162ab * 4..=0x162af * 4).contains(&at) // audio DTO0/DTO1
                || at == BASE + 0x40c * 4 // Azalia stream formats
                || at == 0x16266 * 4 // descriptor's DCN bank 1 + SYMCLK32_LE_CNTL
                || at == BASE + 0x4a * 4 // native FRL character-clock root
                || at == BASE + 0xa0 * 4 // native DC_IP_REQUEST_CNTL, bank 2
                || at == BASE + 0x28f4 * 4 // DC_GPIO_HPD_MASK, bank 2
                || at == 0x7f000 // native HDP flush remap
                || (0..4).any(|p| at == BASE + (0x80 + 2 * p) * 4)
                // DSC0-3 and their power domains (DOMAIN16-19).
                || (BASE + 0x3000 * 4..BASE + (0x3000 + 4 * 0x5c) * 4).contains(&at)
                || (0..4).any(|k| at == BASE + (0x89 + 2 * k) * 4)
                || (BASE + 0x1f0d * 4..=BASE + 0x1f10 * 4).contains(&at)
                || (MPC_BASE..=MPC_BASE + 0x301 * 4).contains(&at)
                || at == MPC_BASE + 0x30a * 4 // MPC_OUT_CSC_COEF_FORMAT
                || (0..4).any(|p| {
                    // Output CSC mode and its set-A coefficients.
                    (MPC_BASE + (0x30b + p * 0xd) * 4..=MPC_BASE + (0x311 + p * 0xd) * 4)
                        .contains(&at)
                        || [0x453, 0x48a, 0x493, 0x4de, 0x4ec].iter()
                            .any(|r| at == MPC_BASE + (r + p * 0xb0) * 4)
                })
                || (MPC_BASE + 0x8d3 * 4..=MPC_BASE + 0x8f0 * 4).contains(&at)
                // Native FRL ACR and AFMT4 LPCM source/channel state.
                || (MPC_BASE + 0x8f2 * 4..=MPC_BASE + 0x8f7 * 4).contains(&at)
                || [0x91d, 0x920, 0x921, 0x927, 0x92a, 0x92d, 0x92f]
                    .iter().any(|&r| at == MPC_BASE + r * 4)
                || [0x95b, 0x95c, 0x965, 0x966].iter().any(|&r| at == MPC_BASE + r * 4)
                // HPO FRL stream attributes, CRC, borrow mode, AFMT4 audio
                // InfoFrame latch, VPG4.
                || [0x8f1, 0x900, 0x901, 0x903, 0x908, 0x92b, 0x931, 0x932, 0x934, 0x935, 0x936]
                    .iter()
                    .any(|&r| at == MPC_BASE + r * 4)
                || (0..4).any(|p| {
                    [
                        0x2094, 0x2095, 0x209b, 0x209e, 0x20a5, 0x20a6, 0x20a9, 0x20aa, 0x20ab,
                        0x20ac, 0x20ad, 0x20ae, 0x20af, 0x20b0, 0x20bc, 0x211e, 0x2122, 0x2123,
                        0x2125, 0x212e, 0x20bb, 0x20bd, 0x2121, 0x2134, 0x212d, 0x2133, 0x2129,
                        0x2093, 0x211f, 0x2120, 0x2124, 0x2162, 0x2163, 0x2164, 0x2165, 0x2146,
                        0x2126, 0x2127, 0x2128, 0x20a2, 0x20a8, 0x20eb, 0x20b1, 0x2068, 0x2069,
                        0x206b, 0x206c, 0x206d, 0x20a0, 0x20a1, 0x20a3, 0x20a4, 0x20b2,
                        0x20b3, 0x20b4, 0x20b5, 0x20b6, 0x20b7, 0x20ba, 0x2075, 0x2078, 0x2079,
                        0x207f, 0x2082, 0x2083, 0x2085, 0x2087, 0x2141, 0x2147, 0x214b,
                        0x2169, 0x2170, 0x2177, 0x214d, 0x214f, 0x2150, 0x2151, 0x2153,
                    ]
                    .iter()
                    .any(|r| at == BASE + (r + p * 0x124) * 4)
                        || [
                            0x3623, 0x3626, 0x365d, 0x365e, 0x367b, 0x3685, 0x369f, 0x36b4, 0x36b8,
                            0x36bf, 0x36c0, 0x36c1, 0x36c2, 0x36c3, 0x36c4,
                            0x3625, 0x3630, 0x3631, 0x3632, 0x3644, 0x367c,
                        ]
                        .iter()
                        .any(|r| at == BASE + (r + p * 0xd4) * 4)
                        // HPO stream encoder attributes, packets, mux, CRC,
                        // VPG power; the link encoder's VC rates.
                        || [
                            0x3624, 0x3656, 0x366c, 0x366e, 0x366f, 0x3671, 0x3687, 0x36b9,
                            0x36ba, 0x36bb, 0x36bc,
                            // A DSC stream's PPS: VPG generic packets,
                            // GSP11 and VBID[6].
                            0x3651, 0x3652, 0x3654, 0x3655, 0x3677, 0x3684,
                        ]
                        .iter()
                        .any(|r| at == BASE + (r + p * 0xd4) * 4)
                        || (BASE + (0x365f + p * 0xd4) * 4..=BASE + (0x366b + p * 0xd4) * 4)
                            .contains(&at)
                        || at == MPC_BASE + (0xe56 + p) * 4 // DP_STREAM_MAPPER_CONTROL
                })
        );
        self.writes.push((at, value));
        if self.reject == Some(self.writes.len()) {
            return;
        }
        self.regs.insert(at, value);
        if (MPC_BASE..=MPC_BASE + 0x2fe * 4).contains(&at) {
            self.disconnecting = true;
        }
        for p in 0..4 {
            if at == BASE + (0x2094 + p * 0x124) * 4 {
                self.encoder_written |= 1 << p;
                assert_eq!(
                    self.regs
                        .get(&(BASE + (0x209b + p * 0x124) * 4))
                        .copied()
                        .unwrap_or(0)
                        & 1,
                    0
                );
                assert_eq!(
                    self.regs
                        .get(&(BASE + (0x2095 + p * 0x124) * 4))
                        .copied()
                        .unwrap_or(0)
                        & 1,
                    0
                );
            }
            if at == BASE + (0x3623 + p * 0xd4) * 4 {
                self.encoder_written |= 1 << (p + 4);
                assert_eq!(
                    self.regs
                        .get(&(BASE + (0x365d + p * 0xd4) * 4))
                        .copied()
                        .unwrap_or(0)
                        & 1,
                    0
                );
            }
            if at == BASE + (0x2122 + p * 0x124) * 4 {
                self.dp_written |= 1 << p;
            }
            if at == BASE + (0x3685 + p * 0xd4) * 4 {
                self.dp_written |= 1 << (p + 4);
            }
            // Fail a model immediately if software cuts a FIFO/SDP before
            // video acknowledgement; requested disable alone is insufficient.
            if at == BASE + (0x2123 + p * 0x124) * 4 && value & 2 != 0 {
                assert_eq!(
                    self.regs
                        .get(&(BASE + (0x2122 + p * 0x124) * 4))
                        .copied()
                        .unwrap_or(0)
                        & 0x10001,
                    0
                );
            }
            if [0x3626, 0x365e, 0x367b]
                .iter()
                .any(|r| at == BASE + (r + p * 0xd4) * 4)
                && value & 1 == 0
                && self.regs.get(&at).copied().unwrap_or(0) & 1 != 0
            {
                assert_eq!(
                    self.regs
                        .get(&(BASE + (0x3685 + p * 0xd4) * 4))
                        .copied()
                        .unwrap_or(0)
                        & 0x101,
                    0
                );
            }
            assert!(
                self.forbidden_hubps & (1 << p) == 0
                    || !(BASE + (0x5e5 + p * 0xdc) * 4..=BASE + (0x68d + p * 0xdc) * 4)
                        .contains(&at)
            );
            if at == BASE + (0x5f4 + p * 0xdc) * 4 && value & 1 != 0 && self.stall & 2048 != 0 {
                self.regs.insert(at, value & !2);
            }
            if at == BASE + (0x1854 + 0x5a * p) * 4 {
                self.regs.insert(BASE + (0x185b + 0x5a * p) * 4, 1);
            }
            if at == BASE + (0x1b43 + 0x80 * p) * 4 {
                self.retiring[p as usize] = value & 1 == 0;
                if value & 1 != 0 {
                    if let Some((at, value)) = self.after_enable.take() {
                        self.regs.insert(at, value);
                    }
                }
            }
        }
        if let Some((n, cap)) = self.revoke {
            if n == self.writes.len() {
                cap.revoke();
            }
        }
        if let Some((n, at, value)) = self.after_write {
            if n == self.writes.len() {
                self.regs.insert(at, value);
            }
        }
    }
}
fn descriptor(words: &mut [u32]) -> AmdGpu {
    let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(words);
    let mut mp = gpu.ip_blocks[0];
    mp.hw_id = ip::HW_ID_MP1;
    (mp.major, mp.minor, mp.revision) = (14, 0, 2);
    mp.num_bases = 2;
    mp.base_addrs[1] = 0x16200;
    let mut dc = mp;
    dc.hw_id = ip::HW_ID_DCN;
    (dc.major, dc.minor, dc.revision) = (4, 1, 0);
    dc.num_bases = 4;
    dc.base_addrs[2] = (BASE / 4) as u32;
    dc.base_addrs[3] = 0xc000;
    gpu.ip_blocks.extend([mp, dc]);
    gpu
}
pub(super) fn engine() -> Engine<Fake> {
    let mut words = vec![0; 0x80000 / 4];
    let gpu = descriptor(&mut words);
    Engine {
        io: Fake {
            regs: BTreeMap::new(),
            writes: Vec::new(),
            stall: 0,
            poll_limit: None,
            retiring: [false; 4],
            delay: [0; 4],
            reject: None,
            gone: None,
            revoke: None,
            after_enable: None,
            after_write: None,
            disconnecting: false,
            forbidden_hubps: 0,
            plane_delay: [0; 4],
            dp_written: 0,
            dp_delay: [0; 8],
            dp_stall: 0,
            encoder_written: 0,
            encoder_delay: [0; 8],
            encoder_stall: 0,
            guarded: true,
        },
        authority: Cap::bootstrap(),
        layout: harvest::note_layout(Layout::resolve(&gpu).unwrap()),
        status: Box::new(Status::new()),
        displays: Displays::new(),
    }
}
pub(super) fn request(pipe: u8) -> Request {
    Request {
        pipe,
        signal: Signal::HpoDisplayPort,
        ycbcr420: false,
        dsc: None,
        odm: SplitPipes::NONE,
        timing: Timing {
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
            v_sync_positive: false,
        },
        sync: GlobalSync {
            vstartup: 43,
            vupdate_offset: 1234,
            vupdate_width: 56,
            vready_offset: 78,
            pstate_keepout: 9,
        },
    }
}
pub(super) fn clock(request: Request) -> dccg::Applied {
    dccg::Applied {
        request: dccg::Request {
            pipe: request.pipe,
            dpp_khz: 148_500,
            pixel: match request.signal {
                Signal::DisplayPort | Signal::HpoDisplayPort => dccg::PixelClock::DisplayPort {
                    pixel_hz: 148_500_000,
                },
                Signal::HdmiFrl => dccg::PixelClock::HdmiFrl {
                    pixel_hz: 148_500_000,
                },
                Signal::Tmds => dccg::PixelClock::Tmds {
                    divider: dccg::TmdsDivider::By2,
                },
            },
        },
        global: clocks::Applied {
            request: clocks::Request {
                displays: 1,
                display_khz: 600_000,
                dpp_khz: 300_000,
                dtb_khz: 600_000,
                deep_sleep_dcfclk_khz: 0,
            },
            display_khz: 600_000,
            dpp_khz: 300_000,
            dtb_khz: 600_000,
            dcf_floor_khz: 1_200_000,
            memory_floor_khz: 1_200_000,
            uclk_pstate: false,
        },
        dpp_phase: 127,
        reference_hz: 720_000_000,
        integer: 0,
        phase: 148_500_000,
    }
}
pub(super) fn run<T>(f: impl Future<Output = T>) -> T {
    // Engine futures carry whole display plans: keep their state on the
    // heap rather than the 64 KiB aarch64 kernel-test stack.
    narf_scheduler::block_on_spin(alloc::boxed::Box::pin(f))
}
/// `run` for the future `make` returns. A future passed by value is a
/// stack temporary as large as its whole state machine (14 KiB for a
/// scanout start) in the caller's frame, under everything its poll calls;
/// `make` builds it in `boxed`'s frame instead, which is gone before the
/// first poll.
pub(super) fn run_boxed<F: Future>(make: impl FnOnce() -> F) -> F::Output {
    run(boxed(make))
}
/// The future `make` returns, moved to the heap in a frame of its own.
#[inline(never)]
pub(super) fn boxed<F: Future>(make: impl FnOnce() -> F) -> core::pin::Pin<alloc::boxed::Box<F>> {
    alloc::boxed::Box::pin(make())
}
fn reg(e: &Engine<Fake>, index: u64) -> u32 {
    *e.io.regs.get(&(BASE + index * 4)).unwrap_or(&0)
}

fn dcn401_otg_native_timing_all_pipes_and_signal_muxes() -> TestResult {
    // Every pipe of the pool, at its OTG/ODM/VTG instance.
    let pool = crate::amdgpu_rdna4::pipe_pool();
    for pipe in pool.pipes() {
        for (signal, control) in [
            (Signal::DisplayPort, 0x1000),
            (Signal::HpoDisplayPort, 0x201000),
            (Signal::Tmds, 0),
            (Signal::HdmiFrl, 0x200000),
        ] {
            let mut e = engine();
            let mut req = request(pipe);
            req.signal = signal;
            let c = clock(req);
            let p = u64::from(pool.hw(pipe));
            let o = |r| BASE + (r + 0x80 * p) * 4;
            let d = |r| BASE + (r + 0x10 * p) * 4;
            // Preserve independent PSTATE bits and clear inherited DSC/DRR.
            e.io.regs.insert(o(0x1b9f), 0x40000000);
            e.io.regs.insert(o(0x1b33), 0x12340013);
            e.io.regs.insert(d(0x1acc), 0x32);
            let applied = run(e.prepare(req, c)).unwrap();
            assert_eq!(
                e.io.writes,
                [
                    (d(0x1ad0), 3),
                    (o(0x1b84), 3),
                    (BASE + (0x530 + p) * 4, 0),
                    (d(0x1acb), 0xfff00000 | (p as u32) << 16),
                    (o(0x1b2e), 0),
                    (d(0x1ad1), 0),
                    (o(0x1b33), 0),
                    (o(0x1b2a), 2199),
                    (o(0x1b2c), 44 << 16),
                    (o(0x1b2b), 192 << 16 | 2112),
                    (o(0x1b2d), 0),
                    (o(0x1b2f), 1124),
                    (o(0x1b30), 1124),
                    (o(0x1b31), 1124),
                    (o(0x1b39), 5 << 16),
                    (o(0x1b38), 41 << 16 | 1121),
                    (o(0x1b3a), 1),
                    (o(0x1b45), 0),
                    (o(0x1b43), control),
                    (o(0x1b85), 43),
                    (o(0x1b86), 56 << 16 | 1234),
                    (o(0x1b87), 78),
                    (o(0x1b9f), 0x40000009),
                    (BASE + (0x530 + p) * 4, 1121 << 16 | 1),
                    (d(0x1acc), 0),
                ]
            );
            assert_eq!(e.status.pipes[usize::from(pipe)], Some(applied));
            assert_eq!(e.status.state, State::Prepared);
            assert_eq!(reg(&e, 0x1b43 + 0x80 * p) & 0x10001, 0);
            assert_eq!(reg(&e, 0x530 + p) & 0x80000000, 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_native_timing_all_pipes_and_signal_muxes
);

fn dcn401_otg_odd_horizontal_boundaries_force_manual_no_divide() -> TestResult {
    for which in 0..4 {
        let mut r = request(0);
        match which {
            0 => r.timing.h_total += 1,
            1 => r.timing.h_front_porch += 1,
            2 => r.timing.h_active += 1,
            _ => r.timing.h_sync_width += 1,
        }
        let mut e = engine();
        run(e.prepare(r, clock(r))).unwrap();
        assert_eq!(reg(&e, 0x1b2e), 0x100);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_odd_horizontal_boundaries_force_manual_no_divide
);

fn dcn401_otg_rejects_malformed_timings_without_writes() -> TestResult {
    let mut cases = Vec::new();
    macro_rules! bad {
        ($field:ident, $value:expr) => {{
            let mut r = request(0);
            r.timing.$field = $value;
            cases.push(r);
        }};
    }
    bad!(pixel_clock_khz, 0);
    bad!(h_active, 0);
    bad!(v_active, 0);
    bad!(h_total, 0);
    bad!(v_total, 0);
    bad!(h_total, 32769);
    bad!(v_total, 32769);
    bad!(h_total, 1920);
    bad!(v_total, 1082);
    bad!(h_active, u32::MAX);
    bad!(h_front_porch, u32::MAX);
    bad!(v_front_porch, u32::MAX);
    bad!(v_front_porch, 0);
    bad!(h_sync_width, 3);
    bad!(v_sync_width, 0);
    bad!(h_sync_width, 193);
    bad!(v_sync_width, 42);
    let mut r = request(4);
    cases.push(r);
    r = request(0);
    r.sync.vstartup = 0;
    cases.push(r);
    r = request(0);
    r.sync.vstartup = 1024;
    cases.push(r);
    r = request(0);
    r.sync.vupdate_offset = 65536;
    cases.push(r);
    r = request(0);
    r.sync.vupdate_width = 1024;
    cases.push(r);
    r = request(0);
    r.sync.vready_offset = 65536;
    cases.push(r);
    r = request(0);
    r.sync.pstate_keepout = 32768;
    cases.push(r);
    for r in cases {
        let mut e = engine();
        assert_eq!(run(e.prepare(r, clock(r))), Err(Error::Invalid));
        assert!(e.io.writes.is_empty());
        assert_eq!(e.status.state, State::Ready);
    }
    // Native maximum totals and zero FP2 remain representable.
    let mut r = request(0);
    r.timing.h_total = 32768;
    r.timing.v_total = 32768;
    let p = r.plan().unwrap();
    assert_eq!(p.vtg & 0xffff, 0);
    r.timing.h_front_porch = 0;
    assert!(r.plan().is_err(), "blank start must fit 15 bits");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_rejects_malformed_timings_without_writes
);

fn dcn401_otg_requires_retired_consumers_and_matching_clocks() -> TestResult {
    for (at, mask) in engine().layout.idle {
        for bit in (0..32).map(|i| 1u32 << i).filter(|b| mask & b != 0) {
            let mut e = engine();
            e.io.regs.insert(at, bit);
            assert_eq!(
                run(e.prepare(request(0), clock(request(0)))),
                Err(Error::Busy)
            );
            assert!(e.io.writes.is_empty());
        }
        let mut e = engine();
        e.io.regs.insert(at, u32::MAX);
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::DeviceGone)
        );
        assert!(e.io.writes.is_empty());
    }
    for (index, value) in [(0x1b89, 1), (0x1b89, 0x100), (0x1b84, 0x10)] {
        let mut e = engine();
        e.io.regs.insert(BASE + index * 4, value);
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Busy)
        );
        assert!(e.io.writes.is_empty());
    }
    for c in [
        {
            let mut c = clock(request(0));
            c.request.pipe = 1;
            c
        },
        {
            let mut c = clock(request(0));
            c.request.pixel = dccg::PixelClock::Disabled;
            c
        },
        {
            let mut c = clock(request(0));
            c.request.pixel = dccg::PixelClock::HdmiFrl {
                pixel_hz: 148_500_000,
            };
            c
        },
        {
            let mut c = clock(request(0));
            c.request.pixel = dccg::PixelClock::DisplayPort {
                pixel_hz: 148_500_001,
            };
            c
        },
        {
            let mut c = clock(request(0));
            c.global.display_khz = 148_499;
            c
        },
    ] {
        let mut e = engine();
        assert_eq!(run(e.prepare(request(0), c)), Err(Error::Invalid));
        assert!(e.io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_requires_retired_consumers_and_matching_clocks
);

fn dcn401_otg_clock_waits_and_cancellation_quarantine() -> TestResult {
    for (stall, at, writes) in [(1, BASE + 0x1ad0 * 4, 1), (2, BASE + 0x1b84 * 4, 2)] {
        let mut e = engine();
        e.io.stall = stall;
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Timeout(at))
        );
        assert_eq!(e.io.writes.len(), writes);
        assert_eq!(e.status.state, State::Failed(Error::Timeout(at)));
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        let mut e = engine();
        e.io.stall = stall;
        // Count polls: a preempted vCPU can otherwise pass the wall-clock
        // deadline before the first poll returns.
        e.io.poll_limit = Some(8);
        let mut future = core::pin::pin!(e.prepare(request(0), clock(request(0))));
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        // Dropping the future below preserves the in-flight state.
    }
    let mut e = engine();
    e.io.stall = 1;
    e.io.poll_limit = Some(8);
    {
        let mut f = core::pin::pin!(e.prepare(request(0), clock(request(0))));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.status.state, State::Preparing(0));
    assert_eq!(
        run(e.prepare(request(0), clock(request(0)))),
        Err(Error::Busy)
    );
    assert_eq!(run(e.retire(0)), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_clock_waits_and_cancellation_quarantine
);

fn dcn401_otg_partial_write_failures_are_terminal() -> TestResult {
    for n in 1..=25 {
        let mut e = engine();
        e.io.gone = Some(n);
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::DeviceGone)
        );
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.state, State::Failed(Error::DeviceGone));
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Busy)
        );
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        let mut e = engine();
        e.io.revoke = Some((n, e.authority));
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Revoked)
        );
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.state, State::Failed(Error::Revoked));
    }
    for (n, at) in [
        (1, 0x1ad0),
        (2, 0x1b84),
        (4, 0x1acb),
        (8, 0x1b2a),
        (19, 0x1b43),
        (24, 0x530),
    ] {
        let mut e = engine();
        e.io.reject = Some(n);
        let err = Error::Readback(BASE + at * 4);
        assert_eq!(run(e.prepare(request(0), clock(request(0)))), Err(err));
        assert_eq!(e.status.state, State::Failed(err));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_partial_write_failures_are_terminal
);

fn active(e: &mut Engine<Fake>, pipe: u8) {
    let p = u64::from(pipe);
    e.io.regs.insert(
        BASE + (0x1acb + 0x10 * p) * 4,
        u32::from(pipe) << 16 | 0x100,
    );
    e.io.regs.insert(BASE + (0x1ad1 + 0x10 * p) * 4, 0xabcd0055);
    e.io.regs.insert(BASE + (0x1b43 + 0x80 * p) * 4, 0x210201);
    e.io.regs.insert(BASE + (0x1b84 + 0x80 * p) * 4, 0x10103);
    e.io.regs.insert(BASE + (0x530 + p) * 4, 0x80000055);
    e.io.delay[usize::from(pipe)] = 3;
}
fn dcn401_otg_retirement_waits_for_current_master_and_busy() -> TestResult {
    for pipe in 0..4 {
        let mut e = engine();
        active(&mut e, pipe);
        let p = u64::from(pipe);
        run(e.retire(pipe)).unwrap();
        assert_eq!(
            e.io.writes,
            [
                (BASE + (0x1acb + 0x10 * p) * 4, 0xffff0100),
                (BASE + (0x1ad1 + 0x10 * p) * 4, 0xabcd0000),
                (BASE + (0x1b43 + 0x80 * p) * 4, 0x210200),
                (BASE + (0x530 + p) * 4, 0x55),
                (BASE + (0x1b43 + 0x80 * p) * 4, 0x200),
            ]
        );
        assert_eq!(reg(&e, 0x1b43 + 0x80 * p), 0x200);
        assert_eq!(reg(&e, 0x1b84 + 0x80 * p), 0x103);
        assert_eq!(e.status.retired, 1 << pipe);
        assert_eq!(e.status.state, State::Retired);
        run(e.prepare(request(pipe), clock(request(pipe)))).unwrap();
        assert_eq!(e.status.retired, 0);
        run(e.retire(pipe)).unwrap();
        assert_eq!(e.status.pipes[usize::from(pipe)], None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_retirement_waits_for_current_master_and_busy
);

fn dcn401_otg_retirement_faults_and_cancel_never_release_resources() -> TestResult {
    for (stall, index) in [(4, 0x1b43), (8, 0x1b84)] {
        let mut e = engine();
        active(&mut e, 0);
        e.io.stall = stall;
        let err = Error::Timeout(BASE + index * 4);
        assert_eq!(run(e.retire(0)), Err(err));
        assert_eq!(e.status.state, State::Failed(err));
        assert_eq!(e.status.retired, 0);
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        // A timing which did not stop must retain its HPO route.
        assert_eq!(reg(&e, 0x1b43) & 0x300000, 0x200000);
        assert_eq!(e.io.writes.len(), 4);
    }
    for n in 1..=5 {
        let mut e = engine();
        active(&mut e, 0);
        e.io.gone = Some(n);
        assert_eq!(run(e.retire(0)), Err(Error::DeviceGone));
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.retired, 0);
        let mut e = engine();
        active(&mut e, 0);
        e.io.revoke = Some((n, e.authority));
        assert_eq!(run(e.retire(0)), Err(Error::Revoked));
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.retired, 0);
    }
    let mut e = engine();
    active(&mut e, 0);
    e.io.reject = Some(5);
    let err = Error::Readback(BASE + 0x1b43 * 4);
    assert_eq!(run(e.retire(0)), Err(err));
    assert_eq!(e.status.state, State::Failed(err));
    assert_eq!(e.status.retired, 0);
    assert_eq!(reg(&e, 0x1b43) & 0x300000, 0x200000);
    assert_eq!(run(e.retire(0)), Err(Error::Busy));
    let mut e = engine();
    active(&mut e, 0);
    e.io.stall = 4;
    {
        let mut f = core::pin::pin!(e.retire(0));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.status.state, State::Retiring(0));
    assert_eq!(e.status.retired, 0);
    assert_eq!(run(e.retire(0)), Err(Error::Busy));
    // Live stream preflight must reject even a request to retire timing.
    for (at, mask) in engine().layout.idle {
        if (0..4)
            .any(|p| at == BASE + (0x1b43 + 0x80 * p) * 4 || at == BASE + (0x1b84 + 0x80 * p) * 4)
        {
            continue;
        }
        let mut e = engine();
        active(&mut e, 0);
        e.io.regs.insert(at, mask);
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        assert!(e.io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_retirement_faults_and_cancel_never_release_resources
);

fn dcn401_otg_constructor_checks_native_discovery_without_writes() -> TestResult {
    let mut words = vec![0; 0x80000 / 4];
    let mut gpu = descriptor(&mut words);
    let before = words.clone();
    let cap = Cap::bootstrap();
    assert_eq!(
        // SAFETY: isolated model RAM; constructor never starts hardware.
        unsafe { Otg::new(&gpu, cap) }.unwrap().status().state,
        State::Ready
    );
    assert_eq!(words, before);
    for which in 0..5 {
        gpu = descriptor(&mut words);
        match which {
            0 => gpu.chip.did = crate::amdgpu::NAVI22,
            1 => gpu.ip_blocks.last_mut().unwrap().major = 3,
            2 => gpu.ip_blocks.last_mut().unwrap().num_bases = 2,
            3 => gpu.regs.len = 0x20000,
            _ => {
                let dc = *gpu.ip_blocks.last().unwrap();
                gpu.ip_blocks.push(dc);
            }
        }
        // SAFETY: same isolated RAM, invalid metadata must be rejected.
        assert!(unsafe { Otg::new(&gpu, cap) }.is_err());
    }
    gpu = descriptor(&mut words);
    cap.revoke();
    assert!(matches!(
        // SAFETY: model-only revoked constructor performs no MMIO.
        unsafe { Otg::new(&gpu, cap) },
        Err(Error::Revoked)
    ));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_otg_constructor_checks_native_discovery_without_writes
);

fn blank_engine(pipe: u8) -> Engine<Fake> {
    let mut e = engine();
    run(e.prepare(request(pipe), clock(request(pipe)))).unwrap();
    // Complete the fixture's prior disable event before injecting a new live
    // consumer; otherwise the simulator would retire that injected event too.
    e.io.retiring = [false; 4];
    e.io.writes.clear();
    e
}
fn blank_request(pipe: u8) -> BlankRequest {
    BlankRequest {
        pipe,
        depth: ColorDepth::Bpc8,
        limited: false,
        ycbcr420: false,
        colorspace: crate::amdgpu_dcn401_otg::BlankRequest::default_colorspace(false, false),
    }
}

fn dcn401_opp_stages_native_rgb_black_without_claiming_blank_completion() -> TestResult {
    for pipe in 0..4 {
        for (depth, trunc, expand, dpg) in [
            (ColorDepth::Bpc8, 0x11, 0x11, 0x1041),
            (ColorDepth::Bpc10, 0x23, 1, 0x2041),
            (ColorDepth::Bpc12, 0, 1, 0x3041),
        ] {
            let mut e = blank_engine(pipe);
            let at = |r| BASE + (r + 0x5a * u64::from(pipe)) * 4;
            e.io.regs.insert(at(0x1841), 0x0061ff33);
            for r in [0x1842, 0x1843, 0x1844] {
                e.io.regs.insert(at(r), 0x80000055);
            }
            e.io.regs.insert(at(0x1840), 0x102f3f00);
            e.io.regs.insert(at(0x1854), 0x41ff3170);
            let req = BlankRequest {
                pipe,
                depth,
                limited: false,
                ycbcr420: false,
                colorspace: crate::amdgpu_dcn401_otg::BlankRequest::default_colorspace(
                    false, false,
                ),
            };
            let a = run(e.prepare_blank(req, clock(request(pipe)))).unwrap();
            assert!(a.pending, "OPP double-buffer still awaits timing enable");
            assert_eq!(e.status.state, State::BlankPrepared);
            assert_eq!(e.status.blanks[usize::from(pipe)], Some(a));
            assert_eq!(
                e.io.writes,
                [
                    (at(0x188c), 1),
                    (at(0x1849), 0),
                    (at(0x1841), 0x00600000 | trunc),
                    (at(0x1842), 0),
                    (at(0x1843), 0),
                    (at(0x1844), 0),
                    (at(0x1840), 0x10000000),
                    (at(0x1845), 1),
                    (at(0x183f), expand),
                    (at(0x1856), 1920 << 16 | 1080),
                    (at(0x185a), 0),
                    (at(0x1859), 0),
                    (at(0x1858), 0),
                    (at(0x1857), 0),
                    (at(0x1854), 0x40000000 | dpg),
                ]
            );
            assert_eq!(reg(&e, 0x1b43 + 0x80 * u64::from(pipe)) & 0x10001, 0);
            assert_eq!(reg(&e, 0x530 + u64::from(pipe)) & 0x80000000, 0);
            e.io.writes.clear();
            assert_eq!(
                run(e.prepare_blank(req, clock(request(pipe)))),
                Err(Error::Busy)
            );
            assert!(e.io.writes.is_empty(), "unlatched pattern overwritten");
            run(e.retire(pipe)).unwrap();
            assert_eq!(e.status.blanks[usize::from(pipe)], None);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-opp",
    dcn401_opp_stages_native_rgb_black_without_claiming_blank_completion
);

fn dcn401_opp_rejects_stale_timing_pending_transactions_and_live_consumers() -> TestResult {
    let mut e = engine();
    assert_eq!(
        run(e.prepare_blank(blank_request(0), clock(request(0)))),
        Err(Error::Invalid)
    );
    assert!(e.io.writes.is_empty());
    let mut e = blank_engine(0);
    for pipe in [1, 4, 255] {
        assert_eq!(
            run(e.prepare_blank(blank_request(pipe), clock(request(0)))),
            Err(Error::Invalid)
        );
    }
    let mut stale = clock(request(0));
    stale.global.dpp_khz += 1;
    assert_eq!(
        run(e.prepare_blank(blank_request(0), stale)),
        Err(Error::Invalid)
    );
    assert!(e.io.writes.is_empty());
    for (r, v) in [
        (0x1840, 0x1000000),
        (0x185b, 1),
        (0x188c, 0x10),
        (0x1b89, 1),
    ] {
        let mut e = blank_engine(0);
        e.io.regs.insert(BASE + r * 4, v);
        assert_eq!(
            run(e.prepare_blank(blank_request(0), clock(request(0)))),
            Err(Error::Busy)
        );
        assert!(e.io.writes.is_empty());
        assert_eq!(e.status.state, State::Prepared);
    }
    for (at, mask) in engine().layout.idle {
        let mut e = blank_engine(0);
        e.io.regs.insert(at, mask);
        assert_eq!(
            run(e.prepare_blank(blank_request(0), clock(request(0)))),
            Err(Error::Busy)
        );
        assert!(e.io.writes.is_empty());
    }
    let mut e = blank_engine(0);
    e.status.pipes[0].as_mut().unwrap().request.timing.h_active = 0x4000;
    assert_eq!(
        run(e.prepare_blank(blank_request(0), clock(request(0)))),
        Err(Error::Invalid)
    );
    assert!(e.io.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-opp",
    dcn401_opp_rejects_stale_timing_pending_transactions_and_live_consumers
);

fn dcn401_opp_partial_failures_and_cancellation_block_clock_reuse() -> TestResult {
    for n in 1..=15 {
        let mut e = blank_engine(0);
        e.io.gone = Some(n);
        assert_eq!(
            run(e.prepare_blank(blank_request(0), clock(request(0)))),
            Err(Error::DeviceGone)
        );
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.state, State::Failed(Error::DeviceGone));
        assert!(e.status.blanks[0].is_none());
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Busy)
        );
        let mut e = blank_engine(0);
        e.io.revoke = Some((n, e.authority));
        assert_eq!(
            run(e.prepare_blank(blank_request(0), clock(request(0)))),
            Err(Error::Revoked)
        );
        assert_eq!(e.io.writes.len(), n);
        assert_eq!(e.status.state, State::Failed(Error::Revoked));
    }
    let mut e = blank_engine(0);
    e.io.stall = 16;
    let err = Error::Timeout(BASE + 0x188c * 4);
    assert_eq!(
        run(e.prepare_blank(blank_request(0), clock(request(0)))),
        Err(err)
    );
    assert_eq!(e.status.state, State::Failed(err));
    assert_eq!(e.io.writes.len(), 1);
    let mut e = blank_engine(0);
    e.io.stall = 16;
    {
        let mut f = core::pin::pin!(e.prepare_blank(blank_request(0), clock(request(0))));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.status.state, State::PreparingBlank(0));
    assert!(!e.status.state.reusable());
    assert!(e.status.blanks[0].is_none());
    assert_eq!(run(e.retire(0)), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-opp",
    dcn401_opp_partial_failures_and_cancellation_block_clock_reuse
);

#[path = "amdgpu_dcn401_harvest_tests.rs"]
pub(crate) mod harvest;

#[path = "amdgpu_dcn401_blank_tests.rs"]
mod blank;

#[path = "amdgpu_dcn401_fetch_tests.rs"]
mod fetch;

#[path = "amdgpu_dcn401_stream_tests.rs"]
mod stream;

#[path = "amdgpu_dcn401_encoder_tests.rs"]
mod encoder;
#[path = "amdgpu_dcn401_hpo_link_tests.rs"]
mod hpo_link;
#[path = "amdgpu_dcn401_link_tests.rs"]
mod link;

#[path = "amdgpu_dcn401_hdmi_tests.rs"]
mod hdmi;

#[path = "amdgpu_dcn401_hdmi_link_tests.rs"]
mod hdmi_link;
#[path = "amdgpu_dcn401_tmds_timing_tests.rs"]
mod tmds_timing;

#[path = "amdgpu_dcn401_tmds_phy_tests.rs"]
mod tmds_phy;

#[path = "amdgpu_dcn401_frl_tests.rs"]
mod frl;

#[path = "amdgpu_dcn401_frl_link_tests.rs"]
mod frl_link;

fn dcn401_admission_inputs_read_live_dchub_timer_and_capped_levels() -> TestResult {
    // SOC, UCLK, FCLK, DISP, DPP, DCF, DTB in MHz.
    let levels = clocks::Levels::fine_grained(
        [
            [300, 1200],
            [96, 1250],
            [300, 2500],
            [100, 2000],
            [100, 2000],
            [200, 1564],
            [100, 1564],
        ],
        16,
    );
    let timer = BASE + GLOBAL_TIMER * 4;
    let mut e = engine();
    for (value, crystal, want) in [
        (0x1002, 100_000, Ok(50_000)),
        (0x1001, 48_000, Ok(48_000)),
        (0x0002, 100_000, Err(Error::Unsupported)),
        (0x1001, 100_000, Err(Error::Unsupported)),
        (0x1002, 27_000, Err(Error::Unsupported)),
    ] {
        e.io.regs.insert(timer, value);
        let writes = e.io.writes.len();
        if e.dchub_refclk_khz(crystal) != want || e.io.writes.len() != writes {
            return TestResult::Fail("DCHUB reference derivation");
        }
    }
    e.io.regs.insert(timer, 0x1002);
    let Ok(soc) = e.admission_soc(&levels, 4_500_000, 100_000) else {
        return TestResult::Fail("admission inputs rejected");
    };
    if soc.uclk_khz != 1_250_000
        || soc.fclk_khz != [300_000, 2_500_000]
        || soc.dcfclk_khz != [200_000, 1_564_000]
        || soc.socclk_khz != 300_000
        || soc.umc_channels != 16
        || soc.dchub_refclk_khz != 50_000
    {
        return TestResult::Fail("admission inputs");
    }
    let mode = dml::Mode {
        timing: Timing {
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
        },
        pitch: 1920,
        bytes_per_pixel: 4,
        ycbcr420: false,
        dsc: None,
        planes: [None; dml::MAX_PLANES],
    };
    if dml::admit(&soc, &mode).map(|p| p.clocks.dispclk_khz) != Ok(151_260) {
        return TestResult::Fail("live inputs do not reproduce the reference plan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_admission_inputs_read_live_dchub_timer_and_capped_levels
);

fn dcn401_running_timing_reports_enable_or_status() -> TestResult {
    let mut e = engine();
    let l = e.layout;
    e.io.regs.insert(l.otg(1, CONTROL), 1);
    e.io.regs.insert(l.otg(3, CONTROL), 0x10000); // disabling, not yet off
    e.io.regs.insert(l.otg(2, CONTROL), 0x100); // other fields only
    if e.running_timing() != Ok(0b1010) {
        return TestResult::Fail("running timing mask");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_running_timing_reports_enable_or_status
);

/// HDMI YCbCr 4:2:0 timing divides the horizontal timing by two and
/// formats 4:2:0 data (optc401_set_odm_bypass, optc1 OPTC_DATA_FORMAT 2);
/// its OPP subsamples with the Cb/Cr bit reduction bypassed, releases the
/// 4:2:0 memory's forced power state and blanks to YCbCr black. Odd
/// horizontal timing, DP 4:2:0 and an OPP request that disagrees with its
/// timing are refused.
fn dcn401_ycbcr420_divides_horizontal_timing_and_subsamples() -> TestResult {
    for signal in [Signal::Tmds, Signal::HdmiFrl] {
        let pipe = 2;
        let mut req = request(pipe);
        (req.signal, req.ycbcr420) = (signal, true);
        let mut e = engine();
        if run(e.prepare(req, clock(req))).is_err() {
            return TestResult::Fail("4:2:0 timing");
        }
        let l = e.layout;
        if e.io.regs[&l.otg(pipe, H_TIMING)] & 0x103 != 1
            || e.io.regs[&l.odm(pipe, FORMAT)] & 0x33 != 2
        {
            return TestResult::Fail("H divide-by-2 and 4:2:0 data format");
        }
        // Odd horizontal timing, and 4:2:0 on DP.
        let mut odd = req;
        odd.timing.h_sync_width = 45;
        let mut dp = req;
        dp.signal = Signal::DisplayPort;
        if run(engine().prepare(odd, clock(odd))) != Err(Error::Unsupported)
            || run(engine().prepare(dp, clock(dp))) != Err(Error::Unsupported)
        {
            return TestResult::Fail("odd or DP 4:2:0 timing");
        }
        let mut wide = req;
        wide.timing.h_active = 5120;
        wide.timing.h_total = 5500;
        let mut e_bad = engine();
        assert_eq!(
            run(e_bad.prepare(wide, clock(wide))),
            Err(Error::Unsupported)
        );
        assert!(e_bad.io.writes.is_empty());
        let opp = |r: u64| BASE + (r + 0x5a * u64::from(pipe)) * 4;
        e.io.regs.insert(opp(0x1847), 3); // 4:2:0 memory power forced
        e.io.retiring = [false; 4];
        let blank = BlankRequest {
            ycbcr420: true,
            colorspace: crate::amdgpu_dcn401_otg::BlankRequest::default_colorspace(false, true),
            ..blank_request(pipe)
        };
        for bad in [
            BlankRequest {
                ycbcr420: false,
                ..blank
            },
            BlankRequest {
                limited: true,
                ..blank
            },
        ] {
            if run(e.prepare_blank(bad, clock(req))) != Err(Error::Invalid) {
                return TestResult::Fail("OPP request disagreeing with 4:2:0 timing");
            }
        }
        if run(e.prepare_blank(blank, clock(req))).is_err() {
            return TestResult::Fail("4:2:0 OPP");
        }
        let regs = &e.io.regs;
        if regs[&opp(0x1840)] & 0x2f3f00 != 0x2a_0000
        || regs[&opp(0x1847)] & 3 != 0
        || regs[&opp(0x1857)] != 0x8000_8000 // Cr
        || regs[&opp(0x1858)] != 0x1000_1000 // Y
        || regs[&opp(0x1859)] != 0x8000_8000 // Cb
        || regs[&opp(0x1849)] & 1 != 0
        {
            return TestResult::Fail("4:2:0 formatter and YCbCr black");
        }
        // RGB leaves the 4:2:0 memory alone.
        let mut e = blank_engine(pipe);
        e.io.regs.insert(opp(0x1847), 3);
        if run(e.prepare_blank(blank_request(pipe), clock(request(pipe)))).is_err()
            || e.io.regs[&opp(0x1847)] != 3
            || e.io.regs[&opp(0x1840)] & 0x2f3f00 != 0
        {
            return TestResult::Fail("RGB OPP touched 4:2:0 state");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_ycbcr420_divides_horizontal_timing_and_subsamples
);

/// A 128b/132b sibling holds its HPO stream encoder and the link encoder
/// it rides (another index for an MST link's owner), with the SYMCLK32
/// route registers their nibbles share; other HPO encoders stay foreign.
fn dcn401_hpo_siblings_hold_their_encoders() -> TestResult {
    let l = engine().layout;
    let s = Siblings {
        hpo: 1 << 2,
        hpo_links: 1 << 0,
        ..Siblings::default()
    };
    let hpo = |i: u8, r: u64| super::stream::DpStream::Hpo(i).at(l, r);
    let held = |at| held_by_sibling(s, l, at);
    let stream = [0x3623, 0x365d, 0x367b, 0x3685];
    let link = [0x369f, 0x36b4, 0x36b5];
    if stream
        .iter()
        .any(|&r| !held(hpo(2, r)) || held(hpo(0, r)) || held(hpo(1, r)))
        || link
            .iter()
            .any(|&r| !held(hpo(0, r)) || held(hpo(2, r)) || held(hpo(1, r)))
        || !held(l.link_clock)
        || !held(l.link_clock - 4)
        || held_by_sibling(Siblings::default(), l, l.link_clock)
        || held_by_sibling(Siblings::default(), l, l.link_clock - 4)
    {
        return TestResult::Fail("HPO sibling registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hpo_siblings_hold_their_encoders
);

/// DSC on the pipe's own DSC, as link_set_dsc_on_stream programs it: the
/// gated domain powered, every DSC register written whole from
/// dsc_prepare_config's values, the DSC clocked and fed from OPP n, then
/// the OPTC's DSC mode, bytes per pixel and slice width. Retirement turns
/// the OPTC's DSC off, disconnects and disables the DSC, and gates it.
/// Only one DSC on 8b/10b DP RGB is taken.
fn dcn401_dsc_follows_link_set_dsc_on_stream() -> TestResult {
    use crate::amdgpu_dsc::DscConfig;
    let pipe = 2u8;
    let cfg = DscConfig {
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
    let req = Request {
        signal: Signal::DisplayPort,
        dsc: Some(cfg),
        ..request(pipe)
    };
    let mut e = engine();
    e.io.regs.insert(BASE + 0x8d * 4, 1); // DSC2 gated
    if let Err(err) = run(e.prepare(req, clock(req))) {
        panic!("DSC prepare: {err:?}");
    }
    let regs = dsc_hw::dsc_registers(&req, &cfg).unwrap();
    let dsc = |r: u64| {
        e.io.regs
            .get(&(BASE + (0x3000 + 2 * 0x5c + r) * 4))
            .copied()
            .unwrap_or(0)
    };
    let odm = |r: u64| {
        e.io.regs
            .get(&(BASE + (r + 2 * 0x10) * 4))
            .copied()
            .unwrap_or(0)
    };
    if e.io.regs[&(BASE + 0x8d * 4)] & 1 != 0
        || dsc(0xa) != (0xf | 1 << 4 | 1 << 8 | 9 << 16)
        || dsc(0x14) != (1920 | 1080 << 16)
        || dsc(0x15) != (960 | 108 << 16)
        || dsc(0x13) & 0x3ff != 128
        || dsc(0x13) >> 16 != u32::from(regs.pps.slice_chunk_size)
        || dsc(5) != 8 << 16 // RGB (0), 8 bpc
        || dsc(0) & 1 != 1
        || e.io.regs[&(BASE + (0x1a64 + 2) * 4)] & 0x71 != (1 | 2 << 4)
        || odm(0x1acc) & 0x30 != 0x10
        || odm(0x1acd) != regs.bytes_per_pixel
        || odm(0x1ace) >> 16 != 960
    {
        return TestResult::Fail("DSC programming");
    }
    e.dsc_running(&req, &cfg).unwrap();
    // Retirement: DSC off before the timing, then gated.
    e.io.retiring = [true; 4];
    run(e.retire(pipe)).unwrap();
    let dsc = |r: u64| {
        e.io.regs
            .get(&(BASE + (0x3000 + 2 * 0x5c + r) * 4))
            .copied()
            .unwrap_or(0)
    };
    if e.io.regs[&(BASE + (0x1a64 + 2) * 4)] & 1 != 0
        || dsc(0) & 1 != 0
        || e.io.regs[&(BASE + 0x8d * 4)] & 1 != 1
        || e.io.regs[&(BASE + (0x1acc + 0x20) * 4)] & 0x30 != 0
    {
        return TestResult::Fail("DSC retirement");
    }
    // DP SST only (DIO or HPO), at most four slices per DSC.
    let mut e = engine();
    for bad in [
        Request {
            signal: Signal::Tmds,
            ..req
        },
        Request {
            dsc: Some(DscConfig { slices_h: 8, ..cfg }),
            ..req
        },
    ] {
        assert_eq!(run(e.prepare(bad, clock(bad))), Err(Error::Unsupported));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dsc_follows_link_set_dsc_on_stream
);

/// 10- and 12-bpc DSC input, as link_set_dsc_on_stream programs a stream
/// whose display_color_depth is deeper than 8: DSC_CIF_CONFIG0's
/// INPUT_BITS_PER_COMPONENT and the PPS's bits_per_component (with the
/// rate control drm_dsc_compute_rc_parameters gives that depth) follow
/// the configuration's depth, and the OPP must feed the DSC that depth:
/// a blank request at another depth is refused. Depths DSC cannot code
/// are refused before any write.
fn dcn401_dsc_takes_10_and_12_bpc_input() -> TestResult {
    use crate::amdgpu_dsc::DscConfig;
    let pipe = 2u8;
    let cfg = |bpc| DscConfig {
        slices_h: 2,
        slices_v: 10,
        bpp_x16: 160,
        block_pred: true,
        linebuf_depth: 13,
        version_minor: 2,
        ycbcr422_simple: false,
        frl: None,
        bpc,
    };
    for (bpc, depth, other) in [
        (10u8, ColorDepth::Bpc10, ColorDepth::Bpc8),
        (12, ColorDepth::Bpc12, ColorDepth::Bpc10),
    ] {
        let cfg = cfg(bpc);
        let req = Request {
            signal: Signal::DisplayPort,
            dsc: Some(cfg),
            ..request(pipe)
        };
        let mut e = engine();
        e.io.regs.insert(BASE + 0x8d * 4, 1); // DSC2 gated
        if let Err(err) = run(e.prepare(req, clock(req))) {
            panic!("{bpc}-bpc DSC prepare: {err:?}");
        }
        let regs = dsc_hw::dsc_registers(&req, &cfg).unwrap();
        let want = crate::amdgpu_dsc::prepare(
            &crate::amdgpu_dsc::DscTiming {
                pix_clk_100hz: req.timing.pixel_clock_khz * 10,
                h_active: req.timing.h_active,
                h_total: req.timing.h_total,
                v_active: req.timing.v_active,
                v_total: req.timing.v_total,
                bpc,
                encoding: crate::amdgpu_dsc::Encoding::Rgb,
            },
            &cfg,
        )
        .unwrap();
        let dsc = |r: u64| {
            e.io.regs
                .get(&(BASE + (0x3000 + 2 * 0x5c + r) * 4))
                .copied()
                .unwrap_or(0)
        };
        if regs != want
            || regs.pps.bits_per_component != bpc
            || dsc(5) != u32::from(bpc) << 16 // RGB (0) at the input depth
            || dsc(0x12) >> 28 != u32::from(bpc)
            || dsc(0x13) & 0x3ff != 160
        {
            return TestResult::Fail("deep DSC input programming");
        }
        e.io.retiring = [false; 4];
        let blank = BlankRequest {
            depth: other,
            ..blank_request(pipe)
        };
        if run(e.prepare_blank(blank, clock(req))) != Err(Error::Invalid) {
            return TestResult::Fail("OPP depth disagreeing with the DSC input");
        }
        let blank = BlankRequest { depth, ..blank };
        if run(e.prepare_blank(blank, clock(req))).is_err() {
            return TestResult::Fail("OPP at the DSC input depth");
        }
    }
    let bad = Request {
        signal: Signal::DisplayPort,
        dsc: Some(cfg(14)),
        ..request(pipe)
    };
    let mut e = engine();
    if run(e.prepare(bad, clock(bad))) != Err(Error::Unsupported) || !e.io.writes.is_empty() {
        return TestResult::Fail("14-bpc DSC input");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dsc_takes_10_and_12_bpc_input
);

/// ODM 2:1 (optc401_set_odm_combine): both OPPs as segments 0 and 1, the
/// segment width, decide_odm_mem_bit_map's line memories and the halved
/// horizontal timing; each OPP formats its half and blanks it at its own
/// offset (dcn20_blank_pixel_data per slice); each segment's DSC
/// compresses its half with half the slices, fed from its own OPP, under
/// one OPTC DSC configuration. Retirement stops both DSCs. Odd horizontal
/// timing, 4:2:0 halves of a split pixel pair, a self-combine and lines
/// past two memories are refused. A 4:2:0 right half's OPP takes one extra
/// left-edge pixel for its chroma filter.
fn dcn401_odm_combines_two_opps_with_split_dsc() -> TestResult {
    odm_split_dsc_on(0, 3)
}
/// The test above on pipes (pipe, odm): the OPTC segments and line
/// memories name both pipes' OPP instances, each segment's DSC is its
/// pipe's (dcn20_acquire_dsc) fed from that pipe's OPP instance.
fn odm_split_dsc_on(pipe: u8, odm: u8) -> TestResult {
    use crate::amdgpu_dsc::DscConfig;
    let mut req = Request {
        signal: Signal::DisplayPort,
        odm: SplitPipes::one(odm),
        ..request(pipe)
    };
    req.timing = Timing {
        pixel_clock_khz: 2_000_000,
        h_active: 7680,
        h_total: 7840,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 4320,
        v_total: 4400,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: false,
    };
    let cfg = DscConfig {
        slices_h: 8,
        slices_v: 4,
        bpp_x16: 192,
        block_pred: true,
        linebuf_depth: 11,
        version_minor: 2,
        ycbcr422_simple: false,
        frl: None,
        bpc: 8,
    };
    req.dsc = Some(cfg);
    // DISPCLK covers half the pixel clock: each segment's share.
    let mut odm_clock = clock(req);
    odm_clock.request.pixel = dccg::PixelClock::DisplayPort {
        pixel_hz: 2_000_000_000,
    };
    odm_clock.global.display_khz = 1_000_000;
    let mut e = engine();
    for k in [u64::from(pipe), u64::from(odm)] {
        e.io.regs.insert(BASE + (0x89 + 2 * k) * 4, 1); // DSC domains gated
    }
    let mut bypass = odm_clock;
    bypass.request.pipe = pipe;
    if run(engine().prepare(
        Request {
            odm: SplitPipes::NONE,
            dsc: None,
            ..req
        },
        bypass,
    )) != Err(Error::Invalid)
    {
        return TestResult::Fail("one pipe at twice DISPCLK");
    }
    if let Err(err) = run(e.prepare(req, odm_clock)) {
        panic!("ODM prepare: {err:?}");
    }
    let l = e.layout;
    let r = |e: &Engine<Fake>, at: u64| e.io.regs.get(&at).copied().unwrap_or(0);
    if r(&e, l.odm(pipe, SOURCE))
        != 0xff00_0001 | l.inst_field(pipe) << 16 | l.inst_field(odm) << 20
        || r(&e, l.odm(pipe, WIDTH)) & 0x1fff != 3840
        || r(&e, l.odm(pipe, MEMORY)) & 0xffff != 3 << (2 * l.inst(pipe)) | 3 << (2 * l.inst(odm))
        || r(&e, l.otg(pipe, H_TIMING)) & 0x103 != 1
    {
        return TestResult::Fail("ODM source, segment width, memories and divide");
    }
    // Each half's DSC: 3840 wide, four slices of 960, from its own OPP.
    let dsc = |e: &Engine<Fake>, k: u64, reg: u64| r(e, BASE + (0x3000 + k * 0x5c + reg) * 4);
    for k in [u64::from(pipe), u64::from(odm)] {
        if dsc(&e, k, 0x14) & 0xffff != 3840
            || dsc(&e, k, 0x15) & 0xffff != 960
            || dsc(&e, k, 0xa) >> 4 & 3 != 3
            || dsc(&e, k, 0) & 1 != 1
            || r(&e, BASE + (0x1a64 + k) * 4) & 0x71 != (1 | l.inst_field(k as u8) << 4)
        {
            return TestResult::Fail("segment DSC");
        }
    }
    if r(&e, l.odm(pipe, FORMAT)) & 0x30 != 0x10 || r(&e, l.odm(pipe, WIDTH)) >> 16 != 960 {
        return TestResult::Fail("OPTC DSC configuration");
    }
    e.dsc_running(&req, &cfg).unwrap();
    // Both OPPs blank their own half.
    e.io.retiring = [false; 4];
    e.io.writes.clear();
    let a = run(e.prepare_blank(blank_request(pipe), odm_clock)).unwrap();
    for (o, x) in [(pipe, 0u32), (odm, 3840)] {
        let at = |reg: u64| BASE + (reg + 0x5a * u64::from(l.inst(o))) * 4;
        if r(&e, at(0x188c)) & 1 != 1
            || r(&e, at(0x1856)) != (3840 << 16 | 4320)
            || r(&e, at(0x185a)) != x
            || r(&e, at(0x1854)) & 0x01ff_3171 != 0x1041
        {
            return TestResult::Fail("segment OPP blank");
        }
    }
    e.verify_blank(a, req.plan().unwrap(), false).unwrap();
    // Retirement turns both segment DSCs off.
    e.io.retiring = [true; 4];
    run(e.retire(pipe)).unwrap();
    for k in [u64::from(pipe), u64::from(odm)] {
        if r(&e, BASE + (0x1a64 + k) * 4) & 1 != 0 || dsc(&e, k, 0) & 1 != 0 {
            return TestResult::Fail("segment DSC retirement");
        }
    }
    // One memory pair suffices to 4096 pixels.
    let mut narrow = request(pipe);
    narrow.odm = SplitPipes::one(odm);
    narrow.timing.h_active = 3840;
    narrow.timing.h_total = 4000;
    let mut e = engine();
    run(e.prepare(narrow, clock(narrow))).unwrap();
    if r(&e, e.layout.odm(pipe, MEMORY)) & 0xffff
        != 1 << (2 * l.inst(pipe)) | 1 << (2 * l.inst(odm))
    {
        return TestResult::Fail("two memories");
    }
    // 4:2:0 wider than one formatter: the right OPP filters across the seam.
    let mut wide420 = narrow;
    (wide420.signal, wide420.ycbcr420) = (Signal::Tmds, true);
    (wide420.timing.h_active, wide420.timing.h_total) = (5120, 5500);
    let mut e = engine();
    run(e.prepare(wide420, clock(wide420))).unwrap();
    e.io.retiring = [false; 4];
    let blank420 = BlankRequest {
        ycbcr420: true,
        colorspace: crate::amdgpu_dcn401_otg::BlankRequest::default_colorspace(false, true),
        ..blank_request(pipe)
    };
    run(e.prepare_blank(blank420, clock(wide420))).unwrap();
    let edge =
        |e: &Engine<Fake>, o: u8| r(e, BASE + (0x1849 + 0x5a * u64::from(l.inst(o))) * 4) & 1;
    if edge(&e, pipe) != 0 || edge(&e, odm) != 1 {
        return TestResult::Fail("4:2:0 left edge pixel");
    }
    // Refusals, with no writes.
    let mut odd = narrow;
    odd.timing.h_sync_width = 33;
    let mut wide = narrow;
    (wide.timing.h_active, wide.timing.h_total) = (8320, 8500);
    let mut ycbcr = narrow;
    (ycbcr.signal, ycbcr.ycbcr420) = (Signal::Tmds, true);
    ycbcr.timing.h_active = 3842; // segments of 1921: half a pixel pair
    for (bad, want) in [
        (odd, Error::Unsupported),
        (wide, Error::Unsupported),
        (ycbcr, Error::Unsupported),
        (
            Request {
                odm: SplitPipes::one(pipe),
                ..narrow
            },
            Error::Invalid,
        ),
        (
            Request {
                odm: SplitPipes::one(4),
                ..narrow
            },
            Error::Invalid,
        ),
    ] {
        let mut e = engine();
        if run(e.prepare(bad, clock(bad))) != Err(want) || !e.io.writes.is_empty() {
            return TestResult::Fail("refused ODM request");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_odm_combines_two_opps_with_split_dsc
);

/// ODM 3:1 and 4:1 (optc401_set_odm_combine): every OPP as a segment in
/// order (OPTC_NUM_OF_INPUT_SEGMENT the count less one, unused segments
/// 0xf), the segment width (and for 3:1 OPTC_SEGMENT_WIDTH_LAST, which an
/// uneven 3:1 line without DSC makes the rest of the line), the
/// first-then-second-preferred line memories and the divide-by-four
/// horizontal timing (four pixels per transfer); each OPP blanks its own
/// segment at its offset; each segment's DSC compresses its segment with
/// its share of the slices (twelve on three pipes). Retirement stops every
/// segment's DSC. A horizontal boundary not divisible by four, a line past
/// the segments' memories, a repeated pipe and slices that do not split
/// are refused.
fn dcn401_odm_combines_three_and_four_opps() -> TestResult {
    use crate::amdgpu_dsc::DscConfig;
    let r = |e: &Engine<Fake>, at: u64| e.io.regs.get(&at).copied().unwrap_or(0);
    let dsc = |e: &Engine<Fake>, k: u64, reg: u64| r(e, BASE + (0x3000 + k * 0x5c + reg) * 4);
    let pipe = 0u8;
    let timing = Timing {
        pixel_clock_khz: 2_400_000,
        h_active: 7680,
        h_total: 7840,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 4320,
        v_total: 4400,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: false,
    };
    let cfg = |slices_h| DscConfig {
        slices_h,
        slices_v: 4,
        bpp_x16: 192,
        block_pred: true,
        linebuf_depth: 11,
        version_minor: 2,
        ycbcr422_simple: false,
        frl: None,
        bpc: 8,
    };
    let odm_clock = |req: Request, display_khz| {
        let mut c = clock(req);
        c.request.pixel = dccg::PixelClock::DisplayPort {
            pixel_hz: u64::from(req.timing.pixel_clock_khz) * 1000,
        };
        c.global.display_khz = display_khz;
        c
    };
    for (odm, slices, source, width, memory, display_khz) in [
        (&[3u8, 2][..], 12, 0xf230_0002, 2560, 0x53, 800_000),
        (&[3, 2, 1][..], 16, 0x1230_0003, 1920, 0x55, 600_000),
    ] {
        let segments = odm.len() as u32 + 1;
        let req = Request {
            signal: Signal::DisplayPort,
            odm: SplitPipes::new(odm).unwrap(),
            dsc: Some(cfg(slices)),
            timing,
            ..request(pipe)
        };
        // Each segment's share of the pixel clock must fit DISPCLK.
        if run(engine().prepare(req, odm_clock(req, display_khz - 200_000))) != Err(Error::Invalid)
        {
            return TestResult::Fail("segment share above DISPCLK");
        }
        let mut e = engine();
        for k in core::iter::once(pipe).chain(odm.iter().copied()) {
            e.io.regs.insert(BASE + (0x89 + 2 * u64::from(k)) * 4, 1); // DSC domains gated
        }
        if let Err(err) = run(e.prepare(req, odm_clock(req, display_khz))) {
            panic!("ODM {segments}:1 prepare: {err:?}");
        }
        let l = e.layout;
        if r(&e, l.odm(pipe, SOURCE)) != source
            || r(&e, l.odm(pipe, WIDTH)) & 0x1fff != width
            || (segments == 3 && r(&e, l.odm(pipe, WIDTH2)) & 0x1fff != width)
            || (segments == 4 && r(&e, l.odm(pipe, WIDTH2)) != 0)
            || r(&e, l.odm(pipe, MEMORY)) & 0xffff != memory
            || r(&e, l.otg(pipe, H_TIMING)) & 0x103 != 3
        {
            return TestResult::Fail("ODM source, segment widths, memories and divide");
        }
        // Each segment's DSC: its width, four slices, from its own OPP.
        for k in core::iter::once(pipe).chain(odm.iter().copied()) {
            let k = u64::from(k);
            if dsc(&e, k, 0x14) & 0xffff != width
                || dsc(&e, k, 0x15) & 0xffff != width / 4
                || dsc(&e, k, 0xa) >> 4 & 3 != 3
                || dsc(&e, k, 0) & 1 != 1
                || r(&e, BASE + (0x1a64 + k) * 4) & 0x71 != (1 | (k as u32) << 4)
            {
                return TestResult::Fail("segment DSC");
            }
        }
        if r(&e, l.odm(pipe, FORMAT)) & 0x30 != 0x10 || r(&e, l.odm(pipe, WIDTH)) >> 16 != width / 4
        {
            return TestResult::Fail("OPTC DSC configuration");
        }
        e.dsc_running(&req, &cfg(slices)).unwrap();
        // Every OPP blanks its own segment.
        e.io.retiring = [false; 4];
        let a = run(e.prepare_blank(blank_request(pipe), odm_clock(req, display_khz))).unwrap();
        for (s, o) in core::iter::once(pipe)
            .chain(odm.iter().copied())
            .enumerate()
        {
            let at = |reg: u64| BASE + (reg + 0x5a * u64::from(o)) * 4;
            if r(&e, at(0x1856)) != (width << 16 | 4320) || r(&e, at(0x185a)) != s as u32 * width {
                return TestResult::Fail("segment OPP blank");
            }
        }
        e.verify_blank(a, req.plan().unwrap(), false).unwrap();
        e.io.retiring = [true; 4];
        run(e.retire(pipe)).unwrap();
        for k in core::iter::once(pipe).chain(odm.iter().copied()) {
            let k = u64::from(k);
            if r(&e, BASE + (0x1a64 + k) * 4) & 1 != 0 || dsc(&e, k, 0) & 1 != 0 {
                return TestResult::Fail("segment DSC retirement");
            }
        }
        if r(&e, l.odm(pipe, SOURCE)) & 0xffff_0003 != 0xffff_0000
            || r(&e, l.odm(pipe, MEMORY)) != 0
        {
            return TestResult::Fail("ODM retirement");
        }
    }
    // An uneven 3:1 line without DSC: the last segment takes the rest.
    let uneven = Request {
        signal: Signal::DisplayPort,
        odm: SplitPipes::new(&[2, 3]).unwrap(),
        timing: Timing {
            pixel_clock_khz: 2_600_000,
            h_active: 5120,
            h_total: 5280,
            ..timing
        },
        ..request(pipe)
    };
    let mut e = engine();
    run(e.prepare(uneven, odm_clock(uneven, 900_000))).unwrap();
    let l = e.layout;
    if r(&e, l.odm(pipe, WIDTH)) & 0x1fff != 1706
        || r(&e, l.odm(pipe, WIDTH2)) & 0x1fff != 1708
        || r(&e, l.odm(pipe, SOURCE)) != 0xf320_0002
    {
        return TestResult::Fail("uneven 3:1 segments");
    }
    e.io.retiring = [false; 4];
    run(e.prepare_blank(blank_request(pipe), odm_clock(uneven, 900_000))).unwrap();
    for (o, x, w) in [(pipe, 0u32, 1706u32), (2, 1706, 1706), (3, 3412, 1708)] {
        let at = |reg: u64| BASE + (reg + 0x5a * u64::from(o)) * 4;
        if r(&e, at(0x1856)) != (w << 16 | 4320) || r(&e, at(0x185a)) != x {
            return TestResult::Fail("uneven segment OPP blank");
        }
    }
    // Refusals, with no writes.
    let mut quarter = uneven;
    quarter.timing.h_total = 5282; // not divisible by four
    let mut wide = uneven;
    (wide.timing.h_active, wide.timing.h_total) = (12_800, 13_000);
    let twelve_on_four = Request {
        odm: SplitPipes::new(&[1, 2, 3]).unwrap(),
        dsc: Some(cfg(12)),
        timing,
        signal: Signal::DisplayPort,
        ..request(pipe)
    };
    let eight_on_three = Request {
        odm: SplitPipes::new(&[2, 3]).unwrap(),
        dsc: Some(cfg(8)),
        ..twelve_on_four
    };
    for (bad, want) in [
        (quarter, Error::Unsupported),
        (wide, Error::Unsupported),
        (eight_on_three, Error::Unsupported),
        (
            Request {
                odm: SplitPipes::new(&[2, 2]).unwrap(),
                ..uneven
            },
            Error::Invalid,
        ),
        (
            Request {
                odm: SplitPipes::new(&[2, 0]).unwrap(),
                ..uneven
            },
            Error::Invalid,
        ),
    ] {
        let mut e = engine();
        if run(e.prepare(bad, odm_clock(bad, 900_000))) != Err(want) || !e.io.writes.is_empty() {
            return TestResult::Fail("refused ODM request");
        }
    }
    // Twelve slices do split over four DSCs of three each.
    let mut e = engine();
    if run(e.prepare(twelve_on_four, odm_clock(twelve_on_four, 600_000))).is_err() {
        return TestResult::Fail("twelve slices on four DSCs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_odm_combines_three_and_four_opps
);
