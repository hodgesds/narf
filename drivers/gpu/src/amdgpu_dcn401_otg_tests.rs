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
    retiring: [bool; 4],
    delay: [u8; 4],
    reject: Option<usize>,
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
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        if self.gone == Some(self.writes.len()) {
            return u32::MAX;
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
        assert!(
            (BASE + 0x475 * 4..=BASE + 0x47a * 4).contains(&at)
                || (BASE + 0x530 * 4..=BASE + 0x1d1f * 4).contains(&at)
                || (BASE + 0x4ba * 4..=BASE + 0x4be * 4).contains(&at)
                || at == BASE + 0x4c4 * 4
                || at == BASE + 0x485 * 4 // SDPIF_REQUEST_RATE_LIMIT
                || (BASE + 0x4fc * 4..=BASE + 0x523 * 4).contains(&at) // arbiter/watermarks
                || (0x162a0 * 4..=0x162a3 * 4).contains(&at)
                || (0x16240 * 4..=0x16243 * 4).contains(&at) // PHYPLL deep-colour resync
                || (0x162ab * 4..=0x162ad * 4).contains(&at) // audio DTO0
                || at == BASE + 0x40c * 4 // Azalia stream formats
                || at == 0x16266 * 4 // descriptor's DCN bank 1 + SYMCLK32_LE_CNTL
                || at == BASE + 0x4a * 4 // native FRL character-clock root
                || at == BASE + 0xa0 * 4 // native DC_IP_REQUEST_CNTL, bank 2
                || at == BASE + 0x28f4 * 4 // DC_GPIO_HPD_MASK, bank 2
                || at == 0x7f000 // native HDP flush remap
                || (0..4).any(|p| at == BASE + (0x80 + 2 * p) * 4)
                || (BASE + 0x1f0d * 4..=BASE + 0x1f10 * 4).contains(&at)
                || (MPC_BASE..=MPC_BASE + 0x301 * 4).contains(&at)
                || (0..4).any(|p| {
                    at == MPC_BASE + (0x30b + p * 0xd) * 4
                        || [0x453, 0x48a, 0x493, 0x4de, 0x4ec].iter()
                            .any(|r| at == MPC_BASE + (r + p * 0xb0) * 4)
                })
                || (MPC_BASE + 0x8d3 * 4..=MPC_BASE + 0x8f0 * 4).contains(&at)
                || [0x95b, 0x95c, 0x965, 0x966].iter().any(|&r| at == MPC_BASE + r * 4)
                || (0..4).any(|p| {
                    [
                        0x2094, 0x2095, 0x209b, 0x209e, 0x20a5, 0x20a6, 0x20a9, 0x20aa, 0x20ab,
                        0x20ac, 0x20ad, 0x20ae, 0x20af, 0x20b0, 0x20bc, 0x211e, 0x2122, 0x2123,
                        0x2125, 0x212e, 0x20bb, 0x20bd, 0x2121, 0x2134, 0x212d, 0x2133, 0x2129,
                        0x2093, 0x211f, 0x2120, 0x2124, 0x2162, 0x2163, 0x2164, 0x2165, 0x2146,
                        0x2126, 0x2127, 0x2128, 0x20a2, 0x20a8, 0x20eb, 0x20b1, 0x2068, 0x2069,
                        0x206b, 0x206c, 0x206d, 0x20a0, 0x20a1, 0x20a3, 0x20a4, 0x20b2,
                        0x20b3, 0x20b4, 0x20b5, 0x20b6, 0x20b7, 0x20ba, 0x2075, 0x2078, 0x2079,
                        0x207f, 0x2082, 0x2083, 0x2085, 0x2087,
                    ]
                    .iter()
                    .any(|r| at == BASE + (r + p * 0x124) * 4)
                        || [
                            0x3623, 0x3626, 0x365d, 0x365e, 0x367b, 0x3685, 0x369f, 0x36b4, 0x36b8,
                            0x36bf, 0x36c0, 0x36c1, 0x36c2, 0x36c3, 0x36c4,
                        ]
                        .iter()
                        .any(|r| at == BASE + (r + p * 0xd4) * 4)
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
        },
        authority: Cap::bootstrap(),
        layout: Layout::resolve(&gpu).unwrap(),
        status: Box::new(Status {
            state: State::Ready,
            pipes: [None; 4],
            blanks: [None; 4],
            running_blank: None,
            planes_retired: None,
            hubp_power: [None; 4],
            surfaces: [None; 4],
            memory: [None; 4],
            dpps: [None; 4],
            mpcs: [None; 4],
            requestor: None,
            deadlines: None,
            scanout: None,
            underflow: None,
            cursor: None,
            dp_blanked: None,
            dp_encoder_retired: None,
            dp_sst_disabled: None,
            dp_phy_ready: None,
            dp_link_trained: None,
            dp_frontend_ready: None,
            dp_video_running: None,
            hpo_link_retired: None,
            hpo_dp_disabled: None,
            hdmi_tmds_retired: None,
            hdmi_link_ready: None,
            hdmi_video_running: None,
            hdmi_audio: None,
            tmds_timing_retired: None,
            tmds_disabled: None,
            frl_encoder_retired: None,
            frl_link_retired: None,
            frl_disabled: None,
            retired: 0,
        }),
    }
}
fn request(pipe: u8) -> Request {
    Request {
        pipe,
        signal: Signal::HpoDisplayPort,
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
fn clock(request: Request) -> dccg::Applied {
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
            },
            display_khz: 600_000,
            dpp_khz: 300_000,
            dtb_khz: 600_000,
            dcf_floor_khz: 1_200_000,
            memory_floor_khz: 1_200_000,
        },
        dpp_phase: 127,
        reference_hz: 720_000_000,
        integer: 0,
        phase: 148_500_000,
    }
}
pub(super) fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn reg(e: &Engine<Fake>, index: u64) -> u32 {
    *e.io.regs.get(&(BASE + index * 4)).unwrap_or(&0)
}

fn dcn401_otg_native_timing_all_pipes_and_signal_muxes() -> TestResult {
    for pipe in 0..4 {
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
            let p = u64::from(pipe);
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
                    (d(0x1acb), 0xfff00000 | u32::from(pipe) << 16),
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
        let mut future = core::pin::pin!(e.prepare(request(0), clock(request(0))));
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        // Dropping the future below preserves the in-flight state.
    }
    let mut e = engine();
    e.io.stall = 1;
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
            ]
        );
        assert_eq!(reg(&e, 0x1b43 + 0x80 * p), 0x200200);
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
    }
    for n in 1..=4 {
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
            let req = BlankRequest { pipe, depth };
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
