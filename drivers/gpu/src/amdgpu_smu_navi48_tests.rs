use super::*;
use alloc::vec;
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
fn put(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn board() -> Vec<u8> {
    let mut b = vec![0; COMBO_BYTES];
    b[..2].copy_from_slice(&(COMBO_BYTES as u16).to_le_bytes());
    b[2] = 23;
    for (f, v) in [
        (6, 1344u16),
        (8, 4468),
        (10, 1372),
        (12, 3552),
        (14, 5284),
        (16, 528),
        (18, 4924),
        (20, 360),
    ] {
        b[f..f + 2].copy_from_slice(&v.to_le_bytes());
    }
    put(&mut b, DRIVER_BYTES + 4, u32::MAX);
    put(&mut b, DRIVER_BYTES + 8, u32::MAX);
    b
}
#[derive(Debug)]
struct Fake {
    regs: [u32; 0x9b],
    memory: Vec<u8>,
    board: Vec<u8>,
    commands: Vec<(u32, u32)>,
    stall: Option<u32>,
    reject: Option<u32>,
    interface: u32,
    enabled: u64,
    reported: Option<u64>,
    revoke: Option<(u32, Cap<BusDeviceCap, Write>)>,
    dirty: bool,
    violation: bool,
    address: u64,
    policy: u32,
    uploaded: Vec<u8>,
    metrics: Vec<u8>,
}
impl Io for Fake {
    fn read(&mut self, reg: u32) -> u32 {
        self.regs[reg as usize]
    }
    fn write(&mut self, reg: u32, value: u32) {
        self.regs[reg as usize] = value;
        if reg != MESSAGE {
            return;
        }
        let p = self.regs[ARGUMENT as usize];
        self.commands.push((value, p));
        if self.stall == Some(value) {
            return;
        }
        if self.reject == Some(value) {
            self.regs[RESPONSE as usize] = 0xfd;
            return;
        }
        self.regs[RESPONSE as usize] = 1;
        self.regs[ARGUMENT as usize] = match value {
            3 => self.interface,
            2 => 0x684c00,
            0xe => {
                self.address = (p as u64) << 32;
                0
            }
            0xf => {
                self.address |= p as u64;
                0
            }
            0x12 => {
                self.violation |= !matches!(p, 1 | 5) || self.dirty || self.address != 0x8_00003000;
                if p == 5 {
                    // Stale staging must have been cleared before PMFW writes.
                    self.violation |= self.memory[..METRICS_BYTES].iter().any(|&b| b != 0);
                    self.memory[..METRICS_BYTES].copy_from_slice(&self.metrics);
                } else {
                    self.memory[..COMBO_BYTES].copy_from_slice(&self.board);
                }
                0
            }
            0x13 => {
                self.violation |= p != 0 || self.dirty;
                self.uploaded = self.memory[..POWER_BYTES].to_vec();
                0
            }
            5 => {
                self.enabled = (p as u64) << 32;
                0
            }
            4 => {
                self.enabled |= p as u64;
                0
            }
            0xc => self.reported.unwrap_or(self.enabled) as u32,
            0xd => (self.reported.unwrap_or(self.enabled) >> 32) as u32,
            // PPCLK_GFXCLK, or PPCLK_UCLK in the high half.
            0x1d if p >> 16 == 2 => 96,
            0x1e if p >> 16 == 2 => 1258,
            0x1d => 500,
            0x1e => 3100,
            0x36 | 6 | 0x19 | 0x1a | 0x2a..=0x2d | 0x32 | 0x15..=0x17 => 0,
            8 => {
                self.enabled |= p as u64;
                0
            }
            9 => {
                self.enabled |= (p as u64) << 32;
                0
            }
            0x33 => {
                self.violation |= p != 0; // AC power source
                304
            }
            _ => panic!("unknown SMU14 message"),
        };
        if let Some((message, cap)) = self.revoke {
            if message == value {
                cap.revoke();
            }
        }
    }
    fn check_policy(&mut self) -> Result<(), Error> {
        if self.policy == 0 {
            Ok(())
        } else {
            Err(Error::PowerPolicy(self.policy))
        }
    }
    fn write_buffer(&mut self, offset: usize, b: &[u8]) {
        self.memory[offset..offset + b.len()].copy_from_slice(b);
        self.dirty = true;
    }
    fn read_buffer(&mut self, offset: usize, b: &mut [u8]) {
        b.copy_from_slice(&self.memory[offset..offset + b.len()]);
    }
    fn flush(&mut self) -> Result<(), Error> {
        self.dirty = false;
        Ok(())
    }
}
fn fixture() -> (Pool, Engine<Fake>) {
    let mapping = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90003000),
        virt: 0x3000,
        len: 1 << 20,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: Fake implements every VRAM access; bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(mapping, 0x8_00003000) }.unwrap();
    let memory = pool.reserve(TRANSFER_BYTES as u64).unwrap();
    (
        pool,
        Engine {
            io: Fake {
                regs: [0; 0x9b],
                memory: vec![0; TRANSFER_BYTES],
                board: board(),
                commands: Vec::new(),
                stall: None,
                reject: None,
                interface: DRIVER_INTERFACE,
                enabled: 0,
                reported: None,
                revoke: None,
                dirty: false,
                violation: false,
                address: 0,
                policy: 0,
                uploaded: Vec::new(),
                metrics: vec![0; METRICS_BYTES],
            },
            authority: Cap::bootstrap(),
            memory,
            state: State::Prepared,
            versions: None,
            board: vec![0; COMBO_BYTES],
            features: 0,
            power: None,
            limits: None,
            protection: 0,
            gfx_level: GfxLevel::Auto,
            baco: BacoState::Exit,
            boot_enabled: 0,
        },
    )
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn smu14_board_roundtrip_and_protection_policy() -> TestResult {
    let (pool, mut e) = fixture();
    if run(e.verify())
        != Ok(Versions {
            firmware: 0x684c00,
            interface: 0x2e,
        })
        || run(e.read_board()).is_err()
        || run(e.upload_board()).is_err()
    {
        return TestResult::Fail("SMU14 handshake/board transfer failed");
    }
    let p = run(e.configure_power()).unwrap();
    if e.io.violation
        || e.io.uploaded != e.io.board[DRIVER_BYTES..]
        || e.state != State::PowerReady
        || p.allowed != ALLOWED
        || p.enabled != ALLOWED
        || p.gfx_min_mhz != 500
        || p.gfx_max_mhz != 3100
        || e.io.commands
            != [
                (3, 0),
                (2, 0),
                (0xe, 8),
                (0xf, 0x3000),
                (0x12, 1),
                (0xe, 8),
                (0xf, 0x3000),
                (0x13, 0),
                (0x36, 0),
                (5, (ALLOWED >> 32) as u32),
                (4, ALLOWED as u32),
                (6, 0),
                (0xc, 0),
                (0xd, 0),
                (0x1d, 0),
                (0x1e, 0),
            ]
        || run(e.configure_power()) != Err(Error::Busy)
    {
        return TestResult::Fail("SMU14 table address/order or boot policy");
    }
    drop(e);
    if pool.available() != 1 << 20 {
        return TestResult::Fail("completed SMU transfer memory leaked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu14",
    smu14_board_roundtrip_and_protection_policy
);
fn smu14_rejects_malformed_board_and_tolerates_foreign_interface() -> TestResult {
    let valid = board();
    for end in 0..valid.len() {
        if board_features(&valid[..end]).is_ok() {
            return TestResult::Fail("truncated SMU14 combo accepted");
        }
    }
    for f in [0, 2, 6, 8, 10, 12, 14, 16, 18, 20, DRIVER_BYTES] {
        let mut b = valid.clone();
        b[f] ^= 1;
        if board_features(&b).is_ok() {
            return TestResult::Fail("invalid combo format or relative subtable offset");
        }
    }
    // smu_cmn_check_fw_version logs an interface mismatch and continues;
    // only an absent device (all-ones) stops the handshake.
    let (_, mut e) = fixture();
    e.io.interface = 0x2f;
    if run(e.verify())
        != Ok(Versions {
            firmware: 0x684c00,
            interface: 0x2f,
        })
        || e.io.commands != [(3, 0), (2, 0)]
        || run(e.read_board()).is_err()
    {
        return TestResult::Fail("PMFW interface mismatch was fatal");
    }
    let (_, mut e) = fixture();
    e.io.interface = u32::MAX;
    if run(e.verify()) != Err(Error::DeviceGone)
        || e.io.commands != [(3, 0)]
        || run(e.read_board()) != Err(Error::Busy)
    {
        return TestResult::Fail("all-ones interface accepted or used after failure");
    }
    let (_, mut e) = fixture();
    run(e.verify()).unwrap();
    e.io.policy = 2;
    if run(e.read_board()) != Err(Error::PowerPolicy(2)) || e.io.commands.len() != 2 {
        return TestResult::Fail("SCPM policy ignored before board transfer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu14",
    smu14_rejects_malformed_board_and_tolerates_foreign_interface
);
fn smu14_cancelled_dma_and_revocation_do_not_recycle_or_retry() -> TestResult {
    for message in [0xe, 0xf, 0x12, 0x13] {
        let (pool, mut e) = fixture();
        run(e.verify()).unwrap();
        if message == 0x13 {
            run(e.read_board()).unwrap();
        }
        e.io.stall = Some(message);
        {
            let f = async {
                if message == 0x13 {
                    e.upload_board().await
                } else {
                    e.read_board().await
                }
            };
            let mut f = core::pin::pin!(f);
            for _ in 0..8 {
                if f.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("stalled SMU DMA completed");
                }
            }
        }
        if run(e.read_board()) != Err(Error::Busy) || run(e.upload_board()) != Err(Error::Busy) {
            return TestResult::Fail("cancelled SMU transaction replayed");
        }
        drop(e);
        if pool.available() != (1 << 20) - TRANSFER_BYTES as u64 {
            return TestResult::Fail("SMU-owned DMA buffer recycled");
        }
    }
    let (pool, mut e) = fixture();
    run(e.verify()).unwrap();
    let authority = e.authority;
    {
        let mut f = core::pin::pin!(e.read_board());
        if f.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("board staging failed to yield");
        }
        authority.revoke();
        if run(f) != Err(Error::Revoked) {
            return TestResult::Fail("revoked SMU staging continued");
        }
    }
    if e.io.commands.len() != 2 {
        return TestResult::Fail("revoked SMU staging published address");
    }
    drop(e);
    if pool.available() != 1 << 20 {
        return TestResult::Fail("unpublished SMU staging leaked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu14",
    smu14_cancelled_dma_and_revocation_do_not_recycle_or_retry
);

fn smu14_constructor_resolves_bank_one_and_validates_pool() -> TestResult {
    let (pool, e) = fixture();
    drop(e);
    let mut g = crate::amdgpu_navi48_firmware::tests::gpu();
    let mut regs = vec![0; 0x80000 / 4];
    g.regs.virt = regs.as_mut_ptr() as u64;
    g.regs.len = 0x80000;
    g.fb_bar = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90000000),
        virt: 0,
        len: 256 << 20,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    g.vram.visible_size = 256 << 20;
    g.vram.size = 16 << 30;
    g.ip_blocks[0].num_bases = 2;
    g.ip_blocks[1].base_addrs[0] = 0x20000; // Unused bank is outside BAR5.
    g.ip_blocks[1].base_addrs[1] = 0x11000;
    let ip = |id, v: (u8, u8, u8), bank, base| {
        let mut bases = [0; crate::amdgpu_discovery::MAX_BASE_ADDRS];
        bases[bank] = base;
        crate::amdgpu_discovery::IpBlock {
            hw_id: id,
            instance: 0,
            major: v.0,
            minor: v.1,
            revision: v.2,
            sub_revision: 0,
            variant: 0,
            base_addrs: bases,
            num_bases: 3,
        }
    };
    g.ip_blocks.extend([
        ip(ip::HW_ID_MP0, (14, 0, 3), 0, 0x10000),
        ip(ip::HW_ID_NBIF, (7, 7, 0), 2, 0xd20),
        ip(ip::HW_ID_HDP, (6, 1, 0), 0, 0),
    ]);
    regs[0x1614] = 0x800;
    regs[0x1615] = 0xbff;
    regs[0x15a7] = 0x100;
    let before = regs.clone();
    // SAFETY: constructor reads only modeled GMC registers; no run calls occur.
    let smu = unsafe { Smu::after_upload(&g, Cap::bootstrap(), &pool) }.unwrap();
    if smu.engine.io.base != 0x44000 || smu.state() != State::Prepared || regs != before {
        return TestResult::Fail("SMU14 used MP1 bank zero or wrote hardware at construction");
    }
    drop(smu);
    // smu_v14_0_2_ppt serves MP1 14.0.2 (Navi44) and 14.0.3 (Navi48) alike.
    for profile in crate::amdgpu_rdna4::tests::Profile::ALL {
        profile.apply(&mut g);
        // SAFETY: as above; construction only.
        let smu = unsafe { Smu::after_upload(&g, Cap::bootstrap(), &pool) };
        if !smu.is_ok_and(|s| s.engine.io.base == 0x44000 && s.state() == State::Prepared) {
            return TestResult::Fail("SMU14 constructor refused an RDNA4 profile");
        }
    }
    crate::amdgpu_rdna4::tests::Profile::Navi48.apply(&mut g);
    let cap = Cap::bootstrap();
    cap.revoke();
    if !matches!(
        // SAFETY: revoked constructor cannot access MMIO.
        unsafe { Smu::after_upload(&g, cap, &pool) },
        Err(Error::Revoked)
    ) {
        return TestResult::Fail("SMU14 constructor ignored current PCI authority");
    }
    g.fb_bar.phys = narf_memory::PhysAddr::new(0xa0000000);
    if !matches!(
        // SAFETY: wrong mapping must be rejected before any buffer use.
        unsafe { Smu::after_upload(&g, Cap::bootstrap(), &pool) },
        Err(Error::Invalid)
    ) {
        return TestResult::Fail("SMU14 accepted another GPU's pool");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu14",
    smu14_constructor_resolves_bank_one_and_validates_pool
);

fn smu14_timeout_and_rejection_prevent_later_power_commands() -> TestResult {
    let (pool, mut e) = fixture();
    run(e.verify()).unwrap();
    e.io.stall = Some(0x12);
    if run(e.read_board()) != Err(Error::Timeout)
        || e.state != State::Failed
        || run(e.upload_board()) != Err(Error::Busy)
    {
        return TestResult::Fail("SMU DMA timeout published board readiness");
    }
    drop(e);
    if pool.available() != (1 << 20) - TRANSFER_BYTES as u64 {
        return TestResult::Fail("timed out SMU DMA buffer recycled");
    }
    let (_, mut e) = fixture();
    run(e.verify()).unwrap();
    run(e.read_board()).unwrap();
    run(e.upload_board()).unwrap();
    e.io.reject = Some(0x36);
    if run(e.configure_power()) != Err(Error::Rejected(0xfd))
        || e.power.is_some()
        || e.io.commands.iter().any(|(m, _)| matches!(m, 4..=6))
        || run(e.configure_power()) != Err(Error::Busy)
    {
        return TestResult::Fail("failed BTC enabled features or allowed retry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu14",
    smu14_timeout_and_rejection_prevent_later_power_commands
);

fn display_engine() -> (Pool, Engine<Fake>) {
    let (pool, mut e) = fixture();
    e.state = State::PowerReady;
    e.features = ALLOWED | DISPLAY;
    e.power = Some(PowerStatus {
        allowed: ALLOWED,
        enabled: ALLOWED,
        gfx_min_mhz: 500,
        gfx_max_mhz: 3100,
        uclk_mhz: None,
    });
    (pool, e)
}
fn smu14_display_policy_enables_only_required_clocks_and_preserves_protection() -> TestResult {
    let (_, mut e) = display_engine();
    let old = e.power.unwrap();
    let power = run(e.enable_display_power()).unwrap();
    assert_eq!(power.allowed, old.allowed | 0xb8);
    assert_eq!(power.enabled, power.allowed);
    assert_eq!(power.enabled & 0xb8, 0xb8);
    assert_eq!(
        power.enabled & ((1 << 6) | (0xff << 8) | (1 << 18) | (1 << 40)),
        0
    );
    assert_eq!((power.gfx_min_mhz, power.gfx_max_mhz), (500, 3100));
    // UCLK DPM now runs, so its range replaces the boot clock.
    assert_eq!(power.uclk_mhz, Some((96, 1258)));
    assert_eq!(
        e.io.commands,
        [
            (5, (power.allowed >> 32) as u32),
            (4, power.allowed as u32),
            (6, 0),
            (12, 0),
            (13, 0),
            (0x1d, 2 << 16),
            (0x1e, 2 << 16),
        ]
    );
    assert_eq!(e.state, State::DisplayPowerReady);
    assert_eq!(e.power, Some(power));
    assert_eq!(run(e.enable_display_power()), Ok(power));
    assert_eq!(e.io.commands.len(), 7);
    e.authority.revoke();
    assert_eq!(run(e.enable_display_power()), Err(Error::Revoked));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_display_policy_enables_only_required_clocks_and_preserves_protection
);

/// DEV_INFO clocks follow amdgpu_dpm_get_sclk/mclk: the GFXCLK DPM range,
/// and the UCLK one once it runs, the boot UCLK before.
fn smu14_dev_info_clocks_follow_dpm_state() -> TestResult {
    let mut power = PowerStatus {
        allowed: ALLOWED,
        enabled: ALLOWED,
        gfx_min_mhz: 500,
        gfx_max_mhz: 3100,
        uclk_mhz: None,
    };
    if dev_info_clocks(&power, Some(1258)) != [500_000, 3_100_000, 1_258_000, 1_258_000]
        || dev_info_clocks(&power, None) != [500_000, 3_100_000, 0, 0]
    {
        return TestResult::Fail("boot UCLK while UCLK DPM is off");
    }
    power.uclk_mhz = Some((96, 1258));
    if dev_info_clocks(&power, Some(1000)) != [500_000, 3_100_000, 96_000, 1_258_000] {
        return TestResult::Fail("UCLK DPM range");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_dev_info_clocks_follow_dpm_state
);

fn smu14_display_power_rejects_missing_or_unprotected_features() -> TestResult {
    for case in 0..5 {
        let (_, mut e) = display_engine();
        let old = e.power;
        match case {
            0 => e.features &= !(1 << 7),
            1 => e.io.policy = 1,
            2 => e.io.reported = Some((ALLOWED | DISPLAY) & !(1 << 36)),
            3 => e.io.reported = Some(ALLOWED),
            _ => e.io.reported = Some(ALLOWED | DISPLAY | (1 << 18)),
        }
        assert!(run(e.enable_display_power()).is_err());
        assert_eq!(e.power, old);
        if case < 2 {
            assert!(e.io.commands.is_empty());
        }
        if case != 0 {
            assert_eq!(run(e.enable_display_power()), Err(Error::Busy));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_display_power_rejects_missing_or_unprotected_features
);

fn smu14_display_power_partial_failures_cancellation_and_revocation_are_terminal() -> TestResult {
    for (i, message) in [5, 4, 6, 12, 13].into_iter().enumerate() {
        for case in 0..3 {
            let (_, mut e) = display_engine();
            let old = e.power;
            match case {
                0 => e.io.reject = Some(message),
                1 => e.io.stall = Some(message),
                _ => e.io.revoke = Some((message, e.authority)),
            }
            if case == 1 {
                let mut f = core::pin::pin!(e.enable_display_power());
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            } else {
                assert_eq!(
                    run(e.enable_display_power()),
                    Err(if case == 0 {
                        Error::Rejected(0xfd)
                    } else {
                        Error::Revoked
                    })
                );
            }
            assert_eq!(
                e.state,
                if case == 1 {
                    State::EnablingDisplayPower
                } else {
                    State::Failed
                }
            );
            assert_eq!(e.power, old);
            assert_eq!(e.io.commands.len(), i + 1);
            assert_eq!(run(e.enable_display_power()), Err(Error::Busy));
            assert_eq!(e.io.commands.len(), i + 1);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_display_power_partial_failures_cancellation_and_revocation_are_terminal
);

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
/// SmuMetrics_t sample at the offsets checked by tests/smu14_metrics.c.
fn metrics(gfx_activity: u16, uclk_activity: u16) -> Vec<u8> {
    let mut m = vec![0; METRICS_BYTES];
    for (i, mhz) in [2400u32, 1200, 1258, 2000, 0, 0, 0, 0, 0, 1500, 0]
        .into_iter()
        .enumerate()
    {
        put(&mut m, i * 4, mhz); // CurrClock[PPCLK_e]
    }
    for (at, v) in [
        (46, 2450u16), // gfx pre-DS
        (48, 120),     // gfx post-DS
        (50, 1900),    // fclk pre-DS
        (52, 400),     // fclk post-DS
        (54, 1250),    // mem pre-DS
        (56, 96),      // mem post-DS
        (108, 1050),   // AvgVoltage[VDD_GFX]
        (124, gfx_activity),
        (126, uclk_activity),
        (136, 287), // AverageSocketPower
        (138, 301), // AverageTotalBoardPower
        (140, 61),  // edge
        (142, 77),  // hotspot
        (148, 70),  // mem
        (150, 58),  // VR GFX
        (152, 55),  // VR SOC
        (170, 1620),
    ] {
        put16(&mut m, at, v);
    }
    put(&mut m, 104, 0x1234);
    m[166] = 4; // PCIe gen
    m[167] = 16;
    m[168] = 50; // fan percent
    m[172 + 1] = 10; // hotspot throttling
    m[172 + 14] = 3; // PPT0 throttling
    m
}
fn limits_board() -> Vec<u8> {
    let mut b = board();
    put16(&mut b, 43, 118); // software_shutdown_temp
    put16(&mut b, 4924, 304); // SocketPowerLimitAc[PPT0]
    put16(&mut b, 3976, 340); // MsgLimits.Power[PPT0][AC]
    put16(&mut b, 4124, (-10i16) as u16); // OverDriveLimitsBasicMin.Ppt
    put16(&mut b, 4188, 1 << 3); // OverDriveLimitsBasicMax: PPT overdrive
    for (i, c) in [(0, 100u16), (1, 110), (4, 108)] {
        put16(&mut b, 4944 + 2 * i, c); // TemperatureLimit
    }
    put16(&mut b, 5046, 3300); // FanMaximumRpm
    put16(&mut b, 5126, (-10i16) as u16); // FanAbnormalTempLimitOffset
    b
}
fn powered() -> (Pool, Engine<Fake>) {
    let (pool, mut e) = fixture();
    e.io.board = limits_board();
    run(e.verify()).unwrap();
    run(e.read_board()).unwrap();
    run(e.upload_board()).unwrap();
    run(e.configure_power()).unwrap();
    e.io.commands.clear();
    (pool, e)
}
/// After the display power transition, with boot's protection recorded.
fn displayed() -> (Pool, Engine<Fake>) {
    let (pool, mut e) = display_engine();
    e.protection = ALLOWED & PROTECTION;
    run(e.enable_display_power()).unwrap();
    e.features |= DEEP_SLEEP_GRAPHICS | DEEP_SLEEP_MEMORY_FABRIC;
    e.io.commands.clear();
    (pool, e)
}
fn smu14_telemetry_decodes_metrics_limits_and_protection() -> TestResult {
    let (pool, mut e) = powered();
    let limits = e.limits.unwrap();
    assert_eq!(
        limits,
        Limits {
            edge_crit_milli: 100_000,
            edge_emergency_milli: 105_000,
            hotspot_crit_milli: 110_000,
            hotspot_emergency_milli: 115_000,
            mem_crit_milli: 108_000,
            mem_emergency_milli: 113_000,
            software_shutdown_c: 118,
            software_shutdown_offset_c: -10,
            fan_max_rpm: Some(3300),
            ppt_default_w: 304,
            // min(304, 340) * (100 - 10) / 100 and max(304, 340).
            ppt_min_w: 273,
            ppt_max_w: 340,
        }
    );
    e.io.metrics = metrics(40, 30);
    let t = run(e.read_telemetry()).unwrap();
    assert_eq!(
        e.io.commands,
        [
            (0xe, 8),
            (0xf, 0x3000),
            (0x12, 5),
            (0xc, 0),
            (0xd, 0),
            (0x33, 0)
        ]
    );
    assert!(!e.io.violation);
    assert_eq!(e.state, State::PowerReady);
    let m = t.metrics;
    assert_eq!(
        (m.counter, t.ppt_limit_w, t.enabled),
        (0x1234, 304, ALLOWED)
    );
    assert_eq!(
        (m.edge_milli, m.hotspot_milli, m.mem_milli),
        (61_000, 77_000, 70_000)
    );
    assert_eq!((m.vr_gfx_milli, m.vr_soc_milli), (58_000, 55_000));
    assert_eq!((m.fan_rpm, m.fan_pwm, m.vddgfx_mv), (1620, 127, 1050));
    assert_eq!((m.socket_power_w, m.board_power_w), (287, 301));
    // Busy: Linux reports pre-deep-sleep averages.
    assert_eq!((m.gfx_mhz, m.fclk_mhz, m.mem_mhz), (2450, 1900, 1250));
    assert_eq!(
        (m.uclk_mhz, m.fclk_current_mhz, m.socclk_mhz, m.dcfclk_mhz),
        (1258, 2000, 1200, 1500)
    );
    assert_eq!(m.throttlers, (1 << 1) | (1 << 14));
    assert_eq!((m.pcie_rate, m.pcie_width), (4, 16));
    // Idle (at the busy threshold) selects post-deep-sleep averages, and a
    // negative-overflow UCLK activity reads as zero (smu_safe_u16_nn).
    e.io.metrics = metrics(5, 0xfff0);
    e.io.metrics[168] = 100;
    let m = run(e.read_telemetry()).unwrap().metrics;
    assert_eq!((m.gfx_mhz, m.fclk_mhz, m.mem_mhz), (120, 400, 96));
    assert_eq!((m.mem_activity, m.fan_pwm), (0, 255));
    assert!(!limits.software_shutdown(&m));
    let mut hot = m;
    hot.hotspot_milli = 118_000;
    assert!(limits.software_shutdown(&hot));
    // Protection is the running autonomous set recorded at boot.
    assert!(e.protected(ALLOWED));
    assert!(!e.protected(ALLOWED & !(1 << 28)));
    assert!(!e.protected(ALLOWED & !(1 << 29)));
    drop(e);
    if pool.available() != 1 << 20 {
        return TestResult::Fail("completed metrics transfer leaked its buffer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_telemetry_decodes_metrics_limits_and_protection
);

fn smu14_missing_board_limits_and_fanless_boards() -> TestResult {
    let mut b = limits_board();
    assert!(Limits::from_board(&b, 0).unwrap().fan_max_rpm.is_none());
    put16(&mut b, 4944 + 8, 0); // no memory temperature limit
    assert!(Limits::from_board(&b, u64::MAX).is_none());
    assert!(Limits::from_board(&b[..4000], u64::MAX).is_none());
    // Absent limits never block the board stage.
    let (_, mut e) = fixture();
    run(e.verify()).unwrap();
    run(e.read_board()).unwrap();
    assert_eq!((e.limits, e.state), (None, State::BoardReady));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_missing_board_limits_and_fanless_boards
);

fn smu14_telemetry_rejection_is_recoverable_but_timeout_is_terminal() -> TestResult {
    let (_, mut e) = fixture();
    assert_eq!(run(e.read_telemetry()), Err(Error::Busy));
    assert!(e.io.commands.is_empty());
    for message in [0x12, 0xc, 0x33] {
        let (_, mut e) = powered();
        e.io.reject = Some(message);
        assert_eq!(run(e.read_telemetry()), Err(Error::Rejected(0xfd)));
        assert_eq!(e.state, State::PowerReady);
        e.io.reject = None;
        assert!(run(e.read_telemetry()).is_ok());
    }
    let (pool, mut e) = powered();
    e.io.stall = Some(0x12);
    assert_eq!(run(e.read_telemetry()), Err(Error::Timeout));
    assert_eq!(e.state, State::Failed);
    let n = e.io.commands.len();
    assert_eq!(run(e.read_telemetry()), Err(Error::Busy));
    assert_eq!(run(e.set_gfx_level(GfxLevel::High)), Err(Error::Busy));
    assert_eq!(e.io.commands.len(), n);
    drop(e);
    if pool.available() != (1 << 20) - TRANSFER_BYTES as u64 {
        return TestResult::Fail("timed out metrics DMA buffer recycled");
    }
    let (_, mut e) = powered();
    e.io.stall = Some(0xd);
    {
        let mut f = core::pin::pin!(e.read_telemetry());
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.state, State::Runtime);
    assert_eq!(run(e.read_telemetry()), Err(Error::Busy));
    let (_, mut e) = powered();
    e.io.revoke = Some((0x33, e.authority));
    assert_eq!(run(e.read_telemetry()), Err(Error::Revoked));
    assert_eq!(e.state, State::Failed);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_telemetry_rejection_is_recoverable_but_timeout_is_terminal
);

fn smu14_gfx_levels_use_soft_limits_only() -> TestResult {
    let (_, mut e) = powered();
    for (level, max, min) in [
        (GfxLevel::Low, 501, 500),
        (GfxLevel::High, 3101, 3100),
        (GfxLevel::Auto, 0xffff, 0),
    ] {
        e.io.commands.clear();
        run(e.set_gfx_level(level)).unwrap();
        assert_eq!(e.io.commands, [(0x1a, max), (0x19, min)]);
        assert_eq!((e.gfx_level, e.state), (level, State::PowerReady));
    }
    e.io.reject = Some(0x19);
    assert_eq!(
        run(e.set_gfx_level(GfxLevel::High)),
        Err(Error::Rejected(0xfd))
    );
    assert_eq!((e.gfx_level, e.state), (GfxLevel::Auto, State::PowerReady));
    let (_, mut e) = displayed();
    run(e.set_gfx_level(GfxLevel::Low)).unwrap();
    assert_eq!(e.state, State::DisplayPowerReady);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_gfx_levels_use_soft_limits_only
);

fn smu14_ppt_limit_is_one_set_ppt_limit_with_ppt_running() -> TestResult {
    let (_, mut e) = powered();
    assert_ne!(e.power.unwrap().enabled & 1 << 23, 0);
    e.io.commands.clear();
    run(e.set_ppt_limit(300)).unwrap();
    assert_eq!(e.io.commands, [(0x32, 300)]);
    assert_eq!(e.state, State::PowerReady);
    e.io.commands.clear();
    for bad in [0, 0x1_0000] {
        assert_eq!(run(e.set_ppt_limit(bad)), Err(Error::Invalid));
    }
    assert!(e.io.commands.is_empty());
    e.io.reject = Some(0x32);
    assert_eq!(run(e.set_ppt_limit(290)), Err(Error::Rejected(0xfd)));
    assert_eq!(e.state, State::PowerReady);
    // Without the PPT feature (THROTTLERS) PMFW cannot take a new limit.
    let (_, mut e) = powered();
    if let Some(p) = e.power.as_mut() {
        p.enabled &= !(1 << 23);
    }
    e.io.commands.clear();
    assert_eq!(run(e.set_ppt_limit(300)), Err(Error::Unsupported));
    assert!(e.io.commands.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_ppt_limit_is_one_set_ppt_limit_with_ppt_running
);

fn smu14_vcn_power_requires_current_static_policy_and_protection() -> TestResult {
    let (_, mut e) = powered();
    for (enabled, command) in [(true, 0x2a), (false, 0x2b)] {
        e.io.commands.clear();
        assert_eq!(run(e.set_vcn_power(enabled)).unwrap().enabled, ALLOWED);
        assert_eq!(e.io.commands, [(0xc, 0), (0xd, 0), (command, 0)]);
        assert_eq!(e.state, State::PowerReady);
    }
    for running in [ALLOWED | 1 << 20, ALLOWED | 1 << 44, ALLOWED & !(1 << 28)] {
        let (_, mut e) = powered();
        e.io.reported = Some(running);
        assert_eq!(run(e.set_vcn_power(true)), Err(Error::Features(running)));
        assert_eq!(e.io.commands, [(0xc, 0), (0xd, 0)]);
        assert_eq!(e.state, State::Failed);
    }
    let (_, mut e) = powered();
    e.io.reject = Some(0x2a);
    assert_eq!(run(e.set_vcn_power(true)), Err(Error::Rejected(0xfd)));
    assert_eq!(e.state, State::PowerReady);
    let (_, mut e) = powered();
    e.io.stall = Some(0x2a);
    {
        let mut future = core::pin::pin!(e.set_vcn_power(true));
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.state, State::Runtime);
    assert_eq!(run(e.set_vcn_power(false)), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_vcn_power_requires_current_static_policy_and_protection
);

fn smu14_jpeg_power_requires_current_static_policy_and_protection() -> TestResult {
    let (_, mut e) = powered();
    for (enabled, command) in [(true, 0x2c), (false, 0x2d)] {
        e.io.commands.clear();
        assert_eq!(run(e.set_jpeg_power(enabled)).unwrap().enabled, ALLOWED);
        assert_eq!(e.io.commands, [(0xc, 0), (0xd, 0), (command, 0)]);
        assert_eq!(e.state, State::PowerReady);
    }
    for running in [ALLOWED | 1 << 20, ALLOWED | 1 << 44, ALLOWED & !(1 << 28)] {
        let (_, mut e) = powered();
        e.io.reported = Some(running);
        assert_eq!(run(e.set_jpeg_power(true)), Err(Error::Features(running)));
        assert_eq!(e.io.commands, [(0xc, 0), (0xd, 0)]);
        assert_eq!(e.state, State::Failed);
    }
    let (_, mut e) = powered();
    e.io.reject = Some(0x2c);
    assert_eq!(run(e.set_jpeg_power(true)), Err(Error::Rejected(0xfd)));
    assert_eq!(e.state, State::PowerReady);
    let (_, mut e) = powered();
    e.io.stall = Some(0x2c);
    {
        let mut future = core::pin::pin!(e.set_jpeg_power(true));
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.state, State::Runtime);
    assert_eq!(run(e.set_jpeg_power(false)), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_jpeg_power_requires_current_static_policy_and_protection
);

fn smu14_deep_sleep_is_gated_and_keeps_protection() -> TestResult {
    let (_, mut e) = powered();
    assert_eq!(
        run(e.allow_deep_sleep(DeepSleep::MemoryFabric)),
        Err(Error::Busy)
    );
    assert!(e.io.commands.is_empty());
    let p = run(e.allow_deep_sleep(DeepSleep::Graphics)).unwrap();
    let allowed = ALLOWED | DEEP_SLEEP_GRAPHICS;
    assert_eq!(
        e.io.commands,
        [
            (5, (allowed >> 32) as u32),
            (4, allowed as u32),
            (8, DEEP_SLEEP_GRAPHICS as u32),
            (9, 0),
            (0xc, 0),
            (0xd, 0)
        ]
    );
    assert_eq!((p.allowed, p.enabled), (allowed, allowed));
    assert_eq!((e.state, e.power), (State::PowerReady, Some(p)));
    // Already running: no commands.
    e.io.commands.clear();
    assert_eq!(run(e.allow_deep_sleep(DeepSleep::Graphics)), Ok(p));
    assert!(e.io.commands.is_empty());
    // Memory/fabric deep sleep only after the display power transition.
    let (_, mut e) = displayed();
    let p = run(e.allow_deep_sleep(DeepSleep::MemoryFabric)).unwrap();
    assert_eq!(
        p.enabled & DEEP_SLEEP_MEMORY_FABRIC,
        DEEP_SLEEP_MEMORY_FABRIC
    );
    assert_eq!(e.state, State::DisplayPowerReady);
    // Unsupported board bits send nothing.
    let (_, mut e) = powered();
    e.features &= !DEEP_SLEEP_GRAPHICS;
    assert!(run(e.allow_deep_sleep(DeepSleep::Graphics)).is_ok());
    assert!(e.io.commands.is_empty());
    // Losing any protection or display DPM bit is terminal.
    for lost in [1u64 << 28, 1 << 29, 1 << 3] {
        let (_, mut e) = displayed();
        e.io.reported = Some((ALLOWED | DISPLAY | DEEP_SLEEP_GRAPHICS) & !lost);
        assert!(matches!(
            run(e.allow_deep_sleep(DeepSleep::Graphics)),
            Err(Error::Features(_))
        ));
        assert_eq!(e.state, State::Failed);
        assert_eq!(run(e.read_telemetry()), Err(Error::Busy));
    }
    // A rejected feature command may have partially applied: terminal too.
    let (_, mut e) = powered();
    e.io.reject = Some(9);
    assert_eq!(
        run(e.allow_deep_sleep(DeepSleep::Graphics)),
        Err(Error::Rejected(0xfd))
    );
    assert_eq!(e.state, State::Failed);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_deep_sleep_is_gated_and_keeps_protection
);

/// A configured owner whose board table carries `caps` as platform_caps.
fn baco_powered(caps: u32) -> (Pool, Engine<Fake>) {
    let (pool, mut e) = fixture();
    e.io.board = limits_board();
    put(&mut e.io.board, PLATFORM_CAPS, caps);
    run(e.verify()).unwrap();
    run(e.read_board()).unwrap();
    run(e.upload_board()).unwrap();
    run(e.configure_power()).unwrap();
    e.io.commands.clear();
    (pool, e)
}
/// smu_v14_0_get_bamaco_support, smu_v14_0_baco_set_state and
/// smu_v14_0_2_baco_enter/exit: EnterBaco(BACO_SEQ_BAMACO or BACO) and
/// ExitBaco without audio, ArmD3(BAMACO by MACO circuitry) / ArmD3(ULPS)
/// with it; repeated requests for the current state send nothing.
fn smu14_baco_messages_follow_smu_v14_0_2() -> TestResult {
    for (caps, want) in [
        (0, 0),
        (PLATFORM_CAP_MACO, 0),
        (PLATFORM_CAP_BACO, BACO_SUPPORT),
        (
            PLATFORM_CAP_BACO | PLATFORM_CAP_MACO,
            BACO_SUPPORT | MACO_SUPPORT,
        ),
    ] {
        let (_, e) = baco_powered(caps);
        if e.bamaco_support() != want {
            return TestResult::Fail("BACO/MACO support from platform_caps");
        }
    }
    // A board-supported BACO feature PMFW stopped running: no BACO.
    let (_, mut e) = baco_powered(PLATFORM_CAP_BACO);
    if e.boot_enabled & FEATURE_BACO == 0 || ALLOWED & FEATURE_BACO == 0 {
        return TestResult::Fail("FEATURE_BACO not allowed at boot");
    }
    e.power.as_mut().unwrap().enabled &= !FEATURE_BACO;
    if e.bamaco_support() != 0 {
        return TestResult::Fail("BACO claimed with the feature disabled");
    }
    for (caps, bamaco, armd3, enter, exit, clear) in [
        // EnterBaco carries the runtime mode's sequence.
        (
            PLATFORM_CAP_BACO | PLATFORM_CAP_MACO,
            true,
            false,
            (0x15, 2),
            (0x16, 0),
            true,
        ),
        (
            PLATFORM_CAP_BACO | PLATFORM_CAP_MACO,
            false,
            false,
            (0x15, 0),
            (0x16, 0),
            true,
        ),
        // ArmD3 follows maco_support whatever the mode.
        (
            PLATFORM_CAP_BACO | PLATFORM_CAP_MACO,
            false,
            true,
            (0x17, 2),
            (0x17, 3),
            false,
        ),
        (PLATFORM_CAP_BACO, true, true, (0x17, 0), (0x17, 3), false),
    ] {
        let (_, mut e) = baco_powered(caps);
        if run(e.baco_enter(bamaco, armd3)).is_err()
            || e.state != State::Baco
            || e.baco != BacoState::Enter
            || e.bamaco_support() & BACO_SUPPORT == 0
        {
            return TestResult::Fail("BACO entry");
        }
        // Telemetry/DPM are refused while the chip is off.
        if run(e.set_gfx_level(GfxLevel::High)) != Err(Error::Busy) {
            return TestResult::Fail("runtime command accepted in BACO");
        }
        if run(e.baco_exit(armd3)) != Ok(clear)
            || e.state != State::BacoExited
            || e.baco != BacoState::Exit
            || e.io.commands != [enter, exit]
        {
            return TestResult::Fail("BACO message sequence");
        }
        // The exited owner is retired; a repeated exit sends nothing.
        if !armd3 && (run(e.baco_exit(false)) != Ok(true) || e.io.commands.len() != 2) {
            return TestResult::Fail("repeated ExitBaco sent a message");
        }
        if run(e.baco_enter(bamaco, armd3)) != Err(Error::Busy) {
            return TestResult::Fail("retired owner re-entered BACO");
        }
    }
    // Entry needs configured power.
    let (_, mut e) = fixture();
    run(e.verify()).unwrap();
    if run(e.baco_enter(false, false)) != Err(Error::Busy) || e.io.commands.len() != 2 {
        return TestResult::Fail("BACO entry before power configuration");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_baco_messages_follow_smu_v14_0_2
);

/// A clean PMFW rejection of EnterBaco/ArmD3 leaves the owner powered and
/// reusable; a stalled exit (cancelled) is terminal and never replayed.
fn smu14_baco_rejection_and_cancellation() -> TestResult {
    for (armd3, message) in [(false, 0x15), (true, 0x17)] {
        let (_, mut e) = baco_powered(PLATFORM_CAP_BACO);
        e.io.reject = Some(message);
        if run(e.baco_enter(false, armd3)) != Err(Error::Rejected(0xfd))
            || e.state != State::PowerReady
            || e.baco != BacoState::Exit
        {
            return TestResult::Fail("rejected BACO entry must leave the owner powered");
        }
        e.io.reject = None;
        if run(e.baco_enter(false, armd3)).is_err() || e.state != State::Baco {
            return TestResult::Fail("BACO entry after a rejection");
        }
        if armd3 {
            // ArmD3(ULPS) follows a 10 ms sleep; the stall case is ExitBaco.
            continue;
        }
        e.io.stall = Some(0x16);
        {
            let f = e.baco_exit(armd3);
            let mut f = core::pin::pin!(f);
            for _ in 0..8 {
                if f.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("stalled BACO exit completed");
                }
            }
        }
        if e.state != State::BacoTransition || run(e.baco_exit(armd3)) != Err(Error::Busy) {
            return TestResult::Fail("cancelled BACO exit replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/smu-navi48",
    smu14_baco_rejection_and_cancellation
);
