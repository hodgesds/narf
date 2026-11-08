use super::*;
use crate::{
    dp_link_training::{DpcdCaps, LinkRate, TrainedLink, VSwingPe},
    intel_gpu_ddi::Ddi,
    intel_gpu_dp::{HpdEvent, HpdMonitor, HpdProfile},
    intel_gpu_gt::Gen12Platform,
    intel_gpu_modeset::{Mode, PixelFormat},
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Debug)]
struct Io {
    family: Gen12Platform,
    profile: Cell<Option<HpdProfile>>,
    allowed: Cell<bool>,
    powered: Cell<bool>,
    regs: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    reads: RefCell<Vec<u64>>,
    pipe: Pipe,
    ddi: Ddi,
    stall_pipe: Cell<bool>,
    stall_idle: Cell<bool>,
    fail_after_iir: Cell<bool>,
    fail_register: Cell<Option<u64>>,
    absent_plane_reads: Cell<u32>,
    refuse_mask: Cell<bool>,
    refuse_status_clear: Cell<bool>,
}
impl Io {
    fn new(family: Gen12Platform, pipe: Pipe, ddi: Ddi) -> Self {
        let io = Self {
            family,
            profile: Cell::new(HpdProfile::from_identity(
                family,
                0x8086,
                if family == Gen12Platform::TigerLake {
                    0xa080
                } else {
                    0x7a80
                },
                0x060100,
            )),
            allowed: Cell::new(true),
            powered: Cell::new(true),
            regs: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
            reads: RefCell::new(Vec::new()),
            pipe,
            ddi,
            stall_pipe: Cell::new(false),
            stall_idle: Cell::new(false),
            fail_after_iir: Cell::new(false),
            fail_register: Cell::new(None),
            absent_plane_reads: Cell::new(0),
            refuse_mask: Cell::new(false),
            refuse_status_clear: Cell::new(false),
        };
        let p = pipe.base() + 0x180;
        let t = pipe.trans_base();
        let ctl = match family {
            Gen12Platform::TigerLake | Gen12Platform::AlderLakeS => 0x84000000,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN => 0x94000000,
        };
        for (r, v) in [
            (p, ctl),
            (p + 8, 64),
            (p + 0x10, 0x02ff03ff),
            (p + 0x1c, 0x4000000),
            (p + 0x2c, 0x4000000),
            (pipe.base() + 8, 0xc0000000),
            (t, 0x053f03ff),
            (t + 4, 0x053f03ff),
            (t + 8, 0x049f0417),
            (t + 0x0c, 0x032502ff),
            (t + 0x10, 0x032502ff),
            (t + 0x14, 0x03080302),
            (t + 0x1c, 0x03ff02ff),
            (
                t + 0x400,
                if ddi == Ddi::B {
                    0x92000006
                } else {
                    0x9a000006
                },
            ),
            (t + 0x540, 0x80040300),
            (ddi.base(), 0x80000006),
            (0x46140 + pipe as u64 * 4, (ddi as u32 + 1) << 28),
            (0xc4004, u32::MAX),
            (0xc400c, u32::MAX),
            (0xc4038, 0xf8),
            // Foreign shared resources and live pipe A stay byte-for-byte intact.
            (0x45008, 0xc0000000),
            (0x46000, 0x12345678),
        ] {
            io.set(r, v);
        }
        io
    }
    fn set(&self, r: u64, v: u32) {
        self.regs.borrow_mut().insert(r, v);
    }
    fn raw(&self, r: u64) -> u32 {
        self.regs.borrow().get(&r).copied().unwrap_or(0)
    }
    fn conn(&self) -> DpConnection {
        DpConnection {
            family: self.family,
            ddi: self.ddi,
            pipe: self.pipe,
            mode: Mode::VESA_1024X768_60,
            trained: TrainedLink {
                rate: LinkRate::Hbr2,
                lanes: 4,
                vswing_pe: VSwingPe::default(),
            },
            caps: DpcdCaps {
                dpcd_rev: 0x14,
                max_rate: LinkRate::Hbr2,
                max_lanes: 4,
                tps3_supported: true,
                enhanced_framing: true,
                training_aux_rd_interval: 0,
                // The fixture link never advertised Ignore-MSA, so
                // no sink on it is VRR-capable.
                msa_timing_par_ignored: false,
            },
            audio_published: false,
        }
    }
    fn fb(&self) -> Framebuffer {
        Framebuffer {
            phys_addr: 0x4000000,
            stride_bytes: 4096,
            format: PixelFormat::Xrgb8888,
        }
    }
    fn session(&self, lease: Arc<()>) -> Session<Arc<()>> {
        Session::adopt(self, self.conn(), self.fb(), lease, 17, 0xabc000)
    }
}
impl MmioWindow for Io {
    fn gen12_display_family(&self) -> Option<Gen12Platform> {
        Some(self.family)
    }
    fn gen12_hpd_profile(&self) -> Option<HpdProfile> {
        self.profile.get()
    }
    fn display_access_ok(&self) -> bool {
        self.allowed.get() && self.powered.get()
    }
    fn read32(&self, r: u64) -> u32 {
        self.reads.borrow_mut().push(r);
        // Independent source inventory: ADL-S/P/N implement planes1..5,
        // so addresses for planes6/7 are unavailable rather than zero-default.
        if self.family != Gen12Platform::TigerLake
            && [self.pipe.base() + 0x680, self.pipe.base() + 0x780].contains(&r)
        {
            self.absent_plane_reads
                .set(self.absent_plane_reads.get() + 1);
            return u32::MAX;
        }
        if self.display_access_ok() {
            self.raw(r)
        } else {
            u32::MAX
        }
    }
    fn write32(&self, r: u64, v: u32) {
        if !self.display_access_ok() {
            return;
        }
        self.writes.borrow_mut().push((r, v));
        if r == 0xc4004 && self.refuse_mask.get() {
            return;
        }
        if r == 0xc4008 {
            self.set(r, self.raw(r) & !v);
            if self.fail_after_iir.get() {
                self.allowed.set(false);
            }
        } else if r == 0xc4030 {
            // Independent literal A-D W1C model: zeros preserve a status latch.
            let clear = if self.refuse_status_clear.get() {
                v & !0x30
            } else {
                v
            };
            self.set(r, (v & !0x3333) | (self.raw(r) & 0x3333 & !clear));
        } else if r == self.pipe.base() + 8 {
            let state = if self.stall_pipe.get() {
                self.raw(r) & 0x40000000
            } else {
                0
            };
            self.set(r, (v & !0x40000000) | state);
        } else if r == self.ddi.base() && v & 0x80000000 == 0 {
            self.set(
                r,
                if self.stall_idle.get() {
                    v & !0x80
                } else {
                    v | 0x80
                },
            );
        } else {
            self.set(r, v);
        }
        if self.fail_register.get() == Some(r) {
            self.allowed.set(false);
        }
    }
}
fn families() -> [Gen12Platform; 4] {
    [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeS,
        Gen12Platform::AlderLakeN,
    ]
}

fn pch(device: u16, bus: u8, function: u8) -> narf_bus::BusDevice {
    let addr = narf_bus::PcieAddr::new(0, bus, 31, function);
    narf_bus::BusDevice {
        addr: narf_bus::BusAddr::Pcie(addr),
        kind: narf_bus::BusKind::Pcie {
            addr,
            cfg_phys: narf_memory::PhysAddr::new(0xe0000000 + addr.ecam_offset()),
        },
        id: narf_bus::DeviceId {
            vendor: 0x8086,
            device,
            class: 0x060100,
            subsystem_vendor: 0,
            subsystem_id: 0,
        },
    }
}
fn smoke_gen12_external_hpd_observed_pch_exact_family_and_no_virtual_fallback() -> TestResult {
    for family in families() {
        let observed = pch(
            if family == Gen12Platform::TigerLake {
                0xa080
            } else {
                0x7a80
            },
            0,
            0,
        );
        if family == Gen12Platform::AlderLakeS {
            assert!(HpdProfile::from_observed(family, 0, &[observed]).is_none());
            continue; // source port mask is A + TC1..4, no external combo B/C
        }
        let profile = HpdProfile::from_observed(family, 0, &[observed]).unwrap();
        assert!(HpdProfile::from_observed(family, 0, &[]).is_none());
        assert!(HpdProfile::from_observed(family, 0, &[observed, observed]).is_none());
        assert!(HpdProfile::from_observed(family, 1, &[observed]).is_none());
        assert!(HpdProfile::from_observed(family, 0, &[pch(observed.id.device, 1, 0)]).is_none());
        assert_ne!(
            HpdProfile::from_observed(family, 0, &[pch(observed.id.device, 0, 1)]),
            Some(profile)
        );
        for (vendor, did, class) in [
            (0x8086, 0x7100, 0x060100),
            (0x8086, 0x7000, 0x060100),
            (0x8086, 0x2900, 0x060100),
            (0x1af4, 0x1100, 0x060100),
            (0x8086, 0xa080, 0x060101),
        ] {
            assert!(HpdProfile::from_identity(family, vendor, did, class).is_none());
        }
        assert_eq!(
            HpdProfile::from_identity(family, 0x8086, 0xa080, 0x060100).is_some(),
            family == Gen12Platform::TigerLake
        );
        assert_eq!(
            HpdProfile::from_identity(family, 0x8086, 0x7a80, 0x060100).is_some(),
            family != Gen12Platform::TigerLake
        );
        let io = Io::new(family, Pipe::B, Ddi::B);
        io.profile.set(None);
        io.set(0xc4000, 0x60000);
        let mut hpd = HpdMonitor::new();
        hpd.enable_interrupts(&io);
        assert_eq!(hpd.poll(&io), None);
        assert!(io.writes.borrow().is_empty());
        // Explicit checked retirement is independent of HPD metadata.
        let mut owner = io.session(Arc::new(()));
        assert!(owner.live());
        owner.request_stop();
        for n in 0..8 {
            if owner.step(&io, n * 250_000).unwrap() {
                break;
            }
        }
        assert!(owner.stopped());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_hpd_observed_pch_exact_family_and_no_virtual_fallback
);

fn smoke_gen12_external_hpd_w1c_order_preserves_foreign_combo_c_and_status() -> TestResult {
    let io = Io::new(Gen12Platform::AlderLakeP, Pipe::B, Ddi::B);
    io.set(0xc4030, 0x4000 | 0x1000 | 0x330 | 0x44); // foreign D/A status, owned B/C both
    let mut hpd = HpdMonitor::new();
    hpd.enable_interrupts(&io);
    assert!(!hpd.uncertain());
    assert_eq!(io.raw(0xc4004), u32::MAX); // MAX is a valid mask, not loss
    assert_eq!(io.raw(0xc400c), u32::MAX);
    assert_eq!(io.raw(0xc4030) & 0x1001, 0x1000);
    assert!(io.writes.borrow().iter().all(|&(r, _)| r != 0xc4038));
    io.set(0xc4000, 0x60000);
    assert_eq!(hpd.poll(&io), Some(HpdEvent::Connected(Ddi::B)));
    assert_eq!(
        hpd.poll(&io),
        None,
        "combo C is absent from the pinned port mask"
    );
    io.set(0xc4008, 0x60000 | 1);
    io.set(0xc4030, io.raw(0xc4030) | 0x30);
    let start = io.writes.borrow().len();
    assert_eq!(hpd.poll(&io), Some(HpdEvent::RetrainRequired(Ddi::B)));
    assert_eq!(hpd.poll(&io), None);
    assert_eq!(hpd.poll(&io), None);
    let writes = io.writes.borrow();
    assert_eq!(writes[start], (0xc4008, 0x20000));
    assert_eq!(writes[start + 1].0, 0xc4030);
    assert_eq!(writes[start + 1].1 & 0x3333, 0x30);
    assert_eq!(io.raw(0xc4030) & 0x3333, 0x1300);
    assert_eq!(io.raw(0xc4008), 0x40001); // foreign IIR is retained
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_hpd_w1c_order_preserves_foreign_combo_c_and_status
);

fn smoke_gen12_external_hpd_ack_loss_filter_change_and_identity_change_quarantine() -> TestResult {
    for failure in 0..4 {
        let io = Io::new(Gen12Platform::TigerLake, Pipe::B, Ddi::B);
        let mut hpd = HpdMonitor::new();
        hpd.enable_interrupts(&io);
        io.set(0xc4000, 0x20000);
        assert_eq!(hpd.poll(&io), Some(HpdEvent::Connected(Ddi::B)));
        io.set(0xc4008, 0x20000);
        io.set(0xc4030, 0x8a0);
        match failure {
            0 => io.fail_after_iir.set(true),
            1 => io.set(0xc4038, 0),
            2 => io.profile.set(io.profile.get().map(|p| p.at(0x1f01))),
            _ => io.powered.set(false),
        }
        assert_eq!(hpd.poll(&io), None);
        assert!(hpd.uncertain());
        io.allowed.set(true);
        io.powered.set(true);
        io.set(0xc4038, 0xf8);
        assert_eq!(
            hpd.poll(&io),
            None,
            "lost ACK must never become a no-event proof"
        );
        if failure == 0 {
            assert_eq!(io.raw(0xc4030) & 0x30, 0x20);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_hpd_ack_loss_filter_change_and_identity_change_quarantine
);

fn smoke_gen12_external_sst_checked_native_pipe_and_port_idle_preserve_lease_and_shared_image(
) -> TestResult {
    for family in [
        Gen12Platform::TigerLake,
        Gen12Platform::AlderLakeP,
        Gen12Platform::AlderLakeN,
    ] {
        for pipe in [Pipe::A, Pipe::B, Pipe::C] {
            let io = Io::new(family, pipe, Ddi::B);
            let lease = Arc::new(());
            let weak = Arc::downgrade(&lease);
            let mut owner = io.session(lease);
            assert!(owner.live());
            assert_eq!(owner.step(&io, 0), Ok(false));
            assert!(io.writes.borrow().is_empty());
            owner.request_stop();
            for n in 0..8 {
                if owner.step(&io, n * 250_000).unwrap() {
                    break;
                }
            }
            assert!(owner.stopped());
            assert!(weak.upgrade().is_some());
            let writes = io.writes.borrow();
            let regs: Vec<_> = writes.iter().map(|&(r, _)| r).collect();
            assert_eq!(
                regs,
                [
                    pipe.base() + 0x180,
                    pipe.base() + 0x19c,
                    pipe.base() + 8,
                    pipe.trans_base() + 0x400,
                    Ddi::B.base(),
                    pipe.trans_base() + 0x540,
                    0x46140 + pipe as u64 * 4
                ]
            );
            assert_eq!(io.raw(0x45008), 0xc0000000);
            assert_eq!(io.raw(0x46000), 0x12345678);
            assert_eq!(io.raw(pipe.base() + 8) & 0xc0000000, 0);
            assert_eq!(io.raw(Ddi::B.base()) & 0x80000080, 0x80);
            assert_eq!(owner.serial, 17);
            assert_eq!(owner.bar, 0xabc000);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_sst_checked_native_pipe_and_port_idle_preserve_lease_and_shared_image
);

fn smoke_gen12_external_sst_cancel_timeout_and_authority_loss_retain_graph() -> TestResult {
    for failure in 0..4 {
        let io = Io::new(Gen12Platform::AlderLakeN, Pipe::B, Ddi::B);
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let mut owner = io.session(lease);
        io.stall_pipe.set(true);
        let mut waiter = alloc::boxed::Box::pin(async {
            owner.request_stop();
            assert_eq!(owner.step(&io, 0), Ok(false));
            core::future::pending::<()>().await;
        });
        assert!(waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(waiter); // owner phase/lease outlive cancellation
        assert!(weak.upgrade().is_some());
        assert_eq!(owner.phase, Phase::Pipe);
        let before = io.writes.borrow().len();
        assert_eq!(owner.step(&io, 99_999_999), Ok(false));
        assert_eq!(io.writes.borrow().len(), before);
        match failure {
            0 => assert_eq!(owner.step(&io, 100_000_000), Err(FsError::TimedOut)),
            1 => {
                io.allowed.set(false);
                assert_eq!(owner.step(&io, 1), Err(FsError::NoDevice));
            }
            2 => {
                io.powered.set(false);
                assert_eq!(owner.step(&io, 1), Err(FsError::NoDevice));
            }
            _ => {
                io.set(io.pipe.base() + 0x19c, 0x5000000);
                assert_eq!(owner.step(&io, 1), Err(FsError::NoDevice));
            }
        }
        assert!(weak.upgrade().is_some());
        assert!(!owner.stopped());
        io.allowed.set(true);
        io.powered.set(true);
        io.stall_pipe.set(false);
        io.set(io.pipe.base() + 8, 0);
        assert!(
            owner.step(&io, 200_000_000).is_err(),
            "reset cannot adopt a quarantined route"
        );
        assert_eq!(io.writes.borrow().len(), before);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_sst_cancel_timeout_and_authority_loss_retain_graph
);

fn smoke_gen12_external_sst_idle_timeout_foreign_fetchers_and_stale_publication_refuse(
) -> TestResult {
    for (r, v) in [
        (0x71280, 0x80000000),
        (0x71080, 0x27),
        (0x71b08, 0x80000000),
        (0x61404, 1),
        (0x420c4, 1 << 23),
        (0x78200, 1 << 29),
        (0x78204, 1 << 31),
    ] {
        let io = Io::new(Gen12Platform::TigerLake, Pipe::B, Ddi::B);
        io.set(r, v);
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let mut owner = io.session(lease);
        owner.request_stop();
        assert!(owner.step(&io, 0).is_err());
        assert!(weak.upgrade().is_some());
        assert!(io.writes.borrow().is_empty());
    }
    let io = Io::new(Gen12Platform::AlderLakeP, Pipe::B, Ddi::B);
    let mut owner = io.session(Arc::new(()));
    io.stall_idle.set(true);
    owner.request_stop();
    for n in 0..4 {
        assert_eq!(owner.step(&io, n * 250_000), Ok(false));
    }
    assert_eq!(owner.phase, Phase::Transport);
    assert_eq!(owner.step(&io, 10_750_000), Err(FsError::TimedOut));
    assert_ne!(io.raw(0x46144), 0, "no clock deselect before DDI idle");
    let mut active = (18, Some(0x2222));
    assert!(!withdraw(&mut active, 17));
    assert_eq!(active, (18, Some(0x2222)));
    assert!(!withdraw(&mut active, 0));
    assert!(withdraw(&mut active, 18));
    assert_eq!(active, (0, None));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_sst_idle_timeout_foreign_fetchers_and_stale_publication_refuse
);

fn smoke_gen12_external_sst_settling_requires_live_surface_and_pipe_state_before_publication(
) -> TestResult {
    let io = Io::new(Gen12Platform::AlderLakeP, Pipe::B, Ddi::B);
    io.set(0x71008, 0x80000000);
    io.set(0x711ac, 0x3000000);
    let mut owner = io.session(Arc::new(()));
    assert!(!owner.live());
    assert!(owner.running());
    assert_eq!(owner.step(&io, 0), Ok(false));
    assert!(!owner.live());
    io.set(0x71008, 0xc0000000);
    assert_eq!(owner.step(&io, 250_000), Ok(false));
    assert!(!owner.live());
    io.set(0x711ac, 0x4000000);
    assert_eq!(owner.step(&io, 500_000), Ok(false));
    assert!(owner.live());
    assert!(io.writes.borrow().is_empty());
    io.set(0x711ac, 0x3000000);
    io.set(0x71008, 0x80000000);
    let mut timeout = io.session(Arc::new(()));
    assert_eq!(timeout.step(&io, 0), Ok(false));
    assert_eq!(timeout.step(&io, 100_000_000), Err(FsError::TimedOut));
    assert!(!timeout.live());
    // PM/cancel may request a stop while activation's native latch is pending.
    let mut early = io.session(Arc::new(()));
    early.request_stop();
    for n in 0..8 {
        if early.step(&io, n * 250_000).unwrap() {
            break;
        }
    }
    assert!(early.stopped());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_sst_settling_requires_live_surface_and_pipe_state_before_publication
);

fn smoke_gen12_external_sst_cancel_at_each_partial_stage_retains_stop_intent() -> TestResult {
    for steps in 0..=5 {
        let io = Io::new(Gen12Platform::AlderLakeP, Pipe::B, Ddi::B);
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let mut owner = io.session(lease);
        let mut waiter = alloc::boxed::Box::pin(async {
            owner.request_stop();
            for n in 0..steps {
                assert_eq!(owner.step(&io, n * 250_000), Ok(false));
            }
            core::future::pending::<()>().await;
        });
        assert!(waiter
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(waiter);
        let phase = owner.phase;
        assert!(!owner.live() && !owner.stopped());
        owner.request_stop();
        assert_eq!(owner.phase, phase, "duplicate stop replayed an earlier arm");
        let writes = io.writes.borrow().len();
        io.allowed.set(false);
        assert_eq!(owner.step(&io, 2_000_000), Err(FsError::NoDevice));
        assert!(weak.upgrade().is_some());
        assert_eq!(io.writes.borrow().len(), writes);
        io.allowed.set(true);
        assert!(owner.step(&io, 3_000_000).is_err());
        assert_eq!(io.writes.borrow().len(), writes);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_sst_cancel_at_each_partial_stage_retains_stop_intent
);

fn smoke_gen12_external_sst_loss_between_each_write_and_readback_never_retires() -> TestResult {
    for register in [
        0x71180, 0x7119c, 0x71008, 0x61400, 0x64100, 0x61540, 0x46144,
    ] {
        let io = Io::new(Gen12Platform::TigerLake, Pipe::B, Ddi::B);
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let mut owner = io.session(lease);
        io.fail_register.set(Some(register));
        owner.request_stop();
        let mut failed = false;
        for n in 0..8 {
            match owner.step(&io, n * 250_000) {
                Err(FsError::NoDevice) => {
                    failed = true;
                    break;
                }
                Ok(false) => {}
                other => panic!("unproven stop: {other:?}"),
            }
        }
        assert!(failed && !owner.stopped());
        assert!(weak.upgrade().is_some());
        assert_eq!(io.writes.borrow().last().map(|w| w.0), Some(register));
        let writes = io.writes.borrow().len();
        io.allowed.set(true);
        assert!(owner.step(&io, 5_000_000).is_err());
        assert_eq!(io.writes.borrow().len(), writes);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_sst_loss_between_each_write_and_readback_never_retires
);

fn smoke_gen12_external_legacy_fallible_disconnect_refuses_denied_or_unavailable_reads(
) -> TestResult {
    for fault in 0..3 {
        let io = Io::new(Gen12Platform::AlderLakeP, Pipe::B, Ddi::B);
        let mut modeset = crate::intel_gpu_modeset::Modeset::for_pipe(&io, Ddi::B, Pipe::B);
        modeset.set_gen12_family(if fault == 0 {
            Gen12Platform::TigerLake
        } else {
            io.family
        });
        if fault == 1 {
            io.allowed.set(false);
        }
        if fault == 2 {
            io.set(0x7119c, u32::MAX);
        }
        assert!(modeset.try_teardown().is_err());
        assert!(io.writes.borrow().is_empty());
    }
    let io = Io::new(Gen12Platform::AlderLakeP, Pipe::B, Ddi::B);
    let lease = Arc::new(());
    let weak = Arc::downgrade(&lease);
    let mut retained = io.session(lease);
    io.allowed.set(false);
    assert!(!crate::intel_gpu_dp::disconnect(&io, &retained.conn));
    assert!(retained.step(&io, 0).is_err());
    assert!(weak.upgrade().is_some());
    assert!(io.writes.borrow().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_legacy_fallible_disconnect_refuses_denied_or_unavailable_reads
);

fn smoke_gen12_external_companion_inventory_denies_absent_adl_planes_and_refuses_every_live_sprite(
) -> TestResult {
    for (family, last) in [
        (Gen12Platform::TigerLake, 7u64),
        (Gen12Platform::AlderLakeS, 5),
        (Gen12Platform::AlderLakeP, 5),
        (Gen12Platform::AlderLakeN, 5),
    ] {
        let io = Io::new(family, Pipe::B, Ddi::B);
        let mut owner = io.session(Arc::new(()));
        idle_companions(&io, &io.conn()).unwrap();
        if family != Gen12Platform::AlderLakeS {
            assert!(owner.live());
        }
        owner.request_stop();
        if family == Gen12Platform::AlderLakeS {
            assert!(owner.step(&io, 0).is_err());
        } else {
            for n in 0..8 {
                if owner.step(&io, n * 250_000).unwrap() {
                    break;
                }
            }
            assert!(owner.stopped());
        }
        assert_eq!(io.absent_plane_reads.get(), 0);
        for plane in 2..=last {
            let foreign = Io::new(family, Pipe::B, Ddi::B);
            foreign.set(0x71080 + plane * 0x100, 0x80000000);
            let lease = Arc::new(());
            let weak = Arc::downgrade(&lease);
            let mut owner = foreign.session(lease);
            owner.request_stop();
            assert!(idle_companions(&foreign, &foreign.conn()).is_err());
            assert!(owner.step(&foreign, 0).is_err());
            assert!(weak.upgrade().is_some());
            assert!(foreign.writes.borrow().is_empty());
            assert_eq!(foreign.absent_plane_reads.get(), 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_companion_inventory_denies_absent_adl_planes_and_refuses_every_live_sprite
);

fn smoke_gen12_external_hpd_masks_before_ier_and_stops_on_failed_mask_readback() -> TestResult {
    for fault in 0..3 {
        let io = Io::new(Gen12Platform::AlderLakeP, Pipe::B, Ddi::B);
        io.set(0xc4004, 0x40);
        io.set(0xc400c, 0x80);
        if fault == 1 {
            io.fail_register.set(Some(0xc4004));
        }
        if fault == 2 {
            io.refuse_mask.set(true);
        }
        let mut hpd = HpdMonitor::new();
        hpd.enable_interrupts(&io);
        let writes = io.writes.borrow();
        assert_eq!(writes[0], (0xc4004, 0x20040));
        if fault != 0 {
            assert!(hpd.uncertain());
            assert_eq!(writes.len(), 1);
            assert_eq!(io.raw(0xc400c), 0x80);
            assert_eq!(io.raw(0xc4030), 0);
        } else {
            assert!(!hpd.uncertain());
            assert_eq!(writes[1], (0xc400c, 0x20080));
            assert_eq!(writes[2].0, 0xc4030);
            assert_eq!(writes[2].1 & 0x880, 0x80);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_hpd_masks_before_ier_and_stops_on_failed_mask_readback
);

fn smoke_gen12_external_hpd_low_short_or_pre_iir_preserves_live_until_source_long() -> TestResult {
    let io = Io::new(Gen12Platform::TigerLake, Pipe::B, Ddi::B);
    let mut hpd = HpdMonitor::new();
    hpd.enable_interrupts(&io);
    io.set(0xc4000, 0x20000);
    assert_eq!(hpd.poll(&io), Some(HpdEvent::Connected(Ddi::B)));
    io.set(0xc4000, 0);
    assert_eq!(hpd.poll(&io), None, "low before IIR is not unplug");
    io.set(0xc4008, 0x20000);
    io.set(0xc4030, 0x90);
    assert_eq!(hpd.poll(&io), Some(HpdEvent::RetrainRequired(Ddi::B)));
    io.set(0xc4000, 0x20000);
    assert_eq!(hpd.poll(&io), None, "short never changed live state");
    io.set(0xc4000, 0);
    io.set(0xc4008, 0x20000);
    io.set(0xc4030, 0x80);
    assert_eq!(
        hpd.poll(&io),
        Some(HpdEvent::RetrainRequired(Ddi::B)),
        "unknown IIR is not long"
    );
    io.set(0xc4000, 0x40000);
    io.set(0xc4008, 0x60000);
    io.set(0xc4030, 0x2a0);
    assert_eq!(hpd.poll(&io), Some(HpdEvent::Disconnected(Ddi::B)));
    assert_eq!(hpd.poll(&io), None);
    assert_eq!(io.raw(0xc4008), 0x40000);
    assert_eq!(
        io.raw(0xc4030) & 0x300,
        0x200,
        "foreign combo C status remains"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_hpd_low_short_or_pre_iir_preserves_live_until_source_long
);

fn smoke_gen12_external_absent_combo_ports_refuse_before_mmio_and_retain_graph() -> TestResult {
    for (family, ddi) in [
        (Gen12Platform::TigerLake, Ddi::C),
        (Gen12Platform::AlderLakeP, Ddi::C),
        (Gen12Platform::AlderLakeN, Ddi::C),
        (Gen12Platform::AlderLakeS, Ddi::B),
        (Gen12Platform::AlderLakeS, Ddi::C),
    ] {
        let io = Io::new(family, Pipe::B, ddi);
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let mut owner = io.session(lease);
        assert!(!owner.live());
        owner.request_stop();
        assert!(owner.step(&io, 0).is_err());
        assert!(weak.upgrade().is_some());
        assert!(io.writes.borrow().is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_absent_combo_ports_refuse_before_mmio_and_retain_graph
);

fn smoke_gen12_external_sst_preflight_refuses_foreign_route_before_any_power_or_stop_write(
) -> TestResult {
    for register in [0x61400, 0x7119c, 0x71180, 0x46144, 0x71280] {
        let io = Io::new(Gen12Platform::AlderLakeP, Pipe::B, Ddi::B);
        let lease = Arc::new(());
        let weak = Arc::downgrade(&lease);
        let mut owner = io.session(lease);
        io.set(register, io.raw(register) ^ 0x80000000);
        assert!(owner.preflight(&io).is_err());
        assert!(io.writes.borrow().is_empty());
        assert!(weak.upgrade().is_some());
        owner.request_stop();
        assert!(owner.step(&io, 0).is_err());
        assert!(io.writes.borrow().is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_sst_preflight_refuses_foreign_route_before_any_power_or_stop_write
);

fn smoke_gen12_external_hpd_fresh_owned_status_clears_inherited_long_before_short_low() -> TestResult
{
    for inherited_iir in [0, 0x60001] {
        let io = Io::new(Gen12Platform::AlderLakeP, Pipe::B, Ddi::B);
        io.set(0xc4004, 0x40);
        io.set(0xc400c, 0x80);
        io.set(0xc4030, 0x42a0); // owned B LONG plus foreign C LONG/output D
        io.set(0xc4008, inherited_iir);
        io.set(0xc4000, 0x60000);
        let mut hpd = HpdMonitor::new();
        hpd.enable_interrupts(&io);
        assert!(!hpd.uncertain());
        assert_eq!(
            io.raw(0xc4030) & 0x3333,
            0x200,
            "first status baseline clears B only"
        );
        assert_eq!(io.raw(0xc4008), inherited_iir & !0x20000);
        let writes = io.writes.borrow();
        assert_eq!(writes[0], (0xc4004, 0x20040));
        assert_eq!(writes[1], (0xc400c, 0x20080));
        let shot = writes.iter().position(|&(r, _)| r == 0xc4030).unwrap();
        assert_eq!(writes[shot].1 & 0x3333, 0x20);
        if inherited_iir != 0 {
            assert!(
                writes
                    .iter()
                    .position(|&(r, v)| r == 0xc4008 && v == 0x20000)
                    .unwrap()
                    < shot
            );
        }
        drop(writes);
        let reads = io.reads.borrow();
        assert!(
            reads.iter().position(|&r| r == 0xc4008).unwrap()
                < reads.iter().position(|&r| r == 0xc4030).unwrap()
        );
        drop(reads);
        assert_eq!(hpd.poll(&io), Some(HpdEvent::Connected(Ddi::B)));
        // The literal review repro: old LONG had no IIR; new SHORT+IIR occurs
        // while live ISR is low. It must preserve the known connected state.
        io.set(0xc4030, io.raw(0xc4030) | 0x10);
        io.set(0xc4008, io.raw(0xc4008) | 0x20000);
        io.set(0xc4000, 0x40000);
        assert_eq!(hpd.poll(&io), Some(HpdEvent::RetrainRequired(Ddi::B)));
        io.set(0xc4000, 0x60000);
        assert_eq!(hpd.poll(&io), None);
        assert_eq!(io.raw(0xc4030) & 0x300, 0x200);
        assert_eq!(io.raw(0xc4008), inherited_iir & !0x20000);
        // Re-enabling an established monitor must not discard a new valid
        // event as inherited status from a different incarnation.
        io.set(0xc4000, 0x40000);
        io.set(0xc4008, io.raw(0xc4008) | 0x20000);
        io.set(0xc4030, io.raw(0xc4030) | 0x20);
        let before = io.writes.borrow().len();
        hpd.enable_interrupts(&io);
        assert_eq!(io.writes.borrow().len(), before);
        assert_eq!(hpd.poll(&io), Some(HpdEvent::Disconnected(Ddi::B)));
    }
    let refused = Io::new(Gen12Platform::TigerLake, Pipe::B, Ddi::B);
    refused.set(0xc4030, 0xa0);
    refused.refuse_status_clear.set(true);
    let mut hpd = HpdMonitor::new();
    hpd.enable_interrupts(&refused);
    assert!(hpd.uncertain());
    refused.set(0xc4000, 0x20000);
    assert_eq!(
        hpd.poll(&refused),
        None,
        "unproven fresh status must not publish a connection"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_dp",
    smoke_gen12_external_hpd_fresh_owned_status_clears_inherited_long_before_short_low
);
