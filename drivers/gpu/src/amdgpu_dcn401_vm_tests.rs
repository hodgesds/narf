use super::*;
use crate::amdgpu_gmc_navi48::DisplayContext;

const ROOT: u64 = BASE + 0x55b * 4;
fn config() -> DisplayContext {
    DisplayContext {
        fb_base: 0x8_0000_0000,
        fb_top: 0xb_ffff_ffff,
        fb_offset: 0x1_0000_0000,
        root: 0x1_0000_4001,
        start: 0xc_0000_0000,
        end: 0xc_001f_ffff,
    }
}
struct MemoryIo {
    surface: SurfaceIo,
    pending: bool,
    delay: u8,
    stall: bool,
    ready_observed: bool,
}
impl Io for MemoryIo {
    fn read(&mut self, at: u64) -> u32 {
        if at == ROOT && self.pending && !self.stall {
            if self.delay == 0 {
                *self.surface.inner.regs.entry(at).or_default() |= 1;
                self.pending = false;
            } else {
                self.delay -= 1;
            }
        }
        let value = self.surface.read(at);
        if at == ROOT && value & 1 != 0 && !self.pending {
            self.ready_observed = true;
        }
        value
    }
    fn write(&mut self, at: u64, value: u32) {
        for p in 0..4 {
            if at == h(p, 0x5f5) && value & 1 != 0 {
                assert!(
                    self.ready_observed,
                    "fetch clock enabled before VMID readiness"
                );
            }
        }
        self.surface.write(at, value);
        if at == ROOT && self.surface.inner.reject != Some(self.surface.inner.writes.len()) {
            assert_eq!(self.surface.inner.regs[&(BASE + 0x55a * 4)], 1);
            assert_eq!(self.surface.inner.regs[&(BASE + 0x55d * 4)], 0xc00000);
            assert_eq!(self.surface.inner.regs[&(BASE + 0x55f * 4)], 0xc001ff);
            assert_eq!(self.surface.inner.regs[&(BASE + 0x559 * 4)], 0);
            self.pending = true;
            *self.surface.inner.regs.entry(ROOT).or_default() &= !1;
        }
    }
}
fn staged(p: u8) -> (Vec<u32>, Pool, Engine<MemoryIo>, Surfaces) {
    let (backing, pool, mut e, mut surfaces) = fixture(p, 8192);
    run(surfaces.prepare(&mut e, &pool, req(p))).unwrap();
    e.io.inner.writes.clear();
    // Poison every programmable field, including valid inherited root, so a
    // dropped write cannot accidentally look like the intended configuration.
    for r in [
        0x475, 0x476, 0x477, 0x478, 0x479, 0x47a, 0x559, 0x55a, 0x55b, 0x55c, 0x55d, 0x55e, 0x55f,
    ] {
        e.io.inner.regs.insert(BASE + r * 4, 0xdeadbeef);
    }
    for r in [0x62c, 0x62d, 0x63a] {
        e.io.inner.regs.insert(h(p, r), 0xdeadbeef);
    }
    e.io.inner.regs.insert(BASE + 0x560 * 4, 0x12345678); // VMID1 untouched
    let engine = Engine {
        io: MemoryIo {
            surface: e.io,
            pending: false,
            delay: 1,
            stall: false,
            ready_observed: false,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
    };
    (backing, pool, engine, surfaces)
}
fn dcn401_vm_programs_native_physical_apertures_and_waits_for_context() -> TestResult {
    for p in 0..4 {
        let (_backing, pool, mut e, mut surfaces) = staged(p);
        let mut checks = 0;
        let applied = run(surfaces.prepare_memory(&mut e, p, || {
            checks += 1;
            Ok(config())
        }))
        .unwrap();
        assert_eq!(checks, 2);
        assert_eq!(applied.page_table_base, 0x1_0000_4001);
        assert_eq!(applied.framebuffer_base, 0x8_0000_0000);
        assert_eq!(applied.framebuffer_offset, 0x1_0000_0000);
        assert_eq!(e.status.state, State::MemoryPrepared);
        assert_eq!(e.status.memory[p as usize], Some(applied));
        let f = &e.io.surface.inner;
        let expected = [
            (BASE + 0x475 * 4, 0x800),
            (BASE + 0x476 * 4, 0xbff),
            (BASE + 0x477 * 4, 0x100),
            (BASE + 0x478 * 4, 0xffffff),
            (BASE + 0x479 * 4, 0),
            (BASE + 0x47a * 4, 0),
            (BASE + 0x55c * 4, 0),
            (BASE + 0x55d * 4, 0xc00000),
            (BASE + 0x55e * 4, 0),
            (BASE + 0x55f * 4, 0xc001ff),
            (BASE + 0x559 * 4, 0),
            (BASE + 0x55a * 4, 1),
            (ROOT, 0x4001),
            (h(p, 0x5f5), 0x100011),
            (h(p, 0x62c), 0x20000),
            (h(p, 0x62d), 0x2ffff),
            (h(p, 0x63a), 0x19),
            (h(p, 0x5f5), 0x100010),
        ];
        assert_eq!(f.writes.as_slice(), expected.as_slice());
        assert_eq!(f.regs[&(BASE + 0x560 * 4)], 0x12345678);
        assert_eq!(f.regs[&h(p, 0x613)] & 0x100, 0x100); // still pending, no timing
        assert_eq!(f.regs[&h(p, 0x5f4)] & 0x1007, 3);
        assert_eq!(pool.available(), 4096);
        drop(surfaces);
        assert_eq!(pool.available(), 4096);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-vm",
    dcn401_vm_programs_native_physical_apertures_and_waits_for_context
);

fn dcn401_vm_rejects_unowned_stale_or_live_surfaces_before_writes() -> TestResult {
    let (_backing, _pool, mut e, mut surfaces) = staged(0);
    for p in [1, 4, 255] {
        assert_eq!(
            run(surfaces.prepare_memory(&mut e, p, || Ok(config()))),
            Err(Error::Invalid)
        );
    }
    for bad in [
        DisplayContext {
            fb_base: 0x8_0010_3000,
            ..config()
        },
        DisplayContext {
            fb_top: 0x8_0010_2ffe,
            ..config()
        },
    ] {
        assert_eq!(
            run(surfaces.prepare_memory(&mut e, 0, || Ok(bad))),
            Err(Error::Invalid)
        );
    }
    assert_eq!(
        run(surfaces.prepare_memory(&mut e, 0, || Err(Error::Memory(
            crate::amdgpu_gmc_navi48::Error::Busy
        )))),
        Err(Error::Memory(crate::amdgpu_gmc_navi48::Error::Busy))
    );
    for (at, value) in [
        (h(0, 0x60a), 0),
        (h(0, 0x609), 1),
        (h(0, 0x5f4), 1),
        (h(0, 0x5f5), 1),
        (h(0, 0x685), 1),
        (BASE + 0x1b43 * 4, 1),
        (MPC_BASE + 0x2f2 * 4, 0),
    ] {
        let old = e.io.surface.inner.regs.insert(at, value);
        assert!(run(surfaces.prepare_memory(&mut e, 0, || Ok(config()))).is_err());
        e.io.surface.inner.regs.insert(at, old.unwrap_or(0));
    }
    assert!(e.io.surface.inner.writes.is_empty());
    assert_eq!(e.status.state, State::SurfacePrepared);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-vm",
    dcn401_vm_rejects_unowned_stale_or_live_surfaces_before_writes
);

fn dcn401_vm_lost_writes_revocation_and_removal_quarantine_the_owner() -> TestResult {
    for mode in 0..3 {
        for n in 1..=18 {
            let (_backing, pool, mut e, mut surfaces) = staged(2);
            match mode {
                0 => e.io.surface.inner.reject = Some(n),
                1 => e.io.surface.inner.revoke = Some((n, e.authority)),
                _ => e.io.surface.inner.gone = Some(n),
            }
            let err = run(surfaces.prepare_memory(&mut e, 2, || Ok(config()))).unwrap_err();
            match mode {
                0 => assert!(matches!(err, Error::Readback(_))),
                1 => assert_eq!(err, Error::Revoked),
                _ => assert_eq!(err, Error::DeviceGone),
            }
            assert_eq!(e.status.state, State::Failed(err));
            assert_eq!(e.status.memory, [None; 4]);
            let count = e.io.surface.inner.writes.len();
            assert_eq!(
                run(surfaces.prepare_memory(&mut e, 2, || Ok(config()))),
                Err(Error::Busy)
            );
            assert_eq!(e.io.surface.inner.writes.len(), count);
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-vm",
    dcn401_vm_lost_writes_revocation_and_removal_quarantine_the_owner
);

fn dcn401_vm_timeout_cancel_and_late_changes_never_report_readiness() -> TestResult {
    for cancel in [false, true] {
        let (_backing, pool, mut e, mut surfaces) = staged(1);
        e.io.stall = true;
        if cancel {
            let mut f = core::pin::pin!(surfaces.prepare_memory(&mut e, 1, || Ok(config())));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        } else {
            assert_eq!(
                run(surfaces.prepare_memory(&mut e, 1, || Ok(config()))),
                Err(Error::Timeout(ROOT))
            );
        }
        assert_eq!(
            e.status.state,
            if cancel {
                State::PreparingMemory(1)
            } else {
                State::Failed(Error::Timeout(ROOT))
            }
        );
        assert_eq!(e.io.surface.inner.writes.len(), 13);
        assert_eq!(e.status.memory, [None; 4]);
        assert_eq!(
            run(surfaces.prepare_memory(&mut e, 1, || Ok(config()))),
            Err(Error::Busy)
        );
        drop(surfaces);
        assert_eq!(pool.available(), 4096);
    }
    // Delayed external changes must fail the post-wait/readback check.
    for (n, at, value) in [
        (13, BASE + 0x1b43 * 4, 1),
        (18, BASE + 0x477 * 4, 0),
        (18, h(3, 0x60a), 0),
        (18, h(3, 0x62d), 0),
    ] {
        let (_backing, _pool, mut e, mut surfaces) = staged(3);
        e.io.surface.inner.after_write = Some((n, at, value));
        assert!(run(surfaces.prepare_memory(&mut e, 3, || Ok(config()))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.status.memory, [None; 4]);
    }
    for revoked in [false, true] {
        let (_backing, _pool, mut e, mut surfaces) = staged(0);
        let mut calls = 0;
        let err = run(surfaces.prepare_memory(&mut e, 0, || {
            calls += 1;
            if calls == 1 {
                Ok(config())
            } else if revoked {
                Err(Error::Memory(crate::amdgpu_gmc_navi48::Error::Revoked))
            } else {
                Ok(DisplayContext {
                    fb_offset: 0,
                    ..config()
                })
            }
        }))
        .unwrap_err();
        assert_eq!(e.status.state, State::Failed(err));
        assert_eq!(e.status.memory, [None; 4]);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-vm",
    dcn401_vm_timeout_cancel_and_late_changes_never_report_readiness
);
