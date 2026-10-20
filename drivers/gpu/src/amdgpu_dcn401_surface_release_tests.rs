use super::*;
use crate::amdgpu_dcn401_otg::tests::{engine, run};
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Model {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    layout: Layout,
    gated: u8,
    after_flush: Option<(u64, u32)>,
    revoke: Option<Cap<BusDeviceCap, Write>>,
}
impl Io for Model {
    fn read(&mut self, at: u64) -> u32 {
        for p in 0..4 {
            assert!(
                self.gated & (1 << p) == 0
                    || !(self.layout.hubp(p, 0x5e5)..=self.layout.hubp(p, 0x68a)).contains(&at),
                "read a power-gated HUBP"
            );
        }
        self.regs.get(&at).copied().unwrap_or(0)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.writes.push((at, value));
        self.regs.insert(at, value);
        if at == 0x7f000 {
            if let Some((at, value)) = self.after_flush.take() {
                self.regs.insert(at, value);
            }
            if let Some(cap) = self.revoke.take() {
                cap.revoke();
            }
        }
    }
}

fn buffers(pool: &Pool, pipe: u8, height: u32) -> Surface {
    let request = SurfaceRequest {
        pipe,
        width: 16,
        height,
        format: SurfaceFormat::Xrgb8888,
        odm: None,
        plane: None,
    };
    let reserve = |bytes| {
        let mut r = pool.reserve(bytes).unwrap();
        r.publish();
        r
    };
    let memory = reserve(4096);
    Surface {
        applied: SurfaceApplied {
            request,
            address: memory.address(),
            pitch_bytes: 256,
            bytes: u64::from(height) * 256,
        },
        memory,
        back: Some(reserve(4096)),
        cursor: Some(reserve(64 * 64 * 4)),
    }
}

fn fixture() -> (Engine<Model>, Surfaces, Pool) {
    let e = engine();
    let l = e.layout;
    let mut io = Model {
        regs: BTreeMap::new(),
        writes: Vec::new(),
        layout: l,
        gated: 0,
        after_flush: None,
        revoke: None,
    };
    for p in 0..4 {
        for at in [
            l.out_mux(p),
            l.mpcc(p, 0),
            l.mpcc(p, 1),
            l.mpcc(p, 2),
            l.mpcc(p, 5),
        ] {
            io.regs.insert(at, 0xf);
        }
        io.regs.insert(l.mpcc(p, 0xe), 5);
        io.regs.insert(l.hubp(p, HUBP_CONTROL), 3);
    }
    io.regs.insert(l.nbio + 0x12d * 4, 0x7f000);
    let mut e = Engine {
        io,
        authority: e.authority,
        layout: l,
        status: e.status,
        displays: e.displays,
    };
    run(e.retire_planes()).unwrap();
    e.io.writes.clear();
    // Bookkeeping only: none of these reservations is dereferenced by release.
    let mapping = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 128 * 1024,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model-only owned address range, no CPU or device access.
    let pool = unsafe { Pool::from_owned_range(mapping, 0x8_0000_0000) }.unwrap();
    let mut surfaces = Surfaces::new();
    surfaces.0[0] = Some(buffers(&pool, 0, 4));
    surfaces.1.push(buffers(&pool, 0, 8));
    surfaces.0[1] = Some(buffers(&pool, 1, 4));
    surfaces.1.push(buffers(&pool, 1, 8));
    e.status.surfaces[0] = Some(surfaces.0[0].as_ref().unwrap().applied);
    e.displays.parked[1].surfaces[1] = Some(surfaces.0[1].as_ref().unwrap().applied);
    e.displays.siblings = Siblings::of(&e.displays.parked[1]);
    (e, surfaces, pool)
}

fn dcn401_release_returns_only_the_retired_pipes_buffers() -> TestResult {
    for gated in [false, true] {
        let (mut e, mut surfaces, pool) = fixture();
        let l = e.layout;
        if gated {
            e.io.gated = 1;
            e.io.regs.insert(l.pg(0, false), 0x100);
            e.io.regs.insert(l.pg(0, true), 0x8000_0000);
            e.status.planes_retired = Some(PlanesRetired {
                blanked: 0xe,
                powered_off: 1,
            });
        }
        let before = pool.available();
        let sibling = e.displays.parked[1];
        let released_address = e.status.surfaces[0].unwrap().address;
        // SAFETY: all model reservations have no CPU or other-engine access.
        assert_eq!(unsafe { surfaces.release(&mut e, 0) }, Ok(48 * 1024));
        assert_eq!(pool.available(), before + 48 * 1024);
        assert!(e.status.surfaces[0].is_none());
        assert_eq!(e.displays.parked[1], sibling);
        assert_eq!(e.io.writes, [(0x7f000, 0)]);
        assert!(surfaces.back_framebuffer(0).is_err());
        assert!(surfaces.back_framebuffer(1).is_ok());
        assert_eq!(surfaces.1.len(), 1);
        assert_eq!(surfaces.1[0].applied.request.pipe, 1);
        let reused = pool.reserve(48 * 1024).unwrap();
        assert_eq!(reused.address(), released_address);
        drop(reused);
        // Releasing twice is harmless; no stale reports recreate the buffers.
        // SAFETY: as above.
        assert_eq!(unsafe { surfaces.release(&mut e, 0) }, Ok(0));
        drop(surfaces);
        assert_eq!(
            pool.available(),
            before + 48 * 1024,
            "sibling allocations leaked back to pool"
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-release",
    dcn401_release_returns_only_the_retired_pipes_buffers
);

fn dcn401_release_requires_fresh_idle_evidence_before_and_after_flush() -> TestResult {
    let (e, _, _) = fixture();
    let l = e.layout;
    let faults = [
        (l.hubp(0, HUBP_CONTROL), 0),
        (l.hubp(0, HUBP_CONTROL), 0x1003),
        (l.hubp(0, HUBP_CLOCK), 1),
        (l.hubp(0, FLIP), 0x100),
        (l.hubp(0, FLIP), 0x200),
        (l.hubp(0, FLIP2), 0x100),
        (l.hubp(0, CURSOR), 1),
        (l.hubp(0, DMDATA), 1),
        (l.hubp(0, LUT3D), 1),
        (l.hubp(0, MALL), 0x10),
        (l.pg(0, false), 0x101),
        (l.pg(0, true), 0x4000_0000),
        (l.out_mux(0), 0),
        (l.mpcc(0, 0), 0),
        (l.mpcc(0, 0xe), 2),
        (l.mpcc(0, 5), 0x7f),
        (l.otg(0, CONTROL), 1),
        (l.otg(0, LOCK), 1),
        (l.otg(0, GSL), 1),
        (l.mpc_base + 0x2c5 * 4, 1),
        (l.nbio + 0x12d * 4, 0),
        (l.nbio + 0xc3 * 4, u32::MAX),
    ];
    for late in [false, true] {
        for (at, value) in faults {
            let (mut e, mut surfaces, pool) = fixture();
            let before = pool.available();
            if late {
                e.io.after_flush = Some((at, value));
            } else {
                e.io.regs.insert(at, value);
            }
            // SAFETY: no memory access in the model, even for malformed hardware.
            let result = unsafe { surfaces.release(&mut e, 0) };
            assert!(result.is_err(), "accepted {at:#x}={value:#x}, late={late}");
            assert!(e.status.surfaces[0].is_some());
            if late {
                assert!(matches!(e.status.state, State::Failed(_)));
            }
            drop(surfaces);
            assert_eq!(pool.available(), before, "released uncertain ownership");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-release",
    dcn401_release_requires_fresh_idle_evidence_before_and_after_flush
);

fn dcn401_release_refuses_partial_retirement_siblings_and_revocation() -> TestResult {
    for state in [
        State::Ready,
        State::RetiringPlanes,
        State::PreparingSurface(0),
        State::StoppingScanout(0),
        State::Flipping(0),
        State::Failed(Error::Busy),
    ] {
        let (mut e, mut surfaces, pool) = fixture();
        e.status.state = state;
        let before = pool.available();
        // SAFETY: model-only reservations and accesses.
        assert_eq!(unsafe { surfaces.release(&mut e, 0) }, Err(Error::Busy));
        assert!(e.io.writes.is_empty());
        drop(surfaces);
        assert_eq!(pool.available(), before);
    }
    for late in [false, true] {
        let (mut e, mut surfaces, pool) = fixture();
        let before = pool.available();
        // SAFETY: model-only. The selected display cannot release its sibling.
        assert_eq!(unsafe { surfaces.release(&mut e, 1) }, Err(Error::Busy));
        // SAFETY: model-only; invalid pipe must reject before indexing/MMIO.
        assert_eq!(unsafe { surfaces.release(&mut e, 4) }, Err(Error::Invalid));
        if late {
            e.io.revoke = Some(e.authority);
        } else {
            e.authority.revoke();
        }
        // SAFETY: model-only reservations.
        assert_eq!(unsafe { surfaces.release(&mut e, 0) }, Err(Error::Revoked));
        drop(surfaces);
        assert_eq!(pool.available(), before);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-release",
    dcn401_release_refuses_partial_retirement_siblings_and_revocation
);

fn dcn401_release_waits_for_cpu_views_and_retains_cancelled_drains() -> TestResult {
    use crate::scanout_access;
    let (mut e, mut surfaces, pool) = fixture();
    let before = pool.available();
    // SAFETY: a simulated CPU view, no pointer or framebuffer escapes.
    let view = unsafe { scanout_access::snapshot(|| ()) };
    scanout_access::replace(|| {});
    {
        let mut release = core::pin::pin!(async {
            scanout_access::wait_retired().await;
            // SAFETY: CPU view drained; model has no other engine references.
            unsafe { surfaces.release(&mut e, 0) }
        });
        assert_eq!(
            release
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
    }
    assert!(e.io.writes.is_empty());
    assert_eq!(pool.available(), before);
    drop(view);
    run(scanout_access::wait_retired());
    // SAFETY: outstanding CPU access is now drained, model-only hardware.
    assert_eq!(unsafe { surfaces.release(&mut e, 0) }, Ok(48 * 1024));
    assert_eq!(pool.available(), before + 48 * 1024);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-release",
    dcn401_release_waits_for_cpu_views_and_retains_cancelled_drains
);

fn dcn401_unlit_abort_retires_staging_before_reclaiming() -> TestResult {
    for state in [
        State::SurfacePrepared,
        State::MemoryPrepared,
        State::Prepared,
        State::BlankPrepared,
        State::DppPrepared,
        State::MpcPrepared,
        State::RequestorPrepared,
        State::DeadlinesPrepared,
        State::DpPhyDisabled,
        State::HpoDpDisabled,
        State::FrlDisabled,
    ] {
        let (mut e, mut surfaces, pool) = fixture();
        let before = pool.available();
        let sibling = e.displays.parked[1];
        let l = e.layout;
        e.status.state = state;
        // A staged, connected MPC tree with fetch never started. Native abort
        // must disconnect it even though no successful ScanoutRunning exists.
        e.io.regs.insert(l.out_mux(0), 0);
        e.io.regs.insert(l.mpcc(0, 0), 0);
        e.io.regs.insert(l.mpcc(0, 2), 0);
        assert_eq!(run(e.retire(0)), Ok(()));
        assert_eq!(pool.available(), before);
        assert!(run(e.retire_planes()).is_ok());
        assert_eq!(pool.available(), before);
        assert_eq!(e.io.regs[&l.out_mux(0)], 0xf);
        // SAFETY: model-only unpublished buffers; timing and planes retired.
        assert_eq!(unsafe { surfaces.release(&mut e, 0) }, Ok(48 * 1024));
        assert_eq!(pool.available(), before + 48 * 1024);
        assert_eq!(e.displays.parked[1], sibling);
        assert!(surfaces.0[0].is_none());
        assert!(surfaces.0[1].is_some());
        assert!(surfaces.1.iter().all(|s| s.applied.request.pipe == 1));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-release",
    dcn401_unlit_abort_retires_staging_before_reclaiming
);

fn dcn401_unlit_abort_refuses_live_failed_and_uncertain_hardware() -> TestResult {
    for state in [
        State::PreparingSurface(0),
        State::PreparingMemory(0),
        State::Preparing(0),
        State::DpLinkTrained(0),
        State::UhbrLinkTrained(0),
        State::HdmiLinkReady(0),
        State::FrlLinkActive(0),
        State::ScanoutRunning(0),
        State::Failed(Error::Readback(0)),
    ] {
        let (mut e, mut surfaces, pool) = fixture();
        let before = pool.available();
        e.status.state = state;
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        // SAFETY: model-only allocations; every live/unknown state must refuse.
        assert_eq!(unsafe { surfaces.release(&mut e, 0) }, Err(Error::Busy));
        assert!(e.io.writes.is_empty());
        drop(surfaces);
        assert_eq!(pool.available(), before);
    }
    for flip in [false, true] {
        let (mut e, mut surfaces, pool) = fixture();
        let before = pool.available();
        e.status.state = State::DeadlinesPrepared;
        let l = e.layout;
        if flip {
            // Timing retirement is insufficient: an unexpected pending flip
            // blocks the later plane drain and preserves every allocation.
            assert_eq!(run(e.retire(0)), Ok(()));
            e.io.regs.insert(l.hubp(0, 0x613), 0x100);
            assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        } else {
            // Historical staging never overrides a newly active stream.
            let (at, mask) = l
                .idle
                .iter()
                .copied()
                .find(|&(at, mask)| {
                    mask != 0
                        && !e.sibling_register(at)
                        && !(0..4).any(|p| at == l.otg(p, CONTROL) || at == l.otg(p, CLOCK))
                })
                .unwrap();
            e.io.regs.insert(at, mask);
            assert_eq!(run(e.retire(0)), Err(Error::Busy));
            assert!(e.io.writes.is_empty());
        }
        // SAFETY: model-only; partial retirement has no release permission.
        assert_eq!(unsafe { surfaces.release(&mut e, 0) }, Err(Error::Busy));
        drop(surfaces);
        assert_eq!(pool.available(), before);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-release",
    dcn401_unlit_abort_refuses_live_failed_and_uncertain_hardware
);
