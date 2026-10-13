use super::*;
use crate::amdgpu_dcn401_otg::fetch::Surfaces;
use crate::amdgpu_vram::Pool;
#[path = "amdgpu_dcn401_vm_tests.rs"]
mod vm;

fn h(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0xdc) * 4
}
struct SurfaceIo {
    inner: Fake,
    flushed: bool,
    address: u64,
    map: MmioRegion,
}
impl Io for SurfaceIo {
    fn read(&mut self, at: u64) -> u32 {
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        if at == 0x7f000 {
            self.flushed = true;
        }
        for p in 0..4 {
            if at == h(p, 0x60a) {
                assert!(self.flushed, "surface published before CPU HDP flush");
                assert_eq!(
                    self.inner.regs[&h(p, 0x60b)] & 0xffff,
                    (self.address >> 32) as u32
                );
                assert_eq!(value, self.address as u32);
                assert_eq!(self.inner.regs[&h(p, 0x5f4)] & 0x1007, 3);
                assert_eq!(self.inner.regs[&h(p, 0x5f5)] & 1, 1);
                for offset in (0..4096).step_by(4) {
                    // SAFETY: fixture owns an aligned heap mapping for this test.
                    assert_eq!(unsafe { self.map.read32(offset) }, 0);
                }
            }
        }
        self.inner.write(at, value);
        if self.inner.reject == Some(self.inner.writes.len()) {
            return;
        }
        for p in 0..4 {
            if at == h(p, 0x60a) {
                // Never fake flip completion merely because the request was written.
                *self.inner.regs.entry(h(p, 0x613)).or_default() |= 0x100;
            }
        }
    }
}
fn fixture(p: u8, bytes: usize) -> (Vec<u32>, Pool, Engine<SurfaceIo>, Surfaces) {
    let mut backing = vec![0xdeadbeef; (bytes + 4096) / 4];
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90000000),
        virt: (backing.as_mut_ptr() as u64 + 4095) & !4095,
        len: bytes as u64,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model memory backed by the returned heap vector. Fake never
    // performs DMA; the vector outlives all CPU accesses in each test.
    let pool = unsafe { Pool::from_owned_range(map, 0x8_0010_2000) }.unwrap();
    let mut e = planes(0xf ^ (1 << p));
    run(e.retire_planes()).unwrap();
    e.io.writes.clear();
    e.io.stall = 512 | 1024;
    e.io.regs.insert(e.layout.nbio + 0x12d * 4, 0x7f000);
    for (r, value) in [
        (0x5e5, 0x40000f7f),
        (0x5e7, 0x40000087),
        (0x607, 0x4000abcd),
        (0x612, 0x40000313),
        (0x66d, 0x40f08000),
        (0x5e6, 0x13579),
        (0x5eb, 0x40014001),
        (0x5e9, 0x10001),
        (0x5ef, 0x40014001),
        (0x5ee, 0x10001),
        (0x5ed, 0x40014001),
        (0x5ec, 0x10001),
        (0x5f1, 0x40014001),
        (0x5f0, 0x10001),
        (0x609, 0x4000000f),
        (0x613, 0x400130f2),
        (0x614, 0x40000600),
        (0x60a, 0x12340000),
        (0x60b, 0x40000123),
    ] {
        e.io.regs.insert(h(p, r), value);
    }
    let engine = Engine {
        io: SurfaceIo {
            inner: e.io,
            flushed: false,
            address: pool.address(),
            map,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
    };
    (backing, pool, engine, Surfaces::new())
}
fn req(pipe: u8) -> SurfaceRequest {
    SurfaceRequest {
        pipe,
        width: 65,
        height: 3,
        format: SurfaceFormat::Xrgb8888,
    }
}

fn dcn401_surface_stages_owned_padded_rgb_on_every_pipe() -> TestResult {
    for p in 0..4 {
        for format in [SurfaceFormat::Xrgb8888, SurfaceFormat::Xbgr8888] {
            let (_backing, pool, mut e, mut surfaces) = fixture(p, 8192);
            let request = SurfaceRequest { format, ..req(p) };
            let applied = run(surfaces.prepare(&mut e, &pool, request)).unwrap();
            assert_eq!(applied.address, 0x8_0010_2000);
            assert_eq!(applied.pitch_bytes, 512);
            assert_eq!(applied.bytes, 1536);
            assert_eq!(e.status.surfaces[p as usize], Some(applied));
            assert_eq!(e.status.state, State::SurfacePrepared);
            assert_eq!(pool.available(), 4096);
            let crossbar = if format == SurfaceFormat::Xrgb8888 {
                0xe00000
            } else {
                0xb00000
            };
            for (r, expected) in [
                (0x5e5, 0x40000008),
                (0x5e7, 0x40000080),
                (0x607, 0x4000007f),
                (0x612, 0x40000110),
                (0x66d, 0x40008000 | crossbar),
                (0x5eb, 0x40034041),
                (0x5ef, 0x40034041),
                (0x5e9, 0),
                (0x5ee, 0),
                (0x5ed, 0x40004000),
                (0x5f1, 0x40004000),
                (0x5ec, 0),
                (0x5f0, 0),
                (0x609, 0x40000000),
                (0x613, 0x40000100),
                (0x614, 0x40000000),
                (0x60b, 0x40000008),
                (0x60a, 0x102000),
                (0x5e6, 0x13579),
            ] {
                assert_eq!(e.io.inner.regs[&h(p, r)], expected);
            }
            assert_eq!(e.io.inner.regs[&h(p, 0x5f5)] & 1, 0);
            assert_eq!(e.io.inner.regs[&h(p, 0x5f4)] & 0x1007, 3);
            assert_eq!(e.io.inner.writes.len(), 21);
            assert_eq!(e.io.inner.writes[18].0, h(p, 0x60b));
            assert_eq!(e.io.inner.writes[19].0, h(p, 0x60a));
            assert!(!e.io.inner.writes.iter().any(|(at, _)| *at == h(p, 0x5e6)));
            let count = e.io.inner.writes.len();
            assert_eq!(
                run(surfaces.prepare(&mut e, &pool, request)),
                Err(Error::Busy)
            );
            assert_eq!(e.io.inner.writes.len(), count);
            // Even a stopped fetcher may still hold the programmed address.
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_stages_owned_padded_rgb_on_every_pipe
);

fn dcn401_surface_validates_before_allocation_or_register_writes() -> TestResult {
    // Highest representable GPU page and maximum viewport width: pitch must
    // round up without wrapping, including the last padding pixel.
    let (_backing, old_pool, mut e, mut surfaces) = fixture(3, 65536);
    drop(old_pool);
    let address = (1 << 48) - 65536;
    // SAFETY: same heap-backed model mapping, with no other reservations.
    let pool = unsafe { Pool::from_owned_range(e.io.map, address) }.unwrap();
    e.io.address = address;
    let request = SurfaceRequest {
        width: 0x3fff,
        height: 1,
        ..req(3)
    };
    let applied = run(surfaces.prepare(&mut e, &pool, request)).unwrap();
    assert_eq!(applied.pitch_bytes, 65536);
    assert_eq!(applied.address + applied.bytes, 1 << 48);
    // SAFETY: last word remains within the fixture's heap mapping.
    assert_eq!(unsafe { e.io.map.read32(65532) }, 0);
    assert_eq!(e.io.inner.regs[&h(3, 0x60b)] & 0xffff, 0xffff);
    for request in [
        SurfaceRequest { width: 0, ..req(0) },
        SurfaceRequest {
            height: 0,
            ..req(0)
        },
        SurfaceRequest {
            width: 0x4000,
            ..req(0)
        },
        SurfaceRequest {
            height: 0x4000,
            ..req(0)
        },
        req(4),
    ] {
        let (_backing, pool, mut e, mut surfaces) = fixture(0, 4096);
        assert_eq!(
            run(surfaces.prepare(&mut e, &pool, request)),
            Err(Error::Invalid)
        );
        assert!(e.io.inner.writes.is_empty());
        assert_eq!(pool.available(), 4096);
    }
    let (_backing, pool, mut e, mut surfaces) = fixture(0, 4096);
    assert_eq!(
        run(surfaces.prepare(
            &mut e,
            &pool,
            SurfaceRequest {
                width: 0x3fff,
                height: 0x3fff,
                ..req(0)
            }
        )),
        Err(Error::Allocation)
    );
    assert!(e.io.inner.writes.is_empty());
    for (at, value) in [
        (h(0, 0x5f4), 1),
        (h(0, 0x613), 0x100),
        (h(0, 0x613), 0x200),
        (h(0, 0x5e7), 0),
        (h(0, 0x5e7), 0x100),
        (h(0, 0x685), 4),
        (MPC_BASE, 0),
        (BASE + 0x1b43 * 4, 1),
        (e.layout.nbio + 0x12d * 4, 0),
    ] {
        let (_backing, pool, mut e, mut surfaces) = fixture(0, 4096);
        e.io.inner.regs.insert(at, value);
        assert_eq!(
            run(surfaces.prepare(&mut e, &pool, req(0))),
            Err(Error::Busy)
        );
        assert!(e.io.inner.writes.is_empty());
        assert_eq!(pool.available(), 4096);
    }
    // Gated HUBP must be refused without reading its surface registers.
    let (_backing, pool, mut e, mut surfaces) = fixture(1, 4096);
    assert_eq!(
        run(surfaces.prepare(&mut e, &pool, req(0))),
        Err(Error::Busy)
    );
    assert!(e.io.inner.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_validates_before_allocation_or_register_writes
);

fn dcn401_surface_upload_bounds_authority_and_live_configuration() -> TestResult {
    let (_backing, pool, mut e, mut surfaces) = fixture(2, 8192);
    run(surfaces.prepare(&mut e, &pool, req(2))).unwrap();
    assert_eq!(
        surfaces.upload(&mut e, 2, 63, 2, &[0x112233, 0x445566]),
        Ok(())
    );
    for (offset, expected) in [
        (1024 + 252, 0x112233),
        (1024 + 256, 0x445566),
        (1024 + 260, 0),
    ] {
        // SAFETY: reads stay inside the test's owned heap mapping.
        assert_eq!(unsafe { e.io.map.read32(offset) }, expected);
    }
    assert_eq!(e.io.inner.writes.last(), Some(&(0x7f000, 0)));
    let count = e.io.inner.writes.len();
    for (pipe, x, y, pixels) in [
        (4, 0, 0, &[1][..]),
        (2, 65, 0, &[1][..]),
        (2, 64, 2, &[1, 2][..]),
        (2, 0, 3, &[1][..]),
        (2, u32::MAX, 0, &[1][..]),
        (2, 0, 0, &[][..]),
    ] {
        assert_eq!(
            surfaces.upload(&mut e, pipe, x, y, pixels),
            Err(Error::Invalid)
        );
    }
    assert_eq!(e.io.inner.writes.len(), count);
    e.io.inner.regs.insert(h(2, 0x60b), 9);
    assert_eq!(
        surfaces.upload(&mut e, 2, 0, 0, &[1]),
        Err(Error::Readback(h(2, 0x60b)))
    );
    e.io.inner.regs.insert(h(2, 0x60b), 8);
    e.io.inner.revoke = Some((count + 1, e.authority));
    assert_eq!(surfaces.upload(&mut e, 2, 0, 0, &[1]), Err(Error::Revoked));
    assert_eq!(e.status.state, State::Failed(Error::Revoked));
    assert!(e.status.surfaces[2].is_none());
    assert_eq!(surfaces.upload(&mut e, 2, 0, 0, &[1]), Err(Error::Busy));
    drop(surfaces);
    assert_eq!(pool.available(), 4096);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_upload_bounds_authority_and_live_configuration
);

fn dcn401_surface_partial_programming_retains_backing_and_blocks_replay() -> TestResult {
    for n in 1..=21 {
        for revoke in [false, true] {
            let (_backing, pool, mut e, mut surfaces) = fixture(0, 8192);
            if revoke {
                e.io.inner.revoke = Some((n, e.authority));
            } else {
                e.io.inner.gone = Some(n);
            }
            let error = if revoke {
                Error::Revoked
            } else {
                Error::DeviceGone
            };
            assert_eq!(run(surfaces.prepare(&mut e, &pool, req(0))), Err(error));
            assert_eq!(e.status.state, State::Failed(error));
            assert!(e.status.surfaces[0].is_none());
            assert_eq!(
                run(surfaces.prepare(&mut e, &pool, req(0))),
                Err(Error::Busy)
            );
            assert_eq!(run(e.set_hubp_power(0, false)), Err(Error::Busy));
            assert_eq!(e.io.inner.writes.len(), n);
            drop(surfaces);
            assert_eq!(pool.available(), if n == 1 { 8192 } else { 4096 });
        }
        if n == 1 {
            continue;
        } // native HDP flush has no writable readback field
        let (_backing, pool, mut e, mut surfaces) = fixture(0, 8192);
        e.io.inner.reject = Some(n);
        assert!(matches!(
            run(surfaces.prepare(&mut e, &pool, req(0))),
            Err(Error::Readback(_))
        ));
        assert!(!e.status.state.reusable());
        assert_eq!(e.io.inner.writes.len(), n);
        drop(surfaces);
        assert_eq!(pool.available(), 4096);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_partial_programming_retains_backing_and_blocks_replay
);

fn dcn401_surface_cancellation_before_and_after_publication_is_retained() -> TestResult {
    for before in [false, true] {
        let (_backing, pool, mut e, mut surfaces) = fixture(0, 131072);
        let request = if before {
            SurfaceRequest {
                width: 1024,
                height: 32,
                ..req(0)
            }
        } else {
            req(0)
        };
        if !before {
            e.io.inner.after_write = Some((20, h(0, 0x5f4), 1));
        }
        {
            let mut f = core::pin::pin!(surfaces.prepare(&mut e, &pool, request));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::PreparingSurface(0));
        assert!(e.status.surfaces[0].is_none());
        assert_eq!(e.io.inner.writes.len(), if before { 0 } else { 20 });
        assert_eq!(
            run(surfaces.prepare(&mut e, &pool, req(0))),
            Err(Error::Busy)
        );
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        drop(surfaces);
        assert_eq!(pool.available(), if before { 131072 } else { 126976 });
    }
    // A late incompatible consumer cannot turn a staged address into success.
    let (_backing, pool, mut e, mut surfaces) = fixture(0, 8192);
    e.io.inner.after_write = Some((21, BASE + 0x20bd * 4, 1));
    assert_eq!(
        run(surfaces.prepare(&mut e, &pool, req(0))),
        Err(Error::Busy)
    );
    assert_eq!(e.status.state, State::Failed(Error::Busy));
    drop(surfaces);
    assert_eq!(pool.available(), 4096);
    // Revocation between clearing chunks must prevent the next CPU write too.
    let (_backing, pool, mut e, mut surfaces) = fixture(0, 131072);
    let cap = e.authority;
    {
        let request = SurfaceRequest {
            width: 1024,
            height: 32,
            ..req(0)
        };
        let mut f = core::pin::pin!(surfaces.prepare(&mut e, &pool, request));
        assert!(f
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        cap.revoke();
        assert_eq!(run(f), Err(Error::Revoked));
    }
    assert_eq!(e.status.state, State::Failed(Error::Revoked));
    assert!(e.io.inner.writes.is_empty());
    // SAFETY: this word lies inside the fixture's heap mapping.
    assert_eq!(unsafe { e.io.map.read32(65532) }, 0);
    // SAFETY: this word also lies inside the fixture's heap mapping.
    assert_eq!(unsafe { e.io.map.read32(65536) }, 0xdeadbeef);
    drop(surfaces);
    assert_eq!(pool.available(), 131072);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_cancellation_before_and_after_publication_is_retained
);

fn dcn401_surface_restages_a_retired_pipe_reusing_only_the_same_geometry() -> TestResult {
    let (_backing, pool, mut e, mut surfaces) = fixture(1, 16384);
    let first = run(surfaces.prepare(&mut e, &pool, req(1))).unwrap();
    let left = pool.available();
    // Occupied and not freshly retired: refused before any write.
    let count = e.io.inner.writes.len();
    assert_eq!(
        run(surfaces.prepare(&mut e, &pool, req(1))),
        Err(Error::Busy)
    );
    assert_eq!(e.io.inner.writes.len(), count);
    // Retired, but a HUBP fetches again: no fresh evidence, no restage.
    e.status.state = State::PlanesRetired;
    let control = e.io.inner.regs[&h(1, 0x5f4)];
    e.io.inner.regs.insert(h(1, 0x5f4), control & !7);
    assert_eq!(
        run(surfaces.prepare(&mut e, &pool, req(1))),
        Err(Error::Busy)
    );
    assert_eq!(e.io.inner.writes.len(), count);
    e.io.inner.regs.insert(h(1, 0x5f4), control);
    // The same geometry reuses (and re-clears) the buffer after teardown,
    // including after the modeset's HUBP power-up.
    // SAFETY: the fixture's heap-backed model VRAM.
    unsafe { e.io.map.write32(0, 0x1234) };
    for state in [State::PlanesRetired, State::HubpPowerChanged] {
        e.status.state = state;
        e.io.flushed = false;
        let again = run(surfaces.prepare(&mut e, &pool, req(1))).unwrap();
        if again != first || pool.available() != left {
            return TestResult::Fail("same geometry not reused");
        }
        // SAFETY: as above.
        if unsafe { e.io.map.read32(0) } != 0 {
            return TestResult::Fail("reused buffer not cleared");
        }
    }
    // A new geometry gets a new buffer; the published old range is never
    // returned to the pool, even when the surfaces are dropped.
    e.status.state = State::PlanesRetired;
    e.io.flushed = false;
    e.io.address = first.address + 4096;
    let taller = SurfaceRequest {
        height: 4,
        ..req(1)
    };
    let moved = run(surfaces.prepare(&mut e, &pool, taller)).unwrap();
    if moved.address != first.address + 4096 || pool.available() != left - 4096 {
        return TestResult::Fail("new geometry");
    }
    drop(surfaces);
    if pool.available() != left - 4096 {
        return TestResult::Fail("published ranges returned to the pool");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_restages_a_retired_pipe_reusing_only_the_same_geometry
);
