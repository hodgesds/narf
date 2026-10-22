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
    fixture_pipes(p, 0, bytes)
}
/// `fixture` with the pipes in `extra` powered and retired too, ready for
/// overlay planes.
fn fixture_pipes(p: u8, extra: u8, bytes: usize) -> (Vec<u32>, Pool, Engine<SurfaceIo>, Surfaces) {
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
    let pipes = 1 << p | extra;
    let mut e = planes(0xf & !pipes);
    run(e.retire_planes()).unwrap();
    e.io.writes.clear();
    e.io.stall = 512 | 1024;
    e.io.regs.insert(e.layout.nbio + 0x12d * 4, 0x7f000);
    for (q, (r, value)) in (0..4u8)
        .filter(|q| pipes & 1 << q != 0)
        .flat_map(|q| HUBP_SEEDS.into_iter().map(move |seed| (q, seed)))
    {
        e.io.regs.insert(h(q, r), value);
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
        displays: e.displays,
    };
    (backing, pool, engine, Surfaces::new())
}
/// Each fixture pipe's inherited HUBP surface registers.
const HUBP_SEEDS: [(u64, u32); 19] = [
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
];
fn req(pipe: u8) -> SurfaceRequest {
    SurfaceRequest {
        surface: Default::default(),
        pipe,
        width: 65,
        height: 3,
        format: SurfaceFormat::Xrgb8888,
        odm: SplitPipes::NONE,
        mpc: SplitPipes::NONE,
        plane: None,
    }
}

/// Each format as Linux programs it, written out from
/// amdgpu_dm_plane_fill_dc_plane_info_and_addr (fourcc to DC format),
/// hubp2_program_pixel_format (SURFACE_PIXEL_FORMAT and the HUBPRET
/// CROSSBAR_SRC_CB_B/CR_R fields, shifts 20/22 in dcn_4_1_0_sh_mask.h),
/// dpp401_dpp_setup (CNVC_SURFACE_PIXEL_FORMAT, FORMAT_CONTROL ALPHA_EN)
/// and amdgpu_dm_plane_fill_blending_from_plane_state's alpha_formats with
/// the default pre-multiplied blend mode: (format, fourcc, bytes per pixel,
/// SURFACE_PIXEL_FORMAT, crossbar, CNVC format, ALPHA_EN, per-pixel alpha).
pub(super) type LinuxFormat = (SurfaceFormat, u32, u32, u32, u32, u32, u32, bool);
pub(super) const LINUX_FORMATS: [LinuxFormat; 17] = [
    (
        SurfaceFormat::Xrgb8888,
        0x3432_5258,
        4,
        8,
        0xe00000,
        8,
        1,
        false,
    ),
    (
        SurfaceFormat::Argb8888,
        0x3432_5241,
        4,
        8,
        0xe00000,
        8,
        1,
        true,
    ),
    (
        SurfaceFormat::Xbgr8888,
        0x3432_4258,
        4,
        8,
        0xb00000,
        8,
        1,
        false,
    ),
    (
        SurfaceFormat::Abgr8888,
        0x3432_4241,
        4,
        8,
        0xb00000,
        8,
        1,
        true,
    ),
    (
        SurfaceFormat::Xrgb2101010,
        0x3033_5258,
        4,
        10,
        0xe00000,
        10,
        1,
        false,
    ),
    (
        SurfaceFormat::Argb2101010,
        0x3033_5241,
        4,
        10,
        0xe00000,
        10,
        1,
        true,
    ),
    (
        SurfaceFormat::Xbgr2101010,
        0x3033_4258,
        4,
        10,
        0xb00000,
        10,
        1,
        false,
    ),
    (
        SurfaceFormat::Abgr2101010,
        0x3033_4241,
        4,
        10,
        0xb00000,
        10,
        1,
        true,
    ),
    (
        SurfaceFormat::Rgb565,
        0x3631_4752,
        2,
        3,
        0xe00000,
        3,
        0,
        false,
    ),
    (
        SurfaceFormat::Xrgb16161616f,
        0x4834_5258,
        8,
        24,
        0xe00000,
        24,
        1,
        false,
    ),
    (
        SurfaceFormat::Argb16161616f,
        0x4834_5241,
        8,
        24,
        0xe00000,
        24,
        1,
        true,
    ),
    (
        SurfaceFormat::Xbgr16161616f,
        0x4834_4258,
        8,
        24,
        0xb00000,
        25,
        1,
        false,
    ),
    // Linux's alpha_formats omits ABGR16161616F: it blends opaque.
    (
        SurfaceFormat::Abgr16161616f,
        0x4834_4241,
        8,
        24,
        0xb00000,
        25,
        1,
        false,
    ),
    (
        SurfaceFormat::Xrgb16161616,
        0x3834_5258,
        8,
        26,
        0xe00000,
        26,
        1,
        false,
    ),
    (
        SurfaceFormat::Argb16161616,
        0x3834_5241,
        8,
        26,
        0xe00000,
        26,
        1,
        true,
    ),
    (
        SurfaceFormat::Xbgr16161616,
        0x3834_4258,
        8,
        26,
        0xb00000,
        26,
        1,
        false,
    ),
    (
        SurfaceFormat::Abgr16161616,
        0x3834_4241,
        8,
        26,
        0xb00000,
        26,
        1,
        true,
    ),
];

/// Every format's fourcc, depth, linear pitch and HUBP words, and the
/// word-granular row upload at each depth.
fn dcn401_surface_programs_every_format_as_linux() -> TestResult {
    for (format, fourcc, bpp, hubp, crossbar, _, _, alpha) in LINUX_FORMATS {
        assert_eq!(SurfaceFormat::from_fourcc(fourcc), Some(format));
        assert_eq!(format.fourcc(), fourcc);
        assert_eq!(format.bytes_per_pixel(), bpp);
        assert_eq!(format.per_pixel_alpha(), alpha);
        // 65 pixels: 130, 260 or 520 bytes, each rounded up to 256.
        let pitch = match bpp {
            2 => 256,
            4 => 512,
            _ => 768,
        };
        let p = 1;
        let (_backing, pool, mut e, mut surfaces) = fixture(p, 8192);
        let request = SurfaceRequest { format, ..req(p) };
        let applied = run(surfaces.prepare(&mut e, &pool, request)).unwrap();
        assert_eq!(applied.pitch_bytes, pitch);
        assert_eq!(applied.bytes, 3 * u64::from(pitch));
        for (r, expected) in [
            (0x5e5, 0x40000000 | hubp),
            (0x607, 0x40000000 | (pitch / bpp - 1)),
            (0x66d, 0x40008000 | crossbar),
            (0x5eb, 0x40034041),
        ] {
            assert_eq!(e.io.inner.regs[&h(p, r)], expected);
        }
        // Words start on a word and stay within the row's pixels.
        let words = (65 * bpp).div_ceil(4) as usize;
        let row = alloc::vec![0x0102_0304u32; words];
        assert_eq!(surfaces.upload(&mut e, p, 0, 1, &row), Ok(()));
        let more = alloc::vec![0u32; words + 1];
        assert_eq!(surfaces.upload(&mut e, p, 0, 1, &more), Err(Error::Invalid));
        // SAFETY: reads stay inside the test's owned heap mapping.
        let last = unsafe { e.io.map.read32(u64::from(pitch) + 4 * (words as u64 - 1)) };
        assert_eq!(last, 0x0102_0304);
        // SAFETY: as above; the padding past the row stays cleared.
        let padding = unsafe { e.io.map.read32(u64::from(pitch) + 4 * words as u64) };
        assert_eq!(padding, 0);
        if bpp == 2 {
            assert_eq!(surfaces.upload(&mut e, p, 1, 1, &[1]), Err(Error::Invalid));
            assert_eq!(surfaces.upload(&mut e, p, 64, 1, &[1]), Ok(()));
            assert_eq!(
                surfaces.upload(&mut e, p, 64, 1, &[1, 2]),
                Err(Error::Invalid)
            );
        }
        if bpp == 8 {
            assert_eq!(surfaces.upload(&mut e, p, 64, 1, &[1, 2]), Ok(()));
            assert_eq!(
                surfaces.upload(&mut e, p, 64, 1, &[1, 2, 3]),
                Err(Error::Invalid)
            );
        }
        drop(surfaces);
        assert_eq!(pool.available(), 4096);
    }
    for fourcc in [
        0,
        0x3432_5241 ^ 1,
        0x3432_4152, /* RA24, Linux refuses despite its format list */
    ] {
        assert_eq!(SurfaceFormat::from_fourcc(fourcc), None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_programs_every_format_as_linux
);

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
                (0x5ed, 0x40034041),
                (0x5f1, 0x40034041),
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
    // Switching back and forth between the two geometries reuses the
    // parked surfaces: no further VRAM is retired.
    for (request, expected) in [(req(1), first), (taller, moved), (req(1), first)] {
        e.status.state = State::PlanesRetired;
        e.io.flushed = false;
        e.io.address = expected.address;
        let again = run(surfaces.prepare(&mut e, &pool, request)).unwrap();
        if again != expected || pool.available() != left - 4096 {
            return TestResult::Fail("parked geometry not reused");
        }
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

fn dcn401_surface_reclaims_staged_buffers_and_restarts_without_vram_growth() -> TestResult {
    let (_backing, pool, mut e, mut surfaces) = fixture(1, 16384);
    let config = crate::amdgpu_gmc_navi48::DisplayContext {
        fb_base: 0x8_0000_0000,
        fb_top: 0xb_ffff_ffff,
        fb_offset: 0x1_0000_0000,
        root: 0x1_0000_4001,
        start: 0xc_0000_0000,
        end: 0xc_001f_ffff,
    };
    for height in [3, 4, 6, 3] {
        e.io.flushed = false;
        let applied =
            run(surfaces.prepare(&mut e, &pool, SurfaceRequest { height, ..req(1) })).unwrap();
        assert_eq!(applied.address, pool.address());
        run(surfaces.prepare_back(&mut e, &pool, 1, config)).unwrap();
        // The staging fixture deliberately leaves a pending flip. Retirement
        // must not infer that a stopped clock proves its completion.
        e.status.state = State::PlanesRetired;
        // SAFETY: model-only backing; no CPU or other-engine references escape.
        assert_eq!(unsafe { surfaces.release(&mut e, 1) }, Err(Error::Busy));
        assert_eq!(pool.available(), 8192);
        // Model the real scanout having latched, then run native plane teardown.
        *e.io.inner.regs.get_mut(&h(1, 0x613)).unwrap() &= !0x100;
        run(e.retire_planes()).unwrap();
        // SAFETY: no outstanding CPU views; model retired its only consumers.
        assert_eq!(unsafe { surfaces.release(&mut e, 1) }, Ok(8192));
        assert_eq!(pool.available(), 16384);
        assert!(e.status.surfaces[1].is_none());
        assert!(surfaces.back_framebuffer(1).is_err());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-release",
    dcn401_surface_reclaims_staged_buffers_and_restarts_without_vram_growth
);

/// A tiled and DCC NV12 / P010 surface (amdgpu_dm_plane_fill_gfx12_attrs_from_modifiers
/// and hubp401_program_surface_config / flip_and_addr): SW_MODE the GFX12
/// swizzle, PRIMARY/SECONDARY_SURFACE_DCC_EN set, PITCH and PITCH_C in
/// pixels less one, the VIDEO_420 pixel format, and the chroma address
/// (behind the luma at a block-aligned offset) written before the luma's.
/// Each plane's layout is the minimum amdgpu_display_verify_sizes takes for
/// a framebuffer of that size and modifier.
fn dcn401_surface_stages_tiled_dcc_video() -> TestResult {
    use crate::amdgpu_dcn401_otg::{DccBlock, PlaneSurface, Swizzle, Tiling};
    use crate::amdgpu_dm_modifiers as m;
    let tiling = Tiling {
        swizzle: Swizzle::S64K2D,
        dcc: Some(DccBlock::B128),
    };
    for (format, hubp, luma_cpp, chroma_cpp) in [
        (SurfaceFormat::Nv12, 64, 1, 2),
        (SurfaceFormat::P010, 66, 2, 4),
    ] {
        let p = 2;
        let request = SurfaceRequest {
            width: 64,
            height: 16,
            format,
            surface: PlaneSurface {
                tiling,
                ..PlaneSurface::LINEAR
            },
            ..req(p)
        };
        let b = request.bytes();
        // 64K_2D blocks: 256x256 at 1 byte, 256x128 at 2, 128x128 at 4.
        let (pitch, chroma_pitch) = (256 * luma_cpp, 512);
        assert_eq!(b.pitch_bytes, pitch);
        assert_eq!(b.chroma, Some((65536, chroma_pitch)));
        assert_eq!(b.bytes, 2 * 65536);
        // The same layout as a framebuffer passes amdgpu's size checks.
        let info = m::format_info(format.fourcc()).unwrap();
        let mut cmd = m::FbCmd {
            width: 64,
            height: 16,
            pixel_format: format.fourcc(),
            flags: m::FB_MODIFIERS,
            ..Default::default()
        };
        cmd.handles[..2].copy_from_slice(&[1, 1]);
        cmd.pitches[..2].copy_from_slice(&[pitch, chroma_pitch]);
        cmd.offsets[1] = 65536;
        cmd.modifier[..2].copy_from_slice(&[tiling.modifier(); 2]);
        assert_eq!(
            m::verify_sizes(&info, &cmd, tiling.modifier(), b.bytes),
            Ok(())
        );
        assert!(m::verify_sizes(&info, &cmd, tiling.modifier(), b.bytes - 1).is_err());
        let (_backing, pool, mut e, mut surfaces) = fixture(p, 2 * 65536 + 8192);
        let applied = run(surfaces.prepare(&mut e, &pool, request)).unwrap();
        assert_eq!((applied.pitch_bytes, applied.bytes), (pitch, b.bytes));
        let chroma = applied.address + 65536;
        for (r, mask, value) in [
            (0x5e7, 7, 3),
            (0x612, 0x213, 0x202),
            (0x607, 0xffff, pitch / luma_cpp - 1),
            (0x608, 0xffff, chroma_pitch / chroma_cpp - 1),
            (0x5e5, 0x17f, hubp),
            (0x60c, u32::MAX, chroma as u32),
            (0x60d, 0xffff, (chroma >> 32) as u32),
            (0x60a, u32::MAX, applied.address as u32),
        ] {
            assert_eq!(e.io.inner.regs[&h(p, r)] & mask, value, "reg {r:#x}");
        }
        // hubp401_program_surface_flip_and_addr's order: chroma high, chroma
        // low, luma high, luma low.
        let order: Vec<u64> =
            e.io.inner
                .writes
                .iter()
                .map(|&(at, _)| at)
                .filter(|&at| (0x60a..=0x60d).any(|r| at == h(p, r)))
                .collect();
        assert_eq!(
            order[order.len() - 4..],
            [h(p, 0x60d), h(p, 0x60c), h(p, 0x60b), h(p, 0x60a)]
        );
        drop(surfaces);
    }
    // A DCC modifier on a linear swizzle is not one the planes list.
    assert_eq!(
        Tiling::from_modifier(
            Tiling {
                swizzle: Swizzle::Linear,
                dcc: Some(DccBlock::B64)
            }
            .modifier()
        ),
        None
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_stages_tiled_dcc_video
);

/// A tiled surface turned 90 or 270 degrees: hubp2_program_rotation's
/// ROTATION_ANGLE (1 or 3, no H_MIRROR_EN: amdgpu_dm never mirrors) beside
/// the pixel format, and hubp401_set_viewport's viewport in surface space
/// (SPL's orthogonal viewport, 64x32 for a 64x32 source shown 32x64). DML
/// scans it vertically. A linear surface turned so, or a 90/270 plane
/// without a layout's tiling, is `Unsupported` before anything is touched.
fn dcn401_surface_stages_rotated_tiled_planes() -> TestResult {
    use crate::amdgpu_dcn401_otg::{DccBlock, PlaneLayout, PlaneSurface, Swizzle, Tiling};
    use crate::amdgpu_dcn401_spl::{Rect, Rotation};
    let tiling = Tiling {
        swizzle: Swizzle::S64K2D,
        dcc: Some(DccBlock::B256),
    };
    let request = |rotation, tiling| SurfaceRequest {
        width: 64,
        height: 32,
        surface: PlaneSurface {
            tiling,
            ..PlaneSurface::LINEAR
        },
        plane: Some(PlaneLayout {
            src: Rect::new(0, 0, 64, 32),
            dst: Rect::new(100, 50, 32, 64),
            stream_width: 1920,
            stream_height: 1080,
            ycbcr420: false,
            rotation,
            blend: Blend::default_for(SurfaceFormat::Xrgb8888),
            underlay: false,
        }),
        ..req(1)
    };
    for (rotation, angle) in [(Rotation::R90, 1), (Rotation::R270, 3)] {
        let r = request(rotation, tiling);
        if r.check().is_err() || !r.dml_plane().vertical_scan {
            return TestResult::Fail("rotated tiled plane refused");
        }
        let scaler = r.scalers().next().unwrap().1;
        if (scaler.viewport.width, scaler.viewport.height) != (64, 32)
            || (scaler.recout.width, scaler.recout.height) != (32, 64)
        {
            return TestResult::Fail("rotated viewport and recout");
        }
        let (_backing, pool, mut e, mut surfaces) = fixture(1, 65536 + 8192);
        let Ok(applied) = run(surfaces.prepare(&mut e, &pool, r)) else {
            return TestResult::Fail("rotated tiled plane not staged");
        };
        if applied.bytes != 65536 {
            return TestResult::Fail("rotated tiled bytes");
        }
        let reg = |at: u64, mask: u32| e.io.inner.regs[&h(1, at)] & mask;
        if reg(0x5e5, 0xf7f) != 8 | angle << 8
            || reg(0x5e7, 7) != Swizzle::S64K2D as u32
            || reg(0x612, 0x202) != 0x202
            || reg(0x5eb, 0x3fff_3fff) != 32 << 16 | 64
            || reg(0x5e9, u32::MAX) != 0
        {
            return TestResult::Fail("rotated HUBP surface registers");
        }
        drop(surfaces);
        let linear = request(rotation, Tiling::LINEAR);
        let (_backing, pool, mut e, mut surfaces) = fixture(1, 65536 + 8192);
        if linear.check() != Err(Error::Unsupported)
            || run(surfaces.prepare(&mut e, &pool, linear)) != Err(Error::Unsupported)
            || !e.io.inner.writes.is_empty()
        {
            return TestResult::Fail("rotated linear plane staged");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_stages_rotated_tiled_planes
);

/// MPC combine of a GFX12-tiled DCC plane turned 90 degrees and of a tiled
/// DCC NV12 frame (resource_build_scaling_params on each slice's pipe):
/// both pipes take the plane's tiling, DCC, rotation, pitch and addresses,
/// and each its own slice's viewport (hubp401_set_viewport). The turned
/// plane's slices split the stream's line, so they are bands along the
/// source's vertical axis (the same columns, other rows); the NV12 slices
/// split the luma columns, and their chroma viewports the chroma columns.
fn dcn401_surface_stages_split_rotated_and_video_planes() -> TestResult {
    use crate::amdgpu_dcn401_otg::{DccBlock, PlaneLayout, PlaneSurface, Swizzle, Tiling};
    use crate::amdgpu_dcn401_spl::{Rect, Rotation};
    let (p, slice) = (1u8, 3u8);
    let tiled = |dcc| PlaneSurface {
        tiling: Tiling {
            swizzle: Swizzle::S64K2D,
            dcc: Some(dcc),
        },
        ..PlaneSurface::LINEAR
    };
    let layout = |src: Rect, dst: Rect, rotation, format| PlaneLayout {
        src,
        dst,
        stream_width: dst.width as u32,
        stream_height: dst.height as u32,
        ycbcr420: false,
        rotation,
        blend: Blend::default_for(format),
        underlay: false,
    };
    let turned = SurfaceRequest {
        width: 256,
        height: 512,
        surface: tiled(DccBlock::B128),
        mpc: SplitPipes::one(slice),
        plane: Some(layout(
            Rect::new(0, 0, 256, 512),
            Rect::new(0, 0, 512, 256),
            Rotation::R90,
            SurfaceFormat::Xrgb8888,
        )),
        ..req(p)
    };
    let video = SurfaceRequest {
        width: 1024,
        height: 512,
        format: SurfaceFormat::Nv12,
        surface: tiled(DccBlock::B64),
        mpc: SplitPipes::one(slice),
        plane: Some(layout(
            Rect::new(0, 0, 1024, 512),
            Rect::new(0, 0, 1024, 512),
            Rotation::R0,
            SurfaceFormat::Nv12,
        )),
        ..req(p)
    };
    for r in [turned, video] {
        if r.check().is_err() {
            return TestResult::Fail("split plane refused");
        }
        let scalers: Vec<(u8, crate::amdgpu_dcn401_spl::Scaler)> = r.scalers().collect();
        let [(p0, s0), (p1, s1)] = scalers[..] else {
            return TestResult::Fail("two slices");
        };
        let (v0, v1) = (s0.viewport, s1.viewport);
        if (p0, p1) != (p, slice) || s0.recout.width + s1.recout.width != r.layout().dst.width {
            return TestResult::Fail("slice pipes and recouts");
        }
        if r.format.is_video() {
            let (c0, c1) = (s0.viewport_c, s1.viewport_c);
            if v0.y != v1.y
                || v1.x <= v0.x
                || v0.height != 512
                || c0.y != c1.y
                || c1.x <= c0.x
                || c0.height != 256
            {
                return TestResult::Fail("4:2:0 slices split luma and chroma columns");
            }
        } else if v0.x != v1.x || v0.width != 256 || v1.width != 256 || v0.y == v1.y {
            return TestResult::Fail("turned slices are row bands of the source");
        }
        let bytes = r.bytes().bytes as usize;
        let (_backing, pool, mut e, mut surfaces) = fixture_pipes(p, 1 << slice, bytes + 8192);
        let Ok(applied) = run(surfaces.prepare(&mut e, &pool, r)) else {
            return TestResult::Fail("split plane not staged");
        };
        let reg = |q: u8, at: u64| e.io.inner.regs.get(&h(q, at)).copied().unwrap_or(0);
        let angle = if r.format.is_video() { 0 } else { 1 };
        for (q, s) in [(p0, s0), (p1, s1)] {
            for (at, mask, value) in crate::amdgpu_dcn401_dscl::viewport(&s) {
                if reg(q, at) & mask != value & mask {
                    return TestResult::Fail("slice viewport registers");
                }
            }
            if reg(q, 0x5e5) & 0xf00 != angle << 8
                || reg(q, 0x5e7) & 7 != Swizzle::S64K2D as u32
                || reg(q, 0x612) & 0x202 != 0x202
                || reg(q, 0x607) & 0xffff != reg(p0, 0x607) & 0xffff
                || reg(q, 0x60a) != applied.address as u32
                || applied
                    .chroma_address(applied.address)
                    .is_some_and(|c| reg(q, 0x60c) != c as u32)
            {
                return TestResult::Fail("slice surface registers");
            }
        }
        drop(surfaces);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_surface_stages_split_rotated_and_video_planes
);

/// Linux maps fixed16 and FP16 into the same DML 444_64 source and scaler
/// class. Check the full placed surface, including tiled DCC rotation and
/// scaling, rather than admitting a fixed16 plane at the old 32-bit depth.
fn dcn401_unorm16_planes_keep_64bit_dml_and_scaler_geometry() -> TestResult {
    use crate::amdgpu_dcn401_otg::{DccBlock, PlaneSurface, Swizzle, Tiling};
    use crate::amdgpu_dcn401_spl::{Rect, Rotation};
    for format in [
        SurfaceFormat::Xrgb16161616,
        SurfaceFormat::Argb16161616,
        SurfaceFormat::Xbgr16161616,
        SurfaceFormat::Abgr16161616,
    ] {
        for tiled in [false, true] {
            let mut r = req(0);
            r.width = 512;
            r.height = 256;
            r.format = format;
            r.surface = PlaneSurface {
                tiling: if tiled {
                    Tiling {
                        swizzle: Swizzle::S64K2D,
                        dcc: Some(DccBlock::B128),
                    }
                } else {
                    Tiling::LINEAR
                },
                ..PlaneSurface::LINEAR
            };
            r.plane = Some(PlaneLayout {
                src: Rect::new(0, 0, 512, 256),
                dst: Rect::new(0, 0, 256, 128),
                stream_width: 256,
                stream_height: 128,
                ycbcr420: false,
                rotation: if tiled { Rotation::R90 } else { Rotation::R0 },
                blend: Blend::default_for(format),
                underlay: false,
            });
            assert_eq!(r.check(), Ok(()));
            let fp = SurfaceRequest {
                format: if format.per_pixel_alpha() {
                    SurfaceFormat::Argb16161616f
                } else {
                    SurfaceFormat::Xrgb16161616f
                },
                ..r
            };
            assert_eq!(r.bytes(), fp.bytes());
            assert_eq!(r.dml_plane(), fp.dml_plane());
            assert_eq!(r.bytes().pitch_bytes, 4096);
            assert_eq!(r.dml_plane().bytes_per_pixel, 8);
            assert!(r.scalers().all(|(_, s)| s.ok));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-surface",
    dcn401_unorm16_planes_keep_64bit_dml_and_scaler_geometry
);
