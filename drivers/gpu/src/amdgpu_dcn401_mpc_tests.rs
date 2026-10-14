use super::*;
#[path = "amdgpu_dcn401_requestor_tests.rs"]
mod requestor;

// Native bank-3 addresses, independently checked by tests/dcn401_mpc.c.
fn rgb(p: u8, depth: ColorDepth) -> [(u64, u32, u32); 20] {
    let m = MPC_BASE + u64::from(p) * 0x15 * 4;
    let o = MPC_BASE + u64::from(p) * 0x5e * 4;
    let c = MPC_BASE + u64::from(p) * 0xb0 * 4;
    let out = MPC_BASE + u64::from(p) * 4 * 4;
    let bits = match depth {
        ColorDepth::Bpc8 => 2,
        ColorDepth::Bpc10 => 4,
        ColorDepth::Bpc12 => 6,
    };
    [
        (m + 3 * 4, 0xffff0ff3, 0xffff0422),
        (m + 4 * 4, 0x3033f, 0),
        (m + 6 * 4, 0x7ffff, 0x1f000),
        (m + 7 * 4, 0x7ffff, 0x1f000),
        (m + 8 * 4, 0x7ffff, 0x1f000),
        (m + 0xa * 4, 0xfff, 0),
        (m + 0xb * 4, 0xfff, 0),
        (m + 0xc * 4, 0xfff, 0),
        (m + 9 * 4, 1, 0),
        (o + 0x7e * 4, 3, 0),
        (o + 0xc9 * 4, 3, 0),
        (c + 0x453 * 4, 3, 0),
        (c + 0x48a * 4, 3, 0),
        (c + 0x493 * 4, 3, 0),
        (c + 0x4de * 4, 3, 0),
        (c + 0x4ec * 4, 3, 0),
        (MPC_BASE + (0x30b + u64::from(p) * 0xd) * 4, 3, 0),
        (out + 0x2f3 * 4, 0x7ffffff, bits << 24 | 0xfff000),
        (out + 0x2f4 * 4, 0xffffff, 0xfff000),
        (out + 0x2f5 * 4, 0xffffff, 0xfff000),
    ]
}
fn ready_mpc(
    p: u8,
    depth: ColorDepth,
) -> (Vec<u32>, Pool, Engine<MemoryIo>, Surfaces, dccg::Applied) {
    ready_mpc_with(p, depth, small(p))
}
fn ready_mpc_with(
    p: u8,
    depth: ColorDepth,
    mode: Mode,
) -> (Vec<u32>, Pool, Engine<MemoryIo>, Surfaces, dccg::Applied) {
    ready_mpc_range(p, depth, mode, false)
}
fn ready_mpc_range(
    p: u8,
    depth: ColorDepth,
    mode: Mode,
    limited: bool,
) -> (Vec<u32>, Pool, Engine<MemoryIo>, Surfaces, dccg::Applied) {
    let (backing, pool, mut e, mut surfaces, clock) = ready_range(p, depth, mode, limited);
    e.io.delay = [0; 2]; // DPP acknowledgement timing is covered by its own tests.
    run(surfaces.prepare_dpp(&mut e, p, || Ok((clock, config())))).unwrap();
    let mut e = Engine {
        io: e.io.memory,
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    let f = &mut e.io.surface.inner;
    for (at, mask, value) in rgb(p, depth) {
        f.regs.insert(at, (0x40000000 & !mask) | (value ^ mask));
    }
    // Stopped timing deliberately keeps CURRENT selectors at inherited values.
    for (at, bits) in [
        (MPC_BASE + (9 + u64::from(p) * 0x15) * 4, 0x10),
        (MPC_BASE + (0x7e + u64::from(p) * 0x5e) * 4, 0x180),
        (MPC_BASE + (0xc9 + u64::from(p) * 0x5e) * 4, 0x180),
        (MPC_BASE + (0x453 + u64::from(p) * 0xb0) * 4, 0xc),
        (MPC_BASE + (0x48a + u64::from(p) * 0xb0) * 4, 0x300),
        (MPC_BASE + (0x493 + u64::from(p) * 0xb0) * 4, 0x30),
        (MPC_BASE + (0x4de + u64::from(p) * 0xb0) * 4, 0x180),
        (MPC_BASE + (0x4ec + u64::from(p) * 0xb0) * 4, 0x180),
        (MPC_BASE + (0x30b + u64::from(p) * 0xd) * 4, 0x180),
    ] {
        *f.regs.entry(at).or_default() |= bits;
    }
    f.writes.clear();
    (backing, pool, e, surfaces, clock)
}
fn dcn401_mpc_stages_opaque_rgb_all_depths_and_pipes_without_connecting() -> TestResult {
    for p in 0..4 {
        for depth in [ColorDepth::Bpc8, ColorDepth::Bpc10, ColorDepth::Bpc12] {
            let (_backing, pool, mut e, mut surfaces, clock) = ready_mpc(p, depth);
            let before = e.io.surface.inner.regs.clone();
            let mut checks = 0;
            let a = surfaces
                .prepare_mpc(&mut e, p, || {
                    checks += 1;
                    Ok((clock, config()))
                })
                .unwrap();
            assert_eq!(checks, 2);
            assert_eq!(a.pending, 0x1ff);
            assert_eq!(a.depth, depth);
            assert_eq!(a.dpp, e.status.dpps[p as usize].unwrap());
            assert_eq!(e.status.mpcs[p as usize], Some(a));
            assert_eq!(e.status.state, State::MpcPrepared);
            let f = &e.io.surface.inner;
            assert_eq!(f.writes.len(), 20);
            for (at, mask, value) in rgb(p, depth) {
                assert_eq!(f.regs[&at], (before[&at] & !mask) | value);
            }
            for (at, value) in before {
                if !rgb(p, depth).iter().any(|&(written, _, _)| written == at) {
                    assert_eq!(f.regs[&at], value);
                }
            }
            assert_eq!(
                surfaces.prepare_mpc(&mut e, p, || Ok((clock, config()))),
                Err(Error::Busy)
            );
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    TestResult::Pass
}
/// A limited-range stream loads mpc3_set_ocsc_default's
/// COLOR_SPACE_SRGB_LIMITED matrix into set A in S2.13 format and selects
/// it, replacing the bypass write; set A in use is not pending.
fn dcn401_mpc_loads_limited_range_output_csc_like_linux() -> TestResult {
    for p in 0..4u8 {
        let (_backing, _pool, mut e, mut surfaces, clock) =
            ready_mpc_range(p, ColorDepth::Bpc10, small(p), true);
        let csc = |r: u64| MPC_BASE + (0x30b + u64::from(p) * 0xd + r) * 4;
        let format = MPC_BASE + 0x30a * 4;
        let f = &mut e.io.surface.inner;
        f.regs.insert(format, 0xf);
        for r in 1..=6 {
            f.regs.insert(csc(r), 0xdead_beef);
        }
        // Set A already in use: only the eight other selectors are pending.
        *f.regs.get_mut(&csc(0)).unwrap() &= !0x100;
        let a = surfaces
            .prepare_mpc(&mut e, p, || Ok((clock, config())))
            .unwrap();
        if !a.limited || a.pending != 0xff {
            return TestResult::Fail("limited MPC report");
        }
        let f = &e.io.surface.inner;
        let want = [
            (csc(1), 0x1b67),
            (csc(2), 0x201 << 16),
            (csc(3), 0x1b67 << 16),
            (csc(4), 0x201 << 16),
            (csc(5), 0),
            (csc(6), 0x201 << 16 | 0x1b67),
        ];
        if want.iter().any(|&(at, v)| f.regs[&at] != v)
            || f.regs[&format] != 0xf & !(1 << p)
            || f.regs[&csc(0)] & 3 != 1
            || f.writes.len() != 27
        {
            return TestResult::Fail("limited-range output CSC");
        }
        // Coefficients are loaded before set A is selected.
        let select = f.writes.iter().rposition(|w| w.0 == csc(0));
        let last_coef = f.writes.iter().rposition(|w| w.0 == csc(6));
        if !matches!((last_coef, select), (Some(c), Some(s)) if c < s) {
            return TestResult::Fail("OCSC select before coefficients");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mpc",
    dcn401_mpc_loads_limited_range_output_csc_like_linux
);
kernel_test_in!(
    "drivers/gpu/dcn401-mpc",
    dcn401_mpc_stages_opaque_rgb_all_depths_and_pipes_without_connecting
);

fn dcn401_mpc_requires_current_owned_surface_timing_vm_and_dpp() -> TestResult {
    let (_backing, _pool, mut e, mut surfaces, clock) = ready_mpc(0, ColorDepth::Bpc8);
    assert_eq!(
        surfaces.prepare_mpc(&mut e, 4, || Ok((clock, config()))),
        Err(Error::Invalid)
    );
    assert_eq!(
        surfaces.prepare_mpc(&mut e, 1, || Ok((clock, config()))),
        Err(Error::Invalid)
    );
    for (c, mem) in [
        (
            dccg::Applied {
                request: dccg::Request {
                    dpp_khz: clock.request.dpp_khz + 1,
                    ..clock.request
                },
                ..clock
            },
            config(),
        ),
        (
            clock,
            DisplayContext {
                fb_offset: config().fb_offset + 4096,
                ..config()
            },
        ),
    ] {
        assert_eq!(
            surfaces.prepare_mpc(&mut e, 0, || Ok((c, mem))),
            Err(Error::Invalid)
        );
    }
    let saved = e.status.dpps[0];
    e.status.dpps[0] = None;
    assert_eq!(
        surfaces.prepare_mpc(&mut e, 0, || Ok((clock, config()))),
        Err(Error::Invalid)
    );
    e.status.dpps[0] = saved;
    for (at, value) in [
        (d(0, 0xcd4), 0),
        (d(0, 0xcc5), 0x10),
        (d(0, 0xcc6), 1),
        (h(0, 0x60a), 0),
        (h(0, 0x5f4), 1),
        (h(0, 0x5f5), 1),
        (BASE + 0x477 * 4, 0),
        (BASE + 0x1b2a * 4, 0),
        (BASE + 0x1840 * 4, 0x100),
        (MPC_BASE + 0x2f2 * 4, 0),
        (MPC_BASE + 5 * 4, 0x1f),
        (MPC_BASE + 0xe * 4, 2),
    ] {
        let old = e.io.surface.inner.regs.insert(at, value);
        assert!(surfaces
            .prepare_mpc(&mut e, 0, || Ok((clock, config())))
            .is_err());
        e.io.surface.inner.regs.insert(at, old.unwrap_or(0));
    }
    assert!(e.io.surface.inner.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mpc",
    dcn401_mpc_requires_current_owned_surface_timing_vm_and_dpp
);

fn dcn401_mpc_lost_writes_revocation_and_device_loss_quarantine() -> TestResult {
    for mode in 0..3 {
        for n in 1..=20 {
            let (_backing, pool, mut e, mut surfaces, clock) = ready_mpc(2, ColorDepth::Bpc10);
            let authority = e.authority;
            let f = &mut e.io.surface.inner;
            match mode {
                0 => f.reject = Some(n),
                1 => f.revoke = Some((n, authority)),
                _ => f.gone = Some(n),
            }
            let err = surfaces
                .prepare_mpc(&mut e, 2, || Ok((clock, config())))
                .unwrap_err();
            assert_eq!(e.status.state, State::Failed(err));
            assert!(matches!(
                err,
                Error::Readback(_) | Error::Revoked | Error::DeviceGone
            ));
            assert_eq!(e.status.mpcs, [None; 4]);
            assert_eq!(e.io.surface.inner.writes.len(), n);
            assert_eq!(
                surfaces.prepare_mpc(&mut e, 2, || Ok((clock, config()))),
                Err(Error::Busy)
            );
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mpc",
    dcn401_mpc_lost_writes_revocation_and_device_loss_quarantine
);

fn dcn401_mpc_late_changes_fail_closed_and_reprepare_invalidates_reports() -> TestResult {
    for (at, value) in [
        (MPC_BASE + 3 * 4, 0),
        (h(0, 0x60a), 0),
        (d(0, 0xcd4), 0),
        (BASE + 0x477 * 4, 0),
        (MPC_BASE + 0x2f2 * 4, 0),
        (BASE + 0x1b43 * 4, 1),
    ] {
        let (_backing, _pool, mut e, mut surfaces, clock) = ready_mpc(0, ColorDepth::Bpc8);
        e.io.surface.inner.after_write = Some((20, at, value));
        assert!(surfaces
            .prepare_mpc(&mut e, 0, || Ok((clock, config())))
            .is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.status.mpcs, [None; 4]);
    }
    for mutate in 0..3 {
        let (_backing, _pool, mut e, mut surfaces, clock) = ready_mpc(0, ColorDepth::Bpc8);
        surfaces
            .prepare_mpc(&mut e, 0, || Ok((clock, config())))
            .unwrap();
        match mutate {
            0 => {
                *e.io
                    .surface
                    .inner
                    .regs
                    .entry(BASE + 0x1840 * 4)
                    .or_default() &= !0x1000000;
                *e.io
                    .surface
                    .inner
                    .regs
                    .entry(BASE + 0x185b * 4)
                    .or_default() &= !1;
                run(e.prepare_blank(
                    BlankRequest {
                        pipe: 0,
                        depth: ColorDepth::Bpc12,
                        limited: false,
                    },
                    clock,
                ))
                .unwrap();
            }
            1 => {
                run(e.prepare(e.status.pipes[0].unwrap().request, clock)).unwrap();
            }
            _ => {
                run(surfaces.prepare_memory(&mut e, 0, || Ok(config()))).unwrap();
            }
        }
        assert_eq!(e.status.mpcs, [None; 4]);
    }
    let (_backing, _pool, mut e, mut surfaces, clock) = ready_mpc(1, ColorDepth::Bpc8);
    let mut checks = 0;
    assert_eq!(
        surfaces.prepare_mpc(&mut e, 1, || {
            checks += 1;
            if checks == 1 {
                Ok((clock, config()))
            } else {
                Err(Error::Memory(crate::amdgpu_gmc_navi48::Error::Busy))
            }
        }),
        Err(Error::Memory(crate::amdgpu_gmc_navi48::Error::Busy))
    );
    assert_eq!(e.status.mpcs, [None; 4]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mpc",
    dcn401_mpc_late_changes_fail_closed_and_reprepare_invalidates_reports
);
