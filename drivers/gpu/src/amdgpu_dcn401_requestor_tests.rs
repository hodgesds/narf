use super::*;
#[path = "amdgpu_dcn401_scanout_chain_tests.rs"]
mod scanout_chain;

fn crb(index: usize) -> u64 {
    BASE + (0x4ba + index as u64) * 4
}
struct RequestIo {
    inner: MemoryIo,
    pending: [Option<u8>; 5],
    delay: [u8; 5],
    stall: u8,
    pipe: u8,
}
impl RequestIo {
    fn fake(&mut self) -> &mut Fake {
        &mut self.inner.surface.inner
    }
}
impl Io for RequestIo {
    fn read(&mut self, at: u64) -> u32 {
        for index in 0..5 {
            if at == crb(index) && self.stall & (1 << index) == 0 {
                if let Some(size) = self.pending[index] {
                    if self.delay[index] == 0 {
                        let v = self.fake().regs.entry(at).or_default();
                        *v = (*v & !0x1f00) | u32::from(size) << 8;
                        if index == 0 {
                            *v |= 0x40000;
                        }
                        self.pending[index] = None;
                    } else {
                        self.delay[index] -= 1;
                    }
                }
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        if (crb(0)..=crb(4)).contains(&at) {
            let mut occupied = 0;
            for index in 0..5 {
                let old = self.fake().regs[&crb(index)];
                assert_eq!(
                    old & 0x1f,
                    (old >> 8) & 0x1f,
                    "reuse before CURRENT acknowledgement"
                );
                let next = if at == crb(index) {
                    value & 0x1f
                } else {
                    old & 0x1f
                };
                occupied += next.max((old >> 8) & 0x1f);
            }
            assert!(occupied <= 21, "transient CRB overcommit");
        }
        if [0x66d, 0x620, 0x5f2, 0x5f3, 0x5f4, 0x5f7, 0x679]
            .iter()
            .any(|&r| at == h(self.pipe, r))
        {
            let p = self.pipe;
            assert_eq!(self.fake().regs[&h(p, 0x5f5)] & 1, 1);
            assert_eq!(self.fake().regs[&h(p, 0x5f4)] & 7, 3);
            assert_eq!(
                self.fake().regs[&(MPC_BASE + (0x2f2 + u64::from(p) * 4) * 4)] & 0xf,
                0xf
            );
        }
        self.inner.write(at, value);
        let f = self.fake();
        if f.reject == Some(f.writes.len()) {
            return;
        }
        if (crb(0)..=crb(4)).contains(&at) {
            self.pending[((at - crb(0)) / 4) as usize] = Some((value & 0x1f) as u8);
        }
    }
}
fn ready_requests(
    p: u8,
    sizes: [u8; 5],
) -> (Vec<u32>, Pool, Engine<RequestIo>, Surfaces, dccg::Applied) {
    ready_requests_with(p, sizes, small(p))
}
fn ready_requests_with(
    p: u8,
    sizes: [u8; 5],
    mode: Mode,
) -> (Vec<u32>, Pool, Engine<RequestIo>, Surfaces, dccg::Applied) {
    let (backing, pool, mut e, mut surfaces, clock) = ready_mpc_with(p, ColorDepth::Bpc8, mode);
    surfaces
        .prepare_mpc(&mut e, p, || Ok((clock, config())))
        .unwrap();
    let f = &mut e.io.surface.inner;
    // The retirement fixture preserves an inherited underflow. Model it as
    // recovered here; requestor preflight separately tests rejection of errors.
    *f.regs.entry(h(p, 0x5f4)).or_default() &= !0xfcf00800;
    for (index, size) in sizes.into_iter().enumerate() {
        f.regs
            .insert(crb(index), 0x40000000 | (u32::from(size) * 0x101));
    }
    for (r, bits) in [
        (0x66d, 0x7ff0),
        (0x620, 0xa9),
        (0x5f2, 0x7701f77),
        (0x5f3, 0x701f77),
        (0x5f4, 0x4f0),
        (0x5f7, 3),
    ] {
        *f.regs.entry(h(p, r)).or_default() |= bits;
    }
    f.regs.insert(BASE + 0x4c4 * 4, 0x40000abc);
    f.writes.clear();
    let e = Engine {
        io: RequestIo {
            inner: e.io,
            pending: [None; 5],
            delay: [2; 5],
            stall: 0,
            pipe: p,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    (backing, pool, e, surfaces, clock)
}
fn dcn401_requestor_repartitions_crb_without_transient_overcommit() -> TestResult {
    for p in 0..4 {
        for sizes in [[21, 0, 0, 0, 0], [1, 5, 5, 5, 5], [0, 0, 21, 0, 0], [0; 5]] {
            let (_backing, pool, mut e, mut surfaces, clock) = ready_requests(p, sizes);
            let a = run(surfaces.prepare_requestor(&mut e, p, || Ok((clock, config())))).unwrap();
            assert_eq!(a.pipe, p);
            assert_eq!(a.det_bytes, 327680);
            assert_eq!(a.compbuf_bytes, 1048576);
            assert_eq!(a.pixel_chunk_bytes, 8192);
            assert_eq!(a.minimum_chunk_bytes, 1024);
            assert_eq!(e.status.requestor, Some(a));
            assert_eq!(e.status.state, State::RequestorPrepared);
            for index in 0..5 {
                let n = if index == 0 {
                    16
                } else if index == p as usize + 1 {
                    5
                } else {
                    0
                };
                let irq_status = if index == 0 { 0x40000 } else { 0 };
                assert_eq!(
                    e.io.fake().regs[&crb(index)],
                    0x40000000 | irq_status | (n * 0x101)
                );
            }
            for (r, mask, want) in [
                (0x5f2, 0x07701f77, 0x1b00),
                (0x5f3, 0x00701f77, 0x1b00),
                (0x620, 0xff, 0x56),
                (0x66d, 0x7ff0, 0),
                (0x5f4, 0x14f7, 3 | u32::from(p) << 4),
                (0x5f5, 1, 0),
                (0x5f7, 0x1f, 8),
                (0x679, 5, 4),
            ] {
                assert_eq!(e.io.fake().regs[&h(p, r)] & mask, want);
            }
            assert_eq!(e.io.fake().regs[&(BASE + 0x4c4 * 4)], 0x40000100);
            assert_eq!(e.io.fake().regs[&h(p, 0x613)] & 0x100, 0x100); // still not a flip latch
            assert_eq!(
                run(surfaces.prepare_requestor(&mut e, p, || Ok((clock, config())))),
                Err(Error::Busy)
            );
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-requestor",
    dcn401_requestor_repartitions_crb_without_transient_overcommit
);

fn dcn401_requestor_rejects_inherited_transactions_errors_and_stale_owners() -> TestResult {
    let (_backing, _pool, mut e, mut surfaces, clock) = ready_requests(0, [1, 5, 5, 5, 5]);
    assert_eq!(
        run(surfaces.prepare_requestor(&mut e, 4, || Ok((clock, config())))),
        Err(Error::Invalid)
    );
    for (at, value) in [
        (crb(0), 0x10000 | 0x101),
        (crb(0), 0x80000 | 0x101),
        (crb(0), 0x80000101),
        (crb(0), 0x1515),
        (crb(2), 0x506),
        (crb(4), 0x1f1f),
        (h(0, 0x5f4), 0x803),
        (h(0, 0x5f4), 0x10000003),
        (h(0, 0x5f4), 0x100003),
        (MPC_BASE + 3 * 4, 0),
        (BASE + 0x477 * 4, 0),
        (h(0, 0x60a), 0),
    ] {
        let old = e.io.fake().regs.insert(at, value);
        assert!(run(surfaces.prepare_requestor(&mut e, 0, || Ok((clock, config())))).is_err());
        e.io.fake().regs.insert(at, old.unwrap_or(0));
    }
    assert_eq!(
        run(surfaces.prepare_requestor(&mut e, 0, || Ok((
            clock,
            DisplayContext {
                root: 1,
                ..config()
            }
        )))),
        Err(Error::Invalid)
    );
    assert!(e.io.fake().writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-requestor",
    dcn401_requestor_rejects_inherited_transactions_errors_and_stale_owners
);

fn dcn401_requestor_lost_writes_and_authority_loss_quarantine() -> TestResult {
    let writes = {
        let (_backing, _pool, mut e, mut surfaces, clock) = ready_requests(2, [1, 5, 5, 5, 5]);
        let result = run(surfaces.prepare_requestor(&mut e, 2, || Ok((clock, config()))));
        assert!(
            result.is_ok(),
            "{result:?}: state={:?}, writes={:?}",
            e.status.state,
            e.io.fake().writes
        );
        e.io.fake().writes.len()
    };
    for mode in 0..3 {
        for n in 1..=writes {
            let (_backing, pool, mut e, mut surfaces, clock) = ready_requests(2, [1, 5, 5, 5, 5]);
            let authority = e.authority;
            match mode {
                0 => e.io.fake().reject = Some(n),
                1 => e.io.fake().revoke = Some((n, authority)),
                _ => e.io.fake().gone = Some(n),
            }
            assert!(run(surfaces.prepare_requestor(&mut e, 2, || Ok((clock, config())))).is_err());
            assert!(matches!(e.status.state, State::Failed(_)));
            assert_eq!(e.status.requestor, None);
            assert_eq!(e.io.fake().writes.len(), n);
            assert_eq!(
                run(surfaces.prepare_requestor(&mut e, 2, || Ok((clock, config())))),
                Err(Error::Busy)
            );
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-requestor",
    dcn401_requestor_lost_writes_and_authority_loss_quarantine
);

fn dcn401_requestor_waits_for_current_and_keeps_resources_on_cancel_or_timeout() -> TestResult {
    for index in [0, 1, 2, 4] {
        // pipe 2 DET already has five segments
        for cancel in [false, true] {
            let (_backing, pool, mut e, mut surfaces, clock) = ready_requests(2, [1, 5, 5, 5, 5]);
            e.io.stall = 1 << index;
            e.io.delay = [0; 5];
            if cancel {
                let mut f = core::pin::pin!(
                    surfaces.prepare_requestor(&mut e, 2, || Ok((clock, config())))
                );
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            } else {
                assert_eq!(
                    run(surfaces.prepare_requestor(&mut e, 2, || Ok((clock, config())))),
                    Err(Error::Timeout(crb(index)))
                );
            }
            assert!(matches!(
                e.status.state,
                State::PreparingRequestor(2) | State::Failed(Error::Timeout(_))
            ));
            assert_eq!(e.status.requestor, None);
            assert!(e
                .io
                .fake()
                .writes
                .iter()
                .all(|&(at, _)| (crb(0)..=crb(4)).contains(&at)));
            assert_eq!(
                run(surfaces.prepare_requestor(&mut e, 2, || Ok((clock, config())))),
                Err(Error::Busy)
            );
            drop(surfaces);
            assert_eq!(pool.available(), 4096);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-requestor",
    dcn401_requestor_waits_for_current_and_keeps_resources_on_cancel_or_timeout
);

fn dcn401_requestor_rechecks_resources_after_buffer_acknowledgement() -> TestResult {
    for (at, value) in [
        (MPC_BASE + 3 * 4, 0),
        (h(0, 0x60a), 0),
        (crb(0), 0x10101),
        (h(0, 0x5f4), 1),
    ] {
        let (_backing, _pool, mut e, mut surfaces, clock) = ready_requests(0, [1, 5, 5, 5, 5]);
        e.io.fake().after_write = Some((1, at, value));
        assert!(run(surfaces.prepare_requestor(&mut e, 0, || Ok((clock, config())))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.io.fake().writes.len(), 1);
        assert_eq!(e.status.requestor, None);
    }
    let (_backing, _pool, mut e, mut surfaces, clock) = ready_requests(0, [1, 5, 5, 5, 5]);
    let mut checks = 0;
    assert_eq!(
        run(surfaces.prepare_requestor(&mut e, 0, || {
            checks += 1;
            if checks == 1 {
                Ok((clock, config()))
            } else {
                Err(Error::PipeClocks(dccg::Error::Revoked))
            }
        })),
        Err(Error::PipeClocks(dccg::Error::Revoked))
    );
    assert_eq!(e.io.fake().writes.len(), 1);
    assert_eq!(e.status.requestor, None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-requestor",
    dcn401_requestor_rechecks_resources_after_buffer_acknowledgement
);

/// With other displays holding DET, a pipe's requestor adds its own default
/// DET beside theirs and the compressed buffer keeps the rest of the CRB.
fn dcn401_requestor_shares_the_crb_with_other_displays() -> TestResult {
    let p = 2;
    for (others, sizes, want) in [
        (0b0001u8, [16, 5, 0, 0, 0], [11u8, 5, 0, 5, 0]),
        (0b1011, [6, 5, 5, 0, 5], [1, 5, 5, 5, 5]),
        (0b1000, [21, 0, 0, 0, 0], [11, 0, 0, 5, 5]),
    ] {
        let (_backing, _pool, mut e, mut surfaces, clock) = ready_requests(p, sizes);
        e.displays.siblings.det = others;
        let Ok(a) = run(surfaces.prepare_requestor(&mut e, p, || Ok((clock, config())))) else {
            return TestResult::Fail("requestor beside other displays' DET");
        };
        for (index, n) in want.into_iter().enumerate() {
            if e.io.fake().regs[&crb(index)] & 0x1f1f != u32::from(n) * 0x101 {
                return TestResult::Fail("CRB partition");
            }
        }
        if a.compbuf_bytes != u32::from(want[0]) * 65536 || e.verify_requestor(p).is_err() {
            return TestResult::Fail("compressed buffer record");
        }
        // The partition is the displays' together: forgetting one is a mismatch.
        e.displays.siblings.det = 0;
        if e.verify_requestor(p) != Err(Error::Busy) {
            return TestResult::Fail("partition verified without its displays");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-requestor",
    dcn401_requestor_shares_the_crb_with_other_displays
);
