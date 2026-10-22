// SPDX-License-Identifier: MIT
use super::*;
use av1_10_words as d;

// Synthetic DMA completion is not a AV1 decoder. Omit the opaque 36.7 MiB
// firmware context tail while counting every initialization write. Addresses,
// descriptors and the real Pool reservation still cover the entire context.
#[derive(Default)]
pub(super) struct Model {
    base: Option<u64>,
    memory: Vec<u8>,
    context_zeroes: u64,
    stages: u8,
    fault: u8,
}
impl Model {
    const OMIT_START: u64 = d::CONTEXT + d::DEFAULT_CDF.len() as u64;
    const OMIT_END: u64 = d::SESSION_END_GUARD;
    const OMIT: u64 = Self::OMIT_END - Self::OMIT_START;
    fn index(at: u64) -> Option<usize> {
        assert!(at < d::BYTES);
        if at < Self::OMIT_START {
            Some(at as usize)
        } else if at >= Self::OMIT_END {
            Some((at - Self::OMIT) as usize)
        } else {
            None
        }
    }
    pub(super) fn contains(&self, at: u64) -> bool {
        self.base
            .is_some_and(|base| (base..base + d::BYTES).contains(&at))
    }
    pub(super) fn read(&self, map: MmioRegion, at: u64) -> Option<u32> {
        (map.len == d::BYTES && self.base == Some(GPU + map.phys.raw() - 0x90004000))
            .then(|| self.word(at))
    }
    fn word(&self, at: u64) -> u32 {
        Self::index(at).map_or(0, |i| {
            u32::from_le_bytes(self.memory[i..i + 4].try_into().unwrap())
        })
    }
    pub(super) fn write(&mut self, map: MmioRegion, at: u64, word: u32) -> bool {
        if map.len != d::BYTES {
            return false;
        }
        let base = GPU + map.phys.raw() - 0x90004000;
        if self.base.is_some_and(|old| old != base) {
            return false;
        }
        self.base = Some(base);
        self.memory.resize((d::BYTES - Self::OMIT) as usize, 0x5a);
        if at == 0 {
            self.context_zeroes = 0;
        }
        if Self::index(at).is_none() {
            assert_eq!(word, 0);
            self.context_zeroes += 4;
        } else {
            self.store(at, word);
        }
        true
    }
    fn store(&mut self, at: u64, word: u32) {
        let i = Self::index(at).unwrap();
        self.memory[i..i + 4].copy_from_slice(&word.to_le_bytes());
    }
    fn bytes(&self, at: u64, len: usize) -> &[u8] {
        let i = Self::index(at).unwrap();
        &self.memory[i..i + len]
    }
    pub(super) fn ib(&mut self, address: u64, len: u32) -> bool {
        let base = self.base.unwrap();
        let phase =
            [d::Phase::Create, d::Phase::Decode, d::Phase::Destroy][(self.stages % 3) as usize];
        let ib = d::ib(base, phase).unwrap();
        assert_eq!(len as usize, ib.as_slice().len());
        for (i, &w) in ib.as_slice().iter().enumerate() {
            assert_eq!(self.word(address - base + i as u64 * 4), w);
        }
        let (msg, bytes) = match phase {
            d::Phase::Create => (d::CREATE_MSG, d::create_message().to_vec()),
            d::Phase::Decode => (
                d::DECODE_MSG,
                d::keyframe_message(d::fixed()).unwrap().to_vec(),
            ),
            d::Phase::Destroy => (d::DESTROY_MSG, d::destroy_message().to_vec()),
        };
        assert_eq!(self.bytes(msg, bytes.len()), bytes.as_slice());
        assert_eq!(self.context_zeroes, Self::OMIT);
        if phase != d::Phase::Destroy {
            assert_eq!(self.bytes(d::CONTEXT, d::DEFAULT_CDF.len()), d::DEFAULT_CDF);
        }
        if phase == d::Phase::Decode {
            // Includes the actual Mesa tier3 reference package with num_bufs=0.
            assert_eq!(&ib.as_slice()[43..], &[16, 12, 8, 0]);
            assert_eq!(self.bytes(d::BITSTREAM, d::STREAM.len()), d::STREAM);
            assert!(self
                .bytes(d::TARGET, d::TARGET_BYTES as usize)
                .iter()
                .all(|b| *b == 0));
            if self.fault == 4 {
                return false;
            }
            if self.fault != 1 {
                for at in 0..d::TARGET_BYTES {
                    self.memory[Self::index(d::TARGET + at).unwrap()] = d::expected(at);
                }
            }
            match self.fault {
                // Equal-sum damage must fail the bytewise image comparison.
                2 => {
                    let i = Self::index(d::TARGET).unwrap();
                    self.memory[i] += 1;
                    self.memory[i + 2] -= 1;
                }
                3 => self.store(d::TARGET_END_GUARD, 0),
                5 => self.memory[Self::index(d::BITSTREAM).unwrap()] ^= 1,
                6 => self.store(d::FEEDBACK + 24, 1),
                7 => self.store(d::DECODE_IB + 4092, 1),
                11 => self.store(d::CONTEXT + 256, self.word(d::CONTEXT + 256) ^ 1),
                12 => {
                    // Eight-bit truncation drops nonzero bits 7:6 of P010's
                    // low byte while preserving the apparently plausible MSB.
                    for at in (0..d::TARGET_BYTES).step_by(2) {
                        self.memory[Self::index(d::TARGET + at).unwrap()] = 0;
                    }
                }
                _ => {}
            }
        }
        self.stages += 1;
        true
    }
}
fn ready(avc: bool) -> (Pool, Engine<Fake>, Irqs) {
    let (pool, mut engine) = fixture_capacity(
        BYTES
            + ib_words::IB_BYTES
            + d::BYTES
            + encode_words::BYTES
            + if avc {
                av1_words::BYTES
                    + decode_words::BYTES
                    + hevc_words::BYTES
                    + hevc10_words::BYTES
                    + vp9_words::BYTES
                    + vp9_10_words::BYTES
            } else {
                0
            },
    );
    run(engine.start(IMAGE, power())).unwrap();
    run(engine.prove()).unwrap();
    let mut observer = irqs(&engine, Some(64));
    run(engine.prove_interrupts(&mut observer)).unwrap();
    run(engine.prove_ibs(&mut observer)).unwrap();
    if avc {
        run(engine.prove_decode(&mut observer)).unwrap();
        run(engine.prove_hevc(&mut observer)).unwrap();
        run(engine.prove_hevc10(&mut observer)).unwrap();
        run(engine.prove_vp9(&mut observer)).unwrap();
        run(engine.prove_vp9_10(&mut observer)).unwrap();
        run(engine.prove_av1(&mut observer)).unwrap();
    }
    (pool, engine, observer)
}
fn vcn5_av1_10_p010_precision_checks_every_pixel_and_coexists_with_avc_encode() -> TestResult {
    assert_eq!(d::BYTES, 37_126_144);
    assert_eq!(d::BYTES - av1_words::BYTES, 49_152);
    assert_eq!(d::CONTEXT_BYTES, av1_words::CONTEXT_BYTES);
    assert_eq!(d::DEFAULT_CDF, av1_words::DEFAULT_CDF);
    for (at, value) in [
        (0, 129u16),
        (256, 321),
        (256 * 128, 577),
        (256 * 128 + 256, 833),
        (256 * 128 * 2, 259),
        (256 * 128 * 2 + 2, 771),
    ] {
        let bytes = [d::expected(at), d::expected(at + 1)];
        assert_eq!(u16::from_le_bytes(bytes), value << 6);
        assert_ne!(bytes[0] & 0xc0, 0);
        assert_eq!(bytes[0] & 0x3f, 0);
    }
    for avc in [false, true] {
        let (pool, mut engine, mut observer) = ready(avc);
        let proof = run(engine.prove_av1_10(&mut observer)).unwrap();
        assert_eq!(
            proof.output_sum,
            (0..d::TARGET_BYTES)
                .map(|at| u64::from(d::expected(at)))
                .sum::<u64>()
        );
        assert_eq!(proof.completion.fence.sequence, if avc { 10 } else { 4 });
        assert!(proof.completion.msi_verified);
        assert_eq!(engine.av1_10_result, Some(Ok(proof)));
        assert_eq!(engine.state, State::Av1TenVerified);
        assert_eq!(run(engine.prove_av1_10(&mut observer)), Err(Error::Busy));
        assert!(!engine.av1_10_memory.as_ref().unwrap().reusable_for_test());
        run(engine.prove_encode(&mut observer)).unwrap();
        // The fixture has exactly the retained codec/transport budget, with
        // no hidden spare capacity covering an incorrect reservation size.
        assert_eq!(pool.available(), 0);
        if avc {
            assert_eq!(
                BYTES
                    + ib_words::IB_BYTES
                    + decode_words::BYTES
                    + hevc_words::BYTES
                    + hevc10_words::BYTES
                    + d::BYTES
                    + encode_words::BYTES
                    + vp9_words::BYTES
                    + vp9_10_words::BYTES
                    + av1_words::BYTES,
                115_326_976
            );
        }
        run(engine.stop()).unwrap();
        assert!(engine.av1_10_memory.as_ref().unwrap().reusable_for_test());
        let capacity = pool.available()
            + engine.memory.size()
            + engine.ib_memory.as_ref().unwrap().size()
            + engine.av1_10_memory.as_ref().unwrap().size()
            + engine.encode_memory.as_ref().unwrap().size()
            + engine.decode_memory.as_ref().map_or(0, Reservation::size)
            + engine.hevc_memory.as_ref().map_or(0, Reservation::size)
            + engine.hevc10_memory.as_ref().map_or(0, Reservation::size)
            + engine.vp9_memory.as_ref().map_or(0, Reservation::size)
            + engine.vp9_10_memory.as_ref().map_or(0, Reservation::size)
            + engine.av1_memory.as_ref().map_or(0, Reservation::size);
        drop(engine);
        assert_eq!(pool.available(), capacity);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48/av1-main10",
    vcn5_av1_10_p010_precision_checks_every_pixel_and_coexists_with_avc_encode
);
fn vcn5_av1_10_bad_pixels_guards_feedback_or_delivery_quarantine_arena() -> TestResult {
    for case in 1..=12 {
        let (pool, mut engine, mut observer) = ready(false);
        if case <= 7 || case >= 11 {
            engine.io.av1_10.fault = case;
        } else if case == 8 {
            engine.io.fence = false;
        } else if case == 9 {
            engine.io.emit_cpu = false;
        } else {
            engine.io.emit_iv = false;
        }
        let expected = match case {
            1 | 2 | 12 => Error::DecodePixel(0),
            4 | 8 | 9 | 10 => Error::Timeout,
            _ => Error::Readback,
        };
        assert_eq!(run(engine.prove_av1_10(&mut observer)), Err(expected));
        assert_eq!(engine.state, State::Failed(expected));
        assert_eq!(engine.av1_10_result, Some(Err(expected)));
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        assert!(!engine.av1_10_memory.as_ref().unwrap().reusable_for_test());
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48/av1-main10",
    vcn5_av1_10_bad_pixels_guards_feedback_or_delivery_quarantine_arena
);
fn vcn5_av1_10_cancel_before_and_after_doorbell_keeps_owned_memory() -> TestResult {
    for published in [false, true] {
        let (pool, mut engine, mut observer) = ready(false);
        observer.stall_observed = published;
        {
            let mut f = core::pin::pin!(engine.prove_av1_10(&mut observer));
            for _ in 0..if published { d::BYTES / 4096 + 1 } else { 1 } {
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
        }
        assert_eq!(engine.io.av1_10.stages, if published { 3 } else { 0 });
        assert_eq!(engine.state, State::Av1TenTesting);
        assert_eq!(engine.av1_10_result, Some(Err(Error::Busy)));
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        assert!(!engine.av1_10_memory.as_ref().unwrap().reusable_for_test());
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48/av1-main10",
    vcn5_av1_10_cancel_before_and_after_doorbell_keeps_owned_memory
);
fn vcn5_av1_10_allocation_refusal_is_unpublished_and_fresh_restart_clears_result() -> TestResult {
    let (pool, mut engine, mut observer) = ib_ready();
    run(engine.prove_ibs(&mut observer)).unwrap();
    // Explicitly exhaust the generic fixture instead of assuming the new
    // codec's arena is larger than its remaining space.
    let held = pool.reserve(pool.available()).unwrap();
    assert_eq!(
        run(engine.prove_av1_10(&mut observer)),
        Err(Error::Allocation)
    );
    assert_eq!(engine.state, State::IbVerified);
    assert!(engine.av1_10_result.is_none() && engine.av1_10_memory.is_none());
    drop(held);
    let (_pool, mut engine, mut observer) = ready(false);
    let first = run(engine.prove_av1_10(&mut observer)).unwrap();
    run(engine.stop()).unwrap();
    run(engine.start(IMAGE, power())).unwrap();
    assert!(engine.av1_10_result.is_none());
    run(engine.prove()).unwrap();
    run(engine.prove_interrupts(&mut observer)).unwrap();
    run(engine.prove_ibs(&mut observer)).unwrap();
    let second = run(engine.prove_av1_10(&mut observer)).unwrap();
    assert_ne!(
        first.completion.fence.sequence,
        second.completion.fence.sequence
    );
    assert_eq!(engine.io.av1_10.stages, 6);
    assert!(engine.io.av1_10.memory.len() < 576 * 1024);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48/av1-main10",
    vcn5_av1_10_allocation_refusal_is_unpublished_and_fresh_restart_clears_result
);

fn vcn5_av1_10_pressure_and_fragmentation_refuse_before_publication() -> TestResult {
    // A realistic 256 MiB visible window still refuses when prior firmware,
    // display or client reservations leave less than the actual codec arena.
    // These claims exercise allocation, not physical firmware size estimates.
    let (pool, mut engine) = fixture_capacity(256 * 1024 * 1024);
    run(engine.start(IMAGE, power())).unwrap();
    run(engine.prove()).unwrap();
    let mut observer = irqs(&engine, Some(64));
    run(engine.prove_interrupts(&mut observer)).unwrap();
    run(engine.prove_ibs(&mut observer)).unwrap();
    let prior = (engine.seq, engine.wptr, engine.io.traps);
    let pressure = pool.reserve(pool.available() - (d::BYTES - 4096)).unwrap();
    assert_eq!(
        run(engine.prove_av1_10(&mut observer)),
        Err(Error::Allocation)
    );
    assert_eq!((engine.seq, engine.wptr, engine.io.traps), prior);
    assert_eq!(engine.state, State::IbVerified);
    assert!(engine.av1_10_result.is_none() && engine.av1_10_memory.is_none());
    assert!(engine.io.av1_10.base.is_none());
    drop(pressure);
    // Enough aggregate free bytes do not imply a contiguous arena. Keep two
    // holes smaller than the arena separated by held pages and exhaust the remaining window.
    let hole = d::BYTES.div_ceil(8192) * 4096;
    let first = pool.reserve(hole).unwrap();
    let barrier = pool.reserve(4096).unwrap();
    let second = pool.reserve(hole).unwrap();
    let tail = pool.reserve(pool.available()).unwrap();
    drop(first);
    drop(second);
    assert!(pool.available() >= d::BYTES);
    assert_eq!(
        run(engine.prove_av1_10(&mut observer)),
        Err(Error::Allocation)
    );
    assert_eq!((engine.seq, engine.wptr, engine.io.traps), prior);
    assert_eq!(engine.state, State::IbVerified);
    assert!(engine.av1_10_result.is_none() && engine.av1_10_memory.is_none());
    assert!(engine.io.av1_10.base.is_none());
    drop(barrier);
    drop(tail);
    run(engine.prove_av1_10(&mut observer)).unwrap();
    assert!(engine.io.av1_10.memory.len() < 576 * 1024);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48/av1-main10",
    vcn5_av1_10_pressure_and_fragmentation_refuse_before_publication
);

fn vcn5_av1_10_waits_for_delayed_rptr_at_wrap() -> TestResult {
    for delayed in [true, false] {
        let (_pool, mut e, mut observer) = ready(false);
        e.wptr = 960;
        e.io.regs.insert(VCN + u64::from(RPTR) * 4, 960);
        e.io.regs.insert(VCN + u64::from(WPTR) * 4, 960);
        e.io.advance = false;
        e.io.advance_on_delay = delayed;
        let prior = e.seq;
        let result = run(e.prove_av1_10(&mut observer));
        if delayed {
            let proof = result.unwrap();
            assert_eq!(proof.completion.fence.sequence, prior + 1);
            assert_eq!(proof.completion.fence.read_pointer, 0);
            assert_eq!(e.reg(RPTR).unwrap(), 0);
            assert!(e.io.pending_pointer.is_none());
            run(e.stop()).unwrap();
        } else {
            // A fresh fence/IH cannot substitute for physical ring consumption.
            // An unchanged old pointer at wrap times out; it is not Readback.
            assert_eq!(result, Err(Error::Timeout));
            assert_eq!(e.reg(RPTR).unwrap(), 960);
            assert_eq!(e.state, State::Failed(Error::Timeout));
            assert!(!e.av1_10_memory.as_ref().unwrap().reusable_for_test());
            assert_eq!(run(e.stop()), Err(Error::Busy));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48/av1-main10",
    vcn5_av1_10_waits_for_delayed_rptr_at_wrap
);

fn vcn5_av1_10_completed_proof_allows_owned_client_submit() -> TestResult {
    let (_pool, mut e, mut o) = ready(false);
    let p = run(e.prove_av1_10(&mut o)).unwrap();
    let job = crate::amdgpu_gfx12_queue::Job::new(3, 11, 0x1000, &[(0x2000, 4)]).unwrap();
    let sequence = p.completion.fence.sequence + 1;
    assert_eq!(e.submit(job), Ok(sequence));
    assert_eq!(e.completed_job(), Ok(sequence));
    assert_eq!(e.io.client_ibs.last(), Some(&(3, 0x2000, 4)));
    assert!(!e.av1_10_memory.as_ref().unwrap().reusable_for_test());
    run(e.stop()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48/av1-main10",
    vcn5_av1_10_completed_proof_allows_owned_client_submit
);
