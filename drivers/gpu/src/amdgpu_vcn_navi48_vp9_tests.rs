// SPDX-License-Identifier: MIT
use super::*;
use vp9_words as d;

// Synthetic DMA completion is not a VP9 decoder. Omit the opaque 10.8 MiB
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
    const OMIT_START: u64 = d::CONTEXT + 4096;
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
        (map.len == d::BYTES).then(|| self.word(at))
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
        if let Some(old) = self.base {
            assert_eq!(base, old);
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
            d::Phase::Decode => (d::DECODE_MSG, d::decode_message().to_vec()),
            d::Phase::Destroy => (d::DESTROY_MSG, d::destroy_message().to_vec()),
        };
        assert_eq!(self.bytes(msg, bytes.len()), bytes.as_slice());
        assert_eq!(self.context_zeroes, Self::OMIT);
        assert_eq!(
            self.bytes(d::CONTEXT, d::DEFAULT_PROBS.len()),
            d::DEFAULT_PROBS
        );
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
                decode_words::BYTES + hevc_words::BYTES + hevc10_words::BYTES
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
    }
    (pool, engine, observer)
}
fn vcn5_vp9_profile0_checks_every_pixel_and_coexists_with_avc_encode() -> TestResult {
    for avc in [false, true] {
        let (pool, mut engine, mut observer) = ready(avc);
        let proof = run(engine.prove_vp9(&mut observer)).unwrap();
        assert_eq!(
            proof.output_sum,
            (0..d::TARGET_BYTES)
                .map(|at| u64::from(d::expected(at)))
                .sum::<u64>()
        );
        assert_eq!(proof.completion.fence.sequence, if avc { 7 } else { 4 });
        assert!(proof.completion.msi_verified);
        assert_eq!(engine.vp9_result, Some(Ok(proof)));
        assert_eq!(engine.state, State::Vp9Verified);
        assert_eq!(run(engine.prove_vp9(&mut observer)), Err(Error::Busy));
        assert!(!engine.vp9_memory.as_ref().unwrap().reusable_for_test());
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
                    + encode_words::BYTES,
                29_962_240
            );
        }
        run(engine.stop()).unwrap();
        assert!(engine.vp9_memory.as_ref().unwrap().reusable_for_test());
        let capacity = pool.available()
            + engine.memory.size()
            + engine.ib_memory.as_ref().unwrap().size()
            + engine.vp9_memory.as_ref().unwrap().size()
            + engine.encode_memory.as_ref().unwrap().size()
            + engine.decode_memory.as_ref().map_or(0, Reservation::size)
            + engine.hevc_memory.as_ref().map_or(0, Reservation::size)
            + engine.hevc10_memory.as_ref().map_or(0, Reservation::size);
        drop(engine);
        assert_eq!(pool.available(), capacity);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_vp9_profile0_checks_every_pixel_and_coexists_with_avc_encode
);
fn vcn5_vp9_bad_pixels_guards_feedback_or_delivery_quarantine_arena() -> TestResult {
    for case in 1..=10 {
        let (pool, mut engine, mut observer) = ready(false);
        if case <= 7 {
            engine.io.vp9.fault = case;
        } else if case == 8 {
            engine.io.fence = false;
        } else if case == 9 {
            engine.io.emit_cpu = false;
        } else {
            engine.io.emit_iv = false;
        }
        let expected = match case {
            1 | 2 => Error::DecodePixel(0),
            4 | 8 | 9 | 10 => Error::Timeout,
            _ => Error::Readback,
        };
        assert_eq!(run(engine.prove_vp9(&mut observer)), Err(expected));
        assert_eq!(engine.state, State::Failed(expected));
        assert_eq!(engine.vp9_result, Some(Err(expected)));
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        assert!(!engine.vp9_memory.as_ref().unwrap().reusable_for_test());
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_vp9_bad_pixels_guards_feedback_or_delivery_quarantine_arena
);
fn vcn5_vp9_cancel_before_and_after_doorbell_keeps_owned_memory() -> TestResult {
    for published in [false, true] {
        let (pool, mut engine, mut observer) = ready(false);
        observer.stall_observed = published;
        {
            let mut f = core::pin::pin!(engine.prove_vp9(&mut observer));
            for _ in 0..if published { d::BYTES / 4096 + 1 } else { 1 } {
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
        }
        assert_eq!(engine.io.vp9.stages, if published { 3 } else { 0 });
        assert_eq!(engine.state, State::Vp9Testing);
        assert_eq!(engine.vp9_result, Some(Err(Error::Busy)));
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        assert!(!engine.vp9_memory.as_ref().unwrap().reusable_for_test());
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_vp9_cancel_before_and_after_doorbell_keeps_owned_memory
);
fn vcn5_vp9_allocation_refusal_is_unpublished_and_fresh_restart_clears_result() -> TestResult {
    let (pool, mut engine, mut observer) = ib_ready();
    run(engine.prove_ibs(&mut observer)).unwrap();
    // Explicitly exhaust the generic fixture instead of assuming the new
    // codec's arena is larger than its remaining space.
    let held = pool.reserve(pool.available()).unwrap();
    assert_eq!(run(engine.prove_vp9(&mut observer)), Err(Error::Allocation));
    assert_eq!(engine.state, State::IbVerified);
    assert!(engine.vp9_result.is_none() && engine.vp9_memory.is_none());
    drop(held);
    let (_pool, mut engine, mut observer) = ready(false);
    let first = run(engine.prove_vp9(&mut observer)).unwrap();
    run(engine.stop()).unwrap();
    run(engine.start(IMAGE, power())).unwrap();
    assert!(engine.vp9_result.is_none());
    run(engine.prove()).unwrap();
    run(engine.prove_interrupts(&mut observer)).unwrap();
    run(engine.prove_ibs(&mut observer)).unwrap();
    let second = run(engine.prove_vp9(&mut observer)).unwrap();
    assert_ne!(
        first.completion.fence.sequence,
        second.completion.fence.sequence
    );
    assert_eq!(engine.io.vp9.stages, 6);
    assert!(engine.io.vp9.memory.len() < 256 * 1024);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_vp9_allocation_refusal_is_unpublished_and_fresh_restart_clears_result
);

fn vcn5_vp9_pressure_and_fragmentation_refuse_before_publication() -> TestResult {
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
    assert_eq!(run(engine.prove_vp9(&mut observer)), Err(Error::Allocation));
    assert_eq!((engine.seq, engine.wptr, engine.io.traps), prior);
    assert_eq!(engine.state, State::IbVerified);
    assert!(engine.vp9_result.is_none() && engine.vp9_memory.is_none());
    assert!(engine.io.vp9.base.is_none());
    drop(pressure);
    // Enough aggregate free bytes do not imply a contiguous arena. Keep two
    // 6 MiB holes separated by held pages and exhaust the remaining window.
    let first = pool.reserve(6 * 1024 * 1024).unwrap();
    let barrier = pool.reserve(4096).unwrap();
    let second = pool.reserve(6 * 1024 * 1024).unwrap();
    let tail = pool.reserve(pool.available()).unwrap();
    drop(first);
    drop(second);
    assert!(pool.available() >= d::BYTES);
    assert_eq!(run(engine.prove_vp9(&mut observer)), Err(Error::Allocation));
    assert_eq!((engine.seq, engine.wptr, engine.io.traps), prior);
    assert_eq!(engine.state, State::IbVerified);
    assert!(engine.vp9_result.is_none() && engine.vp9_memory.is_none());
    assert!(engine.io.vp9.base.is_none());
    drop(barrier);
    drop(tail);
    run(engine.prove_vp9(&mut observer)).unwrap();
    assert!(engine.io.vp9.memory.len() < 256 * 1024);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_vp9_pressure_and_fragmentation_refuse_before_publication
);

fn vcn5_vp9_waits_for_delayed_rptr_at_wrap() -> TestResult {
    let (_pool, mut e, mut observer) = ready(false);
    e.wptr = 960;
    e.io.regs.insert(VCN + u64::from(RPTR) * 4, 960);
    e.io.regs.insert(VCN + u64::from(WPTR) * 4, 960);
    e.io.advance = false;
    e.io.advance_on_delay = true;
    let prior = e.seq;
    let proof = run(e.prove_vp9(&mut observer)).unwrap();
    assert_eq!(proof.completion.fence.sequence, prior + 1);
    assert_eq!(proof.completion.fence.read_pointer, 0);
    assert_eq!(e.reg(RPTR).unwrap(), 0);
    assert!(e.io.pending_pointer.is_none());
    run(e.stop()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_vp9_waits_for_delayed_rptr_at_wrap
);
