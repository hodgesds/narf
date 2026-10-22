// SPDX-License-Identifier: MIT
use super::*;
use hevc10_words as d;

// Synthetic DMA writes exercise completion/ownership; this is not an HEVC decoder.
#[derive(Default)]
pub(super) struct Model {
    base: Option<u64>,
    memory: Vec<u8>,
    stages: u8,
    fault: u8,
}
impl Model {
    pub(super) fn contains(&self, at: u64) -> bool {
        self.base
            .is_some_and(|base| (base..base + d::BYTES).contains(&at))
    }
    pub(super) fn read(&self, map: MmioRegion, at: u64) -> Option<u32> {
        (map.len == d::BYTES).then(|| self.word(at))
    }
    fn word(&self, at: u64) -> u32 {
        u32::from_le_bytes(
            self.memory[at as usize..at as usize + 4]
                .try_into()
                .unwrap(),
        )
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
        self.memory.resize(d::BYTES as usize, 0x5a);
        self.store(at, word);
        true
    }
    fn store(&mut self, at: u64, word: u32) {
        self.memory[at as usize..at as usize + 4].copy_from_slice(&word.to_le_bytes());
    }
    pub(super) fn ib(&mut self, address: u64, len: u32) -> bool {
        let base = self.base.unwrap();
        assert_eq!(len, 43);
        let phase =
            [d::Phase::Create, d::Phase::Decode, d::Phase::Destroy][(self.stages % 3) as usize];
        let expected = d::ib(base, phase).unwrap();
        for (i, w) in expected.into_iter().enumerate() {
            assert_eq!(self.word(address - base + i as u64 * 4), w);
        }
        let (msg, bytes) = match phase {
            d::Phase::Create => (d::CREATE_MSG, d::create_message().to_vec()),
            d::Phase::Decode => (d::DECODE_MSG, d::decode_message().to_vec()),
            d::Phase::Destroy => (d::DESTROY_MSG, d::destroy_message().to_vec()),
        };
        assert_eq!(
            &self.memory[msg as usize..msg as usize + bytes.len()],
            bytes.as_slice()
        );
        if phase == d::Phase::Decode {
            assert_eq!(
                &self.memory[d::BITSTREAM as usize..d::BITSTREAM as usize + d::STREAM.len()],
                d::STREAM
            );
            assert!(
                self.memory[d::TARGET as usize..d::TARGET_END_GUARD as usize]
                    .iter()
                    .all(|b| *b == 0)
            );
            if self.fault == 4 {
                return false;
            }
            if self.fault != 1 {
                for at in 0..d::TARGET_BYTES {
                    self.memory[(d::TARGET + at) as usize] = d::expected(at);
                }
            }
            match self.fault {
                // Balanced corruption defeats the old AVC-style additive checksum.
                2 => {
                    self.memory[d::TARGET as usize] += 1;
                    self.memory[d::TARGET as usize + 2] -= 1;
                }
                3 => self.store(d::TARGET_END_GUARD, 0),
                5 => self.memory[d::BITSTREAM as usize] ^= 1,
                6 => self.store(d::FEEDBACK + 24, 1),
                7 => self.store(d::DECODE_IB + 4092, 1),
                // An 8-bit round trip loses the two least significant sample
                // bits, even when packed into otherwise valid MSB-aligned P010.
                11 => {
                    for at in (d::TARGET..d::TARGET_END_GUARD).step_by(2) {
                        self.memory[at as usize] &= 0x3f;
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
                decode_words::BYTES + hevc_words::BYTES
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
    }
    (pool, engine, observer)
}
fn vcn5_hevc10_main10_checks_every_pixel_and_coexists_with_avc_encode() -> TestResult {
    for avc in [false, true] {
        let (pool, mut engine, mut observer) = ready(avc);
        let proof = run(engine.prove_hevc10(&mut observer)).unwrap();
        assert_eq!(
            proof.output_sum,
            (0..d::TARGET_BYTES)
                .map(|at| u64::from(d::expected(at)))
                .sum::<u64>()
        );
        assert_eq!(proof.completion.fence.sequence, if avc { 6 } else { 4 });
        assert!(proof.completion.msi_verified);
        assert_eq!(engine.hevc10_result, Some(Ok(proof)));
        assert_eq!(engine.state, State::Hevc10Verified);
        assert_eq!(run(engine.prove_hevc10(&mut observer)), Err(Error::Busy));
        assert!(!engine.hevc10_memory.as_ref().unwrap().reusable_for_test());
        run(engine.prove_encode(&mut observer)).unwrap();
        run(engine.stop()).unwrap();
        assert!(engine.hevc10_memory.as_ref().unwrap().reusable_for_test());
        let capacity = pool.available()
            + engine.memory.size()
            + engine.ib_memory.as_ref().unwrap().size()
            + engine.hevc10_memory.as_ref().unwrap().size()
            + engine.encode_memory.as_ref().unwrap().size()
            + engine.decode_memory.as_ref().map_or(0, Reservation::size)
            + engine.hevc_memory.as_ref().map_or(0, Reservation::size);
        drop(engine);
        assert_eq!(pool.available(), capacity);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc10_main10_checks_every_pixel_and_coexists_with_avc_encode
);
fn vcn5_hevc10_bad_pixels_guards_feedback_or_delivery_quarantine_arena() -> TestResult {
    for case in 1..=11 {
        let (pool, mut engine, mut observer) = ready(false);
        if case <= 7 || case == 11 {
            engine.io.hevc10.fault = case;
        } else if case == 8 {
            engine.io.fence = false;
        } else if case == 9 {
            engine.io.emit_cpu = false;
        } else {
            engine.io.emit_iv = false;
        }
        let expected = match case {
            1 | 2 | 11 => Error::DecodePixel(0),
            4 | 8 | 9 | 10 => Error::Timeout,
            _ => Error::Readback,
        };
        assert_eq!(run(engine.prove_hevc10(&mut observer)), Err(expected));
        assert_eq!(engine.state, State::Failed(expected));
        assert_eq!(engine.hevc10_result, Some(Err(expected)));
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        assert!(!engine.hevc10_memory.as_ref().unwrap().reusable_for_test());
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc10_bad_pixels_guards_feedback_or_delivery_quarantine_arena
);
fn vcn5_hevc10_cancel_before_and_after_doorbell_keeps_owned_memory() -> TestResult {
    for published in [false, true] {
        let (pool, mut engine, mut observer) = ready(false);
        observer.stall_observed = published;
        {
            let mut f = core::pin::pin!(engine.prove_hevc10(&mut observer));
            for _ in 0..if published { d::BYTES / 4096 + 1 } else { 1 } {
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
        }
        assert_eq!(engine.io.hevc10.stages, if published { 3 } else { 0 });
        assert_eq!(engine.state, State::Hevc10Testing);
        assert_eq!(engine.hevc10_result, Some(Err(Error::Busy)));
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        assert!(!engine.hevc10_memory.as_ref().unwrap().reusable_for_test());
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc10_cancel_before_and_after_doorbell_keeps_owned_memory
);
fn vcn5_hevc10_allocation_refusal_is_unpublished_and_fresh_restart_clears_result() -> TestResult {
    let (pool, mut engine, mut observer) = ib_ready();
    run(engine.prove_ibs(&mut observer)).unwrap();
    // Explicitly exhaust the generic fixture instead of assuming the new
    // codec's arena is larger than its remaining space.
    let held = pool.reserve(pool.available()).unwrap();
    assert_eq!(
        run(engine.prove_hevc10(&mut observer)),
        Err(Error::Allocation)
    );
    assert_eq!(engine.state, State::IbVerified);
    assert!(engine.hevc10_result.is_none() && engine.hevc10_memory.is_none());
    drop(held);
    let (_pool, mut engine, mut observer) = ready(false);
    let first = run(engine.prove_hevc10(&mut observer)).unwrap();
    run(engine.stop()).unwrap();
    run(engine.start(IMAGE, power())).unwrap();
    assert!(engine.hevc10_result.is_none());
    run(engine.prove()).unwrap();
    run(engine.prove_interrupts(&mut observer)).unwrap();
    run(engine.prove_ibs(&mut observer)).unwrap();
    let second = run(engine.prove_hevc10(&mut observer)).unwrap();
    assert_ne!(
        first.completion.fence.sequence,
        second.completion.fence.sequence
    );
    assert_eq!(engine.io.hevc10.stages, 6);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc10_allocation_refusal_is_unpublished_and_fresh_restart_clears_result
);
