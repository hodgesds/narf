// Original model of retained AV1 encoder command/output ownership.
use super::*;
use av1_encode_words as e;

// Synthetic headers exercise proof ownership and validation. This model is
// not an encoder, and successful model runs say nothing about picture quality.
const STREAM: &[u8] = include_bytes!("../fixtures/vcn5/av1_encode/reference-frame.obu");
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
            .is_some_and(|base| (base..base + e::BYTES).contains(&at))
    }
    pub(super) fn read(&self, map: MmioRegion, at: u64) -> Option<u32> {
        (map.len == e::BYTES).then(|| self.word(at))
    }
    fn word(&self, at: u64) -> u32 {
        u32::from_le_bytes(
            self.memory[at as usize..at as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    pub(super) fn write(&mut self, map: MmioRegion, at: u64, word: u32) -> bool {
        if map.len != e::BYTES {
            return false;
        }
        let base = GPU + map.phys.raw() - 0x90004000;
        if let Some(previous) = self.base {
            assert_eq!(base, previous);
        }
        self.base = Some(base);
        self.memory.resize(e::BYTES as usize, 0x5a);
        self.store(at, word);
        true
    }
    fn store(&mut self, at: u64, word: u32) {
        self.memory[at as usize..at as usize + 4].copy_from_slice(&word.to_le_bytes());
    }
    pub(super) fn ib(&mut self, address: u64, length: u32) -> bool {
        let base = self.base.unwrap();
        assert!(length > 8 && length <= 2048);
        let words: Vec<u32> = (0..length)
            .map(|i| self.word(address - base + u64::from(i) * 4))
            .collect();
        assert_eq!(&words[..2], &[0x10, 0x30000002]);
        assert_eq!(words[3], length - 4);
        assert_eq!(&words[4..7], &[0x10, 0x30000001, 2]);
        assert_eq!(words[7], (length - 4) * 4);
        assert_eq!(
            words[2],
            words[4..].iter().fold(0u32, |s, w| s.wrapping_add(*w))
        );
        let phase = self.stages % 3;
        let mut at = 8;
        let mut operation = 0;
        while at < words.len() {
            let bytes = words[at] as usize;
            assert!(bytes >= 8 && bytes % 4 == 0 && at + bytes / 4 <= words.len());
            let data = &words[at + 2..at + bytes / 4];
            let pointer = |n: usize| (u64::from(data[n]) << 32) | u64::from(data[n + 1]);
            match words[at + 1] {
                1 => {
                    assert_eq!(pointer(1), base + e::SESSION);
                    assert!((0x10008..=0x1000a).contains(&data[0]));
                }
                2 => {
                    assert_eq!(data[0] as usize, (words.len() - at) * 4);
                    assert_eq!(data[1], u32::from(phase) + 1);
                    assert_eq!(data[2], u32::from(phase == 1));
                }
                0x0f => {
                    assert_eq!(pointer(2), base + e::INPUT);
                    assert_eq!(pointer(4), base + e::INPUT + e::LUMA_BYTES);
                    assert_eq!(&data[6..8], &[512, 256]);
                }
                0x12 => {
                    assert_eq!(pointer(1), base + e::OUTPUT);
                    assert_eq!(u64::from(data[3]), e::OUTPUT_BYTES);
                    assert!(pointer(1) - base + u64::from(data[3]) <= e::OUTPUT_END_GUARD);
                }
                0x15 => assert_eq!(pointer(1), base + e::FEEDBACK),
                0x01000001..=0x01000003 => operation = words[at + 1],
                _ => {}
            }
            at += bytes / 4;
        }
        assert_eq!(
            operation,
            [0x01000001, 0x01000003, 0x01000002][phase as usize]
        );
        if phase == 1 {
            for row in 0..192usize {
                assert_eq!(
                    &self.memory
                        [e::INPUT as usize + row * 512..e::INPUT as usize + row * 512 + 320],
                    &e::FRAME[row * 320..(row + 1) * 320]
                );
                assert!(self.memory
                    [e::INPUT as usize + row * 512 + 320..e::INPUT as usize + (row + 1) * 512]
                    .iter()
                    .all(|b| *b == 0));
            }
            assert_eq!(
                &self.memory[e::CDF as usize..e::CDF as usize + e::DEFAULT_CDF.len()],
                e::DEFAULT_CDF
            );
            if self.fault == 7 {
                return false;
            }
            assert_eq!(self.word(e::FEEDBACK + 24), 0);
            assert_eq!(
                &self.memory[e::OUTPUT as usize..e::OUTPUT as usize + e::HEADERS.len()],
                e::HEADERS
            );
            if self.fault != 1 {
                self.memory[e::OUTPUT as usize + e::HEADER_PREFIX as usize
                    ..e::OUTPUT as usize + e::HEADER_PREFIX as usize + STREAM.len()]
                    .copy_from_slice(STREAM);
                self.store(e::FEEDBACK + 32, e::HEADER_PREFIX as u32);
                self.store(e::FEEDBACK + 4, 1);
                self.store(
                    e::FEEDBACK + 24,
                    e::HEADER_PREFIX as u32 + STREAM.len() as u32,
                );
            }
            match self.fault {
                2 => self.memory[e::OUTPUT as usize + 5] = 255,
                3 => self.store(e::FEEDBACK + 24, e::OUTPUT_BYTES as u32 + 1),
                4 => self.store(e::OUTPUT_END_GUARD, 0),
                5 => self.store(e::INPUT, 0),
                6 => self.store(e::ENCODE_IB + 8192 - 4, 1),
                10 => self.store(e::FEEDBACK + 4, 0),
                11 => self.store(e::FEEDBACK + 32, 1),
                12 => self.store(e::FEEDBACK + 24, 0),
                13 => self.memory[e::OUTPUT as usize + e::HEADER_PREFIX as usize] ^= 4,
                14 => self.memory[e::OUTPUT as usize + e::HEADERS.len()] = 1,
                15 => self.store(e::CDF_END_GUARD, 0),
                _ => {}
            }
        }
        self.stages += 1;
        true
    }
}
const CAPACITY: u64 = BYTES
    + ib_words::IB_BYTES
    + e::BYTES
    + av1_320_words::BYTES
    + av1_words::BYTES
    + hevc_encode_words::BYTES
    + hevc_roundtrip_words::BYTES;
fn ready() -> (Pool, Engine<Fake>, Irqs) {
    let (pool, mut engine) = fixture_capacity(CAPACITY);
    run(engine.start(IMAGE, power())).unwrap();
    run(engine.prove()).unwrap();
    let mut o = irqs(&engine, Some(64));
    run(engine.prove_interrupts(&mut o)).unwrap();
    run(engine.prove_ibs(&mut o)).unwrap();
    engine.av1_roundtrip_memory = Some(pool.reserve(av1_320_words::BYTES).unwrap());
    engine
        .io
        .av1_roundtrip
        .bind(engine.av1_roundtrip_memory.as_ref().unwrap());
    (pool, engine, o)
}
fn vcn5_av1_encoder_requires_exact_native_roundtrip_and_newest_completion() -> TestResult {
    let (pool, mut e, mut o) = ready();
    for restart in [false, true] {
        if restart {
            e.seq = u32::MAX;
            run(e.start(IMAGE, power())).unwrap();
            run(e.prove()).unwrap();
            run(e.prove_interrupts(&mut o)).unwrap();
            run(e.prove_ibs(&mut o)).unwrap();
        }
        run(e.prove_av1(&mut o)).unwrap();
        run(e.prove_hevc_encode(&mut o)).unwrap();
        let prior = e.hevc_encode_result.unwrap().unwrap().decoded.completion;
        let p = run(e.prove_av1_encode(&mut o)).unwrap();
        assert_eq!(
            p.encoded.output_bytes,
            (e::HEADERS.len() + STREAM.len()) as u32
        );
        assert_eq!(p.encoded.profile, 0);
        assert_eq!(
            p.encoded.completion.fence.sequence,
            prior.fence.sequence + 1
        );
        assert_eq!(
            p.decoded.completion.fence.sequence,
            p.encoded.completion.fence.sequence + 1
        );
        assert_eq!((p.pixel_error_sum, p.max_pixel_error), (0, 0));
        assert_eq!(e.seq, p.decoded.completion.fence.sequence);
        assert_eq!(e.av1_encode_result, Some(Ok(p)));
        assert_eq!(e.state, State::Av1EncodeVerified);
        assert_eq!(run(e.prove_av1_encode(&mut o)), Err(Error::Busy));
        let job = crate::amdgpu_gfx12_queue::Job::new(3, 11, 0x1000, &[(0x2000, 4)]).unwrap();
        let sequence = p.decoded.completion.fence.sequence + 1;
        assert_eq!(e.submit(job), Ok(sequence));
        assert_eq!(e.completed_job(), Ok(sequence));
        assert_eq!(e.io.client_ibs.last(), Some(&(3, 0x2000, 4)));
        run(e.stop()).unwrap();
        assert!(e.av1_encode_memory.as_ref().unwrap().reusable_for_test());
        assert!(e.av1_roundtrip_memory.as_ref().unwrap().reusable_for_test());
    }
    drop(e);
    assert_eq!(pool.available(), CAPACITY);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_av1_encoder_requires_exact_native_roundtrip_and_newest_completion
);
fn vcn5_av1_encoder_uncertain_output_and_delivery_retain_both_arenas() -> TestResult {
    for fault in [1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15] {
        let (pool, mut e, mut o) = ready();
        e.io.av1_encoding.fault = fault;
        assert!(run(e.prove_av1_encode(&mut o)).is_err());
        assert_eq!(e.io.av1_roundtrip.stages, 0);
        assert!(e.av1_encode_result.unwrap().is_err());
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let free = pool.available();
        drop(e);
        assert_eq!(pool.available(), free);
    }
    for fault in 0..3 {
        let (pool, mut e, mut o) = ready();
        if fault == 0 {
            e.io.fence = false;
        } else if fault == 1 {
            e.io.emit_cpu = false;
        } else {
            e.io.emit_iv = false;
        }
        assert_eq!(run(e.prove_av1_encode(&mut o)), Err(Error::Timeout));
        let free = pool.available();
        drop(e);
        assert_eq!(pool.available(), free);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_av1_encoder_uncertain_output_and_delivery_retain_both_arenas
);
fn vcn5_av1_roundtrip_failures_cancellation_and_pixel_limits_never_publish() -> TestResult {
    for fault in [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12] {
        let (pool, mut e, mut o) = ready();
        e.io.av1_roundtrip.fault = fault;
        assert!(run(e.prove_av1_encode(&mut o)).is_err());
        assert_eq!(e.io.av1_encoding.stages, 3);
        assert!(e.av1_encode_result.unwrap().is_err());
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let free = pool.available();
        drop(e);
        assert_eq!(pool.available(), free);
    }
    for phase in 0..3 {
        let (pool, mut e, mut o) = ready();
        if phase == 2 {
            e.io.av1_roundtrip.fault = 4;
        } else if phase == 1 {
            e.io.av1_encoding.fault = 7;
        }
        let mut future = alloc::boxed::Box::pin(e.prove_av1_encode(&mut o));
        let w = Waker::noop();
        let mut cx = Context::from_waker(w);
        if phase == 0 {
            assert!(future.as_mut().poll(&mut cx).is_pending());
        } else {
            let polls = if phase == 1 { 1000 } else { 11000 };
            for _ in 0..polls {
                assert!(future.as_mut().poll(&mut cx).is_pending());
            }
        }
        drop(future);
        assert_eq!(
            e.io.av1_encoding.stages,
            if phase == 0 {
                0
            } else if phase == 1 {
                1
            } else {
                3
            }
        );
        assert_eq!(e.io.av1_roundtrip.stages, if phase == 2 { 1 } else { 0 });
        assert_eq!(e.state, State::Av1EncodeTesting);
        assert_eq!(e.av1_encode_result, Some(Err(Error::Busy)));
        assert_eq!(run(e.stop()), Err(Error::Busy));
        assert!(!e.av1_encode_memory.as_ref().unwrap().reusable_for_test());
        assert!(!e.av1_roundtrip_memory.as_ref().unwrap().reusable_for_test());
        let free = pool.available();
        drop(e);
        assert_eq!(pool.available(), free);
    }
    let (_pool, mut e, mut o) = ready();
    e.io.av1_roundtrip.fault = 10;
    let p = run(e.prove_av1_encode(&mut o)).unwrap();
    assert_eq!(p.pixel_error_sum, e::FRAME.len() as u64);
    assert_eq!(p.max_pixel_error, 1);
    run(e.stop()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_av1_roundtrip_failures_cancellation_and_pixel_limits_never_publish
);

fn vcn5_av1_encoder_refuses_before_publication_without_complete_budget() -> TestResult {
    for spare in [0, av1_encode_words::BYTES] {
        let capacity = BYTES + ib_words::IB_BYTES + spare;
        let (pool, mut e) = fixture_capacity(capacity);
        run(e.start(IMAGE, power())).unwrap();
        run(e.prove()).unwrap();
        let mut o = irqs(&e, Some(64));
        run(e.prove_interrupts(&mut o)).unwrap();
        run(e.prove_ibs(&mut o)).unwrap();
        assert_eq!(run(e.prove_av1_encode(&mut o)), Err(Error::Allocation));
        assert_eq!(e.state, State::IbVerified);
        assert!(e.av1_encode_result.is_none());
        assert!(e.av1_roundtrip_memory.is_none());
        assert!(e.io.av1_encoding.base.is_none());
        assert!(e.io.av1_roundtrip.base_for_test().is_none());
        run(e.stop()).unwrap();
        drop(e);
        assert_eq!(pool.available(), capacity);
    }
    for stale in [false, true] {
        let (pool, mut e, mut o) = ready();
        if stale {
            e.seq += 1;
        } else {
            e.encode_interface = None;
        }
        assert_eq!(
            run(e.prove_av1_encode(&mut o)),
            Err(if stale {
                Error::Busy
            } else {
                Error::Unsupported
            })
        );
        assert!(e.av1_encode_result.is_none());
        assert!(e.av1_encode_memory.is_none());
        run(e.stop()).unwrap();
        drop(e);
        assert_eq!(pool.available(), CAPACITY);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_av1_encoder_refuses_before_publication_without_complete_budget
);

fn vcn5_av1_encoder_retries_unpublished_budget_refusal_and_rejects_lost_authority() -> TestResult {
    let capacity = BYTES + ib_words::IB_BYTES + e::BYTES + av1_320_words::BYTES;
    let (pool, mut e) = fixture_capacity(capacity);
    run(e.start(IMAGE, power())).unwrap();
    run(e.prove()).unwrap();
    let mut o = irqs(&e, Some(64));
    run(e.prove_interrupts(&mut o)).unwrap();
    run(e.prove_ibs(&mut o)).unwrap();
    let block = pool.reserve(av1_320_words::BYTES).unwrap();
    assert_eq!(run(e.prove_av1_encode(&mut o)), Err(Error::Allocation));
    assert!(e.av1_encode_memory.as_ref().unwrap().reusable_for_test());
    assert!(e.av1_encode_result.is_none());
    drop(block);
    e.av1_roundtrip_memory = Some(pool.reserve(av1_320_words::BYTES).unwrap());
    e.io.av1_roundtrip
        .bind(e.av1_roundtrip_memory.as_ref().unwrap());
    run(e.prove_av1_encode(&mut o)).unwrap();
    run(e.stop()).unwrap();
    drop(e);
    assert_eq!(pool.available(), capacity);
    for revoked in [false, true] {
        let (pool, mut e, mut o) = ready();
        if revoked {
            e.io.fence_revoke = Some(e.authority);
        } else {
            e.io.fence_gone = true;
        }
        assert!(matches!(
            run(e.prove_av1_encode(&mut o)),
            Err(Error::Revoked | Error::DeviceGone)
        ));
        assert!(e.av1_encode_result.unwrap().is_err());
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let free = pool.available();
        drop(e);
        assert_eq!(pool.available(), free);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_av1_encoder_retries_unpublished_budget_refusal_and_rejects_lost_authority
);

fn vcn5_av1_encoder_roundtrip_handles_pending_old_pointer_across_wrap() -> TestResult {
    for (start, stall) in [(960, false), (896, false), (960, true), (896, true)] {
        let (_pool, mut e, mut o) = ready();
        e.wptr = start;
        e.io.regs.insert(e.layout.vcn + u64::from(RPTR) * 4, start);
        e.io.regs.insert(e.layout.vcn + u64::from(WPTR) * 4, start);
        e.ib_result
            .as_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .fence
            .read_pointer = start;
        if stall {
            if start == 960 {
                e.io.advance = false;
            } else {
                e.io.av1_roundtrip.fault = 4;
            }
        }
        let result = run(e.prove_av1_encode(&mut o));
        if stall {
            assert_eq!(result, Err(Error::Timeout));
            assert!(e.av1_encode_result.unwrap().is_err());
            assert_eq!(run(e.stop()), Err(Error::Busy));
        } else {
            let p = result.unwrap();
            assert_eq!(p.encoded.completion.fence.read_pointer, (start + 64) & 1023);
            assert_eq!(
                p.decoded.completion.fence.read_pointer,
                (start + 128) & 1023
            );
            run(e.stop()).unwrap();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_av1_encoder_roundtrip_handles_pending_old_pointer_across_wrap
);
