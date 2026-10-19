// SPDX-License-Identifier: GPL-2.0-or-later
// SPS/PPS test bytes from IGT 2.4 tests/amdgpu/amd_vcn.c:
// Copyright 2023 Advanced Micro Devices, Inc.
// Copyright 2014 Advanced Micro Devices, Inc.
// Original MIT permission notice: ../VCN-NOTICES.
use super::*;
use encode_words as e;

// Synthetic headers exercise proof ownership and validation. This model is
// not an encoder, and successful model runs say nothing about picture quality.
const STREAM: &[u8] = &[
    0, 0, 0, 1, 0x67, 0x64, 0x44, 0x0b, 0xac, 0x54, 0xc2, 0x84, 0x68, 0x07, 0x84, 0x42, 0x37, 0, 0,
    0, 1, 0x68, 0xce, 0x3c, 0x80, 0, 0, 1, 0x65, 0xb8,
];
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
                    assert_eq!(data[0], 0x10009);
                }
                2 => {
                    assert_eq!(data[0] as usize, (words.len() - at) * 4);
                    assert_eq!(data[1], u32::from(phase) + 1);
                    assert_eq!(data[2], u32::from(phase == 1));
                }
                0x0f => {
                    assert_eq!(pointer(2), base + e::INPUT);
                    assert_eq!(pointer(4), base + e::INPUT + e::LUMA_BYTES);
                    assert_eq!(&data[6..8], &[256, 128]);
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
                        [e::INPUT as usize + row * 256..e::INPUT as usize + row * 256 + 160],
                    &e::FRAME[row * 160..row * 160 + 160]
                );
                assert!(self.memory
                    [e::INPUT as usize + row * 256 + 160..e::INPUT as usize + (row + 1) * 256]
                    .iter()
                    .all(|b| *b == 0));
            }
            if self.fault == 7 {
                return false;
            }
            assert_eq!(self.word(e::FEEDBACK + 24), 0);
            assert!(
                self.memory[e::OUTPUT as usize..e::OUTPUT_END_GUARD as usize]
                    .iter()
                    .all(|b| *b == 0)
            );
            if self.fault != 1 {
                self.memory[e::OUTPUT as usize..e::OUTPUT as usize + STREAM.len()]
                    .copy_from_slice(STREAM);
                self.store(e::FEEDBACK + 24, STREAM.len() as u32);
            }
            match self.fault {
                2 => self.memory[e::OUTPUT as usize + 5] = 255,
                3 => self.store(e::FEEDBACK + 24, e::OUTPUT_BYTES as u32 + 1),
                4 => self.store(e::OUTPUT_END_GUARD, 0),
                5 => self.store(e::INPUT, 0),
                6 => self.store(e::ENCODE_IB + 8192 - 4, 1),
                _ => {}
            }
        }
        self.stages += 1;
        true
    }
}
fn ready(decode: bool) -> (Pool, Engine<Fake>, Irqs) {
    let capacity =
        BYTES + ib_words::IB_BYTES + e::BYTES + if decode { decode_words::BYTES } else { 0 };
    let (pool, mut engine) = fixture_capacity(capacity);
    run(engine.start(IMAGE, power())).unwrap();
    run(engine.prove()).unwrap();
    let mut observer = irqs(&engine, Some(64));
    run(engine.prove_interrupts(&mut observer)).unwrap();
    run(engine.prove_ibs(&mut observer)).unwrap();
    if decode {
        run(engine.prove_decode(&mut observer)).unwrap();
    }
    (pool, engine, observer)
}
fn vcn5_encoder_requires_fresh_headers_and_retires_all_storage_on_stop() -> TestResult {
    for decode in [false, true] {
        let (pool, mut engine, mut observer) = ready(decode);
        for restart in [false, true] {
            if restart {
                engine.seq = u32::MAX;
                run(engine.start(IMAGE, power())).unwrap();
                run(engine.prove()).unwrap();
                run(engine.prove_interrupts(&mut observer)).unwrap();
                run(engine.prove_ibs(&mut observer)).unwrap();
                if decode {
                    run(engine.prove_decode(&mut observer)).unwrap();
                }
            }
            let proof = run(engine.prove_encode(&mut observer)).unwrap();
            assert_eq!(
                (proof.profile, proof.output_bytes),
                (100, STREAM.len() as u32)
            );
            assert_eq!(engine.state, State::EncodeVerified);
            assert_eq!(engine.encode_result, Some(Ok(proof)));
            assert_eq!(engine.io.encoding.stages, if restart { 6 } else { 3 });
            assert!(!engine.encode_memory.as_ref().unwrap().reusable_for_test());
            assert_eq!(run(engine.prove_encode(&mut observer)), Err(Error::Busy));
            run(engine.stop()).unwrap();
            assert!(engine.encode_memory.as_ref().unwrap().reusable_for_test());
        }
        let reserved = engine.memory.size()
            + engine.ib_memory.as_ref().unwrap().size()
            + engine.encode_memory.as_ref().unwrap().size()
            + engine.decode_memory.as_ref().map_or(0, Reservation::size);
        assert_eq!(pool.available(), 0);
        drop(engine);
        assert_eq!(pool.available(), reserved);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_encoder_requires_fresh_headers_and_retires_all_storage_on_stop
);

fn vcn5_encoder_failures_quarantine_commands_input_and_declared_output() -> TestResult {
    for fault in 1..=9 {
        let (pool, mut engine, mut observer) = ready(false);
        engine.io.encoding.fault = fault;
        if fault == 8 {
            engine.io.fence = false;
        }
        if fault == 9 {
            engine.io.emit_cpu = false;
        }
        let expected = match fault {
            1..=3 => Error::EncodeOutput,
            4..=6 => Error::Readback,
            _ => Error::Timeout,
        };
        assert_eq!(run(engine.prove_encode(&mut observer)), Err(expected));
        assert_eq!(engine.state, State::Failed(expected));
        assert_eq!(engine.encode_result, Some(Err(expected)));
        assert!(!engine.encode_memory.as_ref().unwrap().reusable_for_test());
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_encoder_failures_quarantine_commands_input_and_declared_output
);

fn vcn5_encoder_cancellation_keeps_the_pending_owner_before_and_after_publication() -> TestResult {
    for published in [false, true] {
        let (pool, mut engine, mut observer) = ready(false);
        observer.stall_observed = published;
        {
            let mut future = core::pin::pin!(engine.prove_encode(&mut observer));
            let polls = if published {
                e::BYTES / 4096 + e::INPUT_BYTES / 4096 + 5
            } else {
                1
            };
            for _ in 0..polls {
                assert!(future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
        }
        assert_eq!(engine.io.encoding.stages, if published { 3 } else { 0 });
        assert_eq!(engine.state, State::EncodeTesting);
        assert_eq!(engine.encode_result, Some(Err(Error::Busy)));
        assert!(!engine.encode_memory.as_ref().unwrap().reusable_for_test());
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_encoder_cancellation_keeps_the_pending_owner_before_and_after_publication
);

fn vcn5_encoder_allocation_failure_keeps_the_prior_proof_usable() -> TestResult {
    let (pool, mut engine, mut observer) = ready(false);
    let filler = pool.reserve(e::BYTES).unwrap();
    assert_eq!(
        run(engine.prove_encode(&mut observer)),
        Err(Error::Allocation)
    );
    assert_eq!(engine.state, State::IbVerified);
    assert!(engine.encode_memory.is_none() && engine.encode_result.is_none());
    drop(filler);
    run(engine.prove_encode(&mut observer)).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_encoder_allocation_failure_keeps_the_prior_proof_usable
);

fn vcn5_encoder_header_inspector_bounds_reads_and_matches_parameter_set_ids() -> TestResult {
    let picture = h264::inspect(STREAM).unwrap();
    assert_eq!(
        (
            picture.width,
            picture.height,
            picture.slice_type,
            picture.idr
        ),
        (160, 128, 2, true)
    );
    // The known decoder fixture deliberately has slices without SPS/PPS.
    assert_eq!(h264::inspect(decode_words::STREAM), None);
    for end in 0..STREAM.len() {
        assert_eq!(h264::inspect(&STREAM[..end]), None);
    }
    let mut wrong = STREAM.to_vec();
    wrong[22] = 0x58; // PPS id 1, SPS id 0; the slice references PPS id 0.
    assert_eq!(h264::inspect(&wrong), None);
    let mut oversized = vec![0; 0x1f001];
    oversized[..STREAM.len()].copy_from_slice(STREAM);
    assert_eq!(h264::inspect(&oversized), None);
    for byte in 0..=255 {
        assert_eq!(h264::inspect(&[byte; 256]), None);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_encoder_header_inspector_bounds_reads_and_matches_parameter_set_ids
);
