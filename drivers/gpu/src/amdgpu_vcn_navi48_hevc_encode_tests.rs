// SPDX-License-Identifier: GPL-2.0-or-later
// SPS/PPS test bytes from IGT 2.4 tests/amdgpu/amd_vcn.c:
// Copyright 2023 Advanced Micro Devices, Inc.
// Copyright 2014 Advanced Micro Devices, Inc.
// Original MIT permission notice: ../VCN-NOTICES.
use super::*;
use hevc_encode_words as e;

// Synthetic headers exercise proof ownership and validation. This model is
// not an encoder, and successful model runs say nothing about picture quality.
const STREAM: &[u8] = include_bytes!("../fixtures/vcn5/hevc_encode/reference.hevc");
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
                        [e::INPUT as usize + row * 512..e::INPUT as usize + row * 512 + 384],
                    &e::FRAME[row * 384..row * 384 + 384]
                );
                assert!(self.memory
                    [e::INPUT as usize + row * 512 + 384..e::INPUT as usize + (row + 1) * 512]
                    .iter()
                    .all(|b| *b == 0));
            }
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
                    ..e::OUTPUT as usize + STREAM.len()]
                    .copy_from_slice(&STREAM[e::HEADER_PREFIX as usize..]);
                self.store(e::FEEDBACK + 32, e::HEADER_PREFIX as u32);
                self.store(e::FEEDBACK + 4, 1);
                self.store(e::FEEDBACK + 24, STREAM.len() as u32);
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
                13 => self.store(e::INPUT + u64::from(e::WIDTH), 1),
                _ => {}
            }
        }
        self.stages += 1;
        true
    }
}
fn ready() -> (Pool, Engine<Fake>, Irqs) {
    let (pool, mut engine) = fixture_capacity(
        BYTES + ib_words::IB_BYTES + e::BYTES + hevc_roundtrip_words::BYTES + encode_words::BYTES,
    );
    run(engine.start(IMAGE, power())).unwrap();
    run(engine.prove()).unwrap();
    let mut observer = irqs(&engine, Some(64));
    run(engine.prove_interrupts(&mut observer)).unwrap();
    run(engine.prove_ibs(&mut observer)).unwrap();
    (pool, engine, observer)
}
fn vcn5_hevc_encoder_requires_roundtrip_and_fresh_successor_after_restart() -> TestResult {
    let (pool, mut engine, mut observer) = ready();
    for restart in [false, true] {
        if restart {
            engine.seq = u32::MAX;
            run(engine.start(IMAGE, power())).unwrap();
            run(engine.prove()).unwrap();
            run(engine.prove_interrupts(&mut observer)).unwrap();
            run(engine.prove_ibs(&mut observer)).unwrap();
        }
        run(engine.prove_encode(&mut observer)).unwrap();
        let p = run(engine.prove_hevc_encode(&mut observer)).unwrap();
        assert_eq!(
            (p.encoded.profile, p.encoded.output_bytes),
            (1, STREAM.len() as u32)
        );
        assert_eq!((p.pixel_error_sum, p.max_pixel_error), (0, 0));
        assert_eq!(
            p.decoded.completion.fence.sequence,
            p.encoded.completion.fence.sequence + 1
        );
        assert_eq!(engine.seq, p.decoded.completion.fence.sequence);
        assert_eq!(engine.hevc_encode_result, Some(Ok(p)));
        assert_eq!(engine.state, State::HevcEncodeVerified);
        assert_eq!(
            run(engine.prove_hevc_encode(&mut observer)),
            Err(Error::Busy)
        );
        run(engine.stop()).unwrap();
        assert!(engine
            .hevc_encode_memory
            .as_ref()
            .unwrap()
            .reusable_for_test());
        assert!(engine
            .hevc_roundtrip_memory
            .as_ref()
            .unwrap()
            .reusable_for_test());
    }
    let used =
        BYTES + ib_words::IB_BYTES + e::BYTES + hevc_roundtrip_words::BYTES + encode_words::BYTES;
    drop(engine);
    assert_eq!(pool.available(), used);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_encoder_requires_roundtrip_and_fresh_successor_after_restart
);
fn vcn5_hevc_encoder_uncertain_feedback_and_delivery_never_publish_roundtrip() -> TestResult {
    for fault in [1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13] {
        let (pool, mut e, mut o) = ready();
        e.io.hevc_encoding.fault = fault;
        assert!(run(e.prove_hevc_encode(&mut o)).is_err());
        assert!(e.hevc_encode_result.unwrap().is_err());
        assert_eq!(e.io.hevc_roundtrip.stages, 0);
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let free = pool.available();
        drop(e);
        assert_eq!(pool.available(), free);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_encoder_uncertain_feedback_and_delivery_never_publish_roundtrip
);
fn vcn5_hevc_roundtrip_pixel_error_feedback_guard_and_cancel_quarantine_both_arenas() -> TestResult
{
    for fault in 1..=9 {
        let (pool, mut e, mut o) = ready();
        e.io.hevc_roundtrip.fault = fault;
        assert!(run(e.prove_hevc_encode(&mut o)).is_err());
        assert_eq!(e.io.hevc_encoding.stages, 3);
        assert!(e.hevc_encode_result.unwrap().is_err());
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let free = pool.available();
        drop(e);
        assert_eq!(pool.available(), free);
    }
    for phase in 0..3 {
        let (pool, mut e, mut o) = ready();
        if phase == 2 {
            e.io.hevc_roundtrip.fault = 4;
        }
        o.stall_observed = phase == 1;
        {
            let mut f = core::pin::pin!(e.prove_hevc_encode(&mut o));
            let polls = if phase == 2 {
                (e::BYTES + e::INPUT_BYTES + hevc_roundtrip_words::BYTES) / 4096 + 200
            } else if phase == 1 {
                e::BYTES / 4096 + e::INPUT_BYTES / 4096 + 10
            } else {
                1
            };
            for _ in 0..polls {
                if f.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    panic!("cancel test completed");
                }
            }
        }
        assert_eq!(e.io.hevc_encoding.stages, if phase == 0 { 0 } else { 3 });
        assert_eq!(e.io.hevc_roundtrip.stages, if phase == 2 { 1 } else { 0 });
        assert_eq!(e.state, State::HevcEncodeTesting);
        assert_eq!(e.hevc_encode_result, Some(Err(Error::Busy)));
        assert!(!e.hevc_encode_memory.as_ref().unwrap().reusable_for_test());
        assert!(!e
            .hevc_roundtrip_memory
            .as_ref()
            .unwrap()
            .reusable_for_test());
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let free = pool.available();
        drop(e);
        assert_eq!(pool.available(), free);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_roundtrip_pixel_error_feedback_guard_and_cancel_quarantine_both_arenas
);

fn vcn5_hevc_encoder_refuses_older_firmware_before_arena_publication() -> TestResult {
    let (pool, mut engine, mut observer) = ready();
    let available = pool.available();
    engine.encode_interface = None;
    assert_eq!(
        run(engine.prove_hevc_encode(&mut observer)),
        Err(Error::Unsupported)
    );
    assert_eq!(pool.available(), available);
    assert!(engine.hevc_encode_memory.is_none());
    assert!(engine.hevc_roundtrip_memory.is_none());
    assert!(engine.hevc_encode_result.is_none());
    assert_eq!(engine.state, State::IbVerified);
    engine.encode_interface = Some(0x10008);
    assert!(run(engine.prove_hevc_encode(&mut observer)).is_ok());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_encoder_refuses_older_firmware_before_arena_publication
);

fn vcn5_hevc_encoder_allocation_and_predecessor_refusals_preserve_prior_transport() -> TestResult {
    for first in [false, true] {
        let (pool, mut e, mut o) = ready();
        let leave = if first { 0 } else { e::BYTES };
        let held = pool.reserve(pool.available() - leave).unwrap();
        assert_eq!(run(e.prove_hevc_encode(&mut o)), Err(Error::Allocation));
        assert_eq!(e.state, State::IbVerified);
        assert!(e.hevc_encode_result.is_none());
        assert!(e.hevc_roundtrip_memory.is_none());
        assert_eq!(e.hevc_encode_memory.is_none(), first);
        drop(held);
        assert!(run(e.prove_hevc_encode(&mut o)).is_ok());
    }
    let (_pool, mut e, mut o) = ready();
    e.seq += 1;
    assert_eq!(run(e.prove_hevc_encode(&mut o)), Err(Error::Busy));
    assert!(e.hevc_encode_memory.is_none());
    assert!(e.hevc_encode_result.is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_encoder_allocation_and_predecessor_refusals_preserve_prior_transport
);
fn vcn5_hevc_encoder_revocation_device_loss_and_missing_evidence_retain_arenas() -> TestResult {
    for case in 0..5 {
        let (pool, mut e, mut o) = ready();
        match case {
            0 => e.io.fence_revoke = Some(e.authority),
            1 => e.io.fence_gone = true,
            2 => e.io.fence = false,
            3 => e.io.emit_cpu = false,
            _ => e.io.emit_iv = false,
        }
        assert!(run(e.prove_hevc_encode(&mut o)).is_err());
        assert!(e.hevc_encode_result.unwrap().is_err());
        assert_eq!(e.io.hevc_roundtrip.stages, 0);
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let free = pool.available();
        drop(e);
        assert_eq!(pool.available(), free);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_encoder_revocation_device_loss_and_missing_evidence_retain_arenas
);

fn vcn5_hevc_roundtrip_checks_per_component_and_mean_fidelity_boundaries() -> TestResult {
    let (_pool, mut e, mut o) = ready();
    e.io.hevc_roundtrip.fault = 10;
    let p = run(e.prove_hevc_encode(&mut o)).unwrap();
    assert_eq!(p.pixel_error_sum, hevc_roundtrip_words::TARGET_BYTES);
    assert_eq!(p.max_pixel_error, 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_roundtrip_checks_per_component_and_mean_fidelity_boundaries
);

fn vcn5_hevc_encode_roundtrip_accepts_pointer_wrap_and_retains_pending_boundary() -> TestResult {
    for (start, stalled) in [(960, false), (896, false), (960, true), (896, true)] {
        let (pool, mut e, mut observer) = ready();
        // Seed a completed, idle queue boundary; the prior proof and both
        // hardware counters name the same retained physical generation.
        e.wptr = start;
        e.io.regs.insert(VCN + u64::from(RPTR) * 4, start);
        e.io.regs.insert(VCN + u64::from(WPTR) * 4, start);
        e.ib_result
            .as_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .fence
            .read_pointer = start;
        if stalled {
            if start == 960 {
                e.io.advance = false;
            } else {
                e.io.hevc_roundtrip.fault = 4;
            }
        }
        let result = run(e.prove_hevc_encode(&mut observer));
        if stalled {
            // The old RPTR960 is still valid progress while next wraps0.
            // It must wait for a genuine completion, then timeout with all
            // published backing retained when this model never advances.
            assert_eq!(result, Err(Error::Timeout));
            assert_eq!(run(e.stop()), Err(Error::Busy));
            let available = pool.available();
            drop(e);
            assert_eq!(pool.available(), available);
        } else {
            let proof = result.unwrap();
            assert_eq!(
                proof.encoded.completion.fence.read_pointer,
                (start + 64) & 1023
            );
            assert_eq!(
                proof.decoded.completion.fence.read_pointer,
                (start + 128) & 1023
            );
            run(e.stop()).unwrap();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_encode_roundtrip_accepts_pointer_wrap_and_retains_pending_boundary
);

fn vcn5_hevc_encode_roundtrip_opens_actual_client_submission() -> TestResult {
    let (_pool, mut engine, mut observer) = ready();
    let proof = run(engine.prove_hevc_encode(&mut observer)).unwrap();
    let job = crate::amdgpu_gfx12_queue::Job::new(3, 11, 0x1000, &[(0x2000, 4)]).unwrap();
    let sequence = proof.decoded.completion.fence.sequence + 1;
    assert_eq!(engine.submit(job), Ok(sequence));
    assert_eq!(engine.completed_job(), Ok(sequence));
    assert_eq!(engine.io.client_ibs.last(), Some(&(3, 0x2000, 4)));
    run(engine.stop()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_encode_roundtrip_opens_actual_client_submission
);

fn vcn5_hevc_encoder_uses_supported_384_geometry_and_every_logical_component() -> TestResult {
    assert_eq!((e::WIDTH, e::HEIGHT, e::PITCH), (384, 128, 512));
    assert_eq!((e::BYTES, hevc_roundtrip_words::BYTES), (798720, 622592));
    assert_eq!((e::REC_BYTES * 2, e::INPUT_BYTES), (393216, 98304));
    assert_eq!(
        (
            hevc_roundtrip_words::CONTEXT_BYTES,
            hevc_roundtrip_words::DPB_BYTES,
            hevc_roundtrip_words::TARGET_BYTES
        ),
        (81952, 147456, 73728)
    );
    assert_eq!(e::FRAME.len(), 73728);
    for (at, &byte) in e::FRAME.iter().enumerate() {
        assert_eq!(byte, hevc_roundtrip_words::expected(at as u64));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_hevc_encoder_uses_supported_384_geometry_and_every_logical_component
);
