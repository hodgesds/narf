//! Synthetic pixel output validates ownership/checksum rules, not JPEG decoding.
use super::*;
use decode_words as d;
#[derive(Default)]
pub(super) struct Model {
    base: Option<u64>,
    memory: Vec<u8>,
    pub(super) fault: u8,
    decoded: u32,
}
impl Model {
    pub(super) fn contains(&self, address: u64) -> bool {
        self.base
            .is_some_and(|base| (base..base + d::BYTES).contains(&address))
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
    pub(super) fn write(&mut self, map: MmioRegion, at: u64, value: u32) -> bool {
        if map.len != d::BYTES {
            return false;
        }
        let base = GPU + map.phys.raw() - 0x90004000;
        if let Some(previous) = self.base {
            assert_eq!(base, previous);
        }
        self.base = Some(base);
        self.memory.resize(d::BYTES as usize, 0x5a);
        self.memory[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
        true
    }
    pub(super) fn execute(&mut self, address: u64, length: u32) -> bool {
        let base = self.base.unwrap();
        assert_eq!(address, base + d::IB);
        assert_eq!(length % 16, 0);
        let mut registers = BTreeMap::new();
        let mut reset = false;
        let mut completed = false;
        for at in (0..length).step_by(2) {
            let header = self.word(address - base + u64::from(at) * 4);
            let value = self.word(address - base + u64::from(at + 1) * 4);
            let reg = header & 0x3ffff;
            match header >> 28 {
                0 => {
                    registers.insert(reg, value);
                    if reg == 0x4051 {
                        reset = value != 0;
                    }
                    if reg == 0x4000 && value == 0xe {
                        let pointer = |n: u32| {
                            (u64::from(registers[&(n + 1)]) << 32) | u64::from(registers[&n])
                        };
                        assert_eq!(pointer(0x40b2), base + d::INPUT);
                        assert_eq!(pointer(0x40b4), base + d::TARGET);
                        assert_eq!((registers[&0x4043], registers[&0x4044]), (16, 16));
                        assert_eq!(
                            (registers[&0x41c0], registers[&0x41c1]),
                            (0, d::CHROMA as u32)
                        );
                        assert_eq!(registers[&0x4002], 128);
                        assert_eq!(
                            &self.memory[d::INPUT as usize..d::INPUT as usize + d::STREAM.len()],
                            d::STREAM
                        );
                        assert!(
                            self.memory[d::TARGET as usize..d::TARGET_END_GUARD as usize]
                                .iter()
                                .all(|b| *b == 0)
                        );
                        if self.fault == 6 {
                            return false;
                        }
                        if self.fault != 1 {
                            for at in 0..d::TARGET_BYTES {
                                if at % d::PITCH < d::WIDTH {
                                    self.memory[(d::TARGET + at) as usize] =
                                        if at < d::CHROMA { 32 } else { 64 };
                                }
                            }
                        }
                        match self.fault {
                            2 => self.memory[(d::TARGET + d::CHROMA) as usize] -= 1,
                            3 => self.memory[d::TARGET_END_GUARD as usize] ^= 1,
                            4 => self.memory[d::INPUT as usize] ^= 1,
                            5 => self.memory[(d::IB + 4092) as usize] = 1,
                            _ => {}
                        }
                        completed = true;
                    }
                }
                3 => {
                    let actual = match reg {
                        0x4051 => u32::from(reset) << 16,
                        0x4003 => {
                            assert!(completed);
                            128
                        }
                        0x4041 => {
                            assert!(completed);
                            1
                        }
                        _ => panic!("unexpected JPEG decode wait"),
                    };
                    assert_eq!(header >> 24, 0x33);
                    assert_eq!(actual & value, registers[&0x408f] & value);
                }
                6 => {}
                _ => panic!("unexpected JPEG picture opcode"),
            }
        }
        assert!(completed);
        assert_eq!(registers[&0x4000], 4);
        self.decoded += 1;
        true
    }
}
fn ready() -> (Pool, Engine<Fake>, Irqs) {
    let (pool, mut engine, mut observer) = fixture_capacity(BYTES + d::BYTES);
    run(engine.start(power())).unwrap();
    run(engine.prove(&mut observer)).unwrap();
    (pool, engine, observer)
}
fn jpeg5_picture_proves_both_active_planes_and_retires_every_arena() -> TestResult {
    for wide in [false, true] {
        let (pool, mut engine, mut observer) = ready();
        engine.io.wide = wide;
        for restart in [false, true] {
            if restart {
                engine.seq = u32::MAX;
                run(engine.start(power())).unwrap();
                run(engine.prove(&mut observer)).unwrap();
            }
            let transport = engine.result.unwrap().unwrap();
            let proof = run(engine.prove_decode(&mut observer)).unwrap();
            assert_eq!(
                proof,
                DecodeProof {
                    completion: Proof {
                        sequence: 2,
                        read_pointer: 144,
                        msi_verified: true
                    },
                    output_sum: d::EXPECTED_SUM
                }
            );
            assert_eq!(engine.result, Some(Ok(transport)));
            assert_eq!(engine.decode_result, Some(Ok(proof)));
            assert_eq!(engine.state, State::DecodeVerified);
            assert_eq!(engine.io.picture.decoded, if restart { 2 } else { 1 });
            assert_eq!(run(engine.prove_decode(&mut observer)), Err(Error::Busy));
            assert!(!engine.decode_memory.as_ref().unwrap().reusable_for_test());
            run(engine.stop()).unwrap();
            assert!(engine.decode_memory.as_ref().unwrap().reusable_for_test());
            assert!(engine.memory.reusable_for_test());
        }
        assert_eq!(pool.available(), 0);
        drop(engine);
        assert_eq!(pool.available(), BYTES + d::BYTES);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_picture_proves_both_active_planes_and_retires_every_arena
);
fn jpeg5_picture_failures_quarantine_all_published_backing() -> TestResult {
    for fault in 1..=12 {
        let (pool, mut engine, mut observer) = ready();
        engine.io.picture.fault = fault;
        match fault {
            7 => {
                engine.io.store(FENCE, 2);
                engine.io.fence = false;
            }
            8 => engine.io.iv = false,
            9 => engine.io.cpu = false,
            10 => engine.io.damage = true,
            12 => {
                engine.io.regs.insert(NBIO + 0xc3 * 4, u32::MAX);
            }
            _ => {}
        }
        let expected = match fault {
            1 => Error::DecodeChecksum(0),
            2 => Error::DecodeChecksum(d::EXPECTED_SUM - 1),
            3..=5 | 10 | 11 => Error::Readback,
            12 => Error::DeviceGone,
            _ => Error::Timeout,
        };
        assert_eq!(run(engine.prove_decode(&mut observer)), Err(expected));
        assert_eq!(engine.state, State::Failed(expected));
        assert_eq!(engine.decode_result, Some(Err(expected)));
        assert!(!engine.memory.reusable_for_test());
        assert!(!engine.decode_memory.as_ref().unwrap().reusable_for_test());
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_picture_failures_quarantine_all_published_backing
);
fn jpeg5_picture_cancel_retains_input_target_and_commands_before_and_after_publish() -> TestResult {
    for published in [false, true] {
        let (pool, mut engine, mut observer) = ready();
        observer.stall_observed = published;
        {
            let mut f = core::pin::pin!(engine.prove_decode(&mut observer));
            for _ in 0..if published { d::BYTES / 4096 + 1 } else { 1 } {
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
        }
        assert_eq!(engine.wptr, if published { 144 } else { 80 });
        assert_eq!(engine.io.picture.decoded, u32::from(published));
        assert_eq!(engine.state, State::DecodeTesting);
        assert_eq!(engine.decode_result, Some(Err(Error::Busy)));
        assert!(!engine.decode_memory.as_ref().unwrap().reusable_for_test());
        assert_eq!(run(engine.stop()), Err(Error::Busy));
        let available = pool.available();
        drop(engine);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_picture_cancel_retains_input_target_and_commands_before_and_after_publish
);
fn jpeg5_picture_allocation_refusal_leaves_the_prior_witness_usable() -> TestResult {
    let (pool, mut engine, mut observer) = ready();
    let filler = pool.reserve(d::BYTES).unwrap();
    assert_eq!(
        run(engine.prove_decode(&mut observer)),
        Err(Error::Allocation)
    );
    assert_eq!(engine.state, State::Verified);
    assert!(engine.decode_result.is_none() && engine.decode_memory.is_none());
    assert_eq!((engine.seq, engine.wptr), (1, 80));
    drop(filler);
    run(engine.prove_decode(&mut observer)).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_picture_allocation_refusal_leaves_the_prior_witness_usable
);
fn jpeg5_picture_requires_the_current_drained_transport_before_allocation() -> TestResult {
    for stale in [false, true] {
        let (pool, mut engine, mut observer) = ready();
        if stale {
            engine.seq += 1;
        } else {
            engine.io.regs.insert(VCN + u64::from(RPTR) * 4, 0);
        }
        let available = pool.available();
        assert_eq!(run(engine.prove_decode(&mut observer)), Err(Error::Busy));
        assert_eq!(engine.state, State::Verified);
        assert!(engine.decode_result.is_none() && engine.decode_memory.is_none());
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/jpeg-navi48",
    jpeg5_picture_requires_the_current_drained_transport_before_allocation
);
