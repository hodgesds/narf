use super::*;
use alloc::{collections::BTreeMap, vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const DIO: u64 = 0x20000;
const CLOCK: u64 = 0x10000;
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    edid: Vec<u8>,
    scdc: [u8; 256],
    mccs: mccs::tests::Monitor,
    stall_vendor: bool,
    fifo: Vec<u8>,
    cursor: usize,
    segment: usize,
    segment_nack: bool,
    nack: bool,
    stuck: bool,
    silent: bool,
    gone: bool,
    refused: bool,
    release_twice: bool,
    releases: usize,
    transactions: usize,
    busy_reads: usize,
    revoke: Option<Cap<BusDeviceCap, Write>>,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        if at == CLOCK + 0x7b * 4 {
            return 0x264;
        } // 100 MHz / 2
        let reg = (at - DIO) / 4;
        match reg {
            0x1eb2 => {
                let v = u32::from(self.fifo[self.cursor]) << 8;
                self.cursor += 1;
                v
            }
            0x1e9b if self.transactions != 0 => {
                if self.gone {
                    return u32::MAX;
                }
                if self.busy_reads != 0 || self.stuck {
                    self.busy_reads = self.busy_reads.saturating_sub(1);
                    return 1;
                }
                *self.regs.get(&reg).unwrap_or(&0)
            }
            _ => *self.regs.get(&reg).unwrap_or(&0),
        }
    }
    fn write(&mut self, at: u64, v: u32) {
        let reg = (at - DIO) / 4;
        self.writes.push((reg, v));
        if self.refused && reg == 0x28ff {
            return;
        }
        match reg {
            0x1e99 => {
                let mut v = v;
                if v & 0x00200000 != 0 {
                    self.releases += 1;
                    if !self.release_twice || self.releases > 1 {
                        v &= !0x0030000c;
                    } else {
                        v &= !0x00200000;
                    }
                } else if v & 0x00100000 != 0 {
                    v = (v & !12) | 4;
                }
                self.regs.insert(reg, v);
            }
            0x1eb2 if v & 1 != 0 => {
                assert!(
                    v == 0x80030001 || v == 0x80010001,
                    "wrong read-buffer index"
                );
                self.cursor = ((v >> 16) & 0xff) as usize;
            }
            0x1eb2 => {
                if v & 0x80000000 != 0 {
                    self.fifo.clear();
                }
                self.fifo.push((v >> 8) as u8);
            }
            0x1e98 => {
                if v & 8 != 0 {
                    self.regs.insert(0x1e9b, 0);
                }
                self.regs.insert(reg, v & !9);
                if v & 1 != 0 {
                    assert_eq!(self.regs[&0x1e99] & 12, 4, "GO without SW arbitration");
                    let port = u64::from((v >> 8) & 7);
                    assert!(port < 4);
                    assert_eq!(self.regs[&(0x1ea2 + port * 2)] & 0xffff0303, 0x01f40202);
                    assert_eq!(self.regs[&(0x28d0 + port * 4)] & 0x11111, 0x1010);
                    assert_eq!(self.regs[&0x28ff] >> (10 + port * 2) & 3, 1);
                    assert_ne!(self.regs[&0x291d] & (1 << (12 + port)), 0);
                    let mut nack = self.nack;
                    match self.fifo.as_slice() {
                        [0x6e, body @ ..] => {
                            assert_eq!(self.regs[&0x1eae], (body.len() as u32) << 16 | 0x3100);
                            assert_eq!(v & 0x00300000, 0);
                            self.mccs.write(body);
                        }
                        [0x6f] => {
                            let len = (self.regs[&0x1eae] >> 16) as usize;
                            assert_eq!(self.regs[&0x1eae] & 0xffff, 0x3101);
                            assert_eq!(v & 0x00300000, 0);
                            let mut b = [0; 38];
                            self.mccs.read(&mut b[..len]);
                            self.fifo.extend_from_slice(&b[..len]);
                        }
                        [0x60, segment] => {
                            assert_eq!(self.regs[&0x1eae], 0x13100);
                            assert_eq!(v & 0x00300000, 0);
                            self.segment = usize::from(*segment);
                            nack |= self.segment_nack && self.segment == 0;
                        }
                        [0xa8, offset, 0xa9] if self.regs[&0x1eae] == 0x11100 => {
                            assert_eq!(self.regs[&0x1eaf], 0x13101);
                            assert_eq!(v & 0x00300000, 0x00100000);
                            let byte = self.scdc[usize::from(*offset)];
                            self.fifo.push(byte);
                        }
                        [0xa8, offset, value] => {
                            assert_eq!(self.regs[&0x1eae], 0x23100);
                            assert_eq!(v & 0x00300000, 0);
                            self.scdc[usize::from(*offset)] = *value;
                        }
                        [0xa0, offset, 0xa1] => {
                            assert_eq!(self.regs[&0x1eae], 0x11100);
                            assert_eq!(self.regs[&0x1eaf], 0x803101);
                            assert_eq!(v & 0x00300000, 0x00100000);
                            let from = self.segment * 256 + usize::from(*offset);
                            self.fifo.extend_from_slice(&self.edid[from..from + 128]);
                        }
                        _ => panic!("invalid native E-EDID wire transaction"),
                    }
                    self.regs.insert(
                        0x1e9b,
                        if nack {
                            0x1100
                        } else if self.silent {
                            0
                        } else {
                            4
                        },
                    );
                    self.transactions += 1;
                    self.busy_reads = 1;
                    if let Some(cap) = self.revoke {
                        cap.revoke();
                    }
                }
            }
            0x1eae
            | 0x1eaf
            | 0x1ea2..=0x1ea9
            | 0x1ede
            | 0x28d0
            | 0x28d4
            | 0x28d8
            | 0x28dc
            | 0x28ff
            | 0x291d => {
                self.regs.insert(reg, v);
            }
            _ => panic!("wrong DCN4 I2C register {reg:x}"),
        }
    }
    async fn delay(&mut self, _: u64) {
        if self.stall_vendor && !self.mccs.requests.is_empty() {
            core::future::pending::<()>().await;
        }
        narf_scheduler::yield_now().await;
    }
}
fn checksum(block: &mut [u8]) {
    block[127] = 0u8.wrapping_sub(block[..127].iter().fold(0u8, |s, b| s.wrapping_add(*b)));
}
fn fixture(blocks: usize) -> Engine<Fake> {
    let mut edid = vec![0; blocks * 128];
    edid[..8].copy_from_slice(&[0, 255, 255, 255, 255, 255, 255, 0]);
    edid[18] = 1;
    edid[19] = 4;
    edid[126] = (blocks - 1) as u8;
    for (index, block) in edid.chunks_exact_mut(128).enumerate() {
        if index != 0 {
            block[0] = 2;
            block[1] = index as u8;
        }
        checksum(block);
    }
    let mut regs = BTreeMap::from([
        (0x1e99, 0x12),
        (0x1e9b, 4),
        (0x1e98, 0x80000300),
        (0x28ff, 0x12345678),
        (0x291d, 0xa5a50000),
    ]);
    for channel in 0..4 {
        regs.insert(0x1ea2 + channel * 2, 0x12340011);
        regs.insert(0x1ea3 + channel * 2, 0x55112200);
        regs.insert(0x28d0 + channel * 4, 0x00515151);
    }
    Engine {
        io: Fake {
            regs,
            writes: Vec::new(),
            edid,
            scdc: [0; 256],
            mccs: Default::default(),
            stall_vendor: false,
            fifo: Vec::new(),
            cursor: 0,
            segment: 7,
            segment_nack: false,
            nack: false,
            stuck: false,
            silent: false,
            gone: false,
            refused: false,
            release_twice: false,
            releases: 0,
            transactions: 0,
            busy_reads: 0,
            revoke: None,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            clock: CLOCK,
            dio: DIO,
        },
        crystal_khz: 100_000,
        saved: None,
        state: State::Ready,
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

fn dcn4_ddc_reads_complete_segmented_edid_and_restores_only_selected_pins() -> TestResult {
    for channel in 0..4 {
        let mut e = fixture(5);
        let before = e.io.regs.clone();
        e.io.release_twice = true;
        assert_eq!(run(e.edid(channel)).unwrap(), e.io.edid);
        assert_eq!(e.state, State::Ready);
        assert!(e.saved.is_none());
        assert_eq!(e.io.transactions, 8);
        assert_eq!(e.io.releases, 2);
        for (at, value) in before {
            let extra = if at == 0x1ea3 + u64::from(channel) * 2 {
                8
            } else {
                0
            };
            if at != 0x1e9b {
                assert_eq!(e.io.regs[&at], value | extra, "register {at:x}");
            }
        }
        assert_eq!(run(e.edid(channel)).unwrap(), e.io.edid);
    }
    assert_eq!(prescale(0, 27000), Ok(0x00870202));
    assert_eq!(prescale(0x464, 27000), Ok(0x00fa0202));
    assert_eq!(prescale(0, 0), Err(Error::Invalid));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ddc",
    dcn4_ddc_reads_complete_segmented_edid_and_restores_only_selected_pins
);

fn dcn4_ddc_releases_known_terminal_sink_failures() -> TestResult {
    for case in 0..5 {
        let mut e = fixture(3);
        let expected = match case {
            0 => {
                e.io.segment_nack = true;
                Ok(e.io.edid.clone())
            }
            1 => {
                e.io.nack = true;
                Err(Error::Nack)
            }
            2 => {
                e.io.edid[128] ^= 1;
                Err(Error::InvalidEdid)
            }
            3 => {
                e.io.edid[0] = 3;
                checksum(&mut e.io.edid[..128]);
                Err(Error::InvalidEdid)
            }
            _ => {
                e.io.edid[126] = 32;
                checksum(&mut e.io.edid[..128]);
                Err(Error::EdidTooLarge)
            }
        };
        assert_eq!(run(e.edid(2)), expected);
        assert_eq!(e.state, State::Ready);
        assert_eq!(e.io.releases, 1);
        assert!(e.saved.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ddc",
    dcn4_ddc_releases_known_terminal_sink_failures
);

fn dcn4_ddc_refuses_inherited_ownership_and_invalid_channels_without_writes() -> TestResult {
    for (at, value) in [
        (0x1e99, 4),
        (0x1e99, 8),
        (0x1e99, 0x00100000),
        (0x1e99, 0x01000000),
        (0x1e9b, 1),
        (0x1e98, 1),
        (0x1e9f, 2),
        (0x1ea9, 0x10),
    ] {
        let mut e = fixture(1);
        e.io.regs.insert(at, value);
        assert_eq!(run(e.edid(0)), Err(Error::Busy));
        assert!(e.io.writes.is_empty());
    }
    let mut e = fixture(1);
    assert_eq!(run(e.edid(4)), Err(Error::Invalid));
    assert!(e.io.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ddc",
    dcn4_ddc_refuses_inherited_ownership_and_invalid_channels_without_writes
);

fn dcn4_ddc_fatal_completion_retains_claim_and_prevents_replay() -> TestResult {
    for case in 0..5 {
        let mut e = fixture(1);
        let error = match case {
            0 => {
                e.io.stuck = true;
                Error::Timeout
            }
            1 => {
                e.io.silent = true;
                Error::Timeout
            }
            2 => {
                e.io.gone = true;
                Error::DeviceGone
            }
            3 => {
                e.io.revoke = Some(e.authority);
                Error::Revoked
            }
            _ => {
                e.io.refused = true;
                e.io.regs.insert(0x28ff, 0);
                Error::Readback
            }
        };
        assert_eq!(run(e.edid(1)), Err(error));
        assert_eq!(e.state, State::Failed(error));
        assert_eq!(e.io.releases, 0);
        assert!(e.saved.is_some());
        let writes = e.io.writes.len();
        assert_eq!(run(e.edid(1)), Err(Error::Busy));
        assert_eq!(e.io.writes.len(), writes);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ddc",
    dcn4_ddc_fatal_completion_retains_claim_and_prevents_replay
);

fn dcn4_ddc_cancellation_retains_arbitration_and_pins() -> TestResult {
    for polls in [1, 2] {
        let mut e = fixture(1);
        {
            let mut f = core::pin::pin!(e.edid(3));
            for _ in 0..polls {
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
        }
        assert!(matches!(e.state, State::Acquiring | State::Reading));
        assert!(e.saved.is_some());
        assert_eq!(e.io.regs[&0x1e99] & 12, 4);
        assert_eq!(e.io.releases, 0);
        let writes = e.io.writes.len();
        assert_eq!(run(e.edid(3)), Err(Error::Busy));
        assert_eq!(writes, e.io.writes.len());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ddc",
    dcn4_ddc_cancellation_retains_arbitration_and_pins
);

fn dcn4_ddc_scdc_reads_and_writes_single_registers_at_0x54() -> TestResult {
    for channel in 0..4 {
        let mut e = fixture(1);
        e.io.scdc[1] = 1; // sink version
        if run(e.scdc(channel, 1, None)) != Ok(1) || e.state != State::Ready {
            return TestResult::Fail("SCDC read");
        }
        if run(e.scdc(channel, 0x20, Some(3))) != Ok(3) || e.io.scdc[0x20] != 3 {
            return TestResult::Fail("SCDC write");
        }
        // Each access is its own claim: both released, pins restored.
        if e.io.releases != 2 || e.saved.is_some() {
            return TestResult::Fail("SCDC release");
        }
        // EDID reads are unchanged by the generalized transfer.
        if run(e.edid(channel)).as_ref() != Ok(&e.io.edid) {
            return TestResult::Fail("EDID after SCDC");
        }
    }
    // A sink without SCDC NACKs: a local error, the owner stays usable.
    let mut e = fixture(1);
    e.io.nack = true;
    if run(e.scdc(0, 0x21, None)) != Err(Error::Nack) || e.state != State::Ready {
        return TestResult::Fail("SCDC NACK");
    }
    assert_eq!(run(e.scdc(4, 1, None)), Err(Error::Invalid));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-ddc",
    dcn4_ddc_scdc_reads_and_writes_single_registers_at_0x54
);

fn dcn4_ddcci_uses_raw_transactions_and_retains_cancelled_claim() -> TestResult {
    let mut e = fixture(1);
    let before = e.io.regs.clone();
    let proof = run(e.mccs(2, 101, mccs::tests::metadata())).unwrap();
    assert!(proof.range(101, mccs::tests::metadata()).is_some());
    assert_eq!(e.io.mccs.value, 0x0101);
    assert_eq!(e.state, State::Ready);
    assert!(e.saved.is_none());
    for reg in [0x28ff, 0x291d, 0x28d0, 0x28d4, 0x28dc] {
        assert_eq!(e.io.regs[&reg], before[&reg]);
    }
    // A malformed but completely read message is a local refusal: release
    // the selected channel and leave unrelated DDC/SCDC users usable.
    e.io.mccs.corrupt = true;
    assert_eq!(
        run(e.mccs(0, 102, mccs::tests::metadata())),
        Err(Error::InvalidMccs)
    );
    assert_eq!(e.state, State::Ready);
    assert!(e.saved.is_none());
    e.io.mccs.corrupt = false;
    assert!(run(e.scdc(1, 0x10, Some(1))).is_ok());
    let mut e = fixture(1);
    e.io.stall_vendor = true;
    {
        let mut f = alloc::boxed::Box::pin(e.mccs(2, 103, mccs::tests::metadata()));
        let mut cx = Context::from_waker(Waker::noop());
        // Step beyond acquisition to the first actual vendor request.
        for _ in 0..32 {
            assert!(f.as_mut().poll(&mut cx).is_pending());
        }
    }
    assert_eq!(e.state, State::Reading);
    assert!(e.saved.is_some());
    assert!(!e.io.mccs.requests.is_empty());
    let writes = e.io.writes.len();
    assert_eq!(run(e.edid(0)), Err(Error::Busy));
    assert_eq!(
        run(e.mccs(1, 104, mccs::tests::metadata())),
        Err(Error::Busy)
    );
    assert_eq!(e.io.writes.len(), writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-mccs",
    dcn4_ddcci_uses_raw_transactions_and_retains_cancelled_claim
);
