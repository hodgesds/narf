use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    sync::atomic::AtomicU32,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
const VCN: u64 = 0x10000;
const NBIO: u64 = 0x30000;
const GC: u64 = 0x50000;
const MM: u64 = 0x70000;
const OSS: u64 = 0x90000;
const GPU: u64 = 0x8_0000_4000;
const IMAGE: u64 = 0x8_1000_0000;

struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    memory: Vec<u8>,
    ib_memory: Vec<u8>,
    decode_memory: Vec<u8>,
    decode_stages: u8,
    decode_dpb_zeroes: u64,
    decode_no_output: bool,
    decode_bad_output: bool,
    decode_guard: bool,
    decode_stall: bool,
    kernel_ibs: u8,
    kernel_sessions: [bool; 2],
    kernel_corrupt: bool,
    kernel_guard: bool,
    kernel_stall_at: Option<u8>,
    dirty: bool,
    boot: bool,
    advance: bool,
    fence: bool,
    ignored: Option<u64>,
    revoked: Option<(u64, Cap<BusDeviceCap, Write>)>,
    delays: Arc<AtomicU32>,
    traps: u32,
    signals: Arc<[AtomicU32; 2]>,
    emit_iv: bool,
    emit_cpu: bool,
    duplicate: bool,
    corrupt_guard: bool,
    wide_fence: bool,
    execute: bool,
    client_ibs: Vec<(u8, u64, u32)>,
    client_writes: Vec<(u64, u32)>,
    fence_revoke: Option<Cap<BusDeviceCap, Write>>,
    fence_gone: bool,
    fence_reads: u32,
}
impl Fake {
    // Keep the opaque, zeroed 16 MiB DPB sparse in the software model.
    // Physical descriptor addresses and the reservation still span it fully.
    fn codec_index(at: u64) -> Option<usize> {
        use decode_words as d;
        assert!(at < d::BYTES);
        if at < d::DPB {
            Some(at as usize)
        } else if at >= d::TARGET_GUARD {
            Some((at - (d::TARGET_GUARD - d::DPB)) as usize)
        } else {
            None
        }
    }
    fn codec_word(&self, at: u64) -> u32 {
        Self::codec_index(at).map_or(0, |i| {
            u32::from_le_bytes(self.decode_memory[i..i + 4].try_into().unwrap())
        })
    }
    fn codec_ib(&mut self, address: u64, length: u32) -> bool {
        use decode_words as d;
        let base = GPU + BYTES + ib_words::IB_BYTES;
        assert_eq!(length, 43);
        let data: Vec<u32> = (0..length)
            .map(|i| self.codec_word(address - base + u64::from(i) * 4))
            .collect();
        assert_eq!(&data[..2], &[0x10, 0x30000002]);
        assert_eq!(&data[3..10], &[39, 0x10, 0x30000001, 3, 156, 140, 1]);
        assert_eq!(
            data[2],
            data[4..].iter().fold(0u32, |s, w| s.wrapping_add(*w))
        );
        let ptr = |at: usize| ((u64::from(data[at]) << 32) | u64::from(data[at + 1])) - base;
        assert_eq!(ptr(17), d::SESSION);
        let msg_word = |index: u64| self.codec_word(ptr(11) + index * 4);
        assert_eq!(msg_word(0), 0x28);
        assert_eq!(msg_word(4), 0x40440003);
        match self.decode_stages % 3 {
            0 => {
                assert_eq!(data[10], 0x100001);
                assert_eq!(msg_word(3), 0);
            }
            1 => {
                assert_eq!(msg_word(3), 1);
                assert_eq!(data[10], 0x100a1f);
                for (at, expected) in [
                    (13, d::DPB),
                    (15, d::TARGET),
                    (19, d::BITSTREAM),
                    (21, d::CONTEXT),
                    (23, d::FEEDBACK),
                    (31, d::SCALING),
                ] {
                    assert_eq!(ptr(at), expected);
                }
                assert_eq!(
                    &self.decode_memory
                        [d::BITSTREAM as usize..d::BITSTREAM as usize + d::STREAM.len()],
                    d::STREAM
                );
                assert_eq!(
                    self.decode_dpb_zeroes,
                    (d::TARGET_GUARD - d::DPB) / 4 * (u64::from(self.decode_stages / 3) + 1)
                );
                if self.decode_stall {
                    return false;
                }
                let target = Self::codec_index(d::TARGET).unwrap();
                assert!(
                    self.decode_memory[target..target + d::TARGET_BYTES as usize]
                        .iter()
                        .all(|b| *b == 0)
                );
                // Synthetic hardware output tests the witness/checksum contract;
                // this model is not an H.264 decoder or silicon acceptance.
                if !self.decode_no_output {
                    let mut remaining = d::EXPECTED_SUM;
                    for byte in &mut self.decode_memory[target..target + d::TARGET_BYTES as usize] {
                        let value = remaining.min(255) as u8;
                        *byte = value;
                        remaining -= u64::from(value);
                    }
                    assert_eq!(remaining, 0);
                    if self.decode_bad_output {
                        self.decode_memory[target] -= 1;
                    }
                }
                if self.decode_guard {
                    self.decode_memory[Self::codec_index(d::TARGET_END_GUARD).unwrap()] ^= 1;
                }
            }
            2 => {
                assert_eq!(data[10], 0x100001);
                assert_eq!(msg_word(3), 2);
            }
            _ => unreachable!(),
        }
        self.decode_stages += 1;
        true
    }
    fn kernel_ib(&mut self, address: u64, length: u32) -> bool {
        let codec_base = GPU + BYTES + ib_words::IB_BYTES;
        if (codec_base..codec_base + decode_words::BYTES).contains(&address) {
            return self.codec_ib(address, length);
        }
        assert!(!self.dirty);
        if self.kernel_corrupt || self.kernel_stall_at == Some(self.kernel_ibs) {
            return false;
        }
        let base = GPU + BYTES;
        let offset = (address - base) as usize;
        let data: Vec<u32> = self.ib_memory[offset..offset + length as usize * 4]
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
            .collect();
        assert_eq!(&data[..2], &[0x10, 0x3000_0002]);
        assert_eq!(data[3], length - 4);
        assert_eq!(&data[4..6], &[0x10, 0x3000_0001]);
        assert_eq!(data[7], (length - 4) * 4);
        assert_eq!(
            data[2],
            data[4..].iter().fold(0u32, |s, w| s.wrapping_add(*w))
        );
        match data[6] {
            2 => {
                assert_eq!(length, 21);
                assert_eq!(&data[8..11], &[0x18, 1, 1]);
                assert_eq!((u64::from(data[11]) << 32) | u64::from(data[12]), base);
                assert_eq!(&data[13..20], &[0, 0x14, 2, 0x1c, 0, 0, 8]);
                match data[20] {
                    0x0800_0001 => {
                        assert!(!self.kernel_sessions[0]);
                        self.kernel_sessions[0] = true;
                    }
                    0x0800_0002 => {
                        assert!(self.kernel_sessions[0]);
                        self.kernel_sessions[0] = false;
                    }
                    _ => panic!("unknown encode session operation"),
                }
                self.ib_memory[..4].copy_from_slice(&0x51a7e001u32.to_le_bytes());
            }
            3 => {
                assert_eq!(length, 43);
                assert_eq!(&data[8..11], &[140, 1, 1]);
                assert!(data[13..].iter().all(|w| *w == 0));
                let at = (((u64::from(data[11]) << 32) | u64::from(data[12])) - base) as usize;
                let message: Vec<u32> = self.ib_memory[at..at + 56]
                    .chunks_exact(4)
                    .map(|w| u32::from_le_bytes(w.try_into().unwrap()))
                    .collect();
                assert_eq!(message[0], 0x28);
                assert_eq!(message[4], 1);
                match message[3] {
                    0 => {
                        assert_eq!(message[1], 0x38);
                        assert_eq!(&message[10..14], &[7, 0, 0x780, 0x440]);
                        assert!(!self.kernel_sessions[1]);
                        self.kernel_sessions[1] = true;
                    }
                    2 => {
                        assert_eq!(message[1], 0x18);
                        assert!(self.kernel_sessions[1]);
                        self.kernel_sessions[1] = false;
                    }
                    _ => panic!("unknown decode session operation"),
                }
            }
            _ => panic!("unknown unified engine selector"),
        }
        self.kernel_ibs += 1;
        if self.kernel_guard {
            self.ib_memory[(ib_words::ENCODE_CREATE + 4092) as usize] = 1;
        }
        true
    }
    fn word(&self, at: u64) -> u32 {
        u32::from_le_bytes(
            self.memory[at as usize..at as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    fn store(&mut self, at: u64, value: u32) {
        self.memory[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
    }
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.writes.push((at, value));
        if at == 0x7f000 {
            self.dirty = false;
        }
        if self.ignored == Some(at) {
            return;
        }
        self.regs.insert(at, value);
        if let Some((reg, cap)) = self.revoked {
            if reg == at {
                cap.revoke();
            }
        }
        if at == VCN + 0x1d6 * 4 && value & (1 << 28) == 0 && self.boot {
            self.regs.insert(VCN + 0x183 * 4, 6);
            // Firmware writes queue_status next to the CPU's queue_mode.
            self.memory[SHARED as usize + 18] = 0xa5;
        }
    }
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32 {
        if map.phys.raw() == 0x90004000 + BYTES + ib_words::IB_BYTES {
            return self.codec_word(at);
        }
        if map.phys.raw() == 0x90004000 + BYTES {
            return u32::from_le_bytes(
                self.ib_memory[at as usize..at as usize + 4]
                    .try_into()
                    .unwrap(),
            );
        }
        if at == FENCE {
            self.fence_reads += 1;
            if self.fence_gone {
                self.regs.insert(NBIO + 0xc3 * 4, u32::MAX);
            }
            if let Some(cap) = self.fence_revoke {
                cap.revoke();
            }
        }
        self.word(at)
    }
    fn memory_write(&mut self, map: MmioRegion, at: u64, value: u32) {
        if map.phys.raw() == 0x90004000 + BYTES + ib_words::IB_BYTES {
            if self.decode_memory.is_empty() {
                self.decode_memory.resize(
                    (decode_words::BYTES - (decode_words::TARGET_GUARD - decode_words::DPB))
                        as usize,
                    0x5a,
                );
            }
            if let Some(i) = Self::codec_index(at) {
                self.decode_memory[i..i + 4].copy_from_slice(&value.to_le_bytes());
            } else {
                assert_eq!(value, 0);
                self.decode_dpb_zeroes += 1;
            }
            self.dirty = true;
            return;
        }
        if map.phys.raw() == 0x90004000 + BYTES {
            self.ib_memory[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
            self.dirty = true;
            return;
        }
        assert!(at < BYTES && at % 4 == 0);
        self.store(at, value);
        self.dirty = true;
    }
    fn memory_read8(&mut self, _: MmioRegion, at: u64) -> u8 {
        self.memory[at as usize]
    }
    fn memory_write8(&mut self, _: MmioRegion, at: u64, value: u8) {
        assert_eq!(at, SHARED + 17);
        self.memory[at as usize] = value;
        self.dirty = true;
    }
    fn doorbell(&mut self, at: u32, value: u32) {
        assert_eq!(at, 0x312);
        assert!(!self.dirty, "host writes must reach the media engine first");
        assert_eq!(self.regs[&(NBIO + 0x1cf * 4)] & 0xf1ff_ffbf, 0x4011_8809);
        assert_eq!(self.regs[&(VCN + 0x72 * 4)] & 0x4fff_fffc, 0x4000_0c48);
        assert_eq!(self.regs[&(VCN + 0x85 * 4)] & 0x3c, 4);
        if let Some((offset, cap)) = self.revoked {
            if offset == u64::from(at) * 4 {
                cap.revoke();
            }
        }
        self.regs.insert(VCN + 0xad * 4, value);
        if !self.execute {
            return;
        }
        let mut p = self.regs[&(VCN + 0xac * 4)];
        let mut hdp = false;
        while p != value {
            let at = RING + u64::from(p & 1023) * 4;
            p = p.wrapping_add(match self.word(at) {
                0 | 1 => 1,
                0xb => {
                    let reg = u64::from(self.word(at + 4));
                    let value = self.word(at + 8);
                    self.client_writes.push((reg, value));
                    self.regs.insert(reg, value);
                    if reg == MM + 0x587 * 4 {
                        self.regs.insert(MM + 0x599 * 4, value & 0xffff);
                    }
                    if reg == MM + 0x575 * 4 {
                        self.regs.insert(reg, 1);
                    } // release semaphore
                    if reg == 0x7f000 {
                        hdp = true;
                    }
                    3
                }
                0xc => {
                    let reg = u64::from(self.word(at + 4));
                    let mask = self.word(at + 8);
                    assert_eq!(self.regs[&reg] & mask, self.word(at + 12));
                    if reg == MM + 0x575 * 4 {
                        self.regs.insert(reg, 0);
                    }
                    4
                }
                2 => {
                    assert!(hdp, "HDP flush before client IB");
                    let vmid = self.word(at + 4) as u8;
                    let address =
                        u64::from(self.word(at + 8)) | u64::from(self.word(at + 12)) << 32;
                    self.client_ibs.push((vmid, address, self.word(at + 16)));
                    if vmid == 0 && !self.kernel_ib(address, self.word(at + 16)) {
                        return;
                    }
                    5
                }
                3 => {
                    let address = u64::from(self.word(at + 4)) | u64::from(self.word(at + 8)) << 32;
                    assert_eq!(address, GPU + FENCE);
                    if self.fence {
                        self.store(FENCE, self.word(at + 12));
                        if self.wide_fence {
                            self.store(WRITEBACK, 0);
                        }
                        if self.corrupt_guard {
                            self.store(FENCE + 8, 0xdeadbeef);
                        }
                    }
                    4
                }
                4 => {
                    self.traps += 1;
                    if self.regs[&(VCN + 0x121 * 4)] & 2 != 0 {
                        if self.emit_iv {
                            self.signals[0]
                                .fetch_add(if self.duplicate { 2 } else { 1 }, Ordering::SeqCst);
                        }
                        if self.emit_cpu {
                            self.signals[1].fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    1
                }
                op => panic!("unexpected VCN5 transport opcode {op}"),
            }) & 1023;
        }
        self.regs.insert(VCN + 0xad * 4, value);
        if self.advance {
            self.regs.insert(VCN + 0xac * 4, value);
        }
        self.regs.insert(VCN + 0x183 * 4, 2);
    }
    async fn delay(&mut self, _: u64) {
        self.delays.fetch_add(1, Ordering::SeqCst);
        narf_scheduler::yield_now().await;
    }
}
fn fixture() -> (Pool, Engine<Fake>) {
    fixture_capacity(BYTES * 2)
}
fn fixture_capacity(capacity: u64) -> (Pool, Engine<Fake>) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x9000_4000),
        virt: 0,
        len: capacity,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model intercepts memory I/O; mapping is bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(map, GPU) }.unwrap();
    let regs = BTreeMap::from([
        (VCN + 0x1d6 * 4, 1 << 28),
        (VCN + 0x331 * 4, 0x24f),
        (GC + 0x263e * 4, 0x545),
        (MM + 0x575 * 4, 1),
    ]);
    let e = Engine {
        io: Fake {
            regs,
            writes: Vec::new(),
            memory: vec![0x5a; BYTES as usize],
            ib_memory: vec![0x5a; ib_words::IB_BYTES as usize],
            decode_memory: Vec::new(),
            decode_stages: 0,
            decode_dpb_zeroes: 0,
            decode_no_output: false,
            decode_bad_output: false,
            decode_guard: false,
            decode_stall: false,
            kernel_ibs: 0,
            kernel_sessions: [false; 2],
            kernel_corrupt: false,
            kernel_guard: false,
            kernel_stall_at: None,
            dirty: false,
            boot: true,
            advance: true,
            fence: true,
            ignored: None,
            revoked: None,
            delays: Arc::new(AtomicU32::new(0)),
            traps: 0,
            signals: Arc::new([AtomicU32::new(0), AtomicU32::new(0)]),
            emit_iv: true,
            emit_cpu: true,
            duplicate: false,
            corrupt_guard: false,
            wide_fence: false,
            execute: true,
            client_ibs: Vec::new(),
            client_writes: Vec::new(),
            fence_revoke: None,
            fence_gone: false,
            fence_reads: 0,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            vcn: VCN,
            nbio: NBIO,
            gc: GC,
            mm: MM,
            oss: OSS,
        },
        memory: pool.reserve(BYTES).unwrap(),
        ib_pool: pool.clone(),
        ib_memory: None,
        decode_memory: None,
        firmware_bytes: 0x11000,
        state: State::Prepared,
        proof: None,
        interrupt_result: None,
        ib_result: None,
        decode_result: None,
        wptr: 0,
        seq: 0,
    };
    (pool, e)
}
fn power() -> crate::amdgpu_smu_navi48::PowerStatus {
    crate::amdgpu_smu_navi48::PowerStatus {
        allowed: 0,
        enabled: 0,
        gfx_min_mhz: 0,
        gfx_max_mhz: 0,
        uclk_mhz: None,
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn vcn5_static_boot_windows_fence_and_retirement_follow_linux() -> TestResult {
    let (pool, mut e) = fixture();
    run(e.start(IMAGE, power())).unwrap();
    assert_eq!(e.state, State::Ready);
    assert!(!e.memory.reusable_for_test());
    for (lo, offset, size, address, bytes) in [
        (0x2cf, 0x1c0, 0x1c1, IMAGE, 0x12000),
        (0x2fb, 0x1c2, 0x1c3, GPU, 128 << 10),
        (0x2ff, 0x1c4, 0x1c5, GPU + (128 << 10), 512 << 10),
        (0x2cb, 0x1d2, 0x1d3, GPU + SHARED, 4096),
    ] {
        assert_eq!(e.io.regs[&(VCN + lo * 4)], address as u32);
        assert_eq!(e.io.regs[&(VCN + (lo + 1) * 4)], (address >> 32) as u32);
        assert_eq!(e.io.regs[&(VCN + offset * 4)], 0);
        assert_eq!(e.io.regs[&(VCN + size * 4)], bytes);
    }
    assert_eq!(e.io.word(SHARED), 0x804);
    assert_eq!(
        e.io.memory[SHARED as usize + 16..SHARED as usize + 19],
        [1, 0, 0xa5]
    );
    assert_eq!(e.reg(MASTINT), Ok(0)); // no unowned CPU IRQ claim
    assert_eq!(e.reg(ADDR_CONFIG), Ok(0x545));
    assert_eq!(
        run(e.prove()),
        Ok(Proof {
            sequence: 1,
            read_pointer: 64
        })
    );
    assert_eq!(e.io.traps, 1);
    assert_eq!(e.state, State::Verified);
    run(e.stop()).unwrap();
    assert_eq!(e.state, State::Stopped);
    assert!(e.memory.reusable_for_test());
    assert_eq!(e.reg(VCPU).unwrap() & ((1 << 28) | (1 << 9)), 1 << 28);
    assert_eq!(e.reg(RESET).unwrap() & 0x2004, 0x2004);
    assert_eq!(
        e.io.memory[SHARED as usize + 16..SHARED as usize + 19],
        [1, 2, 0xa5]
    );
    assert_eq!(e.io.regs[&(NBIO + 0x1cf * 4)] & 0x1fe_0001, 0);
    // A second cold start reruns transport; the old sequence cannot satisfy it.
    run(e.start(IMAGE, power())).unwrap();
    assert_eq!(
        run(e.prove()),
        Ok(Proof {
            sequence: 2,
            read_pointer: 64
        })
    );
    run(e.stop()).unwrap();
    drop(e);
    assert_eq!(pool.available(), BYTES * 2);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_static_boot_windows_fence_and_retirement_follow_linux
);

fn vcn5_refuses_inherited_owners_and_uncertain_completion() -> TestResult {
    for case in 0..5 {
        let (_pool, mut e) = fixture();
        let mut policy = power();
        let mut image = IMAGE;
        let expected = match case {
            0 => {
                policy.enabled = 1 << 44;
                Error::PowerPolicy(policy.enabled)
            }
            1 => {
                image += 4;
                Error::Invalid
            }
            2 => {
                e.io.regs.insert(VCN + 0x85 * 4, 8);
                Error::Busy
            }
            3 => {
                e.io.regs.insert(VCN + 0x1d6 * 4, 0);
                Error::Busy
            }
            _ => {
                e.io.regs.insert(NBIO + 0x1cf * 4, 1);
                Error::Busy
            }
        };
        assert_eq!(run(e.start(image, policy)), Err(expected));
        assert_eq!(e.state, State::Prepared);
        assert!(e.io.writes.is_empty());
        assert!(e.memory.reusable_for_test());
    }
    for missing in 0..2 {
        let (_pool, mut e) = fixture();
        run(e.start(IMAGE, power())).unwrap();
        e.io.advance = missing != 0;
        e.io.fence = missing != 1;
        assert_eq!(run(e.prove()), Err(Error::Timeout));
        assert_eq!(e.state, State::Failed(Error::Timeout));
        assert!(!e.memory.reusable_for_test());
        assert_eq!(run(e.stop()), Err(Error::Busy));
    }
    for last in [false, true] {
        let (_pool, mut e) = fixture();
        let at = if last {
            NBIO + 0x1cf * 4
        } else {
            VCN + 0x1c1 * 4
        };
        if last {
            e.io.revoked = Some((at, e.authority));
        } else {
            e.io.ignored = Some(at);
        }
        let error = if last {
            Error::Revoked
        } else {
            Error::Readback
        };
        assert_eq!(run(e.start(IMAGE, power())), Err(error));
        assert_eq!(e.state, State::Failed(error));
        assert!(!e.memory.reusable_for_test());
        assert_eq!(run(e.start(IMAGE, power())), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_refuses_inherited_owners_and_uncertain_completion
);

fn vcn5_cancelled_start_or_stop_retains_all_published_memory() -> TestResult {
    for count in [1, 80, (BYTES / 4096) as u32, (BYTES / 4096) as u32 + 1] {
        let (_pool, mut e) = fixture();
        e.io.boot = false;
        let steps = e.io.delays.clone();
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut future = core::pin::pin!(e.start(IMAGE, power()));
            while steps.load(Ordering::Acquire) < count {
                assert!(matches!(future.as_mut().poll(&mut cx), Poll::Pending));
            }
        }
        assert_eq!(e.state, State::Starting);
        assert!(!e.memory.reusable_for_test());
        assert_eq!(run(e.start(IMAGE, power())), Err(Error::Busy));
        assert_eq!(run(e.stop()), Err(Error::Busy));
    }
    let (_pool, mut e) = fixture();
    run(e.start(IMAGE, power())).unwrap();
    run(e.prove()).unwrap();
    e.io.regs.insert(VCN + 0x331 * 4, 0); // cannot prove write-clean
    {
        let mut future = core::pin::pin!(e.stop());
        assert!(future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
    }
    assert_eq!(e.state, State::Stopping);
    assert!(!e.memory.reusable_for_test());
    assert_eq!(e.io.memory[SHARED as usize + 18], 0xa5);
    assert_eq!(run(e.stop()), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_cancelled_start_or_stop_retains_all_published_memory
);

fn vcn5_missing_power_boot_or_stop_proof_never_releases_backing() -> TestResult {
    for case in 0..4 {
        let (_pool, mut e) = fixture();
        let error = match case {
            0 => {
                e.io.regs.insert(VCN + 4, 8); // ONO2 did not power on
                assert_eq!(run(e.start(IMAGE, power())), Err(Error::Timeout));
                Error::Timeout
            }
            1 => {
                e.io.boot = false;
                assert_eq!(run(e.start(IMAGE, power())), Err(Error::BootFailed));
                Error::BootFailed
            }
            _ => {
                run(e.start(IMAGE, power())).unwrap();
                run(e.prove()).unwrap();
                let error = if case == 2 {
                    e.io.ignored = Some(VCN + 0x187 * 4); // lost LMI reset
                    Error::Readback
                } else {
                    e.io.revoked = Some((VCN + 0x183 * 4, e.authority));
                    Error::Revoked
                };
                assert_eq!(run(e.stop()), Err(error));
                error
            }
        };
        assert_eq!(e.state, State::Failed(error));
        assert!(!e.memory.reusable_for_test());
        assert_eq!(run(e.stop()), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_missing_power_boot_or_stop_proof_never_releases_backing
);

fn vcn5_layout_rejects_foreign_ip_and_truncated_register_banks() -> TestResult {
    let descriptor = || {
        let mut regs = vec![0; 0x80000 / 4];
        let mut gpu = crate::amdgpu_gmc_navi48::tests::descriptor(&mut regs);
        let nbif = &mut gpu.ip_blocks[2];
        (nbif.major, nbif.minor, nbif.revision) = (6, 3, 1);
        let mut vcn = gpu.ip_blocks[0];
        vcn.hw_id = ip::HW_ID_VCN;
        (vcn.major, vcn.minor, vcn.revision) = (5, 0, 0);
        vcn.base_addrs[1] = 0x18000;
        gpu.ip_blocks.push(vcn);
        let mut oss = vcn;
        oss.hw_id = ip::HW_ID_OSSSYS;
        (oss.major, oss.minor, oss.revision) = (7, 0, 0);
        oss.base_addrs[0] = 0x1a000;
        gpu.ip_blocks.push(oss);
        gpu // metadata only; no MMIO into this expired register fixture
    };
    let gpu = descriptor();
    let layout = Layout::resolve(&gpu).unwrap();
    assert_eq!(
        (layout.vcn, layout.nbio, layout.gc),
        (0x60000, 0x30000, 0x10000)
    );
    for case in 0..10 {
        let mut gpu = descriptor();
        match case {
            0 => gpu.ip_blocks[5].revision = 1,
            1 => gpu.ip_blocks[5].num_bases = 1,
            2 => gpu.ip_blocks[5].base_addrs[1] = 0x20000 - 0x331,
            3 => gpu.ip_blocks[2].base_addrs[2] = 0x20000 - 0x1cf,
            4 => gpu.ip_blocks[0].base_addrs[0] = 0x20000 - 0x263e,
            5 => gpu.ip_blocks.push(gpu.ip_blocks[5]),
            6 => gpu.chip.did = crate::amdgpu::NAVI22,
            7 => gpu.regs.len = 0x7f000,
            8 => gpu.ip_blocks[1].minor = 0,
            _ => gpu.ip_blocks[6].num_bases = 0,
        }
        assert!(Layout::resolve(&gpu).is_err());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_layout_rejects_foreign_ip_and_truncated_register_banks
);

struct Irqs {
    signals: Arc<[AtomicU32; 2]>,
    vector: Option<u8>,
    stall_sample: bool,
    stall_observed: bool,
}
impl crate::amdgpu_navi48_interrupts::Observer for Irqs {
    async fn sample(
        &mut self,
        source: crate::amdgpu_navi48_interrupts::Source,
    ) -> Result<crate::amdgpu_navi48_interrupts::Sample, crate::amdgpu_ih7::Error> {
        use crate::amdgpu_navi48_interrupts::{Sample, Source};
        assert_eq!(source, Source::Vcn0);
        if self.stall_sample {
            core::future::pending::<()>().await;
        }
        Ok(Sample {
            source,
            count: u64::from(self.signals[0].load(Ordering::Acquire)),
            cpu: u64::from(self.signals[1].load(Ordering::Acquire)),
            vector: self.vector,
        })
    }
    async fn observed(
        &mut self,
        sample: crate::amdgpu_navi48_interrupts::Sample,
    ) -> Result<bool, crate::amdgpu_ih7::Error> {
        if self.stall_observed {
            core::future::pending::<()>().await;
        }
        let count = u64::from(self.signals[0].load(Ordering::Acquire));
        if count > sample.count + 1 {
            return Err(crate::amdgpu_ih7::Error::Protocol);
        }
        Ok(count == sample.count + 1
            && (sample.vector.is_none()
                || u64::from(self.signals[1].load(Ordering::Acquire)) != sample.cpu))
    }
}
fn irqs(e: &Engine<Fake>, vector: Option<u8>) -> Irqs {
    Irqs {
        signals: e.io.signals.clone(),
        vector,
        stall_sample: false,
        stall_observed: false,
    }
}
fn vcn5_irq_proof_requires_fresh_fence_drain_trap_and_cpu() -> TestResult {
    for case in 0..9 {
        let (_pool, mut e) = fixture();
        run(e.start(IMAGE, power())).unwrap();
        run(e.prove()).unwrap();
        // Old trap/MSI evidence cannot satisfy the next command frame.
        e.io.signals[0].store(7, Ordering::Release);
        e.io.signals[1].store(9, Ordering::Release);
        let mut observer = irqs(&e, if case == 6 { None } else { Some(64) });
        match case {
            1 => e.io.fence = false,
            2 => e.io.advance = false,
            3 => e.io.emit_iv = false,
            4 => e.io.emit_cpu = false,
            5 => e.io.duplicate = true,
            7 => e.io.corrupt_guard = true,
            8 => e.io.wide_fence = true,
            _ => {}
        }
        let result = run(e.prove_interrupts(&mut observer));
        match case {
            0 | 6 => {
                assert_eq!(
                    result,
                    Ok(InterruptProof {
                        fence: Proof {
                            sequence: 2,
                            read_pointer: 128
                        },
                        msi_verified: case == 0
                    })
                );
                assert_eq!(e.state, State::InterruptVerified);
                assert_eq!(e.interrupt_result, Some(result));
                run(e.stop()).unwrap();
                assert!(e.memory.reusable_for_test());
            }
            _ => {
                let error = if case >= 7 {
                    Error::Readback
                } else if case == 5 {
                    Error::Interrupts(crate::amdgpu_ih7::Error::Protocol)
                } else {
                    Error::Timeout
                };
                assert_eq!(result, Err(error));
                assert_eq!(e.state, State::Failed(error));
                assert!(!e.memory.reusable_for_test());
                assert_eq!(run(e.stop()), Err(Error::Busy));
            }
        }
        assert_eq!(run(e.prove_interrupts(&mut observer)), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_irq_proof_requires_fresh_fence_drain_trap_and_cpu
);

fn vcn5_irq_cancellation_retains_owner_before_and_after_publication() -> TestResult {
    for published in [false, true] {
        let (_pool, mut e) = fixture();
        run(e.start(IMAGE, power())).unwrap();
        run(e.prove()).unwrap();
        let mut observer = irqs(&e, Some(64));
        observer.stall_sample = !published;
        observer.stall_observed = published;
        {
            let mut future = core::pin::pin!(e.prove_interrupts(&mut observer));
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.state, State::InterruptTesting);
        assert_eq!(e.interrupt_result, Some(Err(Error::Busy)));
        assert_eq!(e.wptr, if published { 128 } else { 64 });
        assert!(!e.memory.reusable_for_test());
        assert_eq!(run(e.stop()), Err(Error::Busy));
        assert_eq!(run(e.prove_interrupts(&mut observer)), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_irq_cancellation_retains_owner_before_and_after_publication
);

fn vcn5_client_frame_uses_mmhub_pasid_hdp_and_unified_commands() -> TestResult {
    use crate::amdgpu_gfx12_queue::Job;
    let job = Job::new(
        3,
        0x42,
        0x1_0000_8001,
        &[(0x2_0000_1000, 64), (0x2_0000_2000, 8)],
    )
    .unwrap();
    let fence = GPU + FENCE;
    let want = [
        0xc,
        MM as u32 + 0x575 * 4,
        1,
        1,
        0xb,
        MM as u32 + (0x5cf + 6) * 4,
        0x8001,
        0xb,
        MM as u32 + (0x5d0 + 6) * 4,
        1,
        0xb,
        MM as u32 + 0x587 * 4,
        8 | 0x1f << 19,
        0xc,
        MM as u32 + 0x599 * 4,
        8,
        8,
        0xb,
        MM as u32 + 0x575 * 4,
        0,
        0xc,
        MM as u32 + (0x5cf + 6) * 4,
        !0,
        0x8001,
        0xb,
        OSS as u32 + 0x13 * 4,
        0x42,
        0xb,
        0x7f000,
        0,
        2,
        3,
        0x1000,
        2,
        64,
        2,
        3,
        0x2000,
        2,
        8,
        3,
        fence as u32,
        (fence >> 32) as u32,
        7,
        4,
        1,
    ];
    let words = cs::job_words(job, (MM / 4) as u32, (OSS / 4) as u32, fence, 7).unwrap();
    assert_eq!(words[..want.len()], want);
    assert!(words[want.len()..].iter().all(|w| *w == 0));
    let quiet = Job {
        flush: false,
        map_pasid: false,
        mem_sync: true,
        ctx_switch: true,
        ..Job::new(3, 0x42, 0, &[(0x2_0000_3000, 16)]).unwrap()
    };
    let words = cs::job_words(quiet, (MM / 4) as u32, (OSS / 4) as u32, fence, 8).unwrap();
    assert_eq!(
        words[..14],
        [
            0xb,
            0x7f000,
            0,
            2,
            3,
            0x3000,
            2,
            16,
            3,
            fence as u32,
            (fence >> 32) as u32,
            8,
            4,
            1
        ]
    );
    for bad in [
        Job { vmid: 0, ..job },
        Job { ib_count: 0, ..job },
        Job { ib_count: 9, ..job },
        Job::new(3, 0x42, 0, &[(0x1001, 4)]).unwrap(),
        Job::new(3, 0x42, 0, &[(0x1000, 0)]).unwrap(),
        Job::new(3, 0x42, 0, &[(0x1000, 0x10_0000)]).unwrap(),
    ] {
        assert_eq!(
            cs::job_words(bad, (MM / 4) as u32, (OSS / 4) as u32, fence, 1),
            Err(Error::Invalid)
        );
    }
    assert_eq!(
        cs::job_words(job, u32::MAX, 0, fence, 1),
        Err(Error::Invalid)
    );
    assert_eq!(
        cs::job_words(job, 0, u32::MAX, fence, 1),
        Err(Error::Invalid)
    );
    assert_eq!(cs::job_words(job, 0, 0, fence + 1, 1), Err(Error::Invalid));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_client_frame_uses_mmhub_pasid_hdp_and_unified_commands
);

fn verified_client() -> (Pool, Engine<Fake>) {
    let (pool, mut e) = fixture();
    run(e.start(IMAGE, power())).unwrap();
    run(e.prove()).unwrap();
    let mut observer = irqs(&e, Some(64));
    run(e.prove_interrupts(&mut observer)).unwrap();
    (pool, e)
}
fn vcn5_client_jobs_wrap_backpressure_and_record_published_sequences() -> TestResult {
    use crate::amdgpu_gfx12_queue::Job;
    let job = Job::new(3, 0x42, 0x1_0000_8001, &[(0x2_0000_1000, 64)]).unwrap();
    let (_pool, mut e) = verified_client();
    for seq in 3..=8 {
        assert_eq!(e.submit(job), Ok(seq));
        assert_eq!(e.completed_job(), Ok(seq));
        assert_eq!(e.io.client_ibs.last(), Some(&(3, 0x2_0000_1000, 64)));
        assert_eq!(e.io.regs[&(MM + (0x5cf + 6) * 4)], 0x8001);
        assert_eq!(e.io.regs[&(OSS + 0x13 * 4)], 0x42);
        assert_eq!(e.io.regs[&(VCN + 0xac * 4)], e.wptr);
        assert_eq!(e.wptr, (128 + (seq - 2) * 256) & 1023);
    }
    run(e.stop()).unwrap();
    let (_pool, mut e) = verified_client();
    e.io.execute = false;
    for seq in 3..=5 {
        assert_eq!(e.submit(job), Ok(seq));
    }
    assert_eq!((e.seq, e.wptr), (5, 896));
    assert_eq!(e.submit(job), Err(Error::Busy));
    assert_eq!((e.seq, e.wptr), (5, 896));
    // Firmware retired the queued work; the next frame crosses the ring end.
    e.io.regs.insert(VCN + 0xac * 4, 896);
    e.io.store(FENCE, 5);
    e.io.execute = true;
    assert_eq!(e.submit(job), Ok(6));
    assert_eq!(e.wptr, 128);
    assert_eq!(e.completed_job(), Ok(6));
    let (_pool, mut e) = verified_client();
    // A revocation at the final doorbell cannot undo publication. Returning
    // the sequence lets the caller retain the resources, then observe error.
    e.io.revoked = Some((u64::from(DOORBELL) * 4, e.authority));
    assert_eq!(e.submit(job), Ok(3));
    assert_eq!(e.completed_job(), Err(Error::Revoked));
    assert_eq!(e.submit(job), Err(Error::Revoked));
    assert!(!e.memory.reusable_for_test());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_client_jobs_wrap_backpressure_and_record_published_sequences
);

fn vcn5_client_fences_reject_device_loss_and_revocation() -> TestResult {
    for case in 0..6 {
        let (pool, mut e) = fixture();
        run(e.start(IMAGE, power())).unwrap();
        let available = pool.available();
        e.io.store(FENCE, u32::MAX);
        e.io.fence_reads = 0;
        match case {
            1 => {
                e.io.regs.insert(NBIO + 0xc3 * 4, u32::MAX);
            }
            2 => e.io.fence_gone = true,
            3 => {
                e.authority.revoke();
            }
            4 => e.io.fence_revoke = Some(e.authority),
            5 => {
                e.io.regs.insert(VCN + u64::from(STATUS) * 4, u32::MAX);
            }
            _ => {}
        }
        let expected = match case {
            0 => Ok(u32::MAX),
            1 | 2 | 5 => Err(Error::DeviceGone),
            _ => Err(Error::Revoked),
        };
        assert_eq!(e.completed_job(), expected);
        assert_eq!(e.io.fence_reads, u32::from(!matches!(case, 1 | 3 | 5)));
        assert!(!e.memory.reusable_for_test());
        drop(e);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_client_fences_reject_device_loss_and_revocation
);

fn ib_ready() -> (Pool, Engine<Fake>, Irqs) {
    let (pool, mut e) = fixture();
    run(e.start(IMAGE, power())).unwrap();
    run(e.prove()).unwrap();
    let mut observer = irqs(&e, Some(64));
    run(e.prove_interrupts(&mut observer)).unwrap();
    (pool, e, observer)
}
fn vcn5_kernel_session_ibs_prove_both_engines_and_restart_at_sequence_wrap() -> TestResult {
    let (pool, mut e, mut observer) = ib_ready();
    for restart in [false, true] {
        if restart {
            e.seq = u32::MAX;
            run(e.start(IMAGE, power())).unwrap();
            assert_eq!(run(e.prove()).unwrap().sequence, 1);
            assert_eq!(
                run(e.prove_interrupts(&mut observer))
                    .unwrap()
                    .fence
                    .sequence,
                2
            );
        }
        let proof = run(e.prove_ibs(&mut observer)).unwrap();
        assert_eq!(
            proof.fence,
            Proof {
                sequence: 3,
                read_pointer: 192
            }
        );
        assert!(proof.msi_verified);
        assert_eq!(e.state, State::IbVerified);
        assert_eq!(e.ib_result, Some(Ok(proof)));
        assert_eq!(e.io.kernel_ibs, if restart { 8 } else { 4 });
        assert_eq!(e.io.kernel_sessions, [false; 2]);
        assert!(!e.ib_memory.as_ref().unwrap().reusable_for_test());
        assert_eq!(run(e.prove_ibs(&mut observer)), Err(Error::Busy));
        let job = crate::amdgpu_gfx12_queue::Job::new(3, 11, 0x1000, &[(0x2000, 4)]).unwrap();
        assert_eq!(e.submit(job), Ok(4));
        assert_eq!(e.completed_job(), Ok(4));
        run(e.stop()).unwrap();
        assert!(e.memory.reusable_for_test());
        assert!(e.ib_memory.as_ref().unwrap().reusable_for_test());
    }
    drop(e);
    assert_eq!(pool.available(), BYTES * 2);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_kernel_session_ibs_prove_both_engines_and_restart_at_sequence_wrap
);

fn vcn5_kernel_session_ib_failures_retain_context_commands_and_ring() -> TestResult {
    for case in 0..6 {
        let (pool, mut e, mut observer) = ib_ready();
        match case {
            0 => e.io.kernel_corrupt = true,
            1 => e.io.kernel_stall_at = Some(2),
            2 => e.io.kernel_guard = true,
            3 => e.io.fence = false,
            4 => e.io.emit_iv = false,
            5 => e.io.emit_cpu = false,
            _ => unreachable!(),
        }
        let expected = if case == 2 {
            Error::Readback
        } else {
            Error::Timeout
        };
        assert_eq!(run(e.prove_ibs(&mut observer)), Err(expected));
        assert_eq!(e.state, State::Failed(expected));
        assert_eq!(e.ib_result, Some(Err(expected)));
        assert!(!e.memory.reusable_for_test());
        assert!(!e.ib_memory.as_ref().unwrap().reusable_for_test());
        if case == 1 {
            assert_eq!(e.io.kernel_ibs, 2);
        }
        assert_eq!(run(e.stop()), Err(Error::Busy));
        let available = pool.available();
        drop(e);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_kernel_session_ib_failures_retain_context_commands_and_ring
);

fn vcn5_kernel_session_ib_cancellation_closes_clients_and_retains_backing() -> TestResult {
    for published in [false, true] {
        let (pool, mut e, mut observer) = ib_ready();
        observer.stall_sample = !published;
        observer.stall_observed = published;
        {
            let mut future = core::pin::pin!(e.prove_ibs(&mut observer));
            for _ in 0..=ib_words::IB_BYTES / 4096 {
                assert!(future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
        }
        assert_eq!(e.io.kernel_ibs, if published { 4 } else { 0 });
        assert_eq!(e.state, State::IbTesting);
        assert_eq!(e.ib_result, Some(Err(Error::Busy)));
        assert_eq!(run(e.stop()), Err(Error::Busy));
        assert_eq!(
            e.submit(crate::amdgpu_gfx12_queue::Job::new(3, 11, 0x1000, &[(0x2000, 4)]).unwrap()),
            Err(Error::Busy)
        );
        let available = pool.available();
        drop(e);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_kernel_session_ib_cancellation_closes_clients_and_retains_backing
);

fn vcn5_wrapped_transport_and_interrupt_proofs_cannot_match_cleared_zero() -> TestResult {
    for irq in [false, true] {
        let (_pool, mut e) = fixture();
        run(e.start(IMAGE, power())).unwrap();
        if irq {
            run(e.prove()).unwrap();
        }
        e.seq = u32::MAX;
        e.io.store(FENCE, 0);
        e.io.fence = false;
        let mut observer = irqs(&e, Some(64));
        let result = if irq {
            run(e.prove_interrupts(&mut observer)).map(|p| p.fence)
        } else {
            run(e.prove())
        };
        assert_eq!(result, Err(Error::Timeout));
        assert_eq!(e.seq, 1);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_wrapped_transport_and_interrupt_proofs_cannot_match_cleared_zero
);

fn decode_ready() -> (Pool, Engine<Fake>, Irqs) {
    let (pool, mut e) = fixture_capacity(BYTES * 2 + decode_words::BYTES);
    run(e.start(IMAGE, power())).unwrap();
    run(e.prove()).unwrap();
    let mut observer = irqs(&e, Some(64));
    run(e.prove_interrupts(&mut observer)).unwrap();
    run(e.prove_ibs(&mut observer)).unwrap();
    (pool, e, observer)
}
fn vcn5_avc_picture_proof_requires_new_output_and_preserves_owned_guards() -> TestResult {
    let (pool, mut e, mut observer) = decode_ready();
    let proof = run(e.prove_decode(&mut observer)).unwrap();
    assert_eq!(proof.output_sum, decode_words::EXPECTED_SUM);
    assert_eq!(
        proof.completion.fence,
        Proof {
            sequence: 4,
            read_pointer: 256
        }
    );
    assert!(proof.completion.msi_verified);
    assert_eq!(e.decode_result, Some(Ok(proof)));
    assert_eq!(e.state, State::DecodeVerified);
    assert_eq!(e.io.decode_stages, 3);
    assert!(!e.decode_memory.as_ref().unwrap().reusable_for_test());
    assert_eq!(run(e.prove_decode(&mut observer)), Err(Error::Busy));
    let job = crate::amdgpu_gfx12_queue::Job::new(3, 11, 0x1000, &[(0x2000, 4)]).unwrap();
    assert_eq!(e.submit(job), Ok(5));
    assert_eq!(e.completed_job(), Ok(5));
    run(e.stop()).unwrap();
    assert!(e.decode_memory.as_ref().unwrap().reusable_for_test());
    drop(e);
    assert_eq!(pool.available(), BYTES * 2 + decode_words::BYTES);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_avc_picture_proof_requires_new_output_and_preserves_owned_guards
);

fn vcn5_avc_picture_failures_quarantine_every_published_buffer() -> TestResult {
    for case in 0..6 {
        let (pool, mut e, mut observer) = decode_ready();
        let expected = match case {
            0 => {
                e.io.decode_no_output = true;
                Error::DecodeChecksum(0)
            }
            1 => {
                e.io.decode_bad_output = true;
                Error::DecodeChecksum(decode_words::EXPECTED_SUM - 1)
            }
            2 => {
                e.io.decode_guard = true;
                Error::Readback
            }
            3 => {
                e.io.decode_stall = true;
                Error::Timeout
            }
            4 => {
                e.io.fence = false;
                Error::Timeout
            }
            _ => {
                e.io.emit_cpu = false;
                Error::Timeout
            }
        };
        assert_eq!(run(e.prove_decode(&mut observer)), Err(expected));
        assert_eq!(e.state, State::Failed(expected));
        assert_eq!(e.decode_result, Some(Err(expected)));
        assert_eq!(run(e.stop()), Err(Error::Busy));
        assert!(!e.decode_memory.as_ref().unwrap().reusable_for_test());
        let available = pool.available();
        drop(e);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_avc_picture_failures_quarantine_every_published_buffer
);

fn vcn5_avc_picture_cancel_retains_storage_before_and_after_publication() -> TestResult {
    for published in [false, true] {
        let (pool, mut e, mut observer) = decode_ready();
        observer.stall_observed = published;
        {
            let mut future = core::pin::pin!(e.prove_decode(&mut observer));
            let polls = if published {
                decode_words::BYTES / 4096 + 1
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
        assert_eq!(e.io.decode_stages, if published { 3 } else { 0 });
        assert_eq!(e.state, State::DecodeTesting);
        assert_eq!(e.decode_result, Some(Err(Error::Busy)));
        assert_eq!(run(e.stop()), Err(Error::Busy));
        assert!(!e.decode_memory.as_ref().unwrap().reusable_for_test());
        let available = pool.available();
        drop(e);
        assert_eq!(pool.available(), available);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_avc_picture_cancel_retains_storage_before_and_after_publication
);

fn vcn5_avc_picture_allocation_refusal_does_not_publish_an_empty_proof() -> TestResult {
    let (pool, mut e, mut observer) = ib_ready();
    run(e.prove_ibs(&mut observer)).unwrap();
    let available = pool.available();
    assert_eq!(run(e.prove_decode(&mut observer)), Err(Error::Allocation));
    assert_eq!(e.state, State::IbVerified);
    assert!(e.decode_result.is_none() && e.decode_memory.is_none());
    assert_eq!((e.seq, e.wptr), (3, 192));
    assert_eq!(pool.available(), available);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_avc_picture_allocation_refusal_does_not_publish_an_empty_proof
);
