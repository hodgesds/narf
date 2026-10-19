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
const GPU: u64 = 0x8_0000_4000;
const IMAGE: u64 = 0x8_1000_0000;

struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    memory: Vec<u8>,
    dirty: bool,
    boot: bool,
    advance: bool,
    fence: bool,
    ignored: Option<u64>,
    revoked: Option<(u64, Cap<BusDeviceCap, Write>)>,
    delays: Arc<AtomicU32>,
    traps: u32,
}
impl Fake {
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
    fn memory_read(&mut self, _: MmioRegion, at: u64) -> u32 {
        self.word(at)
    }
    fn memory_write(&mut self, _: MmioRegion, at: u64, value: u32) {
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
        let mut p = self.regs[&(VCN + 0xac * 4)];
        while p != value {
            let at = RING + u64::from(p & 1023) * 4;
            p = p.wrapping_add(match self.word(at) {
                0 | 1 => 1,
                3 => {
                    let address = u64::from(self.word(at + 4)) | u64::from(self.word(at + 8)) << 32;
                    assert_eq!(address, GPU + FENCE);
                    if self.fence {
                        self.store(FENCE, self.word(at + 12));
                    }
                    4
                }
                4 => {
                    self.traps += 1;
                    1
                }
                op => panic!("unexpected VCN5 transport opcode {op}"),
            });
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
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x9000_4000),
        virt: 0,
        len: BYTES * 2,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model intercepts memory I/O; mapping is bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(map, GPU) }.unwrap();
    let regs = BTreeMap::from([
        (VCN + 0x1d6 * 4, 1 << 28),
        (VCN + 0x331 * 4, 0x24f),
        (GC + 0x263e * 4, 0x545),
    ]);
    let e = Engine {
        io: Fake {
            regs,
            writes: Vec::new(),
            memory: vec![0x5a; BYTES as usize],
            dirty: false,
            boot: true,
            advance: true,
            fence: true,
            ignored: None,
            revoked: None,
            delays: Arc::new(AtomicU32::new(0)),
            traps: 0,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            vcn: VCN,
            nbio: NBIO,
            gc: GC,
        },
        memory: pool.reserve(BYTES).unwrap(),
        firmware_bytes: 0x11000,
        state: State::Prepared,
        proof: None,
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
        gpu // metadata only; no MMIO into this expired register fixture
    };
    let gpu = descriptor();
    let layout = Layout::resolve(&gpu).unwrap();
    assert_eq!(
        (layout.vcn, layout.nbio, layout.gc),
        (0x60000, 0x30000, 0x10000)
    );
    for case in 0..8 {
        let mut gpu = descriptor();
        match case {
            0 => gpu.ip_blocks[5].revision = 1,
            1 => gpu.ip_blocks[5].num_bases = 1,
            2 => gpu.ip_blocks[5].base_addrs[1] = 0x20000 - 0x331,
            3 => gpu.ip_blocks[2].base_addrs[2] = 0x20000 - 0x1cf,
            4 => gpu.ip_blocks[0].base_addrs[0] = 0x20000 - 0x263e,
            5 => gpu.ip_blocks.push(gpu.ip_blocks[5]),
            6 => gpu.chip.did = crate::amdgpu::NAVI22,
            _ => gpu.regs.len = 0x7f000,
        }
        assert!(Layout::resolve(&gpu).is_err());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_layout_rejects_foreign_ip_and_truncated_register_banks
);
