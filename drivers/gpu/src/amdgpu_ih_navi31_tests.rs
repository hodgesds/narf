//! Fixture tests for the Navi31 IH v6 ring owner (see `amdgpu_ih_navi31`).
//! Same Fake-Io pattern as `amdgpu_ih_navi22_tests`: the register file is
//! fabricated, the ring memory is a Vec, and every golden is a literal
//! computed from the Linux sequence (`ih_v6_0_irq_init` / `ih_v6_0_enable_ring`
//! / `ih_v6_0_toggle_ring_interrupts`), not from the implementation under
//! test. Both rings are 256 KiB; the single 4 KiB writeback page sits after
//! ring 1 (ring 1 has no writeback address, so its wptr is always read from
//! `IH_RB_WPTR_RING1`).

use super::*;
use alloc::{collections::BTreeMap, sync::Arc, task::Wake, vec, vec::Vec};
use core::sync::atomic::AtomicUsize;
use narf_kernel_test::{kernel_test_in, TestResult};
const OSS: u64 = 0x10000;
const NBIO: u64 = 0x30000;
const PHYS: u64 = 0x9000_0000;
const ADDR: u64 = 0x0301_2345_6000;
const DUMMY: u64 = 0x1234_5000;
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    memory: Vec<u32>,
    hw: [u32; 2],
    invalidated: bool,
    gone: bool,
}
impl Io for Fake {
    fn read(&mut self, address: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        *self.regs.get(&address).unwrap_or(&0)
    }
    fn write(&mut self, address: u64, value: u32) {
        self.writes.push((address, value));
        self.regs.insert(address, value);
        if address == 0x7f000 {
            self.invalidated = true;
        }
        // Hardware acknowledges WPTR_OVERFLOW_CLEAR in both pointer copies.
        if address == OSS + 0x80 * 4 && value & OVERFLOW_CLEAR != 0 {
            self.memory[(WPTR_WB / 4) as usize] &= !RB_OVERFLOW;
            if let Some(wptr) = self.regs.get_mut(&(OSS + 0x84 * 4)) {
                *wptr &= !RB_OVERFLOW;
            }
        }
        if address == OSS + 0x8c * 4 && value & OVERFLOW_CLEAR != 0 {
            if let Some(wptr) = self.regs.get_mut(&(OSS + 0x90 * 4)) {
                *wptr &= !RB_OVERFLOW;
            }
        }
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        assert!(self.invalidated, "stale CPU read");
        if self.gone {
            return u32::MAX;
        }
        self.memory[((map.phys.raw() - PHYS + offset) / 4) as usize]
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        self.memory[((map.phys.raw() - PHYS + offset) / 4) as usize] = value;
    }
}
impl Fake {
    /// IH hardware: append one IV to `ring`, then update its wptr. Ring 0
    /// publishes to the writeback page and its register; ring 1 has no
    /// writeback address, so only its register moves.
    fn push(&mut self, ring: usize, dw: [u32; 8]) {
        let base = if ring == 0 { 0 } else { RING };
        for (index, word) in dw.into_iter().enumerate() {
            self.memory[((base + u64::from(self.hw[ring])) / 4) as usize + index] = word;
        }
        self.hw[ring] = (self.hw[ring] + 32) & MASK;
        self.publish(ring, self.hw[ring]);
    }
    fn publish(&mut self, ring: usize, wptr: u32) {
        if ring == 0 {
            self.memory[(WPTR_WB / 4) as usize] = wptr;
            self.regs.insert(OSS + 0x84 * 4, wptr);
        } else {
            self.regs.insert(OSS + 0x90 * 4, wptr);
        }
        self.invalidated = false;
    }
}
fn iv(source: Source, ring: u8, data: u32) -> [u32; 8] {
    [
        u32::from(source.client) | (u32::from(source.src) << 8) | (u32::from(ring) << 16),
        0,
        0,
        0,
        data,
        0,
        0,
        0,
    ]
}
fn fixture() -> (Pool, Arc<Shared<Fake>>, Handle) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(PHYS),
        virt: 0,
        len: BYTES,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: Fake performs every memory access; bookkeeping-only mapping.
    let pool = unsafe { Pool::from_owned_range(map, ADDR) }.unwrap();
    let mut regs = BTreeMap::new();
    for (address, value) in [
        (NBIO + 0x12d * 4, 0x7f000),
        (NBIO + 0xf1 * 4, 0x0b),
        // Inherited enabled ring 0 with stale MC_VMID/MC_RO and a kept
        // reserved bit; ring 1 with a full threshold.
        (OSS + 0x80 * 4, 0x0346_0001),
        (OSS + 0x8c * 4, 0xf005),
        (OSS + 0xc1 * 4, 0x1f),
        (OSS + 0xc2 * 4, 0x45),
    ] {
        regs.insert(address, value);
    }
    let engine = Engine {
        io: Fake {
            regs,
            writes: Vec::new(),
            memory: vec![0xffff_ffff; (BYTES / 4) as usize],
            hw: [0, 0],
            invalidated: false,
            gone: false,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            die: Die::Navi31,
            oss: OSS,
            nbio: NBIO,
            nbio_ctl: NBIO,
            nbio_cntl: 0xf1,
            nbio_cntl2: 0xf2,
        },
        memory: pool.reserve(BYTES).unwrap(),
        dummy: DUMMY,
        state: State::Prepared,
        rptr: [0, 0],
        inherited: false,
    };
    let shared = Arc::new(Shared {
        hub: Hub::new(),
        engine: Mutex::new(engine),
    });
    let handle = Handle(shared.clone());
    (pool, shared, handle)
}
fn enable(shared: &Shared<Fake>, msi: bool) -> Result<(), Error> {
    let mut engine = shared.engine.try_lock().unwrap();
    engine.preflight()?;
    engine.program(msi)
}
fn with<T>(shared: &Shared<Fake>, f: impl FnOnce(&mut Engine<Fake>) -> T) -> T {
    f(&mut shared.engine.try_lock().unwrap())
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
struct Count(AtomicUsize);
impl Wake for Count {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn ih_navi31_programs_both_rings_like_ih_v6_0_irq_init() -> TestResult {
    for msi in [true, false] {
        let (pool, shared, _handle) = fixture();
        if enable(&shared, msi).is_err() {
            return TestResult::Fail("IH enable failed");
        }
        let failed = with(&shared, |e| {
            let reg = |r: u64| e.io.regs[&(OSS + r * 4)];
            // Goldens from the Linux sequence (ih_v6_0_enable_ring +
            // toggle_ring_interrupts + irq_init storm block), starting from
            // the fixture's inherited 0x0346_0001 / 0xf005. v6 has no
            // GPU_TS bit and the overflow-clear pulse ends clear, so bit 31
            // is 0 here (unlike Navi22's 0xc037_01a1).
            let rb = if msi { 0x4037_0121 } else { 0x4017_0121 };
            let golden = [
                (0x80, rb),
                (0x81, 0x0123_4560),
                (0x82, 3),
                (0x83, 0),
                (0x84, 0),
                (0x85, 0x0301), // WPTR_ADDR_HI precedes LO on OSSSYS 6.0.0
                (0x86, 0x234d_6000),
                (0x87, 0), // doorbell disabled
                (0x8c, 0x4010_0321),
                (0x8d, 0x0123_4960),
                (0x8e, 3),
                (0x8f, 0),
                (0x90, 0),
                (0x93, 0),            // doorbell disabled
                (0xda, 0x0004_0000),  // STORM_CLIENT_LIST_CNTL CLIENT18
                (0xd5, 0x8),          // INT_FLOOD_CNTL FLOOD_CNTL_ENABLE
                (0xf1, 3),            // MSI_STORM_CTRL DELAY=3
                (0x185, 0),           // RING1_CLIENT_CFG_INDEX 0
                (0x186, 0x0001_000a), // ring 1 redirect: GFX, src 0, match
                (0x88, 0x1000_02f4),  // retry CAM doorbell 0x2f4 | ENABLE
                (0xef, 0x0001_000f),  // RETRY_INT_CAM_CNTL ENABLE + SIZE 0xF
                (0xc1, 0x108),        // IH_CNTL2 timeout 8 + FORCE_ENABLE
            ];
            if golden.iter().any(|&(r, v)| reg(r) != v)
                || e.io.regs[&(NBIO + 0xf2 * 4)] != (DUMMY >> 8) as u32
                || e.io.regs[&(NBIO + 0xf1 * 4)] != 2
                || !e.inherited
                || e.state != State::Enabled
                || e.io.memory.iter().any(|&w| w != 0)
            {
                return true;
            }
            // Disable first, base before size/writeback, enable after the
            // storm block, and the self-IV timeout last.
            let at = |address: u64, pred: &dyn Fn(u32) -> bool| {
                e.io.writes
                    .iter()
                    .position(|&(a, v)| a == address && pred(v))
                    .unwrap_or(usize::MAX)
            };
            let off = at(OSS + 0x80 * 4, &|v| v & (ENABLE | ENABLE_INTR) == 0);
            let base = at(OSS + 0x81 * 4, &|_| true);
            let size = at(OSS + 0x80 * 4, &|v| v & WRITEBACK != 0 && v & ENABLE == 0);
            let storm = at(OSS + 0xda * 4, &|_| true);
            let on = at(OSS + 0x80 * 4, &|v| v & ENABLE != 0);
            !(off < base && base < size && size < storm && storm < on)
                || e.io.writes.last() != Some(&(OSS + 0xc1 * 4, 0x108))
        });
        if failed {
            return TestResult::Fail("IH register sequence or encoding");
        }
        if enable(&shared, msi) != Err(Error::Busy) || pool.available() != 0 {
            return TestResult::Fail("IH replayed or released live ring");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_programs_both_rings_like_ih_v6_0_irq_init
);
fn ih_navi31_preflight_failure_writes_nothing() -> TestResult {
    for case in 0..4 {
        let (pool, shared, handle) = fixture();
        with(&shared, |e| match case {
            0 => {
                e.io.regs.insert(NBIO + 0x12d * 4, 0);
            }
            1 => {
                // IH_STATUS without the idle bits: a live ring is running.
                e.io.regs.insert(OSS + 0xc2 * 4, 0x40);
            }
            2 => e.io.gone = true,
            _ => e.authority.revoke(),
        });
        if enable(&shared, true).is_ok() || with(&shared, |e| !e.io.writes.is_empty()) {
            return TestResult::Fail("IH preflight wrote registers");
        }
        if handle.drain() != Ok(0) {
            return TestResult::Fail("disabled ring drained");
        }
        drop((handle, shared));
        if pool.available() != BYTES {
            return TestResult::Fail("unpublished ring leaked");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_preflight_failure_writes_nothing
);
fn ih_navi31_decodes_wrapping_rings_and_routes_sources() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut sdma = handle.subscribe(source::SDMA_TRAP).unwrap();
    let mut eop = handle.subscribe(source::GFX_EOP).unwrap();
    let mut hpd = handle.subscribe(source::DCN_HPD).unwrap();
    let mut fault = handle.subscribe(source::UTCL2_FAULT).unwrap();
    with(&shared, |e| {
        e.rptr[0] = MASK + 1 - 64;
        e.io.hw[0] = MASK + 1 - 64;
        e.io.push(
            0,
            [
                0x8a5e_310a, // vmid_src, vmid 10, ring 0x5e, src 49, client 0x0a
                0x89ab_cdef,
                0x8000_4567,
                0x0012_3456,
                1,
                2,
                3,
                4,
            ],
        );
        e.io.push(0, iv(source::GFX_EOP, 0x5e, 7));
        e.io.push(0, iv(source::DCN_HPD, 0, 7)); // ctxid 7: HPD2_RX
        e.io.push(0, iv(source::GFX_EOP, 0, 8));
        let mut utcl2 = iv(source::UTCL2_FAULT, 0, 0);
        utcl2[4] = 0x12345;
        utcl2[5] = 0xa5;
        utcl2[6] = 0x2ab;
        e.io.push(1, utcl2);
        e.io.push(1, iv(source::DF_ECC, 0, 0)); // nobody subscribed
    });
    if handle.drain() != Ok(6) {
        return TestResult::Fail("wrapped IVs not drained");
    }
    let first = sdma.try_next().unwrap().unwrap();
    if first
        != (Iv {
            client: 0x0a,
            src: 49,
            ring_id: 0x5e,
            vmid: 10,
            vmid_src: true,
            timestamp: 0x4567_89ab_cdef,
            timestamp_src: true,
            pasid: 0x3456,
            node_id: 0x12,
            src_data: [1, 2, 3, 4],
        })
    {
        return TestResult::Fail("SOC21 IV decode");
    }
    let eops = [eop.try_next(), eop.try_next(), eop.try_next()];
    if eops[0].unwrap().map(|i| (i.src_data[0], i.cp_queue()))
        != Some((
            7,
            CpQueue {
                me: 3,
                pipe: 2,
                queue: 5,
            },
        ))
        || eops[1].unwrap().map(|i| i.src_data[0]) != Some(8)
        || eops[2] != Ok(None)
        || sdma.try_next() != Ok(None)
    {
        return TestResult::Fail("IV routed to wrong owner");
    }
    if hpd.try_next().unwrap().map(|i| i.hpd())
        != Some(Some(Hpd {
            instance: 1,
            rx: true,
        }))
    {
        return TestResult::Fail("HPD IV routed or decoded wrong");
    }
    if fault.try_next().unwrap().map(|i| i.page_fault())
        != Some(Some(PageFault {
            mmhub: false,
            address: (0x12345 << 12) | (5 << 44),
            retry: true,
            write: true,
            cam_index: 0x2ab,
        }))
    {
        return TestResult::Fail("ring 1 VM fault routed or decoded wrong");
    }
    let stats = handle.stats();
    if stats.unhandled != 1
        || stats.drained != 6
        || with(&shared, |e| e.io.regs[&(OSS + 0x83 * 4)]) != 64
        || with(&shared, |e| e.io.regs[&(OSS + 0x8f * 4)]) != 64
    {
        return TestResult::Fail("rptr writeback or unhandled accounting");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_decodes_wrapping_rings_and_routes_sources
);

fn ih_navi31_overflow_resumes_after_oldest_overwritten_vector() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut eop = handle.subscribe(source::GFX_EOP).unwrap();
    with(&shared, |e| {
        for index in 0..=MASK / 32 {
            e.io.push(0, iv(source::GFX_EOP, 0, index));
        }
        // Ring wrapped past rptr: hardware reports overflow at wptr 96.
        e.io.hw[0] = 96;
        e.io.publish(0, 96 | RB_OVERFLOW);
        e.io.writes.clear();
    });
    if handle.drain() != Ok(BATCH * ROUNDS) {
        return TestResult::Fail("overflowed ring not drained in bounded rounds");
    }
    let (clear, rptr) = with(&shared, |e| {
        let cntl: Vec<u32> =
            e.io.writes
                .iter()
                .filter(|&&(a, _)| a == OSS + 0x80 * 4)
                .map(|&(_, v)| v)
                .collect();
        (cntl, e.io.regs[&(OSS + 0x83 * 4)])
    });
    let resumed = 128 + (BATCH * ROUNDS) as u32 * 32;
    if clear.len() != 2
        || clear[0] & OVERFLOW_CLEAR == 0
        || clear[1] & OVERFLOW_CLEAR != 0
        || rptr != resumed
        || handle.stats().overflows != 1
    {
        return TestResult::Fail("overflow clear pulse or resume pointer");
    }
    // Oldest mailbox entries are dropped; delivery starts at the newest 64.
    let first = eop.try_next().unwrap().unwrap().src_data[0];
    if eop.lost() != (BATCH * ROUNDS - QUEUE) as u64
        || first != 4 + (BATCH * ROUNDS - QUEUE) as u32
        || handle.stats().dropped != eop.lost()
    {
        return TestResult::Fail("mailbox overflow accounting");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_overflow_resumes_after_oldest_overwritten_vector
);
fn ih_navi31_ring1_overflow_resumes_after_oldest_overwritten_vector() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut fault = handle.subscribe(source::UTCL2_FAULT).unwrap();
    with(&shared, |e| {
        for index in 0..=MASK / 32 {
            e.io.push(1, iv(source::UTCL2_FAULT, 0, index));
        }
        // Ring 1 has no writeback page: the overflow bit arrives in
        // IH_RB_WPTR_RING1 itself.
        e.io.hw[1] = 96;
        e.io.publish(1, 96 | RB_OVERFLOW);
        e.io.writes.clear();
    });
    if handle.drain() != Ok(BATCH * ROUNDS) {
        return TestResult::Fail("overflowed ring 1 not drained in bounded rounds");
    }
    let (clear, rptr) = with(&shared, |e| {
        let cntl: Vec<u32> =
            e.io.writes
                .iter()
                .filter(|&&(a, _)| a == OSS + 0x8c * 4)
                .map(|&(_, v)| v)
                .collect();
        (cntl, e.io.regs[&(OSS + 0x8f * 4)])
    });
    let resumed = 128 + (BATCH * ROUNDS) as u32 * 32;
    if clear.len() != 2
        || clear[0] & OVERFLOW_CLEAR == 0
        || clear[1] & OVERFLOW_CLEAR != 0
        || rptr != resumed
        || handle.stats().overflows != 1
    {
        return TestResult::Fail("ring 1 overflow clear pulse or resume pointer");
    }
    let first = fault.try_next().unwrap().unwrap().src_data[0];
    if fault.lost() != (BATCH * ROUNDS - QUEUE) as u64
        || first != 4 + (BATCH * ROUNDS - QUEUE) as u32
        || handle.stats().dropped != fault.lost()
    {
        return TestResult::Fail("ring 1 mailbox overflow accounting");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_ring1_overflow_resumes_after_oldest_overwritten_vector
);
fn ih_navi31_skips_malformed_entries_and_pointers() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut eop = handle.subscribe(source::GFX_EOP).unwrap();
    with(&shared, |e| {
        e.io.push(
            0,
            iv(
                Source {
                    client: 0x25,
                    src: 181,
                },
                0,
                0,
            ),
        );
        e.io.push(0, [u32::MAX; 8]);
        e.io.push(0, iv(source::GFX_EOP, 0, 9));
        let hw = e.io.hw[0];
        e.io.publish(0, hw + 4); // misaligned writeback is aligned down
    });
    if handle.drain() != Ok(1)
        || handle.stats().malformed != 3
        || eop.try_next().unwrap().map(|i| i.src_data[0]) != Some(9)
        || with(&shared, |e| e.io.regs[&(OSS + 0x83 * 4)]) != 96
    {
        return TestResult::Fail("malformed IVs dispatched or pointer desync");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_skips_malformed_entries_and_pointers
);
fn ih_navi31_decode_helpers_and_source_tables() -> TestResult {
    let fault = Iv {
        client: source::client::VMC,
        src_data: [0x12345, 0xa5, 0x2ab, 0],
        ..Iv::default()
    };
    let utcl2 = Iv {
        client: source::client::GFX,
        ..fault
    };
    let other = Iv { src: 1, ..fault };
    let hpd = |context| Iv {
        client: source::client::DCE,
        src: 9,
        src_data: [context, 0, 0, 0],
        ..Iv::default()
    };
    if fault.page_fault()
        != Some(PageFault {
            mmhub: true,
            address: (0x12345 << 12) | (5 << 44),
            retry: true,
            write: true,
            cam_index: 0x2ab,
        })
        || utcl2.page_fault().map(|f| f.mmhub) != Some(false)
        || other.page_fault().is_some()
        || hpd(7).hpd()
            != Some(Hpd {
                instance: 1,
                rx: true,
            })
        || hpd(4).hpd()
            != Some(Hpd {
                instance: 4,
                rx: false,
            })
        || hpd(10).hpd()
            != Some(Hpd {
                instance: 4,
                rx: true,
            })
        || hpd(5).hpd().is_some()
        || hpd(11).hpd().is_some()
        || hpd(12).hpd().is_some()
        || source::vblank(0).map(|s| s.src) != Some(0x3c)
        || source::vblank(3).map(|s| s.src) != Some(0x3f)
        || source::vblank(4).is_some()
        || source::vupdate(0).map(|s| s.src) != Some(0x57)
        || source::vupdate(4).is_some()
        || source::pflip(3).map(|s| s.src) != Some(0x52)
        || source::pflip(4).is_some()
        || source::GFX_EOP
            != (Source {
                client: 0x14,
                src: 181,
            })
        || source::GFX_RLC_FED
            != (Source {
                client: 0x0a,
                src: 128,
            })
        || source::SDMA_TRAP
            != (Source {
                client: 0x0a,
                src: 49,
            })
        || source::VMC_FAULT
            != (Source {
                client: 0x12,
                src: 0,
            })
        || source::UTCL2_FAULT
            != (Source {
                client: 0x0a,
                src: 0,
            })
        || source::DF_ECC
            != (Source {
                client: 0x17,
                src: 0,
            })
        || source::DCN_HPD
            != (Source {
                client: 0x04,
                src: 9,
            })
        || source::VCN0_TRAP
            != (Source {
                client: 0x10,
                src: 114,
            })
        || source::JPEG_DEC
            != (Source {
                client: 0x10,
                src: 153,
            })
        || Die::from_gc(11, 0, 0) != Some(Die::Navi31)
        || Die::from_gc(11, 0, 3) != Some(Die::Navi32)
        || Die::from_gc(11, 0, 2) != Some(Die::Navi33)
        || Die::from_gc(11, 0, 1).is_some()
        || Die::from_gc(10, 3, 2).is_some()
        || Die::Navi31.dcn_version() != (3, 2, 0)
        || Die::Navi32.dcn_version() != (3, 2, 0)
        || Die::Navi33.dcn_version() != (3, 2, 1)
    {
        return TestResult::Fail("IV helper decode or source ids");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_decode_helpers_and_source_tables
);

fn ih_navi31_revocation_retires_stale_generations() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut old = handle.subscribe(source::SDMA_TRAP).unwrap();
    if handle.subscribe(source::SDMA_TRAP).err() != Some(Error::Busy) {
        return TestResult::Fail("second live owner accepted");
    }
    let woken = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(woken.clone());
    {
        let mut next = core::pin::pin!(old.wait());
        if next
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
        {
            return TestResult::Fail("empty mailbox completed");
        }
        if !handle.revoke(source::SDMA_TRAP) || woken.0.load(Ordering::SeqCst) == 0 {
            return TestResult::Fail("revocation did not wake its waiter");
        }
        if next.as_mut().poll(&mut Context::from_waker(&waker)) != Poll::Ready(Err(Closed::Revoked))
        {
            return TestResult::Fail("revoked waiter not terminated");
        }
    }
    let mut new = handle.subscribe(source::SDMA_TRAP).unwrap();
    with(&shared, |e| e.io.push(0, iv(source::SDMA_TRAP, 0, 1)));
    if new.generation() <= old.generation()
        || old.try_next() != Err(Closed::Revoked)
        || new.try_next().unwrap().map(|i| i.src_data[0]) != Some(1)
    {
        return TestResult::Fail("stale generation received a new owner's IV");
    }
    drop(old); // must not remove the newer slot
    with(&shared, |e| e.io.push(0, iv(source::SDMA_TRAP, 0, 2)));
    if new.try_next().unwrap().map(|i| i.src_data[0]) != Some(2) {
        return TestResult::Fail("stale drop removed live route");
    }
    drop(new);
    if handle.subscribe(source::SDMA_TRAP).is_err() || handle.revoke(source::GFX_EOP) {
        return TestResult::Fail("dropped route not released");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_revocation_retires_stale_generations
);
fn ih_navi31_cancelled_waits_keep_route_and_terminal_errors_wake() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, false).unwrap();
    shared.hub.set_delivery(Delivery::Polling);
    let mut sub = handle.subscribe(source::GFX_EOP).unwrap();
    {
        let mut next = core::pin::pin!(sub.wait());
        if next
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("empty wait completed");
        }
    }
    with(&shared, |e| e.io.push(0, iv(source::GFX_EOP, 0, 3)));
    if run(sub.wait()).map(|i| i.src_data[0]) != Ok(3) {
        return TestResult::Fail("cancelled wait lost its route");
    }
    if handle.stats().unsignalled == 0 {
        return TestResult::Fail("polled delivery not observable");
    }
    let woken = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(woken.clone());
    let mut next = core::pin::pin!(sub.wait());
    if next
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
        .is_ready()
    {
        return TestResult::Fail("empty wait completed");
    }
    with(&shared, |e| e.io.push(0, iv(source::GFX_EOP, 0, 4)));
    handle.drain().unwrap();
    handle.close(Closed::DeviceLost);
    if woken.0.load(Ordering::SeqCst) == 0
        || next.as_mut().poll(&mut Context::from_waker(&waker))
            != Poll::Ready(Ok(Iv::decode(iv(source::GFX_EOP, 0, 4))))
        || next.as_mut().poll(&mut Context::from_waker(&waker))
            != Poll::Ready(Err(Closed::DeviceLost))
        || handle.subscribe(source::GFX_BAD_OPCODE).err() != Some(Error::Closed(Closed::DeviceLost))
    {
        return TestResult::Fail("terminal delivery after device loss");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_cancelled_waits_keep_route_and_terminal_errors_wake
);
fn ih_navi31_device_loss_and_revocation_terminate_every_waiter() -> TestResult {
    for (case, expected) in [(0, Closed::DeviceLost), (1, Closed::AuthorityRevoked)] {
        let (pool, shared, handle) = fixture();
        enable(&shared, true).unwrap();
        let mut a = handle.subscribe(source::GFX_EOP).unwrap();
        let mut b = handle.subscribe(source::VMC_FAULT).unwrap();
        with(&shared, |e| {
            e.io.push(0, iv(source::GFX_EOP, 0, 1));
            if case == 0 {
                e.io.gone = true;
            } else {
                e.authority.revoke();
            }
        });
        if handle.drain() != Err(expected)
            || a.try_next() != Err(expected)
            || run(b.wait()) != Err(expected)
            || with(&shared, |e| e.state) != State::Failed
        {
            return TestResult::Fail("device loss left a waiter running");
        }
        drop((a, b, handle, shared));
        if pool.available() != 0 {
            return TestResult::Fail("lost device's ring recycled");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_device_loss_and_revocation_terminate_every_waiter
);
fn ih_navi31_disable_is_bounded_and_closes_waiters() -> TestResult {
    let (_pool, shared, handle) = fixture();
    let mut sub = handle.subscribe(source::GFX_EOP).unwrap();
    if with(&shared, |e| e.disable()) != Err(Error::Busy) {
        return TestResult::Fail("disabled a ring that never started");
    }
    enable(&shared, true).unwrap();
    with(&shared, |e| e.io.writes.clear());
    if with(&shared, |e| e.disable()).is_err() {
        return TestResult::Fail("disable failed");
    }
    shared.hub.close(Closed::Disabled);
    let failed = with(&shared, |e| {
        let reg = |r: u64| e.io.regs[&(OSS + r * 4)];
        reg(0x80) & (ENABLE | ENABLE_INTR) != 0
            || reg(0xc1) != 8
            || reg(0x83) != 0
            || reg(0x84) != 0
            || reg(0x8c) & ENABLE != 0
            || reg(0x8f) != 0
            || reg(0x90) != 0
            || e.state != State::Disabled
            || e.disable() != Err(Error::Busy)
    });
    if failed || run(sub.wait()) != Err(Closed::Disabled) || handle.drain() != Err(Closed::Disabled)
    {
        return TestResult::Fail("disable sequence or terminal delivery");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_disable_is_bounded_and_closes_waiters
);

fn ih_navi31_round_trip_requires_matching_trap_context() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut sub = handle.subscribe(source::SDMA_TRAP).unwrap();
    let before = shared.hub.interrupts.load(Ordering::SeqCst);
    interrupt(&shared.hub as *const Hub as u64);
    with(&shared, |e| {
        e.io.push(0, iv(source::SDMA_TRAP, 0, 0xf000_0001)); // other context
        e.io.push(0, iv(source::SDMA_TRAP, 0, 0x0675_0022));
    });
    let proof = run(prove(&shared.hub, &mut sub, 0x0675_0022, before));
    if proof.map(|p| (p.iv.src_data[0], p.interrupt)) != Ok((0x0675_0022, true))
        || handle.stats().unsignalled != 0
    {
        return TestResult::Fail("trap round trip not attributed");
    }
    with(&shared, |e| {
        e.io.push(1, iv(source::SDMA_TRAP, 1, 0x0675_0022))
    });
    if run(prove(&shared.hub, &mut sub, 0x0675_0022, 1)) != Err(Error::Timeout) {
        return TestResult::Fail("wrong ring accepted as proof");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_round_trip_requires_matching_trap_context
);
fn ih_navi31_rearm_reprograms_the_same_ring() -> TestResult {
    let (_pool, shared, _handle) = fixture();
    if with(&shared, |e| e.rearm(true)).is_err() {
        return TestResult::Fail("rearm before enable failed");
    }
    enable(&shared, true).unwrap();
    if with(&shared, |e| e.io.regs[&(OSS + 0x80 * 4)] & RPTR_REARM) == 0 {
        return TestResult::Fail("MSI enable left RPTR_REARM clear");
    }
    with(&shared, |e| e.rearm(false).unwrap());
    if with(&shared, |e| e.io.regs[&(OSS + 0x80 * 4)] & RPTR_REARM) != 0 {
        return TestResult::Fail("rearm(false) kept RPTR_REARM");
    }
    with(&shared, |e| e.rearm(true).unwrap());
    if with(&shared, |e| e.io.regs[&(OSS + 0x80 * 4)] & RPTR_REARM) == 0 {
        return TestResult::Fail("rearm(true) did not restore RPTR_REARM");
    }
    // Ring 1 has no RPTR_REARM field: rearm never touches its control.
    if with(&shared, |e| e.io.regs[&(OSS + 0x8c * 4)] & RPTR_REARM) != 0 {
        return TestResult::Fail("rearm wrote ring 1 RPTR_REARM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_rearm_reprograms_the_same_ring
);
fn ih_navi31_layout_requires_osssys_6_0_0_and_bounds() -> TestResult {
    let base = |gc: (u8, u8, u8), nbif: (u8, u8, u8)| {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        let gc_block = gpu
            .ip_blocks
            .iter_mut()
            .find(|b| b.hw_id == ip::HW_ID_GC)
            .unwrap();
        (gc_block.major, gc_block.minor, gc_block.revision) = gc;
        let oss = gpu
            .ip_blocks
            .iter_mut()
            .find(|b| b.hw_id == ip::HW_ID_OSSSYS)
            .unwrap();
        (oss.major, oss.minor, oss.revision) = (6, 0, 0);
        oss.base_addrs[0] = 0x10a0;
        let nbif_block = gpu
            .ip_blocks
            .iter_mut()
            .find(|b| b.hw_id == ip::HW_ID_NBIF)
            .unwrap();
        (nbif_block.major, nbif_block.minor, nbif_block.revision) = nbif;
        nbif_block.num_bases = 6;
        nbif_block.base_addrs[2] = 0xc000;
        nbif_block.base_addrs[5] = 0xc000;
        gpu
    };
    let gpu = base((11, 0, 0), (6, 3, 1));
    let resolved = Layout::resolve(&gpu);
    if resolved.map(|l| (l.die, l.oss, l.nbio, l.nbio_ctl, l.nbio_cntl, l.nbio_cntl2))
        != Ok((Die::Navi31, 0x4280, 0x30000, 0x30000, 0xf1, 0xf2))
    {
        return TestResult::Fail("OSSSYS/NBIO banks not resolved from discovery");
    }
    // Every SOC21 NBIO version resolves its own IH-control window; 7.7.0
    // lives on segment 5, the rest on segment 2.
    for (version, cntl, cntl2) in [
        ((4, 3, 0), 0xf1, 0xf2),
        ((6, 3, 2), 0xf1, 0xf2),
        ((7, 7, 0), 0x8e11, 0x8e12),
        ((7, 10, 0), 0xf1, 0xf2),
        ((7, 11, 5), 0xf1, 0xf2),
    ] {
        let gpu = base((11, 0, 0), version);
        if Layout::resolve(&gpu).map(|l| (l.nbio_cntl, l.nbio_cntl2)) != Ok((cntl, cntl2)) {
            return TestResult::Fail("NBIO IH-control window not version-resolved");
        }
    }
    // The corrected die pairing: 11.0.3 is Navi32, 11.0.2 is Navi33.
    if Layout::resolve(&base((11, 0, 3), (6, 3, 1))).map(|l| l.die) != Ok(Die::Navi32)
        || Layout::resolve(&base((11, 0, 2), (6, 3, 1))).map(|l| l.die) != Ok(Die::Navi33)
    {
        return TestResult::Fail("die pairing did not follow discovered GC version");
    }
    for case in 0..6 {
        let mut gpu = base((11, 0, 0), (6, 3, 1));
        match case {
            0 => {
                // Phoenix GC 11.0.1 is not an RDNA3 discrete die.
                gpu.ip_blocks
                    .iter_mut()
                    .find(|b| b.hw_id == ip::HW_ID_GC)
                    .unwrap()
                    .revision = 1;
            }
            1 => {
                gpu.ip_blocks
                    .iter_mut()
                    .find(|b| b.hw_id == ip::HW_ID_OSSSYS)
                    .unwrap()
                    .revision = 1;
            }
            2 => {
                gpu.ip_blocks.retain(|b| b.hw_id != ip::HW_ID_OSSSYS);
            }
            3 => {
                gpu.ip_blocks
                    .iter_mut()
                    .find(|b| b.hw_id == ip::HW_ID_OSSSYS)
                    .unwrap()
                    .base_addrs[0] = 0x20000 - 0x10;
            }
            4 => gpu.regs.len = 0x7f000,
            _ => {
                gpu.ip_blocks
                    .iter_mut()
                    .find(|b| b.hw_id == ip::HW_ID_NBIF)
                    .unwrap()
                    .minor = 7;
            }
        }
        if Layout::resolve(&gpu).is_ok() {
            return TestResult::Fail("unsupported IH layout accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi31",
    ih_navi31_layout_requires_osssys_6_0_0_and_bounds
);
