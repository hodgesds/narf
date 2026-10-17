use super::*;
use alloc::{collections::BTreeMap, sync::Arc, task::Wake, vec, vec::Vec};
use core::sync::atomic::AtomicUsize;
use narf_kernel_test::{kernel_test_in, TestResult};
const OSS: u64 = 0x10000;
const NBIO: u64 = 0x30000;
const HDP: u64 = 0x40000;
const PHYS: u64 = 0x9000_0000;
const ADDR: u64 = 0x0301_2345_6000;
const DUMMY: u64 = 0x1234_5000;
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    memory: Vec<u32>,
    hw: u32,
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
        if address == HDP + 0xd1 * 4 {
            self.invalidated = true;
        }
        // Hardware acknowledges WPTR_OVERFLOW_CLEAR in both pointer copies.
        if address == OSS + 0x80 * 4 && value & OVERFLOW_CLEAR != 0 {
            self.memory[(RING / 4) as usize] &= !RB_OVERFLOW;
            if let Some(wptr) = self.regs.get_mut(&(OSS + 0x84 * 4)) {
                *wptr &= !RB_OVERFLOW;
            }
        }
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        assert!(self.invalidated, "stale CPU HDP read");
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
    /// IH hardware: append one IV, then update register and writeback wptr.
    fn push(&mut self, dw: [u32; 8]) {
        for (index, word) in dw.into_iter().enumerate() {
            self.memory[(self.hw / 4) as usize + index] = word;
        }
        self.hw = (self.hw + 32) & MASK;
        self.publish(self.hw);
    }
    fn publish(&mut self, wptr: u32) {
        self.memory[(RING / 4) as usize] = wptr;
        self.regs.insert(OSS + 0x84 * 4, wptr);
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
        (NBIO + 0x1d2 * 4, 0x0002_02f0),
        // Inherited enabled ring with stale MC_VMID/MC_RO and a kept MC_SWAP.
        (OSS + 0x80 * 4, 0x0346_0001),
        (OSS + 0x8c * 4, 0xf005),
        (OSS + 0x98 * 4, 0xf000),
        (OSS + 0xc1 * 4, 0x1f),
    ] {
        regs.insert(address, value);
    }
    let engine = Engine {
        io: Fake {
            regs,
            writes: Vec::new(),
            memory: vec![0xffff_ffff; (BYTES / 4) as usize],
            hw: 0,
            invalidated: false,
            gone: false,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            oss: OSS,
            nbio: NBIO,
            hdp: HDP,
        },
        memory: pool.reserve(BYTES).unwrap(),
        dummy: DUMMY,
        state: State::Prepared,
        rptr: 0,
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

fn ih_navi22_programs_ring0_like_navi10_ih_irq_init() -> TestResult {
    for msi in [true, false] {
        let (pool, shared, _handle) = fixture();
        if enable(&shared, msi).is_err() {
            return TestResult::Fail("IH enable failed");
        }
        let failed = with(&shared, |e| {
            let reg = |r: u64| e.io.regs[&(OSS + r * 4)];
            let rb = if msi { 0xc037_01a1 } else { 0xc017_01a1 };
            let golden = [
                (0x80, rb),
                (0x81, 0x0123_4560),
                (0x82, 3),
                (0x83, 0),
                (0x84, 0),
                (0x85, 0x0301), // WPTR_ADDR_HI precedes LO on OSSSYS 5.0
                (0x86, 0x2349_6000),
                (0x87, 0), // doorbell disabled
                (0x8c, 5),
                (0x98, 0),
                (0xc1, 0x108),
            ];
            if golden.iter().any(|&(r, v)| reg(r) != v)
                || e.io.regs[&(NBIO + 0xf2 * 4)] != (DUMMY >> 8) as u32
                || e.io.regs[&(NBIO + 0xf1 * 4)] != 2
                || e.io.regs[&(NBIO + 0x1d2 * 4)] != 0x2f0
                || !e.inherited
                || e.state != State::Enabled
                || e.io.memory.iter().any(|&w| w != 0)
            {
                return true;
            }
            // Disable first, base before size/writeback, enable after doorbell
            // range, and the self-IV timeout last.
            let at = |address: u64, pred: &dyn Fn(u32) -> bool| {
                e.io.writes
                    .iter()
                    .position(|&(a, v)| a == address && pred(v))
                    .unwrap_or(usize::MAX)
            };
            let off = at(OSS + 0x80 * 4, &|v| v & (ENABLE | ENABLE_INTR) == 0);
            let base = at(OSS + 0x81 * 4, &|_| true);
            let size = at(OSS + 0x80 * 4, &|v| v & WRITEBACK != 0 && v & ENABLE == 0);
            let range = at(NBIO + 0x1d2 * 4, &|_| true);
            let on = at(OSS + 0x80 * 4, &|v| v & ENABLE != 0);
            !(off < base && base < size && size < range && range < on)
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
    "drivers/gpu/ih-navi22",
    ih_navi22_programs_ring0_like_navi10_ih_irq_init
);
fn ih_navi22_preflight_failure_writes_nothing() -> TestResult {
    for case in 0..3 {
        let (pool, shared, handle) = fixture();
        with(&shared, |e| match case {
            0 => {
                e.io.regs.insert(NBIO + 0x12d * 4, 0);
            }
            1 => e.io.gone = true,
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
    "drivers/gpu/ih-navi22",
    ih_navi22_preflight_failure_writes_nothing
);
fn ih_navi22_decodes_wrapping_ring_and_routes_sources() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut sdma = handle.subscribe(source::SDMA0_TRAP).unwrap();
    let mut eop = handle.subscribe(source::GFX_EOP).unwrap();
    with(&shared, |e| {
        e.rptr = MASK + 1 - 64;
        e.io.hw = MASK + 1 - 64;
        e.io.push([
            0x8a5e_e008, // vmid_src, vmid 10, ring 0x5e, src 0xe0, client 8
            0x89ab_cdef,
            0x8000_4567,
            0x0012_3456,
            1,
            2,
            3,
            4,
        ]);
        e.io.push(iv(source::GFX_EOP, 0x5e, 7));
        e.io.push(iv(source::THERMAL_CTF, 0, 0)); // nobody subscribed
        e.io.push(iv(source::GFX_EOP, 0, 8));
    });
    if handle.drain() != Ok(4) {
        return TestResult::Fail("wrapped IVs not drained");
    }
    let first = sdma.try_next().unwrap().unwrap();
    if first
        != (Iv {
            client: 8,
            src: 0xe0,
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
        return TestResult::Fail("SOC15 IV decode");
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
    let stats = handle.stats();
    if stats.unhandled != 1
        || stats.drained != 4
        || with(&shared, |e| e.io.regs[&(OSS + 0x83 * 4)]) != 64
    {
        return TestResult::Fail("rptr writeback or unhandled accounting");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi22",
    ih_navi22_decodes_wrapping_ring_and_routes_sources
);
fn ih_navi22_overflow_resumes_after_oldest_overwritten_vector() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut eop = handle.subscribe(source::GFX_EOP).unwrap();
    with(&shared, |e| {
        for index in 0..=MASK / 32 {
            e.io.push(iv(source::GFX_EOP, 0, index));
        }
        // Ring wrapped past rptr: hardware reports overflow at wptr 96.
        e.io.hw = 96;
        e.io.publish(96 | RB_OVERFLOW);
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
    "drivers/gpu/ih-navi22",
    ih_navi22_overflow_resumes_after_oldest_overwritten_vector
);
fn ih_navi22_skips_malformed_entries_and_pointers() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut eop = handle.subscribe(source::GFX_EOP).unwrap();
    with(&shared, |e| {
        e.io.push(iv(
            Source {
                client: 0x25,
                src: 181,
            },
            0,
            0,
        ));
        e.io.push([u32::MAX; 8]);
        e.io.push(iv(source::GFX_EOP, 0, 9));
        let hw = e.io.hw;
        e.io.publish(hw + 4); // misaligned writeback is aligned down
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
    "drivers/gpu/ih-navi22",
    ih_navi22_skips_malformed_entries_and_pointers
);
fn ih_navi22_decode_helpers_and_source_tables() -> TestResult {
    let fault = Iv {
        client: source::client::VMC,
        src_data: [0x12345, 0xa5, 0, 0],
        ..Iv::default()
    };
    let utcl2 = Iv {
        client: source::client::UTCL2,
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
        })
        || utcl2.page_fault().map(|f| f.mmhub) != Some(false)
        || other.page_fault().is_some()
        || hpd(7).hpd()
            != Some(Hpd {
                instance: 1,
                rx: true,
            })
        || hpd(5).hpd()
            != Some(Hpd {
                instance: 5,
                rx: false,
            })
        || hpd(12).hpd().is_some()
        || source::vblank(0).map(|s| s.src) != Some(0x3c)
        || source::vblank(5).map(|s| s.src) != Some(0x41)
        || source::vblank(6).is_some()
        || source::vupdate(0).map(|s| s.src) != Some(0x57)
        || source::pflip(5).map(|s| s.src) != Some(0x54)
        || source::GFX_EOP
            != (Source {
                client: 0x14,
                src: 181,
            })
        || source::SDMA1_TRAP
            != (Source {
                client: 9,
                src: 224,
            })
    {
        return TestResult::Fail("IV helper decode or source ids");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi22",
    ih_navi22_decode_helpers_and_source_tables
);
fn ih_navi22_revocation_retires_stale_generations() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut old = handle.subscribe(source::SDMA0_TRAP).unwrap();
    if handle.subscribe(source::SDMA0_TRAP).err() != Some(Error::Busy) {
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
        if !handle.revoke(source::SDMA0_TRAP) || woken.0.load(Ordering::SeqCst) == 0 {
            return TestResult::Fail("revocation did not wake its waiter");
        }
        if next.as_mut().poll(&mut Context::from_waker(&waker)) != Poll::Ready(Err(Closed::Revoked))
        {
            return TestResult::Fail("revoked waiter not terminated");
        }
    }
    let mut new = handle.subscribe(source::SDMA0_TRAP).unwrap();
    with(&shared, |e| e.io.push(iv(source::SDMA0_TRAP, 0, 1)));
    if new.generation() <= old.generation()
        || old.try_next() != Err(Closed::Revoked)
        || new.try_next().unwrap().map(|i| i.src_data[0]) != Some(1)
    {
        return TestResult::Fail("stale generation received a new owner's IV");
    }
    drop(old); // must not remove the newer slot
    with(&shared, |e| e.io.push(iv(source::SDMA0_TRAP, 0, 2)));
    if new.try_next().unwrap().map(|i| i.src_data[0]) != Some(2) {
        return TestResult::Fail("stale drop removed live route");
    }
    drop(new);
    if handle.subscribe(source::SDMA0_TRAP).is_err() || handle.revoke(source::GFX_EOP) {
        return TestResult::Fail("dropped route not released");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi22",
    ih_navi22_revocation_retires_stale_generations
);
fn ih_navi22_cancelled_waits_keep_route_and_terminal_errors_wake() -> TestResult {
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
    with(&shared, |e| e.io.push(iv(source::GFX_EOP, 0, 3)));
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
    with(&shared, |e| e.io.push(iv(source::GFX_EOP, 0, 4)));
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
    "drivers/gpu/ih-navi22",
    ih_navi22_cancelled_waits_keep_route_and_terminal_errors_wake
);
fn ih_navi22_device_loss_and_revocation_terminate_every_waiter() -> TestResult {
    for (case, expected) in [(0, Closed::DeviceLost), (1, Closed::AuthorityRevoked)] {
        let (pool, shared, handle) = fixture();
        enable(&shared, true).unwrap();
        let mut a = handle.subscribe(source::GFX_EOP).unwrap();
        let mut b = handle.subscribe(source::VMC_FAULT).unwrap();
        with(&shared, |e| {
            e.io.push(iv(source::GFX_EOP, 0, 1));
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
    "drivers/gpu/ih-navi22",
    ih_navi22_device_loss_and_revocation_terminate_every_waiter
);
fn ih_navi22_disable_is_bounded_and_closes_waiters() -> TestResult {
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
            || reg(0x80) & GPU_TS == 0
            || reg(0xc1) != 8
            || reg(0x83) != 0
            || reg(0x84) != 0
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
    "drivers/gpu/ih-navi22",
    ih_navi22_disable_is_bounded_and_closes_waiters
);
fn ih_navi22_round_trip_requires_matching_trap_context() -> TestResult {
    let (_pool, shared, handle) = fixture();
    enable(&shared, true).unwrap();
    let mut sub = handle.subscribe(source::SDMA0_TRAP).unwrap();
    let before = shared.hub.interrupts.load(Ordering::SeqCst);
    interrupt(&shared.hub as *const Hub as u64);
    with(&shared, |e| {
        e.io.push(iv(source::SDMA0_TRAP, 0, 0xf000_0001)); // other context
        e.io.push(iv(source::SDMA0_TRAP, 0, 0x0675_0022));
    });
    let proof = run(prove(&shared.hub, &mut sub, 0x0675_0022, before));
    if proof.map(|p| (p.iv.src_data[0], p.interrupt)) != Ok((0x0675_0022, true))
        || handle.stats().unsignalled != 0
    {
        return TestResult::Fail("trap round trip not attributed");
    }
    with(&shared, |e| {
        e.io.push(iv(source::SDMA0_TRAP, 1, 0x0675_0022))
    });
    if run(prove(&shared.hub, &mut sub, 0x0675_0022, 1)) != Err(Error::Timeout) {
        return TestResult::Fail("wrong ring accepted as proof");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi22",
    ih_navi22_round_trip_requires_matching_trap_context
);
fn ih_navi22_layout_requires_osssys_5_0_3_and_bounds() -> TestResult {
    let base = || {
        let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
        // The fixture's own OSSSYS block (base 0) is replaced by this one.
        gpu.ip_blocks.retain(|b| b.hw_id != ip::HW_ID_OSSSYS);
        let mut oss = gpu.ip_blocks[0];
        (oss.hw_id, oss.major, oss.minor, oss.revision) = (ip::HW_ID_OSSSYS, 5, 0, 3);
        oss.base_addrs[0] = 0x10a0;
        gpu.ip_blocks.push(oss);
        gpu
    };
    let gpu = base();
    if Layout::resolve(&gpu).map(|l| l.oss) != Ok(0x4280) {
        return TestResult::Fail("OSSSYS bank not resolved from discovery");
    }
    for case in 0..4 {
        let mut gpu = base();
        let last = gpu.ip_blocks.len() - 1;
        match case {
            0 => gpu.ip_blocks[last].revision = 0,
            1 => {
                gpu.ip_blocks.pop();
            }
            2 => gpu.ip_blocks[last].base_addrs[0] = 0x20000 - 0x10,
            _ => gpu.regs.len = 0x7f000,
        }
        if Layout::resolve(&gpu).is_ok() {
            return TestResult::Fail("unsupported IH layout accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih-navi22",
    ih_navi22_layout_requires_osssys_5_0_3_and_bounds
);
