use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    regs: [u32; 0x92],
    memory: Vec<u32>,
    writes: Vec<(u32, u32)>,
    complete: bool,
    reject: u32,
    destroy: bool,
    dirty: bool,
    violation: bool,
    submissions: Vec<[u32; 256]>,
}
impl Io for Fake {
    fn read(&mut self, reg: u32) -> u32 {
        self.regs[reg as usize]
    }
    fn write(&mut self, reg: u32, value: u32) {
        self.writes.push((reg, value));
        self.regs[reg as usize] = value;
        if reg == CTRL && (value == CREATE || value == DESTROY && self.destroy) {
            self.regs[CTRL as usize] = RESPONSE;
        }
        if reg == WPTR {
            if self.dirty {
                self.violation = true;
            }
            let offset = ((value + 1024 - 16) % 1024) as usize;
            let frame = &self.memory[offset..offset + 16];
            if frame[2] != 0 || frame[6..].iter().any(|v| *v != 0) {
                self.violation = true;
            }
            let seq = frame[5];
            self.submissions
                .push(self.memory[1024..1280].try_into().unwrap());
            if self.complete {
                self.memory[(FENCE / 4) as usize] = seq;
                self.memory[(COMMAND / 4) as usize + 216] = self.reject;
                self.memory[(COMMAND / 4) as usize + 220] = 4 * 1024 * 1024;
            }
        }
    }
    fn read_mem(&mut self, offset: u64) -> u32 {
        self.memory[(offset / 4) as usize]
    }
    fn write_mem(&mut self, offset: u64, value: u32) {
        self.dirty = true;
        self.memory[(offset / 4) as usize] = value;
    }
    fn setup_hdp(&mut self) -> bool {
        true
    }
    fn flush(&mut self) {
        self.dirty = false;
    }
    fn invalidate(&mut self) {}
}
fn fixture() -> (Pool, Engine<Fake>) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: BUFFER_SIZE + 4096,
        kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
    };
    // SAFETY: bookkeeping-only pool; Fake implements all memory accesses.
    let pool = unsafe { Pool::from_owned_range(map, 0x2_0000_0000) }.unwrap();
    let memory = pool.reserve(BUFFER_SIZE).unwrap();
    let mut io = Fake {
        regs: [0; 0x92],
        memory: vec![0; BUFFER_SIZE as usize / 4],
        writes: Vec::new(),
        complete: true,
        reject: 0,
        destroy: true,
        dirty: false,
        violation: false,
        submissions: Vec::new(),
    };
    io.regs[CTRL as usize] = RESPONSE;
    io.regs[SOS as usize] = 1;
    (
        pool,
        Engine {
            io,
            authority: Cap::bootstrap(),
            memory,
            state: State::Prepared,
            sequence: 0,
        },
    )
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}
fn psp_ring_linux_wire_and_wrap() -> TestResult {
    let (pool, mut engine) = fixture();
    if run(engine.start()).is_err() {
        return TestResult::Fail("ring create");
    }
    let address = engine.memory.address();
    if !engine.io.writes.windows(4).any(|w| {
        w == [
            (RING_LO, address as u32),
            (RING_HI, (address >> 32) as u32),
            (RING_SIZE, 4096),
            (CTRL, CREATE),
        ]
    }) {
        return TestResult::Fail("Linux mailbox sequence");
    }
    for _ in 0..65 {
        let cmd = load_command(6, 0x123_4567_8000, 73, 51);
        if run(engine.submit(&cmd)).is_err() {
            return TestResult::Fail("ring submit/wrap");
        }
    }
    if engine.io.violation || engine.io.regs[WPTR as usize] != 16 {
        return TestResult::Fail("flush, reserved fields, or DWORD wrap");
    }
    let words = engine.io.submissions[0];
    if words[0..7] != [0, 0, 6, 0, 0, 0, 0]
        || words[7..11] != [0x45678000, 0x123, 73, 51]
        || words[11..].iter().any(|v| *v != 0)
    {
        return TestResult::Fail("1024-byte command ABI");
    }
    if run(engine.stop()).is_err() {
        return TestResult::Fail("ring destroy");
    }
    drop(engine);
    if pool.available() != BUFFER_SIZE + 4096 {
        return TestResult::Fail("stopped buffer retained");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_ring_linux_wire_and_wrap);
fn psp_ring_rejection_and_stale_fence() -> TestResult {
    let (_, mut engine) = fixture();
    run(engine.start()).unwrap();
    engine.io.reject = 0xffff000a;
    if run(engine.submit(&command(7, &[]))) != Err(Error::Rejected(0xffff000a)) {
        return TestResult::Fail("PSP rejection ignored");
    }
    engine.io.complete = false;
    let cmd = command(7, &[]);
    {
        let mut future = core::pin::pin!(engine.submit(&cmd));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("stale fence accepted");
        }
    }
    if engine.state != State::Pending || run(engine.submit(&cmd)) != Err(Error::Busy) {
        return TestResult::Fail("cancelled command reused");
    }
    if run(engine.stop()).is_err() {
        return TestResult::Fail("cancel cleanup");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_ring_rejection_and_stale_fence);
fn psp_ring_revocation_and_quarantine() -> TestResult {
    let (pool, mut engine) = fixture();
    run(engine.start()).unwrap();
    engine.authority.revoke();
    let before = engine.io.writes.len();
    if run(engine.submit(&command(7, &[]))) != Err(Error::Revoked)
        || engine.io.writes.len() != before
    {
        return TestResult::Fail("revoked submit touched hardware");
    }
    if run(engine.stop()).is_err() {
        return TestResult::Fail("revoked teardown failed");
    }
    drop(engine);
    if pool.available() != BUFFER_SIZE + 4096 {
        return TestResult::Fail("revoked teardown retained ring");
    }
    let (pool, mut engine) = fixture();
    run(engine.start()).unwrap();
    drop(engine);
    if pool.available() != 4096 {
        return TestResult::Fail("published ring recycled on drop");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_ring_revocation_and_quarantine);
fn psp_ring_invalid_pointer_does_not_publish() -> TestResult {
    let (_, mut engine) = fixture();
    run(engine.start()).unwrap();
    for pointer in [1, 15, 1024, u32::MAX] {
        engine.io.regs[WPTR as usize] = pointer;
        let before = engine.io.writes.len();
        if run(engine.submit(&command(7, &[]))) != Err(Error::Invalid)
            || engine.io.writes.len() != before
        {
            return TestResult::Fail("invalid pointer published");
        }
    }
    run(engine.stop()).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/psp-ring",
    psp_ring_invalid_pointer_does_not_publish
);
fn psp_tmr_gpu_alignment_and_padding() -> TestResult {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: 0,
        len: 4 << 20,
        kind: narf_bus::BarKind::Mmio32 { prefetchable: true },
    };
    // SAFETY: bookkeeping only, no MMIO dereferences.
    let pool = unsafe { Pool::from_owned_range(map, 0x2_0000_1000) }.unwrap();
    let a = pool.reserve_aligned(1 << 20, 1 << 20).unwrap();
    if a.address() != 0x2_0010_0000 || pool.reserve(4096).unwrap().address() != 0x2_0000_1000 {
        return TestResult::Fail("GPU alignment or padding lost");
    }
    if pool.reserve_aligned(4096, 8191).is_ok() || pool.reserve_aligned(u64::MAX, 4096).is_ok() {
        return TestResult::Fail("invalid alignment/overflow");
    }
    drop(a);
    if pool.available() != 4 << 20 {
        return TestResult::Fail("alignment leaked padding");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/psp-ring", psp_tmr_gpu_alignment_and_padding);
