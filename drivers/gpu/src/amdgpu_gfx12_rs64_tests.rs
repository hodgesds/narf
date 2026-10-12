use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

// Intentionally different banks. Golden absolute addresses come from GC12's
// headers, not the implementation constants or a map accepting all writes.
const GC: u64 = 0x10000;
const HYP: u64 = 0x40000;
const INDEX: u64 = 0x42400;
struct Fake {
    index: u32,
    registers: BTreeMap<(u32, u64), u32>,
    writes: Vec<(u32, u64, u32)>,
    busy: Option<(u32, u64)>,
    refuse: Option<u64>,
}
fn fake() -> Fake {
    Fake {
        index: 0x32,
        registers: BTreeMap::from([((0, 0x4200c), 0x14000003), ((0, 0x4a410), 0x40000003)]),
        writes: Vec::new(),
        busy: None,
        refuse: None,
    }
}
impl Io for Fake {
    fn read(&mut self, address: u64) -> u32 {
        match address {
            INDEX => self.index,
            0x4200c | 0x4a410 => self.registers[&(0, address)],
            0x4a01c => {
                if self.busy == Some((self.index, address)) {
                    0x04000000
                } else {
                    0
                }
            }
            0x13d00 | 0x17d00 | 0x17a00 | 0x17eac => {
                u32::from(self.busy == Some((self.index, address)))
            }
            0x17910 | 0x17964 | 0x17914 | 0x179e4 | 0x4a400 | 0x4a4e0 => {
                *self.registers.get(&(self.index, address)).unwrap_or(&0)
            }
            _ => panic!("RS64 read incorrect register bank/address"),
        }
    }
    fn write(&mut self, address: u64, value: u32) {
        self.writes.push((self.index, address, value));
        if self.refuse == Some(address) {
            return;
        }
        match address {
            INDEX => self.index = value,
            0x4200c | 0x4a410 => {
                self.registers.insert((0, address), value);
            }
            0x17910 | 0x17964 | 0x17914 | 0x179e4 => {
                assert!(self.index <= 1);
                self.registers.insert((self.index, address), value);
            }
            0x4a400 | 0x4a4e0 => {
                assert!((4..=7).contains(&self.index));
                self.registers.insert((self.index, address), value);
            }
            _ => panic!("RS64 write incorrect register bank/address"),
        }
    }
}
fn starts() -> Starts {
    Starts {
        pfp: 0x70000_00003000,
        me: 0x80000_00004000,
        mec: 0x90001_00005000,
    }
}
fn gfx12_rs64_program_counters_use_all_firmware_banks_and_pulse_resets() -> TestResult {
    let mut f = fake();
    if program(&mut f, Layout { gc: GC, hyp: HYP }, starts()) != Ok(()) || f.index != 0x32 {
        return TestResult::Fail("RS64 program sequence or selector restore");
    }
    for pipe in 0..2 {
        if f.registers[&(pipe, 0x17910)] != 0xc00
            || f.registers[&(pipe, 0x17964)] != 0x1c000
            || f.registers[&(pipe, 0x17914)] != 0x1000
            || f.registers[&(pipe, 0x179e4)] != 0x20000
        {
            return TestResult::Fail("PFP/ME entrypoint shift or pipe banks");
        }
    }
    for pipe in 4..8 {
        if f.registers[&(pipe, 0x4a400)] != 0x40001400 || f.registers[&(pipe, 0x4a4e0)] != 0x24000 {
            return TestResult::Fail("MEC entrypoint lost high-bit carry or pipe bank");
        }
    }
    let pulses: Vec<_> = f
        .writes
        .iter()
        .filter(|w| matches!(w.1, 0x4200c | 0x4a410))
        .copied()
        .collect();
    if pulses
        != [
            (0, 0x4200c, 0x140c0003),
            (0, 0x4200c, 0x14000003),
            (0, 0x4200c, 0x14300003),
            (0, 0x4200c, 0x14000003),
            (0, 0x4a410, 0x400f0003),
            (0, 0x4a410, 0x40000003),
        ]
    {
        return TestResult::Fail("RS64 reset pulses lost halt/step controls");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_rs64_program_counters_use_all_firmware_banks_and_pulse_resets
);

fn gfx12_rs64_refuses_live_queues_and_restores_failed_indexed_access() -> TestResult {
    for queue in [
        (0, 0x17d00),
        (0x700, 0x17a00),
        (0x305, 0x17eac),
        (0x32, 0x13d00),
        (0x32, 0x4a01c),
    ] {
        let mut f = fake();
        f.busy = Some(queue);
        if program(&mut f, Layout { gc: GC, hyp: HYP }, starts()) != Err(Error::Busy)
            || f.index != 0x32
            || f.writes.iter().any(|w| w.1 != INDEX)
        {
            return TestResult::Fail("live queue reset or selector not restored on refusal");
        }
    }
    let mut f = fake();
    f.refuse = Some(0x17964);
    if program(&mut f, Layout { gc: GC, hyp: HYP }, starts()) != Err(Error::Readback)
        || f.index != 0x32
        || f.writes.iter().any(|w| w.1 == 0x4200c)
    {
        return TestResult::Fail("failed counter readback reset a pipe or lost selector");
    }
    let mut f = fake();
    let invalid = Starts { pfp: 3, ..starts() };
    if program(&mut f, Layout { gc: GC, hyp: HYP }, invalid) != Err(Error::Invalid)
        || !f.writes.is_empty()
    {
        return TestResult::Fail("invalid firmware entry wrote hardware");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_rs64_refuses_live_queues_and_restores_failed_indexed_access
);

fn gfx12_rs64_constructor_and_revocation_are_checked_before_mmio() -> TestResult {
    let firmware = fw::fixture();
    let mut gpu = fw::tests::gpu();
    gpu.ip_blocks[0].num_bases = 2;
    gpu.regs.len = 0x10000;
    let cap = Cap::bootstrap();
    cap.revoke();
    // SAFETY: descriptor has a null mapping; revoked authority must never use it.
    let mut owner = unsafe { Rs64::new(&gpu, cap, &firmware) }.unwrap();
    // SAFETY: revoked authority prevents all access to the inert mapping.
    if unsafe { owner.configure() } != Err(Error::Revoked)
        || owner.state() != State::Failed(Error::Revoked)
        // SAFETY: failed state must reject replay before touching hardware.
        || unsafe { owner.configure() } != Err(Error::Busy)
    {
        return TestResult::Fail("revoked or repeated RS64 setup reached registers");
    }
    for len in [0, 0x2938 * 4 + 3] {
        gpu.regs.len = len;
        // SAFETY: construction validates metadata without accessing MMIO.
        if unsafe { Rs64::new(&gpu, cap, &firmware) }.is_ok() {
            return TestResult::Fail("truncated GC bank accepted");
        }
    }
    gpu.regs.len = 0x10000;
    gpu.ip_blocks[0].revision = 0;
    // SAFETY: construction validates metadata without accessing MMIO.
    if unsafe { Rs64::new(&gpu, cap, &firmware) }.is_ok() {
        return TestResult::Fail("foreign GC12 revision accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/gfx12",
    gfx12_rs64_constructor_and_revocation_are_checked_before_mmio
);
