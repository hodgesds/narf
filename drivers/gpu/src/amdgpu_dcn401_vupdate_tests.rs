use super::*;
use crate::amdgpu_navi48_dispatch as dispatch;
use alloc::{collections::BTreeMap, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
const BASE: u64 = 0x34c0 * 4;
const PENDING: u32 = (1 << 14) | (1 << 15);
#[derive(Default)]
struct Fake {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    reads: Vec<u64>,
    forbidden: u8,
    gone: bool,
    drop: Option<usize>,
    revoke: Option<(usize, Cap<BusDeviceCap, Write>)>,
}
impl Fake {
    fn inst(at: u64) -> u8 {
        u8::try_from(((at - BASE) / 4 - 0x1b88) / 0x80).unwrap()
    }
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        assert_eq!(
            self.forbidden & (1 << Self::inst(at)),
            0,
            "read fused/retired OTG"
        );
        self.reads.push(at);
        if self.gone {
            u32::MAX
        } else {
            self.regs.get(&at).copied().unwrap_or(0)
        }
    }
    fn write(&mut self, at: u64, value: u32) {
        assert_eq!(
            self.forbidden & (1 << Self::inst(at)),
            0,
            "write fused/retired OTG"
        );
        self.writes.push((at, value));
        assert_eq!(
            value & (ALL_ACK & !ACK),
            0,
            "replayed another source's clear strobe"
        );
        if self.drop != Some(self.writes.len()) {
            let value = if value & ACK != 0 {
                value & !(ALL_ACK | PENDING)
            } else {
                value & !ALL_ACK
            };
            self.regs.insert(at, value);
        }
        if let Some((n, cap)) = self.revoke {
            if self.writes.len() == n {
                cap.revoke();
            }
        }
    }
}
fn engine(fuses: u32) -> Engine<Fake> {
    Engine::new(
        Fake {
            forbidden: fuses as u8,
            ..Fake::default()
        },
        Cap::bootstrap(),
        Layout {
            base: BASE,
            pool: PipePool::from_fuses(fuses),
        },
    )
}
fn event(inst: u8) -> ih::Event {
    ih::Event {
        ih_ring: 0,
        vector: ih::Vector::decode([
            u32::from(src::CLIENT_DCN) | u32::from(0x57 + inst) << 8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]),
    }
}
fn dcn401_vupdate_primary_registers_and_harvested_source_lifecycle() -> TestResult {
    // Actual irq_service_dcn401.c macros and ASIC headers generate these rows.
    for row in include_str!("../tests/dcn401_vupdate/vectors.txt").lines() {
        let v: Vec<u64> = row
            .split_whitespace()
            .map(|s| u64::from_str_radix(s, 16).unwrap())
            .collect();
        assert_eq!(v.len(), 8);
        let l = Layout {
            base: BASE,
            pool: PipePool::FULL,
        };
        assert_eq!(l.at(v[0] as u8), v[2]);
        assert_eq!(
            (u64::from(ENABLE), u64::from(ACK), u64::from(ALL_ACK)),
            (v[3], v[4], v[7])
        );
        assert_eq!((v[5], v[6]), (u64::from(ENABLE), 0));
        assert_eq!(
            src::classify(&event(v[0] as u8)),
            src::Class::Display(src::Display::Vupdate((v[1] - 0x57) as u8))
        );
    }
    for fuses in 0..16u32 {
        let mut e = engine(fuses);
        let pool = e.layout.pool;
        for p in pool.pipes() {
            e.io.regs
                .insert(e.layout.at(p), ENABLE | PENDING | 1 | 1 << 4);
        }
        e.initialize().unwrap();
        assert_eq!(e.status.owned, 0);
        assert_eq!(e.status.enabled, 0);
        for p in pool.pipes() {
            e.enable(p).unwrap();
            let at = e.layout.at(p);
            let inst = pool.hw(p);
            e.io.regs.entry(at).and_modify(|v| *v |= PENDING);
            assert!(e.handle(event(inst)).unwrap());
            assert_eq!(e.io.regs[&at] & PENDING, 0, "ACK must precede dispatch");
            assert_ne!(e.io.regs[&at] & ENABLE, 0);
            assert_eq!(e.io.regs[&at] & 1, 1, "other source enable preserved");
            e.mask(p).unwrap();
            let reads = e.io.reads.len();
            let writes = e.io.writes.len();
            e.io.forbidden |= 1 << inst;
            assert!(
                !e.handle(event(inst)).unwrap(),
                "late retired source woke consumer"
            );
            assert_eq!((e.io.reads.len(), e.io.writes.len()), (reads, writes));
            e.io.forbidden &= !(1 << inst);
        }
        e.stop().unwrap();
        assert_eq!(e.status.owned, 0);
        assert_eq!(e.status.acknowledgements, u64::from(pool.count()));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    dcn401_vupdate_primary_registers_and_harvested_source_lifecycle
);

fn dcn401_vupdate_ack_before_live_dispatch_and_no_fused_or_stale_wake() -> TestResult {
    let prior = crate::amdgpu_rdna4::pipe_pool();
    for fuses in [0, 2] {
        let pool = PipePool::from_fuses(fuses);
        crate::amdgpu_rdna4::publish_pipe_pool(pool);
        let mut e = engine(fuses);
        e.initialize().unwrap();
        let pipe = pool.pipe(2).unwrap();
        e.enable(pipe).unwrap();
        let mut table = dispatch::Table::new();
        let irq = event(2);
        e.io.regs
            .entry(e.layout.at(pipe))
            .and_modify(|v| *v |= PENDING);
        assert_eq!(table.summary().display.vupdate, [0; 4]);
        // This is the same gate used by SERVICE before routing any vector.
        if e.handle(irq).unwrap() {
            assert_eq!(e.io.regs[&e.layout.at(pipe)] & PENDING, 0);
            assert_eq!(
                table.route(&irq, src::classify(&irq)),
                dispatch::Delivery::Display
            );
        }
        let mut expected = [0; 4];
        expected[usize::from(pipe)] = 1;
        assert_eq!(table.summary().display.vupdate, expected);
        e.mask(pipe).unwrap();
        if e.handle(irq).unwrap() {
            table.route(&irq, src::classify(&irq));
        }
        assert_eq!(table.summary().display.vupdate, expected);
        // Invalid physical source instances never touch MMIO; the dispatch
        // pool rejects them, preserving diagnostic evidence without wake.
        let fused = event(if fuses == 0 { 4 } else { 1 });
        let before = e.io.reads.len();
        assert!(e.handle(fused).unwrap());
        assert_eq!(
            table.route(&fused, src::classify(&fused)),
            dispatch::Delivery::Unhandled
        );
        assert_eq!(e.io.reads.len(), before);
    }
    crate::amdgpu_rdna4::publish_pipe_pool(prior);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    dcn401_vupdate_ack_before_live_dispatch_and_no_fused_or_stale_wake
);

fn dcn401_vupdate_partial_enable_mask_failure_and_revocation_retain_ownership() -> TestResult {
    let mut e = engine(0);
    e.initialize().unwrap();
    // A lost enable write is still owned until the independent source
    // owner masks/ACKs it and confirms the enable bit is clear.
    e.io.drop = Some(e.io.writes.len() + 2);
    assert_eq!(e.enable(1), Err(ih::Error::Readback));
    assert_eq!(e.status.owned, 2);
    e.io.drop = None;
    e.stop().unwrap();
    assert_eq!(e.status.owned, 0);
    assert_eq!(e.enable(1), Err(ih::Error::Busy));
    let mut e = engine(0);
    e.initialize().unwrap();
    e.enable(0).unwrap();
    e.io.drop = Some(e.io.writes.len() + 1);
    assert_eq!(e.mask(0), Err(ih::Error::Readback));
    assert_eq!(e.status.owned, 1);
    assert_eq!(e.status.enabled, 1);
    e.io.gone = true;
    assert_eq!(e.stop(), Err(ih::Error::DeviceGone));
    assert_eq!(e.status.owned, 1);
    // A revoked capability is checked before any source MMIO; revocation
    // after enable writes is checked again before ownership may be retired.
    let mut e = engine(0);
    e.initialize().unwrap();
    e.authority.revoke();
    let reads = e.io.reads.len();
    assert_eq!(e.enable(0), Err(ih::Error::Revoked));
    assert_eq!(e.io.reads.len(), reads);
    assert_eq!(e.status.owned, 1);
    let mut e = engine(0);
    e.initialize().unwrap();
    e.io.revoke = Some((e.io.writes.len() + 2, e.authority));
    assert_eq!(e.enable(3), Err(ih::Error::Revoked));
    assert_eq!(e.status.owned, 8);
    assert_eq!(e.stop(), Err(ih::Error::Revoked));
    assert_eq!(e.status.owned, 8);
    // ACK/source-read uncertainty never reaches the dispatcher.
    let mut e = engine(0);
    e.initialize().unwrap();
    e.enable(0).unwrap();
    e.io.gone = true;
    assert_eq!(e.handle(event(0)), Err(ih::Error::DeviceGone));
    assert_eq!(e.status.acknowledgements, 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-interrupts",
    dcn401_vupdate_partial_enable_mask_failure_and_revocation_retain_ownership
);
