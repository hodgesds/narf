use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};
const OSS: u64 = 0x10000;
const GC: u64 = 0x30000;
const NBIO: u64 = 0x60000;
const ADDRESS: u64 = 0x8_0020_0000;
struct Fake {
    regs: BTreeMap<u64, u32>,
    data: Vec<u32>,
    writes: Vec<(u64, u32)>,
    dirty: bool,
    flushed: bool,
    refuse: Option<u64>,
    overflow_on_copy: bool,
    copies: usize,
}
impl Io for Fake {
    fn read(&mut self, at: u64) -> u32 {
        *self.regs.get(&at).unwrap_or(&0)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.writes.push((at, value));
        if self.refuse == Some(at) {
            return;
        }
        if at == 0x7f000 {
            self.dirty = false;
            self.flushed = true;
            return;
        }
        assert!(!self.dirty, "published IH addresses before VRAM flush");
        match (at - OSS) / 4 {
            0x80..=0x87 | 0x8c..=0x90 | 0x93 | 0xc1 | 0x183 | 0x184 | 0xaa | 0xd5 | 0xf1 => {}
            _ => panic!("wrong native IH7 register {at:x}"),
        }
        self.regs.insert(at, value);
    }
    fn memory_read(&mut self, _: MmioRegion, at: u64) -> u32 {
        assert!(self.flushed, "read IH vectors without visibility barrier");
        self.copies += 1;
        if self.overflow_on_copy {
            *self.regs.entry(OSS + 0x82 * 4).or_default() |= 1;
        }
        self.data[(at / 4) as usize]
    }
    fn memory_write(&mut self, _: MmioRegion, at: u64, value: u32) {
        self.dirty = true;
        self.data[(at / 4) as usize] = value;
    }
}
fn fixture() -> (Pool, Engine<Fake>) {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(0x90200000),
        virt: 0,
        len: BYTES,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: model intercepts all MMIO; the pool is allocation bookkeeping only.
    let pool = unsafe { Pool::from_owned_range(map, ADDRESS) }.unwrap();
    let e = Engine {
        io: Fake {
            regs: BTreeMap::from([
                (OSS + 0xc2 * 4, 0x40045),
                (OSS + 0x183 * 4, 5),
                (OSS + 0xc1 * 4, 0x12345678),
                (GC + 0x1614 * 4, 0x800),
                (GC + 0x1615 * 4, 0xbff),
                (NBIO + 0x12d * 4, 0x7f000),
            ]),
            data: vec![u32::MAX; BYTES as usize / 4],
            writes: Vec::new(),
            dirty: false,
            flushed: false,
            refuse: None,
            overflow_on_copy: false,
            copies: 0,
        },
        authority: Cap::bootstrap(),
        layout: Layout {
            oss: OSS,
            gc: GC,
            nbio: NBIO,
        },
        memory: pool.reserve(BYTES).unwrap(),
        state: State::Prepared,
        rptr: [0; 2],
        consumed: [0; 2],
        host_interrupts: false,
    };
    (pool, e)
}
fn words(sequence: u32) -> [u32; 8] {
    [
        0x8c03b50a,
        sequence,
        0x80001234,
        0x0056abcd,
        0x10203040,
        u32::MAX,
        3,
        4,
    ]
}
fn push(e: &mut Engine<Fake>, ring: usize, sequence: u32) {
    let reg = OSS + [0x82, 0x8e][ring] * 4;
    let offset = e.io.regs[&reg];
    let start = (OFFSETS[ring] + u64::from(offset)) as usize / 4;
    e.io.data[start..start + 8].copy_from_slice(&words(sequence));
    e.io.regs.insert(reg, (offset + 32) & (SIZES[ring] - 1));
    e.io.flushed = false;
}
fn ih7_decodes_native_fields_and_initializes_two_owned_rings() -> TestResult {
    let v = Vector::decode(words(0x89abcdef));
    assert_eq!(
        v,
        Vector {
            client: 0x0a,
            source: 0xb5,
            ring: 3,
            vmid: 12,
            vmid_source: true,
            timestamp: 0x123489abcdef,
            timestamp_source: true,
            pasid: 0xabcd,
            node: 0x56,
            data: [0x10203040, u32::MAX, 3, 4]
        }
    );
    let (pool, mut e) = fixture();
    let report = e.initialize().unwrap();
    assert_eq!(report.ring_addresses, [ADDRESS, ADDRESS + 256 * 1024]);
    assert_eq!(report.ring_bytes, [256 * 1024, 16 * 1024]);
    assert!(!report.host_interrupts);
    assert_eq!(report.consumed, [0, 0]);
    let r = &e.io.regs;
    for (at, want) in [
        (0x80, 0x40110121),
        (0x8c, 0x40100219),
        (0x83, 0x08002000),
        (0x8f, 0x08002400),
        (0x84, 0),
        (0x90, 0),
        (0x85, 8),
        (0x86, 0x00244000),
        (0x81, 0),
        (0x82, 0),
        (0x8d, 0),
        (0x8e, 0),
        (0x87, 0),
        (0x93, 0),
        (0x183, 5),
        (0x184, 0x1000a),
        (0xc1, 0x12345668),
    ] {
        assert_eq!(r[&(OSS + at * 4)], want, "register {at:x}");
    }
    assert!(e.io.data.iter().all(|w| *w == 0));
    assert!(e.drain().unwrap().is_empty());
    let writes = e.io.writes.len();
    assert_eq!(e.initialize(), Err(Error::Busy));
    assert_eq!(e.io.writes.len(), writes);
    drop(e);
    assert_eq!(pool.available(), 0, "published IH backing freed");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih7",
    ih7_decodes_native_fields_and_initializes_two_owned_rings
);

fn ih7_drains_both_rings_fairly_with_wrap_and_complete_vectors() -> TestResult {
    let (_pool, mut e) = fixture();
    e.initialize().unwrap();
    for ring in 0..2 {
        e.rptr[ring] = SIZES[ring] - 32;
        e.io.regs.insert(OSS + [0x81, 0x8d][ring] * 4, e.rptr[ring]);
        e.io.regs.insert(OSS + [0x82, 0x8e][ring] * 4, e.rptr[ring]);
        for seq in 0..20 {
            push(&mut e, ring, seq);
        }
    }
    let first = e.drain().unwrap();
    assert!(first.pending);
    assert_eq!(first.events().count(), 32);
    for (index, event) in first.events().enumerate() {
        assert_eq!(event.ih_ring, (index / 16) as u8);
        assert_eq!(event.vector, Vector::decode(words((index % 16) as u32)));
    }
    let second = e.drain().unwrap();
    assert!(!second.pending);
    assert_eq!(second.events().count(), 8);
    for (index, event) in second.events().enumerate() {
        assert_eq!(event.ih_ring, (index / 4) as u8);
        assert_eq!(event.vector, Vector::decode(words((index % 4) as u32 + 16)));
    }
    assert_eq!(e.consumed, [20, 20]);
    assert_eq!(e.rptr, [608, 608]);
    assert!(e.drain().unwrap().is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih7",
    ih7_drains_both_rings_fairly_with_wrap_and_complete_vectors
);

fn ih7_overflow_invalid_pointer_and_lost_ownership_fail_closed() -> TestResult {
    for case in 0..6 {
        let (_pool, mut e) = fixture();
        e.initialize().unwrap();
        push(&mut e, 0, 1);
        let error = match case {
            0 => {
                e.io.regs.insert(OSS + 0x82 * 4, 33);
                Error::Overflow(0)
            }
            1 => {
                e.io.regs.insert(OSS + 0x8e * 4, 1);
                Error::Overflow(1)
            }
            2 => {
                e.io.regs.insert(OSS + 0x82 * 4, 4);
                Error::Protocol
            }
            3 => {
                e.io.regs.insert(OSS + 0x8e * 4, 16384);
                Error::Protocol
            }
            4 => {
                e.io.regs.insert(OSS + 0x81 * 4, 32);
                Error::Protocol
            }
            _ => {
                e.io.overflow_on_copy = true;
                Error::Overflow(0)
            }
        };
        assert_eq!(e.drain().unwrap_err(), error);
        assert_eq!(e.state, State::Failed(error));
        assert_eq!(e.consumed, [0, 0]);
        assert_eq!(e.rptr, [0, 0]);
        assert_eq!(e.io.regs[&(OSS + 0x80 * 4)] & 0x20001, 0);
        assert_eq!(e.io.regs[&(OSS + 0x8c * 4)] & 1, 0);
        let writes = e.io.writes.len();
        assert_eq!(e.drain().unwrap_err(), Error::Busy);
        assert_eq!(e.io.writes.len(), writes);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih7",
    ih7_overflow_invalid_pointer_and_lost_ownership_fail_closed
);

fn ih7_refuses_inherited_hardware_before_any_write() -> TestResult {
    for (at, value) in [(0x80, 1), (0x80, 0x20000), (0x8c, 1), (0xc2, 0x41)] {
        let (pool, mut e) = fixture();
        e.io.regs.insert(OSS + at * 4, value);
        assert_eq!(e.initialize(), Err(Error::Busy));
        assert!(e.io.writes.is_empty());
        assert!(e.io.data.iter().all(|w| *w == u32::MAX));
        drop(e);
        assert_eq!(pool.available(), BYTES);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih7",
    ih7_refuses_inherited_hardware_before_any_write
);

fn ih7_publication_and_revocation_retain_backing_without_unauthorized_io() -> TestResult {
    let (pool, mut e) = fixture();
    e.io.refuse = Some(OSS + 0x83 * 4);
    assert_eq!(e.initialize(), Err(Error::Readback));
    drop(e);
    assert_eq!(pool.available(), 0);
    let (pool, mut e) = fixture();
    e.initialize().unwrap();
    push(&mut e, 1, 2);
    e.authority.revoke();
    let writes = e.io.writes.len();
    assert_eq!(e.drain().unwrap_err(), Error::Revoked);
    assert_eq!(writes, e.io.writes.len());
    assert_eq!(e.io.copies, 0);
    drop(e);
    assert_eq!(pool.available(), 0);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih7",
    ih7_publication_and_revocation_retain_backing_without_unauthorized_io
);

fn ih7_host_delivery_arms_last_and_preserves_ring_configuration() -> TestResult {
    let (_pool, mut e) = fixture();
    e.initialize().unwrap();
    let before = e.io.regs[&(OSS + 0x80 * 4)];
    e.io.regs.insert(OSS + 0xaa * 4, 0x55);
    e.io.regs.insert(OSS + 0xd5 * 4, 0x83);
    e.io.regs.insert(OSS + 0xf1 * 4, 0x800000ff);
    host_control(&mut e.io, e.layout, true).unwrap();
    assert_eq!(e.io.regs[&(OSS + 0xaa * 4)], 0x40055);
    assert_eq!(e.io.regs[&(OSS + 0xd5 * 4)], 0x8b);
    assert_eq!(e.io.regs[&(OSS + 0xf1 * 4)], 0x80000003);
    assert_eq!(
        e.io.writes.last(),
        Some(&(OSS + 0x80 * 4, before | 0x220000))
    );
    assert_eq!(e.io.regs[&(OSS + 0xc1 * 4)] & 0x11f, 0x108);
    host_control(&mut e.io, e.layout, false).unwrap();
    assert_eq!(e.io.regs[&(OSS + 0x80 * 4)], before);
    assert_eq!(e.io.regs[&(OSS + 0xc1 * 4)] & 0x11f, 8);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/ih7",
    ih7_host_delivery_arms_last_and_preserves_ring_configuration
);
