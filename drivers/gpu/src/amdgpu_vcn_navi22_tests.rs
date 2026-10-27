//! Register/memory model of two VCN 3.0 instances and JPEG 3.0. The model
//! boots a VCPU only for the programmed TMR window with every tile powered
//! and its reset released, decodes the public VCN decode (PACKET0 to the
//! internal command registers), encode and JRBC ring ABIs independently of
//! the encoders, and executes work only after an HDP flush, inside an open
//! NBIF aperture and the MMSCH doorbell range of the right instance.
use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    future::Future,
    sync::atomic::AtomicU32,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Host IP discovery: UVD/VCN 3.0.0 0x7800 0x7E00, 3.0.64 0x7B00 0x12000.
const VCN: [[u64; 2]; 2] = [[0x7800 * 4, 0x7e00 * 4], [0x7b00 * 4, 0x12000 * 4]];
const GC: u64 = 0x1260 * 4;
const NBIO: u64 = 0xd20 * 4;
const HDP: u64 = 0xf20 * 4;
const PHYS: u64 = 0xa000_0000;
const MC: u64 = 0x8_0080_0000;
const TMR: [u64; 2] = [0x8_0010_1000, 0x8_0018_0000];
const FW_BYTES: u32 = 0x8_1234;
const GB_ADDR: u32 = 0x0000_0444;
const FAST: Timing = Timing {
    retries: 10,
    polls: 3,
    poll_us: 200,
    reset_us: 100,
};

fn v(i: usize, r: Reg) -> u64 {
    VCN[i][r.0 as usize] + u64::from(r.1) * 4
}
fn layout(instances: u8) -> Layout {
    Layout {
        vcn: [
            (instances & 1 != 0).then_some(VCN[0]),
            (instances & 2 != 0).then_some(VCN[1]),
        ],
        gc: GC,
        nbio: NBIO,
        hdp: HDP,
    }
}
fn pool(len: u64) -> Pool {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(PHYS),
        virt: 0,
        len,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: the model performs every access; bookkeeping-only mapping.
    unsafe { Pool::from_owned_range(map, MC) }.unwrap()
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn firmware(instances: u8) -> crate::amdgpu_psp_ring::MediaFirmware {
    crate::amdgpu_psp_ring::MediaFirmware {
        vcn: (instances & 1 != 0).then_some(TMR[0]),
        dmcub: Some(0x8_0020_0000),
        vcn1: (instances & 2 != 0).then_some(TMR[1]),
    }
}

/// Decoded firmware-visible work, in execution order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Work {
    /// Decoder message: instance, msg[1] (size), msg[2], msg[3] (type), handle.
    Message(usize, [u32; 4]),
    /// Encoder session op on (instance, ring).
    Session(usize, usize, u32),
}
struct Model {
    regs: BTreeMap<u64, u32>,
    writes: Vec<(u64, u32)>,
    mem: BTreeMap<u64, u32>,
    doorbells: Vec<(u32, u32)>,
    dirty: bool,
    stale: bool,
    /// VCPU reset releases that do not boot, per instance.
    boot_failures: [u32; 2],
    releases: [u32; 2],
    never_boot: [bool; 2],
    pgfsm_stuck: bool,
    /// Rings that ignore doorbells: dec0, enc0.0, enc0.1, dec1, enc1.0, enc1.1, jpeg.
    stalled: [bool; 7],
    drop_fences: bool,
    gone: bool,
    work: Vec<Work>,
    traps: u32,
    rptr: [u32; 7],
    /// Decoder internal registers per instance: data0, data1, ctx, ib lo/hi.
    internal: [[u32; 5]; 2],
    progress: Arc<AtomicU32>,
    revoke: Option<(u64, u32, Cap<BusDeviceCap, Write>)>,
}
fn mc(map: MmioRegion, offset: u64) -> u64 {
    map.phys.raw() - PHYS + MC + offset
}
impl Model {
    fn new() -> Self {
        let mut regs = BTreeMap::new();
        regs.insert(NBIO + u64::from(NBIO_DOORBELL_APER_EN) * 4, 1);
        regs.insert(GC + u64::from(GB_ADDR_CONFIG) * 4, GB_ADDR);
        for i in [0, 1] {
            // Tiles gated at reset, gates closed, LMI clean.
            regs.insert(v(i, PGFSM_STATUS), 0xaaaa_aaaa);
            regs.insert(v(i, CGC_GATE), CGC_GATE_ALL);
            regs.insert(v(i, CGC_CTRL), 0x1fc0_0000);
            regs.insert(v(i, POWER_STATUS), 0x101);
            regs.insert(v(i, VCPU_CNTL), VCPU_BLK_RST);
            regs.insert(v(i, RB_ARB_CTRL), RB_ARB_VCPU_DIS);
            regs.insert(v(i, LMI_STATUS), 0x24f);
            regs.insert(v(i, LMI_CTRL2), LMI_CTRL2_STALL_ARB_UMC);
            regs.insert(v(i, SOFT_RESET), SOFT_RESET_LMI | SOFT_RESET_LMI_UMC);
        }
        regs.insert(v(0, JPEG_POWER_STATUS), 0x11);
        regs.insert(v(0, JMI_CNTL), 1);
        Self {
            regs,
            writes: Vec::new(),
            mem: BTreeMap::new(),
            doorbells: Vec::new(),
            dirty: false,
            stale: false,
            boot_failures: [0; 2],
            releases: [0; 2],
            never_boot: [false; 2],
            pgfsm_stuck: false,
            stalled: [false; 7],
            drop_fences: false,
            gone: false,
            work: Vec::new(),
            traps: 0,
            rptr: [0; 7],
            internal: [[0; 5]; 2],
            progress: Arc::new(AtomicU32::new(0)),
            revoke: None,
        }
    }
    fn reg(&self, address: u64) -> u32 {
        *self.regs.get(&address).unwrap_or(&0)
    }
    fn word(&self, address: u64) -> u32 {
        *self.mem.get(&address).unwrap_or(&0)
    }
    fn put(&mut self, address: u64, value: u32) {
        assert_eq!(address % 4, 0);
        self.mem.insert(address, value);
        self.stale = true;
    }
    fn pair(&self, low: u64, high: u64) -> u64 {
        u64::from(self.reg(low)) | (u64::from(self.reg(high)) << 32)
    }
    fn booted(&self, i: usize) -> bool {
        self.reg(v(i, STATUS)) & VCPU_REPORT_BOOTED != 0
    }
    /// PGFSM: config 1 powers a tile on (status 0), 2 off (status 2).
    fn pgfsm(&mut self, i: usize, config: u32) {
        if self.pgfsm_stuck {
            return;
        }
        let mut status = self.reg(v(i, PGFSM_STATUS));
        for tile in 0..16 {
            let shift = tile * 2;
            match (config >> shift) & 3 {
                1 => status &= !(3 << shift),
                2 => status = (status & !(3 << shift)) | (2 << shift),
                _ => {}
            }
        }
        self.regs.insert(v(i, PGFSM_STATUS), status);
    }
    fn vcpu(&mut self, i: usize, old: u32, new: u32) {
        if new & VCPU_BLK_RST != 0 {
            let status = self.reg(v(i, STATUS)) & !VCPU_REPORT_BOOTED;
            self.regs.insert(v(i, STATUS), status);
            return;
        }
        if old & VCPU_BLK_RST == 0 || new & VCPU_CLK_EN == 0 {
            return;
        }
        let window = self.pair(v(i, LMI_VCPU_CACHE_BAR_LOW), v(i, LMI_VCPU_CACHE_BAR_HIGH));
        let size = self.reg(v(i, VCPU_CACHE_SIZE0));
        let powered = self.reg(v(i, PGFSM_STATUS)) & PGFSM_STATUS_MASK == 0;
        if window != TMR[i] || size != (FW_BYTES + 4 + 4095) & !4095 || !powered {
            return;
        }
        self.releases[i] += 1;
        if !self.never_boot[i] && self.releases[i] > self.boot_failures[i] {
            let status = self.reg(v(i, STATUS)) | VCPU_REPORT_BOOTED;
            self.regs.insert(v(i, STATUS), status);
        }
    }
    fn range(&self, i: usize, index: u32) -> bool {
        let range = self.reg(NBIO + u64::from(NBIO_MMSCH_DOORBELL_RANGE[i]) * 4);
        let offset = (range & 0xffc) >> 2;
        self.reg(NBIO + u64::from(NBIO_DOORBELL_APER_EN) * 4) & 1 != 0
            && (offset..offset + ((range >> 16) & 0x1f)).contains(&index)
    }
    fn ring(&self, base: u64, from: u32, to: u32) -> Vec<u32> {
        let mut words = Vec::new();
        let mut at = from;
        while at != to {
            words.push(self.word(base + u64::from(at) * 4));
            at = (at + 1) % RING_DW;
        }
        words
    }
    fn dec(&mut self, i: usize, words: &[u32], ib: bool) {
        assert_eq!(words.len() % 2, 0, "odd decode packet stream");
        for pair in words.chunks_exact(2) {
            let (h, value) = (pair[0], pair[1]);
            assert_eq!(h & !0xffff, 0, "decode stream is PACKET0 count 0");
            let s = &mut self.internal[i];
            match h {
                cmd::INTERNAL_DATA0 => s[0] = value,
                cmd::INTERNAL_DATA1 => s[1] = value,
                cmd::INTERNAL_CONTEXT_ID => s[2] = value,
                cmd::INTERNAL_IB_VMID => assert_eq!(value, 0, "kernel IB outside VMID0"),
                cmd::INTERNAL_IB_BAR_LOW => s[3] = value,
                cmd::INTERNAL_IB_BAR_HIGH => s[4] = value,
                cmd::INTERNAL_NOP => {}
                cmd::INTERNAL_SCRATCH9 => {
                    self.regs.insert(v(i, SCRATCH9), value);
                }
                cmd::INTERNAL_IB_SIZE => {
                    assert!(!ib, "chained decode IB");
                    assert_eq!(value, 16);
                    let address = u64::from(s[3]) | (u64::from(s[4]) << 32);
                    let ib_words: Vec<u32> = (0..16).map(|k| self.word(address + k * 4)).collect();
                    self.dec(i, &ib_words, true);
                }
                cmd::INTERNAL_CMD if value & cmd::DEC_KMD != 0 => {
                    match (value & !cmd::DEC_KMD) >> 1 {
                        cmd::DEC_PACKET_START | cmd::DEC_PACKET_END => {}
                        cmd::DEC_FENCE => {
                            let address = u64::from(s[0]) | (u64::from(s[1]) << 32);
                            let seq = s[2];
                            if !self.drop_fences {
                                self.put(address, seq);
                            }
                        }
                        cmd::DEC_TRAP => self.traps += 1,
                        other => panic!("unexpected decode KMD command {other:#x}"),
                    }
                }
                cmd::INTERNAL_CMD => {
                    assert!(ib && value == 0, "message outside an IB");
                    let msg = u64::from(s[0]) | (u64::from(s[1]) << 32);
                    assert_eq!(msg % 4096, 0, "message not page aligned");
                    assert_eq!(self.word(msg), 0x28);
                    let header = [1, 2, 3, 4].map(|k| self.word(msg + k * 4));
                    self.work.push(Work::Message(i, header));
                }
                other => panic!("unexpected decode register {other:#x}"),
            }
        }
    }
    fn enc(&mut self, i: usize, j: usize, words: &[u32]) {
        let mut k = 0;
        while k < words.len() {
            k += match words[k] {
                cmd::ENC_NOP | cmd::ENC_END => 1,
                cmd::ENC_IB => {
                    assert_eq!(words[k + 1], 0, "kernel IB outside VMID0");
                    assert_eq!(words[k + 4], 16);
                    let address = u64::from(words[k + 2]) | (u64::from(words[k + 3]) << 32);
                    let ib: Vec<u32> = (0..16).map(|n| self.word(address + n * 4)).collect();
                    assert_eq!(ib[..3], [0x18, 1, 1], "session info / handle 1");
                    assert_eq!(ib[6..11], [0x14, 2, 0x1c, 0, 0], "task info");
                    let session = (u64::from(ib[3]) << 32) | u64::from(ib[4]);
                    assert_eq!(session % 4096, 0);
                    assert_eq!(ib[11], 8);
                    self.work.push(Work::Session(i, j, ib[12]));
                    5
                }
                cmd::ENC_FENCE => {
                    let address = u64::from(words[k + 1]) | (u64::from(words[k + 2]) << 32);
                    if !self.drop_fences {
                        self.put(address, words[k + 3]);
                    }
                    4
                }
                cmd::ENC_TRAP => {
                    self.traps += 1;
                    1
                }
                other => panic!("unexpected encode command {other:#x}"),
            };
        }
    }
    fn jpeg(&mut self, words: &[u32]) {
        for pair in words.chunks_exact(2) {
            match pair[0] {
                cmd::JPEG_NOP => {}
                h if h == cmd::packet0(cmd::JPEG_INTERNAL_PITCH) => {
                    self.regs.insert(v(0, JPEG_PITCH), pair[1]);
                }
                other => panic!("unexpected JRBC packet {other:#x}"),
            }
        }
    }
    fn ring_doorbell(&mut self, index: u32, value: u32) {
        assert!(!self.dirty, "doorbell before HDP flush");
        assert!(value < RING_DW);
        for i in [0, 1] {
            if !self.range(i, index) {
                continue;
            }
            if index == doorbell::dec(i as u32) {
                let slot = 3 * i;
                if !self.booted(i) || self.stalled[slot] {
                    return;
                }
                let base = self.pair(v(i, LMI_RBC_RB_BAR_LOW), v(i, LMI_RBC_RB_BAR_HIGH));
                assert_eq!(
                    self.word(base + WPTR[0] - DEC_RING),
                    value,
                    "dec wptr shadow"
                );
                let words = self.ring(base, self.rptr[slot], value);
                self.dec(i, &words, false);
                self.rptr[slot] = value;
                self.regs.insert(v(i, RBC_RB_RPTR), value);
                return;
            }
            for j in [0, 1] {
                if index != doorbell::enc(i as u32, j as u32) {
                    continue;
                }
                let slot = 3 * i + 1 + j;
                if !self.booted(i) || self.stalled[slot] {
                    return;
                }
                assert_eq!(self.reg(v(i, RB_SIZE[j])), RING_DW);
                let base = self.pair(v(i, RB_BASE_LO[j]), v(i, RB_BASE_HI[j]));
                let words = self.ring(base, self.rptr[slot], value);
                self.enc(i, j, &words);
                self.rptr[slot] = value;
                self.regs.insert(v(i, RB_RPTR[j]), value);
                return;
            }
            if i == 0 && index == doorbell::JPEG {
                let powered = self.reg(v(0, PGFSM_STATUS)) & PGFSM_UVDJ_STATUS == 0;
                if !powered
                    || self.reg(v(0, JRBC_RB_CNTL)) != 2
                    || self.reg(v(0, JMI_CNTL)) & 1 != 0
                    || self.stalled[6]
                {
                    return;
                }
                let base = self.pair(v(0, LMI_JRBC_RB_BAR_LOW), v(0, LMI_JRBC_RB_BAR_HIGH));
                let words = self.ring(base, self.rptr[6], value);
                self.jpeg(&words);
                self.rptr[6] = value;
                self.regs.insert(v(0, JRBC_RB_RPTR), value);
                return;
            }
        }
    }
}
impl Io for Model {
    fn wait_poll_limit(&self) -> Option<u32> {
        // The model executes ring work synchronously at the doorbell
        // write, so a fence or register wait samples its completion on
        // the first poll after submission. A wait still incomplete
        // after sixteen samples is a designed non-completion (a stalled
        // ring) whose outcome is the timeout — reached by count instead
        // of burning the wall-clock deadline under the spin executor
        // (#879).
        Some(16)
    }
    fn read(&mut self, address: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        self.reg(address)
    }
    fn write(&mut self, address: u64, value: u32) {
        self.writes.push((address, value));
        if address == 0x7f000 {
            self.dirty = false;
        }
        if address == HDP + 0xd1 * 4 {
            self.stale = false;
        }
        let old = self.reg(address);
        self.regs.insert(address, value);
        for i in [0, 1] {
            if address == v(i, PGFSM_CONFIG) {
                self.pgfsm(i, value);
            }
            if address == v(i, VCPU_CNTL) {
                self.progress.fetch_add(1, Ordering::SeqCst);
                self.vcpu(i, old, value);
            }
        }
        if let Some((reg, want, cap)) = self.revoke {
            if reg == address && value == want {
                cap.revoke();
            }
        }
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        if self.gone {
            return u32::MAX;
        }
        assert!(!self.stale, "CPU read without HDP invalidate");
        self.word(mc(map, offset))
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        assert!(offset + 4 <= map.len, "write outside reservation");
        self.dirty = true;
        self.mem.insert(mc(map, offset), value);
    }
    fn zero_memory(&mut self, map: MmioRegion, offset: u64, len: u64) {
        assert!(offset + len <= map.len, "zero outside reservation");
        self.dirty = true;
        let (start, end) = (mc(map, offset), mc(map, offset + len));
        self.mem.retain(|&k, _| !(start..end).contains(&k));
    }
    fn doorbell(&mut self, index: u32, value: u32) {
        self.doorbells.push((index, value));
        self.progress.fetch_add(1 << 16, Ordering::SeqCst);
        self.ring_doorbell(index, value);
    }
}

fn engine(model: Model, instances: u8) -> (Pool, Engine<Model>) {
    let pool = pool(4 << 20);
    let vcn = [0, 1].map(|i| (instances & (1 << i) != 0).then(|| Instance::new(&pool, i).unwrap()));
    let jpeg = (instances & 1 != 0).then(|| Jpeg::new(&pool).unwrap());
    (
        pool,
        Engine {
            enc_count: 2,
            hw: Hw {
                io: model,
                authority: Cap::bootstrap(),
                layout: layout(instances),
            },
            vcn,
            jpeg_state: if jpeg.is_some() {
                JpegState::Prepared
            } else {
                JpegState::Absent
            },
            jpeg,
            firmware_bytes: FW_BYTES,
            timing: FAST,
            state: State::Prepared,
            proof: Proof {
                instances,
                ..Proof::default()
            },
        },
    )
}
fn owned(instances: u8) -> u64 {
    let jpeg = if instances & 1 != 0 { JPEG_BYTES } else { 0 };
    u64::from(instances.count_ones()) * ((INSTANCE_BYTES + 4095) & !4095) + jpeg
}

fn vcn_navi24_decode_only() -> TestResult {
    let (_pool, mut e) = engine(Model::new(), 1);
    e.enc_count = 0;
    if run(e.start(firmware(1), None)).is_err()
        || run(e.start_jpeg()).is_err()
        || run(e.test_ib()).is_err()
        || e.proof.dec_ring != [true, false]
        || e.proof.dec_ib != [2, 0]
        || e.proof.enc_ring != [[false; 2]; 2]
        || e.proof.enc_ib != [[0; 2]; 2]
        || !e.proof.jpeg_ring
    {
        return TestResult::Fail("decode-only VCN/JPEG proofs");
    }
    for regs in [RB_BASE_LO, RB_BASE_HI, RB_SIZE, RB_RPTR, RB_WPTR] {
        if regs
            .iter()
            .any(|r| e.hw.io.writes.iter().any(|(addr, _)| *addr == v(0, *r)))
        {
            return TestResult::Fail("Navi24 touched absent encoder registers");
        }
    }
    if e.hw
        .io
        .doorbells
        .iter()
        .any(|(index, _)| *index == doorbell::enc(0, 0) || *index == doorbell::enc(0, 1))
    {
        return TestResult::Fail("Navi24 rang absent encoder doorbell");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/vcn-navi22", vcn_navi24_decode_only);
fn cancel_at<F: Future>(future: F, progress: &AtomicU32, goal: u32) -> bool {
    let mut future = core::pin::pin!(future);
    let deadline = narf_time::Deadline::after_ms(1000);
    loop {
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return false;
        }
        if progress.load(Ordering::SeqCst) >= goal {
            return true;
        }
        if deadline.expired() {
            return false;
        }
    }
}

fn vcn_navi22_resolves_both_discovered_instances() -> TestResult {
    let mut gpu = crate::amdgpu_gfx_navi22::tests::gpu();
    gpu.regs.len = 1 << 20;
    gpu.ip_blocks.retain(|b| b.hw_id != ip::HW_ID_VCN);
    let base = |id, version: (u8, u8, u8), instance, bases: &[u32]| {
        let mut addrs = [0; ip::MAX_BASE_ADDRS];
        addrs[..bases.len()].copy_from_slice(bases);
        ip::IpBlock {
            hw_id: id,
            instance,
            major: version.0,
            minor: version.1,
            revision: version.2,
            sub_revision: 0,
            variant: 0,
            base_addrs: addrs,
            num_bases: bases.len() as u8,
        }
    };
    gpu.ip_blocks.retain(|b| b.hw_id != ip::HW_ID_GC);
    gpu.ip_blocks.extend([
        base(
            ip::HW_ID_GC,
            (10, 3, 2),
            0,
            &[0x1260, 0xa000, 0x1c000, 0x2402c00],
        ),
        base(
            ip::HW_ID_NBIF,
            (3, 3, 1),
            0,
            &[0, 0x14, 0xd20, 0x10400, 0x241b000],
        ),
        base(ip::HW_ID_HDP, (5, 0, 3), 0, &[0xf20, 0x240a400]),
        base(ip::HW_ID_VCN, (3, 0, 0), 0, &[0x7800, 0x7e00, 0x2403000]),
        base(ip::HW_ID_VCN, (3, 0, 64), 1, &[0x7b00, 0x12000, 0x2445000]),
    ]);
    if Layout::resolve(&gpu, 3) != Ok(layout(3))
        || Layout::resolve(&gpu, 2).map(|l| l.vcn) != Ok([None, Some(VCN[1])])
        || Layout::resolve(&gpu, 4).is_ok()
    {
        return TestResult::Fail("VCN instance banks differ from discovery");
    }
    // SOC15_REG_OFFSET(VCN, 1, mmUVD_STATUS) = 0x12000 + 0x80.
    if layout(3).reg(1, STATUS) != (0x12000 + 0x80) * 4
        || layout(3).reg(0, JRBC_RB_WPTR) != (0x7800 + 0x100) * 4
        || layout(3).nbio(NBIO_MMSCH_DOORBELL_RANGE[1]) != (0xd20 + 0x1d8) * 4
    {
        return TestResult::Fail("VCN/JPEG/NBIO register address");
    }
    gpu.ip_blocks.pop();
    if Layout::resolve(&gpu, 3).is_ok() {
        return TestResult::Fail("missing VCN instance 1 accepted");
    }
    if doorbell::dec(0) != 0x310
        || doorbell::enc(0, 1) != 0x313
        || doorbell::dec(1) != 0x318
        || doorbell::enc(1, 0) != 0x31a
        || doorbell::JPEG != 0x311
    {
        return TestResult::Fail("VCN doorbell assignment");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_resolves_both_discovered_instances
);

/// Build a minimal discovery blob whose harvest table lists `entries`.
fn discovery_blob(entries: &[(u16, u8)], offset: u16, corrupt: bool) -> Vec<u8> {
    let mut blob = alloc::vec![0u8; 1024];
    blob[..4].copy_from_slice(&ip::BINARY_SIGNATURE.to_le_bytes());
    let table = 512usize;
    blob[table..table + 4].copy_from_slice(&ip::HARVEST_TABLE_SIGNATURE.to_le_bytes());
    for (k, &(id, instance)) in entries.iter().enumerate() {
        let at = table + 8 + k * 4;
        blob[at..at + 2].copy_from_slice(&id.to_le_bytes());
        blob[at + 2] = instance;
    }
    let sum = blob[table..table + 136]
        .iter()
        .fold(0u16, |s, &b| s.wrapping_add(u16::from(b)));
    let entry = 12 + ip::TABLE_HARVEST_INFO * 8;
    let offset = if offset == 0 { 0 } else { table as u16 };
    blob[entry..entry + 2].copy_from_slice(&offset.to_le_bytes());
    let sum = if corrupt { sum ^ 1 } else { sum };
    blob[entry + 2..entry + 4].copy_from_slice(&sum.to_le_bytes());
    blob
}
fn vcn_navi22_harvest_table_and_revision_quirk() -> TestResult {
    let dmu = 4; // DMU_HWID
    for (entries, want) in [
        (&[][..], 0u8),
        (&[(ip::HW_ID_VCN, 1)][..], 2),
        (&[(dmu, 0), (ip::HW_ID_VCN, 0)][..], 1),
        (&[(ip::HW_ID_VCN, 0), (0, 0), (ip::HW_ID_VCN, 1)][..], 1),
    ] {
        if ip::parse_vcn_harvest(&discovery_blob(entries, 1, false)) != Ok(want) {
            return TestResult::Fail("harvest table VCN mask");
        }
    }
    if ip::parse_vcn_harvest(&discovery_blob(&[(ip::HW_ID_VCN, 0)], 0, false)) != Ok(0)
        || ip::parse_vcn_harvest(&discovery_blob(&[], 1, true))
            != Err(ip::DiscoveryError::BadHarvestTable)
        || ip::parse_vcn_harvest(&[0; 8]) != Err(ip::DiscoveryError::Truncated)
    {
        return TestResult::Fail("missing/corrupt harvest table handling");
    }
    if Harvest::navi22(0, 0xc0) != Harvest(0)
        || Harvest::navi22(0, 0xc1) != Harvest(2)
        || Harvest::navi22(1, 0xdf) != Harvest(3)
    {
        return TestResult::Fail("Navy Flounder VCN1 harvest quirk");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_harvest_table_and_revision_quirk
);

fn vcn_navi22_starts_both_instances_with_ring_and_ib_tests() -> TestResult {
    let (pool, mut e) = engine(Model::new(), 3);
    if run(e.start(firmware(3), None)).is_err() || e.state != State::Running {
        return TestResult::Fail("VCN start failed");
    }
    if run(e.start_jpeg()).is_err() || run(e.test_ib()).is_err() || e.state != State::Verified {
        return TestResult::Fail("VCN/JPEG ring or IB test failed");
    }
    let m = &e.hw.io;
    for i in [0, 1] {
        let inst = e.vcn[i].as_ref().unwrap();
        let base = inst.address(0);
        let index = doorbell::dec(i as u32);
        for (reg, value) in [
            // JPEG's UVDJ power-up is the last PGFSM command on instance 0.
            (
                PGFSM_CONFIG,
                if i == 0 { PGFSM_UVDJ_ON } else { PGFSM_ALL_ON },
            ),
            (POWER_STATUS, 0),
            (STATUS, VCPU_REPORT_BOOTED),
            (CGC_GATE, 0),
            (CGC_CTRL, 0x105),
            (SUVD_CGC_GATE, SUVD_CGC_GATE_ALL),
            (SUVD_CGC_GATE2, 0x1f),
            (SUVD_CGC_CTRL, 0),
            (VCPU_CNTL, VCPU_CLK_EN),
            (MASTINT_EN, MASTINT_VCPU_EN),
            (LMI_CTRL2, 0),
            (SOFT_RESET, 0),
            (LMI_CTRL, LMI_CTRL_SET),
            (MPC_CNTL, 0x10),
            (MPC_SET_MUXA0, 0x040c_2040),
            (MPC_SET_MUXB0, 0x040c_2040),
            (MPC_SET_MUX, 0x88),
            (LMI_VCPU_CACHE_BAR_LOW, TMR[i] as u32),
            (LMI_VCPU_CACHE_BAR_HIGH, 8),
            (VCPU_CACHE_OFFSET0, 0),
            (VCPU_CACHE_SIZE0, 0x8_2000),
            (LMI_VCPU_CACHE1_BAR_LOW, base as u32),
            (VCPU_CACHE_SIZE1, 0x2_0000),
            (LMI_VCPU_CACHE2_BAR_LOW, (base + 0x2_0000) as u32),
            (VCPU_CACHE_SIZE2, 0x8_0000),
            (LMI_VCPU_NC0_BAR_LOW, (base + 0xa_0000) as u32),
            (VCPU_NONCACHE_SIZE0, 4096),
            (GFX10_ADDR_CONFIG, GB_ADDR),
            (RB_ARB_CTRL, 0),
            (LMI_RBC_RB_VMID, 0),
            (RBC_RB_CNTL, 0x1101_010c),
            (LMI_RBC_RB_BAR_LOW, inst.address(DEC_RING) as u32),
            (RB_BASE_LO[0], inst.address(ENC_RING[0]) as u32),
            (RB_BASE_LO[1], inst.address(ENC_RING[1]) as u32),
            (RB_SIZE[0], 1024),
            (RB_SIZE[1], 1024),
            (SCRATCH9, 0xdead_beef),
        ] {
            if m.reg(v(i, reg)) != value {
                return TestResult::Fail("VCN start register programming");
            }
        }
        let range = m.reg(NBIO + u64::from(NBIO_MMSCH_DOORBELL_RANGE[i]) * 4);
        let shared = mc(inst.memory.mapping(), SHARED);
        if range != ((index << 2) & 0xffc) | (8 << 16)
            || m.word(shared) != 0xb40
            || m.word(shared + shared::QUEUE_MODES) != 0
            || m.word(mc(inst.memory.mapping(), FENCE[0])) != 2
            || m.word(mc(inst.memory.mapping(), FENCE[1])) != 2
            || m.word(mc(inst.memory.mapping(), FENCE[2])) != 2
        {
            return TestResult::Fail("VCN doorbell range, fw_shared or fences");
        }
    }
    let messages: Vec<Work> = m
        .work
        .iter()
        .copied()
        .filter(|w| matches!(w, Work::Message(..)))
        .collect();
    let sessions = m
        .work
        .iter()
        .filter(|w| matches!(w, Work::Session(..)))
        .count();
    let create = Work::Message(0, [0x38, 1, 0, 1]);
    if messages
        != [
            create,
            Work::Message(0, [0x18, 0, 2, 1]),
            Work::Message(1, [0x38, 1, 0, 1]),
            Work::Message(1, [0x18, 0, 2, 1]),
        ]
        || sessions != 8
        || !m.work.contains(&Work::Session(1, 1, 0x0800_0002))
        || m.traps != 12
    {
        return TestResult::Fail("decode messages / encode sessions / traps");
    }
    // Ring tests then IB pairs: dec(16) enc0 enc1 per instance, JPEG, then
    // two decode commits (32 dwords each) and two per encode ring (64).
    let want_doorbells: Vec<(u32, u32)> = [
        (0x310, 16),
        (0x312, 64),
        (0x313, 64),
        (0x318, 16),
        (0x31a, 64),
        (0x31b, 64),
        (0x311, 16),
        (0x310, 48),
        (0x310, 80),
        (0x312, 128),
        (0x312, 192),
        (0x313, 128),
        (0x313, 192),
        (0x318, 48),
        (0x318, 80),
        (0x31a, 128),
        (0x31a, 192),
        (0x31b, 128),
        (0x31b, 192),
    ]
    .into();
    if m.doorbells != want_doorbells
        || m.reg(v(0, JPEG_PITCH)) != 0xabad_cafe
        || m.reg(v(0, JRBC_RB_CNTL)) != 2
        || m.reg(v(0, JRBC_RB_SIZE)) != 1024
        || m.reg(v(0, JPEG_POWER_STATUS)) != 0
        || m.reg(v(0, JPEG_CGC_CTRL)) != 0x83
        || m.reg(v(0, JPEG_DEC_GFX10_ADDR_CONFIG)) != GB_ADDR
        || m.reg(v(0, JPEG_SYS_INT_EN)) != 2
    {
        return TestResult::Fail("doorbell sequence or JPEG programming");
    }
    let proof = e.proof;
    if proof.booted != [1, 1]
        || proof.dec_ring != [true; 2]
        || proof.enc_ring != [[true; 2]; 2]
        || proof.dec_ib != [2, 2]
        || proof.enc_ib != [[2, 2]; 2]
        || !proof.jpeg_ring
        || e.jpeg_state != JpegState::Verified
    {
        return TestResult::Fail("VCN proof");
    }
    let count = e.hw.io.writes.len();
    if run(e.start(firmware(3), None)) != Err(Error::Busy)
        || run(e.start_jpeg()) != Err(Error::Busy)
        || run(e.test_ib()) != Err(Error::Busy)
        || e.hw.io.writes.len() != count
    {
        return TestResult::Fail("VCN bring-up replayed");
    }
    drop(e);
    if pool.available() != (4 << 20) - owned(3) {
        return TestResult::Fail("live VCN memory recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_starts_both_instances_with_ring_and_ib_tests
);

fn vcn_navi22_boot_retry_loop_is_bounded() -> TestResult {
    let mut model = Model::new();
    model.boot_failures = [0, 3];
    let (_pool, mut e) = engine(model, 3);
    if run(e.start(firmware(3), None)).is_err() || e.proof.booted != [1, 4] {
        return TestResult::Fail("VCPU reset retries not mirrored");
    }
    // CLK_EN under the inherited reset, then three Linux reset retries.
    let toggles =
        e.hw.io
            .writes
            .iter()
            .filter(|&&(a, value)| a == v(1, VCPU_CNTL) && value & VCPU_BLK_RST != 0)
            .count();
    if toggles != 4 {
        return TestResult::Fail("wrong VCPU reset count");
    }
    let mut model = Model::new();
    model.never_boot = [true, false];
    let (pool, mut e) = engine(model, 3);
    let start = narf_time::Deadline::after_ms(5000);
    if run(e.start(firmware(3), None)) != Err(Error::BootFailed(0))
        || e.state != State::Failed
        || start.expired()
        || e.hw.io.releases[0] != 11
        || !e.hw.io.doorbells.is_empty()
        || e.hw.io.writes.iter().any(|&(a, _)| a == v(1, PGFSM_CONFIG))
    {
        return TestResult::Fail("dead VCPU not bounded or later instance touched");
    }
    let count = e.hw.io.writes.len();
    if run(e.test_ib()) != Err(Error::Busy) || e.hw.io.writes.len() != count {
        return TestResult::Fail("failed VCN tested");
    }
    drop(e);
    if pool.available() != (4 << 20) - ((INSTANCE_BYTES + 4095) & !4095) {
        return TestResult::Fail("published VCPU memory recycled after boot failure");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_boot_retry_loop_is_bounded
);

fn vcn_navi22_refuses_missing_firmware_and_power_gating() -> TestResult {
    let gated = crate::amdgpu_smu_navi22::PowerStatus {
        allowed: 1 << 22,
        enabled: 1 << 22,
        gfx_min_mhz: 500,
        gfx_max_mhz: 2600,
    };
    for (images, power, want) in [
        (firmware(1), None, Error::Invalid),
        (firmware(3), Some(gated), Error::PowerGated),
    ] {
        let (_pool, mut e) = engine(Model::new(), 3);
        if run(e.start(images, power)) != Err(want)
            || !e.hw.io.writes.is_empty()
            || e.state != State::Failed
        {
            return TestResult::Fail("VCN started without firmware/power prerequisites");
        }
    }
    let ungated = crate::amdgpu_smu_navi22::PowerStatus {
        enabled: 0x3_0300_0002,
        ..gated
    };
    // VCN0 harvested: only instance 1 runs and JPEG does not exist.
    let (_pool, mut e) = engine(Model::new(), 2);
    if run(e.start(firmware(2), Some(ungated))).is_err()
        || run(e.test_ib()).is_err()
        || e.jpeg_state != JpegState::Absent
        || run(e.start_jpeg()) != Err(Error::Busy)
        || e.hw.io.writes.iter().any(|&(a, _)| a == v(0, PGFSM_CONFIG))
        || e.proof.dec_ib != [0, 2]
    {
        return TestResult::Fail("harvested VCN0 layout");
    }
    // CC_UVD_HARVESTING.UVD_DISABLE: JPEG early_init reports no block.
    let mut model = Model::new();
    model.regs.insert(v(0, CC_UVD_HARVESTING), CC_UVD_DISABLE);
    let (_pool, mut e) = engine(model, 1);
    if run(e.start_jpeg()).is_err()
        || e.jpeg_state != JpegState::Absent
        || !e.hw.io.writes.is_empty()
    {
        return TestResult::Fail("fused-off JPEG programmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_refuses_missing_firmware_and_power_gating
);

fn vcn_navi22_failures_are_terminal_and_bounded() -> TestResult {
    for case in 0..6 {
        let mut model = Model::new();
        let want = match case {
            0 => {
                model.pgfsm_stuck = true;
                Error::Timeout
            }
            1 => {
                model.stalled[0] = true;
                Error::Timeout
            }
            2 => {
                model.stalled[4] = true;
                Error::Timeout
            }
            3 => {
                model.drop_fences = true;
                Error::Timeout
            }
            4 => {
                // NBIF aperture closed: refused before the VCPU BO is touched.
                model
                    .regs
                    .insert(NBIO + u64::from(NBIO_DOORBELL_APER_EN) * 4, 0);
                Error::Invalid
            }
            _ => {
                model.stalled[6] = true;
                Error::Timeout
            }
        };
        let (_pool, mut e) = engine(model, 3);
        let result = match run(e.start(firmware(3), None)) {
            Err(error) => Err(error),
            Ok(()) if case == 5 => run(e.start_jpeg()),
            Ok(()) => run(e.test_ib()),
        };
        let failed = if case == 5 {
            e.jpeg_state == JpegState::Failed
        } else {
            e.state == State::Failed
        };
        if result != Err(want) || !failed {
            return TestResult::Fail("VCN failure not terminal");
        }
        if case == 2 && (e.proof.dec_ring != [true, true] || e.proof.enc_ring[1] != [false; 2]) {
            return TestResult::Fail("VCN1 encode stall misattributed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_failures_are_terminal_and_bounded
);

fn vcn_navi22_cancellation_revocation_and_device_loss() -> TestResult {
    // Cancel inside the boot loop of instance 1.
    let mut model = Model::new();
    model.never_boot = [false, true];
    let progress = model.progress.clone();
    let (pool, mut e) = engine(model, 3);
    // Instance 0: CLK_EN, BLK_RST release (2), then instance 1's two.
    if !cancel_at(e.start(firmware(3), None), &progress, 4) {
        return TestResult::Fail("VCN1 boot not reached");
    }
    let count = e.hw.io.writes.len();
    if e.state != State::Starting(1)
        || run(e.start(firmware(3), None)) != Err(Error::Busy)
        || run(e.test_ib()) != Err(Error::Busy)
        || e.hw.io.writes.len() != count
    {
        return TestResult::Fail("cancelled VCN start replayed");
    }
    drop(e);
    if pool.available() != (4 << 20) - 2 * ((INSTANCE_BYTES + 4095) & !4095) {
        return TestResult::Fail("cancelled VCN memory recycled");
    }
    // Authority revoked by the write that releases VCPU reset.
    let mut model = Model::new();
    let authority: Cap<BusDeviceCap, Write> = Cap::bootstrap();
    model.revoke = Some((v(0, VCPU_CNTL), VCPU_CLK_EN, authority));
    let (_pool, mut e) = engine(model, 3);
    e.hw.authority = authority;
    let count = |e: &Engine<Model>| e.hw.io.writes.len();
    let result = run(e.start(firmware(3), None));
    let after = count(&e);
    if result != Err(Error::Revoked) || e.state != State::Failed {
        return TestResult::Fail("revoked VCN authority not reported");
    }
    if run(e.start(firmware(3), None)) != Err(Error::Busy) || count(&e) != after {
        return TestResult::Fail("revoked VCN retried");
    }
    // Surprise removal after a successful start.
    let (_pool, mut e) = engine(Model::new(), 3);
    run(e.start(firmware(3), None)).unwrap();
    e.hw.io.gone = true;
    if run(e.test_ib()) != Err(Error::DeviceGone) || e.state != State::Failed {
        return TestResult::Fail("VCN device loss not reported");
    }
    let mut model = Model::new();
    model.gone = true;
    let (_pool, mut e) = engine(model, 1);
    if run(e.start(firmware(1), None)) != Err(Error::DeviceGone)
        || e.hw.io.writes.iter().any(|&(a, _)| a == v(0, PGFSM_CONFIG))
    {
        return TestResult::Fail("removed VCN programmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_cancellation_revocation_and_device_loss
);

fn vcn_navi22_stop_quiesces_without_power_gating() -> TestResult {
    let (_pool, mut e) = engine(Model::new(), 3);
    if run(e.stop()) != Err(Error::Busy) || !e.hw.io.writes.is_empty() {
        return TestResult::Fail("unstarted VCN stopped");
    }
    run(e.start(firmware(3), None)).unwrap();
    run(e.start_jpeg()).unwrap();
    run(e.test_ib()).unwrap();
    if run(e.stop()).is_err() || e.state != State::Stopped || e.jpeg_state != JpegState::Stopped {
        return TestResult::Fail("VCN stop failed");
    }
    let m = &e.hw.io;
    for i in [0, 1] {
        for (reg, value) in [
            (STATUS, 0),
            (VCPU_CNTL, VCPU_BLK_RST),
            (RB_ARB_CTRL, RB_ARB_VCPU_DIS),
            (LMI_CTRL2, LMI_CTRL2_STALL_ARB_UMC),
            (SOFT_RESET, SOFT_RESET_LMI | SOFT_RESET_LMI_UMC),
            (CGC_CTRL, 0x105 | CGC_CTRL_MODES),
            (SUVD_CGC_CTRL, SUVD_CGC_CTRL_MODES),
            // JPEG's UVDJ power-up is the last PGFSM command on instance 0.
            (
                PGFSM_CONFIG,
                if i == 0 { PGFSM_UVDJ_ON } else { PGFSM_ALL_ON },
            ),
        ] {
            if m.reg(v(i, reg)) != value {
                return TestResult::Fail("VCN stop register sequence");
            }
        }
    }
    if m.reg(v(0, JMI_CNTL)) != 1
        || m.reg(v(0, JPEG_CGC_GATE)) != 0x1f
        || m.reg(v(0, JPEG_POWER_STATUS)) != 1
        || m.writes
            .iter()
            .filter(|&&(a, _)| a == v(0, PGFSM_CONFIG))
            .count()
            != 2
    {
        return TestResult::Fail("JPEG stop or power gating re-enabled");
    }
    // A busy VCPU never reaches idle: the stop wait is bounded.
    let (_pool, mut e) = engine(Model::new(), 1);
    run(e.start(firmware(1), None)).unwrap();
    e.hw.io.regs.insert(v(0, STATUS), 0x5);
    if run(e.stop()) != Err(Error::Timeout) || e.state != State::Failed {
        return TestResult::Fail("busy VCN stop unbounded");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_stop_quiesces_without_power_gating
);

fn vcn_navi22_routes_traps_to_instance_fences() -> TestResult {
    use crate::amdgpu_ih_navi22::{source, Iv};
    let iv = |from: crate::amdgpu_ih_navi22::Source| Iv {
        client: from.client,
        src: from.src,
        ring_id: 0,
        vmid: 0,
        vmid_src: false,
        timestamp: 0,
        timestamp_src: false,
        pasid: 0,
        node_id: 0,
        src_data: [0; 4],
    };
    if fence_engine(&iv(source::VCN0_DEC)) != Some(fence::Engine::Vcn0)
        || fence_engine(&iv(source::VCN0_ENC[1])) != Some(fence::Engine::Vcn0)
        || fence_engine(&iv(source::VCN1_ENC[0])) != Some(fence::Engine::Vcn1)
        || fence_engine(&iv(source::JPEG_DEC)) != Some(fence::Engine::Jpeg)
        || fence_engine(&iv(source::SDMA0_TRAP)).is_some()
        || source::VCN0_DEC.client != 0x10
        || source::VCN1_DEC.client != 0x0e
    {
        return TestResult::Fail("VCN trap decode");
    }
    let mut status = Status {
        state: State::Verified,
        jpeg: JpegState::Absent,
        proof: Proof::default(),
    };
    status.proof.dec_ring = [false, true];
    let sources = interrupt_sources(status);
    if sources != [source::VCN1_DEC, source::VCN1_ENC[0], source::VCN1_ENC[1]] {
        return TestResult::Fail("VCN interrupt sources for harvested VCN0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_routes_traps_to_instance_fences
);

/// Client jobs on the verified media rings (instance 0, VCN1 harvested as on
/// the RX 6750 XT): each frame is `encode_media`'s Linux order under the
/// user VMID, committed with an HDP flush before the doorbell, continuing the
/// kernel fence sequence; the VM flushes once per generation; a third job
/// waits for the first (`amdgpu_sched_hw_submission`); JPEG runs from a
/// kernel copy at VMID 0.
fn vcn_navi22_client_jobs_frame_flush_and_throttle() -> TestResult {
    use crate::amdgpu_navi22_submit::{encode_media, Ib, MediaFrame, MediaRing, VmRef};
    let (pool, mut e) = engine(Model::new(), 1);
    if run(e.start(firmware(1), None)).is_err()
        || run(e.start_jpeg()).is_err()
        || run(e.test_ib()).is_err()
    {
        return TestResult::Fail("media bring-up");
    }
    // The model executes kernel frames only; client frames are recorded.
    e.hw.io.stalled = [true; 7];
    let mut jpeg_ibs = pool.reserve(JPEG_IB_SLOT * 2).unwrap();
    jpeg_ibs.publish();
    let client = Client {
        mmhub: 0x1a000,
        oss: 0x10a0,
        instances: 1,
        jpeg_ibs: Some(jpeg_ibs),
    };
    // The MMHUB grant: flush (and remap the PASID) or reuse.
    let vm = |flush| VmRef {
        vmid: 3,
        page_table_base: 0x1_2345_6001,
        pasid: 0x42,
        flush,
        map_pasid: flush,
    };
    let ibs = [Ib {
        va: 0x7000_0010_0000,
        dwords: 16,
    }];
    let (base, map, seq0) = {
        let i = e.vcn[0].as_ref().unwrap();
        (i.address(0), i.memory.mapping(), i.dec.seq)
    };
    let mut frames = Vec::new();
    for flush in [true, false] {
        let from = e.vcn[0].as_ref().unwrap().dec.wptr;
        let Ok(seq) = e.submit_client(&client, MediaRing::Dec, vm(flush), &ibs, &[]) else {
            return TestResult::Fail("decode client job refused");
        };
        let to = e.vcn[0].as_ref().unwrap().dec.wptr;
        frames.push((seq, e.hw.io.ring(mc(map, DEC_RING), from, to), to));
    }
    for (k, (seq, words, to)) in frames.iter().enumerate() {
        let want = encode_media(&MediaFrame {
            ring: MediaRing::Dec,
            mmhub: 0x1a000,
            engine: 0,
            flush: (k == 0).then_some(vm(true)),
            pasid_map: (k == 0).then_some((0x10a0 + 0x10 + 3, 0x42)),
            vmid: 3,
            ibs: &ibs,
            fence: base + FENCE[0],
            seq: *seq,
            ring_base: base + DEC_RING,
        });
        let pad = &words[want.len().min(words.len())..];
        if *seq != seq0 + 1 + k as u32
            || words[..want.len().min(words.len())] != want[..]
            || to % 16 != 0
            || pad
                .chunks(2)
                .any(|p| p != [cmd::packet0(cmd::INTERNAL_NOP), 0])
        {
            return TestResult::Fail("decode client frame/sequence");
        }
    }
    let m = &e.hw.io;
    let last = frames[1].2;
    if m.doorbells.last() != Some(&(doorbell::dec(0), last)) || m.word(mc(map, WPTR[0])) != last {
        return TestResult::Fail("decode commit: shadow wptr and doorbell");
    }
    // Two outstanding: the third waits for the first fence.
    let third = e.submit_client(&client, MediaRing::Dec, vm(true), &ibs, &[]);
    if third != Err(Error::Busy) || e.vcn[0].as_ref().unwrap().dec.seq != seq0 + 2 {
        return TestResult::Fail("third outstanding decode job not throttled");
    }
    e.hw.io.put(mc(map, FENCE[0]), seq0 + 1);
    let from = e.vcn[0].as_ref().unwrap().dec.wptr;
    if e.submit_client(&client, MediaRing::Dec, vm(true), &ibs, &[]) != Ok(seq0 + 3) {
        return TestResult::Fail("decode job after the throttle fence");
    }
    let to = e.vcn[0].as_ref().unwrap().dec.wptr;
    // A flushing grant: insert_start then the semaphore wait.
    let words = e.hw.io.ring(mc(map, DEC_RING), from, to);
    if words.get(4..6) != Some(&[cmd::packet0(cmd::INTERNAL_DATA0), (0x1a000 + 0x6d1) << 2][..]) {
        return TestResult::Fail("new VM generation not flushed");
    }
    // Encode ring 0: MMHUB engine 1, frame starts with the semaphore wait.
    let enc_from = e.vcn[0].as_ref().unwrap().enc[0].wptr;
    if e.submit_client(&client, MediaRing::Enc(0), vm(true), &ibs, &[])
        .is_err()
    {
        return TestResult::Fail("encode client job refused");
    }
    let enc_to = e.vcn[0].as_ref().unwrap().enc[0].wptr;
    let words = e.hw.io.ring(mc(map, ENC_RING[0]), enc_from, enc_to);
    if words.get(..4) != Some(&[0xc, (0x1a000 + 0x6d1 + 1) << 2, 1, 1][..]) || enc_to % 64 != 0 {
        return TestResult::Fail("encode client frame");
    }
    // JPEG: the copy lands in slot seq % 2 and the frame fetches it at VMID 0.
    let copy = alloc::vec![0x6000_0000, 0, 0x4000, 7];
    let user = [Ib {
        va: 0x7000_0030_0000,
        dwords: 4,
    }];
    let (jbase, jmap, jfrom) = {
        let j = e.jpeg.as_ref().unwrap();
        (j.memory.address(), j.memory.mapping(), j.ring.wptr)
    };
    let mismatch = [alloc::vec![0x6000_0000, 0]];
    if e.submit_client(&client, MediaRing::Jpeg, vm(true), &user, &mismatch) != Err(Error::Invalid)
    {
        return TestResult::Fail("JPEG copy/IB mismatch accepted");
    }
    let Ok(seq) = e.submit_client(
        &client,
        MediaRing::Jpeg,
        vm(true),
        &user,
        core::slice::from_ref(&copy),
    ) else {
        return TestResult::Fail("JPEG client job refused");
    };
    let pool_ibs = client.jpeg_ibs.as_ref().unwrap();
    let at = u64::from(seq % 2) * JPEG_IB_SLOT;
    let jto = e.jpeg.as_ref().unwrap().ring.wptr;
    let words = e.hw.io.ring(mc(jmap, 0), jfrom, jto);
    let stored: Vec<u32> = (0..4)
        .map(|k| e.hw.io.word(mc(pool_ibs.mapping(), at + k * 4)))
        .collect();
    let (ib_low, ib_high) = (
        (pool_ibs.address() + at) as u32,
        ((pool_ibs.address() + at) >> 32) as u32,
    );
    // Frame: start(4) + flush + start(4), then the IB packet group.
    let ib_group = words
        .iter()
        .position(|&w| w == 0x4149)
        .map(|p| &words[p..p + 12]);
    if seq != 1
        || stored != copy
        || ib_group
            != Some(
                &[
                    0x4149,
                    3 << 3,
                    0x40cf,
                    0,
                    0x40d1,
                    0x333,
                    0x40e8,
                    ib_low,
                    0x40e9,
                    ib_high,
                    0x4082,
                    4,
                ][..],
            )
        || !words.contains(&((jbase + JPEG_FENCE) as u32))
    {
        return TestResult::Fail("JPEG client frame / kernel copy");
    }
    // A JPEG job beyond the kernel slot is refused before any ring write.
    let huge = [Ib {
        va: 0x7000_0030_0000,
        dwords: (JPEG_IB_SLOT / 4 + 2) as u32,
    }];
    let big = [alloc::vec![0u32; huge[0].dwords as usize]];
    if e.submit_client(&client, MediaRing::Jpeg, vm(true), &huge, &big) != Err(Error::Invalid)
        || e.jpeg.as_ref().unwrap().ring.wptr != jto
    {
        return TestResult::Fail("oversize JPEG job reached the ring");
    }
    // Kernel-VMID and empty jobs never reach validation's far side.
    if e.submit_client(
        &client,
        MediaRing::Dec,
        VmRef {
            vmid: 0,
            ..vm(true)
        },
        &ibs,
        &[],
    ) != Err(Error::Invalid)
        || e.submit_client(&client, MediaRing::Dec, vm(true), &[], &[]) != Err(Error::Invalid)
    {
        return TestResult::Fail("VMID 0 or empty media job accepted");
    }
    // All-ones is a valid sequence on every media fence. JPEG retains zero
    // at wrap so its two seq % 2 IB slots continue alternating.
    for ring in [
        MediaRing::Dec,
        MediaRing::Enc(0),
        MediaRing::Enc(1),
        MediaRing::Jpeg,
    ] {
        let (_, map, _, at) = e.client_ring(ring).unwrap();
        e.hw.io.put(mc(map, at), u32::MAX);
        if e.client_fences(ring).map(|f| f.0) != Ok(u32::MAX) {
            return TestResult::Fail("media all-ones fence mistaken for device loss");
        }
    }
    e.jpeg.as_mut().unwrap().ring.seq = u32::MAX;
    let copied = alloc::vec![0x6000_0000, 0, 0x4000, 7];
    if e.submit_client(&client, MediaRing::Jpeg, vm(true), &user, &[copied]) != Ok(0) {
        return TestResult::Fail("JPEG wrap lost alternating kernel IB slots");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_client_jobs_frame_flush_and_throttle
);
