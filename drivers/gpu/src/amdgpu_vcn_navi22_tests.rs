//! Register/memory model of two VCN 3.0 instances and JPEG 3.0. The model
//! boots a VCPU only for the programmed TMR window with every tile powered
//! and its reset released, decodes the public VCN decode (PACKET0 to the
//! internal command registers), encode and JRBC ring ABIs independently of
//! the encoders, and executes work only after an HDP flush, inside an open
//! NBIF aperture and the MMSCH doorbell range of the right instance.
use super::*;
use alloc::{collections::BTreeMap, rc::Rc, sync::Arc, vec::Vec};
use core::{
    cell::RefCell,
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
    status_requires_power: bool,
    /// Rings that ignore doorbells: dec0, enc0.0, enc0.1, dec1, enc1.0, enc1.1, jpeg.
    stalled: [bool; 7],
    drop_fences: bool,
    gone: bool,
    gone_on_vcpu: bool,
    work: Vec<Work>,
    traps: u32,
    rptr: [u32; 7],
    /// Decoder internal registers per instance: data0, data1, ctx, ib lo/hi.
    internal: [[u32; 5]; 2],
    progress: Arc<AtomicU32>,
    revoke: Option<(u64, u32, Cap<BusDeviceCap, Write>)>,
    /// DPG register lists PSP wrote into each instance's SRAM.
    sram: Rc<RefCell<BTreeMap<usize, Vec<u32>>>>,
    /// DPG_PAUSE requests that are never acknowledged.
    pause_stuck: bool,
}
fn mc(map: MmioRegion, offset: u64) -> u64 {
    map.phys.raw() - PHYS + MC + offset
}
impl Model {
    fn new() -> Self {
        let mut regs = BTreeMap::new();
        regs.insert(NBIO + u64::from(NBIO_DOORBELL_APER_EN) * 4, 1);
        regs.insert(NBIO + u64::from(NBIO_CONFIG_MEMSIZE) * 4, 12288);
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
            status_requires_power: false,
            stalled: [false; 7],
            drop_fences: false,
            gone: false,
            gone_on_vcpu: false,
            work: Vec::new(),
            traps: 0,
            rptr: [0; 7],
            internal: [[0; 5]; 2],
            progress: Arc::new(AtomicU32::new(0)),
            revoke: None,
            sram: Rc::new(RefCell::new(BTreeMap::new())),
            pause_stuck: false,
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
        if self.dpg(i) {
            return self.dpg_booted(i);
        }
        self.reg(v(i, STATUS)) & VCPU_REPORT_BOOTED != 0
    }
    fn dpg(&self, i: usize) -> bool {
        self.reg(v(i, POWER_STATUS)) & POWER_PG_MODE != 0
    }
    fn paused(&self, i: usize) -> bool {
        self.reg(v(i, DPG_PAUSE)) & DPG_PAUSE_ACK != 0
    }
    /// The last value the SRAM list gives `r`, by the VCN-internal offset
    /// Linux's SOC15_DPG_MODE_OFFSET yields for a BASE_IDX 1 register of
    /// either instance: video registers from 0x80, always-on below.
    fn dpg_reg(&self, i: usize, r: Reg) -> Option<u32> {
        assert_eq!(r.0, 1);
        let internal = if r.1 >= 0x80 {
            r.1 - 0x80
        } else {
            0xc000 + r.1
        };
        let lists = self.sram.borrow();
        let words = lists.get(&i)?;
        words
            .chunks_exact(2)
            .rev()
            .find(|pair| pair[0] == internal)
            .map(|pair| pair[1])
    }
    fn dpg_shared(&self, i: usize) -> u64 {
        let low = self.dpg_reg(i, LMI_VCPU_NC0_BAR_LOW).unwrap_or(0);
        let high = self.dpg_reg(i, LMI_VCPU_NC0_BAR_HIGH).unwrap_or(0);
        u64::from(low) | (u64::from(high) << 32)
    }
    /// A DPG VCPU runs once PSP holds a released, clocked VCPU with the
    /// firmware and stack windows left to PSP and the context and fw_shared
    /// windows in VRAM, and dynamic power gating is on.
    fn dpg_booted(&self, i: usize) -> bool {
        let r = |reg| self.dpg_reg(i, reg);
        let power = POWER_PG_MODE | POWER_PG_EN;
        !self.never_boot[i]
            && self.reg(v(i, POWER_STATUS)) & power == power
            && r(VCPU_CNTL) == Some(VCPU_CNTL_DPG)
            && [
                LMI_VCPU_CACHE_BAR_LOW,
                LMI_VCPU_CACHE_BAR_HIGH,
                VCPU_CACHE_SIZE0,
                LMI_VCPU_CACHE1_BAR_LOW,
            ]
            .iter()
            .all(|&reg| r(reg) == Some(0))
            && r(VCPU_CACHE_SIZE1) == Some(STACK_SIZE)
            && r(VCPU_CACHE_SIZE2) == Some(CONTEXT_SIZE)
            && r(LMI_VCPU_CACHE2_BAR_LOW).is_some_and(|a| a != 0 && a % 4096 == 0)
            && self.dpg_shared(i) % 4096 == 0
            && self.dpg_shared(i) != 0
            && r(VCPU_NONCACHE_SIZE0) == Some(SHARED_SIZE)
            && r(GFX10_ADDR_CONFIG) == Some(GB_ADDR)
            && r(RB_ARB_CTRL) == Some(0)
            && r(LMI_CTRL2) == Some(0)
            && r(MASTINT_EN) == Some(MASTINT_VCPU_EN)
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
                self.regs.insert(v(i, RBC_RB_WPTR), value);
                if !self.booted(i) || self.stalled[slot] {
                    return;
                }
                if self.dpg(i) {
                    assert_eq!(self.reg(v(i, SCRATCH2)), value, "DPG wptr in SCRATCH2");
                    let shared = self.dpg_shared(i);
                    assert_eq!(
                        self.word(shared + shared::RB_WPTR),
                        value,
                        "fw_shared rb.wptr"
                    );
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
                self.regs.insert(v(i, RB_WPTR[j]), value);
                // DPG keeps no encode ring state outside a pause.
                if !self.booted(i) || self.stalled[slot] || (self.dpg(i) && !self.paused(i)) {
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
        if self.gone_on_vcpu && (0..2).any(|i| address == v(i, VCPU_CNTL)) {
            self.gone = true;
        }
        if self.gone {
            return u32::MAX;
        }
        for i in [0, 1] {
            let power = self.reg(v(i, POWER_STATUS));
            if address == v(i, POWER_STATUS) && power & POWER_PG_MODE != 0 {
                // Powered up (2) while paused and not stalled, else 1.
                let up = self.paused(i) && power & POWER_STALL_DPG == 0;
                return (power & !POWER_STATUS_MASK) | if up { 2 } else { 1 };
            }
        }
        if self.status_requires_power
            && (0..2).any(|i| {
                address == v(i, STATUS) && self.reg(v(i, PGFSM_STATUS)) & PGFSM_STATUS_MASK != 0
            })
        {
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
            if address == v(i, DPG_PAUSE) {
                let ack = value & DPG_PAUSE_REQ != 0 && !self.pause_stuck;
                let value = (value & !DPG_PAUSE_ACK) | if ack { DPG_PAUSE_ACK } else { 0 };
                self.regs.insert(address, value);
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

/// PSP writing DPG register lists into the model's SRAM.
struct FakePsp {
    sram: Rc<RefCell<BTreeMap<usize, Vec<u32>>>>,
    loads: Vec<usize>,
    refuse: bool,
}
impl FakePsp {
    fn new(model: &Model) -> Self {
        Self {
            sram: model.sram.clone(),
            loads: Vec::new(),
            refuse: false,
        }
    }
}
impl SramLoader for FakePsp {
    async fn load_sram(&mut self, instance: usize, words: &[u32]) -> Result<(), Error> {
        self.loads.push(instance);
        if self.refuse {
            return Err(Error::Sram(crate::amdgpu_psp_ring::Error::Rejected(0xa)));
        }
        assert!(words.len() <= DPG_SRAM_DW && words.len() % 2 == 0);
        self.sram.borrow_mut().insert(instance, words.to_vec());
        Ok(())
    }
}
/// The static path never asks PSP for a DPG register list.
struct NoSram;
impl SramLoader for NoSram {
    async fn load_sram(&mut self, _: usize, _: &[u32]) -> Result<(), Error> {
        panic!("static start loaded a DPG register list")
    }
}
fn engine(model: Model, instances: u8) -> (Pool, Engine<Model>) {
    let pool = pool(4 << 20);
    let vcn = [0, 1].map(|i| (instances & (1 << i) != 0).then(|| Instance::new(&pool, i).unwrap()));
    let jpeg = (instances & 1 != 0).then(|| Jpeg::new(&pool).unwrap());
    (
        pool,
        Engine {
            runtime: idle::Runtime::new(),
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
            mode: StartMode::Static,
            paused: [false; 2],
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
    if run(e.start(firmware(1), None, &mut NoSram)).is_err()
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

fn vcn_navi22_powers_tiles_before_reading_vcpu_status() -> TestResult {
    let mut model = Model::new();
    model.status_requires_power = true;
    let (_pool, mut e) = engine(model, 3);
    if run(e.start(firmware(3), None, &mut NoSram)).is_err() || e.state != State::Running {
        return TestResult::Fail("gated UVD_STATUS mistaken for device removal");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_powers_tiles_before_reading_vcpu_status
);

fn vcn_navi22_all_ones_vcpu_control_preserves_linux_masked_updates() -> TestResult {
    let mut model = Model::new();
    for i in [0, 1] {
        model.regs.insert(v(i, VCPU_CNTL), u32::MAX);
    }
    let (_pool, mut e) = engine(model, 3);
    if run(e.start(firmware(3), None, &mut NoSram)).is_err() || e.state != State::Running {
        return TestResult::Fail("all-ones VCPU control rejected on a live GPU");
    }
    for i in [0, 1] {
        let writes: Vec<_> =
            e.hw.io
                .writes
                .iter()
                .filter(|&&(a, _)| a == v(i, VCPU_CNTL))
                .collect();
        // WREG32_P(VCPU_CNTL, CLK_EN, ~CLK_EN), then clear BLK_RST.
        if writes.len() != 2
            || writes[0].1 != u32::MAX
            || writes[1].1 != u32::MAX & !VCPU_BLK_RST
            || e.proof.booted[i] != 1
            || !e.proof.dec_ring[i]
            || !e.proof.enc_ring[i].iter().all(|tested| *tested)
        {
            return TestResult::Fail(
                "VCPU masked writes changed unrelated bits or skipped ring tests",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_all_ones_vcpu_control_preserves_linux_masked_updates
);

fn vcn_navi22_all_ones_vcpu_control_checks_independent_device_presence() -> TestResult {
    let mut model = Model::new();
    model.gone_on_vcpu = true;
    let (_pool, mut e) = engine(model, 1);
    if run(e.start(firmware(1), None, &mut NoSram)) != Err(Error::DeviceGone)
        || e.state != State::Failed
        || e.hw.io.writes.iter().any(|&(a, _)| a == v(0, VCPU_CNTL))
    {
        return TestResult::Fail(
            "VCPU control written after independent banks reported device loss",
        );
    }
    // A gated GC bank is not evidence of removal. Linux's working GPU
    // returned all ones for both GB_ADDR_CONFIG and UVD_VCPU_CNTL.
    let mut model = Model::new();
    model
        .regs
        .insert(GC + u64::from(GB_ADDR_CONFIG) * 4, u32::MAX);
    model.regs.insert(v(0, VCPU_CNTL), u32::MAX);
    if update_vcpu(&mut model, layout(1), 0, VCPU_CLK_EN, VCPU_CLK_EN).is_err()
        || model.writes != [(v(0, VCPU_CNTL), u32::MAX)]
    {
        return TestResult::Fail("gated GC mistaken for removal during VCPU masked update");
    }
    // A live memory-size register is insufficient when the aperture is absent or closed.
    for aperture in [0, u32::MAX] {
        let mut model = Model::new();
        model.regs.insert(v(0, VCPU_CNTL), u32::MAX);
        model
            .regs
            .insert(layout(1).nbio(NBIO_DOORBELL_APER_EN), aperture);
        let want = if aperture == 0 {
            Error::Invalid
        } else {
            Error::DeviceGone
        };
        if update_vcpu(&mut model, layout(1), 0, VCPU_CLK_EN, VCPU_CLK_EN) != Err(want)
            || !model.writes.is_empty()
        {
            return TestResult::Fail("VCPU control written without a live NBIO aperture");
        }
    }
    for size in [0, u32::MAX] {
        let mut model = Model::new();
        model.regs.insert(v(0, VCPU_CNTL), u32::MAX);
        model.regs.insert(layout(1).nbio(NBIO_CONFIG_MEMSIZE), size);
        let want = if size == 0 {
            Error::Invalid
        } else {
            Error::DeviceGone
        };
        if update_vcpu(&mut model, layout(1), 0, VCPU_CLK_EN, VCPU_CLK_EN) != Err(want)
            || !model.writes.is_empty()
        {
            return TestResult::Fail("VCPU control written without NBIO memory-size presence");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_all_ones_vcpu_control_checks_independent_device_presence
);

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
    if run(e.start(firmware(3), None, &mut NoSram)).is_err() || e.state != State::Running {
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
    if run(e.start(firmware(3), None, &mut NoSram)) != Err(Error::Busy)
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
    if run(e.start(firmware(3), None, &mut NoSram)).is_err() || e.proof.booted != [1, 4] {
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
    if run(e.start(firmware(3), None, &mut NoSram)) != Err(Error::BootFailed(0))
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
        if run(e.start(images, power, &mut NoSram)) != Err(want)
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
    if run(e.start(firmware(2), Some(ungated), &mut NoSram)).is_err()
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
        let result = match run(e.start(firmware(3), None, &mut NoSram)) {
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
    if !cancel_at(e.start(firmware(3), None, &mut NoSram), &progress, 4) {
        return TestResult::Fail("VCN1 boot not reached");
    }
    let count = e.hw.io.writes.len();
    if e.state != State::Starting(1)
        || run(e.start(firmware(3), None, &mut NoSram)) != Err(Error::Busy)
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
    let result = run(e.start(firmware(3), None, &mut NoSram));
    let after = count(&e);
    if result != Err(Error::Revoked) || e.state != State::Failed {
        return TestResult::Fail("revoked VCN authority not reported");
    }
    if run(e.start(firmware(3), None, &mut NoSram)) != Err(Error::Busy) || count(&e) != after {
        return TestResult::Fail("revoked VCN retried");
    }
    // Surprise removal after a successful start.
    let (_pool, mut e) = engine(Model::new(), 3);
    run(e.start(firmware(3), None, &mut NoSram)).unwrap();
    e.hw.io.gone = true;
    if run(e.test_ib()) != Err(Error::DeviceGone) || e.state != State::Failed {
        return TestResult::Fail("VCN device loss not reported");
    }
    let mut model = Model::new();
    model.gone = true;
    let (_pool, mut e) = engine(model, 1);
    if run(e.start(firmware(1), None, &mut NoSram)) != Err(Error::DeviceGone)
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
    run(e.start(firmware(3), None, &mut NoSram)).unwrap();
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
    run(e.start(firmware(1), None, &mut NoSram)).unwrap();
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
    if run(e.start(firmware(1), None, &mut NoSram)).is_err()
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

fn dpg_engine(instances: u8) -> (Pool, Engine<Model>, FakePsp) {
    let model = Model::new();
    let psp = FakePsp::new(&model);
    let (pool, mut e) = engine(model, instances);
    e.mode = StartMode::Dpg;
    (pool, e, psp)
}

struct RuntimePm {
    psp: FakePsp,
    commands: Vec<([bool; 2], bool)>,
    gated: bool,
    stall: Option<bool>,
    fail: bool,
}
impl SramLoader for RuntimePm {
    async fn load_sram(&mut self, i: usize, words: &[u32]) -> Result<(), Error> {
        self.psp.load_sram(i, words).await
    }
}
impl idle::Control for RuntimePm {
    async fn power(&mut self, instances: [bool; 2], on: bool) -> Result<bool, Error> {
        self.commands.push((instances, on));
        if self.stall == Some(on) {
            core::future::pending::<()>().await;
        }
        if self.fail {
            return Err(Error::Power(crate::amdgpu_smu_navi22::Error::Rejected(
                0xfd,
            )));
        }
        Ok(self.gated)
    }
}
fn runtime_engine(mode: StartMode, gated: bool) -> (Pool, Engine<Model>, RuntimePm) {
    let (pool, mut e, psp) = dpg_engine(3);
    e.mode = mode;
    let mut pm = RuntimePm {
        psp,
        commands: Vec::new(),
        gated,
        stall: None,
        fail: false,
    };
    run(e.start(firmware(3), None, &mut pm)).unwrap();
    run(e.start_jpeg()).unwrap();
    run(e.test_ib()).unwrap();
    (pool, e, pm)
}
fn vcn3_idle_resume_preserves_context_fences_and_jpeg() -> TestResult {
    for mode in [StartMode::Dpg, StartMode::Static] {
        for gated in [false, true] {
            let (_pool, mut e, mut pm) = runtime_engine(mode, gated);
            let marker = e.vcn[0].as_ref().unwrap().address(SHARED + 0x80);
            e.hw.io.put(marker, 0x1234_5678);
            let before = e.vcn[0].as_ref().unwrap();
            let seq = [before.dec.seq, before.enc[0].seq, before.enc[1].seq];
            assert!(!run(e.idle(&mut pm, 0)).unwrap());
            assert!(!run(e.idle(&mut pm, 999_999_999)).unwrap());
            assert!(pm.commands.is_empty());
            assert!(run(e.idle(&mut pm, 1_000_000_000)).unwrap());
            assert_eq!(e.runtime.phase, idle::Phase::Asleep);
            assert_eq!(e.paused, [false; 2]);
            assert_eq!(e.jpeg_state, JpegState::Verified);
            assert_eq!(pm.commands, [([true, true], false)]);
            run(e.begin_use(&mut pm, MediaRing::Enc(0), 2_000_000_000)).unwrap();
            assert_eq!(e.runtime.phase, idle::Phase::Awake);
            assert_eq!(e.hw.io.word(marker), 0x1234_5678);
            let after = e.vcn[0].as_ref().unwrap();
            assert_eq!([after.dec.seq, after.enc[0].seq, after.enc[1].seq], seq);
            assert_eq!(pm.commands.len(), if gated { 2 } else { 1 });
            if gated {
                assert_eq!(pm.commands[1], ([true, true], true));
            }
            if mode == StartMode::Dpg {
                assert!(e.paused[0]);
            }
            run(e.test_enc_ib(0, 0)).unwrap();
            assert_ne!(e.vcn[0].as_ref().unwrap().enc[0].seq, seq[1]);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn3_idle_resume_preserves_context_fences_and_jpeg
);

fn vcn3_idle_uses_physical_fences_and_releases_only_idle_encode_pause() -> TestResult {
    let (_pool, mut e, mut pm) = runtime_engine(StartMode::Dpg, true);
    let inst = e.vcn[0].as_mut().unwrap();
    inst.enc[0].seq += 1;
    let enc_seq = inst.enc[0].seq;
    let enc_at = inst.address(FENCE[1]);
    assert!(!run(e.idle(&mut pm, 0)).unwrap());
    assert!(!run(e.idle(&mut pm, 1_000_000_000)).unwrap());
    assert!(e.paused[0] && pm.commands.is_empty());
    e.hw.io.put(enc_at, enc_seq);
    let inst = e.vcn[0].as_mut().unwrap();
    inst.dec.seq += 1;
    let dec_seq = inst.dec.seq;
    let dec_at = inst.address(FENCE[0]);
    assert!(!run(e.idle(&mut pm, 1_000_000_000)).unwrap());
    assert!(!e.paused[0] && pm.commands.is_empty());
    e.hw.io.put(dec_at, dec_seq);
    assert!(run(e.idle(&mut pm, 1_000_000_000)).unwrap());
    assert_eq!(pm.commands, [([true, true], false)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn3_idle_uses_physical_fences_and_releases_only_idle_encode_pause
);

fn vcn3_cancelled_idle_or_resume_never_replays_power_transitions() -> TestResult {
    for on in [false, true] {
        let (_pool, mut e, mut pm) = runtime_engine(StartMode::Dpg, true);
        run(e.idle(&mut pm, 0)).unwrap();
        if on {
            assert!(run(e.idle(&mut pm, 1_000_000_000)).unwrap());
        }
        pm.stall = Some(on);
        if on {
            let mut f = alloc::boxed::Box::pin(e.begin_use(&mut pm, MediaRing::Dec, 2_000_000_000));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        } else {
            let mut f = alloc::boxed::Box::pin(e.idle(&mut pm, 1_000_000_000));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        let writes = e.hw.io.writes.len();
        let commands = pm.commands.len();
        assert_eq!(run(e.stop()), Err(Error::DeviceGone));
        assert_eq!(
            run(e.begin_use(&mut pm, MediaRing::Dec, 3_000_000_000)),
            Err(Error::DeviceGone)
        );
        assert_eq!(e.state, State::Failed);
        assert_eq!(e.hw.io.writes.len(), writes);
        assert_eq!(pm.commands.len(), commands);
    }
    let (_pool, mut e, mut pm) = runtime_engine(StartMode::Dpg, true);
    run(e.idle(&mut pm, 0)).unwrap();
    pm.fail = true;
    assert!(run(e.idle(&mut pm, 1_000_000_000)).is_err());
    assert_eq!(e.state, State::Failed);
    // Hardware must be quiet before PMFW can cut power.
    let (_pool, mut e, mut pm) = runtime_engine(StartMode::Static, true);
    run(e.idle(&mut pm, 0)).unwrap();
    e.hw.io.regs.insert(v(0, STATUS), 0x5);
    assert_eq!(run(e.idle(&mut pm, 1_000_000_000)), Err(Error::Timeout));
    assert!(pm.commands.is_empty());
    assert_eq!(e.state, State::Failed);
    // A lost power feature or a rejected PSP restore cannot reopen clients.
    for lost_feature in [true, false] {
        let (_pool, mut e, mut pm) = runtime_engine(StartMode::Dpg, true);
        run(e.idle(&mut pm, 0)).unwrap();
        assert!(run(e.idle(&mut pm, 1_000_000_000)).unwrap());
        if lost_feature {
            pm.gated = false;
        } else {
            pm.psp.refuse = true;
        }
        assert!(run(e.begin_use(&mut pm, MediaRing::Dec, 2_000_000_000)).is_err());
        assert_eq!(e.state, State::Failed);
        assert_eq!(e.runtime.phase, idle::Phase::Failed);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn3_cancelled_idle_or_resume_never_replays_power_transitions
);
fn vcn_navi22_dpg_offsets_follow_soc15_dpg_mode_offset() -> TestResult {
    let l = layout(3);
    // Video registers of either instance share internal offsets from 0;
    // always-on registers (below 0x80) map into 0x30000 bytes.
    for i in [0, 1] {
        if dpg_offset(l.reg(i, VCPU_CNTL)) != 0xd6
            || dpg_offset(l.reg(i, CGC_CTRL)) != 0x0a
            || dpg_offset(l.reg(i, LMI_VCPU_CACHE_BAR_LOW)) != 0x3bc
            || dpg_offset(l.reg(i, GFX10_ADDR_CONFIG)) != 0xc04a
            || dpg_offset(l.reg(i, POWER_STATUS)) != 0xc004
        {
            return TestResult::Fail("DPG internal offset");
        }
    }
    // Outside every VCN range the SOC offset passes through.
    if dpg_offset(0x10_0000 + 0x40) != 0x10 {
        return TestResult::Fail("DPG offset outside VCN ranges");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_dpg_offsets_follow_soc15_dpg_mode_offset
);

fn vcn_navi22_dpg_start_programs_the_vcpu_through_psp() -> TestResult {
    let (_pool, mut e, mut psp) = dpg_engine(3);
    if run(e.start(firmware(3), None, &mut psp)).is_err() || e.state != State::Running {
        return TestResult::Fail("DPG start failed");
    }
    if psp.loads != [0, 1] || e.paused != [true, true] {
        return TestResult::Fail("one SRAM load and an encode pause per instance");
    }
    {
        let m = &e.hw.io;
        // PSP owns the VCPU and cache windows: no direct write, and no
        // static PGFSM power-up or VCPU boot poll.
        let direct = [
            VCPU_CNTL,
            LMI_VCPU_CACHE_BAR_LOW,
            VCPU_CACHE_SIZE0,
            LMI_VCPU_NC0_BAR_LOW,
            PGFSM_CONFIG,
            CGC_GATE,
        ];
        if m.writes
            .iter()
            .any(|&(a, _)| (0..2).any(|i| direct.iter().any(|&r| a == v(i, r))))
        {
            return TestResult::Fail("DPG start wrote a PSP-owned register directly");
        }
        for i in [0, 1] {
            let inst = e.vcn[i].as_ref().unwrap();
            let words = m.sram.borrow()[&i].clone();
            // Clock gating first, the PSP size-check NOP last; the VCPU is
            // held in reset until the list releases it.
            if words.len() != 70
                || words[..2] != [0x0a, CGC_CTRL_DYN]
                || words[8..10] != [0xd6, VCPU_CNTL_DPG | VCPU_BLK_RST]
                || words[64..66] != [0xd6, VCPU_CNTL_DPG]
                || words[68..] != [0xd6, VCPU_CNTL_DPG]
                || m.dpg_reg(i, LMI_CTRL) != Some(LMI_CTRL_DPG)
                || m.dpg_reg(i, LMI_VCPU_CACHE2_BAR_LOW) != Some(inst.address(CONTEXT) as u32)
                || m.dpg_shared(i) != inst.address(SHARED)
                || m.dpg_reg(i, REG_XX_MASK) != Some(0x10)
                || m.dpg_reg(i, RBC_XX_IB_REG_CHECK) != Some(3)
            {
                return TestResult::Fail("DPG register list");
            }
            let power = m.reg(v(i, POWER_STATUS));
            let shared = mc(inst.memory.mapping(), SHARED);
            if power & (POWER_PG_MODE | POWER_PG_EN | POWER_STALL_DPG)
                != POWER_PG_MODE | POWER_PG_EN
                || m.reg(v(i, RBC_RB_CNTL)) != RBC_RB_CNTL_IDLE
                || m.reg(v(i, LMI_RBC_RB_BAR_LOW)) != inst.address(DEC_RING) as u32
                || m.reg(v(i, RB_BASE_LO[1])) != inst.address(ENC_RING[1]) as u32
                || m.reg(v(i, RB_SIZE[0])) != RING_DW
                || m.reg(v(i, SCRATCH9)) != 0xdead_beef
                || m.word(shared + shared::QUEUE_MODES) != 0
                || m.word(shared + shared::RB_WPTR) != inst.dec.wptr
                || m.reg(v(i, SCRATCH2)) != inst.dec.wptr
            {
                return TestResult::Fail("DPG power, ring or fw_shared state");
            }
        }
    }
    if run(e.test_ib()).is_err() || e.state != State::Verified {
        return TestResult::Fail("DPG IB tests");
    }
    if e.proof.dec_ring != [true; 2] || e.proof.enc_ring != [[true; 2]; 2] {
        return TestResult::Fail("DPG ring proof");
    }
    if run(e.stop()).is_err() || e.state != State::Stopped || e.paused != [false; 2] {
        return TestResult::Fail("DPG stop failed");
    }
    for i in [0, 1] {
        let power = e.hw.io.reg(v(i, POWER_STATUS));
        if power & POWER_PG_MODE != 0 || e.hw.io.reg(v(i, DPG_PAUSE)) & DPG_PAUSE_REQ != 0 {
            return TestResult::Fail("DPG stop left dynamic power gating or the pause");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_dpg_start_programs_the_vcpu_through_psp
);

fn vcn_navi22_dpg_failures_are_terminal() -> TestResult {
    // PSP refuses the list: nothing reaches a ring.
    let (_pool, mut e, mut psp) = dpg_engine(1);
    psp.refuse = true;
    if run(e.start(firmware(1), None, &mut psp))
        != Err(Error::Sram(crate::amdgpu_psp_ring::Error::Rejected(0xa)))
        || e.state != State::Failed
        || !e.hw.io.doorbells.is_empty()
    {
        return TestResult::Fail("refused SRAM load");
    }
    // A VCPU that never runs fails the decode ring test, bounded.
    let (_pool, mut e, mut psp) = dpg_engine(1);
    e.hw.io.never_boot[0] = true;
    if run(e.start(firmware(1), None, &mut psp)) != Err(Error::Timeout)
        || e.state != State::Failed
        || e.paused[0]
    {
        return TestResult::Fail("DPG VCPU that never ran");
    }
    // An unacknowledged pause leaves the encode rings unprogrammed.
    let (_pool, mut e, mut psp) = dpg_engine(1);
    e.hw.io.pause_stuck = true;
    if run(e.start(firmware(1), None, &mut psp)) != Err(Error::Timeout)
        || e.state != State::Failed
        || !e.proof.dec_ring[0]
        || e.proof.enc_ring[0] != [false; 2]
        || e.hw.io.reg(v(0, RB_SIZE[0])) != 0
    {
        return TestResult::Fail("unacknowledged DPG pause");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_dpg_failures_are_terminal
);
