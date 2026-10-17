//! Register/memory model of GC 10.3 CP, MEC/KIQ and SDMA 5.2 shared by the
//! Navi22 queue owner tests, plus the GFX ring owner tests. The model decodes
//! the public PM4/SDMA packet ABIs independently of the encoders and only
//! executes work an engine could actually see: flushed memory, an enabled
//! doorbell aperture and range, an unhalted engine and a matching doorbell.
use super::*;
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    future::Future,
    sync::atomic::AtomicU32,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

pub(crate) const GC0: u64 = 0x1260 * 4;
pub(crate) const GC1: u64 = 0xa000 * 4;
pub(crate) const NBIO: u64 = 0xd20 * 4;
pub(crate) const HDP: u64 = 0xf20 * 4;
pub(crate) const MC: u64 = 0x8_0040_0000;
const PHYS: u64 = 0x9000_0000;
pub(crate) const BAR2: u64 = 0xf000_0000;

pub(crate) fn layout() -> Layout {
    Layout {
        gc: [GC0, GC1],
        nbio: NBIO,
        hdp: HDP,
    }
}
pub(crate) fn pool(len: u64) -> Pool {
    let map = MmioRegion {
        phys: narf_memory::PhysAddr::new(PHYS),
        virt: 0,
        len,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    };
    // SAFETY: the model performs every access; bookkeeping-only mapping.
    unsafe { Pool::from_owned_range(map, MC) }.unwrap()
}
pub(crate) fn doorbells() -> Doorbells {
    Doorbells::from_region(MmioRegion {
        phys: narf_memory::PhysAddr::new(BAR2),
        virt: 0,
        len: DOORBELL_BYTES,
        kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
    })
}
pub(crate) fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
pub(crate) fn r(reg: Reg) -> u64 {
    layout().reg(reg)
}
pub(crate) fn sdma(i: u32, reg: Reg) -> u64 {
    layout().sdma(i, reg)
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Mapped {
    pub me: u32,
    pub pipe: u32,
    pub queue: u32,
    pub doorbell: u32,
    pub mqd: u64,
    pub wptr: u64,
    pub rptr: u64,
}
pub(crate) struct Model {
    pub regs: BTreeMap<u64, u32>,
    pub writes: Vec<(u64, u32)>,
    pub mem: BTreeMap<u64, u32>,
    pub doorbells: Vec<(u32, u64)>,
    dirty: bool,
    stale: bool,
    /// Hardware already remaps the VGT/SPI UMD aliases.
    pub cam_remapped: bool,
    pub cam: Vec<u32>,
    /// Engines that ignore doorbells: 0 gfx, 1 KIQ, 2 compute, 3/4 SDMA.
    pub stalled: [bool; 5],
    pub drop_ib_writes: bool,
    pub drop_fences: bool,
    /// An active HQD that never acknowledges DEQUEUE_REQUEST.
    pub stuck_hqd: bool,
    pub context: BTreeMap<u32, u32>,
    pub clear_states: u32,
    pub resources: Vec<u64>,
    pub mapped: Vec<Mapped>,
    pub traps: u32,
    rptr: [u64; 5],
    pub progress: Arc<AtomicU32>,
    pub revoke: Option<(u64, u32, Cap<BusDeviceCap, Write>)>,
}
fn mc(map: MmioRegion, offset: u64) -> u64 {
    map.phys.raw() - PHYS + MC + offset
}
impl Model {
    pub(crate) fn new() -> Self {
        let mut regs = BTreeMap::new();
        regs.insert(r(RLC_RLCS_BOOTLOAD_STATUS), 1 << 31);
        regs.insert(r(CP_ME_CNTL), 0x1500_0000);
        regs.insert(r(CP_MEC_CNTL), 0x5000_0000);
        regs.insert(NBIO + 0x12d * 4, 0x7f000);
        for i in 0..2 {
            regs.insert(sdma(i, SDMA0_F32_CNTL), 1);
            regs.insert(sdma(i, SDMA0_UTCL1_PAGE), 0x000f_f000);
        }
        Self {
            regs,
            writes: Vec::new(),
            mem: BTreeMap::new(),
            doorbells: Vec::new(),
            dirty: false,
            stale: false,
            cam_remapped: false,
            cam: Vec::new(),
            stalled: [false; 5],
            drop_ib_writes: false,
            drop_fences: false,
            stuck_hqd: false,
            context: BTreeMap::new(),
            clear_states: 0,
            resources: Vec::new(),
            mapped: Vec::new(),
            traps: 0,
            rptr: [0; 5],
            progress: Arc::new(AtomicU32::new(0)),
            revoke: None,
        }
    }
    pub(crate) fn reg(&self, address: u64) -> u32 {
        *self.regs.get(&address).unwrap_or(&0)
    }
    /// HQD registers are banked by GRBM me/pipe/queue, SH_MEM by VMID.
    fn key(&self, address: u64) -> u64 {
        let select = u64::from(self.reg(r(GRBM_GFX_CNTL)));
        if (r(CP_MQD_BASE_ADDR)..=r(CP_HQD_PQ_WPTR_HI)).contains(&address) {
            address | ((select & 0x70f) << 40)
        } else if address == r(SH_MEM_CONFIG) || address == r(SH_MEM_BASES) {
            address | ((select & 0xf0) << 40)
        } else {
            address
        }
    }
    pub(crate) fn hqd(&self, me: u32, pipe: u32, queue: u32, reg: Reg) -> u32 {
        let select = u64::from(pipe | (me << 2) | (queue << 8));
        *self.regs.get(&(r(reg) | (select << 40))).unwrap_or(&0)
    }
    pub(crate) fn sh_mem(&self, vmid: u32, reg: Reg) -> u32 {
        *self
            .regs
            .get(&(r(reg) | (u64::from(vmid << 4) << 40)))
            .unwrap_or(&0)
    }
    pub(crate) fn word(&self, address: u64) -> u32 {
        *self.mem.get(&address).unwrap_or(&0)
    }
    fn put(&mut self, address: u64, value: u32) {
        assert_eq!(address % 4, 0);
        self.mem.insert(address, value);
        self.stale = true;
    }
    fn cam_target(&self, address: u64) -> u64 {
        let dword = (address / 4) as u32;
        if self.cam_remapped && address == r(VGT_ESGS_RING_SIZE_UMD) {
            return r(VGT_ESGS_RING_SIZE);
        }
        for entry in &self.cam {
            if entry & 0xffff == dword {
                return u64::from(entry >> 16) * 4;
            }
        }
        address
    }
    fn linear(&self, address: u64, dwords: u32) -> Vec<u32> {
        (0..u64::from(dwords))
            .map(|i| self.word(address + i * 4))
            .collect()
    }
    fn ring(&self, base: u64, size_dw: u64, from: u64, to: u64) -> Vec<u32> {
        (from..to)
            .map(|i| self.word(base + (i % size_dw) * 4))
            .collect()
    }
    /// PM4 type-3 decoder. `engine`: 0 gfx, 1 KIQ, 2 compute.
    fn pm4(&mut self, words: &[u32], engine: usize, ib: bool) {
        let mut i = 0;
        while i < words.len() {
            let h = words[i];
            assert_eq!(h >> 30, 3, "non type-3 PM4 header");
            let op = (h >> 8) & 0xff;
            let n = (h >> 16) & 0x3fff;
            if op == 0x10 && n == 0x3fff {
                i += 1;
                continue;
            }
            let body = &words[i + 1..i + 2 + n as usize];
            match op {
                0x10 => {}
                0x79 => {
                    assert_eq!(n, 1);
                    let reg = 0xc000 + body[0];
                    self.regs.insert(u64::from(reg) * 4, body[1]);
                }
                0x37 => {
                    assert_eq!(body[0], (5 << 8) | (1 << 20));
                    if !(ib && self.drop_ib_writes) {
                        let address = u64::from(body[1]) | (u64::from(body[2]) << 32);
                        self.put(address, body[3]);
                    }
                }
                0x49 => {
                    assert_eq!(n, 6);
                    assert_eq!(body[0], 0x0660_3514);
                    assert_eq!(body[1], (1 << 29) | (2 << 24));
                    if !self.drop_fences {
                        let address = u64::from(body[2]) | (u64::from(body[3]) << 32);
                        self.put(address, body[4]);
                    }
                }
                0x3f => {
                    assert!(!ib, "chained IB");
                    let compute = body[2] & (1 << 23) != 0;
                    assert_eq!(compute, engine == 2, "IB VALID bit per ring type");
                    let address = u64::from(body[0]) | (u64::from(body[1]) << 32);
                    let ib_words = self.linear(address, body[2] & 0xfffff);
                    self.pm4(&ib_words, engine, true);
                }
                0x4a | 0x28 | 0x12 | 0x11 | 0x69 => {
                    assert_eq!(engine, 0, "graphics state on a compute queue");
                    if op == 0x69 {
                        for (k, &v) in body[1..].iter().enumerate() {
                            self.context.insert(0xa000 + body[0] + k as u32, v);
                        }
                    }
                    if op == 0x12 {
                        self.clear_states += 1;
                    }
                }
                0xa0 => {
                    assert_eq!(engine, 1, "SET_RESOURCES outside KIQ");
                    self.resources
                        .push(u64::from(body[1]) | (u64::from(body[2]) << 32));
                }
                0xa2 => {
                    assert_eq!(engine, 1, "MAP_QUEUES outside KIQ");
                    assert_eq!(body[0] & 0x0c00_00f0, 0, "ENGINE_SEL/QUEUE_SEL");
                    assert_eq!(body[0] >> 29, 1, "NUM_QUEUES");
                    let mqd = u64::from(body[2]) | (u64::from(body[3]) << 32);
                    let rptr = u64::from(self.word(mqd + 139 * 4))
                        | (u64::from(self.word(mqd + 140 * 4)) << 32);
                    self.mapped.push(Mapped {
                        me: if body[0] & (1 << 18) != 0 { 2 } else { 1 },
                        pipe: (body[0] >> 16) & 3,
                        queue: (body[0] >> 13) & 7,
                        doorbell: body[1] >> 2,
                        mqd,
                        wptr: u64::from(body[4]) | (u64::from(body[5]) << 32),
                        rptr,
                    });
                }
                _ => panic!("unexpected PM4 opcode {op:#x}"),
            }
            i += 2 + n as usize;
        }
    }
    fn sdma_packets(&mut self, words: &[u32], ib: bool) {
        let mut i = 0;
        while i < words.len() {
            let h = words[i];
            i += match h & 0xff {
                0 => 1 + ((h >> 16) & 0x3fff) as usize,
                2 => {
                    assert_eq!(h, 2);
                    let count = words[i + 3] as usize + 1;
                    if !(ib && self.drop_ib_writes) {
                        let address = u64::from(words[i + 1]) | (u64::from(words[i + 2]) << 32);
                        for k in 0..count {
                            self.put(address + k as u64 * 4, words[i + 4 + k]);
                        }
                    }
                    4 + count
                }
                5 => {
                    assert_eq!(h, 0x30005);
                    if !self.drop_fences {
                        let address = u64::from(words[i + 1]) | (u64::from(words[i + 2]) << 32);
                        self.put(address, words[i + 3]);
                    }
                    4
                }
                6 => {
                    self.traps += 1;
                    2
                }
                4 => {
                    assert!(!ib);
                    assert_eq!(i % 8, 2, "SDMA IB packet must end on an 8-dword boundary");
                    let address = u64::from(words[i + 1]) | (u64::from(words[i + 2]) << 32);
                    assert_eq!(address % 32, 0);
                    let ib_words = self.linear(address, words[i + 3]);
                    self.sdma_packets(&ib_words, true);
                    6
                }
                op => panic!("unexpected SDMA opcode {op}"),
            };
        }
    }
    fn apertures(&self, index: u32) -> bool {
        self.reg(NBIO + 0xc0 * 4) & 1 != 0 && u64::from(index) * 4 + 8 <= DOORBELL_BYTES
    }
    fn ring_doorbell(&mut self, index: u32, value: u64) {
        assert!(!self.dirty, "doorbell before HDP flush");
        let shadow = |m: &Self, address: u64| {
            u64::from(m.word(address)) | (u64::from(m.word(address + 4)) << 32)
        };
        if !self.apertures(index) {
            return;
        }
        // GFX ring 0
        let control = self.reg(r(CP_RB_DOORBELL_CONTROL));
        let lower = self.reg(r(CP_RB_DOORBELL_RANGE_LOWER));
        let upper = self.reg(r(CP_RB_DOORBELL_RANGE_UPPER));
        if control & (1 << 30) != 0
            && (control & 0x0fff_fffc) >> 2 == index
            && (lower..=upper).contains(&(index << 2))
            && self.reg(r(CP_RB_ACTIVE)) == 1
            && self.reg(r(CP_ME_CNTL)) & 0x1500_0000 == 0
        {
            let cntl = self.reg(r(CP_RB0_CNTL));
            let base = (u64::from(self.reg(r(CP_RB0_BASE)))
                | (u64::from(self.reg(r(CP_RB0_BASE_HI))) << 32))
                << 8;
            let rptr_address = u64::from(self.reg(r(CP_RB0_RPTR_ADDR)))
                | (u64::from(self.reg(r(CP_RB0_RPTR_ADDR_HI))) << 32);
            let wptr_address = u64::from(self.reg(r(CP_RB_WPTR_POLL_ADDR_LO)))
                | (u64::from(self.reg(r(CP_RB_WPTR_POLL_ADDR_HI))) << 32);
            assert_eq!(shadow(self, wptr_address), value, "gfx wptr shadow");
            if self.stalled[0] {
                return;
            }
            let size = (8u64 << (cntl & 0x3f)) / 4;
            let words = self.ring(base, size, self.rptr[0], value);
            self.pm4(&words, 0, false);
            self.rptr[0] = value;
            self.regs.insert(r(CP_RB0_RPTR), value as u32);
            self.put(rptr_address, value as u32);
            return;
        }
        // MEC queues: KIQ through its HQD registers, KCQs through MAP_QUEUES.
        let mec = self.reg(r(CP_MEC_CNTL)) == 0
            && self.reg(r(CP_PQ_STATUS)) & 2 != 0
            && (self.reg(r(CP_MEC_DOORBELL_RANGE_LOWER))
                ..=self.reg(r(CP_MEC_DOORBELL_RANGE_UPPER)))
                .contains(&(index << 2));
        let kiq = |reg| self.hqd(2, 1, 0, reg);
        let kiq_control = kiq(CP_HQD_PQ_DOORBELL_CONTROL);
        if mec
            && kiq(CP_HQD_ACTIVE) == 1
            && kiq_control & (1 << 30) != 0
            && (kiq_control & 0x0fff_fffc) >> 2 == index
        {
            let base =
                (u64::from(kiq(CP_HQD_PQ_BASE)) | (u64::from(kiq(CP_HQD_PQ_BASE_HI)) << 32)) << 8;
            let size = 2u64 << (kiq(CP_HQD_PQ_CONTROL) & 0x3f);
            let rptr_address = u64::from(kiq(CP_HQD_PQ_RPTR_REPORT_ADDR))
                | (u64::from(kiq(CP_HQD_PQ_RPTR_REPORT_ADDR_HI)) << 32);
            let wptr_address = u64::from(kiq(CP_HQD_PQ_WPTR_POLL_ADDR))
                | (u64::from(kiq(CP_HQD_PQ_WPTR_POLL_ADDR_HI)) << 32);
            assert_eq!(shadow(self, wptr_address), value, "KIQ wptr shadow");
            if self.stalled[1] {
                return;
            }
            let words = self.ring(base, size, self.rptr[1], value);
            self.pm4(&words, 1, false);
            self.rptr[1] = value;
            self.put(rptr_address, value as u32);
            return;
        }
        if let Some(q) = self.mapped.iter().copied().find(|q| q.doorbell == index) {
            if !mec {
                return;
            }
            let field = |m: &Self, i: u64| m.word(q.mqd + i * 4);
            assert_eq!(field(self, 143) & (1 << 30), 1 << 30, "MQD doorbell enable");
            assert_eq!((field(self, 143) & 0x0fff_fffc) >> 2, index);
            assert_eq!(shadow(self, q.wptr), value, "compute wptr shadow");
            if self.stalled[2] {
                return;
            }
            let base = (u64::from(field(self, 136)) | (u64::from(field(self, 137)) << 32)) << 8;
            let size = 2u64 << (field(self, 145) & 0x3f);
            let words = self.ring(base, size, self.rptr[2], value);
            self.pm4(&words, 2, false);
            self.rptr[2] = value;
            self.put(q.rptr, value as u32);
            return;
        }
        for i in 0..2u32 {
            let x = |m: &Self, reg| m.reg(sdma(i, reg));
            let range = self.reg(NBIO + u64::from(0x1d0 + i) * 4);
            let offset = (range & 0xffc) >> 2;
            if x(self, SDMA0_GFX_DOORBELL) & (1 << 28) == 0
                || (x(self, SDMA0_GFX_DOORBELL_OFFSET) & 0x0fff_fffc) >> 2 != index
                || !(offset..offset + ((range >> 16) & 0x1f)).contains(&index)
                || x(self, SDMA0_GFX_RB_CNTL) & 1 == 0
                || x(self, SDMA0_F32_CNTL) & 1 != 0
            {
                continue;
            }
            assert_eq!(value % 4, 0, "SDMA pointers are bytes");
            let wptr_address = u64::from(x(self, SDMA0_GFX_RB_WPTR_POLL_ADDR_LO))
                | (u64::from(x(self, SDMA0_GFX_RB_WPTR_POLL_ADDR_HI)) << 32);
            assert_eq!(shadow(self, wptr_address), value, "SDMA wptr shadow");
            if self.stalled[3 + i as usize] {
                return;
            }
            let cntl = x(self, SDMA0_GFX_RB_CNTL);
            let base = (u64::from(x(self, SDMA0_GFX_RB_BASE))
                | (u64::from(x(self, SDMA0_GFX_RB_BASE_HI)) << 32))
                << 8;
            let size = 1u64 << ((cntl >> 1) & 0x1f);
            let from = self.rptr[3 + i as usize];
            let words = self.ring(base, size, from / 4, value / 4);
            self.sdma_packets(&words, false);
            self.rptr[3 + i as usize] = value;
            for (reg, v) in [
                (SDMA0_GFX_RB_RPTR, value as u32),
                (SDMA0_GFX_RB_RPTR_HI, (value >> 32) as u32),
            ] {
                self.regs.insert(sdma(i, reg), v);
            }
            if cntl & (1 << 12) != 0 {
                let address = u64::from(x(self, SDMA0_GFX_RB_RPTR_ADDR_LO))
                    | (u64::from(x(self, SDMA0_GFX_RB_RPTR_ADDR_HI)) << 32);
                self.put(address, value as u32);
                self.put(address + 4, (value >> 32) as u32);
            }
            return;
        }
    }
}
impl Io for Model {
    fn read(&mut self, address: u64) -> u32 {
        let address = self.key(self.cam_target(address));
        *self.regs.get(&address).unwrap_or(&0)
    }
    fn write(&mut self, address: u64, value: u32) {
        self.writes.push((address, value));
        if address == 0x7f000 {
            self.dirty = false;
        }
        if address == HDP + 0xd1 * 4 {
            self.stale = false;
        }
        if address == r(GRBM_CAM_DATA) {
            assert_eq!(self.reg(r(GRBM_CAM_DATA_UPPER)), 0);
            self.cam.push(value);
        }
        if address == r(GRBM_SOFT_RESET) {
            self.progress.fetch_add(1, Ordering::SeqCst);
        }
        let key = self.key(self.cam_target(address));
        self.regs.insert(key, value);
        if address == r(CP_HQD_DEQUEUE_REQUEST) && value == 1 && !self.stuck_hqd {
            let active = self.key(r(CP_HQD_ACTIVE));
            self.regs.insert(active, 0);
        }
        if let Some((reg, want, cap)) = self.revoke {
            if reg == address && value == want {
                cap.revoke();
            }
        }
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        assert!(!self.stale, "CPU read without HDP invalidate");
        self.word(mc(map, offset))
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        assert!(offset + 4 <= map.len, "write outside reservation");
        self.dirty = true;
        self.mem.insert(mc(map, offset), value);
    }
    fn doorbell(&mut self, index: u32, value: u64) {
        self.doorbells.push((index, value));
        self.progress.fetch_add(1 << 16, Ordering::SeqCst);
        self.ring_doorbell(index, value);
    }
}
pub(crate) fn hw(model: Model) -> Hw<Model> {
    Hw {
        io: model,
        authority: Cap::bootstrap(),
        layout: layout(),
    }
}
/// Model state after the cold-boot doorbell stage.
pub(crate) fn enabled() -> Model {
    let mut model = Model::new();
    enable_doorbells(&mut model, layout(), BAR2).unwrap();
    model.writes.clear();
    model
}
/// Poll until `progress` reaches `goal`, then drop the future.
pub(crate) fn cancel_at<F: Future>(future: F, progress: &AtomicU32, goal: u32) -> bool {
    let mut future = core::pin::pin!(future);
    let deadline = narf_time::Deadline::after_ms(500);
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
        run(delay(100));
    }
}

fn gfx(model: Model) -> (Pool, GfxEngine<Model>) {
    let pool = pool(1 << 20);
    let queue = Queue::new(&pool, Kind::Cp, doorbell::GFX_RING0, fence::Engine::Gfx).unwrap();
    (
        pool,
        GfxEngine {
            hw: hw(model),
            queue,
            state: GfxState::Prepared,
            proof: GfxProof::default(),
        },
    )
}

/// Boot-test GPU descriptor with the live Navi22 discovery bases.
pub(crate) fn navi22_gpu() -> AmdGpu {
    use crate::amdgpu_discovery as d;
    let mut gpu = crate::amdgpu_navi22_boot::tests::gpu();
    for b in gpu.ip_blocks.iter_mut() {
        let bases: &[u32] = match b.hw_id {
            d::HW_ID_GC => &[0x1260, 0xa000, 0x1c000],
            d::HW_ID_NBIF => &[0, 0x14, 0xd20],
            d::HW_ID_HDP => &[0xf20],
            _ => &[],
        };
        b.base_addrs[..bases.len()].copy_from_slice(bases);
    }
    gpu
}
fn cp_navi22_layout_uses_discovery_banks_and_rejects_aliases() -> TestResult {
    let gpu = navi22_gpu();
    if Layout::resolve(&gpu) != Ok(layout()) {
        return TestResult::Fail("live discovery bases not resolved");
    }
    if layout().dword(SCRATCH_REG0) - 0xc000 != 0x40
        || layout().sdma(1, SDMA0_GFX_RB_CNTL) != GC0 + 0x680 * 4
        || layout().dword(CAM_REMAP[0].0) != 0xc24e
        || layout().dword(CAM_REMAP[0].1) != 0x2223
    {
        return TestResult::Fail("SOC15 absolute offsets");
    }
    for case in 0..5 {
        let mut bad = navi22_gpu();
        match case {
            0 => bad.ip_blocks[0].revision = 0,
            1 => bad.ip_blocks[3].minor = 0,
            2 => bad.ip_blocks[0].base_addrs[1] = 0x1000, // UCONFIG aliasing
            3 => bad.regs.len = 0x40000,
            _ => bad.ip_blocks[0].num_bases = 1,
        }
        if Layout::resolve(&bad).is_ok() {
            return TestResult::Fail("unsupported CP layout accepted");
        }
    }
    let mut model = Model::new();
    enable_doorbells(&mut model, layout(), 0x1_2345_6000).unwrap();
    if model.reg(NBIO + 0xc0 * 4) != 1
        || model.reg(NBIO + 0xf4 * 4) != 0x2345_6000
        || model.reg(NBIO + 0xf3 * 4) != 1
        || model.reg(NBIO + 0xf5 * 4) != 3
    {
        return TestResult::Fail("NBIF doorbell apertures");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/cp-navi22",
    cp_navi22_layout_uses_discovery_banks_and_rejects_aliases
);

fn cp_navi22_gfx_configure_programs_golden_cam_and_constants() -> TestResult {
    for remapped in [false, true] {
        let mut model = enabled();
        model.cam_remapped = remapped;
        model.regs.insert(r(GOLDEN[4].0), 0xffff_fff0); // CPF_GCR_CNTL RMW
        model.regs.insert(r(RLC_SRM_CNTL), 0x10);
        model.regs.insert(r(CP_INT_CNTL_RING0), u32::MAX >> 1);
        let (_pool, mut e) = gfx(model);
        if run(e.configure()).is_err() || e.state != GfxState::Configured {
            return TestResult::Fail("gfx configure failed");
        }
        let m = &e.hw.io;
        let csib = e.queue.address(MQD);
        let csb = crate::amdgpu_clearstate_gfx10::csb(0xa000, 0).unwrap();
        if m.reg(r(GOLDEN[4].0)) != (0xffff_fff0 & !0x7ffff) | 0xc000
            || m.reg(r(GOLDEN[5].0)) != 0x280
            || m.reg(r(GOLDEN[41].0)) != 0x20
            || m.reg(r(GRBM_CNTL)) & 0xff != 0xff
            || m.reg(r(GRBM_GFX_INDEX)) != 0xe000_0000
            || m.reg(r(GRBM_GFX_CNTL)) != 0
            || m.sh_mem(0, SH_MEM_CONFIG) != 0xc00c
            || m.sh_mem(0, SH_MEM_BASES) != 0
            || m.sh_mem(3, SH_MEM_BASES) != 0x2000_1000
            || m.sh_mem(9, SH_MEM_BASES) != 0x6000_6000
            || m.reg(r(SPI_GDBG_TRAP_CONFIG)) != 0xff00_8000
            || m.reg(r(RLC_CSIB_ADDR_LO)) != csib as u32
            || m.reg(r(RLC_CSIB_ADDR_HI)) != (csib >> 32) as u32
            || m.reg(r(RLC_CSIB_LENGTH)) != 949
            || m.reg(r(RLC_SPM_MC_CNTL)) != 0xf
            || m.reg(r(RLC_SRM_CNTL)) != 0x13
            || m.reg(r(CP_INT_CNTL_RING0)) != (u32::MAX >> 1) & !0x3c_0000
            || (0..949).any(|i| m.word(csib + i * 4) != csb[i as usize])
            || e.proof.cam_remapped != remapped
            || e.proof.csb_dwords != 949
        {
            return TestResult::Fail("gfx golden/constants/RLC CSB programming");
        }
        let expected_cam = if remapped {
            Vec::new()
        } else {
            CAM_REMAP
                .iter()
                .map(|&(u, t)| layout().dword(u) | (layout().dword(t) << 16))
                .collect()
        };
        if m.cam != expected_cam
            || m.writes
                .iter()
                .any(|&(a, _)| a == r(CP_ME_CNTL) || a == r(CP_RB0_CNTL))
            || !m.doorbells.is_empty()
        {
            return TestResult::Fail("GRBM CAM remap or premature CP start");
        }
        // GDS/GWS/OA cleared for VMIDs 1..15, never VMID0.
        let gds = |a: u64| m.writes.iter().any(|&(w, v)| w == a && v == 0);
        if !gds(r(GDS_OA_VMID0) + 15 * 4) || gds(r(GDS_OA_VMID0)) || !gds(r(GDS_VMID0_SIZE) + 2 * 4)
        {
            return TestResult::Fail("GDS VMID partitioning");
        }
        let count = e.hw.io.writes.len();
        if run(e.configure()) != Err(Error::Busy) || e.hw.io.writes.len() != count {
            return TestResult::Fail("gfx configure replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/cp-navi22",
    cp_navi22_gfx_configure_programs_golden_cam_and_constants
);

fn cp_navi22_gfx_ring_clear_state_ring_and_ib_tests() -> TestResult {
    let (pool, mut e) = gfx(enabled());
    let available = pool.available();
    if run(e.configure()).is_err() || run(e.start()).is_err() || run(e.test_ib()).is_err() {
        return TestResult::Fail("gfx bring-up failed");
    }
    let m = &e.hw.io;
    let base = e.queue.address(0);
    for (reg, value) in [
        (CP_RB0_CNTL, 0x80a),
        (CP_RB0_BASE, (base >> 8) as u32),
        (CP_RB0_BASE_HI, (base >> 40) as u32),
        (CP_RB_ACTIVE, 1),
        (CP_RB_DOORBELL_CONTROL, (1 << 30) | (0x116 << 2)),
        (CP_RB_DOORBELL_RANGE_LOWER, 0x458),
        (CP_RB_DOORBELL_RANGE_UPPER, 0xffc),
        (CP_MAX_CONTEXT, 7),
        (CP_DEVICE_ID, 1),
        (CP_ME_CNTL, 0),
        (CP_RB_VMID, 0),
        (SCRATCH_REG0, 0xdead_beef),
    ] {
        if m.reg(r(reg)) != value {
            return TestResult::Fail("gfx ring register encoding");
        }
    }
    // CP_RB0_CNTL is written twice around the 1 ms pointer settle delay.
    let cntl = m
        .writes
        .iter()
        .filter(|&&(a, _)| a == r(CP_RB0_CNTL))
        .count();
    let order = |a: Reg| m.writes.iter().position(|&(w, _)| w == r(a)).unwrap();
    if cntl != 2
        || order(CP_RB0_RPTR_ADDR) > order(CP_RB0_BASE)
        || order(CP_RB_DOORBELL_CONTROL) > order(CP_ME_CNTL)
        || m.clear_states != 1
        || m.context.get(&0xa00d) != Some(&0x4000_4000)
        || m.context.get(&0xa0d7) != Some(&0)
        || m.context.len() != 922
        || m.doorbells.iter().map(|d| d.0).any(|i| i != 0x116)
        || m.doorbells.iter().map(|d| d.1).collect::<Vec<_>>() != [1024, 1280, 1536]
        || m.word(e.queue.address(SCRATCH)) != 0xdead_beef
        || m.word(e.queue.address(FENCE)) != 1
        || m.word(e.queue.address(RPTR)) != 1536
        || e.state != GfxState::Verified
        || e.proof
            != (GfxProof {
                cam_remapped: false,
                csb_dwords: 949,
                ring: true,
                ib_fence: 1,
            })
    {
        return TestResult::Fail("gfx clear-state/ring/IB execution");
    }
    let count = m.writes.len();
    if run(e.start()) != Err(Error::Busy)
        || run(e.test_ib()) != Err(Error::Busy)
        || e.hw.io.writes.len() != count
    {
        return TestResult::Fail("gfx ring replayed");
    }
    drop(e);
    if pool.available() != available {
        return TestResult::Fail("live gfx ring memory recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/cp-navi22",
    cp_navi22_gfx_ring_clear_state_ring_and_ib_tests
);

fn cp_navi22_gfx_failures_are_bounded_and_terminal() -> TestResult {
    for case in 0..7 {
        let mut model = enabled();
        let expected = match case {
            0 => {
                model.regs.insert(r(GRBM_CNTL), u32::MAX);
                Error::DeviceGone
            }
            1 => {
                model.regs.insert(r(RLC_RLCS_BOOTLOAD_STATUS), 0);
                Error::Timeout
            }
            2 => {
                model.stalled[0] = true;
                Error::Timeout
            }
            3 => {
                model.drop_ib_writes = true;
                Error::DataMismatch
            }
            4 => {
                model.drop_fences = true;
                Error::Timeout
            }
            5 => {
                // Doorbell aperture closed: the CP never sees the ring.
                model.regs.insert(NBIO + 0xc0 * 4, 0);
                Error::Timeout
            }
            _ => Error::Revoked,
        };
        let (pool, mut e) = gfx(model);
        if case == 6 {
            e.hw.io.revoke = Some((r(CP_RB_ACTIVE), 1, e.hw.authority));
        }
        let result = match run(e.configure()) {
            Err(error) => Err(error),
            Ok(()) => match run(e.start()) {
                Err(error) => Err(error),
                Ok(()) => run(e.test_ib()),
            },
        };
        if result != Err(expected) || e.state != GfxState::Failed {
            return TestResult::Fail("gfx failure not reported or not terminal");
        }
        if case == 0 && !e.hw.io.writes.is_empty() {
            return TestResult::Fail("removed device written");
        }
        let count = e.hw.io.writes.len();
        if run(e.start()) != Err(Error::Busy) || e.hw.io.writes.len() != count {
            return TestResult::Fail("failed gfx owner replayed");
        }
        let published = case != 0;
        drop(e);
        if (pool.available() == 1 << 20) == published {
            return TestResult::Fail("gfx failure recycled or leaked storage");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/cp-navi22",
    cp_navi22_gfx_failures_are_bounded_and_terminal
);

fn cp_navi22_gfx_cancellation_retains_ring_and_blocks_replay() -> TestResult {
    let mut model = enabled();
    model.stalled[0] = true;
    let progress = model.progress.clone();
    let (pool, mut e) = gfx(model);
    if run(e.configure()).is_err() {
        return TestResult::Fail("gfx configure failed");
    }
    // First doorbell (clear-state) has been rung; cancel during the ring test.
    if !cancel_at(e.start(), &progress, 2 << 16) {
        return TestResult::Fail("gfx start did not reach its ring test");
    }
    let count = e.hw.io.writes.len();
    if e.state != GfxState::Starting
        || run(e.start()) != Err(Error::Busy)
        || run(e.test_ib()) != Err(Error::Busy)
        || e.hw.io.writes.len() != count
    {
        return TestResult::Fail("cancelled gfx start replayed");
    }
    drop(e);
    if pool.available() != (1 << 20) - QUEUE_BYTES {
        return TestResult::Fail("cancelled gfx ring recycled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/cp-navi22",
    cp_navi22_gfx_cancellation_retains_ring_and_blocks_replay
);

fn cp_navi22_queue_padding_matches_linux_nop_rules() -> TestResult {
    let pool = pool(1 << 20);
    let mut model = Model::new();
    let mut cp = Queue::new(&pool, Kind::Cp, 0, fence::Engine::Gfx).unwrap();
    let mut dma = Queue::new(&pool, Kind::Sdma, 0, fence::Engine::Sdma0).unwrap();
    cp.emit(&mut model, &[1; 255]).unwrap();
    cp.pad(&mut model);
    cp.emit(&mut model, &[1; 3]).unwrap();
    cp.pad(&mut model);
    dma.emit(&mut model, &[1; 5]).unwrap();
    dma.pad(&mut model);
    let oversized = cp.emit(&mut model, &[0; RING_DW as usize]).is_ok();
    let w = |q: &Queue, i: u64| model.word(q.address(i * 4));
    if cp.wptr != 512
        || w(&cp, 255) != pm4::NOP
        || w(&cp, 259) != packet3(PACKET3_NOP, 251)
        || (260..512).any(|i| w(&cp, i) != pm4::NOP)
        || dma.wptr != 16
        || (5..16).any(|i| w(&dma, i) != 0)
        || dma.hw_wptr() != 64
        || oversized
    {
        return TestResult::Fail("ring padding/pointer units");
    }
    // Ring wrap: writes continue at offset 0 with a monotonic pointer.
    cp.wptr = RING_DW - 1;
    cp.emit(&mut model, &[7, 8]).unwrap();
    let w = |q: &Queue, i: u64| model.word(q.address(i * 4));
    if w(&cp, RING_DW - 1) != 7 || w(&cp, 0) != 8 || cp.wptr != RING_DW + 1 {
        return TestResult::Fail("ring wrap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/cp-navi22",
    cp_navi22_queue_padding_matches_linux_nop_rules
);

fn cp_navi22_owner_constructors_reserve_without_io() -> TestResult {
    let gpu = navi22_gpu();
    let pool = pool(1 << 20);
    let authority = Cap::bootstrap();
    // SAFETY: bookkeeping-only constructors; the descriptor's BAR5 and the
    // doorbell page are never dereferenced by these tests.
    let owners = unsafe {
        (
            Gfx::new(&gpu, authority, &pool, doorbells()),
            crate::amdgpu_kiq_navi22::Compute::new(&gpu, authority, &pool, doorbells()),
            crate::amdgpu_sdma_navi22_queues::Sdma::new(&gpu, authority, &pool, doorbells()),
        )
    };
    let (Ok(gfx), Ok(compute), Ok(sdma)) = owners else {
        return TestResult::Fail("queue owner construction failed");
    };
    if gfx.state() != GfxState::Prepared
        || compute.state() != crate::amdgpu_kiq_navi22::State::Prepared
        || sdma.state() != crate::amdgpu_sdma_navi22_queues::State::Prepared
        || pool.available() != (1 << 20) - 5 * QUEUE_BYTES
        || doorbells().bus_address() != BAR2
    {
        return TestResult::Fail("queue owners performed I/O or misreserved");
    }
    drop((gfx, compute, sdma));
    let unbased = crate::amdgpu_navi22_boot::tests::gpu();
    // SAFETY: unsupported layout must be rejected before any reservation.
    let rejected = unsafe { Gfx::new(&unbased, authority, &pool, doorbells()) }.is_err();
    if pool.available() != 1 << 20 || !rejected {
        return TestResult::Fail("unpublished queue storage leaked or bad layout accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/cp-navi22",
    cp_navi22_owner_constructors_reserve_without_io
);
