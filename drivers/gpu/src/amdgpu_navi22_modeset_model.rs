//! One combined register model of the Navi22 display engine for end-to-end
//! modeset tests: every DCN block, the DAL clock mailbox, NBIO/HDP and the
//! VBIOS tables' register traffic land in one log, in global order.
//!
//! The model is a register file with the hardware's acknowledgements:
//! DENTIST done bits, the DAL mailbox, OTG/OPTC clock-on and busy, OTG lock
//! status, PGFSM power status, HUBP no-outstanding-requests, MPCC idle and
//! DP stream status follow what was written. The synthetic VBIOS's tables
//! write their parameter blocks to marker registers, so each table call
//! appears in the log with its parameters; a transmitter ENABLE/DISABLE
//! sets/clears that backend's `DIG_ENABLE` as the real table does.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as d,
    amdgpu_navi22_display::{Connector, Signal, Sink},
    amdgpu_reg_window::model::{self, Attached, Device},
};
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use narf_lib::sync::IrqSafeSpinLock;

pub(crate) const DCN: [u32; 4] = [0x12, 0xc0, 0x34c0, 0x9000];
pub(crate) const NBIF: [u32; 4] = [0x0, 0x14, 0xd20, 0x10400];
pub(crate) const MP1: u32 = 0x16000;
pub(crate) const REGS_BYTES: usize = 1 << 20;
/// Marker dwords the synthetic tables write their PS dwords to: slot n at
/// `MARK + 16 n`, one dword per PS dword.
pub(crate) const MARK: u32 = 0xf000;
pub(crate) const SLOT_STREAM_SETUP: u32 = 0;
pub(crate) const SLOT_PIXEL_CLOCK: u32 = 1;
pub(crate) const SLOT_POWER_GATING: u32 = 2;
pub(crate) const SLOT_TRANSMITTER: u32 = 3;
/// Pseudo-dwords for AUX traffic in the log: `AUX_WRITE | address`.
pub(crate) const AUX_WRITE: u32 = 0x8000_0000;
pub(crate) const AUX_READ: u32 = 0x4000_0000;

pub(crate) const fn d1(reg: u32) -> u32 {
    DCN[1] + reg
}
pub(crate) const fn d2(reg: u32) -> u32 {
    DCN[2] + reg
}
pub(crate) const fn d3(reg: u32) -> u32 {
    DCN[3] + reg
}
const DENTIST: u32 = d1(0x64);
const DAL_MESSAGE: u32 = MP1 + 0x28a;
const DAL_ARGUMENT: u32 = MP1 + 0x273;
const DAL_RESPONSE: u32 = MP1 + 0x274;
const PLL: u32 = 0x17010;

/// One logged access: a register write (dword, value), or AUX traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Write {
    pub dword: u32,
    pub value: u32,
}

#[derive(Default)]
pub(crate) struct State {
    pub mem: BTreeMap<u32, u32>,
    pub log: Vec<Write>,
    /// After this many logged writes every read returns all ones.
    pub die_after: Option<usize>,
    pub dead: bool,
    /// Latch an OTG underflow on this pipe when its update lock drops.
    pub underflow_on_unlock: Option<u8>,
    /// DAL commands seen, (message, argument).
    pub dal: Vec<(u32, u32)>,
    /// Once the log holds more than `.0` writes, reads of `.1` return
    /// `(value & !.2) | .3`: an acknowledgement withheld, so the owner
    /// polling it stays pending there.
    pub stall: Option<(usize, u32, u32, u32)>,
}
impl State {
    fn get(&self, dword: u32) -> u32 {
        *self.mem.get(&dword).unwrap_or(&0)
    }
}
pub(crate) struct Model(pub IrqSafeSpinLock<State>);

/// DAL DPM levels in MHz per PPCLK id: SOCCLK, UCLK, FCLK, DCFCLK,
/// DISPCLK, PIXCLK, PHYCLK.
fn dpm(clock: u32) -> [u32; 2] {
    match clock {
        1 => [500, 1200],
        2 => [97, 1000],
        3 => [400, 1400],
        8 => [300, 1200],
        9 | 10 => [300, 1330],
        11 => [300, 810],
        _ => [0, 0],
    }
}
fn instance(dword: u32, base: u32, stride: u32, count: u32) -> Option<u32> {
    let offset = dword.checked_sub(base)?;
    (offset % stride == 0 && offset / stride < count).then_some(offset / stride)
}

impl Device for Model {
    fn read(&self, offset: u64) -> u32 {
        let dword = (offset / 4) as u32;
        let value = self.acknowledge(dword);
        let s = self.0.lock();
        match s.stall {
            Some((after, at, mask, forced)) if at == dword && s.log.len() > after => {
                (value & !mask) | forced
            }
            _ => value,
        }
    }
    fn write(&self, offset: u64, value: u32) {
        self.store((offset / 4) as u32, value);
    }
}
impl Model {
    fn acknowledge(&self, dword: u32) -> u32 {
        let s = self.0.lock();
        if s.dead {
            return u32::MAX;
        }
        let v = s.get(dword);
        if dword == DENTIST {
            return v | 1 << 19 | 1 << 20 | (v & 0x7f) << 8;
        }
        if dword == PLL {
            // 36.5 x 100 MHz.
            return 36 | 0x8000 << 16;
        }
        if dword == d2(0x51f) {
            // DCHUBBUB_GLOBAL_TIMER_CNTL: enabled, REFDIV 2.
            return 1 << 12 | 2;
        }
        if instance(dword, d2(0x5f3), 0xdc, 6).is_some() {
            // DCHUBP_CNTL: no outstanding requests.
            return v | 1 << 1;
        }
        if let Some(p) = instance(dword, d2(0x1b86), 0x80, 6) {
            // OTG_CLOCK_CONTROL: CLOCK_ON follows EN, BUSY follows MASTER_EN.
            let master = s.get(d2(0x1b41 + p * 0x80)) & 1;
            return (v & !(1 << 8 | 1 << 16)) | (v & 1) << 8 | master << 16;
        }
        if instance(dword, d2(0x1acf), 0x10, 6).is_some() {
            // OPTC_INPUT_CLOCK_CONTROL: CLK_ON follows CLK_EN.
            return (v & !4) | (v & 2) << 1;
        }
        if instance(dword, d2(0x1b8b), 0x80, 6).is_some() {
            return (v & !(1 << 8)) | (v & 1) << 8;
        }
        if let Some(domain) = instance(dword, d2(0x81), 2, 12) {
            // DOMAINn_PG_STATUS: off (2) while POWER_GATE is set.
            let gated = s.get(d2(0x80 + 2 * domain)) & 1 << 8 != 0;
            return if gated { 2 << 30 } else { 0 };
        }
        if instance(dword, d3(0x0d), 0x20, 6).is_some() {
            return 1; // MPCC_IDLE
        }
        if instance(dword, d2(0x210c), 0x100, 6).is_some() {
            // DP_VID_STREAM_STATUS follows DP_VID_STREAM_ENABLE.
            return (v & !(1 << 16)) | (v & 1) << 16;
        }
        v
    }
    fn store(&self, dword: u32, value: u32) {
        let mut s = self.0.lock();
        s.log.push(Write { dword, value });
        if s.die_after.is_some_and(|n| s.log.len() >= n) {
            s.dead = true;
        }
        s.mem.insert(dword, value);
        if dword == DAL_MESSAGE {
            let arg = s.get(DAL_ARGUMENT);
            s.dal.push((value, arg));
            let answer = match value {
                2 => 0x0041_3f00,
                3 => 0xe,
                4 => 1,
                0xb if arg & 0xff == 0xff => 2,
                0xb => dpm(arg >> 16)[(arg & 1) as usize],
                9 => arg & 0xffff,
                _ => 0,
            };
            s.mem.insert(DAL_ARGUMENT, answer);
            s.mem.insert(DAL_RESPONSE, 1);
        }
        // The transmitter table's PS dword 0: phyid, action.
        if dword == MARK + 16 * SLOT_TRANSMITTER {
            let phy = value & 0xff;
            let action = (value >> 8) & 0xff;
            let enable = d2(0x20b1 + phy * 0x100);
            match action {
                1 => {
                    s.mem.insert(enable, 1);
                }
                0 => {
                    s.mem.insert(enable, 0);
                }
                _ => {}
            }
        }
        if let Some(p) = instance(dword, d2(0x1b8b), 0x80, 6) {
            if value & 1 == 0 && s.underflow_on_unlock == Some(p as u8) {
                let optc = d2(0x1aca + p * 0x10);
                let old = s.get(optc);
                s.mem.insert(optc, old | 0x400);
            }
        }
    }
}

/// A model attached to a fresh, otherwise unused 1 MiB register mapping.
pub(crate) struct Bench {
    pub model: Arc<Model>,
    pub gpu: AmdGpu,
    _attached: Attached,
    _backing: Vec<u32>,
}
impl Bench {
    pub fn new() -> Self {
        let mut backing = vec![0u32; REGS_BYTES / 4];
        let regs = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: backing.as_mut_ptr() as u64,
            len: REGS_BYTES as u64,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let model = Arc::new(Model(IrqSafeSpinLock::new(State::default())));
        let attached = model::attach(regs.virt, model.clone());
        let ip = |hw_id, v: (u8, u8, u8), bases: &[u32]| {
            let mut base_addrs = [0; d::MAX_BASE_ADDRS];
            base_addrs[..bases.len()].copy_from_slice(bases);
            d::IpBlock {
                hw_id,
                instance: 0,
                major: v.0,
                minor: v.1,
                revision: v.2,
                sub_revision: 0,
                variant: 0,
                base_addrs,
                num_bases: bases.len() as u8,
            }
        };
        let gpu = AmdGpu {
            regs,
            fb_bar: regs,
            chip: crate::amdgpu::__test_chip_info_for_pci_id(
                crate::amdgpu::AMD_VENDOR,
                crate::amdgpu::NAVI22,
            )
            .unwrap(),
            vram: crate::amdgpu::VramInfo {
                base: 0x80_0000_0000,
                size: 12272 << 20,
                visible_size: 12272 << 20,
            },
            mode: None,
            fw_loaded: false,
            gc_info: None,
            vbios: None,
            ip_blocks: vec![
                ip(
                    d::HW_ID_GC,
                    (10, 3, 2),
                    &[0x1260, 0xa000, 0x1c000, 0x2402c00],
                ),
                ip(d::HW_ID_DCN, (3, 0, 0), &DCN),
                ip(d::HW_ID_NBIF, (3, 3, 1), &NBIF),
                ip(
                    d::HW_ID_MP1,
                    (11, 0, 11),
                    &[MP1, 0xdc0000, 0xe00000, 0xe40000],
                ),
            ],
        };
        Self {
            model,
            gpu,
            _attached: attached,
            _backing: backing,
        }
    }
    pub fn set(&self, dword: u32, value: u32) {
        self.model.0.lock().mem.insert(dword, value);
    }
    pub fn get(&self, dword: u32) -> u32 {
        self.model.0.lock().get(dword)
    }
    pub fn log(&self) -> Vec<Write> {
        self.model.0.lock().log.clone()
    }
    pub fn writes(&self) -> usize {
        self.model.0.lock().log.len()
    }
    pub fn die_after(&self, n: usize) {
        self.model.0.lock().die_after = Some(n);
    }
    pub fn revive(&self) {
        let mut s = self.model.0.lock();
        s.die_after = None;
        s.dead = false;
    }
    pub fn stall(&self, after: usize, dword: u32, mask: u32, forced: u32) {
        self.model.0.lock().stall = Some((after, dword, mask, forced));
    }
    pub fn unstall(&self) {
        self.model.0.lock().stall = None;
    }
    pub fn underflow_on_unlock(&self, pipe: u8) {
        self.model.0.lock().underflow_on_unlock = Some(pipe);
    }
}

/// A synthetic VBIOS whose four display tables each copy their PS dwords
/// to a marker slot. `transmitter_revision` picks v1.6 or v1.7.
pub(crate) fn vbios(transmitter_revision: u8) -> Vec<u8> {
    const ROM: usize = 0x100;
    const CMD_DIR: usize = 0x200;
    const DATA_DIR: usize = 0x400;
    let mut image = vec![0u8; 0x1000];
    image[..2].copy_from_slice(&[0x55, 0xaa]);
    image[0x48..0x4a].copy_from_slice(&(ROM as u16).to_le_bytes());
    image[ROM..ROM + 4].copy_from_slice(&[36, 0, 1, 1]);
    image[ROM + 4..ROM + 8].copy_from_slice(b"ATOM");
    image[ROM + 0x1e..ROM + 0x20].copy_from_slice(&(CMD_DIR as u16).to_le_bytes());
    image[ROM + 0x20..ROM + 0x22].copy_from_slice(&(DATA_DIR as u16).to_le_bytes());
    let entries = 81usize;
    image[CMD_DIR..CMD_DIR + 2].copy_from_slice(&((4 + 2 * entries) as u16).to_le_bytes());
    image[CMD_DIR + 2] = 2;
    image[CMD_DIR + 3] = 1;
    image[DATA_DIR..DATA_DIR + 2].copy_from_slice(&((4 + 2 * 34) as u16).to_le_bytes());
    image[DATA_DIR + 2] = 2;
    image[DATA_DIR + 3] = 1;
    // (table id, content revision, PS bytes, marker slot, PS dwords copied)
    let tables = [
        (4usize, 5u8, 12u8, SLOT_STREAM_SETUP, 3u8),
        (12, 7, 16, SLOT_PIXEL_CLOCK, 4),
        (13, 1, 16, SLOT_POWER_GATING, 1),
        (
            76,
            transmitter_revision,
            if transmitter_revision == 7 { 60 } else { 32 },
            SLOT_TRANSMITTER,
            3,
        ),
    ];
    let mut at = 0x800usize;
    for (id, revision, ps, slot, copied) in tables {
        image[CMD_DIR + 4 + 2 * id..CMD_DIR + 6 + 2 * id]
            .copy_from_slice(&(at as u16).to_le_bytes());
        let mut code = Vec::new();
        for i in 0..copied {
            let reg = (MARK + 16 * slot + u32::from(i)) as u16;
            // MOVE REG[reg] <- PS[i]
            code.extend_from_slice(&[1, 0x01, reg as u8, (reg >> 8) as u8, i]);
        }
        code.push(91);
        let size = 6 + code.len();
        image[at..at + 2].copy_from_slice(&(size as u16).to_le_bytes());
        image[at + 2] = 1;
        image[at + 3] = revision;
        image[at + 4] = 0;
        image[at + 5] = ps;
        image[at + 6..at + size].copy_from_slice(&code);
        at += 0x100;
    }
    image
}

fn checksum(edid: &mut [u8]) {
    for block in edid.chunks_exact_mut(128) {
        let sum = block[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        block[127] = 0u8.wrapping_sub(sum);
    }
}
/// 640x480@60 (25.175 MHz, 800x525, sync 16/96/10/2, negative).
const DTD_640X480: [u8; 18] = [
    0xd5, 0x09, 0x80, 0xa0, 0x20, 0xe0, 0x2d, 0x10, 0x10, 0x60, 0xa2, 0x00, 0, 0, 0, 0, 0, 0x18,
];
/// An HDMI sink (CTA block with the HDMI VSDB) or a DP sink (base block
/// only) whose preferred mode is 640x480.
pub(crate) fn sink(signal: Signal, dpcd: Option<[u8; 16]>) -> Sink {
    sink_audio(signal, dpcd, false)
}
/// [`sink`], optionally with a CTA audio data block (2-channel LPCM, 32–48
/// kHz, 16–24 bit) after the HDMI VSDB.
pub(crate) fn sink_audio(signal: Signal, dpcd: Option<[u8; 16]>, audio: bool) -> Sink {
    let blocks = if signal == Signal::Hdmi { 2 } else { 1 };
    let mut e = vec![0u8; 128 * blocks];
    e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    e[18] = 1;
    e[19] = 4;
    e[54..72].copy_from_slice(&DTD_640X480);
    if signal == Signal::Hdmi {
        e[126] = 1;
        let ext = &mut e[128..];
        ext[0] = 2;
        ext[1] = 3;
        ext[4] = 3 << 5 | 5;
        ext[5..8].copy_from_slice(&[0x03, 0x0c, 0x00]);
        ext[8] = 0x10;
        ext[2] = 10;
        if audio {
            ext[3] = 0x40;
            ext[10] = 1 << 5 | 3;
            ext[11..14].copy_from_slice(&[0x09, 0x07, 0x07]);
            ext[2] = 14;
        }
    }
    checksum(&mut e);
    Sink {
        edid: e,
        preferred: None,
        hdmi: signal == Signal::Hdmi,
        dpcd,
    }
}
/// DPCD 1.2/1.4 receiver caps: HBR2, four lanes, enhanced framing, TPS3.
pub(crate) fn dpcd(revision: u8) -> [u8; 16] {
    let mut caps = [0u8; 16];
    caps[0] = revision;
    caps[1] = 0x14;
    caps[2] = 0x80 | 0x40 | 4;
    caps
}
pub(crate) fn connector(signal: Signal, transmitter: u8, line: u8) -> Connector {
    Connector {
        path: crate::amdgpu_dcn_inventory::Path {
            connector: match signal {
                Signal::Hdmi => crate::amdgpu_dcn_inventory::Connector::HdmiTypeA,
                Signal::DisplayPort => crate::amdgpu_dcn_inventory::Connector::DisplayPort,
            },
            connector_instance: 1,
            transmitter,
            aux: Some(line),
            hpd: line + 1,
            device_tag: 0,
            max_speed_mhz: 0,
        },
        signal,
        line,
        hpd: Some(line),
    }
}

/// A DP sink at the far end of the AUX channel: answers training with
/// clock recovery and equalization done on every lane, except at link
/// rates in `fail_rates`, where clock recovery never locks. AUX traffic is
/// logged into the register model so it shares the global order.
pub(crate) struct DpSink {
    pub model: Arc<Model>,
    pub dpcd: BTreeMap<u32, u8>,
    pub fail_rates: Vec<u8>,
    pub feature: u8,
}
impl DpSink {
    pub fn new(model: Arc<Model>) -> Self {
        Self {
            model,
            dpcd: BTreeMap::new(),
            fail_rates: Vec::new(),
            feature: 0,
        }
    }
}
impl crate::amdgpu_dcn30_dp::Aux for DpSink {
    async fn read(
        &mut self,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), crate::amdgpu_navi22_modeset::Error> {
        self.model.0.lock().log.push(Write {
            dword: AUX_READ | address,
            value: data.len() as u32,
        });
        let rate = *self.dpcd.get(&0x100).unwrap_or(&0);
        let locked = !self.fail_rates.contains(&rate);
        for (i, byte) in data.iter_mut().enumerate() {
            let at = address + i as u32;
            *byte = match at {
                0x202 | 0x203 if locked => 0x77,
                0x204 if locked => 0x01,
                0x2210 => self.feature,
                _ => 0,
            };
        }
        Ok(())
    }
    async fn write(
        &mut self,
        address: u32,
        data: &[u8],
    ) -> Result<(), crate::amdgpu_navi22_modeset::Error> {
        let mut s = self.model.0.lock();
        for (i, &byte) in data.iter().enumerate() {
            s.log.push(Write {
                dword: AUX_WRITE | (address + i as u32),
                value: u32::from(byte),
            });
            self.dpcd.insert(address + i as u32, byte);
        }
        Ok(())
    }
}

/// A VRAM pool over a heap buffer at the board's 0x80_0000_0000 aperture.
pub(crate) struct Vram {
    pub pool: crate::amdgpu_vram::Pool,
    _backing: Vec<u32>,
}
impl Vram {
    pub fn new(bytes: usize) -> Self {
        let mut backing = vec![0u32; bytes / 4];
        let mapping = narf_bus::MmioRegion {
            phys: narf_memory::PhysAddr::new(backing.as_mut_ptr() as u64),
            virt: backing.as_mut_ptr() as u64,
            len: bytes as u64,
            kind: narf_bus::BarKind::Mmio64 { prefetchable: true },
        };
        // SAFETY: the heap buffer is exclusively this pool's for the test.
        let pool =
            unsafe { crate::amdgpu_vram::Pool::from_owned_range(mapping, 0x80_0000_0000) }.unwrap();
        Self {
            pool,
            _backing: backing,
        }
    }
}
