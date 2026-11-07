//! GuC engine error capture: ADS register lists, STATE_CAPTURE output and the
//! device coredump's HW-engine snapshots.
//!
//! MIT Linux b90c984d615e8ce2af96f5b1411a962d83fed2ad: xe_guc_capture.c,
//! xe_guc_capture_types.h, abi/guc_capture_abi.h, abi/guc_log_abi.h,
//! xe_guc_log.h, xe_guc_ads.c::guc_capture_prep_lists and
//! xe_hw_engine.c::xe_hw_engine_snapshot_capture.
//!
//! Disclosure: an engine snapshot names GGTT/PPGTT addresses (RING_START,
//! ACTHD, BBADDR, DMA_FADD, HWS_PGA, CURRENT_LRCA, the GuC header's LRCA),
//! ring head/tail offsets, the instruction header in IPEHR, execlist status
//! and engine/error/interrupt state. It reaches only the CAP_SYSLOG-gated
//! coredump bundle, never the public first-error report. Every list, node and
//! text region has a fixed host bound; firmware lengths never extend one.

use alloc::{boxed::Box, vec::Vec};
use core::fmt::{self, Write};

use crate::{intel_gpu_engine::Engine, intel_gpu_gt::GtPlatform, intel_gpu_rcs::GpuBacking};

pub(crate) const PAGE: usize = 4096;
/// enum guc_state_capture_type.
pub(crate) const GLOBAL: usize = 0;
pub(crate) const CLASS: usize = 1;
pub(crate) const INSTANCE: usize = 2;
const TYPES: usize = 3;
/// GUC_CAPTURE_LIST_CLASS_MAX and GUC_CAPTURE_LIST_INDEX_MAX.
pub(crate) const CLASSES: usize = 5;
const OWNERS: usize = 2;
/// GUC_MAX_ENGINE_CLASSES: stride of guc_ads.capture_{instance,class}[owner].
const ADS_CLASSES: usize = 16;
/// guc_ads offsets of capture_instance, capture_class and capture_global.
pub(crate) const ADS_INSTANCE: u64 = 0x109c;
pub(crate) const ADS_CLASS: u64 = 0x111c;
pub(crate) const ADS_GLOBAL: u64 = 0x119c;
/// guc_mmio_reg.flags.
const STEERING_NEEDED: u32 = 1 << 1;
/// XE_MAX_DSS_FUSE_BITS.
const MAX_DSS: usize = 96;
/// PREALLOC_NODES_DEFAULT_NUMREGS.
const DEFAULT_NUMREGS: usize = 64;
/// NARF bound on retained parsed nodes; the source preallocates
/// PREALLOC_NODES_MAX_COUNT (1536). Reuse follows guc_capture_get_prealloc_node.
pub(crate) const NODES: usize = 4;
/// NARF bound on one parsed register list (the source sizes it by
/// guc_get_max_reglist_count, at most 4 + 6 * XE_MAX_DSS_FUSE_BITS).
pub(crate) const MAX_NODE_REGS: usize = 4 + 6 * MAX_DSS;
/// GUC_LOG_TYPE_STATE_CAPTURE's guc_log_buffer_state (36 bytes each).
pub(crate) const LOG_STATE: u64 = 2 * 36;
/// XE_GUC_LOG_STATE_CAPTURE_OFFSET and _BUFFER_SIZE (non-debug build).
pub(crate) const LOG_REGION: u64 = 0x1000 + 0x10000 + 0x4000;
pub(crate) const LOG_REGION_BYTES: u32 = 0x100000;
/// XE_GUC_ACTION_STATE_CAPTURE_NOTIFICATION and
/// XE_GUC_ACTION_LOG_BUFFER_FILE_FLUSH_COMPLETE.
pub(crate) const NOTIFICATION: u16 = 0x8002;
pub(crate) const FLUSH_COMPLETE: u16 = 0x30;
pub(crate) const LOG_TYPE_STATE_CAPTURE: u32 = 2;
/// NARF bound on capture groups parsed per notification.
const GROUPS: usize = 256;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Width {
    Dword,
    Low,
    High,
}

/// struct __guc_mmio_reg_descr. Engine-instance offsets are relative to the
/// engine's MMIO base; global and class offsets are absolute.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Descr {
    pub offset: u32,
    pub width: Width,
    pub flags: u32,
    pub mask: u32,
    pub dss: u32,
    pub name: &'static str,
}
const fn dw(offset: u32, name: &'static str) -> Descr {
    Descr {
        offset,
        width: Width::Dword,
        flags: 0,
        mask: 0,
        dss: 0,
        name,
    }
}
const fn low(offset: u32) -> Descr {
    Descr {
        offset,
        width: Width::Low,
        flags: 0,
        mask: 0,
        dss: 0,
        name: "",
    }
}
const fn high(offset: u32, name: &'static str) -> Descr {
    Descr {
        offset,
        width: Width::High,
        flags: 0,
        mask: 0,
        dss: 0,
        name,
    }
}

/// COMMON_XELP_BASE_GLOBAL.
const GLOBAL_REGS: [Descr; 1] = [dw(0xa188, "FORCEWAKE_GT")];
/// COMMON_BASE_ENGINE_INSTANCE (regs/xe_engine_regs.h offsets).
pub(crate) const INSTANCE_REGS: [Descr; 27] = [
    dw(0x98, "HWSTAM"),
    dw(0x80, "RING_HWS_PGA"),
    dw(0x34, "RING_HEAD"),
    dw(0x30, "RING_TAIL"),
    dw(0x3c, "RING_CTL"),
    dw(0x9c, "RING_MI_MODE"),
    dw(0x29c, "RING_MODE"),
    dw(0xb8, "RING_ESR"),
    dw(0xb4, "RING_EMR"),
    dw(0xb0, "RING_EIR"),
    dw(0xa8, "RING_IMR"),
    dw(0x68, "IPEHR"),
    dw(0x6c, "RING_INSTDONE"),
    dw(0x108, "INDIRECT_RING_STATE"),
    dw(0x240, "CURRENT_LRCA"),
    low(0x74),
    high(0x5c, "ACTHD"),
    low(0x140),
    high(0x168, "RING_BBADDR"),
    low(0x38),
    high(0x48, "RING_START"),
    low(0x78),
    high(0x60, "RING_DMA_FADD"),
    low(0x234),
    high(0x238, "RING_EXECLIST_STATUS"),
    low(0x510),
    high(0x514, "RING_EXECLIST_SQ_CONTENTS"),
];
/// COMMON_XELP_RC_CLASS + COMMON_XELP_RC_CLASS_INSTDONE (xe_rc_class_regs).
const XELP_RC_CLASS: [Descr; 4] = [
    dw(0x14800, "RCU_MODE"),
    dw(0x7100, "SC_INSTDONE"),
    dw(0x7104, "SC_INSTDONE_EXTRA"),
    dw(0x7108, "SC_INSTDONE_EXTRA2"),
];
/// xe_hpg_rc_class_regs.
const XEHPG_RC_CLASS: [Descr; 1] = [dw(0x14800, "RCU_MODE")];
/// XELP_VEC_CLASS_REGS.
const VEC_CLASS: [Descr; 4] = [
    dw(0x1cc000, "SFC_DONE[0]"),
    dw(0x1cd000, "SFC_DONE[1]"),
    dw(0x1ce000, "SFC_DONE[2]"),
    dw(0x1cf000, "SFC_DONE[3]"),
];
/// xe_extregs and xehpg_extregs.
const XE_EXT: [(u32, &str); 2] = [(0xe160, "SAMPLER_INSTDONE"), (0xe164, "ROW_INSTDONE")];
const XEHPG_EXT: [(u32, &str); 4] = [
    (0x7100, "SC_INSTDONE"),
    (0x7104, "SC_INSTDONE_EXTRA"),
    (0x7108, "SC_INSTDONE_EXTRA2"),
    (0x666c, "INSTDONE_GEOM_SVGUNIT"),
];

/// guc_capture_get_device_reglist. No NARF profile reaches Xe3p (35).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    XeLp,
    XeHpg,
}
impl Family {
    /// GRAPHICS_VERx100 >= 1255 selects xe_hpg_lists; Gen12 is 12.00.
    pub(crate) fn for_platform(platform: GtPlatform) -> Option<Self> {
        platform.guc()?;
        Some(if platform.is_gen12() {
            Self::XeLp
        } else {
            Self::XeHpg
        })
    }
    /// guc_capture_get_steer_reg_num.
    fn steer_regs(self) -> usize {
        XE_EXT.len()
            + if self == Self::XeHpg {
                XEHPG_EXT.len()
            } else {
                0
            }
    }
    /// guc_capture_get_one_list over the device lists: only the PF owns
    /// lists; `Some(&[])` is an intentional empty list.
    pub(crate) fn list(self, owner: usize, ty: usize, class: usize) -> Option<&'static [Descr]> {
        if owner != 0 || class >= CLASSES {
            return None;
        }
        match ty {
            GLOBAL => Some(&GLOBAL_REGS),
            CLASS => Some(match class {
                0 if self == Self::XeHpg => &XEHPG_RC_CLASS,
                0 => &XELP_RC_CLASS,
                2 => &VEC_CLASS,
                _ => &[],
            }),
            INSTANCE => Some(&INSTANCE_REGS),
            _ => None,
        }
    }
    /// xe_guc_capture_ads_input_worst_size, computed before the steered list
    /// exists (guc_cap_list_num_regs' XE_MAX_DSS_FUSE_BITS estimate).
    pub(crate) fn worst_size(self) -> usize {
        let mut total = PAGE;
        for owner in 0..OWNERS {
            for class in 0..CLASSES {
                for ty in [CLASS, INSTANCE] {
                    total += self.list_size(owner, ty, class, None).unwrap_or(0);
                }
            }
            total += self.list_size(owner, GLOBAL, 0, None).unwrap_or(0);
        }
        total.next_multiple_of(PAGE)
    }
    /// guc_capture_getlistsize (is_purpose_est = false). `steered` is the
    /// allocated extension list, or None before it exists.
    fn list_size(
        self,
        owner: usize,
        ty: usize,
        class: usize,
        steered: Option<&[Descr]>,
    ) -> Result<usize, CaptureError> {
        if owner == 0 && self.list(owner, ty, class).is_none() {
            return Err(CaptureError::NoDevice);
        }
        let count = self.num_regs(owner, ty, class, steered);
        if count == 0 {
            return Err(CaptureError::NoData);
        }
        Ok((4 + count * 16).next_multiple_of(PAGE))
    }
    /// guc_cap_list_num_regs.
    fn num_regs(self, owner: usize, ty: usize, class: usize, steered: Option<&[Descr]>) -> usize {
        let base = self.list(owner, ty, class).map_or(0, <[Descr]>::len);
        let rc_class = owner == 0 && ty == CLASS && class == 0;
        match steered {
            Some(ext) if rc_class && !ext.is_empty() => base + ext.len(),
            Some(_) => base,
            None if rc_class => base + self.steer_regs() * MAX_DSS,
            None => base,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum CaptureError {
    NoDevice,
    NoData,
    Io,
    NoMemory,
}

/// xe_engine_class_to_guc_capture_class.
pub(crate) fn capture_class(engine: Engine) -> usize {
    match engine.guc_class() {
        0 | 4 => 0,
        1 => 1,
        2 => 2,
        3 => 3,
        _ => 4,
    }
}

/// The registered lists of one GT: the device family plus the steered
/// render/compute class extension (guc_capture_alloc_steered_lists).
#[derive(Debug)]
pub(crate) struct Lists {
    family: Family,
    steered: Vec<Descr>,
    max_regs: usize,
}
impl Lists {
    /// `geometry`/`compute` are the fused DSS masks; `per_group` is
    /// xe_gt_mcr.c::dss_per_group. The steered list exists only for a GT
    /// with a render or compute engine, sized from the geometry mask as the
    /// source allocates it; DSS beyond that size are never written.
    pub(crate) fn new(
        family: Family,
        render_compute: bool,
        geometry: u128,
        compute: u128,
        per_group: u32,
    ) -> Result<Self, CaptureError> {
        let fused = (1u128 << MAX_DSS) - 1;
        let total = if render_compute {
            (geometry & fused).count_ones() as usize * family.steer_regs()
        } else {
            0
        };
        if per_group == 0 {
            return Err(CaptureError::NoDevice);
        }
        let mut steered = Vec::new();
        steered
            .try_reserve_exact(total)
            .map_err(|_| CaptureError::NoMemory)?;
        let ext = XE_EXT.iter().chain(if family == Family::XeHpg {
            XEHPG_EXT.iter()
        } else {
            [].iter()
        });
        'dss: for dss in (0..MAX_DSS).filter(|dss| ((geometry | compute) & fused) >> dss & 1 != 0) {
            let (group, instance) = (dss as u32 / per_group, dss as u32 % per_group);
            for &(offset, name) in ext.clone() {
                if steered.len() == total {
                    break 'dss;
                }
                steered.push(Descr {
                    offset,
                    width: Width::Dword,
                    flags: STEERING_NEEDED | (group & 0x1f) << 12 | (instance & 0xf) << 20,
                    mask: 0,
                    dss: dss as u32,
                    name,
                });
            }
        }
        // guc_get_max_reglist_count over every owner/type/class.
        let mut max_regs = 0;
        for owner in 0..OWNERS {
            for ty in 0..TYPES {
                for class in 0..CLASSES {
                    if ty == GLOBAL && class > 0 {
                        continue;
                    }
                    max_regs = max_regs.max(family.num_regs(owner, ty, class, Some(&steered)));
                }
            }
        }
        if max_regs == 0 {
            max_regs = DEFAULT_NUMREGS;
        }
        Ok(Self {
            family,
            steered,
            max_regs: max_regs.min(MAX_NODE_REGS),
        })
    }
    pub(crate) fn family(&self) -> Family {
        self.family
    }
    pub(crate) fn max_regs(&self) -> usize {
        self.max_regs
    }
    #[cfg(feature = "kernel-test")]
    pub(crate) fn steered(&self) -> &[Descr] {
        &self.steered
    }
    /// Bytes of the separate list allocation: the source's worst size.
    pub(crate) fn bytes(&self) -> usize {
        self.family.worst_size()
    }

    /// guc_capture_prep_lists: a zero-descriptor page, then per owner each
    /// present class's class and instance lists, then the global list. NARF
    /// places the lists in `lists` (its own GGTT allocation of `bytes()`)
    /// instead of inside the ADS object; the ADS pointers are GGTT addresses.
    /// `masks` are the per-capture-class enabled engine masks.
    pub(crate) fn write_ads(
        &self,
        ads: &impl GpuBacking,
        lists: &impl GpuBacking,
        masks: [u32; CLASSES],
    ) -> usize {
        let capacity = lists.size_pages() as usize * PAGE;
        lists.zero_fill();
        let base = lists.ggtt_offset();
        let null = base;
        let mut offset = PAGE;
        let mut total = PAGE;
        let mut place = |owner: usize, ty: usize, class: usize| -> u32 {
            let Ok(size) = self.family.list_size(owner, ty, class, Some(&self.steered)) else {
                return null;
            };
            if total + size > capacity {
                return null;
            }
            let count = self.family.num_regs(owner, ty, class, Some(&self.steered));
            lists.write32(offset as u64, (count as u32) & 0xffff);
            let entries = self
                .family
                .list(owner, ty, class)
                .unwrap_or(&[])
                .iter()
                .chain(self.ext(owner, ty, class).iter());
            for (index, descr) in entries.take(count).enumerate() {
                let at = (offset + 4 + index * 16) as u64;
                lists.write32(at, descr.offset);
                lists.write32(at + 4, 0xdeadf00d);
                lists.write32(at + 8, descr.flags);
                lists.write32(at + 12, descr.mask);
            }
            let address = base + offset as u32;
            total += size;
            offset += size;
            address
        };
        for owner in 0..OWNERS {
            for (class, mask) in masks.iter().enumerate() {
                let slot = ((owner * ADS_CLASSES + class) * 4) as u64;
                if *mask == 0 {
                    ads.write32(ADS_CLASS + slot, null);
                    ads.write32(ADS_INSTANCE + slot, null);
                    continue;
                }
                let address = place(owner, CLASS, class);
                ads.write32(ADS_CLASS + slot, address);
                let address = place(owner, INSTANCE, class);
                ads.write32(ADS_INSTANCE + slot, address);
            }
            let address = place(owner, GLOBAL, 0);
            ads.write32(ADS_GLOBAL + owner as u64 * 4, address);
        }
        total.next_multiple_of(PAGE)
    }
    fn ext(&self, owner: usize, ty: usize, class: usize) -> &[Descr] {
        if owner == 0 && ty == CLASS && class == 0 {
            &self.steered
        } else {
            &[]
        }
    }
}

/// struct guc_mmio_reg.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Reg {
    pub offset: u32,
    pub value: u32,
    pub flags: u32,
    pub mask: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    GuC,
    Manual,
}

/// struct __guc_capture_parsed_output with fixed preallocated lists.
pub(crate) struct Node {
    pub partial: bool,
    pub class: u32,
    pub instance: u32,
    pub guc_id: u32,
    pub lrca: u32,
    pub source: Source,
    kind: usize,
    locked: bool,
    vfid: [u32; TYPES],
    count: [usize; TYPES],
    regs: [Box<[Reg]>; TYPES],
    /// NARF: a manual read stopped when current wake/authority ended.
    pub lost: bool,
}
impl Node {
    pub(crate) fn new(max: usize) -> Result<Self, CaptureError> {
        let make = || -> Result<Box<[Reg]>, CaptureError> {
            let mut regs = Vec::new();
            regs.try_reserve_exact(max)
                .map_err(|_| CaptureError::NoMemory)?;
            regs.resize(max, Reg::default());
            Ok(regs.into_boxed_slice())
        };
        Ok(Self {
            partial: false,
            class: 0,
            instance: 0,
            guc_id: 0,
            lrca: 0,
            source: Source::GuC,
            kind: 0,
            locked: false,
            vfid: [0; TYPES],
            count: [0; TYPES],
            regs: [make()?, make()?, make()?],
            lost: false,
        })
    }
    /// guc_capture_init_node.
    fn init(&mut self) {
        for list in &mut self.regs {
            list.fill(Reg::default());
        }
        self.partial = false;
        self.class = 0;
        self.instance = 0;
        self.guc_id = 0;
        self.lrca = 0;
        self.source = Source::GuC;
        self.kind = 0;
        self.locked = false;
        self.vfid = [0; TYPES];
        self.count = [0; TYPES];
        self.lost = false;
    }
    pub(crate) fn list(&self, ty: usize) -> &[Reg] {
        &self.regs[ty][..self.count[ty]]
    }
    fn capacity(&self) -> usize {
        self.regs[0].len()
    }

    /// xe_engine_manual_capture for one engine: global, class and instance
    /// lists in source order. `read` returns None once current wake or PCI
    /// authority is lost; capture stops there, never retrying. NARF omits the
    /// steered render/compute extension unless `capture_manual_steered` is called.
    /// guc_id and LRCA stay zero, as the source's node is taken before its
    /// devcoredump is captured.
    pub(crate) fn capture_manual(
        &mut self,
        family: Family,
        engine: Engine,
        read: impl FnMut(u64) -> Option<u32>,
    ) {
        self.capture_manual_steered(family, engine, None, read, |_, _, _| None);
    }

    /// `capture_manual` including steered render/compute extension registers
    /// when `steered` is provided. `read_steered` is called with (offset, group, instance).
    pub(crate) fn capture_manual_steered(
        &mut self,
        family: Family,
        engine: Engine,
        steered: Option<&[Descr]>,
        mut read: impl FnMut(u64) -> Option<u32>,
        mut read_steered: impl FnMut(u32, u32, u32) -> Option<u32>,
    ) {
        self.init();
        let class = capture_class(engine);
        let mut partial = false;
        'types: for ty in 0..TYPES {
            let Some(list) = family.list(0, ty, class) else {
                continue;
            };
            for (index, descr) in list.iter().enumerate().take(self.capacity()) {
                let address = if ty == INSTANCE {
                    u64::from(engine.base()) + u64::from(descr.offset)
                } else {
                    u64::from(descr.offset)
                };
                let Some(value) = read(address) else {
                    self.lost = true;
                    break 'types;
                };
                self.regs[ty][index] = Reg {
                    offset: descr.offset,
                    value,
                    flags: descr.flags,
                    mask: descr.mask,
                };
                self.count[ty] = index + 1;
            }
        }
        if class == 0 && !self.lost {
            if let Some(steered_list) = steered {
                for descr in steered_list {
                    if self.count[CLASS] >= self.capacity() {
                        partial = true;
                        break;
                    }
                    let group = (descr.flags >> 12) & 0x1f;
                    let instance = (descr.flags >> 20) & 0xf;
                    let Some(value) = read_steered(descr.offset, group, instance) else {
                        self.lost = true;
                        break;
                    };
                    let index = self.count[CLASS];
                    self.regs[CLASS][index] = Reg {
                        offset: descr.offset,
                        value,
                        flags: descr.flags,
                        mask: descr.mask,
                    };
                    self.count[CLASS] += 1;
                }
            }
        }
        self.class = engine.guc_class();
        self.instance = engine.physical_instance();
        self.partial = partial;
        self.locked = true;
        self.source = Source::Manual;
    }
}

/// struct __guc_capture_bufstate.
struct Ring {
    size: u32,
    data: u64,
    rd: u32,
    wr: u32,
}
impl Ring {
    fn count(&self) -> u32 {
        if self.wr >= self.rd {
            self.wr - self.rd
        } else {
            (self.size - self.rd) + self.wr
        }
    }
    fn count_to_end(&self) -> u32 {
        if self.rd > self.wr {
            self.size - self.rd
        } else {
            self.wr - self.rd
        }
    }
}

/// The parsed-node pool: guc->capture->{cachelist,outlist}. Both lists are
/// head-first (list_add inserts at the head).
pub(crate) struct Pool {
    nodes: Vec<Node>,
    out: Vec<usize>,
    cache: Vec<usize>,
    max: usize,
    overflow: u32,
    /// Extractions that ended in an error (diagnostic only).
    pub errors: u32,
}
impl Pool {
    pub(crate) fn new(lists: &Lists) -> Result<Self, CaptureError> {
        let mut nodes = Vec::new();
        nodes
            .try_reserve_exact(NODES)
            .map_err(|_| CaptureError::NoMemory)?;
        let mut out = Vec::new();
        out.try_reserve_exact(NODES)
            .map_err(|_| CaptureError::NoMemory)?;
        let mut cache = Vec::new();
        cache
            .try_reserve_exact(NODES)
            .map_err(|_| CaptureError::NoMemory)?;
        for index in 0..NODES {
            nodes.push(Node::new(lists.max_regs)?);
            cache.insert(0, index);
        }
        Ok(Self {
            nodes,
            out,
            cache,
            max: lists.max_regs,
            overflow: 0,
            errors: 0,
        })
    }
    pub(crate) fn node(&self, index: usize) -> &Node {
        &self.nodes[index]
    }
    /// Retained outlist indices, newest first.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn outlist(&self) -> &[usize] {
        &self.out
    }

    /// guc_capture_get_prealloc_node. With an empty cache the source's
    /// reverse walk keeps the last unlocked node it visits: the newest.
    fn prealloc(&mut self) -> Option<usize> {
        let found = if self.cache.is_empty() {
            let at = self
                .out
                .iter()
                .position(|&index| !self.nodes[index].locked)?;
            self.out.remove(at)
        } else {
            self.cache.remove(0)
        };
        self.nodes[found].init();
        Some(found)
    }
    fn free(&mut self, index: usize) {
        self.nodes[index].locked = false;
        if let Some(at) = self.out.iter().position(|&n| n == index) {
            self.out.remove(at);
        }
        self.cache.insert(0, index);
    }
    /// guc_capture_add_node_to_outlist after removing stale same-guc_id nodes.
    fn add_out(&mut self, index: usize) {
        self.remove_stale(index);
        self.out.insert(0, index);
    }
    fn remove_stale(&mut self, index: usize) {
        let guc_id = self.nodes[index].guc_id;
        while let Some(&stale) = self
            .out
            .iter()
            .find(|&&n| n != index && !self.nodes[n].locked && self.nodes[n].guc_id == guc_id)
        {
            self.free(stale);
        }
    }
    /// guc_capture_clone_node.
    fn clone_node(&mut self, original: usize, keep: u32) -> Option<usize> {
        let new = self.prealloc()?;
        if new == original {
            // The prealloc reclaimed the original itself: its lists are gone.
            return Some(new);
        }
        let (from, to) = if original < new {
            let (a, b) = self.nodes.split_at_mut(new);
            (&a[original], &mut b[0])
        } else {
            let (a, b) = self.nodes.split_at_mut(original);
            (&b[0], &mut a[new])
        };
        to.partial = from.partial;
        for ty in 0..TYPES {
            if keep & 1 << ty == 0 {
                continue;
            }
            let count = from.count[ty];
            to.regs[ty][..count].copy_from_slice(&from.regs[ty][..count]);
            to.count[ty] = count;
            to.vfid[ty] = from.vfid[ty];
            if ty == CLASS {
                to.class = from.class;
            } else if ty == INSTANCE {
                to.instance = from.instance;
                to.guc_id = from.guc_id;
                to.lrca = from.lrca;
            }
        }
        Some(new)
    }

    /// __guc_capture_process_output over the GuC log's capture region.
    /// Returns false when current access ended; the read pointer then stays
    /// unpublished and no flush-complete is due.
    pub(crate) fn process(
        &mut self,
        log: &impl GpuBacking,
        mut access: impl FnMut() -> bool,
    ) -> bool {
        if !log.coherent_for_device()
            || u64::from(log.size_pages()) * PAGE as u64 != LOG_REGION + u64::from(LOG_REGION_BYTES)
            || !access()
        {
            return false;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let state: [u32; 9] = core::array::from_fn(|i| log.read32(LOG_STATE + i as u64 * 4));
        let (mut read, mut write) = (state[2], state[5]);
        let full = (state[7] >> 1) & 0xf;
        // xe_guc_check_log_buf_overflow on the 4-bit counter.
        let overflow = full != self.overflow;
        if overflow {
            let previous = self.overflow;
            self.overflow = self.overflow.wrapping_add(full.wrapping_sub(previous));
            if full < previous {
                self.overflow = self.overflow.wrapping_add(16);
            }
        }
        if overflow || read > LOG_REGION_BYTES || write > LOG_REGION_BYTES {
            read = 0;
            write = LOG_REGION_BYTES;
        }
        let mut ring = Ring {
            size: LOG_REGION_BYTES,
            data: LOG_REGION,
            rd: read,
            wr: write,
        };
        for _ in 0..GROUPS {
            if !access() {
                return false;
            }
            match self.extract(&mut ring, log) {
                Ok(()) => {}
                Err(CaptureError::NoData) => break,
                Err(_) => {
                    self.errors = self.errors.saturating_add(1);
                    break;
                }
            }
        }
        if !access() {
            return false;
        }
        log.write32(LOG_STATE + 8, write);
        log.write32(LOG_STATE + 28, state[7] & !1);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        true
    }

    /// guc_capture_log_remove_bytes for whole dwords.
    fn remove(&self, ring: &mut Ring, log: &impl GpuBacking, out: &mut [u32]) -> bool {
        let mut needed = out.len() as u32 * 4;
        if needed > ring.count() {
            return false;
        }
        let mut filled = 0u32;
        let mut tries = 3;
        while needed > 0 && tries > 0 {
            tries -= 1;
            let avail = ring.count_to_end();
            let misaligned = avail % 4;
            if avail == 0 {
                if ring.rd == 0 {
                    return filled == out.len() as u32 * 4;
                }
                ring.rd = 0;
                continue;
            }
            let size = if avail < needed {
                avail - misaligned
            } else {
                needed
            };
            for word in 0..size / 4 {
                out[((filled / 4) + word) as usize] =
                    read_unaligned(log, ring.data + u64::from(ring.rd + word * 4));
            }
            ring.rd += size;
            filled += size;
            needed -= size;
        }
        filled == out.len() as u32 * 4
    }

    /// guc_capture_extract_reglists.
    fn extract(&mut self, ring: &mut Ring, log: &impl GpuBacking) -> Result<(), CaptureError> {
        let available = ring.count();
        if available == 0 {
            return Err(CaptureError::NoData);
        }
        let mut node: Option<usize> = None;
        let mut result = Ok(());
        let mut group = [0u32; 2];
        if available % 4 != 0 || !self.remove(ring, log, &mut group) {
            return Err(CaptureError::Io);
        }
        let partial = (group[1] >> 8) & 0xff != 0;
        let mut lists = group[1] & 0xff;
        while lists > 0 {
            lists -= 1;
            let mut header = [0u32; 5];
            if !self.remove(ring, log, &mut header) {
                result = Err(CaptureError::Io);
                break;
            }
            let ty = (header[1] & 0xf) as usize;
            let registers = (header[4] & 0x3ff) as usize;
            if ty > INSTANCE {
                let mut skipped = [0u32; 4];
                for _ in 0..registers {
                    if !self.remove(ring, log, &mut skipped) {
                        result = Err(CaptureError::Io);
                        break;
                    }
                }
                continue;
            } else if let Some(current) = node {
                if ty == GLOBAL {
                    self.add_out(current);
                    node = None;
                } else if ty == CLASS && self.nodes[current].count[CLASS] != 0 {
                    self.add_out(current);
                    node = self.clone_node(current, 1 << GLOBAL);
                } else if ty == INSTANCE && self.nodes[current].count[INSTANCE] != 0 {
                    self.add_out(current);
                    node = self.clone_node(current, 1 << GLOBAL | 1 << CLASS);
                }
            }
            let current = match node {
                Some(current) => current,
                None => match self.prealloc() {
                    Some(current) => {
                        node = Some(current);
                        current
                    }
                    None => {
                        result = Err(CaptureError::NoMemory);
                        break;
                    }
                },
            };
            let n = &mut self.nodes[current];
            n.partial = partial;
            n.vfid[ty] = header[0] & 0xff;
            n.source = Source::GuC;
            n.kind = ty;
            if ty == INSTANCE {
                n.class = (header[1] >> 4) & 0xf;
                n.instance = (header[1] >> 8) & 0xf;
                n.lrca = header[2];
                n.guc_id = header[3];
            } else if ty == CLASS {
                n.class = (header[1] >> 4) & 0xf;
            }
            let registers = registers.min(self.max);
            self.nodes[current].count[ty] = registers;
            for index in 0..registers {
                let mut words = [0u32; 4];
                if !self.remove(ring, log, &mut words) {
                    result = Err(CaptureError::Io);
                    break;
                }
                self.nodes[current].regs[ty][index] = Reg {
                    offset: words[0],
                    value: words[1],
                    flags: words[2],
                    mask: words[3],
                };
            }
        }
        // Every preallocated node owns register storage: keep it for matching.
        if let Some(current) = node {
            self.add_out(current);
        }
        result
    }

    /// xe_guc_capture_get_matching_and_lock's search, newest first, for a
    /// queue's template GuC class, GuC id and LRCA. NARF accepts any
    /// reported physical instance among the queue's placements; the source
    /// compares only q->hwe. The coredump reads under the GT owner's shared
    /// borrow; extraction needs its exclusive borrow, so the source's lock
    /// becomes the deferred `State::matched` release.
    pub(crate) fn find_match(
        &self,
        guc_class: u32,
        instance: impl Fn(u32) -> bool,
        guc_id: u32,
        lrca: u32,
    ) -> Option<usize> {
        self.out.iter().copied().find(|&index| {
            let n = &self.nodes[index];
            n.class == guc_class
                && instance(n.instance)
                && n.guc_id == guc_id
                && n.lrca == lrca
                && n.source == Source::GuC
        })
    }
    /// xe_guc_capture_put_matched_nodes.
    pub(crate) fn put_matched(&mut self, index: usize) {
        if index >= self.nodes.len() || !self.out.contains(&index) {
            return;
        }
        self.nodes[index].locked = true;
        self.remove_stale(index);
        self.free(index);
    }
}

/// One GT's opt-in GuC error capture: registered lists, the parsed-node pool,
/// header facts cached at preparation and the deferred matched-node release.
pub(crate) struct State {
    pub lists: alloc::sync::Arc<Lists>,
    pub pool: Pool,
    pub device: Device,
    matched: core::sync::atomic::AtomicUsize,
    ack_pending: bool,
}
impl State {
    pub(crate) fn new(
        lists: alloc::sync::Arc<Lists>,
        device: Device,
    ) -> Result<Self, CaptureError> {
        let pool = Pool::new(&lists)?;
        Ok(Self {
            lists,
            pool,
            device,
            matched: core::sync::atomic::AtomicUsize::new(0),
            ack_pending: false,
        })
    }
    /// Record the node a coredump consumed; released at the next `settle`.
    pub(crate) fn consumed(&self, index: usize) {
        self.matched
            .store(index + 1, core::sync::atomic::Ordering::Release);
    }
    /// xe_guc_capture_put_matched_nodes for the last consumed node.
    pub(crate) fn settle(&mut self) {
        let matched = self.matched.swap(0, core::sync::atomic::Ordering::AcqRel);
        if let Some(index) = matched.checked_sub(1) {
            self.pool.put_matched(index);
        }
    }
    /// One STATE_CAPTURE_NOTIFICATION: extract, then owe the flush-complete.
    pub(crate) fn notified(&mut self, log: &impl GpuBacking, access: impl FnMut() -> bool) {
        self.settle();
        if self.pool.process(log, access) {
            self.ack_pending = true;
        }
    }
    /// __guc_capture_flushlog_complete is owed (retried while the CT is full).
    pub(crate) fn ack_pending(&self) -> bool {
        self.ack_pending
    }
    pub(crate) fn acknowledged(&mut self) {
        self.ack_pending = false;
    }
}

/// xe_device_snapshot_print facts, sampled once at preparation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Device {
    pub device_id: u16,
    pub revision: u8,
    /// GMD_ID; zero on pre-GMD platforms (Gen12, DG2), as gt->info.gmdid.
    pub gmd_id: u32,
    pub reference_clock: Option<u32>,
}

/// Lanes and workqueue dwords retained per queue snapshot (NARF bounds).
pub(crate) const QUEUE_LANES: usize = 8;
pub(crate) const WQ_ENTRIES: usize = 64;

/// guc_exec_queue_wq_snapshot_capture over NARF's single-use 1 KiB queue.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Wq {
    pub head: u32,
    pub tail: u32,
    pub status: u32,
    pub internal_tail: u32,
    pub entries: [u32; WQ_ENTRIES],
    pub count: u8,
}

/// xe_guc_exec_queue_snapshot_capture + xe_sched_job_snapshot_capture
/// facts NARF owns for the first guilty context.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Queue {
    pub id: u16,
    pub lrca: u32,
    pub engine: Engine,
    pub placements: crate::intel_gpu_engine::EngineSet,
    pub logical_mask: u32,
    pub width: u8,
    pub stamp: u32,
    pub kernel: bool,
    pub priority: u32,
    pub timeslice_us: u32,
    pub low_latency: bool,
    pub phase: super::ContextPhase,
    pub timed_out: bool,
    pub reset: bool,
    pub batches: [u64; QUEUE_LANES],
    pub batch_count: u8,
    pub wq: Option<Wq>,
    pub comm: Option<&'static str>,
    pub pid: Option<u32>,
    pub snapshot_time: Option<(u64, u32)>,
}
/// xe_guc_submit.c's job timeout and the PREEMPTION_TIMEOUT policy NARF sends.
const JOB_TIMEOUT_MS: u32 = 5000;
const PREEMPT_TIMEOUT_US: u32 = 500_000;
impl Queue {
    #[allow(dead_code)]
    pub(crate) fn with_process(mut self, name: &'static str, pid: u32) -> Self {
        self.comm = Some(name);
        self.pid = Some(pid);
        self
    }
    #[allow(dead_code)]
    pub(crate) fn with_snapshot_time(mut self, secs: u64, nanos: u32) -> Self {
        self.snapshot_time = Some((secs, nanos));
        self
    }
    /// EXEC_QUEUE_STATE_* bits NARF's phases imply: REGISTERED(0),
    /// ENABLED(1), PENDING_ENABLE(2), PENDING_DISABLE(3), RESET(6), BANNED(9).
    fn schedule_state(&self) -> u32 {
        use super::ContextPhase as P;
        let mut state = match self.phase {
            P::Policy | P::Enable | P::Deregister | P::Deregistering => 1,
            P::Enabling => 1 | 4,
            P::Running | P::Disable => 1 | 2,
            P::Disabling => 1 | 8,
            _ => 0,
        };
        if self.reset {
            state |= 1 << 6;
        }
        if self.timed_out || self.reset {
            state |= 1 << 9;
        }
        state
    }
    /// EXEC_QUEUE_FLAG_KERNEL(0) and EXEC_QUEUE_FLAG_LOW_LATENCY(5).
    fn flags(&self) -> u32 {
        u32::from(self.kernel) | u32::from(self.low_latency) << 5
    }
    fn prefix(&self) -> &'static str {
        match self.engine.xe_class() {
            0 => "rcs",
            1 => "bcs",
            2 => "vcs",
            3 => "vecs",
            4 => "ccs",
            _ => "gsccs",
        }
    }
}

/// `__xe_devcoredump_read` in source order. NARF keeps the GuC log, CT,
/// LRC/ring bodies and VM state as the bundle's binary sections; this text
/// names their header offsets instead of re-encoding them in ascii85.
// Each argument is one input __xe_devcoredump_read prints from; grouping
// them would only rename the parameters.
#[allow(clippy::too_many_arguments)]
pub(crate) fn print_dump(
    out: &mut impl Write,
    device: &Device,
    report: &super::Report,
    queue: Option<&Queue>,
    engine: Option<(Facts, &Node)>,
    lists: &Lists,
    nospace: u32,
    errors: u32,
) -> fmt::Result {
    writeln!(out, "**** Xe Device Coredump ****")?;
    match queue {
        Some(queue)
            if matches!(
                report.capture.reason,
                super::Reason::Timeout | super::Reason::EngineReset
            ) =>
        {
            writeln!(
                out,
                "Reason: Timedout job - seqno={}, lrc_seqno={}, guc_id={}, flags=0x{:x}",
                queue.stamp,
                queue.stamp,
                queue.id,
                queue.flags()
            )?
        }
        _ => writeln!(out, "Reason: NARF GT failure: {:?}", report.capture.reason)?,
    }
    writeln!(out, "kernel: narf")?;
    writeln!(out, "module: narf-drivers-gpu")?;
    let snapshot_time = queue
        .and_then(|q| q.snapshot_time)
        .or(report.capture.snapshot_time);
    match snapshot_time {
        Some((secs, nanos)) => writeln!(out, "Snapshot time: {secs}.{nanos:09}")?,
        None => writeln!(out, "Snapshot time: unavailable")?,
    }
    writeln!(
        out,
        "Uptime: {}.{:09}",
        report.capture.now_ns / 1_000_000_000,
        report.capture.now_ns % 1_000_000_000
    )?;
    let process = queue
        .and_then(|q| q.comm.zip(q.pid))
        .or_else(|| report.capture.process_name.zip(report.capture.pid));
    match process {
        Some((name, pid)) => writeln!(out, "Process: {name} [{pid}]")?,
        None => writeln!(out, "Process: unavailable")?,
    }
    writeln!(out, "PCI ID: 0x{:04x}", device.device_id)?;
    writeln!(out, "PCI revision: 0x{:02x}", device.revision)?;
    writeln!(out, "GT id: 0\n\tTile: 0\n\tType: main")?;
    writeln!(
        out,
        "\tIP ver: {}.{}.{}",
        device.gmd_id >> 22,
        (device.gmd_id >> 14) & 0xff,
        device.gmd_id & 0x3f
    )?;
    match device.reference_clock {
        Some(clock) => writeln!(out, "\tCS reference clock: {clock}")?,
        None => writeln!(out, "\tCS reference clock: unavailable")?,
    }
    writeln!(out, "\n**** GT #0 ****\n\tTile: 0")?;
    writeln!(
        out,
        "\n**** GuC Log ****\nNARF: binary section at header 120/124"
    )?;
    writeln!(
        out,
        "\n**** GuC CT ****\nNARF: binary section at header 128/132"
    )?;
    writeln!(out, "\n**** Contexts ****")?;
    if let Some(queue) = queue {
        writeln!(out, "GuC ID: {}", queue.id)?;
        writeln!(out, "\tName: {}{}", queue.prefix(), queue.id)?;
        writeln!(out, "\tClass: {}", queue.engine.xe_class())?;
        writeln!(out, "\tLogical mask: 0x{:x}", queue.logical_mask)?;
        writeln!(out, "\tWidth: {}", queue.width)?;
        writeln!(out, "\tRef: unavailable")?;
        writeln!(out, "\tTimeout: {JOB_TIMEOUT_MS} (ms)")?;
        writeln!(out, "\tTimeslice: {} (us)", queue.timeslice_us)?;
        writeln!(out, "\tPreempt timeout: {PREEMPT_TIMEOUT_US} (us)")?;
        writeln!(
            out,
            "\tNARF: LRC, ring and scratch bodies in the execution section"
        )?;
        writeln!(out, "\tSchedule State: 0x{:x}", queue.schedule_state())?;
        writeln!(out, "\tFlags: 0x{:x}", queue.flags())?;
        writeln!(
            out,
            "\tNARF phase: {:?} priority: {}",
            queue.phase, queue.priority
        )?;
        if let Some(wq) = &queue.wq {
            writeln!(out, "\tWQ head: 0 (internal), {} (memory)", wq.head)?;
            writeln!(
                out,
                "\tWQ tail: {} (internal), {} (memory)",
                wq.internal_tail, wq.tail
            )?;
            writeln!(out, "\tWQ status: {}", wq.status)?;
            let mut at = wq.head;
            for entry in &wq.entries[..usize::from(wq.count)] {
                writeln!(out, "\tWQ[{}]: 0x{:08x}", (at % 1024) / 4, entry)?;
                at = (at + 4) % 1024;
            }
        }
    }
    writeln!(out, "\n**** Job ****")?;
    if let Some(queue) = queue {
        for (lane, address) in queue.batches[..usize::from(queue.batch_count)]
            .iter()
            .enumerate()
        {
            writeln!(out, "batch_addr[{lane}]: 0x{address:016x}")?;
        }
    }
    writeln!(out, "\n**** HW Engines ****")?;
    if nospace != 0 || errors != 0 {
        writeln!(
            out,
            "NARF: GuC capture no-space notifications {nospace}, extraction errors {errors}"
        )?;
    }
    if let Some((facts, node)) = engine {
        print(out, facts, node, lists)?;
    }
    writeln!(
        out,
        "\n**** VM state ****\nNARF: binary section at header 160/164"
    )
}

fn read_unaligned(log: &impl GpuBacking, at: u64) -> u32 {
    if at % 4 == 0 {
        return log.read32(at);
    }
    let shift = (at % 4) * 8;
    let first = log.read32(at & !3) >> shift;
    let second = log.read32((at & !3) + 4) << (32 - shift);
    first | second
}

/// Fixed snapshot facts beside a node (struct xe_hw_engine_snapshot).
#[derive(Copy, Clone, Debug)]
pub(crate) struct Facts {
    pub engine: Engine,
    pub logical: u16,
    /// NARF holds the GT/render wake as one kernel request; 1 when the
    /// current wake proof held at snapshot time.
    pub wake_ref: u32,
}

/// xe_hw_engine.c domain of each engine (enum xe_force_wake_domains).
pub(crate) fn forcewake_domain(engine: Engine) -> u32 {
    match engine.guc_class() {
        1 => 1 << (3 + engine.physical_instance()),
        2 => 1 << (11 + engine.physical_instance()),
        5 => 1 << 15,
        _ => 1 << 1,
    }
}

/// xe_engine_snapshot_print. Registers absent from the node are skipped,
/// as snapshot_print_by_list_order does; no live register is read.
pub(crate) fn print(
    out: &mut impl Write,
    snapshot: Facts,
    node: &Node,
    lists: &Lists,
) -> fmt::Result {
    let class = capture_class(snapshot.engine);
    writeln!(
        out,
        "{} (physical), logical instance={}",
        super::engine_name(snapshot.engine),
        snapshot.logical
    )?;
    writeln!(
        out,
        "\tCapture_source: {}",
        if node.source == Source::GuC {
            "GuC"
        } else {
            "Manual"
        }
    )?;
    writeln!(
        out,
        "\tCoverage: {}",
        if node.partial {
            "partial-capture"
        } else {
            "full-capture"
        }
    )?;
    writeln!(
        out,
        "\tForcewake: domain 0x{:x}, ref {}",
        forcewake_domain(snapshot.engine),
        snapshot.wake_ref
    )?;
    // NARF reserves no published engine (the source reserves GSCCS, CCS
    // beyond ccs_mode and the USM copy engine).
    writeln!(out, "\tReserved: no")?;
    for ty in 0..TYPES {
        if let Some(list) = lists.family.list(0, ty, class) {
            print_by_list_order(out, node.list(ty), list)?;
        }
    }
    if class == 0 {
        print_by_list_order(out, node.list(CLASS), &lists.steered)?;
    }
    writeln!(out)
}

fn print_by_list_order(out: &mut impl Write, regs: &[Reg], list: &[Descr]) -> fmt::Result {
    let mut last = 0u32;
    let mut current_dss: Option<u32> = None;
    for descr in list {
        let Some(reg) = regs
            .iter()
            .find(|reg| reg.offset == descr.offset && reg.flags == descr.flags)
        else {
            continue;
        };
        if descr.flags & STEERING_NEEDED != 0 {
            if current_dss != Some(descr.dss) {
                writeln!(out, "\tDSS_{}:", descr.dss)?;
                current_dss = Some(descr.dss);
            }
            writeln!(out, "\t\t{}: 0x{:08x}", descr.name, reg.value)?;
            continue;
        }
        match descr.width {
            Width::Low => last = reg.value,
            Width::High => writeln!(
                out,
                "\t{}: 0x{:016x}",
                descr.name,
                u64::from(reg.value) << 32 | u64::from(last)
            )?,
            Width::Dword => writeln!(out, "\t{}: 0x{:08x}", descr.name, reg.value)?,
        }
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_guc_capture_tests.rs"]
mod tests;
