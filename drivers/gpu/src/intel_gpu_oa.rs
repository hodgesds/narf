//! Xe OA observation streams, pinned MIT Linux
//! b90c984d615e8ce2af96f5b1411a962d83fed2ad xe_oa.c, xe_oa_types.h,
//! regs/xe_oa_regs.h, xe_observation.c and xe_query.c::query_oa_units.
//!
//! Only the main-GT OAG unit of the qualified DG2 (12.55), MTL/Arrow
//! (12.70/12.71/12.74), BMG (20.01/20.02) and LNL (20.04) profiles is
//! published. Its one GGTT buffer is preallocated (16 MiB) before
//! scheduling and is retained by the GT owner; a stream that opens a
//! larger buffer, up to the 128 MiB Linux maximum, grows it at attach.
//! Hardware head/tail and register programming run only under that owner. Metric configurations are emitted as source
//! MI_LOAD_REGISTER_IMM groups from privileged kernel ring jobs.
use crate::{
    drm::syncobj::SyncObjTable,
    intel_gpu_aux::MmioWindow,
    intel_gpu_engine::{Engine, EngineSet},
    intel_gpu_gt::GtPlatform,
    intel_gpu_guc_boot::BootAllocator,
    intel_gpu_rcs::GpuBacking,
    intel_gpu_uapi::{put32, put64, u32_at, u64_at},
    intel_gpu_user::{UserBackend, UserContext},
    intel_gpu_xe_sync::Sync as XeSync,
};
use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{fence, AtomicBool, AtomicU32, Ordering};
use narf_filesystem::{
    FileOps, FileType, FsError, FsFuture, IoctlContext, MmapBacking, MmapLifetime, Mode,
    PrivatePfnMap, ReadOptions, Stat, POLL_ERR, POLL_HUP, POLL_IN,
};
use narf_lib::{mutex::Mutex, readiness::Readiness, sync::IrqSafeSpinLock};

/// DEFAULT_POLL_FREQUENCY_HZ 200.
pub(crate) const POLL_NS: u64 = 1_000_000_000 / 200;
/// DEFAULT_XE_OA_BUFFER_SIZE; also the preallocated NARF reservation.
/// A stream that opens a larger buffer, up to MAX_BUFFER, grows the
/// reservation at attach; the reservation never shrinks.
pub(crate) const DEFAULT_BUFFER: u32 = 16 << 20;
/// The Linux OA buffer range (`include/uapi/drm/xe_drm.h:3853-3861`):
/// 128 KiB..=128 MiB, power of two, enforced on property 12.
const MIN_BUFFER: u64 = 128 << 10;
const MAX_BUFFER: u64 = 128 << 20;
/// NOA_PROGRAM_ADDITIONAL_DELAY_US after the configuration job retires.
pub(crate) const NOA_DELAY_NS: u64 = 500_000;
const MAX_USER_EXTENSIONS: usize = 16;
const MAX_SYNCS: u64 = 2;
/// MI_LOAD_REGISTER_IMM_MAX_REGS.
const LRI_GROUP: usize = 126;
/// Registers per privileged ring job. Jobs retire in order before the next
/// is queued, preserving the single-batch register order of the source.
pub(crate) const LRI_JOB: usize = 3 * LRI_GROUP;
/// NARF allocation bounds where Linux relies on kmalloc failure (ENOMEM)
/// and an INT_MAX idr (ENOSPC).
pub(crate) const MAX_CONFIG_REGS: u32 = 4096;
const MAX_REGISTRY_REGS: usize = 1 << 17;
const MAX_CONFIGS: u32 = 1024;
/// DRM_XE_OA_CAPS_BASE | SYNCS | OA_BUFFER_SIZE | WAIT_NUM_REPORTS | OA_UNIT_GT_ID.
pub(crate) const CAPS: u64 = 1 | 2 | 4 | 8 | 32;
/// With DRM_XE_OA_CAPS_OAM (1 << 4 = 16) for Media GT OAM units.
pub(crate) const CAPS_OAM: u64 = 1 | 2 | 4 | 8 | 16 | 32;
const QUIESCE_NS: u64 = 50_000_000;

const E2BIG: i64 = 7;
const EOPNOTSUPP: i64 = 95;
const EADDRINUSE: i64 = 98;

pub(crate) const ENABLE: u32 = 0x6900;
pub(crate) const DISABLE: u32 = 0x6901;
pub(crate) const CONFIG: u32 = 0x6902;
pub(crate) const STATUS: u32 = 0x6903;
pub(crate) const INFO: u32 = 0x6904;

const RPM_CONFIG0: u64 = 0xd00;
const RPM_CONFIG1: u64 = 0xd04;
const GT_NOA_ENABLE: u32 = 1 << 9;
const OA_TLB_INV_CR: u64 = 0xceec;
const OAGLBCTXCTRL: u64 = 0x2b28;
const OAHEADPTR: u64 = 0xdb00;
const OATAILPTR: u64 = 0xdb04;
const PTR_MASK: u32 = 0xffff_ffc0;
const OABUFFER: u64 = 0xdb08;
const OACONTROL: u64 = 0xdaf4;
const PES_DISAG_EN: u32 = 0x3f << 22;
const CCS_SELECT: u32 = 7 << 16;
const COUNTER_SEL: u32 = 7 << 2;
const COUNTER_ENABLE: u32 = 1;
const OACONTROL_USED: u32 = PES_DISAG_EN | CCS_SELECT | COUNTER_SEL | COUNTER_ENABLE | 3 << 8;
const OA_DEBUG: u64 = 0xdaf8;
const DISABLE_MMIO_TRG: u32 = 1 << 14;
const START_TRIGGER_SCOPE: u32 = 1 << 13;
const BUF_SIZE_SELECT: u32 = 1 << 12;
const DISABLE_TRG_2_QUAL: u32 = 1 << 8;
const DISABLE_TRG_1_QUAL: u32 = 1 << 7;
const INCLUDE_CLK_RATIO: u32 = 1 << 6;
const DISABLE_CLK_RATIO: u32 = 1 << 5;
const DISABLE_CTX_SWITCH: u32 = 1 << 1;
const OASTATUS: u64 = 0xdafc;
const STATUS_RELEVANT: u32 = (1 << 6) | (1 << 2) | (1 << 1) | 1;
const SQCNT1: u64 = 0x8718;
const SQCNT1_BITS: u32 = (1 << 30) | (1 << 29);
const ROW_CHICKEN: u64 = 0xe4f0;
const ROW_CHICKEN2: u64 = 0xe4f4;
/// OAR unit: regs/xe_oa_regs.h OAR_OACONTROL.
const OAR_OACONTROL: u32 = 0x2960;
/// OAC unit: regs/xe_oa_regs.h OAC_OACONTROL.
const OAC_OACONTROL: u32 = 0x15114;
/// OACTXCONTROL(base): regs/xe_oa_regs.h, engine base + 0x360.
const OACTXCONTROL_OFF: u32 = 0x360;
/// OA_COUNTER_RESUME: regs/xe_oa_regs.h, OACTXCONTROL bit 0.
const OA_COUNTER_RESUME: u32 = 1;
/// RING_CONTEXT_CONTROL(base): regs/xe_engine_regs.h, engine base + 0x244.
const RING_CONTEXT_CONTROL_OFF: u32 = 0x244;
/// CTX_CTRL_OAC_CONTEXT_ENABLE: regs/xe_engine_regs.h, bit 8.
const CTX_CTRL_OAC_CONTEXT_ENABLE: u32 = 1 << 8;
/// CTX_CTRL_RUN_ALONE: regs/xe_engine_regs.h, bit 7.
const CTX_CTRL_RUN_ALONE: u32 = 1 << 7;
/// OAR_OACONTROL_COUNTER_SEL_MASK: regs/xe_oa_regs.h GENMASK(3, 1).
const OAR_COUNTER_SEL_MASK: u32 = 0xe;

const fn masked(mask: u32, value: u32) -> u32 {
    (mask << 16) | value
}

/// errno results that FsError cannot name travel as a raw negative ioctl
/// return, as other DRM drivers in this crate already do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Fs(FsError),
    Errno(i64),
}
impl From<FsError> for Error {
    fn from(error: FsError) -> Self {
        Self::Fs(error)
    }
}
pub(crate) fn errno(result: Result<u64, Error>) -> Result<u64, FsError> {
    match result {
        Ok(value) => Ok(value),
        Err(Error::Fs(error)) => Err(error),
        Err(Error::Errno(errno)) => Ok((-errno) as u64),
    }
}

const OAG: u8 = 0;
const OAR: u8 = 1;
const OAC: u8 = 3;
const MPEC: u8 = 4;
const PEC: u8 = 5;

/// struct xe_oa_format: counter select, record size, type, 64-bit header,
/// counter size and BC report (Bspec 52198/60942).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Format {
    pub(crate) select: u32,
    pub(crate) size: u32,
    pub(crate) kind: u8,
    pub(crate) header64: bool,
    pub(crate) counter_size: u8,
    pub(crate) bc: u8,
}
const fn format(select: u32, size: u32, kind: u8, header64: bool, cs: u8, bc: u8) -> Format {
    Format {
        select,
        size,
        kind,
        header64,
        counter_size: cs,
        bc,
    }
}
/// oa_formats[], indexed by enum xe_oa_format_name.
pub(crate) const FORMATS: [Format; 19] = [
    format(7, 64, OAG, false, 0, 0),
    format(0, 64, OAG, false, 0, 0),
    format(2, 128, OAG, false, 0, 0),
    format(5, 256, OAG, false, 0, 0),
    format(5, 256, OAR, false, 0, 0),
    format(5, 256, OAG, false, 0, 0),
    format(1, 320, OAC, true, 0, 0),
    format(2, 192, OAC, true, 0, 0),
    format(1, 192, MPEC, true, 0, 0),
    format(2, 128, MPEC, true, 0, 0),
    format(1, 576, PEC, true, 1, 0),
    format(1, 640, PEC, true, 1, 1),
    format(1, 320, PEC, true, 0, 0),
    format(5, 320, PEC, true, 1, 0),
    format(5, 192, PEC, true, 0, 0),
    format(6, 320, PEC, true, 1, 0),
    format(6, 192, PEC, true, 0, 0),
    format(3, 320, PEC, true, 1, 0),
    format(4, 320, PEC, true, 1, 0),
];
impl Format {
    /// __format_to_oactrl for the OAG counter-select field (bits 4:2).
    fn control(self) -> u32 {
        ((self.select << 2) & COUNTER_SEL)
            | u32::from(self.bc) << 9
            | u32::from(self.counter_size) << 8
    }
    /// __format_to_oactrl with OAR_OACONTROL_COUNTER_SEL_MASK (bits 3:1):
    /// the select sits one bit lower than in the OAG OACONTROL field
    /// (bits 4:2); BC and counter-size keep their OACONTROL positions.
    fn per_context_control(self) -> u32 {
        ((self.select << 1) & OAR_COUNTER_SEL_MASK)
            | u32::from(self.bc) << 9
            | u32::from(self.counter_size) << 8
    }
    /// The DRM_XE_OA_PROPERTY_OA_FORMAT encoding of this format.
    #[cfg(feature = "kernel-test")]
    pub(crate) fn wire(self) -> u64 {
        u64::from(self.kind)
            | u64::from(self.select) << 8
            | u64::from(self.counter_size) << 16
            | u64::from(self.bc) << 24
    }
}

/// Source OA profiles qualified for NARF's native Xe GT owners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    /// XE_DG2 (12.55).
    Dg2,
    /// XE_METEORLAKE (12.70, 12.71 and Arrow Lake 12.74).
    Mtl,
    /// Xe2 main GT (BMG 20.01/20.02, LNL 20.04).
    Xe2,
}
impl Profile {
    pub(crate) fn of(platform: GtPlatform, graphics: u16) -> Option<Self> {
        match platform {
            GtPlatform::Alchemist if graphics == 1255 => Some(Self::Dg2),
            GtPlatform::Integrated(crate::intel_gpu::Generation::MeteorLake)
                if matches!(graphics, 1270 | 1271 | 1274) =>
            {
                Some(Self::Mtl)
            }
            GtPlatform::Battlemage if matches!(graphics, 2001 | 2002) => Some(Self::Xe2),
            _ if platform.is_lnl() && graphics == 2004 => Some(Self::Xe2),
            _ => None,
        }
    }
    /// xe_oa_init_supported_formats, in format_mask bit order.
    pub(crate) fn formats(self) -> &'static [usize] {
        match self {
            Self::Dg2 => &[4, 5, 6, 7],
            Self::Mtl => &[4, 5, 6, 7, 8, 9],
            Self::Xe2 => &[8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18],
        }
    }
    /// decode_oa_format: the first platform format matching every field.
    pub(crate) fn decode(self, value: u64) -> Option<usize> {
        let field = |shift: u32| ((value >> shift) & 0xff) as u32;
        self.formats().iter().copied().find(|&index| {
            let f = FORMATS[index];
            u32::from(f.counter_size) == field(16)
                && u32::from(f.bc) == field(24)
                && u32::from(f.kind) == field(0)
                && f.select == field(8)
        })
    }
}
/// oa_unit_supports_oa_format for DRM_XE_OA_UNIT_TYPE_OAG.
fn oag_format(kind: u8) -> bool {
    matches!(kind, OAG | OAR | OAC | PEC)
}
/// __hwe_oa_unit: render and compute engines attach to the main-GT OAG.
fn oag_engine(engine: Engine) -> bool {
    engine == Engine::Rcs0 || engine.is_compute()
}

/// Cached OAG facts, published with the live user epoch. No query reads MMIO.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Device {
    pub card: u32,
    pub platform: GtPlatform,
    /// GRAPHICS_VERx100 of the main GT.
    pub graphics: u16,
    /// xe_oa_timestamp_frequency(gt0).
    pub timestamp: u32,
    /// Published GT0 engines; logical instances come from this set.
    pub engines: EngineSet,
    /// Preallocated OA buffer bytes.
    pub reserve: u32,
    /// Published media GT engines (VCS/VECS) for OAM unit enumeration.
    pub media_engines: Option<EngineSet>,
    /// xe_oa_timestamp_frequency(gt1).
    pub media_timestamp: Option<u32>,
}
impl Device {
    pub(crate) fn validate(self) -> Result<Self, FsError> {
        if Profile::of(self.platform, self.graphics).is_none()
            || self.card >= 64
            || self.timestamp == 0
            || !self.reserve.is_power_of_two()
            || u64::from(self.reserve) < MIN_BUFFER
            || u64::from(self.reserve) > MAX_BUFFER
            || self.oag_engines().next().is_none()
        {
            return Err(FsError::NoDevice);
        }
        Ok(self)
    }
    fn profile(self) -> Profile {
        Profile::of(self.platform, self.graphics).expect("validated OA device")
    }
    fn oag_engines(self) -> impl Iterator<Item = Engine> {
        self.engines.iter().filter(|engine| oag_engine(*engine))
    }
    fn oam_engines(self) -> impl Iterator<Item = Engine> {
        self.media_engines
            .into_iter()
            .flat_map(|engines| engines.iter().filter(|engine| oam_engine(*engine)))
    }
    pub fn has_oam(self) -> bool {
        self.oam_engines().next().is_some()
    }
}

fn oam_engine(engine: Engine) -> bool {
    matches!(
        engine,
        Engine::Vcs0
            | Engine::Vcs1
            | Engine::Vcs2
            | Engine::Vcs3
            | Engine::Vcs4
            | Engine::Vcs5
            | Engine::Vcs6
            | Engine::Vcs7
            | Engine::Vecs0
            | Engine::Vecs1
            | Engine::Vecs2
            | Engine::Vecs3
    )
}

/// Wa_18013179988 (12.55 and 12.70..12.74, xe_wa_oob.rules continuation)
/// and Wa_14015568240 (12.55..12.60): the OA unit ignores CTC_SHIFT.
pub(crate) fn ctc_shift_applies(graphics: u16) -> bool {
    graphics == 1255 || (1270..=1274).contains(&graphics)
}
/// xe_oa_timestamp_frequency: scale the reference clock by RPM_CONFIG0's
/// CTC shift where the workaround applies; otherwise it is unchanged.
pub(crate) fn timestamp_frequency(graphics: u16, reference: u32, rpm_config0: u32) -> u32 {
    if ctc_shift_applies(graphics) {
        reference << (3 - ((rpm_config0 >> 1) & 3))
    } else {
        reference
    }
}

/// xe_oa_init_oa_buffer: OABUFFER_SIZE_MASK from the buffer's exponent;
/// above 16 MiB OA_DEBUG BUF_SIZE_SELECT multiplies the field by eight.
pub(crate) fn buffer_field(size: u32) -> u32 {
    let exponent = size.trailing_zeros();
    if exponent > 24 {
        exponent - 20
    } else {
        exponent - 17
    }
}

/// DRM_XE_DEVICE_QUERY_OA_UNITS. Without a published OA owner this is the
/// source's zero-unit reply (gt->oa.num_oa_units == 0).
pub(crate) fn query(device: Option<Device>) -> Vec<u8> {
    let Some(device) = device.and_then(|device| device.validate().ok()) else {
        return vec![0; 16];
    };
    let oag_engines: Vec<Engine> = device.oag_engines().collect();
    let oam_engines: Vec<Engine> = device.oam_engines().collect();
    let has_oam = !oam_engines.is_empty();
    let num_units: u32 = if has_oam { 2 } else { 1 };

    let mut total_len = 16 + 72 + oag_engines.len() * 8;
    if has_oam {
        total_len += 72 + oam_engines.len() * 8;
    }
    let mut reply = vec![0; total_len];
    put32(&mut reply, 8, num_units);

    // Unit 0: OAG (GT0)
    // oa_unit_id 0, DRM_XE_OA_UNIT_TYPE_OAG 0, gt_id 0.
    put64(&mut reply, 16 + 16, CAPS);
    put64(&mut reply, 16 + 24, u64::from(device.timestamp));
    put64(&mut reply, 16 + 64, oag_engines.len() as u64);
    for (i, engine) in oag_engines.iter().enumerate() {
        let at = 16 + 72 + i * 8;
        let logical = device.engines.logical_instance(*engine).expect("published");
        reply[at..at + 2].copy_from_slice(&engine.xe_class().to_le_bytes());
        reply[at + 2..at + 4].copy_from_slice(&logical.to_le_bytes());
    }

    // Unit 1: OAM (GT1)
    if has_oam {
        let unit1_off = 16 + 72 + oag_engines.len() * 8;
        put64(&mut reply, unit1_off, 1); // oa_unit_id: 1
        put64(&mut reply, unit1_off + 8, 1); // DRM_XE_OA_UNIT_TYPE_OAM: 1
        put64(&mut reply, unit1_off + 16, CAPS_OAM);
        put64(
            &mut reply,
            unit1_off + 24,
            u64::from(device.media_timestamp.unwrap_or(device.timestamp)),
        );
        put64(&mut reply, unit1_off + 64, oam_engines.len() as u64);
        let media_set = device.media_engines.expect("has_oam proved media_engines");
        for (i, engine) in oam_engines.iter().enumerate() {
            let at = unit1_off + 72 + i * 8;
            let logical = media_set
                .logical_instance(*engine)
                .expect("published media engine");
            reply[at..at + 2].copy_from_slice(&engine.xe_class().to_le_bytes());
            reply[at + 2..at + 4].copy_from_slice(&logical.to_le_bytes());
        }
    }

    reply
}

/// xe_oa_is_valid_config_reg_addr for the main GT's graphics version.
pub(crate) fn valid_register(graphics: u16, addr: u32) -> bool {
    const FLEX: [u32; 7] = [0xe458, 0xe558, 0xe658, 0xe758, 0xe45c, 0xe55c, 0xe65c];
    const B: [(u32, u32); 13] = [
        (0xdc48, 0xdc48),
        (0xdd00, 0xdd48),
        (0x2b2c, 0x2b2c),
        (0xd900, 0xd91c),
        (0xd920, 0xd93c),
        (0xd940, 0xd97c),
        (0xdc00, 0xdc3c),
        (0xdc40, 0xdc40),
        (0xdc44, 0xdc44),
        (0x393000, 0x39301c),
        (0x393020, 0x39303c),
        (0x393040, 0x39307c),
        (0x393200, 0x39323c),
    ];
    const XE2_B: [(u32, u32); 3] = [
        (0x393200, 0x39323c),
        (0x394200, 0x39423c),
        (0x394a00, 0x394a3c),
    ];
    const XE2_MUX: [(u32, u32); 10] = [
        (0x5194, 0x5194),
        (0x8704, 0x8704),
        (0xb01c, 0xb01c),
        (0xb1bc, 0xb1bc),
        (0xd0e0, 0xd0f4),
        (0xe18c, 0xe18c),
        (0xe590, 0xe590),
        (0x13000, 0x137fc),
        (0x145194, 0x145194),
        (0x145340, 0x14537c),
    ];
    const MTL_MUX: [(u32, u32); 5] = [
        (0x0d00, 0x0d04),
        (0x0d0c, 0x0d2c),
        (0x9840, 0x9840),
        (0x9884, 0x9888),
        (0x38d100, 0x38d114),
    ];
    const GEN12_MUX: [(u32, u32); 5] = [
        (0x0d00, 0x0d04),
        (0x0d0c, 0x0d2c),
        (0x9840, 0x9840),
        (0x9884, 0x9888),
        (0x20cc, 0x20cc),
    ];
    let within = |table: &[(u32, u32)]| table.iter().any(|&(a, b)| addr >= a && addr <= b);
    let mux: &[(u32, u32)] = if graphics >= 2000 {
        &XE2_MUX
    } else if graphics >= 1270 {
        &MTL_MUX
    } else {
        &GEN12_MUX
    };
    FLEX.contains(&addr) || within(&B) || (graphics >= 2000 && within(&XE2_B)) || within(mux)
}

/// write_cs_mi_lri: MI_LOAD_REGISTER_IMM | MI_LRI_NUM_REGS(n), n <= 126.
pub(crate) fn lri(regs: &[(u32, u32)]) -> Vec<u32> {
    let mut words = Vec::with_capacity(regs.len() * 2 + regs.len().div_ceil(LRI_GROUP));
    for (i, &(addr, value)) in regs.iter().enumerate() {
        if i % LRI_GROUP == 0 {
            let n = (regs.len() - i).min(LRI_GROUP) as u32;
            words.push(0x1100_0000 | (2 * n - 1));
        }
        words.extend([addr, value]);
    }
    words
}
/// One privileged kernel ring job of a configuration. Only this module
/// builds jobs, from registry-validated register addresses.
#[derive(Debug)]
pub struct Job(Vec<u32>);
impl Job {
    pub(crate) fn words(&self) -> &[u32] {
        &self.0
    }
}
/// The ordered kernel ring jobs for one configuration.
pub(crate) fn config_jobs(regs: &[(u32, u32)]) -> Vec<Job> {
    regs.chunks(LRI_JOB).map(|regs| Job(lri(regs))).collect()
}

/// xe_oa_configure_oar_context / xe_oa_configure_oac_context: the three
/// MI_LRI pairs, in source order, as one privileged kernel ring job, or
/// None when the stream names no exec queue or its engine class programs
/// nothing (Linux: video engines return 0). Dispatched by engine class,
/// not format kind, as in Linux: Render writes OAR_OACONTROL, Compute
/// writes OAC_OACONTROL with CTX_CTRL_RUN_ALONE.
///
/// NOTE: the job retires through the same kernel-ring path as
/// configuration jobs, on a fresh kernel context (Linux submits its LRI on
/// `stream->exec_q`; NARF has no submit-trusted-words-on-user-context
/// entry point yet). The OAR/OAC_OACONTROL writes name fixed unit
/// addresses and land regardless of context. The RING_CONTEXT_CONTROL
/// write does NOT reach the bound queue: that register is per-context
/// saved state (`xe_lrc.c::reg_offsets`, `intel_gpu_engine::xcs_image`),
/// and the kernel-ring job runs on the kernel context, not the bound
/// queue. Whether OACTXCONTROL is context-saved is UNVERIFIED in-tree
/// (it is absent from `reg_offsets`), so its effect through this path is
/// unknown. Closing the gap needs a trusted-submit-on-user-context entry
/// point; until then the job is built, validated and sequenced, but its
/// per-context effect on silicon is UNVERIFIED.
/// The two-word head of the owned breadcrumb MI_FLUSH_DW that every
/// `resident_ring` job ends with (also the marker the user-fence splice
/// in `intel_gpu_guc_sched::submit_inner` searches for). The per-batch
/// OA query splices immediately before this marker, so it executes
/// after the user's batch returns to the ring and before the
/// completion write.
pub(crate) const BREADCRUMB_MARKER: [u32; 2] = [0x7a000004, 0x01104080];

/// MI_REPORT_PERF_COUNT, Gen8+ 4-dword form (all NARF platforms are
/// Gen12+): [header, address low, address high, report ID]. Opcode
/// 0x28 (2013 Sandybridge patch "MI_REPORT_PERF_COUNT is now opcode
/// 0x28"; IGT tests/perf.c `GEN8_MI_REPORT_PERF_COUNT` and mesa i965
/// `emit_mi_report_perf_count` both emit `(0x28 << 23) | (4 - 2)`).
/// No GTT-select bit is set: the address is a PPGTT address (see
/// [`QuerySampler`]). The Gen6 3-dword form (32-bit address) predates
/// Gen8 and does not apply here.
const MI_REPORT_PERF_COUNT_HEADER: u32 = (0x28 << 23) | (4 - 2);

/// The per-batch OA query sampler for a query-mode OAR/OAC stream.
///
/// Linux never emits MI_REPORT_PERF_COUNT from the kernel: userspace
/// (mesa) inserts it into its own batch, targeting a userspace-provided
/// address in the per-process GPU address space (lkml 2015, Robert
/// Bragg: "the kernel shouldn't be emitting MI_REPORT_PERF_COUNT
/// commands"; "the gpu stores the samples at the userspace provided
/// address in the per-process gpu address space"). NARF has no
/// userspace mesa emitting batches, so the kernel's exec path emits one
/// query per batch on a queue with a live query-mode stream (see
/// [`splice_query`]), targeting the query buffer the stream's opener
/// provided (open properties 14/15) in the bound context's PPGTT. The
/// report lands in the opener's buffer; the report ID (a per-stream
/// sequence, never 0) tells userspace the report has landed and which
/// batch it belongs to (mesa instead uses the fixed magic 0xd2e9c607
/// and checks report[0] == report ID).
///
/// The destination is a PPGTT address, never GGTT: the i915 command
/// parser requires MI_REPORT_PERF_COUNT_GGTT == 0 for userspace
/// batches, and the GPU forces the per-process address space for this
/// command (the GTT select bit is not obeyed). The buffer is separate
/// from the periodic OA circular buffer (i915's command-stream capture
/// likewise keeps CS-based reports in a separate buffer from the
/// periodic one), and the exec path refuses to submit while the range
/// is not resident-writable in the context's VM.
#[derive(Debug)]
pub(crate) struct QuerySampler {
    /// PPGTT address of the query buffer in the bound context's VM.
    address: u64,
    /// Buffer size in bytes (a multiple of `report_size`, at least one
    /// report; validated at open).
    size: u32,
    /// One report's size in bytes (the stream format's size).
    report_size: u32,
    /// (next slot, next report ID). Slots rotate 0..slots; report IDs
    /// run 1, 2, ... and wrap to 1, never 0 (0 means "no report" to the
    /// OA read path's unlanded-report detection).
    state: IrqSafeSpinLock<(u32, u32)>,
}

impl QuerySampler {
    /// Build a sampler for a validated query buffer: `size` is a
    /// nonzero multiple of `report_size`, and `address` is aligned to
    /// `report_size` (checked at open; a caller that skips the check
    /// gets slots that still stay inside the buffer, but the report
    /// addresses are only report-aligned when the base is).
    pub(crate) fn new(address: u64, size: u32, report_size: u32) -> Self {
        Self {
            address,
            size,
            report_size,
            state: IrqSafeSpinLock::new((0, 1)),
        }
    }
    /// PPGTT address of the query buffer, for the exec path's residency
    /// check.
    pub(crate) fn address(&self) -> u64 {
        self.address
    }
    /// Query buffer size in bytes, for the exec path's residency check.
    pub(crate) fn size(&self) -> u32 {
        self.size
    }
    /// The MI_REPORT_PERF_COUNT for the next batch: the next slot's
    /// address in the query buffer and the next report ID. Each call
    /// advances the slot (rotating within the buffer) and the report ID
    /// (wrapping to 1, never 0), so consecutive batches land in
    /// consecutive slots with distinct IDs.
    pub(crate) fn next_query(&self) -> [u32; 4] {
        let slots = (self.size / self.report_size).max(1);
        let mut state = self.state.lock();
        let (slot, id) = *state;
        let address = self.address + u64::from(slot) * u64::from(self.report_size);
        state.0 = (slot + 1) % slots;
        state.1 = if id == u32::MAX { 1 } else { id + 1 };
        [
            MI_REPORT_PERF_COUNT_HEADER,
            address as u32,
            (address >> 32) as u32,
            id,
        ]
    }
}

/// Splice one MI_REPORT_PERF_COUNT from `sampler` into `words`
/// immediately before the owned breadcrumb, so it executes after the
/// user's batch returns to the ring and before the completion write.
/// Returns false (and leaves `words` untouched) when the breadcrumb
/// marker is absent, so a ring that was not built by `resident_ring`
/// never gains a query. Called from `submit_inner` for the resident
/// (render/compute) ring only: video engines do not support
/// MI_REPORT_PERF_COUNT (Linux `xe_oa_configure_oa_context` returns 0
/// for them), and the query-mode stream is bound to a render/compute
/// queue.
pub(crate) fn splice_query(words: &mut Vec<u32>, sampler: &QuerySampler) -> bool {
    let Some(at) = words.windows(2).position(|v| v == BREADCRUMB_MARKER) else {
        return false;
    };
    let query = sampler.next_query();
    words.splice(at..at, query);
    true
}

fn per_context_job(session: &Session, enable: bool) -> Option<Job> {
    session.exec_queue?;
    let base = session.hwe.base();
    let control = session.format.per_context_control() | u32::from(enable);
    let (oacontrol, ctx_bits) = match session.hwe {
        Engine::Rcs0 => (OAR_OACONTROL, CTX_CTRL_OAC_CONTEXT_ENABLE),
        engine if engine.is_compute() => (
            OAC_OACONTROL,
            CTX_CTRL_OAC_CONTEXT_ENABLE | CTX_CTRL_RUN_ALONE,
        ),
        _ => return None,
    };
    let regs = [
        (
            base + OACTXCONTROL_OFF,
            if enable { OA_COUNTER_RESUME } else { 0 },
        ),
        (oacontrol, control),
        (
            base + RING_CONTEXT_CONTROL_OFF,
            masked(ctx_bits, if enable { ctx_bits } else { 0 }),
        ),
    ];
    let mut jobs = config_jobs(&regs);
    jobs.pop()
}

/// struct xe_oa_config: immutable uuid and validated register list.
#[derive(Debug)]
pub struct Config {
    pub(crate) id: u32,
    pub(crate) uuid: [u8; 36],
    pub(crate) regs: Vec<(u32, u32)>,
    pub(crate) n_mux: u32,
    pub(crate) n_bool: u32,
    pub(crate) n_flex: u32,
}
impl Config {
    pub(crate) fn new(
        id: u32,
        uuid: [u8; 36],
        regs: Vec<(u32, u32)>,
        n_mux: u32,
        n_bool: u32,
        n_flex: u32,
    ) -> Self {
        Self {
            id,
            uuid,
            regs,
            n_mux,
            n_bool,
            n_flex,
        }
    }
    pub(crate) fn regs(&self) -> &[(u32, u32)] {
        &self.regs
    }
}
struct Registry {
    configs: BTreeMap<u32, Arc<Config>>,
    regs: usize,
}
/// xe_oa::metrics_idr, one per card for the device lifetime.
static REGISTRY: [IrqSafeSpinLock<Registry>; 64] = [const {
    IrqSafeSpinLock::new(Registry {
        configs: BTreeMap::new(),
        regs: 0,
    })
}; 64];
static ACTIVE: [[AtomicBool; 2]; 64] =
    [const { [AtomicBool::new(false), AtomicBool::new(false)] }; 64];
/// The unit's live OA reservation per card, in bytes. The boot reservation
/// is DEFAULT_BUFFER; a stream that opens a larger buffer grows it (up to
/// MAX_BUFFER) at attach, and the sysfs `oa_buffer_size` node publishes
/// this value, never the stale default.
static RESERVE: [AtomicU32; 64] = [const { AtomicU32::new(DEFAULT_BUFFER) }; 64];

/// The live reservation for `card`, for the sysfs OA telemetry.
fn reserve_of(card: u32) -> u32 {
    RESERVE
        .get(card as usize)
        .map_or(DEFAULT_BUFFER, |reserve| reserve.load(Ordering::Acquire))
}

pub(crate) fn lookup(card: u32, id: u64) -> Option<Arc<Config>> {
    let id = u32::try_from(id).ok()?;
    REGISTRY
        .get(card as usize)?
        .lock()
        .configs
        .get(&id)
        .cloned()
}

pub(crate) fn query_config_ids(card: u32) -> Vec<u64> {
    let Some(reg) = REGISTRY.get(card as usize) else {
        return Vec::new();
    };
    let registry = reg.lock();
    let mut ids: Vec<u64> = registry.configs.keys().map(|&k| u64::from(k)).collect();
    ids.sort_unstable();
    ids
}

pub(crate) fn query_config_by_id(card: u32, id: u64) -> Option<Arc<Config>> {
    lookup(card, id)
}

pub(crate) fn query_config_by_uuid(card: u32, uuid: &[u8; 36]) -> Option<Arc<Config>> {
    REGISTRY
        .get(card as usize)?
        .lock()
        .configs
        .values()
        .find(|c| c.uuid == *uuid)
        .cloned()
}

/// lib/uuid.c uuid_is_valid.
fn uuid_valid(uuid: &[u8; 36]) -> bool {
    uuid.iter().enumerate().all(|(i, &c)| {
        if matches!(i, 8 | 13 | 18 | 23) {
            c == b'-'
        } else {
            c.is_ascii_hexdigit()
        }
    })
}

#[derive(Clone, Copy)]
pub(crate) struct Gate {
    pub(crate) capable: fn() -> bool,
}
impl Gate {
    /// xe_observation_paranoid (default 1) && !perfmon_capable().
    pub(crate) const PHYSICAL: Self = Self {
        capable: crate::intel_gpu_eu_stall::capable,
    };
    fn check(self) -> Result<(), FsError> {
        if (self.capable)() {
            Ok(())
        } else {
            Err(FsError::PermissionDenied)
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Origin {
    Open,
    Config,
}
/// struct xe_oa_open_param, with the source C widths.
struct Params {
    oa_unit: u32,
    sample: bool,
    metric_set: u32,
    format: usize,
    exponent: i32,
    disabled: bool,
    exec_queue: i32,
    engine_instance: i32,
    no_preempt: bool,
    num_syncs: i32,
    syncs: u64,
    buffer: u64,
    wait: i32,
    /// PPGTT address of the opener's query-report buffer in the bound
    /// context's VM (open property 14). 0 means no query sampling.
    query_address: u64,
    /// Query-report buffer size in bytes (open property 15). 0 means no
    /// query sampling.
    query_size: u64,
}
impl Params {
    fn new() -> Self {
        Self {
            oa_unit: 0,
            sample: false,
            metric_set: 0,
            format: 0,
            exponent: -1,
            disabled: false,
            exec_queue: 0,
            engine_instance: 0,
            no_preempt: false,
            num_syncs: 0,
            syncs: 0,
            buffer: 0,
            wait: 0,
            query_address: 0,
            query_size: 0,
        }
    }
    /// xe_oa_set_property_funcs_open / _config.
    fn set(
        &mut self,
        device: Device,
        from: Origin,
        property: u32,
        value: u64,
    ) -> Result<(), Error> {
        let invalid = Err(Error::Fs(FsError::InvalidData));
        if from == Origin::Config && !matches!(property, 3 | 10 | 11) {
            return invalid;
        }
        match property {
            // xe_oa_lookup_oa_unit takes a u32 id (Linux truncates the
            // u64 property value on the call); only units 0 (OAG) and 1
            // (OAM) exist. Compare the truncated id, not the raw value,
            // so a 2^32 unit id still opens unit 0.
            1 if value as u32 == 0 => self.oa_unit = 0,
            1 if value as u32 == 1 && device.has_oam() => self.oa_unit = 1,
            1 => return invalid,
            2 => self.sample = value != 0,
            3 => self.metric_set = value as u32,
            4 => self.format = device.profile().decode(value).ok_or(FsError::InvalidData)?,
            5 if value > 31 => return invalid,
            5 => self.exponent = value as i32,
            6 => self.disabled = value != 0,
            7 => self.exec_queue = value as i32,
            8 => self.engine_instance = value as i32,
            9 => self.no_preempt = value != 0,
            10 if value == 0 || value > MAX_SYNCS => return invalid,
            10 => self.num_syncs = value as i32,
            11 if value == 0 => return invalid,
            11 => self.syncs = value,
            12 if !value.is_power_of_two() || !(MIN_BUFFER..=MAX_BUFFER).contains(&value) => {
                return invalid;
            }
            12 => self.buffer = value,
            13 if value == 0 => return invalid,
            13 => self.wait = value as i32,
            // Query sampling (issue #1774): the opener's per-batch
            // report buffer in the bound context's PPGTT. Both or
            // neither; the cross-checks (bound exec queue, query mode,
            // render/compute engine, size/alignment against the format)
            // run at open, where the format and engine are known.
            14 => self.query_address = value,
            15 => self.query_size = value,
            _ => return invalid,
        }
        Ok(())
    }
}
/// xe_oa_user_extensions + xe_oa_user_ext_set_property.
fn extensions(
    device: Device,
    from: Origin,
    mut address: u64,
    user: &dyn IoctlContext,
    params: &mut Params,
) -> Result<(), Error> {
    let mut number = 0;
    loop {
        if number >= MAX_USER_EXTENSIONS {
            return Err(Error::Errno(E2BIG));
        }
        let mut base = [0u8; 16];
        user.read(address, &mut base)?;
        if u32_at(&base, 12) != 0 || u32_at(&base, 8) >= 1 {
            return Err(FsError::InvalidData.into());
        }
        let mut ext = [0u8; 48];
        user.read(address, &mut ext)?;
        let property = u32_at(&ext, 16);
        if property >= 14 || property == 0 || u32_at(&ext, 20) != 0 {
            return Err(FsError::InvalidData.into());
        }
        params.set(device, from, property, u64_at(&ext, 24))?;
        address = u64_at(&base, 0);
        if address == 0 {
            return Ok(());
        }
        number += 1;
    }
}

/// Retained exec-queue binding (Linux `stream->exec_q`): the queue id, the
/// GuC-schedulable context the per-context LRI job targets, and a liveness
/// probe owned by the queue. Held by the session from open until close so
/// enable time can fail cleanly when the queue is gone instead of
/// programming a dead context.
pub(crate) struct QueueBinding {
    pub(crate) id: u32,
    pub(crate) context: Arc<UserContext>,
    alive: Arc<dyn Fn() -> bool + Send + Sync>,
}
impl QueueBinding {
    pub(crate) fn new(
        id: u32,
        context: Arc<UserContext>,
        alive: Arc<dyn Fn() -> bool + Send + Sync>,
    ) -> Self {
        Self { id, context, alive }
    }
    pub(crate) fn alive(&self) -> bool {
        (self.alive)()
    }
}

/// Facts of a native Xe exec queue: user engine class, parallel width and
/// the retained binding for per-context programming.
pub(crate) type QueueLookup<'a> = &'a (dyn Fn(u32) -> Option<(u16, usize, QueueBinding)> + Sync);

/// DRM_XE_OBSERVATION with observation_type OA.
pub(crate) async fn observation(
    backend: Option<Arc<dyn UserBackend>>,
    op: u64,
    param: u64,
    user: &dyn IoctlContext,
    queues: QueueLookup<'_>,
    syncobjs: Option<Arc<IrqSafeSpinLock<SyncObjTable>>>,
) -> Result<u64, FsError> {
    errno(match op {
        0 => open(backend, param, user, queues, Gate::PHYSICAL, syncobjs).await,
        1 => add_config(backend.as_deref(), param, user, Gate::PHYSICAL),
        2 => remove_config(backend.as_deref(), param, user, Gate::PHYSICAL),
        _ => Err(FsError::InvalidData.into()),
    })
}

fn device_of(backend: Option<&dyn UserBackend>) -> Result<Device, Error> {
    // xe_oa_*_ioctl: "xe oa interface not available for this system".
    Ok(backend
        .and_then(|backend| backend.oa_device())
        .and_then(|device| device.validate().ok())
        .ok_or(FsError::NoDevice)?)
}

/// xe_oa_stream_open_ioctl, xe_oa_stream_open_ioctl_locked and the
/// host-only part of xe_oa_stream_init, in source order.
pub(crate) async fn open(
    backend: Option<Arc<dyn UserBackend>>,
    param: u64,
    user: &dyn IoctlContext,
    queues: QueueLookup<'_>,
    gate: Gate,
    syncobjs: Option<Arc<IrqSafeSpinLock<SyncObjTable>>>,
) -> Result<u64, Error> {
    let device = device_of(backend.as_deref())?;
    let backend = backend.ok_or(FsError::NoDevice)?;
    let mut p = Params::new();
    extensions(device, Origin::Open, param, user, &mut p)?;
    if (p.num_syncs != 0 && p.syncs == 0) || (p.num_syncs == 0 && p.syncs != 0) {
        return Err(FsError::InvalidData.into());
    }
    let mut exec = None;
    let mut binding = None;
    if p.exec_queue > 0 {
        let (class, width, queue_binding) = queues(p.exec_queue as u32).ok_or(FsError::NotFound)?;
        if width > 1 {
            return Err(Error::Errno(EOPNOTSUPP));
        }
        exec = Some(class);
        binding = Some(queue_binding);
    }
    let mut privileged = exec.is_none() || p.sample;
    if p.no_preempt {
        if exec.is_none() {
            return Err(FsError::InvalidData.into());
        }
        privileged = true;
    }
    if privileged {
        gate.check()?;
    }
    if exec.is_none() && !p.sample {
        return Err(FsError::InvalidData.into());
    }
    // OAM does not support periodic sampling.
    if p.oa_unit == 1 && (p.sample || p.exponent >= 0) {
        return Err(FsError::InvalidData.into());
    }
    // xe_oa_assign_hwe: for OAG, render/compute engines; for OAM, media engines.
    let hwe = match (p.oa_unit, exec) {
        (0, Some(class)) => device
            .engines
            .from_class_instance(class, p.engine_instance as u16)
            .filter(|engine| oag_engine(*engine)),
        (0, None) => device.oag_engines().next(),
        (1, Some(class)) => {
            let media = device.media_engines.ok_or(FsError::InvalidData)?;
            media
                .from_class_instance(class, p.engine_instance as u16)
                .filter(|engine| oam_engine(*engine))
        }
        (1, None) => device.oam_engines().next(),
        _ => return Err(FsError::InvalidData.into()),
    }
    .ok_or(FsError::InvalidData)?;
    let format = FORMATS[p.format];
    let valid_format = match p.oa_unit {
        0 => oag_format(format.kind),
        1 => format.kind == MPEC,
        _ => false,
    };
    if p.format == 0 || format.size == 0 || !valid_format {
        return Err(FsError::InvalidData.into());
    }
    if p.oa_unit == 0 {
        if exec.is_some() {
            if hwe == Engine::Rcs0 && format.kind == OAC {
                return Err(FsError::InvalidData.into());
            }
            if hwe.is_compute() && format.kind == OAR {
                return Err(FsError::InvalidData.into());
            }
        } else if format.kind == OAR || format.kind == OAC {
            return Err(FsError::InvalidData.into());
        }
    }
    // Query sampling (issue #1774): both properties or neither, on a
    // query-mode stream (bound exec queue, no periodic sampling) whose
    // engine supports MI_REPORT_PERF_COUNT (render/compute only; Linux
    // xe_oa_configure_oa_context returns 0 for video engines). The
    // buffer holds whole reports, at least one, and the base is
    // report-aligned so every rotated slot is report-aligned.
    if (p.query_address == 0) != (p.query_size == 0)
        || (p.query_address != 0
            && (exec.is_none()
                || p.sample
                || !(hwe == Engine::Rcs0 || hwe.is_compute())
                || p.query_size > MAX_BUFFER
                || p.query_size < u64::from(format.size)
                || p.query_size % u64::from(format.size) != 0
                || p.query_address % u64::from(format.size) != 0))
    {
        return Err(FsError::InvalidData.into());
    }
    if p.exponent >= 0 && !p.sample {
        return Err(FsError::InvalidData.into());
    }
    let buffer = if p.buffer == 0 {
        u64::from(DEFAULT_BUFFER)
    } else {
        p.buffer
    };
    let wait = if p.wait == 0 { 1 } else { p.wait };
    if i64::from(wait) as u64 > buffer / u64::from(format.size) {
        return Err(FsError::InvalidData.into());
    }
    // xe_oa_stream_open_ioctl_locked.
    let permit = Permit::take(device.card, p.oa_unit)?;
    let sync = if p.num_syncs > 0 {
        let table = syncobjs.as_ref().ok_or(FsError::InvalidData)?;
        Some(XeSync::read(user, p.syncs, p.num_syncs as u32, table)?)
    } else {
        None
    };
    // xe_oa_stream_init.
    // No reserve check here: `buffer` is already validated to the Linux
    // 128 KiB..=128 MiB range by property 12 (or the 16 MiB default), and
    // the unit grows its retained reservation to the requested size at
    // attach. A failed growth returns ENOMEM from `oa_control` below.
    let config = lookup(device.card, u64::from(p.metric_set)).ok_or(FsError::InvalidData)?;
    let session = Session::new(
        device,
        format,
        p.sample,
        (p.exponent >= 0).then_some(p.exponent as u8),
        wait as u64,
        buffer as u32,
        hwe,
        permit,
        config,
        false,
        (p.exec_queue > 0).then_some(p.exec_queue as u32),
        binding,
        p.no_preempt,
        p.query_address,
        p.query_size,
        privileged,
    );
    let mut pending = PendingOpen {
        session: session.clone(),
        committed: false,
    };
    if let Some(sync) = &sync {
        sync.wait().await;
    }
    backend
        .oa_control(
            session.clone(),
            Request::Open {
                enable: !p.disabled,
            },
        )
        .await?;
    if privileged {
        if let Err(error) = gate.check() {
            session.fail(error);
            return Err(error.into());
        }
    }
    if let Some(sync) = &sync {
        sync.publish(crate::drm::syncobj::stub());
        if let Some((address, value)) = sync.user_fence {
            user.write_u64_release(address, value)?;
        }
    }
    let file = Arc::new(File {
        session,
        backend,
        gate,
        syncobjs,
    });
    let fd = user.install_file(file, false)?;
    pending.committed = true;
    Ok(fd as u64)
}
struct PendingOpen {
    session: Arc<Session>,
    committed: bool,
}
impl Drop for PendingOpen {
    fn drop(&mut self) {
        if !self.committed {
            self.session.fail(FsError::NoDevice);
            self.session.stop.store(true, Ordering::Release);
            self.session.permit.release();
        }
    }
}

pub(crate) fn map_i915_format(format_id: u64) -> Option<Format> {
    match format_id {
        7 => Some(FORMATS[0]),
        8 => Some(FORMATS[1]),
        9 => Some(FORMATS[2]),
        10..=12 => Some(FORMATS[3]),
        13 => Some(FORMATS[8]),
        14 => Some(FORMATS[9]),
        idx if (idx as usize) < FORMATS.len() && FORMATS[idx as usize].size > 0 => {
            Some(FORMATS[idx as usize])
        }
        _ => None,
    }
}

/// DRM_IOCTL_I915_PERF_OPEN: 16 bytes struct drm_i915_perf_open_param.
pub(crate) async fn i915_open(
    backend: Option<Arc<dyn UserBackend>>,
    param: u64,
    user: &dyn IoctlContext,
    gate: Gate,
) -> Result<u64, Error> {
    let device = device_of(backend.as_deref())?;
    let backend = backend.ok_or(FsError::NoDevice)?;
    let mut open_param = [0u8; 16];
    user.read(param, &mut open_param)?;
    let flags = u32_at(&open_param, 0);
    let num_props = u32_at(&open_param, 4);
    let props_ptr = u64_at(&open_param, 8);

    const I915_PERF_FLAG_FD_CLOEXEC: u32 = 1 << 0;
    const I915_PERF_FLAG_FD_NONBLOCK: u32 = 1 << 1;
    const I915_PERF_FLAG_DISABLED: u32 = 1 << 2;
    let known_flags =
        I915_PERF_FLAG_FD_CLOEXEC | I915_PERF_FLAG_FD_NONBLOCK | I915_PERF_FLAG_DISABLED;
    if flags & !known_flags != 0 {
        return Err(FsError::InvalidData.into());
    }
    if num_props == 0 || num_props >= 11 {
        return Err(FsError::InvalidData.into());
    }
    if props_ptr == 0 {
        return Err(FsError::BadAddress.into());
    }

    let mut single_context = false;
    let mut sample_oa = false;
    let mut metric_set = 0u64;
    let mut oa_format = 0u64;
    let mut exponent = None;
    let mut engine_class = None;
    let mut engine_instance = None;

    for i in 0..u64::from(num_props) {
        let at = props_ptr.checked_add(i * 16).ok_or(FsError::BadAddress)?;
        let mut prop_bytes = [0u8; 16];
        user.read(at, &mut prop_bytes)?;
        let prop_id = u64_at(&prop_bytes, 0);
        let prop_val = u64_at(&prop_bytes, 8);
        if prop_id == 0 || prop_id >= 11 {
            return Err(FsError::InvalidData.into());
        }
        match prop_id {
            crate::intel_gpu_uapi::PERF_PROP_CTX_HANDLE => {
                single_context = true;
            }
            crate::intel_gpu_uapi::PERF_PROP_SAMPLE_OA => {
                sample_oa = prop_val != 0;
            }
            crate::intel_gpu_uapi::PERF_PROP_OA_METRICS_SET => {
                if prop_val == 0 {
                    return Err(FsError::InvalidData.into());
                }
                metric_set = prop_val;
            }
            crate::intel_gpu_uapi::PERF_PROP_OA_FORMAT => {
                if prop_val == 0 {
                    return Err(FsError::InvalidData.into());
                }
                oa_format = prop_val;
            }
            crate::intel_gpu_uapi::PERF_PROP_OA_EXPONENT => {
                if prop_val > 31 {
                    return Err(FsError::InvalidData.into());
                }
                exponent = Some(prop_val as u8);
            }
            crate::intel_gpu_uapi::PERF_PROP_HOLD_PREEMPTION => {
                // HOLD_PREEMPTION accepted
            }
            crate::intel_gpu_uapi::PERF_PROP_GLOBAL_SSEU => {
                return Err(FsError::Unsupported.into());
            }
            crate::intel_gpu_uapi::PERF_PROP_POLL_OA_PERIOD => {
                if prop_val < 100_000 {
                    return Err(FsError::InvalidData.into());
                }
            }
            crate::intel_gpu_uapi::PERF_PROP_OA_ENGINE_CLASS => {
                engine_class = Some(prop_val as u16);
            }
            crate::intel_gpu_uapi::PERF_PROP_OA_ENGINE_INSTANCE => {
                engine_instance = Some(prop_val as u16);
            }
            _ => return Err(FsError::InvalidData.into()),
        }
    }

    if !sample_oa && !single_context {
        return Err(FsError::InvalidData.into());
    }
    if sample_oa {
        gate.check()?;
    }

    let hwe = match engine_class {
        Some(class) => device
            .engines
            .from_class_instance(class, engine_instance.unwrap_or(0))
            .filter(|engine| oag_engine(*engine)),
        None => device.oag_engines().next(),
    }
    .ok_or(FsError::InvalidData)?;

    let format = map_i915_format(oa_format).ok_or(FsError::InvalidData)?;
    if !oag_format(format.kind) {
        return Err(FsError::InvalidData.into());
    }
    if exponent.is_some() && !sample_oa {
        return Err(FsError::InvalidData.into());
    }

    let buffer = u64::from(DEFAULT_BUFFER);
    let wait = 1u64;

    let permit = Permit::take(device.card, 0)?;
    let config = lookup(device.card, metric_set).ok_or(FsError::InvalidData)?;

    let session = Session::new(
        device,
        format,
        sample_oa,
        exponent,
        wait,
        buffer as u32,
        hwe,
        permit,
        config,
        true,
        None,
        None,
        false,
        0,
        0,
        true,
    );

    let mut pending = PendingOpen {
        session: session.clone(),
        committed: false,
    };

    let disabled = (flags & I915_PERF_FLAG_DISABLED) != 0;
    backend
        .oa_control(session.clone(), Request::Open { enable: !disabled })
        .await?;

    if let Err(error) = gate.check() {
        session.fail(error);
        return Err(error.into());
    }

    let file = Arc::new(File {
        session,
        backend,
        gate,
        syncobjs: None,
    });
    let cloexec = (flags & I915_PERF_FLAG_FD_CLOEXEC) != 0;
    let fd = user.install_file(file, cloexec)?;
    pending.committed = true;
    Ok(fd as u64)
}

/// xe_oa_add_config_ioctl.
pub(crate) fn add_config(
    backend: Option<&dyn UserBackend>,
    param: u64,
    user: &dyn IoctlContext,
    gate: Gate,
) -> Result<u64, Error> {
    let device = device_of(backend)?;
    gate.check()?;
    let mut wire = [0u8; 56];
    user.read(param, &mut wire)?;
    let n = u32_at(&wire, 44);
    let regs_ptr = u64_at(&wire, 48);
    if u64_at(&wire, 0) != 0 || regs_ptr == 0 || n == 0 {
        return Err(FsError::InvalidData.into());
    }
    let uuid: [u8; 36] = wire[8..44].try_into().unwrap();
    if !uuid_valid(&uuid) {
        return Err(FsError::InvalidData.into());
    }
    // xe_oa_alloc_regs: kmalloc_objs(n_regs).
    let budget = |registry: &Registry| registry.regs + n as usize > MAX_REGISTRY_REGS;
    if n > MAX_CONFIG_REGS || budget(&REGISTRY[device.card as usize].lock()) {
        return Err(FsError::OutOfMemory.into());
    }
    let mut regs = Vec::new();
    regs.try_reserve_exact(n as usize)
        .map_err(|_| FsError::OutOfMemory)?;
    for i in 0..u64::from(n) {
        let at = regs_ptr.checked_add(i * 8).ok_or(FsError::BadAddress)?;
        let mut word = [0u8; 4];
        user.read(at, &mut word)?;
        let addr = u32::from_le_bytes(word);
        if !valid_register(device.graphics, addr) {
            return Err(FsError::InvalidData.into());
        }
        user.read(at.checked_add(4).ok_or(FsError::BadAddress)?, &mut word)?;
        regs.push((addr & 0x3f_ffff, u32::from_le_bytes(word)));
    }
    let mut registry = REGISTRY[device.card as usize].lock();
    if registry.configs.values().any(|config| config.uuid == uuid) {
        return Err(Error::Errno(EADDRINUSE));
    }
    if budget(&registry) {
        return Err(FsError::OutOfMemory.into());
    }
    // idr_alloc(.., 1, 0): the lowest free id.
    let id = (1..=MAX_CONFIGS)
        .find(|id| !registry.configs.contains_key(id))
        .ok_or(FsError::NoSpace)?;
    registry.regs += regs.len();
    registry
        .configs
        .insert(id, Arc::new(Config::new(id, uuid, regs, n, 0, 0)));
    // create_dynamic_oa_sysfs_entry: metrics/<uuid>/id, under the same lock
    // so a racing REMOVE_CONFIG cannot leave a stale directory.
    metrics_add(device.card, &uuid, id);
    Ok(u64::from(id))
}

/// xe_oa_register: `metrics` and `oa` telemetry under the card's primary-minor node.
/// NARF publishes them only with the OA opt-in, when the unit can exist.
static METRICS: [IrqSafeSpinLock<Option<Arc<narf_filesystem::sysfs::Kobject>>>; 64] =
    [const { IrqSafeSpinLock::new(None) }; 64];
static OA_NODES: [IrqSafeSpinLock<Option<Arc<narf_filesystem::sysfs::Kobject>>>; 64] =
    [const { IrqSafeSpinLock::new(None) }; 64];

pub(crate) fn populate_card(card: u32, node: &Arc<narf_filesystem::sysfs::Kobject>) {
    if enabled() {
        install_metrics(card, node);
        install_oa(card, node);
    }
}

pub(crate) fn oa_status_string(card: u32) -> alloc::string::String {
    let active = ACTIVE
        .get(card as usize)
        .is_some_and(|units| units.iter().any(|a| a.load(Ordering::Acquire)));
    let num_configs = REGISTRY
        .get(card as usize)
        .map_or(0, |r| r.lock().configs.len());
    let enabled_str = if enabled() { "enabled" } else { "disabled" };
    let capable_str = if capable() { "yes" } else { "no" };
    let active_str = if active { "active" } else { "idle" };

    alloc::format!(
        "oa_support: {}\n\
         oa_capable: {}\n\
         oa_status: {}\n\
         oa_buffer_size: {}\n\
         oa_configs: {}\n\
         oa_overflows: 0\n",
        enabled_str,
        capable_str,
        active_str,
        reserve_of(card),
        num_configs,
    )
}

fn install_oa(card: u32, node: &Arc<narf_filesystem::sysfs::Kobject>) {
    let Some(slot) = OA_NODES.get(card as usize) else {
        return;
    };
    let mut slot = slot.lock();
    if slot.is_none() {
        let oa_kobj = narf_filesystem::sysfs::Kobject::new_child(node.clone(), "oa");
        narf_filesystem::sysfs::kobject_add_attr(&oa_kobj, "oa_status", move || {
            oa_status_string(card)
        });
        narf_filesystem::sysfs::kobject_add_attr(&oa_kobj, "oa_buffer_size", move || {
            alloc::format!("{}\n", reserve_of(card))
        });
        narf_filesystem::sysfs::kobject_add_attr(&oa_kobj, "oa_active", move || {
            let active = ACTIVE
                .get(card as usize)
                .is_some_and(|units| units.iter().any(|a| a.load(Ordering::Acquire)));
            alloc::format!("{}\n", if active { 1 } else { 0 })
        });
        narf_filesystem::sysfs::kobject_add_attr(&oa_kobj, "oa_configs_count", move || {
            let num_configs = REGISTRY
                .get(card as usize)
                .map_or(0, |r| r.lock().configs.len());
            alloc::format!("{num_configs}\n")
        });
        narf_filesystem::sysfs::kobject_add_attr(&oa_kobj, "oa_overflow_count", move || {
            alloc::string::String::from("0\n")
        });
        *slot = Some(oa_kobj);
    }
}
fn install_metrics(card: u32, node: &Arc<narf_filesystem::sysfs::Kobject>) {
    let Some(slot) = METRICS.get(card as usize) else {
        return;
    };
    let mut slot = slot.lock();
    if slot.is_none() {
        *slot = Some(narf_filesystem::sysfs::Kobject::new_child(
            node.clone(),
            "metrics",
        ));
    }
}
fn metrics_add(card: u32, uuid: &[u8; 36], id: u32) {
    let Some(metrics) = METRICS
        .get(card as usize)
        .and_then(|slot| slot.lock().clone())
    else {
        return;
    };
    let Ok(name) = core::str::from_utf8(uuid) else {
        return;
    };
    let entry = narf_filesystem::sysfs::Kobject::new_child(metrics, name);
    // show_dynamic_id: "%d\n", mode 0444.
    narf_filesystem::sysfs::kobject_add_attr(&entry, "id", move || alloc::format!("{id}\n"));
}
fn metrics_remove(card: u32, uuid: &[u8; 36]) {
    if let (Some(metrics), Ok(name)) = (
        METRICS
            .get(card as usize)
            .and_then(|slot| slot.lock().clone()),
        core::str::from_utf8(uuid),
    ) {
        metrics.remove_child(name);
    }
}
#[cfg(feature = "kernel-test")]
pub(crate) fn install_metrics_for_test(card: u32, node: &Arc<narf_filesystem::sysfs::Kobject>) {
    install_metrics(card, node);
    install_oa(card, node);
}

/// xe_oa_remove_config_ioctl.
pub(crate) fn remove_config(
    backend: Option<&dyn UserBackend>,
    param: u64,
    user: &dyn IoctlContext,
    gate: Gate,
) -> Result<u64, Error> {
    let device = device_of(backend)?;
    gate.check()?;
    let mut word = [0u8; 8];
    user.read(param, &mut word)?;
    let id = u32::try_from(u64::from_le_bytes(word)).map_err(|_| FsError::NotFound)?;
    let mut registry = REGISTRY[device.card as usize].lock();
    let config = registry.configs.remove(&id).ok_or(FsError::NotFound)?;
    // sysfs_remove_group before idr_remove, under metrics_lock.
    metrics_remove(device.card, &config.uuid);
    registry.regs -= config.regs.len();
    Ok(0)
}

/// DRM_IOCTL_I915_PERF_ADD_CONFIG: 72 bytes struct drm_i915_perf_oa_config.
pub(crate) fn i915_add_config(
    backend: Option<&dyn UserBackend>,
    param: u64,
    user: &dyn IoctlContext,
    gate: Gate,
) -> Result<u64, Error> {
    let device = device_of(backend)?;
    gate.check()?;
    let mut wire = [0u8; 72];
    user.read(param, &mut wire)?;
    let uuid: [u8; 36] = wire[..36].try_into().unwrap();
    if !uuid_valid(&uuid) {
        return Err(FsError::InvalidData.into());
    }
    let n_mux = u32_at(&wire, 36);
    let n_bool = u32_at(&wire, 40);
    let n_flex = u32_at(&wire, 44);
    let mux_ptr = u64_at(&wire, 48);
    let bool_ptr = u64_at(&wire, 56);
    let flex_ptr = u64_at(&wire, 64);

    if (n_mux == 0 || mux_ptr == 0)
        && (n_bool == 0 || bool_ptr == 0)
        && (n_flex == 0 || flex_ptr == 0)
    {
        return Err(FsError::InvalidData.into());
    }

    let n_total = n_mux as usize + n_bool as usize + n_flex as usize;
    let budget = |registry: &Registry| registry.regs + n_total > MAX_REGISTRY_REGS;
    if n_total > MAX_CONFIG_REGS as usize || budget(&REGISTRY[device.card as usize].lock()) {
        return Err(FsError::OutOfMemory.into());
    }

    let mut regs = Vec::new();
    regs.try_reserve_exact(n_total)
        .map_err(|_| FsError::OutOfMemory)?;

    let read_group = |ptr: u64, count: u32, dest: &mut Vec<(u32, u32)>| -> Result<(), Error> {
        if count == 0 || ptr == 0 {
            return Ok(());
        }
        for i in 0..u64::from(count) {
            let at = ptr.checked_add(i * 8).ok_or(FsError::BadAddress)?;
            let mut word = [0u8; 4];
            user.read(at, &mut word)?;
            let addr = u32::from_le_bytes(word);
            if !valid_register(device.graphics, addr) {
                return Err(FsError::InvalidData.into());
            }
            user.read(at.checked_add(4).ok_or(FsError::BadAddress)?, &mut word)?;
            let val = u32::from_le_bytes(word);
            dest.push((addr & 0x3f_ffff, val));
        }
        Ok(())
    };

    read_group(bool_ptr, n_bool, &mut regs)?;
    read_group(flex_ptr, n_flex, &mut regs)?;
    read_group(mux_ptr, n_mux, &mut regs)?;

    let mut registry = REGISTRY[device.card as usize].lock();
    if registry.configs.values().any(|config| config.uuid == uuid) {
        return Err(Error::Errno(EADDRINUSE));
    }
    if budget(&registry) {
        return Err(FsError::OutOfMemory.into());
    }

    let id = (1..=MAX_CONFIGS)
        .find(|id| !registry.configs.contains_key(id))
        .ok_or(FsError::NoSpace)?;
    registry.regs += regs.len();
    registry.configs.insert(
        id,
        Arc::new(Config::new(id, uuid, regs, n_mux, n_bool, n_flex)),
    );
    metrics_add(device.card, &uuid, id);
    Ok(u64::from(id))
}

pub(crate) struct Permit {
    card: u32,
    unit: u32,
    held: AtomicBool,
}
impl Permit {
    /// oa_unit->exclusive_stream.
    pub(crate) fn take(card: u32, unit: u32) -> Result<Self, FsError> {
        if unit >= 2 {
            return Err(FsError::InvalidData);
        }
        ACTIVE
            .get(card as usize)
            .and_then(|units| units.get(unit as usize))
            .ok_or(FsError::NoDevice)?
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| FsError::Busy)?;
        Ok(Self {
            card,
            unit,
            held: AtomicBool::new(true),
        })
    }
    fn release(&self) {
        if self.held.swap(false, Ordering::AcqRel) {
            if let Some(units) = ACTIVE.get(self.card as usize) {
                if let Some(active) = units.get(self.unit as usize) {
                    active.store(false, Ordering::Release);
                }
            }
        }
    }
    #[allow(dead_code)]
    pub(crate) fn unit(&self) -> u32 {
        self.unit
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.release();
    }
}

/// Hardware requests from the stream to its GT owner.
#[derive(Clone, Debug)]
pub enum Request {
    /// Attach, enable the metric set, retire the configuration jobs and,
    /// unless opened disabled, enable the unit.
    Open {
        enable: bool,
    },
    Enable,
    Disable,
    /// DRM_XE_OBSERVATION_IOCTL_CONFIG: retire the new configuration's jobs.
    Config(Arc<Config>),
}

#[derive(Default)]
struct Stream {
    enabled: bool,
    pollin: bool,
    status: u32,
    terminal: Option<FsError>,
}
/// One open OA stream; hardware writes only the GT-owned buffer.
pub struct Session {
    device: Device,
    format: Format,
    sample: bool,
    exponent: Option<u8>,
    wait: u64,
    buffer: u32,
    circ: u32,
    hwe: Engine,
    permit: Permit,
    config: IrqSafeSpinLock<Arc<Config>>,
    stream: IrqSafeSpinLock<Stream>,
    ready: Readiness,
    stop: AtomicBool,
    lock: Mutex<()>,
    /// The attached unit's host pages, for xe_oa_mmap.
    pages: IrqSafeSpinLock<Option<Arc<Pages>>>,
    pub(crate) is_i915: bool,
    exec_queue: Option<u32>,
    /// The retained exec-queue binding (Linux `stream->exec_q`), validated
    /// at enable time; None for queue-less and i915 streams.
    binding: Option<QueueBinding>,
    no_preempt: bool,
    /// PPGTT address of the opener's per-batch query-report buffer in
    /// the bound context's VM (open property 14). 0 when the stream does
    /// no query sampling.
    query_address: u64,
    /// Query-report buffer size in bytes (open property 15). 0 when the
    /// stream does no query sampling.
    query_size: u64,
    privileged: bool,
}
impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("OaSession").field(&self.device).finish()
    }
}
impl Session {
    #[allow(clippy::too_many_arguments)]
    fn new(
        device: Device,
        format: Format,
        sample: bool,
        exponent: Option<u8>,
        wait: u64,
        buffer: u32,
        hwe: Engine,
        permit: Permit,
        config: Arc<Config>,
        is_i915: bool,
        exec_queue: Option<u32>,
        binding: Option<QueueBinding>,
        no_preempt: bool,
        query_address: u64,
        query_size: u64,
        privileged: bool,
    ) -> Arc<Self> {
        // Xe2+ OAG overrun mode writes no partial report at the buffer end.
        let circ = if device.profile() == Profile::Xe2 && sample {
            buffer - buffer % format.size
        } else {
            buffer
        };
        Arc::new(Self {
            device,
            format,
            sample,
            exponent,
            wait,
            buffer,
            circ,
            hwe,
            permit,
            config: IrqSafeSpinLock::new(config),
            stream: IrqSafeSpinLock::new(Stream::default()),
            ready: Readiness::new(0),
            stop: AtomicBool::new(false),
            lock: Mutex::new(()),
            pages: IrqSafeSpinLock::new(None),
            is_i915,
            exec_queue,
            binding,
            no_preempt,
            query_address,
            query_size,
            privileged,
        })
    }
    #[allow(dead_code)]
    pub(crate) fn exec_queue(&self) -> Option<u32> {
        self.exec_queue
    }
    /// The retained exec-queue binding, if this stream names one.
    #[allow(dead_code)]
    pub(crate) fn queue_binding(&self) -> Option<&QueueBinding> {
        self.binding.as_ref()
    }
    /// Whether this stream programs per-context OA: an exec queue on a
    /// render or compute engine (Linux xe_oa_configure_oa_context).
    fn programs_per_context(&self) -> bool {
        self.exec_queue.is_some() && (self.hwe == Engine::Rcs0 || self.hwe.is_compute())
    }
    /// Retain-and-validate the exec queue at enable time (Linux keeps
    /// `stream->exec_q` for the config batches): the binding must still be
    /// alive and bound to this session's engine, else the queue is gone.
    fn validate_binding(&self) -> Result<(), FsError> {
        let Some(id) = self.exec_queue else {
            return Ok(());
        };
        let Some(binding) = &self.binding else {
            return Err(FsError::NotFound);
        };
        if binding.id != id || !binding.alive() || binding.context.engine() != self.hwe {
            return Err(FsError::NotFound);
        }
        Ok(())
    }
    #[allow(dead_code)]
    pub(crate) fn no_preempt(&self) -> bool {
        self.no_preempt
    }
    #[allow(dead_code)]
    pub(crate) fn privileged(&self) -> bool {
        self.privileged
    }
    pub(crate) fn device(&self) -> Device {
        self.device
    }
    #[allow(dead_code)]
    pub(crate) fn oa_unit(&self) -> u32 {
        self.permit.unit
    }
    /// The engine whose kernel queue retires configuration jobs.
    pub(crate) fn engine(&self) -> Engine {
        self.hwe
    }
    pub(crate) fn config(&self) -> Arc<Config> {
        self.config.lock().clone()
    }
    fn level(&self, stream: &Stream) {
        let mask = if stream.terminal.is_some() {
            POLL_IN | POLL_ERR | POLL_HUP
        } else if stream.pollin {
            POLL_IN
        } else {
            0
        };
        self.ready
            .set(mask, (POLL_IN | POLL_ERR | POLL_HUP) & !mask);
    }
    /// Terminal NARF ownership loss: reset, suspend, access loss or close.
    pub(crate) fn fail(&self, error: FsError) {
        let mut stream = self.stream.lock();
        stream.terminal.get_or_insert(error);
        stream.enabled = false;
        self.level(&stream);
    }
    fn set_pollin(&self, pollin: bool) {
        let mut stream = self.stream.lock();
        stream.pollin = pollin;
        self.level(&stream);
    }
    fn set_enabled(&self, enabled: bool) {
        self.stream.lock().enabled = enabled;
    }
    pub(crate) fn enabled(&self) -> bool {
        self.stream.lock().enabled
    }
    /// xe_oa_read's unlocked prologue plus xe_oa_wait_unlocked's refusal.
    fn precheck(&self, blocking: bool) -> Result<(), FsError> {
        let stream = self.stream.lock();
        if let Some(error) = stream.terminal {
            return Err(error);
        }
        if !stream.enabled || !self.sample || (blocking && self.exponent.is_none()) {
            return Err(FsError::InvalidData);
        }
        Ok(())
    }
    /// xe_oa_status_locked: drm_xe_oa_stream_status from the last read.
    fn status_bytes(&self) -> [u8; 40] {
        let status = self.stream.lock().status;
        let mut bytes = [0; 40];
        let mut value = 0u64;
        for (bit, uapi) in [
            (1u32, 1u64),
            (1 << 1, 1 << 1),
            (1 << 2, 1 << 2),
            (1 << 6, 1 << 3),
        ] {
            if status & bit != 0 {
                value |= uapi;
            }
        }
        put64(&mut bytes, 8, value);
        bytes
    }
}

/// The OA buffer's host pages, which xe_oa_mmap remap_pfn_range()s
/// (bo->ttm.ttm->pages). In Linux the VMA's file keeps the stream and its
/// BO alive until munmap; here each mapping holds a [`PageMapping`] token and
/// the unit never returns the pages to its allocator while one is live.
/// When the unit drops with mappings live, the reservation is handed to
/// the last mapping instead: its drop returns it to the allocator
/// (free at last munmap), never while a mapping still aliases it.
pub(crate) struct Pages {
    /// Physical page addresses; empty when the backing has no host frames.
    frames: Vec<u64>,
    state: IrqSafeSpinLock<PageState>,
}
#[derive(Default)]
struct PageState {
    /// The unit gave the reservation up; no new mapping may alias it.
    released: bool,
    maps: usize,
    /// Free installed by `Unit::drop` when the reservation is freeable
    /// but still mapped: run once, by the last mapping's drop, after
    /// the lock is released. `None` until installed, and taken (never
    /// run twice) by whoever observes the last map go.
    pending_free: Option<PendingFree>,
}

/// The allocator and backing a dropping unit hands to the last live
/// mapping, so the reservation is freed at the last munmap instead of
/// leaked. It is type-erased to a raw pointer plus a free function:
/// `Pages` must stay `Send + Sync` (its tokens cross threads as
/// `MmapLifetime`) while `A`/`A::Backing` carry no `Send` bound — the
/// `GpuAllocator` contract does not promise it, and test backings hold
/// `Rc` — so a `Box<dyn FnOnce() + Send>` cannot be stored here.
struct DeferredFree<A: BootAllocator> {
    allocator: A,
    backing: A::Backing,
}

/// A deferred OA reservation free: a heap [`DeferredFree`] erased to a
/// raw pointer plus the function that reconstructs and frees it.
/// The pointer travels as [`CrossThreadPtr`] and the function pointer is
/// plain data, so this is `Send + Sync`; the box contents are only ever
/// touched through `run`.
///
/// # Safety
///
/// - The box is built from owned values; after `into_raw` the stored
///   pointer is the only access path to it — nothing aliases it.
/// - Installed at most once: only `Unit::drop` installs, and a unit
///   drops once with its backing taken once (`Option::take`).
/// - Run at most once: the slot is taken under the `Pages` lock, only
///   by `PageMapping::drop`, and `run` consumes this value; the free
///   function reconstructs the box exactly once via `from_raw`.
/// - Dropping this without `run` leaks the box (and the reservation),
///   by design: the unreachable second-install path prefers a leak to
///   a double free. There is deliberately no `Drop` impl.
/// - Thread use: `run` executes `allocator.free(backing)` on the
///   unmapping thread, so it assumes the allocator tolerates use from
///   that thread. That is true of every allocator in the tree — the
///   production `SharedArena` is already shared across threads behind
///   locks, and the test allocators are `Arc`-based — but it is not
///   enforced by a trait bound: a future `!Send` allocator would be
///   unsound here. A `Send` bound on `GpuAllocator::Backing` was
///   considered and rejected: the test backings in `intel_gpu_media`
///   and `intel_gpu_rcs` hold `Rc`, and converting those fixtures is
///   out of scope for this fix.
///
/// A raw pointer that may cross threads. The address itself is plain
/// data; sending it is sound because the pointed-to box is only ever
/// touched by the thread that takes the `PageState` slot, which
/// reconstructs it with exclusive ownership (see `PendingFree`).
struct CrossThreadPtr(*mut ());
// SAFETY: sending the pointer is sound because after `Box::into_raw` it is
// the only access path to the box — nothing aliases it — and the box is
// only ever touched by the thread that takes the `PageState` slot under
// the `Pages` lock and reconstructs it with exclusive ownership in
// `PendingFree::run`, which consumes the value; moving the pointer to
// another thread cannot create a second access path.
unsafe impl Send for CrossThreadPtr {}
// SAFETY: sharing a reference is sound because the pointer is never
// dereferenced through a shared reference — the only dereference is the
// `Box::from_raw` inside `PendingFree::run`, which requires exclusive
// ownership of the `PendingFree` (slot taken under the lock, value
// consumed), so no thread can touch the box through `&CrossThreadPtr`.
unsafe impl Sync for CrossThreadPtr {}

struct PendingFree {
    /// `Box<DeferredFree<A>>` as a raw pointer; valid until `run`.
    ptr: CrossThreadPtr,
    /// Reconstructs the box exactly once and frees the reservation.
    free: fn(*mut ()),
}
impl PendingFree {
    fn new<A: BootAllocator>(allocator: A, backing: A::Backing) -> Self {
        fn free<A: BootAllocator>(ptr: *mut ()) {
            // SAFETY: `ptr` came from `Box::into_raw` in `new` with this
            // same `A`, and `run` is the only caller, consuming the slot
            // exactly once — so this reconstructs the one live box.
            let deferred = unsafe { Box::from_raw(ptr as *mut DeferredFree<A>) };
            let DeferredFree {
                mut allocator,
                backing,
            } = *deferred;
            allocator.free(backing);
        }
        let ptr =
            CrossThreadPtr(Box::into_raw(Box::new(DeferredFree { allocator, backing })) as *mut ());
        Self {
            ptr,
            free: free::<A>,
        }
    }
    /// Run the deferred free exactly once, consuming this value.
    fn run(self) {
        (self.free)(self.ptr.0);
    }
}
impl Pages {
    fn new(frames: Vec<u64>) -> Arc<Self> {
        Arc::new(Self {
            frames,
            state: IrqSafeSpinLock::new(PageState::default()),
        })
    }
    /// The first `pages` pages and a token that keeps them unreturned.
    fn map(self: &Arc<Self>, pages: usize) -> Result<MmapBacking, FsError> {
        let source = self
            .frames
            .get(..pages)
            .filter(|source| !source.is_empty())
            .ok_or(FsError::NoDevice)?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(source.len())
            .map_err(|_| FsError::OutOfMemory)?;
        frames.extend_from_slice(source);
        let mut state = self.state.lock();
        if state.released {
            return Err(FsError::NoDevice);
        }
        state.maps += 1;
        drop(state);
        Ok(MmapBacking {
            frames,
            lifetime: Some(Arc::new(PageMapping(self.clone())) as Arc<dyn MmapLifetime>),
            memory_type: narf_memory::MemoryType::WriteBack,
        })
    }
    /// Close the reservation to new mappings. True while a user mapping
    /// still aliases it: the caller must then not free the backing.
    fn release(&self) -> bool {
        let mut state = self.state.lock();
        state.released = true;
        state.maps != 0
    }
    fn defer_free(&self, free: PendingFree) {
        let mut state = self.state.lock();
        if state.pending_free.is_none() {
            state.pending_free = Some(free);
        }
        // Otherwise `free` drops here without running: the backing
        // leaks instead of being freed twice. Unreachable in practice.
    }
    /// Live user mappings on this page set; growth refuses while nonzero.
    pub(crate) fn live_maps(&self) -> usize {
        self.state.lock().maps
    }
}
/// One user mapping's hold on the OA buffer pages. The last mapping's
/// drop returns a reservation the unit handed over to the allocator.
struct PageMapping(Arc<Pages>);
impl Drop for PageMapping {
    fn drop(&mut self) {
        let pending = {
            let mut state = self.0.state.lock();
            state.maps -= 1;
            if state.maps == 0 && state.released {
                state.pending_free.take()
            } else {
                None
            }
        };
        // Run outside the lock: the free must never re-enter this state.
        if let Some(free) = pending {
            free.run();
        }
    }
}

pub(crate) struct File {
    session: Arc<Session>,
    backend: Arc<dyn UserBackend>,
    gate: Gate,
    syncobjs: Option<Arc<IrqSafeSpinLock<SyncObjTable>>>,
}
impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("OaFile").field(&self.session).finish()
    }
}
impl Drop for File {
    fn drop(&mut self) {
        // xe_oa_release: the GT owner disables and destroys the stream;
        // the unit becomes available to the next exclusive open.
        self.session.stop.store(true, Ordering::Release);
        self.session.permit.release();
    }
}
impl File {
    fn authority(&self) -> Result<(), FsError> {
        if self.session.privileged {
            self.gate
                .check()
                .inspect_err(|&error| self.session.fail(error))
        } else {
            Ok(())
        }
    }
    async fn ioctl(&self, cmd: u32, arg: u64, user: &dyn IoctlContext) -> Result<u64, Error> {
        let _stream_lock = self.session.lock.lock().await;
        let session = &self.session;
        if let Some(error) = session.stream.lock().terminal {
            return Err(error.into());
        }
        match cmd {
            ENABLE | DISABLE => {
                let enable = cmd == ENABLE;
                if session.enabled() == enable {
                    return Ok(0);
                }
                let request = if enable {
                    Request::Enable
                } else {
                    Request::Disable
                };
                self.backend.oa_control(session.clone(), request).await?;
                Ok(0)
            }
            CONFIG => {
                // xe_oa_config_locked / i915_perf_config_locked returns the previous configuration id.
                let old = session.config().id;
                if session.is_i915 {
                    let config = lookup(session.device.card, arg).ok_or(FsError::InvalidData)?;
                    self.backend
                        .oa_control(session.clone(), Request::Config(config.clone()))
                        .await?;
                    *session.config.lock() = config;
                    Ok(u64::from(old))
                } else {
                    let mut p = Params::new();
                    extensions(session.device, Origin::Config, arg, user, &mut p)?;
                    let config = lookup(session.device.card, u64::from(p.metric_set))
                        .ok_or(FsError::NoDevice)?;
                    if (p.num_syncs != 0 && p.syncs == 0) || (p.num_syncs == 0 && p.syncs != 0) {
                        return Err(FsError::InvalidData.into());
                    }
                    let sync = if p.num_syncs > 0 {
                        let table = self.syncobjs.as_ref().ok_or(FsError::InvalidData)?;
                        Some(XeSync::read(user, p.syncs, p.num_syncs as u32, table)?)
                    } else {
                        None
                    };
                    if let Some(sync) = &sync {
                        sync.wait().await;
                    }
                    self.backend
                        .oa_control(session.clone(), Request::Config(config.clone()))
                        .await?;
                    *session.config.lock() = config;
                    if let Some(sync) = &sync {
                        sync.publish(crate::drm::syncobj::stub());
                        if let Some((address, value)) = sync.user_fence {
                            user.write_u64_release(address, value)?;
                        }
                    }
                    Ok(u64::from(old))
                }
            }
            STATUS => {
                user.write(arg, &session.status_bytes())?;
                Ok(0)
            }
            INFO => {
                let mut bytes = [0u8; 40];
                put64(&mut bytes, 8, u64::from(session.buffer));
                user.write(arg, &bytes)?;
                Ok(0)
            }
            _ => Err(FsError::InvalidData.into()),
        }
    }
}
impl FileOps for File {
    fn read<'a>(&'a self, _: u64, output: &'a mut [u8]) -> FsFuture<'a, usize> {
        self.read_with_options(0, output, ReadOptions::default())
    }
    fn read_with_options<'a>(
        &'a self,
        _: u64,
        output: &'a mut [u8],
        options: ReadOptions,
    ) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.authority()?;
            self.session.precheck(!options.nonblocking)?;
            let _stream_lock = self.session.lock.lock().await;
            self.backend
                .oa_read(self.session.clone(), output, !options.nonblocking)
                .await
        })
    }
    fn write<'a>(&'a self, _: u64, _: &'a [u8]) -> FsFuture<'a, usize> {
        // anon_inode_getfd(.., 0) opens read-only.
        Box::pin(async { Err(FsError::BadFd) })
    }
    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o400,
            },
            mtime_cycles: 0,
        }
    }
    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        user: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            self.authority()?;
            errno(self.ioctl(cmd, arg, user).await)
        })
    }
    fn is_stream(&self) -> bool {
        true
    }
    fn nonblock_read_eagain(&self) -> bool {
        true
    }
    /// xe_oa_mmap's checks in source order: paranoid && !perfmon_capable
    /// (EACCES), a length other than the whole OA buffer (EINVAL), then
    /// VM_WRITE/VM_EXEC/VM_SHARED/VM_MAYSHARE (EINVAL: read-only
    /// MAP_PRIVATE only). The pages are then remapped through
    /// [`FileOps::mmap_private_pfn`] and [`FileOps::mmap_backing`].
    fn validate_mmap(
        &self,
        _offset: u64,
        len: usize,
        prot: u32,
        flags: u32,
    ) -> Result<u32, FsError> {
        const PROT_WRITE: u32 = 2;
        const PROT_EXEC: u32 = 4;
        const MAP_SHARED: u32 = 1;
        if !(self.gate.capable)() {
            return Err(FsError::PermissionDenied);
        }
        if len as u64 != u64::from(self.session.buffer) {
            return Err(FsError::InvalidData);
        }
        // MAP_SHARED and MAP_SHARED_VALIDATE both set VM_MAYSHARE.
        if prot & (PROT_WRITE | PROT_EXEC) != 0 || flags & MAP_SHARED != 0 {
            return Err(FsError::InvalidData);
        }
        Ok(prot)
    }
    /// vm_flags_mod(VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_DONTCOPY,
    /// ..): the mapping is not inherited across fork and cannot grow.
    fn mmap_private_pfn(&self, _offset: u64) -> Option<PrivatePfnMap> {
        Some(PrivatePfnMap { dont_copy: true })
    }
    /// remap_pfn_range of every buffer page from the VMA start; the source
    /// ignores vm_pgoff. ENODEV once the unit released the reservation (GT
    /// reset, suspend or teardown) or when its backing has no host pages.
    fn mmap_backing(&self, _offset: u64, len: usize) -> Result<MmapBacking, FsError> {
        if len as u64 != u64::from(self.session.buffer) {
            return Err(FsError::InvalidData);
        }
        let pages = self.session.pages.lock().clone();
        pages.ok_or(FsError::NoDevice)?.map(len / 4096)
    }
    /// vm_flags_mod(.., VM_MAYWRITE | VM_MAYEXEC): read is the ceiling.
    fn mmap_max_prot(&self, _offset: u64) -> u32 {
        1
    }
    fn poll_readiness(&self) -> u32 {
        if !self.session.privileged || (self.gate.capable)() {
            self.session.ready.mask()
        } else {
            POLL_ERR | POLL_HUP
        }
    }
    fn readiness(&self) -> Option<&Readiness> {
        Some(&self.session.ready)
    }
}

/// Raw MMIO under current GT/D0 authority. A lost transaction is sticky.
struct Io<'a, M: MmioWindow, F: FnMut() -> bool> {
    io: &'a M,
    access: F,
    lost: bool,
}
impl<M: MmioWindow, F: FnMut() -> bool> Io<'_, M, F> {
    fn check(&mut self) -> Result<(), FsError> {
        if self.lost || !(self.access)() {
            self.lost = true;
            Err(FsError::NoDevice)
        } else {
            Ok(())
        }
    }
    fn read(&mut self, reg: u64) -> Result<u32, FsError> {
        self.check()?;
        let value = self.io.read32(reg);
        if value == u32::MAX {
            self.lost = true;
            return Err(FsError::NoDevice);
        }
        self.check()?;
        Ok(value)
    }
    fn write(&mut self, reg: u64, value: u32) -> Result<(), FsError> {
        self.check()?;
        self.io.write32(reg, value);
        self.check()
    }
    /// xe_mmio_rmw32: returns the old value.
    fn rmw(&mut self, reg: u64, clear: u32, set: u32) -> Result<u32, FsError> {
        let old = self.read(reg)?;
        self.write(reg, (old & !clear) | set)?;
        Ok(old)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Quiesce {
    Counter,
    Tlb,
}

/// Allocate and validate one OA reservation of `pages` pages: coherent
/// for the device, exactly the requested size, 64-byte aligned in the
/// GGTT and inside the 4 GiB OA window. A failed validation frees the
/// backing, as `Unit::new` did inline before this helper existed.
fn alloc_reservation<A: BootAllocator>(
    allocator: &mut A,
    pages: u32,
) -> Result<A::Backing, FsError> {
    let backing = allocator.alloc(pages).map_err(|_| FsError::OutOfMemory)?;
    if !backing.coherent_for_device()
        || backing.size_pages() != pages
        || backing.ggtt_offset() & 63 != 0
        || u64::from(backing.ggtt_offset()) + u64::from(pages) * 4096 > 1 << 32
    {
        allocator.free(backing);
        return Err(FsError::Unsupported);
    }
    Ok(backing)
}

/// The host pages a user mapping may alias; empty for device-local or
/// model backings, whose mappings are then ENODEV. Returns `None` only
/// when the frame list itself cannot be allocated.
fn host_frames<B: GpuBacking>(backing: &B, pages: u32) -> Option<Vec<u64>> {
    let mut frames = Vec::new();
    frames.try_reserve_exact(pages as usize).ok()?;
    for page in 0..pages {
        match backing.host_frame(page) {
            Some(frame) if frame != 0 => frames.push(frame),
            _ => {
                frames.clear();
                break;
            }
        }
    }
    Some(frames)
}

/// The main-GT OAG unit and its retained buffer, owned by GuCGt's Parts.
/// Closing or disabling never frees or rebinds the buffer; only verified full
/// GT reset releases storage that the unit was ever pointed at.
pub(crate) struct Unit<A: BootAllocator> {
    /// `Some` until the unit's drop takes it: either freed there, or
    /// handed to the last live mapping with the backing (free at last
    /// munmap). `Option` because `Drop` must move it out of `&mut self`.
    allocator: Option<A>,
    backing: Option<A::Backing>,
    pages: Arc<Pages>,
    platform: GtPlatform,
    graphics: u16,
    session: Option<Arc<Session>>,
    head: u32,
    tail: u32,
    configured: bool,
    active: bool,
    /// Per-context OAR/OAC programming is live on the bound exec queue.
    per_context: bool,
    exposed: bool,
    poisoned: bool,
    retired: bool,
    quiesce: Option<(Quiesce, u64)>,
    next_poll: u64,
}
impl<A: BootAllocator> Unit<A> {
    /// xe_oa_init_gt/__xe_oa_init_oa_units plus the reservation.
    pub(crate) fn new(
        mut allocator: A,
        platform: GtPlatform,
        graphics: u16,
        io: &impl MmioWindow,
        access: impl FnMut() -> bool,
    ) -> Result<Self, FsError> {
        Profile::of(platform, graphics).ok_or(FsError::Unsupported)?;
        let pages = DEFAULT_BUFFER / 4096;
        let backing = alloc_reservation(&mut allocator, pages)?;
        // The host pages a user mapping may alias; none for device-local or
        // model backings, whose mappings are then ENODEV.
        let frames = match host_frames(&backing, pages) {
            Some(frames) => frames,
            None => {
                allocator.free(backing);
                return Err(FsError::OutOfMemory);
            }
        };
        // Counters off and the MMIO trigger disabled until there is a stream.
        let mut io = Io {
            io,
            access,
            lost: false,
        };
        if let Err(error) = io
            .write(OACONTROL, 0)
            .and_then(|()| io.write(OA_DEBUG, masked(DISABLE_MMIO_TRG, DISABLE_MMIO_TRG)))
        {
            allocator.free(backing);
            return Err(error);
        }
        Ok(Self {
            allocator: Some(allocator),
            backing: Some(backing),
            pages: Pages::new(frames),
            platform,
            graphics,
            session: None,
            head: 0,
            tail: 0,
            configured: false,
            active: false,
            per_context: false,
            exposed: false,
            poisoned: false,
            retired: false,
            quiesce: None,
            next_poll: 0,
        })
    }
    pub(crate) fn device(
        &self,
        card: u32,
        engines: EngineSet,
        reference_clock: u32,
        rpm_config0: u32,
    ) -> Option<Device> {
        self.device_with_media(card, engines, reference_clock, rpm_config0, None, None)
    }
    pub(crate) fn device_with_media(
        &self,
        card: u32,
        engines: EngineSet,
        reference_clock: u32,
        rpm_config0: u32,
        media_engines: Option<EngineSet>,
        media_reference_clock: Option<u32>,
    ) -> Option<Device> {
        let media_timestamp = media_reference_clock
            .map(|ref_clk| timestamp_frequency(self.graphics, ref_clk, rpm_config0));
        Device {
            card,
            platform: self.platform,
            graphics: self.graphics,
            timestamp: timestamp_frequency(self.graphics, reference_clock, rpm_config0),
            engines,
            reserve: self.backing.as_ref()?.size_pages() * 4096,
            media_engines,
            media_timestamp,
        }
        .validate()
        .ok()
    }
    fn profile(&self) -> Profile {
        Profile::of(self.platform, self.graphics).expect("qualified OA unit")
    }
    fn gtt(&self) -> Result<u32, FsError> {
        Ok(self
            .backing
            .as_ref()
            .ok_or(FsError::NoDevice)?
            .ggtt_offset())
    }
    pub(crate) fn owns(&self, session: &Arc<Session>) -> bool {
        self.session
            .as_ref()
            .is_some_and(|s| Arc::ptr_eq(s, session))
    }
    /// An open stream holds the device awake, as the source stream's
    /// runtime-PM and forcewake references do.
    pub(crate) fn idle(&self) -> bool {
        self.session.is_none() && !self.poisoned && self.quiesce.is_none()
    }
    pub(crate) fn invalidate(&mut self) {
        if let Some(session) = &self.session {
            session.fail(FsError::NoDevice);
        }
    }
    pub(crate) fn lost(&mut self) {
        self.poisoned = true;
        self.invalidate();
    }
    fn wrap<T>(&mut self, result: Result<T, FsError>) -> Result<T, FsError> {
        if matches!(result, Err(ref e) if *e != FsError::WouldBlock) {
            self.lost();
        }
        result
    }
    fn admit(&self, session: &Arc<Session>) -> Result<(), FsError> {
        if self.poisoned || !self.owns(session) || session.stop.load(Ordering::Acquire) {
            return Err(FsError::NoDevice);
        }
        if let Some(error) = session.stream.lock().terminal {
            return Err(error);
        }
        Ok(())
    }
    /// Run one stream request's register phase. Open returns the ordered
    /// configuration jobs; the owner retires them before `finish`.
    pub(crate) fn begin(
        &mut self,
        io: &impl MmioWindow,
        session: &Arc<Session>,
        request: &Request,
        now: u64,
        access: impl FnMut() -> bool,
    ) -> Result<Vec<Job>, FsError> {
        let mut io = Io {
            io,
            access,
            lost: false,
        };
        match request {
            Request::Open { enable } => {
                if *enable {
                    // A gone queue fails before attach programs
                    // metric-set state for a stream that never runs.
                    session.validate_binding()?;
                }
                self.attach(&mut io, session, now)?;
                let result = self.metric_set(&mut io, session);
                self.wrap(result)?;
                let mut jobs = config_jobs(session.config().regs());
                if *enable {
                    // xe_oa_enable_metric_set configures OAR/OAC before
                    // emitting the metric-set configuration.
                    if let Some(job) = self.per_context_enable(&mut io, session)? {
                        jobs.insert(0, job);
                    }
                }
                Ok(jobs)
            }
            Request::Config(config) => {
                self.admit(session)?;
                Ok(config_jobs(config.regs()))
            }
            Request::Enable => {
                self.admit(session)?;
                Ok(self
                    .per_context_enable(&mut io, session)?
                    .into_iter()
                    .collect())
            }
            Request::Disable => {
                self.admit(session)?;
                Ok(self.per_context_disable(session)?.into_iter().collect())
            }
        }
    }
    /// Validate the retained exec-queue binding and build the per-context
    /// enable job (Linux xe_oa_enable_metric_set's "Configure OAR/OAC").
    /// Compute additionally selects its CCS in OAG OACONTROL first, so the
    /// OAC_OACONTROL LRI below is accepted (Linux
    /// xe_oa_configure_oac_context).
    fn per_context_enable<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
        session: &Session,
    ) -> Result<Option<Job>, FsError> {
        session.validate_binding()?;
        let Some(job) = per_context_job(session, true) else {
            return Ok(None);
        };
        if session.hwe.is_compute() {
            io.rmw(
                OACONTROL,
                CCS_SELECT,
                (session.hwe.physical_instance() << 16) & CCS_SELECT,
            )?;
        }
        Ok(Some(job))
    }
    /// Build the per-context disable job (Linux xe_oa_disable_metric_set's
    /// configure_oa_context(false)). A queue that is already gone takes
    /// its context with it, so the disable job is skipped and the global
    /// disable below still runs; the enable path, unlike disable, must
    /// fail cleanly instead.
    fn per_context_disable(&mut self, session: &Session) -> Result<Option<Job>, FsError> {
        if !self.per_context {
            return Ok(None);
        }
        let Some(job) = per_context_job(session, false) else {
            return Ok(None);
        };
        if session.validate_binding().is_err() {
            self.per_context = false;
            return Ok(None);
        }
        Ok(Some(job))
    }
    /// The register phase after configuration retirement.
    pub(crate) fn finish(
        &mut self,
        io: &impl MmioWindow,
        session: &Arc<Session>,
        request: &Request,
        now: u64,
        access: impl FnMut() -> bool,
    ) -> Result<(), FsError> {
        let mut io = Io {
            io,
            access,
            lost: false,
        };
        self.admit(session)?;
        let result = match request {
            Request::Open { enable: true } | Request::Enable => self.enable(&mut io, session, now),
            Request::Disable => self.disable(&mut io, session, now),
            Request::Open { enable: false } | Request::Config(_) => Ok(()),
        };
        self.wrap(result)
    }
    /// Grow the retained reservation to `size` bytes when a stream requests
    /// more than the unit holds. The reservation is a high-water mark: it
    /// never shrinks, so a later small stream reuses the larger buffer.
    /// Growth refuses (ENOMEM) while a user mapping still aliases the old
    /// pages — freeing them under a live VMA would hand it a recycled
    /// range — and frees the old backing before allocating, so the unit
    /// never holds two reservations at once. A failed allocation leaves
    /// the unit without a backing; later opens then fail NoDevice until
    /// the GT is re-prepared.
    fn grow(&mut self, size: u32, card: u32) -> Result<(), FsError> {
        let current = self
            .backing
            .as_ref()
            .map_or(0, |backing| backing.size_pages() * 4096);
        if size <= current {
            return Ok(());
        }
        if self.pages.live_maps() != 0 {
            return Err(FsError::OutOfMemory);
        }
        // The allocator is `Option` only so `Drop` can move it out; it
        // is only ever taken there, so a live unit always has one. A
        // missing one is unreachable, but fail closed (NoDevice) rather
        // than panic, matching the unit's no-backing convention.
        let Some(allocator) = self.allocator.as_mut() else {
            return Err(FsError::NoDevice);
        };
        if let Some(old) = self.backing.take() {
            allocator.free(old);
        }
        let pages = size / 4096;
        let backing = alloc_reservation(&mut *allocator, pages)?;
        let frames = match host_frames(&backing, pages) {
            Some(frames) => frames,
            None => {
                allocator.free(backing);
                return Err(FsError::OutOfMemory);
            }
        };
        self.pages = Pages::new(frames);
        self.backing = Some(backing);
        if let Some(reserve) = RESERVE.get(card as usize) {
            reserve.store(size, Ordering::Release);
        }
        Ok(())
    }
    fn attach<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
        session: &Arc<Session>,
        now: u64,
    ) -> Result<(), FsError> {
        if self.poisoned {
            return Err(FsError::NoDevice);
        }
        let device = session.device;
        if (device.platform, device.graphics) != (self.platform, self.graphics) {
            return Err(FsError::NoDevice);
        }
        if let Some(old) = &self.session {
            if !old.stop.load(Ordering::Acquire) {
                return Err(FsError::Busy);
            }
            match self.teardown(io, now) {
                Ok(true) => {}
                Ok(false) => return Err(FsError::WouldBlock),
                Err(error) => {
                    self.lost();
                    return Err(error);
                }
            }
        }
        if let Err(error) = self.advance(io, now) {
            self.lost();
            return Err(error);
        }
        if self.quiesce.is_some() {
            return Err(FsError::WouldBlock);
        }
        if session.stop.load(Ordering::Acquire) {
            return Err(FsError::NoDevice);
        }
        // The reservation follows the stream: a buffer inside the Linux
        // range grows the retained backing past the 16 MiB default
        // (ENOMEM while a user mapping aliases the old pages, or when
        // the allocator refuses). The session then maps the new pages.
        self.grow(session.buffer, device.card)?;
        *session.pages.lock() = Some(self.pages.clone());
        self.session = Some(session.clone());
        Ok(())
    }
    /// xe_oa_enable_metric_set before xe_oa_emit_oa_config.
    fn metric_set<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
        session: &Session,
    ) -> Result<(), FsError> {
        self.configured = true;
        if self.profile() == Profile::Dg2 {
            // Wa_1508761755: EU NOA signals need EU/thread-stall DOP gating off.
            io.write(ROW_CHICKEN, masked(1 << 5, 1 << 5))?;
            io.write(ROW_CHICKEN2, masked(1, 1))?;
        }
        let mut debug = DISABLE_CLK_RATIO | INCLUDE_CLK_RATIO;
        if self.profile() == Profile::Xe2 {
            debug |= START_TRIGGER_SCOPE | DISABLE_TRG_2_QUAL | DISABLE_TRG_1_QUAL;
        }
        io.write(
            OA_DEBUG,
            masked(debug, debug)
                | masked(
                    DISABLE_CTX_SWITCH,
                    if session.sample {
                        0
                    } else {
                        DISABLE_CTX_SWITCH
                    },
                )
                | masked(
                    BUF_SIZE_SELECT,
                    if session.buffer > 16 << 20 {
                        BUF_SIZE_SELECT
                    } else {
                        0
                    },
                )
                | masked(
                    DISABLE_MMIO_TRG,
                    if session.sample { 0 } else { DISABLE_MMIO_TRG },
                ),
        )?;
        io.write(
            OAGLBCTXCTRL,
            1 | session
                .exponent
                .map_or(0, |e| 2 | ((u32::from(e) << 2) & 0xfc)),
        )?;
        io.rmw(SQCNT1, 0, SQCNT1_BITS)?;
        Ok(())
    }
    /// xe_oa_disable_metric_set.
    fn stop_metric_set<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
    ) -> Result<(), FsError> {
        if !self.configured {
            return Ok(());
        }
        if self.profile() == Profile::Dg2 {
            io.write(ROW_CHICKEN, masked(1 << 5, 0))?;
            io.write(ROW_CHICKEN2, masked(1, 0))?;
        }
        io.write(OA_DEBUG, masked(DISABLE_MMIO_TRG, DISABLE_MMIO_TRG))?;
        io.rmw(RPM_CONFIG1, GT_NOA_ENABLE, 0)?;
        io.rmw(SQCNT1, SQCNT1_BITS, 0)?;
        self.configured = false;
        Ok(())
    }
    /// xe_oa_stream_enable: xe_oa_init_oa_buffer, then OACONTROL.
    fn enable<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
        session: &Arc<Session>,
        now: u64,
    ) -> Result<(), FsError> {
        if self.active {
            return Ok(());
        }
        if self.quiesce.is_some() {
            self.advance(io, now)?;
            if self.quiesce.is_some() {
                return Err(FsError::WouldBlock);
            }
        }
        session.set_pollin(false);
        let gtt = self.gtt()?;
        let field = buffer_field(session.buffer);
        self.exposed = true;
        io.write(OASTATUS, 0)?;
        io.write(OAHEADPTR, gtt & PTR_MASK)?;
        self.head = 0;
        // "This MMIO must be set before the OATAILPTR register and after the
        // OAHEADPTR register."
        io.write(OABUFFER, gtt | 1 | (field << 3))?;
        io.write(OATAILPTR, gtt & PTR_MASK)?;
        self.tail = 0;
        let backing = self.backing.as_ref().ok_or(FsError::NoDevice)?;
        for at in (0..u64::from(session.buffer)).step_by(4) {
            backing.write32(at, 0);
        }
        fence(Ordering::Release);
        let mut control = session.format.control() | COUNTER_ENABLE;
        if session.hwe.is_compute() {
            control |= (session.hwe.physical_instance() << 16) & CCS_SELECT;
        }
        if self.profile() == Profile::Xe2 {
            control |= PES_DISAG_EN;
        }
        io.rmw(OACONTROL, OACONTROL_USED, control)?;
        // NO_PREEMPT + query sampling (issue #1774), applied only once
        // the MMIO enable has succeeded: the schedule override and the
        // per-batch query sampler live on the bound context from here
        // until disable, so the next claim's GuC Policy KLVs carry
        // quantum 0 / preempt timeout 0 and the exec path emits one
        // MI_REPORT_PERF_COUNT per batch. A stream with no bound queue
        // (or no query buffer) applies nothing.
        if session.no_preempt() {
            if let Some(binding) = session.queue_binding() {
                binding.context.oa_apply_no_preempt();
            }
        }
        if session.query_address != 0 {
            if let Some(binding) = session.queue_binding() {
                binding
                    .context
                    .set_query_sampler(Some(Arc::new(QuerySampler::new(
                        session.query_address,
                        session.query_size as u32,
                        session.format.size,
                    ))));
            }
        }
        self.active = true;
        self.next_poll = now.saturating_add(POLL_NS);
        session.set_enabled(true);
        self.per_context = session.programs_per_context();
        Ok(())
    }
    /// xe_oa_disable: clear OACONTROL, wait for the counter, then the
    /// <=12.70 (not 12.60) OA TLB invalidation. Timeouts are logged only.
    fn disable<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
        session: &Session,
        now: u64,
    ) -> Result<(), FsError> {
        session.set_enabled(false);
        // NO_PREEMPT + query sampling (issue #1774): restore the bound
        // context's schedule and stop the per-batch query. This runs
        // before the active early-return on purpose, so a disable of a
        // stream whose MMIO was never enabled still cannot leak the
        // override; both restores are idempotent no-ops when nothing
        // was applied. The retained binding still names the context
        // even when the queue itself is gone.
        if let Some(binding) = session.queue_binding() {
            binding.context.oa_restore_no_preempt();
            binding.context.set_query_sampler(None);
        }
        if !self.active {
            return Ok(());
        }
        io.rmw(OACONTROL, OACONTROL_USED, 0)?;
        self.active = false;
        self.per_context = false;
        self.quiesce = Some((Quiesce::Counter, now.saturating_add(QUIESCE_NS)));
        self.advance(io, now)
    }
    fn advance<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
        now: u64,
    ) -> Result<(), FsError> {
        loop {
            match self.quiesce {
                None => return Ok(()),
                Some((Quiesce::Counter, deadline)) => {
                    if io.read(OACONTROL)? & COUNTER_ENABLE != 0 && now < deadline {
                        return Ok(());
                    }
                    self.quiesce = if self.graphics <= 1270 && self.graphics != 1260 {
                        io.write(OA_TLB_INV_CR, 1)?;
                        Some((Quiesce::Tlb, now.saturating_add(QUIESCE_NS)))
                    } else {
                        None
                    };
                }
                Some((Quiesce::Tlb, deadline)) => {
                    if io.read(OA_TLB_INV_CR)? & 1 != 0 && now < deadline {
                        return Ok(());
                    }
                    self.quiesce = None;
                }
            }
        }
    }
    /// xe_oa_destroy_locked: disable, then xe_oa_disable_metric_set.
    fn teardown<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
        now: u64,
    ) -> Result<bool, FsError> {
        let Some(session) = self.session.clone() else {
            return Ok(true);
        };
        // Teardown retires no LRI disable: it has no job channel, and the
        // bits are context state (Linux clears them only at stream destroy,
        // not on plain disable).
        if self.active {
            self.disable(io, &session, now)?;
        }
        self.advance(io, now)?;
        if self.quiesce.is_some() {
            return Ok(false);
        }
        self.stop_metric_set(io)?;
        session.set_enabled(false);
        self.session = None;
        Ok(true)
    }
    /// Stop without waiting, before the GT stop/reset that follows.
    pub(crate) fn halt(&mut self, io: &impl MmioWindow, access: impl FnMut() -> bool) {
        let mut io = Io {
            io,
            access,
            lost: false,
        };
        let result = (|| -> Result<(), FsError> {
            if self.active {
                io.rmw(OACONTROL, OACONTROL_USED, 0)?;
                self.active = false;
            }
            self.per_context = false;
            self.stop_metric_set(&mut io)
        })();
        // NO_PREEMPT + query sampling (issue #1774): the GT is stopping
        // and this path clears `active` without going through
        // `disable`, so restore the bound context's schedule and clear
        // the query sampler here before the session is dropped.
        if let Some(session) = &self.session {
            if let Some(binding) = session.queue_binding() {
                binding.context.oa_restore_no_preempt();
                binding.context.set_query_sampler(None);
            }
        }
        self.invalidate();
        self.session = None;
        self.quiesce = None;
        if result.is_err() {
            self.poisoned = true;
        }
    }
    /// The hrtimer and close/teardown service.
    pub(crate) fn poll(&mut self, io: &impl MmioWindow, now: u64, access: impl FnMut() -> bool) {
        let mut io = Io {
            io,
            access,
            lost: false,
        };
        let result = (|| -> Result<(), FsError> {
            if self.poisoned {
                return Ok(());
            }
            if self
                .session
                .as_ref()
                .is_some_and(|s| s.stop.load(Ordering::Acquire))
            {
                self.teardown(&mut io, now)?;
                return Ok(());
            }
            self.advance(&mut io, now)?;
            let Some(session) = self.session.clone() else {
                return Ok(());
            };
            if self.active && session.sample && now >= self.next_poll {
                self.next_poll = now.saturating_add(POLL_NS);
                self.check(&mut io, &session)?;
            }
            Ok(())
        })();
        let _ = self.wrap(result);
    }
    fn report_word(&self, at: u32) -> u32 {
        self.backing
            .as_ref()
            .map_or(0, |backing| backing.read32(u64::from(at)))
    }
    /// xe_oa_buffer_check_unlocked. A report is landed only after the
    /// following report's id or timestamp has landed.
    fn check<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
        session: &Session,
    ) -> Result<bool, FsError> {
        let size = session.format.size;
        let circ = session.circ;
        let diff = |tail: u32, head: u32| {
            if tail >= head {
                tail - head
            } else {
                tail + circ - head
            }
        };
        let hw = (io.read(OATAILPTR)? & PTR_MASK).wrapping_sub(self.gtt()?);
        if hw >= circ {
            // Malformed occupancy: the unit names memory outside its ring.
            return Err(FsError::InvalidData);
        }
        fence(Ordering::Acquire);
        let partial = diff(hw, self.tail) % size;
        let hw = diff(hw, partial);
        let mut tail = hw;
        while diff(tail, self.tail) >= size {
            let landed = if session.format.header64 {
                (0..4).any(|w| self.report_word(tail + w * 4) != 0)
            } else {
                (0..2).any(|w| self.report_word(tail + w * 4) != 0)
            };
            if landed {
                break;
            }
            tail = diff(tail, size);
        }
        self.tail = tail;
        let available = diff(self.tail, self.head);
        let pollin = u64::from(available) >= session.wait * u64::from(size);
        session.set_pollin(pollin);
        Ok(pollin)
    }
    /// xe_oa_read/__xe_oa_read/xe_oa_append_reports under the stream lock.
    pub(crate) fn read(
        &mut self,
        io: &impl MmioWindow,
        session: &Arc<Session>,
        out: &mut [u8],
        blocking: bool,
        access: impl FnMut() -> bool,
    ) -> Result<usize, FsError> {
        let mut io = Io {
            io,
            access,
            lost: false,
        };
        self.admit(session)?;
        session.precheck(blocking)?;
        if !self.active {
            return Err(FsError::InvalidData);
        }
        let hardware = (|| -> Result<Option<(usize, Option<FsError>, bool)>, FsError> {
            let pollin = self.check(&mut io, session)?;
            if blocking && !pollin {
                return Ok(None);
            }
            // Only clear our bits to avoid side effects.
            let status = io.rmw(OASTATUS, STATUS_RELEVANT, 0)?;
            session.stream.lock().status = status;
            if status & STATUS_RELEVANT != 0 {
                return Ok(Some((0, None, true)));
            }
            let (copied, error) = self.append(&mut io, session, out)?;
            Ok(Some((copied, error, false)))
        })();
        let Some((copied, error, eio)) = self.wrap(hardware)? else {
            return Err(FsError::WouldBlock);
        };
        // pollin survives ENOSPC (more data than room) and EIO (status).
        if !eio && error != Some(FsError::NoSpace) {
            session.set_pollin(false);
        }
        match (copied, error) {
            (0, _) if eio => Err(crate::intel_gpu_user::io_error()),
            (0, Some(error)) => Err(error),
            (0, None) => Err(FsError::WouldBlock),
            (copied, _) => Ok(copied),
        }
    }
    fn append<M: MmioWindow, F: FnMut() -> bool>(
        &mut self,
        io: &mut Io<'_, M, F>,
        session: &Session,
        out: &mut [u8],
    ) -> Result<(usize, Option<FsError>), FsError> {
        let size = session.format.size;
        let circ = session.circ;
        let gtt = self.gtt()?;
        let backing = self.backing.as_ref().ok_or(FsError::NoDevice)?;
        let wrap = |at: u32| if at >= circ { at - circ } else { at };
        let mut head = self.head;
        let tail = self.tail;
        let mut copied = 0usize;
        let mut error = None;
        let header_len = if session.is_i915 { 8 } else { 0 };
        let rec_size = header_len + size as usize;
        while head != tail {
            if out.len() - copied < rec_size {
                error = Some(FsError::NoSpace);
                break;
            }
            if session.is_i915 {
                let total_rec_size = (8 + size) as u16;
                put32(&mut out[copied..copied + 4], 0, 1); // DRM_I915_PERF_RECORD_SAMPLE
                out[copied + 4..copied + 6].copy_from_slice(&0u16.to_le_bytes());
                out[copied + 6..copied + 8].copy_from_slice(&total_rec_size.to_le_bytes());
            }
            let report_offset = copied + header_len;
            for (i, chunk) in out[report_offset..report_offset + size as usize]
                .chunks_exact_mut(4)
                .enumerate()
            {
                let at = wrap(head + i as u32 * 4);
                chunk.copy_from_slice(&backing.read32(u64::from(at)).to_le_bytes());
            }
            // Clear the report id and timestamp to detect unlanded reports;
            // zero a report entirely when reports straddle the ring end.
            let clear = if circ % size == 0 {
                if session.format.header64 {
                    16
                } else {
                    8
                }
            } else {
                size
            };
            for i in (0..clear).step_by(4) {
                backing.write32(u64::from(wrap(head + i)), 0);
            }
            copied += rec_size;
            head = wrap(head + size);
        }
        if copied != 0 {
            fence(Ordering::Release);
            io.write(OAHEADPTR, head.wrapping_add(gtt) & PTR_MASK)?;
            self.head = head;
        }
        Ok((copied, error))
    }
    /// # Safety
    /// The caller has proven full graphics-GT reset, GuC reset and DMA idle.
    pub(crate) unsafe fn release_after_reset(mut self) {
        self.invalidate();
        self.session = None;
        self.retired = true;
    }
}
impl<A: BootAllocator> Drop for Unit<A> {
    fn drop(&mut self) {
        self.invalidate();
        let Some(backing) = self.backing.take() else {
            return;
        };
        // The allocator is only ever taken here; a missing one is
        // unreachable, but forgetting the backing is the safe fallback
        // (a leak, never a double free).
        let Some(mut allocator) = self.allocator.take() else {
            core::mem::forget(backing);
            return;
        };
        // Close the reservation to new mappings first: a mapping handed
        // out before this point still aliases the pages.
        let mapped = self.pages.release();
        if (!self.exposed || self.retired) && !mapped {
            allocator.free(backing);
        } else if (!self.exposed || self.retired) && mapped {
            // Freeable but still aliased: hand the reservation to the
            // last live mapping instead of forgetting it. The last
            // `PageMapping` drop returns it to the allocator; a token
            // that never drops keeps it, as before. `release_after_reset`
            // composes here: it sets `retired`, so the unit drops down
            // this path, and the single deferred free is the only free.
            self.pages.defer_free(PendingFree::new(allocator, backing));
        } else {
            // Exposed without a reset proof: the engine may still DMA
            // into the reservation, so it is deliberately retained.
            core::mem::forget(backing);
        }
    }
}

/// Exact boot opt-in `narf.intel.oa=1`.
pub(crate) fn enabled() -> bool {
    let args = narf_boot::args();
    let mut values = args
        .tokens()
        .take_while(|t| *t != "--")
        .filter_map(|t| t.strip_prefix("narf.intel.oa="));
    values.next() == Some("1") && values.next().is_none() && !args.has_flag("narf.intel.oa")
}

/// RPM_CONFIG0, read once at publication for the CTC-shift workaround.
pub(crate) const RPM_CONFIG0_REG: u64 = RPM_CONFIG0;
/// Current OA authority, shared with EU-stall observation.
pub(crate) fn capable() -> bool {
    crate::intel_gpu_eu_stall::capable()
}

/// A sampling stream on `device` with a private configuration, for GT-model
/// fixtures outside this module.
#[cfg(feature = "kernel-test")]
pub(crate) fn test_session(
    device: Device,
    format: usize,
    buffer: u32,
    exponent: Option<u8>,
    regs: &[(u32, u32)],
) -> Arc<Session> {
    Session::new(
        device,
        FORMATS[format],
        true,
        exponent,
        1,
        buffer,
        device.oag_engines().next().expect("OAG engine"),
        Permit::take(device.card, 0).expect("free OA unit"),
        Arc::new(Config::new(
            1,
            [b'0'; 36],
            regs.to_vec(),
            regs.len() as u32,
            0,
            0,
        )),
        false,
        None,
        None,
        false,
        0,
        0,
        true,
    )
}

/// A sampling stream on `device` bound to an exec queue, for GT-model
/// fixtures outside this module. The binding's liveness probe is `alive`.
#[cfg(feature = "kernel-test")]
pub(crate) fn test_session_exec(
    device: Device,
    format: usize,
    buffer: u32,
    engine: Engine,
    queue: u32,
    alive: Arc<dyn Fn() -> bool + Send + Sync>,
) -> Arc<Session> {
    Session::new(
        device,
        FORMATS[format],
        true,
        None,
        1,
        buffer,
        engine,
        Permit::take(device.card, 0).expect("free OA unit"),
        Arc::new(Config::new(1, [b'0'; 36], Vec::new(), 0, 0, 0)),
        false,
        Some(queue),
        Some(QueueBinding::new(
            queue,
            UserContext::for_engine(engine),
            alive,
        )),
        false,
        0,
        0,
        true,
    )
}

#[cfg(feature = "kernel-test")]
pub(crate) fn test_session_i915(
    device: Device,
    format: usize,
    buffer: u32,
    exponent: Option<u8>,
    regs: &[(u32, u32)],
) -> Arc<Session> {
    Session::new(
        device,
        FORMATS[format],
        true,
        exponent,
        1,
        buffer,
        device.oag_engines().next().expect("OAG engine"),
        Permit::take(device.card, 0).expect("free OA unit"),
        Arc::new(Config::new(
            1,
            [b'0'; 36],
            regs.to_vec(),
            regs.len() as u32,
            0,
            0,
        )),
        true,
        None,
        None,
        false,
        0,
        0,
        true,
    )
}

#[cfg(feature = "kernel-test")]
#[path = "intel_gpu_oa_tests.rs"]
mod tests;
