//! RDNA4 (GC 12.0.x) chip identity: which die is bound, and the handful of
//! places where Linux amdgpu treats the two dies differently.
//!
//! Linux binds every RDNA4 board through the generic
//! `{ PCI_DEVICE(0x1002, PCI_ANY_ID), .class = PCI_CLASS_DISPLAY_* }`
//! entries in `amdgpu_drv.c` (`CHIP_IP_DISCOVERY`) and decides everything
//! after that from the discovery blob: `soc24.c` and `gfx_v12_0.c` switch on
//! the GC version, `psp_v14_0.c` and `smu_v14_0_2_ppt.c` on MP0/MP1, DC on
//! `external_rev_id`. This module is that switch. [`Rdna4Chip::of`] keys on
//! discovered GC (and the AMD vendor plus the `Navi4` family the probe
//! assigns) — never on the PCI device id, which only names the board.
//!
//! | GC     | die    | MP0/MP1 | SDMA  | external_rev     | DAL macro             |
//! |--------|--------|---------|-------|------------------|-----------------------|
//! | 12.0.0 | Navi44 | 14.0.2  | 7.0.0 | rev_id + 0x40    | `ASICREV_IS_GC_12_0_1_A0` |
//! | 12.0.1 | Navi48 | 14.0.3  | 7.0.1 | rev_id + 0x50    | `ASICREV_IS_GC_12_0_0_A0` |
//!
//! DAL's `dal_asic_id.h` names the ranges the other way round
//! (`GC_12_0_0_A0 = 0x50`, `GC_12_0_1_A0 = 0x40`): its "GC_12_0_0" range is
//! the external revision `soc24_common_early_init` assigns to IP GC 12.0.1.
//! Every DC difference below is expressed by die to keep that out of callers.
//!
//! The full inventory of Linux's per-version differences, and the reasons the
//! shared paths stay shared, is in the GPU specification §3.
use crate::{
    amdgpu::{AmdGpu, Family, AMD_VENDOR},
    amdgpu_discovery::{self as ip, IpBlock},
};
use core::sync::atomic::{AtomicU8, Ordering};

/// The two RDNA4 dies Linux supports (`soc24_common_early_init`'s cases).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rdna4Chip {
    /// GC 12.0.1: RX 9070 / 9070 XT / 9070 GRE, Radeon AI PRO R9700.
    Navi48,
    /// GC 12.0.0: RX 9060 XT / RX 9060.
    Navi44,
}

/// Every GC version `gfx_v12_0`, `gmc_v12_0`, `imu_v12_0` and `mes_v12_0`
/// handle with one case. Both share `gc_12_0_0_offset.h`, so a register bank
/// lookup that accepts one accepts both.
pub const GC_VERSIONS: &[(u8, u8, u8)] = &[(12, 0, 0), (12, 0, 1)];
/// MP0 / MP1 versions `psp_v14_0` and `smu_v14_0_2_ppt` share
/// (`amdgpu_discovery.c` adds the same IP block for both). Selection between
/// them is by the discovered revision, never by the GC die.
pub const MP_VERSIONS: &[(u8, u8, u8)] = &[(14, 0, 2), (14, 0, 3)];

/// A board whose PCI id `pci.ids` names. The probe does not need this list —
/// an unlisted RDNA4 id (RX 9060, OEM variants) is admitted by the class
/// match plus discovery — but listed ids also get an exact bus match, log a
/// marketing name, and let a test pin the identity. This is the only RDNA4
/// PCI id list in the driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownDevice {
    pub did: u16,
    pub chip: Rdna4Chip,
    /// `pci.ids`' device name.
    pub name: &'static str,
}
pub const KNOWN_DEVICES: &[KnownDevice] = &[
    KnownDevice {
        did: 0x7550,
        chip: Rdna4Chip::Navi48,
        name: "Navi 48 [Radeon RX 9070/9070 XT/9070 GRE]",
    },
    KnownDevice {
        did: 0x7551,
        chip: Rdna4Chip::Navi48,
        name: "Navi 48 [Radeon AI PRO R9700]",
    },
    KnownDevice {
        did: 0x7590,
        chip: Rdna4Chip::Navi44,
        name: "Navi 44 [Radeon RX 9060 XT]",
    },
];
pub fn known_device(did: u16) -> Option<&'static KnownDevice> {
    KNOWN_DEVICES.iter().find(|d| d.did == did)
}

impl Rdna4Chip {
    pub const ALL: [Self; 2] = [Self::Navi48, Self::Navi44];

    pub const fn from_gc(version: (u8, u8, u8)) -> Option<Self> {
        match version {
            (12, 0, 1) => Some(Self::Navi48),
            (12, 0, 0) => Some(Self::Navi44),
            _ => None,
        }
    }
    /// The die discovery describes: exactly one GC instance 0, of a GC 12.0.x
    /// version Linux supports. Duplicate or absent GC fails closed.
    pub fn from_ip_blocks(blocks: &[IpBlock]) -> Option<Self> {
        let mut gc = blocks
            .iter()
            .filter(|b| b.hw_id == ip::HW_ID_GC && b.instance == 0);
        let first = gc.next()?;
        if gc.next().is_some() {
            return None;
        }
        Self::from_gc((first.major, first.minor, first.revision))
    }
    /// The RDNA4 die this probed AMD GPU is, or `None` for every other part.
    /// A device id the PCI table assigns to another family is refused even
    /// with RDNA4 discovery: the identity would be self-contradictory.
    pub fn of(gpu: &AmdGpu) -> Option<Self> {
        if gpu.chip.vid != AMD_VENDOR
            || gpu.chip.family != Family::Navi4
            || crate::amdgpu::family_for_pci_id(gpu.chip.vid, gpu.chip.did)
                .is_some_and(|f| f != Family::Navi4)
        {
            return None;
        }
        Self::from_ip_blocks(&gpu.ip_blocks)
    }
    pub const fn gc_version(self) -> (u8, u8, u8) {
        match self {
            Self::Navi48 => (12, 0, 1),
            Self::Navi44 => (12, 0, 0),
        }
    }
    /// Linux `amdgpu_asic_name`-style short name, also the boot log's.
    pub const fn asic(self) -> &'static str {
        match self {
            Self::Navi48 => "navi48",
            Self::Navi44 => "navi44",
        }
    }
    /// `soc24_common_early_init`: `external_rev_id = rev_id + 0x50` for GC
    /// 12.0.1 and `+ 0x40` for GC 12.0.0. `AMDGPU_INFO_DEV_INFO` reports it
    /// and Mesa picks GFX1201 against GFX1200 from it.
    pub const fn external_rev(self, rev_id: u8) -> u32 {
        rev_id as u32
            + match self {
                Self::Navi48 => 0x50,
                Self::Navi44 => 0x40,
            }
    }
    /// Mesa's `AMDGPU_GFX1200_RANGE` (0x40..0x50) and
    /// `AMDGPU_GFX1201_RANGE` (0x50..0xFF), `amdgpu_asic_addr.h`: the
    /// half-open `external_rev` window `ac_query_gpu_info`'s
    /// `identify_chip` accepts for this die. Anything else leaves Mesa
    /// without a chip and the device unusable.
    pub const fn mesa_external_rev_range(self) -> core::ops::Range<u32> {
        match self {
            Self::Navi48 => 0x50..0xFF,
            Self::Navi44 => 0x40..0x50,
        }
    }
    /// `kfd_device.c` `gfx_target_version` (gfx1201 / gfx1200).
    pub const fn gfx_target_version(self) -> u32 {
        match self {
            Self::Navi48 => 120001,
            Self::Navi44 => 120000,
        }
    }
    /// `soc24_common_early_init` pg_flags: only GC 12.0.1 carries
    /// `AMD_PG_SUPPORT_JPEG_DPG`; both carry VCN, JPEG and VCN_DPG. The cg
    /// flags are identical.
    pub const fn jpeg_dpg(self) -> bool {
        matches!(self, Self::Navi48)
    }
    /// `dcn401_calc_num_avail_chans_for_mall`'s per-ASIC clamp of the
    /// power-of-two MALL channel count: 16 on Navi48, 8 on Navi44.
    pub const fn mall_channel_limit(self) -> u32 {
        match self {
            Self::Navi48 => 16,
            Self::Navi44 => 8,
        }
    }
    /// `dcn401_resource_construct`: `dc->caps.dcc_plane_width_limit = 7680`
    /// only for `ASICREV_IS_GC_12_0_1_A0` (Navi44). Zero means no limit.
    pub const fn dcc_plane_width_limit(self) -> u32 {
        match self {
            Self::Navi48 => 0,
            Self::Navi44 => 7680,
        }
    }
    /// `dcn401_is_ppclk_idle_dpm_enabled`: the PMFW version from which
    /// UCLK/FCLK idle DPM is trusted (Navi48 0x681800, Navi44 0x661300).
    pub const fn idle_dpm_min_smu(self) -> u32 {
        match self {
            Self::Navi48 => 0x0068_1800,
            Self::Navi44 => 0x0066_1300,
        }
    }
    /// `dcn401_is_df_throttle_opt_enabled`: Navi44 only, from PMFW 0x663500.
    pub const fn df_throttle_min_smu(self) -> Option<u32> {
        match self {
            Self::Navi48 => None,
            Self::Navi44 => Some(0x0066_3500),
        }
    }
}

/// `amdgpu_ucode.c` `kicker_device_list`: boards whose PSP SOS/TA, SMU, RLC
/// and IMU firmware are the `_kicker` builds. Of RDNA4 only the AI PRO R9700
/// revision 0xC8 is listed.
pub(crate) const KICKER_DEVICES: &[(u16, u8)] = &[(0x744B, 0x00), (0x7551, 0xC8)];
pub fn is_kicker(did: u16, revision: u8) -> bool {
    KICKER_DEVICES.contains(&(did, revision))
}

/// GC-die firmware names (`gfx_v12_0.c`, `imu_v12_0.c`, `mes_v12_0.c`
/// `MODULE_FIRMWARE`). Kicker builds exist only for GC 12.0.1's RLC and IMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GcFirmware {
    pub pfp: &'static str,
    pub me: &'static str,
    pub mec: &'static str,
    pub rlc: &'static str,
    pub rlc_kicker: Option<&'static str>,
    pub imu: &'static str,
    pub imu_kicker: Option<&'static str>,
    pub mes: &'static str,
    pub mes1: &'static str,
    pub uni_mes: &'static str,
}
macro_rules! gc_fw {
    ($p:literal, $kicker:expr) => {
        GcFirmware {
            pfp: concat!("amdgpu/", $p, "_pfp.bin"),
            me: concat!("amdgpu/", $p, "_me.bin"),
            mec: concat!("amdgpu/", $p, "_mec.bin"),
            rlc: concat!("amdgpu/", $p, "_rlc.bin"),
            rlc_kicker: if $kicker {
                Some(concat!("amdgpu/", $p, "_rlc_kicker.bin"))
            } else {
                None
            },
            imu: concat!("amdgpu/", $p, "_imu.bin"),
            imu_kicker: if $kicker {
                Some(concat!("amdgpu/", $p, "_imu_kicker.bin"))
            } else {
                None
            },
            mes: concat!("amdgpu/", $p, "_mes.bin"),
            mes1: concat!("amdgpu/", $p, "_mes1.bin"),
            uni_mes: concat!("amdgpu/", $p, "_uni_mes.bin"),
        }
    };
}
pub const GC_12_0_1_FW: GcFirmware = gc_fw!("gc_12_0_1", true);
pub const GC_12_0_0_FW: GcFirmware = gc_fw!("gc_12_0_0", false);

/// MP-revision firmware (`psp_v14_0.c`, `smu_v14_0.c` `MODULE_FIRMWARE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MpFirmware {
    pub sos: &'static str,
    pub sos_kicker: Option<&'static str>,
    pub ta: &'static str,
    pub ta_kicker: Option<&'static str>,
    pub smu: &'static str,
    pub smu_kicker: Option<&'static str>,
}
pub const MP_14_0_2_FW: MpFirmware = MpFirmware {
    sos: "amdgpu/psp_14_0_2_sos.bin",
    sos_kicker: None,
    ta: "amdgpu/psp_14_0_2_ta.bin",
    ta_kicker: None,
    smu: "amdgpu/smu_14_0_2.bin",
    smu_kicker: None,
};
pub const MP_14_0_3_FW: MpFirmware = MpFirmware {
    sos: "amdgpu/psp_14_0_3_sos.bin",
    sos_kicker: Some("amdgpu/psp_14_0_3_sos_kicker.bin"),
    ta: "amdgpu/psp_14_0_3_ta.bin",
    ta_kicker: Some("amdgpu/psp_14_0_3_ta_kicker.bin"),
    smu: "amdgpu/smu_14_0_3.bin",
    smu_kicker: Some("amdgpu/smu_14_0_3_kicker.bin"),
};
/// `sdma_v7_0.c`: one image per discovered SDMA revision.
pub const SDMA_7_0_0_FW: &str = "amdgpu/sdma_7_0_0.bin";
pub const SDMA_7_0_1_FW: &str = "amdgpu/sdma_7_0_1.bin";
/// Shared by both dies: VCN 5.0.0 and DCN 4.0.1.
pub const VCN_5_0_0_FW: &str = "amdgpu/vcn_5_0_0.bin";
pub const DCN_4_0_1_DMCUB_FW: &str = "amdgpu/dcn_4_0_1_dmcub.bin";

/// One die's complete firmware set, as `amdgpu_ucode_ip_version_decode`
/// builds the prefixes from discovery: GC names from the GC version, PSP/SMU
/// from MP0/MP1, SDMA from SDMA0 — so a board whose discovery differs from
/// the die default still gets matching images.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareSet {
    pub gc: GcFirmware,
    pub mp: MpFirmware,
    pub sdma: &'static str,
    pub kicker: bool,
}
impl FirmwareSet {
    pub fn select(gc: (u8, u8, u8), mp_rev: u8, sdma_rev: u8, kicker: bool) -> Option<Self> {
        let set = Self {
            gc: match Rdna4Chip::from_gc(gc)? {
                Rdna4Chip::Navi48 => GC_12_0_1_FW,
                Rdna4Chip::Navi44 => GC_12_0_0_FW,
            },
            mp: match mp_rev {
                2 => MP_14_0_2_FW,
                3 => MP_14_0_3_FW,
                _ => return None,
            },
            sdma: match sdma_rev {
                0 => SDMA_7_0_0_FW,
                1 => SDMA_7_0_1_FW,
                _ => return None,
            },
            kicker,
        };
        // Linux requests "%s_kicker.bin" unconditionally for a kicker board;
        // a set that has no such image cannot be loaded.
        if kicker && (set.gc.rlc_kicker.is_none() || set.mp.sos_kicker.is_none()) {
            return None;
        }
        Some(set)
    }
    pub fn rlc(&self) -> &'static str {
        self.pick(self.gc.rlc, self.gc.rlc_kicker)
    }
    pub fn imu(&self) -> &'static str {
        self.pick(self.gc.imu, self.gc.imu_kicker)
    }
    pub fn sos(&self) -> &'static str {
        self.pick(self.mp.sos, self.mp.sos_kicker)
    }
    pub fn smu(&self) -> &'static str {
        self.pick(self.mp.smu, self.mp.smu_kicker)
    }
    fn pick(&self, normal: &'static str, kicker: Option<&'static str>) -> &'static str {
        match kicker {
            Some(k) if self.kicker => k,
            _ => normal,
        }
    }
}

/// `amdgpu_device_get_rev_id`'s register: the byte offset of
/// `RCC_DEV0_EPF0_STRAP0` in the register BAR for the discovered NBIO.
///
/// `nbif_v6_3_1_get_rev_id` (NBIO 6.3.1, 7.11.4, 7.11.5) and
/// `nbio_v7_7_get_rev_id` (7.7.0, 7.7.1), the NBIO versions
/// `amdgpu_discovery_set_ip_blocks` gives those functions: 0x1c for 6.3.1,
/// 0x21 for the `_nbif_4_10` (7.11.4) and `RCC_STRAP1 ... _nbio_7_11_5`
/// (7.11.5) variants, 0x15 for 7.7.x, all `BASE_IDX` 2. `None` for any
/// other NBIO, for which Linux would have no `get_rev_id` at all.
pub fn rev_id_strap(blocks: &[IpBlock]) -> Option<u64> {
    let nbio = ip::find_ip(blocks, ip::HW_ID_NBIF, 0)?;
    let reg = match (nbio.major, nbio.minor, nbio.revision) {
        (6, 3, 1) => 0x1c,
        (7, 11, 4) | (7, 11, 5) => 0x21,
        (7, 7, 0) | (7, 7, 1) => 0x15,
        _ => return None,
    };
    if nbio.num_bases <= 2 {
        return None;
    }
    Some((u64::from(nbio.base_addrs[2]) + reg) * 4)
}
/// `STRAP_ATI_REV_ID_DEV0_F0`, bits 27:24 of `RCC_DEV0_EPF0_STRAP0`.
pub const fn rev_id(strap: u32) -> u8 {
    ((strap & 0x0F00_0000) >> 24) as u8
}

/// `dcn401_calc_num_avail_chans_for_mall` × `mall_size_per_mem_channel`
/// (4 MiB): the largest power of two not above the UMC channel count, made
/// even and clamped per die. 256-bit Navi48 (16 channels) has 64 MiB, the
/// 192-bit 9070 GRE (12) and 128-bit Navi44 (8) 32 MiB.
pub const fn mall_bytes(chip: Rdna4Chip, umc_channels: u32) -> u64 {
    let mut chans = umc_channels;
    let mut avail = 1u32;
    while chans > 1 {
        avail <<= 1;
        chans >>= 1;
    }
    avail &= !1;
    let limit = chip.mall_channel_limit();
    if avail > limit {
        avail = limit;
    }
    avail as u64 * 4 * 1024 * 1024
}

/// `regCC_DC_PIPE_DIS` (dcn_4_1_0_offset.h, BASE_IDX 2).
pub const CC_DC_PIPE_DIS: u32 = 0x00ca;
/// `res_cap_dcn4_01.num_timing_generator`.
pub const DCN401_PIPES: u32 = 4;

/// `dcn401_resource_construct`'s resource pool: which hardware instance
/// backs each of DC's pipe indices once `CC_DC_PIPE_DIS` has removed the
/// fused pipes.
///
/// `read_pipe_fuses` keeps the four DCN401 bits; each set bit removes that
/// pipe. The construct loop (`for (i = 0, j = 0; i < num_timing_generator;
/// i++) { if (pipe_fuses & 1 << i) continue; ... j++; }`) packs the
/// surviving instances into pool slots 0..`pipe_count`: slot `j`'s HUBP,
/// DPP, OPP, timing generator and ABM are all instance `i`, the `j`-th
/// unfused one. A pipe index (`pipe_ctx->pipe_idx`; not a CRTC, whose
/// stream's head pipe DC acquires) is a slot; every block programmed for it is addressed by the slot's instance
/// (`hubps[j]->inst`, `dpps[j]->inst`, `opps[j]->inst`, `tg->inst`), and its
/// MPCC is its DPP's (`plane_res.mpcc_inst = dpps[j]->inst`). The MPC keeps
/// all four MPCCs and the pool all four DSCs (`res_cap->num_dsc`), unfused;
/// `dcn20_acquire_dsc` gives pipe index `j` DSC `j` (one to one, as num_dsc
/// equals res_cap's num_opp), so a DSC follows the pipe index while its OPP
/// source is the slot's OPP instance. Pipe 0 fused (Linux asserts and
/// continues) leaves instances 1-3 in slots 0-2; all four fused leave no
/// pipe and no display.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipePool {
    fuses: u8,
}
impl PipePool {
    /// No pipe fused: every slot its own instance.
    pub const FULL: Self = Self { fuses: 0 };
    /// The pool `read_pipe_fuses` builds from a `CC_DC_PIPE_DIS` value.
    pub const fn from_fuses(cc_dc_pipe_dis: u32) -> Self {
        Self {
            fuses: (cc_dc_pipe_dis & 0xf) as u8,
        }
    }
    /// The fused instances, by bit.
    pub const fn fuses(self) -> u8 {
        self.fuses
    }
    /// `pool->base.pipe_count` (also its timing generator and MPCC counts).
    pub const fn count(self) -> u8 {
        DCN401_PIPES as u8 - self.fuses.count_ones() as u8
    }
    /// The pipe indices, 0..`count`.
    pub fn pipes(self) -> core::ops::Range<u8> {
        0..self.count()
    }
    /// Every pipe index, by bit.
    pub const fn all(self) -> u8 {
        ((1u16 << self.count()) - 1) as u8
    }
    /// The hardware instance of pipe `pipe`'s HUBP, DPP, OPP, OTG and MPCC.
    /// Indices past `count` continue over the fused instances in order, so
    /// the map is a permutation of 0..4 (the identity from 4 up); nothing
    /// programs such a pipe.
    pub const fn hw(self, pipe: u8) -> u8 {
        if pipe >= DCN401_PIPES as u8 {
            return pipe;
        }
        let fused = pipe >= self.count();
        let want = if fused { pipe - self.count() } else { pipe };
        let mut seen = 0u8;
        let mut inst = 0u8;
        while inst < DCN401_PIPES as u8 {
            if (self.fuses >> inst & 1 != 0) == fused {
                if seen == want {
                    return inst;
                }
                seen += 1;
            }
            inst += 1;
        }
        pipe
    }
    /// The pipe index whose blocks are hardware instance `inst`; `None` for
    /// a fused (or nonexistent) instance.
    pub const fn pipe(self, inst: u8) -> Option<u8> {
        if inst >= DCN401_PIPES as u8 || self.fuses >> inst & 1 != 0 {
            return None;
        }
        Some(inst - (self.fuses & ((1 << inst) - 1)).count_ones() as u8)
    }
    /// The instances of the pipes in `pipes` (by bit), by bit.
    pub const fn hw_mask(self, pipes: u8) -> u8 {
        let mut out = 0u8;
        let mut p = 0u8;
        while p < DCN401_PIPES as u8 {
            if pipes >> p & 1 != 0 {
                out |= 1 << self.hw(p);
            }
            p += 1;
        }
        out
    }
    /// The pipes whose instances are in `insts` (by bit), by bit; fused
    /// instances drop out.
    pub const fn pipe_mask(self, insts: u8) -> u8 {
        let mut out = 0u8;
        let mut i = 0u8;
        while i < DCN401_PIPES as u8 {
            if insts >> i & 1 != 0 {
                if let Some(p) = self.pipe(i) {
                    out |= 1 << p;
                }
            }
            i += 1;
        }
        out
    }
    /// The DSC `dcn20_acquire_dsc` gives pipe `pipe`: its own index, the
    /// pool keeping all four DSCs.
    pub const fn dsc(self, pipe: u8) -> u8 {
        pipe
    }
}

struct ReadOp<F>(F);
impl<F: FnOnce() -> T, T> narf_capabilities::CapOp<narf_bus::BusDeviceCap, narf_capabilities::Write>
    for ReadOp<F>
{
    type Output = T;
    fn execute(
        self,
        _: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    ) -> Result<T, narf_capabilities::CapError> {
        Ok((self.0)())
    }
}

/// Read `CC_DC_PIPE_DIS` and return the resource pool it leaves, or `None`
/// when the DCN bank is absent or the device is gone.
///
/// # Safety
/// The caller owns this GPU's register mapping; the read has no side effect.
pub(crate) unsafe fn read_pipe_pool(
    gpu: &AmdGpu,
    authority: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Option<PipePool> {
    Rdna4Chip::of(gpu)?;
    let base = crate::amdgpu_psp_ring::bank(
        gpu,
        ip::HW_ID_DCN,
        &[(4, 0, 1), (4, 1, 0)],
        2,
        CC_DC_PIPE_DIS,
    )
    .ok()?;
    let regs = gpu.regs;
    // SAFETY: the bank bounds CC_DC_PIPE_DIS inside the owned BAR5 mapping.
    let value = authority
        .invoke(ReadOp(|| unsafe {
            regs.read32(base + u64::from(CC_DC_PIPE_DIS) * 4)
        }))
        .ok()?;
    if value == u32::MAX {
        return None;
    }
    Some(PipePool::from_fuses(value))
}

const NONE: u8 = 0;
static BOUND: AtomicU8 = AtomicU8::new(NONE);
static FUSES: AtomicU8 = AtomicU8::new(0);

/// Record the die the probe bound. Read by DC policy that has no `AmdGpu`.
///
/// A bind is a new device: its resource pool is unknown until that
/// device's own `CC_DC_PIPE_DIS` read, so the previous device's fuses are
/// dropped here (dcn401_resource_construct builds a fresh pool per device).
pub(crate) fn publish(chip: Option<Rdna4Chip>) {
    let code = match chip {
        None => NONE,
        Some(Rdna4Chip::Navi48) => 1,
        Some(Rdna4Chip::Navi44) => 2,
    };
    FUSES.store(0, Ordering::Release);
    BOUND.store(code, Ordering::Release);
}
/// The bound RDNA4 die, if any.
pub fn bound() -> Option<Rdna4Chip> {
    match BOUND.load(Ordering::Acquire) {
        1 => Some(Rdna4Chip::Navi48),
        2 => Some(Rdna4Chip::Navi44),
        _ => None,
    }
}
/// Record the resource pool `CC_DC_PIPE_DIS` leaves, before any display
/// owner is constructed (each keeps the pool it was built with).
pub(crate) fn publish_pipe_pool(pool: PipePool) {
    FUSES.store(pool.fuses(), Ordering::Release);
}
/// The display resource pool: every pipe until the fuse read says otherwise.
pub fn pipe_pool() -> PipePool {
    PipePool::from_fuses(u32::from(FUSES.load(Ordering::Acquire)))
}
/// DCN pipes DML may assign: the pool's `pipe_count`.
pub fn available_pipes() -> u32 {
    u32::from(pipe_pool().count())
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_rdna4_tests.rs"]
pub(crate) mod tests;
