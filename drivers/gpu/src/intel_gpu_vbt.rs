//! Intel Video BIOS Table (VBT): discovery and a bounds-checked parser.
//!
//! The VBT is the board description the firmware hands the display
//! driver: which DDI ports exist and what they carry, their AUX channel
//! and DDC pin, Type-C wiring, the eDP panel's power sequencing and link
//! parameters, PSR timing, backlight and the SSC preference. Linux reads
//! it in `intel_bios.c`; every structure, offset and rule here comes from
//! Linux b90c984d (`intel_vbt_defs.h`, `intel_bios.c`, `intel_opregion.c`,
//! `intel_rom.c`, `drivers/pci/rom.c`, `intel_ddi.c::intel_ddi_init`,
//! `intel_dp_aux.c::intel_dp_aux_ch`, `intel_hdmi.c::intel_hdmi_ddc_pin`).
//!
//! ## Discovery
//!
//! `intel_bios_get_vbt` looks, in order, at the ACPI IGD OpRegion
//! (`intel_opregion_setup`: the RVDA/RVDS raw VBT for OpRegion 2.0+, then
//! mailbox #4 at OpRegion + 0x400), at SPI flash (discrete parts only) and
//! at the PCI option ROM (`oprom_get_vbt`). This module parses each source
//! from a byte slice ([`opregion_vbt`], [`rom_find_vbt`]); the production
//! glue that copies the firmware bytes is [`discover`].
//!
//! The OpRegion lives in ACPI NVS memory the boot map registers as known
//! RAM (`narf_memory::frame::is_system_ram`), which the kernel direct map
//! already covers, so [`discover`] copies it read-only through
//! `PhysAddr::kernel_ptr` after proving every page is known RAM. No mapping
//! or memory-subsystem change is needed. Linux also writes the OpRegion
//! (`chpd`, `ardy`); this module never does. SPI is discrete-only and the
//! PCI option ROM needs the expansion-ROM BAR assigned and enabled, which
//! the bus layer does not do, so production discovery is OpRegion-only and
//! the ROM scan is available to callers that already hold ROM bytes.
//!
//! ## Parsing
//!
//! [`validate_vbt`] is `intel_bios_is_valid_vbt`. [`Vbt::parse`] walks the
//! BDB blocks exactly as `find_raw_section` does (a block whose size runs
//! past `bdb_size` ends the walk) and copies each block it uses, zero
//! padded to the structure size, as `init_bdb_block` does. A block shorter
//! than its structure is therefore accepted with zero tails, which is what
//! Linux does; structural damage (headers, sizes, the block walk) refuses.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::intel_gpu_gmbus::{GmbusPinTable, PinPair};

// ── Containers (intel_vbt_defs.h) ───────────────────────────────────

/// `sizeof(struct vbt_header)`.
pub const VBT_HEADER_SIZE: usize = 48;
/// `sizeof(struct bdb_header)`.
pub const BDB_HEADER_SIZE: usize = 22;
/// `vbt_signature`.
pub const VBT_SIGNATURE: [u8; 4] = *b"$VBT";

const VBT_SIZE_OFF: usize = 24;
const VBT_BDB_OFFSET_OFF: usize = 28;
const BDB_VERSION_OFF: usize = 16;
const BDB_HEADER_SIZE_OFF: usize = 18;
const BDB_SIZE_OFF: usize = 20;

/// `enum bdb_block_id` values this module reads.
pub mod block {
    /// `BDB_GENERAL_FEATURES`.
    pub const GENERAL_FEATURES: u8 = 1;
    /// `BDB_GENERAL_DEFINITIONS`.
    pub const GENERAL_DEFINITIONS: u8 = 2;
    /// `BDB_PSR` (165+).
    pub const PSR: u8 = 9;
    /// `BDB_DRIVER_FEATURES`.
    pub const DRIVER_FEATURES: u8 = 12;
    /// `BDB_EDP`.
    pub const EDP: u8 = 27;
    /// `BDB_LFP_OPTIONS`.
    pub const LFP_OPTIONS: u8 = 40;
    /// `BDB_LFP_BACKLIGHT`.
    pub const LFP_BACKLIGHT: u8 = 43;
    /// `BDB_LFP_POWER`.
    pub const LFP_POWER: u8 = 44;
    /// `BDB_MIPI_SEQUENCE` (its v3+ size field is a u32 at +4).
    pub const MIPI_SEQUENCE: u8 = 53;
}

/// `sizeof` of each parsed block structure (the `bdb_blocks[].min_size`
/// Linux pads short blocks to).
pub mod block_size {
    /// `struct bdb_general_features`.
    pub const GENERAL_FEATURES: usize = 7;
    /// `struct bdb_general_definitions` (header only).
    pub const GENERAL_DEFINITIONS: usize = 5;
    /// `struct bdb_psr`.
    pub const PSR: usize = 100;
    /// `struct bdb_driver_features`.
    pub const DRIVER_FEATURES: usize = 19;
    /// `struct bdb_edp`.
    pub const EDP: usize = 848;
    /// `struct bdb_lfp_options`.
    pub const LFP_OPTIONS: usize = 34;
    /// `struct bdb_lfp_backlight`.
    pub const LFP_BACKLIGHT: usize = 305;
    /// `struct bdb_lfp_power`.
    pub const LFP_POWER: usize = 136;
}

/// `sizeof(struct child_device_config)`.
pub const CHILD_DEVICE_SIZE: usize = 44;
/// `LEGACY_CHILD_DEVICE_CONFIG_SIZE`: the smallest usable child.
pub const LEGACY_CHILD_DEVICE_CONFIG_SIZE: usize = 33;

/// Why a buffer is not a VBT (`intel_bios_is_valid_vbt`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VbtError {
    /// Fewer bytes than a VBT header ("VBT header incomplete").
    HeaderIncomplete,
    /// The buffer does not start with `$VBT` ("VBT invalid signature").
    BadSignature,
    /// `vbt_size` is larger than the buffer ("vbt_size overflows").
    VbtSizeOverflow,
    /// No room for the BDB header inside `vbt_size`.
    BdbHeaderIncomplete,
    /// `bdb_size` runs past `vbt_size` ("BDB incomplete").
    BdbIncomplete,
}

fn le16(b: &[u8], off: usize) -> u16 {
    match b.get(off..off + 2) {
        Some(s) => u16::from_le_bytes([s[0], s[1]]),
        None => 0,
    }
}

fn le32(b: &[u8], off: usize) -> u32 {
    match b.get(off..off + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

fn le64(b: &[u8], off: usize) -> u64 {
    match b.get(off..off + 8) {
        Some(s) => u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]),
        None => 0,
    }
}

/// `range_overflows(start, size, max)` (`include/linux/overflow.h`).
const fn range_overflows(start: usize, size: usize, max: usize) -> bool {
    start >= max || size > max - start
}

/// `intel_bios_is_valid_vbt`: the `vbt_size` bytes of a valid VBT.
pub fn validate_vbt(buf: &[u8]) -> Result<&[u8], VbtError> {
    if buf.len() < VBT_HEADER_SIZE {
        return Err(VbtError::HeaderIncomplete);
    }
    if buf[..4] != VBT_SIGNATURE {
        return Err(VbtError::BadSignature);
    }
    let size = le16(buf, VBT_SIZE_OFF) as usize;
    if size > buf.len() {
        return Err(VbtError::VbtSizeOverflow);
    }
    let vbt = &buf[..size];
    let bdb_offset = le32(buf, VBT_BDB_OFFSET_OFF) as usize;
    if range_overflows(bdb_offset, BDB_HEADER_SIZE, size) {
        return Err(VbtError::BdbHeaderIncomplete);
    }
    let bdb_size = le16(vbt, bdb_offset + BDB_SIZE_OFF) as usize;
    if range_overflows(bdb_offset, bdb_size, size) {
        return Err(VbtError::BdbIncomplete);
    }
    Ok(vbt)
}

/// `_get_blocksize` for the block whose ID byte is at `index`, or `None`
/// when the size field itself lies outside `bdb`.
fn raw_block_size(bdb: &[u8], index: usize) -> Option<usize> {
    if *bdb.get(index)? == block::MIPI_SEQUENCE && *bdb.get(index + 3)? >= 3 {
        let size = bdb.get(index + 4..index + 8)?;
        Some(u32::from_le_bytes([size[0], size[1], size[2], size[3]]) as usize)
    } else {
        let size = bdb.get(index + 1..index + 3)?;
        Some(u16::from_le_bytes([size[0], size[1]]) as usize)
    }
}

/// `find_raw_section`: the data of block `id` (after its 3-byte header).
/// The walk starts at `header_size`, stops at the first block that does
/// not fit in `bdb_size`, and never reads outside `bdb`.
pub fn find_raw_section(bdb: &[u8], id: u8) -> Option<&[u8]> {
    let total = (le16(bdb, BDB_SIZE_OFF) as usize).min(bdb.len());
    let mut index = le16(bdb, BDB_HEADER_SIZE_OFF) as usize;
    while index + 3 < total {
        let current_id = bdb[index];
        let size = raw_block_size(bdb, index)?;
        index += 3;
        let end = index.checked_add(size)?;
        if end > total {
            return None;
        }
        if current_id == id {
            return Some(&bdb[index..end]);
        }
        index = end;
    }
    None
}

/// `init_bdb_block`: a copy of the block zero-padded to `min_size`.
fn padded_block(bdb: &[u8], id: u8, min_size: usize) -> Option<Vec<u8>> {
    let raw = find_raw_section(bdb, id)?;
    let mut copy = vec![0u8; min_size.max(raw.len())];
    copy[..raw.len()].copy_from_slice(raw);
    Some(copy)
}

// ── Child devices (struct child_device_config) ─────────────────────

/// `DEVICE_TYPE_*` bits.
pub mod device_type {
    /// `DEVICE_TYPE_INTERNAL_CONNECTOR`.
    pub const INTERNAL_CONNECTOR: u16 = 1 << 12;
    /// `DEVICE_TYPE_NOT_HDMI_OUTPUT`.
    pub const NOT_HDMI_OUTPUT: u16 = 1 << 11;
    /// `DEVICE_TYPE_MIPI_OUTPUT`.
    pub const MIPI_OUTPUT: u16 = 1 << 10;
    /// `DEVICE_TYPE_TMDS_DVI_SIGNALING`.
    pub const TMDS_DVI_SIGNALING: u16 = 1 << 4;
    /// `DEVICE_TYPE_DISPLAYPORT_OUTPUT`.
    pub const DISPLAYPORT_OUTPUT: u16 = 1 << 2;
    /// `DEVICE_TYPE_ANALOG_OUTPUT`.
    pub const ANALOG_OUTPUT: u16 = 1 << 0;
    /// `DEVICE_TYPE_HDMI`.
    pub const HDMI: u16 = 0x60D2;
    /// `DEVICE_TYPE_DP`.
    pub const DP: u16 = 0x68C6;
    /// `DEVICE_TYPE_DP_DUAL_MODE`.
    pub const DP_DUAL_MODE: u16 = 0x60D6;
    /// `DEVICE_TYPE_eDP`.
    pub const EDP: u16 = 0x78C6;
}

/// `DVO_PORT_*` values (BDB 155+).
pub mod dvo_port {
    /// `DVO_PORT_HDMIA`.
    pub const HDMIA: u8 = 0;
    /// `DVO_PORT_HDMIB`.
    pub const HDMIB: u8 = 1;
    /// `DVO_PORT_HDMIC`.
    pub const HDMIC: u8 = 2;
    /// `DVO_PORT_HDMID`.
    pub const HDMID: u8 = 3;
    /// `DVO_PORT_CRT`.
    pub const CRT: u8 = 6;
    /// `DVO_PORT_DPB`.
    pub const DPB: u8 = 7;
    /// `DVO_PORT_DPC`.
    pub const DPC: u8 = 8;
    /// `DVO_PORT_DPD`.
    pub const DPD: u8 = 9;
    /// `DVO_PORT_DPA`.
    pub const DPA: u8 = 10;
    /// `DVO_PORT_DPE`.
    pub const DPE: u8 = 11;
    /// `DVO_PORT_HDMIE`.
    pub const HDMIE: u8 = 12;
    /// `DVO_PORT_DPF`.
    pub const DPF: u8 = 13;
    /// `DVO_PORT_HDMIF`.
    pub const HDMIF: u8 = 14;
    /// `DVO_PORT_DPG`.
    pub const DPG: u8 = 15;
    /// `DVO_PORT_HDMIG`.
    pub const HDMIG: u8 = 16;
    /// `DVO_PORT_DPH`.
    pub const DPH: u8 = 17;
    /// `DVO_PORT_HDMIH`.
    pub const HDMIH: u8 = 18;
    /// `DVO_PORT_DPI`.
    pub const DPI: u8 = 19;
    /// `DVO_PORT_HDMII`.
    pub const HDMII: u8 = 20;
    /// `DVO_PORT_MIPIA`.
    pub const MIPIA: u8 = 21;
    /// `DVO_PORT_MIPIC`.
    pub const MIPIC: u8 = 23;
}

/// `DP_AUX_*` VBT AUX channel codes.
pub mod dp_aux {
    /// `DP_AUX_A`.
    pub const A: u8 = 0x40;
    /// `DP_AUX_B`.
    pub const B: u8 = 0x10;
    /// `DP_AUX_C`.
    pub const C: u8 = 0x20;
    /// `DP_AUX_D`.
    pub const D: u8 = 0x30;
    /// `DP_AUX_E`.
    pub const E: u8 = 0x50;
    /// `DP_AUX_F`.
    pub const F: u8 = 0x60;
    /// `DP_AUX_G`.
    pub const G: u8 = 0x70;
    /// `DP_AUX_H`.
    pub const H: u8 = 0x80;
    /// `DP_AUX_I`.
    pub const I: u8 = 0x90;
}

/// One VBT child device, the first [`CHILD_DEVICE_SIZE`] bytes (zero
/// tail when the VBT's `child_dev_size` is smaller), with the BDB version
/// every version-gated field is read under.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChildDevice {
    raw: [u8; CHILD_DEVICE_SIZE],
    version: u16,
}

impl ChildDevice {
    /// A child from raw `child_device_config` bytes (tests, synthetic
    /// defaults).
    pub fn from_raw(raw: &[u8], version: u16) -> Self {
        let mut copy = [0u8; CHILD_DEVICE_SIZE];
        let n = raw.len().min(CHILD_DEVICE_SIZE);
        copy[..n].copy_from_slice(&raw[..n]);
        Self { raw: copy, version }
    }

    /// The raw bytes.
    pub fn raw(&self) -> &[u8; CHILD_DEVICE_SIZE] {
        &self.raw
    }
    /// `handle`.
    pub fn handle(&self) -> u16 {
        le16(&self.raw, 0)
    }
    /// `device_type`.
    pub fn device_type(&self) -> u16 {
        le16(&self.raw, 2)
    }
    /// `dvo_port`.
    pub fn dvo_port(&self) -> u8 {
        self.raw[16]
    }
    /// `ddc_pin` (VBT DDC bus code, see `map_ddc_pin`).
    pub fn ddc_pin(&self) -> u8 {
        self.raw[19]
    }
    /// `aux_channel` (`DP_AUX_*`).
    pub fn aux_channel(&self) -> u8 {
        self.raw[25]
    }
    /// `lane_reversal` (184+, read unconditionally as Linux does).
    pub fn lane_reversal(&self) -> bool {
        self.raw[23] & (1 << 1) != 0
    }
    /// `lspcon` (192+).
    pub fn lspcon(&self) -> bool {
        self.raw[23] & (1 << 2) != 0
    }
    /// `hpd_invert` (196+).
    pub fn hpd_invert(&self) -> bool {
        self.raw[23] & (1 << 4) != 0
    }
    /// `intel_bios_encoder_supports_crt`.
    pub fn supports_crt(&self) -> bool {
        self.device_type() & device_type::ANALOG_OUTPUT != 0
    }
    /// `intel_bios_encoder_supports_dvi`.
    pub fn supports_dvi(&self) -> bool {
        self.device_type() & device_type::TMDS_DVI_SIGNALING != 0
    }
    /// `intel_bios_encoder_supports_hdmi`.
    pub fn supports_hdmi(&self) -> bool {
        self.supports_dvi() && self.device_type() & device_type::NOT_HDMI_OUTPUT == 0
    }
    /// `intel_bios_encoder_supports_dp`.
    pub fn supports_dp(&self) -> bool {
        self.device_type() & device_type::DISPLAYPORT_OUTPUT != 0
    }
    /// `intel_bios_encoder_supports_edp`.
    pub fn supports_edp(&self) -> bool {
        self.supports_dp() && self.device_type() & device_type::INTERNAL_CONNECTOR != 0
    }
    /// `intel_bios_encoder_supports_dsi`.
    pub fn supports_dsi(&self) -> bool {
        self.device_type() & device_type::MIPI_OUTPUT != 0
    }
    /// `intel_bios_encoder_supports_typec_usb` (195+).
    pub fn supports_typec_usb(&self) -> bool {
        self.version >= 195 && self.raw[33] & 1 != 0
    }
    /// `intel_bios_encoder_supports_tbt` (209+).
    pub fn supports_tbt(&self) -> bool {
        self.version >= 209 && self.raw[33] & (1 << 1) != 0
    }
    /// `intel_bios_encoder_is_dedicated_external` (264+).
    pub fn dedicated_external(&self) -> bool {
        self.version >= 264 && self.raw[33] & (1 << 2) != 0
    }
    /// `intel_bios_encoder_supports_dyn_port_over_tc` (264+).
    pub fn dyn_port_over_tc(&self) -> bool {
        self.version >= 264 && self.raw[33] & (1 << 3) != 0
    }
    /// `sanitize_dedicated_external`: a port outside the Type-C subsystem
    /// drops its `dp_usb_type_c`, `tbt` and `dyn_port_over_tc` bits.
    pub fn sanitized(mut self) -> Self {
        if self.dedicated_external() {
            self.raw[33] &= !(1 | (1 << 1) | (1 << 3));
        }
        self
    }
    /// `intel_bios_encoder_supports_dp_dual_mode`.
    pub fn supports_dp_dual_mode(&self) -> bool {
        if !self.supports_dp() || !self.supports_hdmi() {
            return false;
        }
        match dvo_port_type(self.dvo_port()) {
            dvo_port::DPA => true,
            dvo_port::HDMIA => self.aux_channel() != 0,
            _ => false,
        }
    }
    /// `intel_bios_hdmi_level_shift`: the HDMI buffer-translation index,
    /// `None` below BDB 158 or on display 14+.
    pub fn hdmi_level_shift(&self, display_ver: u8) -> Option<u8> {
        if self.version < 158 || display_ver >= 14 {
            None
        } else {
            Some(self.raw[7] & 0x1F)
        }
    }
    /// `intel_bios_hdmi_max_tmds_clock` in kHz (0: platform limit).
    pub fn hdmi_max_tmds_clock_khz(&self) -> u32 {
        if self.version < 204 {
            return 0;
        }
        match self.raw[7] >> 5 {
            3 => 594_000,
            4 => 340_000,
            5 => 300_000,
            1 => 297_000,
            2 => 165_000,
            _ => 0,
        }
    }
    /// `intel_bios_dp_max_link_rate` in kHz (0: no VBT limit).
    pub fn dp_max_link_rate_khz(&self) -> u32 {
        if self.version < 216 {
            return 0;
        }
        let rate = self.raw[38] & 0x7;
        if self.version >= 230 {
            match rate {
                7 => 2_000_000,
                6 => 1_350_000,
                5 => 1_000_000,
                4 => 810_000,
                3 => 540_000,
                2 => 270_000,
                1 => 162_000,
                _ => 0,
            }
        } else {
            match rate {
                1 => 540_000,
                2 => 270_000,
                3 => 162_000,
                _ => 810_000,
            }
        }
    }
    /// `intel_bios_dp_max_lane_count` (0: no VBT limit).
    pub fn dp_max_lane_count(&self) -> u8 {
        if self.version < 244 {
            0
        } else {
            (self.raw[23] >> 6) + 1
        }
    }
}

/// `dvo_port_type`.
pub const fn dvo_port_type(port: u8) -> u8 {
    match port {
        0..=3 | 12 | 14 | 16 | 18 | 20 => dvo_port::HDMIA,
        7..=11 | 13 | 15 | 17 | 19 => dvo_port::DPA,
        21..=24 => dvo_port::MIPIA,
        other => other,
    }
}

// ── Platforms ───────────────────────────────────────────────────────

/// Linux `enum port` values used below.
pub mod port {
    /// `PORT_A`.
    pub const A: u8 = 0;
    /// `PORT_B`.
    pub const B: u8 = 1;
    /// `PORT_C`.
    pub const C: u8 = 2;
    /// `PORT_TC1` (= `PORT_D`).
    pub const TC1: u8 = 3;
    /// `PORT_TC2`.
    pub const TC2: u8 = 4;
    /// `PORT_TC3`.
    pub const TC3: u8 = 5;
    /// `PORT_TC4`.
    pub const TC4: u8 = 6;
    /// `PORT_TC5` (= `PORT_D_XELPD`).
    pub const TC5: u8 = 7;
    /// `PORT_TC6` (= `PORT_E_XELPD`).
    pub const TC6: u8 = 8;
}

/// The display platform a VBT is interpreted for. Each Linux per-platform
/// table branch (`dvo_port_to_port`, `map_aux_ch`, `map_ddc_pin`,
/// `intel_hdmi_default_ddc_pin`, `intel_phy_is_tc`, the
/// `intel_display_device.c` port masks) is selected from this.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VbtPlatform {
    /// Tiger Lake (display 12, PCH_TGP).
    TigerLake,
    /// Alder Lake S / Raptor Lake S (display 12, PCH_ADP).
    AlderLakeS,
    /// Alder Lake P/N, Raptor Lake P/U (display 13, `alderlake_p`).
    AlderLakeP,
    /// Meteor Lake / Arrow Lake (display 14, PCH_MTL).
    MeteorLake,
}

impl VbtPlatform {
    /// The platform for a Gen12 display family (ADL-N is an ADL-P
    /// subplatform in `intel_display_device.c`).
    pub const fn from_gen12(family: crate::intel_gpu_gt::Gen12Platform) -> Self {
        use crate::intel_gpu_gt::Gen12Platform;
        match family {
            Gen12Platform::TigerLake => VbtPlatform::TigerLake,
            Gen12Platform::AlderLakeS => VbtPlatform::AlderLakeS,
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN => VbtPlatform::AlderLakeP,
        }
    }

    /// `DISPLAY_VER`.
    pub const fn display_ver(self) -> u8 {
        match self {
            VbtPlatform::TigerLake | VbtPlatform::AlderLakeS => 12,
            VbtPlatform::AlderLakeP => 13,
            VbtPlatform::MeteorLake => 14,
        }
    }

    /// `__runtime_defaults.port_mask` as `BIT(enum port)`: TGL A, B,
    /// TC1-TC6; ADL-S A, TC1-TC4; ADL-P (`xe_lpd_display`) and MTL
    /// (`XE_LPDP_FEATURES`) A, B, TC1-TC4.
    pub const fn port_mask(self) -> u16 {
        const A: u16 = 1 << port::A;
        const B: u16 = 1 << port::B;
        const TC1_4: u16 = 0xF << port::TC1;
        match self {
            VbtPlatform::TigerLake => A | B | (0x3F << port::TC1),
            VbtPlatform::AlderLakeS => A | TC1_4,
            VbtPlatform::AlderLakeP | VbtPlatform::MeteorLake => A | B | TC1_4,
        }
    }

    /// `assert_port_valid`.
    pub const fn port_valid(self, port: u8) -> bool {
        port < 16 && self.port_mask() & (1 << port) != 0
    }

    /// `dvo_port_to_port` with the platform's mapping table
    /// (`xelpd_port_mapping` for display 13+, `adls_port_mapping`,
    /// otherwise the direct `port_mapping`), then the display 11+ DSI
    /// fallback `dsi_dvo_port_to_port`.
    pub const fn dvo_port_to_port(self, dvo: u8) -> Option<u8> {
        use dvo_port::*;
        let mapped = match self {
            VbtPlatform::AlderLakeP | VbtPlatform::MeteorLake => match dvo {
                HDMIA | DPA => Some(port::A),
                HDMIB | DPB => Some(port::B),
                HDMIC | DPC => Some(port::C),
                HDMID | DPD => Some(port::TC5),
                HDMIE | DPE => Some(port::TC6),
                HDMIF | DPF => Some(port::TC1),
                HDMIG | DPG => Some(port::TC2),
                HDMIH | DPH => Some(port::TC3),
                HDMII | DPI => Some(port::TC4),
                _ => None,
            },
            VbtPlatform::AlderLakeS => match dvo {
                HDMIA | DPA => Some(port::A),
                HDMIB | DPB => Some(port::TC1),
                HDMIC | DPC => Some(port::TC2),
                HDMID | DPD => Some(port::TC3),
                HDMIE | DPE => Some(port::TC4),
                _ => None,
            },
            VbtPlatform::TigerLake => match dvo {
                HDMIA | DPA => Some(0),
                HDMIB | DPB => Some(1),
                HDMIC | DPC => Some(2),
                HDMID | DPD => Some(3),
                HDMIE | DPE | CRT => Some(4),
                HDMIF | DPF => Some(5),
                HDMIG | DPG => Some(6),
                HDMIH | DPH => Some(7),
                HDMII | DPI => Some(8),
                _ => None,
            },
        };
        match mapped {
            Some(p) => Some(p),
            None => match dvo {
                MIPIA => Some(port::A),
                MIPIC => Some(port::B),
                _ => None,
            },
        }
    }

    /// `map_aux_ch`: a VBT `DP_AUX_*` code to Linux `enum aux_ch`
    /// (`adlp_aux_ch_map` on display 13+, `adls_aux_ch_map`, otherwise
    /// `direct_aux_ch_map`). `None` for codes the platform has no channel
    /// for.
    pub const fn map_aux_ch(self, code: u8) -> Option<u8> {
        use dp_aux::*;
        match self {
            VbtPlatform::AlderLakeP | VbtPlatform::MeteorLake => match code {
                A => Some(0),
                B => Some(1),
                C => Some(2),
                // AUX_CH_D_XELPD / AUX_CH_E_XELPD = AUX_CH_USBC5 / USBC6.
                D => Some(7),
                E => Some(8),
                F => Some(3),
                G => Some(4),
                H => Some(5),
                I => Some(6),
                _ => None,
            },
            VbtPlatform::AlderLakeS => match code {
                A => Some(0),
                B => Some(3),
                C => Some(4),
                D => Some(5),
                E => Some(6),
                _ => None,
            },
            VbtPlatform::TigerLake => match code {
                A => Some(0),
                B => Some(1),
                C => Some(2),
                D => Some(3),
                E => Some(4),
                F => Some(5),
                G => Some(6),
                H => Some(7),
                I => Some(8),
                _ => None,
            },
        }
    }

    /// `map_ddc_pin`: a VBT DDC bus code to a GMBUS pin number, 0 when the
    /// code is not valid for the platform (`adlp_ddc_pin_map` for
    /// PCH_MTL+ and ADL-P, `adls_ddc_pin_map`, `icp_ddc_pin_map` for TGL).
    pub const fn map_ddc_pin(self, code: u8) -> u8 {
        match self {
            VbtPlatform::AlderLakeP | VbtPlatform::MeteorLake => match code {
                1 => 1,
                2 => 2,
                3 => 9,
                4 => 10,
                5 => 11,
                6 => 12,
                _ => 0,
            },
            VbtPlatform::AlderLakeS => match code {
                1 => 1,
                2 => 9,
                3 => 10,
                4 => 11,
                5 => 12,
                _ => 0,
            },
            VbtPlatform::TigerLake => match code {
                1 => 1,
                2 => 2,
                3 => 3,
                4 => 9,
                5 => 10,
                6 => 11,
                7 => 12,
                8 => 13,
                9 => 14,
                _ => 0,
            },
        }
    }

    /// `get_gmbus_pin`'s table.
    pub const fn gmbus_pin_table(self) -> GmbusPinTable {
        match self {
            VbtPlatform::MeteorLake => GmbusPinTable::Mtp,
            _ => GmbusPinTable::Icp,
        }
    }

    /// `intel_port_to_phy` (PHY_A = 0).
    pub const fn port_to_phy(self, port: u8) -> u8 {
        match self {
            VbtPlatform::AlderLakeP | VbtPlatform::MeteorLake if port >= port::TC5 => {
                3 + port - port::TC5
            }
            VbtPlatform::AlderLakeP | VbtPlatform::MeteorLake if port >= port::TC1 => {
                5 + port - port::TC1
            }
            VbtPlatform::AlderLakeS if port >= port::TC1 => 1 + port - port::TC1,
            _ => port,
        }
    }

    /// `intel_phy_is_tc` for this port's PHY (display 13+: PHY F-I; TGL:
    /// PHY D-I; ADL-S has no Type-C PHY).
    pub const fn port_is_tc(self, port: u8) -> bool {
        let phy = self.port_to_phy(port);
        match self {
            VbtPlatform::AlderLakeP | VbtPlatform::MeteorLake => matches!(phy, 5..=8),
            VbtPlatform::TigerLake => matches!(phy, 3..=8),
            VbtPlatform::AlderLakeS => false,
        }
    }

    /// `intel_hdmi_default_ddc_pin` as a raw GMBUS pin number:
    /// `adls_encoder_to_ddc_pin` on ADL-S, `dg1_encoder_to_ddc_pin`
    /// (PHY + 1) for PCH_DG1 and later (MTL), `icl_encoder_to_ddc_pin`
    /// otherwise (combo `GMBUS_PIN_1_BXT + port`, Type-C
    /// `GMBUS_PIN_9_TC1_ICP + tc`).
    pub const fn default_ddc_pin(self, port: u8) -> u8 {
        match self {
            VbtPlatform::AlderLakeS => {
                let phy = self.port_to_phy(port);
                if phy == 0 {
                    1
                } else {
                    9 + phy - 1
                }
            }
            VbtPlatform::MeteorLake => self.port_to_phy(port) + 1,
            VbtPlatform::TigerLake | VbtPlatform::AlderLakeP => {
                if self.port_is_tc(port) {
                    9 + port - port::TC1
                } else {
                    1 + port
                }
            }
        }
    }

    /// `default_aux_ch`: `(enum aux_ch)port`.
    pub const fn default_aux_ch(self, port: u8) -> u8 {
        port
    }
}

/// A GMBUS pin number valid in the platform's pin table
/// (`intel_gmbus_is_valid_pin`).
fn valid_pin(platform: VbtPlatform, pin: u8) -> Option<PinPair> {
    let pin = PinPair::try_from(pin as u32).ok()?;
    if pin == PinPair::Disabled || !platform.gmbus_pin_table().is_valid(pin) {
        return None;
    }
    Some(pin)
}

/// One encoder `intel_ddi_init` would create from a child device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VbtEncoder {
    /// Linux `enum port`.
    pub port: u8,
    /// Index into [`Vbt::children`].
    pub child: usize,
    /// A DSI encoder (claims the port; no DP/HDMI).
    pub dsi: bool,
    /// A DP connector exists (`init_dp`).
    pub dp: bool,
    /// The DP connector is eDP (`_intel_dp_is_port_edp`).
    pub edp: bool,
    /// The HDMI connector's DDC pin; `None` when no HDMI connector was
    /// created (no TMDS, eDP, or no valid unclaimed DDC pin).
    pub hdmi_ddc: Option<PinPair>,
    /// `init_hdmi` (TMDS signalling declared), before the DDC check.
    pub tmds: bool,
    /// `intel_encoder_is_tc` (a Type-C PHY not marked dedicated external).
    pub type_c: bool,
    /// `intel_tc_port_init` legacy flag (Type-C only).
    pub tc_legacy: bool,
    /// The resolved AUX channel (`intel_dp_aux_ch`), when one is needed.
    pub aux_ch: Option<u8>,
    /// The child's `dedicated_external` bit.
    pub dedicated_external: bool,
    /// `intel_bios_encoder_lane_reversal`.
    pub lane_reversal: bool,
    /// `intel_bios_encoder_supports_dp_dual_mode`.
    pub dp_dual_mode: bool,
    /// `intel_bios_hdmi_max_tmds_clock` in kHz (0: platform limit).
    pub hdmi_max_tmds_khz: u32,
    /// `intel_bios_dp_max_link_rate` in kHz (0: no VBT limit).
    pub dp_max_link_rate_khz: u32,
    /// `intel_bios_dp_max_lane_count` (0: no VBT limit).
    pub dp_max_lane_count: u8,
}

// ── Panel facts (intel_bios_init_panel) ─────────────────────────────

/// The panel-type decision `vbt_get_panel_type` reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PanelType {
    /// A panel index 0-15.
    Index(u8),
    /// 0xFF: the panel is chosen by matching its EDID PnP ID against the
    /// LFP data block (`pnpid_get_panel_type`), which this module does not
    /// implement; Linux falls back to 0 when nothing matches.
    PnpId,
    /// No LFP options block, or an invalid value (> 15, not 0xFF).
    Unknown,
}

impl PanelType {
    /// `get_panel_type` without the OpRegion (SWSCI) and PnP-ID sources:
    /// the VBT index, else `fallback_get_panel_type`'s 0.
    pub const fn index_or_fallback(self) -> u8 {
        match self {
            PanelType::Index(i) => i,
            _ => 0,
        }
    }
}

/// `vbt_edp_to_pps_delays`: eDP power sequencing in the VBT's 100 µs
/// units (`struct edp_power_seq`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VbtPpsDelays {
    /// T1+T3: power up.
    pub power_up: u16,
    /// T8: backlight on.
    pub backlight_on: u16,
    /// T9: backlight off.
    pub backlight_off: u16,
    /// T10: power down.
    pub power_down: u16,
    /// T11+T12: power cycle.
    pub power_cycle: u16,
}

/// `parse_edp` for one panel index.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EdpPanel {
    /// `edp.bpp` (18/24/30), `None` for the reserved encoding.
    pub bpp: Option<u8>,
    /// `edp.pps`.
    pub pps: VbtPpsDelays,
    /// `edp.rate` in kHz (`None`: unknown legacy encoding).
    pub rate_khz: Option<u32>,
    /// `edp.lanes`.
    pub lanes: Option<u8>,
    /// `edp.preemphasis` as a DP pre-emphasis level 0-3.
    pub preemphasis: Option<u8>,
    /// `edp.vswing` as a DP voltage-swing level 0-3.
    pub vswing: Option<u8>,
    /// `edp.low_vswing` (173+).
    pub low_vswing: Option<bool>,
    /// `edp.drrs_msa_timing_delay`.
    pub drrs_msa_timing_delay: u8,
    /// `edp.max_link_rate` in kHz (244+; 0 means none).
    pub max_link_rate_khz: Option<u32>,
    /// `edp.dsc_disable` (251+).
    pub dsc_disable: Option<bool>,
}

/// `parse_psr` plus the PSR enable of `parse_panel_driver_features`
/// (< 228) / `parse_power_conservation_features` (228+).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PsrPanel {
    /// `psr.enable`.
    pub enable: bool,
    /// PSR block fields, `None` when the VBT has no PSR block.
    pub table: Option<PsrTable>,
}

/// The per-panel `struct psr_table` decoded by `parse_psr`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PsrTable {
    /// `psr.full_link`.
    pub full_link: bool,
    /// `psr.require_aux_wakeup`.
    pub require_aux_wakeup: bool,
    /// `psr.idle_frames`.
    pub idle_frames: u8,
    /// `psr.tp1_wakeup_time_us`.
    pub tp1_wakeup_time_us: u32,
    /// `psr.tp2_tp3_wakeup_time_us`.
    pub tp2_tp3_wakeup_time_us: u32,
    /// `psr.psr2_tp2_tp3_wakeup_time_us`.
    pub psr2_tp2_tp3_wakeup_time_us: u32,
}

/// `parse_lfp_backlight` for one panel index.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BacklightPanel {
    /// `backlight.present` (entry type is `BDB_BACKLIGHT_TYPE_PWM`).
    pub present: bool,
    /// `backlight.type` (`enum intel_backlight_type`; DISPLAY_DDI = 2
    /// before BDB 191).
    pub control_type: u8,
    /// `backlight.controller`.
    pub controller: u8,
    /// `backlight.pwm_freq_hz`.
    pub pwm_freq_hz: u16,
    /// `backlight.active_low_pwm`.
    pub active_low_pwm: bool,
    /// `backlight.min_brightness`.
    pub min_brightness: u16,
    /// `backlight.brightness_precision_bits` (234+, else 0).
    pub brightness_precision_bits: u8,
    /// `backlight.hdr_dpcd_refresh_timeout` (×100 µs rounded up, 239+;
    /// 30 before).
    pub hdr_dpcd_refresh_timeout: u16,
}

/// The `BDB_GENERAL_FEATURES` bits this driver consumes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GeneralFeatures {
    /// `enable_ssc` (`display->vbt.lvds_use_ssc`).
    pub enable_ssc: bool,
    /// `ssc_freq` (alternate SSC reference).
    pub ssc_freq: bool,
    /// `dp_ssc_enable` (PCH-attached eDP SSC).
    pub dp_ssc_enable: bool,
    /// `dp_ssc_freq`.
    pub dp_ssc_freq: bool,
    /// `dp_ssc_dongle_supported`.
    pub dp_ssc_dongle_supported: bool,
    /// `display_clock_mode`.
    pub display_clock_mode: bool,
}

/// The `BDB_DRIVER_FEATURES` fields Linux consumes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DriverFeatures {
    /// `lvds_config` (`BDB_DRIVER_FEATURE_*`).
    pub lvds_config: u8,
    /// `drrs_enabled` (159-227).
    pub drrs_enabled: bool,
    /// `psr_enabled` (165-227).
    pub psr_enabled: bool,
    /// `dmrrs_enabled` (174-227).
    pub dmrrs_enabled: bool,
}

// ── The parsed VBT ──────────────────────────────────────────────────

/// A parsed VBT: BDB version, child devices and the blocks this driver
/// reads (zero padded to their structure sizes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vbt {
    version: u16,
    children: Vec<ChildDevice>,
    general_features: Option<Vec<u8>>,
    driver_features: Option<Vec<u8>>,
    psr: Option<Vec<u8>>,
    edp: Option<Vec<u8>>,
    lfp_options: Option<Vec<u8>>,
    lfp_backlight: Option<Vec<u8>>,
    lfp_power: Option<Vec<u8>>,
}

impl Vbt {
    /// Validate (`intel_bios_is_valid_vbt`) and parse a VBT image.
    pub fn parse(buf: &[u8]) -> Result<Self, VbtError> {
        let vbt = validate_vbt(buf)?;
        // The BDB header lies inside `vbt_size` (validated); the block walk
        // stops at `bdb_size`, which also lies inside it.
        let bdb = &vbt[le32(vbt, VBT_BDB_OFFSET_OFF) as usize..];
        let version = le16(bdb, BDB_VERSION_OFF);
        Ok(Self {
            version,
            children: parse_children(bdb, version),
            general_features: padded_block(
                bdb,
                block::GENERAL_FEATURES,
                block_size::GENERAL_FEATURES,
            ),
            driver_features: padded_block(bdb, block::DRIVER_FEATURES, block_size::DRIVER_FEATURES),
            psr: padded_block(bdb, block::PSR, block_size::PSR),
            edp: padded_block(bdb, block::EDP, block_size::EDP),
            lfp_options: padded_block(bdb, block::LFP_OPTIONS, block_size::LFP_OPTIONS),
            lfp_backlight: padded_block(bdb, block::LFP_BACKLIGHT, block_size::LFP_BACKLIGHT),
            lfp_power: padded_block(bdb, block::LFP_POWER, block_size::LFP_POWER),
        })
    }

    /// The BDB version (`display->vbt.version`).
    pub fn version(&self) -> u16 {
        self.version
    }

    /// The child devices with a non-zero `device_type`, in VBT order.
    pub fn children(&self) -> &[ChildDevice] {
        &self.children
    }

    /// `BDB_GENERAL_FEATURES`, if present.
    pub fn general_features(&self) -> Option<GeneralFeatures> {
        let g = self.general_features.as_deref()?;
        Some(GeneralFeatures {
            enable_ssc: g[1] & (1 << 1) != 0,
            ssc_freq: g[1] & (1 << 2) != 0,
            display_clock_mode: g[1] & (1 << 6) != 0,
            dp_ssc_enable: g[4] & (1 << 3) != 0,
            dp_ssc_freq: g[4] & (1 << 4) != 0,
            dp_ssc_dongle_supported: g[4] & (1 << 5) != 0,
        })
    }

    /// `display->vbt.lvds_use_ssc`: `init_vbt_defaults` sets it, a
    /// general-features block overrides it with `enable_ssc`. This is what
    /// `intel_panel_use_ssc` returns (no module parameter, no quirk).
    pub fn use_ssc(&self) -> bool {
        self.general_features().is_none_or(|g| g.enable_ssc)
    }

    /// `BDB_DRIVER_FEATURES`, if present.
    pub fn driver_features(&self) -> Option<DriverFeatures> {
        let d = self.driver_features.as_deref()?;
        let ext1 = le16(d, 7);
        let flags = le16(d, 17);
        Some(DriverFeatures {
            lvds_config: ((ext1 >> 11) & 0x3) as u8,
            drrs_enabled: flags & (1 << 5) != 0,
            psr_enabled: flags & (1 << 9) != 0,
            dmrrs_enabled: flags & (1 << 12) != 0,
        })
    }

    /// `display->vbt.int_lvds_support` on display 5+: cleared unless the
    /// driver-features `lvds_config` is `BDB_DRIVER_FEATURE_INT_LVDS`.
    pub fn int_lvds_support(&self) -> bool {
        self.driver_features().is_none_or(|d| d.lvds_config == 1)
    }

    /// `vbt_get_panel_type` for LFP1 (`second` false) or LFP2.
    pub fn panel_type(&self, second: bool) -> PanelType {
        let Some(o) = self.lfp_options.as_deref() else {
            return PanelType::Unknown;
        };
        let primary = o[0];
        if primary > 0xF && primary != 0xFF {
            return PanelType::Unknown;
        }
        let value = if second { o[1] } else { primary };
        match value {
            0..=0xF => PanelType::Index(value),
            0xFF => PanelType::PnpId,
            _ => PanelType::Unknown,
        }
    }

    /// `parse_edp` for `panel` (0-15); `None` without an eDP block.
    pub fn edp_panel(&self, panel: u8) -> Option<EdpPanel> {
        let e = self.edp.as_deref()?;
        let p = (panel & 0xF) as usize;
        let bpp = match panel_bits(le32(e, 160), p, 2) {
            0 => Some(18),
            1 => Some(24),
            2 => Some(30),
            _ => None,
        };
        let seq = 10 * p;
        let pps = VbtPpsDelays {
            power_up: le16(e, seq),
            backlight_on: le16(e, seq + 2),
            backlight_off: le16(e, seq + 4),
            power_down: le16(e, seq + 6),
            power_cycle: le16(e, seq + 8),
        };
        let fast = 164 + 2 * p;
        let rate_khz = if self.version >= 224 {
            Some(u32::from(le16(e, 748 + 2 * p)) * 20)
        } else {
            match e[fast] & 0xF {
                0 => Some(162_000),
                1 => Some(270_000),
                2 => Some(540_000),
                _ => None,
            }
        };
        let lanes = match e[fast] >> 4 {
            0 => Some(1),
            1 => Some(2),
            3 => Some(4),
            _ => None,
        };
        let level = |v: u8| if v <= 3 { Some(v) } else { None };
        Some(EdpPanel {
            bpp,
            pps,
            rate_khz,
            lanes,
            preemphasis: level(e[fast + 1] & 0xF),
            vswing: level(e[fast + 1] >> 4),
            low_vswing: (self.version >= 173).then(|| (le64(e, 204) >> (p * 4)) & 0xF == 0),
            drrs_msa_timing_delay: panel_bits(le32(e, 196), p, 2) as u8,
            max_link_rate_khz: (self.version >= 244).then(|| u32::from(le16(e, 780 + 2 * p)) * 20),
            dsc_disable: (self.version >= 251)
                .then(|| panel_bits(u32::from(le16(e, 812)), p, 1) != 0),
        })
    }

    /// BDB_LFP_POWER `vrr_feature_enabled` (BDB 233+, Linux 6.12
    /// `intel_vbt_defs.h` `struct bdb_lfp_power`): the `u16` at block
    /// offset 56 — packed layout `u8 lfp_feature_bits`, `als[5]` (4 B
    /// each), `u8 lace_aggressiveness_profile`, seven `u16` fields
    /// (`dpst`, `psr`, `drrs`, `lace_support`, `adt`, `dmrrs`,
    /// `adb`), `u16 lace_enabled_status`, `aggressivenes[16]` (1 B
    /// each), `u16 hobl`, then `u16 vrr_feature_enabled`.
    ///
    /// Linux's `intel_vrr_is_capable` gates eDP on the VBT `vrr`
    /// flag; this is the only VRR field in the VBT definitions.
    /// The per-panel bit layout is UNVERIFIED (no `intel_bios.c`
    /// consumer was readable in this lane): like the neighbouring
    /// PSR enable at offset 24, the field is read as a per-panel
    /// bitmask and the Pipe-A panel (LFP1, panel 0) is bit 0. A VBT
    /// older than BDB 233 or a short block reads as disabled.
    pub fn vrr_feature_enabled(&self) -> bool {
        self.lfp_power
            .as_deref()
            .is_some_and(|w| self.version >= 233 && panel_bits(u32::from(le16(w, 56)), 0, 1) != 0)
    }

    /// `parse_psr` + the PSR enable for `panel` (0-15).
    pub fn psr_panel(&self, panel: u8) -> PsrPanel {
        let p = (panel & 0xF) as usize;
        let enable = if self.version < 228 {
            self.driver_features().is_some_and(|d| d.psr_enabled)
        } else {
            self.lfp_power
                .as_deref()
                .is_some_and(|w| panel_bits(u32::from(le16(w, 24)), p, 1) != 0)
        };
        let table = self.psr.as_deref().map(|s| {
            let t = &s[6 * p..6 * p + 6];
            let tp1_raw = le16(t, 2);
            let tp23_raw = le16(t, 4);
            let new_encoding = |v: u16| match v {
                0 => 500,
                1 => 100,
                3 => 0,
                _ => 2500,
            };
            let (tp1, tp23) = if self.version >= 205 {
                (new_encoding(tp1_raw), new_encoding(tp23_raw))
            } else {
                (u32::from(tp1_raw) * 100, u32::from(tp23_raw) * 100)
            };
            let psr2 = if self.version >= 226 {
                match panel_bits(le32(s, 96), p, 2) {
                    0 => 500,
                    1 => 100,
                    3 => 50,
                    _ => 2500,
                }
            } else {
                tp23
            };
            PsrTable {
                full_link: t[0] & 1 != 0,
                require_aux_wakeup: t[0] & 2 != 0,
                idle_frames: t[1] & 0xF,
                tp1_wakeup_time_us: tp1,
                tp2_tp3_wakeup_time_us: tp23,
                psr2_tp2_tp3_wakeup_time_us: psr2,
            }
        });
        PsrPanel { enable, table }
    }

    /// `parse_lfp_backlight` for `panel` (0-15); `None` without the block
    /// or with an `entry_size` other than 6.
    pub fn backlight_panel(&self, panel: u8) -> Option<BacklightPanel> {
        let b = self.lfp_backlight.as_deref()?;
        if b[0] != 6 {
            return None;
        }
        let p = (panel & 0xF) as usize;
        let entry = &b[1 + 6 * p..1 + 6 * p + 6];
        let present = entry[0] & 0x3 == 2;
        let (control_type, controller) = if self.version >= 191 {
            let method = b[113 + p];
            (method & 0xF, method >> 4)
        } else {
            (2, 0)
        };
        let (min_brightness, precision) = if self.version >= 234 {
            let level = le16(b, 129 + 4 * p);
            let mut min = le16(b, 193 + 4 * p);
            let precision = b[257 + p];
            let scale = if self.version >= 236 {
                precision == 16
            } else {
                level > 255
            };
            if scale {
                min /= 255;
            }
            (min, precision)
        } else {
            (u16::from(entry[3]), 0)
        };
        let hdr = if self.version >= 239 {
            le16(b, 273 + 2 * p).div_ceil(100)
        } else {
            30
        };
        Some(BacklightPanel {
            present,
            control_type,
            controller,
            pwm_freq_hz: le16(entry, 1),
            active_low_pwm: entry[0] & (1 << 2) != 0,
            min_brightness,
            brightness_precision_bits: precision,
            hdr_dpcd_refresh_timeout: hdr,
        })
    }

    /// The encoders `intel_ddi_init` would create, in VBT child order:
    /// port mapping, the platform port mask, first-claim of a port, DSI
    /// claims, `init_dp`/`init_hdmi`, the AUX channel (VBT or default,
    /// first claim wins, a claimed channel drops the port), the Type-C
    /// legacy rule, and the HDMI DDC pin (`intel_hdmi_ddc_pin`: VBT pin
    /// through `map_ddc_pin`, else the platform default, valid in the
    /// GMBUS table and not claimed by an earlier HDMI connector). HTI-owned
    /// PHYs and the runtime lane count are hardware facts not modelled.
    pub fn encoders(&self, platform: VbtPlatform) -> Vec<VbtEncoder> {
        let mut out: Vec<VbtEncoder> = Vec::new();
        for (index, child) in self.children.iter().enumerate() {
            let child = child.sanitized();
            let Some(port) = platform.dvo_port_to_port(child.dvo_port()) else {
                continue;
            };
            if !platform.port_valid(port) || out.iter().any(|e| e.port == port) {
                continue;
            }
            let base = VbtEncoder {
                port,
                child: index,
                dsi: false,
                dp: false,
                edp: false,
                hdmi_ddc: None,
                tmds: false,
                type_c: false,
                tc_legacy: false,
                aux_ch: None,
                dedicated_external: child.dedicated_external(),
                lane_reversal: child.lane_reversal(),
                dp_dual_mode: child.supports_dp_dual_mode(),
                hdmi_max_tmds_khz: child.hdmi_max_tmds_clock_khz(),
                dp_max_link_rate_khz: child.dp_max_link_rate_khz(),
                dp_max_lane_count: child.dp_max_lane_count(),
            };
            if child.supports_dsi() {
                out.push(VbtEncoder { dsi: true, ..base });
                continue;
            }
            let init_hdmi = child.supports_dvi() || child.supports_hdmi();
            let init_dp = child.supports_dp();
            if !init_dp && !init_hdmi {
                continue;
            }
            let type_c = platform.port_is_tc(port) && !child.dedicated_external();
            let mut aux_ch = None;
            if init_dp || type_c {
                let vbt = match child.aux_channel() {
                    0 => None,
                    code => platform.map_aux_ch(code),
                };
                let aux = vbt.unwrap_or(platform.default_aux_ch(port));
                if out.iter().any(|e| e.aux_ch == Some(aux)) {
                    continue;
                }
                aux_ch = Some(aux);
            }
            let mut tc_legacy = false;
            if type_c {
                tc_legacy = !child.supports_typec_usb() && !child.supports_tbt();
                if !tc_legacy && init_hdmi {
                    tc_legacy = !init_dp;
                }
            }
            let edp = init_dp && child.supports_edp();
            let hdmi_ddc = if init_hdmi && !edp {
                let pin = match child.ddc_pin() {
                    0 => 0,
                    code => platform.map_ddc_pin(code),
                };
                let pin = if pin == 0 {
                    platform.default_ddc_pin(port)
                } else {
                    pin
                };
                valid_pin(platform, pin).filter(|p| out.iter().all(|e| e.hdmi_ddc != Some(*p)))
            } else {
                None
            };
            out.push(VbtEncoder {
                dp: init_dp,
                edp,
                hdmi_ddc,
                tmds: init_hdmi,
                type_c,
                tc_legacy,
                aux_ch,
                ..base
            });
        }
        out
    }

    /// The encoder for `port`, if `intel_ddi_init` would create one.
    pub fn encoder(&self, platform: VbtPlatform, port: u8) -> Option<VbtEncoder> {
        self.encoders(platform).into_iter().find(|e| e.port == port)
    }
}

/// `panel_bits`.
const fn panel_bits(value: u32, panel: usize, bits: usize) -> u32 {
    (value >> (panel * bits)) & ((1 << bits) - 1)
}

/// `child_device_expected_size` (`None`: unknown version, Linux then
/// assumes `sizeof(struct child_device_config)`).
pub const fn child_device_expected_size(version: u16) -> Option<usize> {
    if version > 264 {
        None
    } else if version >= 263 {
        Some(44)
    } else if version >= 256 {
        Some(40)
    } else if version >= 216 {
        Some(39)
    } else if version >= 196 {
        Some(38)
    } else if version >= 195 {
        Some(37)
    } else if version >= 111 {
        Some(LEGACY_CHILD_DEVICE_CONFIG_SIZE)
    } else if version >= 106 {
        Some(27)
    } else {
        Some(22)
    }
}

/// `parse_general_definitions`: the child devices of the general
/// definitions block. A block smaller than its header or a
/// `child_dev_size` below the legacy 33 bytes yields none
/// (`child_device_size_valid`; an unexpected but large-enough size is
/// accepted, as Linux only logs it).
fn parse_children(bdb: &[u8], version: u16) -> Vec<ChildDevice> {
    let mut children = Vec::new();
    let Some(defs) = find_raw_section(bdb, block::GENERAL_DEFINITIONS) else {
        return children;
    };
    if defs.len() < block_size::GENERAL_DEFINITIONS {
        return children;
    }
    let child_size = defs[4] as usize;
    if child_size < LEGACY_CHILD_DEVICE_CONFIG_SIZE {
        return children;
    }
    let count = (defs.len() - block_size::GENERAL_DEFINITIONS) / child_size;
    for i in 0..count {
        let start = block_size::GENERAL_DEFINITIONS + i * child_size;
        let child = ChildDevice::from_raw(&defs[start..start + child_size], version);
        if child.device_type() != 0 {
            children.push(child);
        }
    }
    children
}

// ── DP SSC (intel_cx0pll_update_ssc) ────────────────────────────────

/// `DP_MAX_DOWNSPREAD` DPCD address.
pub const DP_MAX_DOWNSPREAD: usize = 0x003;
/// `DP_MAX_DOWNSPREAD_0_5`.
pub const DP_MAX_DOWNSPREAD_0_5: u8 = 1 << 0;

/// `intel_cx0pll_update_ssc` for a DP encoder: SSC only when
/// `intel_panel_use_ssc` (the VBT's `lvds_use_ssc`, default on without a
/// VBT) and the sink's `DP_MAX_DOWNSPREAD` advertises 0.5% downspread.
pub const fn dp_ssc_enabled(vbt_use_ssc: bool, max_downspread: u8) -> bool {
    vbt_use_ssc && max_downspread & DP_MAX_DOWNSPREAD_0_5 != 0
}

// ── OpRegion (intel_opregion.c) ─────────────────────────────────────

/// `ASLS` PCI config offset (`intel_pci_config.h`).
pub const ASLS: u16 = 0xFC;
/// `OPREGION_SIZE`.
pub const OPREGION_SIZE: usize = 8 * 1024;
/// `OPREGION_SIGNATURE`.
pub const OPREGION_SIGNATURE: [u8; 16] = *b"IntelGraphicsMem";
/// `OPREGION_ASLE_OFFSET`.
pub const OPREGION_ASLE_OFFSET: usize = 0x300;
/// `OPREGION_VBT_OFFSET` (mailbox #4).
pub const OPREGION_VBT_OFFSET: usize = 0x400;
/// `OPREGION_ASLE_EXT_OFFSET`.
pub const OPREGION_ASLE_EXT_OFFSET: usize = 0x1C00;
/// `MBOX_ASLE` (mailbox #3).
pub const MBOX_ASLE: u32 = 1 << 2;
/// `MBOX_ASLE_EXT` (mailbox #5).
pub const MBOX_ASLE_EXT: u32 = 1 << 4;
/// `opregion_header.mboxes` offset.
const OPREGION_MBOXES_OFF: usize = 88;
/// `opregion_header.over` offset (rsvd, revision, minor, major).
const OPREGION_OVER_OFF: usize = 20;
/// `opregion_asle.rvda` / `.rvds` offsets inside the ASLE mailbox.
const ASLE_RVDA_OFF: usize = 186;
const ASLE_RVDS_OFF: usize = 194;
/// The largest VBT a 16-bit `vbt_size` can describe; RVDA reads are
/// bounded by it.
pub const MAX_VBT_SIZE: usize = 0xFFFF;

/// Why the OpRegion yielded no VBT.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpRegionError {
    /// ASLS is 0 ("ACPI OpRegion not supported").
    NotSupported,
    /// The region is shorter than `OPREGION_SIZE`.
    Truncated,
    /// "opregion signature mismatch".
    BadSignature,
    /// Neither the RVDA VBT nor mailbox #4 holds a valid VBT.
    NoVbt,
}

/// Where a VBT came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VbtSource {
    /// The OpRegion 2.0+ raw VBT at RVDA.
    OpRegionRvda,
    /// OpRegion mailbox #4.
    OpRegionMailbox,
    /// A PCI option ROM image.
    PciRom,
}

/// The OpRegion header facts `intel_opregion_setup` reads.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OpRegionHeader {
    /// `over.major`.
    pub major: u8,
    /// `over.minor`.
    pub minor: u8,
    /// `over.revision`.
    pub revision: u8,
    /// `mboxes`.
    pub mboxes: u32,
}

/// Validate an OpRegion image and read its header.
pub fn opregion_header(region: &[u8]) -> Result<OpRegionHeader, OpRegionError> {
    if region.len() < OPREGION_SIZE {
        return Err(OpRegionError::Truncated);
    }
    if region[..16] != OPREGION_SIGNATURE {
        return Err(OpRegionError::BadSignature);
    }
    Ok(OpRegionHeader {
        revision: region[OPREGION_OVER_OFF + 1],
        minor: region[OPREGION_OVER_OFF + 2],
        major: region[OPREGION_OVER_OFF + 3],
        mboxes: le32(region, OPREGION_MBOXES_OFF),
    })
}

/// The physical RVDA window `intel_opregion_setup` maps, when the header
/// names one: OpRegion 2.0+ with the ASLE mailbox and non-zero RVDA/RVDS.
/// 2.0 RVDA is physical; 2.1+ RVDA is relative to ASLS. The size is
/// clamped to [`MAX_VBT_SIZE`]; an address that overflows is `None`.
pub fn opregion_rvda(region: &[u8], asls: u64) -> Option<(u64, usize)> {
    let header = opregion_header(region).ok()?;
    if header.major < 2 || header.mboxes & MBOX_ASLE == 0 {
        return None;
    }
    let rvda = le64(region, OPREGION_ASLE_OFFSET + ASLE_RVDA_OFF);
    let rvds = le32(region, OPREGION_ASLE_OFFSET + ASLE_RVDS_OFF);
    if rvda == 0 || rvds == 0 {
        return None;
    }
    let phys = if header.major > 2 || header.minor >= 1 {
        rvda.checked_add(asls)?
    } else {
        rvda
    };
    phys.checked_add(u64::from(rvds))?;
    Some((phys, (rvds as usize).min(MAX_VBT_SIZE)))
}

/// `intel_opregion_setup`'s VBT selection: the RVDA VBT when it validates
/// (`fetch` copies `len` bytes of firmware memory at a physical address),
/// else mailbox #4, whose size runs to the ASLE extension when mailbox #5
/// exists and to the end of the OpRegion otherwise.
pub fn opregion_vbt(
    region: &[u8],
    asls: u64,
    fetch: &mut dyn FnMut(u64, usize) -> Option<Vec<u8>>,
) -> Result<(Vec<u8>, VbtSource), OpRegionError> {
    if asls == 0 {
        return Err(OpRegionError::NotSupported);
    }
    let header = opregion_header(region)?;
    if let Some((phys, len)) = opregion_rvda(region, asls) {
        if let Some(bytes) = fetch(phys, len) {
            if let Ok(vbt) = validate_vbt(&bytes) {
                return Ok((vbt.to_vec(), VbtSource::OpRegionRvda));
            }
        }
    }
    let end = if header.mboxes & MBOX_ASLE_EXT != 0 {
        OPREGION_ASLE_EXT_OFFSET
    } else {
        OPREGION_SIZE
    };
    match validate_vbt(&region[OPREGION_VBT_OFFSET..end]) {
        Ok(vbt) => Ok((vbt.to_vec(), VbtSource::OpRegionMailbox)),
        Err(_) => Err(OpRegionError::NoVbt),
    }
}

// ── PCI option ROM (intel_rom.c, drivers/pci/rom.c) ─────────────────

/// `pci_get_rom_size`: the length of the chained PCI ROM images (0x55AA
/// header, "PCIR" data structure, image length ×512, last-image bit),
/// never more than `rom.len()`. 0 when the first header is invalid.
pub fn pci_rom_size(rom: &[u8]) -> usize {
    let mut image = 0usize;
    loop {
        if le16(rom, image) != 0xAA55 || image + 2 > rom.len() {
            break;
        }
        let pds = image + le16(rom, image + 24) as usize;
        if pds + 22 > rom.len() || le32(rom, pds) != 0x5249_4350 {
            break;
        }
        let last_image = rom[pds + 21] & 0x80 != 0;
        let length = le16(rom, pds + 16) as usize;
        image += length * 512;
        if image >= rom.len() {
            break;
        }
        if !last_image && le16(rom, image) != 0xAA55 {
            break;
        }
        if length == 0 || last_image {
            break;
        }
    }
    image.min(rom.len())
}

/// `intel_rom_pci` + `oprom_get_vbt` over a mapped ROM window: the window
/// is trimmed to `pci_get_rom_size` (an invalid image yields nothing, as
/// `pci_map_rom` returns NULL) and searched with [`rom_find_vbt`].
pub fn pci_rom_vbt(window: &[u8]) -> Option<Vec<u8>> {
    let size = pci_rom_size(window);
    if size == 0 {
        return None;
    }
    rom_find_vbt(&window[..size])
}

/// `oprom_get_vbt` over a ROM image: the first 4-byte aligned `$VBT`
/// (`intel_rom_find`), bounded by the ROM, copied and validated.
pub fn rom_find_vbt(rom: &[u8]) -> Option<Vec<u8>> {
    let needle = u32::from_le_bytes(VBT_SIGNATURE);
    let mut offset = 0usize;
    let found = loop {
        if offset + 4 > rom.len() {
            return None;
        }
        if le32(rom, offset) == needle {
            break offset;
        }
        offset += 4;
    };
    if VBT_HEADER_SIZE > rom.len() - found {
        return None;
    }
    let vbt_size = le16(rom, found + VBT_SIZE_OFF) as usize;
    if vbt_size > rom.len() - found {
        return None;
    }
    let copy = rom[found..found + vbt_size].to_vec();
    validate_vbt(&copy).ok()?;
    Some(copy)
}

// ── Production discovery ────────────────────────────────────────────

/// The direct map always spans at least one 512 GiB PML4 slot
/// (`narf_memory::mmu::init_mmu`); firmware reads stay below it.
const DIRECT_MAP_FLOOR: u64 = 512 << 30;

/// Copy `len` bytes of firmware memory at `phys` through the kernel
/// direct map, read-only. Every page must be known RAM (usable, kernel,
/// ACPI reclaimable or ACPI NVS per the boot map), so the read can never
/// reach device MMIO; anything else is refused.
fn copy_firmware_ram(phys: u64, len: usize) -> Option<Vec<u8>> {
    let end = phys.checked_add(len as u64)?;
    if len == 0 || end > DIRECT_MAP_FLOOR {
        return None;
    }
    let mut page = phys & !0xFFF;
    while page < end {
        if !narf_memory::frame::is_system_ram(narf_memory::PhysAddr::new(page)) {
            return None;
        }
        page += 0x1000;
    }
    let src = narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>();
    let mut out = vec![0u8; len];
    for (i, slot) in out.iter_mut().enumerate() {
        // SAFETY: every page of [phys, end) is boot-registered RAM below
        // the direct map's guaranteed span, so `src + i` is a mapped,
        // side-effect-free read; nothing is written.
        *slot = unsafe { core::ptr::read_volatile(src.add(i)) };
    }
    Some(out)
}

/// `intel_bios_get_vbt` for an integrated part: the ACPI OpRegion named by
/// `asls` (PCI config 0xFC), RVDA first, then mailbox #4. `None` leaves
/// every consumer on its `init_vbt_missing_defaults` behaviour.
pub fn discover(asls: u32) -> Option<(Vbt, VbtSource)> {
    if asls == 0 {
        return None;
    }
    let region = copy_firmware_ram(u64::from(asls), OPREGION_SIZE)?;
    let (bytes, source) = opregion_vbt(&region, u64::from(asls), &mut copy_firmware_ram).ok()?;
    Vbt::parse(&bytes).ok().map(|vbt| (vbt, source))
}

// ── Gen12 HDMI DDC overrides ────────────────────────────────────────

/// The Gen12 HDMI DDC pins a VBT resolves, per DDI (`intel_hdmi_ddc_pin`
/// for every HDMI connector `intel_ddi_init` would create), for one
/// display family. A DDI the VBT gives no HDMI connector keeps the
/// platform default ([`crate::intel_gpu_gmbus::gen12_ddc_pin`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Gen12DdcOverrides {
    family: Option<crate::intel_gpu_gt::Gen12Platform>,
    pins: [Option<PinPair>; 8],
}

impl Gen12DdcOverrides {
    /// No VBT: every DDI uses the platform default.
    pub const NONE: Self = Self {
        family: None,
        pins: [None; 8],
    };

    /// The overrides a VBT declares for `family`.
    pub fn from_vbt(vbt: &Vbt, family: crate::intel_gpu_gt::Gen12Platform) -> Self {
        let mut pins = [None; 8];
        for encoder in vbt.encoders(VbtPlatform::from_gen12(family)) {
            if let Some(slot) = pins.get_mut(encoder.port as usize) {
                *slot = encoder.hdmi_ddc;
            }
        }
        Self {
            family: Some(family),
            pins,
        }
    }

    /// The HDMI DDC pin for `ddi` on `family`: the VBT pin when these
    /// overrides were resolved for the same family and declare one, else
    /// the platform default.
    pub fn pin(
        &self,
        family: crate::intel_gpu_gt::Gen12Platform,
        ddi: crate::intel_gpu_ddi::Ddi,
    ) -> Option<PinPair> {
        let vbt = if self.family == Some(family) {
            self.pins[ddi as usize]
        } else {
            None
        };
        vbt.or_else(|| crate::intel_gpu_gmbus::gen12_ddc_pin(family, ddi))
    }
}

static GEN12_DDC: narf_lib::sync::IrqSafeSpinLock<Gen12DdcOverrides> =
    narf_lib::sync::IrqSafeSpinLock::new(Gen12DdcOverrides::NONE);

/// Install the Gen12 HDMI DDC overrides resolved at probe.
pub fn install_gen12_ddc(overrides: Gen12DdcOverrides) {
    *GEN12_DDC.lock() = overrides;
}

/// The installed Gen12 HDMI DDC overrides ([`Gen12DdcOverrides::NONE`]
/// until a VBT was found).
pub fn gen12_ddc_overrides() -> Gen12DdcOverrides {
    *GEN12_DDC.lock()
}

/// What probe installed from the board's VBT.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VbtInstall {
    /// No consumer on this generation; nothing was read.
    NotApplicable,
    /// No VBT found: every consumer keeps its no-VBT behaviour.
    Missing,
    /// A VBT from `source` was parsed and its facts installed.
    Installed(VbtSource),
    /// A VBT was found but the consumer refused the new facts (a route
    /// or hotplug baseline already exists); the old facts stay.
    Refused(VbtSource),
}

/// Probe-time discovery and installation (`intel_bios_init`'s place in
/// probe): Meteor Lake gets [`crate::intel_gpu_xelpg_external::MtlPortPolicy::from_vbt`]
/// (ports, legacy Type-C, DDC pins, SSC) or `NO_VBT`, and the Pipe-A eDP
/// PSR facts ([`crate::intel_gpu_psr::VbtPsr`]); Gen12 gets its HDMI
/// DDC overrides. `asls` is PCI config [`ASLS`] (`None`: unreadable).
pub fn install_for_probe(
    generation: crate::intel_gpu::Generation,
    gen12: Option<crate::intel_gpu_gt::Gen12Platform>,
    asls: Option<u32>,
) -> VbtInstall {
    use crate::intel_gpu::Generation;
    use crate::intel_gpu_xelpg_external::{install_mtl_port_policy, MtlPortPolicy};
    let applicable = match generation {
        Generation::MeteorLake => true,
        Generation::TigerLake | Generation::AlderLake => gen12.is_some(),
        _ => false,
    };
    if !applicable {
        return VbtInstall::NotApplicable;
    }
    let found = asls.and_then(discover);
    // The Pipe-A eDP panel's VRR feature flag (Linux
    // `intel_vrr_is_capable`'s VBT gate); installed for every
    // generation the VBT applies to, not just Meteor Lake — the
    // panel on Tiger/Alder Lake reads the same flag. Without a VBT
    // the projection is Missing and eDP VRR is never capable.
    crate::intel_gpu_vrr::install_vbt(
        found
            .as_ref()
            .map_or(crate::intel_gpu_vrr::VbtVrr::Missing, |(vbt, _)| {
                crate::intel_gpu_vrr::VbtVrr::from_vbt(vbt)
            }),
    );
    // The Pipe-A eDP PSR facts (intel_bios_init_panel's parse_psr and PSR
    // enable); without a VBT, psr.enable stays false as in Linux.
    if generation == Generation::MeteorLake {
        crate::intel_gpu_psr::install_vbt(
            found
                .as_ref()
                .map_or(crate::intel_gpu_psr::VbtPsr::Missing, |(vbt, _)| {
                    crate::intel_gpu_psr::VbtPsr::from_vbt(vbt)
                }),
        );
        // The same panel's edp.dsc_disable and edp.max_link_rate for the
        // eDP DSC decision; without a VBT neither applies.
        crate::intel_gpu_xelpg_dsc::install_edp_vbt(
            found
                .as_ref()
                .map_or(crate::intel_gpu_xelpg_dsc::EdpVbt::Missing, |(vbt, _)| {
                    crate::intel_gpu_xelpg_dsc::EdpVbt::from_vbt(vbt)
                }),
        );
    }
    let ok = match (generation, &found) {
        (Generation::MeteorLake, Some((vbt, _))) => {
            install_mtl_port_policy(MtlPortPolicy::from_vbt(vbt))
        }
        (Generation::MeteorLake, None) => install_mtl_port_policy(MtlPortPolicy::NO_VBT),
        (_, Some((vbt, _))) => match gen12 {
            Some(family) => {
                install_gen12_ddc(Gen12DdcOverrides::from_vbt(vbt, family));
                true
            }
            None => false,
        },
        (_, None) => {
            install_gen12_ddc(Gen12DdcOverrides::NONE);
            true
        }
    };
    match (found, ok) {
        (None, _) => VbtInstall::Missing,
        (Some((_, source)), true) => VbtInstall::Installed(source),
        (Some((_, source)), false) => VbtInstall::Refused(source),
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_vbt_tests.rs"]
pub mod tests;
