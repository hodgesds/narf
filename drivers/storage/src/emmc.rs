//! eMMC EXT_CSD register decoder (clean-room).
//!
//! References (public-only):
//! - JEDEC Standard JESD84-B51 — "Embedded Multi-Media Card (e•MMC)
//!   Electrical Standard (5.1)". Public document. §7.4 (EXT_CSD
//!   register: 512 bytes, indexed by byte offset).
//! - JESD84-B51 §7.3 — `BUS_WIDTH` setting via CMD6 (SWITCH).
//! - JESD84-B51 §6.6.5 — High-Speed timings (HS200, HS400) and the
//!   `HS_TIMING` byte's encoding.
//!
//! No GPL Linux source consulted.
//!
//! ## EXT_CSD layout (excerpt; offsets in decimal per §7.4 Table 39)
//!
//! ```text
//!   162  PARTITIONING_SUPPORT
//!   168  RST_n_FUNCTION
//!   175  ERASE_GROUP_DEF
//!   177  PARTITION_CONFIG
//!   179  BOOT_BUS_WIDTH
//!   183  BUS_WIDTH
//!   185  HS_TIMING
//!   187  POWER_CLASS
//!   192  EXT_CSD_REV
//!   194  CSD_STRUCTURE
//!   196  CARD_TYPE
//!   212..216  SEC_COUNT (32-bit LE — capacity in 512-byte sectors)
//!   217  MIN_PERF_W_8_52
//!   220  PWR_CL_52_360
//!   222  PWR_CL_26_195
//!   226  HC_ERASE_GRP_SIZE
//!   267  PRE_EOL_INFO
//!   268  DEVICE_LIFE_TIME_EST_TYP_A
//!   269  DEVICE_LIFE_TIME_EST_TYP_B
//! ```
//!
//! `SEC_COUNT == 0` means the card is < 2 GiB and the capacity comes
//! from the legacy CSD instead.

use core::convert::TryInto;

/// Size of the EXT_CSD register, in bytes.
pub const EXT_CSD_SIZE: usize = 512;

// Byte offsets (§7.4 Table 39).
pub const EXT_CSD_PARTITIONING_SUPPORT: usize = 162;
pub const EXT_CSD_RST_N_FUNCTION: usize = 168;
pub const EXT_CSD_ERASE_GROUP_DEF: usize = 175;
pub const EXT_CSD_PARTITION_CONFIG: usize = 179;
pub const EXT_CSD_BOOT_BUS_WIDTH: usize = 177;
pub const EXT_CSD_BUS_WIDTH: usize = 183;
pub const EXT_CSD_HS_TIMING: usize = 185;
pub const EXT_CSD_POWER_CLASS: usize = 187;
pub const EXT_CSD_REV: usize = 192;
pub const EXT_CSD_CSD_STRUCTURE: usize = 194;
pub const EXT_CSD_CARD_TYPE: usize = 196;
pub const EXT_CSD_SEC_COUNT: usize = 212;
pub const EXT_CSD_HC_ERASE_GRP_SIZE: usize = 224;
pub const EXT_CSD_BOOT_SIZE_MULT: usize = 226;
pub const EXT_CSD_PRE_EOL_INFO: usize = 267;
pub const EXT_CSD_DEVICE_LIFE_TIME_EST_TYP_A: usize = 268;
pub const EXT_CSD_DEVICE_LIFE_TIME_EST_TYP_B: usize = 269;
pub const EXT_CSD_RPMB_SIZE_MULT: usize = 168;

// CARD_TYPE bits (§7.4.66).
pub const CARD_TYPE_HS_26: u8 = 1 << 0; // 26 MHz
pub const CARD_TYPE_HS_52: u8 = 1 << 1; // 52 MHz
pub const CARD_TYPE_HS_DDR_1V8_OR_3V: u8 = 1 << 2;
pub const CARD_TYPE_HS_DDR_1V2: u8 = 1 << 3;
pub const CARD_TYPE_HS200_1V8: u8 = 1 << 4;
pub const CARD_TYPE_HS200_1V2: u8 = 1 << 5;
pub const CARD_TYPE_HS400_1V8: u8 = 1 << 6;
pub const CARD_TYPE_HS400_1V2: u8 = 1 << 7;

// HS_TIMING values (§7.4.78).
pub const HS_TIMING_BACKWARD_COMPAT: u8 = 0;
pub const HS_TIMING_HIGH_SPEED: u8 = 1;
pub const HS_TIMING_HS200: u8 = 2;
pub const HS_TIMING_HS400: u8 = 3;

// BUS_WIDTH values (§7.4.79).
pub const BUS_WIDTH_1: u8 = 0;
pub const BUS_WIDTH_4: u8 = 1;
pub const BUS_WIDTH_8: u8 = 2;
pub const BUS_WIDTH_4_DDR: u8 = 5;
pub const BUS_WIDTH_8_DDR: u8 = 6;

// PRE_EOL_INFO values (§7.4.85).
pub const PRE_EOL_NORMAL: u8 = 0x01;
pub const PRE_EOL_WARNING: u8 = 0x02;
pub const PRE_EOL_URGENT: u8 = 0x03;

/// PARTITION_CONFIG (§7.4.69) bits.
pub const PARTITION_CONFIG_BOOT_ACK: u8 = 1 << 6;
pub const PARTITION_CONFIG_BOOT_PARTITION_ENABLE_MASK: u8 = 0b0011_1000;
pub const PARTITION_CONFIG_BOOT_PARTITION_ENABLE_SHIFT: u8 = 3;
pub const PARTITION_CONFIG_PARTITION_ACCESS_MASK: u8 = 0b0000_0111;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EmmcError {
    /// Buffer must be exactly 512 bytes.
    BadLength,
}

/// Decoded EXT_CSD register.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtCsd {
    pub revision: u8,
    pub csd_structure: u8,
    pub card_type: u8,
    pub bus_width: u8,
    pub hs_timing: u8,
    pub power_class: u8,
    pub partition_config: u8,
    pub boot_size_mult: u8,
    pub rpmb_size_mult: u8,
    pub hc_erase_grp_size: u8,
    /// Capacity in 512-byte sectors. 0 ⇒ legacy CSD-derived capacity.
    pub sec_count: u32,
    pub pre_eol_info: u8,
    pub life_time_est_a: u8,
    pub life_time_est_b: u8,
}

impl ExtCsd {
    /// Parse a 512-byte EXT_CSD register snapshot read from CMD8.
    pub fn parse(buf: &[u8]) -> Result<Self, EmmcError> {
        if buf.len() != EXT_CSD_SIZE {
            return Err(EmmcError::BadLength);
        }
        let sec_count = u32::from_le_bytes(
            buf[EXT_CSD_SEC_COUNT..EXT_CSD_SEC_COUNT + 4]
                .try_into()
                .expect("len 4"),
        );
        Ok(Self {
            revision: buf[EXT_CSD_REV],
            csd_structure: buf[EXT_CSD_CSD_STRUCTURE],
            card_type: buf[EXT_CSD_CARD_TYPE],
            bus_width: buf[EXT_CSD_BUS_WIDTH],
            hs_timing: buf[EXT_CSD_HS_TIMING],
            power_class: buf[EXT_CSD_POWER_CLASS],
            partition_config: buf[EXT_CSD_PARTITION_CONFIG],
            boot_size_mult: buf[EXT_CSD_BOOT_SIZE_MULT],
            // RPMB_SIZE_MULT lives at offset 168 (same as RST_n_FUNCTION
            // is offset 168 in earlier revisions; the spec moved it to
            // 168 as RPMB_SIZE_MULT in 5.0). For B51 the canonical
            // location is byte 168 — surfaced here as `rpmb_size_mult`.
            rpmb_size_mult: buf[EXT_CSD_RPMB_SIZE_MULT],
            hc_erase_grp_size: buf[EXT_CSD_HC_ERASE_GRP_SIZE],
            sec_count,
            pre_eol_info: buf[EXT_CSD_PRE_EOL_INFO],
            life_time_est_a: buf[EXT_CSD_DEVICE_LIFE_TIME_EST_TYP_A],
            life_time_est_b: buf[EXT_CSD_DEVICE_LIFE_TIME_EST_TYP_B],
        })
    }

    /// Capacity of the user partition in bytes.
    /// `sec_count == 0` → caller must consult the legacy CSD.
    pub fn user_capacity_bytes(self) -> u64 {
        (self.sec_count as u64) * 512
    }

    /// Boot partition size per JESD84-B51 §7.4.79: BOOT_SIZE_MULT × 128 KiB.
    pub fn boot_partition_bytes(self) -> u64 {
        (self.boot_size_mult as u64) * 128 * 1024
    }

    /// RPMB partition size per JESD84-B51 §7.4.84: RPMB_SIZE_MULT × 128 KiB.
    pub fn rpmb_partition_bytes(self) -> u64 {
        (self.rpmb_size_mult as u64) * 128 * 1024
    }

    pub fn supports_hs200(self) -> bool {
        (self.card_type & (CARD_TYPE_HS200_1V8 | CARD_TYPE_HS200_1V2)) != 0
    }

    pub fn supports_hs400(self) -> bool {
        (self.card_type & (CARD_TYPE_HS400_1V8 | CARD_TYPE_HS400_1V2)) != 0
    }

    /// Currently-active boot partition (1 = boot1, 2 = boot2,
    /// 7 = user). `None` if no boot partition is enabled.
    pub fn active_boot_partition(self) -> Option<u8> {
        let v = (self.partition_config & PARTITION_CONFIG_BOOT_PARTITION_ENABLE_MASK)
            >> PARTITION_CONFIG_BOOT_PARTITION_ENABLE_SHIFT;
        if v == 0 {
            None
        } else {
            Some(v)
        }
    }

    /// Currently-accessed partition (0..7). 0 = user, 1 = boot1,
    /// 2 = boot2, 3 = RPMB, 4..=7 = GP1..GP4.
    pub fn current_partition_access(self) -> u8 {
        self.partition_config & PARTITION_CONFIG_PARTITION_ACCESS_MASK
    }

    /// Build the SWITCH (CMD6) argument that writes `value` to byte
    /// `index` of EXT_CSD using `Access=Write Byte (3)`.
    /// JESD84-B51 §6.6.4: argument layout is
    /// `[Access:2 | Index:8 | Value:8 | Reserved:6]` packed into 32 bits.
    pub const fn switch_argument(index: u8, value: u8) -> u32 {
        // bits[31:26] reserved, bits[25:24] Access (3 = Write Byte),
        // bits[23:16] Index, bits[15:8] Value, bits[7:0] CmdSet (0).
        (3u32 << 24) | ((index as u32) << 16) | ((value as u32) << 8)
    }
}
