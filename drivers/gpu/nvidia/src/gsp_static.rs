//! GET_GSP_STATIC_INFO parse — the GPU facts the GSP reports post-boot.
//!
//! Right after `GSP_INIT_DONE` the host sends `GET_GSP_STATIC_INFO`
//! (function 65); the reply is a large `GspStaticConfigInfo`. This
//! module extracts the fields the driver needs: the GSP-RM's own
//! pre-allocated internal client/device/subdevice handles (control
//! calls on display/engine internals target the internal subdevice),
//! the BAR1/BAR2 page-directory bases, total FB length, and the usable
//! framebuffer region map.
//!
//! The field offsets are computed from the exact
//! `GspStaticConfigInfo` layout in `/usr/src/linux`
//! `rm/r535/nvrm/gsp.h` (accounting for the `NV_DECLARE_ALIGNED` u64
//! padding); cross-checked against `rm/r535/gsp.c::
//! r535_gsp_get_static_info`. The parser is bounds-checked, so a
//! layout mismatch fails gracefully rather than reading garbage.
//!
//! Pure CPU work (no hardware), unit-tested.

#![allow(dead_code)]

use alloc::vec::Vec;

/// `sizeof(GspStaticConfigInfo)` (r535). The reply payload is this big.
pub const GSP_STATIC_INFO_SIZE: usize = 2168;

// Field offsets within GspStaticConfigInfo (see module docs).
const OFF_NUM_FB_REGIONS: usize = 840;
const OFF_FB_REGION0: usize = 848;
const FB_REGION_STRIDE: usize = 48;
const FB_REGION_MAX: usize = 16;
const OFF_FB_LENGTH: usize = 1752;
const OFF_BAR1_PDE: usize = 2088;
const OFF_BAR2_PDE: usize = 2096;
const OFF_H_INTERNAL_CLIENT: usize = 2152;
const OFF_H_INTERNAL_DEVICE: usize = 2156;
const OFF_H_INTERNAL_SUBDEVICE: usize = 2160;

// Per-region (NV2080_CTRL_CMD_FB_GET_FB_REGION_FB_REGION_INFO) offsets.
const RGN_BASE: usize = 0;
const RGN_LIMIT: usize = 8;
const RGN_RESERVED: usize = 16;
const RGN_PERFORMANCE: usize = 24;
const RGN_SUPPORT_COMPRESSED: usize = 28;
const RGN_SUPPORT_ISO: usize = 29;
const RGN_PROTECTED: usize = 30;

/// One framebuffer region the GSP reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FbRegion {
    pub base: u64,
    /// Inclusive upper bound.
    pub limit: u64,
    pub reserved: u64,
    pub performance: u32,
    pub support_compressed: bool,
    pub support_iso: bool,
    pub protected: bool,
}

impl FbRegion {
    /// A region usable for general driver allocation: not reserved, not
    /// protected, supports both compressed + ISO memory. Mirrors the
    /// filter in `r535_gsp_get_static_info_fb`.
    pub fn is_usable(&self) -> bool {
        self.reserved == 0 && !self.protected && self.support_compressed && self.support_iso
    }

    /// Region size in bytes (`limit - base + 1`).
    pub fn size(&self) -> u64 {
        self.limit.wrapping_sub(self.base).wrapping_add(1)
    }
}

/// The subset of `GspStaticConfigInfo` the driver consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StaticInfo {
    /// GSP-RM's pre-allocated internal handles (control-call targets).
    pub internal_client: u32,
    pub internal_device: u32,
    pub internal_subdevice: u32,
    pub bar1_pde_base: u64,
    pub bar2_pde_base: u64,
    pub fb_length: u64,
    pub fb_regions: Vec<FbRegion>,
}

fn rd32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn rd64(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8)
        .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
}

/// Parse the GET_GSP_STATIC_INFO reply payload. Returns `None` if the
/// payload is too short for the struct.
pub fn parse_static_info(payload: &[u8]) -> Option<StaticInfo> {
    if payload.len() < GSP_STATIC_INFO_SIZE {
        return None;
    }
    let num = (rd32(payload, OFF_NUM_FB_REGIONS)? as usize).min(FB_REGION_MAX);
    let mut fb_regions = Vec::with_capacity(num);
    for i in 0..num {
        let r = OFF_FB_REGION0 + i * FB_REGION_STRIDE;
        fb_regions.push(FbRegion {
            base: rd64(payload, r + RGN_BASE)?,
            limit: rd64(payload, r + RGN_LIMIT)?,
            reserved: rd64(payload, r + RGN_RESERVED)?,
            performance: rd32(payload, r + RGN_PERFORMANCE)?,
            support_compressed: payload[r + RGN_SUPPORT_COMPRESSED] != 0,
            support_iso: payload[r + RGN_SUPPORT_ISO] != 0,
            protected: payload[r + RGN_PROTECTED] != 0,
        });
    }
    Some(StaticInfo {
        internal_client: rd32(payload, OFF_H_INTERNAL_CLIENT)?,
        internal_device: rd32(payload, OFF_H_INTERNAL_DEVICE)?,
        internal_subdevice: rd32(payload, OFF_H_INTERNAL_SUBDEVICE)?,
        bar1_pde_base: rd64(payload, OFF_BAR1_PDE)?,
        bar2_pde_base: rd64(payload, OFF_BAR2_PDE)?,
        fb_length: rd64(payload, OFF_FB_LENGTH)?,
        fb_regions,
    })
}
