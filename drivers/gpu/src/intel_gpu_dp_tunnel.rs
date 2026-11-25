//! DP tunnel bandwidth allocation (BWA) over a USB4 / Thunderbolt DP IN
//! adapter, for the 128b/132b route over Thunderbolt alt mode under
//! `narf.intel.uhbr=1` ([`super::uhbr::BOOT_OPTION`]).
//!
//! A tunnelled DPRX reports no rate in `DP_128B132B_SUPPORTED_LINK_RATES`
//! (`drm_dp_tunnel_128b132b_dprx_rates`, DP 2.1 5.14.3): Linux learns its
//! 128b/132b rates only from the tunnel's own DPCD after enabling BW
//! allocation mode (`intel_dp_set_dpcd_sink_rates` through
//! `dprx_128b132b_link_rates`), caps every link configuration at the
//! tunnel's available bandwidth (`intel_dp_max_link_data_rate`) and asks the
//! connection manager for the stream's bandwidth before the port is enabled
//! (`intel_dp_tunnel_atomic_alloc_bw`). What this module owns, each from
//! Linux 7.4 `drm_dp_tunnel.c` / `intel_dp_tunnel.c`:
//!
//! - [`TunnelRegs::read`] (`read_tunnel_regs`): the six DPCD ranges of
//!   `DPTUN_INFO_REG_MASK`, one AUX read each, never `DP_TUNNELING_STATUS`.
//! - [`detect`] (`drm_dp_tunnel_detect`, `create_tunnel`,
//!   `tunnel_regs_are_valid` without the DPRX check).
//! - [`enable_bw_alloc`] / [`disable_bw_alloc`]
//!   (`drm_dp_tunnel_enable_bw_alloc`, `set_bw_alloc_mode`,
//!   `read_and_verify_tunnel_regs`, `update_dprx_caps`,
//!   `update_group_available_bw`).
//! - [`alloc_bw`] (`drm_dp_tunnel_alloc_bw`, `allocate_tunnel_bw`,
//!   `bw_req_complete`, `clear_bw_req_state`): the request in granularity
//!   units and its 3000 ms completion.
//! - [`Tunnel::max_link_data_rate`] (`intel_dp_max_link_data_rate`) and
//!   [`Tunnel::uhbr_lane_mask`] (`intel_dp_tunnel_uhbr_lanes_wa_setup`).
//!
//! Everything is DPCD (0xe0000..=0xe0031). The connection manager's half
//! (the DP IN adapter's BW allocation support, the estimated bandwidth and
//! the grant) is the USB4 driver's (`narf_drivers_thunderbolt::dp_bw`); this
//! module only reads what it publishes through the adapter, so a tunnel
//! whose connection manager does not offer BW allocation reads as
//! [`TunnelError::Unsupported`] and keeps its legacy allocation.
//!
//! NARF owns one external route, so a tunnel's group holds only this
//! tunnel: `calc_group_available_bw` reduces to its estimated bandwidth.
//! Linux wakes the BW request wait from the tunnel's HPD IRQ
//! (`drm_dp_tunnel_handle_irq`); here the wait polls
//! `DP_TUNNELING_STATUS` every millisecond, the read after the deadline
//! still deciding.

use crate::dp_aux::{AuxChannel, AuxError};

use super::uhbr::Clock;

/// `DP_TUNNELING_BASE` / `DP_TUNNELING_OUI`.
pub const DP_TUNNELING_BASE: u32 = 0xe_0000;
/// `DP_TUNNELING_CAPABILITIES` and its bits.
pub const DP_TUNNELING_CAPABILITIES: u32 = 0xe_000d;
pub const DP_IN_BW_ALLOCATION_MODE_SUPPORT: u8 = 1 << 7;
pub const DP_TUNNELING_SUPPORT: u8 = 1 << 0;
/// `DP_USB4_DRIVER_ID` (`DP_USB4_DRIVER_ID_MASK`, four bits).
pub const DP_USB4_DRIVER_ID: u32 = 0xe_000f;
/// `DP_USB4_DRIVER_BW_CAPABILITY` / `DP_USB4_DRIVER_BW_ALLOCATION_MODE_SUPPORT`.
pub const DP_USB4_DRIVER_BW_CAPABILITY: u32 = 0xe_0020;
pub const DP_USB4_DRIVER_BW_ALLOCATION_MODE_SUPPORT: u8 = 1 << 7;
/// `DP_IN_ADAPTER_TUNNEL_INFORMATION` (`DP_GROUP_ID_MASK`, three bits).
pub const DP_IN_ADAPTER_TUNNEL_INFORMATION: u32 = 0xe_0021;
/// `DP_BW_GRANULARITY` (`DP_BW_GRANULARITY_MASK`).
pub const DP_BW_GRANULARITY: u32 = 0xe_0022;
/// `DP_ESTIMATED_BW` / `DP_ALLOCATED_BW`, in granularity units.
pub const DP_ESTIMATED_BW: u32 = 0xe_0023;
pub const DP_ALLOCATED_BW: u32 = 0xe_0024;
/// `DP_TUNNELING_STATUS` and its bits (write 1 to clear).
pub const DP_TUNNELING_STATUS: u32 = 0xe_0025;
pub const DP_BW_ALLOCATION_CAPABILITY_CHANGED: u8 = 1 << 3;
pub const DP_ESTIMATED_BW_CHANGED: u8 = 1 << 2;
pub const DP_BW_REQUEST_SUCCEEDED: u8 = 1 << 1;
pub const DP_BW_REQUEST_FAILED: u8 = 1 << 0;
/// `DP_TUNNELING_MAX_LINK_RATE` (a link BW code).
pub const DP_TUNNELING_MAX_LINK_RATE: u32 = 0xe_0028;
/// `DP_TUNNELING_MAX_LANE_COUNT` (`DP_TUNNELING_MAX_LANE_COUNT_MASK`).
pub const DP_TUNNELING_MAX_LANE_COUNT: u32 = 0xe_0029;
/// `DP_TUNNELING_MAIN_LINK_CHANNEL_CODING` / `DP_128B132B_DP_SUPPORTED`.
pub const DP_TUNNELING_MAIN_LINK_CHANNEL_CODING: u32 = 0xe_002b;
pub const DP_128B132B_DP_SUPPORTED: u8 = 1 << 0;
/// `DP_TUNNELING_128B132B_LINK_RATE`: the `DP_TUNNELING_*GBPS_PER_LANE_SUPPORT`
/// bits (equal to `DP_UHBR10/20/13_5`) and
/// `DP_TUNNELING_128B132B_LL_LANE0_MAPPING_SUPPORT`.
pub const DP_TUNNELING_128B132B_LINK_RATE: u32 = 0xe_002c;
pub const DP_TUNNELING_128B132B_LINK_RATE_MASK: u8 = 0x7;
pub const DP_TUNNELING_128B132B_LL_LANE0_MAPPING_SUPPORT: u8 = 1 << 7;
/// `DP_DPTX_BW_ALLOCATION_MODE_CONTROL` and its bits.
pub const DP_DPTX_BW_ALLOCATION_MODE_CONTROL: u32 = 0xe_0030;
pub const DP_DISPLAY_DRIVER_BW_ALLOCATION_MODE_ENABLE: u8 = 1 << 7;
pub const DP_UNMASK_BW_ALLOCATION_IRQ: u8 = 1 << 6;
/// `DP_REQUEST_BW` and `MAX_DP_REQUEST_BW`.
pub const DP_REQUEST_BW: u32 = 0xe_0031;
pub const MAX_DP_REQUEST_BW: u32 = 255;

/// The contiguous ranges of `DPTUN_INFO_REG_MASK` (address, length): Linux's
/// `next_reg_area` walk reads each with one AUX transfer.
pub const REG_AREAS: [(u32, usize); 6] = [
    (0xe_0000, 12),
    (0xe_000d, 3),
    (0xe_0020, 5),
    (0xe_0028, 2),
    (0xe_002b, 2),
    (0xe_0030, 1),
];

/// `drm_dp_bw_code_to_link_rate`: the 128b/132b codes, else `code * 27000`.
pub const fn bw_code_to_link_rate(code: u8) -> u32 {
    match code {
        0x01 => 1_000_000,
        0x04 => 1_350_000,
        0x02 => 2_000_000,
        _ => code as u32 * 27_000,
    }
}

/// `drm_dp_max_dprx_data_rate`, kBps: 8b/10b at 80%, 128b/132b at 96.71%.
pub fn max_dprx_data_rate(link_rate: u32, lanes: u32) -> u64 {
    let efficiency: u64 = if link_rate >= 1_000_000 {
        967_100
    } else {
        800_000
    };
    u64::from(link_rate) * 10 * u64::from(lanes) * efficiency / (1_000_000 * 8)
}

/// The tunnel registers `read_tunnel_regs` returns, indexed from
/// [`DP_TUNNELING_BASE`]; bytes outside [`REG_AREAS`] stay zero.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TunnelRegs(pub [u8; 0x31]);

impl Default for TunnelRegs {
    fn default() -> Self {
        Self([0; 0x31])
    }
}

impl TunnelRegs {
    /// `read_tunnel_regs`.
    pub fn read<A: AuxChannel + ?Sized>(aux: &mut A) -> Result<Self, AuxError> {
        let mut regs = Self::default();
        for (address, len) in REG_AREAS {
            let at = (address - DP_TUNNELING_BASE) as usize;
            aux.dpcd_read(address, &mut regs.0[at..at + len])?;
        }
        Ok(regs)
    }

    fn reg(&self, address: u32) -> u8 {
        self.0[(address - DP_TUNNELING_BASE) as usize]
    }

    /// `DP_TUNNELING_SUPPORT`.
    pub fn tunneling(&self) -> bool {
        self.reg(DP_TUNNELING_CAPABILITIES) & DP_TUNNELING_SUPPORT != 0
    }

    /// `tunnel_reg_drv_group_id`: driver ID above the three group-ID bits;
    /// 0 when the group ID is 0.
    pub fn drv_group_id(&self) -> u8 {
        let drv = self.reg(DP_USB4_DRIVER_ID) & 0xf;
        let group = self.reg(DP_IN_ADAPTER_TUNNEL_INFORMATION) & 0x7;
        if group == 0 {
            0
        } else {
            (drv << 3) | group
        }
    }

    /// `tunnel_reg_bw_granularity`: `(250000 << gr) / 8` kBps (0.25, 0.5 or
    /// 1 Gbps); `None` for the reserved code 3.
    pub fn granularity(&self) -> Option<u32> {
        let gr = self.reg(DP_BW_GRANULARITY) & 0x3;
        (gr <= 2).then(|| (250_000u32 << gr) / 8)
    }

    /// `tunnel_reg_dprx_128b132b_support`.
    pub fn dprx_128b132b(&self) -> bool {
        self.reg(DP_TUNNELING_MAIN_LINK_CHANNEL_CODING) & DP_128B132B_DP_SUPPORTED != 0
    }

    /// `tunnel_reg_dprx_128b132b_lane0_mapping_support`.
    pub fn lane0_mapping(&self) -> bool {
        self.reg(DP_TUNNELING_128B132B_LINK_RATE) & DP_TUNNELING_128B132B_LL_LANE0_MAPPING_SUPPORT
            != 0
    }

    /// `tunnel_reg_dprx_128b132b_rates` (`DP_UHBR*` bits).
    pub fn dprx_128b132b_rates(&self) -> u8 {
        if !self.dprx_128b132b() {
            return 0;
        }
        self.reg(DP_TUNNELING_128B132B_LINK_RATE) & DP_TUNNELING_128B132B_LINK_RATE_MASK
    }

    /// `tunnel_reg_max_dprx_rate`: the highest 128b/132b rate, else
    /// `DP_TUNNELING_MAX_LINK_RATE` (Linux link units).
    pub fn max_dprx_rate(&self) -> u32 {
        let rates = self.dprx_128b132b_rates();
        // max_128b132b_rate: UHBR20, UHBR13.5, UHBR10 (the bits equal the
        // 128b/132b link BW codes).
        let code = if rates & 0x2 != 0 {
            0x2
        } else if rates & 0x4 != 0 {
            0x4
        } else if rates & 0x1 != 0 {
            0x1
        } else {
            self.reg(DP_TUNNELING_MAX_LINK_RATE)
        };
        bw_code_to_link_rate(code)
    }

    /// `tunnel_reg_max_dprx_lane_count`.
    pub fn max_dprx_lanes(&self) -> u8 {
        self.reg(DP_TUNNELING_MAX_LANE_COUNT) & 0x1f
    }

    /// `tunnel_reg_bw_alloc_supported`: the adapter's tunneling and BW
    /// allocation support and the USB4 driver's.
    pub fn bw_alloc_supported(&self) -> bool {
        let cap = DP_TUNNELING_SUPPORT | DP_IN_BW_ALLOCATION_MODE_SUPPORT;
        self.reg(DP_TUNNELING_CAPABILITIES) & cap == cap
            && self.reg(DP_USB4_DRIVER_BW_CAPABILITY) & DP_USB4_DRIVER_BW_ALLOCATION_MODE_SUPPORT
                != 0
    }

    /// `tunnel_reg_bw_alloc_enabled`.
    pub fn bw_alloc_enabled(&self) -> bool {
        self.reg(DP_DPTX_BW_ALLOCATION_MODE_CONTROL) & DP_DISPLAY_DRIVER_BW_ALLOCATION_MODE_ENABLE
            != 0
    }

    /// `tunnel_regs_are_valid` (`check_dprx` false is
    /// `SKIP_DPRX_CAPS_CHECK`).
    pub fn valid(&self, check_dprx: bool) -> bool {
        let group = self.drv_group_id() & 0x7;
        if !self.bw_alloc_supported() {
            return group == 0 && self.reg(DP_ALLOCATED_BW) == 0;
        }
        group != 0
            && (!check_dprx || self.max_dprx_lanes().count_ones() == 1)
            && (!check_dprx || self.max_dprx_rate() != 0)
            && self.granularity().is_some()
            && self.reg(DP_ALLOCATED_BW) <= self.reg(DP_ESTIMATED_BW)
    }
}

/// Why a tunnel operation failed (Linux's error codes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TunnelError {
    /// A tunnel DPCD access failed (`-EIO`; the tunnel has an I/O error).
    Aux(AuxError),
    /// No DP tunnel on the link (`-ENODEV`).
    NoTunnel,
    /// The tunnel registers are inconsistent (`-EINVAL`).
    Invalid,
    /// The adapter or the USB4 connection manager does not offer BW
    /// allocation (`-EOPNOTSUPP`): the tunnel keeps its legacy allocation.
    Unsupported,
    /// The request exceeds `MAX_DP_REQUEST_BW` units (`-EINVAL`).
    TooLarge,
    /// The connection manager refused the request (`-ENOSPC`).
    Refused,
    /// No completion within 3000 ms (`-ETIMEDOUT`).
    Timeout,
}

impl From<AuxError> for TunnelError {
    fn from(e: AuxError) -> Self {
        Self::Aux(e)
    }
}

/// One detected tunnel (`struct drm_dp_tunnel` with its one-tunnel group).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tunnel {
    /// `bw_granularity`, kBps.
    pub granularity: u32,
    /// `estimated_bw`, kBps.
    pub estimated_bw: u32,
    /// `allocated_bw`, kBps; `None` is Linux's -1 (undetermined: the
    /// connection manager's legacy allocation until the first request).
    pub allocated_bw: Option<u32>,
    /// `group->available_bw`, kBps; `None` is -1 (not yet valid).
    pub available_bw: Option<u32>,
    /// `drv_group_id`.
    pub drv_group_id: u8,
    /// `bw_alloc_supported` / `bw_alloc_enabled`.
    pub bw_alloc_supported: bool,
    pub bw_alloc_enabled: bool,
    /// `dprx_128b132b_rates` (`DP_UHBR*` bits).
    pub dprx_128b132b_rates: u8,
    /// `dprx_128b132b_lane0_mapping_support`.
    pub lane0_mapping: bool,
    /// `max_dprx_rate` (Linux link units) and `max_dprx_lane_count`.
    pub max_dprx_rate: u32,
    pub max_dprx_lanes: u8,
}

impl Tunnel {
    /// `drm_dp_tunnel_bw_alloc_is_enabled`.
    pub fn bw_alloc(&self) -> bool {
        self.bw_alloc_enabled
    }

    /// `intel_dp_max_link_data_rate`: the DPRX data rate of `rate` x `lanes`,
    /// capped at the tunnel's available bandwidth while BW allocation is
    /// enabled.
    pub fn max_link_data_rate(&self, link_rate: u32, lanes: u32) -> u64 {
        let rate = max_dprx_data_rate(link_rate, lanes);
        match (self.bw_alloc_enabled, self.available_bw) {
            (true, Some(available)) => rate.min(u64::from(available)),
            _ => rate,
        }
    }

    /// `intel_dp_tunnel_uhbr_lanes_wa_setup`: with BW allocation enabled and
    /// no `DP_TUNNELING_128B132B_LL_LANE0_MAPPING_SUPPORT`, the one- and
    /// two-lane UHBR configurations are disabled (a lane-count conversion
    /// failure in the DPRX, DP 2.1b 3.5.2.16.3). Returns the disabled lane
    /// counts as a mask of `1 << ilog2(lanes)`.
    pub fn uhbr_lane_mask(&self) -> u8 {
        if !self.bw_alloc_enabled || self.lane0_mapping {
            0
        } else {
            (1 << 0) | (1 << 1)
        }
    }

    fn update_dprx_caps(&mut self, regs: &TunnelRegs) {
        self.dprx_128b132b_rates = regs.dprx_128b132b_rates();
        self.lane0_mapping = regs.lane0_mapping();
        self.max_dprx_rate = regs.max_dprx_rate();
        self.max_dprx_lanes = regs.max_dprx_lanes();
    }

    /// `update_group_available_bw` for a one-tunnel group: the estimated
    /// bandwidth (which includes this tunnel's allocation).
    fn update_available_bw(&mut self, regs: &TunnelRegs) {
        self.estimated_bw = u32::from(regs.reg(DP_ESTIMATED_BW)) * self.granularity;
        self.available_bw = Some(self.estimated_bw);
    }

    /// `tunnel_info_changes_are_valid` with `ALLOW_ALLOCATED_BW_CHANGE`.
    fn info_unchanged(&self, regs: &TunnelRegs) -> bool {
        self.bw_alloc_supported == regs.bw_alloc_supported()
            && self.drv_group_id == regs.drv_group_id()
            && (!self.bw_alloc_supported || regs.granularity() == Some(self.granularity))
    }
}

/// `drm_dp_tunnel_detect` and `create_tunnel`: the tunnel registers, the
/// tunneling support bit and `tunnel_regs_are_valid` without the DPRX
/// check ("The DPRX caps are valid only after enabling BW alloc mode").
/// An initial `DP_ALLOCATED_BW` of 0 is undetermined.
pub fn detect<A: AuxChannel + ?Sized>(aux: &mut A) -> Result<Tunnel, TunnelError> {
    let regs = TunnelRegs::read(aux)?;
    if !regs.tunneling() {
        return Err(TunnelError::NoTunnel);
    }
    if !regs.valid(false) {
        return Err(TunnelError::Invalid);
    }
    // A tunnel without BW allocation support has no valid granularity.
    let granularity = regs.granularity().unwrap_or(0);
    let allocated = u32::from(regs.reg(DP_ALLOCATED_BW)) * granularity;
    Ok(Tunnel {
        granularity,
        estimated_bw: 0,
        allocated_bw: (allocated != 0).then_some(allocated),
        available_bw: None,
        drv_group_id: regs.drv_group_id(),
        bw_alloc_supported: regs.bw_alloc_supported(),
        bw_alloc_enabled: regs.bw_alloc_enabled(),
        dprx_128b132b_rates: 0,
        lane0_mapping: false,
        max_dprx_rate: 0,
        max_dprx_lanes: 0,
    })
}

/// `set_bw_alloc_mode`: read-modify-write of
/// `DP_DPTX_BW_ALLOCATION_MODE_CONTROL` with the enable and IRQ-unmask bits.
fn set_bw_alloc_mode<A: AuxChannel + ?Sized>(
    aux: &mut A,
    tunnel: &mut Tunnel,
    enable: bool,
) -> Result<(), TunnelError> {
    let mask = DP_DISPLAY_DRIVER_BW_ALLOCATION_MODE_ENABLE | DP_UNMASK_BW_ALLOCATION_IRQ;
    let mut value = [0u8];
    aux.dpcd_read(DP_DPTX_BW_ALLOCATION_MODE_CONTROL, &mut value)?;
    let value = if enable {
        value[0] | mask
    } else {
        value[0] & !mask
    };
    aux.dpcd_write(DP_DPTX_BW_ALLOCATION_MODE_CONTROL, &[value])?;
    tunnel.bw_alloc_enabled = enable;
    Ok(())
}

/// `drm_dp_tunnel_enable_bw_alloc`: refused without BW allocation support
/// or with a zero group ID; the mode set, the registers re-read and
/// verified (the allocation may have changed: `ALLOW_ALLOCATED_BW_CHANGE`;
/// a failed verification clears the mode again), the DPRX capabilities
/// taken from the tunnel and the group's available bandwidth.
pub fn enable_bw_alloc<A: AuxChannel + ?Sized>(
    aux: &mut A,
    tunnel: &mut Tunnel,
) -> Result<(), TunnelError> {
    if !tunnel.bw_alloc_supported {
        return Err(TunnelError::Unsupported);
    }
    if tunnel.drv_group_id & 0x7 == 0 {
        return Err(TunnelError::Invalid);
    }
    set_bw_alloc_mode(aux, tunnel, true)?;
    let regs = match TunnelRegs::read(aux) {
        Ok(regs) if regs.valid(true) && tunnel.info_unchanged(&regs) => regs,
        Ok(_) => {
            let _ = set_bw_alloc_mode(aux, tunnel, false);
            return Err(TunnelError::Invalid);
        }
        Err(e) => {
            let _ = set_bw_alloc_mode(aux, tunnel, false);
            return Err(TunnelError::Aux(e));
        }
    };
    if tunnel.max_dprx_rate == 0 {
        tunnel.update_dprx_caps(&regs);
    }
    if tunnel.available_bw.is_none() {
        tunnel.update_available_bw(&regs);
    }
    Ok(())
}

/// `drm_dp_tunnel_disable_bw_alloc`: the allocation is undetermined again
/// and the mode cleared.
pub fn disable_bw_alloc<A: AuxChannel + ?Sized>(
    aux: &mut A,
    tunnel: &mut Tunnel,
) -> Result<(), TunnelError> {
    tunnel.allocated_bw = None;
    set_bw_alloc_mode(aux, tunnel, false)
}

/// `clear_bw_req_state`.
fn clear_bw_req_state<A: AuxChannel + ?Sized>(aux: &mut A) -> Result<(), AuxError> {
    aux.dpcd_write(
        DP_TUNNELING_STATUS,
        &[DP_BW_REQUEST_SUCCEEDED | DP_BW_REQUEST_FAILED],
    )
}

/// `bw_req_complete`: `None` while neither result bit is set, else the
/// result after clearing it; the status-change bits are reported.
fn bw_req_complete<A: AuxChannel + ?Sized>(
    aux: &mut A,
) -> Result<(Option<bool>, bool), AuxError> {
    let mut status = [0u8];
    aux.dpcd_read(DP_TUNNELING_STATUS, &mut status)?;
    let changed =
        status[0] & (DP_BW_ALLOCATION_CAPABILITY_CHANGED | DP_ESTIMATED_BW_CHANGED) != 0;
    let result = status[0] & (DP_BW_REQUEST_SUCCEEDED | DP_BW_REQUEST_FAILED);
    if result == 0 {
        return Ok((None, changed));
    }
    clear_bw_req_state(aux)?;
    Ok((Some(result == DP_BW_REQUEST_SUCCEEDED), changed))
}

/// The BW request's completion budget (`msecs_to_jiffies(3000)`).
pub const BW_REQUEST_TIMEOUT_US: u64 = 3_000_000;
/// This driver's poll interval for the completion Linux's tunnel IRQ wakes.
pub const BW_REQUEST_POLL_US: u64 = 1_000;

/// `drm_dp_tunnel_alloc_bw` / `allocate_tunnel_bw`: `DIV_ROUND_UP(bw,
/// granularity)` units, nothing to do when that is the current allocation;
/// the request status cleared, `DP_REQUEST_BW` written, then the result
/// awaited for 3000 ms (a status change re-reads and verifies the tunnel
/// registers). `bw` is kBps; 0 frees the tunnel's allocation.
pub fn alloc_bw<A: AuxChannel + ?Sized, C: Clock>(
    aux: &mut A,
    clock: &mut C,
    tunnel: &mut Tunnel,
    bw: u32,
) -> Result<(), TunnelError> {
    let gr = tunnel.granularity;
    if gr == 0 {
        return Err(TunnelError::Unsupported);
    }
    let request = bw.div_ceil(gr);
    if tunnel.allocated_bw == Some(request * gr) {
        return Ok(());
    }
    if request > MAX_DP_REQUEST_BW {
        return Err(TunnelError::TooLarge);
    }
    clear_bw_req_state(aux)?;
    aux.dpcd_write(DP_REQUEST_BW, &[request as u8])?;
    let deadline = clock.now_us() + BW_REQUEST_TIMEOUT_US;
    loop {
        let expired = clock.now_us() > deadline;
        let (result, changed) = bw_req_complete(aux)?;
        match result {
            Some(true) => break,
            Some(false) => return Err(TunnelError::Refused),
            None => {}
        }
        if changed {
            let regs = TunnelRegs::read(aux)?;
            if !regs.valid(true) || !tunnel.info_unchanged(&regs) {
                return Err(TunnelError::Invalid);
            }
        }
        if expired {
            return Err(TunnelError::Timeout);
        }
        clock.sleep_us(BW_REQUEST_POLL_US);
    }
    tunnel.allocated_bw = Some(request * gr);
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "intel_gpu_dp_tunnel_tests.rs"]
mod tests;
