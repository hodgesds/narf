//! RTL8XXXU MAC initialisation sequence and queue mapping.
//!
//! After firmware is downloaded and running, the driver programs:
//!
//! 1. **TRX FIFO boundary** (`REG_TRXFF_BNDY`) — splits the on-chip
//!    SRAM between TX page area and RX FIFO.
//! 2. **Queue → endpoint priority** (`REG_TRXDMA_CTRL`) — maps the eight
//!    `TXDESC_QUEUE_*` selectors to the available bulk-OUT endpoints
//!    (low / normal / high priority groups).
//! 3. **MAC address apply** — write the 48-bit MAC factory address read
//!    from EFUSE into `REG_MACID`.
//! 4. **EDCA parameters** — per-AC default contention window values.
//! 5. **Beacon timing** (`REG_BCN_INTERVAL`) — beacon period in 1024 µs
//!    units (100 = 102.4 ms).
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c`
//!   - `rtl8xxxu_init_mac` (~L2187).
//!   - `rtl8xxxu_init_queue_priority` (~L2670).
//!   - `rtl8xxxu_init_queue_reserved_page` (~L2540).
//! - `drivers/net/wireless/realtek/rtl8xxxu/regs.h` — TXDESC_QUEUE_*,
//!   REG_EDCA_*, REG_TRXFF_BNDY, REG_TRXDMA_CTRL.

#![allow(dead_code)]

use super::regs::*;
use super::usb::UsbControlSetup;

// ── Queue→endpoint mapping ────────────────────────────────────────────

/// One USB bulk-OUT endpoint slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EndpointAddr(pub u8);

/// Per-chip queue-to-endpoint mapping for the four AC queues plus
/// beacon / mgmt / high / cmd.
///
/// 8188EU/8723BU have a single bulk-OUT EP, so all queues share it.
/// 8192EU/8821CU have 2 bulk-OUT EPs (HQ/LQ split).
/// 8822BU exposes 3 bulk-OUT EPs (HQ/NQ/LQ).
///
/// The order matches `TXDESC_QUEUE_*` numerical values.
/// Source: `core.c::rtl8xxxu_init_queue_priority` ~L2695..L2710.
#[derive(Copy, Clone, Debug)]
pub struct QueueMap {
    /// VO endpoint.
    pub vo: EndpointAddr,
    /// VI endpoint.
    pub vi: EndpointAddr,
    /// BE endpoint.
    pub be: EndpointAddr,
    /// BK endpoint.
    pub bk: EndpointAddr,
    /// Beacon endpoint (always EP0 of the bulk-OUT set in Linux).
    pub beacon: EndpointAddr,
    /// MGMT endpoint.
    pub mgmt: EndpointAddr,
    /// High-priority endpoint.
    pub hi: EndpointAddr,
    /// Cmd / H2C endpoint.
    pub cmd: EndpointAddr,
}

impl QueueMap {
    /// Single-endpoint chips (8188EU, 8723BU).
    /// All queues map to the same EP (the only bulk-OUT).
    pub const fn single(ep: u8) -> Self {
        Self {
            vo: EndpointAddr(ep),
            vi: EndpointAddr(ep),
            be: EndpointAddr(ep),
            bk: EndpointAddr(ep),
            beacon: EndpointAddr(ep),
            mgmt: EndpointAddr(ep),
            hi: EndpointAddr(ep),
            cmd: EndpointAddr(ep),
        }
    }

    /// Dual-endpoint chips (8192EU, 8821CU) — HQ/LQ split.
    ///
    /// VO/VI/MGMT/HI/Cmd → high-priority EP.
    /// BE/BK/Beacon → low-priority EP.
    pub const fn dual(hq: u8, lq: u8) -> Self {
        Self {
            vo: EndpointAddr(hq),
            vi: EndpointAddr(hq),
            be: EndpointAddr(lq),
            bk: EndpointAddr(lq),
            beacon: EndpointAddr(lq),
            mgmt: EndpointAddr(hq),
            hi: EndpointAddr(hq),
            cmd: EndpointAddr(hq),
        }
    }

    /// Triple-endpoint chips (8822BU) — HQ/NQ/LQ split.
    pub const fn triple(hq: u8, nq: u8, lq: u8) -> Self {
        Self {
            vo: EndpointAddr(hq),
            vi: EndpointAddr(nq),
            be: EndpointAddr(nq),
            bk: EndpointAddr(lq),
            beacon: EndpointAddr(lq),
            mgmt: EndpointAddr(hq),
            hi: EndpointAddr(hq),
            cmd: EndpointAddr(hq),
        }
    }

    /// Endpoint for a given `TXDESC_QUEUE_*` value.
    pub fn endpoint_for_qsel(&self, qsel: u8) -> EndpointAddr {
        match qsel {
            x if x == TXDESC_QUEUE_VO => self.vo,
            x if x == TXDESC_QUEUE_VI => self.vi,
            x if x == TXDESC_QUEUE_BE => self.be,
            x if x == TXDESC_QUEUE_BK => self.bk,
            x if x == TXDESC_QUEUE_BEACON => self.beacon,
            x if x == TXDESC_QUEUE_MGNT => self.mgmt,
            x if x == TXDESC_QUEUE_HIGH => self.hi,
            x if x == TXDESC_QUEUE_CMD => self.cmd,
            _ => self.be,
        }
    }
}

// ── EDCA parameter defaults ──────────────────────────────────────────

/// Default EDCA parameter packed into the 32-bit register layout:
/// `(txop << 16) | (cw_max << 12) | (cw_min << 8) | aifs`.
///
/// Source: `core.c::rtl8xxxu_init_mac` (mac table) — these are the
/// 802.11-2016 §10.22.2 defaults.
pub const fn edca_param(aifs: u8, cw_min: u8, cw_max: u8, txop: u16) -> u32 {
    (txop as u32) << EDCA_PARAM_TXOP_SHIFT
        | (cw_max as u32) << EDCA_PARAM_ECW_MAX_SHIFT
        | (cw_min as u32) << EDCA_PARAM_ECW_MIN_SHIFT
        | aifs as u32
}

/// EDCA constant — TXOP shift in 32-bit parameter register.
pub const EDCA_PARAM_TXOP_SHIFT: u32 = 16;
/// EDCA constant — eCW_max shift.
pub const EDCA_PARAM_ECW_MAX_SHIFT: u32 = 12;
/// EDCA constant — eCW_min shift.
pub const EDCA_PARAM_ECW_MIN_SHIFT: u32 = 8;

/// 802.11-2016 default EDCA parameters for the AP-class.
///
/// Source: 802.11-2016 Table 9-156.
pub const EDCA_DEFAULT_VO: u32 = edca_param(2, 2, 3, 47);
pub const EDCA_DEFAULT_VI: u32 = edca_param(2, 3, 4, 94);
pub const EDCA_DEFAULT_BE: u32 = edca_param(3, 4, 6, 0);
pub const EDCA_DEFAULT_BK: u32 = edca_param(7, 4, 10, 0);

/// Build the list of (register, 32-bit value) writes to apply the
/// default EDCA params to all four AC queues.
pub fn edca_defaults() -> [(u16, u32); 4] {
    [
        (REG_EDCA_VO_PARAM, EDCA_DEFAULT_VO),
        (REG_EDCA_VI_PARAM, EDCA_DEFAULT_VI),
        (REG_EDCA_BE_PARAM, EDCA_DEFAULT_BE),
        (REG_EDCA_BK_PARAM, EDCA_DEFAULT_BK),
    ]
}

// ── MAC address apply ───────────────────────────────────────────────

/// Build the (addr, byte) sequence to load the 6-byte MAC address into
/// `REG_MACID` (bytes 0..3 via 32-bit write, bytes 4..5 via 16-bit
/// write — but expressed as 6 byte writes here for simplicity).
///
/// Source: `core.c::rtl8xxxu_init_device` ~L4255.
pub fn macid_writes(mac: [u8; 6]) -> [(u16, u8); 6] {
    [
        (REG_MACID, mac[0]),
        (REG_MACID + 1, mac[1]),
        (REG_MACID + 2, mac[2]),
        (REG_MACID + 3, mac[3]),
        (REG_MACID_4_5, mac[4]),
        (REG_MACID_4_5 + 1, mac[5]),
    ]
}

/// Build the BSSID write sequence.
pub fn bssid_writes(bssid: [u8; 6]) -> [(u16, u8); 6] {
    [
        (REG_BSSID, bssid[0]),
        (REG_BSSID + 1, bssid[1]),
        (REG_BSSID + 2, bssid[2]),
        (REG_BSSID + 3, bssid[3]),
        (REG_BSSID + 4, bssid[4]),
        (REG_BSSID + 5, bssid[5]),
    ]
}

// ── TRX FIFO boundary write ─────────────────────────────────────────

/// Build the USB control-transfer setup for the TRXFF boundary write.
///
/// The chip uses 16-bit boundary stored in `REG_TRXFF_BNDY + 2`.
pub fn trxff_bndy_setup() -> UsbControlSetup {
    UsbControlSetup::write(REG_TRXFF_BNDY + 2, 2)
}

/// Build the MAC init register table — the post-FW startup sequence.
///
/// Returns `(register, value)` pairs to be written as 32-bit values.
///
/// Source: `core.c::rtl8xxxu_init_mac` mactable per-chip + the EDCA /
/// beacon defaults applied generically.
pub fn mac_init_post_fw(beacon_interval_tu: u16) -> [(u16, u32); 6] {
    [
        (REG_EDCA_VO_PARAM, EDCA_DEFAULT_VO),
        (REG_EDCA_VI_PARAM, EDCA_DEFAULT_VI),
        (REG_EDCA_BE_PARAM, EDCA_DEFAULT_BE),
        (REG_EDCA_BK_PARAM, EDCA_DEFAULT_BK),
        (REG_BCN_INTERVAL, beacon_interval_tu as u32),
        // RX configuration: accept BC/MC/Mgmt + check CRC.
        (REG_RCR, 0x7000_080C),
    ]
}
