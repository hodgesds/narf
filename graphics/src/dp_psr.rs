//! Panel Self-Refresh + Adaptive-Sync DPCD registers — clean-room.
//!
//! References (public-only):
//! - "VESA DisplayPort Standard, Version 1.4a" — VESA. Public.
//!   §3.6 (eDP-specific DPCD block at 0x700..0x7FF — eDP Display
//!   Control Capabilities, Backlight, Panel Self-Refresh).
//!   §3.6.6 (PSR DPCD register block: PSR_SUPPORT 0x70, PSR_VERSION
//!   0x71, PSR_CAPS 0x72, PSR_CONFIGURATION 0x170, PSR_STATUS 0x2007,
//!   PSR_ERROR_STATUS 0x2008).
//!   §3.5.1.5 (eDP MAIN_LINK_CHANNEL_CODING_SET — for the
//!   Adaptive-Sync / Variable Refresh-Rate handshake).
//! - "VESA Embedded DisplayPort (eDP) Standard, Version 1.5" — VESA.
//!   Public. The eDP supplement defines the PSR2 extension at
//!   §3.6.10 (PSR2_CAPS at DPCD 0x2030).
//! - "VESA Adaptive-Sync / FreeSync over DisplayPort" — VESA.
//!   Public TID. The MSA-VSYNC ignore behaviour the source uses to
//!   stretch each frame is gated by a sink-cap bit in
//!   DOWN_STREAM_PORT_PRESENT (DPCD 0x05) bit 6.
//!
//! No GPL Linux source consulted.

/// PSR_SUPPORT DPCD address (eDP §3.6.6).
pub const DPCD_PSR_SUPPORT: u32 = 0x00070;
/// PSR_VERSION DPCD address.
pub const DPCD_PSR_VERSION: u32 = 0x00071;
/// PSR_CAPS DPCD address.
pub const DPCD_PSR_CAPS: u32 = 0x00072;
/// PSR_CONFIGURATION DPCD address (writeable).
pub const DPCD_PSR_CONFIGURATION: u32 = 0x00170;
/// PSR_STATUS DPCD address (read-only).
pub const DPCD_PSR_STATUS: u32 = 0x02007;
/// PSR_ERROR_STATUS DPCD address (W1C).
pub const DPCD_PSR_ERROR_STATUS: u32 = 0x02008;
/// PSR_EVENT_STATUS DPCD address.
pub const DPCD_PSR_EVENT_STATUS: u32 = 0x02009;
/// PSR2_CAPS DPCD address (eDP 1.5 §3.6.10).
pub const DPCD_PSR2_CAPS: u32 = 0x02030;

// PSR_SUPPORT bits (§3.6.6).
pub const PSR_SUPPORT_PSR1: u8 = 1 << 0;
pub const PSR_SUPPORT_PSR2: u8 = 1 << 1;
pub const PSR_SUPPORT_Y_COORD_VALID: u8 = 1 << 2;

// PSR_CAPS bits.
pub const PSR_CAP_LINK_TRAINING_REQUIRED_ON_EXIT: u8 = 1 << 0;
pub const PSR_CAP_FRAME_CAPTURE_INDICATION: u8 = 1 << 1;
pub const PSR_CAP_SU_LINE_CAPTURE_INDICATION: u8 = 1 << 2;
pub const PSR_CAP_IRQ_HPD_WITH_CRC_ERROR: u8 = 1 << 3;
pub const PSR_CAP_DEEP_SLEEP_ON_EXIT: u8 = 1 << 4;
/// Setup Time field (3 bits at bits 7..5):
///   0 = 330 µs, 1 = 275 µs, 2 = 220 µs, 3 = 165 µs, 4 = 110 µs,
///   5 = 55 µs, 6 = 0 µs.
pub const PSR_CAP_SETUP_TIME_MASK: u8 = 0b111 << 5;
pub const PSR_CAP_SETUP_TIME_SHIFT: u8 = 5;

// PSR_CONFIGURATION bits (§3.6.6).
pub const PSR_CFG_ENABLE: u8 = 1 << 0;
pub const PSR_CFG_MAIN_LINK_ACTIVE: u8 = 1 << 1;
pub const PSR_CFG_CRC_VERIFICATION: u8 = 1 << 2;
pub const PSR_CFG_FRAME_CAPTURE: u8 = 1 << 3;
pub const PSR_CFG_SU_LINE_CAPTURE: u8 = 1 << 4;
pub const PSR_CFG_HPD_IRQ_ON_CRC_ERROR: u8 = 1 << 5;
pub const PSR_CFG_ENABLE_PSR2: u8 = 1 << 6;
pub const PSR_CFG_ENABLE_EARLY_TX: u8 = 1 << 7;

// PSR_STATUS values (§3.6.6 table 3-22).
pub const PSR_STATE_INACTIVE: u8 = 0;
pub const PSR_STATE_TX_TRAINING: u8 = 1;
pub const PSR_STATE_TX_RX_LOCKED: u8 = 2;
pub const PSR_STATE_ACTIVE_NO_FRAME: u8 = 3;
pub const PSR_STATE_ACTIVE_SINGLE_FRAME: u8 = 4;
pub const PSR_STATE_ACTIVE_NO_BACKLIGHT: u8 = 5;
pub const PSR_STATE_RX_VERIFY_PANEL_REFRESH: u8 = 6;
pub const PSR_STATE_INTERNAL_ERROR: u8 = 7;

// PSR_ERROR_STATUS bits.
pub const PSR_ERR_LINK_CRC: u8 = 1 << 0;
pub const PSR_ERR_RFB_STORAGE: u8 = 1 << 1;
pub const PSR_ERR_VSC_SDP_UNCORRECTABLE: u8 = 1 << 2;

// PSR_EVENT_STATUS bits.
pub const PSR_EVENT_CAPTURE: u8 = 1 << 0;
pub const PSR_EVENT_SU_LINE: u8 = 1 << 1;

// PSR2_CAPS bits (eDP 1.5 §3.6.10).
pub const PSR2_CAP_SU: u8 = 1 << 0;
pub const PSR2_CAP_SU_GRANULARITY_REQUIRED: u8 = 1 << 1;
pub const PSR2_CAP_HPD_REQUIRED_ON_FRAME_CAPTURE: u8 = 1 << 2;

/// Decoded PSR Capabilities byte (DPCD 0x72).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PsrCaps {
    pub link_training_required_on_exit: bool,
    pub frame_capture_indication: bool,
    pub su_line_capture_indication: bool,
    pub irq_hpd_on_crc_error: bool,
    pub deep_sleep_on_exit: bool,
    pub setup_time_index: u8,
}

impl PsrCaps {
    /// Setup-Time index → microseconds (table 3-22).
    pub const fn setup_time_us(index: u8) -> u16 {
        match index {
            0 => 330,
            1 => 275,
            2 => 220,
            3 => 165,
            4 => 110,
            5 => 55,
            _ => 0,
        }
    }

    pub const fn decode(b: u8) -> Self {
        Self {
            link_training_required_on_exit: (b & PSR_CAP_LINK_TRAINING_REQUIRED_ON_EXIT) != 0,
            frame_capture_indication: (b & PSR_CAP_FRAME_CAPTURE_INDICATION) != 0,
            su_line_capture_indication: (b & PSR_CAP_SU_LINE_CAPTURE_INDICATION) != 0,
            irq_hpd_on_crc_error: (b & PSR_CAP_IRQ_HPD_WITH_CRC_ERROR) != 0,
            deep_sleep_on_exit: (b & PSR_CAP_DEEP_SLEEP_ON_EXIT) != 0,
            setup_time_index: (b & PSR_CAP_SETUP_TIME_MASK) >> PSR_CAP_SETUP_TIME_SHIFT,
        }
    }

    /// Look up the configured Setup-Time in µs.
    pub const fn setup_time(self) -> u16 {
        Self::setup_time_us(self.setup_time_index)
    }
}

// ── Adaptive-Sync (§3.5.1.5) ───────────────────────────────────────

/// DPCD bit at 0x05 (DOWN_STREAM_PORT_PRESENT) bit 6 — sink supports
/// MSA-VSYNC-IGNORE for variable-refresh-rate / FreeSync.
pub const DPCD_DOWN_STREAM_PORT_PRESENT_MSA_TIMING_PAR_IGNORED: u8 = 1 << 6;

/// DPCD address for Adaptive-Sync version (DP 2.0 §3.5.1.5
/// extension, kept here as a sink-cap probe).
pub const DPCD_ADAPTIVE_SYNC_VERSION: u32 = 0x07000;
pub const DPCD_ADAPTIVE_SYNC_CAPABILITY: u32 = 0x07001;

pub const ADAPTIVE_SYNC_CAP_SUPPORT: u8 = 1 << 0;
pub const ADAPTIVE_SYNC_CAP_SDP_FRAME_LOCK_LIMIT: u8 = 1 << 1;
