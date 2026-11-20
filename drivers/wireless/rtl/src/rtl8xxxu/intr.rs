//! RTL8XXXU interrupt-IN status decoder.
//!
//! Realtek USB chips push a 56-byte status block to the host on the
//! interrupt-IN endpoint at a fixed interval (`bInterval` from the
//! endpoint descriptor; typically 1 ms). The block contains:
//!
//! ```text
//! u32  c2h_evt_ints[2]      — chip-to-host event interrupts.
//! u32  txok_counter         — frames acked since last urb.
//! u32  txdrop_counter       — frames dropped since last urb.
//! u32  rxavl_counter        — frames available in RX FIFO.
//! ...
//! ```
//!
//! The first 32 bits carry the bitmap of pending C2H events; later
//! 32-bit words carry per-counter sums. We expose just enough to drive
//! the kernel-side flow-control logic.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/net/wireless/realtek/rtl8xxxu/core.c::rtl8xxxu_int_complete`
//!   (~L7720) — interrupt URB completion handler.
//! - `rtl8xxxu.h::USB_INTR_CONTENT_LENGTH = 56`.

#![allow(dead_code)]

use super::regs::USB_INTR_CONTENT_LEN;

/// Decoded interrupt-IN status frame.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IntrStatus {
    /// Bitmap of pending C2H events (low word).
    pub c2h_events_lo: u32,
    /// Bitmap of pending C2H events (high word).
    pub c2h_events_hi: u32,
    /// Per-poll TX_OK count (frames acked).
    pub tx_ok: u32,
    /// Per-poll TX_DROP count.
    pub tx_drop: u32,
    /// Per-poll RX_AVL count.
    pub rx_avl: u32,
    /// Per-poll RX overflow count.
    pub rx_ovf: u32,
}

impl IntrStatus {
    /// Word offset of the TX_OK counter in the 56-byte payload.
    /// Source: `rtl8xxxu_int_complete` indexed access.
    pub const TXOK_WORD: usize = 2;
    pub const TXDROP_WORD: usize = 3;
    pub const RXAVL_WORD: usize = 4;
    pub const RXOVF_WORD: usize = 5;

    /// Parse a 56-byte interrupt URB payload.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < USB_INTR_CONTENT_LEN {
            return None;
        }
        let w = |idx: usize| -> u32 {
            u32::from_le_bytes([
                bytes[idx * 4],
                bytes[idx * 4 + 1],
                bytes[idx * 4 + 2],
                bytes[idx * 4 + 3],
            ])
        };
        Some(Self {
            c2h_events_lo: w(0),
            c2h_events_hi: w(1),
            tx_ok: w(Self::TXOK_WORD),
            tx_drop: w(Self::TXDROP_WORD),
            rx_avl: w(Self::RXAVL_WORD),
            rx_ovf: w(Self::RXOVF_WORD),
        })
    }

    /// `true` if any C2H event bit is set.
    pub fn has_c2h_event(&self) -> bool {
        self.c2h_events_lo != 0 || self.c2h_events_hi != 0
    }
}

/// Bit positions in the C2H event word — `rtl8xxxu_c2h_event` defs.
pub mod c2h {
    /// BT info update (8723BU coexistence).
    pub const BT_INFO: u32 = 1 << 0;
    /// MAC link status changed.
    pub const LINK_STATUS: u32 = 1 << 1;
    /// FW error trap.
    pub const FW_ERROR: u32 = 1 << 2;
    /// BT MP report.
    pub const BT_MP: u32 = 1 << 3;
    /// TX report fired.
    pub const TX_REPORT: u32 = 1 << 4;
}
