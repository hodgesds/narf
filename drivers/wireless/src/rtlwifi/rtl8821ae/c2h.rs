// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE firmware-to-host (C2H) packets.
//!
//! An RX descriptor with `rpt_sel` set carries a C2H packet instead of an
//! 802.11 frame (`rtl8821ae_rx_query_desc` → `C2H_PACKET`; `pci.c`
//! `rtl_c2hcmd_enqueue`). `base.c::rtl_c2h_content_parsing` dispatches on
//! byte 0 with the command body starting at `C2H_DATA_OFFSET` (2).
//! RTL8821AE's `spec_ver` lacks `RTL_SPEC_EXT_C2H`, so TX reports use the
//! V1 layout (`wifi.h::GET_TX_REPORT_*_V1`).

/// `enum rtl_c2h_evt_v2` ids used by the core dispatcher (`wifi.h`).
pub const C2H_DBG: u8 = 0;
pub const C2H_TXBF: u8 = 2;
pub const C2H_TX_REPORT: u8 = 3;
pub const C2H_BT_INFO: u8 = 9;
pub const C2H_BT_MP: u8 = 11;
pub const C2H_RA_RPT: u8 = 12;
/// `C2H_DATA_OFFSET`.
pub const C2H_DATA_OFFSET: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event<'a> {
    /// `rtl_tx_report_handler` (V1): `st == 0` means acknowledged.
    TxReport {
        sn: u16,
        st: u8,
        retry: u8,
    },
    /// `rtl8821ae_c2h_ra_report_handler`: firmware RA picked `DESC_RATE*`.
    RaReport {
        hw_rate: u8,
        mgn_rate: u8,
    },
    Debug(&'a [u8]),
    TxBf(&'a [u8]),
    BtInfo(&'a [u8]),
    BtMp(&'a [u8]),
    Unknown {
        id: u8,
        body: &'a [u8],
    },
}

impl Event<'_> {
    pub fn acked(&self) -> Option<bool> {
        match *self {
            Self::TxReport { st, .. } => Some(st == 0),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Shorter than the id/sequence header or the fixed event body.
    Truncated,
}

/// Parse one C2H packet (the RX buffer from `RxStatus::payload_offset`,
/// `RxStatus::length` bytes).
pub fn parse(packet: &[u8]) -> Result<Event<'_>, Error> {
    if packet.len() < C2H_DATA_OFFSET {
        return Err(Error::Truncated);
    }
    let id = packet[0];
    let body = &packet[C2H_DATA_OFFSET..];
    Ok(match id {
        C2H_TX_REPORT => {
            if body.len() < 7 {
                return Err(Error::Truncated);
            }
            Event::TxReport {
                sn: u16::from(body[6]),
                st: body[0] & 0xc0,
                retry: body[2] & 0x3f,
            }
        }
        C2H_RA_RPT => {
            let &first = body.first().ok_or(Error::Truncated)?;
            let hw_rate = first & 0x3f;
            Event::RaReport {
                hw_rate,
                mgn_rate: hw_rate_to_mrate(hw_rate),
            }
        }
        C2H_DBG => Event::Debug(body),
        C2H_TXBF => Event::TxBf(body),
        C2H_BT_INFO => Event::BtInfo(body),
        C2H_BT_MP => Event::BtMp(body),
        _ => Event::Unknown { id, body },
    })
}

/// `rtl8821ae/dm.c::rtl8821ae_hw_rate_to_mrate` (`DESC_RATE*` → `MGN_*`);
/// unlisted rates (MCS15 SGI, MCS32) fall back to `MGN_1M` as in Linux.
pub const fn hw_rate_to_mrate(rate: u8) -> u8 {
    const LEGACY: [u8; 12] = [
        0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
    ];
    match rate {
        0x00..=0x0b => LEGACY[rate as usize],
        0x0c..=0x1b => 0x80 + (rate - 0x0c),
        0x2c..=0x3f => 0x90 + (rate - 0x2c),
        _ => 0x02,
    }
}

/// Retained TX-report sequence state (`struct rtl_tx_report`): the last
/// requested and last reported SW sequence numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxReportState {
    counter: u16,
    pub last_sent_sn: u16,
    pub last_recv_sn: u16,
}

impl TxReportState {
    /// `rtl_get_tx_report_sn`: `(++sn & 0x3f) << 2`. SW_DEFINE[11:8] and
    /// [1:0] stay zero (reserved for driver padding and firmware).
    pub fn next_sn(&mut self) -> u16 {
        self.counter = self.counter.wrapping_add(1);
        let sn = (self.counter & 0x3f) << 2;
        self.last_sent_sn = sn;
        sn
    }
    /// `rtl_tx_report_handler` bookkeeping.
    pub fn record(&mut self, sn: u16) {
        self.last_recv_sn = sn;
    }
    /// `rtl_check_tx_report_acked` without the 3 s timeout, which the
    /// caller's deadline owns.
    pub fn all_acked(&self) -> bool {
        self.last_sent_sn == self.last_recv_sn
    }
}
