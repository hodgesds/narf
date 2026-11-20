// SPDX-License-Identifier: GPL-2.0-only
// Copyright(c) 2009-2014 Realtek Corporation.
//! `rtl8723be_dm_check_edca_turbo`, `rtl8723_dm_init_edca_turbo`, and
//! `base.c::rtl_recognize_peer` from the rtlwifi source used by this port.
//! Byte totals and Linux's function-static snapshots are per owner here.
use super::super::h2c::WirelessMode;
use crate::rtlwifi::{firmware_transport::Io, prepare::Error};

pub(crate) const REG_EDCA_BE_PARAM: u16 = 0x508;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Vendor {
    #[default]
    Unknown,
    Atheros,
    Broadcom,
    Ralink,
    Cisco,
    Marvell,
}

#[derive(Debug, Default)]
pub(crate) struct Edca {
    pub(crate) tx_bytes: u64,
    pub(crate) rx_bytes: u64,
    last_tx: u64,
    last_rx: u64,
    pub(crate) turbo: bool,
    pub(crate) non_be: bool,
    pub(crate) downlink: bool,
    pub(crate) disable_framebursting: bool,
    pub(crate) vendor: Vendor,
    linked_periods: u8,
}

impl Edca {
    /// `rtl8723_dm_init_edca_turbo`: reset flags, retaining cumulative
    /// byte counts and the previous watchdog's snapshots.
    pub(crate) fn reset(&mut self) {
        self.turbo = false;
        self.non_be = false;
        self.downlink = false;
    }

    pub(crate) fn clear_peer(&mut self) {
        self.vendor = Vendor::Unknown;
        self.linked_periods = 0;
        self.reset();
    }

    /// `rtl_watchdog_wq_callback` advances this before the chip DM steps,
    /// including periods when firmware LPS suppresses those steps.
    pub(crate) fn linked_tick(&mut self, linked: bool) {
        if linked {
            self.linked_periods = self.linked_periods.saturating_add(1).min(3);
        } else {
            self.vendor = Vendor::Unknown;
            self.linked_periods = 0;
        }
    }

    /// PCI stats include every unicast frame, not only DATA. Native RX
    /// omits the FCS; Linux's RX skb still includes its four bytes.
    pub(crate) fn transmitted(&mut self, frame: &[u8]) {
        if frame.get(4).is_some_and(|byte| byte & 1 == 0) {
            self.tx_bytes = self.tx_bytes.wrapping_add(frame.len() as u64);
        }
    }

    pub(crate) fn received(&mut self, frame: &[u8], bssid: [u8; 6], linked: bool) {
        if frame.get(4).is_some_and(|byte| byte & 1 == 0) {
            self.rx_bytes = self.rx_bytes.wrapping_add(frame.len() as u64 + 4);
        }
        if linked && self.linked_periods <= 2 {
            if let Some(vendor) = recognize(frame, bssid) {
                self.vendor = vendor;
            }
        }
    }

    /// Source order: RA refresh, EDCA, ATC. Mode B skips the write and
    /// retains the turbo/direction flags, but still advances snapshots.
    pub(crate) fn watchdog(&mut self, io: &impl Io, mode: WirelessMode) -> Result<(), Error> {
        let tx = self.tx_bytes.wrapping_sub(self.last_tx);
        let rx = self.rx_bytes.wrapping_sub(self.last_rx);
        if mode != WirelessMode::B {
            if !self.non_be && !self.disable_framebursting {
                let downlink = if matches!(self.vendor, Vendor::Ralink | Vendor::Atheros) {
                    tx <= rx.wrapping_mul(4)
                } else {
                    rx > tx.wrapping_mul(4)
                };
                let value = if self.vendor == Vendor::Cisco && mode == WirelessMode::N24 {
                    if downlink {
                        0x5e_a630
                    } else {
                        0x3e_a430
                    }
                } else {
                    0x6e_a42b
                };
                // Linux writes on every eligible pass, including an
                // unchanged direction. Each Io write retains authority.
                io.write32(REG_EDCA_BE_PARAM, value)?;
                self.downlink = downlink;
                self.turbo = true;
            } else {
                if self.turbo {
                    // HW_VAR_AC_PARAM(AC0_BE) -> set_qos: flag reset only,
                    // no BE register write on this chip.
                    self.reset();
                }
                self.turbo = false;
            }
        }
        self.non_be = false;
        self.last_tx = self.tx_bytes;
        self.last_rx = self.rx_bytes;
        Ok(())
    }
}

/// Only a complete, associated-BSSID beacon is a vendor observation.
/// Bounds are checked before reading each IE's OUI (Linux checks after).
fn recognize(frame: &[u8], bssid: [u8; 6]) -> Option<Vendor> {
    if frame.len() <= 40 || frame[0] & 0xfc != 0x80 || frame[16..22] != bssid {
        return None;
    }
    let mut vendor = Vendor::Unknown;
    let mut ies = &frame[36..];
    while ies.len() >= 2 {
        let length = usize::from(ies[1]);
        let Some(data) = ies.get(2..2 + length) else {
            break;
        };
        if ies[0] == 221 {
            vendor = match data.get(..3) {
                Some([0, 3, 0x7f] | [0, 0x13, 0x74]) => Vendor::Atheros,
                Some([0, 0x10, 0x18] | [0, 0x0a, 0xf7] | [0, 5, 0xb5]) => Vendor::Broadcom,
                Some([0, 0x0c, 0x43]) => Vendor::Ralink,
                Some([0, 0x40, 0x96]) => Vendor::Cisco,
                Some([0, 0x50, 0x43]) => Vendor::Marvell,
                _ => Vendor::Unknown,
            };
            if vendor != Vendor::Unknown {
                break;
            }
        }
        ies = &ies[2 + length..];
    }
    let prefix = [bssid[0], bssid[1], bssid[2]];
    // Keep the upstream precedence: e.g. an Atheros IE wins over a
    // Cisco address prefix, while an Atheros prefix wins over a Cisco IE.
    Some(
        if vendor == Vendor::Atheros
            || matches!(
                prefix,
                [0, 0x1c, 0xf0]
                    | [0, 0x21, 0x91]
                    | [0, 0x24, 1]
                    | [0, 0x15, 0xe9]
                    | [0, 0x17, 0x9a]
                    | [0, 0x18, 0xe7]
            )
        {
            Vendor::Atheros
        } else if vendor == Vendor::Ralink
            || matches!(
                prefix,
                [0, 0x17, 0x3f]
                    | [0, 0x1c, 0xdf]
                    | [0, 0x90, 0xcc]
                    | [0, 0x0e, 0x2e]
                    | [0, 0x18, 2]
            )
        {
            Vendor::Ralink
        } else if vendor == Vendor::Cisco || prefix == [0, 0x17, 0x94] {
            Vendor::Cisco
        } else if vendor == Vendor::Broadcom
            || matches!(prefix, [0, 0x14, 0xbf] | [0, 0x1a, 0x70] | [0, 0x1d, 0x7e])
        {
            Vendor::Broadcom
        } else if vendor == Vendor::Marvell || prefix == [0, 0x14, 0xa4] {
            Vendor::Marvell
        } else {
            vendor
        },
    )
}
