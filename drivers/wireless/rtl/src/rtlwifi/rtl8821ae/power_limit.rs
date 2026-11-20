// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8821AE regulatory TX power limits.
//!
//! Rows are the mechanically generated `RTL8821AE_TXPWR_LMT` strings from
//! Linux `rtl8821ae/table.c`, parsed at build time into typed rows. Linux
//! `_rtl8821ae_phy_set_txpower_limit` stores each row into
//! `txpwr_limit_{2_4g,5g}[regulation][bw][section][channel][path]`; the value
//! 63 is Linux `MAX_POWER_INDEX` ("no limit programmed") and is never treated
//! as an admitted limit here. Conversion of the limit to a power index
//! (`_rtl8812ae_phy_convert_txpower_limit_to_power_index`) additionally needs
//! the per-board power-by-rate base, so a lookup alone does not admit a
//! channel: the signed board envelope must also cover it.

/// Linux `TXPWR_LMT_{FCC,ETSI,MKK}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Regulation {
    Fcc,
    Etsi,
    Mkk,
}

/// `"2.4G"` / `"5G"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Band {
    B2g,
    B5g,
}

/// `"20M"` .. `"160M"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bandwidth {
    Bw20,
    Bw40,
    Bw80,
    Bw160,
}

/// Rate section column (`"CCK"`, `"OFDM"`, `"HT"`, `"VHT"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Cck,
    Ofdm,
    Ht,
    Vht,
}

/// Linux `MAX_POWER_INDEX`: the table's "unspecified" value.
pub const UNSPECIFIED: u8 = 63;

/// One `RTL8821AE_TXPWR_LMT` row (seven strings in Linux).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row {
    pub regulation: Regulation,
    pub band: Band,
    pub bandwidth: Bandwidth,
    pub section: Section,
    /// RF TX path count column (`"1T"` / `"2T"`).
    pub ntx: u8,
    pub channel: u8,
    /// Limit in 0.5 dBm units, or [`UNSPECIFIED`].
    pub limit: u8,
}

impl Row {
    pub const fn new(
        regulation: Regulation,
        band: Band,
        bandwidth: Bandwidth,
        section: Section,
        ntx: u8,
        channel: u8,
        limit: u8,
    ) -> Self {
        Self {
            regulation,
            band,
            bandwidth,
            section,
            ntx,
            channel,
            limit,
        }
    }
}

/// Exact-row limit for one selector. `None` when Linux carries no row or the
/// row is [`UNSPECIFIED`]; callers must then refuse the channel rather than
/// substitute a default.
pub fn limit(
    regulation: Regulation,
    band: Band,
    bandwidth: Bandwidth,
    section: Section,
    ntx: u8,
    channel: u8,
) -> Option<u8> {
    super::tables::TXPWR_LMT
        .iter()
        .find(|row| {
            row.regulation == regulation
                && row.band == band
                && row.bandwidth == bandwidth
                && row.section == section
                && row.ntx == ntx
                && row.channel == channel
        })
        .map(|row| row.limit)
        .filter(|&limit| limit != UNSPECIFIED)
}
