//! Transmit Power Envelope element parsing (`ieee80211_parse_tpe` /
//! `ieee80211_valid_tpe_element`).
//!
//! Shared across Wi-Fi drivers: the 6 GHz regulatory TX-power limits an AP
//! advertises in its beacon are the same wire format whatever silicon consumes
//! them. Lived in `ath11k::mac_frame` originally; promoted here so iwlwifi (and
//! any other driver) can parse a TPE element without depending on an Atheros
//! driver crate.

use alloc::vec::Vec;

/// `IEEE80211_TX_PWR_ENV_INFO_*`.
pub mod tpe {
    /// Bits 0..=2: one fewer EIRP power entries, or the PSD subchannel
    /// encoding described by 802.11ax §9.4.2.161.
    pub const COUNT_MASK: u8 = 0x07;
    /// Bits 3..=5: [`super::TxPowerInterpretation`].
    pub const INTERPRET_MASK: u8 = 0x38;
    /// Bits 6..=7: default or subordinate 6 GHz client category.
    pub const CATEGORY_MASK: u8 = 0xc0;
    /// Low four bits of the PSD extension count byte.
    pub const EXT_COUNT_MASK: u8 = 0x0f;
    pub const CATEGORY_DEFAULT: u8 = 0;
    pub const CATEGORY_SUBORDINATE: u8 = 1;
    /// `IEEE80211_TPE_MAX_TX_PWR_NO_CONSTRAINT` and
    /// `IEEE80211_TPE_PSD_NO_LIMIT`, represented in half-dBm units.
    pub const NO_LIMIT: i8 = 127;
}

/// `enum ieee80211_tx_power_intrpt_type`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxPowerInterpretation {
    LocalEirp,
    LocalPsd,
    RegulatoryClientEirp,
    RegulatoryClientPsd,
}

impl TxPowerInterpretation {
    pub const fn is_psd(self) -> bool {
        matches!(self, Self::LocalPsd | Self::RegulatoryClientPsd)
    }

    pub const fn is_regulatory_client(self) -> bool {
        matches!(self, Self::RegulatoryClientEirp | Self::RegulatoryClientPsd)
    }
}

/// One validated `ieee80211_tx_pwr_env`. `powers` holds signed half-dBm
/// values, as transmitted; the WCN6855 TPC command uses integral dBm and
/// converts them when it consumes this structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxPowerEnvelope {
    pub category: u8,
    pub interpretation: TxPowerInterpretation,
    /// Valid entries in [`Self::powers`].  PSD entries can have default
    /// `NO_LIMIT` values after mac80211-style channel-width rearrangement,
    /// so this count deliberately remains distinct from the vector length.
    pub count: usize,
    /// The PSD element's first N group length. `Some(0)` represents the
    /// all-subchannels default form; `None` means this is an EIRP envelope.
    pub psd_n: Option<usize>,
    pub powers: Vec<i8>,
}

impl TxPowerEnvelope {
    /// `ieee80211_valid_tpe_element` plus `ieee80211_parse_tpe`.
    ///
    /// This preserves every valid value (including the optional PSD K
    /// extension) instead of trusting the advertised count alone. The
    /// station's WCN6855 path subsequently limits the result to its eight
    /// 160 MHz power entries.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let (&info, values) = data.split_first()?;
        let count = info & tpe::COUNT_MASK;
        let category = (info & tpe::CATEGORY_MASK) >> 6;
        if !matches!(category, tpe::CATEGORY_DEFAULT | tpe::CATEGORY_SUBORDINATE) {
            return None;
        }
        let interpretation = match (info & tpe::INTERPRET_MASK) >> 3 {
            0 => TxPowerInterpretation::LocalEirp,
            1 => TxPowerInterpretation::LocalPsd,
            2 => TxPowerInterpretation::RegulatoryClientEirp,
            3 => TxPowerInterpretation::RegulatoryClientPsd,
            _ => return None,
        };
        let mut powers = Vec::new();
        let mut psd_n = None;
        if interpretation.is_psd() {
            if count > 4 {
                return None;
            }
            let n = if count == 0 { 1 } else { 1usize << (count - 1) };
            if values.len() < n {
                return None;
            }
            // The optional K-count field is present after N for both the
            // count-zero and nonzero PSD forms. Validate it before the
            // count-zero expansion, exactly as `ieee80211_valid_tpe_element`
            // does.
            if values.len() > n {
                let k = (values[n] & tpe::EXT_COUNT_MASK) as usize;
                if values.len() < n + 1 + k {
                    return None;
                }
            }
            if count == 0 {
                // A count of zero is one value applying to every 20 MHz
                // subchannel (`ieee80211_parse_tpe`).
                powers.resize(16, values[0] as i8);
                psd_n = Some(0);
            } else {
                powers.extend(values[..n].iter().map(|&v| v as i8));
                psd_n = Some(n);
                if values.len() > n {
                    let k = (values[n] & tpe::EXT_COUNT_MASK) as usize;
                    powers.extend(values[n + 1..n + 1 + k].iter().map(|&v| v as i8));
                }
            }
        } else {
            if count > 3 || values.len() < count as usize + 1 {
                return None;
            }
            let count = count as usize + 1;
            powers.extend(values[..count].iter().map(|&v| v as i8));
            // A fifth value is the optional 320 MHz limit. Preserve it even
            // though WCN6855 itself stops at contiguous 160 MHz.
            if count == 4 && values.len() > count {
                powers.push(values[4] as i8);
            }
        }
        Some(TxPowerEnvelope {
            category,
            interpretation,
            count: powers.len(),
            psd_n,
            powers,
        })
    }
}
