//! AP_TX_POWER_CONSTRAINTS_CMD v1, Linux mld/power.c and fw/api/power.h.
//! IEEE TPE parsing reuses the existing family-independent wire parser.
use crate::ath11k::mac_frame::TxPowerEnvelope;
#[cfg(any(test, feature = "kernel-test"))]
use crate::ath11k::mac_frame::TxPowerInterpretation;
use narf_wireless::reg::PowerType6Ghz;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Constraints([u8; 28]);
impl Constraints {
    #[cfg(any(test, feature = "kernel-test"))]
    pub fn parse(power_type: PowerType6Ghz, mut ies: &[u8]) -> Result<Self, &'static str> {
        let mut eirp = [127i8; 5];
        let mut psd = [127i8; 16];
        while !ies.is_empty() {
            let len = usize::from(*ies.get(1).ok_or("truncated6GHz power IE")?);
            let body = ies.get(2..2 + len).ok_or("truncated6GHz power IE")?;
            if ies[0] == 195 {
                let tpe = TxPowerEnvelope::parse(body).ok_or("invalid6GHz AP TPE")?;
                // Intel/mac80211 use the default client category only.
                if tpe.category == 0 {
                    match tpe.interpretation {
                        TxPowerInterpretation::LocalEirp
                        | TxPowerInterpretation::RegulatoryClientEirp => {
                            for (limit, &value) in eirp.iter_mut().zip(&tpe.powers) {
                                *limit = (*limit).min(value);
                            }
                        }
                        TxPowerInterpretation::LocalPsd
                        | TxPowerInterpretation::RegulatoryClientPsd => {
                            for (limit, &value) in psd.iter_mut().zip(&tpe.powers) {
                                *limit = (*limit).min(value);
                            }
                        }
                    }
                }
            }
            ies = &ies[2 + len..];
        }
        // This owner admits an AP20/STA20 span, so slot0 is its only
        // occupied20MHz subchannel. -128 is prohibition, never a ceiling.
        if psd[0] == i8::MIN {
            return Err("6GHz AP TPE prohibits the occupied subchannel");
        }
        let mut body = [0; 28];
        body[2..4].copy_from_slice(
            &match power_type {
                PowerType6Ghz::Lpi => 0u16,
                PowerType6Ghz::Sp => 1,
                PowerType6Ghz::Vlp => 2,
            }
            .to_le_bytes(),
        );
        for (slot, value) in body[4..9].iter_mut().zip(eirp) {
            *slot = value as u8;
        }
        for (slot, value) in body[9..25].iter_mut().zip(psd) {
            *slot = value as u8;
        }
        Ok(Self(body))
    }
    pub fn command(&self) -> &[u8; 28] {
        &self.0
    }
    /// Linux ieee80211_rearrange_tpe_psd: N belongs to the primary HE
    /// block, K covers the remaining AP subchannels. Native firmware needs
    /// monotonically increasing used20MHz frequencies, not N/K IE order.
    pub fn parse_span(
        power_type: PowerType6Ghz,
        mut ies: &[u8],
        ap: super::six_ghz_span::Span,
        used: super::six_ghz_span::Span,
    ) -> Result<Self, &'static str> {
        if !ap.contains(used) {
            return Err("6GHz TPE used span outside AP channel");
        }
        let mut eirp = [127i8; 5];
        let mut psd = [127i8; 16];
        while !ies.is_empty() {
            let len = usize::from(*ies.get(1).ok_or("truncated6GHz wide power IE")?);
            let body = ies.get(2..2 + len).ok_or("truncated6GHz wide power IE")?;
            if ies[0] == 195 {
                let tpe = TxPowerEnvelope::parse(body).ok_or("invalid6GHz wide TPE")?;
                if tpe.category == 0 {
                    if tpe.interpretation.is_psd() {
                        let n = tpe.psd_n.unwrap_or(0);
                        let have = 1usize << ap.width;
                        let offset = if n == 0 || n >= have {
                            0
                        } else {
                            let block = 4 * n as u16;
                            let low = (u16::from(ap.primary.number) - 1) / block * block + 1;
                            usize::from(low.saturating_sub(ap.low()) / 4)
                        };
                        let used_offset = usize::from((used.low() - ap.low()) / 4);
                        for (i, limit) in psd.iter_mut().enumerate().take(1usize << used.width) {
                            let full = used_offset + i;
                            let source = if n == 0 {
                                full
                            } else if full < offset {
                                full + n
                            } else if full < offset + n {
                                full - offset
                            } else {
                                full
                            };
                            *limit = (*limit).min(tpe.powers.get(source).copied().unwrap_or(127));
                        }
                    } else {
                        for (limit, &value) in eirp.iter_mut().zip(&tpe.powers) {
                            *limit = (*limit).min(value);
                        }
                    }
                }
            }
            ies = &ies[2 + len..];
        }
        if psd[..1usize << used.width].contains(&i8::MIN) {
            return Err("6GHz TPE prohibits an occupied wide subchannel");
        }
        let mut body = [0; 28];
        body[2..4].copy_from_slice(
            &(match power_type {
                PowerType6Ghz::Lpi => 0u16,
                PowerType6Ghz::Sp => 1,
                PowerType6Ghz::Vlp => 2,
            })
            .to_le_bytes(),
        );
        for (slot, value) in body[4..9].iter_mut().zip(eirp) {
            *slot = value as u8;
        }
        for (slot, value) in body[9..25].iter_mut().zip(psd) {
            *slot = value as u8;
        }
        Ok(Self(body))
    }
}
