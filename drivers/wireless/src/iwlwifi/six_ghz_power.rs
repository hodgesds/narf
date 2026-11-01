//! AP_TX_POWER_CONSTRAINTS_CMD v1, Linux mld/power.c and fw/api/power.h.
//! IEEE TPE parsing reuses the existing family-independent wire parser.
use crate::ath11k::mac_frame::{TxPowerEnvelope, TxPowerInterpretation};
use narf_wireless::reg::PowerType6Ghz;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Constraints([u8; 28]);
impl Constraints {
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
}
