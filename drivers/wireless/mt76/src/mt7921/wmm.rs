//! Station WMM negotiation and CONNAC2 EDCA command payload.
//! Wire definitions: IEEE WMM Parameter/Information elements; Linux
//! ecd997b0189a mlme.c::_ieee80211_sta_wmm_params and mt7921_mcu_set_tx.
use super::Error;

pub(crate) const INFORMATION: [u8; 9] = [221, 7, 0, 0x50, 0xf2, 2, 0, 1, 0];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ac {
    cw_min: u16,
    cw_max: u16,
    txop: u16,
    aifs: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Parameters {
    // Canonical WMM ACI order: BE, BK, VI, VO. Linux's LMAC mapping and
    // set_tx's to_aci permutation compose to this exact command order.
    ac: [Ac; 4],
}

impl Parameters {
    /// Inspect the complete IE stream; an Information IE alone offers no
    /// contention parameters and cannot authorize this QoS station profile.
    pub(crate) fn parse(mut ies: &[u8]) -> Result<Option<Self>, Error> {
        let mut found = false;
        let mut result = None;
        while !ies.is_empty() {
            let head = ies.get(..2).ok_or(Error::InvalidBss)?;
            let end = 2 + usize::from(head[1]);
            let body = ies.get(2..end).ok_or(Error::InvalidBss)?;
            if head[0] == 221 && body.starts_with(&[0, 0x50, 0xf2, 2]) {
                if found {
                    return Err(Error::Protocol);
                }
                found = true;
                if body.get(5) != Some(&1) {
                    return Err(Error::Protocol);
                }
                match body.get(4) {
                    Some(0) if body.len() == 7 => {}
                    Some(1) if body.len() == 24 && body[6] & 0x70 == 0 && body[7] == 0 => {
                        let empty = Ac {
                            cw_min: 0,
                            cw_max: 0,
                            txop: 0,
                            aifs: 0,
                        };
                        let mut ac = [empty; 4];
                        let mut seen = 0u8;
                        for record in body[8..].chunks_exact(4) {
                            let index = usize::from((record[0] >> 5) & 3);
                            let min = record[1] & 15;
                            let max = record[1] >> 4;
                            if record[0] & 0x80 != 0
                                || record[0] & 15 < 2
                                || seen & (1 << index) != 0
                                || min == 0
                                || min > max
                                // No TSPEC/admission-control owner exists. Only
                                // BE/TID 0 is selected by this station profile.
                                || index == 0 && record[0] & 0x10 != 0
                            {
                                return Err(Error::Protocol);
                            }
                            seen |= 1 << index;
                            ac[index] = Ac {
                                cw_min: ((1u32 << min) - 1) as u16,
                                cw_max: ((1u32 << max) - 1) as u16,
                                txop: u16::from_le_bytes([record[2], record[3]]),
                                aifs: u16::from(record[0] & 15),
                            };
                        }
                        if seen != 15 {
                            return Err(Error::Protocol);
                        }
                        result = Some(Self { ac });
                    }
                    _ => return Err(Error::Protocol),
                }
            }
            ies = &ies[end..];
        }
        Ok(result)
    }

    /// Native CE SET_EDCA_PARMS (0x1d), one BSS and WMM set zero.
    /// The host has no country-specific WMM rule interface yet. Its sole
    /// selected AC therefore contends at least as conservatively as legacy
    /// DCF, with no TXOP burst. Unused ACs never receive a TX descriptor.
    pub(crate) fn edca(self) -> [u8; 44] {
        let mut ac = self.ac;
        ac[0].cw_min = ac[0].cw_min.max(31);
        ac[0].cw_max = ac[0].cw_max.max(1023);
        ac[0].aifs = ac[0].aifs.max(3);
        ac[0].txop = 0;
        Self { ac }.encode(true)
    }

    fn encode(self, qos: bool) -> [u8; 44] {
        let mut out = [0; 44];
        for (index, params) in self.ac.iter().enumerate() {
            let row = &mut out[index * 10..index * 10 + 10];
            for (field, value) in [params.cw_min, params.cw_max, params.txop, params.aifs]
                .iter()
                .enumerate()
            {
                row[field * 2..field * 2 + 2].copy_from_slice(&value.to_le_bytes());
            }
        }
        out[41] = u8::from(qos); // bss_idx=0, wmm_idx=0, padding=0.
        out
    }
}

pub(crate) fn legacy_edca() -> [u8; 44] {
    Parameters {
        ac: [Ac {
            cw_min: 31,
            cw_max: 1023,
            txop: 0,
            aifs: 3,
        }; 4],
    }
    .encode(false)
}
