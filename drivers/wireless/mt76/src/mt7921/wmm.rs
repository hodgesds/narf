//! Station WMM negotiation and CONNAC2 EDCA command payload.
//! Wire definitions: IEEE WMM Parameter/Information elements; Linux
//! ecd997b0189a mlme.c::_ieee80211_sta_wmm_params and mt7921_mcu_set_tx.
use super::Error;

pub(crate) use narf_wireless::wmm::INFORMATION;

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
    parameter_set_count: u8,
}

impl Parameters {
    /// Inspect the complete IE stream; an Information IE alone offers no
    /// contention parameters and cannot authorize this QoS station profile.
    pub(crate) fn parse(ies: &[u8]) -> Result<Option<Self>, Error> {
        let Some(parameters) =
            narf_wireless::wmm::Parameters::parse(ies).map_err(|_| Error::Protocol)?
        else {
            return Ok(None);
        };
        // Native mt7921 policy is intentionally stricter than wire parsing:
        // no zero contention window and no TSPEC/admission-controlled BE.
        if parameters.ac.iter().any(|ac| ac.cw_min() == 0) || parameters.ac[0].admission_control {
            return Err(Error::Protocol);
        }
        Ok(Some(Self {
            parameter_set_count: parameters.parameter_set_count,
            ac: parameters.ac.map(|ac| Ac {
                cw_min: ac.cw_min(),
                cw_max: ac.cw_max(),
                txop: ac.txop,
                aifs: u16::from(ac.aifsn),
            }),
        }))
    }

    /// The AP's four-bit change counter wraps; it is not a monotonic serial
    /// number. A changed counter earns a fresh native command even when the
    /// host's conservative BE clamp yields the same command bytes.
    pub(crate) fn same_set(self, other: Self) -> bool {
        self.parameter_set_count == other.parameter_set_count
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
        Self { ac, ..self }.encode(true)
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
        parameter_set_count: 0,
        ac: [Ac {
            cw_min: 31,
            cw_max: 1023,
            txop: 0,
            aifs: 3,
        }; 4],
    }
    .encode(false)
}
