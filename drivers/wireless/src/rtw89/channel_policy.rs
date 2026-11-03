// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Optional signed per-channel full-program record (N52C) for one noninitial
//! RTL8852B 20MHz primary (2.4GHz 2..=13 or a typed 5GHz primary). A child
//! of radio_policy.
//!
//! The base N52B v2 record keeps its exact channel1 meaning and is never
//! reinterpreted for another primary. Each noninitial primary has its own
//! [`Board`] identity composed exactly like the channel1 one (same factory,
//! firmware PHY_CAP, recipe list and lifecycle) but over the plan built by
//! `radio_power::Plan::from_assets_for_channel`, i.e. the Linux
//! rtw8852b_table.c WW0 limit/RU rows and rtw8852b_common.c SCO/FIR/TSSI
//! groups of that primary, then extended by the same signed operating
//! programs (WMM/QoS/RA/HT/HE/A-MPDU) as the base. The record binds that
//! identity to the exact base record/signer and every installed optional
//! companion, so it measures the complete joint program on that channel.
//! Its peaks/antenna/ceiling are checked against the current host rule over
//! the channel's whole occupied span. Channel14 (CCK-only) has no record.
use super::super::operating_channel::Profile;
use super::*;

pub(super) struct Channel {
    authority: Cap<FirmwareBlob, Read>,
    profile: Profile,
    board: Board,
    binding: [u8; 32],
    digest: [u8; 32],
    antenna_qdb: i16,
    ceiling_qdbm: i16,
    peaks_qdbm: [i16; 3],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub name: alloc::string::String,
    pub binding: [u8; 32],
}
/// Noninitial primaries that may carry a record: 2.4GHz 2..=13 and every
/// typed 5GHz 20MHz primary. 14 stays unadvertised.
pub(super) fn admissible(profile: Profile) -> bool {
    (2..=13).contains(&profile.primary()) || profile.is_5ghz()
}
/// 5GHz cross-band operating program recipe (distinct from the unchanged
/// 2.4GHz v1 recipe, so no 2.4GHz binding moves).
fn recipe_5ghz() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"RTL8852B 5GHz/20MHz full operating program v1; Linux core.c __rtw89_set_channel (MAC band mode, BB band select/gain_a/CCK off/BT-share release, RF CFGCH 5G band bits, set_txpwr) then rtw8852b_rfk_band_changed TSSI scan on a band change, then rtw8852b_rfk_channel on a Ready owner; RXDCK pauses prior TSSI; fresh A-band IQK/TSSI/DPK (MDPD order2), DPK reload disabled; RFK MCC slot0");
    hash.update(b"actual primary WW0 5GHz OFDM/MCS/RU limits, no CCK byrate/DFIR, rtw8852bx_sco_mapping, rtw89_encode_chan_idx, TSSI OFDM/trim groups and subband thermal rows; init-only power reference/trim/RX-AB retained from initial program; no BTC switch-band");
    hash.update(b"ordinary TX/CMAC/autonomous response drained before retune, reopened only after Ready; worst-case peaks/antenna cover all calibration, packet, response and optional companion emissions on this primary under the current host rule over the whole occupied span; DFS/NO_IR spans refused");
    hash.finalize()
}
fn recipe() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"RTL8852B noninitial 2.4GHz/20MHz full operating program v1; Linux core.c __rtw89_set_channel then rtw8852b_rfk_channel on a Ready owner; same band, no band-change TSSI scan; RXDCK pauses prior TSSI; fresh IQK/TSSI/DPK, DPK reload disabled; RFK MCC slot0");
    hash.update(b"actual primary WW0 CCK/OFDM/MCS/RU limits, SCO barker/CCK and compensation, CCK TXFIR/DFIR, TSSI CCK/OFDM/trim groups; init-only power reference/trim/RX-AB retained from initial program");
    hash.update(b"ordinary TX/CMAC/autonomous response drained before retune, reopened only after Ready; worst-case peaks/antenna cover all calibration, packet, response and optional companion emissions on this primary under the current host rule over the whole occupied span");
    hash.finalize()
}
fn present(hash: &mut narf_crypto::sha256::Sha256, value: Option<[u8; 32]>) {
    match value {
        Some(value) => {
            hash.update(&[1]);
            hash.update(&value);
        }
        None => hash.update(&[0]),
    }
}
impl Request {
    /// `board` is the noninitial channel identity already extended by the
    /// base record's program flags.
    pub(super) fn new(base: &Qualification, profile: Profile, board: Board) -> Result<Self, Error> {
        base.authority
            .invoke(Current)
            .map_err(|_| Error::Authority)?;
        if !admissible(profile) || board.mac != base.board.mac || board.device != base.board.device
        {
            return Err(Error::Identity);
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852B measured noninitial channel full program v1");
        hash.update(&[profile.primary(), 20]);
        hash.update(&board.identity);
        hash.update(&base.board.identity);
        hash.update(&base.record_digest);
        hash.update(&base.record_signer);
        hash.update(&[base.flags]);
        present(&mut hash, base.amsdu.as_ref().map(amsdu::Amsdu::digest));
        present(
            &mut hash,
            base.rf_tracking.as_ref().map(rf_tracking::Tracking::digest),
        );
        // N52P/N52F are canonical for their request: their bindings (plus
        // the LPS profile version) determine the exact accepted bytes.
        match base.lps.as_ref() {
            Some(sleep) => {
                let request = lps::Request::new(base, sleep.profile())?;
                hash.update(&[1]);
                hash.update(&request.binding);
                hash.update(&sleep.profile().version);
            }
            None => hash.update(&[0]),
        }
        present(
            &mut hash,
            match base.fragments.as_ref() {
                Some(_) => Some(fragment::Request::new(base)?.binding),
                None => None,
            },
        );
        hash.update(&if profile.is_5ghz() {
            recipe_5ghz()
        } else {
            recipe()
        });
        let m = base.board.mac;
        Ok(Self {
            name: format!(
                "rtw89/rtw8852b-chan-v1-ch{:02}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                profile.primary(),
                m[0],
                m[1],
                m[2],
                m[3],
                m[4],
                m[5]
            ),
            binding: hash.finalize(),
        })
    }
}
impl Channel {
    pub(super) fn optional(
        base: &Qualification,
        profile: Profile,
        board: Board,
    ) -> Result<Option<Self>, Error> {
        let request = Request::new(base, profile, board)?;
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|c| c.derive::<Read>().ok())
            .ok_or(Error::Authority)?;
        let cap = match narf_firmware::open(&request.name, &loader) {
            Ok(cap) => cap,
            Err(FirmwareError::NotFound) => return Ok(None),
            Err(error) => return Err(Error::Firmware(error)),
        };
        struct Decode<'a> {
            base: &'a Qualification,
            request: &'a Request,
            profile: Profile,
            board: Board,
        }
        impl CapOp<FirmwareBlob, Read> for Decode<'_> {
            type Output = Result<Channel, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Channel::from_verified(
                        self.base,
                        self.request,
                        self.profile,
                        self.board,
                        view.bytes,
                        view.signer,
                        *cap,
                    )
                })())
            }
        }
        cap.invoke(Decode {
            base,
            request: &request,
            profile,
            board,
        })
        .map_err(|_| Error::Authority)?
        .map(Some)
    }
    pub(super) fn from_verified(
        base: &Qualification,
        request: &Request,
        profile: Profile,
        board: Board,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        if *request != Request::new(base, profile, board)?
            || signer.ok_or(Error::Unsigned)? != base.record_signer
        {
            return Err(Error::Identity);
        }
        if bytes.len() != 128
            || &bytes[..4] != b"N52C"
            || bytes[4..8] != [1, 0, 128, 0]
            || bytes[8..12] != 128u32.to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != base.board.device.to_le_bytes()
            || bytes[54..57] != [1, 20, profile.primary()]
            || bytes[57] != base.flags
            || bytes[68..] != [0; 60]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != request.binding || bytes[48..54] != base.board.mac {
            return Err(Error::Identity);
        }
        let signed = |at: usize| i16::from_le_bytes([bytes[at], bytes[at + 1]]);
        let antenna_qdb = signed(58);
        let ceiling_qdbm = signed(60);
        let peaks_qdbm = [signed(62), signed(64), signed(66)];
        if !(0..=256).contains(&antenna_qdb)
            || !(-512..=256).contains(&ceiling_qdbm)
            || peaks_qdbm.iter().any(|v| !(-512..=256).contains(v))
        {
            return Err(Error::Format);
        }
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(bytes);
        Ok(Self {
            authority,
            profile,
            board,
            binding: request.binding,
            digest: digest.finalize(),
            antenna_qdb,
            ceiling_qdbm,
            peaks_qdbm,
        })
    }
    pub(super) fn profile(&self) -> Profile {
        self.profile
    }
    pub(super) fn board(&self) -> Board {
        self.board
    }
    /// The exact joint binding still matches the base and companions now
    /// installed (a later companion change retires this record).
    pub(super) fn bound(&self, base: &Qualification) -> Result<(), Error> {
        self.current()?;
        if Request::new(base, self.profile, self.board)?.binding != self.binding {
            return Err(Error::Identity);
        }
        Ok(())
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(super) fn envelope(&self) -> Envelope {
        Envelope {
            span: self.profile.occupied(),
            antenna_qdb: self.antenna_qdb,
            ceiling_qdbm: self.ceiling_qdbm,
            peaks_qdbm: self.peaks_qdbm,
        }
    }
    pub(super) fn current(&self) -> Result<(), Error> {
        self.authority.invoke(Current).map_err(|_| Error::Authority)
    }
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, super::super::power::Error>,
    ) -> Result<T, super::super::power::Error> {
        struct Live<F>(F);
        impl<T, F: FnOnce() -> Result<T, super::super::power::Error>> CapOp<FirmwareBlob, Read>
            for Live<F>
        {
            type Output = Result<T, super::super::power::Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        self.authority
            .invoke(Live(operation))
            .map_err(|_| super::super::power::Error::Access)?
    }
}
