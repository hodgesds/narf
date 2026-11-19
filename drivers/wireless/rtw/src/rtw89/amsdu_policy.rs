// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Separately signed expanded full-radio TX A-MSDU program. The ordinary
//! radio-v2 identity and flag byte stay exact; no existing v2 grant admits it.
use super::*;
use alloc::string::String;

const AMSDU_LENGTH: usize = 128;
const PREFIX: usize = super::super::tx_amsdu::PREFIX;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AmsduRequest {
    pub name: String,
    pub binding: [u8; 32],
}
pub(super) struct Amsdu {
    authority: Cap<FirmwareBlob, Read>,
    digest: [u8; 32],
}
fn recipe() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"RTL8852B chip5000/current MACID0 RA length policy full TX A-MSDU v1; exact installed radio-v2 bytes digest and full board/program identity; base worst-case peak/antenna/power limits cover expanded full operating program; protected CCMP one-PN/SN or Open one-SN; same-TID original ordered prefix; body<=peer HT3839/7935; no HTC in A-MSDU; no local RX capability expansion");
    hash.update(b"standalone NormalAck and A-MSDU-in-A-MPDU only actual per-TID BA peer permit; sticky TXQ_NO_AMSDU; original peer/key/port/source/power; dynamic contiguous native DMA; one MPDU/ticket/RPQ terminal; retained maps until consumption+air terminal; no per-subframe fake completion");
    hash.update(&(PREFIX as u32).to_le_bytes());
    hash.finalize()
}
impl AmsduRequest {
    pub(super) fn new(base: &Qualification) -> Result<Self, Error> {
        base.authority
            .invoke(Current)
            .map_err(|_| Error::Authority)?;
        if base.flags & Program::Ampdu.flags() != Program::Ampdu.flags() {
            return Err(Error::Format);
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852B measured expanded full A-MSDU operating program v1");
        hash.update(&base.board.identity);
        hash.update(&base.record_digest);
        hash.update(&base.record_signer);
        hash.update(&recipe());
        let m = base.board.mac;
        Ok(Self {
            binding: hash.finalize(),
            name: format!(
                "rtw89/rtw8852b-tx-amsdu-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
        })
    }
}
impl Amsdu {
    pub(super) fn optional(base: &Qualification) -> Result<Option<Self>, Error> {
        // Existing profiles without originator HT A-MPDU cannot reach this
        // full emitter. No extra record is needed for their unchanged path.
        if base.flags & Program::Ampdu.flags() != Program::Ampdu.flags() {
            return Ok(None);
        }
        let request = AmsduRequest::new(base)?;
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
            request: &'a AmsduRequest,
        }
        impl CapOp<FirmwareBlob, Read> for Decode<'_> {
            type Output = Result<Amsdu, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Amsdu::from_verified(self.base, self.request, view.bytes, view.signer, *cap)
                })())
            }
        }
        cap.invoke(Decode {
            base,
            request: &request,
        })
        .map_err(|_| Error::Authority)?
        .map(Some)
    }
    pub(super) fn from_verified(
        base: &Qualification,
        request: &AmsduRequest,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        if *request != AmsduRequest::new(base)? {
            return Err(Error::Identity);
        }
        if signer.ok_or(Error::Unsigned)? != base.record_signer {
            return Err(Error::Identity);
        }
        if bytes.len() != AMSDU_LENGTH
            || &bytes[..4] != b"N52A"
            || bytes[4..8] != [1, 0, 128, 0]
            || bytes[8..12] != (AMSDU_LENGTH as u32).to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != base.board.device.to_le_bytes()
            || bytes[54..58] != [1, 20, 1, 3]
            || bytes[58..60] != (super::super::tx_amsdu::MAX_BODY as u16).to_le_bytes()
            || bytes[60] != PREFIX as u8
            || bytes[61..] != [0; 67]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != request.binding || bytes[48..54] != base.board.mac {
            return Err(Error::Identity);
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(bytes);
        Ok(Self {
            authority,
            digest: hash.finalize(),
        })
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.digest
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
