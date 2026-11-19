// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Optional signed expanded periodic-DPK program for this exact full radio.
//! Loaded after the optional A-MSDU record so the combined program is measured.
use super::super::rf_tracking::Window;
use super::*;

pub(super) struct Tracking {
    authority: Cap<FirmwareBlob, Read>,
    digest: [u8; 32],
    window: Window,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub name: alloc::string::String,
    pub binding: [u8; 32],
}
fn recipe() -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"RTL8852B periodic DPK full radio operating program v1; initial actual Ready slot0 DPK thermal/pwsf and TSSI-AB completion; ch1/20/TXA1/RXAB; 2s source track_work; BB TSSI thermal/EWMA4,4; source2G thermal3/2 and signed8bit offset; TXAGC_RF/BB/TP, hardware-offset and TXDPD; both9bit PWSF fields; fixed source window, no clamp; no new IQK/TSSI rerun/PMAC");
    hash.update(b"current exact base record/program/signer and optional installed A-MSDU digest; base worst-case peaks/antenna/power must cover full joint radio/aggregation/tracking operation across every permitted PWSF; all raw current PCI/base/companions/host power scopes at native reads/RMW/write/readback; original retained one owner, no concurrent retune/reset/calibration; actual fault retires, uncertain DMA retained");
    hash.finalize()
}
impl Request {
    pub(super) fn new(base: &Qualification) -> Result<Self, Error> {
        base.authority
            .invoke(Current)
            .map_err(|_| Error::Authority)?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852B measured expanded periodic DPK full program v1");
        hash.update(&base.board.identity);
        hash.update(&base.record_digest);
        hash.update(&base.record_signer);
        match base.amsdu.as_ref() {
            Some(program) => {
                program.current()?;
                hash.update(&[1]);
                hash.update(&program.digest());
            }
            None => hash.update(&[0]),
        }
        hash.update(&recipe());
        let m = base.board.mac;
        Ok(Self {
            name: format!(
                "rtw89/rtw8852b-rf-track-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
            binding: hash.finalize(),
        })
    }
}
impl Tracking {
    pub(super) fn optional(base: &Qualification) -> Result<Option<Self>, Error> {
        let request = Request::new(base)?;
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
        }
        impl CapOp<FirmwareBlob, Read> for Decode<'_> {
            type Output = Result<Tracking, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Tracking::from_verified(self.base, self.request, view.bytes, view.signer, *cap)
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
        request: &Request,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        if *request != Request::new(base)? {
            return Err(Error::Identity);
        }
        if signer.ok_or(Error::Unsigned)? != base.record_signer {
            return Err(Error::Identity);
        }
        if bytes.len() != 128
            || &bytes[..4] != b"N52T"
            || bytes[4..8] != [1, 0, 128, 0]
            || bytes[8..12] != 128u32.to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != base.board.device.to_le_bytes()
            || bytes[54..58] != [1, 20, 1, 3]
            || bytes[62..] != [0; 66]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != request.binding || bytes[48..54] != base.board.mac {
            return Err(Error::Identity);
        }
        let window = Window {
            low: u16::from_le_bytes([bytes[58], bytes[59]]),
            high: u16::from_le_bytes([bytes[60], bytes[61]]),
        };
        if !window.valid() {
            return Err(Error::Format);
        }
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(bytes);
        Ok(Self {
            authority,
            digest: digest.finalize(),
            window,
        })
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub(super) fn window(&self) -> Result<Window, Error> {
        self.current()?;
        Ok(self.window)
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
