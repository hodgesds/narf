// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Optional signed full joint fragment emitter program. Intended as a child
//! of radio_policy_a, consumed by the actual retained native fragment owner.
//! Existing N5AB/N5AC records and fingerprints keep their exact meaning.
//!
//! A has no A-MSDU, RF-tracking or sleep companion yet, so the request
//! binds only the base identity/digest/signer and the A fragment recipe.
//! When an A companion lands, [`Request::new`] must bind its digest too
//! (as B's does); old `N5AF` records then stop verifying and must be
//! re-issued, which is the safe direction.
use super::*;
pub(super) struct Fragments {
    authority: Cap<FirmwareBlob, Read>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub name: alloc::string::String,
    pub binding: [u8; 32],
}
impl Request {
    pub(super) fn new(base: &Qualification) -> Result<Self, Error> {
        base.current()?;
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852A signed measured full joint software fragmentation program v1");
        hash.update(&base.board.identity);
        hash.update(&base.record_digest);
        hash.update(&base.record_signer);
        hash.update(&super::super::fragment_wire::recipe_a());
        hash.update(b"all actual selected W1/board/RFE/source/host limits/base programs jointly measured; no borrowed nonfragment-only envelope; actual fragment train, per-fragment RTS/ACK/retry/NAV/CCK1 and software CCMP/BIP/RX admission stay under the original declared full joint peaks/antenna/power ceiling");
        let m = base.board.mac;
        Ok(Self {
            name: format!(
                "rtw89/rtw8852a-fragment-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
            binding: hash.finalize(),
        })
    }
}
impl Fragments {
    pub(super) fn optional(base: &Qualification) -> Result<Option<Self>, Error> {
        let request = Request::new(base)?;
        let loader = narf_firmware::trusted_loader_authority()
            .and_then(|cap| cap.derive::<Read>().ok())
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
            type Output = Result<Fragments, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Fragments::from_verified(self.base, self.request, view.bytes, view.signer, *cap)
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
        if *request != Request::new(base)? || signer.ok_or(Error::Unsigned)? != base.record_signer {
            return Err(Error::Identity);
        }
        if bytes.len() != 128
            || &bytes[..4] != b"N5AF"
            || bytes[4..8] != [1, 0, 128, 0]
            || bytes[8..12] != 128u32.to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != base.board.device.to_le_bytes()
            || bytes[54..58] != [1, 20, 1, 3]
            || bytes[58..60] != 2346u16.to_le_bytes()
            || bytes[60..64] != [16, 0, 3, 1]
            || bytes[64..] != [0; 64]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != request.binding || bytes[48..54] != base.board.mac {
            return Err(Error::Identity);
        }
        Ok(Self { authority })
    }
    pub(super) fn current(&self) -> Result<(), Error> {
        self.authority.invoke(Current).map_err(|_| Error::Authority)
    }
    /// Finite direct capability scope; never calls Qualification/current or
    /// recursively dispatches back through optional operating programs.
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
