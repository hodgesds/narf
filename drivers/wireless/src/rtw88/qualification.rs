// SPDX-License-Identifier: GPL-2.0-or-later
//! Reusable separately signed continuation contract for new RTW88 programs.
//!
//! Each new emitting/tracking program (dynamic-mechanism watchdog, future
//! channel/width/coding programs) is described once by a static [`Kind`]:
//! a tag letter, a filename stem, the hashed upstream source contract and a
//! payload admission check. The generic loader then supplies the common
//! layout, exact identity binding, signer/capability checks and live
//! invocation, so new programs no longer re-implement those mechanics.
//!
//! The identity binds the chip, the exact retained board/calibration base
//! (`Gate::extension_request`, i.e. the N22Cv2 or N21S qualification the
//! station already runs under) and the kind's source description. Every
//! operation of the program runs inside [`Grant::invoke`], which re-checks the
//! continuation capability and then enters the current base gate (and thus
//! the current regulatory policy and base capabilities).
//!
//! Layout (128 bytes):
//!
//! | Bytes | Field |
//! |---|---|
//! | 0..4 | `N21<tag>` / `N22<tag>` |
//! | 4..8 | `[1, 0, 128, 0]` (layout v1, length 128) |
//! | 8..12 | length 128 LE |
//! | 12..16 | `ec 10` + PCI device id LE |
//! | 16..48 | request identity |
//! | 48..54 | exact factory MAC |
//! | 54..56 | `[tag, 1]` (kind version 1) |
//! | 56..120 | kind payload, admitted by [`Kind::admit`] |
//! | 120..128 | zero |
use super::{firmware_transport::Error, power_policy::Gate};
#[cfg(any(test, feature = "kernel-test"))]
use alloc::vec::Vec;
use alloc::{format, string::String, sync::Arc};
use narf_capabilities::{Cap, CapError, CapOp, NoopOp, Read};
use narf_firmware::FirmwareBlob;

pub(super) const LENGTH: usize = 128;
pub(super) const PAYLOAD: usize = 64;

/// Static description of one separately qualified continuation program.
pub(super) struct Kind {
    /// Fourth magic byte and kind-version tag.
    pub(super) tag: u8,
    /// Filename stem: `rtw88/rtw882{1,2}ce-<stem>-v1-<mac>.bin`.
    pub(super) stem: &'static str,
    /// Exact upstream source contract hashed into the identity.
    pub(super) source: &'static [u8],
    /// Kind-specific payload admission for the given PCI device id.
    pub(super) admit: fn(u16, &[u8; PAYLOAD]) -> bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub identity: [u8; 32],
    pub mac: [u8; 6],
    pub filename: String,
}

fn base_identity(gate: &Gate) -> Result<[u8; 32], Error> {
    Ok(gate.extension_request().ok_or(Error::State)?.identity)
}

/// Measurement metadata for `kind` over the exact current base. No grant.
pub(super) fn request(kind: &'static Kind, gate: &Gate) -> Result<Request, Error> {
    let did = gate.did();
    let mac = gate.own();
    let base = base_identity(gate)?;
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(b"NARF RTW88 separately signed continuation contract v1");
    hash.update(&[kind.tag]);
    hash.update(kind.stem.as_bytes());
    hash.update(&did.to_le_bytes());
    hash.update(&mac);
    hash.update(&base);
    hash.update(kind.source);
    Ok(Request {
        identity: hash.finalize(),
        mac,
        filename: format!(
            "rtw88/rtw882{}ce-{}-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
            if did == 0xc821 { 1 } else { 2 },
            kind.stem,
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]
        ),
    })
}

pub(super) enum Source {
    Registered,
    #[cfg(any(test, feature = "kernel-test"))]
    Verified {
        bytes: Vec<u8>,
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
    },
}

/// A decoded, signed, capability-backed continuation over one exact base.
pub(super) struct Grant {
    kind: &'static Kind,
    did: u16,
    base: [u8; 32],
    request: Request,
    cap: Cap<FirmwareBlob, Read>,
    payload: [u8; PAYLOAD],
}

impl core::fmt::Debug for Grant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw88Continuation")
            .field("tag", &(self.kind.tag as char))
            .field("did", &self.did)
            .finish_non_exhaustive()
    }
}

impl Source {
    pub(super) fn load(self, kind: &'static Kind, gate: &Gate) -> Result<Arc<Grant>, Error> {
        let request = request(kind, gate)?;
        let did = gate.did();
        let base = base_identity(gate)?;
        struct Decode {
            kind: &'static Kind,
            did: u16,
            base: [u8; 32],
            request: Request,
        }
        impl CapOp<FirmwareBlob, Read> for Decode {
            type Output = Result<Grant, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Grant::decode(
                        view.bytes,
                        view.signer,
                        *cap,
                        self.kind,
                        self.did,
                        self.base,
                        self.request,
                    )
                })())
            }
        }
        let grant = match self {
            Self::Registered => {
                let loader = narf_firmware::trusted_loader_authority()
                    .and_then(|c| c.derive::<Read>().ok())
                    .ok_or(Error::Access)?;
                let cap =
                    narf_firmware::open(&request.filename, &loader).map_err(Error::Firmware)?;
                cap.invoke(Decode {
                    kind,
                    did,
                    base,
                    request,
                })
                .map_err(|_| Error::Access)??
            }
            #[cfg(any(test, feature = "kernel-test"))]
            Self::Verified { bytes, signer, cap } => {
                Grant::decode(&bytes, signer, cap, kind, did, base, request)?
            }
        };
        // Live policy/base checks run when the grant binds to the station
        // gate (and on every invocation); decode already proved the cap.
        Ok(Arc::new(grant))
    }
}

impl Grant {
    fn decode(
        b: &[u8],
        signer: Option<[u8; 32]>,
        cap: Cap<FirmwareBlob, Read>,
        kind: &'static Kind,
        did: u16,
        base: [u8; 32],
        request: Request,
    ) -> Result<Self, Error> {
        cap.invoke(NoopOp).map_err(|_| Error::Access)?;
        let chip = match did {
            0xc821 => b'1',
            0xc822 => b'2',
            _ => return Err(Error::Unsupported),
        };
        if signer.is_none()
            || b.len() != LENGTH
            || b[..4] != [b'N', b'2', chip, kind.tag]
            || b[4..8] != [1, 0, LENGTH as u8, 0]
            || b[8..12] != (LENGTH as u32).to_le_bytes()
            || b[12..14] != [0xec, 0x10]
            || b[14..16] != did.to_le_bytes()
            || b[16..48] != request.identity
            || b[48..54] != request.mac
            || b[54..56] != [kind.tag, 1]
            || b[120..] != [0; 8]
        {
            return Err(Error::Prerequisite);
        }
        let payload: [u8; PAYLOAD] = b[56..120].try_into().map_err(|_| Error::Prerequisite)?;
        if !(kind.admit)(did, &payload) {
            return Err(Error::Prerequisite);
        }
        Ok(Self {
            kind,
            did,
            base,
            request,
            cap,
            payload,
        })
    }
    pub(super) fn tag(&self) -> u8 {
        self.kind.tag
    }
    pub(super) fn is(&self, kind: &'static Kind) -> bool {
        core::ptr::eq(self.kind, kind)
    }
    pub(super) fn request(&self) -> Request {
        self.request.clone()
    }
    pub(super) fn payload(&self) -> &[u8; PAYLOAD] {
        &self.payload
    }
    /// The grant applies only to the exact base it was qualified against.
    pub(super) fn matches(&self, gate: &Gate) -> bool {
        gate.did() == self.did
            && base_identity(gate).is_ok_and(|b| b == self.base)
            && request(self.kind, gate).as_ref() == Ok(&self.request)
    }
    /// Run `op` under the current continuation capability and the current
    /// base gate (regulatory policy plus every bound base capability).
    pub(super) fn invoke<T>(
        &self,
        gate: &Gate,
        op: impl FnOnce() -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.matches(gate) {
            return Err(Error::State);
        }
        struct Live<F>(F);
        impl<T, F: FnOnce() -> Result<T, Error>> CapOp<FirmwareBlob, Read> for Live<F> {
            type Output = Result<T, Error>;
            fn execute(self, _: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((self.0)())
            }
        }
        gate.invoke(|| self.cap.invoke(Live(op)).map_err(|_| Error::Access)?)
    }
    pub(super) fn check(&self, gate: &Gate) -> Result<(), Error> {
        self.invoke(gate, || Ok(()))
    }
}
