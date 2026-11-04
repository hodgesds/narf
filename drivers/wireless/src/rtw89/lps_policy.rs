// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Optional measured full joint awake/clock-gated/autonomous-template program.
//! Existing N52B/N52A/N52T bytes and identities remain unchanged.
use super::super::lps_wire::Profile;
use super::*;
pub(super) struct Sleep {
    authority: Cap<FirmwareBlob, Read>,
    profile: Profile,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Request {
    pub name: alloc::string::String,
    pub binding: [u8; 32],
}
impl Request {
    pub(super) fn new(base: &Qualification, profile: Profile) -> Result<Self, Error> {
        base.current()?;
        if Profile::for_version(profile.version) != Some(profile) {
            return Err(Error::Identity);
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        hash.update(b"NARF RTL8852B measured joint runtime sleep full program v1");
        hash.update(&base.board.identity);
        hash.update(&base.record_digest);
        hash.update(&base.record_signer);
        for digest in [
            base.amsdu.as_ref().map(amsdu::Amsdu::digest),
            base.rf_tracking.as_ref().map(rf_tracking::Tracking::digest),
        ] {
            match digest {
                Some(d) => {
                    hash.update(&[1]);
                    hash.update(&d);
                }
                None => hash.update(&[0]),
            }
        }
        hash.update(&profile.version);
        hash.update(b"live B WLAN-only coex0.29.29<=v<0.29.122; MACID0/ch1/20/TXA1/RXAB; clock-gated RPWM5/Active0 exact toggle/request/CPWM response; old LPS H2C DONE_ACK+MAC0 clear; actual WLAN-only scoreboard FWCTRL/ON, retained fixed-grant readbacks and exact OFF_BT DONE; HCI geometry unchanged; no BE RF_PS/ML_CMN/TRX_PROTECT, no new C2HREG/beacon-level producer");
        hash.update(b"actual original association AID, current peer and original admin-UP registration lifetime; PS-Poll/NULL/QoS-NULL exact native ADD RECV+DONE+C2H and GENERAL DONE; no hardware keys or host DATA PN/SN use; all autonomous PM/NULL/PS-Poll/beacon response and every awake/restore/optional aggregation/periodic DPK state jointly measured under base peaks/antenna and current full host power envelope; no borrowed AP-only/awake-only measurement");
        hash.update(b"single retained owner idle/prefix/use-count and current capability/program fences before native publication and after waits; post-coex/credit-wait completed prefix and actual final ENTER HCI/backlog guard before descriptor/doorbell; Busy only proven unpublished defer; quiet actual IRQ receipts/HCI producer and host/source recheck before Line wait baseline, no own-DONE RF churn; actual CPWM Active then PHY env/PHYSTS restore then leave H2C/DONE then MAC0 clear then coex ON before ordinary/BB work; source loss nonemitting device-authorized physical reset, no unauthorized NULL wake; uncertain command/DMA/storage retained, no packet ID reuse in one verified firmware epoch");
        let m = base.board.mac;
        Ok(Self {
            name: format!(
                "rtw89/rtw8852b-lps-v1-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.bin",
                m[0], m[1], m[2], m[3], m[4], m[5]
            ),
            binding: hash.finalize(),
        })
    }
}
impl Sleep {
    pub(super) fn optional(base: &Qualification, profile: Profile) -> Result<Option<Self>, Error> {
        let request = Request::new(base, profile)?;
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
        }
        impl CapOp<FirmwareBlob, Read> for Decode<'_> {
            type Output = Result<Sleep, Error>;
            fn execute(self, cap: &Cap<FirmwareBlob, Read>) -> Result<Self::Output, CapError> {
                Ok((|| {
                    let view = narf_firmware::view_of(cap).map_err(Error::Firmware)?;
                    Sleep::from_verified(
                        self.base,
                        self.request,
                        self.profile,
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
        })
        .map_err(|_| Error::Authority)?
        .map(Some)
    }
    pub(super) fn from_verified(
        base: &Qualification,
        request: &Request,
        profile: Profile,
        bytes: &[u8],
        signer: Option<[u8; 32]>,
        authority: Cap<FirmwareBlob, Read>,
    ) -> Result<Self, Error> {
        authority.invoke(Current).map_err(|_| Error::Authority)?;
        if *request != Request::new(base, profile)?
            || signer.ok_or(Error::Unsigned)? != base.record_signer
        {
            return Err(Error::Identity);
        }
        if bytes.len() != 128
            || &bytes[..4] != b"N52P"
            || bytes[4..8] != [1, 0, 128, 0]
            || bytes[8..12] != 128u32.to_le_bytes()
            || bytes[12..14] != 0x10ecu16.to_le_bytes()
            || bytes[14..16] != base.board.device.to_le_bytes()
            || bytes[54..58] != [1, 20, 1, 3]
            || bytes[58..62] != profile.version
            || bytes[62..] != [0; 66]
        {
            return Err(Error::Format);
        }
        if bytes[16..48] != request.binding || bytes[48..54] != base.board.mac {
            return Err(Error::Identity);
        }
        Ok(Self { authority, profile })
    }
    pub(super) fn profile(&self) -> Profile {
        self.profile
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
