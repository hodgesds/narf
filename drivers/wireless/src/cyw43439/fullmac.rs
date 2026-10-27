// SPDX-License-Identifier: GPL-2.0-or-later
//! Shared command/event/data seam for SDIO-BCDC and PCIe-msgbuf station owners.
//! This does not grant station authorization; set_link follows verified events.
use super::{
    ioctl::Direction,
    runtime::{Error, Event, Runtime},
    PacketTransport,
};
use alloc::vec::Vec;
use core::future::Future;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Sdio,
    Pcie,
}
/// Linux `enum brcmf_fwvendor` (`bus.h`): the firmware branch whose
/// vendor-specific ABI (`fwvid.h` ops) the attached image implements. It is
/// fixed by the bus match table (`bcmsdh.c`/`pcie.c`), never by a reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareVendor {
    /// `BRCMF_FWVENDOR_WCC`: BCM43602 PCIe and the Broadcom-ID 43439 SDIO
    /// match; SAE passwords use `BRCMF_C_SET_WSEC_PMK` + `BRCMF_WSEC_PASSPHRASE`.
    Wcc,
    /// `BRCMF_FWVENDOR_CYW`: the Cypress-ID 43439 SDIO match; SAE passwords
    /// use the `sae_password` iovar (`struct brcmf_wsec_sae_pwd_le`).
    Cyw,
}
impl FirmwareVendor {
    /// Linux `bcmsdh.c` `brcmf_sdmmc_ids` for the two 43439 SDIO identities:
    /// `BRCMF_SDIO_DEVICE(43439, WCC)` and `CYW_SDIO_DEVICE(43439, CYW)`.
    pub fn sdio(vendor: u16) -> Self {
        if vendor == 0x04b4 {
            Self::Cyw
        } else {
            Self::Wcc
        }
    }
}
pub trait Fullmac: Send {
    const FAMILY: Family;
    const EXTERNAL_CLM: bool;
    /// Exact attached chip profile supports the firmware's 5 GHz channel set.
    /// The SDIO CYW43439 profile remains 2.4 GHz only.
    const BAND_5GHZ: bool = false;
    /// Exact attached native family can qualify VHT80 from its firmware.
    /// CYW43439 has no such PHY, regardless of malformed capability replies.
    const VHT80: bool = false;
    fn command<'a>(
        &'a mut self,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a;
    fn configure_bus(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
    /// Consumed transport records, bounded per call. Positive progress may
    /// leave more RX/events beyond the budget. Zero requires an actual current
    /// FIFO/completion-ring idle observation, not an empty decoded host queue;
    /// queued events/data remain available to their pop methods.
    fn poll(&mut self) -> Result<usize, Error>;
    fn fail(&mut self);
    fn pop_event(&mut self) -> Option<Event>;
    fn pop_data(&mut self) -> Option<Vec<u8>>;
    fn send_data(&mut self, frame: &[u8], priority: u8) -> Result<(), Error>;
    /// Only a station's correlated link/key lifecycle calls this method.
    /// Transport completion alone must never call it or open a controlled port.
    fn set_link(&mut self, peer: Option<[u8; 6]>);
    /// Current negotiated 802.1D-to-AC rank map (`brcmf_get_assoc_ies`).
    /// Transports whose queueing does not consume it ignore the update.
    fn set_ac_priority(&mut self, _ac_priority: [u8; 8]) {}
    /// Bus-match firmware vendor (Linux `bus_if->fwvid`).
    fn firmware_vendor(&self) -> FirmwareVendor {
        FirmwareVendor::Wcc
    }
}
impl<T: PacketTransport> Fullmac for Runtime<T> {
    const FAMILY: Family = Family::Sdio;
    const EXTERNAL_CLM: bool = true;
    fn command<'a>(
        &'a mut self,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a {
        Runtime::command(self, direction, command, input, maximum)
    }
    async fn configure_bus(&mut self) -> Result<(), Error> {
        for name in [b"bus:txglom\0".as_slice(), b"bus:rxglom\0".as_slice()] {
            let mut bytes = name.to_vec();
            bytes.extend_from_slice(&0u32.to_le_bytes());
            self.command(Direction::Set, 263, &bytes, 1502).await?;
        }
        Ok(())
    }
    fn poll(&mut self) -> Result<usize, Error> {
        Runtime::poll(self)
    }
    fn fail(&mut self) {
        Runtime::fail(self)
    }
    fn pop_event(&mut self) -> Option<Event> {
        Runtime::pop_event(self)
    }
    fn pop_data(&mut self) -> Option<Vec<u8>> {
        Runtime::pop_data(self)
    }
    fn send_data(&mut self, frame: &[u8], priority: u8) -> Result<(), Error> {
        Runtime::send_data(self, frame, priority)
    }
    fn set_link(&mut self, _: Option<[u8; 6]>) {}
    fn set_ac_priority(&mut self, ac_priority: [u8; 8]) {
        Runtime::set_ac_priority(self, ac_priority)
    }
    fn firmware_vendor(&self) -> FirmwareVendor {
        Runtime::firmware_vendor(self)
    }
}
