//! Persistent RTL8188EU native USB packet ownership.
//! No receive timeout cancels/reposts a TD; receipts survive quiet intervals.
//! One owner is bound to one policy-admitted channel. Retune/recovery needs
//! endpoint stop/drain and cannot be implemented by changing this label.
use super::{
    device_init::Endpoints,
    packet_codec::{self, Kind, Record, MAX_TRANSFER},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use narf_drivers_usb::device::{BulkToken, USBDevice, UsbError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Endpoints,
    Channel,
    Busy,
    NotStarted,
    Failed,
    Usb(UsbError),
    Packet(packet_codec::Error),
    ShortTransmit,
}
/// No caller/DMA alias survives a begin call: native USB stages TX bytes and
/// retains RX storage itself. Only an exact terminal receipt may copy/reuse.
#[async_trait::async_trait]
pub trait Io: Send + Sync {
    type Receipt: Send + Sync;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<Self::Receipt, UsbError>;
    fn poll_receive(
        &self,
        receipt: &Self::Receipt,
        bytes: &mut [u8],
    ) -> Result<Option<usize>, UsbError>;
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<Self::Receipt, UsbError>;
    fn poll_send(&self, receipt: &Self::Receipt) -> Result<Option<usize>, UsbError>;
    async fn stop(&self, receipt: &Self::Receipt) -> Result<(), UsbError>;
}
pub struct UsbIo(Arc<USBDevice>);
impl core::fmt::Debug for UsbIo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188euUsbIo").finish_non_exhaustive()
    }
}
impl UsbIo {
    pub fn new(device: Arc<USBDevice>) -> Self {
        Self(device)
    }
}
#[async_trait::async_trait]
impl Io for UsbIo {
    type Receipt = BulkToken;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<BulkToken, UsbError> {
        self.0.begin_bulk_in(dci, length)
    }
    fn poll_receive(
        &self,
        receipt: &BulkToken,
        bytes: &mut [u8],
    ) -> Result<Option<usize>, UsbError> {
        self.0.poll_bulk_in(receipt, bytes)
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<BulkToken, UsbError> {
        self.0.begin_bulk_out(dci, bytes)
    }
    fn poll_send(&self, receipt: &BulkToken) -> Result<Option<usize>, UsbError> {
        self.0.poll_bulk_out(receipt)
    }
    async fn stop(&self, receipt: &BulkToken) -> Result<(), UsbError> {
        self.0.stop_bulk(receipt).await
    }
}
struct Transmit<R> {
    receipt: R,
    bytes: usize,
}
/// USB completion does not constitute radio ACK or controlled-port readiness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivered {
    pub native_bytes: usize,
}
pub struct Owner<I: Io> {
    io: I,
    endpoints: Endpoints,
    channel: u8,
    failed: bool,
    pub(super) qos: bool,
    pub(super) ht: bool,
    receive: Option<I::Receipt>,
    transmit: Option<Transmit<I::Receipt>>,
    scratch: Vec<u8>,
}
impl<I: Io> core::fmt::Debug for Owner<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188euPacketOwner")
            .field("channel", &self.channel)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}
impl<I: Io> Owner<I> {
    pub fn new(io: I, endpoints: Endpoints, channel: u8) -> Result<Self, Error> {
        let n = usize::from(endpoints.output_count);
        if !(1..=3).contains(&n) || endpoints.input & 0xf0 != 0x80 || endpoints.input & 15 == 0 {
            return Err(Error::Endpoints);
        }
        for (i, &e) in endpoints.output[..n].iter().enumerate() {
            if e & 0xf0 != 0 || e == 0 || endpoints.output[..i].contains(&e) {
                return Err(Error::Endpoints);
            }
        }
        if !(1..=14).contains(&channel) {
            return Err(Error::Channel);
        }
        Ok(Self {
            io,
            endpoints,
            channel,
            failed: false,
            qos: false,
            ht: false,
            receive: None,
            transmit: None,
            scratch: alloc::vec![0;MAX_TRANSFER],
        })
    }
    pub fn channel(&self) -> u8 {
        self.channel
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }
    pub fn fail(&mut self) {
        self.failed = true;
    }
    /// Install the first persistent RX receipt before opening the MAC RX gate.
    pub fn start(&mut self) -> Result<(), Error> {
        self.check()?;
        if self.receive.is_some() {
            return Err(Error::Busy);
        }
        self.post()
    }
    fn check(&self) -> Result<(), Error> {
        if self.failed {
            Err(Error::Failed)
        } else {
            Ok(())
        }
    }
    fn post(&mut self) -> Result<(), Error> {
        match self
            .io
            .begin_receive((self.endpoints.input & 15) * 2 + 1, MAX_TRANSFER)
        {
            Ok(receipt) => {
                self.receive = Some(receipt);
                Ok(())
            }
            Err(e) => {
                self.failed = true;
                Err(Error::Usb(e))
            }
        }
    }
    /// None is indefinite pending, not an instruction to cancel or retry.
    pub fn poll_receive(&mut self) -> Result<Option<Vec<Record>>, Error> {
        self.check()?;
        let receipt = self.receive.as_ref().ok_or(Error::NotStarted)?;
        let length = match self.io.poll_receive(receipt, &mut self.scratch) {
            Ok(None) => return Ok(None),
            Ok(Some(length)) => length,
            Err(e) => {
                self.failed = true;
                return Err(Error::Usb(e));
            }
        };
        if length > self.scratch.len() {
            self.failed = true;
            return Err(Error::Packet(packet_codec::Error::Length));
        }
        // Exact terminal completion released USB's endpoint page. Drop this
        // receipt only now, then parse a private CPU copy before re-posting.
        self.receive = None;
        let records = match packet_codec::receive(&self.scratch[..length]) {
            Ok(records) => records,
            Err(e) => {
                self.failed = true;
                return Err(Error::Packet(e));
            }
        };
        self.post()?;
        Ok(Some(records))
    }
    pub fn submit(&mut self, kind: Kind, frame: &[u8]) -> Result<(), Error> {
        self.submit_rate(kind, frame, 0)
    }
    pub(super) fn submit_rate(&mut self, kind: Kind, frame: &[u8], rate: u8) -> Result<(), Error> {
        self.check()?;
        if rate >= 12 && (!self.ht || kind != Kind::Data || frame.first() != Some(&0x88)) {
            return Err(Error::Packet(packet_codec::Error::Header));
        }
        if kind == Kind::Data && frame.first() == Some(&0x88) && !self.qos {
            return Err(Error::Packet(packet_codec::Error::Header));
        }
        if self.receive.is_none() {
            return Err(Error::NotStarted);
        }
        if self.transmit.is_some() {
            return Err(Error::Busy);
        }
        let packet = packet_codec::transmit_rate(frame, kind, rate).map_err(Error::Packet)?;
        let index = match kind {
            Kind::Management => 0,
            Kind::Data => packet_codec::data_endpoint(
                packet_codec::access_category(packet_codec::data_tid(frame)).1,
                self.endpoints.output_count,
            ),
        };
        let dci = self.endpoints.output[index] * 2;
        match self.io.begin_send(dci, &packet) {
            Ok(receipt) => {
                self.transmit = Some(Transmit {
                    receipt,
                    bytes: packet.len(),
                });
                Ok(())
            }
            Err(e) => {
                self.failed = true;
                Err(Error::Usb(e))
            }
        }
    }
    /// Pause this single-channel packet owner. MAC RX/TX closure belongs to
    /// the radio owner before this call; this proves only host TD quiescence.
    /// Every dropped/failed stop leaves this owner terminal and its receipts
    /// retained. A successful pause permits re-posting on the same channel.
    pub async fn stop(&mut self) -> Result<(), Error> {
        self.check()?;
        self.failed = true;
        if let Some(receipt) = &self.receive {
            self.io.stop(receipt).await.map_err(Error::Usb)?;
        }
        self.receive = None;
        if let Some(tx) = &self.transmit {
            self.io.stop(&tx.receipt).await.map_err(Error::Usb)?;
        }
        self.transmit = None;
        self.failed = false;
        Ok(())
    }
    pub fn poll_transmit(&mut self) -> Result<Option<Delivered>, Error> {
        self.check()?;
        let Some(tx) = self.transmit.as_ref() else {
            return Ok(None);
        };
        let length = match self.io.poll_send(&tx.receipt) {
            Ok(None) => return Ok(None),
            Ok(Some(length)) => length,
            Err(e) => {
                self.failed = true;
                return Err(Error::Usb(e));
            }
        };
        if length != tx.bytes {
            self.failed = true;
            return Err(Error::ShortTransmit);
        }
        let delivered = Delivered {
            native_bytes: length - packet_codec::TX_DESC,
        };
        self.transmit = None;
        Ok(Some(delivered))
    }
}
#[cfg(feature = "kernel-test")]
#[path = "packet_transport_tests.rs"]
mod tests;
