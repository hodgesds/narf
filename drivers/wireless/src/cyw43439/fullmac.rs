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
pub trait Fullmac: Send {
    const FAMILY: Family;
    const EXTERNAL_CLM: bool;
    fn command<'a>(
        &'a mut self,
        direction: Direction,
        command: u32,
        input: &'a [u8],
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<u8>, Error>> + Send + 'a;
    fn configure_bus(&mut self) -> impl Future<Output = Result<(), Error>> + Send;
    fn poll(&mut self) -> Result<usize, Error>;
    fn fail(&mut self);
    fn pop_event(&mut self) -> Option<Event>;
    fn pop_data(&mut self) -> Option<Vec<u8>>;
    fn send_data(&mut self, frame: &[u8], priority: u8) -> Result<(), Error>;
    /// Only a station's correlated link/key lifecycle calls this method.
    /// Transport completion alone must never call it or open a controlled port.
    fn set_link(&mut self, peer: Option<[u8; 6]>);
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
}
