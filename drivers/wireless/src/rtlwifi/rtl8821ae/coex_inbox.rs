// SPDX-License-Identifier: GPL-2.0-or-later
//! Bounded original RX reports. MP waits poll arrivals only; ordinary
//! dispatch takes deferred reports first. No report is its own new arrival.

use super::btc::{C2hSource, C2H_MAX};
use crate::rtlwifi::prepare::Error;
use alloc::collections::VecDeque;

type Entry = (usize, [u8; C2H_MAX]);
pub const CAPACITY: usize = 32;

#[derive(Default)]
pub struct Inbox {
    arrivals: VecDeque<Entry>,
    deferred: VecDeque<Entry>,
}
impl Inbox {
    fn entry(packet: &[u8]) -> Result<Entry, Error> {
        if !(2..=C2H_MAX).contains(&packet.len()) {
            return Err(Error::Descriptor);
        }
        let mut bytes = [0; C2H_MAX];
        bytes[..packet.len()].copy_from_slice(packet);
        Ok((packet.len(), bytes))
    }
    pub fn push(&mut self, packet: &[u8]) -> Result<(), Error> {
        if self.arrivals.len() + self.deferred.len() >= CAPACITY {
            return Err(Error::Memory);
        }
        self.arrivals.try_reserve(1).map_err(|_| Error::Memory)?;
        self.arrivals.push_back(Self::entry(packet)?);
        Ok(())
    }
    pub fn pop(&mut self) -> Option<Entry> {
        self.deferred
            .pop_front()
            .or_else(|| self.arrivals.pop_front())
    }
    pub fn len(&self) -> usize {
        self.arrivals.len() + self.deferred.len()
    }
}
impl C2hSource for Inbox {
    fn poll_c2h(&mut self, out: &mut [u8; C2H_MAX]) -> Result<Option<usize>, Error> {
        Ok(self.arrivals.pop_front().map(|(n, bytes)| {
            out[..n].copy_from_slice(&bytes[..n]);
            n
        }))
    }
    fn defer_c2h(&mut self, packet: &[u8]) -> Result<(), Error> {
        if self.len() >= CAPACITY {
            return Err(Error::Memory);
        }
        self.deferred.try_reserve(1).map_err(|_| Error::Memory)?;
        self.deferred.push_back(Self::entry(packet)?);
        Ok(())
    }
}
