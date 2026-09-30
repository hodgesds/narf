//! Serialized configuration transactions and unsolicited hotplug demux.
use super::{
    cm::{Address, CfgSpace, Header},
    ring::{Error, Packet, Ring},
};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Event {
    pub route: u64,
    pub port: u8,
    pub unplug: bool,
}
#[derive(Debug)]
pub(crate) struct Control {
    pub ring: Ring,
    sequence: u8,
    pub events: Vec<Event>,
    failed: bool,
}
impl Control {
    pub fn new(ring: Ring) -> Self {
        Self {
            ring,
            sequence: 0,
            events: Vec::new(),
            failed: false,
        }
    }
    fn event(&mut self, packet: &Packet) -> Result<bool, Error> {
        if packet.words.len() < 2 {
            return Err(Error::Invalid);
        }
        let header = Header::decode([packet.words[0], packet.words[1]]);
        let h = Header {
            route: header.route,
            unknown: 0,
        }
        .encode();
        if packet.kind == 5 && packet.words.len() == 3 {
            let value = packet.words[2];
            let event = Event {
                route: header.route,
                port: (value & 63) as u8,
                unplug: value & (1 << 31) != 0,
            };
            self.ring.send(
                3,
                &[
                    h[0],
                    h[1],
                    7 | ((event.port as u32) << 8) | ((if event.unplug { 3 } else { 2 }) << 30),
                ],
            )?;
            // A topology rescan is sufficient if the bounded event queue fills.
            if self.events.len() < 64 {
                self.events.push(event);
            }
            return Ok(true);
        }
        if packet.kind == 3 && packet.words.len() == 3 && packet.words[2] & 255 >= 32 {
            self.ring.send(4, &h)?;
            if self.events.len() < 64 {
                self.events.push(Event {
                    route: header.route,
                    port: ((packet.words[2] >> 8) & 63) as u8,
                    unplug: false,
                });
            }
            return Ok(true);
        }
        Ok(false)
    }
    pub fn poll_events(&mut self) -> Result<(), Error> {
        // Drain a bounded batch so a noisy peripheral cannot monopolize a poll.
        for _ in 0..32 {
            match self.ring.receive() {
                Ok(Some(packet)) => {
                    self.event(&packet)?;
                }
                Ok(None) => break,
                Err(Error::Invalid) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    async fn transaction(
        &mut self,
        route: u64,
        addr: Address,
        data: Option<&[u32]>,
    ) -> Result<Vec<u32>, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if route > Header::ROUTE_MAX
            || addr.port > 63
            || addr.offset > 8191
            || addr.offset as u32 + addr.length as u32 > 8192
            || addr.length == 0
            || addr.length > 60
        {
            return Err(Error::Invalid);
        }
        let kind = if data.is_some() { 2 } else { 1 };
        let header = Header { route, unknown: 0 }.encode();
        let mut words = alloc::vec![header[0], header[1], addr.encode()];
        if let Some(data) = data {
            if data.len() != addr.length as usize {
                return Err(Error::Invalid);
            }
            words.extend_from_slice(data);
        }
        self.ring.send(kind, &words)?;
        self.failed = true;
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            for _ in 0..32 {
                match self.ring.receive() {
                    Ok(Some(packet)) => {
                        if self.event(&packet)? {
                            continue;
                        }
                        if let Some(result) = match_reply(&packet, route, addr, kind) {
                            self.failed = matches!(result, Err(Error::Invalid));
                            return result;
                        }
                    }
                    Ok(None) => break,
                    Err(Error::Invalid) => continue,
                    Err(e) => {
                        self.failed = true;
                        return Err(e);
                    }
                }
            }
            if deadline.expired() {
                // No sequence-number reuse after a timed-out transaction.
                self.failed = true;
                return Err(Error::Timeout);
            }
            self.ring.wait(1).await;
        }
    }
}

/// Config-space transport used by both the native ring and device-model tests.
pub(crate) trait Config {
    async fn read(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        len: u8,
    ) -> Result<Vec<u32>, Error>;
    async fn write(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        data: &[u32],
    ) -> Result<(), Error>;
}
impl Config for Control {
    async fn read(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        len: u8,
    ) -> Result<Vec<u32>, Error> {
        self.sequence = (self.sequence + 1) & 3;
        self.transaction(
            route,
            Address {
                offset,
                length: len,
                port,
                space,
                seq: self.sequence,
            },
            None,
        )
        .await
    }
    async fn write(
        &mut self,
        route: u64,
        port: u8,
        space: CfgSpace,
        offset: u16,
        data: &[u32],
    ) -> Result<(), Error> {
        if data.len() > 60 {
            return Err(Error::Invalid);
        }
        self.sequence = (self.sequence + 1) & 3;
        self.transaction(
            route,
            Address {
                offset,
                length: data.len() as u8,
                port,
                space,
                seq: self.sequence,
            },
            Some(data),
        )
        .await
        .map(|_| ())
    }
}
fn match_reply(
    packet: &Packet,
    route: u64,
    addr: Address,
    kind: u8,
) -> Option<Result<Vec<u32>, Error>> {
    if packet.words.len() < 3 {
        return None;
    }
    let h = Header::decode([packet.words[0], packet.words[1]]);
    if h.route != route {
        return None;
    }
    if packet.kind == 3 {
        if packet.words.len() != 3
            || ((packet.words[2] >> 8) & 63) != addr.port as u32
            || packet.words[2] & 255 >= 32
        {
            return None;
        }
        return Some(Err(Error::Remote((packet.words[2] & 255) as u8)));
    }
    if packet.kind != kind || Address::decode(packet.words[2]) != Some(addr) {
        return None;
    }
    let expected = if kind == 1 {
        3 + addr.length as usize
    } else {
        3
    };
    if packet.words.len() != expected {
        return Some(Err(Error::Invalid));
    }
    Some(Ok(packet.words[3..].to_vec()))
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn usb4_response_identity() -> TestResult {
        let a = Address {
            offset: 2,
            length: 1,
            port: 3,
            space: CfgSpace::Port,
            seq: 2,
        };
        let mut p = Packet {
            kind: 1,
            words: alloc::vec![0x8000_0000, 7, a.encode(), 42],
        };
        if match_reply(&p, 7, a, 1) != Some(Ok(alloc::vec![42]))
            || match_reply(&p, 8, a, 1).is_some()
        {
            return TestResult::Fail("route matching");
        }
        p.words[2] ^= 1 << 27;
        if match_reply(&p, 7, a, 1).is_some() {
            return TestResult::Fail("stale sequence accepted");
        }
        p.words[2] = a.encode();
        p.words.pop();
        if match_reply(&p, 7, a, 1) != Some(Err(Error::Invalid)) {
            return TestResult::Fail("short response accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/thunderbolt/control", usb4_response_identity);
}
