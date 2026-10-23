// SPDX-License-Identifier: GPL-2.0-or-later
//! Owned HTC control runtime. Linux ath10k/htc.{c,h}; PCI does not negotiate
//! receive bundling. WMI credit ownership and each wire transaction fail-stop
//! on cancellation or malformed replies.
use super::{bmi::BmiError, hw::HwRev};
use alloc::{collections::VecDeque, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Transport(BmiError),
    Malformed,
    Rejected(u8),
    Unsupported,
    Credits,
    Failed,
    NoMemory,
}
impl From<BmiError> for Error {
    fn from(error: BmiError) -> Self {
        Self::Transport(error)
    }
}
pub(super) trait Hif {
    async fn send(&mut self, pipe: u8, bytes: &[u8]) -> Result<(), BmiError>;
    async fn receive(&mut self, budget_ms: u64) -> Result<(u8, Vec<u8>), BmiError>;
    /// Optional idle-safe progress. A timeout of an outstanding protocol wait
    /// remains an error; native polling overrides this without cancelling DMA.
    async fn poll(&mut self, budget_ms: u64) -> Result<Option<(u8, Vec<u8>)>, BmiError> {
        Ok(Some(self.receive(budget_ms).await?))
    }
}
impl Hif for super::boot::PciBoot {
    async fn send(&mut self, pipe: u8, bytes: &[u8]) -> Result<(), BmiError> {
        self.hif_send(pipe, bytes).await
    }
    async fn receive(&mut self, budget_ms: u64) -> Result<(u8, Vec<u8>), BmiError> {
        self.hif_receive(budget_ms).await
    }
    async fn poll(&mut self, budget_ms: u64) -> Result<Option<(u8, Vec<u8>)>, BmiError> {
        self.hif_poll(budget_ms).await
    }
}
#[derive(Clone, Copy, Debug, Default)]
struct Endpoint {
    service: u16,
    maximum: u16,
    credits: u16,
    sequence: u8,
    pipe: u8,
    flow: bool,
}
#[derive(Debug)]
struct Packet {
    eid: u8,
    payload: Vec<u8>,
    credits: Vec<(u8, u8)>,
}
fn u16at(bytes: &[u8], at: usize) -> Result<u16, Error> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or(Error::Malformed)?
            .try_into()
            .unwrap(),
    ))
}
fn owned(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| Error::NoMemory)?;
    v.extend_from_slice(bytes);
    Ok(v)
}
fn packet(frame: &[u8]) -> Result<Packet, Error> {
    if frame.len() < 8 || frame[0] >= 9 || frame[1] & 0xfc != 0 {
        return Err(Error::Malformed);
    }
    let length = usize::from(u16at(frame, 2)?);
    let end = 8usize.checked_add(length).ok_or(Error::Malformed)?;
    if end > frame.len() || frame.len() - end > 3 {
        return Err(Error::Malformed);
    }
    let trailer = if frame[1] & 2 != 0 {
        usize::from(frame[4])
    } else {
        0
    };
    if (frame[1] & 2 != 0 && trailer < 4) || trailer > length {
        return Err(Error::Malformed);
    }
    let payload_end = end - trailer;
    let mut credits = Vec::new();
    let mut at = payload_end;
    while at < end {
        if end - at < 4 {
            return Err(Error::Malformed);
        }
        let id = frame[at];
        let size = usize::from(frame[at + 1]);
        at += 4;
        let next = at.checked_add(size).ok_or(Error::Malformed)?;
        if next > end {
            return Err(Error::Malformed);
        }
        if id == 1 {
            if size % 4 != 0 {
                return Err(Error::Malformed);
            }
            credits.try_reserve(size / 4).map_err(|_| Error::NoMemory)?;
            for report in frame[at..next].chunks_exact(4) {
                if report[0] >= 9 {
                    return Err(Error::Malformed);
                }
                credits.push((report[0], report[1]));
            }
        }
        at = next;
    }
    Ok(Packet {
        eid: frame[0],
        payload: owned(&frame[8..payload_end])?,
        credits,
    })
}
#[derive(Debug)]
pub(super) struct Session<T> {
    pub transport: T,
    endpoints: [Endpoint; 9],
    pub wmi: u8,
    pub htt: u8,
    pub credit_size: u16,
    total_credits: u16,
    sequence: u8,
    rx_htt_pipe: u8,
    pending_wire: VecDeque<(u8, Vec<u8>)>,
    payloads: VecDeque<(u8, Vec<u8>)>,
    started: bool,
    failed: bool,
}
impl<T: Hif> Session<T> {
    pub fn new(transport: T, hardware: HwRev) -> Self {
        let mut endpoints = [Endpoint::default(); 9];
        endpoints[0] = Endpoint {
            service: 1,
            maximum: 248,
            ..Endpoint::default()
        };
        Self {
            transport,
            endpoints,
            wmi: 0,
            htt: 0,
            credit_size: 0,
            total_credits: 0,
            sequence: 0,
            rx_htt_pipe: if matches!(hardware, HwRev::Qca6174 | HwRev::Qca9377) {
                1
            } else {
                5
            },
            pending_wire: VecDeque::new(),
            payloads: VecDeque::new(),
            started: false,
            failed: false,
        }
    }
    fn credit_reports(&mut self, packet: &Packet) -> Result<(), Error> {
        for &(eid, count) in &packet.credits {
            let endpoint = &mut self.endpoints[eid as usize];
            if endpoint.service == 0 {
                return Err(Error::Malformed);
            }
            if endpoint.flow {
                endpoint.credits = endpoint
                    .credits
                    .checked_add(u16::from(count))
                    .ok_or(Error::Credits)?;
                if endpoint.credits > self.total_credits {
                    return Err(Error::Credits);
                }
            }
        }
        Ok(())
    }
    fn room(&self) -> Result<(), Error> {
        if self.pending_wire.len() + self.payloads.len() >= 32 {
            Err(Error::Malformed)
        } else {
            Ok(())
        }
    }
    async fn send_control(&mut self, body: &[u8]) -> Result<(), Error> {
        if body.len() > 248 {
            return Err(Error::Malformed);
        }
        let mut frame = owned(&[0; 8])?;
        frame
            .try_reserve_exact(body.len())
            .map_err(|_| Error::NoMemory)?;
        frame[2..4].copy_from_slice(&(body.len() as u16).to_le_bytes());
        frame[5] = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        frame.extend_from_slice(body);
        self.transport.send(0, &frame).await?;
        Ok(())
    }
    async fn control(&mut self, expected: u16) -> Result<Packet, Error> {
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            if deadline.expired() {
                return Err(Error::Transport(BmiError::Timeout));
            }
            let (pipe, bytes) = self.transport.receive(1000).await?;
            if pipe != 1 && pipe != 2 && pipe != self.rx_htt_pipe {
                return Err(Error::Malformed);
            }
            if bytes.first().copied() != Some(0) {
                self.room()?;
                self.pending_wire
                    .try_reserve(1)
                    .map_err(|_| Error::NoMemory)?;
                self.pending_wire.push_back((pipe, bytes));
                continue;
            }
            if pipe != 1 {
                return Err(Error::Malformed);
            }
            let packet = packet(&bytes)?;
            if u16at(&packet.payload, 0)? != expected {
                return Err(Error::Malformed);
            }
            return Ok(packet);
        }
    }
    async fn connect(&mut self, service: u16) -> Result<u8, Error> {
        let mut body = [0; 8];
        body[..2].copy_from_slice(&2u16.to_le_bytes());
        body[2..4].copy_from_slice(&service.to_le_bytes());
        let flags = if service == 0x100 {
            self.total_credits << 8
        } else {
            8
        };
        body[4..6].copy_from_slice(&flags.to_le_bytes());
        self.send_control(&body).await?;
        let response = self.control(3).await?;
        if response.payload.len() < 8 || u16at(&response.payload, 2)? != service {
            return Err(Error::Malformed);
        }
        if response.payload[4] != 0 {
            return Err(Error::Rejected(response.payload[4]));
        }
        let eid = response.payload[5];
        let maximum = u16at(&response.payload, 6)?;
        if eid == 0 || eid >= 9 || maximum == 0 || self.endpoints[eid as usize].service != 0 {
            return Err(Error::Malformed);
        }
        let wmi = service == 0x100;
        self.endpoints[eid as usize] = Endpoint {
            service,
            maximum: maximum.min(if wmi { 2040 } else { 248 }),
            credits: if wmi { self.total_credits } else { 0 },
            sequence: 0,
            pipe: if wmi { 3 } else { 4 },
            flow: wmi,
        };
        self.credit_reports(&response)?;
        Ok(eid)
    }
    pub async fn start(&mut self) -> Result<(), Error> {
        if self.failed || self.started {
            return Err(Error::Failed);
        }
        self.failed = true;
        let ready = self.control(1).await?;
        if ready.payload.len() < 8 {
            return Err(Error::Malformed);
        }
        self.total_credits = u16at(&ready.payload, 2)?;
        self.credit_size = u16at(&ready.payload, 4)?;
        if !(1..=255).contains(&self.total_credits)
            || self.credit_size == 0
            || ready.payload[6] == 0
        {
            return Err(Error::Malformed);
        }
        self.credit_reports(&ready)?;
        self.htt = self.connect(0x300).await?;
        self.wmi = self.connect(0x100).await?;
        // struct ath10k_htc_msg_hdr + setup_complete_extended =12 bytes.
        // PCI never sets SDIO's RX bundle enable flag or max receive count.
        let mut setup = [0; 12];
        setup[..2].copy_from_slice(&5u16.to_le_bytes());
        self.send_control(&setup).await?;
        self.started = true;
        self.failed = false;
        Ok(())
    }
    fn accept(&mut self, pipe: u8, bytes: &[u8]) -> Result<(), Error> {
        let packet = packet(bytes)?;
        let endpoint = self.endpoints[packet.eid as usize];
        if endpoint.service == 0
            || packet.eid == 0
            || pipe
                != if endpoint.service == 0x100 {
                    2
                } else {
                    self.rx_htt_pipe
                }
        {
            return Err(Error::Malformed);
        }
        self.credit_reports(&packet)?;
        if !packet.payload.is_empty() {
            self.room()?;
            self.payloads.try_reserve(1).map_err(|_| Error::NoMemory)?;
            self.payloads.push_back((packet.eid, packet.payload));
        }
        Ok(())
    }
    async fn progress(&mut self) -> Result<(), Error> {
        let (pipe, bytes) = match self.pending_wire.pop_front() {
            Some(packet) => packet,
            None => self.transport.receive(1000).await?,
        };
        self.accept(pipe, &bytes)
    }
    pub async fn send_wmi(&mut self, payload: &[u8]) -> Result<(), Error> {
        if !self.started || self.failed {
            return Err(Error::Failed);
        }
        if payload.is_empty()
            || payload.len() > usize::from(self.endpoints[self.wmi as usize].maximum)
        {
            return Err(Error::Malformed);
        }
        self.failed = true;
        let credits = (payload.len() + 8).div_ceil(usize::from(self.credit_size)) as u16;
        let deadline = narf_time::Deadline::after_ms(3000);
        while self.endpoints[self.wmi as usize].credits < credits {
            if deadline.expired() {
                return Err(Error::Transport(BmiError::Timeout));
            }
            self.progress().await?;
        }
        let endpoint = &mut self.endpoints[self.wmi as usize];
        endpoint.credits -= credits;
        let mut frame = owned(&[0; 8])?;
        frame
            .try_reserve_exact(payload.len())
            .map_err(|_| Error::NoMemory)?;
        frame[0] = self.wmi;
        frame[1] = 1;
        frame[2..4].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        frame[5] = endpoint.sequence;
        endpoint.sequence = endpoint.sequence.wrapping_add(1);
        frame.extend_from_slice(payload);
        self.transport.send(endpoint.pipe, &frame).await?;
        self.failed = false;
        Ok(())
    }
    pub async fn send_htt(&mut self, payload: &[u8]) -> Result<(), Error> {
        if !self.started || self.failed {
            return Err(Error::Failed);
        }
        let endpoint = &mut self.endpoints[self.htt as usize];
        if endpoint.service != 0x300
            || endpoint.flow
            || payload.is_empty()
            || payload.len() > usize::from(endpoint.maximum)
        {
            return Err(Error::Malformed);
        }
        self.failed = true;
        let mut frame = owned(&[0; 8])?;
        frame
            .try_reserve_exact(payload.len())
            .map_err(|_| Error::NoMemory)?;
        frame[0] = self.htt;
        frame[2..4].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        frame[5] = endpoint.sequence;
        endpoint.sequence = endpoint.sequence.wrapping_add(1);
        frame.extend_from_slice(payload);
        self.transport.send(endpoint.pipe, &frame).await?;
        self.failed = false;
        Ok(())
    }
    pub async fn poll(&mut self) -> Result<Option<(u8, Vec<u8>)>, Error> {
        self.poll_with_progress().await.map(|(_, payload)| payload)
    }
    /// Credit-only input is progress, even though it carries no payload.
    /// Only an empty nonblocking HIF poll establishes receive quiescence.
    pub async fn poll_with_progress(&mut self) -> Result<(bool, Option<(u8, Vec<u8>)>), Error> {
        if !self.started || self.failed {
            return Err(Error::Failed);
        }
        self.failed = true;
        if let Some(payload) = self.payloads.pop_front() {
            self.failed = false;
            return Ok((true, Some(payload)));
        }
        let wire = if let Some(wire) = self.pending_wire.pop_front() {
            Some(wire)
        } else {
            self.transport.poll(0).await?
        };
        let progressed = wire.is_some();
        if let Some((pipe, bytes)) = wire {
            self.accept(pipe, &bytes)?;
        }
        let result = self.payloads.pop_front();
        self.failed = false;
        Ok((progressed, result))
    }
    pub async fn receive(&mut self) -> Result<(u8, Vec<u8>), Error> {
        if !self.started || self.failed {
            return Err(Error::Failed);
        }
        self.failed = true;
        let deadline = narf_time::Deadline::after_ms(3000);
        loop {
            if deadline.expired() {
                return Err(Error::Transport(BmiError::Timeout));
            }
            if let Some(payload) = self.payloads.pop_front() {
                self.failed = false;
                return Ok(payload);
            }
            self.progress().await?;
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests;
