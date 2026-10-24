// SPDX-License-Identifier: GPL-2.0-or-later
//! Owned runtime CE storage. CE0/1 remain in the original BMI owner;
//! these allocations must be retained before BMI_DONE can activate firmware.
use super::{allocate, PciBoot};
use crate::ath10k::{
    bmi::BmiError,
    ce::Ath10kMmio,
    dma::{barrier, Direction, Memory, Ring},
    hw::HwRev,
};
use alloc::{collections::VecDeque, vec::Vec};

#[derive(Debug)]
pub(super) struct Pipe<B> {
    pub number: u8,
    pub direction: Direction,
    pub maximum: u16,
    pub ring: Ring<B>,
    pub buffer: B,
    pub pending: Option<narf_time::Deadline>,
}
#[derive(Debug)]
pub(super) struct Runtime<B> {
    pub pipes: Vec<Pipe<B>>,
    pub received: VecDeque<(u8, Vec<u8>)>,
    pub wmi_memory: Option<Vec<B>>,
    pub management_memory: Option<crate::ath10k::wmi_runtime::management::Pool<B>>,
    pub htt_memory: Option<crate::ath10k::htt_runtime::storage::Storage<B>>,
}
impl<B: Memory> Runtime<B> {
    pub fn allocate(
        hw: HwRev,
        mut allocate: impl FnMut(usize) -> Result<B, BmiError>,
    ) -> Result<Self, BmiError> {
        let mut pipes = Vec::new();
        pipes.try_reserve_exact(5).map_err(|_| BmiError::NoMemory)?;
        // Linux pci_host_ce_config_wlan + ath10k_pci_override_ce_config.
        // QCA6174/9377 CE5 is disabled on the HOST, not a new source pipe.
        for (number, direction, entries, maximum) in [
            (2, Direction::Destination, 128, 2048),
            (3, Direction::Source, 32, 2048),
            (4, Direction::Source, 8192, 256),
            (5, Direction::Destination, 512, 512),
            (8, Direction::Destination, 128, 2048),
        ] {
            if number == 5 && matches!(hw, HwRev::Qca6174 | HwRev::Qca9377) {
                continue;
            }
            if number == 8 && hw.registers().ok_or(BmiError::Unsupported)?.ce_count < 12 {
                continue;
            }
            let ring = Ring::new(
                allocate(entries as usize * 8)?,
                hw,
                number,
                entries,
                direction,
            )?;
            let buffer = allocate(maximum as usize)?;
            pipes.push(Pipe {
                number,
                direction,
                maximum,
                ring,
                buffer,
                pending: None,
            });
        }
        Ok(Self {
            pipes,
            received: VecDeque::new(),
            wmi_memory: None,
            management_memory: None,
            htt_memory: None,
        })
    }
    pub fn initialize(&mut self, io: &mut impl Ath10kMmio, hw: HwRev) -> Result<(), BmiError> {
        for pipe in &mut self.pipes {
            pipe.ring.initialize(io, hw, pipe.number, pipe.maximum)?;
            if pipe.direction == Direction::Destination {
                pipe.ring
                    .post(io, pipe.buffer.dma_address() as u32, pipe.maximum)?;
            }
        }
        Ok(())
    }
    pub fn poll(&mut self, io: &mut impl Ath10kMmio) -> Result<(), BmiError> {
        for pipe in &mut self.pipes {
            if pipe.direction == Direction::Source && pipe.pending.is_some() {
                source_ready(pipe, io)?;
            }
            if pipe.direction == Direction::Destination {
                if let Some(frame) = receive(&mut pipe.ring, &mut pipe.buffer, io, pipe.maximum)? {
                    if self.received.len() >= 32 {
                        return Err(BmiError::BadResponse);
                    }
                    self.received
                        .try_reserve(1)
                        .map_err(|_| BmiError::NoMemory)?;
                    self.received.push_back((pipe.number, frame));
                }
            }
        }
        Ok(())
    }
}
fn source_ready<B: Memory>(pipe: &mut Pipe<B>, io: &mut impl Ath10kMmio) -> Result<bool, BmiError> {
    if let Some(deadline) = pipe.pending {
        if pipe.ring.completion(io)?.is_some() {
            pipe.pending = None;
        } else if deadline.expired() {
            return Err(BmiError::Timeout);
        }
    }
    Ok(pipe.pending.is_none() && !pipe.ring.busy())
}
fn begin_send<B: Memory>(
    pipe: &mut Pipe<B>,
    io: &mut impl Ath10kMmio,
    bytes: &[u8],
) -> Result<(), BmiError> {
    if !io.authorized() {
        return Err(BmiError::Pci);
    }
    if !source_ready(pipe, io)? {
        return Err(super::super::dma::DmaError::Busy.into());
    }
    if bytes.is_empty() || bytes.len() > pipe.buffer.len() {
        return Err(BmiError::BadResponse);
    }
    // Occupancy is checked before touching the still-device-owned bounce.
    // Store the terminal deadline before any descriptor becomes visible.
    pipe.pending = Some(narf_time::Deadline::after_ms(3000));
    for (at, &byte) in bytes.iter().enumerate() {
        pipe.buffer.write(at, byte);
    }
    barrier();
    pipe.ring
        .post(io, pipe.buffer.dma_address() as u32, bytes.len() as u16)?;
    Ok(())
}
fn receive<B: Memory>(
    ring: &mut Ring<B>,
    buffer: &mut B,
    io: &mut impl Ath10kMmio,
    capacity: u16,
) -> Result<Option<Vec<u8>>, BmiError> {
    let Some(count) = ring.completion(io)? else {
        return Ok(None);
    };
    let mut frame = Vec::new();
    frame
        .try_reserve_exact(count as usize)
        .map_err(|_| BmiError::NoMemory)?;
    for offset in 0..count as usize {
        frame.push(buffer.read(offset));
    }
    ring.post(io, buffer.dma_address() as u32, capacity)?;
    Ok(Some(frame))
}
async fn send<B: Memory>(
    ring: &mut Ring<B>,
    buffer: &mut B,
    io: &mut impl Ath10kMmio,
    poisoned: &mut bool,
    bytes: &[u8],
) -> Result<(), BmiError> {
    if !io.authorized() {
        return Err(BmiError::Pci);
    }
    if *poisoned || bytes.is_empty() || bytes.len() > buffer.len() {
        return Err(BmiError::BadResponse);
    }
    if ring.busy() {
        return Err(crate::ath10k::dma::DmaError::Busy.into());
    }
    *poisoned = true; // Cancellation cannot turn a pending DMA buffer reusable.
    for (offset, &byte) in bytes.iter().enumerate() {
        buffer.write(offset, byte);
    }
    barrier();
    ring.post(io, buffer.dma_address() as u32, bytes.len() as u16)?;
    let deadline = narf_time::Deadline::after_ms(3000);
    loop {
        if ring.completion(io)?.is_some() {
            *poisoned = false;
            return Ok(());
        }
        if deadline.expired() {
            return Err(BmiError::Timeout);
        }
        PciBoot::delay(1).await;
    }
}

impl PciBoot {
    pub fn hif_source_ready(&mut self, number: u8) -> Result<bool, BmiError> {
        if !self.mmio.authorized() || self.poisoned || !self.hif_live {
            return Err(BmiError::Pci);
        }
        let pipe = self
            .hif
            .as_mut()
            .ok_or(BmiError::BadResponse)?
            .pipes
            .iter_mut()
            .find(|p| p.number == number && p.direction == Direction::Source)
            .ok_or(BmiError::Unsupported)?;
        let result = source_ready(pipe, &mut self.mmio);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn hif_begin_send(&mut self, number: u8, bytes: &[u8]) -> Result<(), BmiError> {
        if !self.mmio.authorized() || self.poisoned || !self.hif_live {
            return Err(BmiError::Pci);
        }
        let pipe = self
            .hif
            .as_mut()
            .ok_or(BmiError::BadResponse)?
            .pipes
            .iter_mut()
            .find(|p| p.number == number && p.direction == Direction::Source)
            .ok_or(BmiError::Unsupported)?;
        let result = begin_send(pipe, &mut self.mmio, bytes);
        if result.is_err_and(|e| e != BmiError::Dma(crate::ath10k::dma::DmaError::Busy)) {
            self.poisoned = true;
        }
        result
    }
    fn poll_packets(&mut self) -> Result<Option<(u8, Vec<u8>)>, BmiError> {
        if !self.mmio.authorized() {
            return Err(BmiError::Pci);
        }
        let hif = self.hif.as_mut().ok_or(BmiError::BadResponse)?;
        hif.poll(&mut self.mmio)?;
        let resources = &mut *self.resources;
        if let Some(frame) = receive(
            &mut resources.rx,
            &mut resources.response,
            &mut self.mmio,
            2048,
        )? {
            if hif.received.len() >= 32 {
                return Err(BmiError::BadResponse);
            }
            hif.received
                .try_reserve(1)
                .map_err(|_| BmiError::NoMemory)?;
            hif.received.push_back((1, frame));
        }
        Ok(hif.received.pop_front())
    }
    pub fn hif_poll_now(&mut self) -> Result<Option<(u8, Vec<u8>)>, BmiError> {
        if self.poisoned || !self.hif_live || self.hif.is_none() {
            return Err(BmiError::BadResponse);
        }
        self.poisoned = true;
        let result = self.poll_packets();
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    pub fn prepare_hif(&mut self) -> Result<(), BmiError> {
        if !self.mmio.authorized() {
            return Err(BmiError::Pci);
        }
        if !self.power_ready || self.poisoned || self.hif.is_some() {
            return Err(BmiError::BadResponse);
        }
        let runtime = Runtime::allocate(self.hardware, allocate)?;
        // Store all allocations under fail-safe Drop before the first fallible
        // ring-base write. A partially initialized attempt must never free them.
        *self.hif = Some(runtime);
        self.poisoned = true;
        self.hif
            .as_mut()
            .unwrap()
            .initialize(&mut self.mmio, self.hardware)?;
        let address = self.resources.response.dma_address() as u32;
        self.resources.rx.post(&mut self.mmio, address, 2048)?;
        if !self.mmio.authorized() {
            return Err(BmiError::Pci);
        }
        self.poisoned = false;
        Ok(())
    }
    pub async fn hif_send(&mut self, pipe: u8, bytes: &[u8]) -> Result<(), BmiError> {
        if !self.mmio.authorized() {
            return Err(BmiError::Pci);
        }
        if !self.hif_live || self.hif.is_none() {
            return Err(BmiError::Unsupported);
        }
        if pipe == 0 {
            let resources = &mut *self.resources;
            return send(
                &mut resources.tx,
                &mut resources.request,
                &mut self.mmio,
                &mut self.poisoned,
                bytes,
            )
            .await;
        }
        let port = self
            .hif
            .as_mut()
            .unwrap()
            .pipes
            .iter_mut()
            .find(|p| p.number == pipe && p.direction == Direction::Source)
            .ok_or(BmiError::Unsupported)?;
        if !source_ready(port, &mut self.mmio)? {
            return Err(crate::ath10k::dma::DmaError::Busy.into());
        }
        send(
            &mut port.ring,
            &mut port.buffer,
            &mut self.mmio,
            &mut self.poisoned,
            bytes,
        )
        .await
    }
    pub async fn hif_receive(&mut self, budget_ms: u64) -> Result<(u8, Vec<u8>), BmiError> {
        match self.hif_poll(budget_ms).await? {
            Some(frame) => Ok(frame),
            None => {
                self.poisoned = true;
                Err(BmiError::Timeout)
            }
        }
    }
    pub async fn hif_poll(&mut self, budget_ms: u64) -> Result<Option<(u8, Vec<u8>)>, BmiError> {
        if !self.mmio.authorized() {
            return Err(BmiError::Pci);
        }
        if self.poisoned || !self.hif_live || self.hif.is_none() {
            return Err(BmiError::BadResponse);
        }
        self.poisoned = true; // A cancelled protocol wait requires reset, not replay.
        let deadline = narf_time::Deadline::after_ms(budget_ms);
        loop {
            if let Some(frame) = self.poll_packets()? {
                self.poisoned = false;
                return Ok(Some(frame));
            }
            if deadline.expired() {
                self.poisoned = false;
                return Ok(None);
            }
            PciBoot::delay(1).await;
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "hif/tests.rs"]
pub(super) mod tests;
