// SPDX-License-Identifier: MIT
// Protocol port from cyw43-driver fa9627e6076c61b58632289a36fcab4811f32c3a.
// Copyright (C) 2019-2026 George Robotics Pty Ltd
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//! Whole-CS CYW43 gSPI protocol. No native source/selection/stop is minted here.

use alloc::{boxed::Box, sync::Arc};
use narf_drivers_spi::{
    SpiBus, SpiClaimError, SpiDevice, SpiDeviceConfig, SpiError, SpiMode, SpiWiring,
};

use super::super::gspi::{self, AddrMode, CommandWord, Direction, ADDR_MASK};
use super::super::transport::{Function, LoaderMode, PacketTransport, Transport, TransportError};
use super::PortError;

const F1_LIMIT: usize = 64;
const READ_PAD: usize = 16;
const RX_LIMIT: usize = 1536;
const TX_LIMIT: usize = 2040;
const IRQ: u32 = 4;
const IRQ_ERRORS: u16 = 0x009f;
const STATUS: u32 = 8;
const STATUS_ERRORS: u32 = 0x87;
const F2_READY: u32 = 0x20;
const PACKET_AVAILABLE: u32 = 0x100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Cold,
    Ready,
    Failed,
}

/// A protocol session over a host that actually provides the whole-transaction
/// contract. Construction does not reset/power the chip or establish a signed
/// native identity. The original platform owner must reset before startup.
#[derive(Debug)]
pub struct GspiTransport {
    bus: Arc<dyn SpiBus>,
    device: Box<dyn SpiDevice>,
    cs: u8,
    state: State,
    packets_ready: bool,
    rx_continuation: bool,
}

impl GspiTransport {
    pub fn new(
        bus: Arc<dyn SpiBus>,
        cs: u8,
        mode: SpiMode,
        freq_hz: u32,
    ) -> Result<Self, PortError> {
        // This port implements the source's mode-0/shared-pad/wake-high profile.
        // A different electrical profile needs its own actual producer.
        if mode != SpiMode::Mode0 || freq_hz == 0 {
            return Err(PortError::Spi(SpiError::FrequencyOutOfRange));
        }
        let device = bus
            .claim_device(SpiDeviceConfig {
                mode,
                freq_hz,
                cs,
                wiring: SpiWiring::SharedData,
                post_cs_delay_ns: 100,
            })
            .map_err(|error| match error {
                SpiClaimError::Unsupported => PortError::TransactionUnavailable,
                SpiClaimError::Busy => PortError::BusClaimed,
                SpiClaimError::Bus(error) => PortError::Spi(error),
            })?;
        Ok(Self {
            bus,
            device,
            cs,
            state: State::Cold,
            packets_ready: false,
            rx_continuation: false,
        })
    }

    pub fn bus_name(&self) -> &str {
        self.bus.name()
    }
    pub fn cs(&self) -> u8 {
        self.cs
    }

    fn wire(&mut self, write: &[u8], read: &mut [u8]) -> Result<(), TransportError> {
        if self.state == State::Failed {
            return Err(TransportError::NotReady);
        }
        self.device.transaction(write, read).map_err(|error| {
            // A command may already have reached the chip. Never replay it,
            // including when the host reports timeout after partial emission.
            self.state = State::Failed;
            match error {
                SpiError::Timeout => TransportError::Timeout,
                SpiError::BufferTooLarge => TransportError::LengthOverflow,
                SpiError::HwError(code) => TransportError::Other(code),
                _ => TransportError::NotReady,
            }
        })
    }

    fn fail<T>(&mut self, error: TransportError) -> Result<T, TransportError> {
        self.state = State::Failed;
        Err(error)
    }

    /// One-shot 16-bit bootstrap -> normal 32-bit profile. It may only follow
    /// the original owner's actual reset. A failed transition is terminal.
    pub fn initialize_link(&mut self) -> Result<(), TransportError> {
        if self.state != State::Cold {
            return Err(TransportError::NotReady);
        }
        let mut bootstrap = [0u8; 4];
        self.wire(&[0xa0, 0x04, 0x40, 0x00], &mut bootstrap)?;
        if bootstrap != [0xbe, 0xad, 0xfe, 0xed] {
            return self.fail(TransportError::BadFraming);
        }
        self.wire(&[0x00, 0x04, 0xc0, 0x00, 0x04, 0xb3, 0x00, 0x02], &mut [])?;
        self.state = State::Ready;
        if !self.probe_link()? || self.read32(Function::Bus, 0)? != 0x0002_04b3 {
            return self.fail(TransportError::BadFraming);
        }
        self.write_burst(Function::Bus, 0x1d, &[READ_PAD as u8])?;
        self.write_burst(Function::Bus, IRQ, &[0x99])?;
        self.write_burst(Function::Bus, 6, &[0xbe, 0])?;
        Ok(())
    }

    pub fn probe_link(&mut self) -> Result<bool, TransportError> {
        Ok(self.read32(Function::Bus, gspi::REG_TEST_RO)? == gspi::TEST_RO_PATTERN)
    }

    fn access(
        &mut self,
        function: Function,
        address: u32,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<(), TransportError> {
        if self.state != State::Ready {
            return Err(TransportError::NotReady);
        }
        let read = !output.is_empty();
        let len = input.len().max(output.len());
        if len == 0 || len > usize::from(gspi::MAX_LEN) {
            return Err(TransportError::LengthOverflow);
        }
        if function == Function::Bt {
            return Err(TransportError::NotReady);
        }
        if function == Function::Backplane && len > F1_LIMIT {
            return Err(TransportError::LengthOverflow);
        }
        let command = CommandWord::new(
            if read {
                Direction::Read
            } else {
                Direction::Write
            },
            AddrMode::Increment,
            function.into(),
            address,
            len as u16,
        )
        .map_err(|error| match error {
            gspi::CommandError::AddressOverflow => TransportError::AddressOverflow,
            gspi::CommandError::LengthOverflow => TransportError::LengthOverflow,
        })?
        .encode()
        .to_le_bytes();
        let physical = (len + 3) & !3;
        if read {
            let dummy = if function == Function::Backplane {
                READ_PAD
            } else {
                0
            };
            let mut received = alloc::vec![0u8; dummy + physical];
            self.wire(&command, &mut received)?;
            output.copy_from_slice(&received[dummy..dummy + len]);
        } else {
            let mut bytes = alloc::vec![0u8; 4 + physical];
            bytes[..4].copy_from_slice(&command);
            bytes[4..4 + len].copy_from_slice(input);
            self.wire(&bytes, &mut [])?;
        }
        Ok(())
    }

    fn check_window(function: Function, address: u32, len: usize) -> Result<(), TransportError> {
        if !matches!(function, Function::Bus | Function::Backplane) {
            // F2 is a packet FIFO, never an incrementing RAM burst.
            return Err(TransportError::NotReady);
        }
        let len = u32::try_from(len).map_err(|_| TransportError::LengthOverflow)?;
        let end = address
            .checked_add(len)
            .ok_or(TransportError::AddressOverflow)?;
        if address > ADDR_MASK || end > ADDR_MASK + 1 {
            return Err(TransportError::AddressOverflow);
        }
        if function == Function::Backplane && address < 0x10000 {
            // Bit15 is the RAM access flag, not another window. Normalize
            // already-flagged addresses before bounding the complete burst;
            // chunking must never carry into the F1 local-register region.
            let offset = address & 0x7fff;
            if len > 0x8000 - offset {
                return Err(TransportError::AddressOverflow);
            }
        }
        Ok(())
    }

    fn status(&mut self) -> Result<u32, TransportError> {
        let status = self.read32(Function::Bus, STATUS)?;
        if status == u32::MAX {
            return self.fail(TransportError::NotReady);
        }
        Ok(status)
    }

    fn abort_frame(&mut self, error: TransportError) -> Result<usize, TransportError> {
        // Source SPI_FRAME_CONTROL read-frame abort. Even a successful abort
        // is not a recovery/stop receipt for an uncertain packet generation.
        self.write_burst(Function::Backplane, 0x1000d, &[1])?;
        self.fail(error)
    }

    /// The loader alone establishes boot-ready before consuming the source's
    /// single initial control credit. SDIO's Runtime::new remains zero-credit.
    pub(in crate::cyw43439) fn into_booted_runtime(
        self,
    ) -> Result<super::super::runtime::Runtime<GspiPackets>, TransportError> {
        if !self.packets_ready || self.state != State::Ready {
            return Err(TransportError::NotReady);
        }
        Ok(super::super::runtime::Runtime::new_gspi(GspiPackets(self)))
    }
}

impl Transport for GspiTransport {
    fn loader_mode(&self) -> LoaderMode {
        LoaderMode::Gspi
    }
    fn initialize_gspi(&mut self) -> Result<(), TransportError> {
        self.initialize_link()
    }
    fn finish_gspi_boot(&mut self) -> Result<(), TransportError> {
        if self.state != State::Ready || self.packets_ready {
            return Err(TransportError::NotReady);
        }
        self.write_burst(Function::Backplane, 0x10008, &[32])?;
        let mut failure = None;
        let ready = narf_scheduler::responsive_spin_until(
            || match self.status() {
                Ok(status) if status & STATUS_ERRORS != 0 => {
                    failure = Some(TransportError::ChipFlowError);
                    true
                }
                Ok(status) => status & F2_READY != 0,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_ms(1000),
        );
        if let Some(error) = failure {
            return self.fail(error);
        }
        if !ready {
            return self.fail(TransportError::Timeout);
        }
        self.packets_ready = true;
        Ok(())
    }
    fn read32(&mut self, function: Function, address: u32) -> Result<u32, TransportError> {
        Self::check_window(function, address, 4)?;
        let mut data = [0; 4];
        let address = if function == Function::Backplane && address < 0x8000 {
            address | 0x8000
        } else {
            address
        };
        self.access(function, address, &[], &mut data)?;
        Ok(u32::from_le_bytes(data))
    }
    fn write32(
        &mut self,
        function: Function,
        address: u32,
        value: u32,
    ) -> Result<(), TransportError> {
        Self::check_window(function, address, 4)?;
        let address = if function == Function::Backplane && address < 0x8000 {
            address | 0x8000
        } else {
            address
        };
        self.access(function, address, &value.to_le_bytes(), &mut [])
    }
    fn read_burst(
        &mut self,
        function: Function,
        address: u32,
        buffer: &mut [u8],
    ) -> Result<(), TransportError> {
        Self::check_window(function, address, buffer.len())?;
        let address = if function == Function::Backplane && address < 0x8000 {
            address | 0x8000
        } else {
            address
        };
        for (index, part) in buffer.chunks_mut(F1_LIMIT).enumerate() {
            self.access(function, address + (index * F1_LIMIT) as u32, &[], part)?;
        }
        Ok(())
    }
    fn write_burst(
        &mut self,
        function: Function,
        address: u32,
        buffer: &[u8],
    ) -> Result<(), TransportError> {
        Self::check_window(function, address, buffer.len())?;
        let address = if function == Function::Backplane && address < 0x8000 {
            address | 0x8000
        } else {
            address
        };
        for (index, part) in buffer.chunks(F1_LIMIT).enumerate() {
            self.access(function, address + (index * F1_LIMIT) as u32, part, &mut [])?;
        }
        Ok(())
    }
}

impl GspiTransport {
    fn receive_packet_inner(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        if self.state != State::Ready || !self.packets_ready {
            return Err(TransportError::NotReady);
        }
        if !self.rx_continuation {
            let mut irq = [0u8; 2];
            self.read_burst(Function::Bus, IRQ, &mut irq)?;
            let pending = u16::from_le_bytes(irq);
            if pending == u16::MAX {
                return self.fail(TransportError::NotReady);
            }
            if pending != 0 {
                self.write_burst(Function::Bus, IRQ, &irq)?;
            }
            if pending & IRQ_ERRORS != 0 {
                return self.abort_frame(TransportError::ChipFlowError);
            }
            if pending & 0x20 == 0 {
                return Ok(0);
            }
        }
        let status = self.status()?;
        if status & STATUS_ERRORS != 0 {
            return self.abort_frame(TransportError::ChipFlowError);
        }
        if status & PACKET_AVAILABLE == 0 {
            self.rx_continuation = false;
            return Ok(0);
        }
        let len = ((status >> 9) & 0x7ff) as usize;
        if !(12..=RX_LIMIT).contains(&len) {
            return self.abort_frame(TransportError::BadFraming);
        }
        if len > buffer.len() {
            return self.abort_frame(TransportError::LengthOverflow);
        }
        self.access(Function::Wlan, 0, &[], &mut buffer[..len])?;
        let size = u16::from_le_bytes([buffer[0], buffer[1]]) as usize;
        let complement = u16::from_le_bytes([buffer[2], buffer[3]]);
        if size < 12 || size > len || (size as u16) ^ complement != u16::MAX {
            return self.fail(TransportError::BadFraming);
        }
        self.rx_continuation = true;
        Ok(len)
    }
    fn transmit_packet_inner(&mut self, packet: &[u8]) -> Result<(), TransportError> {
        if self.state != State::Ready || !self.packets_ready {
            return Err(TransportError::NotReady);
        }
        if !(12..=TX_LIMIT).contains(&packet.len()) {
            return Err(TransportError::LengthOverflow);
        }
        let status = self.status()?;
        if status & STATUS_ERRORS != 0 {
            return self.fail(TransportError::ChipFlowError);
        }
        if status & F2_READY == 0 {
            return Err(TransportError::Busy); // No F2 command emitted.
        }
        self.access(Function::Wlan, 0, packet, &mut [])
    }
}

// Kept inside the CYW protocol implementation: no native gSPI host/selected
// source exists yet. Public register diagnostics cannot be attached as a station.
#[derive(Debug)]
pub(in crate::cyw43439) struct GspiPackets(GspiTransport);
impl Transport for GspiPackets {
    fn loader_mode(&self) -> LoaderMode {
        LoaderMode::Gspi
    }
    fn read32(&mut self, f: Function, a: u32) -> Result<u32, TransportError> {
        self.0.read32(f, a)
    }
    fn write32(&mut self, f: Function, a: u32, v: u32) -> Result<(), TransportError> {
        self.0.write32(f, a, v)
    }
    fn read_burst(&mut self, f: Function, a: u32, b: &mut [u8]) -> Result<(), TransportError> {
        self.0.read_burst(f, a, b)
    }
    fn write_burst(&mut self, f: Function, a: u32, b: &[u8]) -> Result<(), TransportError> {
        self.0.write_burst(f, a, b)
    }
}
impl PacketTransport for GspiPackets {
    fn receive_packet(&mut self, b: &mut [u8]) -> Result<usize, TransportError> {
        self.0.receive_packet_inner(b)
    }
    fn transmit_packet(&mut self, b: &[u8]) -> Result<(), TransportError> {
        self.0.transmit_packet_inner(b)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "gspi_port_tests.rs"]
mod tests;
