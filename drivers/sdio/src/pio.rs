//! Owned SDHCI command/PIO execution. Linux reference: sdhci.c
//! sdhci_send_command, sdhci_transfer_pio and the block PIO helpers.
//! PIO keeps PCI bus mastering disabled and has no borrowed DMA lifetime.

use crate::sdhci::regs::*;
use narf_time::Deadline;

const COMMAND_TIMEOUT_US: u64 = 100_000;
const TRANSFER_TIMEOUT_US: u64 = 1_000_000;
pub const MAX_TRANSFER: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    Failed,
    Gone,
    Timeout,
    Controller(u32),
    Card(u8),
    ShortTransfer,
}

/// Immutable identity captured by the exclusive host owner; no I/O authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostIdentity {
    pub address: narf_bus::BusAddr,
    pub id: narf_bus::DeviceId,
}
/// An owned register aperture. Accessors use the exact SDHCI register width.
/// All waits are deadline-bounded and feed the scheduler's common pumps.
pub trait Registers {
    /// Immutable host facts captured by its exclusive platform/PCI owner.
    /// This supplies no register handle or authority and configures no wiring.
    fn host_identity(&self) -> Option<HostIdentity> {
        None
    }
    fn read8(&mut self, offset: u32) -> u8;
    fn read16(&mut self, offset: u32) -> u16;
    fn read32(&mut self, offset: u32) -> u32;
    fn write8(&mut self, offset: u32, value: u8);
    fn write16(&mut self, offset: u32, value: u16);
    fn write32(&mut self, offset: u32, value: u32);
}

#[derive(Clone, Copy, Debug)]
pub enum Response {
    None,
    R4,
    Short,
    R5,
    Busy,
}

#[derive(Debug)]
pub enum Data<'a> {
    Read {
        bytes: &'a mut [u8],
        block_size: u16,
    },
    Write {
        bytes: &'a [u8],
        block_size: u16,
    },
}
impl Data<'_> {
    fn shape(&self) -> (usize, u16, bool) {
        match self {
            Self::Read { bytes, block_size } => (bytes.len(), *block_size, true),
            Self::Write { bytes, block_size } => (bytes.len(), *block_size, false),
        }
    }
}

pub struct Controller<R: Registers> {
    io: R,
    failed: bool,
}
impl<R: Registers> core::fmt::Debug for Controller<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdhciPio")
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<R: Registers> Controller<R> {
    /// Caller has exclusively mapped/reset the controller, established
    /// power/clock and left DMA disabled. This value owns every command.
    pub fn new(io: R) -> Self {
        Self { io, failed: false }
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }
    pub fn registers(&mut self) -> &mut R {
        &mut self.io
    }
    pub fn host_identity(&self) -> Option<HostIdentity> {
        self.io.host_identity()
    }

    pub(crate) fn wait(
        &mut self,
        deadline: Deadline,
        mut condition: impl FnMut(&mut R) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        let mut failure = None;
        let complete = narf_scheduler::responsive_spin_until(
            || match condition(&mut self.io) {
                Ok(ready) => ready,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
            deadline,
        );
        if let Some(error) = failure {
            Err(error)
        } else if complete {
            Ok(())
        } else {
            Err(Error::Timeout)
        }
    }

    fn status(io: &mut R) -> Result<u32, Error> {
        let status = io.read32(INT_STATUS);
        if status == u32::MAX {
            return Err(Error::Gone);
        }
        if status & (INT_ERROR | 0xffff_0000) != 0 {
            return Err(Error::Controller(status));
        }
        Ok(status)
    }

    /// Complete one command and optional PIO transfer. A hardware error is
    /// terminal: reset/reselect is required before another command, including
    /// after a FIFO write that may have been partly accepted by the card.
    pub fn execute(
        &mut self,
        command: u8,
        argument: u32,
        response: Response,
        mut data: Option<Data<'_>>,
    ) -> Result<u32, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if command > 63 {
            return Err(Error::Invalid);
        }
        let shape = data.as_ref().map(Data::shape);
        if let Some((len, block, _)) = shape {
            if len == 0
                || len > MAX_TRANSFER
                || block == 0
                || block > 512
                || len % block as usize != 0
                || len / block as usize > 511
            {
                return Err(Error::Invalid);
            }
        }
        let result = self.execute_inner(command, argument, response, &mut data, shape);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn execute_inner(
        &mut self,
        command: u8,
        argument: u32,
        response: Response,
        data: &mut Option<Data<'_>>,
        shape: Option<(usize, u16, bool)>,
    ) -> Result<u32, Error> {
        let inhibit = PS_CMD_INHIBIT
            | if shape.is_some() || matches!(response, Response::Busy) {
                PS_DATA_INHIBIT
            } else {
                0
            };
        self.wait(Deadline::after_us(COMMAND_TIMEOUT_US), |io| {
            let present = io.read32(PRESENT_STATE);
            if present == u32::MAX {
                Err(Error::Gone)
            } else {
                Ok(present & inhibit == 0)
            }
        })?;
        // Clear only command/data completion state; preserve card insertion,
        // removal and SDIO card-interrupt state for their owning lifecycle.
        Self::status(&mut self.io)?;
        self.io
            .write32(INT_STATUS, INT_CMD_MASK | INT_DATA_MASK | INT_ERROR);
        self.io.write8(TIMEOUT_CONTROL, 0x0e);
        let mut flags = match response {
            Response::None => CMD_RESP_NONE,
            Response::R4 => CMD_RESP_SHORT, // CMD5 R4 has no CRC/opcode.
            Response::Short | Response::R5 => CMD_RESP_SHORT | CMD_CRC | CMD_INDEX,
            Response::Busy => CMD_RESP_SHORT_BUSY | CMD_CRC | CMD_INDEX,
        };
        let mut mode = 0;
        if let Some((len, block_size, read)) = shape {
            let blocks = len / block_size as usize;
            self.io.write16(BLOCK_SIZE, block_size);
            self.io.write16(BLOCK_COUNT, blocks as u16);
            mode = TRNS_BLK_CNT_EN
                | if read { TRNS_READ } else { 0 }
                | if blocks > 1 { TRNS_MULTI } else { 0 };
            flags |= CMD_DATA;
        }
        // SDIO CMD53 never uses the memory-card auto-CMD12/CMD23 paths.
        self.io.write32(ARGUMENT, argument);
        self.io.write16(TRANSFER_MODE, mode);
        self.io.write16(COMMAND, make_cmd(command, flags));
        self.wait(Deadline::after_us(COMMAND_TIMEOUT_US), |io| {
            Ok(Self::status(io)? & INT_RESPONSE != 0)
        })?;
        let result = if matches!(response, Response::None) {
            0
        } else {
            self.io.read32(RESPONSE)
        };
        self.io.write32(INT_STATUS, INT_RESPONSE);
        // An R5 rejection precedes any FIFO access, even if the host also
        // reports a buffer-ready bit. Never write bytes for a rejected CMD53.
        let flags = crate::sdhci::cmd::r5_flags(result);
        if matches!(response, Response::R5) && crate::sdhci::cmd::r5_is_error(flags) {
            return Err(Error::Card(flags));
        }
        let deadline = Deadline::after_us(TRANSFER_TIMEOUT_US);
        if let Some((len, block_size, read)) = shape {
            let size = block_size as usize;
            for offset in (0..len).step_by(size) {
                let ready = if read { PS_DATA_AVAIL } else { PS_SPACE_AVAIL };
                self.wait(deadline, |io| {
                    let status = Self::status(io)?;
                    let present = io.read32(PRESENT_STATE);
                    if present == u32::MAX {
                        return Err(Error::Gone);
                    }
                    if present & ready != 0 {
                        return Ok(true);
                    }
                    if status & INT_DATA_END != 0 {
                        return Err(Error::ShortTransfer);
                    }
                    Ok(false)
                })?;
                match data.as_mut().unwrap() {
                    Data::Read { bytes, .. } => {
                        for chunk in bytes[offset..offset + size].chunks_mut(4) {
                            let word = self.io.read32(BUFFER).to_le_bytes();
                            chunk.copy_from_slice(&word[..chunk.len()]);
                        }
                    }
                    Data::Write { bytes, .. } => {
                        for chunk in bytes[offset..offset + size].chunks(4) {
                            let mut word = [0; 4];
                            word[..chunk.len()].copy_from_slice(chunk);
                            self.io.write32(BUFFER, u32::from_le_bytes(word));
                        }
                    }
                }
                self.io.write32(
                    INT_STATUS,
                    if read {
                        INT_DATA_AVAIL
                    } else {
                        INT_SPACE_AVAIL
                    },
                );
            }
        }
        if shape.is_some() || matches!(response, Response::Busy) {
            self.wait(deadline, |io| Ok(Self::status(io)? & INT_DATA_END != 0))?;
            self.io.write32(INT_STATUS, INT_DATA_END);
        }
        Ok(result)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "pio_tests.rs"]
mod tests;
