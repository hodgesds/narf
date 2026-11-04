//! Owned SDHCI command/PIO execution. Linux reference: sdhci.c
//! sdhci_send_command, sdhci_transfer_pio and the block PIO helpers.
//! PIO keeps PCI bus mastering disabled and has no borrowed DMA lifetime.
//! When the platform owner grants bus mastering ([`Registers::enable_dma`])
//! and the host advertises ADMA2/SDMA, data commands instead run through
//! the host DMA engine (`crate::dma`) with a host-owned bounce buffer;
//! caller slices are still copied before return.

use crate::sdhci::regs::*;
use narf_time::Deadline;

#[path = "pio_publication.rs"]
mod publication;
pub use publication::Publication;

const COMMAND_TIMEOUT_US: u64 = 100_000;
const TRANSFER_TIMEOUT_US: u64 = 1_000_000;
pub const MAX_TRANSFER: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Invalid,
    /// Original fixed scope refused before actual COMMAND action.
    Denied,
    /// Native CARD_INT became pending before COMMAND; apply prefix first.
    Busy,
    Failed,
    Gone,
    Timeout,
    Controller(u32),
    Card(u8),
    ShortTransfer,
    /// `SDHCI_INT_ADMA_ERROR` with the ADMA error-status register value.
    Dma(u32),
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
    /// Opaque original native host receipt; no caller validator or lookup.
    /// Card adds its own actual Controller/Card lifetimes before use.
    fn source(&self) -> Option<crate::source::Source> {
        None
    }
    fn read8(&mut self, offset: u32) -> u8;
    fn read16(&mut self, offset: u32) -> u16;
    fn read32(&mut self, offset: u32) -> u32;
    fn write8(&mut self, offset: u32, value: u8);
    fn write16(&mut self, offset: u32, value: u16);
    fn write32(&mut self, offset: u32, value: u32);
    /// Let the function assert legacy INTx (clear PCI INTx-disable) once a
    /// oneshot line is bound. `false`: the platform cannot; keep polling.
    fn enable_intx(&mut self) -> bool {
        false
    }
    /// Host PM capabilities the platform owner grants (Linux
    /// `mmc->pm_caps`). `WAKE_SDIO_IRQ` additionally needs a bound card
    /// interrupt line (`Card` masks it otherwise). Default: none.
    fn pm_caps(&mut self) -> crate::sdio::function::PmFlags {
        crate::sdio::function::PmFlags::NONE
    }
    /// Grant host DMA: Linux `sdhci_pci_enable_dma` -> `pci_set_master`.
    /// The platform owner enables and reads back bus mastering and returns
    /// the `narf_io` DMA facts of the host function (coherence, pool,
    /// IOMMU domain), or `None` to keep PIO (no grant, a host needing DMA
    /// quirks this crate does not carry, or a failed transition).
    fn enable_dma(&mut self) -> Option<narf_io::DmaDevice> {
        None
    }
    /// Revoke the DMA grant (clear bus mastering, with readback). `true`
    /// once the host provably can no longer master; DMA buffers are only
    /// freed then. Never-enabled hosts return `true`.
    fn disable_dma(&mut self) -> bool {
        true
    }
    /// Host base clock when CAPABILITIES reports none: Linux
    /// `sdhci_setup_host` -> `ops->get_max_clock` (a platform clock rate).
    /// Default: none, and such a host stays unsupported.
    fn base_clock_hz(&mut self) -> Option<u32> {
        None
    }
    /// The SD clock just requested (Linux `host->clock` after
    /// `ops->set_clock`); front-ends whose register ops depend on it
    /// observe it here. Default: no effect.
    fn clock_changed(&mut self, _hz: u32) {}
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
    live: alloc::sync::Arc<crate::source::Lifetime>,
    /// Host DMA buffers once [`Controller::setup_dma`] admitted a mode.
    dma: Option<crate::dma::Engine>,
    /// A DMA transfer failed after COMMAND or DMA setup failed after the
    /// grant: this owner is PIO-only for the rest of its life.
    dma_fault: bool,
    /// DMA prepared for the current command (reset needed on failure).
    dma_armed: bool,
}
impl<R: Registers> Drop for Controller<R> {
    fn drop(&mut self) {
        self.live.retire();
        self.release_dma();
    }
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
        Self {
            io,
            failed: false,
            live: crate::source::Lifetime::new(),
            dma: None,
            dma_fault: false,
            dma_armed: false,
        }
    }
    /// Linux `sdhci_setup_host` DMA admission for an exclusively owned,
    /// reset host: select ADMA2 (32/64-bit) or SDMA from the capabilities
    /// ([`crate::sdhci::adma::select`]), take the platform DMA grant and
    /// allocate the coherent ADMA region and bounce buffer, falling back
    /// ADMA -> SDMA -> PIO. Idempotent; a faulted or failed owner stays PIO.
    pub fn setup_dma(&mut self, spec_version: u8, caps: u32) -> Option<crate::sdhci::adma::Mode> {
        if let Some(engine) = self.dma.as_ref() {
            return Some(engine.mode());
        }
        if self.failed || self.dma_fault {
            return None;
        }
        let mut mode = crate::sdhci::adma::select(spec_version, caps)?;
        let device = self.io.enable_dma()?;
        loop {
            match crate::dma::Engine::new(&device, mode) {
                Ok(engine) => {
                    self.dma = Some(engine);
                    return Some(mode);
                }
                Err(()) => match mode.without_adma(caps) {
                    Some(next) => mode = next,
                    None => {
                        // "No suitable DMA available - falling back to PIO".
                        self.dma_fault = true;
                        let _ = self.io.disable_dma();
                        return None;
                    }
                },
            }
        }
    }
    /// The admitted DMA mode, `None` for PIO.
    pub fn dma_mode(&self) -> Option<crate::sdhci::adma::Mode> {
        self.dma.as_ref().map(crate::dma::Engine::mode)
    }
    /// Host DMA engine state (tests and diagnostics).
    pub fn dma_engine(&self) -> Option<&crate::dma::Engine> {
        self.dma.as_ref()
    }
    /// Stop host DMA for good: revoke the grant, then free the buffers
    /// only if bus mastering is provably off; otherwise they are leaked
    /// (quarantined) so a still-mastering device cannot hit freed frames.
    fn release_dma(&mut self) {
        if let Some(engine) = self.dma.take() {
            if !self.io.disable_dma() {
                core::mem::forget(engine);
            }
        }
    }
    /// Linux `sdhci_do_reset(host, SDHCI_RESET_CMD | SDHCI_RESET_DATA)`
    /// after a failed DMA command, then PIO-only for this owner.
    fn abort_dma(&mut self) {
        self.dma_armed = false;
        self.dma_fault = true;
        if let Some(engine) = self.dma.as_mut() {
            engine.disarm();
        }
        self.io.write8(SOFTWARE_RESET, RESET_CMD | RESET_DATA);
        let _ = Self::wait_on(&mut self.io, Deadline::after_us(COMMAND_TIMEOUT_US), |io| {
            let value = io.read8(SOFTWARE_RESET);
            if value == u8::MAX {
                Err(Error::Gone)
            } else {
                Ok(value & (RESET_CMD | RESET_DATA) == 0)
            }
        });
        self.release_dma();
    }
    pub(crate) fn source(&self) -> Option<crate::source::Source> {
        if self.failed {
            return None;
        }
        self.io.source()?.retain_controller(&self.live)
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }
    /// The caller power-cycled or reset the host's command/data engines
    /// (Linux `sdhci_do_reset` after an errored request, or the card's
    /// `mmc_hw_reset`): commands may be issued again under a new lifetime.
    /// Every receipt of the previous lifetime stays retired.
    pub(crate) fn revive(&mut self) {
        self.live.retire();
        self.live = crate::source::Lifetime::new();
        self.dma_armed = false;
        self.failed = false;
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
        condition: impl FnMut(&mut R) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        Self::wait_on(&mut self.io, deadline, condition)
    }
    fn wait_on(
        io: &mut R,
        deadline: Deadline,
        mut condition: impl FnMut(&mut R) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        let mut failure = None;
        let complete = narf_scheduler::responsive_spin_until(
            || match condition(io) {
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
        data: Option<Data<'_>>,
    ) -> Result<u32, Error> {
        self.execute_mode(
            command,
            argument,
            response,
            data,
            publication::Mode {
                scope: &mut publication::Immediate,
                observe_pending: false,
            },
        )
    }
    pub fn execute_published(
        &mut self,
        command: u8,
        argument: u32,
        response: Response,
        data: Option<Data<'_>>,
        scope: &mut dyn Publication,
    ) -> Result<u32, Error> {
        self.execute_mode(
            command,
            argument,
            response,
            data,
            publication::Mode {
                scope,
                observe_pending: true,
            },
        )
    }
    fn execute_mode(
        &mut self,
        command: u8,
        argument: u32,
        response: Response,
        mut data: Option<Data<'_>>,
        mode: publication::Mode<'_>,
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
        let result = self.execute_inner(command, argument, response, &mut data, shape, mode);
        let issued = result
            .as_ref()
            .is_err_and(|error| !matches!(*error, Error::Denied | Error::Busy));
        if self.dma_armed {
            if issued {
                self.abort_dma();
            } else {
                // Refused before COMMAND: the engine never started.
                self.dma_armed = false;
                if let Some(engine) = self.dma.as_mut() {
                    engine.disarm();
                }
            }
        }
        if issued {
            self.live.retire();
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
        mode: publication::Mode<'_>,
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
        let mut transfer_mode = 0;
        // sdhci_prepare_dma: DMA for every data command once admitted; a
        // preparation failure (never issued) latches PIO for this owner.
        let mut dma = false;
        if let (Some(engine), Some(data)) = (self.dma.as_mut(), data.as_ref()) {
            if engine.prepare(&mut self.io, data).is_ok() {
                dma = true;
                self.dma_armed = true;
            } else {
                self.dma_fault = true;
                self.release_dma();
            }
        }
        if let Some((len, block_size, read)) = shape {
            let blocks = len / block_size as usize;
            if dma {
                // Linux sdhci_set_block_info: SDMA boundary + block size.
                self.io
                    .write16(BLOCK_SIZE, make_blksz(DEFAULT_BOUNDARY_ARG, block_size));
            } else {
                if self.dma_mode().is_some() || self.dma_fault {
                    // sdhci_config_dma: always clear the DMA select for PIO.
                    let control = self.io.read8(HOST_CONTROL);
                    self.io.write8(HOST_CONTROL, control & !CTRL_DMA_MASK);
                }
                self.io.write16(BLOCK_SIZE, block_size);
            }
            self.io.write16(BLOCK_COUNT, blocks as u16);
            transfer_mode = TRNS_BLK_CNT_EN
                | if read { TRNS_READ } else { 0 }
                | if blocks > 1 { TRNS_MULTI } else { 0 }
                | if dma { TRNS_DMA } else { 0 };
            flags |= CMD_DATA;
        }
        // SDIO CMD53 never uses the memory-card auto-CMD12/CMD23 paths.
        self.io.write32(ARGUMENT, argument);
        self.io.write16(TRANSFER_MODE, transfer_mode);
        publication::issue(&mut self.io, make_cmd(command, flags), mode)?;
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
        if dma {
            return self.finish_dma(deadline, data, result);
        }
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

    /// `sdhci_data_irq` for a DMA data command: wait for transfer complete,
    /// restarting SDMA at buffer boundaries, with `SDHCI_INT_ADMA_ERROR`
    /// reported as [`Error::Dma`]; then `sdhci_request_done` copy-out.
    fn finish_dma(
        &mut self,
        deadline: Deadline,
        data: &mut Option<Data<'_>>,
        result: u32,
    ) -> Result<u32, Error> {
        let Some(engine) = self.dma.as_mut() else {
            return Err(Error::Failed);
        };
        Self::wait_on(&mut self.io, deadline, |io| {
            let status = io.read32(INT_STATUS);
            if status == u32::MAX {
                return Err(Error::Gone);
            }
            if status & INT_ADMA_ERROR != 0 {
                return Err(Error::Dma(io.read32(ADMA_ERROR)));
            }
            if status & (INT_ERROR | 0xffff_0000) != 0 {
                return Err(Error::Controller(status));
            }
            if status & INT_DMA_END != 0 {
                engine.sdma_boundary(io);
                io.write32(INT_STATUS, INT_DMA_END);
            }
            Ok(status & INT_DATA_END != 0)
        })?;
        self.io.write32(INT_STATUS, INT_DATA_END | INT_DMA_END);
        if let Some(data) = data.as_mut() {
            engine.complete(data);
        }
        self.dma_armed = false;
        Ok(result)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "pio_tests.rs"]
mod tests;
