// SPDX-License-Identifier: GPL-2.0-or-later
//! CYW43439 additional host ports: gSPI + platform SDIO enumeration/wiring.
//!
//! This is step 1 of the `additional_host_ports` TSV row. The retained
//! profile until now is standard PCI SDHCI (see the spec §6: "A non-PCI
//! platform additionally needs its real host/wiring owner; standard PCI
//! selection does not implement Pico W gSPI"). This module supplies the
//! port layer for the other two kinds:
//!
//! - **gSPI** (`SpiGspi`): a real `Transport` over a registered
//!   `narf_drivers_spi::SpiBus`, using the landed [`super::gspi`]
//!   command-word codec. It covers register/RAM access — the path the
//!   firmware loader needs — plus a link probe. Packet service over
//!   gSPI is NOT implemented here (see below).
//! - **Platform SDHCI** (`PlatformSdhci`): described but NOT openable
//!   yet. Its blocker is named precisely below; this lane does not
//!   invent around it.
//!
//! ## F21 boundary (held decision, not decided here)
//!
//! Platform clock/pin mux, regulator, and WL_REG_ON/reset authority
//! remain with the actual platform owner. This module never configures
//! them: bus mode, frequency, chip-select, and MMIO base are
//! caller-supplied platform facts, and a port never infers a chip's
//! presence from a MANFID or a firmware filename. Presence is proven
//! by [`GspiTransport::probe_link`] plus chip identification through
//! the firmware-loader path, never by enumeration alone.
//!
//! ## Grounding
//!
//! - gSPI framing: CYW43439 datasheet §6.4, via the landed
//!   [`super::gspi`] codec (command-word layout Figure 6-2, Table 6-3;
//!   bus-control registers Table 6-5).
//! - Linux provides NO gSPI bus model to mirror: mainline brcmfmac at
//!   torvalds/linux @ 05441d6 has `sdio.c`, `pcie.c`, and `usb.c` but
//!   no SPI bus driver, so the gSPI port follows the datasheet and
//!   the landed codec, not Linux.
//! - SDIO side: Linux brcmfmac `sdio.c` / `bcmsdh.c` via the existing
//!   [`super::sdio_bridge`] adapter; the CYW43439 SDIO function
//!   matches (0x02D0/0xA9AF, 0x04B4/0xBD3D) already live in
//!   [`super::bootstrap`].
//!
//! ## Derived conventions, flagged for silicon qualification
//!
//! The following are derived from the in-tree codec layout plus
//! standard MSB-first SPI, pinned by the fixture smokes, and must be
//! re-verified on silicon (Pico W qualification) before any
//! deployment claim:
//!
//! 1. The 32-bit command word is clocked big-endian (Figure 6-2 lays
//!    the word out MSB → LSB; SPI clocks MSB first).
//! 2. 32-bit data words are clocked big-endian.
//! 3. [`GspiTransport::probe_link`] is the byte-order oracle: it reads
//!    `REG_TEST_RO` and expects exactly `TEST_RO_PATTERN` (0xFEED_BEAD),
//!    which the codec documents as "returned when the host has the
//!    gSPI byte-order configured correctly". A wrong convention fails
//!    the probe loudly instead of silently corrupting data.
//! 4. Reads clock the command word followed immediately by the data
//!    bytes, with no interposed response-delay bytes. Tuning
//!    `REG_RESPONSE_DELAY_F0` is a silicon-qualification remainder.
//! 5. `REG_STATUS` is NOT sampled after transactions: its
//!    overflow/underflow bit layout (datasheet Table 6-5, full text)
//!    is not grounded in-tree, so no bit is interpreted here.
//!
//! ## Deliberate non-goals (row stays open)
//!
//! - **Packet service over gSPI**: `GspiTransport` implements
//!   `Transport` only. The `PacketTransport` defaults refuse
//!   (`NotReady`), so no packet receipt can be manufactured. The
//!   SDPCM-over-gSPI packet exchange (FIFO address discipline,
//!   packet-available signalling) has no in-tree grounding and no
//!   Linux bus to mirror; it is remaindered, not guessed.
//! - **Platform SDHCI opening**: `HostPort::PlatformSdhci` describes
//!   the port but `is_available()` is false. `narf-drivers-sdio`'s
//!   MMIO aperture (`native::Mmio`, `native::probe`) is bound to a
//!   PCI device + capability authority; a platform (non-PCI) aperture
//!   is a `drivers/sdio` design decision, not something this lane
//!   invents by bypassing the capability model.
//! - **Bus exclusivity**: a `GspiTransport` configures its bus's mode
//!   and frequency at construction. The caller must not share that
//!   bus with another device while the transport exists.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use narf_drivers_spi::{registry, SpiBus, SpiError, SpiMode};

use super::gspi::{
    AddrMode, CommandError, CommandWord, Direction, ADDR_MASK, MAX_LEN, REG_TEST_RO,
    TEST_RO_PATTERN,
};
use super::transport::{Function, Transport, TransportError};

/// The kind of host port a CYW43439 can sit behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPortKind {
    /// The retained profile: PCI SDHCI via `narf-drivers-sdio`.
    PciSdhci,
    /// A non-PCI SDHCI controller at an explicit MMIO base.
    PlatformSdhci,
    /// A gSPI link over a registered SPI bus.
    SpiGspi,
}

/// A host port for a CYW43439, identified by the explicit host handle
/// the platform owner supplies. Nothing here is inferred from a chip
/// MANFID or a firmware filename.
#[derive(Debug, Clone)]
pub enum HostPort {
    /// The retained PCI SDHCI profile (see [`super::bootstrap`]).
    PciSdhci,
    /// A non-PCI SDHCI controller. Described, but not openable until
    /// `drivers/sdio` gains a platform MMIO aperture (see the module
    /// docs); `is_available()` is false for this kind.
    PlatformSdhci {
        /// Physical MMIO base of the SDHCI register aperture.
        mmio_base: u64,
    },
    /// A gSPI link over an already-registered SPI bus.
    SpiGspi {
        /// The bus controller, from `narf_drivers_spi::registry`.
        bus: Arc<dyn SpiBus>,
        /// Chip-select index on that bus.
        cs: u8,
    },
}

/// Errors opening or describing a host port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// The port is not a gSPI port.
    NotGspi,
    /// The port kind cannot be opened yet (platform SDHCI aperture).
    PlatformApertureUnavailable,
    /// The SPI bus reported an error.
    Spi(SpiError),
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortError::NotGspi => f.write_str("host port is not a gSPI port"),
            PortError::PlatformApertureUnavailable => {
                f.write_str("platform SDHCI aperture unavailable")
            }
            PortError::Spi(_) => f.write_str("SPI bus error"),
        }
    }
}

impl HostPort {
    /// The kind of this port.
    pub fn kind(&self) -> HostPortKind {
        match self {
            HostPort::PciSdhci => HostPortKind::PciSdhci,
            HostPort::PlatformSdhci { .. } => HostPortKind::PlatformSdhci,
            HostPort::SpiGspi { .. } => HostPortKind::SpiGspi,
        }
    }

    /// Whether this port can be opened today. Platform SDHCI is false:
    /// its aperture needs a `drivers/sdio` design decision (see the
    /// module docs). The other two kinds are openable.
    pub fn is_available(&self) -> bool {
        !matches!(self, HostPort::PlatformSdhci { .. })
    }

    /// Open the gSPI transport for a `SpiGspi` port, configuring the
    /// bus mode and frequency from the caller-supplied platform facts.
    /// Any other kind returns `PortError::NotGspi`.
    pub fn open_gspi(&self, mode: SpiMode, freq_hz: u32) -> Result<GspiTransport, PortError> {
        match self {
            HostPort::SpiGspi { bus, cs } => GspiTransport::new(bus.clone(), *cs, mode, freq_hz),
            HostPort::PciSdhci | HostPort::PlatformSdhci { .. } => Err(PortError::NotGspi),
        }
    }
}

/// Candidate gSPI ports: every SPI bus registered with
/// `narf_drivers_spi::registry`. These are candidates only — a bus
/// being registered says nothing about a CYW43439 being attached to
/// it. Presence is proven by [`GspiTransport::probe_link`] plus chip
/// identification through the loader, never by this list.
pub fn discover_spi_ports() -> Vec<Arc<dyn SpiBus>> {
    registry::list()
}

/// Map a SPI bus error onto the transport error surface.
fn map_spi_error(error: SpiError) -> TransportError {
    match error {
        SpiError::Timeout => TransportError::Timeout,
        SpiError::BufferTooLarge => TransportError::LengthOverflow,
        SpiError::HwError(code) => TransportError::Other(code),
        SpiError::BadHardware | SpiError::FrequencyOutOfRange | SpiError::InvalidCs => {
            TransportError::Other(0)
        }
    }
}

/// Map a gSPI command-word validation failure onto the transport
/// error surface.
fn map_command_error(error: CommandError) -> TransportError {
    match error {
        CommandError::AddressOverflow => TransportError::AddressOverflow,
        CommandError::LengthOverflow => TransportError::LengthOverflow,
    }
}

/// A gSPI host-port adapter: `Transport` over a registered SPI bus.
///
/// Implements register/RAM access (the firmware-loader path) and the
/// link probe. It deliberately does NOT implement `PacketTransport`:
/// packet service over gSPI stays refused until the SDPCM-over-gSPI
/// packet exchange is grounded (see the module docs).
#[derive(Debug)]
pub struct GspiTransport {
    bus: Arc<dyn SpiBus>,
    cs: u8,
}

impl GspiTransport {
    /// Claim a bus for a CYW43439 gSPI link, configuring the
    /// caller-supplied mode and frequency. The caller must not share
    /// this bus with another device while the transport exists.
    pub fn new(
        bus: Arc<dyn SpiBus>,
        cs: u8,
        mode: SpiMode,
        freq_hz: u32,
    ) -> Result<Self, PortError> {
        bus.set_mode(mode).map_err(PortError::Spi)?;
        bus.set_freq(freq_hz).map_err(PortError::Spi)?;
        Ok(Self { bus, cs })
    }

    /// The registry name of the underlying SPI bus.
    pub fn bus_name(&self) -> &str {
        self.bus.name()
    }

    /// The chip-select index on the bus.
    pub fn cs(&self) -> u8 {
        self.cs
    }

    /// Link probe: `REG_TEST_RO` must read back `TEST_RO_PATTERN`.
    /// `Ok(false)` means no CYW43439 answers or the byte-order
    /// convention is wrong — not a bus error. `Err` is a bus error.
    pub fn probe_link(&mut self) -> Result<bool, TransportError> {
        Ok(self.read32(Function::Bus, REG_TEST_RO)? == TEST_RO_PATTERN)
    }

    /// One gSPI transaction: assert CS, clock the command word
    /// big-endian followed by `tx_payload`, and collect `rx_payload`
    /// bytes clocked in after the command word. For reads the caller
    /// passes an empty `tx_payload` and a zero-filled `rx_payload`
    /// of the read length; the transfer length is command + payload.
    fn transact(
        &mut self,
        cmd: CommandWord,
        tx_payload: &[u8],
        rx_payload: &mut [u8],
    ) -> Result<(), TransportError> {
        let total = 4 + tx_payload.len().max(rx_payload.len());
        let mut tx = alloc::vec![0u8; total];
        tx[0..4].copy_from_slice(&cmd.encode().to_be_bytes());
        tx[4..4 + tx_payload.len()].copy_from_slice(tx_payload);
        let mut rx = alloc::vec![0u8; total];
        self.bus.set_cs(self.cs).map_err(map_spi_error)?;
        self.bus.transfer(&tx, &mut rx).map_err(map_spi_error)?;
        rx_payload.copy_from_slice(&rx[4..4 + rx_payload.len()]);
        Ok(())
    }

    /// Validate a burst window before any transaction: the start
    /// address and the whole window must fit the 17-bit gSPI address
    /// field, so a burst can never wrap the field mid-window.
    fn check_window(address: u32, len: usize) -> Result<(), TransportError> {
        if address & !ADDR_MASK != 0 {
            return Err(TransportError::AddressOverflow);
        }
        if len > 0 && (len - 1) as u32 > ADDR_MASK - address {
            return Err(TransportError::AddressOverflow);
        }
        Ok(())
    }
}

impl Transport for GspiTransport {
    fn read32(&mut self, function: Function, address: u32) -> Result<u32, TransportError> {
        let cmd = CommandWord::reg(Direction::Read, function.into(), address)
            .map_err(map_command_error)?;
        let mut out = [0u8; 4];
        self.transact(cmd, &[], &mut out)?;
        Ok(u32::from_be_bytes(out))
    }

    fn write32(
        &mut self,
        function: Function,
        address: u32,
        value: u32,
    ) -> Result<(), TransportError> {
        let cmd = CommandWord::reg(Direction::Write, function.into(), address)
            .map_err(map_command_error)?;
        self.transact(cmd, &value.to_be_bytes(), &mut [])?;
        Ok(())
    }

    fn read_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &mut [u8],
    ) -> Result<(), TransportError> {
        Self::check_window(address, buf.len())?;
        let mut offset = 0usize;
        while offset < buf.len() {
            let take = (buf.len() - offset).min(MAX_LEN as usize);
            let cmd = CommandWord::new(
                Direction::Read,
                AddrMode::Increment,
                function.into(),
                address + offset as u32,
                take as u16,
            )
            .map_err(map_command_error)?;
            let chunk = &mut buf[offset..offset + take];
            self.transact(cmd, &[], chunk)?;
            offset += take;
        }
        Ok(())
    }

    fn write_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &[u8],
    ) -> Result<(), TransportError> {
        Self::check_window(address, buf.len())?;
        let mut offset = 0usize;
        while offset < buf.len() {
            let take = (buf.len() - offset).min(MAX_LEN as usize);
            let cmd = CommandWord::new(
                Direction::Write,
                AddrMode::Increment,
                function.into(),
                address + offset as u32,
                take as u16,
            )
            .map_err(map_command_error)?;
            self.transact(cmd, &buf[offset..offset + take], &mut [])?;
            offset += take;
        }
        Ok(())
    }
}
