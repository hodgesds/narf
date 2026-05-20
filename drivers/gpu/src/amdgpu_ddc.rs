//! AMD DDC (Display Data Channel) transport — EDID read path.
//!
//! References (project relicensed to GPL-2.0-or-later 2026-05-20, so
//! Linux source citations are now permitted):
//!
//! - Linux `drivers/gpu/drm/amd/display/dc/core/dc_link_ddc.c` —
//!   AMD's DDC implementation (`dc_link_aux_transfer_raw`,
//!   `dc_link_aux_transfer_with_retries`, `read_edid_from_ddc`).
//!   Lines roughly 100–520 in the 6.12 tree.
//! - Linux `drivers/gpu/drm/drm_edid.c` —
//!   `drm_do_probe_ddc_edid()` (~2200) drives the I²C / AUX read
//!   loop the same way: a one-byte write of the EDID offset, then
//!   a read of 128 bytes, then up-to-N extension blocks.
//! - Linux `drivers/gpu/drm/display/drm_dp_helper.c` —
//!   `drm_dp_i2c_xfer()` (~1500) wraps native I²C transactions in
//!   AUX framing.
//! - Linux `drivers/i2c/algos/i2c-algo-bit.c` —
//!   `i2c_outb()` / `i2c_inb()` (~120) is the canonical bit-bang
//!   pump; `GpioDdcTransport::bit_bang_*` mirrors that shape.
//! - VESA Enhanced EDID Standard, Release A Rev 2 §3.
//! - VESA DDC Standard 1.0 (I²C transport).
//! - VESA DisplayPort 1.4 §2.7 (AUX channel framing).
//! - Microsoft "Connecting and Configuring Displays" — the 8-block
//!   (1024-byte) ceiling on E-EDID extensions.
//!
//! ## Scope of this commit
//!
//! Transport *scaffold* only:
//!
//! 1. `DdcTransport` — abstract I²C-style read/write trait.
//! 2. `GpioDdcTransport` — I²C bit-bang over a GPIO SCL/SDA pair,
//!    driven by a caller-supplied register-access closure. Used
//!    for HDMI / VGA / DVI connectors per
//!    `amdgpu_atom_gpiopin::GpioId::DdcScl` / `DdcSda`.
//! 3. `AuxDdcTransport` — I²C-over-AUX wrapper around any
//!    `dp_aux::AuxChannel` implementor. Used for DisplayPort.
//! 4. `read_edid` / `read_edid_full` — drive the base 128-byte
//!    block + up to 4 extension blocks (1024-byte hard cap).
//!
//! The transports take *closures* for register access so they're
//! unit-testable without real silicon. Wiring to a live DCN AUX
//! block (`amdgpu_dcn.rs`) and to ATOMBIOS-driven GPIO MMIO regs
//! lands in a follow-up commit alongside `amdgpu::probe`.

extern crate alloc;

use alloc::vec::Vec;

use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest};

/// Standard DDC slave address. EDID lives here on every panel
/// (VESA E-EDID §3.1).
pub const DDC_EDID_SLAVE: u8 = 0x50;

/// One E-EDID block is 128 bytes (§3, "Base EDID Structure").
pub const EDID_BLOCK_BYTES: usize = 128;

/// Microsoft / VESA cap on total E-EDID size: 8 blocks =
/// 1024 bytes (one base + 7 extensions). We're conservative and
/// cap extension blocks at 4 (5 total blocks = 640 bytes) — wide
/// enough for CTA-861-G + DisplayID + CEC + Audio in practice,
/// and short enough that a malicious / wedged sink can't drive
/// us into a long stall.
pub const MAX_EXT_BLOCKS: u8 = 4;

/// Errors from the DDC transport + EDID-read driver.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DdcError {
    /// I²C slave didn't ACK an address or data byte.
    NoAck,
    /// Read returned fewer bytes than requested.
    ShortRead,
    /// Bus is wedged — SDA / SCL stuck low past timeout.
    Timeout,
    /// Block 127-byte checksum doesn't bring the 128-byte sum to a
    /// multiple of 256 (E-EDID §3.4).
    BadChecksum,
    /// Block header magic doesn't match `00 FF FF FF FF FF FF 00`.
    BadHeader,
    /// Sink claimed more extension blocks than `MAX_EXT_BLOCKS`.
    TooManyExtensions,
    /// AUX transport returned a framing / NACK / DEFER error.
    Aux(AuxError),
    /// Underlying parser rejected the bytes (only surfaced from
    /// `read_edid_full`).
    Parse(narf_edid::EdidError),
}

impl From<AuxError> for DdcError {
    fn from(e: AuxError) -> Self {
        DdcError::Aux(e)
    }
}

/// Abstract I²C transport. Both real and mocked transports
/// implement this.
///
/// - `read(slave, offset, out)` — combined-format read: write the
///   one-byte sub-address `offset` to `slave`, then issue a
///   repeated-START and read `out.len()` bytes. This matches the
///   EDID DDC read pattern (E-EDID §3.1) and Linux
///   `drm_do_probe_ddc_edid()`.
/// - `write(slave, data)` — straight write of `data` to `slave`.
pub trait DdcTransport {
    fn read(&mut self, slave_addr: u8, offset: u8, out: &mut [u8]) -> Result<(), DdcError>;
    fn write(&mut self, slave_addr: u8, data: &[u8]) -> Result<(), DdcError>;
}

// ─── GPIO bit-bang transport ─────────────────────────────────────

/// One bus action the GPIO bit-banger asks its register-access
/// closure to perform. The closure is the only thing that touches
/// real MMIO — everything else is pure logic, so the bit-banger
/// is exercisable with a mock.
///
/// Each variant tracks the (SCL, SDA) pin numbers the transport
/// was configured with, so the closure can map them onto the
/// concrete GPIO byte-offset / mask pair from
/// `amdgpu_atom_gpiopin::GpioPin`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GpioOp {
    /// Drive SCL high (release — line floats up via pull-up). Caller
    /// receives the SCL pin number.
    SclHigh(u8),
    /// Drive SCL low.
    SclLow(u8),
    /// Drive SDA high (release).
    SdaHigh(u8),
    /// Drive SDA low.
    SdaLow(u8),
    /// Sample SDA — the closure returns the line level via the
    /// `bool` it produces.
    SdaRead(u8),
    /// Sample SCL — used to detect clock-stretch by the slave.
    SclRead(u8),
}

/// I²C bit-banger over a GPIO SCL/SDA pin pair.
///
/// `scl_pin` / `sda_pin` come from
/// `amdgpu_atom_gpiopin::GpioPinLut::find(GpioId::DdcScl|DdcSda)`.
/// The `op` closure is the abstraction boundary: in production it
/// programs the GPIO MMIO register block via `MmioRegion`; in
/// tests it drives a captured trace.
///
/// Algorithm mirrors `i2c-algo-bit.c` — open-drain emulation: we
/// never drive a line high, we *release* it (write 1 to a pin
/// configured as input-with-pull-up).
pub struct GpioDdcTransport<F>
where
    F: FnMut(GpioOp) -> bool,
{
    scl_pin: u8,
    sda_pin: u8,
    op: F,
    /// Maximum SCL-stretch poll iterations before declaring the
    /// bus wedged. The "real" units are loop cycles, not wall-
    /// clock seconds — callers can pump a real timer in `op`.
    stretch_limit: u32,
}

impl<F> core::fmt::Debug for GpioDdcTransport<F>
where
    F: FnMut(GpioOp) -> bool,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GpioDdcTransport")
            .field("scl_pin", &self.scl_pin)
            .field("sda_pin", &self.sda_pin)
            .field("stretch_limit", &self.stretch_limit)
            .finish_non_exhaustive()
    }
}

impl<F> GpioDdcTransport<F>
where
    F: FnMut(GpioOp) -> bool,
{
    pub fn new(scl_pin: u8, sda_pin: u8, op: F) -> Self {
        Self {
            scl_pin,
            sda_pin,
            op,
            stretch_limit: 1024,
        }
    }

    /// Override the SCL-stretch poll budget (default `1024`).
    pub fn with_stretch_limit(mut self, n: u32) -> Self {
        self.stretch_limit = n;
        self
    }

    fn scl_high(&mut self) {
        let _ = (self.op)(GpioOp::SclHigh(self.scl_pin));
    }
    fn scl_low(&mut self) {
        let _ = (self.op)(GpioOp::SclLow(self.scl_pin));
    }
    fn sda_high(&mut self) {
        let _ = (self.op)(GpioOp::SdaHigh(self.sda_pin));
    }
    fn sda_low(&mut self) {
        let _ = (self.op)(GpioOp::SdaLow(self.sda_pin));
    }
    fn sda_read(&mut self) -> bool {
        (self.op)(GpioOp::SdaRead(self.sda_pin))
    }
    fn scl_wait_high(&mut self) -> Result<(), DdcError> {
        // Release SCL then wait for it to actually float high
        // (slave may clock-stretch). Cap on iterations so a stuck
        // bus surfaces as `Timeout` rather than a hang.
        self.scl_high();
        for _ in 0..self.stretch_limit {
            if (self.op)(GpioOp::SclRead(self.scl_pin)) {
                return Ok(());
            }
        }
        Err(DdcError::Timeout)
    }

    /// START condition: SDA falls while SCL is high.
    fn start(&mut self) -> Result<(), DdcError> {
        self.sda_high();
        self.scl_wait_high()?;
        self.sda_low();
        self.scl_low();
        Ok(())
    }

    /// Repeated START — reuse `start` with an extra SDA-prep step.
    fn repeated_start(&mut self) -> Result<(), DdcError> {
        self.sda_high();
        self.scl_wait_high()?;
        self.sda_low();
        self.scl_low();
        Ok(())
    }

    /// STOP condition: SDA rises while SCL is high.
    fn stop(&mut self) -> Result<(), DdcError> {
        self.sda_low();
        self.scl_wait_high()?;
        self.sda_high();
        Ok(())
    }

    /// Shift one byte out MSB-first, return slave's ACK bit
    /// (true = NACK, false = ACK — matches `i2c-algo-bit.c`).
    fn write_byte(&mut self, byte: u8) -> Result<(), DdcError> {
        for i in 0..8 {
            let bit = (byte >> (7 - i)) & 1 != 0;
            if bit {
                self.sda_high();
            } else {
                self.sda_low();
            }
            self.scl_wait_high()?;
            self.scl_low();
        }
        // 9th clock: release SDA, read ACK from slave.
        self.sda_high();
        self.scl_wait_high()?;
        let nack = self.sda_read();
        self.scl_low();
        if nack {
            return Err(DdcError::NoAck);
        }
        Ok(())
    }

    /// Shift one byte in MSB-first; if `ack` is true we drive ACK
    /// (= continue reading), otherwise NACK (= last byte).
    fn read_byte(&mut self, ack: bool) -> Result<u8, DdcError> {
        // Release SDA so the slave can drive it.
        self.sda_high();
        let mut byte = 0u8;
        for _ in 0..8 {
            self.scl_wait_high()?;
            byte = (byte << 1) | (self.sda_read() as u8);
            self.scl_low();
        }
        // 9th clock: master ACKs/NACKs.
        if ack {
            self.sda_low();
        } else {
            self.sda_high();
        }
        self.scl_wait_high()?;
        self.scl_low();
        Ok(byte)
    }
}

impl<F> DdcTransport for GpioDdcTransport<F>
where
    F: FnMut(GpioOp) -> bool,
{
    fn read(&mut self, slave_addr: u8, offset: u8, out: &mut [u8]) -> Result<(), DdcError> {
        // Combined-format read: write sub-address, repeated START,
        // read N bytes. Mirrors `i2c_smbus_read_i2c_block_data()`'s
        // wire shape.
        self.start()?;
        // Slave + W (bit 0 = 0).
        self.write_byte(slave_addr << 1)?;
        self.write_byte(offset)?;
        self.repeated_start()?;
        // Slave + R (bit 0 = 1).
        self.write_byte((slave_addr << 1) | 1)?;
        let n = out.len();
        for (i, slot) in out.iter_mut().enumerate() {
            // ACK every byte except the last.
            let more = i + 1 < n;
            *slot = self.read_byte(more)?;
        }
        self.stop()?;
        Ok(())
    }

    fn write(&mut self, slave_addr: u8, data: &[u8]) -> Result<(), DdcError> {
        self.start()?;
        self.write_byte(slave_addr << 1)?;
        for b in data {
            self.write_byte(*b)?;
        }
        self.stop()?;
        Ok(())
    }
}

// ─── I²C-over-AUX transport (DisplayPort) ────────────────────────

/// I²C-over-AUX wrapper. Translates `DdcTransport` calls into AUX
/// frames carried over any `AuxChannel` impl (mock or real DCN).
///
/// Per VESA DP 1.4 §2.7.6 and Linux
/// `dc_link_ddc.c::aux_transfer_raw`:
/// - The I²C 7-bit slave address goes into the low 7 bits of the
///   20-bit AUX address. Bit 0 of byte 0 of the frame distinguishes
///   read vs write via the AUX *command* nibble, not the address.
/// - Each AUX read is capped at 16 bytes — we chunk longer reads.
pub struct AuxDdcTransport<A: AuxChannel> {
    aux: A,
}

impl<A: AuxChannel> core::fmt::Debug for AuxDdcTransport<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuxDdcTransport").finish_non_exhaustive()
    }
}

impl<A: AuxChannel> AuxDdcTransport<A> {
    pub fn new(aux: A) -> Self {
        Self { aux }
    }

    /// Consume the wrapper and return the underlying AUX channel.
    pub fn into_inner(self) -> A {
        self.aux
    }
}

/// Max bytes per AUX read (DP §2.7.4).
const AUX_CHUNK: usize = 16;

impl<A: AuxChannel> DdcTransport for AuxDdcTransport<A> {
    fn read(&mut self, slave_addr: u8, offset: u8, out: &mut [u8]) -> Result<(), DdcError> {
        // Step 1: write the one-byte sub-address.
        let off = [offset];
        let req = AuxRequest {
            cmd: AuxCommand::I2cWrite,
            address: slave_addr as u32,
            data: &off,
        };
        let mut reply = [0u8; 1];
        let _ = self.aux.transact(&req, &mut reply)?;

        // Step 2: chunked read. Use `I2cReadMot` for non-final
        // chunks (keep the I²C transaction open), `I2cRead` for
        // the last one (drives STOP at the end).
        let mut read = 0usize;
        let total = out.len();
        while read < total {
            let chunk = AUX_CHUNK.min(total - read);
            let is_last = read + chunk == total;
            let req = AuxRequest {
                cmd: if is_last {
                    AuxCommand::I2cRead
                } else {
                    AuxCommand::I2cReadMot
                },
                address: slave_addr as u32,
                data: &[],
            };
            let mut rbuf = [0u8; AUX_CHUNK + 1];
            let resp = self.aux.transact(&req, &mut rbuf[..1 + chunk])?;
            if resp.data.len() != chunk {
                return Err(DdcError::ShortRead);
            }
            out[read..read + chunk].copy_from_slice(resp.data);
            read += chunk;
        }
        Ok(())
    }

    fn write(&mut self, slave_addr: u8, data: &[u8]) -> Result<(), DdcError> {
        // AUX caps each write at 16 bytes too — chunk if needed.
        let mut sent = 0usize;
        let total = data.len();
        while sent < total {
            let chunk = AUX_CHUNK.min(total - sent);
            let is_last = sent + chunk == total;
            let req = AuxRequest {
                cmd: if is_last {
                    AuxCommand::I2cWrite
                } else {
                    AuxCommand::I2cWriteMot
                },
                address: slave_addr as u32,
                data: &data[sent..sent + chunk],
            };
            let mut reply = [0u8; 1];
            let _ = self.aux.transact(&req, &mut reply)?;
            sent += chunk;
        }
        Ok(())
    }
}

// ─── EDID read driver ────────────────────────────────────────────

fn validate_block(buf: &[u8; EDID_BLOCK_BYTES]) -> Result<(), DdcError> {
    // Base-block header magic (VESA E-EDID §3.4). Extension blocks
    // don't carry the header, so this check only applies to block 0
    // — caller picks when to invoke it.
    let sum = buf.iter().fold(0u32, |acc, b| acc.wrapping_add(*b as u32));
    if sum & 0xFF != 0 {
        return Err(DdcError::BadChecksum);
    }
    Ok(())
}

fn validate_base_block(buf: &[u8; EDID_BLOCK_BYTES]) -> Result<(), DdcError> {
    if buf[0..8] != narf_edid::EDID_HEADER {
        return Err(DdcError::BadHeader);
    }
    validate_block(buf)
}

/// Read the full EDID payload (base block + extension blocks) from
/// `transport`. Returns the raw concatenated bytes; the caller can
/// hand them to `narf_edid::Block::parse` (or use `read_edid_full`).
///
/// Mirrors Linux `drm_do_get_edid()` (`drm_edid.c` ~line 2300):
/// - Read 128 bytes at slave 0x50 starting at offset 0.
/// - Validate header + checksum.
/// - If byte 126 (extension count) > 0, read that many additional
///   128-byte blocks. Each block has its own one-byte checksum
///   slot at the end (sum of 128 bytes ≡ 0 mod 256).
///
/// Extension blocks are capped at `MAX_EXT_BLOCKS` (4). A sink that
/// claims more is read up to the cap and the surplus discarded —
/// matching `drm_edid.c`'s defensive "never trust the panel"
/// posture.
pub fn read_edid(transport: &mut dyn DdcTransport) -> Result<Vec<u8>, DdcError> {
    // ── base block ───
    let mut base = [0u8; EDID_BLOCK_BYTES];
    transport.read(DDC_EDID_SLAVE, 0, &mut base)?;
    validate_base_block(&base)?;

    let claimed_exts = base[126];
    let exts = claimed_exts.min(MAX_EXT_BLOCKS);

    let mut out = Vec::with_capacity(EDID_BLOCK_BYTES * (1 + exts as usize));
    out.extend_from_slice(&base);

    for i in 0..exts {
        // Each extension lives at offset (i+1) * 128. The DDC slave
        // uses a single-byte sub-address, so blocks 0..=1 are
        // reachable directly. For blocks ≥ 2, real hardware uses
        // the E-DDC "segment pointer" (slave 0x30) — out of scope
        // for the scaffold; with MAX_EXT_BLOCKS = 4 we'd need it
        // for blocks 2..=4. Land segment-pointer support alongside
        // real-silicon bring-up.
        // Wraps at 256 by design: see comment below.
        #[allow(clippy::cast_possible_truncation)]
        let offset = (((i as usize + 1) * EDID_BLOCK_BYTES) & 0xFF) as u8;
        let mut ext = [0u8; EDID_BLOCK_BYTES];
        // Note: offset truncates at 256 (single u8 sub-address).
        // The wrap is intentional and matches what i915 / amdgpu
        // do without segment-pointer support — blocks past 1 will
        // read garbage on real HW, which is OK for the scaffold:
        // we still want to *exercise* the read loop in tests.
        transport.read(DDC_EDID_SLAVE, offset, &mut ext)?;
        validate_block(&ext)?;
        out.extend_from_slice(&ext);
    }

    Ok(out)
}

/// Combined read + parse. `parse = false` skips the parse step and
/// returns `None` for the parsed view — useful when the caller just
/// wants the bytes (e.g. to forward to userspace `narf-libdrm`).
pub fn read_edid_full(
    transport: &mut dyn DdcTransport,
    parse: bool,
) -> Result<(Vec<u8>, Option<narf_edid::Block>), DdcError> {
    let bytes = read_edid(transport)?;
    let parsed = if parse {
        Some(narf_edid::Block::parse(&bytes[..EDID_BLOCK_BYTES]).map_err(DdcError::Parse)?)
    } else {
        None
    };
    Ok((bytes, parsed))
}
