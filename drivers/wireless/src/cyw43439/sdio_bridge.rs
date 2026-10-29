// SPDX-License-Identifier: GPL-2.0-or-later
//! CYW43439 SDIO transport bridge.
//!
//! Owned F0/F1 register/RAM and F2 packet adapter over `SdioFunction`.
//! Reference: Linux brcmfmac/{bcmsdh,sdio}.c. F1 words use CMD53 with
//! the 32-bit backplane access flag. F2 RX uses fixed reads, TX follows
//! incrementing writes; mailbox handling bounds readiness and flow control.

#![allow(dead_code)]

use narf_drivers_sdio::sdhci::cmd::{cmd52_arg, cmd53_arg};
use narf_drivers_sdio::sdio::function::{SdioError, SdioFunction};

use super::transport::{Function, PacketTransport, Transport, TransportError};

/// Maximum byte-mode CMD53 command extent (zero count encodes512).
pub const CYW43439_F2_MAX_BURST: usize = 512;

/// SDIO F2 block size, matching Linux bcmsdh.c (F1 uses64).
pub const CYW43439_SDIO_BLOCK_SIZE: u16 = 512;
const F1_BLOCK_SIZE: u16 = 64;

// ── Argument-word encoders (pure functions for test coverage) ─────────

/// Build the CMD52 argument for a CYW43439 function read.
/// Adapts from the `Transport` `Function` enum to SDIO function index.
pub fn bridge_cmd52_read_arg(function: Function, address: u32) -> u32 {
    cmd52_arg(false, function as u8, false, address, 0)
}

/// Build the CMD52 argument for a CYW43439 function write.
pub fn bridge_cmd52_write_arg(function: Function, address: u32, data: u8) -> u32 {
    cmd52_arg(true, function as u8, false, address, data)
}

/// Build the CMD53 argument for a CYW43439 bulk read (byte mode, auto-increment).
pub fn bridge_cmd53_read_arg(function: Function, address: u32, len: u16) -> u32 {
    // 512 encodes as 0; cap at 512.
    let count = if len >= 512 { 0 } else { len };
    cmd53_arg(false, function as u8, false, true, address, count)
}

/// Build the CMD53 argument for a CYW43439 bulk write (byte mode, auto-increment).
pub fn bridge_cmd53_write_arg(function: Function, address: u32, len: u16) -> u32 {
    let count = if len >= 512 { 0 } else { len };
    cmd53_arg(true, function as u8, false, true, address, count)
}

/// Map a `SdioError` onto a `TransportError` for the
/// `Transport` trait surface.
fn map_err(e: SdioError) -> TransportError {
    match e {
        SdioError::ResponseError(_) => TransportError::BadFraming,
        SdioError::LengthOverflow => TransportError::LengthOverflow,
        SdioError::BadFunction => TransportError::AddressOverflow,
        SdioError::HostError => TransportError::Timeout,
        SdioError::NotEnabled => TransportError::NotReady,
        SdioError::AddressOverflow => TransportError::AddressOverflow,
        SdioError::Unsupported => TransportError::NotReady,
    }
}

/// SDIO-backed CYW43439 transport adapter.
///
/// `F` is any type that implements `SdioFunction` — in production
/// it wraps the SDHCI host; in tests it is a `MockSdio`.
pub struct SdioTransport<F: SdioFunction> {
    proof: Option<alloc::sync::Arc<crate::brcmfmac::provision::Proof>>,
    func: F,
    packet_core: Option<u32>,
    rx_pending: bool,
    flow_stopped: bool,
    failed: bool,
    /// Card-interrupt wake when the host delivers F1/F2 interrupts.
    interrupt: Option<alloc::sync::Arc<crate::brcmfmac::irq::Signal>>,
}

impl<F: SdioFunction> core::fmt::Debug for SdioTransport<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SdioTransport")
            .field("failed", &self.failed)
            .field("packet_core", &self.packet_core)
            .finish_non_exhaustive()
    }
}
impl<F: SdioFunction> SdioTransport<F> {
    pub fn new(func: F) -> Self {
        Self {
            proof: None,
            func,
            packet_core: None,
            rx_pending: false,
            flow_stopped: false,
            failed: false,
            interrupt: None,
        }
    }
    pub(crate) fn qualify(
        mut self,
        proof: alloc::sync::Arc<crate::brcmfmac::provision::Proof>,
    ) -> Self {
        self.proof = Some(proof);
        self
    }
    fn check_qualification(&mut self) -> Result<(), TransportError> {
        if self.failed {
            return Err(TransportError::NotReady);
        }
        if self
            .proof
            .as_ref()
            .is_some_and(|proof| proof.validate().is_err())
        {
            self.failed = true;
            return Err(TransportError::NotReady);
        }
        Ok(())
    }
    /// F1 is enabled before any backplane command. The host retains matching
    /// enable/block-size state; raw CCCR writes cannot bypass its lifecycle.
    pub fn prepare(&mut self) -> Result<(), TransportError> {
        self.check_qualification()?;
        self.func.enable_func(1).map_err(map_err)?;
        self.func
            .set_block_size(1, F1_BLOCK_SIZE)
            .map_err(map_err)?;
        self.func
            .set_block_size(2, CYW43439_SDIO_BLOCK_SIZE)
            .map_err(map_err)
    }
    pub fn enable_wlan(&mut self) -> Result<(), TransportError> {
        self.check_qualification()?;
        self.func.enable_func(2).map_err(map_err)
    }
    pub fn read_backplane(&mut self, address: u32) -> Result<u32, TransportError> {
        self.window(address)?;
        self.read32(Function::Backplane, address & 0x7fff)
    }
    pub fn write_backplane(&mut self, address: u32, value: u32) -> Result<(), TransportError> {
        self.window(address)?;
        self.write32(Function::Backplane, address & 0x7fff, value)
    }
    fn window(&mut self, address: u32) -> Result<(), TransportError> {
        self.check_qualification()?;
        for write in super::backplane::window_writes(address) {
            self.func
                .cmd52_write(1, write.address, write.data)
                .map_err(map_err)?;
        }
        Ok(())
    }
    /// Linux sdio.c firmware callback: publish protocol v4 before enabling
    /// F2, and latch core mailbox/frame indications; then claim F1 and F2
    /// card interrupts (`brcmf_sdiod_intr_register`) when the host has a
    /// line. Without one the owner keeps polling.
    pub fn initialize_packets(&mut self, core: u32) -> Result<(), TransportError> {
        if !crate::brcmfmac::chip::valid_address(core) {
            return Err(TransportError::AddressOverflow);
        }
        self.write_backplane(core + 0x48, 4 << 16)?;
        self.enable_wlan()?;
        self.write_backplane(core + 0x24, 0xf0 | (1 << 29))?;
        self.packet_core = Some(core);
        let signal = crate::brcmfmac::irq::Signal::new();
        let raised = signal.clone();
        if self
            .func
            .enable_card_interrupt(
                (1 << 1) | (1 << 2),
                alloc::sync::Arc::new(move || raised.raise()),
            )
            .map_err(map_err)?
        {
            self.interrupt = Some(signal);
        }
        Ok(())
    }
    fn mailbox(&mut self) -> Result<(), TransportError> {
        let core = self.packet_core.ok_or(TransportError::NotReady)?;
        let status = self.read_backplane(core + 0x20)?;
        if status == u32::MAX || status & 0xff00 != 0 {
            return Err(TransportError::ChipFlowError);
        }
        // FC_CHANGE is W1C; STATE reflects the current global stop state.
        if status & 0x20 != 0 {
            self.write_backplane(core + 0x20, 0x20)?;
            // A second CHANGE may race the ACK. Linux treats either STATE
            // or a reasserted CHANGE as stopped until the next debounce.
            self.flow_stopped = self.read_backplane(core + 0x20)? & 0x30 != 0;
        } else {
            self.flow_stopped = status & 0x10 != 0;
        }
        let pending = status & ((1 << 6) | (1 << 7) | (1 << 29));
        if pending != 0 {
            self.write_backplane(core + 0x20, pending)?;
        }
        if status & (1 << 7) != 0 {
            let data = self.read_backplane(core + 0x4c)?;
            self.write_backplane(core + 0x40, 2)?; // SMB_INT_ACK.
            if data & 0x10 != 0 {
                return Err(TransportError::NotReady);
            }
            if data & 0xa != 0 && (data >> 16) & 255 != 4 {
                return Err(TransportError::BadFraming);
            }
            if data & 1 != 0 {
                self.rx_pending = true;
            }
        }
        if status & (1 << 6) != 0 {
            self.rx_pending = true;
        }
        Ok(())
    }
    fn receive_inner(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        self.mailbox()?;
        if !self.rx_pending {
            return Ok(0);
        }
        if buffer.len() < 64 {
            return Err(TransportError::LengthOverflow);
        }
        self.window(0x1800_0000)?;
        self.func
            .cmd53_read_fixed(2, 0x8000, &mut buffer[..64])
            .map_err(map_err)?;
        let length = usize::from(u16::from_le_bytes([buffer[0], buffer[1]]));
        let inverted = u16::from_le_bytes([buffer[2], buffer[3]]);
        if length == 0 && inverted == 0 {
            self.rx_pending = false;
            return Ok(0);
        }
        if length < 12 || !(length as u16) != inverted || length > super::runtime::MAX_PACKET {
            return Err(TransportError::BadFraming);
        }
        let physical = length.max(64).next_multiple_of(4);
        if physical > buffer.len() {
            return Err(TransportError::LengthOverflow);
        }
        for chunk in buffer[64..physical].chunks_mut(512) {
            self.func
                .cmd53_read_fixed(2, 0x8000, chunk)
                .map_err(map_err)?;
        }
        Ok(length)
    }
}
impl<F: SdioFunction> crate::brcmfmac::chip::Backplane for SdioTransport<F> {
    fn read32(&mut self, address: u32) -> Result<u32, crate::brcmfmac::chip::Error> {
        self.read_backplane(address)
            .map_err(|_| crate::brcmfmac::chip::Error::Access)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), crate::brcmfmac::chip::Error> {
        self.write_backplane(address, value)
            .map_err(|_| crate::brcmfmac::chip::Error::Access)
    }
}
impl<F: SdioFunction> Transport for SdioTransport<F> {
    fn read32(&mut self, function: Function, address: u32) -> Result<u32, TransportError> {
        self.check_qualification()?;
        let mut bytes = [0; 4];
        if function == Function::Backplane && address < 0x10000 {
            if address & 3 != 0 || address & 0x7fff > 0x7ffc {
                return Err(TransportError::AddressOverflow);
            }
            self.func
                .cmd53_read(1, address | 0x8000, &mut bytes)
                .map_err(map_err)?;
        } else {
            self.read_burst(function, address, &mut bytes)?;
        }
        Ok(u32::from_le_bytes(bytes))
    }
    fn write32(
        &mut self,
        function: Function,
        address: u32,
        value: u32,
    ) -> Result<(), TransportError> {
        self.check_qualification()?;
        if function == Function::Backplane && address < 0x10000 {
            if address & 3 != 0 || address & 0x7fff > 0x7ffc {
                return Err(TransportError::AddressOverflow);
            }
            self.func
                .cmd53_write(1, address | 0x8000, &value.to_le_bytes())
                .map_err(map_err)
        } else {
            self.write_burst(function, address, &value.to_le_bytes())
        }
    }
    fn read_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &mut [u8],
    ) -> Result<(), TransportError> {
        self.check_qualification()?;
        if address > 0x1ffff || buf.len() > (0x20000 - address) as usize {
            return Err(TransportError::AddressOverflow);
        }
        if function == Function::Bus || buf.len() == 1 {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self
                    .func
                    .cmd52_read(function as u8, address + i as u32)
                    .map_err(map_err)?;
            }
        } else {
            let stride = if function == Function::Backplane {
                usize::from(F1_BLOCK_SIZE)
            } else {
                512
            };
            for (i, chunk) in buf.chunks_mut(stride).enumerate() {
                self.func
                    .cmd53_read(function as u8, address + (i * stride) as u32, chunk)
                    .map_err(map_err)?;
            }
        }
        Ok(())
    }
    fn write_burst(
        &mut self,
        function: Function,
        address: u32,
        buf: &[u8],
    ) -> Result<(), TransportError> {
        self.check_qualification()?;
        if address > 0x1ffff || buf.len() > (0x20000 - address) as usize {
            return Err(TransportError::AddressOverflow);
        }
        if function == Function::Bus || buf.len() == 1 {
            for (i, &b) in buf.iter().enumerate() {
                let at = address + i as u32;
                if function == Function::Bus && at == super::sdio::CCCR_IO_ENABLE {
                    for number in 1..=7 {
                        if b & (1 << number) != 0 {
                            self.func.enable_func(number).map_err(map_err)?;
                        }
                    }
                } else {
                    self.func
                        .cmd52_write(function as u8, at, b)
                        .map_err(map_err)?;
                }
            }
        } else {
            let stride = if function == Function::Backplane {
                usize::from(F1_BLOCK_SIZE)
            } else {
                512
            };
            for (i, chunk) in buf.chunks(stride).enumerate() {
                self.func
                    .cmd53_write(function as u8, address + (i * stride) as u32, chunk)
                    .map_err(map_err)?;
            }
        }
        Ok(())
    }
}
impl<F: SdioFunction + Send> PacketTransport for SdioTransport<F> {
    fn interrupt(&self) -> Option<alloc::sync::Arc<crate::brcmfmac::irq::Signal>> {
        self.interrupt.clone()
    }
    fn interrupt_serviced(&mut self) {
        if self.interrupt.is_some() && !self.failed {
            self.func.rearm_card_interrupt();
        }
    }
    fn receive_packet(&mut self, buffer: &mut [u8]) -> Result<usize, TransportError> {
        if self.failed {
            return Err(TransportError::NotReady);
        }
        let result = self.receive_inner(buffer);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn transmit_packet(&mut self, packet: &[u8]) -> Result<(), TransportError> {
        if self.failed {
            return Err(TransportError::NotReady);
        }
        if packet.len() < 12 || packet.len() > super::runtime::MAX_PACKET || packet.len() % 4 != 0 {
            return Err(TransportError::LengthOverflow);
        }
        if let Err(error) = self.mailbox() {
            self.failed = true;
            return Err(error);
        }
        if self.flow_stopped {
            return Err(TransportError::Busy);
        }
        self.window(0x1800_0000)?;
        // Linux uses incrementing memcpy_toio for F2 TX and fixed readsb
        // for F2 RX. Each byte-mode command is at most 512 bytes.
        for (i, chunk) in packet.chunks(512).enumerate() {
            if let Err(error) = self
                .func
                .cmd53_write(2, 0x8000 + (i * 512) as u32, chunk)
                .map_err(map_err)
            {
                self.failed = true;
                return Err(error);
            }
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "sdio_bridge_tests.rs"]
mod runtime_tests;

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Argument-word round-trip against reference ─────────────────────

    fn smoke_bridge_cmd52_read_backplane() -> TestResult {
        // Read from F1 (backplane) address 0x000A — same as soypat/cyw43439
        // sdio.go F1_SBADDRLOW read sequence.
        let arg = bridge_cmd52_read_arg(Function::Backplane, 0x000A);
        // Read bit should be clear.
        if (arg >> 31) & 1 != 0 {
            return TestResult::Fail("read bit must be 0");
        }
        // Function 1.
        if (arg >> 28) & 7 != 1 {
            return TestResult::Fail("function must be 1 (backplane)");
        }
        // Address field (bits 25:9).
        if (arg >> 9) & 0x1_FFFF != 0x000A {
            return TestResult::Fail("address mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd52_read_backplane
    );

    fn smoke_bridge_cmd52_write_io_enable() -> TestResult {
        // Write IO_ENABLE to enable F2 — matches Embassy cyw43 SDIO init.
        // CCCR IO_ENABLE = 0x02, data = 0x04 (bit 2 = F2 enable).
        let arg = bridge_cmd52_write_arg(Function::Bus, 0x02, 0x04);
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit must be 1");
        }
        if (arg >> 28) & 7 != 0 {
            return TestResult::Fail("function must be 0 (CCCR/Bus)");
        }
        if (arg >> 9) & 0x1_FFFF != 0x02 {
            return TestResult::Fail("IO_ENABLE address mismatch");
        }
        if arg & 0xFF != 0x04 {
            return TestResult::Fail("IO_ENABLE data byte mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd52_write_io_enable
    );

    fn smoke_bridge_cmd53_wlan_burst() -> TestResult {
        // 256-byte bulk write to F2, address 0 — matches soypat/cyw43439
        // wlan.go TX path and Embassy cyw43 send_packet().
        let arg = bridge_cmd53_write_arg(Function::Wlan, 0x0000, 256);
        if (arg >> 31) & 1 != 1 {
            return TestResult::Fail("write bit must be 1");
        }
        if (arg >> 28) & 7 != 2 {
            return TestResult::Fail("function must be 2 (WLAN)");
        }
        // byte mode: block bit = 0.
        if (arg >> 27) & 1 != 0 {
            return TestResult::Fail("block-mode bit must be 0 for byte mode");
        }
        // auto-increment: incr bit = 1.
        if (arg >> 26) & 1 != 1 {
            return TestResult::Fail("auto-increment must be 1");
        }
        if arg & 0x1FF != 256 {
            return TestResult::Fail("byte count mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd53_wlan_burst
    );

    fn smoke_bridge_cmd53_512_encodes_zero() -> TestResult {
        // Per SDIO spec: count field = 0 means 512 bytes in byte mode.
        let arg = bridge_cmd53_write_arg(Function::Wlan, 0x0000, 512);
        if arg & 0x1FF != 0 {
            return TestResult::Fail("count=512 should encode as 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdio_bridge",
        smoke_bridge_cmd53_512_encodes_zero
    );
}
