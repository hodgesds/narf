//! CYW43439 firmware-load codec.
//!
//! The chip's firmware-load procedure is documented in
//! **CYW43439 datasheet Rev. 03 §6.6 ("Firmware download
//! procedure")**. The host stages a binary firmware image into the
//! SOC-RAM core, appends the chip's NVRAM configuration in a
//! checksum-trailed format, then deasserts the WLAN-ARM core's
//! reset. This module provides:
//!
//! - [`build_nvram_blob`] — convert a public-format NVRAM text
//!   ("`key=value`" lines, `#` comments) into the binary trailer
//!   the chip expects.
//! - [`LoadStep`] — the discrete steps of the load sequence,
//!   ordered for direct iteration by a caller that owns a
//!   [`Transport`].
//! - [`FirmwareLoader`] — a small state machine that walks those
//!   steps over a [`Transport`].
//!
//! Cross-checked against `soypat/cyw43439` (MIT) and Embassy
//! `cyw43` (Apache-2.0 / MIT). **No GPL `brcmfmac` / `bcmdhd`
//! source consulted.**

use alloc::vec::Vec;

use super::backplane::{split as window_split, window_writes};
use super::chipclk;
use super::core::{bring_up_sequence, reset_sequence, wrapper, SOC_RAM_BASE};
use super::sdio::{BusWidth, CCCR_BUS_IFACE_CTRL, CCCR_IO_ENABLE, CCCR_IO_READY, F1_CHIPCLK_CTRL};
use super::transport::{Function, Transport, TransportError};

/// Errors specific to firmware loading on top of the underlying
/// [`TransportError`] surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// Adapter / chip transport reported a failure.
    Transport(TransportError),
    /// NVRAM trailer length would exceed `u16::MAX` bytes.
    NvramTooLarge,
    /// Polled status bit failed to assert in the budgeted retries.
    StatusTimeout,
    /// `gSPI` test-pattern read returned the wrong factory value;
    /// the host bytes are byte-swapped relative to the chip.
    EndianMismatch,
    /// ALP clock failed to come up after the request.
    AlpDidNotComeUp,
    /// HT clock failed to come up after taking the WLAN core out
    /// of reset.
    HtDidNotComeUp,
}

impl From<TransportError> for LoadError {
    fn from(e: TransportError) -> Self {
        LoadError::Transport(e)
    }
}

/// One step in the firmware-load procedure. The variants are
/// ordered top-to-bottom in the procedure flow; a caller can
/// pattern-match on the variant to log progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStep {
    /// Confirm gSPI byte-order via the test-RO factory pattern.
    /// Skipped on SDIO transports.
    VerifyEndian,
    /// Configure F0 bus width (1-bit → 4-bit) and enable F1.
    BusInit,
    /// Request and wait for the ALP clock.
    AlpUp,
    /// Park the SOC-RAM and WLAN-ARM cores in reset.
    HoldCoresInReset,
    /// Stream the firmware binary into the SOC-RAM region.
    FirmwareUpload,
    /// Compute and stream the NVRAM trailer.
    NvramUpload,
    /// Take the WLAN-ARM core out of reset.
    BringWlanArmUp,
    /// Wait for the HT clock to assert.
    HtUp,
    /// Final readiness check on F2 (WLAN function).
    EnableWlanFunction,
}

/// All steps in the order a loader visits them.
pub const LOAD_SEQUENCE: [LoadStep; 9] = [
    LoadStep::VerifyEndian,
    LoadStep::BusInit,
    LoadStep::AlpUp,
    LoadStep::HoldCoresInReset,
    LoadStep::FirmwareUpload,
    LoadStep::NvramUpload,
    LoadStep::BringWlanArmUp,
    LoadStep::HtUp,
    LoadStep::EnableWlanFunction,
];

// ── NVRAM blob format ──────────────────────────────────────────────

/// Convert a public-format NVRAM text into the chip-binary trailer.
///
/// Format (datasheet §6.6 + Infineon NVRAM toolchain):
///
/// 1. Strip `#` comments and surrounding whitespace.
/// 2. Drop empty lines.
/// 3. Concatenate the surviving `key=value` entries separated by
///    a single NUL (`\0`) byte.
/// 4. Pad with NULs to a 4-byte boundary.
/// 5. Append a 4-byte trailer:
///    `[len_lo, len_hi, ~len_lo, ~len_hi]` where `len` is the
///    total length **in 32-bit words including the trailer**.
///
/// The chip rejects the upload if the inverted-length checksum does
/// not match — the trailer's primary purpose is integrity, not size
/// reporting.
pub fn build_nvram_blob(text: &str) -> Result<Vec<u8>, LoadError> {
    let mut buf: Vec<u8> = Vec::new();
    let mut first = true;
    for raw in text.lines() {
        // Strip trailing comment.
        let line = match raw.find('#') {
            Some(i) => &raw[..i],
            None => raw,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !first {
            buf.push(0);
        }
        buf.extend_from_slice(trimmed.as_bytes());
        first = false;
    }
    // Terminate the last record with a NUL.
    if !buf.is_empty() {
        buf.push(0);
    }
    // Pad to a 4-byte boundary.
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    // Append the length-checksum trailer.
    let len_words = (buf.len() + 4) / 4;
    if len_words > u16::MAX as usize {
        return Err(LoadError::NvramTooLarge);
    }
    let len = len_words as u16;
    let inv = !len;
    buf.push((len & 0xFF) as u8);
    buf.push((len >> 8) as u8);
    buf.push((inv & 0xFF) as u8);
    buf.push((inv >> 8) as u8);
    Ok(buf)
}

/// Compute the SOC-RAM address at which the NVRAM trailer begins,
/// given the chip's SOC-RAM size and the trailer length.
///
/// The trailer is placed at the very top of SOC-RAM so the WLAN-ARM
/// firmware can find it via a fixed offset at boot.
pub fn nvram_blob_address(soc_ram_size: u32, blob_len: u32) -> u32 {
    SOC_RAM_BASE + soc_ram_size - blob_len
}

// ── High-level loader ─────────────────────────────────────────────

/// Polling budget for status-bit waits. Each iteration yields a
/// single transport read. The driver's caller is expected to insert
/// timing between iterations as appropriate for the transport.
pub const POLL_RETRIES: u32 = 4096;

/// State machine that drives the firmware-load procedure over a
/// caller-provided [`Transport`].
#[derive(Debug)]
pub struct FirmwareLoader<'fw, T: Transport> {
    transport: T,
    firmware: &'fw [u8],
    nvram: &'fw [u8],
    soc_ram_size: u32,
    /// Whether the transport is gSPI (and therefore needs the
    /// endian self-check + bus-control register dance) versus SDIO.
    pub is_gspi: bool,
}

impl<'fw, T: Transport> FirmwareLoader<'fw, T> {
    pub fn new(
        transport: T,
        firmware: &'fw [u8],
        nvram: &'fw [u8],
        soc_ram_size: u32,
        is_gspi: bool,
    ) -> Self {
        Self {
            transport,
            firmware,
            nvram,
            soc_ram_size,
            is_gspi,
        }
    }

    /// Borrow the underlying transport (e.g. for the IOCTL codec
    /// once the loader has finished).
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Run the full load procedure.
    pub fn run(&mut self) -> Result<(), LoadError> {
        for step in LOAD_SEQUENCE {
            self.execute_step(step)?;
        }
        Ok(())
    }

    pub fn execute_step(&mut self, step: LoadStep) -> Result<(), LoadError> {
        match step {
            LoadStep::VerifyEndian => self.verify_endian(),
            LoadStep::BusInit => self.bus_init(),
            LoadStep::AlpUp => self.alp_up(),
            LoadStep::HoldCoresInReset => self.hold_cores_in_reset(),
            LoadStep::FirmwareUpload => self.firmware_upload(),
            LoadStep::NvramUpload => self.nvram_upload(),
            LoadStep::BringWlanArmUp => self.bring_wlan_arm_up(),
            LoadStep::HtUp => self.ht_up(),
            LoadStep::EnableWlanFunction => self.enable_wlan_function(),
        }
    }

    fn verify_endian(&mut self) -> Result<(), LoadError> {
        if !self.is_gspi {
            return Ok(());
        }
        let val = self
            .transport
            .read32(Function::Bus, super::gspi::REG_TEST_RO)?;
        if val != super::gspi::TEST_RO_PATTERN {
            return Err(LoadError::EndianMismatch);
        }
        Ok(())
    }

    fn bus_init(&mut self) -> Result<(), LoadError> {
        // 4-bit bus + enable F1 are the SDIO-side sequence.
        self.write_byte(Function::Bus, CCCR_BUS_IFACE_CTRL, BusWidth::FourBit as u8)?;
        self.write_byte(Function::Bus, CCCR_IO_ENABLE, 1 << 1)?; // F1
        self.poll_byte(Function::Bus, CCCR_IO_READY, 1 << 1)?;
        Ok(())
    }

    fn alp_up(&mut self) -> Result<(), LoadError> {
        self.write_byte(Function::Backplane, F1_CHIPCLK_CTRL, chipclk::FORCE_ALP_REQ)?;
        for _ in 0..POLL_RETRIES {
            let v = self.read_byte(Function::Backplane, F1_CHIPCLK_CTRL)?;
            if v & chipclk::ALP_AVAIL != 0 {
                return Ok(());
            }
        }
        Err(LoadError::AlpDidNotComeUp)
    }

    fn hold_cores_in_reset(&mut self) -> Result<(), LoadError> {
        for w in reset_sequence(wrapper::WLAN_ARM) {
            self.backplane_write32(w.address, w.value)?;
        }
        for w in reset_sequence(wrapper::SOC_RAM) {
            self.backplane_write32(w.address, w.value)?;
        }
        // SOC-RAM needs to be brought up so the firmware can be
        // staged into it. The WLAN-ARM core stays parked.
        for w in bring_up_sequence(wrapper::SOC_RAM) {
            self.backplane_write32(w.address, w.value)?;
        }
        Ok(())
    }

    fn firmware_upload(&mut self) -> Result<(), LoadError> {
        self.backplane_write_burst(SOC_RAM_BASE, self.firmware)
    }

    fn nvram_upload(&mut self) -> Result<(), LoadError> {
        let blob_len = self.nvram.len() as u32;
        let addr = nvram_blob_address(self.soc_ram_size, blob_len);
        self.backplane_write_burst(addr, self.nvram)
    }

    fn bring_wlan_arm_up(&mut self) -> Result<(), LoadError> {
        for w in bring_up_sequence(wrapper::WLAN_ARM) {
            self.backplane_write32(w.address, w.value)?;
        }
        Ok(())
    }

    fn ht_up(&mut self) -> Result<(), LoadError> {
        for _ in 0..POLL_RETRIES {
            let v = self.read_byte(Function::Backplane, F1_CHIPCLK_CTRL)?;
            if v & chipclk::HT_AVAIL != 0 {
                return Ok(());
            }
        }
        Err(LoadError::HtDidNotComeUp)
    }

    fn enable_wlan_function(&mut self) -> Result<(), LoadError> {
        self.write_byte(Function::Bus, CCCR_IO_ENABLE, (1 << 1) | (1 << 2))?; // F1+F2
        self.poll_byte(Function::Bus, CCCR_IO_READY, 1 << 2)?; // F2 ready
        Ok(())
    }

    // ── Helpers ────────────────────────────────────────────────────

    fn read_byte(&mut self, f: Function, addr: u32) -> Result<u8, LoadError> {
        let mut b = [0u8; 1];
        self.transport.read_burst(f, addr, &mut b)?;
        Ok(b[0])
    }

    fn write_byte(&mut self, f: Function, addr: u32, val: u8) -> Result<(), LoadError> {
        self.transport.write_burst(f, addr, &[val])?;
        Ok(())
    }

    fn poll_byte(&mut self, f: Function, addr: u32, mask: u8) -> Result<(), LoadError> {
        for _ in 0..POLL_RETRIES {
            if self.read_byte(f, addr)? & mask != 0 {
                return Ok(());
            }
        }
        Err(LoadError::StatusTimeout)
    }

    fn backplane_write32(&mut self, addr: u32, val: u32) -> Result<(), LoadError> {
        self.set_backplane_window(addr)?;
        let (_, off) = window_split(addr);
        self.transport.write32(Function::Backplane, off, val)?;
        Ok(())
    }

    fn backplane_write_burst(&mut self, addr: u32, mut buf: &[u8]) -> Result<(), LoadError> {
        let mut cursor = addr;
        while !buf.is_empty() {
            self.set_backplane_window(cursor)?;
            let (_, off) = window_split(cursor);
            // The remaining contiguous range inside the current window.
            let window_room = (super::backplane::WINDOW_SIZE - off) as usize;
            let n = window_room.min(buf.len());
            self.transport
                .write_burst(Function::Backplane, off, &buf[..n])?;
            cursor = cursor.wrapping_add(n as u32);
            buf = &buf[n..];
        }
        Ok(())
    }

    fn set_backplane_window(&mut self, addr: u32) -> Result<(), LoadError> {
        let (base, _) = window_split(addr);
        for w in window_writes(base) {
            self.write_byte(Function::Backplane, w.address, w.data)?;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_nvram_trailer_round_trip() -> TestResult {
        // Pico-W-style minimal NVRAM with a comment + blank line.
        let text = "\
# vendor configuration
manfid=0x2d0
prodid=0x0727

ccode=US
";
        let blob = match build_nvram_blob(text) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("trailer build failed"),
        };
        // Length must be 4-byte aligned and >= 8 bytes.
        if blob.len() < 8 || blob.len() % 4 != 0 {
            return TestResult::Fail("blob alignment wrong");
        }
        // Inspect the trailer.
        let n = blob.len();
        let len_lo = blob[n - 4];
        let len_hi = blob[n - 3];
        let inv_lo = blob[n - 2];
        let inv_hi = blob[n - 1];
        let len = u16::from_le_bytes([len_lo, len_hi]);
        let inv = u16::from_le_bytes([inv_lo, inv_hi]);
        if (!len) != inv {
            return TestResult::Fail("trailer checksum mismatch");
        }
        if usize::from(len) * 4 != n {
            return TestResult::Fail("trailer length mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/firmware",
        smoke_nvram_trailer_round_trip
    );

    fn smoke_nvram_address_top_of_ram() -> TestResult {
        let soc_size: u32 = 512 * 1024;
        let blob_len: u32 = 256;
        let addr = nvram_blob_address(soc_size, blob_len);
        // Trailer must end exactly at the top of SOC-RAM.
        if addr.wrapping_add(blob_len) != SOC_RAM_BASE + soc_size {
            return TestResult::Fail("NVRAM address not anchored to SOC-RAM top");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/firmware",
        smoke_nvram_address_top_of_ram
    );

    fn smoke_load_sequence_complete() -> TestResult {
        // The hard-coded LOAD_SEQUENCE must match the procedure
        // length exactly (a runtime guard against accidental
        // re-ordering).
        if LOAD_SEQUENCE.len() != 9 {
            return TestResult::Fail("LOAD_SEQUENCE drifted from procedure");
        }
        if LOAD_SEQUENCE[0] != LoadStep::VerifyEndian {
            return TestResult::Fail("first step must be VerifyEndian");
        }
        if LOAD_SEQUENCE[LOAD_SEQUENCE.len() - 1] != LoadStep::EnableWlanFunction {
            return TestResult::Fail("last step must be EnableWlanFunction");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/firmware",
        smoke_load_sequence_complete
    );

    // Mock transport that records the writes the loader issues. The
    // record is then inspected by smoke tests below.
    struct MockTransport {
        log: alloc::vec::Vec<(Function, u32, alloc::vec::Vec<u8>)>,
        // For status reads the loader expects to eventually flip:
        // we return the polled bit on the second read.
        poll_call: u32,
    }

    impl Transport for MockTransport {
        fn read32(&mut self, _f: Function, addr: u32) -> Result<u32, TransportError> {
            // Return the gSPI factory pattern for the endian probe,
            // 0 elsewhere.
            if addr == super::super::gspi::REG_TEST_RO {
                Ok(super::super::gspi::TEST_RO_PATTERN)
            } else {
                Ok(0)
            }
        }
        fn write32(&mut self, _f: Function, _addr: u32, _v: u32) -> Result<(), TransportError> {
            Ok(())
        }
        fn read_burst(
            &mut self,
            _f: Function,
            addr: u32,
            buf: &mut [u8],
        ) -> Result<(), TransportError> {
            self.poll_call += 1;
            // After the first poll, satisfy any status check by
            // returning all-ones — both ALP_AVAIL and HT_AVAIL +
            // F1/F2 ready will be set.
            let v = if self.poll_call > 1 { 0xFFu8 } else { 0u8 };
            for b in buf.iter_mut() {
                *b = v;
            }
            // Special-case: returning the gSPI test-RO factory
            // pattern through `read_burst`-of-byte is not used by
            // the loader, so this is fine.
            let _ = addr;
            Ok(())
        }
        fn write_burst(
            &mut self,
            f: Function,
            addr: u32,
            buf: &[u8],
        ) -> Result<(), TransportError> {
            self.log.push((f, addr, buf.to_vec()));
            Ok(())
        }
    }

    fn smoke_loader_drives_full_sequence() -> TestResult {
        let firmware = [0xAAu8; 64];
        let nvram_text = "ccode=US\n";
        let nvram_blob = match build_nvram_blob(nvram_text) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("NVRAM build failed"),
        };
        let mock = MockTransport {
            log: alloc::vec::Vec::new(),
            poll_call: 0,
        };
        let mut loader = FirmwareLoader::new(
            mock,
            &firmware,
            &nvram_blob,
            256 * 1024,
            false, /* SDIO */
        );
        if loader.run().is_err() {
            return TestResult::Fail("loader returned an error");
        }
        // The recorded writes must include the firmware blob and
        // the NVRAM blob (each as one or more bursts). We check
        // that *some* burst's payload exactly equals the firmware
        // and *some* equals the NVRAM blob.
        let log = &loader.transport.log;
        let saw_firmware = log
            .iter()
            .any(|(_, _, payload)| payload.as_slice() == firmware);
        let saw_nvram = log
            .iter()
            .any(|(_, _, payload)| payload.as_slice() == nvram_blob.as_slice());
        if !saw_firmware {
            return TestResult::Fail("loader did not stream firmware blob");
        }
        if !saw_nvram {
            return TestResult::Fail("loader did not stream NVRAM blob");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/firmware",
        smoke_loader_drives_full_sequence
    );
}
