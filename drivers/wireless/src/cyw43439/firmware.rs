//! CYW43439 owned firmware bootstrap.
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
//! Original public/permissive references: soypat/cyw43439 and Embassy
//! cyw43. Live AI core/RAM/reset and NVRAM contracts now follow local
//! Linux brcmfmac/{chip,firmware,sdio}.c under GPL-2.0-or-later.

use alloc::vec::Vec;

use super::backplane::{split as window_split, window_writes};
use super::chipclk;
use super::core::{D11, SDIO_DEVICE, SOC_RAM, SOC_RAM_BASE, WLAN_ARM};
use super::sdio::{BusWidth, CCCR_BUS_IFACE_CTRL, CCCR_IO_ENABLE, CCCR_IO_READY, F1_CHIPCLK_CTRL};
use super::transport::{Function, Transport, TransportError};
use crate::brcmfmac::chip::{Backplane, Chip, Core};

/// Existing loader image-size ceiling, also checked before native F1 setup.
pub(crate) const MAX_IMAGE_SIZE: usize = 4 * 1024 * 1024;

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
    InvalidImage,
    InvalidState,
    UnsupportedChip,
    Chip(crate::brcmfmac::chip::Error),
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
///    payload length **in 32-bit words excluding the trailer**. An extra
///    NUL terminates the record list before alignment padding.
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
    // Linux firmware.c rounds up nvram_len + 1: preserve a separate
    // list terminator even when the final key's NUL lands on a word edge.
    buf.push(0);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
    // Append the length-checksum trailer.
    let len_words = buf.len() / 4;
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
pub fn nvram_blob_address(soc_ram_size: u32, blob_len: u32) -> Option<u32> {
    soc_ram_size
        .checked_sub(blob_len)?
        .checked_add(SOC_RAM_BASE)
}

// ── High-level loader ─────────────────────────────────────────────

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
    layout: Option<(Core, Core)>,
    next_step: usize,
    failed: bool,
    revision_mask: Option<u16>,
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
            layout: None,
            next_step: 0,
            failed: false,
            revision_mask: None,
        }
    }

    /// Borrow the underlying transport (e.g. for the IOCTL codec
    /// once the loader has finished).
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }
    pub(crate) fn require_revisions(mut self, mask: u16) -> Self {
        self.revision_mask = Some(mask);
        self
    }

    /// Transfer the retained host adapter to the packet runtime after boot.
    pub fn into_transport(self) -> Result<T, LoadError> {
        if self.packet_core().is_none() {
            return Err(LoadError::InvalidState);
        }
        Ok(self.transport)
    }

    /// Run the full load procedure.
    pub fn run(&mut self) -> Result<(), LoadError> {
        if self.failed || self.next_step != 0 {
            return Err(LoadError::InvalidState);
        }
        for step in LOAD_SEQUENCE {
            self.execute_step(step)?;
        }
        Ok(())
    }

    fn validate_images(&self) -> Result<(), LoadError> {
        if self.firmware.is_empty()
            || self.firmware.len() > MAX_IMAGE_SIZE
            || self.nvram.len() < 8
            || self.nvram.len() % 4 != 0
        {
            return Err(LoadError::InvalidImage);
        }
        let end = self.nvram.len();
        let words = u16::from_le_bytes([self.nvram[end - 4], self.nvram[end - 3]]);
        let inverted = u16::from_le_bytes([self.nvram[end - 2], self.nvram[end - 1]]);
        if !words != inverted || usize::from(words) * 4 != end - 4 {
            return Err(LoadError::InvalidImage);
        }
        Ok(())
    }

    pub fn execute_step(&mut self, step: LoadStep) -> Result<(), LoadError> {
        if self.failed || LOAD_SEQUENCE.get(self.next_step) != Some(&step) {
            return Err(LoadError::InvalidState);
        }
        if self.next_step == 0 {
            self.validate_images()?;
        }
        let result = match step {
            LoadStep::VerifyEndian => self.verify_endian(),
            LoadStep::BusInit => self.bus_init(),
            LoadStep::AlpUp => self.alp_up(),
            LoadStep::HoldCoresInReset => self.hold_cores_in_reset(),
            LoadStep::FirmwareUpload => self.firmware_upload(),
            LoadStep::NvramUpload => self.nvram_upload(),
            LoadStep::BringWlanArmUp => self.bring_wlan_arm_up(),
            LoadStep::HtUp => self.ht_up(),
            LoadStep::EnableWlanFunction => self.enable_wlan_function(),
        };
        if result.is_err() {
            self.failed = true;
        } else {
            self.next_step += 1;
        }
        result
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
        self.write_byte(Function::Bus, CCCR_BUS_IFACE_CTRL, BusWidth::OneBit as u8)?;
        self.write_byte(Function::Bus, CCCR_IO_ENABLE, 1 << 1)?; // F1
        self.poll_byte(Function::Bus, CCCR_IO_READY, 1 << 1)?;
        Ok(())
    }

    fn alp_up(&mut self) -> Result<(), LoadError> {
        self.write_byte(Function::Backplane, F1_CHIPCLK_CTRL, 0x08)?;
        self.poll_byte(Function::Backplane, F1_CHIPCLK_CTRL, chipclk::ALP_AVAIL)
            .map_err(|e| {
                if e == LoadError::StatusTimeout {
                    LoadError::AlpDidNotComeUp
                } else {
                    e
                }
            })?;
        self.write_byte(Function::Backplane, F1_CHIPCLK_CTRL, chipclk::FORCE_ALP_REQ)
    }
    fn hold_cores_in_reset(&mut self) -> Result<(), LoadError> {
        let mut bus = LoaderBackplane(&mut self.transport);
        let chip = Chip::discover_ai(&mut bus).map_err(LoadError::Chip)?;
        if chip.id != 43439 {
            return Err(LoadError::UnsupportedChip);
        }
        if self
            .revision_mask
            .is_some_and(|mask| chip.revision >= 16 || mask & (1 << chip.revision) == 0)
        {
            return Err(LoadError::UnsupportedChip);
        }
        let unique = |id| {
            let mut matching = chip.cores.iter().copied().filter(|c| c.id == id);
            let first = matching.next().ok_or(LoadError::UnsupportedChip)?;
            if matching.next().is_some() {
                return Err(LoadError::UnsupportedChip);
            }
            Ok(first)
        };
        let arm = unique(WLAN_ARM)?;
        let ram = unique(SOC_RAM)?;
        let d11 = unique(D11)?;
        let sdio = unique(SDIO_DEVICE)?;
        Chip::disable_core(&mut bus, arm, 0, 0).map_err(LoadError::Chip)?;
        Chip::reset_core(&mut bus, d11, 12, 4, 4).map_err(LoadError::Chip)?;
        Chip::reset_core(&mut bus, ram, 0, 0, 0).map_err(LoadError::Chip)?;
        // 43439 CM3 must not retain the firmware bank-3 remap.
        bus.write32(ram.base + 0x10, 3).map_err(LoadError::Chip)?;
        bus.write32(ram.base + 0x44, 0).map_err(LoadError::Chip)?;
        let info = bus.read32(ram.base).map_err(LoadError::Chip)?;
        // Bank-info layout (rev>=8 excluding12). Older SOCRAM layouts
        // remain gated rather than guessing capacity from a caller's size.
        if ram.revision < 8 || ram.revision == 12 {
            return Err(LoadError::UnsupportedChip);
        }
        let banks = (info & if ram.revision >= 23 { 0x1f0 } else { 0xf0 }) >> 4;
        if info == u32::MAX || banks == 0 {
            return Err(LoadError::UnsupportedChip);
        }
        let mut size = 0u32;
        for bank in 0..banks {
            bus.write32(ram.base + 0x10, bank)
                .map_err(LoadError::Chip)?;
            let bank_info = bus.read32(ram.base + 0x40).map_err(LoadError::Chip)?;
            if bank_info == u32::MAX {
                return Err(LoadError::Chip(crate::brcmfmac::chip::Error::Gone));
            }
            size = size
                .checked_add(((bank_info & 0x7f) + 1) * 8192)
                .ok_or(LoadError::InvalidImage)?;
        }
        if size > 4 * 1024 * 1024
            || (self.soc_ram_size != 0 && self.soc_ram_size != size)
            || self.firmware.len() + self.nvram.len() > size as usize
        {
            return Err(LoadError::InvalidImage);
        }
        self.soc_ram_size = size;
        self.layout = Some((arm, sdio));
        Ok(())
    }

    fn firmware_upload(&mut self) -> Result<(), LoadError> {
        self.backplane_write_burst(SOC_RAM_BASE, self.firmware)
    }

    fn nvram_upload(&mut self) -> Result<(), LoadError> {
        let blob_len = self.nvram.len() as u32;
        let addr =
            nvram_blob_address(self.soc_ram_size, blob_len).ok_or(LoadError::InvalidImage)?;
        self.backplane_write_burst(addr, self.nvram)
    }

    fn bring_wlan_arm_up(&mut self) -> Result<(), LoadError> {
        let (arm, sdio) = self.layout.ok_or(LoadError::InvalidState)?;
        // Linux activate clears interrupts before releasing the CM3.
        self.backplane_write32(sdio.base + 0x20, u32::MAX)?;
        Chip::reset_core(&mut LoaderBackplane(&mut self.transport), arm, 0, 0, 0)
            .map_err(LoadError::Chip)
    }
    fn ht_up(&mut self) -> Result<(), LoadError> {
        self.write_byte(Function::Backplane, F1_CHIPCLK_CTRL, 0x10)?;
        self.poll_byte(
            Function::Backplane,
            F1_CHIPCLK_CTRL,
            chipclk::HT_AVAIL | chipclk::ALP_AVAIL,
        )
        .map_err(|e| {
            if e == LoadError::StatusTimeout {
                LoadError::HtDidNotComeUp
            } else {
                e
            }
        })?;
        self.write_byte(Function::Backplane, F1_CHIPCLK_CTRL, chipclk::FORCE_HT_REQ)
    }
    fn enable_wlan_function(&mut self) -> Result<(), LoadError> {
        let (_, sdio) = self.layout.ok_or(LoadError::InvalidState)?;
        self.backplane_write32(sdio.base + 0x48, 4 << 16)?;
        self.write_byte(Function::Bus, CCCR_IO_ENABLE, 6)?;
        self.poll_byte(Function::Bus, CCCR_IO_READY, 4)
    }
    pub fn packet_core(&self) -> Option<u32> {
        if self.failed || self.next_step != LOAD_SEQUENCE.len() {
            None
        } else {
            self.layout.map(|(_, c)| c.base)
        }
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
        let mut failure = None;
        let ready = narf_scheduler::responsive_spin_until(
            || match self.read_byte(f, addr) {
                Ok(value) => value & mask == mask,
                Err(error) => {
                    failure = Some(error);
                    true
                }
            },
            narf_time::Deadline::after_ms(1000),
        );
        if let Some(error) = failure {
            Err(error)
        } else if ready {
            Ok(())
        } else {
            Err(LoadError::StatusTimeout)
        }
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
            cursor = cursor
                .checked_add(n as u32)
                .ok_or(LoadError::InvalidImage)?;
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

/// Adapter for generic firmware transports; the SDIO implementation adds
/// the 32-bit backplane access flag at its CMD53 boundary.
struct LoaderBackplane<'a, T: Transport>(&'a mut T);
impl<T: Transport> Backplane for LoaderBackplane<'_, T> {
    fn read32(&mut self, address: u32) -> Result<u32, crate::brcmfmac::chip::Error> {
        loader_window(self.0, address)?;
        self.0
            .read32(Function::Backplane, address & 0x7fff)
            .map_err(|_| crate::brcmfmac::chip::Error::Access)
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), crate::brcmfmac::chip::Error> {
        loader_window(self.0, address)?;
        self.0
            .write32(Function::Backplane, address & 0x7fff, value)
            .map_err(|_| crate::brcmfmac::chip::Error::Access)
    }
}
fn loader_window(t: &mut impl Transport, address: u32) -> Result<(), crate::brcmfmac::chip::Error> {
    if !crate::brcmfmac::chip::valid_address(address) {
        return Err(crate::brcmfmac::chip::Error::Address);
    }
    for w in window_writes(address) {
        t.write_burst(Function::Backplane, w.address, &[w.data])
            .map_err(|_| crate::brcmfmac::chip::Error::Access)?;
    }
    Ok(())
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
        if usize::from(len) * 4 != n - 4 {
            return TestResult::Fail("trailer length mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/firmware",
        smoke_nvram_trailer_round_trip
    );

    fn smoke_nvram_linux_token_excludes_trailer_and_has_list_nul() -> TestResult {
        if build_nvram_blob("a=b\n")
            != Ok(alloc::vec![
                b'a', b'=', b'b', 0, 0, 0, 0, 0, 2, 0, 0xfd, 0xff
            ])
            || nvram_blob_address(4, 8).is_some()
        {
            return TestResult::Fail("Linux NVRAM payload/list terminator/token extent differs");
        }
        let mock = MockTransport {
            log: Vec::new(),
            poll_call: 0,
            word_writes: 0,
            window: 0,
            words: alloc::collections::BTreeMap::new(),
        };
        let mut loader = FirmwareLoader::new(mock, &[1; 4], &[0; 8], 0, false);
        if loader.run() != Err(LoadError::InvalidImage)
            || !loader.transport.log.is_empty()
            || loader.execute_step(LoadStep::FirmwareUpload) != Err(LoadError::InvalidState)
        {
            return TestResult::Fail("invalid image or out-of-order step performed bus I/O");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/firmware",
        smoke_nvram_linux_token_excludes_trailer_and_has_list_nul
    );

    fn smoke_nvram_address_top_of_ram() -> TestResult {
        let soc_size: u32 = 512 * 1024;
        let blob_len: u32 = 256;
        let addr = match nvram_blob_address(soc_size, blob_len) {
            Some(a) => a,
            None => return TestResult::Fail("address rejected"),
        };
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
        word_writes: usize,
        window: u32,
        words: alloc::collections::BTreeMap<u32, u32>,
    }

    impl Transport for MockTransport {
        fn read32(&mut self, _f: Function, addr: u32) -> Result<u32, TransportError> {
            Ok(*self
                .words
                .get(&(self.window | (addr & 0x7fff)))
                .unwrap_or(&0))
        }
        fn write32(&mut self, _f: Function, addr: u32, value: u32) -> Result<(), TransportError> {
            self.word_writes += 1;
            self.words.insert(self.window | (addr & 0x7fff), value);
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
            if f == Function::Backplane && buf.len() == 1 {
                let shift = match addr {
                    super::super::sdio::F1_SBADDRLOW => Some(8),
                    super::super::sdio::F1_SBADDRMID => Some(16),
                    super::super::sdio::F1_SBADDRHIGH => Some(24),
                    _ => None,
                };
                if let Some(shift) = shift {
                    self.window = (self.window & !(255 << shift)) | (u32::from(buf[0]) << shift);
                }
            }
            Ok(())
        }
    }

    fn mock() -> MockTransport {
        let mut mock = MockTransport {
            log: alloc::vec::Vec::new(),
            poll_call: 0,
            word_writes: 0,
            window: 0,
            words: alloc::collections::BTreeMap::new(),
        };
        mock.words.insert(0x18000000, 0x1000a9af); // AI, 43439 A0.
        mock.words.insert(0x180000fc, 0x18100000);
        let descriptors = [
            0x4bf80001, 0x18080001, 0x18000005, 0x18110085, 0x4bf82a01, 0x07080001, 0x18002005,
            0x18114085, 0x4bf80e01, 0x18080001, 0x18004005, 0x18116085, 0x4bf81201, 0x18080001,
            0x18003005, 0x18118085, 0x4bf82901, 0x18080001, 0x18011005, 0x1811a085, 0xf,
        ];
        for (i, word) in descriptors.into_iter().enumerate() {
            mock.words.insert(0x18100000 + i as u32 * 4, word);
        }
        mock.words.insert(0x18004000, 0x40); // four 64-KiB banks.
        mock.words.insert(0x18004040, 7);
        mock
    }

    fn smoke_loader_drives_full_sequence() -> TestResult {
        let firmware = [0xAAu8; 64];
        let nvram_text = "ccode=US\n";
        let nvram_blob = match build_nvram_blob(nvram_text) {
            Ok(b) => b,
            Err(_) => return TestResult::Fail("NVRAM build failed"),
        };
        let mock = mock();
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
        if loader.packet_core() != Some(0x18011000)
            || loader.transport.words.get(&0x18004044) != Some(&0)
            || loader.transport.words.get(&0x18114408) != Some(&1)
            || loader.transport.words.get(&0x18011048) != Some(&(4 << 16))
        {
            return TestResult::Fail("discovered core reset/remap/mailbox contract differs");
        }
        if loader.run() != Err(LoadError::InvalidState) {
            return TestResult::Fail("firmware owner reused after CPU release");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/firmware",
        smoke_loader_drives_full_sequence
    );
    fn smoke_cyw_signed_selected_chip_revision_precedes_core_mutation_and_payload() -> TestResult {
        use crate::brcmfmac::provision::{tests::selected_fixture, Family};
        let (selection, assets) = match selected_fixture(Family::Sdio43439) {
            Ok(value) => value,
            Err(reason) => return TestResult::Fail(reason),
        };
        let nvram = crate::brcmfmac::boot::pack_nvram(&assets.nvram).unwrap();
        let mut rejected =
            FirmwareLoader::new(mock(), &assets.firmware, &nvram, 0, false).require_revisions(2); // signed fixture admits A0, not A1.
        if rejected.run() != Err(LoadError::UnsupportedChip)
            || rejected.transport.word_writes != 0
            || rejected
                .transport
                .log
                .iter()
                .any(|(_, _, body)| body == &assets.firmware || body == &nvram)
            || rejected.run() != Err(LoadError::InvalidState)
        {
            return TestResult::Fail(
                "unselected CM3 revision reset a core, streamed payload, or retried failed loader",
            );
        }
        let mut accepted = FirmwareLoader::new(mock(), &assets.firmware, &nvram, 0, false)
            .require_revisions(selection.revisions());
        if accepted.run().is_err()
            || accepted.packet_core() != Some(0x18011000)
            || !accepted
                .transport
                .log
                .iter()
                .any(|(_, _, body)| body == &assets.firmware)
            || !accepted
                .transport
                .log
                .iter()
                .any(|(_, _, body)| body == &nvram)
        {
            return TestResult::Fail(
                "signed selected CM3 bytes did not reach actual discovered loader",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/firmware",
        smoke_cyw_signed_selected_chip_revision_precedes_core_mutation_and_payload
    );
}
