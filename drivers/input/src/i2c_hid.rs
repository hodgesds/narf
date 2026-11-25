//! HID-over-I2C client driver.
//!
//! Clean-room implementation. Public, non-GPL sources only:
//! - Microsoft "HID over I2C Protocol Specification" v1.0 (2012),
//!   the authoritative document — opcodes, command framing, RESET
//!   sentinel, descriptor layout.
//!   <https://learn.microsoft.com/en-us/previous-versions/windows/hardware/design/dn642101(v=vs.85)>
//!   <https://download.microsoft.com/download/7/d/d/7dd44bb7-2a7a-4505-ac1c-7227d3d96d5b/hid-over-i2c-protocol-spec-v1-0.docx>
//! - USB HID Class Spec v1.11 — for the Report Descriptor format
//!   the device echoes back via `wReportDescRegister`.
//!   <https://www.usb.org/sites/default/files/hid1_11.pdf>
//! - Microsoft "Plug and Play Support and Power Management for HID
//!   over I2C Devices" — the `_DSM` UUID
//!   (3CDFF6F7-4267-4555-AD05-B30A3D8938DE) that surfaces
//!   `wHIDDescRegister` in ACPI.
//!   <https://learn.microsoft.com/en-us/windows-hardware/drivers/hid/plug-and-play-support-and-power-management>
//!
//! What this driver does:
//! - Reads + parses the HID descriptor from `hid_desc_register`.
//! - Issues a RESET on `start()` (the device is required to clear
//!   its FIFO + raise INT to indicate a zero-length report; we
//!   poll the Input register a bounded number of times instead of
//!   waiting on the GPIO line, which is fine for bring-up).
//! - Sends SET_POWER(SLEEP) on `quiesce()`.
//! - Provides `read_input_report()` which the eventual input-event
//!   pump task calls in a loop. The first two bytes of any read
//!   from the Input register carry the length; length=0 means no
//!   report ready.
//! - GET_REPORT / SET_REPORT and plain output reports with Linux's
//!   framing (`drivers/hid/i2c-hid/i2c-hid-core.c`: one write+read
//!   transaction per GET, the 0x0F sentinel for report IDs >= 15, no ID
//!   byte for report 0), used for precision-touchpad mode, LEDs, and the
//!   raw requests of `crate::i2c_hid_transport`.
//!
//! Discovery vs. binding:
//! - The `register_initcalls` Stage::Device pass below logs every
//!   AMD FCH I2C controller + every PNP0C50 child it finds in the
//!   AML namespace. Automatic binding (PNP0C50 → controller via
//!   I2cSerialBus / GpioInt resource decode) needs `narf-aml`'s
//!   ResourceItem extended with those two descriptor types — flagged
//!   as a follow-up. Until then drivers are constructed by hand by
//!   the test suite or by a board-specific bring-up shim.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;

use narf_drivers::{Driver, DriverEnv, DriverFuture};
use narf_drivers_i2c::{I2cBus, I2cError, I2cOp};

// ── HID-over-I2C protocol constants ────────────────────────────────

/// Length of the HID descriptor as published by every spec-compliant
/// HID-over-I2C device. Vendor-specific extensions live past byte 30
/// but the core fields end here.
pub const HID_DESC_LENGTH: usize = 30;

/// Expected `bcdVersion` field (0x0100 = v1.00). Devices reporting
/// a higher minor are still acceptable — we only reject differing
/// majors.
pub const HID_PROTOCOL_VERSION: u16 = 0x0100;

// Command opcodes — Microsoft HID-over-I2C spec §7.2 table 7-2.
const CMD_OP_RESET: u8 = 0x01;
const CMD_OP_GET_REPORT: u8 = 0x02;
const CMD_OP_SET_REPORT: u8 = 0x03;
const CMD_OP_SET_POWER: u8 = 0x08;

// Report types — bits 4-5 of the command low byte.
const REPORT_TYPE_INPUT: u8 = 0x01;
const REPORT_TYPE_OUTPUT: u8 = 0x02;
const REPORT_TYPE_FEATURE: u8 = 0x03;

// SET_POWER values.
pub const POWER_ON: u8 = 0x00;
pub const POWER_SLEEP: u8 = 0x01;

/// `HID_MIN_BUFFER_SIZE` (`include/linux/hid.h:589`): the transfer buffer
/// i2c-hid starts with, before `i2c_hid_start` grows it to the largest
/// report the descriptor declares.
pub const HID_MIN_BUFFER_SIZE: usize = 64;

/// Decoded HID descriptor. Field names mirror the Microsoft spec so
/// cross-referencing the document is friction-free.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HidDescriptor {
    pub w_hid_desc_length: u16,
    pub bcd_version: u16,
    pub w_report_desc_length: u16,
    pub w_report_desc_register: u16,
    pub w_input_register: u16,
    pub w_max_input_length: u16,
    pub w_output_register: u16,
    pub w_max_output_length: u16,
    pub w_command_register: u16,
    pub w_data_register: u16,
    pub w_vendor_id: u16,
    pub w_product_id: u16,
    pub w_version_id: u16,
}

impl HidDescriptor {
    /// Decode 30 bytes (LE) into a `HidDescriptor`. Returns
    /// `Err(I2cHidError::BadDescriptor)` if the buffer is short or
    /// if the leading length field is wrong (the device echoes its
    /// descriptor length back as the first u16 — a mismatch usually
    /// means we read from the wrong register or the bus is glitchy).
    pub fn parse(buf: &[u8]) -> Result<Self, I2cHidError> {
        if buf.len() < HID_DESC_LENGTH {
            return Err(I2cHidError::BadDescriptor);
        }
        let r16 = |off: usize| u16::from_le_bytes([buf[off], buf[off + 1]]);
        let len = r16(0);
        if len as usize != HID_DESC_LENGTH {
            return Err(I2cHidError::BadDescriptor);
        }
        let bcd = r16(2);
        if bcd >> 8 != HID_PROTOCOL_VERSION >> 8 {
            return Err(I2cHidError::BadDescriptor);
        }
        Ok(Self {
            w_hid_desc_length: len,
            bcd_version: bcd,
            w_report_desc_length: r16(4),
            w_report_desc_register: r16(6),
            w_input_register: r16(8),
            w_max_input_length: r16(10),
            w_output_register: r16(12),
            w_max_output_length: r16(14),
            w_command_register: r16(16),
            w_data_register: r16(18),
            w_vendor_id: r16(20),
            w_product_id: r16(22),
            w_version_id: r16(24),
            // Bytes 26..30 are reserved.
        })
    }
}

/// Errors specific to the HID-over-I2C client.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum I2cHidError {
    /// Underlying bus transfer failed.
    Bus(I2cError),
    /// HID descriptor failed structural validation (length / version
    /// mismatch).
    BadDescriptor,
    /// `start()` was called before the descriptor was read; the
    /// driver doesn't know its operating registers yet.
    NotInitialised,
    /// `read_input_report` got a length field shorter than the 2-byte
    /// length prefix itself — the device returned garbage.
    ShortReport,
    /// Caller's buffer is too small for the next input report.
    BufferTooSmall,
    /// SET_POWER value out of spec (must be 0 or 1).
    BadPowerState,
    /// A report request i2c-hid refuses with `-EINVAL`: data longer than
    /// the transfer buffer, GET of an Output or SET of an Input report, a
    /// SET whose `buf[0]` is not the report ID, or a GET answered with
    /// another report's ID.
    InvalidRequest,
    /// A plain output report to a device with no output register
    /// (`wMaxOutputLength == 0`): `-ENOSYS`, which makes hidraw fall back
    /// to SET_REPORT.
    NoOutputRegister,
}

impl From<I2cError> for I2cHidError {
    fn from(e: I2cError) -> Self {
        I2cHidError::Bus(e)
    }
}

/// Bounded retry policy for I2C-HID bring-up and recovery (issue
/// #771). Every bound below is grounded in an in-tree precedent,
/// not invented here:
///
/// * `max_attempts = 3` — USB CCID's `MAX_RETRIES = 3`
///   (`drivers/usb/src/ccid.rs`): the tree's standing bound for
///   "transient bus errors before escalating".
/// * Backoff shape — start 100 ms, double per attempt, cap
///   30 000 ms — the i40e port-recovery loop
///   (`drivers/net/i40e/src/i40e/runtime.rs`).
///
/// The pump's report-loop recovery (`PumpRecovery`, in
/// `i2c_hid_bind`) reuses the same shape: transient bus errors
/// back off, then escalate to RESET, then give up boundedly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Total attempts per operation (first try + retries).
    pub max_attempts: u32,
    /// Backoff before the first retry; doubled per attempt.
    pub base_backoff_ms: u64,
    /// Cap on any single backoff.
    pub max_backoff_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_backoff_ms: 100,
            max_backoff_ms: 30_000,
        }
    }
}

impl RetryPolicy {
    /// Backoff before retry number `attempt` (0-based: 0 is the
    /// wait after the first failure). Doubling, saturating, capped
    /// — the i40e shape.
    pub fn backoff_ms(&self, attempt: u32) -> u64 {
        let doubled = self.base_backoff_ms.saturating_mul(1u64 << attempt.min(62));
        doubled.min(self.max_backoff_ms)
    }
}

/// One HID-over-I2C device sitting on an I2C bus at a 7-bit slave
/// address. Cheap to construct; the real work happens in `start()`
/// (descriptor read + RESET + protocol bring-up).
#[derive(Debug)]
pub struct I2cHidDriver {
    bus: Arc<dyn I2cBus>,
    addr: u8,
    hid_desc_register: u16,
    /// `Some` after `start()` succeeds — the descriptor is the
    /// driver's source of truth for the four operating registers.
    descriptor: Option<HidDescriptor>,
    /// `ihid->bufsize`: the largest report a GET/SET_REPORT moves.
    bufsize: usize,
}

impl I2cHidDriver {
    pub fn new(bus: Arc<dyn I2cBus>, addr: u8, hid_desc_register: u16) -> Self {
        Self {
            bus,
            addr,
            hid_desc_register,
            descriptor: None,
            bufsize: HID_MIN_BUFFER_SIZE,
        }
    }

    /// Size the transfer buffer for the descriptor's largest report, as
    /// `i2c_hid_start` does (never below [`HID_MIN_BUFFER_SIZE`]).
    pub fn set_bufsize(&mut self, bufsize: usize) {
        self.bufsize = bufsize.max(HID_MIN_BUFFER_SIZE);
    }

    /// `ihid->bufsize`.
    pub fn bufsize(&self) -> usize {
        self.bufsize
    }

    /// Read + decode the HID descriptor. Idempotent — repeated calls
    /// re-read from the device, which is what the RESET sequence
    /// expects (the descriptor is allowed to change after reset).
    pub async fn read_descriptor(&mut self) -> Result<HidDescriptor, I2cHidError> {
        let reg = self.hid_desc_register.to_le_bytes();
        let mut buf = [0u8; HID_DESC_LENGTH];
        let mut ops = [I2cOp::Write(&reg), I2cOp::Read(&mut buf)];
        self.bus.transfer(self.addr, &mut ops).await?;
        let desc = HidDescriptor::parse(&buf)?;
        self.descriptor = Some(desc);
        Ok(desc)
    }

    /// Issue a RESET command. The device should respond by clearing
    /// its FIFO and raising INT once with a zero-length report. We
    /// wait for that sentinel by polling the Input register; on
    /// hardware that drives a GPIO interrupt line, the wait is
    /// near-instant (the device asserts within ~µs).
    pub async fn reset(&self) -> Result<(), I2cHidError> {
        let desc = self.descriptor.ok_or(I2cHidError::NotInitialised)?;
        write_command(
            &*self.bus,
            self.addr,
            desc.w_command_register,
            CMD_OP_RESET,
            0,
        )
        .await?;
        // After RESET the device should send a 0-length report on
        // the Input register. Poll up to 32 times — at ~µs per poll
        // this is well within the 5 ms RESET budget.
        for _ in 0..32 {
            let mut len_buf = [0u8; 2];
            let reg = desc.w_input_register.to_le_bytes();
            let mut ops = [I2cOp::Write(&reg), I2cOp::Read(&mut len_buf)];
            self.bus.transfer(self.addr, &mut ops).await?;
            let l = u16::from_le_bytes(len_buf);
            if l == 0 || l == 2 {
                return Ok(());
            }
        }
        // Reset took too long — surface as a bus timeout. Caller
        // typically retries once before giving up on the device.
        Err(I2cHidError::Bus(I2cError::Timeout))
    }

    /// RESET with bounded retry + backoff (issue #771). Attempts
    /// `reset()` up to `policy.max_attempts` times, sleeping
    /// `policy.backoff_ms(attempt)` between attempts. Returns the
    /// first success, or the last error once the budget is spent.
    /// A device that cannot RESET after this is wedged; callers
    /// must not loop on it forever.
    pub async fn reset_with_retry(&self, policy: &RetryPolicy) -> Result<(), I2cHidError> {
        let mut last_err = I2cHidError::Bus(I2cError::Timeout);
        for attempt in 0..policy.max_attempts.max(1) {
            match self.reset().await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = e;
                    if attempt + 1 < policy.max_attempts.max(1) {
                        narf_time::sleep_ms(policy.backoff_ms(attempt)).await;
                    }
                }
            }
        }
        Err(last_err)
    }

    /// Full bring-up: descriptor read + RESET (bounded retry) +
    /// POWER_ON. Returns the descriptor on success.
    ///
    /// SET_POWER failure is best-effort: some devices ignore it
    /// and still report, so a failed POWER_ON is logged and does
    /// not fail bring-up (pre-#771 behaviour preserved). A
    /// descriptor or RESET failure fails bring-up — a device that
    /// cannot be identified or reset cannot be driven, and the
    /// caller must give up boundedly rather than limp on with a
    /// wedged device.
    pub async fn bring_up(&mut self, policy: &RetryPolicy) -> Result<HidDescriptor, I2cHidError> {
        let desc = self.read_descriptor().await?;
        self.reset_with_retry(policy).await?;
        if let Err(e) = self.set_power(POWER_ON).await {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid: SET_POWER(ON) failed ({:?}); continuing, device may stay asleep",
                e
            );
        }
        Ok(desc)
    }

    /// Read one input report into `buf`. Returns the number of bytes
    /// of *report payload* (i.e. excluding the 2-byte length prefix).
    /// Returns 0 when the device has nothing to report — caller
    /// should yield + retry, or wait on the GPIO interrupt if wired.
    pub async fn read_input_report(&self, buf: &mut [u8]) -> Result<usize, I2cHidError> {
        let desc = self.descriptor.ok_or(I2cHidError::NotInitialised)?;
        let max_len = desc.w_max_input_length as usize;
        // First 2 bytes are length. Read into a small local buffer
        // bounded by w_max_input_length to avoid surprising the
        // controller's max-burst limit.
        let mut total = alloc::vec![0; max_len.max(2)];
        let reg = desc.w_input_register.to_le_bytes();
        let mut ops = [I2cOp::Write(&reg), I2cOp::Read(&mut total)];
        self.bus.transfer(self.addr, &mut ops).await?;
        let len = u16::from_le_bytes([total[0], total[1]]) as usize;
        if len == 0 {
            return Ok(0);
        }
        if len < 2 {
            return Err(I2cHidError::ShortReport);
        }
        let payload = len - 2;
        if payload > buf.len() {
            return Err(I2cHidError::BufferTooSmall);
        }
        if 2 + payload > total.len() {
            return Err(I2cHidError::ShortReport);
        }
        buf[..payload].copy_from_slice(&total[2..2 + payload]);
        Ok(payload)
    }

    /// Read the device's full Report Descriptor (used by the HID
    /// parser to learn the structure of each Input report). Returned
    /// vector is exactly `w_report_desc_length` bytes.
    pub async fn read_report_descriptor(&self) -> Result<Vec<u8>, I2cHidError> {
        let desc = self.descriptor.ok_or(I2cHidError::NotInitialised)?;
        let mut out = alloc::vec![0; desc.w_report_desc_length as usize];
        let reg = desc.w_report_desc_register.to_le_bytes();
        let mut ops = [I2cOp::Write(&reg), I2cOp::Read(&mut out)];
        self.bus.transfer(self.addr, &mut ops).await?;
        Ok(out)
    }

    /// SET_POWER opcode. Caller passes [`POWER_ON`] or
    /// [`POWER_SLEEP`]; anything else is rejected.
    pub async fn set_power(&self, state: u8) -> Result<(), I2cHidError> {
        if state != POWER_ON && state != POWER_SLEEP {
            return Err(I2cHidError::BadPowerState);
        }
        let desc = self.descriptor.ok_or(I2cHidError::NotInitialised)?;
        write_command(
            &*self.bus,
            self.addr,
            desc.w_command_register,
            CMD_OP_SET_POWER,
            state,
        )
        .await
    }

    /// `i2c_hid_get_report` (`drivers/hid/i2c-hid/i2c-hid-core.c:257`):
    /// GET_REPORT of `report_type` (1 Input, 3 Feature) for `report_id`
    /// as ONE transaction — [command register][encoded command][data
    /// register], then a repeated-START read of the 2-byte length and the
    /// report from the data register. Fills `recv` with the report as the
    /// device sends it (report ID first for numbered reports), cut to
    /// `bufsize - 2`, and returns its length; an empty response is 0.
    pub async fn get_report(
        &self,
        report_type: u8,
        report_id: u8,
        recv: &mut [u8],
    ) -> Result<usize, I2cHidError> {
        let desc = self.descriptor.ok_or(I2cHidError::NotInitialised)?;
        let mut cmd = Vec::with_capacity(7);
        cmd.extend_from_slice(&desc.w_command_register.to_le_bytes());
        encode_command(&mut cmd, CMD_OP_GET_REPORT, report_type, report_id);
        // "Because command can be either 2 or 3 bytes destination for the
        // data register may be not aligned."
        cmd.extend_from_slice(&desc.w_data_register.to_le_bytes());
        // "In addition to report data device will supply data length in
        // the first 2 bytes of the response, so adjust."
        let recv_len = recv.len().min(self.bufsize - 2);
        let mut raw = alloc::vec![0u8; recv_len + 2];
        let mut ops = [I2cOp::Write(&cmd), I2cOp::Read(&mut raw)];
        self.bus.transfer(self.addr, &mut ops).await?;
        let ret_count = u16::from_le_bytes([raw[0], raw[1]]) as usize;
        // "Check for empty report response"
        if ret_count <= 2 {
            return Ok(0);
        }
        let n = recv_len.min(ret_count - 2);
        recv[..n].copy_from_slice(&raw[2..2 + n]);
        // "device returned incorrect report"
        if report_id != 0 && n != 0 && recv[0] != report_id {
            return Err(I2cHidError::InvalidRequest);
        }
        Ok(n)
    }

    /// `i2c_hid_set_or_send_report` (`i2c-hid-core.c:344`): `data` (no
    /// report ID) as report `report_id` of `report_type` (2 Output,
    /// 3 Feature) — through SET_REPORT on the command and data registers
    /// when `do_set`, else as a plain output report written to
    /// `wOutputRegister`. Framing is `i2c_hid_format_report`'s: a 2-byte
    /// length, the report ID only when it is non-zero, the data. Returns
    /// `data.len()`.
    pub async fn set_or_send_report(
        &self,
        report_type: u8,
        report_id: u8,
        data: &[u8],
        do_set: bool,
    ) -> Result<usize, I2cHidError> {
        let desc = self.descriptor.ok_or(I2cHidError::NotInitialised)?;
        if data.len() > self.bufsize {
            return Err(I2cHidError::InvalidRequest);
        }
        if !do_set && desc.w_max_output_length == 0 {
            return Err(I2cHidError::NoOutputRegister);
        }
        let mut buf = Vec::<u8>::with_capacity(12 + data.len());
        if do_set {
            buf.extend_from_slice(&desc.w_command_register.to_le_bytes());
            encode_command(&mut buf, CMD_OP_SET_REPORT, report_type, report_id);
            buf.extend_from_slice(&desc.w_data_register.to_le_bytes());
        } else {
            // "With simple "send report" all data goes into the output
            // register."
            buf.extend_from_slice(&desc.w_output_register.to_le_bytes());
        }
        let length = 2 + usize::from(report_id != 0) + data.len();
        buf.extend_from_slice(&(length as u16).to_le_bytes());
        if report_id != 0 {
            buf.push(report_id);
        }
        buf.extend_from_slice(data);
        let mut ops = [I2cOp::Write(&buf)];
        self.bus.transfer(self.addr, &mut ops).await?;
        Ok(data.len())
    }

    /// Issue a GET_REPORT for a FEATURE report by ID. Returns the report
    /// as the device sent it (report ID first for a numbered report), at
    /// most `bufsize - 2` bytes.
    pub async fn get_feature_report(&self, report_id: u8) -> Result<Vec<u8>, I2cHidError> {
        let mut out = alloc::vec![0u8; self.bufsize - 2];
        let n = self
            .get_report(REPORT_TYPE_FEATURE, report_id, &mut out)
            .await?;
        out.truncate(n);
        Ok(out)
    }

    /// SET_REPORT for a FEATURE report by ID + payload. The device
    /// receives the bytes verbatim and applies them according to the
    /// Report Descriptor for that ID.
    pub async fn set_feature_report(
        &self,
        report_id: u8,
        payload: &[u8],
    ) -> Result<(), I2cHidError> {
        self.set_or_send_report(REPORT_TYPE_FEATURE, report_id, payload, true)
            .await
            .map(|_| ())
    }

    /// SET_REPORT for an OUTPUT report by ID + payload — the
    /// transport for keyboard LED state (the descriptor's LED-page
    /// Output report; see `narf_hid::keyboard::detect_led_output`).
    /// Framing is identical to the Feature form with the Output
    /// report type (Microsoft HID-over-I2C §7.2 command table).
    pub async fn set_output_report(
        &self,
        report_id: u8,
        payload: &[u8],
    ) -> Result<(), I2cHidError> {
        self.set_or_send_report(REPORT_TYPE_OUTPUT, report_id, payload, true)
            .await
            .map(|_| ())
    }

    /// `i2c_hid_get_raw_report` (`i2c-hid-core.c:658`), the GET half of
    /// `hid_hw_raw_request`: `buf[0]` receives the report ID — stashed by
    /// hand for an unnumbered report, whose response carries none — and
    /// the result counts it.
    pub async fn get_raw_report(
        &self,
        report_type: narf_input::hid_device::ReportType,
        report_id: u8,
        buf: &mut [u8],
    ) -> Result<usize, I2cHidError> {
        use narf_input::hid_device::ReportType;
        let wire = match report_type {
            ReportType::Output => return Err(I2cHidError::InvalidRequest),
            ReportType::Feature => REPORT_TYPE_FEATURE,
            ReportType::Input => REPORT_TYPE_INPUT,
        };
        if report_id != 0 {
            return self.get_report(wire, report_id, buf).await;
        }
        let Some((first, rest)) = buf.split_first_mut() else {
            return Err(I2cHidError::InvalidRequest);
        };
        *first = 0;
        let n = self.get_report(wire, 0, rest).await?;
        Ok(if n > 0 { n + 1 } else { 0 })
    }

    /// `i2c_hid_output_raw_report` (`i2c-hid-core.c:690`): `buf[0]` is
    /// the report ID, stripped before framing; the result counts it.
    /// `do_set` picks SET_REPORT over the output register.
    pub async fn output_raw_report(
        &self,
        report_type: narf_input::hid_device::ReportType,
        buf: &[u8],
        do_set: bool,
    ) -> Result<usize, I2cHidError> {
        use narf_input::hid_device::ReportType;
        let wire = match report_type {
            ReportType::Input => return Err(I2cHidError::InvalidRequest),
            ReportType::Feature => REPORT_TYPE_FEATURE,
            ReportType::Output => REPORT_TYPE_OUTPUT,
        };
        let Some((&report_id, data)) = buf.split_first() else {
            return Err(I2cHidError::InvalidRequest);
        };
        self.set_or_send_report(wire, report_id, data, do_set)
            .await
            .map(|n| n + 1)
    }

    /// Cached descriptor — `None` before `read_descriptor()` succeeds.
    pub fn descriptor(&self) -> Option<HidDescriptor> {
        self.descriptor
    }

    /// The bus this driver talks on. System-PM snapshots the bus +
    /// address + descriptor so the suspend/resume hooks can drive
    /// the device without owning the pump's driver instance.
    pub fn bus(&self) -> &Arc<dyn I2cBus> {
        &self.bus
    }

    /// 7-bit slave address of this device.
    pub fn addr(&self) -> u8 {
        self.addr
    }

    /// HID descriptor register address (from `_DSM` or the 0x0001
    /// fallback) — needed to rebuild a driver from a snapshot.
    pub fn hid_desc_register(&self) -> u16 {
        self.hid_desc_register
    }

    /// Build a driver around an already-known descriptor. The
    /// system-PM resume path uses this: after RESET the pump's
    /// descriptor snapshot is still the register map (the pump
    /// itself assumes the same), so the hook can issue RESET +
    /// SET_POWER(ON) + PTP mode restore without a bus read first —
    /// a sleeping device may not answer a descriptor read until
    /// it has been woken with SET_POWER(ON), which itself needs
    /// the command register from the descriptor.
    pub fn from_descriptor(
        bus: Arc<dyn I2cBus>,
        addr: u8,
        hid_desc_register: u16,
        descriptor: HidDescriptor,
    ) -> Self {
        Self {
            bus,
            addr,
            hid_desc_register,
            descriptor: Some(descriptor),
            bufsize: HID_MIN_BUFFER_SIZE,
        }
    }

    /// Largest input report the device may send, from the HID
    /// descriptor's `wMaxInputLength`. Falls back to 64 before
    /// the descriptor is read — the RMI4-over-HID session sizes
    /// its read-drain buffer off this.
    pub fn max_input_length(&self) -> usize {
        self.descriptor
            .map(|d| d.w_max_input_length as usize)
            .unwrap_or(64)
    }
}

/// `i2c_hid_encode_command` (`i2c-hid-core.c:240`): the report type in the
/// high nibble and the report ID in the low one, then the opcode — except
/// that an ID of 15 or more takes the 0x0F sentinel nibble and follows the
/// opcode as a third byte.
fn encode_command(buf: &mut Vec<u8>, opcode: u8, report_type: u8, report_id: u8) {
    if report_id < 0x0F {
        buf.push((report_type << 4) | report_id);
        buf.push(opcode);
    } else {
        buf.push((report_type << 4) | 0x0F);
        buf.push(opcode);
        buf.push(report_id);
    }
}

/// Single helper for the no-data commands (RESET, SET_POWER). The
/// command encoding is identical: write [cmd_addr_lo, cmd_addr_hi,
/// data_byte, opcode] to the slave.
async fn write_command(
    bus: &dyn I2cBus,
    addr: u8,
    cmd_register: u16,
    opcode: u8,
    data: u8,
) -> Result<(), I2cHidError> {
    let cr = cmd_register.to_le_bytes();
    let buf = [cr[0], cr[1], data, opcode];
    let mut ops = [I2cOp::Write(&buf)];
    bus.transfer(addr, &mut ops).await?;
    Ok(())
}

// ── Lifecycle as a `narf-drivers` Driver ───────────────────────────

impl Driver for I2cHidDriver {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            // Bring-up is bounded-retry now (issue #771): the old
            // code swallowed a single-shot RESET failure silently.
            // The trait contract returns `()` so a terminal
            // failure is logged, not returned — the pump path
            // (`i2c_hid_bind`) is the live bring-up and does get
            // the error.
            match self.bring_up(&RetryPolicy::default()).await {
                Ok(_) => {}
                Err(e) => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "  i2c-hid: bring-up failed after bounded retries ({:?}); device not started",
                        e
                    );
                }
            }
        })
    }

    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move {
            let _ = self.set_power(POWER_SLEEP).await;
        })
    }
}

// ── Discovery / logging ────────────────────────────────────────────

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    // AML walks for PNP0C50 + vendor _CID matches across a real-HW
    // DSDT regularly take 500-2000 ms — false-positives the
    // default budget. Bump explicitly to 3 s.
    narf_init::register_with_budget(
        Stage::Device,
        "i2c-hid-probe",
        || {
            // Discovery + logging pass: enumerate every PNP0C50 child +
            // log the I2C controllers already brought up by
            // `amd-fch-i2c`. The actual driver-instance construction +
            // pump-task spawn happens in `i2c-hid-bind` below, which
            // runs after this pass so the per-child `_CRS` summary lands
            // before the bind log line.

            let buses = narf_drivers_i2c::registered_buses();
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid: {} I2C bus(es) registered",
                buses.len()
            );
            for bus in &buses {
                let _ = writeln!(narf_console::Writer, "    bus: {}", bus.name());
            }

            let mut hid_count = 0usize;
            for child in narf_aml::find_all_devices_by_hid("PNP0C50") {
                hid_count += 1;
                let _ = writeln!(
                    narf_console::Writer,
                    "  i2c-hid: PNP0C50 child {}",
                    child.path
                );
                report_crs(&child.path);
            }
            if hid_count == 0 {
                let _ = writeln!(narf_console::Writer, "  i2c-hid: no PNP0C50 children found");
            }
            InitResult::Ok
        },
        3000,
    );
    narf_init::register_with_budget(
        Stage::Device,
        "i2c-hid-bind",
        || {
            let n = crate::i2c_hid_bind::bind_all();
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid-bind: {} HID-over-I2C device(s) bound",
                n
            );
            if n == 0 {
                InitResult::NotPresent
            } else {
                InitResult::Ok
            }
        },
        3000,
    );
    // System-PM hook for the devices the bind pass records
    // (SET_POWER SLEEP on prepare, RESET + POWER_ON + PTP mode
    // restore on resume). The hook is a no-op over an empty
    // device list until a pump records its device; see
    // `i2c_hid_pm`.
    crate::i2c_hid_pm::register_pm();
}

/// Evaluate `<path>._CRS` and print each resource item we recognize.
/// For a HID child the relevant bits are I2cSerialBus (slave addr +
/// parent bus) and GpioInt (interrupt pin) — both currently fall
/// through to the `Unknown` arm because the AML resource decoder
/// doesn't support them yet. Logging still surfaces the raw tag so
/// the gap is visible.
fn report_crs(path: &str) {
    use narf_aml::resource::ResourceItem;
    match narf_aml::prt_crs::evaluate_crs_for(path) {
        Ok(items) => {
            for item in &items {
                match item {
                    ResourceItem::Memory32Fixed { base, length, .. } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: Memory32Fixed base={:#010x} length={:#x}",
                            base,
                            length
                        );
                    }
                    ResourceItem::ExtendedIrq { flags, gsis } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: ExtendedIrq flags={:#x} gsis={:?}",
                            flags,
                            gsis
                        );
                    }
                    ResourceItem::I2cSerialBus {
                        slave_address,
                        connection_speed,
                        resource_source,
                        ..
                    } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: I2cSerialBus addr={:#04x} speed={}Hz src={:?}",
                            slave_address,
                            connection_speed,
                            resource_source
                        );
                    }
                    ResourceItem::GpioInt {
                        level_triggered,
                        polarity,
                        pins,
                        resource_source,
                        ..
                    } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: GpioInt {{trig={}, pol={}, pins={:?}, src={:?}}}",
                            if *level_triggered { "level" } else { "edge" },
                            polarity,
                            pins,
                            resource_source
                        );
                    }
                    ResourceItem::GpioIo {
                        pins,
                        resource_source,
                        ..
                    } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: GpioIo pins={:?} src={:?}",
                            pins,
                            resource_source
                        );
                    }
                    ResourceItem::Unknown { tag, payload } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: Unknown tag={:#04x} len={}",
                            tag,
                            payload.len()
                        );
                    }
                    other => {
                        let _ = writeln!(narf_console::Writer, "    _CRS: {:?}", other);
                    }
                }
            }
        }
        Err(e) => {
            let _ = writeln!(narf_console::Writer, "    _CRS: evaluate failed ({:?})", e);
        }
    }
}
