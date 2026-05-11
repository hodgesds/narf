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
//!   (4F1C8DA2-D5A0-4C7B-8169-3D2DBFCA3C03) that surfaces
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
//! - GET_REPORT / SET_REPORT round-trip helpers for FEATURE reports
//!   (used for things like setting precision-touchpad mode).
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
}

impl From<I2cError> for I2cHidError {
    fn from(e: I2cError) -> Self {
        I2cHidError::Bus(e)
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
}

impl I2cHidDriver {
    pub fn new(bus: Arc<dyn I2cBus>, addr: u8, hid_desc_register: u16) -> Self {
        Self {
            bus,
            addr,
            hid_desc_register,
            descriptor: None,
        }
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
        let mut total = Vec::<u8>::new();
        total.resize(max_len.max(2), 0);
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
        let mut out = Vec::<u8>::new();
        out.resize(desc.w_report_desc_length as usize, 0);
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

    /// Issue a GET_REPORT for a FEATURE report by ID. Reads the
    /// payload bytes (length-prefixed) into a fresh Vec.
    pub async fn get_feature_report(&self, report_id: u8) -> Result<Vec<u8>, I2cHidError> {
        let desc = self.descriptor.ok_or(I2cHidError::NotInitialised)?;
        // GET_REPORT command: opcode in low byte, report-type +
        // report-id in next byte, then the Data Register (LE u16),
        // then read length-prefixed payload from Data Register.
        let cmd_addr = desc.w_command_register.to_le_bytes();
        let data_addr = desc.w_data_register.to_le_bytes();
        let cmd = [
            cmd_addr[0],
            cmd_addr[1],
            (REPORT_TYPE_FEATURE << 4) | (report_id & 0x0f),
            CMD_OP_GET_REPORT,
            data_addr[0],
            data_addr[1],
        ];
        let mut len_buf = [0u8; 2];
        // Phase 1: write the command. STOP, then a fresh START with
        // the Data Register address + read of length prefix.
        let mut ops1 = [I2cOp::Write(&cmd)];
        self.bus.transfer(self.addr, &mut ops1).await?;
        let mut ops2 = [I2cOp::Write(&data_addr), I2cOp::Read(&mut len_buf)];
        self.bus.transfer(self.addr, &mut ops2).await?;
        let len = u16::from_le_bytes(len_buf) as usize;
        if len < 2 {
            return Err(I2cHidError::ShortReport);
        }
        let payload_len = len - 2;
        let mut payload = Vec::<u8>::new();
        payload.resize(payload_len, 0);
        // Phase 2 continued: read the rest of the report. The Data
        // Register stays at the next byte after the length prefix
        // for a continuation read against the same slave address.
        let mut ops3 = [I2cOp::Read(&mut payload)];
        self.bus.transfer(self.addr, &mut ops3).await?;
        Ok(payload)
    }

    /// SET_REPORT for a FEATURE report by ID + payload. The device
    /// receives the bytes verbatim and applies them according to the
    /// Report Descriptor for that ID.
    pub async fn set_feature_report(
        &self,
        report_id: u8,
        payload: &[u8],
    ) -> Result<(), I2cHidError> {
        let desc = self.descriptor.ok_or(I2cHidError::NotInitialised)?;
        let cmd_addr = desc.w_command_register.to_le_bytes();
        let data_addr = desc.w_data_register.to_le_bytes();
        // Total length includes the 2-byte length prefix + the
        // 1-byte report ID echo + the payload.
        let total_len = 2u16 + 1 + payload.len() as u16;
        let total_le = total_len.to_le_bytes();
        let mut buf = Vec::<u8>::with_capacity(8 + payload.len());
        buf.extend_from_slice(&cmd_addr);
        buf.push((REPORT_TYPE_FEATURE << 4) | (report_id & 0x0f));
        buf.push(CMD_OP_SET_REPORT);
        buf.extend_from_slice(&data_addr);
        buf.extend_from_slice(&total_le);
        buf.push(report_id);
        buf.extend_from_slice(payload);
        let mut ops = [I2cOp::Write(&buf)];
        self.bus.transfer(self.addr, &mut ops).await?;
        Ok(())
    }

    /// Cached descriptor — `None` before `read_descriptor()` succeeds.
    pub fn descriptor(&self) -> Option<HidDescriptor> {
        self.descriptor
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
            // Read descriptor first; without it we can't talk to
            // any of the operating registers.
            let _ = self.read_descriptor().await;
            // Then RESET to a known state. Failure is logged and
            // swallowed — the input-pump task can retry later.
            let _ = self.reset().await;
            // Power up explicitly. Some devices ship asleep.
            let _ = self.set_power(POWER_ON).await;
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
    narf_init::register(Stage::Device, "i2c-hid-probe", || {
        // Discovery pass: enumerate every PNP0C50 child + log the
        // I2C controllers already brought up by `amd-fch-i2c`. Once
        // narf-aml grows I2cSerialBus + GpioInt resource decoding,
        // this pass can match a child to its parent bus by the
        // ResourceSource path inside I2cSerialBus and instantiate
        // an `I2cHidDriver` automatically. Until then, instantiation
        // is hand-driven by board-bring-up shims (and by tests).

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
    });
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
                            base, length
                        );
                    }
                    ResourceItem::ExtendedIrq { flags, gsis } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: ExtendedIrq flags={:#x} gsis={:?}",
                            flags, gsis
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
                            slave_address, connection_speed, resource_source
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
                            pins, resource_source
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

// REPORT_TYPE_INPUT / OUTPUT are exported in case future code (e.g.
// a debug shell that issues GET_REPORT against an Input report
// directly) needs them; suppress unused warnings until then.
#[allow(dead_code)]
const _ENSURE_REPORT_TYPES_LIVE: (u8, u8) = (REPORT_TYPE_INPUT, REPORT_TYPE_OUTPUT);
