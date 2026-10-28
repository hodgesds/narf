//! ACPI Smart Battery Subsystem (SBS) driver — clean-room.
//!
//! Specifications (SBS Implementers Forum + ACPI):
//!
//! * **Smart Battery Data Specification** rev 1.1 — the battery
//!   command set, `BatteryMode` / `BatteryStatus` bit layouts,
//!   unit scaling, block-string format.
//! * **Smart Battery Selector Specification** rev 1.1 —
//!   `SelectorState()` (0x01) and `SelectorInfo()` (0x04) on the
//!   selector device.
//! * **Smart Battery Charger Specification** rev 1.1 §6.1.9 — a
//!   charger with embedded selector functions exposes them at
//!   `selector command | 0x20` on the charger address, and
//!   advertises the fact in `ChargerSpecInfo()` (0x11) bit 4.
//! * **Smart Battery System Manager Specification** rev 1.0 —
//!   `BatterySystemState()` (0x01) on the System Manager.
//! * **ACPI 6.4 §10.1** — the `ACPI0002` subsystem: `_SBS`
//!   returns the maximum number of batteries supported (0 = a
//!   single battery and no manager/selector); fixed SMBus
//!   addresses (Table 10.1): host 0x08, charger 0x09, System
//!   Manager / Selector 0x0A, battery 0x0B.
//! * **SMBus Specification 3.0** — Read/Write Word and Read Block
//!   framing (low byte first; a block read leads with a count
//!   byte, and SBS block payloads lead with a string-length byte).
//!
//! An SBS machine has **no** control-method battery (`PNP0C0A`):
//! the battery lives behind the SMBus host at the fixed address
//! 0x0B. This driver discovers the `ACPI0002` subsystem, probes
//! the battery (or batteries, behind a selector / system
//! manager), and publishes each battery through the same
//! surfaces the control-method driver uses:
//!
//! * `narf_power::register_source` — one `PowerSource` per slot;
//! * the power service's battery provider (see
//!   `power_service::battery_snapshot`) falls back to
//!   [`snapshot_first`] when no `PNP0C0A` device exists, yielding
//!   the same `(BatteryInfo, BatteryState)` pair in the same
//!   units — consumers of `narf_power::service::snapshot()` see
//!   one battery abstraction regardless of transport.
//!
//! Failure discipline: a battery that NAKs its probe is simply
//! absent. A battery that ACKs but returns implausible data
//! (zero design capacity, state-of-charge above 100 %, a nonzero
//! `BatteryStatus` error code, a block string whose length byte
//! disagrees with the transfer) is rejected with
//! [`SbsError::Garbage`] and never published — no value is ever
//! fabricated to fill a gap.
//!
//! Polling: status changes are surfaced through the
//! `narf_power::battery` notify fan-out (0x80 StatusChanged /
//! CapacityLow), driven from [`SbsBattery::poll`], which the
//! snapshot path invokes opportunistically — the same effective
//! cadence as the control-method `_BST` path. The spec's event
//! path (SMBus Alarm Notify → EC SCI, ACPI §10.1.1) is not
//! wired: the in-tree ICH SMBus host has no host-notify
//! receiver, so polling is the v1 mechanism.
//!
//! PEC (SMBus packet error checking) is not used, matching the
//! default of other SBS host stacks; the ICH host driver does
//! not expose PEC framing. The DesignWare I2C host is not wired
//! as a transport here — ACPI0002 subsystems hang off the SMBus
//! host by definition (ACPI §10.1); the [`SbsTransport`] seam is
//! where an I2C-backed transport would attach.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_acpi::battery::{BatteryInfo, BatteryState, BatteryStatus, BatteryTech, PowerUnit};
use narf_aml::eval::evaluate_method;
use narf_aml::find_all_devices_by_hid;
use narf_lib::sync::IrqSafeSpinLock;
use narf_power::{register_source, PowerSource, PowerSourceType};

use crate::smbus::SmbusError;

// ── Fixed SMBus addresses (ACPI 6.4 Table 10.1) ─────────────────

/// Smart Battery Charger.
pub const ADDR_CHARGER: u8 = 0x09;
/// Smart Battery System Manager **or** Selector (same address;
/// the device answers either `BatterySystemState()` or the
/// selector command set).
pub const ADDR_MANAGER_OR_SELECTOR: u8 = 0x0A;
/// Smart Battery. All batteries in a multi-battery subsystem
/// share this address; the selector routes it.
pub const ADDR_BATTERY: u8 = 0x0B;

// ── Battery command set (SBS Data Specification, Table 3.1) ─────

pub const CMD_MANUFACTURER_ACCESS: u8 = 0x00;
pub const CMD_REMAINING_CAPACITY_ALARM: u8 = 0x01;
pub const CMD_REMAINING_TIME_ALARM: u8 = 0x02;
pub const CMD_BATTERY_MODE: u8 = 0x03;
pub const CMD_AT_RATE: u8 = 0x04;
pub const CMD_TEMPERATURE: u8 = 0x08;
pub const CMD_VOLTAGE: u8 = 0x09;
pub const CMD_CURRENT: u8 = 0x0A;
pub const CMD_AVERAGE_CURRENT: u8 = 0x0B;
pub const CMD_MAX_ERROR: u8 = 0x0C;
pub const CMD_RELATIVE_STATE_OF_CHARGE: u8 = 0x0D;
pub const CMD_ABSOLUTE_STATE_OF_CHARGE: u8 = 0x0E;
pub const CMD_REMAINING_CAPACITY: u8 = 0x0F;
pub const CMD_FULL_CHARGE_CAPACITY: u8 = 0x10;
pub const CMD_RUN_TIME_TO_EMPTY: u8 = 0x11;
pub const CMD_AVERAGE_TIME_TO_EMPTY: u8 = 0x12;
pub const CMD_AVERAGE_TIME_TO_FULL: u8 = 0x13;
pub const CMD_CHARGING_CURRENT: u8 = 0x14;
pub const CMD_CHARGING_VOLTAGE: u8 = 0x15;
pub const CMD_BATTERY_STATUS: u8 = 0x16;
pub const CMD_CYCLE_COUNT: u8 = 0x17;
pub const CMD_DESIGN_CAPACITY: u8 = 0x18;
pub const CMD_DESIGN_VOLTAGE: u8 = 0x19;
pub const CMD_SPECIFICATION_INFO: u8 = 0x1A;
pub const CMD_MANUFACTURE_DATE: u8 = 0x1B;
pub const CMD_SERIAL_NUMBER: u8 = 0x1C;
pub const CMD_MANUFACTURER_NAME: u8 = 0x20;
pub const CMD_DEVICE_NAME: u8 = 0x21;
pub const CMD_DEVICE_CHEMISTRY: u8 = 0x22;
pub const CMD_MANUFACTURER_DATA: u8 = 0x23;

/// `RunTimeToEmpty()` value meaning "not available" (the battery
/// is charging, or cannot estimate).
pub const RUN_TIME_UNAVAILABLE: u16 = 0xFFFF;

// ── Charger commands used by this driver (SBCS) ─────────────────

/// `ChargerSpecInfo()` on the charger.
pub const CMD_CHARGER_SPEC_INFO: u8 = 0x11;
/// ChargerSpecInfo bit 4: the charger also implements the System
/// Manager / Selector functions (ACPI 6.4 §10.1.1.2).
pub const CHARGER_SPEC_INFO_SELECTOR_SUPPORT: u16 = 1 << 4;

// ── Selector / System Manager commands (SBSS / SBSM) ────────────

/// `SelectorState()` on a selector; `BatterySystemState()` on a
/// System Manager. Same address + command by design.
pub const CMD_SELECTOR_STATE: u8 = 0x01;
/// `SelectorInfo()` on a selector.
pub const CMD_SELECTOR_INFO: u8 = 0x04;
/// SelectorState bits 0–3: `OK_TO_USE_x` — one bit per battery
/// position. A bit reads zero when the battery is not present,
/// and is set automatically on insertion (SBSS §SelectorState).
pub const SELECTOR_OK_TO_USE_MASK: u16 = 0x000F;
/// SelectorState bits 8–11: `USE_NEXT_x` — the host sets exactly
/// one bit to select which battery the selector uses next.
pub const SELECTOR_USE_NEXT_MASK: u16 = 0x0F00;
/// Bit position of the `USE_NEXT_x` nibble.
pub const SELECTOR_USE_NEXT_SHIFT: u32 = 8;

/// `BatteryMode()` bits (SBS Data Specification §5.1.4). Only
/// the bits this driver consumes or reports are named.
pub mod battery_mode {
    /// The battery contains an internal charge controller.
    pub const INTERNAL_CHARGE_CONTROLLER: u16 = 1 << 0;
    /// The internal charge controller is enabled.
    pub const CHARGE_CONTROLLER_ENABLED: u16 = 1 << 8;
    /// This is the primary battery in a multi-battery system.
    pub const PRIMARY_BATTERY: u16 = 1 << 9;
    /// Set: capacity / current values are in 10 mW / 10 mWh
    /// units. Clear: mA / mAh.
    pub const CAPACITY_MODE: u16 = 1 << 15;
}

/// `BatteryStatus()` bits (SBS Data Specification §5.1.21).
pub mod battery_status {
    pub const OVER_CHARGED_ALARM: u16 = 1 << 15;
    pub const TERMINATE_CHARGE_ALARM: u16 = 1 << 14;
    pub const OVER_TEMP_ALARM: u16 = 1 << 12;
    pub const TERMINATE_DISCHARGE_ALARM: u16 = 1 << 11;
    pub const REMAINING_CAPACITY_ALARM: u16 = 1 << 9;
    pub const REMAINING_TIME_ALARM: u16 = 1 << 8;
    pub const INITIALIZED: u16 = 1 << 7;
    pub const DISCHARGING: u16 = 1 << 6;
    pub const FULLY_CHARGED: u16 = 1 << 5;
    pub const FULLY_DISCHARGED: u16 = 1 << 4;
    /// Bits 0–3: error code of the most recent operation
    /// (Appendix C; 0 = OK). A nonzero code means the battery
    /// itself is reporting trouble — reads are refused.
    pub const ERROR_CODE_MASK: u16 = 0x000F;
}

// ── Errors ──────────────────────────────────────────────────────

/// Typed SBS failure. `NotPresent` is the healthy "no battery
/// here" outcome; `Garbage` is a device that answered but whose
/// data failed validation — the two are never conflated, and
/// neither is ever papered over with fabricated values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SbsError {
    /// No SMBus host controller has been probed on this machine.
    NoController,
    /// Transport-level failure other than a NAK (bus error,
    /// timeout, framing error on the host controller).
    Transport(SmbusError),
    /// The addressed device did not acknowledge (SMBus NAK) —
    /// the slot / device is absent.
    NotPresent,
    /// The device answered, but its data failed validation.
    Garbage(&'static str),
    /// The subsystem shape is outside what this driver models.
    Unsupported(&'static str),
}

impl From<SmbusError> for SbsError {
    fn from(e: SmbusError) -> Self {
        match e {
            // DEV_ERR on the ICH host is a NAK: the addressed
            // device is not there (or refused the command).
            SmbusError::DeviceError => SbsError::NotPresent,
            other => SbsError::Transport(other),
        }
    }
}

// ── Transport seam ──────────────────────────────────────────────

/// The SMBus conversations the SBS stack needs, abstracted so
/// fixtures can script a spec-shaped device and the production
/// path can ride the ICH SMBus host. A second backing (e.g. a
/// DesignWare I2C client using SMBus-compatible framing) can
/// attach at this seam without touching the codec.
pub trait SbsTransport {
    /// SMBus Read Word at (`addr`, `cmd`), low byte first.
    fn read_word(&self, addr: u8, cmd: u8) -> Result<u16, SbsError>;
    /// SMBus Write Word at (`addr`, `cmd`), low byte first.
    fn write_word(&self, addr: u8, cmd: u8, value: u16) -> Result<(), SbsError>;
    /// SMBus Read Block at (`addr`, `cmd`); returns the payload
    /// bytes that followed the on-wire count byte. For SBS block
    /// strings that payload is `[string_length, chars...]`.
    fn read_block(&self, addr: u8, cmd: u8) -> Result<Vec<u8>, SbsError>;
}

/// Production transport over the platform crate's ICH SMBus host
/// controller. Stateless: every call borrows the probed
/// controller through `smbus::with_controller`.
#[derive(Debug)]
pub struct IchSmbusTransport;

impl SbsTransport for IchSmbusTransport {
    fn read_word(&self, addr: u8, cmd: u8) -> Result<u16, SbsError> {
        match crate::smbus::with_controller(|c| c.read_word_data(addr, cmd)) {
            Some(r) => r.map_err(SbsError::from),
            None => Err(SbsError::NoController),
        }
    }

    fn write_word(&self, addr: u8, cmd: u8, value: u16) -> Result<(), SbsError> {
        match crate::smbus::with_controller(|c| c.write_word_data(addr, cmd, value)) {
            Some(r) => r.map_err(SbsError::from),
            None => Err(SbsError::NoController),
        }
    }

    fn read_block(&self, addr: u8, cmd: u8) -> Result<Vec<u8>, SbsError> {
        let mut buf = [0u8; 32];
        match crate::smbus::with_controller(|c| c.read_block_data(addr, cmd, &mut buf)) {
            Some(Ok(n)) => Ok(buf[..n].to_vec()),
            Some(Err(e)) => Err(SbsError::from(e)),
            None => Err(SbsError::NoController),
        }
    }
}

// ── Spec decoders (pure) ────────────────────────────────────────

/// `SpecificationInfo()` (SBS Data Specification §5.1.25):
/// revision (bits 0–3), version (bits 4–7), voltage scale
/// (bits 8–11), current scale (bits 12–15). The scales describe
/// the raw register units of the broadcast values; the command
/// functions this driver reads (`Voltage()`, `Current()`, …)
/// already return engineering units (mV / mA / mAh, or 10 mW
/// units under `CAPACITY_MODE`), so the scales are decoded and
/// exposed here rather than applied a second time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpecificationInfo {
    pub revision: u8,
    pub version: u8,
    pub v_scale: u8,
    pub ip_scale: u8,
}

impl SpecificationInfo {
    pub fn decode(raw: u16) -> Self {
        Self {
            revision: (raw & 0x0F) as u8,
            version: ((raw >> 4) & 0x0F) as u8,
            v_scale: ((raw >> 8) & 0x0F) as u8,
            ip_scale: ((raw >> 12) & 0x0F) as u8,
        }
    }
}

/// `ManufactureDate()` (SBS Data Specification §5.1.26):
/// `(year − 1980) × 512 + month × 32 + day` — day in bits 0–4,
/// month in bits 5–8, years since 1980 in bits 9–15.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManufactureDate {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl ManufactureDate {
    pub fn decode(raw: u16) -> Self {
        Self {
            day: (raw & 0x1F) as u8,
            month: ((raw >> 5) & 0x0F) as u8,
            year: 1980 + (raw >> 9),
        }
    }
}

/// Decode an SBS block string payload (`[length, chars...]`,
/// SBS Data Specification §4.4.1). The length byte must agree
/// exactly with the transfer length, and the characters must be
/// printable ASCII — anything else is garbage and refused, never
/// lossy-decoded into a published identity string.
pub fn decode_block_string(payload: &[u8]) -> Result<String, SbsError> {
    if payload.is_empty() {
        return Err(SbsError::Garbage("empty block string"));
    }
    let len = payload[0] as usize;
    if len != payload.len() - 1 {
        return Err(SbsError::Garbage(
            "block string length byte disagrees with transfer length",
        ));
    }
    let bytes = &payload[1..];
    if bytes.iter().any(|b| !(0x20..=0x7E).contains(b)) {
        return Err(SbsError::Garbage(
            "block string contains a non-printable byte",
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| SbsError::Garbage("block string is not valid UTF-8"))
}

// ── Typed battery views ─────────────────────────────────────────

/// Static battery information, decoded from the SBS command set
/// with units normalised: capacities and the capacity alarm are
/// in mAh, or in mWh when `capacity_in_10mw_units` is set (the
/// raw 10 mW-unit values have already been multiplied by 10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SbsInfo {
    /// `BatteryMode.CAPACITY_MODE`: raw capacity/current units
    /// were 10 mWh / 10 mW rather than mAh / mA.
    pub capacity_in_10mw_units: bool,
    pub design_capacity: u32,
    pub full_charge_capacity: u32,
    pub design_voltage_mv: u32,
    pub cycle_count: u16,
    pub serial_number: u16,
    pub manufacture_date: ManufactureDate,
    pub specification_info: SpecificationInfo,
    /// `RemainingCapacityAlarm()` threshold, scaled like the
    /// capacities. This is the threshold at which the battery
    /// raises `REMAINING_CAPACITY_ALARM`.
    pub capacity_alarm: u32,
    pub manufacturer_name: String,
    pub device_name: String,
    pub device_chemistry: String,
}

impl SbsInfo {
    pub fn power_unit(&self) -> PowerUnit {
        if self.capacity_in_10mw_units {
            PowerUnit::MilliWatt
        } else {
            PowerUnit::MilliAmp
        }
    }

    /// Map onto the shared battery-info surface the control-
    /// method battery publishes, so power-service consumers see
    /// one shape. SBS has a single alarm threshold where `_BIF`
    /// has separate warning/low fields; it is reported in both.
    pub fn to_battery_info(&self) -> BatteryInfo {
        BatteryInfo {
            power_unit: self.power_unit(),
            design_capacity: self.design_capacity,
            last_full_capacity: self.full_charge_capacity,
            // Smart batteries are rechargeable by construction
            // (the subsystem includes a charger).
            technology: BatteryTech::Secondary,
            design_voltage_mv: self.design_voltage_mv,
            design_capacity_warning: self.capacity_alarm,
            design_capacity_low: self.capacity_alarm,
            model_number: self.device_name.clone(),
            serial_number: alloc::format!("{}", self.serial_number),
            battery_type: self.device_chemistry.clone(),
            oem_info: self.manufacturer_name.clone(),
        }
    }
}

/// Dynamic battery state, decoded from the SBS command set.
/// `current` is signed (positive = charging, per the Data
/// Specification) and in mA, or in 10 mW units when the
/// battery's `CAPACITY_MODE` is set — the same units as the
/// capacities in [`SbsInfo`]. `remaining_capacity` is in those
/// capacity units, unscaled (apply the ×10 via `SbsInfo` when
/// mapping; see [`SbsStatus::to_battery_state`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SbsStatus {
    /// Raw `BatteryStatus()` word.
    pub status_word: u16,
    /// Error code field of the status word (bits 0–3); reads are
    /// refused unless this is 0, so a returned status always has
    /// `error_code == 0`.
    pub error_code: u8,
    /// `Temperature()` in 0.1 °K units.
    pub temperature_01k: u16,
    /// `Voltage()` in mV.
    pub voltage_mv: u16,
    /// `Current()` — signed; positive while charging.
    pub current: i32,
    /// `RelativeStateOfCharge()` in percent, 0–100 (validated).
    pub relative_state_of_charge: u8,
    /// `RemainingCapacity()` in the battery's capacity units.
    pub remaining_capacity: u32,
    /// `RunTimeToEmpty()` in minutes; `None` when the battery
    /// reports 0xFFFF (unavailable).
    pub run_time_to_empty_min: Option<u16>,
}

impl SbsStatus {
    pub fn is_discharging(&self) -> bool {
        self.status_word & battery_status::DISCHARGING != 0
    }

    pub fn is_fully_charged(&self) -> bool {
        self.status_word & battery_status::FULLY_CHARGED != 0
    }

    pub fn is_fully_discharged(&self) -> bool {
        self.status_word & battery_status::FULLY_DISCHARGED != 0
    }

    pub fn capacity_alarm(&self) -> bool {
        self.status_word & battery_status::REMAINING_CAPACITY_ALARM != 0
    }

    /// Temperature in milli-°C: 0.1 °K units → °C is
    /// `raw / 10 − 273.15`.
    pub fn temperature_mc(&self) -> i32 {
        self.temperature_01k as i32 * 100 - 273_150
    }

    /// Map onto the shared battery-state surface. ACPI's state
    /// carries a magnitude rate with the direction in the status
    /// bits, so the SBS signed current is split accordingly:
    /// the `DISCHARGING` bit wins; otherwise a positive current
    /// means charging. `CRITICAL` follows the ACPI meaning —
    /// remaining capacity at/below the low threshold, here the
    /// battery's own capacity-alarm threshold — or a
    /// fully-discharged report.
    pub fn to_battery_state(&self, info: &SbsInfo) -> BatteryState {
        let scale: u32 = if info.capacity_in_10mw_units { 10 } else { 1 };
        let remaining = self.remaining_capacity * scale;
        let mut bits = 0u32;
        if self.is_discharging() {
            bits |= BatteryStatus::DISCHARGING;
        } else if self.current > 0 {
            bits |= BatteryStatus::CHARGING;
        }
        if self.is_fully_discharged() || remaining <= info.capacity_alarm {
            bits |= BatteryStatus::CRITICAL;
        }
        BatteryState {
            status: BatteryStatus(bits),
            present_rate: self.current.unsigned_abs() * scale,
            remaining_capacity: remaining,
            present_voltage_mv: self.voltage_mv as u32,
        }
    }
}

// ── Selector / manager ──────────────────────────────────────────

/// Where the selector functions live: on the standalone device
/// at 0x0A, or embedded in the charger at 0x09 with the command
/// codes offset by 0x20 (SBCS §6.1.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectorKind {
    Standalone,
    ChargerEmbedded,
}

impl SelectorKind {
    fn state_cmd(self) -> (u8, u8) {
        match self {
            SelectorKind::Standalone => (ADDR_MANAGER_OR_SELECTOR, CMD_SELECTOR_STATE),
            SelectorKind::ChargerEmbedded => (ADDR_CHARGER, CMD_SELECTOR_STATE | 0x20),
        }
    }

    fn info_cmd(self) -> (u8, u8) {
        match self {
            SelectorKind::Standalone => (ADDR_MANAGER_OR_SELECTOR, CMD_SELECTOR_INFO),
            SelectorKind::ChargerEmbedded => (ADDR_CHARGER, CMD_SELECTOR_INFO | 0x20),
        }
    }
}

/// `SelectorInfo()` (SBSS §5.3): bits 0–3 are the per-position
/// supported mask, bits 4–7 the specification revision
/// (1 = 1.0, 2 = 1.1, 3 = 1.1 with PEC), bit 8 reports whether
/// the selector reports charger status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectorInfo {
    pub supported_mask: u8,
    pub revision: u8,
    pub charging_indicator: bool,
}

impl SelectorInfo {
    pub fn decode(raw: u16) -> Self {
        Self {
            supported_mask: (raw & 0x0F) as u8,
            revision: ((raw >> 4) & 0x0F) as u8,
            charging_indicator: raw & (1 << 8) != 0,
        }
    }
}

fn selector_state<T: SbsTransport>(t: &T, kind: SelectorKind) -> Result<u16, SbsError> {
    let (addr, cmd) = kind.state_cmd();
    t.read_word(addr, cmd)
}

fn selector_info<T: SbsTransport>(t: &T, kind: SelectorKind) -> Result<SelectorInfo, SbsError> {
    let (addr, cmd) = kind.info_cmd();
    Ok(SelectorInfo::decode(t.read_word(addr, cmd)?))
}

/// Point the selector at `slot`: read-modify-write of
/// `SelectorState()` replacing only the `USE_NEXT_x` nibble.
/// A no-op when the slot is already selected, so repeated polls
/// don't generate bus traffic.
fn selector_select<T: SbsTransport>(t: &T, kind: SelectorKind, slot: u8) -> Result<(), SbsError> {
    let cur = selector_state(t, kind)?;
    let next = (cur & !SELECTOR_USE_NEXT_MASK)
        | (((1u16 << slot) << SELECTOR_USE_NEXT_SHIFT) & SELECTOR_USE_NEXT_MASK);
    if next != cur {
        let (addr, cmd) = kind.state_cmd();
        t.write_word(addr, cmd, next)?;
    }
    Ok(())
}

/// What, if anything, multiplexes the battery address 0x0B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagerKind {
    /// Single battery (or no working manager): 0x0B is direct.
    None,
    /// A selector routes 0x0B per `SelectorState()`.
    Selector(SelectorKind),
    /// A System Manager answers `BatterySystemState()` but has
    /// no selector command set; it multiplexes autonomously, so
    /// only the battery it presents is published.
    SystemManager,
}

// ── Battery ─────────────────────────────────────────────────────

/// Outcome of one [`SbsBattery::poll`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollOutcome {
    /// The status word changed since the previous poll (the
    /// first successful poll always reports a change).
    pub status_changed: bool,
    /// `REMAINING_CAPACITY_ALARM` rose on this poll.
    pub capacity_low: bool,
    /// The freshly-read status.
    pub status: SbsStatus,
}

/// One smart battery behind a transport. Owns its static info
/// (read once at enumeration) and re-reads dynamic state on
/// demand.
#[derive(Debug)]
pub struct SbsBattery<T: SbsTransport> {
    transport: Arc<T>,
    slot: u8,
    selector: Option<SelectorKind>,
    info: SbsInfo,
    last_status_word: Option<u16>,
}

impl<T: SbsTransport> SbsBattery<T> {
    pub fn slot(&self) -> u8 {
        self.slot
    }

    pub fn info(&self) -> &SbsInfo {
        &self.info
    }

    /// Read the full static info set from the battery currently
    /// addressed at 0x0B (selection, if any, is the caller's
    /// job). Validates the values a published battery must have:
    /// nonzero design capacity, full-charge capacity and design
    /// voltage, and well-formed block strings.
    fn read_info(t: &T) -> Result<SbsInfo, SbsError> {
        let mode = t.read_word(ADDR_BATTERY, CMD_BATTERY_MODE)?;
        let capacity_in_10mw_units = mode & battery_mode::CAPACITY_MODE != 0;
        let scale: u32 = if capacity_in_10mw_units { 10 } else { 1 };
        let specification_info =
            SpecificationInfo::decode(t.read_word(ADDR_BATTERY, CMD_SPECIFICATION_INFO)?);
        let design_capacity = t.read_word(ADDR_BATTERY, CMD_DESIGN_CAPACITY)? as u32 * scale;
        if design_capacity == 0 {
            return Err(SbsError::Garbage("design capacity reads zero"));
        }
        let full_charge_capacity =
            t.read_word(ADDR_BATTERY, CMD_FULL_CHARGE_CAPACITY)? as u32 * scale;
        if full_charge_capacity == 0 {
            return Err(SbsError::Garbage("full charge capacity reads zero"));
        }
        let design_voltage_mv = t.read_word(ADDR_BATTERY, CMD_DESIGN_VOLTAGE)? as u32;
        if design_voltage_mv == 0 {
            return Err(SbsError::Garbage("design voltage reads zero"));
        }
        let cycle_count = t.read_word(ADDR_BATTERY, CMD_CYCLE_COUNT)?;
        let serial_number = t.read_word(ADDR_BATTERY, CMD_SERIAL_NUMBER)?;
        let manufacture_date =
            ManufactureDate::decode(t.read_word(ADDR_BATTERY, CMD_MANUFACTURE_DATE)?);
        let capacity_alarm =
            t.read_word(ADDR_BATTERY, CMD_REMAINING_CAPACITY_ALARM)? as u32 * scale;
        let manufacturer_name = read_block_string(t, CMD_MANUFACTURER_NAME)?;
        let device_name = read_block_string(t, CMD_DEVICE_NAME)?;
        let device_chemistry = read_block_string(t, CMD_DEVICE_CHEMISTRY)?;
        Ok(SbsInfo {
            capacity_in_10mw_units,
            design_capacity,
            full_charge_capacity,
            design_voltage_mv,
            cycle_count,
            serial_number,
            manufacture_date,
            specification_info,
            capacity_alarm,
            manufacturer_name,
            device_name,
            device_chemistry,
        })
    }

    /// If this battery lives behind a selector, select its slot
    /// and then verify the battery now answering at 0x0B is the
    /// one enumerated for the slot (serial number match). The
    /// check defeats a selector that silently failed to route:
    /// the driver would otherwise publish one battery's data
    /// under another slot's identity.
    fn select_and_verify(&self) -> Result<(), SbsError> {
        if let Some(kind) = self.selector {
            selector_select(&*self.transport, kind, self.slot)?;
            let serial = self.transport.read_word(ADDR_BATTERY, CMD_SERIAL_NUMBER)?;
            if serial != self.info.serial_number {
                return Err(SbsError::Garbage(
                    "selector did not route to the enumerated battery (serial mismatch)",
                ));
            }
        }
        Ok(())
    }

    /// Read and validate the dynamic state. Refuses (typed
    /// `Garbage`) a nonzero status error code, a zero temperature
    /// or voltage, and a state-of-charge above 100 %.
    pub fn read_status(&self) -> Result<SbsStatus, SbsError> {
        self.select_and_verify()?;
        let t = &*self.transport;
        let status_word = t.read_word(ADDR_BATTERY, CMD_BATTERY_STATUS)?;
        let error_code = (status_word & battery_status::ERROR_CODE_MASK) as u8;
        if error_code != 0 {
            return Err(SbsError::Garbage(
                "battery status carries a nonzero error code",
            ));
        }
        let temperature_01k = t.read_word(ADDR_BATTERY, CMD_TEMPERATURE)?;
        if temperature_01k == 0 {
            return Err(SbsError::Garbage("temperature reads zero (0 K)"));
        }
        let voltage_mv = t.read_word(ADDR_BATTERY, CMD_VOLTAGE)?;
        if voltage_mv == 0 {
            return Err(SbsError::Garbage("voltage reads zero"));
        }
        let current = t.read_word(ADDR_BATTERY, CMD_CURRENT)? as i16 as i32;
        let rsoc = t.read_word(ADDR_BATTERY, CMD_RELATIVE_STATE_OF_CHARGE)?;
        if rsoc > 100 {
            return Err(SbsError::Garbage(
                "relative state of charge above 100 percent",
            ));
        }
        let remaining_capacity = t.read_word(ADDR_BATTERY, CMD_REMAINING_CAPACITY)? as u32;
        let rte = t.read_word(ADDR_BATTERY, CMD_RUN_TIME_TO_EMPTY)?;
        Ok(SbsStatus {
            status_word,
            error_code,
            temperature_01k,
            voltage_mv,
            current,
            relative_state_of_charge: rsoc as u8,
            remaining_capacity,
            run_time_to_empty_min: if rte == RUN_TIME_UNAVAILABLE {
                None
            } else {
                Some(rte)
            },
        })
    }

    /// Poll the battery and drive the `narf_power::battery`
    /// notify fan-out: 0x80 (`StatusChanged`) when the status
    /// word changed, and `CapacityLow` on the rising edge of
    /// `REMAINING_CAPACITY_ALARM`. This is the SBS counterpart
    /// of the control-method battery's ACPI Notify handling.
    pub fn poll(&mut self) -> Result<PollOutcome, SbsError> {
        let status = self.read_status()?;
        let status_changed = self.last_status_word != Some(status.status_word);
        let was_alarm = self
            .last_status_word
            .is_some_and(|w| w & battery_status::REMAINING_CAPACITY_ALARM != 0);
        let capacity_low = status.capacity_alarm() && !was_alarm;
        if status_changed {
            narf_power::battery::notify(0x80);
        }
        if capacity_low {
            narf_power::battery::notify_capacity_low();
        }
        self.last_status_word = Some(status.status_word);
        Ok(PollOutcome {
            status_changed,
            capacity_low,
            status,
        })
    }

    /// `(info, state)` in the shared surface, from a fresh
    /// status read. `None` when the read fails validation.
    pub fn snapshot(&self) -> Option<(BatteryInfo, BatteryState)> {
        let status = self.read_status().ok()?;
        Some((
            self.info.to_battery_info(),
            status.to_battery_state(&self.info),
        ))
    }
}

fn read_block_string<T: SbsTransport>(t: &T, cmd: u8) -> Result<String, SbsError> {
    decode_block_string(&t.read_block(ADDR_BATTERY, cmd)?)
}

// ── Subsystem discovery ─────────────────────────────────────────

/// A discovered SBS subsystem: the batteries that probed and
/// validated, in slot order. Batteries that NAK or return
/// garbage are simply not here — discovery is infallible
/// because per-slot failure is an ordinary outcome (an empty
/// battery bay), not an error.
#[derive(Debug)]
pub struct SbsSubsystem<T: SbsTransport> {
    manager: ManagerKind,
    charger_present: bool,
    batteries: Vec<SbsBattery<T>>,
    last_rsoc: [Option<u8>; 4],
}

impl<T: SbsTransport> SbsSubsystem<T> {
    pub fn manager(&self) -> ManagerKind {
        self.manager
    }

    pub fn charger_present(&self) -> bool {
        self.charger_present
    }

    pub fn batteries(&self) -> &[SbsBattery<T>] {
        &self.batteries
    }

    pub fn batteries_mut(&mut self) -> &mut [SbsBattery<T>] {
        &mut self.batteries
    }
}

/// Run subsystem discovery over `transport`. `sbs_count` is the
/// value of the ACPI `_SBS` method (0 = single battery, no
/// manager/selector; ≥1 = a System Manager or Selector is
/// present and up to that many batteries are supported).
pub fn discover<T: SbsTransport>(transport: Arc<T>, sbs_count: u8) -> SbsSubsystem<T> {
    // Charger: presence + the embedded-selector indication
    // (ChargerSpecInfo bit 4). Any error reads as "no charger
    // answering" — battery probing below is the authoritative
    // path, and a charger is not required for it.
    let (charger_present, charger_embedded) =
        match transport.read_word(ADDR_CHARGER, CMD_CHARGER_SPEC_INFO) {
            Ok(v) => (true, v & CHARGER_SPEC_INFO_SELECTOR_SUPPORT != 0),
            Err(_) => (false, false),
        };

    let mut manager = ManagerKind::None;
    let mut supported_mask: u8 = 0x01;
    if sbs_count >= 1 {
        if let Ok(info) = selector_info(&*transport, SelectorKind::Standalone) {
            manager = ManagerKind::Selector(SelectorKind::Standalone);
            supported_mask = info.supported_mask;
        } else if charger_embedded {
            if let Ok(info) = selector_info(&*transport, SelectorKind::ChargerEmbedded) {
                manager = ManagerKind::Selector(SelectorKind::ChargerEmbedded);
                supported_mask = info.supported_mask;
            }
        }
        if manager == ManagerKind::None
            && transport
                .read_word(ADDR_MANAGER_OR_SELECTOR, CMD_SELECTOR_STATE)
                .is_ok()
        {
            manager = ManagerKind::SystemManager;
        }
    }

    let selector = match manager {
        ManagerKind::Selector(kind) => Some(kind),
        _ => None,
    };
    let slots: Vec<u8> = match manager {
        ManagerKind::Selector(_) => (0..sbs_count.min(4))
            .filter(|&s| supported_mask & (1u8 << s) != 0)
            .collect(),
        _ => alloc::vec![0],
    };

    // Presence via OK_TO_USE on selector systems: a clear bit
    // means the position is empty — don't even select the slot.
    // If the state read fails, fall back to probing every slot.
    let presence = match selector {
        Some(kind) => selector_state(&*transport, kind)
            .map(|w| (w & SELECTOR_OK_TO_USE_MASK) as u8)
            .unwrap_or(0xFF),
        None => 0xFF,
    };

    let mut batteries: Vec<SbsBattery<T>> = Vec::new();
    let mut seen_serials: Vec<u16> = Vec::new();
    for slot in slots {
        if presence & (1u8 << slot) == 0 {
            continue;
        }
        if let Some(kind) = selector {
            if selector_select(&*transport, kind, slot).is_err() {
                continue;
            }
        }
        let info = match SbsBattery::read_info(&*transport) {
            Ok(info) => info,
            Err(_) => continue,
        };
        // A second slot answering with an earlier slot's serial
        // is the selector failing to route (one battery visible
        // twice). Publishing it would report the same battery as
        // two distinct ones — reject the duplicate.
        if seen_serials.contains(&info.serial_number) {
            continue;
        }
        seen_serials.push(info.serial_number);
        batteries.push(SbsBattery {
            transport: transport.clone(),
            slot,
            selector,
            info,
            last_status_word: None,
        });
    }

    SbsSubsystem {
        manager,
        charger_present,
        batteries,
        last_rsoc: [None; 4],
    }
}

// ── Production wiring ───────────────────────────────────────────

static SUBSYSTEM: IrqSafeSpinLock<Option<SbsSubsystem<IchSmbusTransport>>> =
    IrqSafeSpinLock::new(None);

/// `PowerSource` facade over one discovered SBS battery. Reads
/// are live (each call runs the SMBus conversation, like the
/// control-method driver's per-call `_BST` evaluation); a
/// failed read falls back to the last polled state-of-charge
/// rather than inventing one, and to 0 (the control-method
/// driver's failure convention) when nothing was ever read.
#[derive(Debug)]
pub struct SbsPowerSource {
    slot: u8,
    name: &'static str,
}

impl PowerSource for SbsPowerSource {
    fn source_type(&self) -> PowerSourceType {
        PowerSourceType::Battery
    }

    fn capacity_percent(&self) -> u8 {
        let mut guard = SUBSYSTEM.lock();
        let Some(sub) = guard.as_mut() else {
            return 0;
        };
        let fresh = sub
            .batteries
            .iter()
            .find(|b| b.slot() == self.slot)
            .and_then(|bat| bat.read_status().ok())
            .map(|st| st.relative_state_of_charge);
        match fresh {
            Some(rsoc) => {
                sub.last_rsoc[self.slot as usize] = Some(rsoc);
                rsoc
            }
            None => sub.last_rsoc[self.slot as usize].unwrap_or(0),
        }
    }

    fn is_charging(&self) -> bool {
        let guard = SUBSYSTEM.lock();
        let Some(sub) = guard.as_ref() else {
            return false;
        };
        match sub.batteries.iter().find(|b| b.slot() == self.slot) {
            Some(bat) => bat
                .read_status()
                .map(|st| !st.is_discharging() && st.current > 0)
                .unwrap_or(false),
            None => false,
        }
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// Snapshot of the first SBS battery in the shared
/// `(BatteryInfo, BatteryState)` surface, or `None` when no SBS
/// subsystem was discovered (or its battery fails validation).
/// Polls the battery first, so the notify fan-out observes
/// status transitions at snapshot cadence. Called by the power
/// service's battery provider as the fallback when no
/// control-method battery exists.
pub fn snapshot_first() -> Option<(BatteryInfo, BatteryState)> {
    let mut guard = SUBSYSTEM.lock();
    let sub = guard.as_mut()?;
    let bat = sub.batteries.first_mut()?;
    let outcome = bat.poll().ok()?;
    Some((
        bat.info().to_battery_info(),
        outcome.status.to_battery_state(bat.info()),
    ))
}

/// Poll every discovered SBS battery, driving the notify
/// fan-out. Returns how many batteries polled successfully.
pub fn poll_all() -> usize {
    let mut guard = SUBSYSTEM.lock();
    let Some(sub) = guard.as_mut() else {
        return 0;
    };
    let mut n = 0;
    for bat in &mut sub.batteries {
        if bat.poll().is_ok() {
            n += 1;
        }
    }
    n
}

/// Stage::Late init: discover the `ACPI0002` subsystem and
/// publish its batteries. Runs at Stage::Late because discovery
/// needs the probed SMBus host controller (PCI probes land at
/// Stage::Device, after this crate's Stage::Subsys initcalls)
/// and must precede the power-service wiring that consumes
/// [`snapshot_first`]. No-op on machines without an SBS
/// subsystem or without a probed SMBus host.
pub fn init() {
    let Some(dev) = find_all_devices_by_hid("ACPI0002").into_iter().next() else {
        return;
    };
    if !crate::smbus::is_probed() {
        return;
    }
    // `_SBS` returns the maximum number of batteries supported
    // (ACPI 6.4 §10.1.3). A missing/failing `_SBS` reads as the
    // conservative single-battery, no-manager shape.
    let sbs_count = evaluate_method(&alloc::format!("{}._SBS", dev.path), &[])
        .ok()
        .map(|v| (v.as_integer().min(4)) as u8)
        .unwrap_or(0);
    let sub = discover(Arc::new(IchSmbusTransport), sbs_count);
    const NAMES: &[&str] = &["SBS0", "SBS1", "SBS2", "SBS3"];
    for bat in sub.batteries() {
        let name = NAMES.get(bat.slot() as usize).copied().unwrap_or("SBSX");
        register_source(Arc::new(SbsPowerSource {
            slot: bat.slot(),
            name,
        }));
    }
    *SUBSYSTEM.lock() = Some(sub);
}

// ── Fixtures ────────────────────────────────────────────────────
//
// The fake bus scripts the SBS conversation from the
// specifications: a battery is a raw command→register map (the
// values below are the on-wire words, e.g. Current −1500 mA is
// 0xFA24), block payloads carry their length byte, a selector
// routes the shared 0x0B address according to the USE_NEXT
// nibble it was last written, and every transaction is logged
// so tests can pin ordering (selection write before the reads
// it routes). Nothing in the fake knows how the driver decodes
// — expectations are asserted on the driver's typed output.

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    macro_rules! check {
        ($cond:expr, $msg:expr) => {
            if !($cond) {
                return TestResult::Fail($msg);
            }
        };
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        ReadWord,
        WriteWord,
        ReadBlock,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct LogEntry {
        op: Op,
        addr: u8,
        cmd: u8,
        /// Word read/written, or block payload length.
        value: u32,
        ok: bool,
    }

    #[derive(Debug)]
    struct FakeBattery {
        words: Vec<(u8, u16)>,
        blocks: Vec<(u8, Vec<u8>)>,
    }

    impl FakeBattery {
        fn word(&self, cmd: u8) -> Option<u16> {
            self.words.iter().find(|(c, _)| *c == cmd).map(|(_, v)| *v)
        }

        fn block(&self, cmd: u8) -> Option<&[u8]> {
            self.blocks
                .iter()
                .find(|(c, _)| *c == cmd)
                .map(|(_, v)| v.as_slice())
        }

        fn set_word(&mut self, cmd: u8, value: u16) {
            if let Some(e) = self.words.iter_mut().find(|(c, _)| *c == cmd) {
                e.1 = value;
            } else {
                self.words.push((cmd, value));
            }
        }
    }

    #[derive(Debug)]
    struct FakeSelector {
        /// SelectorInfo() word returned verbatim.
        info: u16,
        /// Stored USE_NEXT nibble (already shifted).
        use_next: u16,
        /// Slot currently routed to the battery address.
        routed: usize,
        embedded: bool,
    }

    #[derive(Debug)]
    struct FakeInner {
        batteries: Vec<Option<FakeBattery>>,
        selector: Option<FakeSelector>,
        manager_state: Option<u16>,
        charger_spec_info: Option<u16>,
        log: Vec<LogEntry>,
    }

    impl FakeInner {
        /// SelectorState as the device composes it: OK_TO_USE
        /// bits track physical presence; USE_NEXT is whatever
        /// the host last wrote.
        fn selector_state(&self) -> u16 {
            let mut ok_to_use = 0u16;
            for (i, b) in self.batteries.iter().enumerate() {
                if b.is_some() {
                    ok_to_use |= 1 << i;
                }
            }
            let use_next = self.selector.as_ref().map(|s| s.use_next).unwrap_or(0);
            ok_to_use | use_next
        }

        fn routed_battery(&self) -> Option<&FakeBattery> {
            let routed = self.selector.as_ref().map(|s| s.routed).unwrap_or(0);
            self.batteries.get(routed).and_then(|b| b.as_ref())
        }

        fn read_word(&self, addr: u8, cmd: u8) -> Result<u16, SbsError> {
            match addr {
                ADDR_CHARGER => {
                    if cmd == CMD_CHARGER_SPEC_INFO {
                        return self.charger_spec_info.ok_or(SbsError::NotPresent);
                    }
                    if let Some(sel) = &self.selector {
                        if sel.embedded {
                            if cmd == CMD_SELECTOR_STATE | 0x20 {
                                return Ok(self.selector_state());
                            }
                            if cmd == CMD_SELECTOR_INFO | 0x20 {
                                return Ok(sel.info);
                            }
                        }
                    }
                    Err(SbsError::NotPresent)
                }
                ADDR_MANAGER_OR_SELECTOR => {
                    if let Some(sel) = &self.selector {
                        if !sel.embedded {
                            if cmd == CMD_SELECTOR_STATE {
                                return Ok(self.selector_state());
                            }
                            if cmd == CMD_SELECTOR_INFO {
                                return Ok(sel.info);
                            }
                        }
                    }
                    if cmd == CMD_SELECTOR_STATE {
                        if let Some(state) = self.manager_state {
                            return Ok(state);
                        }
                    }
                    Err(SbsError::NotPresent)
                }
                ADDR_BATTERY => match self.routed_battery() {
                    Some(bat) => bat
                        .word(cmd)
                        .ok_or(SbsError::Garbage("fake battery: unmodelled word command")),
                    None => Err(SbsError::NotPresent),
                },
                _ => Err(SbsError::NotPresent),
            }
        }

        fn write_word(&mut self, addr: u8, cmd: u8, value: u16) -> Result<(), SbsError> {
            let target = match self.selector.as_ref() {
                Some(sel) if sel.embedded => (ADDR_CHARGER, CMD_SELECTOR_STATE | 0x20),
                Some(_) => (ADDR_MANAGER_OR_SELECTOR, CMD_SELECTOR_STATE),
                None => return Err(SbsError::NotPresent),
            };
            if (addr, cmd) != target {
                return Err(SbsError::Unsupported("fake bus: unexpected write target"));
            }
            let sel = self.selector.as_mut().expect("selector checked above");
            sel.use_next = value & SELECTOR_USE_NEXT_MASK;
            let bits = sel.use_next >> SELECTOR_USE_NEXT_SHIFT;
            if bits.count_ones() == 1 {
                sel.routed = bits.trailing_zeros() as usize;
            }
            Ok(())
        }

        fn read_block(&self, addr: u8, cmd: u8) -> Result<Vec<u8>, SbsError> {
            if addr != ADDR_BATTERY {
                return Err(SbsError::NotPresent);
            }
            match self.routed_battery() {
                Some(bat) => bat
                    .block(cmd)
                    .map(|p| p.to_vec())
                    .ok_or(SbsError::Garbage("fake battery: unmodelled block command")),
                None => Err(SbsError::NotPresent),
            }
        }
    }

    #[derive(Debug)]
    struct FakeBus {
        inner: IrqSafeSpinLock<FakeInner>,
    }

    impl FakeBus {
        fn new(
            batteries: Vec<Option<FakeBattery>>,
            selector: Option<FakeSelector>,
            manager_state: Option<u16>,
            charger_spec_info: Option<u16>,
        ) -> Self {
            Self {
                inner: IrqSafeSpinLock::new(FakeInner {
                    batteries,
                    selector,
                    manager_state,
                    charger_spec_info,
                    log: Vec::new(),
                }),
            }
        }

        fn log(&self) -> Vec<LogEntry> {
            self.inner.lock().log.clone()
        }

        fn set_word(&self, slot: usize, cmd: u8, value: u16) {
            let mut inner = self.inner.lock();
            if let Some(Some(bat)) = inner.batteries.get_mut(slot) {
                bat.set_word(cmd, value);
            }
        }
    }

    impl SbsTransport for FakeBus {
        fn read_word(&self, addr: u8, cmd: u8) -> Result<u16, SbsError> {
            let mut inner = self.inner.lock();
            let result = inner.read_word(addr, cmd);
            let value = result.as_ref().map(|v| *v as u32).unwrap_or(0);
            inner.log.push(LogEntry {
                op: Op::ReadWord,
                addr,
                cmd,
                value,
                ok: result.is_ok(),
            });
            result
        }

        fn write_word(&self, addr: u8, cmd: u8, value: u16) -> Result<(), SbsError> {
            let mut inner = self.inner.lock();
            let result = inner.write_word(addr, cmd, value);
            inner.log.push(LogEntry {
                op: Op::WriteWord,
                addr,
                cmd,
                value: value as u32,
                ok: result.is_ok(),
            });
            result
        }

        fn read_block(&self, addr: u8, cmd: u8) -> Result<Vec<u8>, SbsError> {
            let mut inner = self.inner.lock();
            let result = inner.read_block(addr, cmd);
            let value = result.as_ref().map(|p| p.len() as u32).unwrap_or(0);
            inner.log.push(LogEntry {
                op: Op::ReadBlock,
                addr,
                cmd,
                value,
                ok: result.is_ok(),
            });
            result
        }
    }

    fn block_string(s: &str) -> Vec<u8> {
        let mut v = vec![s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    /// Battery A: discharging at 1500 mA, 63 % of a 4870 mAh
    /// full charge (3068 mAh left), 25.05 °C, made 2024-06-15.
    fn battery_a() -> FakeBattery {
        FakeBattery {
            words: vec![
                (CMD_BATTERY_MODE, 0x0001),
                (CMD_REMAINING_CAPACITY_ALARM, 487),
                (CMD_TEMPERATURE, 2982),
                (CMD_VOLTAGE, 12345),
                (CMD_CURRENT, (-1500i16) as u16),
                (CMD_RELATIVE_STATE_OF_CHARGE, 63),
                (CMD_REMAINING_CAPACITY, 3068),
                (CMD_FULL_CHARGE_CAPACITY, 4870),
                (CMD_RUN_TIME_TO_EMPTY, 122),
                (CMD_BATTERY_STATUS, 0x00C0),
                (CMD_CYCLE_COUNT, 132),
                (CMD_DESIGN_CAPACITY, 5200),
                (CMD_DESIGN_VOLTAGE, 11100),
                (CMD_SPECIFICATION_INFO, 0x0011),
                (CMD_MANUFACTURE_DATE, 22735),
                (CMD_SERIAL_NUMBER, 0x1234),
            ],
            blocks: vec![
                (CMD_MANUFACTURER_NAME, block_string("SBS-IF")),
                (CMD_DEVICE_NAME, block_string("NARFBOOK-1")),
                (CMD_DEVICE_CHEMISTRY, block_string("LION")),
            ],
        }
    }

    /// Battery B: charging at 2000 mA, 80 % of 5000 mAh. Every
    /// value differs from battery A, so a driver that reads the
    /// wrong battery behind the selector cannot pass.
    fn battery_b() -> FakeBattery {
        FakeBattery {
            words: vec![
                (CMD_BATTERY_MODE, 0x0001),
                (CMD_REMAINING_CAPACITY_ALARM, 500),
                (CMD_TEMPERATURE, 3000),
                (CMD_VOLTAGE, 11800),
                (CMD_CURRENT, 2000),
                (CMD_RELATIVE_STATE_OF_CHARGE, 80),
                (CMD_REMAINING_CAPACITY, 4000),
                (CMD_FULL_CHARGE_CAPACITY, 5000),
                (CMD_RUN_TIME_TO_EMPTY, RUN_TIME_UNAVAILABLE),
                (CMD_BATTERY_STATUS, 0x0080),
                (CMD_CYCLE_COUNT, 45),
                (CMD_DESIGN_CAPACITY, 5500),
                (CMD_DESIGN_VOLTAGE, 10800),
                (CMD_SPECIFICATION_INFO, 0x0011),
                (CMD_MANUFACTURE_DATE, 22735),
                (CMD_SERIAL_NUMBER, 0x2345),
            ],
            blocks: vec![
                (CMD_MANUFACTURER_NAME, block_string("SBS-IF")),
                (CMD_DEVICE_NAME, block_string("NARFBOOK-2")),
                (CMD_DEVICE_CHEMISTRY, block_string("LION")),
            ],
        }
    }

    fn smoke_sbs_single_battery_end_to_end() -> TestResult {
        let bus = Arc::new(FakeBus::new(
            vec![Some(battery_a())],
            None,
            None,
            Some(0x0000),
        ));
        let sub = discover(bus.clone(), 0);
        check!(
            sub.manager() == ManagerKind::None,
            "no manager for _SBS = 0"
        );
        check!(sub.charger_present(), "charger answered ChargerSpecInfo");
        check!(sub.batteries().len() == 1, "one battery published");
        let bat = &sub.batteries()[0];
        let info = bat.info();
        check!(info.design_capacity == 5200, "design capacity");
        check!(info.full_charge_capacity == 4870, "full charge capacity");
        check!(info.design_voltage_mv == 11100, "design voltage");
        check!(info.cycle_count == 132, "cycle count");
        check!(info.serial_number == 0x1234, "serial number");
        check!(
            info.manufacture_date
                == ManufactureDate {
                    year: 2024,
                    month: 6,
                    day: 15
                },
            "manufacture date decode"
        );
        check!(
            info.specification_info
                == SpecificationInfo {
                    revision: 1,
                    version: 1,
                    v_scale: 0,
                    ip_scale: 0
                },
            "specification info decode"
        );
        check!(info.capacity_alarm == 487, "capacity alarm");
        check!(!info.capacity_in_10mw_units, "capacity mode is mA");
        check!(info.manufacturer_name == "SBS-IF", "manufacturer name");
        check!(info.device_name == "NARFBOOK-1", "device name");
        check!(info.device_chemistry == "LION", "chemistry");

        let st = match bat.read_status() {
            Ok(st) => st,
            Err(_) => return TestResult::Fail("status read must succeed"),
        };
        check!(st.voltage_mv == 12345, "voltage");
        check!(
            st.current == -1500,
            "signed current, negative = discharging"
        );
        check!(
            st.relative_state_of_charge == 63,
            "relative state of charge"
        );
        check!(st.remaining_capacity == 3068, "remaining capacity");
        check!(st.run_time_to_empty_min == Some(122), "run time to empty");
        check!(st.temperature_mc() == 25050, "temperature in milli-C");
        check!(st.is_discharging(), "discharging bit decoded");

        let (binfo, bstate) = match bat.snapshot() {
            Some(p) => p,
            None => return TestResult::Fail("snapshot must succeed"),
        };
        check!(binfo.power_unit == PowerUnit::MilliAmp, "mapped power unit");
        check!(
            binfo.design_capacity == 5200 && binfo.last_full_capacity == 4870,
            "mapped capacities"
        );
        check!(binfo.model_number == "NARFBOOK-1", "mapped model");
        check!(binfo.serial_number == "4660", "mapped serial");
        check!(binfo.battery_type == "LION", "mapped chemistry");
        check!(binfo.oem_info == "SBS-IF", "mapped oem");
        check!(
            bstate.status.contains(BatteryStatus::DISCHARGING),
            "mapped discharging"
        );
        check!(bstate.present_rate == 1500, "mapped rate is the magnitude");
        check!(bstate.remaining_capacity == 3068, "mapped remaining");
        check!(bstate.present_voltage_mv == 12345, "mapped voltage");

        // Conversation shape: units come first (BatteryMode
        // before any capacity is interpreted), and the Current
        // read is pinned to the exact on-wire word for −1500 mA.
        let log = bus.log();
        let first_batt = log.iter().find(|e| e.addr == ADDR_BATTERY);
        check!(
            matches!(first_batt, Some(e) if e.op == Op::ReadWord && e.cmd == CMD_BATTERY_MODE),
            "first battery transaction must be the BatteryMode read"
        );
        let cur = log
            .iter()
            .find(|e| e.op == Op::ReadWord && e.addr == ADDR_BATTERY && e.cmd == CMD_CURRENT);
        check!(
            matches!(cur, Some(e) if e.ok && e.value == 0xFA24),
            "current word pinned byte-for-byte"
        );
        check!(
            log.iter()
                .any(|e| e.op == Op::ReadBlock && e.cmd == CMD_DEVICE_CHEMISTRY),
            "chemistry block read happened"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-sbs", smoke_sbs_single_battery_end_to_end);

    fn smoke_sbs_capacity_mode_scaling() -> TestResult {
        let mut a = battery_a();
        a.set_word(CMD_BATTERY_MODE, 0x8001); // CAPACITY_MODE set
        a.set_word(CMD_DESIGN_CAPACITY, 440); // 440 × 10 mWh
        a.set_word(CMD_FULL_CHARGE_CAPACITY, 400);
        a.set_word(CMD_REMAINING_CAPACITY, 200);
        a.set_word(CMD_CURRENT, (-120i16) as u16); // −120 × 10 mW
        a.set_word(CMD_REMAINING_CAPACITY_ALARM, 40);
        a.set_word(CMD_RELATIVE_STATE_OF_CHARGE, 50);
        let bus = Arc::new(FakeBus::new(vec![Some(a)], None, None, None));
        let sub = discover(bus, 0);
        check!(sub.batteries().len() == 1, "battery published");
        let bat = &sub.batteries()[0];
        check!(bat.info().capacity_in_10mw_units, "capacity mode flag set");
        check!(
            bat.info().design_capacity == 4400,
            "design capacity scaled to mWh"
        );
        check!(
            bat.info().full_charge_capacity == 4000,
            "full charge scaled"
        );
        check!(bat.info().capacity_alarm == 400, "alarm scaled");
        check!(
            bat.info().power_unit() == PowerUnit::MilliWatt,
            "power unit mW"
        );
        let st = match bat.read_status() {
            Ok(st) => st,
            Err(_) => return TestResult::Fail("status read must succeed"),
        };
        let mapped = st.to_battery_state(bat.info());
        check!(mapped.remaining_capacity == 2000, "remaining scaled to mWh");
        check!(mapped.present_rate == 1200, "rate scaled to mW");
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-sbs", smoke_sbs_capacity_mode_scaling);

    fn smoke_sbs_absent_battery_not_published() -> TestResult {
        let bus = Arc::new(FakeBus::new(vec![None], None, None, None));
        let sub = discover(bus, 0);
        check!(
            sub.batteries().is_empty(),
            "NAKing battery must not be published"
        );
        check!(!sub.charger_present(), "no charger answered");
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-sbs",
        smoke_sbs_absent_battery_not_published
    );

    fn smoke_sbs_garbage_design_capacity_rejected() -> TestResult {
        let mut a = battery_a();
        a.set_word(CMD_DESIGN_CAPACITY, 0);
        let bus = Arc::new(FakeBus::new(vec![Some(a)], None, None, None));
        let sub = discover(bus, 0);
        check!(
            sub.batteries().is_empty(),
            "zero design capacity must be rejected, never published"
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-sbs",
        smoke_sbs_garbage_design_capacity_rejected
    );

    fn smoke_sbs_garbage_rsoc_rejected() -> TestResult {
        let mut a = battery_a();
        a.set_word(CMD_RELATIVE_STATE_OF_CHARGE, 140);
        let bus = Arc::new(FakeBus::new(vec![Some(a)], None, None, None));
        let sub = discover(bus, 0);
        check!(sub.batteries().len() == 1, "info alone is publishable");
        check!(
            matches!(sub.batteries()[0].read_status(), Err(SbsError::Garbage(_))),
            "state of charge above 100 percent must be refused"
        );
        check!(
            sub.batteries()[0].snapshot().is_none(),
            "no snapshot from garbage"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-sbs", smoke_sbs_garbage_rsoc_rejected);

    fn smoke_sbs_status_error_code_rejected() -> TestResult {
        let mut a = battery_a();
        a.set_word(CMD_BATTERY_STATUS, 0x00C7); // error code 7 = UnknownError
        let bus = Arc::new(FakeBus::new(vec![Some(a)], None, None, None));
        let sub = discover(bus, 0);
        check!(sub.batteries().len() == 1, "info alone is publishable");
        check!(
            matches!(sub.batteries()[0].read_status(), Err(SbsError::Garbage(_))),
            "nonzero status error code must be refused"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-sbs", smoke_sbs_status_error_code_rejected);

    fn smoke_sbs_block_string_length_rejected() -> TestResult {
        let mut a = battery_a();
        a.blocks.retain(|(c, _)| *c != CMD_MANUFACTURER_NAME);
        // Length byte claims 5; six bytes actually follow.
        a.blocks.push((
            CMD_MANUFACTURER_NAME,
            vec![5, b'S', b'B', b'S', b'-', b'I', b'F'],
        ));
        let bus = Arc::new(FakeBus::new(vec![Some(a)], None, None, None));
        let sub = discover(bus, 0);
        check!(
            sub.batteries().is_empty(),
            "a block string whose length byte lies must reject the battery"
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-sbs",
        smoke_sbs_block_string_length_rejected
    );

    fn smoke_sbs_alarm_poll_notifies() -> TestResult {
        let bus = Arc::new(FakeBus::new(vec![Some(battery_a())], None, None, None));
        let mut sub = discover(bus.clone(), 0);
        check!(sub.batteries().len() == 1, "battery published");
        let bat = &mut sub.batteries_mut()[0];
        let o1 = match bat.poll() {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("first poll must succeed"),
        };
        check!(
            o1.status_changed && !o1.capacity_low,
            "first poll reports a change, no alarm"
        );
        bus.set_word(0, CMD_BATTERY_STATUS, 0x02C0); // + REMAINING_CAPACITY_ALARM
        let o2 = match bat.poll() {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("second poll must succeed"),
        };
        check!(
            o2.status_changed && o2.capacity_low,
            "alarm rising edge must report capacity_low"
        );
        check!(o2.status.capacity_alarm(), "alarm bit decoded in outcome");
        let o3 = match bat.poll() {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("third poll must succeed"),
        };
        check!(
            !o3.status_changed && !o3.capacity_low,
            "steady state must be quiet (edge, not level)"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-sbs", smoke_sbs_alarm_poll_notifies);

    fn smoke_sbs_selector_two_batteries() -> TestResult {
        let selector = FakeSelector {
            info: 0x0023, // supports A+B, selector spec rev 1.1
            use_next: 0x0100,
            routed: 0,
            embedded: false,
        };
        let bus = Arc::new(FakeBus::new(
            vec![Some(battery_a()), Some(battery_b())],
            Some(selector),
            None,
            Some(0x0000),
        ));
        let sub = discover(bus.clone(), 2);
        check!(
            sub.manager() == ManagerKind::Selector(SelectorKind::Standalone),
            "standalone selector detected"
        );
        check!(sub.batteries().len() == 2, "both batteries published");
        check!(sub.batteries()[0].slot() == 0, "slot 0 first");
        check!(sub.batteries()[1].slot() == 1, "slot 1 second");
        check!(
            sub.batteries()[1].info().serial_number == 0x2345,
            "slot 1 enumerated battery B, not A twice"
        );
        let st_b = match sub.batteries()[1].read_status() {
            Ok(st) => st,
            Err(_) => return TestResult::Fail("slot 1 status must succeed"),
        };
        check!(
            st_b.remaining_capacity == 4000,
            "slot 1 reads battery B's capacity (masking check)"
        );
        check!(
            st_b.run_time_to_empty_min.is_none(),
            "0xFFFF run time is unavailable"
        );
        let st_a = match sub.batteries()[0].read_status() {
            Ok(st) => st,
            Err(_) => return TestResult::Fail("slot 0 status must succeed"),
        };
        check!(
            st_a.remaining_capacity == 3068,
            "slot 0 still reads battery A"
        );

        // The selection write for B must precede the first read
        // that returned B's data.
        let log = bus.log();
        let write_idx = log.iter().position(|e| {
            e.op == Op::WriteWord
                && e.addr == ADDR_MANAGER_OR_SELECTOR
                && e.cmd == CMD_SELECTOR_STATE
                && (e.value & 0x0F00) == 0x0200
        });
        check!(
            write_idx.is_some(),
            "driver must select battery B via USE_NEXT"
        );
        let design_b_idx = log.iter().position(|e| {
            e.op == Op::ReadWord
                && e.addr == ADDR_BATTERY
                && e.cmd == CMD_DESIGN_CAPACITY
                && e.value == 5500
        });
        check!(design_b_idx.is_some(), "battery B design capacity was read");
        check!(
            write_idx.unwrap() < design_b_idx.unwrap(),
            "selection write must precede battery B reads"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-sbs", smoke_sbs_selector_two_batteries);

    fn smoke_sbs_selector_absent_slot_skipped() -> TestResult {
        let selector = FakeSelector {
            info: 0x0023,
            use_next: 0x0100,
            routed: 0,
            embedded: false,
        };
        let bus = Arc::new(FakeBus::new(
            vec![Some(battery_a()), None],
            Some(selector),
            None,
            Some(0x0000),
        ));
        let sub = discover(bus.clone(), 2);
        check!(
            sub.batteries().len() == 1,
            "only the present battery published"
        );
        check!(
            sub.batteries()[0].slot() == 0,
            "published battery is slot 0"
        );
        check!(
            !bus.log().iter().any(|e| e.op == Op::WriteWord),
            "an absent slot (OK_TO_USE clear) must never be selected"
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-sbs",
        smoke_sbs_selector_absent_slot_skipped
    );

    fn smoke_sbs_charger_embedded_selector() -> TestResult {
        let selector = FakeSelector {
            info: 0x0023,
            use_next: 0x0100,
            routed: 0,
            embedded: true,
        };
        let bus = Arc::new(FakeBus::new(
            vec![Some(battery_a()), Some(battery_b())],
            Some(selector),
            None,
            Some(0x0010), // ChargerSpecInfo bit 4: selector embedded in charger
        ));
        let sub = discover(bus.clone(), 2);
        check!(
            sub.manager() == ManagerKind::Selector(SelectorKind::ChargerEmbedded),
            "charger-embedded selector detected"
        );
        check!(sub.batteries().len() == 2, "both batteries published");
        let st_b = match sub.batteries()[1].read_status() {
            Ok(st) => st,
            Err(_) => return TestResult::Fail("slot 1 status must succeed"),
        };
        check!(st_b.remaining_capacity == 4000, "slot 1 reads battery B");
        check!(
            bus.log()
                .iter()
                .any(|e| e.op == Op::ReadWord && e.addr == ADDR_CHARGER && e.cmd == 0x24),
            "SelectorInfo must be read at charger command 0x24"
        );
        TestResult::Pass
    }
    kernel_test_in!("drivers-platform-sbs", smoke_sbs_charger_embedded_selector);

    fn smoke_sbs_system_manager_presented_battery() -> TestResult {
        // A System Manager answers BatterySystemState (0x01) but
        // has no SelectorInfo; _SBS says two batteries fit, but
        // the manager multiplexes autonomously — only the
        // presented battery is published.
        let bus = Arc::new(FakeBus::new(
            vec![Some(battery_a())],
            None,
            Some(0x0003),
            Some(0x0000),
        ));
        let sub = discover(bus, 2);
        check!(
            sub.manager() == ManagerKind::SystemManager,
            "system manager detected"
        );
        check!(
            sub.batteries().len() == 1,
            "only the presented battery published"
        );
        check!(
            sub.batteries()[0].info().serial_number == 0x1234,
            "presented battery is battery A"
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers-platform-sbs",
        smoke_sbs_system_manager_presented_battery
    );
}
