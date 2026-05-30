//! USB-to-serial adapter class drivers — common types and trait.
//!
//! ## Background
//!
//! USB-to-serial adapters expose a virtual UART over USB bulk
//! endpoints, but each chip family uses its own vendor-specific
//! control protocol.  This module defines the shared [`UsbSerial`]
//! trait and the concrete data types it operates on.  The four chip
//! family implementations are in sibling modules:
//!
//! - [`super::serial::ch341`] — WCH CH340/CH341 (1A86:7523 / 5523)
//! - [`super::serial::ftdi`]  — FTDI FT232R/FT2232H/FT4232H (0403:…)
//! - [`super::serial::pl2303`] — Prolific PL2303HX/EA (067B:2303 / …)
//! - [`super::serial::cp210x`] — Silicon Labs CP210x (10C4:EA60 / …)
//!
//! ## Physical topology
//!
//! All four chip families wire the same way at the USB level:
//!
//! ```text
//!   Bulk-OUT  (host → device)  — TX data
//!   Bulk-IN   (device → host)  — RX data
//!   Intr-IN   (device → host)  — modem-status change notification
//! ```
//!
//! Configuration (baud rate, line format, flow control, modem
//! signals) is performed via vendor-specific control transfers on
//! endpoint 0 before data traffic begins.
//!
//! ## VID:PID dispatch
//!
//! [`identify`] maps a `(vid, pid)` pair to the appropriate
//! [`ChipFamily`] discriminant, which the attach path uses to select
//! the right init sequence.

pub mod ch341;
pub mod cp210x;
pub mod ftdi;
pub mod pl2303;

// ── Shared line-format types ──────────────────────────────────────

/// Number of data bits per UART character.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DataBits {
    Five = 5,
    Six = 6,
    Seven = 7,
    Eight = 8,
}

/// Parity mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Parity {
    None,
    Odd,
    Even,
    Mark,
    Space,
}

/// Number of stop bits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StopBits {
    One,
    OnePointFive,
    Two,
}

/// Hardware flow control mode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FlowControl {
    /// No flow control.
    None,
    /// Hardware RTS/CTS handshake.
    RtsCts,
    /// Software XON/XOFF in-band signaling.
    XonXoff,
}

/// Decoded modem-status register.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct ModemStatus {
    /// CTS — Clear To Send.
    pub cts: bool,
    /// DSR — Data Set Ready.
    pub dsr: bool,
    /// DCD — Data Carrier Detect (RLSD).
    pub dcd: bool,
    /// RI — Ring Indicator.
    pub ri: bool,
}

// ── VID:PID dispatch table ────────────────────────────────────────

/// Which physical chip family does a `(vid, pid)` pair belong to?
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChipFamily {
    /// WCH CH340 / CH341.
    Ch341,
    /// FTDI FT232R / FT2232H / FT4232H / FT232H / FTX.
    Ftdi,
    /// Prolific PL2303 (any HX/HXA/HXD/X/EA/SA/TA variant).
    Pl2303,
    /// Silicon Labs CP2101 / CP2102 / CP2103 / CP2104 / CP2105.
    Cp210x,
}

/// Known USB ID pairs — a compact table of `(vid, pid, family)`.
///
/// Linux reference:
/// - ch341:  `usb_serial_id_table` in `drivers/usb/serial/ch341.c`
/// - ftdi:   `id_table_combined` in `drivers/usb/serial/ftdi_sio.c`
/// - pl2303: `id_table` in `drivers/usb/serial/pl2303.c`
/// - cp210x: `id_table` in `drivers/usb/serial/cp210x.c`
static KNOWN_IDS: &[(u16, u16, ChipFamily)] = &[
    // ── CH341 ────────────────────────────────────────────────────
    // Linux: ch341.c id_table
    (0x1A86, 0x7523, ChipFamily::Ch341), // CH340
    (0x1A86, 0x5523, ChipFamily::Ch341), // CH341
    (0x1A86, 0x7522, ChipFamily::Ch341), // CH340K
    (0x4348, 0x5523, ChipFamily::Ch341), // CH341 alt VID
    // ── FTDI ─────────────────────────────────────────────────────
    // Linux: ftdi_sio.c id_table_combined (subset — most common)
    (0x0403, 0x6001, ChipFamily::Ftdi), // FT232R
    (0x0403, 0x6010, ChipFamily::Ftdi), // FT2232H
    (0x0403, 0x6011, ChipFamily::Ftdi), // FT4232H
    (0x0403, 0x6014, ChipFamily::Ftdi), // FT232H
    (0x0403, 0x6015, ChipFamily::Ftdi), // FT-X / FT231X / FT234X
    (0x0403, 0x6048, ChipFamily::Ftdi), // FT4233HP
    // ── PL2303 ───────────────────────────────────────────────────
    // Linux: pl2303.c id_table (subset — main Prolific PIDs)
    (0x067B, 0x2303, ChipFamily::Pl2303), // PL2303HX
    (0x067B, 0x2304, ChipFamily::Pl2303), // PL2303X
    (0x067B, 0x0611, ChipFamily::Pl2303), // PL2303GC (HXN)
    (0x067B, 0x0612, ChipFamily::Pl2303), // PL2303GS (HXN)
    (0x067B, 0x0613, ChipFamily::Pl2303), // PL2303GT (HXN)
    (0x067B, 0x0614, ChipFamily::Pl2303), // PL2303GL (HXN)
    (0x067B, 0x0615, ChipFamily::Pl2303), // PL2303GE (HXN)
    // ── CP210x ───────────────────────────────────────────────────
    // Linux: cp210x.c id_table (Silicon Labs baseline PIDs)
    (0x10C4, 0xEA60, ChipFamily::Cp210x), // CP2102 / CP2104
    (0x10C4, 0xEA61, ChipFamily::Cp210x), // CP2101
    (0x10C4, 0xEA63, ChipFamily::Cp210x), // CP2103
    (0x10C4, 0xEA70, ChipFamily::Cp210x), // CP2105 dual
    (0x10C4, 0xEA71, ChipFamily::Cp210x), // CP2108 quad
    (0x10C4, 0xEA80, ChipFamily::Cp210x), // CP2109
];

/// Identify a device from its USB VID:PID.
///
/// Returns the [`ChipFamily`] if the pair appears in the static
/// table, or `None` for unknown devices.
///
/// # Examples
///
/// ```
/// assert_eq!(
///     narf_drivers_usb::serial::identify(0x1A86, 0x7523),
///     Some(narf_drivers_usb::serial::ChipFamily::Ch341)
/// );
/// ```
pub fn identify(vid: u16, pid: u16) -> Option<ChipFamily> {
    for &(v, p, fam) in KNOWN_IDS {
        if v == vid && p == pid {
            return Some(fam);
        }
    }
    None
}

// ── UsbSerial trait ───────────────────────────────────────────────

/// Protocol-independent USB serial port interface.
///
/// Each chip-family driver implements this trait.  All control
/// methods are synchronous (they block until the control transfer
/// completes or returns an error); bulk I/O methods are async.
///
/// The trait is `no_std` + `no_alloc` friendly: no `Box<dyn …>` is
/// required by callers who only hold a concrete type.  A dynamic
/// dispatch layer (`dyn UsbSerial`) is possible but is not part of
/// this module — callers should match on [`ChipFamily`] and hold the
/// concrete driver struct instead.
pub trait UsbSerial {
    /// Error type returned by control and I/O operations.
    type Error: core::fmt::Debug;

    /// Set the baud rate in bits/second.
    ///
    /// Common values: 9600, 19200, 38400, 57600, 115200, 230400,
    /// 460800, 921600.  Each chip family has a maximum rate; the
    /// implementation clamps or returns an error for out-of-range
    /// values.
    fn set_baud(&mut self, rate: u32) -> Result<(), Self::Error>;

    /// Configure data bits, parity, and stop bits.
    fn set_line(
        &mut self,
        data_bits: DataBits,
        parity: Parity,
        stop_bits: StopBits,
    ) -> Result<(), Self::Error>;

    /// Configure hardware or software flow control.
    fn set_flow(&mut self, flow: FlowControl) -> Result<(), Self::Error>;

    /// Set DTR (Data Terminal Ready) and RTS (Request To Send).
    fn set_modem(&mut self, dtr: bool, rts: bool) -> Result<(), Self::Error>;

    /// Read the current modem status signals from the device.
    fn get_modem(&self) -> Result<ModemStatus, Self::Error>;
}

// ── Shared smoke tests ────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_identify_ch341() -> TestResult {
        match identify(0x1A86, 0x7523) {
            Some(ChipFamily::Ch341) => TestResult::Pass,
            _ => TestResult::Fail("1A86:7523 not identified as CH341"),
        }
    }
    kernel_test_in!("drivers/usb/serial/mod", smoke_identify_ch341);

    fn smoke_identify_ftdi() -> TestResult {
        match identify(0x0403, 0x6001) {
            Some(ChipFamily::Ftdi) => TestResult::Pass,
            _ => TestResult::Fail("0403:6001 not identified as FTDI"),
        }
    }
    kernel_test_in!("drivers/usb/serial/mod", smoke_identify_ftdi);

    fn smoke_identify_pl2303() -> TestResult {
        match identify(0x067B, 0x2303) {
            Some(ChipFamily::Pl2303) => TestResult::Pass,
            _ => TestResult::Fail("067B:2303 not identified as PL2303"),
        }
    }
    kernel_test_in!("drivers/usb/serial/mod", smoke_identify_pl2303);

    fn smoke_identify_cp210x() -> TestResult {
        match identify(0x10C4, 0xEA60) {
            Some(ChipFamily::Cp210x) => TestResult::Pass,
            _ => TestResult::Fail("10C4:EA60 not identified as CP210x"),
        }
    }
    kernel_test_in!("drivers/usb/serial/mod", smoke_identify_cp210x);

    fn smoke_identify_unknown() -> TestResult {
        match identify(0xDEAD, 0xBEEF) {
            None => TestResult::Pass,
            _ => TestResult::Fail("unknown VID:PID should return None"),
        }
    }
    kernel_test_in!("drivers/usb/serial/mod", smoke_identify_unknown);

    fn smoke_modem_status_default() -> TestResult {
        let ms = ModemStatus::default();
        if ms.cts || ms.dsr || ms.dcd || ms.ri {
            return TestResult::Fail("default ModemStatus should be all-false");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/usb/serial/mod", smoke_modem_status_default);
}
