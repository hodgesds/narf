//! Cable type enumeration — mirrors Linux `include/linux/extcon.h`
//! EXTCON_* IDs.
//!
//! Linux ref: `include/linux/extcon.h` lines 38–87 (EXTCON_USB …
//! EXTCON_MECHANICAL) and lines 63–79 (JACK / DISP subtypes).
//!
//! The enum is `#[repr(u8)]` so cable-state bitmaps can be stored in
//! a single `u32` (≤ 32 cables; Linux SUPPORTED_CABLE_MAX = 32,
//! `extcon.c` line 42).

/// A cable or accessory type that an extcon device can report.
///
/// Variants map directly to the Linux `EXTCON_*` IDs so future
/// platform drivers that share documentation with Linux can use the
/// same names.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Cable {
    // USB (Linux EXTCON_USB = 1, EXTCON_USB_HOST = 2).
    /// USB device — port acts as USB peripheral (UFP).
    Usb = 1,
    /// USB host — port acts as USB host (DFP).
    UsbHost = 2,
    // Charger (Linux EXTCON_CHG_USB_SDP = 5 …).
    /// Standard Downstream Port charger (USB SDP).
    ChargerSdp = 5,
    /// Dedicated Charging Port (DCP).
    ChargerDcp = 6,
    /// Charging Downstream Port (CDP).
    ChargerCdp = 7,
    /// Fast charger (≥ USB PD FAST profile).
    FastCharger = 9,
    /// Slow / standard charger (≤ 500 mA @ 5 V).
    SlowCharger = 10,
    // Audio jacks (Linux EXTCON_JACK_* = 20–27).
    /// 3.5 mm microphone jack.
    Microphone = 20,
    /// 3.5 mm headphone jack.
    Headphone = 21,
    /// Analog line-in.
    JackLineIn = 22,
    /// Analog line-out.
    JackLineOut = 23,
    /// Video-in (composite).
    JackVideoIn = 24,
    /// Video-out (composite / S-Video).
    JackVideoOut = 25,
    // Display (Linux EXTCON_DISP_* = 40–47).
    /// HDMI.
    Hdmi = 40,
    /// Mobile High-Definition Link (MHL).
    Mhl = 41,
    /// DisplayPort (DP Alt Mode or native DP cable).
    Dp = 44,
    // Miscellaneous (Linux EXTCON_DOCK = 60).
    /// Generic dock (USB-C dock or proprietary dock).
    Dock = 60,
    /// Thunderbolt 3/4 dock.
    ThunderboltDock = 61,
}

impl Cable {
    /// The total number of distinct `Cable` variants. Used to size
    /// per-connector bitmaps.
    pub const COUNT: usize = 19;

    /// Return a static slice of all `Cable` values in declaration
    /// order.
    pub fn all() -> &'static [Cable] {
        &[
            Cable::Usb,
            Cable::UsbHost,
            Cable::ChargerSdp,
            Cable::ChargerDcp,
            Cable::ChargerCdp,
            Cable::FastCharger,
            Cable::SlowCharger,
            Cable::Microphone,
            Cable::Headphone,
            Cable::JackLineIn,
            Cable::JackLineOut,
            Cable::JackVideoIn,
            Cable::JackVideoOut,
            Cable::Hdmi,
            Cable::Mhl,
            Cable::Dp,
            Cable::Dock,
            Cable::ThunderboltDock,
        ]
    }
}

impl core::fmt::Display for Cable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Cable::Usb => "USB",
            Cable::UsbHost => "USB-HOST",
            Cable::ChargerSdp => "SDP",
            Cable::ChargerDcp => "DCP",
            Cable::ChargerCdp => "CDP",
            Cable::FastCharger => "FAST-CHG",
            Cable::SlowCharger => "SLOW-CHG",
            Cable::Microphone => "MICROPHONE",
            Cable::Headphone => "HEADPHONE",
            Cable::JackLineIn => "LINE-IN",
            Cable::JackLineOut => "LINE-OUT",
            Cable::JackVideoIn => "VIDEO-IN",
            Cable::JackVideoOut => "VIDEO-OUT",
            Cable::Hdmi => "HDMI",
            Cable::Mhl => "MHL",
            Cable::Dp => "DP",
            Cable::Dock => "DOCK",
            Cable::ThunderboltDock => "TBT-DOCK",
        })
    }
}
