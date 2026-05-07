//! narf-hid — transport-neutral HID 1.11 codec (clean-room).
//!
//! ## Sources (public only)
//!
//! - "Device Class Definition for Human Interface Devices (HID)"
//!   Version 1.11, 27 June 2001 — USB-IF. §6.2.2 (Report
//!   Descriptor), §5.3 (Generic Item Format), §6.2.2.7 (Global Items)
//!   define the wire format we decode here.
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>
//! - "USB HID Usage Tables", Version 1.4, 28 May 2020 — USB-IF. The
//!   `usage` submodule pulls page + ID constants from this table.
//!   <https://usb.org/document-library/hid-usage-tables-14>
//!
//! Linux source not consulted.
//!
//! ## What this crate is
//!
//! Two codecs, both no-allocation-policy-beyond-`Vec`:
//!
//! 1. **Report-descriptor parser** (`descriptor`) — consumes the
//!    raw bytes a device returns from `GET_DESCRIPTOR(Report)` (USB)
//!    or the equivalent on i2c-HID / HoGP, walks HID's Main / Global
//!    / Local item state machine, and produces an ordered list of
//!    [`Field`]s. Each field carries the position + size of its
//!    bits within a report, plus the static metadata (usage page,
//!    usage list, logical-range, etc.) needed to decode runtime
//!    reports.
//! 2. **Report value codec** (`report`) — given a parsed
//!    [`ReportDescriptor`] and a wire-format report, extracts each
//!    field's value(s) with proper sign-extension; symmetrical
//!    `pack` builds an Output / Feature report from values.
//!
//! Transport (USB control, USB interrupt, i2c, BT-L2CAP, GATT) is
//! out of scope — those layers feed bytes in and read decoded values
//! out.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

/// Lightweight bitflags-style macro — declared at the crate root so
/// every submodule can use it via `crate::bitflags_local!` regardless
/// of declaration order.
#[macro_export]
macro_rules! bitflags_local {
    (
        $(#[$outer:meta])*
        pub struct $name:ident: $repr:ty {
            $(
                $(#[$inner:meta])*
                const $flag:ident = $value:expr;
            )*
        }
    ) => {
        $(#[$outer])*
        #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
        #[repr(transparent)]
        pub struct $name(pub $repr);

        impl $name {
            pub const EMPTY: Self = Self(0);
            $(
                $(#[$inner])*
                pub const $flag: Self = Self($value);
            )*

            pub const fn from_bits_truncate(bits: $repr) -> Self {
                let mask = 0 $( | $value)*;
                Self(bits & mask)
            }
            pub const fn bits(self) -> $repr { self.0 }
            pub const fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }
            pub fn insert(&mut self, other: Self) { self.0 |= other.0; }
            pub fn remove(&mut self, other: Self) { self.0 &= !other.0; }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "(0x{:x})"), self.0)
            }
        }
    };
}

pub mod descriptor;
pub mod pen;
pub mod ptp;
pub mod report;
pub mod sensor;
pub mod usage;

pub use descriptor::{
    parse, CollectionKind, DescriptorError, Field, FieldFlags, FieldKind, ReportDescriptor,
};
pub use report::{extract, pack, ReportError};

mod tests;
