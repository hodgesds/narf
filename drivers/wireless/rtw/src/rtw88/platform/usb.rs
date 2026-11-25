//! `narf_drivers_usb` for the module: the USB error, port speed and
//! endpoint-index helpers the rtw88 USB transport names. The transfers
//! themselves are `narf_usb_*` requests (`usb_kabi.rs`).

/// A USB transfer failure (the built-in variants).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbError {
    NotConfigured,
    StaleSlot,
    BufferTooSmall,
    Stall,
    Babble,
    TransactionError,
    Timeout,
    HardwareError(u8),
}

impl UsbError {
    /// The `UsbError` for a terminal `narf_usb_poll` / submit errno.
    pub fn from_errno(errno: i32) -> Self {
        match errno {
            -32 => Self::Stall,                  // -EPIPE
            -75 => Self::Babble,                 // -EOVERFLOW
            -71 | -84 => Self::TransactionError, // -EPROTO, -EILSEQ
            -110 | -62 => Self::Timeout,         // -ETIMEDOUT, -ETIME
            -19 | -108 => Self::StaleSlot,       // -ENODEV, -ESHUTDOWN
            -22 => Self::NotConfigured,          // -EINVAL: no such endpoint
            -105 => Self::BufferTooSmall,        // -ENOBUFS
            e => Self::HardwareError(e.unsigned_abs().min(255) as u8),
        }
    }
}

pub mod device {
    pub use super::UsbError;
}

pub mod xhci {
    /// A port's negotiated speed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PortSpeed {
        Full = 1,
        Low = 2,
        High = 3,
        Super = 4,
        SuperPlus = 5,
    }

    impl PortSpeed {
        /// The speed a function's bulk endpoints were enumerated at, from
        /// their `wMaxPacketSize` (USB 2.0 §5.8.3 / USB 3.2 §9.6.6: 64 at
        /// full speed, 512 at high speed, 1024 at SuperSpeed). The USB KABI
        /// carries no port speed; the descriptor fixes it.
        pub fn from_bulk_packet(max_packet: u16) -> Self {
            match max_packet {
                1024.. => Self::Super,
                512..=1023 => Self::High,
                _ => Self::Full,
            }
        }
    }
}

pub mod bulk {
    /// xHCI Device Context Index of endpoint `ep_addr` (xHCI §4.5.1).
    pub const fn dci_for(ep_addr: u8) -> u8 {
        let ep_num = ep_addr & 0x0F;
        if ep_addr & 0x80 != 0 {
            ep_num * 2 + 1
        } else {
            ep_num * 2
        }
    }

    /// The endpoint address of DCI `dci` (the inverse of [`dci_for`]).
    pub const fn ep_for(dci: u8) -> u8 {
        if dci & 1 != 0 {
            0x80 | (dci / 2)
        } else {
            dci / 2
        }
    }
}
