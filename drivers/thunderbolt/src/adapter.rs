//! Adapter type decode — every port on every Thunderbolt switch.
//!
//! A "switch" in Thunderbolt parlance is a router; an "adapter" is a
//! port on that router. Each adapter has a 24-bit *type* word in
//! `TB_CFG_PORT` dword 2 (`struct tb_regs_port_header.type`). The
//! type encodes both the protocol family (PCIe / DP / USB3 / NHI /
//! INACTIVE / generic) AND the direction (upstream / downstream /
//! IN / OUT) for tunneling-capable protocols.
//!
//! Source: Linux `drivers/thunderbolt/tb_regs.h::enum tb_port_type`.
//! USB4 spec §3 ("Adapter Layer") is the public-spec backstop.

use core::fmt;

/// Adapter (port) type, decoded from the 24-bit `type` field of
/// `tb_regs_port_header`.
///
/// Layout: bits 0..7 = direction sub-code, bits 8..15 = sub-category,
/// bits 16..23 = primary family. We just enumerate the values Linux
/// uses — the bit-level decoding isn't load-bearing in practice
/// because the constants are stable across silicon generations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AdapterType {
    /// Port exists but is unused / unwired on this SKU.
    Inactive = 0x000000,
    /// Generic lane adapter — present on every switch as port 1, 2.
    /// Carries the physical lane(s) between switches.
    Port = 0x000001,
    /// NHI adapter — only present on the host switch; it's the port
    /// that loops back to the host PCIe interface.
    Nhi = 0x000002,
    /// DisplayPort sink (IN) — accepts an inbound DP stream.
    DpHdmiIn = 0x0E0101,
    /// DisplayPort source (OUT) — drives an outbound DP stream.
    DpHdmiOut = 0x0E0102,
    /// PCIe downstream-facing adapter (host side of a tunnel).
    PcieDown = 0x100101,
    /// PCIe upstream-facing adapter (peripheral side of a tunnel).
    PcieUp = 0x100102,
    /// USB 3.x downstream port (host side of a USB3 tunnel).
    Usb3Down = 0x200101,
    /// USB 3.x upstream port (peripheral side of a USB3 tunnel).
    Usb3Up = 0x200102,
}

impl AdapterType {
    /// Decode a raw 24-bit type word. Returns `None` for values not
    /// in the enum — caller logs an unknown-type warning.
    pub fn from_raw(value: u32) -> Option<Self> {
        // Mask to 24 bits: `tb_regs_port_header.type` is `u32 type:24`.
        Some(match value & 0x00FF_FFFF {
            0x000000 => Self::Inactive,
            0x000001 => Self::Port,
            0x000002 => Self::Nhi,
            0x0E0101 => Self::DpHdmiIn,
            0x0E0102 => Self::DpHdmiOut,
            0x100101 => Self::PcieDown,
            0x100102 => Self::PcieUp,
            0x200101 => Self::Usb3Down,
            0x200102 => Self::Usb3Up,
            _ => return None,
        })
    }

    /// Short tag for log lines. Mirrors the shape Linux uses in its
    /// switch / port dev_dbg lines ("PCIe-UP", "DP-IN", etc.) so the
    /// boot transcript is grep-friendly across both kernels.
    pub fn short_name(self) -> &'static str {
        match self {
            Self::Inactive => "INACTIVE",
            Self::Port => "LANE",
            Self::Nhi => "NHI",
            Self::DpHdmiIn => "DP-IN",
            Self::DpHdmiOut => "DP-OUT",
            Self::PcieDown => "PCIe-DOWN",
            Self::PcieUp => "PCIe-UP",
            Self::Usb3Down => "USB3-DOWN",
            Self::Usb3Up => "USB3-UP",
        }
    }

    /// True if this adapter can be the *source* end of a PCIe tunnel.
    /// That's `PcieDown` on the host side — the upstream peer at the
    /// far end is `PcieUp`. Useful when picking endpoints for
    /// Stage-2 tunnel setup.
    pub fn is_pcie_source(self) -> bool {
        matches!(self, Self::PcieDown)
    }

    /// True if this adapter can be the *sink* end of a PCIe tunnel
    /// (the peripheral side).
    pub fn is_pcie_sink(self) -> bool {
        matches!(self, Self::PcieUp)
    }

    /// True if this adapter is a DisplayPort IN (accepts a DP stream
    /// from a downstream graphics source — e.g. an external GPU dock
    /// driving the host display).
    pub fn is_dp_in(self) -> bool {
        matches!(self, Self::DpHdmiIn)
    }

    /// True if this adapter is a DisplayPort OUT (drives a DP stream
    /// to a downstream sink — e.g. a host iGPU lane driving a USB-C
    /// monitor on a TB cable).
    pub fn is_dp_out(self) -> bool {
        matches!(self, Self::DpHdmiOut)
    }

    /// True if this adapter is a generic lane port — i.e. the
    /// link-layer port that carries the tunneled protocols between
    /// switches. Lane ports are *not* tunnel endpoints themselves;
    /// they're the substrate that tunnels run over.
    pub fn is_lane(self) -> bool {
        matches!(self, Self::Port)
    }

    /// True if this adapter terminates a tunnel — i.e. is a PCIe /
    /// DP / USB3 endpoint, not a lane.
    pub fn is_tunnel_endpoint(self) -> bool {
        matches!(
            self,
            Self::PcieDown
                | Self::PcieUp
                | Self::DpHdmiIn
                | Self::DpHdmiOut
                | Self::Usb3Down
                | Self::Usb3Up
        )
    }
}

impl fmt::Display for AdapterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short_name())
    }
}
