//! HCR — the ConnectX-3 *Hardware Command Register* firmware interface.
//!
//! Unlike ConnectX-4+ (which posts commands as 64-byte entries into a
//! host-memory command queue — see `narf-drivers-net-mlx5`), ConnectX-3
//! drives firmware through a 28-byte register window inside BAR0. The
//! driver writes up to a 64-bit input parameter, an input modifier, a
//! 64-bit output parameter and a token, then sets the GO bit in the
//! status dword; firmware clears GO when the command completes and
//! leaves a status byte in the top 8 bits of that dword.
//!
//! All HCR dwords are big-endian on the wire. The actual MMIO pokes live
//! in [`super::Mlx4Eth::cmd`]; this module is the pure, unit-testable
//! encode/decode half: opcodes, the GO-word layout, the pending
//! predicate and the status catalog. Clean-room from the public
//! ConnectX-3 PRM §9 (command interface).

/// Byte offset of the HCR window within BAR0.
pub const HCR_BASE: u64 = 0x0008_0680;
/// Size of the HCR window (7 dwords).
pub const HCR_SIZE: u64 = 0x1c;

/// Dword byte offsets within the HCR window.
pub const HCR_IN_PARAM_H: u64 = 0x00;
pub const HCR_IN_PARAM_L: u64 = 0x04;
pub const HCR_IN_MODIFIER: u64 = 0x08;
pub const HCR_OUT_PARAM_H: u64 = 0x0c;
pub const HCR_OUT_PARAM_L: u64 = 0x10;
pub const HCR_TOKEN: u64 = 0x14;
pub const HCR_STATUS: u64 = 0x18;

/// GO bit — set by the driver to submit, cleared by firmware on
/// completion (bit 23 of the status dword).
pub const HCR_GO: u32 = 1 << 23;
/// Event bit — request a completion EQ event instead of polling GO.
pub const HCR_EVENT: u32 = 1 << 22;
/// Toggle bit — the driver alternates it on every command; firmware
/// echoes it so a stale completion can be told from a fresh one.
pub const HCR_TOGGLE: u32 = 1 << 21;
/// Low bit of the op_modifier field within the status dword.
pub const HCR_OPMOD_SHIFT: u32 = 12;
/// Opcode occupies the low 12 bits of the status dword.
pub const HCR_OPCODE_MASK: u32 = 0x0fff;

/// One DMA mailbox is a single 4-KiB page; its physical address rides
/// in the HCR in/out parameter when a command carries more than 8 bytes.
pub const MAILBOX_SIZE: usize = 4096;

/// A poll-mode command tags its token with this sentinel; event-mode
/// commands (unused during synchronous bring-up) carry a rotating tag.
pub const POLL_TOKEN: u16 = 0xffff;

/// Command opcodes used by the Ethernet bring-up and datapath. Values
/// are the 12-bit HCR opcodes (PRM §9.4). The InfiniBand/SR-IOV opcodes
/// are intentionally omitted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CmdOp {
    QueryDevCap = 0x003,
    QueryFw = 0x004,
    QueryAdapter = 0x006,
    InitHca = 0x007,
    CloseHca = 0x008,
    InitPort = 0x009,
    ClosePort = 0x00a,
    QueryHca = 0x00b,
    SetPort = 0x00c,
    Sw2hwMpt = 0x00d,
    Hw2swMpt = 0x00f,
    WriteMtt = 0x011,
    MapEq = 0x012,
    Sw2hwEq = 0x013,
    Hw2swEq = 0x014,
    Sw2hwCq = 0x016,
    Hw2swCq = 0x017,
    Rst2initQp = 0x019,
    Init2rtrQp = 0x01a,
    Rtr2rtsQp = 0x01b,
    Err2rstQp = 0x021,
    Nop = 0x031,
    ModStatCfg = 0x034,
    QueryPort = 0x043,
    SetIcmSize = 0xffd,
    MapFa = 0xfff,
    UnmapFa = 0xffe,
    RunFw = 0xff6,
    MapIcm = 0xffa,
    UnmapIcm = 0xff9,
    MapIcmAux = 0xffc,
    UnmapIcmAux = 0xffb,
}

impl CmdOp {
    /// The 12-bit opcode value.
    #[inline]
    pub const fn code(self) -> u16 {
        self as u16
    }
}

/// Firmware command status (the HCR status byte, PRM §9.5). `Ok` is the
/// only non-error value.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmdStatus {
    Ok,
    InternalErr,
    BadOp,
    BadParam,
    BadSysState,
    BadResource,
    ResourceBusy,
    ExceedLim,
    BadResState,
    BadIndex,
    BadNvmem,
    IcmError,
    BadQpState,
    BadSegParam,
    RegBound,
    LamNotPre,
    BadPkt,
    BadSize,
    /// Any status byte not in the catalog above.
    Unknown(u8),
}

impl CmdStatus {
    /// Decode the raw status byte (top 8 bits of the status dword).
    pub const fn from_raw(b: u8) -> Self {
        match b {
            0x00 => CmdStatus::Ok,
            0x01 => CmdStatus::InternalErr,
            0x02 => CmdStatus::BadOp,
            0x03 => CmdStatus::BadParam,
            0x04 => CmdStatus::BadSysState,
            0x05 => CmdStatus::BadResource,
            0x06 => CmdStatus::ResourceBusy,
            0x08 => CmdStatus::ExceedLim,
            0x09 => CmdStatus::BadResState,
            0x0a => CmdStatus::BadIndex,
            0x0b => CmdStatus::BadNvmem,
            0x0c => CmdStatus::IcmError,
            0x10 => CmdStatus::BadQpState,
            0x20 => CmdStatus::BadSegParam,
            0x21 => CmdStatus::RegBound,
            0x22 => CmdStatus::LamNotPre,
            0x30 => CmdStatus::BadPkt,
            0x40 => CmdStatus::BadSize,
            other => CmdStatus::Unknown(other),
        }
    }

    #[inline]
    pub const fn is_ok(self) -> bool {
        matches!(self, CmdStatus::Ok)
    }
}

/// Build the HCR status/go dword (host value, before the BE MMIO swap):
/// GO set, toggle `t`, optional event bit, op_modifier and opcode.
pub fn go_word(op: CmdOp, op_modifier: u8, toggle: bool, event: bool) -> u32 {
    let mut w = HCR_GO | (u32::from(op_modifier) << HCR_OPMOD_SHIFT) | u32::from(op.code());
    if toggle {
        w |= HCR_TOGGLE;
    }
    if event {
        w |= HCR_EVENT;
    }
    w
}

/// The token dword value (host) for a poll-mode command.
#[inline]
pub fn token_word(token: u16) -> u32 {
    u32::from(token) << 16
}

/// Extract the status byte from a status-dword read (host value, after
/// the BE MMIO swap): the firmware leaves it in the top 8 bits.
#[inline]
pub fn status_of(status_dword: u32) -> u8 {
    (status_dword >> 24) as u8
}

/// A command is still in flight when GO is still set, or when the
/// echoed toggle does not yet match the toggle the driver last posted.
/// `posted_toggle` is the value the driver put in the GO word.
pub fn is_pending(status_dword: u32, posted_toggle: bool) -> bool {
    if status_dword & HCR_GO != 0 {
        return true;
    }
    let echoed = status_dword & HCR_TOGGLE != 0;
    echoed != posted_toggle
}
