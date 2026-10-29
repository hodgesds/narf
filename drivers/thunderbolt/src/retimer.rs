//! USB4 retimer management over the sideband channel.
//!
//! Retimers sit on the link between a router's USB4 port and the
//! Type-C connector (on-board retimers) or inside an active cable
//! (cable retimers). They are reached from the router through
//! Addressed RT Transactions: the connection manager programs the
//! USB4 Port Capability (`PORT_CS_1`/`PORT_CS_2`) and the router
//! carries the access over the Sideband Channel (USB4 v2.0 §4.1.1.2,
//! §4.1.1.3, Table 8-13). Before that traffic means anything the
//! retimers must be enumerated: a Broadcast RT Transaction, issued by
//! writing the `ENUMERATE_RE-TIMERS` Port Operation to the router's
//! own SB register space, makes each retimer assign itself the
//! one-based index of its distance from the issuing router
//! (USB4 v2.0 §8.3.2.3.2, Figure 4-3; at most six retimers per link).
//!
//! This module implements that surface: the sideband read/write
//! engine, Port Operations with their completion protocol
//! (USB4 v2.0 §8.3.2.1: opcode clears to 0 on success, `ERR ` when
//! the operation is supported but failed, `!CMD` when unsupported),
//! retimer enumeration with Vendor/Product/Firmware identity, the
//! post-training link verification (each retimer's Link
//! Configuration Enabling Decisions — the Phase 3 record of lane
//! bonding, §4.1.1.3 — must agree with the router port's own, or the
//! link is rejected with a typed error rather than silently treated
//! as single-lane), and the retimer NVM firmware-update surface
//! (sector size, offset, 64-byte block writes, read-back, and the
//! authenticate handshake) restricted to on-board retimers.
//!
//! Register indices, `PORT_CS_1` field positions and FourCC opcodes
//! follow USB4 Specification v2.0 (June 2023) Table 4-18, Table 8-13
//! and Table 8-64, cross-checked against Linux `sb_regs.h`,
//! `tb_regs.h`, `usb4.c` and `retimer.c`. Retimer-specific
//! operations (`SET_INBOUND_SBTX` and the NVM operations) are
//! defined by the USB4 Re-Timer Specification and named here with
//! the FourCC values Linux uses for them.

use super::{cm::CfgSpace, control::Config, ring};
use alloc::vec::Vec;

/// SB register index of the Vendor ID register (Table 4-18).
pub const SB_VENDOR_ID: u8 = 0;
/// SB register index of the Product ID register.
pub const SB_PRODUCT_ID: u8 = 1;
/// SB register index of the Firmware Version register.
pub const SB_FW_VERSION: u8 = 2;
/// SB register index of the Opcode register (Port Operations).
pub const SB_OPCODE: u8 = 8;
/// SB register index of the Metadata register (Port Operations).
pub const SB_METADATA: u8 = 9;
/// SB register index of the Link Configuration register.
pub const SB_LINK_CONF: u8 = 12;
/// SB register index of the Data register (Port Operations, 64 bytes).
pub const SB_DATA: u8 = 18;

/// FourCC completion value: operation supported but failed ("ERR ").
pub const OP_ERR: u32 = 0x2052_5245;
/// FourCC completion value: operation not supported ("!CMD").
pub const OP_ONS: u32 = 0x444d_4321;
/// `ROUTER_OFFLINE_MODE` Port Operation ("LSEN", USB4 §8.3.2.3.1).
pub const OP_ROUTER_OFFLINE: u32 = 0x4e45_534c;
/// `ENUMERATE_RE-TIMERS` Port Operation ("ENUM", USB4 §8.3.2.3.2).
pub const OP_ENUMERATE_RETIMERS: u32 = 0x4d55_4e45;
/// `SET_INBOUND_SBTX` retimer operation ("LSUP", Re-Timer spec):
/// enable sideband transactions toward the connector side.
pub const OP_SET_INBOUND_SBTX: u32 = 0x5055_534c;
/// `UNSET_INBOUND_SBTX` retimer operation ("USUP", Re-Timer spec).
pub const OP_UNSET_INBOUND_SBTX: u32 = 0x5055_5355;
/// `QUERY_LAST_RETIMER` retimer operation ("LAST"): completion
/// metadata bit 0 is set when this retimer is the last on the link.
pub const OP_QUERY_LAST_RETIMER: u32 = 0x5453_414c;
/// `QUERY_CABLE_RETIMER` retimer operation ("CBLR"): completion
/// metadata bit 0 is set when this retimer is a cable retimer.
pub const OP_QUERY_CABLE_RETIMER: u32 = 0x524c_4243;
/// `GET_NVM_SECTOR_SIZE` retimer operation ("GNSS"): completion
/// metadata bits 23:0 carry the NVM sector size in bytes.
pub const OP_GET_NVM_SECTOR_SIZE: u32 = 0x5353_4e47;
/// `NVM_SET_OFFSET` retimer operation ("BOPS"): the write offset is
/// staged in Metadata as a dword address in bits 23:2.
pub const OP_NVM_SET_OFFSET: u32 = 0x5350_4f42;
/// `NVM_BLOCK_WRITE` retimer operation ("BLKW"): writes the 64-byte
/// Data register contents to NVM at the current offset.
pub const OP_NVM_BLOCK_WRITE: u32 = 0x574b_4c42;
/// `NVM_AUTH_WRITE` retimer operation ("AUTH"): validates the
/// written image and restarts the retimer on it. The retimer loses
/// its index, so no completion is polled for this operation.
pub const OP_NVM_AUTH_WRITE: u32 = 0x4854_5541;
/// `NVM_READ` retimer operation ("AFRR"): reads NVM into the Data
/// register; offset/length are staged in Metadata.
pub const OP_NVM_READ: u32 = 0x5252_4641;

/// Maximum number of retimers on one link (USB4 v2.0 Figure 4-3).
pub const MAX_RETIMERS: u8 = 6;
/// Dwords in the SB Data window (`PORT_CS_2`..`PORT_CS_17`).
pub const SB_DATA_DWORDS: usize = 16;

/// Sideband access deadline for one `PORT_CS_1` transaction; the
/// router retransmits RT Transactions below this layer, so a Pending
/// bit that survives the deadline means the link or device is gone.
const SB_TIMEOUT_MS: u64 = 500;
/// Default completion deadline for a Port Operation.
const OP_TIMEOUT_MS: u64 = 500;
/// Completion deadline for `NVM_BLOCK_WRITE` (flash program time).
const BLOCK_WRITE_TIMEOUT_MS: u64 = 1000;

// `PORT_CS_1` fields (USB4 v2.0 Table 8-13).
const CS1_WNR: u32 = 1 << 24;
const CS1_NR: u32 = 1 << 25;
const CS1_RC: u32 = 1 << 26;
const CS1_PND: u32 = 1 << 31;

/// Which SB register space a `PORT_CS_1` access targets
/// (Table 8-13 Target field encodings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SbTarget {
    /// The router's own SB space, via local access (000b).
    Router = 0,
    /// The link partner router, via AT Transaction (001b).
    Partner = 1,
    /// A retimer on the link, via RT Transaction (010b); the
    /// Retimer Index field selects which one.
    Retimer = 2,
}

/// Address of one sideband channel: the router port whose USB4
/// adapter hosts the transactions, and the target on the link
/// beyond it. The five fields are the `PORT_CS_1` addressing of a
/// single transaction (route, port, capability, target, index)
/// and are never meaningful apart, so the sideband primitives
/// take the channel as one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SbChannel {
    /// Route string of the router that owns the port.
    pub route: u64,
    /// Port number on that router.
    pub port: u8,
    /// Offset of the port's USB4 adapter capability.
    pub usb4_cap: u16,
    /// Which SB register space the transaction targets.
    pub target: SbTarget,
    /// Retimer Index field (for [`SbTarget::Retimer`]).
    pub index: u8,
}

impl SbChannel {
    /// The channel to retimer `index` on the link off `port`.
    pub fn retimer(route: u64, port: &super::topology::Port, index: u8) -> Self {
        Self {
            route,
            port: port.number,
            usb4_cap: port.usb4_cap,
            target: SbTarget::Retimer,
            index,
        }
    }

    /// The channel to the router's own SB space on `port`.
    pub fn router(route: u64, port: &super::topology::Port) -> Self {
        Self {
            route,
            port: port.number,
            usb4_cap: port.usb4_cap,
            target: SbTarget::Router,
            index: 0,
        }
    }
}

/// Typed failure of a sideband access, Port Operation, enumeration,
/// link verification or NVM step. Every variant is a distinct,
/// diagnosable condition; nothing in this module degrades a failed
/// retimer conversation into a silent single-lane or no-retimer
/// assumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The underlying config transport failed.
    Transport(ring::Error),
    /// The router reported No Response (PORT_CS_1 NR): no device
    /// answered at the addressed target/index.
    NoResponse,
    /// The router reported a Result Code (PORT_CS_1 RC): for a read
    /// the target answered with zero length, for a write the target
    /// refused the data.
    Refused,
    /// Pending never cleared, or a Port Operation never completed,
    /// within its deadline.
    Timeout,
    /// The Port Operation completed with `!CMD`: not supported.
    NotSupported,
    /// The Port Operation completed with `ERR `: supported, but it
    /// could not be completed.
    OpFailed,
    /// A reply was structurally wrong: a short read, an unknown
    /// completion FourCC, or an out-of-range argument.
    Malformed,
    /// The enumerated chain ended without any retimer reporting
    /// itself last, so the chain's true extent is unknown.
    ChainNotTerminated,
    /// A retimer's Link Configuration decisions disagree with the
    /// router port's own decisions for the trained link. `router`
    /// and `retimer` carry the decision nibble (Link Configuration
    /// byte 0 bits 3:0) each side recorded in Phase 3.
    BondingDisagreement {
        /// Retimer index whose decisions disagree.
        index: u8,
        /// The router port's decision nibble.
        router: u8,
        /// The retimer's decision nibble.
        retimer: u8,
    },
    /// NVM write/authenticate was attempted on a cable retimer;
    /// firmware update is an on-board-retimer operation.
    CableRetimer,
    /// A caller supplied an out-of-range argument (no USB4
    /// capability, empty or oversized transfer).
    InvalidArgument,
}

impl From<ring::Error> for Error {
    fn from(error: ring::Error) -> Self {
        Error::Transport(error)
    }
}

/// One enumerated retimer on a link, as recorded by [`scan_link`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retimer {
    /// One-based index from the issuing router (its distance along
    /// the link, assigned by the Broadcast RT Transaction).
    pub index: u8,
    /// Contents of the SB Vendor ID register.
    pub vendor_id: u32,
    /// Contents of the SB Product ID register.
    pub product_id: u32,
    /// Contents of the SB Firmware Version register.
    pub fw_version: u32,
    /// True when this retimer reported itself last on the link
    /// (`QUERY_LAST_RETIMER` completion metadata bit 0).
    pub last: bool,
    /// True when this retimer is a cable retimer
    /// (`QUERY_CABLE_RETIMER` completion metadata bit 0); false
    /// for an on-board retimer.
    pub cable: bool,
    /// NVM authentication status (low 6 bits of the completion
    /// metadata after an `ERR ` opcode read-back), when it could be
    /// read; 0 means no pending authentication failure.
    pub auth_status: Option<u32>,
    /// The retimer's Link Configuration register (SB register 12),
    /// bytes 0..2: byte 0 holds the Phase 3 Enabling/Asymmetric
    /// Decisions, byte 1 the requests and Bonding Support, byte 2
    /// the speed/asymmetric support bits.
    pub link_conf: [u8; 3],
}

impl Retimer {
    /// The Phase 3 decision nibble this retimer recorded: Link
    /// Configuration byte 0 bits 3:0 (Enabling Decision Lane 0,
    /// Enabling Decision Lane 1, Asymmetric Decision Tx/Rx).
    pub fn decisions(&self) -> u8 {
        self.link_conf[0] & 0x0f
    }

    /// Whether this retimer's Phase 3 record has Lane 1 enabled,
    /// i.e. whether it participated in a bonded (dual-lane) link.
    pub fn lane1_enabled(&self) -> bool {
        self.link_conf[0] & (1 << 1) != 0
    }
}

/// The `PORT_CS_1` command dword for one SB access (Table 8-13).
fn cs1_command(reg: u8, len: u8, target: SbTarget, index: u8, write: bool) -> u32 {
    (reg as u32)
        | ((len as u32) << 8)
        | ((target as u32) << 16)
        | ((index as u32) << 20)
        | (if write { CS1_WNR } else { 0 })
        | CS1_PND
}

async fn poll_pause() {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
}

/// Issue one SB access through the USB4 Port Capability and wait
/// for the router to clear Pending. Write data must already be
/// staged in `PORT_CS_2`.. by the caller. Returns the final
/// `PORT_CS_1` value (Length field updated by the router).
async fn sb_command(
    ctl: &mut impl Config,
    route: u64,
    port: u8,
    usb4_cap: u16,
    command: u32,
) -> Result<u32, Error> {
    ctl.write(route, port, CfgSpace::Port, usb4_cap + 1, &[command])
        .await?;
    let deadline = narf_time::Deadline::after_ms(SB_TIMEOUT_MS);
    loop {
        let value = ctl
            .read(route, port, CfgSpace::Port, usb4_cap + 1, 1)
            .await?[0];
        if value & CS1_PND == 0 {
            if value & CS1_NR != 0 {
                return Err(Error::NoResponse);
            }
            return Ok(value);
        }
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        poll_pause().await;
    }
}

/// Read `len` bytes (1..=64) from SB register `reg` of the selected
/// target. The data dwords land in `PORT_CS_2`.. in increasing
/// address order, little-endian within each dword.
#[allow(clippy::too_many_arguments)] // the USB4 sideband request's fields
pub async fn sb_read(
    ctl: &mut impl Config,
    ch: SbChannel,
    reg: u8,
    len: u8,
) -> Result<Vec<u32>, Error> {
    if ch.usb4_cap == 0 || len == 0 || len as usize > SB_DATA_DWORDS * 4 {
        return Err(Error::InvalidArgument);
    }
    let command = cs1_command(reg, len, ch.target, ch.index, false);
    let done = sb_command(ctl, ch.route, ch.port, ch.usb4_cap, command).await?;
    if done & CS1_RC != 0 {
        // Per Table 8-13 a read sets RC exactly when the response
        // carried zero length: the target refused the read.
        return Err(Error::Refused);
    }
    if ((done >> 8) & 0xff) < len as u32 {
        return Err(Error::Malformed);
    }
    let dwords = (len as usize).div_ceil(4) as u8;
    Ok(ctl
        .read(ch.route, ch.port, CfgSpace::Port, ch.usb4_cap + 2, dwords)
        .await?)
}

/// Write `data` dwords to SB register `reg` of the selected target.
/// Data is staged in `PORT_CS_2`.. before the command is issued.
#[allow(clippy::too_many_arguments)] // the USB4 sideband request's fields
pub async fn sb_write(
    ctl: &mut impl Config,
    ch: SbChannel,
    reg: u8,
    data: &[u32],
) -> Result<(), Error> {
    if ch.usb4_cap == 0 || data.is_empty() || data.len() > SB_DATA_DWORDS {
        return Err(Error::InvalidArgument);
    }
    ctl.write(ch.route, ch.port, CfgSpace::Port, ch.usb4_cap + 2, data)
        .await?;
    let len = (data.len() * 4) as u8;
    let command = cs1_command(reg, len, ch.target, ch.index, true);
    let done = sb_command(ctl, ch.route, ch.port, ch.usb4_cap, command).await?;
    if done & CS1_RC != 0 {
        return Err(Error::Refused);
    }
    Ok(())
}

/// Run one Port Operation against the selected target and return
/// its completion metadata (USB4 §8.3.2, §8.3.2.1). The opcode is
/// written to the Opcode register; completion is polled by reading
/// the Opcode register back until it changes: 0 is success,
/// `ERR ` is [`Error::OpFailed`], `!CMD` is
/// [`Error::NotSupported`], anything else is
/// [`Error::Malformed`]. Callers stage any operation Metadata/Data
/// before calling.
#[allow(clippy::too_many_arguments)] // the USB4 sideband request's fields
pub async fn port_op(
    ctl: &mut impl Config,
    ch: SbChannel,
    opcode: u32,
    timeout_ms: u64,
) -> Result<u32, Error> {
    sb_write(ctl, ch, SB_OPCODE, &[opcode]).await?;
    let deadline = narf_time::Deadline::after_ms(timeout_ms);
    loop {
        let value = sb_read(ctl, ch, SB_OPCODE, 4).await?[0];
        if value != opcode {
            return match value {
                0 => Ok(sb_read(ctl, ch, SB_METADATA, 4).await?[0]),
                OP_ERR => Err(Error::OpFailed),
                OP_ONS => Err(Error::NotSupported),
                _ => Err(Error::Malformed),
            };
        }
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        poll_pause().await;
    }
}

/// Send the Broadcast RT Transaction that makes every retimer on
/// the link assign itself an index facing this router's port
/// (USB4 §8.3.2.3.2). The operation is delivered locally, to the
/// router's own SB space; it has no completion metadata.
pub async fn enumerate_retimers(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
) -> Result<(), Error> {
    sb_write(
        ctl,
        SbChannel::router(route, port),
        SB_OPCODE,
        &[OP_ENUMERATE_RETIMERS],
    )
    .await
}

/// Enable sideband transactions on a retimer's connector-facing
/// side (`SET_INBOUND_SBTX`). Per the Re-Timer Specification the
/// retimer is not required to answer the first command with an RT
/// response, so a single No Response outcome is tolerated and the
/// command retried once.
pub async fn set_inbound_sbtx(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
    index: u8,
) -> Result<(), Error> {
    let ch = SbChannel::retimer(route, port, index);
    match port_op(ctl, ch, OP_SET_INBOUND_SBTX, OP_TIMEOUT_MS).await {
        Err(Error::NoResponse) => {
            port_op(ctl, ch, OP_SET_INBOUND_SBTX, OP_TIMEOUT_MS).await?;
            Ok(())
        }
        other => other.map(|_| ()),
    }
}

/// Disable sideband transactions on a retimer's connector-facing
/// side (`UNSET_INBOUND_SBTX`), returning it to passthrough. An
/// inbound sideband session opened for NVM access must be closed
/// with this operation when the access ends.
pub async fn unset_inbound_sbtx(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
    index: u8,
) -> Result<(), Error> {
    port_op(
        ctl,
        SbChannel::retimer(route, port, index),
        OP_UNSET_INBOUND_SBTX,
        OP_TIMEOUT_MS,
    )
    .await
    .map(|_| ())
}

/// Read a retimer's NVM authentication status. After an
/// `NVM_AUTH_WRITE` the retimer validates the new image; the
/// outcome is read back by inspecting the Opcode register: a
/// cleared opcode means the status is 0, an `ERR ` opcode means
/// the status is in the low 6 bits of the Metadata register.
pub async fn auth_status(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
    index: u8,
) -> Result<u32, Error> {
    let ch = SbChannel::retimer(route, port, index);
    let value = sb_read(ctl, ch, SB_OPCODE, 4).await?[0];
    match value {
        0 => Ok(0),
        OP_ERR => {
            let metadata = sb_read(ctl, ch, SB_METADATA, 4).await?[0];
            Ok(metadata & 0x3f)
        }
        OP_ONS => Err(Error::NotSupported),
        _ => Err(Error::Malformed),
    }
}

/// The pure link-agreement check behind [`scan_link`]: a non-empty
/// chain must terminate in a retimer that reports itself last, and
/// every retimer's Phase 3 decision nibble must equal the router
/// port's own. Any deviation is a typed error — a retimer that did
/// not take part in lane bonding must never let the link be treated
/// as bonded (or silently as single-lane) by assumption.
pub fn check_agreement(router_decisions: u8, chain: &[Retimer]) -> Result<(), Error> {
    if let Some(last) = chain.last() {
        if !last.last {
            return Err(Error::ChainNotTerminated);
        }
    }
    for retimer in chain {
        if retimer.decisions() != router_decisions {
            return Err(Error::BondingDisagreement {
                index: retimer.index,
                router: router_decisions,
                retimer: retimer.decisions(),
            });
        }
    }
    Ok(())
}

/// Enumerate the retimers on one trained link and verify them
/// against the link's trained configuration. Issues the Broadcast
/// RT enumeration, then probes indices 1..=[`MAX_RETIMERS`]: the
/// first index that does not answer ends the chain, and each
/// answering retimer's Vendor/Product/Firmware identity, last and
/// cable status, authentication status and Link Configuration are
/// recorded. The router port's own Link Configuration decisions
/// are read first and every retimer must agree with them
/// ([`check_agreement`]).
///
/// A link with no retimers enumerates as an empty chain — the
/// pre-retimer behaviour, unchanged. A retimer-side fault (no
/// response mid-chain, a refused or garbage reply, a bonding
/// disagreement) is a typed [`Error`], never an empty chain.
pub async fn scan_link(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
) -> Result<Vec<Retimer>, Error> {
    if port.usb4_cap == 0 {
        return Err(Error::InvalidArgument);
    }
    let router_conf = sb_read(ctl, SbChannel::router(route, port), SB_LINK_CONF, 4).await?[0];
    enumerate_retimers(ctl, route, port).await?;
    let mut chain = Vec::new();
    for index in 1..=MAX_RETIMERS {
        let ch = SbChannel::retimer(route, port, index);
        let vendor_id = match sb_read(ctl, ch, SB_VENDOR_ID, 4).await {
            Ok(value) => value[0],
            Err(Error::NoResponse) => break,
            Err(error) => return Err(error),
        };
        let product_id = sb_read(ctl, ch, SB_PRODUCT_ID, 4).await?[0];
        let fw_version = sb_read(ctl, ch, SB_FW_VERSION, 4).await?[0];
        let conf = sb_read(ctl, ch, SB_LINK_CONF, 4).await?[0].to_le_bytes();
        let last = port_op(ctl, ch, OP_QUERY_LAST_RETIMER, OP_TIMEOUT_MS).await? & 1 != 0;
        let cable = port_op(ctl, ch, OP_QUERY_CABLE_RETIMER, OP_TIMEOUT_MS).await? & 1 != 0;
        let auth = auth_status(ctl, route, port, index).await.ok();
        chain.push(Retimer {
            index,
            vendor_id,
            product_id,
            fw_version,
            last,
            cable,
            auth_status: auth,
            link_conf: [conf[0], conf[1], conf[2]],
        });
        if last {
            break;
        }
    }
    check_agreement((router_conf & 0x0f) as u8, &chain)?;
    Ok(chain)
}

/// Read a retimer's NVM sector size in bytes
/// (`GET_NVM_SECTOR_SIZE` completion metadata bits 23:0). A
/// retimer without upgradeable NVM answers 0 or `!CMD`.
pub async fn nvm_sector_size(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
    retimer: &Retimer,
) -> Result<u32, Error> {
    let metadata = port_op(
        ctl,
        SbChannel::retimer(route, port, retimer.index),
        OP_GET_NVM_SECTOR_SIZE,
        OP_TIMEOUT_MS,
    )
    .await?;
    Ok(metadata & 0x00ff_ffff)
}

/// Stage the NVM write offset (`NVM_SET_OFFSET`): the byte
/// address is converted to a dword address in Metadata bits 23:2.
pub async fn nvm_set_offset(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
    retimer: &Retimer,
    address: u32,
) -> Result<(), Error> {
    if retimer.cable {
        return Err(Error::CableRetimer);
    }
    let metadata = ((address / 4) << 2) & 0x00ff_fffc;
    let ch = SbChannel::retimer(route, port, retimer.index);
    sb_write(ctl, ch, SB_METADATA, &[metadata]).await?;
    port_op(ctl, ch, OP_NVM_SET_OFFSET, OP_TIMEOUT_MS).await?;
    Ok(())
}

/// Pack bytes into little-endian dwords, zero-padding the tail.
fn pack_dwords(bytes: &[u8]) -> Vec<u32> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(4));
    for chunk in bytes.chunks(4) {
        let mut word = [0u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        out.push(u32::from_le_bytes(word));
    }
    out
}

/// Write `data` to a retimer's NVM starting at byte `address`, in
/// 64-byte Data-register blocks (`NVM_BLOCK_WRITE` per block). The
/// offset auto-advances within the retimer after each block. The
/// image takes effect only after [`nvm_authenticate`].
pub async fn nvm_write(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
    retimer: &Retimer,
    address: u32,
    data: &[u8],
) -> Result<(), Error> {
    if retimer.cable {
        return Err(Error::CableRetimer);
    }
    if data.is_empty() {
        return Err(Error::InvalidArgument);
    }
    nvm_set_offset(ctl, route, port, retimer, address).await?;
    let ch = SbChannel::retimer(route, port, retimer.index);
    for block in data.chunks(SB_DATA_DWORDS * 4) {
        // Stage the whole Data register each block: BLKW writes
        // all 64 bytes, so a partial final block must be padded
        // with zeros rather than left holding the previous block's
        // tail.
        let packed = pack_dwords(block);
        let mut staged = [0u32; SB_DATA_DWORDS];
        staged[..packed.len()].copy_from_slice(&packed);
        sb_write(ctl, ch, SB_DATA, &staged).await?;
        port_op(ctl, ch, OP_NVM_BLOCK_WRITE, BLOCK_WRITE_TIMEOUT_MS).await?;
    }
    Ok(())
}

/// Read a retimer's NVM into `out` starting at byte `address`, in
/// blocks of at most 64 bytes (`NVM_READ` per block; the block
/// dword count rides in Metadata bits 27:24 when it is not a full
/// block). Reads are permitted for cable retimers too — only
/// writes and authentication are on-board operations.
pub async fn nvm_read(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
    retimer: &Retimer,
    address: u32,
    out: &mut [u8],
) -> Result<(), Error> {
    if out.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let ch = SbChannel::retimer(route, port, retimer.index);
    let mut done = 0usize;
    while done < out.len() {
        let take = (out.len() - done).min(SB_DATA_DWORDS * 4);
        let dwords = take.div_ceil(4);
        let dwaddress = (address / 4) + (done / 4) as u32;
        let mut metadata = dwaddress << 2;
        if dwords < SB_DATA_DWORDS {
            metadata |= (dwords as u32) << 24;
        }
        sb_write(ctl, ch, SB_METADATA, &[metadata]).await?;
        port_op(ctl, ch, OP_NVM_READ, OP_TIMEOUT_MS).await?;
        let data = sb_read(ctl, ch, SB_DATA, (dwords * 4) as u8).await?;
        for (i, word) in data.iter().enumerate() {
            let bytes = word.to_le_bytes();
            for (j, byte) in bytes.iter().enumerate() {
                let at = done + i * 4 + j;
                if at < out.len() {
                    out[at] = *byte;
                }
            }
        }
        done += take;
    }
    Ok(())
}

/// Trigger NVM authentication (`NVM_AUTH_WRITE`): the retimer
/// validates the image written by [`nvm_write`] and restarts on
/// it. The restart unassigns the retimer's index, so this is a raw
/// opcode write with no completion poll; the caller re-enumerates
/// ([`enumerate_retimers`]) and then reads the outcome with
/// [`auth_status`].
pub async fn nvm_authenticate(
    ctl: &mut impl Config,
    route: u64,
    port: &super::topology::Port,
    retimer: &Retimer,
) -> Result<(), Error> {
    if retimer.cable {
        return Err(Error::CableRetimer);
    }
    sb_write(
        ctl,
        SbChannel::retimer(route, port, retimer.index),
        SB_OPCODE,
        &[OP_NVM_AUTH_WRITE],
    )
    .await
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::super::{cm::CfgSpace, control::Config, ring::Error as RingError, topology::Port};
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// USB4 Port Capability offset the fixtures expose.
    const CAP: u16 = 0x40;

    /// One SB register space (a router's or a retimer's), modelled
    /// from USB4 v2.0 §4.1.1.3 / §8.3.2 rather than from the
    /// production code: Port Operations complete asynchronously
    /// (the first Opcode read-back still shows the opcode, the
    /// completion value appears on the next), and `PORT_CS_1`
    /// Pending clears only on the second read after a command.
    #[derive(Clone, Debug)]
    struct SbDevice {
        present: bool,
        vendor: u32,
        product: u32,
        fw: u32,
        link_conf: u32,
        last: bool,
        cable: bool,
        opcode: u32,
        metadata: u32,
        data: [u32; SB_DATA_DWORDS],
        op_pending: Option<(u32, u32)>,
        op_reads: u8,
        sector_size: u32,
        nvm: Vec<u8>,
        nvm_offset: usize,
        auth_code: u32,
        rc_reads: bool,
        garbage_ops: bool,
        drop_first_inbound: bool,
    }

    impl Default for SbDevice {
        fn default() -> Self {
            Self {
                present: false,
                vendor: 0,
                product: 0,
                fw: 0,
                link_conf: 0,
                last: false,
                cable: false,
                opcode: 0,
                metadata: 0,
                data: [0; SB_DATA_DWORDS],
                op_pending: None,
                op_reads: 0,
                sector_size: 0,
                nvm: Vec::new(),
                nvm_offset: 0,
                auth_code: 0,
                rc_reads: false,
                garbage_ops: false,
                drop_first_inbound: false,
            }
        }
    }

    impl SbDevice {
        /// A Port Operation landed in the Opcode register: stage
        /// its completion. The completion becomes visible on the
        /// second Opcode read (see the model's read path).
        fn execute_op(&mut self, opcode: u32) {
            if opcode == OP_NVM_AUTH_WRITE {
                // The retimer restarts on the new image; the
                // opcode register reads back ERR with the
                // validation status in Metadata.
                self.opcode = OP_ERR;
                self.metadata = self.auth_code;
                self.op_pending = None;
                return;
            }
            let result = if self.garbage_ops {
                (0xdead_beef, 0)
            } else {
                match opcode {
                    OP_QUERY_LAST_RETIMER => (0, self.last as u32),
                    OP_QUERY_CABLE_RETIMER => (0, self.cable as u32),
                    OP_GET_NVM_SECTOR_SIZE => (0, self.sector_size),
                    OP_NVM_SET_OFFSET => {
                        self.nvm_offset = (((self.metadata >> 2) & 0x003f_ffff) as usize) * 4;
                        (0, self.metadata)
                    }
                    OP_NVM_BLOCK_WRITE => {
                        let mut bytes = Vec::with_capacity(64);
                        for word in self.data {
                            bytes.extend_from_slice(&word.to_le_bytes());
                        }
                        if self.nvm.len() < self.nvm_offset + 64 {
                            self.nvm.resize(self.nvm_offset + 64, 0);
                        }
                        self.nvm[self.nvm_offset..self.nvm_offset + 64].copy_from_slice(&bytes);
                        self.nvm_offset += 64;
                        (0, 0)
                    }
                    OP_NVM_READ => {
                        let dwords = ((self.metadata >> 24) & 0xf) as usize;
                        let dwords = if dwords == 0 { SB_DATA_DWORDS } else { dwords };
                        let base = (((self.metadata >> 2) & 0x003f_ffff) as usize) * 4;
                        for i in 0..dwords {
                            let mut word = [0u8; 4];
                            for (j, byte) in word.iter_mut().enumerate() {
                                *byte = self.nvm.get(base + i * 4 + j).copied().unwrap_or(0);
                            }
                            self.data[i] = u32::from_le_bytes(word);
                        }
                        (0, self.metadata)
                    }
                    OP_SET_INBOUND_SBTX | OP_UNSET_INBOUND_SBTX => (0, 0),
                    OP_ENUMERATE_RETIMERS => (0, 0),
                    _ => (OP_ONS, 0),
                }
            };
            self.opcode = opcode;
            self.op_pending = Some(result);
            self.op_reads = 0;
        }

        fn register(&self, reg: u8) -> u32 {
            match reg {
                SB_VENDOR_ID => self.vendor,
                SB_PRODUCT_ID => self.product,
                SB_FW_VERSION => self.fw,
                SB_METADATA => self.metadata,
                SB_LINK_CONF => self.link_conf,
                _ => 0,
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Load {
        Router,
        Retimer(usize),
    }

    #[derive(Debug)]
    struct SbModel {
        router: SbDevice,
        retimers: Vec<SbDevice>,
        cs1: u32,
        pnd_reads: u8,
        outcome_nr: bool,
        outcome_rc: bool,
        outcome_len: u8,
        pending_load: Option<(Load, u8, u8)>,
        window: [u32; SB_DATA_DWORDS],
        stuck_pnd: bool,
        cs1_writes: Vec<u32>,
        inbound_attempts: u8,
    }

    impl SbModel {
        fn new() -> Self {
            let mut router = SbDevice {
                present: true,
                ..SbDevice::default()
            };
            router.link_conf = link_conf(0x03);
            Self {
                router,
                retimers: Vec::new(),
                cs1: 0,
                pnd_reads: 0,
                outcome_nr: false,
                outcome_rc: false,
                outcome_len: 0,
                pending_load: None,
                window: [0; SB_DATA_DWORDS],
                stuck_pnd: false,
                cs1_writes: Vec::new(),
                inbound_attempts: 0,
            }
        }

        fn device_mut(&mut self, load: Load) -> Option<&mut SbDevice> {
            match load {
                Load::Router => Some(&mut self.router),
                Load::Retimer(i) => self.retimers.get_mut(i),
            }
        }

        fn command(&mut self, command: u32) {
            self.cs1_writes.push(command);
            self.cs1 = command;
            self.pnd_reads = 0;
            self.outcome_nr = false;
            self.outcome_rc = false;
            self.outcome_len = 0;
            self.pending_load = None;
            let reg = (command & 0xff) as u8;
            let len = ((command >> 8) & 0xff) as u8;
            let target = (command >> 16) & 0x7;
            let index = ((command >> 20) & 0xf) as u8;
            let write = command & CS1_WNR != 0;
            let load = match target {
                0 => Some(Load::Router),
                2 if (1..=MAX_RETIMERS).contains(&index) => {
                    Some(Load::Retimer((index - 1) as usize))
                }
                _ => None,
            };
            let present = match load {
                Some(Load::Router) => true,
                Some(Load::Retimer(i)) => self.retimers.get(i).is_some_and(|device| device.present),
                _ => false,
            };
            if !present {
                self.outcome_nr = true;
                return;
            }
            let load = load.unwrap();
            if write {
                let staged = self.window;
                if reg == SB_OPCODE && staged[0] == OP_SET_INBOUND_SBTX && load != Load::Router {
                    self.inbound_attempts += 1;
                    let drop = self
                        .device_mut(load)
                        .is_some_and(|device| device.drop_first_inbound)
                        && self.inbound_attempts == 1;
                    if drop {
                        // The Re-Timer Specification does not
                        // require an RT response to the first
                        // SET_INBOUND_SBTX: the router reports
                        // No Response and nothing executes.
                        self.outcome_nr = true;
                        return;
                    }
                }
                match reg {
                    SB_OPCODE => {
                        let opcode = staged[0];
                        if let Some(device) = self.device_mut(load) {
                            device.execute_op(opcode);
                        }
                    }
                    SB_METADATA => {
                        if let Some(device) = self.device_mut(load) {
                            device.metadata = staged[0];
                        }
                    }
                    SB_DATA => {
                        if let Some(device) = self.device_mut(load) {
                            device.data = staged;
                        }
                    }
                    _ => {}
                }
            } else {
                let rc = self.device_mut(load).is_some_and(|device| device.rc_reads);
                if rc {
                    self.outcome_rc = true;
                } else {
                    self.outcome_len = len;
                    self.pending_load = Some((load, reg, len));
                }
            }
        }

        fn complete_read(&mut self) -> u32 {
            if let Some((load, reg, len)) = self.pending_load.take() {
                if reg == SB_OPCODE {
                    if let Some(device) = self.device_mut(load) {
                        if let Some(result) = device.op_pending {
                            if device.op_reads == 0 {
                                device.op_reads = 1;
                                self.window[0] = device.opcode;
                            } else {
                                device.opcode = result.0;
                                device.metadata = result.1;
                                device.op_pending = None;
                                self.window[0] = result.0;
                            }
                        } else {
                            self.window[0] = device.opcode;
                        }
                    }
                } else if reg == SB_DATA {
                    if let Some(device) = self.device_mut(load) {
                        let data = device.data;
                        self.window = data;
                    }
                } else if let Some(device) = self.device_mut(load) {
                    self.window[0] = device.register(reg);
                }
                let _ = len;
            }
            let mut value = self.cs1 & !CS1_PND;
            value = (value & !(0xff << 8)) | ((self.outcome_len as u32) << 8);
            if self.outcome_nr {
                value |= CS1_NR;
            }
            if self.outcome_rc {
                value |= CS1_RC;
            }
            value
        }
    }

    impl Config for SbModel {
        async fn read(
            &mut self,
            _route: u64,
            _port: u8,
            space: CfgSpace,
            offset: u16,
            len: u8,
        ) -> Result<Vec<u32>, RingError> {
            if space != CfgSpace::Port {
                return Ok(alloc::vec![0; len as usize]);
            }
            if offset == CAP + 1 {
                if self.stuck_pnd {
                    return Ok(alloc::vec![self.cs1 | CS1_PND]);
                }
                if self.pnd_reads == 0 && self.cs1 & CS1_PND != 0 {
                    self.pnd_reads = 1;
                    return Ok(alloc::vec![self.cs1]);
                }
                return Ok(alloc::vec![self.complete_read()]);
            }
            if (CAP + 2..CAP + 2 + SB_DATA_DWORDS as u16).contains(&offset) {
                let start = (offset - (CAP + 2)) as usize;
                return Ok(self.window[start..start + len as usize].to_vec());
            }
            Ok(alloc::vec![0; len as usize])
        }

        async fn write(
            &mut self,
            _route: u64,
            _port: u8,
            space: CfgSpace,
            offset: u16,
            data: &[u32],
        ) -> Result<(), RingError> {
            if space != CfgSpace::Port {
                return Ok(());
            }
            if offset == CAP + 1 {
                self.command(data[0]);
            } else if (CAP + 2..CAP + 2 + SB_DATA_DWORDS as u16).contains(&offset) {
                let start = (offset - (CAP + 2)) as usize;
                self.window[start..start + data.len()].copy_from_slice(data);
            }
            Ok(())
        }
    }

    /// Link Configuration dword with the given Phase 3 decision
    /// nibble, Bonding Support set and SB channel support set.
    fn link_conf(decisions: u8) -> u32 {
        (decisions as u32) | (0x10 << 8) | (0x01 << 16)
    }

    fn device(vendor: u32, product: u32, fw: u32, last: bool, decisions: u8) -> SbDevice {
        SbDevice {
            present: true,
            vendor,
            product,
            fw,
            link_conf: link_conf(decisions),
            last,
            ..SbDevice::default()
        }
    }

    fn link_port() -> Port {
        Port {
            number: 1,
            kind: 1,
            adapter_cap: 0,
            phy_cap: 0x20,
            usb4_cap: CAP,
            max_in_hop: 0,
            max_out_hop: 0,
            total_credits: 0,
            secondary: false,
            retimers: Vec::new(),
            retimer_fault: None,
        }
    }

    fn run<T>(future: impl core::future::Future<Output = T>) -> T {
        narf_scheduler::block_on_spin(future)
    }

    fn usb4_retimer_two_retimer_chain() -> TestResult {
        let mut m = SbModel::new();
        m.retimers = alloc::vec![
            device(0x8087, 0x1111, 0x0001_0000, false, 0x03),
            device(0x0451, 0x2222, 0x0002_0000, true, 0x03),
        ];
        let chain = match run(scan_link(&mut m, 0, &link_port())) {
            Ok(chain) => chain,
            Err(_) => return TestResult::Fail("two-retimer chain did not enumerate"),
        };
        if chain.len() != 2
            || chain[0].index != 1
            || chain[0].vendor_id != 0x8087
            || chain[0].product_id != 0x1111
            || chain[0].fw_version != 0x0001_0000
            || chain[0].last
            || chain[0].cable
            || chain[0].auth_status != Some(0)
            || !chain[0].lane1_enabled()
            || chain[1].index != 2
            || chain[1].vendor_id != 0x0451
            || chain[1].product_id != 0x2222
            || chain[1].fw_version != 0x0002_0000
            || !chain[1].last
        {
            return TestResult::Fail("chain records are not two distinct retimers");
        }
        // Byte-for-byte PORT_CS_1 pins: the ENUMERATE_RE-TIMERS
        // broadcast write to the router's Opcode register, and the
        // Vendor ID read addressed to retimer index 2.
        if !m.cs1_writes.contains(&0x8100_0408) || !m.cs1_writes.contains(&0x8022_0400) {
            return TestResult::Fail("PORT_CS_1 command dwords do not match Table 8-13");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/retimer",
        usb4_retimer_two_retimer_chain
    );

    fn usb4_retimer_absent_link() -> TestResult {
        let mut m = SbModel::new();
        let chain = match run(scan_link(&mut m, 0, &link_port())) {
            Ok(chain) => chain,
            Err(_) => return TestResult::Fail("retimer-absent link errored"),
        };
        if !chain.is_empty() {
            return TestResult::Fail("retimer-absent link reported retimers");
        }
        // The broadcast was still issued, and exactly one probe
        // (index 1, Vendor ID) went unanswered before the scan
        // concluded the link has no retimers.
        let probes = m
            .cs1_writes
            .iter()
            .filter(|word| ((*word >> 16) & 0x7) == 2 && (*word & 0xff) == 0)
            .count();
        if !m.cs1_writes.contains(&0x8100_0408) || probes != 1 {
            return TestResult::Fail("absent link was not probed exactly once");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/thunderbolt/retimer", usb4_retimer_absent_link);

    fn usb4_retimer_bonding_disagreement() -> TestResult {
        let mut m = SbModel::new();
        // The retimer's Phase 3 record enables Lane 0 only while
        // the router port trained a bonded link (both lanes).
        m.retimers = alloc::vec![device(0x8087, 0x1111, 0x0001_0000, true, 0x01)];
        match run(scan_link(&mut m, 0, &link_port())) {
            Err(Error::BondingDisagreement {
                index: 1,
                router: 0x03,
                retimer: 0x01,
            }) => TestResult::Pass,
            _ => TestResult::Fail("bonding disagreement was not a typed error"),
        }
    }
    kernel_test_in!(
        "drivers/thunderbolt/retimer",
        usb4_retimer_bonding_disagreement
    );

    fn usb4_retimer_malformed_replies() -> TestResult {
        // A Port Operation completing with a garbage FourCC.
        let mut m = SbModel::new();
        let mut bad = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        bad.garbage_ops = true;
        m.retimers = alloc::vec![bad];
        if run(scan_link(&mut m, 0, &link_port())) != Err(Error::Malformed) {
            return TestResult::Fail("garbage completion was not Malformed");
        }
        // Reads refused with a Result Code.
        let mut m = SbModel::new();
        let mut refusing = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        refusing.rc_reads = true;
        m.retimers = alloc::vec![refusing];
        if run(scan_link(&mut m, 0, &link_port())) != Err(Error::Refused) {
            return TestResult::Fail("RC read was not Refused");
        }
        // Pending never clears: a bounded Timeout, not a hang.
        let mut m = SbModel::new();
        m.stuck_pnd = true;
        if run(scan_link(&mut m, 0, &link_port())) != Err(Error::Timeout) {
            return TestResult::Fail("stuck Pending was not a bounded Timeout");
        }
        // A chain whose only retimer denies being last.
        let mut m = SbModel::new();
        m.retimers = alloc::vec![device(0x8087, 0x1111, 0x0001_0000, false, 0x03)];
        if run(scan_link(&mut m, 0, &link_port())) != Err(Error::ChainNotTerminated) {
            return TestResult::Fail("unterminated chain was not typed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/retimer",
        usb4_retimer_malformed_replies
    );

    fn usb4_retimer_nvm_update() -> TestResult {
        let mut m = SbModel::new();
        let mut on_board = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        on_board.sector_size = 0x1000;
        on_board.nvm = alloc::vec![0; 0x1000];
        m.retimers = alloc::vec![on_board];
        let port = link_port();
        let chain = match run(scan_link(&mut m, 0, &port)) {
            Ok(chain) => chain,
            Err(_) => return TestResult::Fail("NVM fixture chain did not enumerate"),
        };
        let rt = &chain[0];
        if run(nvm_sector_size(&mut m, 0, &port, rt)) != Ok(0x1000) {
            return TestResult::Fail("sector size");
        }
        let image: Vec<u8> = (0..100u32).map(|i| (i as u8) ^ 0x5a).collect();
        if run(nvm_write(&mut m, 0, &port, rt, 0, &image)).is_err() {
            return TestResult::Fail("NVM block write");
        }
        if m.retimers[0].nvm[..100] != image[..] || m.retimers[0].nvm[100..128] != [0; 28] {
            return TestResult::Fail("NVM contents after block writes");
        }
        let mut back = [0u8; 100];
        if run(nvm_read(&mut m, 0, &port, rt, 0, &mut back)).is_err() || back != image[..] {
            return TestResult::Fail("NVM read-back");
        }
        if run(nvm_authenticate(&mut m, 0, &port, rt)).is_err()
            || run(auth_status(&mut m, 0, &port, rt.index)) != Ok(0)
        {
            return TestResult::Fail("NVM authenticate + status");
        }
        // Cable retimers refuse writes and authentication.
        let cable = Retimer {
            index: 2,
            vendor_id: 0x0451,
            product_id: 0x2222,
            fw_version: 0,
            last: true,
            cable: true,
            auth_status: None,
            link_conf: [0x03, 0x10, 0x01],
        };
        if run(nvm_write(&mut m, 0, &port, &cable, 0, &image)) != Err(Error::CableRetimer)
            || run(nvm_authenticate(&mut m, 0, &port, &cable)) != Err(Error::CableRetimer)
        {
            return TestResult::Fail("cable retimer accepted an NVM write");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/thunderbolt/retimer", usb4_retimer_nvm_update);

    fn usb4_retimer_inbound_sbtx_tolerance() -> TestResult {
        let mut m = SbModel::new();
        let mut rt = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        rt.drop_first_inbound = true;
        m.retimers = alloc::vec![rt];
        let port = link_port();
        if run(set_inbound_sbtx(&mut m, 0, &port, 1)).is_err() || m.inbound_attempts != 2 {
            return TestResult::Fail("first SET_INBOUND_SBTX no-response was not tolerated");
        }
        if run(unset_inbound_sbtx(&mut m, 0, &port, 1)).is_err() {
            return TestResult::Fail("UNSET_INBOUND_SBTX");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/retimer",
        usb4_retimer_inbound_sbtx_tolerance
    );
}
