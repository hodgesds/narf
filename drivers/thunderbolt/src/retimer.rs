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
//! as single-lane), the retimer NVM firmware-update surface
//! (sector size, offset, 64-byte block writes, read-back, and the
//! authenticate handshake) restricted to on-board retimers, and the
//! lane-margining Port Operations (capabilities, hardware and
//! software runs, software error counters; USB4 v2.0 §8.3.2.4).
//!
//! Register indices, `PORT_CS_1` field positions and FourCC opcodes
//! follow USB4 Specification v2.0 (June 2023) Table 4-18, Table 8-13
//! and Table 8-64, cross-checked against Linux `sb_regs.h`,
//! `tb_regs.h`, `usb4.c` and `retimer.c`. Retimer-specific
//! operations (`SET_INBOUND_SBTX` and the NVM operations) are
//! defined by the USB4 Re-Timer Specification and named here with
//! the FourCC values Linux uses for them. The lane-margining
//! operation FourCCs, Metadata encodings, completion timeouts and
//! Data-register result layouts are taken from Linux
//! `drivers/thunderbolt/sb_regs.h` and `usb4.c`
//! (`usb4_port_margining_caps`, `usb4_port_hw_margin`,
//! `usb4_port_sw_margin`, `usb4_port_sw_margin_errors`).

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
/// `READ_LANE_MARGINING_CAP` Port Operation ("RDCP", USB4 §8.3.2.4):
/// read the lane-margining capabilities; the three capability
/// dwords land in the Data register after completion.
pub const OP_READ_LANE_MARGINING_CAP: u32 = 0x5043_4452;
/// `RUN_HW_LANE_MARGINING` Port Operation ("RHMG", USB4 §8.3.2.4):
/// run hardware lane margining; the run parameters are staged in
/// Metadata and the three result dwords land in the Data register
/// after completion.
pub const OP_RUN_HW_LANE_MARGINING: u32 = 0x474d_4852;
/// `RUN_SW_LANE_MARGINING` Port Operation ("RSMG", USB4 §8.3.2.4):
/// run software lane margining; the run parameters are staged in
/// Metadata and the single result dword lands in the Data register
/// after completion. The error counters it accumulates are read
/// back with [`OP_READ_SW_MARGIN_ERR`].
pub const OP_RUN_SW_LANE_MARGINING: u32 = 0x474d_5352;
/// `READ_SW_MARGIN_ERR` Port Operation ("RDSW", USB4 §8.3.2.4):
/// read the software margining error counters; the standard
/// counters arrive in the completion Metadata, the extended
/// counters (when the capabilities report them) in the Data
/// register.
pub const OP_READ_SW_MARGIN_ERR: u32 = 0x5753_4452;

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
/// Completion deadline for the lane-margining run operations
/// (`RUN_HW_LANE_MARGINING`, `RUN_SW_LANE_MARGINING`; Linux
/// `usb4_port_hw_margin`/`usb4_port_sw_margin` use 2500 ms).
const MARGIN_RUN_TIMEOUT_MS: u64 = 2500;
/// Completion deadline for `READ_SW_MARGIN_ERR` (Linux
/// `usb4_port_sw_margin_errors` uses 150 ms).
const MARGIN_ERR_TIMEOUT_MS: u64 = 150;

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

/// Which receiver lanes a lane-margining run covers (USB4 §8.3.2.4;
/// Linux `enum usb4_margining_lane`). The value is the Metadata
/// lanes field itself: a single receiver lane, or 7 for all lanes
/// at once (when the capabilities report `all_lanes`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarginLane {
    /// Receiver lane 0.
    Rx0 = 0,
    /// Receiver lane 1.
    Rx1 = 1,
    /// Receiver lane 2 (asymmetric links only).
    Rx2 = 2,
    /// All lanes simultaneously.
    All = 7,
}

/// Software margining error-counter operation (Linux `enum
/// usb4_margin_sw_error_counter`): what a [`sw_margin`] run does
/// to the error counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarginErrorCounter {
    /// No change in counter setup.
    Nop = 0,
    /// Set the error counter to 0, enable counter.
    Clear = 1,
    /// Start counter, count from last value.
    Start = 2,
    /// Stop counter, do not clear value.
    Stop = 3,
}

/// Parameters for a hardware or software lane-margining run (Linux
/// `struct usb4_port_margining_params`). Fields that only one run
/// kind uses are ignored by the other: `ber_level` is a hardware
/// run field, `error_counter` and `voltage_time_offset` are
/// software run fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarginParams {
    /// Lanes to run on.
    pub lanes: MarginLane,
    /// True for time margining instead of voltage margining.
    pub time: bool,
    /// False for a left/low margin test, true for right/high.
    pub right_high: bool,
    /// True when the margin test runs on the upper eye, false for
    /// the lower eye.
    pub upper_eye: bool,
    /// Enable the optional extended voltage range.
    pub optional_voltage_offset_range: bool,
    /// BER level contour value for a hardware run (0..=31); 0
    /// leaves the contour unselected.
    pub ber_level: u8,
    /// Error-counter operation for a software run.
    pub error_counter: MarginErrorCounter,
    /// Voltage/time offset for a software run (0..=127).
    pub voltage_time_offset: u8,
}

/// The Metadata word for a hardware lane-margining run (Linux
/// `usb4_port_hw_margin`): lanes in bits 2:0, time in bit 3,
/// right/high-or-upper-eye in bit 4, BER level in bits 9:5,
/// optional voltage range in bit 10.
fn hw_margin_metadata(params: &MarginParams) -> Result<u32, Error> {
    if params.ber_level > 31 {
        return Err(Error::InvalidArgument);
    }
    let mut value = params.lanes as u32;
    if params.time {
        value |= 1 << 3;
    }
    if params.right_high || params.upper_eye {
        value |= 1 << 4;
    }
    value |= (params.ber_level as u32) << 5;
    if params.optional_voltage_offset_range {
        value |= 1 << 10;
    }
    Ok(value)
}

/// The Metadata word for a software lane-margining run (Linux
/// `usb4_port_sw_margin`): lanes in bits 2:0, time in bit 3,
/// right/high in bit 4, optional voltage range in bit 5,
/// voltage/time offset in bits 12:6, error-counter operation in
/// bits 14:13, upper eye in bit 15.
fn sw_margin_metadata(params: &MarginParams) -> Result<u32, Error> {
    if params.voltage_time_offset > 127 {
        return Err(Error::InvalidArgument);
    }
    let mut value = params.lanes as u32;
    if params.time {
        value |= 1 << 3;
    }
    if params.right_high {
        value |= 1 << 4;
    }
    if params.optional_voltage_offset_range {
        value |= 1 << 5;
    }
    value |= (params.voltage_time_offset as u32) << 6;
    value |= (params.error_counter as u32) << 13;
    if params.upper_eye {
        value |= 1 << 15;
    }
    Ok(value)
}

/// Lane-margining capabilities read by `RDCP`: the three Data
/// dwords (USB4 §8.3.2.4; Linux `usb4_port_margining_caps` reads
/// three). Dwords 0/1 describe Gen 2/3 behaviour; dword 2 is the
/// Gen 4 set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarginCaps {
    /// The three capability dwords, in Data-register order.
    pub words: [u32; 3],
}

impl MarginCaps {
    /// Hardware margining is supported (dword 0 bit 0).
    pub fn supports_hw(&self) -> bool {
        self.words[0] & 1 != 0
    }
    /// Software margining is supported (dword 0 bit 1).
    pub fn supports_sw(&self) -> bool {
        self.words[0] & (1 << 1) != 0
    }
    /// All lanes can be margined simultaneously (dword 0 bit 2).
    pub fn all_lanes(&self) -> bool {
        self.words[0] & (1 << 2) != 0
    }
    /// Time margining is supported (dword 0 bit 5).
    pub fn time_supported(&self) -> bool {
        self.words[0] & (1 << 5) != 0
    }
    /// Number of voltage margin steps (dword 0 bits 12:6).
    pub fn voltage_steps(&self) -> u32 {
        (self.words[0] >> 6) & 0x7f
    }
    /// Maximum voltage offset in mV (dword 0 bits 18:13).
    pub fn max_voltage_offset(&self) -> u32 {
        (self.words[0] >> 13) & 0x3f
    }
    /// The optional extended voltage range is supported
    /// (dword 0 bit 19).
    pub fn optional_voltage_supported(&self) -> bool {
        self.words[0] & (1 << 19) != 0
    }
    /// Number of voltage margin steps in the optional range
    /// (dword 0 bits 26:20).
    pub fn voltage_steps_optional(&self) -> u32 {
        (self.words[0] >> 20) & 0x7f
    }
    /// The extended error counter is supported (dword 0 bit 28):
    /// [`sw_margin_errors_ext`] returns per-lane extended counts.
    pub fn extended_error_counter(&self) -> bool {
        self.words[0] & (1 << 28) != 0
    }
    /// Maximum voltage offset in mV in the optional range
    /// (dword 1 bits 7:0).
    pub fn max_voltage_offset_optional(&self) -> u32 {
        self.words[1] & 0xff
    }
    /// Time margining is destructive (dword 1 bit 8).
    pub fn time_destructive(&self) -> bool {
        self.words[1] & (1 << 8) != 0
    }
    /// Number of time margin steps (dword 1 bits 15:11).
    pub fn time_steps(&self) -> u32 {
        (self.words[1] >> 11) & 0x1f
    }
    /// Maximum time offset in mUI (dword 1 bits 20:16).
    pub fn max_time_offset(&self) -> u32 {
        (self.words[1] >> 16) & 0x1f
    }
    /// Minimum BER level contour (dword 1 bits 25:21).
    pub fn min_ber_level(&self) -> u32 {
        (self.words[1] >> 21) & 0x1f
    }
    /// Maximum BER level contour (dword 1 bits 30:26).
    pub fn max_ber_level(&self) -> u32 {
        (self.words[1] >> 26) & 0x1f
    }
    /// Hardware margining is supported on a Gen 4 link
    /// (dword 2 bit 0).
    pub fn supports_hw_gen4(&self) -> bool {
        self.words[2] & 1 != 0
    }
    /// Software margining is supported on a Gen 4 link
    /// (dword 2 bit 1).
    pub fn supports_sw_gen4(&self) -> bool {
        self.words[2] & (1 << 1) != 0
    }
    /// Time margining is supported on a Gen 4 link (dword 2 bit 2).
    pub fn time_supported_gen4(&self) -> bool {
        self.words[2] & (1 << 2) != 0
    }
}

/// Hardware lane-margining results from `RHMG`: the three Data
/// dwords (Linux `HW_MARGINING_DWORDS`). Linux interprets dwords
/// 1..2 as the per-lane results and leaves dword 0 uninterpreted:
/// dword 1 holds lanes 0 (low half) and 1 (high half), dword 2
/// holds lane 2. Each lane result is a byte pair — the low byte is
/// the right/high margin, the high byte the left/low margin — with
/// the margin value in bits 6:0 and the exceeds-maximum flag in
/// bit 7.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HwMarginResults {
    /// The three result dwords, in Data-register order.
    pub words: [u32; 3],
}

impl HwMarginResults {
    /// The raw margin byte for `lane` on the requested side
    /// (Linux `margining_hw_result_val` in `debugfs.c`).
    pub fn lane_byte(&self, lane: MarginLane, right_high: bool) -> u8 {
        let value = match lane {
            MarginLane::Rx0 => self.words[1],
            MarginLane::Rx1 => self.words[1] >> 16,
            MarginLane::Rx2 => self.words[2],
            MarginLane::All => 0,
        };
        let byte = if right_high { value } else { value >> 8 };
        byte as u8
    }

    /// The margin value (bits 6:0) of a margin byte.
    pub fn margin(byte: u8) -> u8 {
        byte & 0x7f
    }

    /// Whether a margin byte reports the margin exceeds the
    /// maximum (bit 7).
    pub fn exceeds(byte: u8) -> bool {
        byte & 0x80 != 0
    }
}

/// Software margining error counters from `RDSW`: the standard
/// counter word. Lane 0 occupies bits 3:0, lane 1 bits 7:4, lane 2
/// bits 11:8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwMarginErrors {
    /// The standard counter word.
    pub word: u32,
}

impl SwMarginErrors {
    /// The error count for one lane (0 for `All`: the standard
    /// word holds per-lane counts, not an aggregate).
    pub fn lane(&self, lane: MarginLane) -> u32 {
        match lane {
            MarginLane::Rx0 => self.word & 0xf,
            MarginLane::Rx1 => (self.word >> 4) & 0xf,
            MarginLane::Rx2 => (self.word >> 8) & 0xf,
            MarginLane::All => 0,
        }
    }
}

/// Extended software margining error counters from `RDSW`: the
/// four Data dwords (Linux `SW_MARGINING_DWORDS`). Dword 0 is the
/// standard counter word (see [`SwMarginErrors`]); dword 1 + lane
/// holds that lane's extended counter bits, placed in bits 15:4 of
/// the lane's error count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SwMarginErrorsExt {
    /// The four counter dwords, in Data-register order.
    pub words: [u32; 4],
}

impl SwMarginErrorsExt {
    /// The error count for one lane, standard nibble plus its
    /// extended bits (Linux `margining_get_lane_error`).
    pub fn lane(&self, lane: MarginLane) -> u32 {
        let index = match lane {
            MarginLane::Rx0 => 0,
            MarginLane::Rx1 => 1,
            MarginLane::Rx2 => 2,
            MarginLane::All => return 0,
        };
        let standard = SwMarginErrors {
            word: self.words[0],
        }
        .lane(lane);
        standard | ((self.words[1 + index] & 0xfff) << 4)
    }
}

/// Read a port's lane-margining capabilities (`RDCP`, USB4
/// §8.3.2.4). The operation runs against the channel's target —
/// the router port itself or one retimer on the link, selected by
/// `ch` — and the three capability dwords are read from the Data
/// register after completion. A port without margining answers
/// `!CMD` ([`Error::NotSupported`]).
pub async fn margining_caps(ctl: &mut impl Config, ch: SbChannel) -> Result<MarginCaps, Error> {
    port_op(ctl, ch, OP_READ_LANE_MARGINING_CAP, OP_TIMEOUT_MS).await?;
    let data = sb_read(ctl, ch, SB_DATA, 12).await?;
    Ok(MarginCaps {
        words: [data[0], data[1], data[2]],
    })
}

/// Run hardware lane margining (`RHMG`, USB4 §8.3.2.4) against the
/// channel's target. The run parameters are staged in Metadata;
/// the three result dwords are read from the Data register after
/// completion and interpreted with [`HwMarginResults::lane_byte`].
/// A `ber_level` above 31 is [`Error::InvalidArgument`].
pub async fn hw_margin(
    ctl: &mut impl Config,
    ch: SbChannel,
    params: &MarginParams,
) -> Result<HwMarginResults, Error> {
    let metadata = hw_margin_metadata(params)?;
    sb_write(ctl, ch, SB_METADATA, &[metadata]).await?;
    port_op(ctl, ch, OP_RUN_HW_LANE_MARGINING, MARGIN_RUN_TIMEOUT_MS).await?;
    let data = sb_read(ctl, ch, SB_DATA, 12).await?;
    Ok(HwMarginResults {
        words: [data[0], data[1], data[2]],
    })
}

/// Run software lane margining (`RSMG`, USB4 §8.3.2.4) against the
/// channel's target. The run parameters are staged in Metadata;
/// the single result dword is read from the Data register after
/// completion. The error counters the run accumulates are read
/// back with [`sw_margin_errors`] (or [`sw_margin_errors_ext`]
/// when the capabilities report the extended counter). A
/// `voltage_time_offset` above 127 is [`Error::InvalidArgument`].
pub async fn sw_margin(
    ctl: &mut impl Config,
    ch: SbChannel,
    params: &MarginParams,
) -> Result<u32, Error> {
    let metadata = sw_margin_metadata(params)?;
    sb_write(ctl, ch, SB_METADATA, &[metadata]).await?;
    port_op(ctl, ch, OP_RUN_SW_LANE_MARGINING, MARGIN_RUN_TIMEOUT_MS).await?;
    Ok(sb_read(ctl, ch, SB_DATA, 4).await?[0])
}

/// Read the software margining error counters (`RDSW`, USB4
/// §8.3.2.4) against the channel's target. The standard counters
/// arrive in the completion Metadata; use
/// [`sw_margin_errors_ext`] for the extended counters.
pub async fn sw_margin_errors(
    ctl: &mut impl Config,
    ch: SbChannel,
) -> Result<SwMarginErrors, Error> {
    let metadata = port_op(ctl, ch, OP_READ_SW_MARGIN_ERR, MARGIN_ERR_TIMEOUT_MS).await?;
    Ok(SwMarginErrors { word: metadata })
}

/// Read the extended software margining error counters (`RDSW`,
/// USB4 §8.3.2.4) against the channel's target. Only meaningful
/// when the capabilities report the extended error counter
/// ([`MarginCaps::extended_error_counter`]); the four dwords are
/// read from the Data register after completion and interpreted
/// with [`SwMarginErrorsExt::lane`].
pub async fn sw_margin_errors_ext(
    ctl: &mut impl Config,
    ch: SbChannel,
) -> Result<SwMarginErrorsExt, Error> {
    port_op(ctl, ch, OP_READ_SW_MARGIN_ERR, MARGIN_ERR_TIMEOUT_MS).await?;
    let data = sb_read(ctl, ch, SB_DATA, 16).await?;
    Ok(SwMarginErrorsExt {
        words: [data[0], data[1], data[2], data[3]],
    })
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
        /// Lane-margining capabilities returned by `RDCP`.
        margin_caps: [u32; 3],
        /// Hardware margining results returned by `RHMG`.
        hw_results: [u32; 3],
        /// Software margining result dword returned by `RSMG`.
        sw_result: u32,
        /// Standard software error counters returned by `RDSW`
        /// in the completion Metadata.
        sw_errors: u32,
        /// Extended software error counters returned by `RDSW`
        /// in the Data register.
        sw_errors_ext: [u32; 4],
        /// Metadata word staged for the last `RHMG`/`RSMG` run,
        /// snapshotted when the operation executes (the completion
        /// overwrites the Metadata register, so the test reads the
        /// request encoding here).
        margin_metadata: u32,
        /// The four lane-margining operations complete with `!CMD`.
        margining_unsupported: bool,
        /// The four lane-margining operations complete with `ERR `.
        margining_failed: bool,
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
                margin_caps: [0; 3],
                hw_results: [0; 3],
                sw_result: 0,
                sw_errors: 0,
                sw_errors_ext: [0; 4],
                margin_metadata: 0,
                margining_unsupported: false,
                margining_failed: false,
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
            } else if self.margining_unsupported
                && matches!(
                    opcode,
                    OP_READ_LANE_MARGINING_CAP
                        | OP_RUN_HW_LANE_MARGINING
                        | OP_RUN_SW_LANE_MARGINING
                        | OP_READ_SW_MARGIN_ERR
                )
            {
                (OP_ONS, 0)
            } else if self.margining_failed
                && matches!(
                    opcode,
                    OP_READ_LANE_MARGINING_CAP
                        | OP_RUN_HW_LANE_MARGINING
                        | OP_RUN_SW_LANE_MARGINING
                        | OP_READ_SW_MARGIN_ERR
                )
            {
                (OP_ERR, 0)
            } else {
                match opcode {
                    OP_QUERY_LAST_RETIMER => (0, self.last as u32),
                    OP_QUERY_CABLE_RETIMER => (0, self.cable as u32),
                    OP_GET_NVM_SECTOR_SIZE => (0, self.sector_size),
                    OP_READ_LANE_MARGINING_CAP => {
                        self.data[0] = self.margin_caps[0];
                        self.data[1] = self.margin_caps[1];
                        self.data[2] = self.margin_caps[2];
                        (0, 0)
                    }
                    OP_RUN_HW_LANE_MARGINING => {
                        self.margin_metadata = self.metadata;
                        self.data[0] = self.hw_results[0];
                        self.data[1] = self.hw_results[1];
                        self.data[2] = self.hw_results[2];
                        (0, 0)
                    }
                    OP_RUN_SW_LANE_MARGINING => {
                        self.margin_metadata = self.metadata;
                        self.data[0] = self.sw_result;
                        (0, 0)
                    }
                    OP_READ_SW_MARGIN_ERR => {
                        self.data[0] = self.sw_errors_ext[0];
                        self.data[1] = self.sw_errors_ext[1];
                        self.data[2] = self.sw_errors_ext[2];
                        self.data[3] = self.sw_errors_ext[3];
                        (0, self.sw_errors)
                    }
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

    /// Lane-margining capabilities (`RDCP`, USB4 §8.3.2.4): the
    /// three Data dwords come back and the capability fields decode
    /// per Linux `sb_regs.h`.
    fn usb4_retimer_lane_margining_caps() -> TestResult {
        let mut m = SbModel::new();
        let mut rt = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        rt.margin_caps = [
            (1 << 0)
                | (1 << 1)
                | (1 << 2)
                | (1 << 5)
                | (40 << 6)
                | (30 << 13)
                | (1 << 19)
                | (20 << 20)
                | (1 << 28),
            0x55 | (1 << 8) | (25 << 11) | (18 << 16) | (3 << 21) | (12 << 26),
            0x7,
        ];
        m.retimers = alloc::vec![rt];
        let port = link_port();
        let ch = SbChannel::retimer(0, &port, 1);
        let caps = match run(margining_caps(&mut m, ch)) {
            Ok(caps) => caps,
            Err(_) => return TestResult::Fail("RDCP did not complete"),
        };
        if caps.words != m.retimers[0].margin_caps {
            return TestResult::Fail("RDCP capability dwords are not the fixture words");
        }
        if !caps.supports_hw()
            || !caps.supports_sw()
            || !caps.all_lanes()
            || !caps.time_supported()
            || caps.voltage_steps() != 40
            || caps.max_voltage_offset() != 30
            || !caps.optional_voltage_supported()
            || caps.voltage_steps_optional() != 20
            || !caps.extended_error_counter()
            || caps.max_voltage_offset_optional() != 0x55
            || !caps.time_destructive()
            || caps.time_steps() != 25
            || caps.max_time_offset() != 18
            || caps.min_ber_level() != 3
            || caps.max_ber_level() != 12
            || !caps.supports_hw_gen4()
            || !caps.supports_sw_gen4()
            || !caps.time_supported_gen4()
        {
            return TestResult::Fail("RDCP capability fields do not decode");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/retimer",
        usb4_retimer_lane_margining_caps
    );

    /// Hardware lane margining (`RHMG`, USB4 §8.3.2.4): the request
    /// Metadata encodes lanes/time/right-high/BER/optional-voltage
    /// per Linux `usb4_port_hw_margin`, and the three result dwords
    /// parse per Linux `margining_hw_result_val`.
    fn usb4_retimer_lane_margining_hw() -> TestResult {
        let mut m = SbModel::new();
        let mut rt = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        rt.hw_results = [0xdead_0001, 0x3310_8a25, 0x0000_0741];
        m.retimers = alloc::vec![rt];
        let port = link_port();
        let ch = SbChannel::retimer(0, &port, 1);
        let params = MarginParams {
            lanes: MarginLane::All,
            time: false,
            right_high: true,
            upper_eye: false,
            optional_voltage_offset_range: true,
            ber_level: 5,
            error_counter: MarginErrorCounter::Nop,
            voltage_time_offset: 0,
        };
        let results = match run(hw_margin(&mut m, ch, &params)) {
            Ok(results) => results,
            Err(_) => return TestResult::Fail("RHMG did not complete"),
        };
        // lanes 7 | right/high bit 4 | BER 5 in bits 9:5 |
        // optional voltage bit 10.
        if m.retimers[0].margin_metadata != 0x4b7 {
            return TestResult::Fail("RHMG request Metadata is not the Linux encoding");
        }
        if results.words != [0xdead_0001, 0x3310_8a25, 0x0000_0741] {
            return TestResult::Fail("RHMG result dwords are not the fixture words");
        }
        if results.lane_byte(MarginLane::Rx0, true) != 0x25
            || results.lane_byte(MarginLane::Rx0, false) != 0x8a
            || HwMarginResults::margin(0x8a) != 0x0a
            || !HwMarginResults::exceeds(0x8a)
            || HwMarginResults::exceeds(0x25)
            || results.lane_byte(MarginLane::Rx1, true) != 0x10
            || results.lane_byte(MarginLane::Rx1, false) != 0x33
            || results.lane_byte(MarginLane::Rx2, true) != 0x41
            || results.lane_byte(MarginLane::Rx2, false) != 0x07
            || results.lane_byte(MarginLane::All, true) != 0
        {
            return TestResult::Fail("RHMG lane results do not parse");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/retimer",
        usb4_retimer_lane_margining_hw
    );

    /// Software lane margining (`RSMG`, USB4 §8.3.2.4): the request
    /// Metadata encodes lanes/time/right-high/upper-eye/counter/
    /// voltage-time offset per Linux `usb4_port_sw_margin`, and the
    /// single result dword comes back from the Data register.
    fn usb4_retimer_lane_margining_sw() -> TestResult {
        let mut m = SbModel::new();
        let mut rt = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        rt.sw_result = 0x0000_0001;
        m.retimers = alloc::vec![rt];
        let port = link_port();
        let ch = SbChannel::retimer(0, &port, 1);
        let params = MarginParams {
            lanes: MarginLane::Rx1,
            time: true,
            right_high: true,
            upper_eye: true,
            optional_voltage_offset_range: false,
            ber_level: 0,
            error_counter: MarginErrorCounter::Start,
            voltage_time_offset: 0x2a,
        };
        let result = match run(sw_margin(&mut m, ch, &params)) {
            Ok(result) => result,
            Err(_) => return TestResult::Fail("RSMG did not complete"),
        };
        // lanes 1 | time bit 3 | right/high bit 4 | VT 0x2a in
        // bits 12:6 | counter START (2) in bits 14:13 | upper eye
        // bit 15.
        if m.retimers[0].margin_metadata != 0xca99 {
            return TestResult::Fail("RSMG request Metadata is not the Linux encoding");
        }
        if result != 0x0000_0001 {
            return TestResult::Fail("RSMG result dword is not the fixture word");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/retimer",
        usb4_retimer_lane_margining_sw
    );

    /// Software margining error counters (`RDSW`, USB4 §8.3.2.4):
    /// the standard counters arrive in the completion Metadata and
    /// the extended counters in the Data register, parsed per Linux
    /// `margining_get_lane_error`.
    fn usb4_retimer_lane_margining_errors() -> TestResult {
        let mut m = SbModel::new();
        let mut rt = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        rt.sw_errors = 0x3a5;
        rt.sw_errors_ext = [0x3a5, 0x123, 0x456, 0x789];
        m.retimers = alloc::vec![rt];
        let port = link_port();
        let ch = SbChannel::retimer(0, &port, 1);
        let errors = match run(sw_margin_errors(&mut m, ch)) {
            Ok(errors) => errors,
            Err(_) => return TestResult::Fail("RDSW did not complete"),
        };
        if errors.word != 0x3a5
            || errors.lane(MarginLane::Rx0) != 0x5
            || errors.lane(MarginLane::Rx1) != 0xa
            || errors.lane(MarginLane::Rx2) != 0x3
            || errors.lane(MarginLane::All) != 0
        {
            return TestResult::Fail("RDSW standard counters do not parse");
        }
        let ext = match run(sw_margin_errors_ext(&mut m, ch)) {
            Ok(ext) => ext,
            Err(_) => return TestResult::Fail("RDSW extended read did not complete"),
        };
        if ext.words != [0x3a5, 0x123, 0x456, 0x789]
            || ext.lane(MarginLane::Rx0) != 0x1235
            || ext.lane(MarginLane::Rx1) != 0x456a
            || ext.lane(MarginLane::Rx2) != 0x7893
            || ext.lane(MarginLane::All) != 0
        {
            return TestResult::Fail("RDSW extended counters do not parse");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/retimer",
        usb4_retimer_lane_margining_errors
    );

    /// Lane-margining failure paths: `!CMD` is `NotSupported`,
    /// `ERR ` is `OpFailed`, a garbage completion is `Malformed`,
    /// and out-of-range run parameters are `InvalidArgument`
    /// before any sideband traffic. The fixture's margining fault
    /// flags are scoped to the four margining operations: an
    /// unrelated NVM operation still completes.
    fn usb4_retimer_lane_margining_failures() -> TestResult {
        let port = link_port();
        let ch = SbChannel::retimer(0, &port, 1);
        let params = MarginParams {
            lanes: MarginLane::All,
            time: false,
            right_high: false,
            upper_eye: false,
            optional_voltage_offset_range: false,
            ber_level: 0,
            error_counter: MarginErrorCounter::Nop,
            voltage_time_offset: 0,
        };
        let mut m = SbModel::new();
        let mut rt = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        rt.margining_unsupported = true;
        rt.sector_size = 0x1000;
        m.retimers = alloc::vec![rt];
        if run(margining_caps(&mut m, ch)) != Err(Error::NotSupported)
            || run(hw_margin(&mut m, ch, &params)) != Err(Error::NotSupported)
            || run(sw_margin_errors(&mut m, ch)) != Err(Error::NotSupported)
        {
            return TestResult::Fail("unsupported margining was not NotSupported");
        }
        let rt = Retimer {
            index: 1,
            vendor_id: 0x8087,
            product_id: 0x1111,
            fw_version: 0x0001_0000,
            last: true,
            cable: false,
            auth_status: None,
            link_conf: [0x03, 0x10, 0x01],
        };
        if run(nvm_sector_size(&mut m, 0, &port, &rt)) != Ok(0x1000) {
            return TestResult::Fail("margining fault flags leaked into NVM operations");
        }
        let mut m = SbModel::new();
        let mut rt = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        rt.margining_failed = true;
        m.retimers = alloc::vec![rt];
        if run(margining_caps(&mut m, ch)) != Err(Error::OpFailed)
            || run(sw_margin(&mut m, ch, &params)) != Err(Error::OpFailed)
        {
            return TestResult::Fail("failed margining was not OpFailed");
        }
        let mut m = SbModel::new();
        let mut rt = device(0x8087, 0x1111, 0x0001_0000, true, 0x03);
        rt.garbage_ops = true;
        m.retimers = alloc::vec![rt];
        if run(margining_caps(&mut m, ch)) != Err(Error::Malformed) {
            return TestResult::Fail("garbage margining completion was not Malformed");
        }
        let mut m = SbModel::new();
        m.retimers = alloc::vec![device(0x8087, 0x1111, 0x0001_0000, true, 0x03)];
        let bad_ber = MarginParams {
            ber_level: 32,
            ..params
        };
        let bad_vt = MarginParams {
            voltage_time_offset: 128,
            ..params
        };
        if run(hw_margin(&mut m, ch, &bad_ber)) != Err(Error::InvalidArgument)
            || run(sw_margin(&mut m, ch, &bad_vt)) != Err(Error::InvalidArgument)
        {
            return TestResult::Fail("out-of-range margining parameters were not rejected");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/thunderbolt/retimer",
        usb4_retimer_lane_margining_failures
    );
}
