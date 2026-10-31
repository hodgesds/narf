// SPDX-License-Identifier: GPL-2.0-or-later
//
// drivers/wwan/src/bearer.rs — MBIM datapath: NTB framing + netdev handoff
//
// An activated MBIM session is a raw-IP bearer. On the wire it rides
// the CDC NCM NTB-16 framing (MBIM 1.0 §9 / NCM 1.0 §3) with one
// MBIM-specific twist: the NDP16 signature's fourth byte is the
// SessionId, which is how multiple sessions share one pair of bulk
// endpoints. Linux's `cdc_mbim.c` is the reference implementation of
// exactly this adaptation:
//
//   TX: the net stack hands us Ethernet frames; we strip the
//       14-byte Ethernet header, require an IPv4/IPv6 ethertype
//       (MBIM cannot do ARP — cdc_mbim sets IFF_NOARP for the same
//       reason), wrap the raw IP packet as the single datagram of an
//       NTB whose NDP is signed for the session.
//   RX: we verify the NTH, walk the NDP chain, demultiplex by the
//       signature's session byte, and synthesize an Ethernet header
//       around each raw IP datagram (destination = the iface MAC,
//       source = zero, ethertype from the IP version nibble) before
//       handing it to the stack — byte-for-byte the construction in
//       `cdc_mbim_process_dgram`.
//
// The netdev handoff itself is the stack's existing shape —
// `narf_net::iface::register_with_context` with a per-session cookie,
// `set_iface_ipv4` / `set_mtu` for the session parameters reported by
// MBIM_CID_IP_CONFIGURATION_INFO, and `set_link_metadata` for carrier
// (published at activation, dropped at deactivation) — the same
// registration shape cdc_ncm and r8152 already use, so no new
// net-stack interface is introduced.
//
// NDP signature constants (Linux `include/uapi/linux/usb/cdc.h`,
// verbatim from linux-libc-dev 6.8):
//   USB_CDC_MBIM_NDP16_IPS_SIGN  0x00535049  /* IPS<sessionID> */
//   USB_CDC_MBIM_NDP16_DSS_SIGN  0x00535344  /* DSS<sessionID> */
// The low three bytes spell "IPS" / "DSS" and the fourth wire byte is
// the SessionId. cdc_mbim masks RX signatures with 0x00FFFFFF and
// reads the session from byte 3 (DSS: tci = byte 3 + 256); this
// module does the same. The NCM signatures are SEPARATE constants
// in the same header (NCM0 0x304D434E, NCM1 0x314D434E) and are NOT
// MBIM signatures: an earlier revision of this module used the NCM
// base for IPS, which real MBIM hardware would reject. Corrected
// 2026-10-29 as the #1143 prerequisite; NDP32 variants ("ips" /
// "dss") are out of scope — this module implements NTB-16 only.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_drivers_usb::cdc_ncm::Nth16;
use narf_lib::sync::IrqSafeSpinLock;

use crate::mbim::{ConnectSetParams, IpConfigurationInfo, Ipv4Configuration};
use crate::session::MbimModem;
use crate::{WwanError, WwanPort, WwanPortKind};

// ─── NDP signatures ──────────────────────────────────────────────────────────

/// Low three bytes of the IPS NDP16 signature ("IPS"); the fourth
/// wire byte is the SessionId. Source: Linux
/// `include/uapi/linux/usb/cdc.h` (verbatim):
/// `USB_CDC_MBIM_NDP16_IPS_SIGN 0x00535049 /* IPS<sessionID> */`.
/// An earlier revision used the NCM "NCM" base (0x004D434E) here,
/// reading that constant as the NCM value — wrong: the header
/// defines the NCM signatures separately (NCM0 0x304D434E, NCM1
/// 0x314D434E), and a genuine "IPS<session>" NTB from real MBIM
/// hardware failed this module's check. Corrected 2026-10-29 as
/// the #1143 prerequisite.
pub const NDP16_IPS_SIGN_BASE: u32 = 0x0053_5049;

/// Low three bytes of the DSS NDP16 signature ("DSS"); the fourth
/// wire byte is the SessionId. Same source:
/// `USB_CDC_MBIM_NDP16_DSS_SIGN 0x00535344 /* DSS<sessionID> */`.
pub const NDP16_DSS_SIGN_BASE: u32 = 0x0053_5344;

/// Compose the NDP16 signature for IP session `session`.
pub fn ndp_signature_ips(session: u8) -> u32 {
    NDP16_IPS_SIGN_BASE | ((session as u32) << 24)
}

/// Compose the NDP16 signature for DSS session `session`.
pub fn ndp_signature_dss(session: u8) -> u32 {
    NDP16_DSS_SIGN_BASE | ((session as u32) << 24)
}

/// Which stream an NDP16 belongs to, decoded from its signature.
/// IPS and DSS sessions are separate namespaces sharing one pair of
/// bulk endpoints: Linux's cdc_mbim demux keys IPS on
/// `USB_CDC_MBIM_NDP16_IPS_SIGN` (`tci = c[3]`) and DSS on
/// `USB_CDC_MBIM_NDP16_DSS_SIGN` (`tci = c[3] + 256`), both under
/// the `dwSignature & 0x00ffffff` mask. An NCM "NCM0"/"NCM1"
/// signature matches NEITHER: it is not an MBIM NDP at all, and an
/// NTB signed with it is rejected whole — the earlier revision's
/// decode of NCM0 as IPS session 0x30 was the same NCM/MBIM
/// conflation as the IPS base error, and is gone with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpStream {
    /// IP session `0` (the session id in the signature's byte 3).
    Ips(u8),
    /// DSS session `0` (same byte, a different namespace).
    Dss(u8),
}

impl NdpStream {
    /// The session id carried in the signature's fourth byte.
    pub fn session(self) -> u8 {
        match self {
            NdpStream::Ips(s) | NdpStream::Dss(s) => s,
        }
    }

    /// Whether this is a DSS stream (never an IP netdev's traffic).
    pub fn is_dss(self) -> bool {
        matches!(self, NdpStream::Dss(_))
    }
}

/// Decode an NDP16 signature into its stream, or `None` when it is
/// not an MBIM NDP at all.
pub fn ndp_signature_stream(signature: u32) -> Option<NdpStream> {
    match signature & 0x00FF_FFFF {
        NDP16_IPS_SIGN_BASE => Some(NdpStream::Ips((signature >> 24) as u8)),
        NDP16_DSS_SIGN_BASE => Some(NdpStream::Dss((signature >> 24) as u8)),
        _ => None,
    }
}

// ─── NTB build / parse ───────────────────────────────────────────────────────

/// NDP16 block for a single-datagram NTB: 8-byte header + one entry +
/// the null terminator entry.
const SINGLE_NDP16_LEN: usize = 8 + 4 + 4;

/// Build a single-datagram NTB-16 with an explicit NDP16 signature:
/// NTH16 (offset 0), NDP16 (offset 12), datagram (offset 28).
/// The layout is one of the placements NCM 1.0 §3.2 permits (the
/// wNdpIndex in the NTH locates the NDP; datagrams live wherever
/// their pointer entries say).
fn build_ntb_with_signature(sequence: u16, signature: u32, datagram: &[u8]) -> Vec<u8> {
    let ndp_offset = Nth16::LEN;
    let dgram_offset = ndp_offset + SINGLE_NDP16_LEN;
    let total = dgram_offset + datagram.len();
    let nth = Nth16 {
        signature: narf_drivers_usb::cdc_ncm::NTH16_SIGNATURE,
        header_length: Nth16::LEN as u16,
        sequence,
        block_length: total as u16,
        ndp_index: ndp_offset as u16,
    };
    let mut ntb = Vec::with_capacity(total);
    ntb.extend_from_slice(&nth.encode());
    // NDP16: signature (session-signed), wLength, wNextNdpIndex = 0.
    ntb.extend_from_slice(&signature.to_le_bytes());
    ntb.extend_from_slice(&(SINGLE_NDP16_LEN as u16).to_le_bytes());
    ntb.extend_from_slice(&0u16.to_le_bytes());
    // The single datagram-pointer entry, then the null terminator.
    ntb.extend_from_slice(&(dgram_offset as u16).to_le_bytes());
    ntb.extend_from_slice(&(datagram.len() as u16).to_le_bytes());
    ntb.extend_from_slice(&0u16.to_le_bytes());
    ntb.extend_from_slice(&0u16.to_le_bytes());
    ntb.extend_from_slice(datagram);
    ntb
}

/// Build a single-datagram NTB-16 for IP session `session`.
pub fn build_mbim_ntb(sequence: u16, session: u8, datagram: &[u8]) -> Vec<u8> {
    build_ntb_with_signature(sequence, ndp_signature_ips(session), datagram)
}

/// Build a single-datagram NTB-16 for DSS session `session`.
pub fn build_mbim_dss_ntb(sequence: u16, session: u8, datagram: &[u8]) -> Vec<u8> {
    build_ntb_with_signature(sequence, ndp_signature_dss(session), datagram)
}

/// One datagram recovered from an NTB: the stream it belongs to
/// (from the NDP signature) and the raw datagram bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbimDatagram<'a> {
    /// Stream from the NDP signature (IPS session or DSS session).
    pub stream: NdpStream,
    /// The raw datagram bytes.
    pub data: &'a [u8],
}

/// Parse an NTB received on an MBIM data channel into its datagrams,
/// demultiplexed by NDP signature. Follows cdc_mbim's RX discipline:
/// the NTH must verify; a malformed first datagram entry invalidates
/// the NTB, while a malformed later entry just ends that NDP's walk.
pub fn parse_mbim_ntb(ntb: &[u8]) -> Result<Vec<MbimDatagram<'_>>, WwanError> {
    let nth = Nth16::decode(ntb).map_err(|_| WwanError::MalformedFrame)?;
    let mut out: Vec<MbimDatagram<'_>> = Vec::new();
    let mut ndp_offset = nth.ndp_index as usize;
    let mut hops = 0usize;
    while ndp_offset != 0 {
        hops += 1;
        if hops > 16 || ndp_offset + 8 > ntb.len() {
            return Err(WwanError::MalformedFrame);
        }
        let signature = u32::from_le_bytes([
            ntb[ndp_offset],
            ntb[ndp_offset + 1],
            ntb[ndp_offset + 2],
            ntb[ndp_offset + 3],
        ]);
        let ndp_len = u16::from_le_bytes([ntb[ndp_offset + 4], ntb[ndp_offset + 5]]) as usize;
        let next = u16::from_le_bytes([ntb[ndp_offset + 6], ntb[ndp_offset + 7]]) as usize;
        let stream = ndp_signature_stream(signature).ok_or(WwanError::MalformedFrame)?;
        if ndp_len < 8 + 4 || ndp_len % 4 != 0 || ndp_offset + ndp_len > ntb.len() {
            return Err(WwanError::MalformedFrame);
        }
        let entries = ndp_len / 4 - 2;
        for i in 0..entries {
            let at = ndp_offset + 8 + i * 4;
            let off = u16::from_le_bytes([ntb[at], ntb[at + 1]]) as usize;
            let len = u16::from_le_bytes([ntb[at + 2], ntb[at + 3]]) as usize;
            if off == 0 && len == 0 {
                break; // null terminator entry
            }
            if off + len > ntb.len() || len == 0 {
                if i == 0 && out.is_empty() {
                    return Err(WwanError::MalformedFrame);
                }
                break;
            }
            out.push(MbimDatagram {
                stream,
                data: &ntb[off..off + len],
            });
        }
        ndp_offset = next;
    }
    Ok(out)
}

// ─── Bearer registry ─────────────────────────────────────────────────────────

/// Synchronous NTB emitter for one bearer's data channel. The
/// production implementation bridges to the USB bulk-OUT transfer
/// with `narf_scheduler::block_on` (the same bridge cdc_ncm's send
/// trampoline uses); fixtures record the bytes.
pub trait BearerTxSink: Send + Sync {
    /// Emit one framed NTB on the bearer's data channel.
    fn send_ntb(&self, ntb: &[u8]) -> Result<(), WwanError>;
}

/// Netdev state for one session of a bearer.
struct SessionNet {
    session: u8,
    iface_name: String,
    connected: bool,
    ipv4: Option<Ipv4Configuration>,
}

/// One DSS stream's queued datagrams, backing its registry port.
/// DSS payloads are service-defined byte streams (modem logs, NMEA,
/// ...); the NTB datagram is transport framing only, so RX flattens
/// datagrams into a per-datagram queue the port drains in order.
struct DssStream {
    session: u8,
    queue: Vec<Vec<u8>>,
}

/// One registered bearer (one modem data channel).
struct BearerRecord {
    tx: Arc<dyn BearerTxSink>,
    mac: [u8; 6],
    detached: bool,
    next_sequence: u16,
    sessions: Vec<SessionNet>,
    dss_streams: Vec<DssStream>,
    /// TX frames dropped because the ethertype was not IPv4/IPv6
    /// (ARP and friends cannot cross an MBIM bearer).
    dropped_non_ip_tx: u64,
    /// RX datagrams dropped because their session has no netdev.
    dropped_unknown_session_rx: u64,
    /// RX datagrams dropped because they were not IP-shaped.
    dropped_non_ip_rx: u64,
    /// RX DSS datagrams dropped because no DSS stream is registered
    /// for their session. Never misrouted to an IP netdev.
    dropped_dss_no_consumer_rx: u64,
}

static BEARERS: IrqSafeSpinLock<Vec<BearerRecord>> = IrqSafeSpinLock::new(Vec::new());

/// Register a bearer over `tx` with the (locally administered) MAC
/// its netdevs will carry. Returns the bearer index, which is also
/// the high byte of every session netdev's registration cookie.
pub fn register_bearer(tx: Arc<dyn BearerTxSink>, mac: [u8; 6]) -> usize {
    let mut g = BEARERS.lock();
    g.push(BearerRecord {
        tx,
        mac,
        detached: false,
        next_sequence: 0,
        sessions: Vec::new(),
        dss_streams: Vec::new(),
        dropped_non_ip_tx: 0,
        dropped_unknown_session_rx: 0,
        dropped_non_ip_rx: 0,
        dropped_dss_no_consumer_rx: 0,
    });
    g.len() - 1
}

/// Number of registered bearers.
pub fn bearer_count() -> usize {
    BEARERS.lock().len()
}

/// The netdev name assigned to `(bearer, session)`, if published.
pub fn session_iface_name(bearer: usize, session: u8) -> Option<String> {
    let g = BEARERS.lock();
    g.get(bearer)?
        .sessions
        .iter()
        .find(|s| s.session == session)
        .map(|s| s.iface_name.clone())
}

/// Drop counters for a bearer: (non-IP TX, unknown-session RX,
/// non-IP RX).
pub fn bearer_drop_counters(bearer: usize) -> Option<(u64, u64, u64)> {
    let g = BEARERS.lock();
    g.get(bearer).map(|r| {
        (
            r.dropped_non_ip_tx,
            r.dropped_unknown_session_rx,
            r.dropped_non_ip_rx,
        )
    })
}

/// RX DSS datagrams dropped for want of a registered DSS stream.
pub fn bearer_dss_drop_counters(bearer: usize) -> Option<u64> {
    BEARERS
        .lock()
        .get(bearer)
        .map(|r| r.dropped_dss_no_consumer_rx)
}

/// Whether bearer `bearer` has been marked detached.
pub fn bearer_detached(bearer: usize) -> bool {
    let g = BEARERS.lock();
    g.get(bearer).map(|r| r.detached).unwrap_or(true)
}

/// Mark a bearer detached (device removed): its netdevs lose carrier
/// and its TX trampoline starts failing.
pub fn detach_bearer(bearer: usize) {
    let names: Vec<String> = {
        let mut g = BEARERS.lock();
        let Some(rec) = g.get_mut(bearer) else {
            return;
        };
        rec.detached = true;
        rec.sessions
            .iter_mut()
            .map(|s| {
                s.connected = false;
                s.iface_name.clone()
            })
            .collect()
    };
    for name in names {
        narf_net::iface::set_link_metadata(&name, false, None, None);
    }
}

// ─── Netdev publication ──────────────────────────────────────────────────────

/// Cookie encoding for session netdevs: bearer index in the high
/// bytes, session id in the low byte. The TX trampoline resolves the
/// frame's destination bearer+session from the cookie alone, so a
/// frame submitted on one session's iface can never leave on
/// another's — the property the two-session fixture pins.
fn session_cookie(bearer: usize, session: u8) -> u64 {
    ((bearer as u64) << 8) | session as u64
}

/// Publish the netdev for `(bearer, session)` if not already
/// published, with carrier DOWN: session 0 of bearer N is `wwanN`,
/// other sessions are `wwanNs<session>`. Returns the iface name.
///
/// Publication happens on successful activation (see
/// [`activate_session`]): a refused or never-attempted connect
/// leaves NO netdev at all, so the stack never sees a half-configured
/// interface, while a session that connected and later disconnects
/// keeps its published netdev with carrier down — the same
/// registered-but-down state a cabled NIC reports with no link.
pub fn publish_session_netdev(bearer: usize, session: u8) -> Result<String, WwanError> {
    {
        let g = BEARERS.lock();
        let rec = g.get(bearer).ok_or(WwanError::NotReady)?;
        if rec.detached {
            return Err(WwanError::NotReady);
        }
        if let Some(s) = rec.sessions.iter().find(|s| s.session == session) {
            return Ok(s.iface_name.clone());
        }
    }
    let (mac, name) = {
        let g = BEARERS.lock();
        let rec = g.get(bearer).ok_or(WwanError::NotReady)?;
        let name = if session == 0 {
            alloc::format!("wwan{}", bearer)
        } else {
            alloc::format!("wwan{}s{}", bearer, session)
        };
        (rec.mac, name)
    };
    let assigned = narf_net::iface::register_with_context(
        &name,
        mac,
        session_cookie(bearer, session),
        mbim_send_ctx,
    );
    narf_net::iface::set_link_metadata(&assigned, false, None, None);
    let mut g = BEARERS.lock();
    if let Some(rec) = g.get_mut(bearer) {
        rec.sessions.push(SessionNet {
            session,
            iface_name: assigned.clone(),
            connected: false,
            ipv4: None,
        });
    }
    Ok(assigned)
}

/// A DSS stream surfaced as a registry port. Unlike IP bearers
/// (netdevs), a DSS stream carries a service-defined byte stream
/// with no IP, ethertype, or carrier semantics, so the port
/// registry — not a netdev — is its home. TX wraps one payload in
/// one DSS-signed NTB; RX drains queued datagrams in order,
/// preserving datagram boundaries across partial reads.
struct DssStreamPort {
    bearer: usize,
    session: u8,
    name: String,
}

impl WwanPort for DssStreamPort {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> WwanPortKind {
        WwanPortKind::Dss
    }

    fn send(&self, payload: &[u8]) -> Result<(), WwanError> {
        let (tx, sequence) = {
            let mut g = BEARERS.lock();
            let Some(rec) = g.get_mut(self.bearer) else {
                return Err(WwanError::NotReady);
            };
            if rec.detached || !rec.dss_streams.iter().any(|s| s.session == self.session) {
                return Err(WwanError::NotReady);
            }
            let seq = rec.next_sequence;
            rec.next_sequence = rec.next_sequence.wrapping_add(1);
            (rec.tx.clone(), seq)
        };
        let ntb = build_mbim_dss_ntb(sequence, self.session, payload);
        tx.send_ntb(&ntb)
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, WwanError> {
        let mut g = BEARERS.lock();
        let Some(rec) = g.get_mut(self.bearer) else {
            return Err(WwanError::NotReady);
        };
        let Some(stream) = rec
            .dss_streams
            .iter_mut()
            .find(|s| s.session == self.session)
        else {
            return Err(WwanError::NotReady);
        };
        let Some(front) = stream.queue.first_mut() else {
            return Ok(0);
        };
        let n = front.len().min(buf.len());
        buf[..n].copy_from_slice(&front[..n]);
        if n == front.len() {
            stream.queue.remove(0);
        } else {
            front.drain(..n);
        }
        Ok(n)
    }
}

/// Register a DSS stream port for `(bearer, session)`, idempotent:
/// re-registering returns the existing port name without duplicating
/// the port or the stream. Port name: `wwan{bearer}dss{session}`.
///
/// This is the DATAPATH half of #1143 only. It does not activate
/// anything on the modem: the MBIM_CID_DSS_CONNECT command values
/// (service UUID, CID, payload layout) did not ground from any
/// source reachable for this lane (MBIM 1.0 §10.5.38 text and
/// libmbim's mbim-cid.h/mbim-uuid.h DSS entries were both
/// unobtainable), so no connect command is built here rather than
/// a guessed one. A stream registered here still demultiplexes
/// device-initiated DSS traffic correctly.
pub fn register_dss_stream(bearer: usize, session: u8) -> Result<String, WwanError> {
    let name = alloc::format!("wwan{}dss{}", bearer, session);
    {
        let mut g = BEARERS.lock();
        let rec = g.get_mut(bearer).ok_or(WwanError::NotReady)?;
        if rec.detached {
            return Err(WwanError::NotReady);
        }
        if rec.dss_streams.iter().any(|s| s.session == session) {
            return Ok(name);
        }
        rec.dss_streams.push(DssStream {
            session,
            queue: Vec::new(),
        });
    }
    crate::register_port(Arc::new(DssStreamPort {
        bearer,
        session,
        name: name.clone(),
    }));
    Ok(name)
}

/// The `SendCtxFn` trampoline for every MBIM session netdev. The
/// cookie resolves to exactly one (bearer, session); the Ethernet
/// header the stack put on the frame is validated and stripped, and
/// the raw IP packet is wrapped in a session-signed NTB.
fn mbim_send_ctx(cookie: u64, frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    let bearer = (cookie >> 8) as usize;
    let session = (cookie & 0xFF) as u8;
    // Resolve the sink + sequence under the lock; send outside it
    // (the production sink bridges to async USB with block_on, which
    // must never run under an IrqSafeSpinLock).
    let (tx, sequence) = {
        let mut g = BEARERS.lock();
        let Some(rec) = g.get_mut(bearer) else {
            return Err(());
        };
        if rec.detached {
            return Err(());
        }
        let seq = rec.next_sequence;
        rec.next_sequence = rec.next_sequence.wrapping_add(1);
        (rec.tx.clone(), seq)
    };
    if frame.len() <= 14 {
        count_drop(bearer, DropKind::NonIpTx);
        return Ok(());
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x0800 && ethertype != 0x86DD {
        // ARP and other L2 control traffic cannot cross the bearer
        // (cdc_mbim drops these too, behind IFF_NOARP).
        count_drop(bearer, DropKind::NonIpTx);
        return Ok(());
    }
    let ntb = build_mbim_ntb(sequence, session, &frame[14..]);
    tx.send_ntb(&ntb).map_err(|_| ())
}

#[derive(Copy, Clone)]
enum DropKind {
    NonIpTx,
    UnknownSessionRx,
    NonIpRx,
}

fn count_drop(bearer: usize, kind: DropKind) {
    let mut g = BEARERS.lock();
    if let Some(rec) = g.get_mut(bearer) {
        match kind {
            DropKind::NonIpTx => rec.dropped_non_ip_tx += 1,
            DropKind::UnknownSessionRx => rec.dropped_unknown_session_rx += 1,
            DropKind::NonIpRx => rec.dropped_non_ip_rx += 1,
        }
    }
}

// ─── RX delivery ─────────────────────────────────────────────────────────────

/// Deliver one received NTB to its streams. IPS datagrams go to
/// their session's netdev, each wrapped in a synthesized Ethernet
/// header — destination = the iface MAC, source = zero, ethertype
/// from the IP version nibble — mirroring
/// `cdc_mbim_process_dgram`. DSS datagrams go ONLY to their
/// session's registered DSS stream port, never to an IP netdev,
/// and IPS datagrams never land in a DSS queue: the two namespaces
/// share a wire but no delivery path. Datagrams for sessions with
/// no published netdev (IPS) or no registered stream (DSS) and
/// non-IP payloads are dropped and counted, never cross-delivered.
pub fn deliver_ntb(bearer: usize, ntb: &[u8]) -> Result<(), WwanError> {
    let datagrams = parse_mbim_ntb(ntb)?;
    for dg in datagrams {
        if let NdpStream::Dss(session) = dg.stream {
            let mut g = BEARERS.lock();
            if let Some(rec) = g.get_mut(bearer) {
                if let Some(stream) = rec.dss_streams.iter_mut().find(|s| s.session == session) {
                    stream.queue.push(dg.data.to_vec());
                } else {
                    rec.dropped_dss_no_consumer_rx += 1;
                }
            }
            continue;
        }
        let session = dg.stream.session();
        let Some(name) = session_iface_name(bearer, session) else {
            count_drop(bearer, DropKind::UnknownSessionRx);
            continue;
        };
        let ethertype: u16 = match dg.data.first().map(|b| b & 0xF0) {
            Some(0x40) => 0x0800,
            Some(0x60) => 0x86DD,
            _ => {
                count_drop(bearer, DropKind::NonIpRx);
                continue;
            }
        };
        let mac = {
            let g = BEARERS.lock();
            match g.get(bearer) {
                Some(rec) => rec.mac,
                None => return Err(WwanError::NotReady),
            }
        };
        let mut frame = Vec::with_capacity(14 + dg.data.len());
        frame.extend_from_slice(&mac);
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(dg.data);
        narf_net::iface::on_rx_frame_from(&name, &mut frame);
    }
    Ok(())
}

// ─── Session activation ──────────────────────────────────────────────────────

/// Activation polling bound: a function that reports ACTIVATING is
/// given this many state queries to settle before the attempt fails.
const ACTIVATION_POLLS: usize = 16;

/// Activate `params.session_id` on the modem and bind the result to
/// bearer `bearer`: connect, settle, query the IP configuration,
/// publish the session netdev, stamp its address/gateway/MTU from
/// the MBIM-reported configuration, and raise carrier.
///
/// On any failure — including the modem refusing the connect with a
/// non-success MBIM_STATUS — no netdev is published and no carrier is
/// raised; the error names the modem's status code.
pub async fn activate_session<T: crate::session::MbimTransport>(
    modem: &mut MbimModem<T>,
    bearer: usize,
    params: &ConnectSetParams,
) -> Result<IpConfigurationInfo, WwanError> {
    if params.session_id > u8::MAX as u32 {
        return Err(WwanError::MalformedFrame);
    }
    let session = params.session_id as u8;
    let mut info = modem.connect(params).await?;
    let mut polls = 0usize;
    while info.activation_state == crate::mbim::ACTIVATION_STATE_ACTIVATING
        && polls < ACTIVATION_POLLS
    {
        polls += 1;
        narf_scheduler::yield_now().await;
        info = modem.connect_query(params.session_id).await?;
    }
    if info.activation_state != crate::mbim::ACTIVATION_STATE_ACTIVATED {
        let status = if info.nw_error != 0 {
            info.nw_error
        } else {
            crate::mbim::MBIM_STATUS_FAILURE
        };
        return Err(WwanError::ModemStatus(status));
    }
    let ip = modem.ip_configuration(params.session_id).await?;
    let name = publish_session_netdev(bearer, session)?;
    if let Some(v4) = &ip.ipv4 {
        match v4.gateway {
            Some(gw) => narf_net::iface::set_iface_ipv4(&name, v4.address, gw),
            None => narf_net::iface::set_iface_ipv4_fields(&name, v4.address, [0, 0, 0, 0]),
        }
        if let Some(mtu) = v4.mtu {
            narf_net::iface::set_mtu(&name, mtu);
        }
    }
    narf_net::iface::set_link_metadata(&name, true, None, None);
    let mut g = BEARERS.lock();
    if let Some(rec) = g.get_mut(bearer) {
        if let Some(s) = rec.sessions.iter_mut().find(|s| s.session == session) {
            s.connected = true;
            s.ipv4 = ip.ipv4.clone();
        }
    }
    Ok(ip)
}

/// Deactivate a session: modem disconnect, then drop the netdev's
/// carrier. The iface stays registered (carrier-down), matching the
/// stack's link semantics.
pub async fn deactivate_session<T: crate::session::MbimTransport>(
    modem: &mut MbimModem<T>,
    bearer: usize,
    session: u8,
) -> Result<(), WwanError> {
    modem.disconnect(session as u32).await?;
    if let Some(name) = session_iface_name(bearer, session) {
        narf_net::iface::set_link_metadata(&name, false, None, None);
    }
    let mut g = BEARERS.lock();
    if let Some(rec) = g.get_mut(bearer) {
        if let Some(s) = rec.sessions.iter_mut().find(|s| s.session == session) {
            s.connected = false;
        }
    }
    Ok(())
}

/// Reflect an externally observed connect-state change (an
/// unsolicited CID_CONNECT event) onto the session's netdev carrier.
pub fn note_external_connect_state(bearer: usize, session: u8, activated: bool) {
    if let Some(name) = session_iface_name(bearer, session) {
        narf_net::iface::set_link_metadata(&name, activated, None, None);
    }
    let mut g = BEARERS.lock();
    if let Some(rec) = g.get_mut(bearer) {
        if let Some(s) = rec.sessions.iter_mut().find(|s| s.session == session) {
            s.connected = activated;
        }
    }
}
