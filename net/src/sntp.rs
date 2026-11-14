//! SNTP client — the other half of issue #1764.
//!
//! `net/src/pkt_ntp.rs` is a packet codec only; this module is the client
//! that speaks it: one UDP exchange against an explicit server (RFC 5905
//! §14: an SNTP client has a single server and no dependent clients),
//! validation of the reply, the §8 offset/delay computation, and the feed
//! into the kernel discipline loop (`narf_time::ntp::apply_sample`).
//!
//! ## References (all verified against the source, not trusted from memory)
//!
//! - RFC 5905 — Network Time Protocol Version 4 (June 2010).
//!   §6 NTP timestamp format (64-bit: seconds since the 1900 prime epoch
//!   + 2^-32 fractions). §7.3/§7.5 packet header (48-byte fixed header).
//!     §7.4 kiss-o'-death packets (stratum 0 + 4-byte kiss code; DENY/RSTR
//!     demobilise the association, RATE backs the poll interval off).
//!     §8 on-wire protocol: `theta = 1/2 * [(T2-T1) + (T3-T4)]`,
//!     `delta = (T4-T1) - (T3-T2)`; the bogus check (origin timestamp must
//!     match the transmitted T1), the duplicate check, and the rule that
//!     `delta` is clamped not less than the system precision. §14 SNTP.
//!     §16: UDP/TCP port 123. Appendix A: `STEPT` 0.128 s, `PANICT` 1000 s.
//!     <https://datatracker.ietf.org/doc/html/rfc5905>
//! - Linux `kernel/time/ntp.c` (`second_overflow`, `ntp_update_offset`)
//!   and `include/{linux,uapi/linux}/timex.h` — the discipline model the
//!   sample feeds; see `narf_time::ntp` for the per-constant grounding.
//! - The codec's fields were re-verified against RFC 5905 §7.3/§7.5 while
//!   writing this client; the header layout, the 2_208_988_800 s epoch
//!   offset and the `client_request` builder all check out. One note:
//!   `client_request` sends LI=3 (alarm/unsynchronised), which is the
//!   honest value for a client that has never synced — the reference
//!   implementation reports its own sync state the same way — and servers
//!   ignore the request's LI (they build the reply from their own state,
//!   §14 Fig. 31), so it is kept as-is.
//!
//! ## Transport
//!
//! The exchange uses the in-tree UDP socket API (`udp_bind` with port 0
//! for an ephemeral port, `udp_connect` to the server, `udp_send`,
//! `udp_recv`), not raw frames: `deliver_in` routes replies to the bound
//! socket, so the client needs no RX hook. The wait mirrors the DNS
//! resolver's (`dns::resolve`): `responsive_spin_until` on a deadline,
//! pumping `iface::drain_pump()` each round so NIC RX keeps flowing while
//! the caller spins. The datagram path is independent of the stream
//! recv-EOF fix (#1936 / PR #1941) — datagrams never had EOF semantics.
//!
//! ## Server discovery — explicit, by design
//!
//! The client takes an explicit server IPv4 address. There is no discovery
//! mechanism in-tree to learn one: the DHCP codec defines option 42
//! (`OPT_NTP_SERVERS`, RFC 2132 §3.7) but `dhcp.rs` does not parse it, and
//! no NTP-server config surface exists anywhere else. This module names no
//! default server and hardcodes no pool address — a hardcoded pool would be
//! a silent policy choice, and the wrong one on a private network. Callers
//! that want a name resolved can use [`resolve_server`] (the UDP-only DNS
//! stub, needs configured nameservers); the name itself is the caller's
//! choice. DHCP option-42 parsing is a follow-up (#1955 bullet 2); the
//! periodic poll daemon is [`poll_daemon`] / [`start_poll_daemon`]
//! (issue #1956).
//!
//! ## What this does not do
//!
//! - No authentication (no symmetric-key MAC, no Autokey/NTS): RFC 5905
//!   §9.2 requires no authentication, and the on-wire origin-timestamp
//!   check is the replay defence §8 prescribes. A spoofed reply can still
//!   move the clock by up to the panic threshold — the same exposure every
//!   unauthenticated SNTP client has; NTS is follow-up work.
//! - No multi-server selection or clock filter (RFC 5905 §10/§11):
//!   one server, one association, one sample per round. The poll
//!   daemon adapts that association's interval (§13) and honours
//!   kiss-o'-death (§7.4); selection across servers waits on a
//!   second source existing.
//! - No IPv6: the in-tree UDP socket API is IPv4 (`UdpSocket` /
//!   `SocketAddrV4`); an IPv6 client waits on a v6 socket surface.

extern crate alloc;

use alloc::vec::Vec;

use crate::iface;
use crate::pkt_ntp::{
    client_request, unix_to_ntp, NtpHeader, LI_ALARM_UNSYNCED, MODE_SERVER, NTP_HDR_LEN,
    STRATUM_UNSPECIFIED, STRATUM_UNSYNCED,
};
use crate::udp_sock::{
    udp_bind, udp_close, udp_connect, udp_recv, udp_send, SocketAddrV4, UdpError, UdpOptions,
};
use narf_scheduler::narf_time::Deadline;
use narf_scheduler::{narf_time, responsive_spin_until};

/// UDP port for NTP (RFC 5905 §16, IANA-assigned).
pub const NTP_PORT: u16 = 123;

/// Default reply wait, milliseconds. Mirrors the DNS resolver's
/// `DNS_REPLY_TIMEOUT_MS` (3 s): long enough for a LAN server plus ARP,
/// short enough that a dead server does not wedge a boot path.
pub const DEFAULT_TIMEOUT_MS: u64 = 3_000;

/// The discipline loop's outcome, re-exported so callers of [`sync_once`]
/// do not need to name the time crate's path.
pub type DisciplineOutcome = narf_time::ntp::DisciplineOutcome;

/// Configuration for one SNTP exchange. The server is explicit — see the
/// module docs on discovery.
#[derive(Copy, Clone, Debug)]
pub struct SntpConfig {
    /// NTP server IPv4 address.
    pub server: [u8; 4],
    /// UDP port, normally [`NTP_PORT`].
    pub port: u16,
    /// Reply wait, milliseconds.
    pub timeout_ms: u64,
}

impl SntpConfig {
    /// A config for `server` on the standard port with the default timeout.
    pub fn new(server: [u8; 4]) -> Self {
        Self {
            server,
            port: NTP_PORT,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        }
    }
}

/// One validated SNTP exchange: the §8 offset/delay plus the reply fields
/// the discipline loop's error accounting needs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SntpSample {
    /// The server this sample came from.
    pub server: [u8; 4],
    /// The server's stratum (1..=15; 0 and 16 are rejected before this
    /// struct is built).
    pub stratum: u8,
    /// The server's leap indicator (0..=2; 3 is rejected).
    pub leap: u8,
    /// Clock offset, nanoseconds: server minus local, so a positive value
    /// means the local clock is behind (RFC 5905 §8 `theta`).
    pub offset_ns: i64,
    /// Round-trip delay, nanoseconds (RFC 5905 §8 `delta`, clamped ≥ 0).
    pub delay_ns: i64,
    /// The server's root delay, nanoseconds (16.16 short format).
    pub root_delay_ns: i64,
    /// The server's root dispersion, nanoseconds (16.16 short format).
    pub root_dispersion_ns: i64,
}

/// What can go wrong in an exchange or a resolve.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SntpError {
    /// No ephemeral port was available to bind.
    BindFailed,
    /// No interface or route to the server (or the neighbour is
    /// unreachable).
    NoRoute,
    /// The request datagram could not be sent.
    SendFailed,
    /// No reply within `timeout_ms`.
    Timeout,
    /// The reply was shorter than the 48-byte fixed header.
    ShortPacket,
    /// The reply's version is outside 1..=4 (RFC 5905 §9.2 format check).
    BadVersion(u8),
    /// The reply's mode is not server (4) — e.g. a stray client packet.
    BadMode(u8),
    /// The server is not synchronised (leap alarm, or stratum 16).
    Unsynced,
    /// The reply's origin timestamp does not match the transmitted T1
    /// (RFC 5905 §8 bogus check: duplicate, bogus, or replayed packet).
    BogusOrigin,
    /// A synchronised-looking reply with zero receive/transmit timestamps
    /// carries no time.
    ZeroTimestamps,
    /// Kiss-o'-death (stratum 0): the 4-byte kiss code. DENY/RSTR mean
    /// stop sending to this server; RATE means back off. The client
    /// reports the code and leaves the policy to the caller.
    KissOfDeath([u8; 4]),
    /// DNS resolution failed (no nameserver, no answer, or no A record).
    DnsFailed,
}

// ── Pure helpers (no network; unit-testable) ──────────────────────────

/// NTP 2^-32 fractional seconds → nanoseconds.
fn frac32_to_ns(frac: i128) -> i128 {
    frac * 1_000_000_000 / (1i128 << 32)
}

/// RFC 5905 §8 offset and delay from the four timestamps (all NTP 64-bit
/// stamps; T1 is the client's transmit, T4 the client's receive).
///
/// The parenthesised differences are computed from 64-bit unsigned
/// timestamps and result in signed values (63 bits + sign); `wrapping_sub`
/// plus the cast to `i64` is exactly that arithmetic, and the second-order
/// sums run in `i128` so they cannot overflow. The RFC's caveat applies:
/// the result is unambiguous only if the client clock is within 34 years
/// of the server's (68 in floating point) — a freshly booted kernel with
/// an RTC-anchored wall clock is, an epoch-1970 clock is not, which is
/// why the panic threshold exists on the discipline side.
///
/// The delay is clamped at zero (the RFC clamps it at the system
/// precision; at nanosecond resolution zero is that floor): a negative
/// delay means the two clocks disagree about causality, and the offset is
/// still usable.
pub fn compute_offset_delay(t1: u64, t2: u64, t3: u64, t4: u64) -> (i128, i128) {
    let d1 = t2.wrapping_sub(t1) as i64 as i128; // T2 - T1
    let d2 = t3.wrapping_sub(t4) as i64 as i128; // T3 - T4
    let offset = frac32_to_ns(d1 + d2) / 2;
    let d3 = t4.wrapping_sub(t1) as i64 as i128; // T4 - T1
    let d4 = t3.wrapping_sub(t2) as i64 as i128; // T3 - T2
    let delay = frac32_to_ns(d3 - d4).max(0);
    (offset, delay)
}

/// NTP short fixed-point (16.16) → nanoseconds (RFC 5905 §6).
fn short_to_ns(short: u32) -> i64 {
    let secs = (short >> 16) as i64;
    let frac = (short & 0xFFFF) as i64;
    secs * 1_000_000_000 + frac * 1_000_000_000 / 65_536
}

/// Saturate an `i128` nanosecond value into `i64` (the sample's fields).
fn saturate_ns(v: i128) -> i64 {
    v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

/// Validate a decoded reply against the request's transmit timestamp.
/// The checks are RFC 5905 §9.2's format checks plus §8's bogus check and
/// §7.4's kiss-o'-death rule, in the order a server reply can fail them.
pub fn validate_reply(request_xmt: u64, reply: &NtpHeader) -> Result<(), SntpError> {
    // Format checks: acceptable version number (1-4), server mode.
    if !(1..=4).contains(&reply.version) {
        return Err(SntpError::BadVersion(reply.version));
    }
    if reply.mode != MODE_SERVER {
        return Err(SntpError::BadMode(reply.mode));
    }
    // Stratum 0 is a kiss-o'-death packet: report the code, never time —
    // its timestamps are undefined (§7.4) and must be discarded.
    if reply.stratum == STRATUM_UNSPECIFIED {
        return Err(SntpError::KissOfDeath(reply.reference_id));
    }
    // Stratum 16, or a leap alarm, means the server is not synchronised.
    if reply.stratum >= STRATUM_UNSYNCED || reply.leap_indicator == LI_ALARM_UNSYNCED {
        return Err(SntpError::Unsynced);
    }
    // Bogus check (§8): the origin timestamp must match the T1 we sent.
    if reply.origin_timestamp != request_xmt {
        return Err(SntpError::BogusOrigin);
    }
    if reply.receive_timestamp == 0 || reply.transmit_timestamp == 0 {
        return Err(SntpError::ZeroTimestamps);
    }
    Ok(())
}

// ── Transport ─────────────────────────────────────────────────────────

/// Current wall time as an NTP timestamp (RFC 5905 §6). The wall clock is
/// RTC-anchored at boot, so this is true Unix time once the kernel has
/// booted; before the anchor it is monotonic time since boot, which the
/// §8 differences still handle — only the absolute value is wrong, and
/// the panic threshold on the discipline side refuses a sample that far
/// out.
fn wall_ntp_timestamp() -> u64 {
    let nanos = narf_time::now_wall().as_nanos().max(0) as u128;
    let secs = (nanos / 1_000_000_000) as u64;
    let frac = ((nanos % 1_000_000_000) * (1u128 << 32) / 1_000_000_000) as u32;
    unix_to_ntp(secs, frac)
}

/// One SNTP exchange against `cfg`'s server: send a client request,
/// wait up to `timeout_ms` for the reply, validate it, compute the
/// offset/delay. Returns the sample; disciplining the clock from it is
/// [`discipline_sample`]'s job (or [`sync_once`] for both at once).
pub fn exchange(cfg: &SntpConfig) -> Result<SntpSample, SntpError> {
    let server = SocketAddrV4::new(cfg.server, cfg.port);
    let sock = match udp_bind(SocketAddrV4::new([0, 0, 0, 0], 0), UdpOptions::default()) {
        Ok(s) => s,
        Err(_) => return Err(SntpError::BindFailed),
    };
    udp_connect(&sock, server);

    let t1 = wall_ntp_timestamp();
    let req = client_request(t1);
    if let Err(e) = udp_send(&sock, &req.encode(), None) {
        udp_close(&sock);
        return Err(match e {
            UdpError::NoInterface | UdpError::NetworkUnreachable => SntpError::NoRoute,
            _ => SntpError::SendFailed,
        });
    }

    // Wait for the reply, pumping NIC RX while spinning — the DNS
    // resolver's pattern. T4 is struck the moment the datagram is read,
    // not when the loop exits, so the delay is not padded by the poll.
    let deadline = Deadline::after_ns(cfg.timeout_ms.saturating_mul(1_000_000));
    let mut raw: Option<Vec<u8>> = None;
    let mut t4: u64 = 0;
    let mut buf = [0u8; NTP_HDR_LEN + 64];
    let _ = responsive_spin_until(
        || {
            while iface::drain_pump() {}
            match udp_recv(&sock, &mut buf) {
                Ok((n, _src)) => {
                    t4 = wall_ntp_timestamp();
                    raw = Some(buf[..n].to_vec());
                    true
                }
                Err(_) => false,
            }
        },
        deadline,
    );
    udp_close(&sock);

    let bytes = raw.ok_or(SntpError::Timeout)?;
    let reply = NtpHeader::decode(&bytes).map_err(|_| SntpError::ShortPacket)?;
    validate_reply(t1, &reply)?;
    let (offset, delay) =
        compute_offset_delay(t1, reply.receive_timestamp, reply.transmit_timestamp, t4);
    Ok(SntpSample {
        server: cfg.server,
        stratum: reply.stratum,
        leap: reply.leap_indicator,
        offset_ns: saturate_ns(offset),
        delay_ns: saturate_ns(delay),
        root_delay_ns: short_to_ns(reply.root_delay),
        root_dispersion_ns: short_to_ns(reply.root_dispersion),
    })
}

/// Resolve an NTP server hostname to IPv4 via the in-tree DNS resolver
/// (UDP, needs configured nameservers — DHCP option 6 or resolv.conf).
/// Returns the first A record. The name is the caller's choice; this
/// module names no default server.
pub fn resolve_server(iface_name: &str, name: &str) -> Result<[u8; 4], SntpError> {
    crate::dns::resolve_a(iface_name, name)
        .map_err(|_| SntpError::DnsFailed)?
        .into_iter()
        .next()
        .ok_or(SntpError::DnsFailed)
}

// ── Discipline glue ───────────────────────────────────────────────────

/// Feed a sample to the kernel discipline loop
/// (`narf_time::ntp::apply_sample`) and report what it did. The current
/// realtime seconds come from the wall clock.
pub fn discipline_sample(sample: &SntpSample) -> DisciplineOutcome {
    let now_sec = (narf_time::now_wall().as_nanos() / 1_000_000_000) as i64;
    narf_time::ntp::apply_sample(
        sample.offset_ns,
        sample.delay_ns,
        sample.root_dispersion_ns,
        sample.stratum,
        now_sec,
    )
}

/// One full synchronisation round against an explicit server: exchange +
/// discipline. This is the entry point a boot path or a future poll daemon
/// calls. The poll loop itself (RFC 5905 §13 poll intervals, KoD backoff,
/// multi-server selection) does not exist yet.
pub fn sync_once(cfg: &SntpConfig) -> Result<(SntpSample, DisciplineOutcome), SntpError> {
    let sample = exchange(cfg)?;
    let outcome = discipline_sample(&sample);
    Ok((sample, outcome))
}

// ── Periodic poll daemon (RFC 5905 §13/§14, §7.4; issue #1956) ────────
//
// `sync_once` is one exchange. A working desktop needs a loop that
// re-polls on a schedule and keeps the discipline loop fed, adapting
// the poll interval to the sync quality the way §13 prescribes and
// honouring kiss-o'-death packets the way §7.4 prescribes. That loop
// is here: [`PollState`] is the pure, unit-testable state machine,
// [`poll_round`] is one exchange plus its state transition, and
// [`poll_daemon`] / [`start_poll_daemon`] run it forever (or until
// the server demobilises the association).
//
// Single server only, by design: RFC 5905 §14 says an SNTP client has
// a single server, and §9/§10 clock selection only matters once more
// than one source exists. When a second source arrives (e.g. the
// DHCP-advertised server from #1955 bullet 2), the selection logic
// goes here — one `PollState` per server, best-stratum/lowest-dispersion
// wins — not in the callers.

/// Default minimum poll exponent (RFC 5905 §13 SNTP default minpoll 6:
/// 2^6 = 64 s between polls).
pub const DEFAULT_MIN_POLL: u8 = 6;
/// Default maximum poll exponent (RFC 5905 §13 SNTP default maxpoll 10:
/// 2^10 = 1024 s between polls).
pub const DEFAULT_MAX_POLL: u8 = 10;
/// Kiss code: the server asks the client to reduce its polling rate
/// (RFC 5905 §7.4).
pub const KISS_RATE: [u8; 4] = *b"RATE";
/// Kiss code: the server refuses service; demobilise (RFC 5905 §7.4).
pub const KISS_DENY: [u8; 4] = *b"DENY";
/// Kiss code: access restricted; demobilise (RFC 5905 §7.4).
pub const KISS_RSTR: [u8; 4] = *b"RSTR";

/// How many consecutive successful rounds make the clock "stable"
/// enough to step the poll interval up one exponent (RFC 5905 §13:
/// the interval grows while the clock stays synchronised). Two is
/// the smallest count that distinguishes a fluke from stability
/// without waiting minutes at minpoll.
const STABLE_ROUNDS_TO_STEP_UP: u32 = 2;

/// Poll-interval bounds for one association, as exponents: the
/// interval is 2^`poll` seconds (RFC 5905 §13). Exponents are
/// clamped to 0..=15 so the interval always fits in a `u64` of
/// milliseconds and never exceeds ~9 h.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PollConfig {
    /// Minimum poll exponent (SNTP default 6).
    pub min_poll: u8,
    /// Maximum poll exponent (SNTP default 10).
    pub max_poll: u8,
    /// Poll exponent the first round uses.
    pub initial_poll: u8,
}

impl PollConfig {
    /// The SNTP defaults: minpoll 6, maxpoll 10, start at minpoll.
    pub fn new() -> Self {
        Self {
            min_poll: DEFAULT_MIN_POLL,
            max_poll: DEFAULT_MAX_POLL,
            initial_poll: DEFAULT_MIN_POLL,
        }
    }

    /// Normalise: clamp every exponent to 0..=15, order min ≤ max,
    /// clamp the initial exponent into [min, max].
    fn normalised(self) -> Self {
        let min_poll = self.min_poll.min(15);
        let max_poll = self.max_poll.min(15);
        let (min_poll, max_poll) = if min_poll <= max_poll {
            (min_poll, max_poll)
        } else {
            (max_poll, min_poll)
        };
        Self {
            min_poll,
            max_poll,
            initial_poll: self.initial_poll.clamp(min_poll, max_poll),
        }
    }
}

impl Default for PollConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// What a kiss-o'-death packet tells the poll loop to do (RFC 5905 §7.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KodAction {
    /// RATE: back the poll interval off (one exponent, up to maxpoll).
    BackOff,
    /// DENY/RSTR: demobilise the association — stop polling this server.
    Demobilise,
    /// Any other code: not a §7.4 policy code, treat as a plain failure.
    Failure,
}

/// The poll loop's per-association state: the current poll exponent
/// plus the streaks that drive §13 adaptation. Pure data + pure
/// transitions, so the adaptation is unit-testable without a network.
#[derive(Copy, Clone, Debug)]
pub struct PollState {
    /// Bounds for this association.
    pub config: PollConfig,
    /// Current poll exponent; the interval is 2^`poll` seconds.
    pub poll: u8,
    /// Consecutive successful rounds since the last failure.
    pub consecutive_successes: u32,
    /// Consecutive failed rounds since the last success.
    pub consecutive_failures: u32,
    /// True once a DENY/RSTR kiss demobilised the association; the
    /// daemon stops polling when this is set.
    pub demobilised: bool,
}

impl PollState {
    /// Fresh state at the configured initial poll exponent.
    pub fn new(config: PollConfig) -> Self {
        let config = config.normalised();
        Self {
            config,
            poll: config.initial_poll,
            consecutive_successes: 0,
            consecutive_failures: 0,
            demobilised: false,
        }
    }

    /// Current poll interval, seconds (2^`poll`).
    pub fn poll_interval_secs(&self) -> u64 {
        1u64 << self.poll
    }

    /// Current poll interval, milliseconds (for the sleep between rounds).
    pub fn poll_interval_ms(&self) -> u64 {
        self.poll_interval_secs() * 1_000
    }

    /// A round succeeded (§13): the failure streak resets, and once
    /// the clock has held for [`STABLE_ROUNDS_TO_STEP_UP`] rounds the
    /// interval steps up one exponent, capped at maxpoll.
    pub fn on_success(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        if self.consecutive_successes >= STABLE_ROUNDS_TO_STEP_UP
            && self.poll < self.config.max_poll
        {
            self.poll += 1;
            self.consecutive_successes = 0;
        }
    }

    /// A round failed (§13): the success streak resets and the
    /// interval steps down one exponent, floored at minpoll, so a
    /// flapping server is re-polled sooner rather than later.
    pub fn on_failure(&mut self) {
        self.consecutive_successes = 0;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.poll > self.config.min_poll {
            self.poll -= 1;
        }
    }

    /// A kiss-o'-death packet arrived (§7.4). The detection itself is
    /// [`validate_reply`]'s job — this only applies the policy:
    /// RATE backs the interval off one exponent (up to maxpoll) and
    /// resets the success streak; DENY/RSTR demobilise the
    /// association; any other code is a plain failure.
    pub fn on_kiss_of_death(&mut self, code: [u8; 4]) -> KodAction {
        match code {
            KISS_RATE => {
                self.consecutive_successes = 0;
                if self.poll < self.config.max_poll {
                    self.poll += 1;
                }
                KodAction::BackOff
            }
            KISS_DENY | KISS_RSTR => {
                self.demobilised = true;
                KodAction::Demobilise
            }
            _ => {
                self.on_failure();
                KodAction::Failure
            }
        }
    }
}

/// What one poll round did.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PollRoundOutcome {
    /// The exchange succeeded and the sample was disciplined.
    Synced {
        /// The validated sample from this round.
        sample: SntpSample,
        /// What the discipline loop did with it.
        outcome: DisciplineOutcome,
    },
    /// The exchange failed for a non-KoD reason; the interval was
    /// stepped down (see [`PollState::on_failure`]).
    Failed {
        /// The exchange error.
        error: SntpError,
    },
    /// The server sent a RATE kiss: the interval was backed off.
    BackedOff {
        /// The kiss code (`b"RATE"`).
        code: [u8; 4],
    },
    /// The server sent DENY/RSTR: the association is demobilised and
    /// the daemon stops polling this server.
    Demobilised {
        /// The kiss code (`b"DENY"` or `b"RSTR"`).
        code: [u8; 4],
    },
}

/// One poll round: a [`sync_once`] exchange plus the state transition
/// its outcome prescribes. The daemon calls this; tests drive it
/// directly against the fixture server, so the transitions are
/// exercised end-to-end without waiting out a real poll interval.
pub fn poll_round(cfg: &SntpConfig, state: &mut PollState) -> PollRoundOutcome {
    match sync_once(cfg) {
        Ok((sample, outcome)) => {
            state.on_success();
            PollRoundOutcome::Synced { sample, outcome }
        }
        Err(SntpError::KissOfDeath(code)) => match state.on_kiss_of_death(code) {
            KodAction::BackOff => PollRoundOutcome::BackedOff { code },
            KodAction::Demobilise => PollRoundOutcome::Demobilised { code },
            KodAction::Failure => PollRoundOutcome::Failed {
                error: SntpError::KissOfDeath(code),
            },
        },
        Err(error) => {
            state.on_failure();
            PollRoundOutcome::Failed { error }
        }
    }
}

/// The periodic poll daemon: exchange first (an association polls
/// immediately on mobilisation, §13), then sleep for the current
/// poll interval and repeat, until a DENY/RSTR kiss demobilises the
/// association.
///
/// The round itself is synchronous — `exchange` spins with
/// `drain_pump` for at most `timeout_ms` (default 3 s) — so the
/// executor task is blocked for that long per round; the interval
/// between rounds is ≥ 64 s at minpoll, which dwarfs it, and the
/// spin keeps NIC RX flowing. There is no stop handle yet: the
/// daemon runs until demobilised. A future multi-server daemon can
/// add epoch-based stop (the hwmon monitor's pattern) when a second
/// source exists.
pub async fn poll_daemon(cfg: SntpConfig, poll_cfg: PollConfig) {
    let mut state = PollState::new(poll_cfg);
    loop {
        if matches!(
            poll_round(&cfg, &mut state),
            PollRoundOutcome::Demobilised { .. }
        ) {
            return;
        }
        narf_time::sleep_ms(state.poll_interval_ms()).await;
    }
}

/// Start the periodic poll daemon for one explicit server. Returns
/// the spawned task id. Single server only — see the module docs on
/// multi-server selection and the #1955 bullet-2 follow-up (a
/// DHCP-advertised server as the source when no explicit server is
/// configured).
pub fn start_poll_daemon(cfg: SntpConfig, poll_cfg: PollConfig) -> narf_scheduler::TaskId {
    narf_scheduler::spawn(poll_daemon(cfg, poll_cfg))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // Pure offset/delay vectors (RFC 5905 §8), in 2^-32 units: 1 s == 2^32.
    fn secs(s: u64) -> u64 {
        s << 32
    }

    fn smoke_sntp_compute_offset_delay_known_vectors() -> TestResult {
        // Binary-exact fractions only (halves/quarters are exact in 2^-32;
        // tenths are not — 0.6 s truncates by a unit and would shift the
        // result by 1 ns). T1=100 s, T2=101.5 s, T3=101.75 s, T4=102.25 s:
        // theta = 1/2[(1.5) + (-0.5)] = 0.5 s; delta = 2.25 - 0.25 = 2 s.
        let (off, delay) = compute_offset_delay(
            secs(100),
            secs(101) + secs(1) / 2,
            secs(101) + (secs(1) * 3) / 4,
            secs(102) + secs(1) / 4,
        );
        if off != 500_000_000 {
            return TestResult::Fail("offset should be exactly +500 ms");
        }
        if delay != 2_000_000_000 {
            return TestResult::Fail("delay should be exactly 2 s");
        }
        // Symmetric zero-offset exchange: T2-T1 == T4-T3.
        let (off, delay) = compute_offset_delay(secs(1000), secs(1001), secs(1001), secs(1002));
        if off != 0 {
            return TestResult::Fail("a symmetric exchange should have zero offset");
        }
        if delay != 2_000_000_000 {
            return TestResult::Fail("a symmetric exchange should have 2 s delay");
        }
        // Negative delay (the server's processing exceeds the round trip,
        // so the clocks disagree about causality) clamps to zero; the
        // offset is still usable: theta = 1/2[(1) + (3)] = 2 s.
        let (off, delay) = compute_offset_delay(secs(100), secs(101), secs(105), secs(102));
        if off != 2_000_000_000 {
            return TestResult::Fail("offset should be +2 s even with a negative delay");
        }
        if delay != 0 {
            return TestResult::Fail("a negative delay should clamp to zero");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/sntp", smoke_sntp_compute_offset_delay_known_vectors);

    fn base_reply() -> NtpHeader {
        NtpHeader {
            leap_indicator: 0,
            version: NTP_VERSION_4,
            mode: MODE_SERVER,
            stratum: 2,
            poll: 6,
            precision: -20,
            root_delay: 0x0000_1000,
            root_dispersion: 0x0000_1000,
            reference_id: *b"GPS\0",
            reference_timestamp: secs(1000),
            origin_timestamp: secs(100),
            receive_timestamp: secs(101),
            transmit_timestamp: secs(101),
        }
    }

    fn smoke_sntp_validate_reply_accepts_and_rejects() -> TestResult {
        let t1 = secs(100);
        // The base reply is well-formed.
        if validate_reply(t1, &base_reply()).is_err() {
            return TestResult::Fail("a well-formed server reply should validate");
        }
        // NTPv3 replies are acceptable too (RFC 5905 §9.2: versions 1-4).
        let mut r = base_reply();
        r.version = 3;
        if validate_reply(t1, &r).is_err() {
            return TestResult::Fail("an NTPv3 reply should validate");
        }
        // Version 5 does not exist.
        let mut r = base_reply();
        r.version = 5;
        if validate_reply(t1, &r) != Err(SntpError::BadVersion(5)) {
            return TestResult::Fail("a version-5 reply should be BadVersion");
        }
        // A client-mode packet is not a server reply.
        let mut r = base_reply();
        r.mode = 3;
        if validate_reply(t1, &r) != Err(SntpError::BadMode(3)) {
            return TestResult::Fail("a mode-3 reply should be BadMode");
        }
        // Origin mismatch: bogus / replayed (§8 bogus check).
        let mut r = base_reply();
        r.origin_timestamp = secs(99);
        if validate_reply(t1, &r) != Err(SntpError::BogusOrigin) {
            return TestResult::Fail("an origin mismatch should be BogusOrigin");
        }
        // Leap alarm: the server is not synchronised.
        let mut r = base_reply();
        r.leap_indicator = LI_ALARM_UNSYNCED;
        if validate_reply(t1, &r) != Err(SntpError::Unsynced) {
            return TestResult::Fail("a leap-alarm reply should be Unsynced");
        }
        // Stratum 16: unsynchronised.
        let mut r = base_reply();
        r.stratum = STRATUM_UNSYNCED;
        if validate_reply(t1, &r) != Err(SntpError::Unsynced) {
            return TestResult::Fail("a stratum-16 reply should be Unsynced");
        }
        // Stratum 0: kiss-o'-death — the code comes back, no time.
        let mut r = base_reply();
        r.stratum = STRATUM_UNSPECIFIED;
        r.reference_id = *b"RATE";
        if validate_reply(t1, &r) != Err(SntpError::KissOfDeath(*b"RATE")) {
            return TestResult::Fail("a stratum-0 reply should be KissOfDeath(RATE)");
        }
        // Zero timestamps carry no time.
        let mut r = base_reply();
        r.receive_timestamp = 0;
        r.transmit_timestamp = 0;
        if validate_reply(t1, &r) != Err(SntpError::ZeroTimestamps) {
            return TestResult::Fail("zero timestamps should be ZeroTimestamps");
        }
        // Short packets fail at decode, before validation.
        if NtpHeader::decode(&[0u8; 47]).is_ok() {
            return TestResult::Fail("a 47-byte reply should fail decode");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/sntp", smoke_sntp_validate_reply_accepts_and_rejects);

    fn smoke_sntp_short_format_conversions() -> TestResult {
        // 16.16: 0x00010000 = 1 s; 0x00008000 = 0.5 s.
        if short_to_ns(0x0001_0000) != 1_000_000_000 {
            return TestResult::Fail("short 0x00010000 should be 1 s");
        }
        if short_to_ns(0x0000_8000) != 500_000_000 {
            return TestResult::Fail("short 0x00008000 should be 0.5 s");
        }
        // The wall clock converts to an NTP stamp at/after the Unix epoch.
        let ntp = wall_ntp_timestamp();
        if (ntp >> 32) < crate::pkt_ntp::NTP_UNIX_EPOCH_OFFSET_SECS {
            return TestResult::Fail("wall NTP timestamp should be at/after 1970");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/sntp", smoke_sntp_short_format_conversions);

    // ── Poll daemon: pure state machine (RFC 5905 §13/§14, §7.4) ───────

    fn smoke_sntp_poll_state_adapts_up_and_down() -> TestResult {
        // SNTP defaults: start at minpoll 6 → 64 s.
        let mut st = PollState::new(PollConfig::new());
        if st.poll != 6 || st.poll_interval_secs() != 64 || st.poll_interval_ms() != 64_000 {
            return TestResult::Fail("a fresh poll state should start at minpoll 6 (64 s)");
        }
        // One success is not stable yet: the interval stays.
        st.on_success();
        if st.poll != 6 {
            return TestResult::Fail("one success should not step the poll interval up");
        }
        // A second consecutive success is stable: step up to 7 (128 s).
        st.on_success();
        if st.poll != 7 || st.poll_interval_secs() != 128 {
            return TestResult::Fail("two stable successes should step poll 6 -> 7 (128 s)");
        }
        // A failure steps back down to minpoll.
        st.on_failure();
        if st.poll != 6 {
            return TestResult::Fail("a failure should step poll 7 -> 6");
        }
        // Failures never go below minpoll.
        st.on_failure();
        if st.poll != 6 {
            return TestResult::Fail("failures should never step below minpoll");
        }
        // Successes cap at maxpoll 10 (1024 s).
        let mut st = PollState::new(PollConfig {
            initial_poll: 10,
            ..PollConfig::new()
        });
        st.on_success();
        st.on_success();
        if st.poll != 10 || st.poll_interval_secs() != 1024 {
            return TestResult::Fail("successes should never step above maxpoll 10 (1024 s)");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/sntp", smoke_sntp_poll_state_adapts_up_and_down);

    fn smoke_sntp_poll_kod_transitions() -> TestResult {
        // RATE backs the interval off one exponent, no demobilisation.
        let mut st = PollState::new(PollConfig::new());
        if st.on_kiss_of_death(KISS_RATE) != KodAction::BackOff {
            return TestResult::Fail("a RATE kiss should be BackOff");
        }
        if st.poll != 7 || st.demobilised {
            return TestResult::Fail("RATE should step poll 6 -> 7 without demobilising");
        }
        // RATE at maxpoll stays at maxpoll.
        let mut st = PollState::new(PollConfig {
            initial_poll: 10,
            ..PollConfig::new()
        });
        if st.on_kiss_of_death(KISS_RATE) != KodAction::BackOff {
            return TestResult::Fail("a RATE kiss at maxpoll should still be BackOff");
        }
        if st.poll != 10 || st.demobilised {
            return TestResult::Fail("RATE at maxpoll should stay at 10 without demobilising");
        }
        // DENY demobilises.
        let mut st = PollState::new(PollConfig::new());
        if st.on_kiss_of_death(KISS_DENY) != KodAction::Demobilise {
            return TestResult::Fail("a DENY kiss should be Demobilise");
        }
        if !st.demobilised {
            return TestResult::Fail("DENY should demobilise the association");
        }
        // RSTR demobilises too.
        let mut st = PollState::new(PollConfig::new());
        if st.on_kiss_of_death(KISS_RSTR) != KodAction::Demobilise || !st.demobilised {
            return TestResult::Fail("an RSTR kiss should demobilise the association");
        }
        // An unknown kiss code is a plain failure: interval steps
        // down, no demobilisation.
        let mut st = PollState::new(PollConfig {
            initial_poll: 8,
            ..PollConfig::new()
        });
        if st.on_kiss_of_death(*b"INIT") != KodAction::Failure {
            return TestResult::Fail("an unknown kiss code should be a plain failure");
        }
        if st.demobilised || st.poll != 7 {
            return TestResult::Fail("an unknown kiss should step poll down, not demobilise");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/sntp", smoke_sntp_poll_kod_transitions);

    fn smoke_sntp_poll_config_normalises() -> TestResult {
        // Inverted bounds swap; the initial exponent clamps into range.
        let cfg = PollConfig {
            min_poll: 10,
            max_poll: 6,
            initial_poll: 9,
        }
        .normalised();
        if cfg.min_poll != 6 || cfg.max_poll != 10 || cfg.initial_poll != 9 {
            return TestResult::Fail("inverted poll bounds should swap, initial should clamp in");
        }
        // An initial exponent below min clamps up to min.
        let cfg = PollConfig {
            initial_poll: 2,
            ..PollConfig::new()
        }
        .normalised();
        if cfg.initial_poll != 6 {
            return TestResult::Fail("an initial poll below min should clamp up to minpoll");
        }
        // Exponents above 15 clamp to 15 (the interval must stay a u64).
        let cfg = PollConfig {
            min_poll: 20,
            max_poll: 30,
            initial_poll: 25,
        }
        .normalised();
        if cfg.min_poll != 15 || cfg.max_poll != 15 || cfg.initial_poll != 15 {
            return TestResult::Fail("poll exponents above 15 should clamp to 15");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/sntp", smoke_sntp_poll_config_normalises);

    // ── End-to-end fixture ──────────────────────────────────────────
    //
    // A synthetic NIC captures the client's request frame; the capture
    // function plays the server, building a crafted reply from the
    // request's T1 plus a fixed server offset and injecting it through
    // `udp_sock::deliver` — the real RX dispatch — before `udp_send`
    // returns. The exchange then exercises the real send path (route,
    // ARP, frame build, xmit), the real RX path (deliver → rx queue →
    // udp_recv) and the real discipline feed. Only the server itself is
    // a fixture, which is what "fixture-validated" means here.

    use core::sync::atomic::{AtomicI64, Ordering};
    use narf_lib::sync::IrqSafeSpinLock;

    use crate::arp_cache;
    use crate::pkt::{ETH_HDR_LEN, IPV4_HDR_LEN};
    use crate::pkt_ntp::NTP_VERSION_4;
    use crate::pkt_udp::UDP_HDR_LEN;
    use crate::route;
    use crate::udp_sock::{deliver as udp_deliver, RxIpMeta};

    static FAKE_TX: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());
    /// Server-minus-client clock offset the fixture server applies, ns.
    static FAKE_OFFSET_NS: AtomicI64 = AtomicI64::new(0);
    /// Whether the fixture server answers at all (timeout test clears it).
    static FAKE_ANSWER: IrqSafeSpinLock<bool> = IrqSafeSpinLock::new(true);
    /// Kiss code the fixture server answers with, if any: stratum 0 +
    /// this code instead of a time reply (KoD poll-round tests set it).
    static FAKE_KOD: IrqSafeSpinLock<Option<[u8; 4]>> = IrqSafeSpinLock::new(None);

    const E2E_IFACE: &str = "sntp-e2e";
    const E2E_LOCAL: [u8; 4] = [10, 0, 9, 1];
    const E2E_SERVER: [u8; 4] = [10, 0, 9, 53];
    const E2E_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x09, 0x01];
    const E2E_SERVER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x09, 0x35];

    fn fake_send(frame: &[u8], _meta: crate::TxMeta) -> Result<(), ()> {
        FAKE_TX.lock().push(frame.to_vec());
        if !*FAKE_ANSWER.lock() {
            return Ok(());
        }
        // Parse the outgoing frame: ETH + IPv4 + UDP + NTP request.
        if frame.len() < ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + NTP_HDR_LEN {
            return Ok(());
        }
        let udp_off = ETH_HDR_LEN + IPV4_HDR_LEN;
        let ntp_off = udp_off + UDP_HDR_LEN;
        let client_port = u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]);
        let req = match NtpHeader::decode(&frame[ntp_off..ntp_off + NTP_HDR_LEN]) {
            Ok(h) => h,
            Err(_) => return Ok(()),
        };
        // The fake server's clock is the client's T1 plus the fixed offset.
        let off_units =
            (FAKE_OFFSET_NS.load(Ordering::Relaxed) as i128 * (1i128 << 32) / 1_000_000_000) as u64;
        let t2 = req.transmit_timestamp.wrapping_add(off_units);
        let t3 = t2.wrapping_add((1u64 << 32) / 1_000); // +1 ms server processing
        let mut reply = NtpHeader {
            leap_indicator: 0,
            version: NTP_VERSION_4,
            mode: MODE_SERVER,
            stratum: 2,
            poll: 6,
            precision: -20,
            root_delay: 0x0000_1000,
            root_dispersion: 0x0000_1000,
            reference_id: *b"GPS\0",
            reference_timestamp: t2.wrapping_sub(1 << 32),
            origin_timestamp: req.transmit_timestamp,
            receive_timestamp: t2,
            transmit_timestamp: t3,
        };
        // A configured kiss code replaces the time reply with a
        // stratum-0 KoD packet carrying that code (§7.4).
        if let Some(code) = *FAKE_KOD.lock() {
            reply.stratum = STRATUM_UNSPECIFIED;
            reply.reference_id = code;
        }
        let payload = reply.encode();
        // UDP datagram (header + payload) for the deliver path.
        let udp_len = (UDP_HDR_LEN + payload.len()) as u16;
        let mut seg = alloc::vec![0u8; UDP_HDR_LEN + payload.len()];
        seg[0..2].copy_from_slice(&NTP_PORT.to_be_bytes());
        seg[2..4].copy_from_slice(&client_port.to_be_bytes());
        seg[4..6].copy_from_slice(&udp_len.to_be_bytes());
        seg[UDP_HDR_LEN..].copy_from_slice(&payload);
        udp_deliver(E2E_SERVER, E2E_LOCAL, &seg, RxIpMeta { ttl: 64, tos: 0 });
        Ok(())
    }

    fn e2e_setup(offset_ns: i64, answer: bool) {
        route::__reset_for_test();
        arp_cache::__reset_for_test();
        crate::ifaddr::__reset_for_test();
        crate::bypass::__reset_for_test();
        crate::udp_sock::__reset_pending_udp4_for_test();
        crate::netfilter::__reset_all_for_test();
        FAKE_TX.lock().clear();
        FAKE_OFFSET_NS.store(offset_ns, Ordering::Relaxed);
        *FAKE_ANSWER.lock() = answer;
        *FAKE_KOD.lock() = None;
        narf_time::ntp::__test_reset();
        narf_time::wall::__test_reset();

        iface::register(E2E_IFACE, E2E_MAC, fake_send);
        iface::set_link_state(E2E_IFACE, true);
        iface::set_iface_ipv4_fields(E2E_IFACE, E2E_LOCAL, E2E_LOCAL);
        iface::add_addr(E2E_IFACE, E2E_LOCAL, 24);
        crate::tcp_stack::__arp_insert_legacy(E2E_SERVER, E2E_SERVER_MAC);
        arp_cache::insert(E2E_IFACE, E2E_SERVER, E2E_SERVER_MAC);
        crate::tcp_stack::__arp_insert_legacy(E2E_LOCAL, E2E_MAC);
        arp_cache::insert(E2E_IFACE, E2E_LOCAL, E2E_MAC);
    }

    fn e2e_teardown() {
        narf_time::ntp::__test_reset();
        narf_time::wall::__test_reset();
    }

    /// Make the fixture server answer the next exchanges with a
    /// kiss-o'-death packet carrying `code` (call after `e2e_setup`).
    fn e2e_set_kod(code: [u8; 4]) {
        *FAKE_KOD.lock() = Some(code);
    }

    fn smoke_sntp_exchange_slew_end_to_end() -> TestResult {
        // Server is 50 ms ahead: the sample slews, and one discipline
        // second folds 1/16 of the phase into the wall clock.
        e2e_setup(50_000_000, true);
        let cfg = SntpConfig::new(E2E_SERVER);
        let (sample, outcome) = match sync_once(&cfg) {
            Ok(r) => r,
            Err(_) => {
                e2e_teardown();
                return TestResult::Fail("exchange against the fixture server failed");
            }
        };
        // theta = offset + (1 ms - RTT)/2: 50.0–50.5 ms in this fixture.
        if !(50_000_000..=51_000_000).contains(&sample.offset_ns) {
            e2e_teardown();
            return TestResult::Fail("fixture offset should read ~+50 ms");
        }
        if sample.stratum != 2 || sample.leap != 0 {
            e2e_teardown();
            return TestResult::Fail("fixture sample should carry stratum 2, LI 0");
        }
        if !(0..100_000_000).contains(&sample.delay_ns) {
            e2e_teardown();
            return TestResult::Fail("fixture delay should be small and non-negative");
        }
        if !matches!(outcome, DisciplineOutcome::Slewed(_)) {
            e2e_teardown();
            return TestResult::Fail("a 50 ms sample should slew, not step");
        }
        // The request actually went out on UDP/123.
        let saw_request = FAKE_TX.lock().iter().any(|f| {
            f.len() >= ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + NTP_HDR_LEN
                && f[ETH_HDR_LEN + IPV4_HDR_LEN + 2] == 0
                && f[ETH_HDR_LEN + IPV4_HDR_LEN + 3] == 123
        });
        if !saw_request {
            e2e_teardown();
            return TestResult::Fail("no NTP request frame reached UDP/123");
        }
        // One discipline second: 1/16 of ~50 ms ≈ 3.1 ms into the wall.
        // The range admits a second chunk if a live tick boundary crossed
        // mid-test and the `on_tick` hook ran `tick_second` concurrently
        // (the hook fires once per wall second from IRQ context).
        let before = narf_time::wall_offset_ns();
        narf_time::ntp::tick_second();
        let moved = narf_time::wall_offset_ns() - before;
        e2e_teardown();
        if !(2_900_000..=6_400_000).contains(&moved) {
            return TestResult::Fail("one discipline second should slew ~3.1 ms");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/sntp", smoke_sntp_exchange_slew_end_to_end);

    fn smoke_sntp_exchange_step_end_to_end() -> TestResult {
        // Server is 3600 s ahead: the sample steps the wall clock at once.
        e2e_setup(3_600_000_000_000, true);
        let cfg = SntpConfig::new(E2E_SERVER);
        let before = narf_time::wall_offset_ns();
        let (sample, outcome) = match sync_once(&cfg) {
            Ok(r) => r,
            Err(_) => {
                e2e_teardown();
                return TestResult::Fail("exchange against the fixture server failed");
            }
        };
        let moved = narf_time::wall_offset_ns() - before;
        e2e_teardown();
        if !matches!(outcome, DisciplineOutcome::Stepped(_)) {
            return TestResult::Fail("a 3600 s sample should step, not slew");
        }
        if moved != sample.offset_ns {
            return TestResult::Fail("a step should move the wall by exactly the sample offset");
        }
        if !(3_600_000_000_000..=3_600_001_000_000).contains(&sample.offset_ns) {
            return TestResult::Fail("fixture offset should read ~+3600 s");
        }
        TestResult::Pass
    }
    kernel_test_in!("net/sntp", smoke_sntp_exchange_step_end_to_end);

    fn smoke_sntp_exchange_times_out_without_reply() -> TestResult {
        // The server stays silent: the exchange must fail fast with
        // Timeout, not hang — 100 ms budget, well under the 3 s default.
        e2e_setup(50_000_000, false);
        let cfg = SntpConfig {
            timeout_ms: 100,
            ..SntpConfig::new(E2E_SERVER)
        };
        let r = exchange(&cfg);
        e2e_teardown();
        match r {
            Err(SntpError::Timeout) => TestResult::Pass,
            Err(_) => TestResult::Fail("a silent server should be Timeout, not another error"),
            Ok(_) => TestResult::Fail("a silent server should not produce a sample"),
        }
    }
    kernel_test_in!("net/sntp", smoke_sntp_exchange_times_out_without_reply);

    // ── Poll rounds end-to-end (fixture server + real exchange) ──────

    fn smoke_sntp_poll_round_syncs_and_adapts_end_to_end() -> TestResult {
        // Two good rounds against the fixture server: the first syncs
        // at minpoll, the second is stable enough to step poll up.
        e2e_setup(50_000_000, true);
        let cfg = SntpConfig::new(E2E_SERVER);
        let mut st = PollState::new(PollConfig::new());
        match poll_round(&cfg, &mut st) {
            PollRoundOutcome::Synced { sample, outcome } => {
                if !(50_000_000..=51_000_000).contains(&sample.offset_ns) {
                    e2e_teardown();
                    return TestResult::Fail("first poll round should read ~+50 ms");
                }
                if !matches!(outcome, DisciplineOutcome::Slewed(_)) {
                    e2e_teardown();
                    return TestResult::Fail("a 50 ms round should slew, not step");
                }
            }
            _ => {
                e2e_teardown();
                return TestResult::Fail("first poll round against the fixture server failed");
            }
        }
        if st.poll != 6 {
            e2e_teardown();
            return TestResult::Fail("one good round should stay at minpoll 6");
        }
        match poll_round(&cfg, &mut st) {
            PollRoundOutcome::Synced { .. } => {}
            _ => {
                e2e_teardown();
                return TestResult::Fail("second poll round against the fixture server failed");
            }
        }
        e2e_teardown();
        if st.poll != 7 {
            return TestResult::Fail("two stable rounds should step poll 6 -> 7");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "net/sntp",
        smoke_sntp_poll_round_syncs_and_adapts_end_to_end
    );

    fn smoke_sntp_poll_round_kod_rate_backs_off_end_to_end() -> TestResult {
        // The fixture server answers RATE: the round reports BackedOff
        // and the interval steps up, without demobilising.
        e2e_setup(50_000_000, true);
        e2e_set_kod(KISS_RATE);
        let cfg = SntpConfig::new(E2E_SERVER);
        let mut st = PollState::new(PollConfig::new());
        match poll_round(&cfg, &mut st) {
            PollRoundOutcome::BackedOff { code } => {
                if code != KISS_RATE {
                    e2e_teardown();
                    return TestResult::Fail("a RATE round should report the RATE code");
                }
            }
            _ => {
                e2e_teardown();
                return TestResult::Fail("a RATE reply should back off, not sync or fail");
            }
        }
        e2e_teardown();
        if st.poll != 7 || st.demobilised {
            return TestResult::Fail("RATE should step poll 6 -> 7 without demobilising");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "net/sntp",
        smoke_sntp_poll_round_kod_rate_backs_off_end_to_end
    );

    fn smoke_sntp_poll_round_kod_deny_demobilises_end_to_end() -> TestResult {
        // The fixture server answers DENY: the round reports
        // Demobilised and the association is demobilised.
        e2e_setup(50_000_000, true);
        e2e_set_kod(KISS_DENY);
        let cfg = SntpConfig::new(E2E_SERVER);
        let mut st = PollState::new(PollConfig::new());
        match poll_round(&cfg, &mut st) {
            PollRoundOutcome::Demobilised { code } => {
                if code != KISS_DENY {
                    e2e_teardown();
                    return TestResult::Fail("a DENY round should report the DENY code");
                }
            }
            _ => {
                e2e_teardown();
                return TestResult::Fail("a DENY reply should demobilise, not sync or fail");
            }
        }
        e2e_teardown();
        if !st.demobilised {
            return TestResult::Fail("DENY should demobilise the association");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "net/sntp",
        smoke_sntp_poll_round_kod_deny_demobilises_end_to_end
    );

    fn smoke_sntp_poll_round_timeout_steps_down_end_to_end() -> TestResult {
        // The server stays silent: the round reports Failed(Timeout)
        // and the interval steps down, floored at minpoll.
        e2e_setup(50_000_000, false);
        let cfg = SntpConfig {
            timeout_ms: 100,
            ..SntpConfig::new(E2E_SERVER)
        };
        let mut st = PollState::new(PollConfig {
            initial_poll: 8,
            ..PollConfig::new()
        });
        match poll_round(&cfg, &mut st) {
            PollRoundOutcome::Failed { error } => {
                if error != SntpError::Timeout {
                    e2e_teardown();
                    return TestResult::Fail("a silent server should fail the round with Timeout");
                }
            }
            _ => {
                e2e_teardown();
                return TestResult::Fail("a silent server should fail the round, not sync");
            }
        }
        e2e_teardown();
        if st.poll != 7 {
            return TestResult::Fail("a failed round should step poll 8 -> 7");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "net/sntp",
        smoke_sntp_poll_round_timeout_steps_down_end_to_end
    );
}
