//! H5 — Three-Wire UART HCI transport — clean-room.
//!
//! Reference: **Bluetooth Core Specification, Vol 4 Part D
//! "Three-Wire UART Transport Layer"** (Bluetooth SIG, public).
//! Section numbers below are the current public HTML edition's
//! (§8 link establishment, §6 reliable packets, §12 timing); in
//! Core 5.3 the link-establishment state machine is §5.
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! No GPL Linux source consulted.
//!
//! ## What this is
//!
//! [`H5Transport`] implements [`HciTransport`] over a [`BytePort`]
//! (see [`crate::transport::BytePort`]): the SLIP stream decoder
//! from [`crate::h5`] turns the byte stream back into link frames,
//! and the link-establishment state machine (§8 — Uninitialized →
//! Initialized → Active) plus the reliable-packet machinery (§6 —
//! sequence numbers, sliding window, acknowledgment, retransmission)
//! turn those frames into HCI commands, events and ACL data.
//!
//! Link establishment, per §8:
//!
//! ```text
//!   host                         controller
//!     ── SYNC (0x01 0x7E) ──────────────►
//!     ◄──────── SYNC RESPONSE (0x02 0x7D) ──
//!     ── CONFIG (0x03 0xFC + field) ────►
//!     ◄──── CONFIG RESPONSE (0x04 0x7B + field) ──
//!   ... link Active; SEQ and ACK reset to zero (§8.3) ...
//! ```
//!
//! The host's CONFIG carries its proposal (sliding window, CRC
//! wish, version 0); the controller's CONFIG RESPONSE carries the
//! values both sides shall use (§8.8.1) — window ≤ proposed
//! (§8.8.2), CRC only if the host offered it (§8.8.3), version ≤
//! proposed (§8.8.5). The controller sends CONFIG without a field
//! and the host answers CONFIG RESPONSE without one (§8.8); the
//! transport answers a peer CONFIG that way.
//!
//! There is no RST link message in Part D: a peer reset is signalled
//! by a SYNC arriving while Active (§8.3), which restarts link
//! establishment at Uninitialized.
//!
//! ## Byte port
//!
//! The serial registry publishes descriptors only, so the byte ports
//! ([`Uart8250BytePort`], [`Pl011BytePort`]) rebuild their handles
//! from the registry entry — the same shape `filesystem::console_tty`
//! uses for probed-UART ttys. [`H5Transport::from_uart_info`] builds
//! a transport from a [`UartInfo`], dispatching on the entry's
//! [`UartFamily`]; [`H5Transport::bind_named`] finds one by name,
//! establishes the link, and registers the transport. Boot bind is
//! opt-in only (`bt-h5=<name>`, Stage::Late `bluetooth-h5-boot`
//! initcall in `crate::register_initcalls`): claiming a UART at boot
//! without opt-in would steal it from the `/dev/ttyS<N>` data ttys.
//!
//! ## H4 convergence
//!
//! H4 landed with its own byte-port trait (`H4BytePort`, #821, PR
//! #1557, merged 2026-11-05) instead of the shared [`BytePort`]
//! trait in [`crate::transport`]. This transport therefore keeps its
//! own [`Uart8250BytePort`] over the serial registry. H4 should
//! still adopt the shared trait and the two transports should share
//! one 8250 adapter — that convergence is open, not done here.
//!
//! ## Timing
//!
//! Link-establishment messages are sent periodically, suggested
//! 4/second (§8 footnote [1]) — 250 ms pacing here. Retransmission
//! follows §12.1.2: a reliable packet is resent every 3 × Tmax,
//! where Tmax is the largest emitted packet in bits over the baud
//! rate (§12.1). Pure acknowledgments go out on receipt (§6.5),
//! piggybacked on the next data frame when one is available.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_drivers_serial::pl011::Pl011;
use narf_drivers_serial::registry::{UartFamily, UartInfo};
use narf_drivers_serial::uart_8250::{Uart8250, UartBase};
use narf_lib::sync::IrqSafeSpinLock;
use narf_time::Deadline;

use crate::h5::{self, H5Config, H5Frame, H5Header, H5PacketType, LinkControlKind};
use crate::hci::{Command, Event};
use crate::transport::{BytePort, HciTransport, TransportError};

// ── Tunables ────────────────────────────────────────────────────────

/// Suggested link-establishment period (§8 footnote [1]: 4
/// messages per second).
const LINK_ESTABLISH_INTERVAL_MS: u64 = 250;

/// Budget [`H5Transport::bind_named`] gives link establishment
/// before declining to register the transport.
const ESTABLISH_BUDGET_MS: u64 = 5_000;

/// Proposed sliding window when the caller does not say otherwise.
/// Spec-legal (1..=7, §8.8.2); a local choice, not a spec value.
const DEFAULT_WINDOW: u8 = 4;

/// Default baud for Tmax / retransmission timing when the registry
/// entry names none.
const DEFAULT_BAUD: u32 = 115_200;

/// Largest SLIP body (header + payload + CRC, escaped) the decoder
/// accepts. HCI traffic is small; 8 KiB leaves ample headroom for
/// escaped bytes while bounding the decoder buffer.
const DEFAULT_MAX_FRAME: usize = 8192;

/// Hard ceiling for the decoder cap: the largest legal frame (4095
/// payload octets, §4) fully SLIP-escaped plus CRC is ~8.2 KiB.
const MAX_DECODER_FRAME: usize = 16_384;

/// Largest packet this transport emits, in octets, used to compute
/// Tmax (§12.1). HCI commands are ≤ 258 octets and ACL frames are
/// bounded by the controller's MTU; 1024 covers both with margin.
/// A larger ACL MTU only makes the resend timer fire early, which
/// wastes bandwidth but never breaks the protocol.
const TX_MAX_BYTES: u64 = 1024;

/// Bytes drained from the port per [`H5Transport::drive`] step, so
/// one pump step cannot wedge on a fast peer.
const MAX_DRIVE_BYTES: usize = 512;

/// Largest H5 payload in octets (§4: 0 to 4095).
const MAX_PAYLOAD: usize = 4095;

// ── Link state ──────────────────────────────────────────────────────

/// Link-establishment state machine (§8).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum H5LinkState {
    /// Sending SYNC periodically, waiting for SYNC RESPONSE (§8.1).
    Uninitialized,
    /// Sending CONFIG periodically, waiting for CONFIG RESPONSE
    /// (§8.2).
    Initialized,
    /// Higher-layer packets may flow (§8.3).
    Active,
}

/// Transport configuration. All fields have spec-legal defaults;
/// see [`H5TransportConfig::default`].
#[derive(Copy, Clone, Debug)]
pub struct H5TransportConfig {
    /// Proposed sliding window size, 1..=7 (§8.8.2). Out-of-range
    /// values are clamped to [`DEFAULT_WINDOW`] at construction.
    pub window: u8,
    /// Propose 16-bit CCITT-CRC data integrity checks (§8.8.3).
    pub want_crc: bool,
    /// Baud rate the port is programmed for; drives Tmax (§12.1).
    /// Zero means [`DEFAULT_BAUD`].
    pub baud: u32,
    /// Decoder cap for one SLIP body, in octets. Zero means
    /// [`DEFAULT_MAX_FRAME`]; capped at [`MAX_DECODER_FRAME`].
    pub max_frame: usize,
}

impl Default for H5TransportConfig {
    fn default() -> Self {
        Self {
            window: DEFAULT_WINDOW,
            want_crc: true,
            baud: DEFAULT_BAUD,
            max_frame: DEFAULT_MAX_FRAME,
        }
    }
}

// ── 8250 byte port ──────────────────────────────────────────────────

/// [`BytePort`] over a 8250/16550 UART, rebuilt from a serial
/// registry entry (the `console_tty` shape: the probe already
/// programmed baud/FIFO/MCR, the handle itself is stateless apart
/// from base/shift/clock, so it may be rebuilt freely).
///
/// Writes spin on THRE and reads poll DR, exactly like the
/// probed-UART tty backend. On aarch64 the 8250 accessors are
/// stubs (writes dropped, reads `None`), so this port is inert
/// there; a PL011 byte port is a follow-up.
#[derive(Debug)]
pub struct Uart8250BytePort {
    uart: Uart8250,
    name: &'static str,
}

impl Uart8250BytePort {
    /// Rebuild the handle from a registry entry.
    pub fn from_info(info: &UartInfo) -> Self {
        let uart = match info.base {
            UartBase::Io(port) => Uart8250::new(port, info.irq),
            UartBase::Mmio(addr) => {
                Uart8250::new_mmio(addr, info.irq, info.reg_shift, info.clock_hz)
            }
        };
        Self {
            uart,
            name: info.name,
        }
    }
}

impl BytePort for Uart8250BytePort {
    fn write_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            self.uart.write_byte(b);
        }
    }

    fn read_byte(&self) -> Option<u8> {
        self.uart.read_byte()
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// [`BytePort`] over a PL011 UART, rebuilt from a serial registry
/// entry (the `console_tty` shape: the probe already programmed
/// baud/FIFO, the handle itself is stateless apart from base, so it
/// may be rebuilt freely).
///
/// Writes spin on FR.TXFF and reads poll FR.RXFE + DR, exactly like
/// the console PL011 backend (`console::aarch64`). On aarch64 this
/// is the usable byte port for H5; the 8250 port is inert there.
#[derive(Debug)]
pub struct Pl011BytePort {
    uart: Pl011,
    name: &'static str,
}

impl Pl011BytePort {
    /// Build a byte port over an already-constructed PL011 handle.
    pub fn new(uart: Pl011, name: &'static str) -> Self {
        Self { uart, name }
    }

    /// Rebuild the handle from a registry entry. Returns `None`
    /// when the entry carries no mapped VA, or when a PL011 entry
    /// carries an I/O base (PL011 is MMIO-only) — a corrupt entry
    /// binds nothing rather than poking the wrong address.
    pub fn from_info(info: &UartInfo) -> Option<Self> {
        let UartBase::Mmio(_) = info.base else {
            return None;
        };
        let va = info.virt?;
        // SAFETY: `va` is the probe-installed mapping for this
        // entry (see `UartInfo::virt`); the handle lives only as
        // long as the mapping does (ioremap mappings persist until
        // explicit iounmap, which no probe performs).
        let uart = unsafe { Pl011::from_va(va, info.irq) };
        Some(Self::new(uart, info.name))
    }
}

impl BytePort for Pl011BytePort {
    fn write_bytes(&self, bytes: &[u8]) {
        for &b in bytes {
            self.uart.write_byte(b);
        }
    }

    fn read_byte(&self) -> Option<u8> {
        self.uart.read_byte()
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

/// The `bt-h5=<name>` cmdline opt-in: the UART name to bind at boot,
/// or `None` when the key is absent, bare (`bt-h5` with no value),
/// or empty (`bt-h5=`). Only the first `bt-h5=` token counts
/// (`KernelCmdline::value`). A missing or malformed value binds
/// nothing — the Stage::Late `bluetooth-h5-boot` initcall skips the
/// bind instead of stealing a UART.
pub fn boot_bind_name<'a>(args: narf_boot::args::KernelCmdline<'a>) -> Option<&'a str> {
    let name = args.value("bt-h5")?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

// ── Transport ───────────────────────────────────────────────────────

/// One unacknowledged reliable frame, kept for retransmission
/// (§6.6): the same sequence number is reused on every resend
/// (§4.1), with a fresh acknowledgment number (§6.5).
#[derive(Clone, Debug)]
struct Unacked {
    seq: u8,
    ptype: H5PacketType,
    payload: Vec<u8>,
    resend_at: Deadline,
}

/// Mutable link state, behind one lock. All transport methods take
/// it briefly; the byte port is a separate field, so `drive` can
/// pump bytes while holding this lock without deadlocking.
#[derive(Debug)]
struct H5Inner {
    decoder: h5::Decoder,
    state: H5LinkState,
    /// Our CONFIG proposal (§8.8).
    proposal: H5Config,
    /// Next sequence number for a reliable send (§4.1).
    tx_seq: u8,
    /// Next sequence number expected from the peer (§6.4).
    rx_expected: u8,
    /// Negotiated sliding window (§8.8.2); 0 until Active.
    window: u8,
    /// Negotiated CRC use (§8.8.3); false until Active.
    use_crc: bool,
    unacked: VecDeque<Unacked>,
    /// An acknowledgment is owed (§6.5).
    ack_pending: bool,
    /// The peer announced SLEEP and has not answered WAKEUP yet
    /// (§9.3); sends stall with `Transient` until WOKEN arrives.
    peer_asleep: bool,
    events: VecDeque<Event>,
    acls: VecDeque<Vec<u8>>,
    scos: VecDeque<Vec<u8>>,
    /// Next time a periodic SYNC / CONFIG may go out (§8
    /// footnote [1]).
    next_link_tx: Deadline,
}

impl H5Inner {
    fn new(config: &H5TransportConfig) -> Self {
        Self {
            decoder: h5::Decoder::new(config.max_frame),
            state: H5LinkState::Uninitialized,
            proposal: H5Config {
                window: config.window,
                oof_flow_control: false,
                crc: config.want_crc,
                version: 0,
            },
            tx_seq: 0,
            rx_expected: 0,
            window: 0,
            use_crc: false,
            unacked: VecDeque::new(),
            ack_pending: false,
            peer_asleep: false,
            events: VecDeque::new(),
            acls: VecDeque::new(),
            scos: VecDeque::new(),
            next_link_tx: Deadline::after_ms(0),
        }
    }
}

/// H5 HCI transport over a byte port. See the module docs.
#[derive(Debug)]
pub struct H5Transport {
    port: Arc<dyn BytePort>,
    config: H5TransportConfig,
    inner: IrqSafeSpinLock<H5Inner>,
}

impl H5Transport {
    /// Build a transport over `port`. Out-of-range config values
    /// are clamped to their defaults (see [`H5TransportConfig`]).
    pub fn new(port: Arc<dyn BytePort>, config: H5TransportConfig) -> Self {
        let mut config = config;
        if !(1..=7).contains(&config.window) {
            config.window = DEFAULT_WINDOW;
        }
        if config.baud == 0 {
            config.baud = DEFAULT_BAUD;
        }
        if config.max_frame == 0 {
            config.max_frame = DEFAULT_MAX_FRAME;
        }
        if config.max_frame > MAX_DECODER_FRAME {
            config.max_frame = MAX_DECODER_FRAME;
        }
        Self {
            port,
            inner: IrqSafeSpinLock::new(H5Inner::new(&config)),
            config,
        }
    }

    /// Build the [`BytePort`] for a serial registry entry,
    /// dispatching on the entry's [`UartFamily`]: PL011 entries get
    /// a [`Pl011BytePort`], 8250-family entries a
    /// [`Uart8250BytePort`]. Returns `None` when a PL011 entry
    /// cannot be built (see [`Pl011BytePort::from_info`]).
    pub fn byte_port_for(info: &UartInfo) -> Option<Arc<dyn BytePort>> {
        match info.kind {
            UartFamily::Pl011 => {
                Pl011BytePort::from_info(info).map(|p| Arc::new(p) as Arc<dyn BytePort>)
            }
            UartFamily::Uart8250 => Some(Arc::new(Uart8250BytePort::from_info(info))),
        }
    }

    /// Build a transport from a serial registry entry, rebuilding
    /// the byte-port handle from the descriptor (the `console_tty`
    /// shape). The port kind follows the entry's [`UartFamily`]
    /// (see [`Self::byte_port_for`]). Returns `None` when a PL011
    /// entry cannot be built. The port's programmed baud is used
    /// for Tmax timing.
    pub fn from_uart_info(info: &UartInfo) -> Option<Arc<Self>> {
        let port = Self::byte_port_for(info)?;
        let mut config = H5TransportConfig::default();
        if info.baud != 0 {
            config.baud = info.baud;
        }
        Some(Arc::new(Self::new(port, config)))
    }

    /// Find a registry UART by name, establish the link, and
    /// register the transport so [`crate::controller::bring_up_all`]
    /// picks it up. Returns `None` when no such UART is registered,
    /// when its byte port cannot be built, or when the peer does
    /// not answer link establishment within the budget — in all
    /// cases nothing is registered.
    pub fn bind_named(name: &str) -> Option<Arc<Self>> {
        let info = narf_drivers_serial::registry::uarts()
            .into_iter()
            .find(|u| u.name == name)?;
        let transport = Self::from_uart_info(&info)?;
        if transport
            .establish(Deadline::after_ms(ESTABLISH_BUDGET_MS))
            .is_err()
        {
            return None;
        }
        crate::transport::register(transport.clone());
        Some(transport)
    }

    /// Current link-establishment state (§8).
    pub fn link_state(&self) -> H5LinkState {
        self.inner.lock().state
    }

    /// The byte port's name (e.g. the registry entry's "COM2").
    pub fn port_name(&self) -> &'static str {
        self.port.name()
    }

    /// Negotiated sliding window (§8.8.2); 0 until Active.
    pub fn negotiated_window(&self) -> u8 {
        self.inner.lock().window
    }

    /// Whether the link negotiated CRC data-integrity checks
    /// (§8.8.3); false until Active.
    pub fn negotiated_crc(&self) -> bool {
        self.inner.lock().use_crc
    }

    /// Drive link establishment until Active, or `budget` expires.
    /// Spins via `responsive_spin_until` (ticks the sleep pumps,
    /// like the controller's bring-up wait) and returns
    /// [`TransportError::Timeout`] on expiry.
    pub fn establish(&self, budget: Deadline) -> Result<(), TransportError> {
        let ok = narf_scheduler::responsive_spin_until(
            || {
                self.drive();
                self.link_state() == H5LinkState::Active
            },
            budget,
        );
        if ok {
            Ok(())
        } else {
            Err(TransportError::Timeout)
        }
    }

    /// One pump step: drain available bytes into the SLIP decoder,
    /// handle completed frames, pace link-establishment messages,
    /// retransmit overdue reliable frames, and send a pure ACK when
    /// one is owed. Bounded work per call; returns promptly when
    /// the port is dry. This is the fixture-drivable step and the
    /// work `recv_event` / `recv_acl` do on every call.
    pub fn drive(&self) {
        let mut inner = self.inner.lock();
        drive_locked(&self.port, &self.config, &mut inner);
    }
}

impl HciTransport for H5Transport {
    fn send_command(&self, cmd: &Command) -> Result<(), TransportError> {
        self.drive();
        let mut inner = self.inner.lock();
        send_reliable(
            &self.port,
            &self.config,
            &mut inner,
            H5PacketType::HciCommand,
            &cmd.encode(),
        )
    }

    fn recv_event(&self) -> Result<Option<Event>, TransportError> {
        self.drive();
        Ok(self.inner.lock().events.pop_front())
    }

    fn send_acl(&self, data: &[u8]) -> Result<(), TransportError> {
        self.drive();
        let mut inner = self.inner.lock();
        send_reliable(
            &self.port,
            &self.config,
            &mut inner,
            H5PacketType::AclData,
            data,
        )
    }

    fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError> {
        self.drive();
        Ok(self.inner.lock().acls.pop_front())
    }

    fn send_sco(&self, data: &[u8]) -> Result<(), TransportError> {
        self.drive();
        let mut inner = self.inner.lock();
        send_unreliable(&self.port, &mut inner, H5PacketType::SyncData, data)
    }

    fn recv_sco(&self) -> Result<Option<Vec<u8>>, TransportError> {
        self.drive();
        Ok(self.inner.lock().scos.pop_front())
    }

    fn name(&self) -> &'static str {
        "h5-uart"
    }
}

// ── Drive step ──────────────────────────────────────────────────────

/// Resend interval (§12.1.2): 3 × Tmax, with Tmax the largest
/// emitted packet in bits over the baud rate (§12.1).
fn resend_interval_ms(config: &H5TransportConfig) -> u64 {
    let tmax_ms = TX_MAX_BYTES
        .saturating_mul(10)
        .saturating_mul(1000)
        .checked_div(config.baud as u64)
        .unwrap_or(0)
        .max(1);
    tmax_ms.saturating_mul(3)
}

fn drive_locked(port: &Arc<dyn BytePort>, config: &H5TransportConfig, inner: &mut H5Inner) {
    // 1. Drain available bytes (bounded) into the SLIP decoder.
    let mut budget = MAX_DRIVE_BYTES;
    while budget > 0 {
        let Some(b) = port.read_byte() else {
            break;
        };
        budget -= 1;
        match inner.decoder.feed(b) {
            Ok(Some(frame)) => handle_frame(port, inner, frame),
            Ok(None) => {}
            Err(_) => {
                // Corrupt / oversize frame (§6.1–§6.3): dropped. In
                // Active, still acknowledge with our current expected
                // sequence so the peer retransmits (§6.7 example);
                // in Uninitialized no ACKs are sent (§8.1 footnote
                // [2]).
                if inner.state == H5LinkState::Active {
                    inner.ack_pending = true;
                }
            }
        }
    }

    // 2. Link-establishment pacing (§8 footnote [1]: 4/second).
    match inner.state {
        H5LinkState::Uninitialized => {
            if inner.next_link_tx.expired() {
                send_link_frame(port, inner, LinkControlKind::Sync, &[]);
                inner.next_link_tx = Deadline::after_ms(LINK_ESTABLISH_INTERVAL_MS);
            }
        }
        H5LinkState::Initialized => {
            if inner.next_link_tx.expired() {
                let field = [inner.proposal.encode()];
                send_link_frame(port, inner, LinkControlKind::Config, &field);
                inner.next_link_tx = Deadline::after_ms(LINK_ESTABLISH_INTERVAL_MS);
            }
        }
        H5LinkState::Active => {}
    }

    // 3. Retransmission (§6.6, §12.1.2): resend the oldest unacked
    // frame past its deadline, with a fresh acknowledgment number
    // (§6.5). One resend per step keeps the work bounded.
    if inner.state == H5LinkState::Active && !inner.peer_asleep {
        if let Some(front) = inner.unacked.front() {
            if front.resend_at.expired() {
                let header = H5Header {
                    seq: front.seq,
                    ack: inner.rx_expected,
                    crc_present: inner.use_crc,
                    reliable: true,
                    ptype: front.ptype,
                    payload_len: front.payload.len() as u16,
                };
                let wire = h5::encode_frame(header, &front.payload);
                port.write_bytes(&wire);
                inner.ack_pending = false;
                if let Some(f) = inner.unacked.front_mut() {
                    f.resend_at = Deadline::after_ms(resend_interval_ms(config));
                }
            }
        }
    }

    // 4. Pure ACK when one is owed and nothing sent since (§6.5).
    if inner.ack_pending && inner.state == H5LinkState::Active {
        send_pure_ack(port, inner);
    }
}

// ── Frame handling ──────────────────────────────────────────────────

fn handle_frame(port: &Arc<dyn BytePort>, inner: &mut H5Inner, frame: H5Frame) {
    // Every received frame acknowledges our unacked reliable frames
    // via its ACK number (§4.2, §6.5) — link-control frames
    // included (§7.1 sets their ACK the same as a reliable
    // packet's).
    apply_ack(inner, frame.header.ack);
    match frame.header.ptype {
        H5PacketType::Ack => {}
        H5PacketType::LinkControl => handle_link_control(port, inner, &frame.payload),
        H5PacketType::HciCommand
        | H5PacketType::AclData
        | H5PacketType::HciEvent
        | H5PacketType::IsoData
        | H5PacketType::SyncData => handle_data_frame(inner, &frame),
        H5PacketType::VendorSpecific => {}
    }
}

/// `ack` is the next sequence number the peer expects (§4.2): every
/// queued frame strictly before it (mod 8) is acknowledged. The
/// window is ≤ 7, so a distance larger than the queue means a stale
/// or bogus ack — pop nothing.
fn apply_ack(inner: &mut H5Inner, ack: u8) {
    while let Some(front) = inner.unacked.front() {
        let dist = ack.wrapping_sub(front.seq) & 0x07;
        if dist == 0 || dist as usize > inner.unacked.len() {
            break;
        }
        inner.unacked.pop_front();
    }
}

fn handle_data_frame(inner: &mut H5Inner, frame: &H5Frame) {
    // Before Active, data frames are ignored (§8.1/§8.2).
    if inner.state != H5LinkState::Active {
        return;
    }
    if frame.header.reliable {
        // Out-of-sequence reliable packets are discarded (§6.4);
        // an ACK is still generated so the peer retransmits (§6.7).
        if frame.header.seq != inner.rx_expected {
            inner.ack_pending = true;
            return;
        }
        inner.rx_expected = (inner.rx_expected + 1) % 8;
        inner.ack_pending = true;
    }
    match frame.header.ptype {
        H5PacketType::HciEvent => {
            // HCI Events are always reliable (§4.5); an unreliable
            // event violates the spec — discard it.
            if !frame.header.reliable {
                return;
            }
            if let Some(ev) = Event::decode(&frame.payload) {
                inner.events.push_back(ev);
            }
        }
        H5PacketType::AclData => {
            if !frame.header.reliable {
                return;
            }
            inner.acls.push_back(frame.payload.clone());
        }
        H5PacketType::IsoData => {
            if !frame.header.reliable {
                return;
            }
            inner.scos.push_back(frame.payload.clone());
        }
        H5PacketType::SyncData => {
            // Synchronous (SCO) data: unreliable unless HCI
            // Synchronous Flow Control is enabled (§4.5). No flow
            // control is negotiated here, so accept unreliable
            // only.
            if frame.header.reliable {
                return;
            }
            inner.scos.push_back(frame.payload.clone());
        }
        // The host never receives HCI Commands; the link layer
        // already consumed the sequence number above, so the
        // payload is dropped here.
        H5PacketType::HciCommand => {}
        _ => {}
    }
}

fn handle_link_control(port: &Arc<dyn BytePort>, inner: &mut H5Inner, payload: &[u8]) {
    let Some((kind, field)) = LinkControlKind::from_payload(payload) else {
        // Unrecognised link-control payload. In Uninitialized the
        // pacer re-sends SYNC within 250 ms (§8.1 answers invalid
        // packets with SYNC); elsewhere it is discarded.
        return;
    };
    match kind {
        LinkControlKind::Sync => {
            // Always answer SYNC with SYNC RESPONSE (§8.1/§8.2).
            // In Active the peer has reset: restart establishment
            // at Uninitialized (§8.3).
            if inner.state == H5LinkState::Active {
                reset_link(inner);
            }
            send_link_frame(port, inner, LinkControlKind::SyncResp, &[]);
        }
        LinkControlKind::SyncResp => {
            if inner.state == H5LinkState::Uninitialized {
                inner.state = H5LinkState::Initialized;
                inner.next_link_tx = Deadline::after_ms(0);
            }
        }
        LinkControlKind::Config => {
            // Reply CONFIG RESPONSE without a Configuration Field
            // (§8.8: the host sends CONFIG RESPONSE without one).
            // In Uninitialized only SYNC / SYNC RESPONSE are valid
            // (§8.1).
            if inner.state != H5LinkState::Uninitialized {
                send_link_frame(port, inner, LinkControlKind::ConfigResp, &[]);
            }
        }
        LinkControlKind::ConfigResp => {
            if inner.state != H5LinkState::Initialized {
                // §8.3: in Active a CONFIG RESPONSE is discarded.
                return;
            }
            let Some(&cfg_byte) = field.first() else {
                // No Configuration Field: stay Initialized and keep
                // sending CONFIG.
                return;
            };
            let cfg = H5Config::decode(cfg_byte);
            if !cfg.is_valid() {
                return;
            }
            // The response's values govern both directions (§8.8.1):
            // window ≤ proposed (§8.8.2), CRC only if we offered it
            // (§8.8.3). Version is 0 on both sides (§8.8.5); OOF
            // stays off — we never propose it.
            inner.window = cfg.window.min(inner.proposal.window);
            inner.use_crc = inner.proposal.crc && cfg.crc;
            enter_active(inner);
        }
        LinkControlKind::Wakeup => {
            // It is mandatory to respond to WAKEUP (§9.1).
            send_link_frame(port, inner, LinkControlKind::Woken, &[]);
        }
        LinkControlKind::Woken => {
            inner.peer_asleep = false;
        }
        LinkControlKind::Sleep => {
            // The peer is going to sleep (§9.3): run the Wakeup /
            // Woken sequence before sending any data. Sends stall
            // with `Transient` until WOKEN arrives.
            inner.peer_asleep = true;
            send_link_frame(port, inner, LinkControlKind::Wakeup, &[]);
        }
    }
}

/// Restart link establishment at Uninitialized (§8.3): sequence
/// numbers reset, unacked frames and stale inboxes dropped.
fn reset_link(inner: &mut H5Inner) {
    inner.state = H5LinkState::Uninitialized;
    inner.tx_seq = 0;
    inner.rx_expected = 0;
    inner.window = 0;
    inner.use_crc = false;
    inner.unacked.clear();
    inner.events.clear();
    inner.acls.clear();
    inner.scos.clear();
    inner.ack_pending = false;
    inner.peer_asleep = false;
    inner.next_link_tx = Deadline::after_ms(0);
}

/// Enter Active (§8.3): the first packet sent shall have its SEQ
/// and ACK numbers set to zero.
fn enter_active(inner: &mut H5Inner) {
    inner.state = H5LinkState::Active;
    inner.tx_seq = 0;
    inner.rx_expected = 0;
    inner.unacked.clear();
    inner.ack_pending = false;
    inner.peer_asleep = false;
}

// ── Frame sending ───────────────────────────────────────────────────

/// Send a link-control frame: unreliable, no CRC (§8: the four
/// establishment messages are sent with DIC = 0; WAKEUP / WOKEN /
/// SLEEP follow the same shape), carrying the current ACK (§7.1),
/// which clears any pending acknowledgment.
fn send_link_frame(
    port: &Arc<dyn BytePort>,
    inner: &mut H5Inner,
    kind: LinkControlKind,
    field: &[u8],
) {
    let mut payload = Vec::with_capacity(2 + field.len());
    payload.extend_from_slice(&kind.prefix());
    payload.extend_from_slice(field);
    let header = H5Header {
        seq: 0,
        ack: inner.rx_expected,
        crc_present: false,
        reliable: false,
        ptype: H5PacketType::LinkControl,
        payload_len: payload.len() as u16,
    };
    port.write_bytes(&h5::encode_frame(header, &payload));
    inner.ack_pending = false;
}

/// Send a pure acknowledgment (§6.5): an Unreliable packet, Packet
/// Type 0, Payload Length 0, Sequence Number 0, with the ACK number
/// set to the next sequence number expected (§4.2). DIC follows the
/// negotiated link setting (§7.1: unreliable headers set DIC the
/// same as reliable ones).
fn send_pure_ack(port: &Arc<dyn BytePort>, inner: &mut H5Inner) {
    let header = H5Header {
        seq: 0,
        ack: inner.rx_expected,
        crc_present: inner.use_crc,
        reliable: false,
        ptype: H5PacketType::Ack,
        payload_len: 0,
    };
    port.write_bytes(&h5::encode_frame(header, &[]));
    inner.ack_pending = false;
}

/// Send a reliable HCI frame (§4.5: Command / ACL / Event / ISO are
/// always reliable). Assigns the next sequence number (§4.1) and
/// queues the frame for retransmission until acknowledged (§6.6).
/// Returns `Transient` when the link is not Active, the peer is
/// asleep, the payload exceeds the 4095-octet cap (§4), or the
/// sliding window is full — the caller retries after the link
/// advances or an ACK arrives.
fn send_reliable(
    port: &Arc<dyn BytePort>,
    config: &H5TransportConfig,
    inner: &mut H5Inner,
    ptype: H5PacketType,
    payload: &[u8],
) -> Result<(), TransportError> {
    if inner.state != H5LinkState::Active {
        return Err(TransportError::Transient);
    }
    if inner.peer_asleep {
        return Err(TransportError::Transient);
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(TransportError::Transient);
    }
    if inner.unacked.len() >= inner.window as usize {
        return Err(TransportError::Transient);
    }
    let seq = inner.tx_seq;
    inner.tx_seq = (inner.tx_seq + 1) % 8;
    let header = H5Header {
        seq,
        ack: inner.rx_expected,
        crc_present: inner.use_crc,
        reliable: true,
        ptype,
        payload_len: payload.len() as u16,
    };
    port.write_bytes(&h5::encode_frame(header, payload));
    inner.ack_pending = false;
    inner.unacked.push_back(Unacked {
        seq,
        ptype,
        payload: payload.to_vec(),
        resend_at: Deadline::after_ms(resend_interval_ms(config)),
    });
    Ok(())
}

/// Send an unreliable data frame (SCO over Synchronous Data, §4.5).
/// No sequence number, no retransmission (§7.1).
fn send_unreliable(
    port: &Arc<dyn BytePort>,
    inner: &mut H5Inner,
    ptype: H5PacketType,
    payload: &[u8],
) -> Result<(), TransportError> {
    if inner.state != H5LinkState::Active {
        return Err(TransportError::Transient);
    }
    if inner.peer_asleep {
        return Err(TransportError::Transient);
    }
    if payload.len() > MAX_PAYLOAD {
        return Err(TransportError::Transient);
    }
    let header = H5Header {
        seq: 0,
        ack: inner.rx_expected,
        crc_present: inner.use_crc,
        reliable: false,
        ptype,
        payload_len: payload.len() as u16,
    };
    port.write_bytes(&h5::encode_frame(header, payload));
    inner.ack_pending = false;
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::controller::{BringupPhase, Controller};
    use crate::opcode as op;

    // ── Scripted peer ───────────────────────────────────────────────
    //
    // A minimal H5 controller behind `BytePort`: it decodes the
    // transport's frames and answers them the way a real controller
    // would — SYNC RESPONSE to SYNC, CONFIG RESPONSE to CONFIG,
    // Command Complete to HCI commands — with its own sequence
    // numbers, so the exchange exercises both directions of the
    // reliable-packet machinery. `drop_first_command` models a lost
    // frame: the first reliable command is swallowed whole (no ACK,
    // no reply), so the transport must retransmit it (§6.6).

    #[derive(Debug)]
    struct PeerInner {
        decoder: h5::Decoder,
        /// Bytes the transport can read.
        rx: VecDeque<u8>,
        /// Frames received, in order — assertions read this.
        received: Vec<H5Frame>,
        tx_seq: u8,
        rx_expected: u8,
        dropped_once: bool,
    }

    #[derive(Debug)]
    struct ScriptedPeer {
        inner: IrqSafeSpinLock<PeerInner>,
        config_answer: H5Config,
        drop_first_command: bool,
    }

    impl ScriptedPeer {
        fn new(config_answer: H5Config, drop_first_command: bool) -> Arc<Self> {
            Arc::new(Self {
                inner: IrqSafeSpinLock::new(PeerInner {
                    decoder: h5::Decoder::new(8192),
                    rx: VecDeque::new(),
                    received: Vec::new(),
                    tx_seq: 0,
                    rx_expected: 0,
                    dropped_once: false,
                }),
                config_answer,
                drop_first_command,
            })
        }

        /// Inject a link-control frame into the transport's receive
        /// path. A SYNC resets the peer's sequence numbers, modelling
        /// a controller that just reset (§8.3).
        fn inject_link(&self, kind: LinkControlKind) {
            let mut inner = self.inner.lock();
            if kind == LinkControlKind::Sync {
                inner.tx_seq = 0;
                inner.rx_expected = 0;
            }
            queue_link(&mut inner, kind, &[]);
        }

        /// Inject a reliable HCI Event frame with an explicit
        /// sequence number (for out-of-sequence tests).
        fn inject_reliable_event(&self, seq: u8, payload: &[u8]) {
            let crc = self.config_answer.crc;
            let mut inner = self.inner.lock();
            let header = H5Header {
                seq,
                ack: inner.rx_expected,
                crc_present: crc,
                reliable: true,
                ptype: H5PacketType::HciEvent,
                payload_len: payload.len() as u16,
            };
            inner.rx.extend(h5::encode_frame(header, payload));
        }

        fn received_frames(&self) -> Vec<H5Frame> {
            self.inner.lock().received.clone()
        }

        /// How many reliable HCI Command frames with `seq` arrived.
        fn receipts_of_seq(&self, seq: u8) -> usize {
            self.inner
                .lock()
                .received
                .iter()
                .filter(|f| {
                    f.header.ptype == H5PacketType::HciCommand
                        && f.header.reliable
                        && f.header.seq == seq
                })
                .count()
        }

        /// True when the peer received a link-control frame of this
        /// kind.
        fn saw_link(&self, want: LinkControlKind) -> bool {
            self.inner.lock().received.iter().any(|f| {
                f.header.ptype == H5PacketType::LinkControl
                    && LinkControlKind::from_payload(&f.payload)
                        .map(|(k, _)| k == want)
                        .unwrap_or(false)
            })
        }

        /// True when the peer received a pure ACK carrying `ack`.
        fn saw_pure_ack(&self, ack: u8) -> bool {
            self.inner
                .lock()
                .received
                .iter()
                .any(|f| f.header.ptype == H5PacketType::Ack && f.header.ack == ack)
        }
    }

    impl BytePort for ScriptedPeer {
        fn write_bytes(&self, bytes: &[u8]) {
            let cfg = self.config_answer;
            let drop_first = self.drop_first_command;
            let mut inner = self.inner.lock();
            let frames = match inner.decoder.drain(bytes) {
                Ok(f) => f,
                Err(_) => return,
            };
            for frame in frames {
                inner.received.push(frame.clone());
                react_peer(cfg, drop_first, &mut inner, &frame);
            }
        }

        fn read_byte(&self) -> Option<u8> {
            self.inner.lock().rx.pop_front()
        }

        fn name(&self) -> &'static str {
            "scripted-peer"
        }
    }

    fn queue_frame(inner: &mut PeerInner, header: H5Header, payload: &[u8]) {
        inner.rx.extend(h5::encode_frame(header, payload));
    }

    fn queue_link(inner: &mut PeerInner, kind: LinkControlKind, field: &[u8]) {
        let mut payload = Vec::with_capacity(2 + field.len());
        payload.extend_from_slice(&kind.prefix());
        payload.extend_from_slice(field);
        let header = H5Header {
            seq: 0,
            ack: inner.rx_expected,
            crc_present: false,
            reliable: false,
            ptype: H5PacketType::LinkControl,
            payload_len: payload.len() as u16,
        };
        queue_frame(inner, header, &payload);
    }

    fn queue_pure_ack(inner: &mut PeerInner, ack: u8, crc: bool) {
        let header = H5Header {
            seq: 0,
            ack,
            crc_present: crc,
            reliable: false,
            ptype: H5PacketType::Ack,
            payload_len: 0,
        };
        queue_frame(inner, header, &[]);
    }

    fn queue_reliable(inner: &mut PeerInner, ptype: H5PacketType, payload: &[u8], crc: bool) {
        let header = H5Header {
            seq: inner.tx_seq,
            ack: inner.rx_expected,
            crc_present: crc,
            reliable: true,
            ptype,
            payload_len: payload.len() as u16,
        };
        inner.tx_seq = (inner.tx_seq + 1) % 8;
        queue_frame(inner, header, payload);
    }

    /// Command Complete event payload for `opcode`, mirroring the
    /// return parameters the e2e bring-up test expects (Vol 4 Part E
    /// §7): Num_HCI_Command_Packets, opcode, status, return params.
    fn command_complete_payload(cmd: &[u8]) -> Vec<u8> {
        let opcode = if cmd.len() >= 2 {
            u16::from_le_bytes([cmd[0], cmd[1]])
        } else {
            0
        };
        let ret: &[u8] = match opcode {
            op::HCI_READ_LOCAL_VERSION => &[0x0C, 0x10, 0x00, 0x0C, 0xAA, 0xBB, 0x01, 0x00],
            op::HCI_READ_BD_ADDR => &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            op::HCI_READ_BUFFER_SIZE => &[0x40, 0x01, 0x40, 0x10, 0x00, 0x08, 0x00],
            _ => &[],
        };
        let mut params = Vec::with_capacity(4 + ret.len());
        params.push(0x01);
        params.extend_from_slice(&opcode.to_le_bytes());
        params.push(0x00);
        params.extend_from_slice(ret);
        let mut out = Vec::with_capacity(2 + params.len());
        out.push(0x0E);
        out.push(params.len() as u8);
        out.extend_from_slice(&params);
        out
    }

    fn react_peer(cfg: H5Config, drop_first: bool, inner: &mut PeerInner, frame: &H5Frame) {
        match frame.header.ptype {
            H5PacketType::LinkControl => {
                let Some((kind, _)) = LinkControlKind::from_payload(&frame.payload) else {
                    return;
                };
                match kind {
                    LinkControlKind::Sync => queue_link(inner, LinkControlKind::SyncResp, &[]),
                    LinkControlKind::Config => {
                        let field = [cfg.encode()];
                        queue_link(inner, LinkControlKind::ConfigResp, &field);
                    }
                    LinkControlKind::Wakeup => queue_link(inner, LinkControlKind::Woken, &[]),
                    _ => {}
                }
            }
            H5PacketType::HciCommand => {
                if !frame.header.reliable {
                    return;
                }
                // Loss model: swallow the first reliable command
                // whole, as if it never arrived.
                if drop_first && !inner.dropped_once {
                    inner.dropped_once = true;
                    return;
                }
                if frame.header.seq != inner.rx_expected {
                    queue_pure_ack(inner, inner.rx_expected, cfg.crc);
                    return;
                }
                inner.rx_expected = (inner.rx_expected + 1) % 8;
                let payload = command_complete_payload(&frame.payload);
                queue_reliable(inner, H5PacketType::HciEvent, &payload, cfg.crc);
            }
            H5PacketType::AclData => {
                if frame.header.reliable {
                    if frame.header.seq == inner.rx_expected {
                        inner.rx_expected = (inner.rx_expected + 1) % 8;
                    }
                    queue_pure_ack(inner, inner.rx_expected, cfg.crc);
                }
            }
            _ => {}
        }
    }

    // ── Fixtures ────────────────────────────────────────────────────

    fn peer_transport(
        answer: H5Config,
        drop_first: bool,
        config: H5TransportConfig,
    ) -> (Arc<ScriptedPeer>, Arc<H5Transport>) {
        let peer = ScriptedPeer::new(answer, drop_first);
        let transport = Arc::new(H5Transport::new(peer.clone(), config));
        (peer, transport)
    }

    fn default_answer() -> H5Config {
        H5Config {
            window: 3,
            oof_flow_control: false,
            crc: true,
            version: 0,
        }
    }

    /// Drive until `cond` holds or the budget expires.
    fn drive_until(
        transport: &H5Transport,
        budget_ms: u64,
        mut cond: impl FnMut() -> bool,
    ) -> bool {
        let deadline = Deadline::after_ms(budget_ms);
        loop {
            transport.drive();
            if cond() {
                return true;
            }
            if deadline.expired() {
                return cond();
            }
        }
    }

    fn smoke_h5_link_establishment_then_command_event() -> TestResult {
        let (peer, transport) = peer_transport(
            default_answer(),
            false,
            H5TransportConfig {
                baud: 921_600,
                ..Default::default()
            },
        );
        // SYNC → SYNC-RESP → CONFIG → CONFIG-RESP (§8).
        if transport.establish(Deadline::after_ms(2_000)).is_err() {
            return TestResult::Fail("link did not establish");
        }
        if transport.link_state() != H5LinkState::Active {
            return TestResult::Fail("not Active after establish");
        }
        if transport.negotiated_window() != 3 || !transport.negotiated_crc() {
            return TestResult::Fail("config not adopted from CONFIG RESPONSE");
        }
        // HCI_RESET command → Command Complete event.
        let cmd = Command::with_params(op::HCI_RESET, &[]);
        if transport.send_command(&cmd).is_err() {
            return TestResult::Fail("send_command failed");
        }
        let mut event = None;
        let got = drive_until(&transport, 2_000, || match transport.recv_event() {
            Ok(Some(e)) => {
                event = Some(e);
                true
            }
            _ => false,
        });
        if !got {
            return TestResult::Fail("no Command Complete event");
        }
        let event = event.expect("guarded by drive_until");
        if event.code != 0x0E || event.params.len() < 4 {
            return TestResult::Fail("event is not Command Complete");
        }
        if u16::from_le_bytes([event.params[1], event.params[2]]) != op::HCI_RESET {
            return TestResult::Fail("event opcode != HCI_RESET");
        }
        // The peer saw exactly one SYNC, one CONFIG, one command.
        let frames = peer.received_frames();
        let count = |ptype: H5PacketType| frames.iter().filter(|f| f.header.ptype == ptype).count();
        if count(H5PacketType::LinkControl) != 2 {
            return TestResult::Fail("expected one SYNC + one CONFIG");
        }
        if peer.receipts_of_seq(0) != 1 {
            return TestResult::Fail("expected exactly one command at seq 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h5-transport",
        smoke_h5_link_establishment_then_command_event
    );

    fn smoke_h5_retransmits_unacked_command() -> TestResult {
        let (peer, transport) = peer_transport(
            default_answer(),
            true,
            H5TransportConfig {
                baud: 921_600,
                ..Default::default()
            },
        );
        if transport.establish(Deadline::after_ms(2_000)).is_err() {
            return TestResult::Fail("link did not establish");
        }
        let cmd = Command::with_params(op::HCI_RESET, &[]);
        if transport.send_command(&cmd).is_err() {
            return TestResult::Fail("send_command failed");
        }
        // The peer swallowed the first copy (§6.6 loss); the
        // transport must resend it (same seq 0) within the budget.
        // Resend interval at 921600 baud is ~33 ms (§12.1.2).
        let resent = drive_until(&transport, 2_000, || peer.receipts_of_seq(0) >= 2);
        if !resent {
            return TestResult::Fail("unacked command was not retransmitted");
        }
        // The peer answered the retransmission; the event arrives.
        let mut event = None;
        let got = drive_until(&transport, 2_000, || match transport.recv_event() {
            Ok(Some(e)) => {
                event = Some(e);
                true
            }
            _ => false,
        });
        if !got || event.is_none() {
            return TestResult::Fail("no event after retransmission");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h5-transport",
        smoke_h5_retransmits_unacked_command
    );

    fn smoke_h5_peer_sync_in_active_restarts_link() -> TestResult {
        let (peer, transport) = peer_transport(
            default_answer(),
            false,
            H5TransportConfig {
                baud: 921_600,
                ..Default::default()
            },
        );
        if transport.establish(Deadline::after_ms(2_000)).is_err() {
            return TestResult::Fail("link did not establish");
        }
        // The peer resets: SYNC while Active (§8.3).
        peer.inject_link(LinkControlKind::Sync);
        transport.drive();
        if transport.link_state() != H5LinkState::Uninitialized {
            return TestResult::Fail("SYNC in Active must restart the link");
        }
        if !peer.saw_link(LinkControlKind::SyncResp) {
            return TestResult::Fail("SYNC must be answered with SYNC RESPONSE");
        }
        // Stale inboxes are dropped and the link re-establishes.
        if transport.establish(Deadline::after_ms(2_000)).is_err() {
            return TestResult::Fail("link did not re-establish");
        }
        if transport.link_state() != H5LinkState::Active {
            return TestResult::Fail("not Active after re-establishment");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h5-transport",
        smoke_h5_peer_sync_in_active_restarts_link
    );

    fn smoke_h5_wakeup_gets_woken_reply() -> TestResult {
        let (peer, transport) = peer_transport(
            default_answer(),
            false,
            H5TransportConfig {
                baud: 921_600,
                ..Default::default()
            },
        );
        if transport.establish(Deadline::after_ms(2_000)).is_err() {
            return TestResult::Fail("link did not establish");
        }
        peer.inject_link(LinkControlKind::Wakeup);
        transport.drive();
        if !peer.saw_link(LinkControlKind::Woken) {
            return TestResult::Fail("WAKEUP must be answered with WOKEN (§9.1)");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5-transport", smoke_h5_wakeup_gets_woken_reply);

    fn smoke_h5_out_of_sequence_event_discarded() -> TestResult {
        let (peer, transport) = peer_transport(
            default_answer(),
            false,
            H5TransportConfig {
                baud: 921_600,
                ..Default::default()
            },
        );
        if transport.establish(Deadline::after_ms(2_000)).is_err() {
            return TestResult::Fail("link did not establish");
        }
        // A reliable event with seq 5 when 0 is expected (§6.4).
        let payload = alloc::vec![0x0Eu8, 0x04, 0x01, 0x03, 0x0C, 0x00];
        peer.inject_reliable_event(5, &payload);
        transport.drive();
        match transport.recv_event() {
            Ok(None) => {}
            _ => return TestResult::Fail("out-of-sequence event must be discarded"),
        }
        // The transport still acknowledges with its expected seq so
        // the peer retransmits (§6.7).
        if !peer.saw_pure_ack(0) {
            return TestResult::Fail("no pure ACK with expected seq 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h5-transport",
        smoke_h5_out_of_sequence_event_discarded
    );

    fn smoke_h5_config_response_clamped_to_proposal() -> TestResult {
        // The peer answers window 7 + CRC while we propose window 4
        // and no CRC: the response governs (§8.8.1) but never above
        // the proposal (§8.8.2) and never a CRC we did not offer
        // (§8.8.3).
        let answer = H5Config {
            window: 7,
            oof_flow_control: false,
            crc: true,
            version: 0,
        };
        let (_peer, transport) = peer_transport(
            answer,
            false,
            H5TransportConfig {
                window: 4,
                want_crc: false,
                baud: 921_600,
                ..Default::default()
            },
        );
        if transport.establish(Deadline::after_ms(2_000)).is_err() {
            return TestResult::Fail("link did not establish");
        }
        if transport.negotiated_window() != 4 {
            return TestResult::Fail("window must clamp to the proposal");
        }
        if transport.negotiated_crc() {
            return TestResult::Fail("CRC must stay off when not proposed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h5-transport",
        smoke_h5_config_response_clamped_to_proposal
    );

    fn smoke_h5_full_controller_bring_up() -> TestResult {
        // The endpoint bar end to end: link establishment, then the
        // mandatory HCI bring-up (Reset → Read Local Version → Read
        // BD_ADDR → Read Buffer Size → Set Event Mask, Vol 4 Part E
        // §3) over the H5 transport against the scripted peer.
        let (peer, transport) = peer_transport(
            default_answer(),
            false,
            H5TransportConfig {
                baud: 921_600,
                ..Default::default()
            },
        );
        if transport.establish(Deadline::after_ms(2_000)).is_err() {
            return TestResult::Fail("link did not establish");
        }
        let controller = Controller::new(transport);
        let cap = crate::bootstrap_bluetooth_authority();
        let info = match controller.bring_up(&cap) {
            Ok(i) => i,
            Err(_) => return TestResult::Fail("bring_up failed over H5"),
        };
        if controller.phase() != BringupPhase::Ready {
            return TestResult::Fail("phase != Ready");
        }
        if info.bd_addr != [0x11, 0x22, 0x33, 0x44, 0x55, 0x66] {
            return TestResult::Fail("BD_ADDR not captured");
        }
        // Five commands, each at the next sequence number.
        let frames = peer.received_frames();
        let cmds: Vec<u8> = frames
            .iter()
            .filter(|f| f.header.ptype == H5PacketType::HciCommand)
            .map(|f| f.header.seq)
            .collect();
        if cmds != alloc::vec![0u8, 1, 2, 3, 4] {
            return TestResult::Fail("bring-up commands not sequenced 0..4");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5-transport", smoke_h5_full_controller_bring_up);

    fn smoke_h5_from_uart_info_rebuilds_handle() -> TestResult {
        // Pure construction: rebuilds the 8250 handle from the
        // registry entry (the console_tty shape) without touching
        // hardware — no bytes are ever written or read here.
        use narf_drivers_serial::registry::UartFamily;
        use narf_drivers_serial::uart_8250::{COM2_BASE, UART_CLOCK_HZ};
        let info = UartInfo {
            base: UartBase::Io(COM2_BASE),
            reg_shift: 0,
            clock_hz: UART_CLOCK_HZ,
            irq: Some(3),
            name: "COM2",
            baud: 115_200,
            kind: UartFamily::Uart8250,
            virt: None,
        };
        let Some(transport) = H5Transport::from_uart_info(&info) else {
            return TestResult::Fail("from_uart_info must build a transport for an 8250 entry");
        };
        if transport.port_name() != "COM2" {
            return TestResult::Fail("port name must come from the registry entry");
        }
        if transport.link_state() != H5LinkState::Uninitialized {
            return TestResult::Fail("new transport must start Uninitialized");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h5-transport",
        smoke_h5_from_uart_info_rebuilds_handle
    );

    /// `bt-h5=<name>` parsing is the `KernelCmdline::value` rule, no
    /// more: the first token wins, a bare flag has no value, and an
    /// empty value binds nothing.
    fn smoke_h5_boot_bind_name_parses() -> TestResult {
        use narf_boot::args::KernelCmdline;
        if boot_bind_name(KernelCmdline::new("bt-h5=COM2")) != Some("COM2") {
            return TestResult::Fail("bt-h5=COM2 must parse to COM2");
        }
        if boot_bind_name(KernelCmdline::new("quiet bt-h5=PL011-0 debug")) != Some("PL011-0") {
            return TestResult::Fail("bt-h5=PL011-0 must parse among other tokens");
        }
        if boot_bind_name(KernelCmdline::new("bt-h5=COM2 bt-h5=COM1")) != Some("COM2") {
            return TestResult::Fail("first bt-h5= token must win");
        }
        if boot_bind_name(KernelCmdline::new("")).is_some() {
            return TestResult::Fail("absent bt-h5= must bind nothing");
        }
        if boot_bind_name(KernelCmdline::new("bt-h5")).is_some() {
            return TestResult::Fail("bare bt-h5 flag must bind nothing");
        }
        if boot_bind_name(KernelCmdline::new("bt-h5=")).is_some() {
            return TestResult::Fail("empty bt-h5= value must bind nothing");
        }
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h5-transport", smoke_h5_boot_bind_name_parses);

    /// `bind_named` for a name no registry entry carries binds
    /// nothing and touches no hardware (the lookup fails before any
    /// port is built).
    fn smoke_h5_bind_named_missing_name_binds_nothing() -> TestResult {
        if H5Transport::bind_named("no-such-uart-h5-test").is_some() {
            return TestResult::Fail("bind_named must return None for an unregistered name");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h5-transport",
        smoke_h5_bind_named_missing_name_binds_nothing
    );

    /// Fake PL011 register block, leaked-box shape as
    /// `drivers/serial::pl011`'s fixture: 16 u32 cells covering DR
    /// (cell 0) and FR (cell 6, offset 0x18).
    fn make_fake_pl011_regs() -> &'static mut [u32; 16] {
        let buf: alloc::boxed::Box<[u32; 16]> = alloc::boxed::Box::new([0u32; 16]);
        alloc::boxed::Box::leak(buf)
    }

    /// `Pl011BytePort` read/write against the fake UART: FR.RXFE
    /// gates reads, DR carries the byte, and writes are 32-bit
    /// stores into DR — the PL011 semantics, not the 8250's.
    fn smoke_h5_pl011_byte_port_read_write() -> TestResult {
        use narf_drivers_serial::pl011::{Pl011, FR_RXFE, REG_DR, REG_FR};
        let regs = make_fake_pl011_regs();
        let base = regs.as_mut_ptr();
        // SAFETY: `regs` is a live RAM-backed register block for the
        // duration of this test; every index below is in-bounds
        // (< 16). Manipulation uses volatile ops so the port's
        // volatile accesses observe them in order.
        unsafe {
            core::ptr::write_volatile(base.add(REG_FR / 4), FR_RXFE);
            let uart = Pl011::from_va(base as u64, None);
            let port = Pl011BytePort::new(uart, "test-PL011-0");
            if port.read_byte().is_some() {
                return TestResult::Fail("read_byte must be None when FR.RXFE is set");
            }
            core::ptr::write_volatile(base.add(REG_DR / 4), 0x42);
            core::ptr::write_volatile(base.add(REG_FR / 4), 0);
            match port.read_byte() {
                Some(0x42) => {}
                _ => {
                    return TestResult::Fail(
                        "read_byte must return the DR byte when RXFE is clear",
                    );
                }
            }
            core::ptr::write_volatile(base.add(REG_DR / 4), 0xDEAD_BEEF);
            core::ptr::write_volatile(base.add(REG_FR / 4), 0);
            port.write_bytes(&[0x41]);
            if core::ptr::read_volatile(base.add(REG_DR / 4)) != 0x41 {
                return TestResult::Fail("write_bytes must store the byte in DR (32-bit write)");
            }
            if port.name() != "test-PL011-0" {
                return TestResult::Fail("port name must come from the constructor");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h5-transport",
        smoke_h5_pl011_byte_port_read_write
    );

    /// `byte_port_for` dispatches on the registry entry's kind: a
    /// PL011 entry yields a port that talks PL011 registers. The
    /// proof is behavioral, not a type assertion — if the dispatch
    /// had built an 8250 port instead, the write would be an 8-bit
    /// store (DR keeps its high bytes) on x86_64, or dropped
    /// entirely on aarch64 (inert 8250 accessors), and reads would
    /// follow LSR instead of FR.
    fn smoke_h5_byte_port_for_dispatches_on_family() -> TestResult {
        use narf_drivers_serial::pl011::{FR_RXFE, REG_DR, REG_FR};
        use narf_drivers_serial::registry::UartFamily;
        use narf_memory::PhysAddr;
        let regs = make_fake_pl011_regs();
        let base = regs.as_mut_ptr();
        let info = UartInfo {
            base: UartBase::Mmio(PhysAddr::new(0x0900_0000)),
            reg_shift: 0,
            clock_hz: 24_000_000,
            irq: None,
            name: "test-PL011-0",
            baud: 115_200,
            kind: UartFamily::Pl011,
            virt: Some(base as u64),
        };
        let Some(port) = H5Transport::byte_port_for(&info) else {
            return TestResult::Fail("byte_port_for must build a port for a PL011 entry");
        };
        if port.name() != "test-PL011-0" {
            return TestResult::Fail("port name must come from the registry entry");
        }
        // SAFETY: `regs` is a live RAM-backed register block for the
        // duration of this test; every index below is in-bounds.
        unsafe {
            core::ptr::write_volatile(base.add(REG_DR / 4), 0xDEAD_BEEF);
            core::ptr::write_volatile(base.add(REG_FR / 4), 0);
            port.write_bytes(&[0x41]);
            if core::ptr::read_volatile(base.add(REG_DR / 4)) != 0x41 {
                return TestResult::Fail(
                    "PL011 port write must be a 32-bit DR store (wrong port kind?)",
                );
            }
            core::ptr::write_volatile(base.add(REG_DR / 4), 0x55);
            core::ptr::write_volatile(base.add(REG_FR / 4), 0);
            if port.read_byte() != Some(0x55) {
                return TestResult::Fail("PL011 port read must return the DR byte");
            }
            core::ptr::write_volatile(base.add(REG_FR / 4), FR_RXFE);
            if port.read_byte().is_some() {
                return TestResult::Fail("PL011 port read must be None when FR.RXFE is set");
            }
        }
        // A PL011 entry with no mapped VA builds nothing rather
        // than poking the physical base.
        let unmapped = UartInfo { virt: None, ..info };
        if H5Transport::byte_port_for(&unmapped).is_some() {
            return TestResult::Fail("byte_port_for must return None for an unmapped PL011 entry");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h5-transport",
        smoke_h5_byte_port_for_dispatches_on_family
    );
}
