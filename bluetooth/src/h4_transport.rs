//! H4 UART transport — `HciTransport` over a serial byte port.
//!
//! Reference: **Bluetooth Core Specification 5.3, Vol 4 Part A
//! "UART Transport Layer"** (Bluetooth SIG, public).
//!   <https://www.bluetooth.com/specifications/specs/core-specification/>
//!
//! H4 is the single-stream UART transport: every HCI packet is
//! prefixed by a one-byte packet-type indicator (Vol 4 Part A §2:
//! `0x01` Command, `0x02` ACL Data, `0x03` Synchronous Data, `0x04`
//! Event, `0x05` ISO Data) and shares the wire body of the USB
//! transport (Vol 4 Part E §5.4). The framing codec lives in
//! [`crate::h4`]; this module is the binding that turns a UART byte
//! stream into an [`HciTransport`].
//!
//! No GPL Linux source consulted.
//!
//! ## Binding
//!
//! The transport talks to the serial layer through the
//! [`H4BytePort`] trait — `write_byte` / `read_byte` — which mirrors
//! the two byte methods [`Uart8250`] already exposes, and is
//! implemented for it here. `H4Transport` holds a `&'static dyn
//! H4BytePort`, the same `&'static` handle shape the console/TTY
//! layer builds from a serial-registry entry
//! (`filesystem::console_tty` rebuilds its `&'static Uart8250` the
//! same way).
//!
//! [`bind_uart`] is the boot-time entry point: it looks a port up
//! by name in the `narf-drivers-serial` registry, programs it to
//! the requested baud, and registers the transport, so the existing
//! Stage::Late `bluetooth-bringup` initcall picks it up through
//! `controller::bring_up_all` — no new initcall, no pump change.
//! There is deliberately **no auto-bind**: nothing in the tree says
//! which UART (if any) has a Bluetooth module attached, and a blind
//! bind would emit HCI Reset bytes on an arbitrary COM port and
//! stall bring-up on the 5.5 s command-complete timeout. Discovery
//! (device-tree `bluetooth` child node / ACPI _DSD) is a follow-up.
//! Binding the console port (`COM1`, the early console) is refused.
//!
//! ## Receive path
//!
//! H4 carries every packet type on one RX byte stream, while
//! `HciTransport` asks for them through separate `recv_event` /
//! `recv_acl` / `recv_sco` calls. `pump_rx` drains the UART FIFO
//! into the [`h4::Decoder`] and sorts completed frames into
//! per-type queues, so a call for one type never loses a frame of
//! another type. Inbound Command frames (a host never expects them)
//! and ISO frames (the trait has no ISO channel, same as the USB
//! transport) are dropped. A malformed indicator increments
//! `frame_errors` and the decoder resynchronises on the next byte.
//!
//! `recv_*` are non-blocking, like the USB transport's: they return
//! `Ok(None)` when no frame of the requested type is queued. The
//! pump and `Controller::bring_up`'s `wait_for_event` poll on that
//! contract.
//!
//! ## Scope
//!
//! H4 only. H5 (Vol 4 Part D) does not fall out of this binding:
//! its codec is wire-format only and the retransmission / link
//! establishment state machine (SYNC / CONFIG / RST, sliding
//! window) is still missing — see `h5.rs` scope note. That is a
//! follow-up issue, not part of this transport.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_drivers_serial::registry;
use narf_drivers_serial::uart_8250::{Uart8250, UartBase};
use narf_lib::sync::IrqSafeSpinLock;

use crate::h4::{self, Decoder, H4Frame};
use crate::hci::{Command, Event, PacketType, ScoData};
use crate::transport::{HciTransport, TransportError};

/// Default H4 baud: 115200, the rate the serial layer already
/// programs probed legacy UARTs to, and the power-on rate of most
/// UART-attached controllers.
pub const DEFAULT_H4_BAUD: u32 = 115_200;

/// Largest H4 frame body the decoder accepts. An ACL body tops out
/// at the controller's buffer size (typically 1021 bytes); 4096
/// leaves headroom for ISO-sized loads while bounding a runaway
/// controller's RAM grab.
pub const MAX_H4_FRAME_BYTES: usize = 4096;

/// Bytes drained from the UART FIFO per `recv_*` call. Bounds one
/// pump step against a flooding controller; the pump re-polls on
/// its next step.
const MAX_RX_BYTES_PER_CALL: usize = 1024;

/// A serial byte port: the two operations an H4 transport needs.
///
/// Mirrors [`Uart8250::write_byte`] / [`Uart8250::read_byte`]
/// exactly — no new UART API is invented here. A fake port
/// implementing this trait is what the fixtures drive.
pub trait H4BytePort: Send + Sync + core::fmt::Debug {
    /// Write one byte, blocking until the transmitter accepts it
    /// (the 8250 spins on THRE, as the console does).
    fn write_byte(&self, b: u8);
    /// Read one received byte if available, else `None` (polled;
    /// never blocks).
    fn read_byte(&self) -> Option<u8>;
}

impl H4BytePort for Uart8250 {
    fn write_byte(&self, b: u8) {
        Uart8250::write_byte(self, b);
    }

    fn read_byte(&self) -> Option<u8> {
        Uart8250::read_byte(self)
    }
}

/// H4 transport: an [`HciTransport`] over a [`H4BytePort`].
#[derive(Debug)]
pub struct H4Transport {
    port: &'static dyn H4BytePort,
    decoder: IrqSafeSpinLock<Decoder>,
    events: IrqSafeSpinLock<VecDeque<Event>>,
    acl: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    sco: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    frame_errors: AtomicU64,
    name: &'static str,
}

impl H4Transport {
    /// Build a transport over `port`. `name` is the diagnostic
    /// name `HciTransport::name` returns — for a bound UART this is
    /// the registry port name (e.g. `"COM2"`).
    pub fn new(port: &'static dyn H4BytePort, name: &'static str) -> Self {
        Self {
            port,
            decoder: IrqSafeSpinLock::new(Decoder::new(MAX_H4_FRAME_BYTES)),
            events: IrqSafeSpinLock::new(VecDeque::new()),
            acl: IrqSafeSpinLock::new(VecDeque::new()),
            sco: IrqSafeSpinLock::new(VecDeque::new()),
            frame_errors: AtomicU64::new(0),
            name,
        }
    }

    /// Frames rejected by the H4 decoder since construction (bad
    /// indicator or over-budget body). Monotonic; a rising count
    /// with no events means the peer is speaking another protocol
    /// (or the wrong baud).
    pub fn frame_errors(&self) -> u64 {
        self.frame_errors.load(Ordering::Relaxed)
    }

    /// Drain the UART FIFO into the decoder and sort completed
    /// frames into the per-type queues. Non-blocking: returns when
    /// the FIFO is empty or the per-call byte budget is spent.
    fn pump_rx(&self) {
        let mut events = Vec::new();
        let mut acl = Vec::new();
        let mut sco = Vec::new();
        let mut errors = 0u64;
        {
            let mut decoder = self.decoder.lock();
            let mut budget = MAX_RX_BYTES_PER_CALL;
            while budget > 0 {
                let Some(b) = self.port.read_byte() else {
                    break;
                };
                budget -= 1;
                match decoder.feed(b) {
                    Ok(Some(H4Frame::Event(e))) => events.push(e),
                    Ok(Some(H4Frame::AclData(a))) => acl.push(a.encode()),
                    Ok(Some(H4Frame::SyncData {
                        handle,
                        pb_flag,
                        data,
                    })) => sco.push(
                        ScoData {
                            handle,
                            packet_status: pb_flag,
                            data,
                        }
                        .encode(),
                    ),
                    // Inbound Command: a host never expects one.
                    // ISO Data: `HciTransport` has no ISO channel
                    // (same as the USB transport). Both dropped.
                    Ok(Some(_)) => {}
                    Ok(None) => {}
                    // `feed` resets the decoder on error, so the
                    // next byte is treated as a fresh indicator.
                    Err(_) => errors += 1,
                }
            }
        }
        if !events.is_empty() {
            self.events.lock().extend(events);
        }
        if !acl.is_empty() {
            self.acl.lock().extend(acl);
        }
        if !sco.is_empty() {
            self.sco.lock().extend(sco);
        }
        if errors > 0 {
            self.frame_errors.fetch_add(errors, Ordering::Relaxed);
        }
    }

    fn write_frame(&self, indicator: PacketType, body: &[u8]) {
        self.port.write_byte(indicator as u8);
        for &b in body {
            self.port.write_byte(b);
        }
    }
}

impl HciTransport for H4Transport {
    fn send_command(&self, cmd: &Command) -> Result<(), TransportError> {
        // `h4::encode_command` is indicator + body; write it out
        // byte by byte (the port blocks on THRE per byte).
        for b in h4::encode_command(cmd) {
            self.port.write_byte(b);
        }
        Ok(())
    }

    fn recv_event(&self) -> Result<Option<Event>, TransportError> {
        self.pump_rx();
        Ok(self.events.lock().pop_front())
    }

    fn send_acl(&self, data: &[u8]) -> Result<(), TransportError> {
        // `data` is already the ACL body (handle+flags, length,
        // payload) as the pump hands it out; H4 only adds the 0x02
        // indicator (Vol 4 Part A §2).
        self.write_frame(PacketType::AclData, data);
        Ok(())
    }

    fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError> {
        self.pump_rx();
        Ok(self.acl.lock().pop_front())
    }

    fn send_sco(&self, data: &[u8]) -> Result<(), TransportError> {
        // Same shape as ACL: 0x03 indicator + SCO body (Vol 4
        // Part A §2, Vol 4 Part E §5.4.3).
        self.write_frame(PacketType::SyncData, data);
        Ok(())
    }

    fn recv_sco(&self) -> Result<Option<Vec<u8>>, TransportError> {
        self.pump_rx();
        Ok(self.sco.lock().pop_front())
    }

    fn name(&self) -> &'static str {
        self.name
    }
}

// ── Binding ─────────────────────────────────────────────────────────

/// Why [`bind_uart`] refused to bind a UART.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BindError {
    /// No UART by that name in the serial registry.
    NotFound,
    /// `COM1` is the early console; a Bluetooth transport must not
    /// share the console port.
    ConsolePort,
    /// The UART did not detect / program at the requested baud
    /// (absent port, or no 8250 byte I/O on this arch).
    InitFailed,
    /// A transport with this name is already registered; two
    /// transports sharing one UART would split its byte stream
    /// between two decoders.
    AlreadyBound,
}

/// Bind a registered UART to a new H4 transport.
///
/// Looks `name` up in the `narf-drivers-serial` registry, rebuilds
/// the `&'static Uart8250` handle from the registry entry (the same
/// construction the console/TTY layer uses), programs it to `baud`
/// with [`Uart8250::init`], and registers the transport — the
/// Stage::Late `bluetooth-bringup` initcall then brings it up
/// through `controller::bring_up_all` like any other transport.
///
/// Returns the transport so callers can inspect it (e.g.
/// [`H4Transport::frame_errors`]); registration in the global
/// transport registry has already happened on success.
pub fn bind_uart(name: &str, baud: u32) -> Result<Arc<H4Transport>, BindError> {
    if name == "COM1" {
        return Err(BindError::ConsolePort);
    }
    if crate::transport::transports()
        .iter()
        .any(|t| t.name() == name)
    {
        return Err(BindError::AlreadyBound);
    }
    let entry = registry::uarts()
        .into_iter()
        .find(|e| e.name == name)
        .ok_or(BindError::NotFound)?;
    let mut uart = match entry.base {
        UartBase::Io(port) => Uart8250::new(port, entry.irq),
        UartBase::Mmio(addr) => {
            Uart8250::new_mmio(addr, entry.irq, entry.reg_shift, entry.clock_hz)
        }
    };
    uart.clock_hz = entry.clock_hz;
    let uart: &'static mut Uart8250 = alloc::boxed::Box::leak(alloc::boxed::Box::new(uart));
    if !uart.init(baud) {
        return Err(BindError::InitFailed);
    }
    let transport = Arc::new(H4Transport::new(uart, entry.name));
    crate::transport::register(transport.clone() as Arc<dyn HciTransport>);
    let _ = writeln!(
        narf_console::Writer,
        "  bluetooth: H4 on {} @ {} baud",
        entry.name,
        baud
    );
    Ok(transport)
}

// ── Fixtures ────────────────────────────────────────────────────────
//
// The fake below plays the controller half of the conversation:
// it answers every complete H4 Command frame with a scripted
// Command Complete event (Vol 4 Part E §7.7.14) whose bytes are
// built literally in the test — no production encoder is involved
// in the expected bytes, so a wrong codec cannot agree with its
// own fake and pass while silicon would fail.

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

    /// Scripted fake UART-attached controller.
    ///
    /// Outbound bytes are accumulated until they form one complete
    /// H4 frame (indicator + header + announced body, per Vol 4
    /// Part A §2 — the same header layout `h4::Decoder` uses).
    /// A complete Command frame is answered synchronously with the
    /// scripted Command Complete for its opcode, so
    /// `Controller::bring_up`'s poll loop finds the reply waiting.
    /// Other outbound frames are swallowed (the host side of an H4
    /// link only originates commands, ACL and SCO).
    #[derive(Debug)]
    struct FakeUart {
        rx: IrqSafeSpinLock<VecDeque<u8>>,
        tx: IrqSafeSpinLock<Vec<u8>>,
        tx_frame: IrqSafeSpinLock<Vec<u8>>,
        /// (opcode, return parameters after the status byte).
        script: Vec<(u16, Vec<u8>)>,
    }

    /// Total length of the frame starting at `buf`, once enough
    /// bytes are present to read its announced body length.
    /// Returns `None` while the frame is incomplete.
    fn frame_total_len(buf: &[u8]) -> Option<usize> {
        if buf.is_empty() {
            return None;
        }
        let header_len = match buf[0] {
            0x01 => 3,           // Command
            0x02 => 4,           // ACL
            0x03 => 3,           // Synchronous
            0x04 => 2,           // Event
            0x05 => 4,           // ISO
            _ => return Some(1), // Unknown indicator: drop the byte.
        };
        if buf.len() < 1 + header_len {
            return None;
        }
        let header = &buf[1..1 + header_len];
        let body_len = match buf[0] {
            0x01 => header[2] as usize,
            0x02 => u16::from_le_bytes([header[2], header[3]]) as usize,
            0x03 => header[2] as usize,
            0x04 => header[1] as usize,
            0x05 => {
                let raw = u16::from_le_bytes([header[2], header[3]]);
                (raw & 0x3FFF) as usize
            }
            _ => unreachable!(),
        };
        Some(1 + header_len + body_len)
    }

    impl FakeUart {
        fn new(script: Vec<(u16, Vec<u8>)>) -> Self {
            Self {
                rx: IrqSafeSpinLock::new(VecDeque::new()),
                tx: IrqSafeSpinLock::new(Vec::new()),
                tx_frame: IrqSafeSpinLock::new(Vec::new()),
                script,
            }
        }

        /// Inject bytes the controller "received" (inbound to host).
        fn push_rx(&self, bytes: &[u8]) {
            self.rx.lock().extend(bytes.iter().copied());
        }

        /// Snapshot every byte the host wrote.
        fn tx_bytes(&self) -> Vec<u8> {
            self.tx.lock().clone()
        }

        /// Answer one complete outbound Command frame, if scripted.
        fn answer_command(&self, frame: &[u8]) {
            if frame.len() < 4 || frame[0] != 0x01 {
                return;
            }
            let opcode = u16::from_le_bytes([frame[1], frame[2]]);
            let Some((_, ret)) = self.script.iter().find(|(op, _)| *op == opcode) else {
                return;
            };
            // Command Complete event, literal per Vol 4 Part E
            // §7.7.14: indicator 0x04, code 0x0E, plen, then
            // [num_cmd_packets=1, opcode LE, status=0, ...return].
            let mut params = Vec::with_capacity(4 + ret.len());
            params.push(1u8);
            params.extend_from_slice(&opcode.to_le_bytes());
            params.push(0u8);
            params.extend_from_slice(ret);
            let mut ev = Vec::with_capacity(3 + params.len());
            ev.push(0x04);
            ev.push(0x0E);
            ev.push(params.len() as u8);
            ev.extend_from_slice(&params);
            self.rx.lock().extend(ev);
        }
    }

    impl H4BytePort for FakeUart {
        fn write_byte(&self, b: u8) {
            self.tx.lock().push(b);
            let mut pending = self.tx_frame.lock();
            pending.push(b);
            if let Some(total) = frame_total_len(&pending) {
                if pending.len() >= total {
                    let frame: Vec<u8> = pending.drain(..total).collect();
                    drop(pending);
                    self.answer_command(&frame);
                }
            }
        }

        fn read_byte(&self) -> Option<u8> {
            self.rx.lock().pop_front()
        }
    }

    /// Unwrap a transport `Result` or fail the smoke. `?` cannot be
    /// used here: these smokes return `TestResult`, not `Result`.
    macro_rules! check {
        ($e:expr, $msg:literal) => {
            match $e {
                Ok(v) => v,
                Err(_) => return TestResult::Fail($msg),
            }
        };
    }

    fn fixture_transport(script: Vec<(u16, Vec<u8>)>) -> (&'static FakeUart, H4Transport) {
        let fake: &'static FakeUart =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(FakeUart::new(script)));
        let transport = H4Transport::new(fake, "h4-fixture");
        (fake, transport)
    }

    fn smoke_h4_transport_command_bytes_are_spec_shaped() -> TestResult {
        let (fake, transport) = fixture_transport(Vec::new());
        // HCI_Reset, no params: indicator 0x01 + opcode 0x0C03 LE +
        // plen 0 (Vol 4 Part A §2 + Part E §5.4.1).
        check!(
            transport.send_command(&Command::with_params(0x0C03, &[])),
            "send_command failed"
        );
        // A command with parameters: opcode 0x1001 LE + plen 1.
        check!(
            transport.send_command(&Command::with_params(0x1001, &[0x01])),
            "send_command failed"
        );
        kt_assert_eq!(
            fake.tx_bytes(),
            alloc::vec![0x01, 0x03, 0x0C, 0x00, 0x01, 0x01, 0x10, 0x01, 0x01]
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h4-transport",
        smoke_h4_transport_command_bytes_are_spec_shaped
    );

    fn smoke_h4_transport_acl_and_sco_bytes_are_spec_shaped() -> TestResult {
        let (fake, transport) = fixture_transport(Vec::new());
        check!(
            transport.send_acl(&[0x01, 0x00, 0x03, 0x00, 0xAA, 0xBB, 0xCC]),
            "send_acl failed"
        );
        check!(
            transport.send_sco(&[0x01, 0x00, 0x02, 0x11, 0x22]),
            "send_sco failed"
        );
        kt_assert_eq!(
            fake.tx_bytes(),
            alloc::vec![
                0x02, 0x01, 0x00, 0x03, 0x00, 0xAA, 0xBB, 0xCC, // ACL
                0x03, 0x01, 0x00, 0x02, 0x11, 0x22, // SCO
            ]
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h4-transport",
        smoke_h4_transport_acl_and_sco_bytes_are_spec_shaped
    );

    fn smoke_h4_transport_bring_up_end_to_end() -> TestResult {
        // Scripted controller answers, return-parameters after the
        // status byte (Vol 4 Part E §7.4.1/§7.4.2/§7.4.5):
        // local version, BD_ADDR, buffer size, plus bare status for
        // Reset and Set Event Mask.
        let script = alloc::vec![
            (0x0C03u16, alloc::vec![]),
            (
                0x1001u16,
                alloc::vec![0x0C, 0x34, 0x12, 0x0C, 0x02, 0x00, 0x78, 0x56]
            ),
            (0x1009u16, alloc::vec![0x06, 0x05, 0x04, 0x03, 0x02, 0x01]),
            (
                0x1005u16,
                alloc::vec![0xFD, 0x03, 0xFF, 0x0A, 0x00, 0x02, 0x00]
            ),
            (0x0C01u16, alloc::vec![]),
        ];
        let (fake, transport) = fixture_transport(script);
        let transport: Arc<dyn HciTransport> = Arc::new(transport);
        let controller = crate::controller::Controller::new(transport);
        let cap = crate::bootstrap_bluetooth_authority();
        let info = match controller.bring_up(&cap) {
            Ok(info) => info,
            Err(_) => return TestResult::Fail("bring_up failed over the H4 transport"),
        };
        kt_assert_eq!(info.bd_addr, [0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        kt_assert_eq!(info.hci_version, 0x0C);
        kt_assert_eq!(info.hci_revision, 0x1234);
        kt_assert_eq!(info.lmp_version, 0x0C);
        kt_assert_eq!(info.manufacturer, 0x0002);
        kt_assert_eq!(info.lmp_subversion, 0x5678);
        kt_assert_eq!(info.acl_data_mtu, 1021);
        kt_assert_eq!(info.sco_data_mtu, 0xFF);
        kt_assert_eq!(info.acl_total_num, 10);
        kt_assert_eq!(info.sco_total_num, 2);
        // The five bring-up commands, in order, as literal H4
        // frames — including the 8-byte default event mask
        // (0xFF×5, 0x1F, 0x00, 0x00) on Set Event Mask.
        kt_assert_eq!(
            fake.tx_bytes(),
            alloc::vec![
                0x01, 0x03, 0x0C, 0x00, // Reset
                0x01, 0x01, 0x10, 0x00, // Read Local Version
                0x01, 0x09, 0x10, 0x00, // Read BD_ADDR
                0x01, 0x05, 0x10, 0x00, // Read Buffer Size
                0x01, 0x01, 0x0C, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0x00,
                0x00,
                // Set Event Mask
            ]
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h4-transport",
        smoke_h4_transport_bring_up_end_to_end
    );

    fn smoke_h4_transport_demuxes_interleaved_frames() -> TestResult {
        let (fake, transport) = fixture_transport(Vec::new());
        // Two Command Complete events with an ACL frame between
        // them — all literal wire bytes. A single-entry fixture
        // would hide a demux that returns the wrong queue's head.
        fake.push_rx(&[
            0x04, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00, // CC(Reset)
            0x02, 0x01, 0x00, 0x03, 0x00, 0xAA, 0xBB, 0xCC, // ACL
            0x04, 0x0E, 0x04, 0x01, 0x01, 0x10, 0x00, // CC(Read Local Version)
        ]);
        let first = check!(transport.recv_event(), "recv_event failed");
        kt_assert_eq!(
            first,
            Some(Event {
                code: 0x0E,
                params: alloc::vec![0x01, 0x03, 0x0C, 0x00],
            })
        );
        let acl = check!(transport.recv_acl(), "recv_acl failed");
        kt_assert_eq!(
            acl,
            Some(alloc::vec![0x01, 0x00, 0x03, 0x00, 0xAA, 0xBB, 0xCC])
        );
        let second = check!(transport.recv_event(), "recv_event failed");
        kt_assert_eq!(
            second,
            Some(Event {
                code: 0x0E,
                params: alloc::vec![0x01, 0x01, 0x10, 0x00],
            })
        );
        let none_event = check!(transport.recv_event(), "recv_event failed");
        kt_assert_eq!(none_event, None);
        let none_acl = check!(transport.recv_acl(), "recv_acl failed");
        kt_assert_eq!(none_acl, None);
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h4-transport",
        smoke_h4_transport_demuxes_interleaved_frames
    );

    fn smoke_h4_transport_bad_indicator_resyncs() -> TestResult {
        let (fake, transport) = fixture_transport(Vec::new());
        // 0xFF is not a packet indicator; the decoder must reject
        // it, count the error, and still deliver the valid event
        // that follows.
        fake.push_rx(&[0xFF, 0x04, 0x0E, 0x00]);
        let event = check!(transport.recv_event(), "recv_event failed");
        kt_assert_eq!(
            event,
            Some(Event {
                code: 0x0E,
                params: alloc::vec![],
            })
        );
        kt_assert_eq!(transport.frame_errors(), 1);
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h4-transport",
        smoke_h4_transport_bad_indicator_resyncs
    );

    fn smoke_h4_transport_split_frame_across_polls() -> TestResult {
        let (fake, transport) = fixture_transport(Vec::new());
        // First half of a Command Complete event: nothing complete
        // yet, so recv_event reports nothing ready.
        fake.push_rx(&[0x04, 0x0E, 0x04]);
        let none_event = check!(transport.recv_event(), "recv_event failed");
        kt_assert_eq!(none_event, None);
        // Second half completes the frame on a later poll.
        fake.push_rx(&[0x01, 0x03, 0x0C, 0x00]);
        let event = check!(transport.recv_event(), "recv_event failed");
        kt_assert_eq!(
            event,
            Some(Event {
                code: 0x0E,
                params: alloc::vec![0x01, 0x03, 0x0C, 0x00],
            })
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h4-transport",
        smoke_h4_transport_split_frame_across_polls
    );

    fn smoke_h4_transport_sco_round_trip() -> TestResult {
        let (fake, transport) = fixture_transport(Vec::new());
        fake.push_rx(&[0x03, 0x01, 0x00, 0x02, 0x11, 0x22]);
        let sco = check!(transport.recv_sco(), "recv_sco failed");
        kt_assert_eq!(sco, Some(alloc::vec![0x01, 0x00, 0x02, 0x11, 0x22]));
        check!(
            transport.send_sco(&[0x01, 0x00, 0x02, 0x11, 0x22]),
            "send_sco failed"
        );
        kt_assert_eq!(
            fake.tx_bytes(),
            alloc::vec![0x03, 0x01, 0x00, 0x02, 0x11, 0x22]
        );
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/h4-transport", smoke_h4_transport_sco_round_trip);

    fn smoke_bind_uart_unknown_name_is_not_found() -> TestResult {
        kt_assert!(matches!(
            bind_uart("NOPE", DEFAULT_H4_BAUD),
            Err(BindError::NotFound)
        ));
        TestResult::Pass
    }
    kernel_test_in!(
        "bluetooth/h4-transport",
        smoke_bind_uart_unknown_name_is_not_found
    );
}
