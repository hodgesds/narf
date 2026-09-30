//! `HciTransport` binding for the PCIe controller.
//!
//! The DMA rings carry a single mixed stream: HCI events, ACL data
//! and synchronous data all arrive through the same RX descriptor
//! ring, tagged with the Intel 4-byte packet-type word. The
//! `HciTransport` trait, modelled on USB where each packet class has
//! its own endpoint, asks for them through separate calls.
//!
//! So this type is a demultiplexer. Any call that wants a packet
//! drains the ring completely and files each packet under its type,
//! then answers from the caller's queue. Draining into per-type
//! queues rather than returning the first packet found is what keeps
//! `recv_event` from swallowing an ACL frame — with one shared ring
//! and no queues, whichever call happened to run first would consume
//! and discard the other's traffic.
//!
//! The queues are bounded. A host that stops draining ACL must not be
//! able to grow them without limit, so a full queue drops the newest
//! packet and counts it; `dropped()` reports the total. Linux does
//! the same thing in `hci_rx_work`'s queue limits.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::hci::{Command, Event};
use crate::transport::{HciTransport, TransportError};

use super::rings::{HCI_ACL_PKT, HCI_CMD_PKT, HCI_EVT_PKT, HCI_ISO_PKT, HCI_SCO_PKT};
use super::{BtIntelPcie, BtPcieError};

/// Most packets of one class held before the transport starts
/// dropping. Sized for the burst a controller can produce between
/// two polls of the host's pump, not for buffering a stalled host.
pub const QUEUE_DEPTH: usize = 64;

/// Map a transport-layer failure onto the HCI transport's vocabulary.
fn map_err(e: BtPcieError) -> TransportError {
    match e {
        // The device stopped retiring descriptors, or was never
        // there. Both mean this controller is gone as far as the HCI
        // core is concerned.
        BtPcieError::TxTimeout => TransportError::Timeout,
        BtPcieError::DeviceGone => TransportError::Detached,
        // A packet that does not fit a DMA buffer, or a ring index
        // the device put out of range: retryable at the HCI layer,
        // and not a reason to tear the controller down.
        _ => TransportError::Transient,
    }
}

/// The per-packet-class queues and the rule for filing a packet into
/// them.
///
/// Split out of the transport so the demultiplexing can be exercised
/// without a controller: everything interesting here is a decision
/// about a `(type word, bytes)` pair, and none of it needs DMA.
#[derive(Debug)]
pub struct RxQueues {
    events: IrqSafeSpinLock<VecDeque<Event>>,
    acl: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    sco: IrqSafeSpinLock<VecDeque<Vec<u8>>>,
    dropped: AtomicU64,
    malformed: AtomicU64,
}

impl RxQueues {
    /// Empty queues.
    pub fn new() -> Self {
        Self {
            events: IrqSafeSpinLock::new(VecDeque::new()),
            acl: IrqSafeSpinLock::new(VecDeque::new()),
            sco: IrqSafeSpinLock::new(VecDeque::new()),
            dropped: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
        }
    }

    /// Packets discarded because their queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Packets the device delivered that did not decode, or that
    /// carried a type word this controller should never emit.
    pub fn malformed(&self) -> u64 {
        self.malformed.load(Ordering::Relaxed)
    }

    /// Queue depths, in `(events, acl, sco)` order.
    pub fn depths(&self) -> (usize, usize, usize) {
        (
            self.events.lock().len(),
            self.acl.lock().len(),
            self.sco.lock().len(),
        )
    }

    /// Push onto a bounded queue, counting an overflow rather than
    /// growing without limit.
    ///
    /// The newest packet is the one dropped: the queued ones are
    /// older, and for ACL that means they are earlier in an L2CAP
    /// stream that has a better chance of being useful in order.
    fn push_bounded<T>(&self, q: &IrqSafeSpinLock<VecDeque<T>>, item: T) {
        let mut q = q.lock();
        if q.len() >= QUEUE_DEPTH {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        q.push_back(item);
    }

    /// File one packet from the ring under its type.
    ///
    /// Each lock is taken for a single push and released, so the
    /// three queues are never held at once and there is no lock
    /// ordering between them to get wrong.
    pub fn file(&self, ty: u32, pkt: Vec<u8>) {
        match ty {
            HCI_EVT_PKT => match Event::decode(&pkt) {
                Some(e) => self.push_bounded(&self.events, e),
                None => {
                    self.malformed.fetch_add(1, Ordering::Relaxed);
                }
            },
            HCI_ACL_PKT => self.push_bounded(&self.acl, pkt),
            HCI_SCO_PKT | HCI_ISO_PKT => self.push_bounded(&self.sco, pkt),
            _ => {
                self.malformed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Take the oldest queued event.
    pub fn pop_event(&self) -> Option<Event> {
        self.events.lock().pop_front()
    }

    /// Take the oldest queued ACL packet.
    pub fn pop_acl(&self) -> Option<Vec<u8>> {
        self.acl.lock().pop_front()
    }

    /// Take the oldest queued synchronous-data packet.
    pub fn pop_sco(&self) -> Option<Vec<u8>> {
        self.sco.lock().pop_front()
    }
}

impl Default for RxQueues {
    fn default() -> Self {
        Self::new()
    }
}

/// HCI transport over the Intel PCIe DMA rings.
pub struct BtIntelPcieTransport {
    dev: Arc<BtIntelPcie>,
    rx: RxQueues,
}

impl fmt::Debug for BtIntelPcieTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (events, acl, sco) = self.rx.depths();
        f.debug_struct("BtIntelPcieTransport")
            .field("events", &events)
            .field("acl", &acl)
            .field("sco", &sco)
            .field("dropped", &self.rx.dropped())
            .field("malformed", &self.rx.malformed())
            .finish_non_exhaustive()
    }
}

impl BtIntelPcieTransport {
    /// Wrap a controller whose firmware is already running.
    pub fn new(dev: Arc<BtIntelPcie>) -> Self {
        Self {
            dev,
            rx: RxQueues::new(),
        }
    }

    /// The receive queues, for diagnostics.
    pub fn rx(&self) -> &RxQueues {
        &self.rx
    }

    /// Drain the RX ring, filing every packet under its type.
    fn pump(&self) {
        while let Some((ty, pkt)) = self.dev.recv_packet() {
            self.rx.file(ty, pkt);
        }
    }
}

impl HciTransport for BtIntelPcieTransport {
    fn send_command(&self, cmd: &Command) -> Result<(), TransportError> {
        // `encode` produces opcode-LE + parameter length + parameters,
        // which is exactly the Command packet body; the Intel type
        // word replaces the 0x01 indicator USB would prepend.
        self.dev
            .send_packet(HCI_CMD_PKT, &cmd.encode())
            .map_err(map_err)
    }

    fn recv_event(&self) -> Result<Option<Event>, TransportError> {
        self.pump();
        Ok(self.rx.pop_event())
    }

    fn send_acl(&self, data: &[u8]) -> Result<(), TransportError> {
        self.dev.send_packet(HCI_ACL_PKT, data).map_err(map_err)
    }

    fn recv_acl(&self) -> Result<Option<Vec<u8>>, TransportError> {
        self.pump();
        Ok(self.rx.pop_acl())
    }

    fn send_sco(&self, data: &[u8]) -> Result<(), TransportError> {
        self.dev.send_packet(HCI_SCO_PKT, data).map_err(map_err)
    }

    fn recv_sco(&self) -> Result<Option<Vec<u8>>, TransportError> {
        self.pump();
        Ok(self.rx.pop_sco())
    }

    fn name(&self) -> &'static str {
        "btintel-pcie"
    }
}
