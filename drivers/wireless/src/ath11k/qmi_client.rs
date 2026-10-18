//! QRTR endpoint over the MHI IPCR channels + the QMI client the WLFW
//! handshake ([`super::wlfw`]) talks through.
//!
//! Linux splits this across `net/qrtr/mhi.c` (one QRTR packet per MHI
//! buffer), `net/qrtr/af_qrtr.c` + `ns.c` (framing, node ids, the name
//! service — modelled frame-in / frame-out by [`QrtrLink`]) and
//! `drivers/soc/qcom/qmi_interface.c` (the QMI handle: lookups,
//! transactions, indication dispatch). Here one owner drives it all
//! from a single async task: [`QmiClient::pump`] moves DL buffers into
//! the link, sends whatever the link answers (HELLO, RESUME_TX) on UL,
//! and sorts what arrives for the client into the matching
//! transaction or the inbound queue (server arrival / exit,
//! indications) the state machine drains.
//!
//! ## Who speaks first (HELLO ordering)
//!
//! The host never sends an unsolicited HELLO on this endpoint. In
//! Linux the name service broadcasts its HELLO once, from
//! `qrtr_ns_init` (`say_hello(&qrtr_ns.bcast_sq)`), which runs from
//! `qrtr_proto_init` — a `postcore_initcall` / module init of
//! `qrtr.ko`, which `qrtr-mhi.ko` depends on — so it always runs
//! before `qcom_mhi_qrtr_probe` registers the MHI endpoint, and
//! `qrtr_bcast_enqueue` only reaches nodes already on
//! `qrtr_all_nodes`. `qrtr_endpoint_register` itself transmits nothing
//! (it only allocates the node, `nid = QRTR_EP_NID_AUTO`). So the
//! device's HELLO comes first; `qrtr_endpoint_post` assigns the node
//! id from it, and the name service's `ctrl_cmd_hello` answers with
//! `say_hello(sq)` to `(remote node, QRTR_PORT_CTRL)` followed by
//! `announce_servers` (none on a host that hosts no QMI services).
//! The device then announces WLFW with NEW_SERVER. `qmi_add_lookup`'s
//! NEW_LOOKUP goes to the *local* name service, never on the wire.
//!
//! ## Transactions
//!
//! `qmi_txn_init` allocates ids with `idr_alloc_cyclic(&txns, txn, 0,
//! U16_MAX)`: 0, 1, 2, … 65534, then wrapping to 0 (an idr starts with
//! `idr_next = 0`). A response is matched on `txn_id` alone and decoded
//! with the waiting transaction's decoder — Linux never checks its
//! `msg_id`; responses with no waiting transaction are dropped
//! ("Ignore unexpected responses"). Everything else goes to the
//! indication handlers, which match `(type, msg_id)`.
//!
//! The client socket's port: `qrtr_port_assign` → `xa_alloc(..,
//! QRTR_EPH_PORT_RANGE)` hands out the lowest free ephemeral port; on
//! a host where ath11k's QMI handle is the only QRTR client that is
//! `QRTR_MIN_EPH_SOCKET` (0x4000).

#![allow(dead_code)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;
use core::future::Future;

use super::mhi_host::{MhiBus, MhiController, MhiNotify, POLL_INTERVAL_MS};
use super::qmi::{split_message, QmiError, QmiHeader, QMI_HEADER_SIZE, QMI_RESPONSE};
use super::qmi_wlfw::{WlfwMessage, WlfwRequest};
use super::qrtr::{
    qmi_instance, QrtrError, QrtrEvent, QrtrLink, QrtrServer, QRTR_DEFAULT_LOCAL_NODE,
    QRTR_MIN_EPH_SOCKET,
};

/// One QRTR packet per transfer in each direction — what `net/qrtr/mhi.c`
/// gives `af_qrtr.c`, plus the time source and the wait.
pub trait QrtrPipe {
    /// `qcom_mhi_qrtr_send`: queue one frame on UL. `Err` = positive
    /// errno.
    fn send(&mut self, frame: &[u8]) -> Result<(), i32>;
    /// Service completions without waiting (`mhi_irq_handler` work).
    fn poll(&mut self);
    /// The next received frame (`qcom_mhi_qrtr_dl_callback`).
    fn recv(&mut self) -> Option<Vec<u8>>;
    /// Wait up to `ms` for traffic, then service completions.
    fn wait(&mut self, ms: u32) -> impl Future<Output = ()> + Send;
    /// Monotonic milliseconds.
    fn now_ms(&self) -> u64;
    /// One console line.
    fn log(&self, _args: fmt::Arguments<'_>) {}
    /// The transport after bring-up (the MHI controller's interrupt work
    /// and state changes, [`MhiController::service`]).
    fn service(&mut self) {
        self.poll()
    }
    /// An interrupt is waiting to be serviced.
    fn irqs_pending(&self) -> bool {
        false
    }
    /// A crash the transport reported (`ath11k_mhi_op_status_cb` →
    /// `reset_work`), once.
    fn take_reset_request(&mut self) -> Option<MhiNotify> {
        None
    }
}

impl<B: MhiBus + Send> QrtrPipe for MhiController<B> {
    fn send(&mut self, frame: &[u8]) -> Result<(), i32> {
        self.queue_ul(frame).map_err(|e| e.errno)
    }
    fn poll(&mut self) {
        MhiController::poll(self)
    }
    fn recv(&mut self) -> Option<Vec<u8>> {
        self.take_dl().map(|p| p.data)
    }
    fn wait(&mut self, ms: u32) -> impl Future<Output = ()> + Send {
        self.wait_and_poll(ms)
    }
    fn now_ms(&self) -> u64 {
        self.bus.now_ms()
    }
    fn log(&self, args: fmt::Arguments<'_>) {
        self.bus.log(args)
    }
    fn service(&mut self) {
        MhiController::service(self)
    }
    fn irqs_pending(&self) -> bool {
        MhiController::irqs_pending(self)
    }
    fn take_reset_request(&mut self) -> Option<MhiNotify> {
        MhiController::take_reset_request(self)
    }
}

/// Why a QMI transaction failed. Each variant names the Linux return
/// it stands for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TxnError {
    /// `qmi_send_request` → `qmi_encode_message` failed.
    Encode(QmiError),
    /// No WLFW server connected (`kernel_sendmsg` on an unconnected
    /// socket, `-ENOTCONN`).
    NotConnected,
    /// QRTR refused the frame (`-EMSGSIZE`).
    Frame(QrtrError),
    /// The UL queue refused the frame (`qcom_mhi_qrtr_send` errno).
    Send(i32),
    /// NARF-only bound: `qrtr_tx_wait` sleeps until RESUME_TX with no
    /// timeout; here the wait shares the transaction's budget.
    FlowTimeout,
    /// `qmi_txn_wait` `-ETIMEDOUT`.
    Timeout,
    /// The matched response failed `qmi_decode_message`.
    Decode(QmiError),
}

impl TxnError {
    /// Kind code for diag details (`detail = kind << 16 | value`).
    pub fn kind(&self) -> u32 {
        match self {
            TxnError::Timeout => 1,
            TxnError::Decode(_) => 3,
            TxnError::Encode(_) => 4,
            TxnError::Send(_) => 5,
            TxnError::NotConnected => 6,
            TxnError::FlowTimeout => 7,
            TxnError::Frame(_) => 8,
        }
    }

    /// Positive Linux errno.
    pub fn errno(&self) -> i32 {
        match self {
            TxnError::Timeout | TxnError::FlowTimeout => 110, // ETIMEDOUT
            TxnError::NotConnected => 107,                    // ENOTCONN
            TxnError::Frame(_) => 90,                         // EMSGSIZE
            TxnError::Send(e) => *e,
            TxnError::Encode(_) | TxnError::Decode(_) => 22, // EINVAL
        }
    }
}

/// What arrived for the client outside a transaction, in arrival order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inbound {
    /// `ops->new_server` (after `kernel_connect` to it).
    ServerArrive(QrtrServer),
    /// `ops->del_server` (DEL_SERVER, or the remote's BYE).
    ServerExit(QrtrServer),
    /// A non-response QMI message (indication) for the handlers.
    Message(Vec<u8>),
}

/// Counters for the console.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QmiStats {
    pub frames_rx: u32,
    pub frames_tx: u32,
    /// Frames `qrtr_endpoint_post` would refuse.
    pub bad_frames: u32,
    /// Link replies (HELLO / RESUME_TX) the UL queue refused.
    pub ctrl_tx_failed: u32,
    /// Responses with no waiting transaction.
    pub unexpected_responses: u32,
    /// QMI payloads under 7 bytes ("ignoring short QMI packet").
    pub short_messages: u32,
    /// DATA to a port other than the client's.
    pub misdirected: u32,
}

/// The ath11k QMI handle over one QRTR endpoint.
#[allow(missing_debug_implementations)]
pub struct QmiClient<P: QrtrPipe> {
    pub pipe: P,
    link: QrtrLink,
    port: u32,
    server: Option<QrtrServer>,
    /// `idr->idr_next` of the transaction idr.
    txn_next: u32,
    pending_txn: Option<u16>,
    response: Option<Vec<u8>>,
    inbox: VecDeque<Inbound>,
    pub stats: QmiStats,
}

/// Largest transaction id `idr_alloc_cyclic(.., 0, U16_MAX)` returns.
pub const QMI_TXN_ID_MAX: u32 = u16::MAX as u32 - 1;

impl<P: QrtrPipe> QmiClient<P> {
    /// `qmi_handle_init` + the endpoint registration: local node
    /// `QRTR_DEFAULT_LOCAL_NODE`, client port `QRTR_MIN_EPH_SOCKET`.
    pub fn new(pipe: P) -> Self {
        Self {
            pipe,
            link: QrtrLink::new(QRTR_DEFAULT_LOCAL_NODE),
            port: QRTR_MIN_EPH_SOCKET,
            server: None,
            txn_next: 0,
            pending_txn: None,
            response: None,
            inbox: VecDeque::new(),
            stats: QmiStats::default(),
        }
    }

    pub fn port(&self) -> u32 {
        self.port
    }

    /// The connected WLFW server, once one arrived.
    pub fn server(&self) -> Option<QrtrServer> {
        self.server
    }

    pub fn link(&self) -> &QrtrLink {
        &self.link
    }

    /// The id the next `qmi_txn_init` returns.
    pub fn next_txn_id(&self) -> u16 {
        if self.txn_next > QMI_TXN_ID_MAX {
            0
        } else {
            self.txn_next as u16
        }
    }

    /// Test hook: position the cyclic allocator.
    pub fn set_next_txn_id(&mut self, next: u32) {
        self.txn_next = next;
    }

    /// `qmi_txn_init`'s id: `idr_alloc_cyclic(.., 0, U16_MAX)` with at
    /// most one transaction outstanding.
    fn txn_init(&mut self) -> u16 {
        let id = self.next_txn_id();
        self.txn_next = id as u32 + 1;
        id
    }

    /// `qmi_add_lookup(service, version, instance)`.
    pub fn add_lookup(&mut self, service: u32, version: u32, instance: u32) {
        for ev in self
            .link
            .add_lookup(service, qmi_instance(version, instance))
        {
            self.on_event(ev);
        }
    }

    /// Pop the oldest inbound item.
    pub fn take_inbound(&mut self) -> Option<Inbound> {
        self.inbox.pop_front()
    }

    pub fn has_inbound(&self) -> bool {
        !self.inbox.is_empty()
    }

    /// Move every received frame through the link: answers go out on
    /// UL, client traffic lands in the transaction / inbound queue.
    pub fn pump(&mut self) {
        self.pipe.poll();
        while let Some(frame) = self.pipe.recv() {
            self.stats.frames_rx += 1;
            match self.link.receive(&frame) {
                Err(e) => {
                    self.stats.bad_frames += 1;
                    self.pipe
                        .log(format_args!("qrtr: dropping invalid frame: {:?}", e));
                }
                Ok(rx) => {
                    for f in rx.tx {
                        match self.pipe.send(&f) {
                            Ok(()) => self.stats.frames_tx += 1,
                            Err(e) => {
                                self.stats.ctrl_tx_failed += 1;
                                self.pipe
                                    .log(format_args!("qrtr: control reply failed: -{}", e));
                            }
                        }
                    }
                    for ev in rx.events {
                        self.on_event(ev);
                    }
                }
            }
        }
    }

    fn on_event(&mut self, ev: QrtrEvent) {
        match ev {
            QrtrEvent::NewServer(s) => {
                // qmi_recv_new_server: "Ignore EOF marker".
                if s.node == 0 && s.port == 0 {
                    return;
                }
                self.server = Some(s);
                self.inbox.push_back(Inbound::ServerArrive(s));
            }
            QrtrEvent::DelServer(s) => self.inbox.push_back(Inbound::ServerExit(s)),
            QrtrEvent::Data {
                dst_port, payload, ..
            } => {
                if dst_port != self.port {
                    self.stats.misdirected += 1;
                    return;
                }
                self.handle_message(payload);
            }
            QrtrEvent::ResumeTx { .. } => {}
        }
    }

    /// `qmi_handle_message`.
    fn handle_message(&mut self, buf: Vec<u8>) {
        if buf.len() < QMI_HEADER_SIZE {
            self.stats.short_messages += 1;
            return;
        }
        let Ok(hdr) = QmiHeader::parse(&buf) else {
            return;
        };
        if hdr.msg_type == QMI_RESPONSE {
            if self.pending_txn == Some(hdr.txn_id) && self.response.is_none() {
                self.response = Some(buf);
            } else {
                self.stats.unexpected_responses += 1;
            }
            return;
        }
        self.inbox.push_back(Inbound::Message(buf));
    }

    /// Wait up to `ms` for something inbound; `true` if the queue is
    /// non-empty on return.
    pub async fn wait_inbound(&mut self, ms: u32) -> bool {
        let deadline = self.pipe.now_ms() + ms as u64;
        loop {
            self.pump();
            if self.has_inbound() {
                return true;
            }
            let now = self.pipe.now_ms();
            if now >= deadline {
                return false;
            }
            let slice = (deadline - now).min(POLL_INTERVAL_MS as u64) as u32;
            self.pipe.wait(slice).await;
        }
    }

    /// `qmi_txn_init` + `qmi_send_request(.., NULL, &txn, ..)` +
    /// `qmi_txn_wait(&txn, timeout_ms)`: the decoded response, whatever
    /// its `result` (callers apply ath11k's result checks).
    pub async fn request<Q: WlfwRequest, M: WlfwMessage>(
        &mut self,
        req: &Q,
        timeout_ms: u32,
    ) -> Result<M, TxnError> {
        let txn = self.txn_init();
        let msg = req.encode(txn).map_err(TxnError::Encode)?;
        let server = self.server.ok_or(TxnError::NotConnected)?;
        self.response = None;
        self.pending_txn = Some(txn);
        let r = self.send_and_wait::<M>(&msg, server, timeout_ms).await;
        self.pending_txn = None;
        self.response = None;
        r
    }

    async fn send_and_wait<M: WlfwMessage>(
        &mut self,
        msg: &[u8],
        server: QrtrServer,
        timeout_ms: u32,
    ) -> Result<M, TxnError> {
        // qrtr_sendmsg → qrtr_tx_wait → qrtr_node_enqueue.
        let deadline = self.pipe.now_ms() + timeout_ms as u64;
        let frame = loop {
            match self.link.data_frame(self.port, server.addr(), msg) {
                Ok(f) => break f,
                Err(QrtrError::FlowBlocked) => {
                    self.pump();
                    let now = self.pipe.now_ms();
                    if now >= deadline {
                        return Err(TxnError::FlowTimeout);
                    }
                    let slice = (deadline - now).min(POLL_INTERVAL_MS as u64) as u32;
                    self.pipe.wait(slice).await;
                }
                Err(e) => return Err(TxnError::Frame(e)),
            }
        };
        self.pipe.send(&frame).map_err(TxnError::Send)?;
        self.stats.frames_tx += 1;

        // qmi_txn_wait.
        let deadline = self.pipe.now_ms() + timeout_ms as u64;
        loop {
            self.pump();
            if let Some(raw) = self.response.take() {
                let (_, payload) = split_message(&raw).map_err(TxnError::Decode)?;
                return M::decode_payload(payload).map_err(TxnError::Decode);
            }
            let now = self.pipe.now_ms();
            if now >= deadline {
                return Err(TxnError::Timeout);
            }
            let slice = (deadline - now).min(POLL_INTERVAL_MS as u64) as u32;
            self.pipe.wait(slice).await;
        }
    }
}
