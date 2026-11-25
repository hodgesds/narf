//! The usbfs URB engine: one queue of submitted URBs per open file, the
//! part of Linux `devio.c` (`async_newpending` / `async_completed` /
//! `async_getcompleted`) and the HCD's per-endpoint ordering it relies on.
//!
//! The controller moves at most one bulk or interrupt TD of up to one page
//! per endpoint at a time (`Xhci::begin_bulk`), so the engine keeps each
//! endpoint's URBs in submission order, posts only the oldest, and splits
//! it into page-sized TDs. A page is a whole number of packets at every
//! USB speed, so a short packet still ends the URB exactly where the
//! device ended its transfer, as it would on a scatter-gather TD.
//!
//! Control transfers do not pass through here: usbfs awaits them in the
//! submitting ioctl (EP0 is serialised by the controller anyway).

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::sync::atomic::{AtomicU64, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::bulk::dci_for;
use crate::device::{BulkToken, USBDevice, UsbError};
use crate::xhci::EndpointConfig;

/// The largest TD the controller posts (one DMA page).
pub const TD_MAX: usize = 4096;

pub const ENOENT: i32 = 2;
pub const EIO: i32 = 5;
pub const ENODEV: i32 = 19;
pub const EBUSY: i32 = 16;
pub const EINVAL: i32 = 22;
pub const EPIPE: i32 = 32;
pub const EPROTO: i32 = 71;
pub const EOVERFLOW: i32 = 75;
pub const ECONNRESET: i32 = 104;
pub const ESHUTDOWN: i32 = 108;
pub const ETIMEDOUT: i32 = 110;
pub const EREMOTEIO: i32 = 121;

/// `USBDEVFS_URB_*` flags.
pub const URB_SHORT_NOT_OK: u32 = 0x01;
pub const URB_ISO_ASAP: u32 = 0x02;
pub const URB_BULK_CONTINUATION: u32 = 0x04;
pub const URB_NO_FSBR: u32 = 0x20;
pub const URB_ZERO_PACKET: u32 = 0x40;
pub const URB_NO_INTERRUPT: u32 = 0x80;

/// A URB status for a controller error, as the Linux xHCI driver gives
/// it back (`xhci_td_cleanup` → `urb->status`).
pub fn errno(error: UsbError) -> i32 {
    match error {
        UsbError::Stall => EPIPE,
        UsbError::TransactionError => EPROTO,
        UsbError::Babble | UsbError::BufferTooSmall => EOVERFLOW,
        UsbError::Timeout => ETIMEDOUT,
        UsbError::StaleSlot => ESHUTDOWN,
        UsbError::NotConfigured => EINVAL,
        UsbError::HardwareError(0xFE) => EBUSY,
        UsbError::HardwareError(_) => EIO,
    }
}

/// Errors that leave the controller endpoint Halted (xHCI §4.10.2): the
/// host side must be reset before the endpoint moves data again.
fn halts(error: UsbError) -> bool {
    matches!(
        error,
        UsbError::Stall | UsbError::TransactionError | UsbError::Babble
    )
}

/// The transfer type a TD is posted as.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Xfer {
    Bulk,
    Interrupt,
}

/// What usbfs needs from the controller for one device: the seam the
/// smokes model.
#[async_trait]
pub trait Pipe: Send + Sync {
    /// Post one TD of at most [`TD_MAX`] bytes on endpoint address `ep`;
    /// `data` is the OUT payload (empty for IN). Returns a receipt.
    fn begin(&self, ep: u8, xfer: Xfer, len: usize, data: &[u8]) -> Result<u64, UsbError>;
    /// Poll a receipt: `Some(n)` once its TD completed (IN bytes in `out`).
    fn poll(&self, receipt: u64, out: &mut [u8]) -> Result<Option<usize>, UsbError>;
    /// Retire a posted TD without completing it (Stop Endpoint + Set TR
    /// Dequeue). `Ok` proves the TD never completed.
    async fn stop(&self, receipt: u64) -> Result<(), UsbError>;
    /// Forget a receipt that completed or was stopped.
    fn forget(&self, receipt: u64);
    /// One control transfer on EP0. `data` is the IN buffer or OUT payload.
    async fn control(&self, setup: [u8; 8], data: &mut [u8]) -> Result<usize, UsbError>;
    /// Whether endpoint `ep` is configured on the controller.
    fn configured(&self, ep: u8) -> bool;
    /// Configure endpoints on the controller.
    async fn configure(&self, eps: &[EndpointConfig]) -> Result<(), UsbError>;
    /// Remove endpoints from the controller (each must be idle).
    async fn deconfigure(&self, eps: &[u8]) -> Result<(), UsbError>;
    /// Whether the host side of `ep` is Halted.
    fn halted(&self, ep: u8) -> bool;
    /// Recover a Halted endpoint's host side (Reset Endpoint + Set TR
    /// Dequeue); the device side is the caller's CLEAR_FEATURE.
    async fn recover(&self, ep: u8) -> Result<(), UsbError>;
}

/// [`Pipe`] over a real controller slot.
#[derive(Debug)]
pub struct XhciPipe {
    device: USBDevice,
    /// `(receipt, is_in, token)` of every posted TD.
    receipts: IrqSafeSpinLock<Vec<(u64, bool, BulkToken)>>,
    next: AtomicU64,
}

impl XhciPipe {
    pub fn new(device: USBDevice) -> Self {
        Self {
            device,
            receipts: IrqSafeSpinLock::new(Vec::new()),
            next: AtomicU64::new(1),
        }
    }
}

#[async_trait]
impl Pipe for XhciPipe {
    fn begin(&self, ep: u8, xfer: Xfer, len: usize, data: &[u8]) -> Result<u64, UsbError> {
        let dci = dci_for(ep);
        let is_in = ep & 0x80 != 0;
        let token = match (xfer, is_in) {
            (Xfer::Bulk, true) => self.device.begin_bulk_in(dci, len)?,
            (Xfer::Bulk, false) => self.device.begin_bulk_out(dci, data)?,
            (Xfer::Interrupt, true) => self.device.begin_interrupt_in(dci, len)?,
            (Xfer::Interrupt, false) => self.device.begin_interrupt_out(dci, data)?,
        };
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.receipts.lock().push((id, is_in, token));
        Ok(id)
    }

    fn poll(&self, receipt: u64, out: &mut [u8]) -> Result<Option<usize>, UsbError> {
        // The receipt lock is a leaf: the poll takes only controller locks.
        let receipts = self.receipts.lock();
        let (_, is_in, token) = receipts
            .iter()
            .find(|(id, _, _)| *id == receipt)
            .ok_or(UsbError::StaleSlot)?;
        if *is_in {
            self.device.poll_bulk_in(token, out)
        } else {
            self.device.poll_bulk_out(token)
        }
    }

    async fn stop(&self, receipt: u64) -> Result<(), UsbError> {
        let taken = {
            let mut receipts = self.receipts.lock();
            let i = receipts
                .iter()
                .position(|(id, _, _)| *id == receipt)
                .ok_or(UsbError::StaleSlot)?;
            receipts.remove(i)
        };
        let r = self.device.stop_bulk(&taken.2).await;
        if r.is_err() {
            // The TD may have completed first: keep it pollable.
            self.receipts.lock().push(taken);
        }
        r
    }

    fn forget(&self, receipt: u64) {
        self.receipts.lock().retain(|(id, _, _)| *id != receipt);
    }

    async fn control(&self, setup: [u8; 8], data: &mut [u8]) -> Result<usize, UsbError> {
        let [rt, req, v0, v1, i0, i1, _, _] = setup;
        let value = u16::from_le_bytes([v0, v1]);
        let index = u16::from_le_bytes([i0, i1]);
        if rt & 0x80 != 0 && !data.is_empty() {
            self.device.control_in(rt, req, value, index, data).await
        } else {
            self.device.control_out(rt, req, value, index, data).await
        }
    }

    fn configured(&self, ep: u8) -> bool {
        self.device.endpoint_kind(dci_for(ep)).is_some()
    }

    async fn configure(&self, eps: &[EndpointConfig]) -> Result<(), UsbError> {
        self.device.configure_endpoints(eps).await
    }

    async fn deconfigure(&self, eps: &[u8]) -> Result<(), UsbError> {
        let dcis: Vec<u8> = eps.iter().map(|&ep| dci_for(ep)).collect();
        self.device.drop_endpoints(&dcis).await
    }

    fn halted(&self, ep: u8) -> bool {
        self.device.endpoint_halted(dci_for(ep))
    }

    async fn recover(&self, ep: u8) -> Result<(), UsbError> {
        self.device.reset_host_endpoint(dci_for(ep)).await
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum State {
    /// Waiting behind an older URB on the same endpoint.
    Queued,
    /// A TD of `len` bytes is posted.
    InFlight { receipt: u64, len: usize },
    /// A kill is stopping the posted TD.
    Stopping { receipt: u64, len: usize },
}

/// One submitted URB (Linux `struct async`).
#[derive(Debug)]
pub struct Urb {
    /// The user's `struct usbdevfs_urb` address: DISCARDURB's key and
    /// what REAPURB hands back.
    pub userurb: u64,
    /// Interface the endpoint belongs to; `None` for EP0.
    pub ifnum: Option<u8>,
    /// Endpoint address, direction bit included.
    pub ep: u8,
    pub xfer: Xfer,
    /// User address of the data.
    pub buffer: u64,
    pub length: usize,
    /// Translated flags: [`URB_SHORT_NOT_OK`] only where a short IN
    /// packet is possible, [`URB_ZERO_PACKET`] only on OUT.
    pub flags: u32,
    pub continuation: bool,
    /// Bytes charged against the usbfs memory budget.
    pub charge: usize,
    /// Owned by a CONTROL/BULK ioctl, not reapable.
    pub sync: u64,
    /// OUT payload.
    out: Vec<u8>,
    /// IN bytes received so far.
    pub data: Vec<u8>,
    /// Bytes moved so far.
    pub actual: usize,
    posted_any: bool,
    zlp_owed: bool,
    state: State,
    /// Terminal status (0 or a negative errno) once complete.
    pub status: i32,
}

/// A control URB the submitting ioctl already ran: reapable as is.
#[allow(clippy::too_many_arguments)]
pub fn completed_urb(
    userurb: u64,
    ifnum: Option<u8>,
    ep: u8,
    buffer: u64,
    length: usize,
    status: i32,
    actual: usize,
    data: Vec<u8>,
    charge: usize,
) -> Urb {
    Urb {
        userurb,
        ifnum,
        ep,
        xfer: Xfer::Bulk,
        buffer,
        length,
        flags: 0,
        continuation: false,
        charge,
        sync: 0,
        out: Vec::new(),
        data,
        actual,
        posted_any: true,
        zlp_owed: false,
        state: State::Queued,
        status,
    }
}

/// What a submitter supplies; see [`Urb`].
pub struct Submit {
    pub userurb: u64,
    pub ifnum: Option<u8>,
    pub ep: u8,
    pub xfer: Xfer,
    pub buffer: u64,
    pub length: usize,
    pub flags: u32,
    pub continuation: bool,
    /// `wMaxPacketSize`, for ZERO_PACKET.
    pub maxp: usize,
    pub charge: usize,
    pub sync: u64,
    pub out: Vec<u8>,
}

/// A TD a kill must stop outside the engine lock.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Stop {
    pub userurb: u64,
    pub sync: u64,
    pub receipt: u64,
    pub len: usize,
}

/// Bulk endpoint index Linux uses for `disabled_bulk_eps`: the number,
/// with the direction bit moved to 0x10.
fn bulk_index(ep: u8) -> u32 {
    u32::from(ep & 0x0f) | (u32::from(ep & 0x80) >> 3)
}

/// The URBs of one open file.
#[derive(Default)]
pub struct Engine {
    pending: Vec<Urb>,
    completed: VecDeque<Urb>,
    sync_done: Vec<Urb>,
    /// Linux `ps->disabled_bulk_eps`.
    disabled_bulk: u32,
    /// Endpoints whose host side halted and awaits [`Pipe::recover`].
    halted: Vec<u8>,
}

impl Engine {
    /// Queue a URB. A continuation URB on a bulk endpoint an earlier
    /// error disabled is refused with `-EREMOTEIO`, as `proc_do_submiturb`.
    pub fn submit(&mut self, s: Submit) -> Result<(), i32> {
        if s.xfer == Xfer::Bulk {
            let bit = 1u32 << bulk_index(s.ep);
            if !s.continuation {
                self.disabled_bulk &= !bit;
            }
            if self.disabled_bulk & bit != 0 {
                return Err(EREMOTEIO);
            }
        }
        let zlp_owed =
            s.flags & URB_ZERO_PACKET != 0 && s.length > 0 && s.maxp > 0 && s.length % s.maxp == 0;
        self.pending.push(Urb {
            userurb: s.userurb,
            ifnum: s.ifnum,
            ep: s.ep,
            xfer: s.xfer,
            buffer: s.buffer,
            length: s.length,
            flags: s.flags,
            continuation: s.continuation,
            charge: s.charge,
            sync: s.sync,
            out: s.out,
            data: Vec::new(),
            actual: 0,
            posted_any: false,
            zlp_owed,
            state: State::Queued,
            status: 0,
        });
        Ok(())
    }

    /// Queue a URB that already completed (a control URB the submitting
    /// ioctl ran to completion).
    pub fn push_completed(&mut self, urb: Urb) {
        self.completed.push_back(urb);
    }

    /// Whether any URB is still pending.
    pub fn busy(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Whether any reapable completion is waiting.
    pub fn has_completed(&self) -> bool {
        !self.completed.is_empty()
    }

    /// Whether a URB on `ep` is pending.
    pub fn endpoint_busy(&self, ep: u8) -> bool {
        self.pending.iter().any(|u| u.ep == ep)
    }

    /// Endpoints awaiting host-side halt recovery; cleared by the call.
    pub fn take_halted(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.halted)
    }

    /// `async_getcompleted`.
    pub fn take_completed(&mut self) -> Option<Urb> {
        self.completed.pop_front()
    }

    /// The finished URB a CONTROL/BULK ioctl `sync` owns.
    pub fn take_sync(&mut self, sync: u64) -> Option<Urb> {
        let i = self.sync_done.iter().position(|u| u.sync == sync)?;
        Some(self.sync_done.remove(i))
    }

    /// Whether `userurb` names a pending URB (`async_getpending`).
    pub fn is_pending(&self, userurb: u64) -> bool {
        self.pending
            .iter()
            .any(|u| u.sync == 0 && u.userurb == userurb)
    }

    fn finish(&mut self, index: usize, status: i32) -> Urb {
        let mut urb = self.pending.remove(index);
        urb.status = status;
        // `async_completed` → `cancel_bulk_urbs`: an error ends the bulk
        // transfer, so the continuation URBs queued behind it are unlinked
        // and the endpoint refuses continuations until a new transfer.
        if urb.xfer == Xfer::Bulk && status < 0 && status != -ECONNRESET && status != -ENOENT {
            let mut unlink = Vec::new();
            let mut disable = true;
            for (i, later) in self.pending.iter().enumerate() {
                if later.ep != urb.ep || later.xfer != Xfer::Bulk {
                    continue;
                }
                if !later.continuation {
                    disable = false;
                    break;
                }
                unlink.push(i);
            }
            if disable {
                self.disabled_bulk |= 1u32 << bulk_index(urb.ep);
            }
            for i in unlink.into_iter().rev() {
                if self.pending[i].state == State::Queued {
                    let killed = self.finish_plain(i, -ECONNRESET);
                    self.deliver(killed);
                }
            }
        }
        urb
    }

    fn finish_plain(&mut self, index: usize, status: i32) -> Urb {
        let mut urb = self.pending.remove(index);
        urb.status = status;
        urb
    }

    fn deliver(&mut self, urb: Urb) {
        if urb.sync != 0 {
            self.sync_done.push(urb);
        } else {
            self.completed.push_back(urb);
        }
    }

    fn complete(&mut self, index: usize, status: i32) {
        let urb = self.finish(index, status);
        self.deliver(urb);
    }

    /// Post the next TD of the URB at `index`, or complete it when nothing
    /// is left to move.
    fn post(&mut self, pipe: &dyn Pipe, index: usize) {
        let urb = &mut self.pending[index];
        let remaining = urb.length - urb.actual;
        let is_in = urb.ep & 0x80 != 0;
        let len = remaining.min(TD_MAX);
        if len == 0 {
            // A zero-length OUT URB is one zero-length packet; ZERO_PACKET
            // adds one after a full last packet. A zero-length IN URB has
            // nothing to receive.
            let zlp = !is_in && (!urb.posted_any || urb.zlp_owed);
            if !zlp {
                self.complete(index, 0);
                return;
            }
            urb.zlp_owed = false;
        }
        let data: &[u8] = if is_in {
            &[]
        } else {
            &urb.out[urb.actual..urb.actual + len]
        };
        match pipe.begin(urb.ep, urb.xfer, len, data) {
            Ok(receipt) => {
                urb.posted_any = true;
                urb.state = State::InFlight { receipt, len };
            }
            Err(e) => {
                let ep = urb.ep;
                if halts(e) && !self.halted.contains(&ep) {
                    self.halted.push(ep);
                }
                self.complete(index, -errno(e));
            }
        }
    }

    /// Account a completed TD of `len` bytes that moved `n`.
    fn advance(&mut self, pipe: &dyn Pipe, index: usize, len: usize, n: usize, buf: &[u8]) {
        let urb = &mut self.pending[index];
        let is_in = urb.ep & 0x80 != 0;
        if is_in {
            urb.data.extend_from_slice(&buf[..n.min(buf.len())]);
        }
        urb.actual += n;
        urb.state = State::Queued;
        if is_in && n < len {
            // A short packet ends the transfer.
            let short = urb.actual < urb.length && urb.flags & URB_SHORT_NOT_OK != 0;
            self.complete(index, if short { -EREMOTEIO } else { 0 });
        } else if urb.actual >= urb.length && !urb.zlp_owed {
            self.complete(index, 0);
        } else {
            self.post(pipe, index);
        }
    }

    /// Drive every endpoint once: poll each posted TD, start the next TD
    /// or URB. Returns whether a reapable URB completed.
    pub fn pump(&mut self, pipe: &dyn Pipe) -> bool {
        let before = self.completed.len();
        let mut buf = alloc::vec![0u8; TD_MAX];
        // Two passes: a URB that completes lets the next one on its
        // endpoint start in the same call.
        for _ in 0..2 {
            let mut seen = 0u64;
            let mut i = 0;
            while i < self.pending.len() {
                let urb = &self.pending[i];
                let bit = 1u64 << (u32::from(urb.ep & 0x0f) | (u32::from(urb.ep & 0x80) >> 2));
                if seen & bit != 0 || self.halted.contains(&urb.ep) {
                    i += 1;
                    continue;
                }
                seen |= bit;
                let len_before = self.pending.len();
                match urb.state {
                    State::Queued => self.post(pipe, i),
                    State::InFlight { receipt, len } => match pipe.poll(receipt, &mut buf) {
                        Ok(None) => {}
                        Ok(Some(n)) => {
                            pipe.forget(receipt);
                            self.advance(pipe, i, len, n, &buf);
                        }
                        Err(e) => {
                            pipe.forget(receipt);
                            let ep = self.pending[i].ep;
                            if halts(e) && !self.halted.contains(&ep) {
                                self.halted.push(ep);
                            }
                            self.complete(i, -errno(e));
                        }
                    },
                    State::Stopping { .. } => {}
                }
                if self.pending.len() == len_before {
                    i += 1;
                }
            }
        }
        self.completed.len() != before
    }

    /// Start killing a URB (`usb_kill_urb`). A queued URB completes with
    /// `-ENOENT` at once; a posted TD is returned for the caller to stop.
    pub fn begin_kill(&mut self, index: usize) -> Option<Stop> {
        let urb = &mut self.pending[index];
        match urb.state {
            State::Queued => {
                let killed = self.finish_plain(index, -ENOENT);
                self.deliver(killed);
                None
            }
            State::InFlight { receipt, len } => {
                urb.state = State::Stopping { receipt, len };
                Some(Stop {
                    userurb: urb.userurb,
                    sync: urb.sync,
                    receipt,
                    len,
                })
            }
            State::Stopping { .. } => None,
        }
    }

    fn position(&self, stop: &Stop) -> Option<usize> {
        self.pending.iter().position(|u| {
            u.userurb == stop.userurb
                && u.sync == stop.sync
                && matches!(u.state, State::Stopping { receipt, .. } if receipt == stop.receipt)
        })
    }

    /// Finish a kill after [`Pipe::stop`] returned `stopped`. A TD that
    /// completed before the stop reached it keeps its real result.
    pub fn end_kill(&mut self, pipe: &dyn Pipe, stop: Stop, stopped: Result<(), UsbError>) {
        let Some(index) = self.position(&stop) else {
            pipe.forget(stop.receipt);
            return;
        };
        let status = match stopped {
            Ok(()) => -ENOENT,
            Err(e) => {
                let mut buf = alloc::vec![0u8; TD_MAX];
                match pipe.poll(stop.receipt, &mut buf) {
                    Ok(Some(n)) => {
                        let urb = &mut self.pending[index];
                        if urb.ep & 0x80 != 0 {
                            urb.data.extend_from_slice(&buf[..n.min(TD_MAX)]);
                        }
                        urb.actual += n;
                        if urb.actual >= urb.length || (urb.ep & 0x80 != 0 && n < stop.len) {
                            0
                        } else {
                            -ENOENT
                        }
                    }
                    _ => -errno(e),
                }
            }
        };
        pipe.forget(stop.receipt);
        let killed = self.finish_plain(index, status);
        self.deliver(killed);
    }

    /// Pending URBs matching `pred`, newest first (`destroy_async` walks
    /// `list_last_entry`).
    pub fn matching(&self, pred: impl Fn(&Urb) -> bool) -> Vec<usize> {
        let mut out: Vec<usize> = (0..self.pending.len())
            .filter(|&i| pred(&self.pending[i]))
            .collect();
        out.reverse();
        out
    }

    /// The pending URB `userurb` names.
    pub fn index_of(&self, userurb: u64) -> Option<usize> {
        self.pending
            .iter()
            .position(|u| u.sync == 0 && u.userurb == userurb)
    }

    /// The pending URB a sync ioctl owns.
    pub fn index_of_sync(&self, sync: u64) -> Option<usize> {
        self.pending.iter().position(|u| u.sync == sync)
    }

    /// The device went away: every pending URB completes with
    /// `-ESHUTDOWN`, as `usb_hcd_flush_endpoint` gives them back.
    pub fn flush(&mut self, pipe: &dyn Pipe) {
        while !self.pending.is_empty() {
            let urb = self.finish_plain(0, -ESHUTDOWN);
            if let State::InFlight { receipt, .. } | State::Stopping { receipt, .. } = urb.state {
                pipe.forget(receipt);
            }
            self.deliver(urb);
        }
        self.halted.clear();
    }

    /// Bytes still charged to every URB the engine holds.
    pub fn charged(&self) -> usize {
        self.pending
            .iter()
            .chain(self.completed.iter())
            .chain(self.sync_done.iter())
            .map(|u| u.charge)
            .sum()
    }
}
