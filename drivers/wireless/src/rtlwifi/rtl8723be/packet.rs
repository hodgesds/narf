// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8723BE packet owner: TX descriptor fill, RX descriptor query, RX
//! C2H dispatch, station-owner notify calls, and packet-path admission.
//!
//! Linux `rtl8723be/trx.c` (`rtl8723be_tx_fill_desc`,
//! `rtl8723be_rx_query_desc`) over the `trx.h` layouts, as already
//! ported in [`super::trx`]. Descriptor field positions below are the
//! `trx.rs` fill rules; every value the fill programs is one Linux
//! sets on the same path.
//!
//! ## Admission (fail-closed)
//!
//! [`Owner`] can only be built from a successful firmware download
//! (`firmware_transport::Info`, obtainable only from `run_8723be`)
//! plus a [`super::envelope::Permission`] and the matching
//! [`super::channel::Grant`] for the operating point (same board
//! identity, same primary channel / width / prime sub-carrier).
//! Transmit goes through [`Owner::fill_tx_slot`], which refuses
//! unless the frame's operating point equals the permission's point
//! and the rate is admitted by the permission. There is deliberately
//! NO per-packet BT rejection: Linux's
//! `rtl8723be_dm_bt_reject_ap_aggregated_packet` path is not a
//! per-packet gate in the retained driver, so inventing one would be
//! fabrication — coexistence acts through the periodical decision and
//! the DM primitives (`coex.rs`), not per packet.
//!
//! ## RX C2H dispatch (BE has no firmware-event mailbox)
//!
//! The 8723AE-only `REG_C2HEVT_MSG_NORMAL` mailbox drain does NOT
//! apply here. On this chip a C2H packet arrives as an RX buffer whose
//! status has `rpt_sel` set (`pci.c` RX → `rtl_c2hcmd_enqueue` →
//! `base.c::rtl_c2h_content_parsing`). [`Owner::service_rx`] is that
//! dispatch: a delivered RX descriptor with the C2H bit has its
//! payload enqueued on the owner's C2H queue and drained through
//! [`super::coex::Owner::c2h`]; TX reports are returned to the caller
//! (the packet owner does not own TX-report handling), everything else
//! is consumed. The owner implements [`super::btc::C2hSource`] over
//! that queue, so the coexistence MP wait (`RxBtMp`) runs over the
//! real RX C2H stream instead of `NoC2h` — non-MP packets the wait
//! meets are deferred back into the queue and drained by the outer
//! loop, so none is lost.
//!
//! Termination of the drain loop: each iteration pops one packet and
//! dispatches it; a dispatch's MP wait only defers packets it meets
//! while polling, and a deferred packet, when outer-dispatched, meets
//! an empty-or-MP-only queue on its own wait. No packet is ever
//! re-enqueued by its own dispatch, so the loop ends with the queue
//! empty. The queue is empty between `service_rx` calls by the same
//! argument.
//!
//! ## Single-segment scope
//!
//! This pass fills single-MPDU descriptors only (`firstseg` +
//! `lastseg`, no fragmentation, no AMPDU aggregation). Multi-segment
//! / AMPDU aggregation, RDG + HTC for QoS data, LPS hardware sequence
//! numbers, encryption `sectype`, TX-report requests, and multi-station
//! rate-id / MAC-id are remainders for the station owner. Ring-slot
//! allocation, descriptor-ring base programming, the doorbell, and
//! OWN publication stay with the caller: this module fills a
//! caller-provided [`super::trx::TxDesc`] (OWN left clear, as
//! `trx::TxDesc::fill` leaves it) and the future
//! `Prepared::Chip::Rtl8723be` packet path owns the rings. No
//! `Prepared` signature changes in this lane (see the census in the
//! PR body).
//!
//! ## Rate numbering
//!
//! Descriptor `hw_rate` values are the `def.h` `DESC92C_RATE*` codes
//! (1M `0x00` … 54M `0x0b`, MCS0-7 continuing at `0x0c`), which is
//! exactly the envelope's full-order rate numbering (CCK 0..3, OFDM
//! 4..11, HT MCS0-7 12..19) — so
//! [`super::envelope::Permission::admits`] gates the descriptor rate
//! directly.

use super::btc::{C2hSource, C2H_MAX};
use super::channel::Grant;
use super::coex::{self, C2h as CoexC2h};
use super::envelope::{Operating, Permission};
use super::trx::{self, RxStatus, TxDesc, TxParams};
use crate::rtlwifi::firmware_transport::{Info, Io};
use crate::rtlwifi::prepare::Error as PrepareError;
use alloc::collections::VecDeque;

/// Frame class for the firmware queue-select mapping
/// (`_rtl8723be_map_hwqueue_to_fwqueue`: beacon → `QSLT_BEACON`,
/// management / control → `QSLT_MGNT`, data → priority).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameClass {
    /// Beacon frame.
    Beacon,
    /// Management frame.
    Mgmt,
    /// Control frame.
    Ctl,
    /// Data frame with 802.11d priority (TID) 0..7.
    Data {
        /// Traffic identifier / priority.
        priority: u8,
    },
}

impl FrameClass {
    /// Firmware queue selector for the class.
    pub const fn queue_sel(self) -> u8 {
        match self {
            FrameClass::Beacon => trx::QSLT_BEACON,
            FrameClass::Mgmt | FrameClass::Ctl => trx::QSLT_MGNT,
            FrameClass::Data { priority } => priority & 7,
        }
    }
}

/// RTS/CTS parameters for a TX descriptor (`ptcb_desc` RTS fields).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rts {
    /// `rts_enable && !cts_enable` → `rts_en`.
    pub rts_enable: bool,
    /// `rts_enable || cts_enable` → `hwrts_en`.
    pub cts_enable: bool,
    /// Short preamble (legacy RTS rate) / short GI (HT RTS rate):
    /// `trx::TxDesc::fill` selects by the RTS rate, so one flag
    /// covers both.
    pub rts_short: bool,
    /// `rts_rate` (descriptor rate code).
    pub rts_rate: u8,
    /// `rts_sc` (sub-carrier).
    pub rts_sc: u8,
}

/// One single-MPDU TX frame to fill a descriptor for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxFrame {
    /// Operating point the frame transmits on (must equal the
    /// permission's point).
    pub op: Operating,
    /// Frame class (queue selector).
    pub class: FrameClass,
    /// Payload length in bytes (packet size and buffer size).
    pub len: usize,
    /// DMA address of the payload buffer (32-bit; `trx.h` dword 10).
    pub buf_addr: u32,
    /// Descriptor rate code (full-order rate, see the module docs).
    pub rate: u8,
    /// Sequence number (`seq_ctrl >> 4`, 12 bits).
    pub seq: u16,
    /// `use_shortgi || use_shortpreamble` → the short bit:
    /// `trx::TxDesc::fill` selects short-GI above `DESC92C_RATEMCS0`,
    /// short preamble at or below it.
    pub short: bool,
    /// Whether the destination address is multicast / broadcast
    /// (`bmc` bit; Linux derives it from the frame DA).
    pub bmc: bool,
    /// RTS/CTS parameters, or `None` for no RTS/CTS.
    pub rts: Option<Rts>,
    /// Next descriptor address for the ring link (dword 12); 0
    /// terminates.
    pub next_desc: u32,
}

/// Packet-path error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No firmware admission, no envelope permission, or a
    /// permission / grant mismatch for the operating point / rate.
    NotAdmitted,
    /// Frame length invalid (zero or wider than the 16-bit size
    /// fields), or a descriptor / buffer pair that cannot hold the
    /// payload.
    Frame,
    /// The RX descriptor is still hardware-owned (`RxStatus::parse`
    /// returned `None`); the caller must not service the slot yet.
    NotReady,
    /// Register access failed while servicing RX / coexistence.
    Access,
}

impl From<PrepareError> for Error {
    fn from(_: PrepareError) -> Self {
        Error::Access
    }
}

/// Outcome of servicing one delivered RX descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RxOutcome<'a> {
    /// Normal frame: status plus the payload slice (from
    /// [`RxStatus::payload_offset`]; for data frames the slice still
    /// carries the trailing FCS, which the caller strips).
    Frame {
        /// Decoded RX status.
        status: RxStatus,
        /// Payload bytes (C2H packets: the whole packet).
        payload: &'a [u8],
    },
    /// C2H TX report, returned to the caller: the packet owner does
    /// not own TX-report handling.
    TxReport {
        /// `rtl_tx_report_handler` sequence number (`sw_define`).
        sn: u16,
        /// Report status (`st == 0` means acknowledged).
        st: u8,
        /// Retry count.
        retry: u8,
    },
    /// C2H consumed by coexistence or ignored (RA report, debug,
    /// TXBF, unknown ids).
    Consumed,
}

/// The owner's RX C2H queue: the `C2hSource` the coexistence MP wait
/// polls. Packets are `(length, bytes)` with `length <= C2H_MAX`;
/// longer RX C2H payloads are truncated to the command buffer
/// `rtl_c2h_content_parsing` reads (see `btc::C2H_MAX`).
#[derive(Debug, Default)]
pub struct C2hQueue {
    queue: VecDeque<(usize, [u8; C2H_MAX])>,
}

impl C2hQueue {
    /// Number of packets currently queued (0 between `service_rx`
    /// calls, by the drain-loop invariant).
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Enqueue one RX C2H payload, truncated to [`C2H_MAX`].
    pub(crate) fn push(&mut self, packet: &[u8]) {
        let n = packet.len().min(C2H_MAX);
        let mut buf = [0u8; C2H_MAX];
        buf[..n].copy_from_slice(&packet[..n]);
        self.queue.push_back((n, buf));
    }

    /// Pop the oldest queued packet.
    pub(crate) fn pop(&mut self) -> Option<(usize, [u8; C2H_MAX])> {
        self.queue.pop_front()
    }
}

impl C2hSource for C2hQueue {
    fn poll_c2h(&mut self, out: &mut [u8; C2H_MAX]) -> Result<Option<usize>, PrepareError> {
        match self.pop() {
            Some((n, buf)) => {
                out[..n].copy_from_slice(&buf[..n]);
                Ok(Some(n))
            }
            None => Ok(None),
        }
    }

    fn defer_c2h(&mut self, packet: &[u8]) -> Result<(), PrepareError> {
        self.push(packet);
        Ok(())
    }
}

/// The BE packet owner: firmware admission + envelope permission +
/// channel grant, over the RX C2H queue. The coexistence owner is
/// held by the station owner (via `Prepared`) and passed to the
/// methods that need it, so this owner never aliases it.
#[derive(Debug)]
pub struct Owner {
    /// Firmware download result (proof of admission).
    firmware: Info,
    /// Admitted operating point + rates for this board.
    permission: Permission,
    /// Admitted channel grant for the operating point.
    grant: Grant,
    /// RX C2H queue (the `C2hSource` for coexistence).
    queue: C2hQueue,
}

impl Owner {
    /// Admit a packet owner: only a successful `run_8723be` result
    /// plus a minted envelope permission and the grant minted from
    /// that permission's operating point can construct one. A
    /// permission / grant mismatch (different board identity, or a
    /// grant whose wide channel / width / prime sub-carrier does not
    /// match the permission's primary channel / width) is refused.
    pub fn admit(firmware: Info, permission: Permission, grant: Grant) -> Result<Self, Error> {
        let op = permission.operating();
        let shape = permission.identity() == grant.identity()
            && grant.forty() == op.forty()
            && grant.channel() == op.grant_channel().ok_or(Error::NotAdmitted)?
            && grant.prime_sc() == op.grant_prime_sc();
        if !shape {
            return Err(Error::NotAdmitted);
        }
        Ok(Self {
            firmware,
            permission,
            grant,
            queue: C2hQueue::default(),
        })
    }

    /// Firmware version admitted (for logging / diagnostics).
    pub fn firmware_version(&self) -> u16 {
        self.firmware.version
    }

    /// The admitted permission.
    pub fn permission(&self) -> Permission {
        self.permission
    }

    /// The admitted channel grant.
    pub fn grant(&self) -> Grant {
        self.grant
    }

    /// Queued RX C2H packets (0 between `service_rx` calls).
    pub fn c2h_queued(&self) -> usize {
        self.queue.len()
    }

    /// Admission gate: the operating point must equal the permission's
    /// point and the rate must be admitted by the permission.
    pub fn admit_tx(&self, op: Operating, rate: u8) -> Result<(), Error> {
        if op != self.permission.operating() || !self.permission.admits(rate) {
            return Err(Error::NotAdmitted);
        }
        Ok(())
    }

    /// Fill a TX descriptor for an admitted frame; refused before
    /// any descriptor byte is written when admission fails or the
    /// length is invalid. OWN is left clear: the caller publishes
    /// the slot after the payload buffer is visible, and sets the
    /// ring link from `tx.next_desc` (written here).
    pub fn fill_tx_slot(&self, slot: &mut TxDesc, tx: &TxFrame) -> Result<(), Error> {
        self.admit_tx(tx.op, tx.rate)?;
        if tx.len == 0 || tx.len > 0xffff {
            return Err(Error::Frame);
        }
        let (rts_enable, cts_enable, rts_rate, rts_sc, rts_short) = match tx.rts {
            Some(r) => (
                r.rts_enable,
                r.cts_enable,
                r.rts_rate,
                r.rts_sc,
                r.rts_short,
            ),
            None => (false, false, 0, 0, false),
        };
        let forty = self.grant.forty();
        *slot = TxDesc::fill(&TxParams {
            pkt_size: tx.len as u16,
            queue_sel: tx.class.queue_sel(),
            // Single-station pass 1: no RA mask programmed, so the
            // descriptor rate is driver-chosen (`use_driver_rate`)
            // and the rate id / MAC id are 0.
            macid: 0,
            rate_id: 0,
            hw_rate: tx.rate,
            use_driver_rate: true,
            disable_fallback: false,
            use_shortgi: tx.short,
            use_shortpreamble: tx.short,
            bw_40: forty,
            // The frame transmits on the grant's operating point, so
            // the packet bandwidth always equals the station width.
            packet_bw_40: forty,
            cur_40_prime_sc: self.grant.prime_sc(),
            ampdu: false,
            ampdu_density: 0,
            // No security offload in pass 1.
            sec_type: 0,
            qos_data: matches!(tx.class, FrameClass::Data { .. }),
            seq: tx.seq,
            multicast: tx.bmc,
            rts_enable,
            cts_enable,
            rts_rate,
            rts_sc,
            rts_use_shortpreamble: rts_short,
            rts_use_shortgi: rts_short,
            tx_report: None,
            buffer_len: tx.len as u16,
            buffer_addr: tx.buf_addr,
        });
        slot.set_next(tx.next_desc);
        Ok(())
    }

    /// The RX dispatch (step-2 item (a)): decode one delivered RX
    /// descriptor from its ring slot (`dw`) against its buffer. A
    /// hardware-owned slot is [`Error::NotReady`]. A normal frame is
    /// returned with its payload slice for the caller to deliver. A
    /// C2H payload is enqueued and drained through the coexistence
    /// owner; the first TX report met during the drain is returned
    /// (the drain still runs to completion), everything else is
    /// consumed.
    pub async fn service_rx<'a, I: Io>(
        &mut self,
        io: &I,
        coex: &mut coex::Owner,
        dw: &[u32; 8],
        buffer: &'a [u8],
    ) -> Result<RxOutcome<'a>, Error> {
        let status = RxStatus::parse(dw).ok_or(Error::NotReady)?;
        let offset = status.payload_offset();
        let end = offset
            .saturating_add(usize::from(status.length))
            .min(buffer.len());
        let payload = buffer.get(offset..end).ok_or(Error::Frame)?;
        if !status.c2h {
            return Ok(RxOutcome::Frame { status, payload });
        }
        self.queue.push(payload);
        let mut report = None;
        while let Some((n, pkt)) = self.queue.pop() {
            if let Some(r) = Self::dispatch_c2h(io, coex, &mut self.queue, &pkt[..n]).await? {
                report = report.or(Some(r));
            }
        }
        Ok(match report {
            Some((sn, st, retry)) => RxOutcome::TxReport { sn, st, retry },
            None => RxOutcome::Consumed,
        })
    }

    /// One C2H packet through the coexistence owner, with the
    /// owner's queue as the MP-wait source. Returns the TX report,
    /// if the packet was one.
    async fn dispatch_c2h<I: Io>(
        io: &I,
        coex: &mut coex::Owner,
        queue: &mut C2hQueue,
        packet: &[u8],
    ) -> Result<Option<(u16, u8, u8)>, Error> {
        Ok(match coex.c2h(io, queue, packet).await? {
            CoexC2h::TxReport { sn, st, retry } => Some((sn, st, retry)),
            CoexC2h::Coex | CoexC2h::Other => None,
        })
    }

    /// `btc_ips_notify` (`ps.c:239/284`) through the coexistence owner.
    pub async fn ips<I: Io>(
        &mut self,
        io: &I,
        coex: &mut coex::Owner,
        rf_off: bool,
    ) -> Result<(), Error> {
        coex.ips(io, &mut self.queue, rf_off).await?;
        Ok(())
    }

    /// `rtl_lps_set_psmode(EACTIVE)` (`ps.c:368`) through the
    /// coexistence owner. Returns the `SETPWRMODE` body sent.
    pub async fn lps_leave<I: Io>(
        &mut self,
        io: &I,
        coex: &mut coex::Owner,
    ) -> Result<Option<[u8; 7]>, Error> {
        Ok(coex.lps_leave(io).await?)
    }

    /// `rtl_lps_set_psmode(EAUTOPS)` (`ps.c:375`) through the
    /// coexistence owner. Returns the `SETPWRMODE` body sent.
    pub async fn lps_enter<I: Io>(
        &mut self,
        io: &I,
        coex: &mut coex::Owner,
    ) -> Result<Option<[u8; 7]>, Error> {
        Ok(coex.lps_enter(io).await?)
    }

    /// `btc_scan_notify` (`core.c:1425/1478`) through the coexistence
    /// owner.
    pub async fn scan<I: Io>(
        &mut self,
        io: &I,
        coex: &mut coex::Owner,
        start: bool,
    ) -> Result<(), Error> {
        coex.scan(io, &mut self.queue, start).await?;
        Ok(())
    }

    /// `exhalbtc_connect_notify` (association start / finish) through
    /// the coexistence owner.
    pub async fn connect<I: Io>(
        &mut self,
        io: &I,
        coex: &mut coex::Owner,
        start: bool,
    ) -> Result<(), Error> {
        coex.connect(io, &mut self.queue, start).await?;
        Ok(())
    }

    /// `btc_mediastatus_notify` (`core.c:1181`, `BSS_CHANGED_ASSOC`)
    /// through the coexistence owner.
    pub async fn media_status<I: Io>(
        &mut self,
        io: &I,
        coex: &mut coex::Owner,
        connect: bool,
    ) -> Result<(), Error> {
        coex.media_status(io, &mut self.queue, connect).await?;
        Ok(())
    }

    /// `setup_special_tx` (`base.c:1455`) through the coexistence
    /// owner; the caller then runs [`Self::lps_leave`].
    pub async fn special_packet<I: Io>(
        &mut self,
        io: &I,
        coex: &mut coex::Owner,
        pkt: crate::rtlwifi::btcoex::btc::Packet,
    ) -> Result<(), Error> {
        coex.special_packet(io, &mut self.queue, pkt).await?;
        Ok(())
    }

    /// `base.c:1539`: an EAPOL frame (either direction) marks `in_4way`.
    pub fn eapol(&mut self, coex: &mut coex::Owner, now_ms: u64) {
        coex.eapol(now_ms);
    }

    /// `rtl_watchdog_wq_callback` (`base.c:2205`) through the
    /// coexistence owner. Returns whether the watchdog ran.
    pub async fn watchdog<I: Io>(
        &mut self,
        io: &I,
        coex: &mut coex::Owner,
        now_ms: u64,
    ) -> Result<bool, Error> {
        Ok(coex.watchdog(io, &mut self.queue, now_ms).await?)
    }
}
