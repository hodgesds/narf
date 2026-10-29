// SPDX-License-Identifier: GPL-2.0-or-later
//! N-deep native HTT TX ownership, keyed by MSDU ID.
//!
//! Linux v7.2 keeps every outstanding frame in `htt->pending_tx` (an IDR of
//! MSDU IDs, htt_tx.c::ath10k_htt_tx_alloc_msdu_id) and releases each one only
//! when its HTT TX completion indication names that ID
//! (htt_rx.c::ath10k_htt_rx_tx_compl_ind -> txrx.c::ath10k_txrx_tx_unref).
//! DMA ownership itself stays in `htt_runtime::tx::Pool`; this table owns the
//! station-data meaning of each ID: whether it is ordinary data (one TID) or a
//! supplicant key reply (M2/M4 or group 2/2), and when it must have completed.
//!
//! Key-reply fencing is explicit and two-sided:
//! * a reply is published only once every earlier data ID has reached its
//!   terminal indication (`reply_admissible`), so the reply's delivery is the
//!   single receive-admission/key epoch boundary;
//! * while a reply is in flight no data ID is admitted (`data_admissible`), and
//!   a reply receipt with a non-OK status fails the owner, as before.
//!
//! Data receipts never fail the owner: like Linux, NO_ACK/DISCARD/POSTPONE are
//! accounted (mac80211 sees them as un-ACKed frames) and the MSDU ID is freed.
use super::Error;
use crate::ath10k::htt_runtime as htt;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Station-data in-flight bound. The HTT pool (`Config::pending`, Linux
/// `htt->max_num_pending_tx`) is larger; this keeps per-TID aggregation depth
/// useful while bounding retained software-crypto payloads.
pub(super) const IN_FLIGHT: usize = 32;
const TIMEOUT_MS: u64 = 3000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    /// Ordinary data on an 802.11 TID (16 = non-QoS).
    Data { tid: u8 },
    /// A supplicant EAPOL reply; its receipt opens/rotates the key epoch.
    Reply,
}
#[derive(Debug)]
struct Entry {
    id: u16,
    role: Role,
    length: usize,
    deadline: narf_time::Deadline,
}
/// Terminal outcome of one native HTT ID (Linux `htt_tx_compl_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    Ack,
    NoAck,
    Discard,
}
impl Outcome {
    /// htt_rx.c::ath10k_htt_rx_tx_compl_ind status mapping.
    pub(super) fn from_status(status: u8) -> Self {
        match status {
            0 => Self::Ack,
            2 => Self::NoAck,
            _ => Self::Discard,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Completion {
    /// The ID is not station-data owned (management, or already retired).
    Foreign,
    Data {
        tid: u8,
        outcome: Outcome,
    },
    Reply {
        length: usize,
        outcome: Outcome,
    },
}
/// Per-TID terminal counters (index 8 = non-QoS).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TidCounters {
    pub acked: u64,
    pub no_ack: u64,
    pub discarded: u64,
}
#[derive(Debug)]
pub(super) struct Pipeline {
    entries: Vec<Entry>,
    counters: Box<[TidCounters; 9]>,
}
impl Pipeline {
    pub(super) fn new() -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(IN_FLIGHT)
            .map_err(|_| Error::NoMemory)?;
        Ok(Self {
            entries,
            counters: Box::new([TidCounters::default(); 9]),
        })
    }
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(super) fn reply_in_flight(&self) -> bool {
        self.entries.iter().any(|e| e.role == Role::Reply)
    }
    /// Another data ID may be published: room remains and no key reply
    /// is awaiting its terminal indication.
    pub(super) fn data_admissible(&self) -> bool {
        self.entries.len() < IN_FLIGHT && !self.reply_in_flight()
    }
    /// A key reply drains every earlier data ID first.
    pub(super) fn reply_admissible(&self) -> bool {
        self.entries.is_empty()
    }
    pub(super) fn expired(&self) -> bool {
        self.entries.iter().any(|e| e.deadline.expired())
    }
    /// Record a freshly published HTT ID. Admission was checked before the
    /// HTT publish; a duplicate ID means the DMA pool and this table diverged.
    pub(super) fn push(&mut self, id: u16, role: Role, length: usize) -> Result<(), Error> {
        let admissible = match role {
            Role::Data { .. } => self.entries.len() < IN_FLIGHT && !self.reply_in_flight(),
            Role::Reply => self.reply_admissible(),
        };
        if !admissible || self.entries.iter().any(|e| e.id == id) {
            return Err(Error::Failed);
        }
        self.entries.push(Entry {
            id,
            role,
            length,
            deadline: narf_time::Deadline::after_ms(TIMEOUT_MS),
        });
        Ok(())
    }
    /// Retire the ID named by one terminal HTT receipt.
    pub(super) fn complete(&mut self, receipt: htt::TxReceipt) -> Completion {
        let Some(at) = self.entries.iter().position(|e| e.id == receipt.id) else {
            return Completion::Foreign;
        };
        let entry = self.entries.swap_remove(at);
        let outcome = Outcome::from_status(receipt.status);
        match entry.role {
            Role::Data { tid } => {
                let c = &mut self.counters[usize::from(tid.min(8))];
                match outcome {
                    Outcome::Ack => c.acked += 1,
                    Outcome::NoAck => c.no_ack += 1,
                    Outcome::Discard => c.discarded += 1,
                }
                Completion::Data { tid, outcome }
            }
            Role::Reply => Completion::Reply {
                length: entry.length,
                outcome,
            },
        }
    }
    pub(super) fn counters(&self, tid: u8) -> TidCounters {
        self.counters[usize::from(tid.min(8))]
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn ids(&self) -> Vec<u16> {
        self.entries.iter().map(|e| e.id).collect()
    }
}
