//! Copy-time management capture, separate from home station/AP port epochs.
//! The native owner separately proves actual started WDEV and CNM/source
//! authority before opening this observation and again before delivery.
use super::{Error, RadioInfo};
use crate::mt7921::{
    p2p_cnm::{Lease, Phase},
    vif_slots::Vif,
};
use alloc::{collections::VecDeque, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
const QUEUE_LIMIT: usize = 32;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Spec {
    pub epoch: u64,
    pub filters: u64,
    pub cookie: u64,
    pub frequency_mhz: u32,
    pub expires_ns: u64,
    pub local: [u8; 6],
    pub vif: Vif,
    pub nss: u8,
}
impl Spec {
    pub fn prepare(
        info: RadioInfo,
        vif: Vif,
        local: [u8; 6],
        filters: u64,
        lease: &Lease,
        now_ns: u64,
    ) -> Result<Self, Error> {
        let Phase::Granted { expires_ns, .. } = lease.phase else {
            return Err(Error::Busy);
        };
        if filters == 0
            || lease.cookie == 0
            || now_ns >= expires_ns
            || local == [0; 6]
            || local[0] & 1 != 0
            || !(1..=2).contains(&info.capabilities.phy.spatial_streams)
        {
            return Err(Error::Bounds);
        }
        let epoch = NEXT_EPOCH
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::EventOverflow)?;
        Ok(Self {
            epoch,
            filters,
            cookie: lease.cookie,
            frequency_mhz: lease.frequency_mhz,
            expires_ns,
            local,
            vif,
            nss: info.capabilities.phy.spatial_streams,
        })
    }
}
#[derive(Debug)]
pub(super) struct Captured {
    pub spec: Spec,
    pub packet: Vec<u8>,
}
#[derive(Debug)]
pub(super) struct Queue {
    spec: Option<Spec>,
    pending: VecDeque<Captured>,
}
impl Queue {
    pub fn new() -> Self {
        Self {
            spec: None,
            pending: VecDeque::new(),
        }
    }
    pub fn close(&mut self) {
        self.spec = None;
        self.pending.clear();
    }
    /// Call only AFTER draining every finite already-completed native ring
    /// prefix with capture closed. No old host queue acquires a new epoch.
    pub fn open_after_cut(&mut self, spec: Spec, now_ns: u64) -> Result<(), Error> {
        if self.spec.is_some() || spec.epoch == 0 || now_ns >= spec.expires_ns {
            return Err(Error::Busy);
        }
        self.spec = Some(spec);
        Ok(())
    }
    /// Invoked at the actual RX descriptor copy, before ordinary routing or
    /// command waits. The caller still owns the real native DMA/device cap.
    pub fn copy(&mut self, packet: &[u8], now_ns: u64) {
        let Some(spec) = self.spec.filter(|spec| now_ns < spec.expires_ns) else {
            return;
        };
        if super::p2p_management_wire::received(packet, spec.nss, spec.local, spec.frequency_mhz)
            .is_none()
        {
            return;
        }
        if self.pending.len() == QUEUE_LIMIT {
            self.pending.pop_front();
        }
        self.pending.push_back(Captured {
            spec,
            packet: packet.to_vec(),
        });
    }
    pub fn pop(&mut self) -> Option<Captured> {
        self.pending.pop_front()
    }
}
