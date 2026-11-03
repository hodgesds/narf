// SPDX-License-Identifier: GPL-2.0-or-later
//! Per-ifidx FullMAC transport demultiplexing shared by the SDIO-BCDC
//! (`cyw43439::runtime`) and PCIe-msgbuf (`brcmfmac::station_transport`)
//! transports.
//!
//! Interface 0 keeps its original queues and behaviour exactly; this owner
//! only holds records for secondary interfaces. It grants no role, link or
//! port authority: a secondary interface owner explicitly opens an ifidx
//! for data once its own link lifecycle allows it, and enables event
//! listening only while it waits on or owns secondary bsscfgs.
//!
//! Linux 7.3-rc4 sources mirrored here:
//! - `bcdc.c` `BCDC_GET_IF_IDX`/`BCDC_SET_IF_IDX` (BDC `flags2` low nibble)
//!   and `brcmf_proto_bcdc_hdrpull`, which drops (`-EBADE`) data for an ifidx
//!   without a registered `brcmf_if` instead of failing the bus;
//! - `bcdc.c::brcmf_proto_bcdc_msg` (`BCDC_DCMD_IF_SHIFT` ioctl ifidx);
//! - `msgbuf.c` per-(ifidx, tid, da) flow rings
//!   (`brcmf_msgbuf_flowring_create_worker` `create->msg.ifidx`) and
//!   `brcmf_msgbuf_process_rx_complete`/`brcmf_msgbuf_process_event`, which
//!   drop records whose ifidx has no `brcmf_if`;
//! - `fweh.c::brcmf_fweh_event_worker`: `BRCMF_E_IF` is handled specially
//!   regardless of the header indices, every other event dispatches to
//!   `iflist[emsg.bsscfgidx]`.
use crate::{
    brcmfmac::vif_wire::{E_IF, MAX_IFS},
    cyw43439::runtime::Event,
};
use alloc::{collections::VecDeque, vec::Vec};

/// Bound for both the secondary event queue and the secondary data queue.
pub const QUEUE_DEPTH: usize = 32;

/// Where a decoded firmware event belongs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// Unchanged interface-0 station/AP event queue.
    Primary,
    /// `BRCMF_E_IF` or a secondary-bsscfg event.
    Secondary,
    /// Indices outside `BRCMF_MAX_IFS` (`fweh.c` rejects the bsscfg).
    Invalid,
}

/// Classify one event header. Interface-0 events keep their original
/// route; `BRCMF_E_IF` always belongs to the interface owner, as Linux
/// handles it before any per-bsscfg dispatch.
pub fn route(event_type: u32, if_idx: u8, bsscfg_idx: u8) -> Route {
    if if_idx >= MAX_IFS || bsscfg_idx >= MAX_IFS {
        Route::Invalid
    } else if event_type == E_IF {
        Route::Secondary
    } else if if_idx == 0 && bsscfg_idx == 0 {
        Route::Primary
    } else {
        Route::Secondary
    }
}

/// Secondary-interface record owner held inside one transport generation.
#[derive(Debug, Default)]
pub struct Demux {
    listening: bool,
    open: u16,
    events: VecDeque<Event>,
    data: VecDeque<(u8, Vec<u8>)>,
    dropped: usize,
}

/// Secondary event queue overflowed while an owner was listening. The
/// transport treats this like its primary event overflow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Overflow;

impl Demux {
    pub const fn new() -> Self {
        Self {
            listening: false,
            open: 0,
            events: VecDeque::new(),
            data: VecDeque::new(),
            dropped: 0,
        }
    }
    /// Enable/disable secondary event retention. Disabling purges every
    /// queued secondary event; a later listener never sees stale records.
    pub fn listen(&mut self, on: bool) {
        self.listening = on;
        if !on {
            self.events.clear();
        }
    }
    pub fn is_listening(&self) -> bool {
        self.listening
    }
    /// Admit data for one secondary ifidx (1..`MAX_IFS`).
    pub fn open(&mut self, ifidx: u8) -> Result<(), crate::cyw43439::runtime::Error> {
        if ifidx == 0 || ifidx >= MAX_IFS {
            return Err(crate::cyw43439::runtime::Error::Malformed);
        }
        self.open |= 1 << ifidx;
        Ok(())
    }
    /// Stop admitting data for `ifidx` and discard what was queued for it.
    pub fn close(&mut self, ifidx: u8) {
        if ifidx == 0 || ifidx >= MAX_IFS {
            return;
        }
        self.open &= !(1 << ifidx);
        self.data.retain(|(index, _)| *index != ifidx);
    }
    pub fn is_open(&self, ifidx: u8) -> bool {
        ifidx != 0 && ifidx < MAX_IFS && self.open & (1 << ifidx) != 0
    }
    pub fn any_open(&self) -> bool {
        self.open != 0
    }
    /// Retain a secondary event only while an owner listens; otherwise it
    /// is dropped, as Linux drops events for a bsscfg without `brcmf_if`.
    pub fn push_event(&mut self, event: Event) -> Result<(), Overflow> {
        if !self.listening {
            self.dropped += 1;
            return Ok(());
        }
        if self.events.len() == QUEUE_DEPTH {
            return Err(Overflow);
        }
        self.events.push_back(event);
        Ok(())
    }
    /// Retain a secondary received frame only for an open ifidx; a full
    /// queue drops the frame (no head-of-line authority over ifidx 0).
    pub fn push_data(&mut self, ifidx: u8, frame: Vec<u8>) {
        if !self.is_open(ifidx) || self.data.len() == QUEUE_DEPTH {
            self.dropped += 1;
            return;
        }
        self.data.push_back((ifidx, frame));
    }
    pub fn pop_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
    pub fn pop_data(&mut self, ifidx: u8) -> Option<Vec<u8>> {
        let position = self.data.iter().position(|(index, _)| *index == ifidx)?;
        self.data.remove(position).map(|(_, frame)| frame)
    }
    /// Queued (not yet consumed) secondary events.
    pub fn events(&self) -> impl Iterator<Item = &Event> {
        self.events.iter()
    }
    pub fn has_events_for(&self, ifidx: u8) -> bool {
        self.events.iter().any(|event| event.header.if_idx == ifidx)
    }
    pub fn has_data_for(&self, ifidx: u8) -> bool {
        self.data.iter().any(|(index, _)| *index == ifidx)
    }
    pub fn has_data(&self) -> bool {
        !self.data.is_empty()
    }
    pub fn dropped(&self) -> usize {
        self.dropped
    }
    /// Transport failure/stop: no secondary record survives a generation.
    pub fn clear(&mut self) {
        self.listening = false;
        self.open = 0;
        self.events.clear();
        self.data.clear();
    }
}
