//! Native Qu/API77 Block Ack ownership. TLC43 owns TX negotiation/retries;
//! recipient agreements use ADD_STA48 or BAID_ML_SUPPORT CONFIG v1/v2,
//! with the same host reorder and retirement owner (Linux mvm/sta.c).
use super::super::{boot_context::put16, scan_api};
use super::{Owner, Phase};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::sync::atomic::AtomicUsize;
use narf_wireless::{reg::RegulatoryDomain, reorder::Reorder};

#[path = "mvm_ba_bundle.rs"]
mod bundle;
use bundle::{Bundle, Partial, Raw};
#[path = "mvm_baid.rs"]
mod baid;

const TIDS: usize = 8;
const WINDOW: u16 = 32;
pub(super) const PIPELINE: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Request {
    token: u8,
    tid: u8,
    window: u16,
    ssn: u16,
    timeout: u16,
    original_parameters: u16,
    nested: bool,
}
struct Session {
    request: Request,
    baid: Option<u8>,
    active: bool,
    queues: Vec<Queue>,
    last_rx: u64,
}
struct Queue {
    reorder: Reorder<Bundle>,
    partial: Option<Partial>,
}
impl Queue {
    fn new(request: Request) -> Result<Self, &'static str> {
        let mut reorder = Reorder::new(request.window as u8, 100_000_000)
            .map_err(|_| "MVM BA physical queue window")?;
        reorder
            .advance(request.ssn, now())
            .map_err(|_| "MVM BA physical queue seed")?;
        Ok(Self {
            reorder,
            partial: None,
        })
    }
}
#[derive(Clone, Copy)]
enum Work {
    Add(Request),
    Remove(u8, bool),
    RejectBar(u8),
}
#[derive(Default)]
pub(super) struct Context {
    pub selected: bool,
    pub nested_selected: bool,
    pub tx_enabled: bool,
    sessions: Vec<Session>,
    work: VecDeque<Work>,
    ready: VecDeque<Bundle>,
    draining: Option<Bundle>,
    raw_bytes: Arc<AtomicUsize>,
}
fn now() -> u64 {
    narf_time::wall::cycles_to_ns(narf_time::now_cycles())
}
fn permission(enabled: bool) -> [u8; 48] {
    let mut b = [0; 48];
    b[0] = 1;
    b[17] = 2;
    put16(&mut b, 2, if enabled { 0xfffe } else { 0xffff });
    b
}
fn response(request: Request, status: u16) -> [u8; 9] {
    let mut body = super::super::aggregation::add_response(
        request.token,
        request.tid,
        request.window,
        request.timeout,
        status,
    );
    // mac80211/agg-rx.c::ieee80211_send_addba_resp. Tag4 further
    // restricts this local ability to an explicitly requesting originator.
    if status == 0 && request.nested {
        body[5] |= 1;
    }
    body
}
fn status(b: &[u8]) -> Result<u32, &'static str> {
    if b.len() != 4 {
        return Err("MVM BA station receipt extent");
    }
    let s = u32::from_le_bytes(b.try_into().unwrap());
    if s & 255 != 1 {
        return Err("MVM BA station receipt rejected");
    }
    Ok(s)
}
impl Context {
    pub fn needs_work(&self) -> bool {
        !self.work.is_empty()
    }
    pub fn clear_packets(&mut self) {
        self.ready.clear();
        self.draining = None;
        for s in &mut self.sessions {
            for queue in &mut s.queues {
                queue.reorder.clear();
                queue.partial = None;
            }
            s.active = false;
        }
    }
    pub fn cancel_incomplete(&mut self) {
        for s in &mut self.sessions {
            for queue in &mut s.queues {
                queue.partial = None;
            }
        }
    }
    pub fn cancel_queue(&mut self, queue: u8) {
        for session in &mut self.sessions {
            if let Some(rx) = session.queues.get_mut(usize::from(queue)) {
                rx.partial = None;
            }
        }
    }
    pub fn pop(&mut self) -> Option<(u8, Option<u64>, Vec<u8>)> {
        loop {
            if self.draining.as_ref().is_none_or(|b| b.0.is_empty()) {
                self.draining = self.ready.pop_front();
            }
            let bundle = self.draining.as_mut()?;
            let raw = bundle.0.pop_front()?;
            if scan_api::mpdu_gen2(raw.bytes()).is_some_and(|m| {
                self.sessions
                    .iter()
                    .any(|s| s.active && s.baid == Some(((m.reorder >> 24) & 127) as u8))
            }) {
                return Some(raw.into_capture());
            }
        }
    }
    pub fn qos_policy(&self, qos: u8, reorder: u32) -> bool {
        qos & 15 < 8
            && match qos & 0x70 {
                0 => true,
                0x60 => self.sessions.iter().any(|s| {
                    s.active
                        && s.request.tid == qos & 15
                        && s.baid == Some(((reorder >> 24) & 127) as u8)
                }),
                _ => false,
            }
    }
    fn append(&mut self, frames: Vec<Bundle>) -> Result<(), &'static str> {
        if self.ready.len() + frames.len() > 3 * TIDS * usize::from(WINDOW) {
            return Err("MVM BA released packet bound");
        }
        self.ready.extend(frames);
        Ok(())
    }
    pub fn observe(
        &mut self,
        queue: u8,
        epoch: Option<u64>,
        bytes: &[u8],
        local: [u8; 6],
    ) -> Result<(), &'static str> {
        let Some(m) = scan_api::mpdu_gen2(bytes) else {
            self.cancel_incomplete();
            return Ok(());
        };
        let baid = ((m.reorder >> 24) & 127) as u8;
        let Some(index) = self
            .sessions
            .iter()
            .position(|s| s.active && s.baid == Some(baid))
        else {
            return Ok(());
        };
        let s = &mut self.sessions[index];
        let Some(rx) = s.queues.get_mut(usize::from(queue)) else {
            return Err("MVM BA physical queue absent");
        };
        let f = m.frame;
        if f.len() < 26
            || f[0] != 0x88
            || f[4] & 1 != 0
            || f[4..10] != local
            || f[24] & 15 != s.request.tid
            || f[24] & 0x10 != 0 && f[1] & 0x80 == 0
            || !matches!(f[24] & 0x60, 0 | 0x60)
            || f[25] != 0
            || (f[24] & 0x80 != 0) != m.amsdu
            || m.amsdu && !s.request.nested
            || m.reorder >> 31 != 0
            || f[22] & 15 != 0
        {
            rx.partial = None;
            return Ok(());
        }
        let sn = u16::from_le_bytes([f[22], f[23]]) >> 4;
        if sn != ((m.reorder >> 12) & 4095) as u16 {
            rx.partial = None;
            return Ok(());
        }
        let clock = now();
        let raw = Raw::captured(bytes, &self.raw_bytes, queue, epoch)?;
        let complete = if m.amsdu {
            let Some(complete) = bundle::capture(&mut rx.partial, &m, raw, clock) else {
                return Ok(());
            };
            complete
        } else {
            rx.partial = None;
            Bundle::one(raw)
        };
        let mut frames = rx
            .reorder
            .push(sn, clock, complete)
            .map_err(|_| "MVM BA reorder insertion")?;
        frames.extend(
            rx.reorder
                .advance((m.reorder & 4095) as u16, clock)
                .map_err(|_| "MVM BA NSSN")?,
        );
        s.last_rx = clock;
        if rx
            .partial
            .as_ref()
            .is_some_and(|p| p.passed(rx.reorder.head().unwrap()))
        {
            rx.partial = None;
        }
        self.append(frames)
    }
    pub fn release(&mut self, queue: u8, command: u8, bytes: &[u8]) -> Result<(), &'static str> {
        let (baid, tid, nssn) = match command {
            0xc3 if bytes.len() == 4 && bytes[1] == 0 => {
                (bytes[0], None, u16::from_le_bytes([bytes[2], bytes[3]]))
            }
            0xc2 if bytes.len() == 8 => {
                let st = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                let ba = u32::from_le_bytes(bytes[4..].try_into().unwrap());
                if st & !15 != 0 || st > 7 || ba & 0xc0000000 != 0 {
                    return Err("MVM BAR release identity/masks");
                }
                (((ba >> 24) & 63) as u8, Some(st as u8), (ba & 4095) as u16)
            }
            _ => return Err("MVM BA release geometry"),
        };
        if baid >= 32 || nssn >= 4096 {
            return Err("MVM BA release range");
        }
        let Some(s) = self
            .sessions
            .iter_mut()
            .find(|s| s.active && s.baid == Some(baid))
        else {
            return Ok(());
        };
        if tid.is_some_and(|t| t != s.request.tid) {
            return Err("MVM BAR release foreign TID");
        }
        let Some(rx) = s.queues.get_mut(usize::from(queue)) else {
            return Err("MVM BA release physical queue absent");
        };
        let frames = rx
            .reorder
            .advance(nssn, now())
            .map_err(|_| "MVM BA release ordering")?;
        if rx
            .partial
            .as_ref()
            .is_some_and(|p| rx.reorder.head().is_some_and(|head| p.passed(head)))
        {
            rx.partial = None;
        }
        self.append(frames)
    }
    pub fn tick(&mut self) -> Result<(), &'static str> {
        let clock = now();
        for index in 0..self.sessions.len() {
            let s = &mut self.sessions[index];
            if !s.active {
                continue;
            }
            let mut frames = Vec::new();
            for queue in &mut s.queues {
                if queue.partial.as_ref().is_some_and(|p| p.expired(clock)) {
                    queue.partial = None;
                }
                frames.extend(
                    queue
                        .reorder
                        .expire(clock)
                        .map_err(|_| "MVM BA hole expiry")?,
                );
                if queue
                    .partial
                    .as_ref()
                    .is_some_and(|p| p.passed(queue.reorder.head().unwrap()))
                {
                    queue.partial = None;
                }
            }
            let expired = s.request.timeout != 0
                && clock.saturating_sub(s.last_rx) >= u64::from(s.request.timeout) * 1_024_000;
            if expired {
                s.active = false;
                self.work.push_back(Work::Remove(s.request.tid, true));
            }
            self.append(frames)?;
        }
        Ok(())
    }
}
impl Owner {
    fn baid_profile(&self) -> Option<baid::Profile> {
        let parsed = super::super::parse_ucode(&self.firmware).ok()?;
        if !parsed.api.has_capability(63) {
            return Some(baid::Profile::Station);
        }
        // Linux lookup defaults this command to v1, including UNKNOWN.
        match self.hardware.version(5, 0x16).map(|v| v.0).unwrap_or(1) {
            1 | 99 => Some(baid::Profile::ConfigV1),
            2 => Some(baid::Profile::ConfigV2),
            _ => None,
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::iwlwifi) fn model_expire_ba_partials(&mut self) {
        for s in &mut self.power.phy.ba.sessions {
            for queue in &mut s.queues {
                if let Some(p) = &mut queue.partial {
                    p.model_expire();
                }
            }
        }
    }
    pub(in crate::iwlwifi) fn supports_native_ba(&self) -> bool {
        self.supports_native_ht20()
            && self
                .hardware
                .version(0, 0xc5)
                .is_some_and(|v| matches!(v.1, 4 | 6 | 7))
            && self.hardware.version(0, 0xc2).is_some_and(|v| v.1 == 1)
            && self.hardware.version(0, 0xc3).is_some_and(|v| v.1 == 1)
            && self.baid_profile().is_some()
    }
    pub(super) fn ba_qualified(&self) -> bool {
        self.power.phy.ba.selected
            && self.power.phy.negotiated.is_some_and(|p| p.ht)
            && self
                .power
                .prepared
                .as_ref()
                .is_some_and(|p| p.emission.features() & super::power::feature::BA != 0)
    }
    pub(super) fn capture_ba_action(&mut self, body: &[u8]) -> bool {
        if !self.ba_qualified()
            || self.phase != Phase::DataPrepared
            || self
                .power
                .prepared
                .as_ref()
                .and_then(|p| p.mlme.data.as_ref())
                .is_none_or(|d| d.status.protected && !self.security.ready())
        {
            return false;
        }
        let queues = self.hardware.receive_queue_count();
        let ba = &mut self.power.phy.ba;
        if ba.work.len() >= 8 {
            return true;
        }
        if body.len() == 6 && body[1] == 2 && u16::from_le_bytes([body[2], body[3]]) & 0x7ff != 0 {
            return true;
        }
        match super::super::aggregation::action(body) {
            Some(super::super::aggregation::Action::Add {
                token,
                tid,
                window,
                ssn,
                timeout,
                immediate,
            }) if tid < 8 && immediate => {
                let request = Request {
                    token,
                    tid,
                    window: window.min(WINDOW),
                    ssn,
                    timeout,
                    original_parameters: u16::from_le_bytes([body[3], body[4]]),
                    nested: ba.nested_selected && body[3] & 1 != 0,
                };
                if let Some(s) = ba.sessions.iter().find(|s| s.request.tid == tid) {
                    // Exact retransmission may reuse its response. A changed
                    // agreement cannot replace live firmware/reorder ownership.
                    if s.request == request && s.active {
                        ba.work.push_back(Work::Add(request));
                    } else {
                        return false;
                    }
                } else {
                    let Ok(queues) = (0..queues)
                        .map(|_| Queue::new(request))
                        .collect::<Result<Vec<_>, _>>()
                    else {
                        return false;
                    };
                    ba.sessions.push(Session {
                        request,
                        baid: None,
                        active: false,
                        queues,
                        last_rx: now(),
                    });
                    ba.work.push_back(Work::Add(request));
                }
                true
            }
            Some(super::super::aggregation::Action::Delete {
                tid,
                originator: true,
            }) if tid < 8 => {
                if let Some(s) = ba.sessions.iter_mut().find(|s| s.request.tid == tid) {
                    s.active = false;
                    ba.work.push_back(Work::Remove(tid, false));
                }
                true
            }
            Some(super::super::aggregation::Action::Delete { .. }) => true, // TX manager consumes its own DELBA.
            _ => false,
        }
    }
    pub(super) fn receive_ba_bar(
        &mut self,
        m: &scan_api::Mpdu<'_>,
        local: [u8; 6],
        peer: [u8; 6],
        channel: u8,
    ) -> bool {
        if !self.ba_qualified() || m.channel != channel || m.amsdu {
            return false;
        }
        let f = m.frame;
        if f.len() < 20
            || f[0] != 0x84
            || f[1] & 0xc7 != 0
            || f[4..10] != local
            || f[10..16] != peer
            || m.status & 0xf40 != 0
        {
            return false;
        }
        let Some(body) = m.body(16, 0).filter(|b| b.len() == 4) else {
            return true;
        };
        let control = u16::from_le_bytes([body[0], body[1]]);
        if control & 0xfff != 4 || body[2] & 15 != 0 {
            return true;
        }
        let tid = (control >> 12) as u8;
        let ba = &mut self.power.phy.ba;
        if tid < 8
            && !ba.sessions.iter().any(|s| s.active && s.request.tid == tid)
            && ba.work.len() < 8
        {
            ba.work.push_back(Work::RejectBar(tid));
        }
        // Firmware forwards native BAR_FRAME_RELEASE for an allocated BAID.
        // Applying the raw BAR as well would advance the same window twice.
        true
    }
    pub(super) async fn ba_management(
        &mut self,
        body: &[u8],
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        let queue = self
            .management_queue
            .as_ref()
            .and_then(|q| q.id)
            .ok_or("MVM BA management owner absent")?;
        let data = self
            .power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap();
        let frame = super::super::frame_api::management(
            0xd0,
            self.mac.unwrap(),
            data.status.bssid,
            data.sequence,
            body,
        );
        data.sequence = data.sequence.wrapping_add(1) & 4095;
        let rates = super::super::rates::Rates {
            supported: data.status.supported_rates,
            basic: data.status.basic_rates,
        };
        let chains = self.nvm.as_ref().unwrap().tx_chains;
        let rate = rates.management_rate(chains & chains.wrapping_neg());
        self.fresh_data_policy(policy).await?;
        self.qualified_management_transmit(queue, &frame, rate, policy)
            .await
    }
    pub(super) async fn service_ba(
        &mut self,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if !self.power.phy.ba.needs_work() {
            return Ok(());
        }
        if self.phase != Phase::DataPrepared || !self.ba_qualified() {
            return Err("MVM BA work outside qualified owner");
        }
        if !self.data_port_using(&mut *policy) {
            return Err("MVM BA response requires current controlled port");
        }
        self.phase = Phase::TransmittingData; // Reserved before any native publication/await.
        let result = async {
            for _ in 0..8 {
                let Some(work) = self.power.phy.ba.work.front().copied() else {
                    break;
                };
                self.check_link_power(&policy()?)?;
                match work {
                    Work::Add(request) => {
                        let index = self
                            .power
                            .phy
                            .ba
                            .sessions
                            .iter()
                            .position(|s| s.request == request)
                            .ok_or("MVM BA reservation lost")?;
                        if self.power.phy.ba.sessions[index].baid.is_none() {
                            let profile = self.baid_profile().ok_or("MVM BAID profile changed")?;
                            let command = profile.add(request.tid, request.ssn, request.window);
                            let reply = self
                                .qualified_link_command(
                                    command.group,
                                    command.command,
                                    &command.bytes,
                                    policy,
                                )
                                .await?;
                            let Some(id) = profile.allocated(&reply)? else {
                                self.ba_management(&response(request, 37), policy).await?;
                                self.power.phy.ba.sessions.remove(index);
                                self.power.phy.ba.work.pop_front();
                                continue;
                            };
                            if self
                                .power
                                .phy
                                .ba
                                .sessions
                                .iter()
                                .any(|s| s.baid == Some(id))
                            {
                                return Err("MVM allocated BAID missing/foreign/reused");
                            }
                            self.power.phy.ba.sessions[index].baid = Some(id);
                        }
                        self.ba_management(&response(request, 0), policy).await?;
                        self.check_link_power(&policy()?)?;
                        self.power.phy.ba.sessions[index].active = true;
                    }
                    Work::Remove(tid, notify) => {
                        self.remove_ba_tid(tid, Some(&mut *policy)).await?;
                        if notify {
                            self.ba_management(&super::super::aggregation::delete(tid), policy)
                                .await?;
                        }
                    }
                    Work::RejectBar(tid) => {
                        let mut body = super::super::aggregation::delete(tid);
                        body[4] = 38; // WLAN_REASON_QSTA_REQUIRE_SETUP
                        self.ba_management(&body, policy).await?;
                    }
                }
                self.power.phy.ba.work.pop_front();
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => {
                self.phase = Phase::DataPrepared;
                Ok(())
            }
            Err(e) => self.data_failed(e),
        }
    }
    async fn remove_ba_tid(
        &mut self,
        tid: u8,
        mut policy: Option<&mut impl FnMut() -> Result<RegulatoryDomain, &'static str>>,
    ) -> Result<(), &'static str> {
        let Some(index) = self
            .power
            .phy
            .ba
            .sessions
            .iter()
            .position(|s| s.request.tid == tid)
        else {
            return Ok(());
        };
        self.power.phy.ba.sessions[index].active = false;
        for queue in &mut self.power.phy.ba.sessions[index].queues {
            queue.partial = None;
            queue.reorder.clear();
        }
        if self.power.phy.ba.sessions[index].baid.is_some() {
            let profile = self.baid_profile().ok_or("MVM BAID profile changed")?;
            let command = profile.remove(tid, self.power.phy.ba.sessions[index].baid.unwrap());
            let reply = if let Some(p) = policy.as_deref_mut() {
                self.qualified_link_command(command.group, command.command, &command.bytes, p)
                    .await?
            } else {
                self.hardware
                    .command_with_header_version(command.group, command.command, &command.bytes, 0)
                    .await?
                    .payload
            };
            profile.removed(&reply)?;
            // Do not reuse a firmware BAID/reorder map on command ACK alone.
            self.sync_ba_rx(self.power.phy.ba.sessions[index].baid.unwrap(), policy)
                .await?;
        }
        self.power.phy.ba.sessions.remove(index);
        self.power.phy.ba.ready.clear();
        self.power.phy.ba.draining = None;
        Ok(())
    }
    pub(super) async fn retire_ba(
        &mut self,
        mut policy: Option<&mut impl FnMut() -> Result<RegulatoryDomain, &'static str>>,
    ) -> Result<(), &'static str> {
        if self.power.phy.ba.tx_enabled {
            let reply = if let Some(p) = policy.as_deref_mut() {
                self.qualified_link_command(1, 0x18, &permission(false), p)
                    .await?
            } else {
                self.hardware
                    .command_with_header_version(1, 0x18, &permission(false), 0)
                    .await?
                    .payload
            };
            status(&reply)?;
            self.power.phy.ba.tx_enabled = false;
            let queue = self
                .power
                .prepared
                .as_ref()
                .unwrap()
                .mlme
                .data
                .as_ref()
                .unwrap()
                .queue
                .unwrap();
            self.hardware.gen2_tx_aggregation(queue, false)?;
        }
        while let Some(tid) = self.power.phy.ba.sessions.first().map(|s| s.request.tid) {
            self.remove_ba_tid(tid, policy.as_deref_mut()).await?;
        }
        self.power.phy.ba.work.clear();
        self.power.phy.ba.ready.clear();
        self.power.phy.ba.draining = None;
        Ok(())
    }
    pub(super) async fn enable_ba_tx(
        &mut self,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if !self.ba_qualified() || self.power.phy.ba.tx_enabled {
            return Ok(());
        }
        self.check_link_power(&policy()?)?;
        let reply = self
            .qualified_link_command(1, 0x18, &permission(true), policy)
            .await?;
        status(&reply)?;
        let queue = self
            .power
            .prepared
            .as_ref()
            .unwrap()
            .mlme
            .data
            .as_ref()
            .unwrap()
            .queue
            .unwrap();
        self.check_link_power(&policy()?)?;
        self.hardware.gen2_tx_aggregation(queue, true)?;
        self.power.phy.ba.tx_enabled = true;
        Ok(())
    }
}
