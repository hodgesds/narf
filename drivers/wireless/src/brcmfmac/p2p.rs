// SPDX-License-Identifier: GPL-2.0-or-later
//! brcmfmac P2P device (discovery bsscfg) owner: discovery state,
//! remain-on-channel, action-frame TX/RX and P2P probe-request delivery.
//!
//! Linux 7.3-rc4 `p2p.c` mirrored here (`struct brcmf_p2p_info` subset):
//! - `brcmf_p2p_enable_discovery` / `brcmf_p2p_start_device` /
//!   `brcmf_p2p_stop_device` (`p2p_disc 1`, bsscfg `p2p_state` SCAN, bsscfg
//!   `wsec` AES; stop returns to SCAN);
//! - `brcmf_p2p_remain_on_channel` / `brcmf_p2p_discover_listen` /
//!   `brcmf_p2p_notify_listen_complete` /
//!   `brcmf_p2p_cancel_remain_on_channel` (`p2p_state` LISTEN with a 20 MHz
//!   chanspec and dwell, `BRCMF_E_P2P_DISC_LISTEN_COMPLETE`);
//! - `brcmf_p2p_send_action_frame` / `brcmf_p2p_tx_action_frame` /
//!   `brcmf_p2p_notify_action_tx_complete` / `brcmf_p2p_abort_action_frame`
//!   / `brcmf_p2p_stop_wait_next_action_frame` (bsscfg `actframe`, up to
//!   `P2P_AF_TX_MAX_RETRY` attempts, `BRCMF_E_ACTION_FRAME_COMPLETE` /
//!   `..._OFF_CHAN_COMPLETE` within `P2P_AF_MAX_WAIT_TIME`, `mpc` toggling,
//!   GO-negotiation phase and next-subtype tracking);
//! - `brcmf_p2p_notify_action_frame_rx` (including
//!   `brcmf_p2p_gon_req_collision`) and
//!   `brcmf_p2p_notify_rx_mgmt_p2p_probereq`.
//!
//! Not mirrored (each is unreachable in Linux too without the P2P escan,
//! which is not implemented here): the peer-channel search
//! (`brcmf_p2p_af_searching_channel`, needs saved P2P probe-request IEs on
//! the discovery vif) and the extra-listen WAR (needs `my_listen_chan`,
//! set only by `brcmf_p2p_scan_prep`). The primary-scan abort before TX
//! (`brcmf_abort_scanning`) is left to the caller.
use super::{
    p2p_wire::{self as wire, DiscState},
    vif_owner::Owner,
    vif_wire::{self, Entry},
};
use crate::cyw43439::{
    fullmac::Fullmac,
    ioctl::Direction,
    runtime::{Error, Event},
};
use alloc::{collections::VecDeque, vec::Vec};

const SET_VAR: u32 = 263;
const GET_BSSID: u32 = 23;
/// `AES_ENABLED`.
const AES_ENABLED: u32 = 4;
/// Retained notices before the consumer is considered stalled.
pub const NOTICE_DEPTH: usize = 32;

/// Upward notifications (`cfg80211_*` callbacks of `p2p.c`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Notice {
    /// `cfg80211_remain_on_channel_expired`.
    RocExpired { cookie: u64, frequency_mhz: u32 },
    /// `cfg80211_rx_mgmt` of an action frame or P2P probe request.
    Rx { frequency_mhz: u32, frame: Vec<u8> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Listen {
    cookie: u64,
    frequency_mhz: u32,
}

/// One `actframe` attempt in flight (`BRCMF_P2P_STATUS_SENDING_ACT_FRAME`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Sending {
    completed: bool,
    noack: bool,
    /// `send_af_done` signalled.
    done: bool,
    wait_for_offchan_complete: bool,
    af_sent_channel: u32,
}

/// The discovery bsscfg owner (`P2PAPI_BSSCFG_DEVICE`).
#[derive(Debug)]
pub struct Device {
    entry: Entry,
    /// `BRCMF_P2P_STATUS_ENABLED`.
    enabled: bool,
    /// `BRCMF_VIF_STATUS_READY` (`start_device`/`stop_device`).
    ready: bool,
    /// `BRCMF_P2P_STATUS_DISCOVER_LISTEN` + the ROC record.
    listen: Option<Listen>,
    go_neg_phase: bool,
    waiting_next_af: bool,
    next_af_subtype: u8,
    gon_req_action: bool,
    block_gon_req_tx: bool,
    sending: Option<Sending>,
    abort_pending: bool,
    /// `vif->mgmt_rx_reg` bits for action (13) and probe request (4).
    rx_action: bool,
    rx_probe_req: bool,
    notices: VecDeque<Notice>,
    /// `vif->saved_ie` probe-request / probe-response vendor IEs installed
    /// on the discovery bsscfg (`brcmf_vif_set_mgmt_ie`).
    probe_req_ies: Vec<u8>,
    probe_resp_ies: Vec<u8>,
    /// `afx_hdl.my_listen_chan` from the last P2P scan request.
    my_listen_chan: Option<u8>,
}

impl Device {
    /// The created discovery entry from
    /// [`Owner::create_p2p_device`](super::vif_owner::Owner::create_p2p_device).
    pub fn new(entry: Entry) -> Self {
        Self {
            entry,
            enabled: false,
            ready: false,
            listen: None,
            go_neg_phase: false,
            waiting_next_af: false,
            next_af_subtype: wire::PAF_SUBTYPE_INVALID,
            gon_req_action: false,
            block_gon_req_tx: false,
            sending: None,
            abort_pending: false,
            rx_action: false,
            rx_probe_req: false,
            notices: VecDeque::new(),
            probe_req_ies: Vec::new(),
            probe_resp_ies: Vec::new(),
            my_listen_chan: None,
        }
    }
    pub fn entry(&self) -> Entry {
        self.entry
    }
    pub fn ready(&self) -> bool {
        self.ready
    }
    pub fn listening(&self) -> Option<u64> {
        self.listen.map(|listen| listen.cookie)
    }
    /// `brcmf_cfg80211_update_mgmt_frame_registrations` (`mgmt_rx_reg`).
    pub fn set_registrations(&mut self, action: bool, probe_req: bool) {
        self.rx_action = action;
        self.rx_probe_req = probe_req;
    }
    pub fn pop_notice(&mut self) -> Option<Notice> {
        self.notices.pop_front()
    }
    fn notify(&mut self, notice: Notice) -> Result<(), Error> {
        if self.notices.len() == NOTICE_DEPTH {
            return Err(Error::EventOverflow);
        }
        self.notices.push_back(notice);
        Ok(())
    }

    /// The discovery bsscfg's per-interface need in the composed mask:
    /// the P2P events `fweh` enables for the registered handlers, written
    /// only when they add bits.
    pub async fn declare_events<R: Fullmac>(&self, runtime: &mut R) -> Result<(), Error> {
        let mask = runtime.events_compose(
            super::event_mask::Need::Secondary(self.entry.ifidx),
            super::event_mask::mask(&wire::DEVICE_EVENTS),
        );
        if runtime.events_current() == Some(mask) {
            return Ok(());
        }
        let input = vif_wire::bsscfg_iovar(0, b"event_msgs", &mask)?;
        runtime
            .command(Direction::Set, SET_VAR, &input, input.len())
            .await?;
        runtime.events_written(mask);
        Ok(())
    }

    async fn bsscfg_set<R: Fullmac>(
        &self,
        runtime: &mut R,
        name: &[u8],
        data: &[u8],
    ) -> Result<(), Error> {
        let input = vif_wire::bsscfg_iovar(self.entry.bsscfgidx, name, data)?;
        runtime
            .command_vif(
                self.entry.ifidx,
                Direction::Set,
                SET_VAR,
                &input,
                input.len(),
            )
            .await
            .map(|_| ())
    }

    async fn set_discover_state<R: Fullmac>(
        &self,
        runtime: &mut R,
        state: DiscState,
        chanspec: u16,
        dwell: u16,
    ) -> Result<(), Error> {
        self.bsscfg_set(
            runtime,
            b"p2p_state",
            &wire::disc_state(state, chanspec, dwell),
        )
        .await
    }

    /// `brcmf_p2p_enable_discovery`.
    async fn enable_discovery<R: Fullmac>(&mut self, runtime: &mut R) -> Result<(), Error> {
        if self.enabled {
            return Ok(());
        }
        let input = vif_wire::bsscfg_iovar(0, b"p2p_disc", &1u32.to_le_bytes())?;
        runtime
            .command(Direction::Set, SET_VAR, &input, input.len())
            .await?;
        self.set_discover_state(runtime, DiscState::Scan, 0, 0)
            .await?;
        self.bsscfg_set(runtime, b"wsec", &AES_ENABLED.to_le_bytes())
            .await?;
        self.enabled = true;
        Ok(())
    }

    /// `brcmf_p2p_start_device`.
    pub async fn start<R: Fullmac>(&mut self, runtime: &mut R) -> Result<(), Error> {
        self.declare_events(runtime).await?;
        self.enable_discovery(runtime).await?;
        self.ready = true;
        Ok(())
    }

    /// `brcmf_p2p_stop_device`: discovery back to SCAN (result ignored,
    /// as in Linux), READY cleared.
    pub async fn stop<R: Fullmac>(&mut self, runtime: &mut R) -> Result<(), Error> {
        match self
            .set_discover_state(runtime, DiscState::Scan, 0, 0)
            .await
        {
            Ok(()) | Err(Error::Firmware(_)) => {}
            Err(error) => return Err(error),
        }
        self.ready = false;
        Ok(())
    }

    /// `brcmf_p2p_remain_on_channel` + `brcmf_p2p_discover_listen`. On
    /// success the caller reports `cfg80211_ready_on_channel`. A listen
    /// still in progress keeps running and is reported ready under the new
    /// cookie, as Linux's "prevent cookie mismatch" WAR does.
    pub async fn remain_on_channel<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        cookie: u64,
        frequency_mhz: u32,
        duration_ms: u32,
    ) -> Result<(), Error> {
        let channel = wire::frequency_channel(frequency_mhz).ok_or(Error::Malformed)?;
        let chanspec = wire::chanspec20(channel).ok_or(Error::Malformed)?;
        self.enable_discovery(runtime).await?;
        if self.listen.is_none() {
            self.set_discover_state(runtime, DiscState::Listen, chanspec, duration_ms as u16)
                .await?;
        }
        self.listen = Some(Listen {
            cookie,
            frequency_mhz,
        });
        Ok(())
    }

    /// `afx_hdl.my_listen_chan` of the last P2P scan request.
    pub fn my_listen_channel(&self) -> Option<u8> {
        self.my_listen_chan
    }

    /// `brcmf_vif_set_mgmt_ie` on the discovery bsscfg: replace the saved
    /// vendor IEs of `flag` (PRBREQ or PRBRSP) with the vendor elements
    /// of `ies`. A refused or cancelled update leaves the installed set
    /// unknown; the saved copy is then cleared so the next request
    /// re-issues a full `add` without claiming the old set was deleted.
    pub async fn set_mgmt_ie<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        flag: u32,
        ies: &[u8],
    ) -> Result<(), Error> {
        let requested = wire::vendor_ies(ies).map_err(|_| Error::Malformed)?;
        let installed = core::mem::take(self.saved_ies(flag)?);
        let Some(update) = wire::vndr_ie_update(&installed, &requested, flag) else {
            *self.saved_ies(flag)? = installed;
            return Ok(());
        };
        let input = vif_wire::bsscfg_iovar(self.entry.bsscfgidx, b"vndr_ie", &update)?;
        let result = runtime
            .command_vif(
                self.entry.ifidx,
                Direction::Set,
                SET_VAR,
                &input,
                input.len(),
            )
            .await;
        match result {
            Ok(_) => *self.saved_ies(flag)? = requested,
            // A firmware refusal rejects the whole batch: the old set is
            // still installed. Any other failure leaves it unknown.
            Err(Error::Firmware(_)) => *self.saved_ies(flag)? = installed,
            Err(_) => {}
        }
        result.map(|_| ())
    }

    fn saved_ies(&mut self, flag: u32) -> Result<&mut Vec<u8>, Error> {
        match flag {
            wire::VNDR_IE_PRBREQ_FLAG => Ok(&mut self.probe_req_ies),
            wire::VNDR_IE_PRBRSP_FLAG => Ok(&mut self.probe_resp_ies),
            _ => Err(Error::Unsupported),
        }
    }

    /// `brcmf_p2p_scan_prep` for a P2P scan request (the caller checked
    /// `brcmf_p2p_scan_is_p2p_request`): the social listen channel from
    /// the request's P2P IE (`-EPERM` otherwise), GO-negotiation phase
    /// cleared, discovery enabled, then the caller's probe-request vendor
    /// IEs on this vif (`brcmf_cfg80211_scan` `brcmf_vif_set_mgmt_ie`).
    pub async fn scan_prep<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        ies: &[u8],
    ) -> Result<(), Error> {
        let listen = wire::listen_channel(ies).ok_or(Error::Authority)?;
        self.my_listen_chan = Some(listen);
        self.go_neg_phase = false;
        self.enable_discovery(runtime).await?;
        self.set_mgmt_ie(runtime, wire::VNDR_IE_PRBREQ_FLAG, ies)
            .await
    }

    /// `brcmf_p2p_escan` on the discovery bsscfg: discovery state
    /// `state` (SEARCH or SCAN), then bsscfg `p2p_scan` 'E'. The escan
    /// results carry `wire::ESCAN_SYNC_ID`.
    pub async fn run_escan<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        state: DiscState,
        chanspecs: &[u16],
    ) -> Result<(), Error> {
        let body = wire::p2p_scan(state, chanspecs).map_err(|_| Error::Malformed)?;
        // Linux ignores this result (`brcmf_p2p_set_discover_state`).
        match self.set_discover_state(runtime, state, 0, 0).await {
            Ok(()) | Err(Error::Firmware(_)) => {}
            Err(error) => return Err(error),
        }
        self.bsscfg_set(runtime, b"p2p_scan", &body).await
    }

    /// [`Self::service`] during a P2P escan: `BRCMF_E_ESCAN_RESULT`
    /// records of this bsscfg go to `escan` (the escan handler), every
    /// other event to the `p2p.c` handlers as usual.
    pub async fn service_escan<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        owner: &mut Owner,
        escan: &mut Vec<Event>,
    ) -> Result<(), Error> {
        owner.service(runtime)?;
        while let Some(event) = owner.pop_event(&self.entry) {
            if event.header.event_type == wire::E_ESCAN_RESULT {
                escan.push(event);
            } else {
                self.handle(runtime, event).await?;
            }
        }
        Ok(())
    }

    /// `brcmf_p2p_notify_listen_complete`.
    fn listen_complete(&mut self) -> Result<(), Error> {
        if let Some(listen) = self.listen.take() {
            self.waiting_next_af = false;
            self.notify(Notice::RocExpired {
                cookie: listen.cookie,
                frequency_mhz: listen.frequency_mhz,
            })?;
        }
        Ok(())
    }

    /// `brcmf_p2p_cancel_remain_on_channel`: SCAN state (result ignored)
    /// and the listen-complete notification.
    pub async fn cancel_remain_on_channel<R: Fullmac>(
        &mut self,
        runtime: &mut R,
    ) -> Result<(), Error> {
        match self
            .set_discover_state(runtime, DiscState::Scan, 0, 0)
            .await
        {
            Ok(()) | Err(Error::Firmware(_)) => {}
            Err(error) => return Err(error),
        }
        self.listen_complete()
    }

    /// `brcmf_p2p_stop_wait_next_action_frame` (deferred to the service
    /// loop because the event handlers cannot issue commands).
    fn stop_wait_next(&mut self) {
        if let Some(sending) = self.sending {
            if (sending.completed || sending.noack) && sending.af_sent_channel != 0 {
                self.abort_pending = true;
            }
        }
    }

    /// Drain this bsscfg's events (`fweh` handlers of `p2p.c`).
    pub async fn service<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        owner: &mut Owner,
    ) -> Result<(), Error> {
        owner.service(runtime)?;
        while let Some(event) = owner.pop_event(&self.entry) {
            self.handle(runtime, event).await?;
        }
        if core::mem::take(&mut self.abort_pending) {
            // brcmf_p2p_abort_action_frame; a refusal falls back to the
            // escan-complete notification, which has no host state here.
            match self
                .bsscfg_set(runtime, b"actframe_abort", &1i32.to_le_bytes())
                .await
            {
                Ok(()) | Err(Error::Firmware(_)) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn handle<R: Fullmac>(&mut self, runtime: &mut R, event: Event) -> Result<(), Error> {
        let header = event.header;
        match header.event_type {
            wire::E_P2P_DISC_LISTEN_COMPLETE => self.listen_complete(),
            wire::E_ACTION_FRAME_COMPLETE | wire::E_ACTION_FRAME_OFF_CHAN_COMPLETE => {
                let Some(mut sending) = self.sending else {
                    return Ok(());
                };
                if header.event_type == wire::E_ACTION_FRAME_COMPLETE {
                    if header.status == wire::E_STATUS_SUCCESS {
                        sending.completed = true;
                        if !sending.wait_for_offchan_complete {
                            sending.done = true;
                        }
                        self.sending = Some(sending);
                    } else {
                        sending.noack = true;
                        self.sending = Some(sending);
                        self.stop_wait_next();
                    }
                } else {
                    sending.done = true;
                    self.sending = Some(sending);
                }
                Ok(())
            }
            wire::E_ACTION_FRAME_RX => self.action_rx(runtime, &event).await,
            wire::E_P2P_PROBEREQ_MSG => {
                let Ok(rx) = wire::parse_rx_action(header.datalen, &event.payload) else {
                    return Ok(());
                };
                if header.bsscfg_idx == 0 || self.go_neg_phase || !self.rx_probe_req {
                    return Ok(());
                }
                let Some(frequency_mhz) = wire::chanspec_frequency(rx.chanspec) else {
                    return Ok(());
                };
                self.notify(Notice::Rx {
                    frequency_mhz,
                    frame: rx.body,
                })
            }
            _ => Ok(()),
        }
    }

    /// `brcmf_p2p_notify_action_frame_rx`.
    async fn action_rx<R: Fullmac>(&mut self, runtime: &mut R, event: &Event) -> Result<(), Error> {
        let header = event.header;
        let Ok(rx) = wire::parse_rx_action(header.datalen, &event.payload) else {
            return Ok(());
        };
        if !self.rx_action {
            return Ok(());
        }
        let Some(frequency_mhz) = wire::chanspec_frequency(rx.chanspec) else {
            return Ok(());
        };
        let action = wire::rx_subtype(&rx.body);
        if wire::is_pub_action(&rx.body) {
            if action == wire::PAF_GON_REQ && self.gon_req_collision(header.source_mac) {
                return Ok(());
            }
            if action == wire::PAF_GON_CONF || action == wire::PAF_PROVDIS_RSP {
                self.set_mpc(runtime, true).await?;
            }
            if action == wire::PAF_GON_CONF {
                self.go_neg_phase = false;
            }
        }
        if self.waiting_next_af && self.next_af_subtype == action {
            self.waiting_next_af = false;
            self.stop_wait_next();
        }
        let mut bssid = [0; 6];
        match runtime
            .command_vif(self.entry.ifidx, Direction::Get, GET_BSSID, &[0; 6], 6)
            .await
        {
            Ok(reply) if reply.len() >= 6 => bssid.copy_from_slice(&reply[..6]),
            Ok(_) | Err(Error::Firmware(_)) => {}
            Err(error) => return Err(error),
        }
        let frame = wire::rx_frame(self.entry.mac, header.source_mac, bssid, &rx.body);
        self.notify(Notice::Rx {
            frequency_mhz,
            frame,
        })
    }

    /// `brcmf_p2p_gon_req_collision`: true drops the peer's request.
    fn gon_req_collision(&mut self, peer: [u8; 6]) -> bool {
        if !self.waiting_next_af || !self.gon_req_action {
            return false;
        }
        if peer < self.entry.mac {
            self.block_gon_req_tx = true;
            if core::mem::take(&mut self.waiting_next_af) {
                self.stop_wait_next();
            }
            return false;
        }
        true
    }

    /// `brcmf_set_mpc` on the discovery interface (only while READY, as
    /// `check_vif_up` requires).
    async fn set_mpc<R: Fullmac>(&self, runtime: &mut R, on: bool) -> Result<(), Error> {
        if !self.ready {
            return Ok(());
        }
        let input = vif_wire::bsscfg_iovar(0, b"mpc", &u32::from(on).to_le_bytes())?;
        match runtime
            .command_vif(
                self.entry.ifidx,
                Direction::Set,
                SET_VAR,
                &input,
                input.len(),
            )
            .await
        {
            Ok(_) | Err(Error::Firmware(_)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// `brcmf_cfg80211_mgmt_tx` action branch + `brcmf_p2p_send_action_frame`.
    /// `channel` is the requested channel number (or the firmware's current
    /// one), `wait_ms` the requested dwell. Returns the ACK used for
    /// `cfg80211_mgmt_tx_status`.
    pub async fn send_action_frame<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        owner: &mut Owner,
        frame: &[u8],
        channel: u32,
        wait_ms: u32,
        cookie: u64,
    ) -> Result<bool, Error> {
        let mut params =
            wire::af_params(frame, channel, wait_ms, cookie).map_err(|_| Error::Malformed)?;
        let requested_dwell = wire::af_dwell(&params);
        wire::set_af_dwell(&mut params, wire::AF_DWELL_TIME);
        self.next_af_subtype = wire::PAF_SUBTYPE_INVALID;
        self.gon_req_action = false;
        let Some(policy) = wire::af_policy(wire::af_body(&params)) else {
            // "Unknown Frame": no transmission, reported without ACK.
            return Ok(false);
        };
        wire::set_af_dwell(&mut params, policy.dwell_ms);
        self.next_af_subtype = policy.next_subtype;
        // Only a GO Negotiation Request enters the GO_NEG phase.
        self.gon_req_action = policy.go_neg_phase == Some(true);
        if let Some(phase) = policy.go_neg_phase {
            self.go_neg_phase = phase;
        }
        if policy.mpc == Some(false) {
            self.set_mpc(runtime, false).await?;
        }
        if self.next_af_subtype != wire::PAF_SUBTYPE_INVALID {
            self.waiting_next_af = true;
        }
        let start_ns = narf_time::wall::monotonic_ns();
        let overflow = |now: u64| {
            requested_dwell & wire::CUSTOM_RETRY_MASK != 0
                && now.saturating_sub(start_ns) / 1_000_000
                    > u64::from(requested_dwell & !wire::CUSTOM_RETRY_MASK)
        };
        let mut ack = false;
        let mut retry = 0;
        let result: Result<(), Error> = async {
            let mut dwell_overflow = overflow(narf_time::wall::monotonic_ns());
            while !self.block_gon_req_tx && !ack && retry < wire::AF_TX_MAX_RETRY && !dwell_overflow
            {
                if wire::af_channel(&params) != 0 {
                    sleep_ms(wire::AF_RETRY_DELAY_TIME_MS).await;
                }
                ack = self.tx_action_frame(runtime, owner, &params).await?;
                retry += 1;
                dwell_overflow = overflow(narf_time::wall::monotonic_ns());
            }
            Ok(())
        }
        .await;
        self.sending = None;
        if !ack {
            self.go_neg_phase = false;
        }
        if core::mem::take(&mut self.block_gon_req_tx) {
            ack = true;
        }
        self.waiting_next_af = false;
        result?;
        if policy.mpc == Some(true) {
            self.set_mpc(runtime, true).await?;
        }
        Ok(ack)
    }

    /// `brcmf_p2p_tx_action_frame`: one `actframe` and the wait for its
    /// completion event(s).
    async fn tx_action_frame<R: Fullmac>(
        &mut self,
        runtime: &mut R,
        owner: &mut Owner,
        params: &[u8],
    ) -> Result<bool, Error> {
        let channel = wire::af_channel(params);
        let on_listen_channel = self.listen.is_some_and(|listen| {
            wire::frequency_channel(listen.frequency_mhz).map(u32::from) == Some(channel)
        });
        self.sending = Some(Sending {
            wait_for_offchan_complete: !on_listen_channel,
            ..Sending::default()
        });
        match self.bsscfg_set(runtime, b"actframe", params).await {
            Ok(()) => {}
            Err(Error::Firmware(_)) => return Ok(false),
            Err(error) => return Err(error),
        }
        if let Some(sending) = self.sending.as_mut() {
            sending.af_sent_channel = channel;
        }
        let deadline = narf_time::Deadline::after_ms(wire::AF_MAX_WAIT_TIME_MS);
        loop {
            runtime.poll()?;
            self.service(runtime, owner).await?;
            if self.sending.is_some_and(|sending| sending.done) || deadline.expired() {
                break;
            }
            sleep_ms(1).await;
        }
        let completed = self.sending.is_some_and(|sending| sending.completed);
        if let Some(sending) = self.sending.as_mut() {
            sending.completed = false;
            sending.noack = false;
            sending.done = false;
        }
        Ok(completed)
    }

    /// Teardown order of `brcmf_p2p_del_vif` for the device: cancel the
    /// listen, then the owner removes the discovery bsscfg.
    pub async fn delete<R: Fullmac>(
        mut self,
        runtime: &mut R,
        owner: &mut Owner,
    ) -> Result<Vec<Notice>, Error> {
        let cancelled = self.cancel_remain_on_channel(runtime).await;
        self.go_neg_phase = false;
        let removed = owner.remove_p2p_device(runtime, self.entry).await;
        cancelled?;
        removed?;
        Ok(self.notices.into_iter().collect())
    }
}

async fn sleep_ms(ms: u64) {
    narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(ms.saturating_mul(1_000_000))).await;
}
