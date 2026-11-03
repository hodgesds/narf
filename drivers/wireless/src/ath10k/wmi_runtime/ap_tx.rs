// SPDX-License-Identifier: GPL-2.0-or-later
//! AP SME/control transmission with actual native air-terminal ownership.
use super::{
    ap::{self, Token},
    htt, management, Error, Hif, HostMemory, HttMemory, Radio,
};
use alloc::vec::Vec;
use narf_wireless::{ap_control::ApEmissionAuthority, ControlPortTxRequest, MgmtTxRequest};

impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    async fn ap_tx_space(
        &mut self,
        needs_htt: bool,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let deadline = narf_time::Deadline::after_ms(3000);
        for _ in 0..8192 {
            validate()?;
            self.ap_prefix(validate).await?;
            validate()?;
            if (!needs_htt || self.htt.source_ready()?)
                && self.ap.as_ref().is_some_and(|ap| ap.pending.len() < 32)
            {
                validate()?;
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = super::checked_policy(
                async { self.htt.poll().await.map_err(Error::from) },
                validate,
            )
            .await?;
            self.ap_event(event)?;
            narf_scheduler::yield_now().await;
        }
        Err(Error::Exhausted)
    }
    async fn ap_tx_result(
        &mut self,
        token: Token,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<bool, Error> {
        self.ap_wait(
            |ap| {
                ap.pending
                    .iter()
                    .any(|pending| pending.token == token && pending.status.is_some())
            },
            validate,
        )
        .await?;
        validate()?;
        let ap = self.ap.as_mut().ok_or(Error::Failed)?;
        let index = ap
            .pending
            .iter()
            .position(|pending| pending.token == token)
            .ok_or(Error::Failed)?;
        ap.pending.remove(index).status.ok_or(Error::Failed)
    }
    pub(in crate::ath10k) async fn ap_tx_control(
        &mut self,
        request: ControlPortTxRequest,
        source: ApEmissionAuthority,
        domain: &narf_wireless::reg::RegulatoryDomain,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(bool, ap::Capture), Error> {
        validate()?;
        self.ap_current(domain)?;
        if !self.ap_running() || !source.current() {
            return Err(Error::Failed);
        }
        let ap = self.ap.as_ref().unwrap();
        let peer = ap
            .peers
            .iter()
            .find(|peer| peer.record.mac == request.dest && peer.associated && peer.record.mapped())
            .ok_or(Error::Unsupported)?;
        let configured = request.ethertype == ap.plan.settings.control_port.ethertype;
        let encrypt = !request.no_encrypt
            && if configured {
                !ap.plan.settings.control_port.no_encrypt
            } else {
                ap.plan.config.privacy
            };
        if !ap.plan.settings.control_port.enabled
            || !configured && request.ethertype != narf_wireless::ETH_P_PREAUTH
            || request.pdu().is_empty()
            || request.pdu().len() > 1500
            || !configured && !peer.authorized
            || encrypt && peer.key.is_none()
        {
            return Err(Error::Unsupported);
        }
        let peer_fence = ap::PeerFence::capture(peer);
        let capture = ap.capture(!configured, true)?.with_peer(peer_fence);
        let current = || {
            validate()?;
            if !source.current() {
                return Err(Error::Failed);
            }
            capture.current(domain)
        };
        let mut ethernet = Vec::new();
        ethernet
            .try_reserve_exact(14 + request.pdu().len())
            .map_err(|_| Error::NoMemory)?;
        ethernet.extend_from_slice(&request.dest);
        ethernet.extend_from_slice(&ap.own.mac);
        ethernet.extend_from_slice(&request.ethertype.to_be_bytes());
        ethernet.extend_from_slice(request.pdu());
        self.ap_tx_space(true, &current).await?;
        let ap = self.ap.as_mut().unwrap();
        ap.pending.try_reserve(1).map_err(|_| Error::NoMemory)?;
        let (bytes, tid) = ap
            .ethernet(&ethernet, true, !encrypt)?
            .ok_or(Error::Failed)?;
        current()?;
        let id = self.htt.begin_transmit(
            htt::tx::Parameters {
                kind: htt::tx::Kind::Raw,
                vdev: self.primary.id(),
                tid,
                hardware_crypto: false,
            },
            &bytes,
        )?;
        let token = Token::Htt(id);
        self.ap.as_mut().unwrap().pending.push(ap::Pending {
            token,
            deadline: narf_time::Deadline::after_ms(3000),
            status: None,
            control: true,
        });
        let ack = self.ap_tx_result(token, &current).await?;
        Ok((ack, capture))
    }
    pub(in crate::ath10k) async fn ap_tx_management(
        &mut self,
        mut request: MgmtTxRequest,
        source: ApEmissionAuthority,
        domain: &narf_wireless::reg::RegulatoryDomain,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(bool, ap::Capture), Error> {
        validate()?;
        self.ap_current(domain)?;
        if !self.ap_running() || !source.current() {
            return Err(Error::Failed);
        }
        let ap = self.ap.as_ref().unwrap();
        let frame = &request.frame;
        if !(24..=2048).contains(&frame.len())
            || !matches!(frame[0], 0x10 | 0x30 | 0x50 | 0xb0 | 0xa0 | 0xc0 | 0xd0)
            || frame[1] & 0xc7 != 0
            || frame[4..10] == [0; 6]
            || frame[10..16] != ap.own.mac
            || frame[16..22] != ap.own.mac
            || frame[22] & 15 != 0
            || request.frequency_mhz != 0 && request.frequency_mhz != ap.plan.config.frequency_mhz
            || request.duration != 0
            || request.no_cck && ap.permission.frequency < 3000
        {
            return Err(Error::Unsupported);
        }
        // No PMF/SAE/optional PHY is advertised by this bounded AP owner.
        // Plain userspace-SME management never installs a key or opens DATA.
        if matches!(frame[0], 0x10 | 0x30) {
            if frame.len() < 30 {
                return Err(Error::Malformed);
            }
            for (id, body) in super::ap_wire::elements(&frame[30..])? {
                if matches!(id, 45 | 61 | 191 | 192 | 255) {
                    return Err(Error::Unsupported);
                }
                if id == 48 && narf_wireless::rsn::RsnIe::decode_body(body) != ap.plan.rsn {
                    return Err(Error::Unsupported);
                }
            }
        }
        if frame[0] == 0xb0 && (frame.len() != 30 || frame[24..28] != [0, 0, 2, 0]) {
            return Err(Error::Unsupported);
        }
        if frame[0] == 0x50 {
            if frame.len() < 36 {
                return Err(Error::Malformed);
            }
            let mut config = ap.plan.config.clone();
            config.beacon_head = frame.clone();
            config.beacon_head[0] = 0x80;
            config.beacon_head[4..10].fill(255);
            config.beacon_tail.clear();
            config.probe_resp = None;
            config.hidden_ssid = 0;
            let offered = super::ap_wire::Plan::new(
                config,
                ap.plan.settings.clone(),
                ap.own.mac,
                self.ap_uapsd(),
            )?;
            if offered.rsn != ap.plan.rsn
                || offered.rates != ap.plan.rates
                || offered.basic != ap.plan.basic
                || offered.wmm != ap.plan.wmm
            {
                return Err(Error::Unsupported);
            }
        }
        if matches!(frame[0], 0xa0 | 0xc0) && frame.len() != 26 {
            return Err(Error::Malformed);
        }
        if matches!(frame[0], 0xa0 | 0xc0) {
            let ap = self.ap.as_mut().unwrap();
            if let Some(peer) = ap
                .peers
                .iter_mut()
                .find(|peer| peer.record.mac == frame[4..10])
            {
                ap::Session::advance(&ap.data_epoch)?;
                ap::Session::advance(&ap.key_epoch)?;
                ap::Session::advance(&peer.denial)?;
                peer.authorized = false;
            }
        }
        let ap = self.ap.as_ref().unwrap();
        let mut capture = ap.capture(false, false)?;
        if let Some(peer) = ap
            .peers
            .iter()
            .find(|peer| peer.record.mac == frame[4..10] && peer.record.mapped())
        {
            capture = capture.with_peer(ap::PeerFence::capture(peer));
        }
        let current = || {
            validate()?;
            if !source.current() {
                return Err(Error::Failed);
            }
            capture.current(domain)
        };
        let multicast = request.frame[4] & 1 != 0;
        let path = management::path(
            self.wire.dialect,
            self.features,
            self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?,
        )?;
        self.ap_tx_space(path == management::Path::Htt, &current)
            .await?;
        let ap = self.ap.as_mut().unwrap();
        ap.pending.try_reserve(1).map_err(|_| Error::NoMemory)?;
        request.frame[22..24].copy_from_slice(&((ap.sequence & 4095) << 4).to_le_bytes());
        ap.sequence = ap.sequence.wrapping_add(1) & 4095;
        let token = match path {
            management::Path::Htt => Token::Htt(self.htt.begin_transmit(
                htt::tx::Parameters {
                    kind: htt::tx::Kind::Management,
                    vdev: self.primary.id(),
                    tid: 17,
                    hardware_crypto: false,
                },
                &request.frame,
            )?),
            management::Path::Reference => {
                let (id, address) = self
                    .htt
                    .wmi
                    .htc
                    .transport
                    .prepare_wmi_management(&request.frame)?;
                let token = Token::Wmi(id);
                self.ap.as_mut().unwrap().pending.push(ap::Pending {
                    token,
                    deadline: narf_time::Deadline::after_ms(3000),
                    status: None,
                    control: true,
                });
                self.ap_command(
                    &management::reference(id, address, &request.frame)?,
                    &current,
                )
                .await?;
                let ack = self.ap_tx_result(token, &current).await?;
                return Ok((ack && !multicast, capture));
            }
            management::Path::Inline(_) => return Err(Error::Unsupported),
        };
        self.ap.as_mut().unwrap().pending.push(ap::Pending {
            token,
            deadline: narf_time::Deadline::after_ms(3000),
            status: None,
            control: true,
        });
        let ack = self.ap_tx_result(token, &current).await?;
        Ok((ack && !multicast, capture))
    }
}
