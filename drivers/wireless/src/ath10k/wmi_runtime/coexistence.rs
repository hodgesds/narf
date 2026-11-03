// SPDX-License-Identifier: GPL-2.0-or-later
//! 2.4 GHz station SME OBSS control. Hostap sme.c owns the passive affected
//! channel scan and Public Action report; ath10k/mac.c owns native peer width.
//! A retained peer may narrow once, never reopen or widen an ambiguous restart.
use super::*;
use alloc::boxed::Box;
use narf_wireless::reg::RegulatoryDomain;

#[derive(Debug)]
pub(super) struct State {
    bssid: [u8; 6],
    primary: u16,
    secondary: u16,
    channels: Vec<u16>,
    interval: u64,
    deadline: narf_time::Deadline,
    pub allow_wide: bool,
    trigger: bool,
    report_channels: u16,
    intolerant: bool,
    report_pending: bool,
    scan_owned: bool,
    force_scan: bool,
    restart_started: bool,
    narrowed: bool,
}
fn element(mut ies: &[u8], id: u8) -> Result<Option<&[u8]>, Error> {
    let mut found = None;
    while !ies.is_empty() {
        let h = ies.get(..2).ok_or(Error::Malformed)?;
        let body = ies.get(2..2 + usize::from(h[1])).ok_or(Error::Malformed)?;
        if h[0] == id && found.replace(body).is_some() {
            return Err(Error::Malformed);
        }
        ies = &ies[2 + body.len()..];
    }
    Ok(found)
}
fn ht_cap(ies: &[u8]) -> Result<Option<u16>, Error> {
    element(ies, 45)?
        .map(|b| {
            if b.len() != 26 {
                return Err(Error::Malformed);
            }
            Ok(u16::from_le_bytes([b[0], b[1]]))
        })
        .transpose()
}
impl State {
    pub(super) fn blocked(&self) -> bool {
        self.allow_wide && self.trigger && !self.narrowed
    }
    fn new(bss: &ScanBss, secondary: u16, available: &[u16]) -> Result<Option<Self>, Error> {
        if bss.frequency >= 3000 || secondary.abs_diff(bss.frequency) != 20 {
            return Ok(None);
        }
        if element(&bss.information_elements, 7)?
            .is_some_and(|country| country.len() >= 6 && country[3] >= 201)
        {
            // Hostap cannot encode operating-class triplets as an unknown
            // class0 intolerant-channel report. Keep this unsupported form20.
            return Ok(None);
        }
        let Some(params) = element(&bss.information_elements, 74)? else {
            // No AP OBSS program: do not create new40 radiation authority.
            return Ok(None);
        };
        if params.len() != 14 {
            return Err(Error::Malformed);
        }
        // Hostap SME clamps BSS Channel Width Trigger Scan Interval to10s.
        let interval = u64::from(u16::from_le_bytes([params[4], params[5]]).max(10)) * 1000;
        let low = bss.frequency.min(secondary) - 10;
        let high = bss.frequency.max(secondary) + 10;
        let mut channels = Vec::new();
        for f in (2412..=2472u16).step_by(5) {
            if f - 10 < high && low < f + 10 {
                if !available.contains(&f) {
                    // An incomplete inventory never proves a clear OBSS.
                    return Ok(None);
                }
                channels.push(f);
            }
        }
        Ok(Some(Self {
            bssid: bss.bssid,
            primary: bss.frequency,
            secondary,
            channels,
            interval,
            deadline: narf_time::Deadline::after_ms(interval),
            allow_wide: true,
            trigger: false,
            report_channels: 0,
            intolerant: false,
            report_pending: false,
            scan_owned: false,
            force_scan: false,
            restart_started: false,
            narrowed: false,
        }))
    }
    fn observe(&mut self, bss: &ScanBss) -> Result<(), Error> {
        if !self.channels.contains(&bss.frequency) {
            return Ok(());
        }
        let cap = ht_cap(&bss.information_elements)?;
        if cap.is_none_or(|cap| cap == 0 || cap & 0x4000 != 0) {
            let channel = ((bss.frequency - 2407) / 5) as u8;
            self.report_channels |= 1 << (channel - 1);
            self.intolerant |= cap.is_some_and(|cap| cap & 0x4000 != 0);
            self.trigger = true;
            self.report_pending = true;
        }
        if let Some(coex) = element(&bss.information_elements, 72)? {
            if coex.len() != 1 || coex[0] & !31 != 0 {
                return Err(Error::Malformed);
            }
            if coex[0] & 6 != 0 {
                self.trigger = true;
                self.intolerant = true;
                self.report_pending = true;
            }
        }
        if bss.bssid == self.bssid {
            if let Some(op) = element(&bss.information_elements, 61)? {
                if op.len() != 22 || u16::from(op[0]) * 5 + 2407 != self.primary {
                    return Err(Error::Malformed);
                }
                let direction = if self.secondary > self.primary { 1 } else { 3 };
                if op[1] & 7 != (4 | direction) {
                    self.trigger = true;
                }
            }
        }
        Ok(())
    }
    fn report(&mut self, report: &ScanReport) -> Result<(), Error> {
        if report.truncated {
            return Err(Error::Exhausted);
        }
        // A complete scan replaces observations, but a width trigger is
        // sticky for this owner: absence later never widens a narrowed peer.
        self.report_channels = 0;
        // A latched20MHz request remains ours even if a later scan no longer
        // sees the original intolerant BSS; this owner never widens again.
        for bss in &report.bss {
            self.observe(bss)?;
        }
        self.report_pending = true;
        self.deadline = narf_time::Deadline::after_ms(self.interval);
        self.force_scan = false;
        Ok(())
    }
    fn action(&mut self, frame: &[u8], own: [u8; 6]) -> Result<(), Error> {
        if frame.len() < 26
            || frame[..2] != [0xd0, 0]
            || frame[22] & 15 != 0
            || (frame[4..10] != own && frame[4..10] != [255; 6])
            || frame[10..16] != self.bssid
            || frame[16..22] != self.bssid
            || frame[24..26] != [4, 0]
        {
            return Ok(());
        }
        let coex = element(&frame[26..], 72)?.ok_or(Error::Malformed)?;
        if coex.len() != 1 || coex[0] & !31 != 0 {
            return Err(Error::Malformed);
        }
        if let Some(channels) = element(&frame[26..], 73)? {
            if !(2..=14).contains(&channels.len()) || channels[0] != 0 {
                return Err(Error::Unsupported);
            }
            for c in &channels[1..] {
                if !(1..=13).contains(c) {
                    return Err(Error::Malformed);
                }
            }
        }
        self.force_scan |= coex[0] & 1 != 0;
        self.report_pending |= coex[0] & 1 != 0;
        if coex[0] & 6 != 0 {
            self.trigger = true;
            self.intolerant = true;
            self.report_pending = true;
        }
        Ok(())
    }
    fn frame(&self, own: [u8; 6]) -> Vec<u8> {
        let mut f = alloc::vec![0xd0, 0, 0, 0];
        f.extend_from_slice(&self.bssid);
        f.extend_from_slice(&own);
        f.extend_from_slice(&self.bssid);
        f.extend_from_slice(&[0, 0, 4, 0, 72, 1, if self.intolerant { 4 } else { 0 }]);
        if self.report_channels != 0 {
            f.extend_from_slice(&[73, self.report_channels.count_ones() as u8 + 1, 0]);
            for c in 1..=13 {
                if self.report_channels & (1 << (c - 1)) != 0 {
                    f.push(c);
                }
            }
        }
        f
    }
}
impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) async fn prepare_coexistence(
        &mut self,
        domain: &RegulatoryDomain,
        bssid: [u8; 6],
        frequency: u16,
        validate: &impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        if frequency >= 3000 {
            return Ok(());
        }
        if self
            .station
            .coexistence
            .as_ref()
            .is_some_and(|state| state.bssid == bssid && state.primary == frequency)
        {
            return Ok(());
        }
        let caps = self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?;
        let cached = self
            .scan_cache
            .iter()
            .find(|b| b.bssid == bssid && b.frequency == frequency)
            .ok_or(Error::Unsupported)?;
        let Some(profile) = ht::Profile::offer(
            caps,
            cached,
            self.ready.ok_or(Error::Failed)?.mac,
            ht::Phy::Ht40,
            self.chains.ok_or(Error::Failed)?,
        )?
        else {
            return Ok(());
        };
        let Some(secondary) = profile.secondary else {
            return Ok(());
        };
        if crate::ath10k::regulatory::Permission::occupied(caps, domain, frequency, Some(secondary))
            .is_err()
        {
            return Ok(());
        }
        let Some(mut state) = State::new(cached, secondary, &self.channels)? else {
            return Ok(());
        };
        associated_scan::receive_permission(domain, &state.channels)?;
        let report = self
            .scan_run(&state.channels, (&[], &[]), &[], None, || {
                validate()?;
                associated_scan::receive_permission(domain, &state.channels)
            })
            .await?;
        state.report(&report)?;
        state.allow_wide = !state.trigger;
        if !report
            .bss
            .iter()
            .any(|b| b.bssid == bssid && b.frequency == frequency)
        {
            return Err(Error::Unsupported);
        }
        self.station.coexistence = Some(Box::new(state));
        Ok(())
    }
    pub(super) fn coexistence_wide(&self, bssid: [u8; 6], frequency: u16) -> bool {
        self.station.coexistence.as_ref().is_some_and(|s| {
            s.bssid == bssid && s.primary == frequency && s.allow_wide && !s.trigger && !s.narrowed
        })
    }
    pub(super) fn coexistence_blocked(&self) -> bool {
        self.station
            .coexistence
            .as_ref()
            .is_some_and(|s| s.blocked())
    }
    pub(super) fn observe_coexistence(&mut self, event: &htt::Event) -> Result<(), Error> {
        let Some(state) = self.station.coexistence.as_mut() else {
            return Ok(());
        };
        let htt::Event::Wmi(bytes) = event else {
            return Ok(());
        };
        if wire::word(bytes, 0)? & 0xffffff != self.wire.management_event {
            return Ok(());
        }
        let m = self.wire.management(&bytes[4..], self.features)?;
        if m.status & !0x40 != 0 {
            return Ok(());
        }
        let blocked = state.blocked();
        if let Some(bss) = beacon(&m, &state.channels)? {
            state.observe(&bss)?;
        }
        if wire::channel_to_frequency(m.channel) == Some(state.primary) {
            state.action(&m.frame, self.ready.ok_or(Error::Failed)?.mac)?;
        }
        if !blocked && state.blocked() {
            self.coexistence_epoch
                .fetch_update(
                    core::sync::atomic::Ordering::AcqRel,
                    core::sync::atomic::Ordering::Acquire,
                    |epoch| epoch.checked_add(1),
                )
                .map_err(|_| Error::Exhausted)?;
        }
        Ok(())
    }
    pub(in crate::ath10k) fn coexistence_capture(
        &self,
    ) -> (alloc::sync::Arc<core::sync::atomic::AtomicU64>, u64) {
        (
            self.coexistence_epoch.clone(),
            self.coexistence_epoch
                .load(core::sync::atomic::Ordering::Acquire),
        )
    }
}
impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(super) fn coexistence_geometry(
        &self,
        bssid: [u8; 6],
        frequency: u16,
        secondary: Option<u16>,
    ) -> bool {
        self.coexistence_wide(bssid, frequency)
            && self
                .station
                .coexistence
                .as_ref()
                .is_some_and(|s| Some(s.secondary) == secondary)
    }
    pub(super) fn bind_coexistence_width(
        &mut self,
        bssid: [u8; 6],
        permission: &crate::ath10k::regulatory::Permission,
    ) -> Result<(), Error> {
        if permission.frequency >= 3000 {
            return Ok(());
        }
        if let Some(state) = &mut self.station.coexistence {
            if state.bssid != bssid || state.primary != permission.frequency {
                return Err(Error::Failed);
            }
            if permission.secondary.is_some()
                && (!state.allow_wide
                    || state.trigger
                    || permission.secondary != Some(state.secondary))
            {
                return Err(Error::Unsupported);
            }
            state.allow_wide = permission.secondary.is_some();
        } else if permission.secondary.is_some() {
            return Err(Error::Unsupported);
        }
        Ok(())
    }
    /// Called by the retained normal management worker. An internal scan
    /// retains its own terminal/restore owner; it cannot steal a public scan.
    pub(super) async fn service_coexistence(
        &mut self,
        domain: &RegulatoryDomain,
    ) -> Result<bool, Error> {
        if self.failed
            || self
                .station
                .peer
                .as_ref()
                .is_none_or(|p| p.associated.is_none() || p.mapped().is_none())
        {
            return Ok(false);
        }
        let Some(state) = self.station.coexistence.as_ref() else {
            return Ok(false);
        };
        if state.scan_owned {
            if !self.associated_scan_complete(domain)? {
                return Ok(false);
            }
            let report = self.finish_associated_scan(|| Ok(domain.clone())).await?;
            let state = self.station.coexistence.as_mut().ok_or(Error::Failed)?;
            state.scan_owned = false;
            state.report(&report)?;
        }
        let state = self.station.coexistence.as_ref().ok_or(Error::Failed)?;
        let report = state.report_pending;
        let blocked = self.coexistence_blocked();
        if blocked && !self.coexistence_ready() {
            // A running M4/rekey keeps its original key/terminal owner. DATA
            // admission already stopped; the same worker will retry afterward.
            return Ok(false);
        }
        if report {
            self.check_data_policy(domain)?;
            let frame = state.frame(self.ready.ok_or(Error::Failed)?.mac);
            management::validate(&frame, self.ready.ok_or(Error::Failed)?.mac, state.bssid)?;
            self.failed = true;
            self.send_management_frame(&frame).await?;
            self.check_data_policy(domain)?;
            self.station
                .coexistence
                .as_mut()
                .ok_or(Error::Failed)?
                .report_pending = false;
            self.failed = false;
        }
        if blocked {
            self.narrow_coexistence(domain).await?;
            return Ok(true);
        }
        let state = self.station.coexistence.as_ref().ok_or(Error::Failed)?;
        if !self.scan_in_progress() && (state.force_scan || state.deadline.expired()) {
            let channels = state.channels.clone();
            let plan = self.prepare_associated_passive_scan(&channels, domain)?;
            self.begin_associated_scan(plan, || Ok(domain.clone()))
                .await?;
            self.station
                .coexistence
                .as_mut()
                .ok_or(Error::Failed)?
                .scan_owned = true;
            return Ok(true);
        }
        Ok(report)
    }
    async fn narrow_coexistence(&mut self, domain: &RegulatoryDomain) -> Result<(), Error> {
        let peer = self.station.peer.as_ref().ok_or(Error::Failed)?;
        let old = peer.permission.clone();
        let bssid = peer.bssid;
        let profile = peer
            .ht
            .ok_or(Error::Failed)?
            .coexistence_twenty(old.frequency)?;
        if old.frequency >= 3000 || old.secondary.is_none() || self.scan_in_progress() {
            return Err(Error::Unsupported);
        }
        let permission = crate::ath10k::regulatory::Permission::from_domain(
            self.htt.wmi.caps.as_ref().ok_or(Error::Failed)?,
            domain,
            old.frequency,
        )?;
        let cached = self
            .scan_cache
            .iter()
            .find(|b| b.bssid == bssid && b.frequency == old.frequency)
            .ok_or(Error::Failed)?;
        let dtim = if let Some(tim) = element(&cached.information_elements, 5)? {
            if tim.len() < 4 || tim[1] == 0 || tim[0] >= tim[1] {
                return Err(Error::Malformed);
            }
            tim[1]
        } else {
            1
        };
        let vdev = self.station.peer.as_ref().ok_or(Error::Failed)?.vdev;
        let restart =
            self.wire
                .coexistence_restart(vdev, &permission, cached.beacon_interval, dtim)?;
        let parameters = self.wire.coexistence_peer(vdev, bssid)?;
        let inventory = self
            .wire
            .coexistence_channels(&permission, &self.channels)?;
        let power = self.wire.power(&permission)?;
        let state = self.station.coexistence.as_mut().ok_or(Error::Failed)?;
        if state.restart_started || state.narrowed || !state.allow_wide {
            return Err(Error::Failed);
        }
        // Before the first await: public DATA closes, this single native
        // RESTART type is reserved forever, and all queued RX loses admission.
        state.restart_started = true;
        self.failed = true;
        self.discard_coexistence_receive()?;
        let validate = || {
            old.check(domain)?;
            permission.check(domain)
        };
        let deadline = narf_time::Deadline::after_ms(5000);
        let mut drained = false;
        for _ in 0..4096 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = checked_policy(self.station_progress(), &validate).await?;
            while let Some(receipt) = self.htt.take_tx_receipt() {
                self.coexistence_receipt(receipt)?;
            }
            if self
                .station
                .peer
                .as_ref()
                .is_none_or(|p| p.bssid != bssid || p.mapped().is_none() || p.associated.is_none())
            {
                return Err(Error::Failed);
            }
            if matches!(event, htt::Event::Idle)
                && self.tx_in_flight() == 0
                && self.htt.source_ready()?
            {
                drained = true;
                break;
            }
            narf_scheduler::yield_now().await;
        }
        if !drained {
            return Err(Error::Exhausted);
        }
        // Drain the completed WMI source prefix before publishing the unique
        // restart. Old START/foreign-vdev responses cannot satisfy type1.
        checked_policy(
            async {
                self.htt
                    .wmi
                    .htc
                    .wait_wmi_source()
                    .await
                    .map_err(htt::Error::from)?;
                Ok(())
            },
            &validate,
        )
        .await?;
        // Keep the original global RF ceiling until the real20 response.
        // A20-only host rule may allow more power than the old full40 span;
        // raising PDEV power now would loosen still-owned old40 emissions.
        for command in [&parameters[0], &parameters[1], &inventory, &restart] {
            self.send_station_command(command, &validate).await?;
        }
        let mut restarted = false;
        for _ in 0..65536 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = checked_policy(self.station_progress(), &validate).await?;
            if self
                .station
                .peer
                .as_ref()
                .is_none_or(|p| p.bssid != bssid || p.mapped().is_none() || p.associated.is_none())
            {
                return Err(Error::Failed);
            }
            if let htt::Event::Wmi(bytes) = event {
                if wire::word(&bytes, 0)? & 0xffffff == self.wire.start_response_id()
                    && self.wire.coexistence_response(vdev, &bytes[4..])?.is_some()
                {
                    restarted = true;
                    break;
                }
            }
            narf_scheduler::yield_now().await;
        }
        if !restarted {
            return Err(Error::Timeout);
        }
        self.send_station_command(&power, &validate).await?;
        // Consume the captured pre-publication RX prefix under old admission;
        // no frame seen during the transition can acquire the new20 epoch.
        let mut settled = false;
        for _ in 0..4096 {
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let event = checked_policy(self.station_progress(), &validate).await?;
            if self
                .station
                .peer
                .as_ref()
                .is_none_or(|p| p.bssid != bssid || p.mapped().is_none() || p.associated.is_none())
            {
                return Err(Error::Failed);
            }
            if matches!(event, htt::Event::Idle) {
                settled = true;
                break;
            }
            narf_scheduler::yield_now().await;
        }
        if !settled {
            return Err(Error::Exhausted);
        }
        validate()?;
        self.discard_coexistence_receive()?;
        let source = self.htt.wmi.htc.transport.current_sources();
        crate::ath10k::firmware_source::invoke(source.as_ref(), || {
            self.narrow_coexistence_receive(permission.frequency)?;
            let peer = self.station.peer.as_mut().ok_or(Error::Failed)?;
            peer.permission = permission;
            peer.ht = Some(profile);
            let state = self.station.coexistence.as_mut().ok_or(Error::Failed)?;
            state.narrowed = true;
            self.failed = false;
            Ok::<(), Error>(())
        })
        .map_err(|_| Error::Failed)??;
        Ok(())
    }
}

impl wire::Wire {
    fn coexistence_restart(
        self,
        vdev: u8,
        permission: &crate::ath10k::regulatory::Permission,
        beacon: u16,
        dtim: u8,
    ) -> Result<Vec<u8>, Error> {
        let mut command = self.start_station(vdev, permission, beacon, dtim)?;
        // Every native dialect places RESTART immediately after START.
        let id = wire::word(&command, 0)?;
        wire::put(&mut command, 0, id + 1);
        let at = if self.dialect == Dialect::Tlv { 84 } else { 4 };
        wire::put(&mut command, at + 12, 5 | (1 << 11)); //11NG_HT20, real center=primary.
        Ok(command)
    }
    /// `WMI_PEER_SET_PARAM` on the BSS peer of the station `vdev`.
    fn coexistence_peer(self, vdev: u8, bssid: [u8; 6]) -> Result<[Vec<u8>; 2], Error> {
        let tlv = self.dialect == Dialect::Tlv;
        let id = match self.dialect {
            Dialect::Main | Dialect::Tlv => 0x6004,
            Dialect::TenOne | Dialect::TenTwo | Dialect::TenTwoFour => 0x901f,
            Dialect::TenFour => 0x9025,
        };
        let command = |parameter, value| -> Result<Vec<u8>, Error> {
            let mut out = wire::packet(id, if tlv { 24 } else { 20 })?;
            let at = if tlv {
                wire::put(&mut out, 4, (100 << 16) | 20);
                8
            } else {
                4
            };
            wire::put(&mut out, at, u32::from(vdev));
            out[at + 4..at + 10].copy_from_slice(&bssid);
            wire::put(&mut out, at + 12, parameter);
            wire::put(&mut out, at + 16, value);
            Ok(out)
        };
        // Linux sta_rc_update_wk: PHYMODE then CHAN_WIDTH, not PEER_ASSOC
        // flags relabeled in host memory. These commands have no FW ACK.
        Ok([command(13, 5)?, command(4, 0)?])
    }
    fn coexistence_response(self, vdev: u8, body: &[u8]) -> Result<Option<()>, Error> {
        let b = if self.dialect == Dialect::Tlv {
            wire::tag(body, 40)?
        } else {
            body
        };
        if b.len() != 16 {
            return Err(Error::Malformed);
        }
        if wire::word(b, 0)? != u32::from(vdev) || wire::word(b, 4)? != 0 || wire::word(b, 8)? != 1
        {
            return Ok(None);
        }
        let status = wire::word(b, 12)?;
        if status != 0 {
            return Err(Error::Firmware(status));
        }
        Ok(Some(()))
    }
    fn coexistence_channels(
        self,
        permission: &crate::ath10k::regulatory::Permission,
        channels: &[u16],
    ) -> Result<Vec<u8>, Error> {
        let mut out = self.channels(channels)?;
        let tlv = self.dialect == Dialect::Tlv;
        let index = channels
            .iter()
            .position(|f| *f == permission.frequency)
            .ok_or(Error::Unsupported)?;
        let at = if tlv { 20 + index * 28 } else { 8 + index * 24 };
        wire::put(&mut out, at + 12, 1 | (1 << 11));
        for field in [17, 18, 21] {
            out[at + field] = permission.half_dbm;
        }
        Ok(out)
    }
}

pub(super) fn validate_report(ies: &[u8]) -> Result<(), Error> {
    let coex = element(ies, 72)?.ok_or(Error::Malformed)?;
    if coex.len() != 1 || coex[0] & !31 != 0 {
        return Err(Error::Malformed);
    }
    if let Some(channels) = element(ies, 73)? {
        if !(2..=14).contains(&channels.len()) || channels[0] != 0 {
            return Err(Error::Malformed);
        }
        let mut seen = 0u16;
        for channel in &channels[1..] {
            if !(1..=13).contains(channel) || seen & (1 << (channel - 1)) != 0 {
                return Err(Error::Malformed);
            }
            seen |= 1 << (channel - 1);
        }
    }
    let mut remaining = ies;
    while !remaining.is_empty() {
        if !matches!(remaining[0], 72 | 73) {
            return Err(Error::Unsupported);
        }
        remaining = &remaining[2 + usize::from(remaining[1])..];
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "coexistence_tests.rs"]
mod tests;
#[cfg(any(test, feature = "kernel-test"))]
impl<T: Hif + HostMemory + HttMemory> Radio<T> {
    pub(in crate::ath10k) fn expire_coexistence_for_test(&mut self) {
        if let Some(state) = &mut self.station.coexistence {
            state.deadline = narf_time::Deadline::after_ms(0);
        }
    }
}
