// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! API77 native RSNA/key owner. Linux mvm/{sta,rxmq,mac80211}.c and
//! fw/api/{sta,rx,tx}.h. Crypto verification never substitutes for firmware
//! key, RX-epoch or positive EAPOL TX receipts.
use super::super::{
    boot_context::{put16, put32},
    frame_api, security,
};
use super::{data::LegacyDataStatus, Owner, Phase};
use alloc::{collections::VecDeque, vec::Vec};
use narf_wireless::{
    eapol::{KeyFrame, KI_KEY_MIC, KI_KEY_TYPE_PAIRWISE},
    reg::RegulatoryDomain,
};
use zeroize::Zeroizing;

const KEY: u8 = 0x17;
const HISTORY: usize = 32;

struct NativeKey {
    material: Zeroizing<[u8; 16]>,
    id: u8,
    group: bool,
    slot: u8,
    rsc: u64,
    api: u8,
    peer: [u8; 6],
    /// Pairwise TX PN handed to firmware (`transmit_seq_cnt`). Zero for
    /// fresh material; a safely reused PTK starts above its retired floor.
    tx_pn: u64,
    /// `Hardware::protected_transmits` when this key became device-visible.
    tx_base: u64,
    /// Per-TID host RX replay floors restored for a reused PTK.
    restored: Option<[u64; 17]>,
}

struct KeyHistory {
    digest: [u8; 32],
    peer: [u8; 6],
    group: bool,
    id: u8,
    floors: [u64; 17],
    /// Upper bound of every pairwise TX PN the firmware may have used with
    /// this material: its install PN plus each protected MPDU published
    /// while it was installed (retries reuse their PN).
    tx_floor: u64,
    /// Only native key REMOVE followed by the exact RX marker sets this.
    retired: bool,
}

/// What a retired history entry permits for newly authenticated material
/// with the same fingerprint. Replay floors only ever rise.
///
/// * GTK (RX-only): restorable after an initial four-way exchange from any
///   peer and at any key index (cross-peer / cross-index restore). The
///   floor is per key material, so the maximum committed TID floor
///   carries over unchanged (Linux `sta.c` single install RSC).
/// * PTK: reusable only from the same peer at index 0. Host RX replay
///   floors are restored per TID instead of reset, and the firmware TX PN
///   starts above every PN the old installation could have used, so no
///   CCMP nonce repeats (Linux `iwl_mvm_send_sta_key` `transmit_seq_cnt`).
/// * A live (unretired) entry or a role change is never reused.
fn restore_retired(
    previous: &KeyHistory,
    key: &mut NativeKey,
    first_keys: bool,
) -> Result<(), &'static str> {
    if !previous.retired || previous.group != key.group || !first_keys && key.group {
        return Err("MVM retired key role/peer/epoch reuse");
    }
    let floor = *previous.floors.iter().max().unwrap();
    if key.group {
        key.rsc = key.rsc.max(floor);
        if key.rsc >= 0xffff_ffff_ffff {
            return Err("MVM retired GTK PN exhausted");
        }
        return Ok(());
    }
    if previous.peer != key.peer || previous.id != key.id {
        return Err("MVM retired PTK cross-peer reuse");
    }
    let tx = previous
        .tx_floor
        .checked_add(1)
        .filter(|pn| *pn < 0xffff_ffff_ffff)
        .ok_or("MVM retired PTK TX PN exhausted")?;
    if floor >= 0xffff_ffff_ffff {
        return Err("MVM retired PTK RX PN exhausted");
    }
    key.tx_pn = tx;
    key.rsc = floor;
    key.restored = Some(previous.floors);
    Ok(())
}

struct Pending {
    reply: Vec<u8>,
    change: Option<security::KeyUpdate>,
    frame: Vec<u8>,
    install: Vec<Option<NativeKey>>,
    changed: Vec<usize>,
}

/// An IGTK this owner installed with MGMT_MCAST_KEY (index 4 or 5).
struct InstalledIgtk {
    material: Zeroizing<[u8; 16]>,
    id: u16,
}

struct Exchange {
    session: security::Session,
    /// WPA3-SAE: every key carries `STA_KEY_MFP` and IGTKs are installed.
    pmf: bool,
    igtks: [Option<InstalledIgtk>; 2],
    keys: [Option<NativeKey>; 5],
    incoming: VecDeque<(Vec<u8>, bool)>,
    pending: Option<Pending>,
    waiting: bool,
    complete: bool,
    key_api: u8,
    first_keys: bool,
}

#[derive(Default)]
pub(super) struct Context {
    active: Option<Exchange>,
    // Retired key material must never reset a PN during this native owner
    // lifetime, even after association/data teardown and recreation.
    history: Vec<KeyHistory>,
    cookie: u32,
    mic_keys: bool,
    /// Station identity whose radio-scoped ledger this owner adopted.
    ledger: Option<[u8; 6]>,
}

/// Radio-scoped retired-key ledgers, keyed by station MAC. A native owner
/// adopts its radio's ledger after configuration and hands it back when it
/// is dropped, so a later owner of the same radio (re-probe/rebind) keeps
/// every replay floor and TX PN bound instead of starting from an empty
/// history. Entries hold only key fingerprints and counters, never key
/// material. Entries still live when their owner dropped stay unretired,
/// so they are never reused, only kept as floors.
static LEDGERS: narf_lib::sync::IrqSafeSpinLock<Vec<([u8; 6], Vec<KeyHistory>)>> =
    narf_lib::sync::IrqSafeSpinLock::new(Vec::new());
/// Bound on retained radio identities; the oldest ledger is evicted.
const LEDGER_RADIOS: usize = 4;

impl Drop for Context {
    fn drop(&mut self) {
        let Some(mac) = self.ledger else {
            return;
        };
        let history = core::mem::take(&mut self.history);
        let mut ledgers = LEDGERS.lock();
        ledgers.retain(|(owner, _)| *owner != mac);
        if ledgers.len() == LEDGER_RADIOS {
            ledgers.remove(0);
        }
        ledgers.push((mac, history));
    }
}

impl Context {
    /// Adopt the ledger a previous owner of this radio left behind, merging
    /// by fingerprint (floors and TX bounds only rise; an entry stays
    /// reusable only if both copies are retired).
    pub(super) fn adopt_ledger(&mut self, mac: [u8; 6]) {
        if self.ledger.is_some() {
            return;
        }
        self.ledger = Some(mac);
        let mut ledgers = LEDGERS.lock();
        let Some(index) = ledgers.iter().position(|(owner, _)| *owner == mac) else {
            return;
        };
        let (_, previous) = ledgers.remove(index);
        drop(ledgers);
        for entry in previous {
            if let Some(own) = self.history.iter_mut().find(|h| h.digest == entry.digest) {
                for (saved, old) in own.floors.iter_mut().zip(entry.floors) {
                    *saved = (*saved).max(old);
                }
                own.tx_floor = own.tx_floor.max(entry.tx_floor);
                own.retired &= entry.retired;
            } else {
                // Never drop a floor: an over-full ledger makes later key
                // installation fail closed ("history exhausted").
                self.history.push(entry);
            }
        }
    }
    pub(super) fn new(api: &super::super::firmware_api::FirmwareApi<'_>) -> Self {
        Self {
            active: None,
            history: Vec::new(),
            cookie: 0,
            mic_keys: api.api_changes[0] & (1 << 29) != 0,
            ledger: None,
        }
    }
    pub(super) fn ready(&self) -> bool {
        self.active
            .as_ref()
            .is_some_and(|s| s.complete && !s.waiting && s.pending.is_none() && s.keys[0].is_some())
    }
    pub(super) fn started(&self) -> bool {
        self.active.is_some()
    }
    pub(super) fn needs_service(&self) -> bool {
        self.active.as_ref().is_some_and(|s| !s.incoming.is_empty())
    }
    pub(super) fn has_pairwise(&self) -> bool {
        self.active.as_ref().is_some_and(|s| s.keys[0].is_some())
    }
    pub(super) fn receive(
        &mut self,
        ethernet: Vec<u8>,
        encrypted: bool,
    ) -> Result<(), &'static str> {
        let active = self.active.as_mut().ok_or("MVM RSNA owner missing")?;
        if active.incoming.len() == 8 {
            return Err("MVM EAPOL input overflow");
        }
        active.incoming.push_back((ethernet, encrypted));
        Ok(())
    }
}

fn key_command(key: &NativeKey, remove: bool, mfp: bool) -> Zeroizing<[u8; 76]> {
    let mut bytes = Zeroizing::new([0; 76]);
    bytes[1] = key.slot;
    // Linux iwl_mvm_send_sta_key adds STA_KEY_MFP for an MFP station.
    let flags = 8
        | u16::from(key.id) << 8
        | if key.group { 1 << 14 } else { 0 }
        | if mfp { super::pmf::STA_KEY_MFP } else { 0 }
        | if remove { 1 << 11 } else { 2 };
    put16(&mut bytes[..], 2, flags);
    if !remove {
        bytes[4..20].copy_from_slice(key.material.as_ref());
        // Match sta.c's memcpy from ieee80211_key_seq.ccmp.pn (six
        // most-significant-first bytes). v2 leaves a hole at2/3; v3
        // keeps the six bytes contiguous. TX sequence below is LE64.
        let pn = key.rsc.to_be_bytes();
        bytes[36..38].copy_from_slice(&pn[2..4]);
        let tail = if key.api == 2 { 40 } else { 38 };
        bytes[tail..tail + 4].copy_from_slice(&pn[4..]);
        // Native TX PN starts0 only for authenticated new material; a
        // reused PTK continues above its retired floor. Firmware owns
        // increments and IV/MIC insertion; retries never re-add this key.
        if !key.group {
            bytes[68..76].copy_from_slice(&key.tx_pn.to_le_bytes());
        }
    }
    bytes
}

fn success(bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.len() != 4 || u32::from_le_bytes(bytes.try_into().unwrap()) != 1 {
        return Err("MVM native key/peer status rejected");
    }
    Ok(())
}

impl Owner {
    pub(super) fn security_status(&self) -> Result<LegacyDataStatus, &'static str> {
        let data = self
            .power
            .prepared
            .as_ref()
            .and_then(|p| p.mlme.data.as_ref())
            .ok_or("MVM RSNA data context missing")?;
        if !data.status.protected
            || !self
                .hardware
                .idle_tx_binding(data.queue.ok_or("MVM RSNA queue absent")?, 0, 0)
        {
            return Err("MVM RSNA requires an idle protected data binding");
        }
        Ok(LegacyDataStatus {
            bssid: data.status.bssid,
            channel: data.status.channel,
            queue: data.queue.unwrap(),
            supported_rates: data.status.supported_rates,
            protected: true,
        })
    }
    pub(super) fn security_api(&self) -> Result<u8, &'static str> {
        // sta.c uses API_TKIP_MIC_KEYS to select the76-byte command and
        // iwl_fw_lookup_cmd_ver(..., new_api ? 2 : 1). Missing/UNKNOWN
        // table records therefore meanv2 here, not an absent command.
        let version = match self.hardware.version(1, KEY).map(|v| v.0) {
            None | Some(99) => 2,
            Some(version) => version,
        };
        // mac80211.c sends the fixed RX sync-v1 structure without a
        // version lookup. Respect an explicit incompatible table record,
        // but do not invent a requirement that unversioned IDs be listed.
        if !self.security.mic_keys
            || !matches!(version, 2 | 3)
            || self
                .hardware
                .version(5, 2)
                .is_some_and(|v| !matches!(v.0, 1 | 99))
            || self
                .hardware
                .version(5, 0xff)
                .is_some_and(|v| !matches!(v.1, 1 | 99))
        {
            return Err("unsupported MVM key-v2/v3/RX-sync-v1 contract");
        }
        Ok(version)
    }

    pub async fn secure_legacy_wpa2(&mut self, pmk: [u8; 32]) -> Result<(), &'static str> {
        self.secure_using(pmk, security::fresh_nonce, || {
            narf_wireless::reg::db::get_domain().ok_or("MVM WPA2 policy unavailable")
        })
        .await
    }
    pub(super) async fn secure_using(
        &mut self,
        pmk: [u8; 32],
        nonce: impl FnMut() -> Result<[u8; 32], &'static str>,
        policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        let pmk = Zeroizing::new(pmk);
        if self.associated_pmf() {
            return Err("MVM PMF association requires its SAE PMK owner");
        }
        self.secure_with(security::Akm::Wpa2Psk, pmk, nonce, policy)
            .await
    }

    /// WPA3-SAE four-way exchange with the PMK the retained SAE
    /// authentication derived. The station RSNE in message 2 repeats the
    /// association request's (with its PMKID); message 3 must carry the
    /// IGTK, which is installed with MGMT_MCAST_KEY.
    pub async fn secure_legacy_sae(&mut self) -> Result<(), &'static str> {
        self.secure_sae_using(security::fresh_nonce, || {
            narf_wireless::reg::db::get_domain().ok_or("MVM WPA3 policy unavailable")
        })
        .await
    }
    pub(super) async fn secure_sae_using(
        &mut self,
        nonce: impl FnMut() -> Result<[u8; 32], &'static str>,
        policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if !self.associated_pmf() {
            return Err("MVM SAE security requires a PMF association");
        }
        let pmk = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.sae_pmk.take())
            .ok_or("MVM SAE PMK absent or already consumed")?;
        self.secure_with(security::Akm::Wpa3Sae, pmk, nonce, policy)
            .await
    }
    fn associated_pmf(&self) -> bool {
        self.power
            .prepared
            .as_ref()
            .and_then(|p| p.mlme.data.as_ref())
            .is_some_and(|d| d.status.pmf)
    }
    async fn secure_with(
        &mut self,
        akm: security::Akm,
        pmk: Zeroizing<[u8; 32]>,
        mut nonce: impl FnMut() -> Result<[u8; 32], &'static str>,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if self.phase != Phase::DataPrepared || self.security.started() {
            return Err("MVM WPA2 already started or data owner not ready");
        }
        let status = self.security_status()?;
        let key_api = self.security_api()?;
        if let Err(error) = policy().and_then(|domain| self.check_link_power(&domain)) {
            return self.data_failed(error);
        }
        let own = self.mac.ok_or("MVM WPA2 MAC missing")?;
        let rsn = self
            .beacons
            .iter()
            .find(|b| b.bssid == status.bssid && b.channel == status.channel)
            .and_then(|b| {
                let mut ies = b.information_elements.as_slice();
                while ies.len() >= 2 {
                    let end = 2 + usize::from(ies[1]);
                    let bytes = ies.get(2..end)?;
                    if ies[0] == 48 {
                        return Some(bytes.to_vec());
                    }
                    ies = &ies[end..];
                }
                None
            })
            .ok_or("MVM actual WPA2 RSN offer absent")?;
        let pmf = akm == security::Akm::Wpa3Sae;
        let station_rsn = if pmf {
            Some(
                self.power
                    .prepared
                    .as_ref()
                    .and_then(|p| p.mlme.plan.as_ref())
                    .and_then(|plan| plan.rsn_body())
                    .ok_or("MVM SAE association RSNE absent")?,
            )
        } else {
            None
        };
        let snonce = Zeroizing::new(nonce()?);
        let session = security::Session::new(akm, *pmk, status.bssid, own, *snonce, rsn);
        self.security.active = Some(Exchange {
            session: match station_rsn {
                Some(body) => session.with_station_rsn(body),
                None => session,
            },
            pmf,
            igtks: [None, None],
            keys: core::array::from_fn(|_| None),
            incoming: VecDeque::new(),
            pending: None,
            waiting: true,
            complete: false,
            key_api,
            first_keys: true,
        });
        self.phase = Phase::SecuringData;
        let result = async {
            self.fresh_data_policy(&mut policy).await?;
            let reply = self
                .qualified_link_command(1, 0x18, &super::auth::disable_tx(false), &mut policy)
                .await?;
            success(&reply)?;
            self.security_loop(&mut nonce, &mut policy).await
        }
        .await;
        self.finish_security(result)
    }

    /// Drive captured native EAPOL rekeys/retransmissions with the same PMK,
    /// key slots, replay and current qualification owner. No caller RX bytes.
    pub async fn service_legacy_wpa2(&mut self) -> Result<(), &'static str> {
        self.service_security_using(security::fresh_nonce, || {
            narf_wireless::reg::db::get_domain().ok_or("MVM WPA2 policy unavailable")
        })
        .await
    }
    pub(super) async fn service_security_using(
        &mut self,
        mut nonce: impl FnMut() -> Result<[u8; 32], &'static str>,
        mut policy: impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if self.phase != Phase::DataPrepared || !self.security.started() {
            return Err("MVM RSNA service owner absent");
        }
        if let Err(e) = policy().and_then(|domain| self.check_link_power(&domain)) {
            return self.data_failed(e);
        }
        if self.security.active.as_ref().unwrap().incoming.is_empty() {
            return Ok(());
        }
        self.power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap()
            .port_open = false;
        self.clear_data_aggregate();
        self.phase = Phase::SecuringData;
        let result = self.security_loop(&mut nonce, &mut policy).await;
        self.finish_security(result)
    }

    fn finish_security(&mut self, result: Result<(), &'static str>) -> Result<(), &'static str> {
        match result {
            Ok(()) => {
                self.power
                    .prepared
                    .as_mut()
                    .unwrap()
                    .mlme
                    .data
                    .as_mut()
                    .unwrap()
                    .port_open = true;
                self.phase = Phase::DataPrepared;
                Ok(())
            }
            Err(e) => self.data_failed(e),
        }
    }

    async fn security_loop(
        &mut self,
        nonce: &mut impl FnMut() -> Result<[u8; 32], &'static str>,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        let deadline = narf_time::Deadline::after_ms(6000);
        for _ in 0..4096 {
            self.check_link_power(&policy()?)?;
            let activity = self.hardware.activity();
            // Shared native receive checks bind the current AP/channel,
            // rates, CRC/crypto metadata and every packet's current grant.
            self.receive_data_inner(policy)?;
            let next = self.security.active.as_mut().unwrap().incoming.pop_front();
            if let Some((ethernet, encrypted)) = next {
                let pdu = ethernet.get(14..).ok_or("short native EAPOL")?;
                let key = KeyFrame::decode(pdu.get(4..).ok_or("short EAPOL key")?, 16)
                    .ok_or("malformed EAPOL key")?;
                let challenge = key.key_information & (KI_KEY_TYPE_PAIRWISE | KI_KEY_MIC)
                    == KI_KEY_TYPE_PAIRWISE;
                let active = self.security.active.as_mut().unwrap();
                if active.complete
                    && !encrypted
                    && !challenge
                    && key.key_information & KI_KEY_TYPE_PAIRWISE == 0
                {
                    return Err("unprotected group rekey");
                }
                let response = active.session.process_with_nonce(pdu, &mut *nonce)?;
                if challenge {
                    active.waiting = true;
                }
                let own = self.mac.unwrap();
                let status = self.security_status()?;
                let old_key = self.security.active.as_ref().unwrap().keys[0].is_some();
                let data = self
                    .power
                    .prepared
                    .as_mut()
                    .unwrap()
                    .mlme
                    .data
                    .as_mut()
                    .unwrap();
                let mut bytes = frame_api::transmit(
                    own,
                    status.bssid,
                    data.sequence,
                    &ethernet_reply(own, status.bssid, &response.bytes),
                    old_key,
                )
                .ok_or("MVM EAPOL reply geometry")?;
                data.sequence = data.sequence.wrapping_add(1) & 4095;
                // EAPOL uses the management/non-QoS queue, never an ordinary
                // Ethernet producer. The native old PTK protects rekey replies.
                bytes[16..22].copy_from_slice(&status.bssid);
                let install = self.key_changes(response.keys.as_ref())?;
                self.security.active.as_mut().unwrap().pending = Some(Pending {
                    reply: response.bytes,
                    change: response.keys,
                    frame: bytes,
                    install,
                    changed: Vec::new(),
                });
                self.deliver_security_reply(policy).await?;
            }
            self.check_link_power(&policy()?)?;
            if deadline.expired() {
                return Err("MVM native RSNA deadline");
            }
            if self.security.ready() && self.security.active.as_ref().unwrap().incoming.is_empty() {
                // Native control/TX waits can have collected a later AP
                // close or EAPOL challenge. Drain those before port commit.
                self.receive_data_inner(policy)?;
                if self.security.active.as_ref().unwrap().incoming.is_empty() {
                    self.check_link_power(&policy()?)?;
                    return Ok(());
                }
            }
            if self.security.active.as_ref().unwrap().incoming.is_empty()
                && !self
                    .hardware
                    .notifications
                    .iter()
                    .any(|p| p.header.group_id == 0 && p.header.cmd == 0xc1)
            {
                activity.await;
            }
        }
        Err("MVM native RSNA receive budget")
    }

    async fn deliver_security_reply(
        &mut self,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        self.fresh_data_policy(policy).await?;
        let queue = self
            .management_queue
            .ok_or("MVM EAPOL management owner absent")?
            .id
            .ok_or("MVM EAPOL management queue absent")?;
        if !self.hardware.idle_tx_binding(queue, 0, 15) {
            return Err("MVM EAPOL management queue not terminal");
        }
        let status = self.security_status()?;
        let rate = super::super::rates::Rates {
            supported: status.supported_rates,
            basic: self
                .power
                .prepared
                .as_ref()
                .unwrap()
                .mlme
                .data
                .as_ref()
                .unwrap()
                .status
                .basic_rates,
        }
        .management_rate(
            self.nvm.as_ref().unwrap().tx_chains
                & self.nvm.as_ref().unwrap().tx_chains.wrapping_neg(),
        );
        let frame = self
            .security
            .active
            .as_ref()
            .unwrap()
            .pending
            .as_ref()
            .unwrap()
            .frame
            .clone();
        let reply = &self
            .security
            .active
            .as_ref()
            .unwrap()
            .pending
            .as_ref()
            .unwrap()
            .reply;
        if frame.get(32..) != Some(reply.as_slice()) {
            return Err("MVM retained EAPOL reply changed before native publication");
        }
        self.qualified_management_transmit(queue, &frame, rate, policy)
            .await?;
        if !self.hardware.idle_tx_binding(queue, 0, 15) {
            return Err("MVM EAPOL completion not terminal");
        }
        if self
            .security
            .active
            .as_ref()
            .unwrap()
            .pending
            .as_ref()
            .unwrap()
            .change
            .is_some()
        {
            self.apply_security_keys(policy).await?;
            let active = self.security.active.as_mut().unwrap();
            active.waiting = false;
            active.complete = true;
        }
        self.security.active.as_mut().unwrap().pending = None;
        Ok(())
    }

    fn key_changes(
        &self,
        change: Option<&security::KeyUpdate>,
    ) -> Result<Vec<Option<NativeKey>>, &'static str> {
        let Some(change) = change else {
            return Ok(Vec::new());
        };
        let pmf = self.security.active.as_ref().unwrap().pmf;
        if change
            .igtk
            .is_some_and(|(_, id, ipn)| !pmf || !matches!(id, 4 | 5) || ipn >> 48 != 0)
            || change.group_id > 3
            || change.group_rx_pn >> 48 != 0
        {
            return Err("unsupported MVM key update");
        }
        let mut keys = Vec::new();
        let api = self.security.active.as_ref().unwrap().key_api;
        let peer = self.security_status()?.bssid;
        if let Some(material) = change.pairwise {
            keys.push(NativeKey {
                material: Zeroizing::new(material),
                id: 0,
                group: false,
                slot: 0,
                rsc: 0,
                api,
                peer,
                tx_pn: 0,
                tx_base: 0,
                restored: None,
            });
        }
        keys.push(NativeKey {
            material: Zeroizing::new(change.group),
            id: change.group_id,
            group: true,
            slot: change.group_id + 1,
            rsc: change.group_rx_pn,
            api,
            peer,
            tx_pn: 0,
            tx_base: 0,
            restored: None,
        });
        let mut install = Vec::new();
        for mut key in keys {
            let index = usize::from(key.slot);
            if let Some(old) = self.security.active.as_ref().unwrap().keys[index].as_ref() {
                if old.material.as_ref() == key.material.as_ref() {
                    continue;
                }
            }
            let digest = key_digest(key.material.as_ref());
            let previous = self
                .security
                .history
                .iter()
                .find(|entry| entry.digest == digest);
            if let Some(previous) = previous {
                restore_retired(
                    previous,
                    &mut key,
                    self.security.active.as_ref().unwrap().first_keys,
                )?;
            }
            let fresh = install
                .iter()
                .flatten()
                .filter(|k: &&NativeKey| {
                    !self
                        .security
                        .history
                        .iter()
                        .any(|h| h.digest == key_digest(k.material.as_ref()))
                })
                .count();
            if previous.is_none() && self.security.history.len() + fresh >= HISTORY
                || install
                    .iter()
                    .flatten()
                    .any(|k: &NativeKey| key_digest(k.material.as_ref()) == digest)
            {
                return Err("MVM key history exhausted/aliased");
            }
            install.push(Some(key));
        }
        Ok(install)
    }

    /// Snapshot only already-committed PN floors before native retirement.
    /// The ledger remains non-reusable until the later single-RFH marker.
    fn snapshot_key_history(&mut self, slot: usize) -> Result<usize, &'static str> {
        let key = self.security.active.as_ref().unwrap().keys[slot]
            .as_ref()
            .ok_or("MVM key retirement owner absent")?;
        let digest = key_digest(key.material.as_ref());
        let index = self
            .security
            .history
            .iter()
            .position(|entry| {
                entry.digest == digest
                    && entry.peer == key.peer
                    && entry.group == key.group
                    && entry.id == key.id
            })
            .ok_or("MVM key retirement history identity absent")?;
        let data = self
            .power
            .prepared
            .as_ref()
            .unwrap()
            .mlme
            .data
            .as_ref()
            .unwrap();
        let floor = if key.group {
            data.replay.group[usize::from(key.id)]
        } else {
            data.replay.pairwise
        };
        let used = if key.group {
            0
        } else {
            key.tx_pn.saturating_add(
                self.hardware
                    .protected_transmits()
                    .wrapping_sub(key.tx_base),
            )
        };
        let entry = &mut self.security.history[index];
        for (saved, current) in entry.floors.iter_mut().zip(floor) {
            *saved = (*saved).max(current);
        }
        entry.tx_floor = entry.tx_floor.max(used);
        entry.retired = false;
        Ok(index)
    }

    async fn apply_security_keys(
        &mut self,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        self.clear_data_aggregate();
        self.retire_ba(Some(&mut *policy)).await?;
        let reply = self
            .qualified_link_command(1, 0x18, &super::auth::disable_tx(true), policy)
            .await?;
        success(&reply)?;
        let mut retired = Vec::new();
        let count = self
            .security
            .active
            .as_ref()
            .unwrap()
            .pending
            .as_ref()
            .unwrap()
            .install
            .len();
        for entry in 0..count {
            let key = self
                .security
                .active
                .as_ref()
                .unwrap()
                .pending
                .as_ref()
                .unwrap()
                .install[entry]
                .as_ref()
                .unwrap();
            let index = usize::from(key.slot);
            let pmf = self.security.active.as_ref().unwrap().pmf;
            let body = key_command(key, false, pmf);
            let digest = key_digest(key.material.as_ref());
            let (peer, group, id, rsc, tx_pn) = (key.peer, key.group, key.id, key.rsc, key.tx_pn);
            let old_history = if self.security.active.as_ref().unwrap().keys[index].is_some() {
                Some(self.snapshot_key_history(index)?)
            } else {
                None
            };
            if let Some(old) = self.security.active.as_ref().unwrap().keys[index].as_ref() {
                let remove = key_command(old, true, pmf);
                let reply = self
                    .qualified_link_command(1, KEY, &remove[..], policy)
                    .await?;
                success(&reply)?;
                self.security.active.as_mut().unwrap().keys[index] = None;
                retired.push(old_history.unwrap());
            }
            // Reserve the fingerprint BEFORE ADD can become device-visible.
            // An uncertain publication must not leave an old reusable GTK
            // proof, nor make fresh material appear unseen to a later owner.
            if let Some(entry) = self
                .security
                .history
                .iter_mut()
                .find(|h| h.digest == digest)
            {
                // A restored GTK may now live at another index or peer;
                // retirement must find the entry under its current identity.
                entry.retired = false;
                entry.peer = peer;
                entry.id = id;
                entry.tx_floor = entry.tx_floor.max(tx_pn);
                for pn in &mut entry.floors {
                    *pn = (*pn).max(rsc);
                }
            } else {
                self.security.history.push(KeyHistory {
                    digest,
                    peer,
                    group,
                    id,
                    floors: [rsc; 17],
                    tx_floor: tx_pn,
                    retired: false,
                });
            }
            let tx_base = self.hardware.protected_transmits();
            let reply = self
                .qualified_link_command(1, KEY, &body[..], policy)
                .await?;
            success(&reply)?;
            let key = self
                .security
                .active
                .as_mut()
                .unwrap()
                .pending
                .as_mut()
                .unwrap()
                .install[entry]
                .take()
                .unwrap();
            let key = NativeKey { tx_base, ..key };
            self.security.active.as_mut().unwrap().keys[index] = Some(key);
            self.security
                .active
                .as_mut()
                .unwrap()
                .pending
                .as_mut()
                .unwrap()
                .changed
                .push(index);
        }
        let igtk = self.install_igtk(policy).await?;
        self.sync_security_rx(Some(policy)).await?;
        for index in retired {
            self.security.history[index].retired = true;
        }
        let active = self.security.active.as_ref().unwrap();
        let pending = active.pending.as_ref().unwrap();
        let data = self
            .power
            .prepared
            .as_mut()
            .unwrap()
            .mlme
            .data
            .as_mut()
            .unwrap();
        for &index in &pending.changed {
            let key = active.keys[index].as_ref().unwrap();
            if key.group {
                data.replay.group[usize::from(key.id)].fill(key.rsc);
                data.replay.group_valid[usize::from(key.id)] = true;
            } else if let Some(floors) = key.restored {
                data.replay.reset_pairwise();
                data.replay.pairwise = floors;
                // The AP's single per-key PN also bounds robust management.
                data.pmf.mgmt_pn = floors.iter().copied().max().unwrap_or(0);
            } else {
                data.replay.reset_pairwise();
                data.pmf.mgmt_pn = 0;
            }
        }
        // Host BIP verification uses the IGTK only after its native receipt
        // and the RX epoch, with the KDE IPN as replay floor (mac80211
        // ieee80211_crypto_aes_cmac_decrypt over the installed rx_pn).
        if let Some((material, id, ipn)) = igtk {
            data.pmf
                .mfp
                .install_active(*material, id)
                .map_err(|_| "MVM IGTK key index invalid")?;
            data.pmf.mfp.active.as_mut().unwrap().rx_pn = ipn;
        }
        let change = pending.change.as_ref().unwrap();
        for pn in &mut data.replay.group[usize::from(change.group_id)] {
            *pn = (*pn).max(change.group_rx_pn);
        }
        let reply = self
            .qualified_link_command(1, 0x18, &super::auth::disable_tx(false), policy)
            .await?;
        success(&reply)?;
        self.security.active.as_mut().unwrap().first_keys = false;
        self.check_link_power(&policy()?)
    }

    pub(super) async fn remove_security_keys(&mut self) -> Result<(), &'static str> {
        if self.security.active.is_none() {
            return Ok(());
        }
        let mut retired = Vec::new();
        for index in 0..5 {
            let history = if self.security.active.as_ref().unwrap().keys[index].is_some() {
                Some(self.snapshot_key_history(index)?)
            } else {
                None
            };
            if let Some(key) = self.security.active.as_ref().unwrap().keys[index].as_ref() {
                let body = key_command(key, true, self.security.active.as_ref().unwrap().pmf);
                let reply = self
                    .hardware
                    .command_with_header_version(1, KEY, &body[..], 0)
                    .await?;
                success(&reply.payload)?;
                self.security.active.as_mut().unwrap().keys[index] = None;
                retired.push(history.unwrap());
            }
        }
        for slot in 0..2 {
            let Some(id) = self.security.active.as_ref().unwrap().igtks[slot]
                .as_ref()
                .map(|k| k.id)
            else {
                continue;
            };
            let body = super::pmf::igtk_command(None, id, 0);
            self.hardware
                .command_with_header_version(0, super::pmf::MGMT_MCAST_KEY, &body[..], 0)
                .await?;
            self.security.active.as_mut().unwrap().igtks[slot] = None;
        }
        self.sync_security_rx(None::<&mut fn() -> Result<RegulatoryDomain, &'static str>>)
            .await?;
        for index in retired {
            self.security.history[index].retired = true;
        }
        self.security.active = None;
        if let Some(data) = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.data.as_mut())
        {
            data.pmf = super::pmf::PmfRx::default();
        }
        Ok(())
    }

    /// Install a new IGTK from the pending update with MGMT_MCAST_KEY
    /// (Linux `iwl_mvm_send_sta_igtk`; the command's response carries no
    /// status Linux checks, so its receipt alone completes it). Identical
    /// material at the same index is never reinstalled, so its IPN floor
    /// cannot be reset. Returns the key the host BIP owner must adopt.
    async fn install_igtk(
        &mut self,
        policy: &mut impl FnMut() -> Result<RegulatoryDomain, &'static str>,
    ) -> Result<Option<(Zeroizing<[u8; 16]>, u16, u64)>, &'static str> {
        let active = self.security.active.as_ref().unwrap();
        let Some((material, id, ipn)) = active
            .pending
            .as_ref()
            .and_then(|p| p.change.as_ref())
            .and_then(|c| c.igtk)
        else {
            return Ok(None);
        };
        let material = Zeroizing::new(material);
        let slot = usize::from(id - 4);
        if active.igtks[slot]
            .as_ref()
            .is_some_and(|k| k.material.as_ref() == material.as_ref())
        {
            return Ok(None);
        }
        let body = super::pmf::igtk_command(Some(&material), id, ipn);
        self.qualified_link_command(0, super::pmf::MGMT_MCAST_KEY, &body[..], policy)
            .await?;
        self.security.active.as_mut().unwrap().igtks[slot] = Some(InstalledIgtk {
            material: material.clone(),
            id,
        });
        Ok(Some((material, id, ipn)))
    }

    /// Firmware restart retirement. The transport has acknowledged its DMA
    /// stop and cleared bus mastering, so the device can no longer use or
    /// report any installed key: this is stronger than native key REMOVE plus
    /// the ordered RX marker. Committed PN floors move into the retained
    /// history first, so a later reinstall of the same key cannot lower its
    /// replay window (Linux `iwl_mvm_restart_cleanup` plus mac80211's key
    /// reconfiguration with the current PN).
    pub(super) fn retire_security_after_reset(&mut self) -> Result<(), &'static str> {
        if self.security.active.is_none() {
            return Ok(());
        }
        let mut retired = Vec::new();
        for index in 0..5 {
            if self.security.active.as_ref().unwrap().keys[index].is_some() {
                if self
                    .power
                    .prepared
                    .as_ref()
                    .and_then(|p| p.mlme.data.as_ref())
                    .is_none()
                {
                    return Err("MVM restart retired keys without their replay owner");
                }
                retired.push(self.snapshot_key_history(index)?);
            }
        }
        for index in retired {
            self.security.history[index].retired = true;
        }
        self.security.active = None;
        if let Some(data) = self
            .power
            .prepared
            .as_mut()
            .and_then(|p| p.mlme.data.as_mut())
        {
            data.pmf = super::pmf::PmfRx::default();
        }
        Ok(())
    }

    pub(super) async fn sync_security_rx(
        &mut self,
        policy: Option<&mut impl FnMut() -> Result<RegulatoryDomain, &'static str>>,
    ) -> Result<(), &'static str> {
        self.sync_native_rx(policy, None).await
    }

    pub(super) async fn sync_ba_rx(
        &mut self,
        baid: u8,
        policy: Option<&mut impl FnMut() -> Result<RegulatoryDomain, &'static str>>,
    ) -> Result<(), &'static str> {
        self.sync_native_rx(policy, Some(baid)).await
    }

    async fn sync_native_rx(
        &mut self,
        mut policy: Option<&mut impl FnMut() -> Result<RegulatoryDomain, &'static str>>,
        baid: Option<u8>,
    ) -> Result<(), &'static str> {
        let bound = if policy.is_some() {
            let data = self
                .power
                .prepared
                .as_ref()
                .and_then(|p| p.mlme.data.as_ref())
                .ok_or("MVM RX epoch data owner absent")?;
            let queue = data.queue.ok_or("MVM RX epoch queue absent")?;
            if !self.hardware.idle_tx_binding(queue, 0, 0) {
                return Err("MVM RX epoch TX still outstanding");
            }
            Some((
                self.mac.ok_or("MVM RX epoch MAC absent")?,
                LegacyDataStatus {
                    bssid: data.status.bssid,
                    channel: data.status.channel,
                    queue,
                    supported_rates: data.status.supported_rates,
                    protected: data.status.protected,
                },
            ))
        } else {
            None
        };
        self.security.cookie = self
            .security
            .cookie
            .checked_add(1)
            .ok_or("MVM RX key epoch exhausted")?;
        let cookie = self.security.cookie;
        let mut body = alloc::vec![0; if baid.is_some(){24}else{20}];
        put32(&mut body, 4, 1);
        put32(&mut body, 8, if baid.is_some() { 12 } else { 8 });
        put16(&mut body, 12, u16::from(baid.is_some()));
        put16(&mut body, 14, 1);
        put32(&mut body, 16, cookie);
        if let Some(id) = baid {
            put32(&mut body, 20, u32::from(id));
        }
        let reply = if let Some(p) = policy.as_deref_mut() {
            self.qualified_link_command(5, 2, &body, p).await?
        } else {
            self.hardware
                .command_with_header_version(5, 2, &body, 0)
                .await?
                .payload
        };
        if !reply.is_empty() {
            return Err("MVM RX key fence command receipt malformed");
        }
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            if let Some(p) = policy.as_deref_mut() {
                self.check_link_power(&p()?)?;
            }
            let activity = self.hardware.activity();
            self.hardware.poll()?;
            while let Some(packet) = self.hardware.notifications.pop_front() {
                if bound.is_some()
                    && packet.header.group_id == 0
                    && packet.header.cmd == 0xc1
                    && super::super::scan_api::mpdu_gen2(&packet.payload).is_some_and(|mpdu| {
                        let (mac, status) = bound.unwrap();
                        let data = self
                            .power
                            .prepared
                            .as_mut()
                            .and_then(|p| p.mlme.data.as_mut());
                        let pmf = data.and_then(|d| d.status.pmf.then_some(&mut d.pmf));
                        super::pmf::ap_disconnected(&mpdu, mac, status.bssid, status.channel, pmf)
                    })
                {
                    return Err("MVM AP disconnected during native RX key epoch");
                }
                if packet.header.group_id == 5 && packet.header.cmd == 0xff {
                    let bytes = packet.payload;
                    let prefix = if baid.is_some() {
                        [12, 0, 0, 0, 1, 0, 1, 0]
                    } else {
                        [8, 0, 0, 0, 0, 0, 1, 0]
                    };
                    let expected_length = if baid.is_some() { 16 } else { 12 };
                    if bytes.len() != expected_length
                        || bytes[..8] != prefix
                        || baid.is_some_and(|id| bytes[12..16] != u32::from(id).to_le_bytes())
                    {
                        return Err("MVM RX key epoch marker malformed");
                    }
                    if u32::from_le_bytes(bytes[8..12].try_into().unwrap()) == cookie {
                        return Ok(());
                    }
                }
                // Every earlier packet belongs to the retired RX epoch. The
                // single owned RX queue's matching marker orders that prefix.
            }
            if deadline.expired() {
                return Err("MVM RX key epoch marker timeout");
            }
            activity.await;
        }
    }
}

fn ethernet_reply(own: [u8; 6], peer: [u8; 6], pdu: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&peer);
    out.extend_from_slice(&own);
    out.extend_from_slice(&[0x88, 0x8e]);
    out.extend_from_slice(pdu);
    out
}

fn key_digest(key: &[u8]) -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(key);
    hash.finalize()
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "mvm_security_tests.rs"]
pub(super) mod tests;
