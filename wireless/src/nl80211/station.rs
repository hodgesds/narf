//! nl80211 for a station whose supplicant runs in userspace (mac80211's
//! side of wpa_supplicant without handshake offload), plus the
//! per-`wireless_dev` connection-owner state.
//!
//! | NARF | Linux |
//! |---|---|
//! | [`new_key`] / [`set_key`] / [`del_key`] | `nl80211_new_key` / `_set_key` / `_del_key` + `nl80211_parse_key` + `cfg80211_validate_key_settings` + `nl80211_key_allowed` |
//! | [`set_station`] | `nl80211_set_station` + `cfg80211_check_station_change(CFG80211_STA_AP_STA)` |
//! | [`pmksa`] | `nl80211_set_pmksa` / `_del_pmksa` / `_flush_pmksa` (mac80211 has no PMKSA ops: -EOPNOTSUPP) |
//! | [`tx_control_port`] | `nl80211_tx_control_port` |
//! | [`rx_control_port`] | `cfg80211_rx_control_port` → `__nl80211_rx_control_port` |
//! | [`power_save`] | `nl80211_set_power_save` / `_get_power_save` |
//! | [`get_reg`] | `nl80211_get_reg_do` / `_dump` + `nl80211_put_regdom` |
//! | [`release`] | `nl80211_netlink_notify` → `cfg80211_autodisconnect_wk` |

use super::*;
use core::{
    future::Future,
    sync::atomic::{AtomicU64, Ordering},
};

pub(super) const ENOLINK: i32 = 67;
pub(super) const ENOTCONN: i32 = 107;
pub(super) const ENETDOWN: i32 = 100;
pub(super) const ERANGE: i32 = 34;

pub(super) const GET_REG: u8 = 31;
pub(super) const SET_KEY: u8 = 10;
pub(super) const NEW_KEY: u8 = 11;
pub(super) const DEL_KEY: u8 = 12;
pub(super) const SET_PMKSA: u8 = 52;
pub(super) const DEL_PMKSA: u8 = 53;
pub(super) const FLUSH_PMKSA: u8 = 54;
pub(super) const SET_POWER_SAVE: u8 = 61;
pub(super) const GET_POWER_SAVE: u8 = 62;
pub(super) const SET_REKEY_OFFLOAD: u8 = 79;
pub(super) const CONTROL_PORT_FRAME: u8 = 129;
/// `NL80211_CMD_CONTROL_PORT_FRAME_TX_STATUS`.
pub(super) const CONTROL_PORT_FRAME_TX_STATUS: u8 = 130;
/// `NL80211_CMD_MICHAEL_MIC_FAILURE`.
pub(super) const MICHAEL_MIC_FAILURE: u8 = 41;

/// `NL80211_IFTYPE_STATION`.
const IFTYPE_STATION: u32 = 2;
const IFTYPE_AP: u32 = 3;

// ── wireless_dev state ───────────────────────────────────────────────

/// What cfg80211 keeps in `struct wireless_dev` for a station that NARF's
/// control layer needs: the connection owner (`conn_owner_nlportid`,
/// `disconnect_bssid`), whether EAPOL goes over nl80211, and `wdev->ps`.
#[derive(Clone, Debug)]
pub(super) struct Wdev {
    pub name: String,
    pub namespace: u64,
    // None is reserved for internal linkless fixtures. A real registration
    // always replaces that state before any owner or port fact is read.
    pub ifindex: Option<u32>,
    pub conn_owner: u32,
    // A socket portid may be reused without replacing the netdev. Tokens
    // also distinguish a grant from the teardown claim that retired it.
    pub owner_epoch: u64,
    pub disconnect_bssid: [u8; 6],
    pub control_port_over_nl80211: bool,
    /// `wdev->ps` (`None` until first read: the driver's default).
    pub ps: Option<bool>,
}

static WDEVS: IrqSafeSpinLock<Vec<Wdev>> = IrqSafeSpinLock::new(Vec::new());
static NEXT_OWNER_EPOCH: AtomicU64 = AtomicU64::new(1);

fn next_owner_epoch() -> Result<u64, i32> {
    NEXT_OWNER_EPOCH
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |epoch| {
            epoch.checked_add(1)
        })
        .map_err(|_| ERANGE)
}

impl Wdev {
    fn empty(name: &str, namespace: u64, ifindex: Option<u32>) -> Self {
        Self {
            name: String::from(name),
            namespace,
            ifindex,
            conn_owner: 0,
            owner_epoch: 0,
            disconnect_bssid: [0; 6],
            control_port_over_nl80211: false,
            ps: None,
        }
    }

    fn bind(&mut self, namespace: u64, ifindex: Option<u32>) {
        if self.namespace != namespace || self.ifindex != ifindex {
            *self = Self::empty(&self.name, namespace, ifindex);
        }
    }

    fn refresh(&mut self) {
        if let Some(link) = narf_net::iface::lookup(&self.name) {
            self.bind(link.net_ns_id, Some(link.ifindex));
        } else if self.ifindex.is_some() {
            // Removed registrations cannot leave owner/port/PS facts behind.
            self.bind(self.namespace, None);
        }
    }

    fn retire_owner(&mut self) {
        self.conn_owner = 0;
        self.owner_epoch = 0;
        self.control_port_over_nl80211 = false;
    }

    fn grant_owner(&mut self, portid: u32, bssid: Option<[u8; 6]>) -> Result<(), i32> {
        self.retire_owner();
        if portid != 0 {
            self.owner_epoch = next_owner_epoch()?;
            self.conn_owner = portid;
        }
        self.disconnect_bssid = bssid.unwrap_or([0; 6]);
        Ok(())
    }
}

fn entry<'a>(
    wdevs: &'a mut Vec<Wdev>,
    name: &str,
    namespace: u64,
    index: Option<u32>,
) -> &'a mut Wdev {
    let position = match wdevs.iter().position(|w| w.name == name) {
        Some(position) => position,
        None => {
            wdevs.push(Wdev::empty(name, namespace, index));
            wdevs.len() - 1
        }
    };
    let wdev = &mut wdevs[position];
    wdev.bind(namespace, index);
    wdev
}

/// Run `f` on `name`'s state (created on first use).
pub(super) fn with_wdev<R>(name: &str, namespace: u64, f: impl FnOnce(&mut Wdev) -> R) -> R {
    let mut wdevs = WDEVS.lock();
    let link = narf_net::iface::lookup(name);
    if link
        .as_ref()
        .is_some_and(|link| link.net_ns_id != namespace)
    {
        // A stale namespace caller receives empty detached state. It must
        // never reset or mutate the current namespace's live record.
        return f(&mut Wdev::empty(name, namespace, None));
    }
    f(entry(
        &mut wdevs,
        name,
        namespace,
        link.map(|link| link.ifindex),
    ))
}

/// The identity check and state mutation share WDEVS ownership. A stale
/// caller cannot rebind a replacement's entry, even if it resolved its old
/// index before the replacement operation acquired its own owner.
fn with_link_wdev<R>(
    name: &str,
    namespace: u64,
    index: u32,
    f: impl FnOnce(&mut Wdev) -> R,
) -> Result<R, i32> {
    let mut wdevs = WDEVS.lock();
    if narf_net::iface::lookup_in(namespace, name).is_none_or(|link| link.ifindex != index) {
        return Err(ENODEV);
    }
    Ok(f(entry(&mut wdevs, name, namespace, Some(index))))
}

/// The connection owner of `name` (0 = none).
pub(super) fn conn_owner(name: &str) -> u32 {
    let mut wdevs = WDEVS.lock();
    let Some(wdev) = wdevs.iter_mut().find(|w| w.name == name) else {
        return 0;
    };
    wdev.refresh();
    wdev.conn_owner
}

/// `if (wdev->conn_owner_nlportid && wdev->conn_owner_nlportid !=
/// info->snd_portid) return -EPERM;` (ASSOCIATE, DEAUTHENTICATE,
/// DISASSOCIATE, DISCONNECT).
pub(super) fn check_owner(name: &str, portid: u32) -> Result<(), i32> {
    let owner = conn_owner(name);
    if owner != 0 && owner != portid {
        Err(EPERM)
    } else {
        Ok(())
    }
}

/// A successful CONNECT / ASSOCIATE with `NL80211_ATTR_SOCKET_OWNER`
/// records the sender as owner (and where to disconnect from).
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn set_owner(name: &str, namespace: u64, portid: u32, bssid: Option<[u8; 6]>) {
    with_wdev(name, namespace, |w| {
        let _ = w.grant_owner(portid, bssid);
    });
}

pub(super) fn set_owner_for_link(
    name: &str,
    namespace: u64,
    index: u32,
    portid: u32,
    bssid: Option<[u8; 6]>,
) -> Result<(), i32> {
    with_link_wdev(name, namespace, index, |w| w.grant_owner(portid, bssid))?
}

/// `wdev->conn_owner_nlportid = 0` (cfg80211_disconnect, a failed connect
/// result, a deauth of the connected / connecting BSS).
pub(super) fn clear_owner(name: &str) {
    if let Some(w) = WDEVS.lock().iter_mut().find(|w| w.name == name) {
        w.refresh();
        w.retire_owner();
    }
}

pub(super) fn clear_owner_for_link(name: &str, namespace: u64, index: u32) -> Result<(), i32> {
    with_link_wdev(name, namespace, index, |w| w.retire_owner())
}

/// Drop cfg80211's per-wireless_dev bookkeeping when a virtual netdev is
/// deleted.  Without this, a later interface reusing the same name could
/// inherit a dead supplicant port owner or power-save preference.
pub(super) fn unregister_wdev(name: &str) {
    WDEVS.lock().retain(|wdev| wdev.name != name);
}

/// Where received EAPOL goes for this association.
#[cfg(any(test, feature = "kernel-test"))]
pub(super) fn set_control_port(name: &str, namespace: u64, over_nl80211: bool) {
    with_wdev(name, namespace, |w| {
        w.control_port_over_nl80211 = over_nl80211
    });
}

pub(super) fn set_control_port_for_link(
    name: &str,
    namespace: u64,
    index: u32,
    over: bool,
) -> Result<(), i32> {
    with_link_wdev(name, namespace, index, |w| {
        w.control_port_over_nl80211 = over
    })
}

/// The owners that disconnected and still need their association torn
/// down (`schedule_work(&wdev->disconnect_wk)`), run by a spawned task.
pub(super) async fn autodisconnect(
    iface: Arc<dyn crate::WirelessNetIface>,
    namespace: u64,
    index: u32,
    portid: u32,
    grant_epoch: u64,
) {
    // cfg80211_autodisconnect_wk → cfg80211_disconnect(
    // WLAN_REASON_DEAUTH_LEAVING): owner cleared first, then the
    // driver disconnects (its own events report it).
    let claimed = with_link_wdev(iface.name(), namespace, index, |w| {
        if portid == 0 || grant_epoch == 0 || w.conn_owner != portid || w.owner_epoch != grant_epoch
        {
            return None;
        }
        w.retire_owner();
        let claim_epoch = next_owner_epoch().ok()?;
        w.owner_epoch = claim_epoch;
        Some(claim_epoch)
    });
    let Ok(Some(claim_epoch)) = claimed else {
        return;
    };
    // Dropping a retired native future preserves the driver's own pending
    // command/DMA ownership; it must never resume against a later grant.
    let mut future = core::pin::pin!(iface.disassociate());
    let result = core::future::poll_fn(|cx| {
        if !current_owner_claim(iface.name(), namespace, index, claim_epoch) {
            return core::task::Poll::Ready(None);
        }
        future.as_mut().poll(cx).map(Some)
    })
    .await;
    if matches!(result, Some(Ok(())))
        && !iface.reports_disconnect_events()
        && current_owner_claim(iface.name(), namespace, index, claim_epoch)
    {
        publish_event(
            NL80211_FAMILY_ID,
            19,
            namespace,
            GenlReply {
                command: DISCONNECT,
                attrs: super::super::disconnect_attrs(index, 3, false),
            },
        );
    }
}

fn current_owner_claim(name: &str, namespace: u64, index: u32, claim_epoch: u64) -> bool {
    with_link_wdev(name, namespace, index, |w| {
        w.conn_owner == 0 && w.owner_epoch == claim_epoch
    }) == Ok(true)
}

/// `nl80211_netlink_notify(NETLINK_URELEASE)`: a closed socket that owned
/// a connection disconnects it.
pub(crate) fn release(namespace: u64, portid: u32) {
    let owned: Vec<(String, u32, u64)> = {
        let mut wdevs = WDEVS.lock();
        wdevs
            .iter_mut()
            .filter_map(|w| {
                w.refresh();
                (portid != 0
                    && w.conn_owner == portid
                    && w.namespace == namespace
                    && w.owner_epoch != 0)
                    .then_some(w.ifindex)
                    .flatten()
                    .map(|index| (w.name.clone(), index, w.owner_epoch))
            })
            .collect()
    };
    for (name, index, grant_epoch) in owned {
        if let Some(iface) = crate::registry::list()
            .into_iter()
            .find(|i| i.name() == name)
        {
            narf_scheduler::spawn(autodisconnect(iface, namespace, index, portid, grant_epoch));
        }
    }
}

// ── pre_doit helpers ─────────────────────────────────────────────────

/// `NL80211_FLAG_NEED_NETDEV_UP`: -ENETDOWN unless `netif_running`.
pub(super) fn netdev_up(iface: &dyn crate::WirelessNetIface) -> Result<(), i32> {
    if narf_net::iface::lookup(iface.name()).is_some_and(|i| i.link_up) {
        Ok(())
    } else {
        Err(ENETDOWN)
    }
}

/// `nl80211_key_allowed`: a station needs `wdev->connected`.
fn key_allowed(iface: &dyn crate::WirelessNetIface) -> Result<(), i32> {
    match iface.current_iftype() {
        IFTYPE_AP => Ok(()),
        IFTYPE_STATION | 8 => {
            if iface.connected_bssid().is_some() {
                Ok(())
            } else {
                Err(ENOLINK)
            }
        }
        _ => Err(EINVAL),
    }
}

/// `nl80211_set_rekey_data`: parse the nested
/// `NL80211_ATTR_REKEY_DATA`, keep the required KCK/KEK/replay-counter
/// lengths exact, and pass the opaque material to the driver.  The
/// `SET_REKEY_OFFLOAD` command itself has NEED_NETDEV_UP; that check and
/// the namespace-admin check happen in `station_handle` before this point.
pub(super) fn set_rekey_offload(
    iface: Arc<dyn crate::WirelessNetIface>,
    attrs: &[(u16, &[u8])],
) -> Result<Vec<GenlReply>, i32> {
    // `NL80211_ATTR_REKEY_DATA` = 122; nested enum nl80211_rekey_data:
    // KEK=1, KCK=2, REPLAY_CTR=3, AKM=4.
    const ATTR_REKEY_DATA: u16 = 122;
    const KEK: u16 = 1;
    const KCK: u16 = 2;
    const REPLAY_CTR: u16 = 3;
    const AKM: u16 = 4;
    let data = attributes(attr(attrs, ATTR_REKEY_DATA).ok_or(EINVAL)?)?;
    let (Some(kek), Some(kck), Some(replay_counter)) =
        (attr(&data, KEK), attr(&data, KCK), attr(&data, REPLAY_CTR))
    else {
        return Err(EINVAL);
    };
    if kek.len() != 16 || kck.len() != 16 || replay_counter.len() != 8 {
        return Err(ERANGE);
    }
    let akm = attr(&data, AKM)
        .map(|raw| int_le::<4>(raw).map(u32::from_ne_bytes))
        .transpose()?;
    // Match `nl80211_set_rekey_data`: validate the nested payload before
    // examining association or driver support, then prefer ENOTCONN when a
    // syntactically valid request targets a disconnected station.
    if iface.connected_bssid().is_none() {
        return Err(ENOTCONN);
    }
    if !iface.supports_gtk_rekey_offload() {
        return Err(EOPNOTSUPP);
    }
    iface.set_gtk_rekey_data(crate::GtkRekeyData {
        kek: kek.try_into().unwrap(),
        kck: kck.try_into().unwrap(),
        replay_counter: replay_counter.try_into().unwrap(),
        akm,
    })?;
    Ok(Vec::new())
}

/// A fixed-size integer attribute as the policy reads it: shorter than the
/// type is -ERANGE (`nla_attr_minlen`), longer is accepted (non-strict).
fn int_le<const N: usize>(raw: &[u8]) -> Result<[u8; N], i32> {
    if raw.len() < N {
        return Err(ERANGE);
    }
    Ok(raw[..N].try_into().unwrap())
}

// ── keys ─────────────────────────────────────────────────────────────

/// `struct key_parse`.
#[derive(Default)]
struct KeyParse {
    key: Option<Vec<u8>>,
    seq: Option<Vec<u8>>,
    cipher: u32,
    mode: u8,
    idx: i32,
    ktype: i32,
    def: bool,
    defmgmt: bool,
    defbeacon: bool,
    def_uni: bool,
    def_multi: bool,
}

/// `nl80211_key_default_policy` nest: UNICAST (1) / MULTICAST (2) flags.
fn default_types(raw: &[u8]) -> Result<(bool, bool), i32> {
    let a = attributes(raw)?;
    Ok((attr(&a, 1).is_some(), attr(&a, 2).is_some()))
}

/// `nl80211_parse_key` (nested `NL80211_ATTR_KEY`, else the old top-level
/// attributes), with the policies' bounds.
fn parse_key(attrs: &[(u16, &[u8])]) -> Result<KeyParse, i32> {
    let mut k = KeyParse {
        idx: -1,
        ktype: -1,
        ..KeyParse::default()
    };
    if let Some(nest) = attr(attrs, 80) {
        // nl80211_key_policy
        let tb = attributes(nest)?;
        k.def = attr(&tb, 5).is_some();
        k.defmgmt = attr(&tb, 6).is_some();
        k.defbeacon = attr(&tb, 10).is_some();
        if k.def {
            k.def_uni = true;
            k.def_multi = true;
        }
        if k.defmgmt || k.defbeacon {
            k.def_multi = true;
        }
        if let Some(raw) = attr(&tb, 2) {
            k.idx = int_le::<1>(raw)?[0] as i32;
        }
        if let Some(raw) = attr(&tb, 1) {
            if raw.len() > 32 {
                return Err(ERANGE); // WLAN_MAX_KEY_LEN
            }
            k.key = Some(raw.to_vec());
        }
        if let Some(raw) = attr(&tb, 4) {
            if raw.len() > 16 {
                return Err(ERANGE);
            }
            k.seq = Some(raw.to_vec());
        }
        if let Some(raw) = attr(&tb, 3) {
            k.cipher = u32::from_ne_bytes(int_le::<4>(raw)?);
        }
        if let Some(raw) = attr(&tb, 7) {
            let t = u32::from_ne_bytes(int_le::<4>(raw)?);
            if t > 2 {
                return Err(ERANGE); // NUM_NL80211_KEYTYPES - 1
            }
            k.ktype = t as i32;
        }
        if let Some(raw) = attr(&tb, 8) {
            (k.def_uni, k.def_multi) = default_types(raw)?;
        }
        if let Some(raw) = attr(&tb, 9) {
            let m = int_le::<1>(raw)?[0];
            if m > 2 {
                return Err(ERANGE); // NL80211_KEY_SET_TX
            }
            k.mode = m;
        }
    } else {
        if let Some(raw) = attr(attrs, 7) {
            if raw.len() > 32 {
                return Err(ERANGE);
            }
            k.key = Some(raw.to_vec());
        }
        if let Some(raw) = attr(attrs, 10) {
            if raw.len() > 16 {
                return Err(ERANGE);
            }
            k.seq = Some(raw.to_vec());
        }
        if let Some(raw) = attr(attrs, 8) {
            let i = int_le::<1>(raw)?[0];
            if i > 7 {
                return Err(ERANGE); // NLA_POLICY_MAX(NLA_U8, 7)
            }
            k.idx = i as i32;
        }
        if let Some(raw) = attr(attrs, 9) {
            k.cipher = u32::from_ne_bytes(int_le::<4>(raw)?);
        }
        k.def = attr(attrs, 11).is_some();
        k.defmgmt = attr(attrs, 40).is_some();
        if k.def {
            k.def_uni = true;
            k.def_multi = true;
        }
        if k.defmgmt {
            k.def_multi = true;
        }
        if let Some(raw) = attr(attrs, 55) {
            let t = u32::from_ne_bytes(int_le::<4>(raw)?);
            if t > 2 {
                return Err(ERANGE);
            }
            k.ktype = t as i32;
        }
        if let Some(raw) = attr(attrs, 110) {
            (k.def_uni, k.def_multi) = default_types(raw)?;
        }
    }
    if (k.def as u8) + (k.defmgmt as u8) + (k.defbeacon as u8) > 1 {
        return Err(EINVAL);
    }
    if (k.defmgmt || k.defbeacon) && (k.def_uni || !k.def_multi) {
        return Err(EINVAL);
    }
    if k.idx != -1 {
        let ok = if k.defmgmt {
            (4..=5).contains(&k.idx)
        } else if k.defbeacon {
            (6..=7).contains(&k.idx)
        } else if k.def {
            (0..=3).contains(&k.idx)
        } else {
            (0..=7).contains(&k.idx)
        };
        if !ok {
            return Err(EINVAL);
        }
    }
    Ok(k)
}

/// `cfg80211_valid_key_idx`: an external-supplicant wiphy reserves key
/// indices 4 and 5 for IGTKs; beacon protection is not advertised.
fn valid_key_idx(iface: &dyn crate::WirelessNetIface, idx: i32, pairwise: bool) -> bool {
    let max = if pairwise {
        3
    } else if iface.supports_external_supplicant() {
        5
    } else {
        3
    };
    (0..=max).contains(&idx)
}

/// The wiphy's `cipher_suites` (`cfg80211_supported_cipher_suite`).
pub(crate) fn cipher_suites(iface: &dyn crate::WirelessNetIface) -> &'static [u32] {
    iface.cipher_suites()
}

/// `cfg80211_validate_key_settings` for the ciphers NARF knows.
fn validate_key_settings(
    iface: &dyn crate::WirelessNetIface,
    k: &KeyParse,
    pairwise: bool,
    mac: Option<[u8; 6]>,
) -> Result<(), i32> {
    if !valid_key_idx(iface, k.idx, pairwise) {
        return Err(EINVAL);
    }
    // No WIPHY_FLAG_IBSS_RSN.
    if !pairwise && mac.is_some() {
        return Err(EINVAL);
    }
    if pairwise && mac.is_none() {
        return Err(EINVAL);
    }
    const TKIP: u32 = crate::CIPHER_SUITE_TKIP;
    const WEP40: u32 = 0x000f_ac01;
    const WEP104: u32 = 0x000f_ac05;
    const CCMP_256: u32 = crate::CIPHER_SUITE_CCMP_256;
    const GCMP: u32 = crate::CIPHER_SUITE_GCMP;
    const GCMP_256: u32 = crate::CIPHER_SUITE_GCMP_256;
    const BIP_GMAC_128: u32 = crate::CIPHER_SUITE_BIP_GMAC_128;
    const BIP_GMAC_256: u32 = crate::CIPHER_SUITE_BIP_GMAC_256;
    const BIP_CMAC_256: u32 = crate::CIPHER_SUITE_BIP_CMAC_256;
    let key_len = k.key.as_ref().map_or(0, Vec::len);
    match k.cipher {
        TKIP => {
            if (pairwise && k.idx != 0) || k.mode != 0 {
                return Err(EINVAL);
            }
        }
        crate::CIPHER_SUITE_CCMP | CCMP_256 | GCMP | GCMP_256 => {
            if (k.mode == 1 && !pairwise) || k.mode == 2 {
                return Err(EINVAL);
            }
            // No NL80211_EXT_FEATURE_EXT_KEY_ID.
            if pairwise && k.idx != 0 {
                return Err(EINVAL);
            }
        }
        crate::CIPHER_SUITE_AES_CMAC | BIP_CMAC_256 | BIP_GMAC_128 | BIP_GMAC_256 => {
            if pairwise || k.idx < 4 {
                return Err(EINVAL);
            }
        }
        WEP40 | WEP104 => {
            if k.idx > 3 {
                return Err(EINVAL);
            }
        }
        _ => {}
    }
    let want_len = match k.cipher {
        WEP40 => Some(5),
        TKIP => Some(32),
        crate::CIPHER_SUITE_CCMP | GCMP | crate::CIPHER_SUITE_AES_CMAC | BIP_GMAC_128 => Some(16),
        CCMP_256 | GCMP_256 | BIP_CMAC_256 | BIP_GMAC_256 => Some(32),
        WEP104 => Some(13),
        _ => None,
    };
    if want_len.is_some_and(|l| l != key_len) {
        return Err(EINVAL);
    }
    if let Some(seq) = k.seq.as_ref() {
        match k.cipher {
            WEP40 | WEP104 => return Err(EINVAL),
            TKIP
            | crate::CIPHER_SUITE_CCMP
            | CCMP_256
            | GCMP
            | GCMP_256
            | crate::CIPHER_SUITE_AES_CMAC
            | BIP_CMAC_256
            | BIP_GMAC_128
            | BIP_GMAC_256 => {
                if seq.len() != 6 {
                    return Err(EINVAL);
                }
            }
            _ => {}
        }
    }
    if !cipher_suites(iface).contains(&k.cipher) {
        return Err(EINVAL);
    }
    Ok(())
}

/// `nl80211_link_id_or_invalid` + `nl80211_validate_key_link_id` for a
/// non-MLO wdev: any `NL80211_ATTR_MLO_LINK_ID` is -EINVAL.
fn no_link_id(attrs: &[(u16, &[u8])]) -> Result<(), i32> {
    if attr(attrs, 313).is_some() {
        Err(EINVAL)
    } else {
        Ok(())
    }
}

fn mac_of(attrs: &[(u16, &[u8])]) -> Result<Option<[u8; 6]>, i32> {
    match attr(attrs, 6) {
        // NLA_POLICY_EXACT_LEN_WARN(ETH_ALEN): short is -ERANGE, long warns.
        Some(raw) if raw.len() < 6 => Err(ERANGE),
        Some(raw) => Ok(Some(raw[..6].try_into().unwrap())),
        None => Ok(None),
    }
}

fn errno_of(e: i32) -> i32 {
    e.abs()
}

/// `nl80211_new_key`.
pub(super) fn new_key(
    iface: Arc<dyn crate::WirelessNetIface>,
    attrs: &[(u16, &[u8])],
) -> Result<Vec<GenlReply>, i32> {
    let mut k = parse_key(attrs)?;
    let Some(key) = k.key.clone() else {
        return Err(EINVAL); // "no key"
    };
    let mac = mac_of(attrs)?;
    if k.ktype == -1 {
        k.ktype = if mac.is_some() { 1 } else { 0 };
    }
    // NL80211_KEYTYPE_GROUP = 0, PAIRWISE = 1.
    if k.ktype != 0 && k.ktype != 1 {
        return Err(EINVAL);
    }
    let pairwise = k.ktype == 1;
    if !iface.supports_external_supplicant() {
        return Err(EOPNOTSUPP); // !rdev->ops->add_key
    }
    validate_key_settings(iface.as_ref(), &k, pairwise, mac)?;
    key_allowed(iface.as_ref())?;
    no_link_id(attrs)?;
    let params = crate::KeyParams {
        idx: k.idx as u8,
        pairwise,
        peer: mac,
        cipher: k.cipher,
        key,
        seq: k.seq.unwrap_or_default(),
        default_mgmt: k.defmgmt,
    };
    iface.add_key(params).map_err(errno_of)?;
    Ok(Vec::new())
}

/// `nl80211_set_key`: default keys (mac80211's `set_default_key` /
/// `_mgmt_key` / `_beacon_key` only record the choice); Extended Key ID
/// `SET_TX` is not advertised.
pub(super) fn set_key(
    iface: Arc<dyn crate::WirelessNetIface>,
    attrs: &[(u16, &[u8])],
) -> Result<Vec<GenlReply>, i32> {
    let k = parse_key(attrs)?;
    if k.idx < 0 {
        return Err(EINVAL);
    }
    if !k.def && !k.defmgmt && !k.defbeacon && k.mode != 2 {
        return Err(EINVAL);
    }
    let have_op = iface.supports_external_supplicant();
    if k.def {
        if !have_op {
            return Err(EOPNOTSUPP);
        }
        key_allowed(iface.as_ref())?;
        no_link_id(attrs)?;
        return Ok(Vec::new());
    }
    if k.defmgmt || k.defbeacon {
        if k.def_uni || !k.def_multi {
            return Err(EINVAL);
        }
        if !have_op {
            return Err(EOPNOTSUPP);
        }
        key_allowed(iface.as_ref())?;
        no_link_id(attrs)?;
        if k.defmgmt {
            iface.set_default_mgmt_key(k.idx as u8).map_err(errno_of)?;
        }
        return Ok(Vec::new());
    }
    // KEY_MODE = SET_TX without NL80211_EXT_FEATURE_EXT_KEY_ID.
    Err(EINVAL)
}

/// `nl80211_del_key`.
pub(super) fn del_key(
    iface: Arc<dyn crate::WirelessNetIface>,
    attrs: &[(u16, &[u8])],
) -> Result<Vec<GenlReply>, i32> {
    let mut k = parse_key(attrs)?;
    let mac = mac_of(attrs)?;
    if k.ktype == -1 {
        k.ktype = if mac.is_some() { 1 } else { 0 };
    }
    if k.ktype != 0 && k.ktype != 1 {
        return Err(EINVAL);
    }
    let pairwise = k.ktype == 1;
    if !valid_key_idx(iface.as_ref(), k.idx, pairwise) {
        return Err(EINVAL);
    }
    if !iface.supports_external_supplicant() {
        return Err(EOPNOTSUPP);
    }
    key_allowed(iface.as_ref())?;
    if !pairwise && mac.is_some() {
        return Err(ENOENT);
    }
    no_link_id(attrs)?;
    iface
        .del_key(k.idx as u8, pairwise, mac)
        .map_err(errno_of)?;
    Ok(Vec::new())
}

// ── SET_STATION on a station interface ───────────────────────────────

/// Parse the per-peer transmit-power controls shared by `NEW_STATION` and
/// `SET_STATION`. Linux validates the setting enum only when it is present;
/// a stray `STA_TX_POWER` attribute is otherwise ignored. In particular its
/// parser only reads the dBm value for the LIMITED form, leaving FIXED for
/// the driver to reject or interpret.
pub(super) fn station_tx_power(
    attrs: &[(u16, &[u8])],
    iface: &dyn crate::WirelessNetIface,
) -> Result<Option<crate::StationTxPower>, i32> {
    const ATTR_SETTING: u16 = 275;
    const ATTR_POWER: u16 = 276;
    let Some(raw) = attr(attrs, ATTR_SETTING) else {
        return Ok(None);
    };
    if !iface.supports_station_tx_power() {
        return Err(EOPNOTSUPP);
    }
    let setting = match raw.first().copied().ok_or(ERANGE)? {
        0 => crate::StationTxPower::Automatic,
        1 => {
            let value = attr(attrs, ATTR_POWER).ok_or(EINVAL)?;
            crate::StationTxPower::Limited(i16::from_ne_bytes(int_le::<2>(value)?))
        }
        2 => crate::StationTxPower::Fixed,
        _ => return Err(ERANGE),
    };
    Ok(Some(setting))
}

/// `nl80211_set_station` → `ieee80211_change_station` for the AP's entry.
pub(super) fn set_station(
    iface: Arc<dyn crate::WirelessNetIface>,
    attrs: &[(u16, &[u8])],
) -> Result<Vec<GenlReply>, i32> {
    if !iface.supports_external_supplicant() {
        return Err(EOPNOTSUPP); // !rdev->ops->change_station
    }
    let aid = attr(attrs, 16)
        .map(|r| int_le::<2>(r).map(u16::from_ne_bytes))
        .transpose()?;
    let listen = attr(attrs, 18)
        .map(|r| int_le::<2>(r).map(u16::from_ne_bytes))
        .transpose()?;
    let mac = mac_of(attrs)?.ok_or(EINVAL)?;
    // parse_station_flags: STA_FLAGS2 first, else the old nested flags.
    let (mask, set) = if let Some(raw) = attr(attrs, 67) {
        if raw.len() < 8 {
            return Err(ERANGE);
        }
        let mask = u32::from_ne_bytes(raw[0..4].try_into().unwrap());
        let set = u32::from_ne_bytes(raw[4..8].try_into().unwrap()) & mask;
        if (mask | set) & 1 != 0 {
            return Err(EINVAL); // __NL80211_STA_FLAG_INVALID
        }
        (mask, set)
    } else if let Some(raw) = attr(attrs, 17) {
        let flags = attributes(raw).map_err(|_| EINVAL)?;
        // Station: AUTHORIZED | TDLS_PEER.
        let mask = (1 << 1) | (1 << 6);
        let mut set = 0u32;
        for (flag, _) in flags {
            if flag == 0 || flag > 8 {
                continue;
            }
            set |= 1 << flag;
            // NL80211_STA_FLAG_MAX_OLD_API = TDLS_PEER (6).
            if flag > 6 {
                return Err(EINVAL);
            }
        }
        (mask, set)
    } else {
        (0, 0)
    };
    // ieee80211_change_station: sta_info_get_bss.
    let ap = iface.connected_bssid();
    if ap != Some(mac) {
        return Err(ENOENT);
    }
    // cfg80211_check_station_change(CFG80211_STA_AP_STA).
    if listen.is_some() || aid.is_some_and(|a| a != 0) && set & (1 << 6) == 0 {
        return Err(EINVAL);
    }
    if set & (1 << 6) != 0 {
        return Err(EINVAL); // TDLS can't be set
    }
    let mask = mask & !(1 << 6);
    if attr(attrs, 19).is_some()
        || attr(attrs, 172).is_some()
        || attr(attrs, 31).is_some()
        || attr(attrs, 157).is_some()
        || attr(attrs, 269).is_some()
    {
        return Err(EINVAL);
    }
    if mask & !(1 << 1) != 0 {
        return Err(EINVAL); // reject any changes other than AUTHORIZED
    }
    if mask & (1 << 1) != 0 {
        iface
            .set_port_authorized(mac, set & (1 << 1) != 0)
            .map_err(errno_of)?;
    }
    if let Some(setting) = station_tx_power(attrs, iface.as_ref())? {
        iface.set_station_tx_power(mac, setting).map_err(errno_of)?;
    }
    Ok(Vec::new())
}

// ── PMKSA ────────────────────────────────────────────────────────────

/// `nl80211_set_pmksa` / `_del_pmksa` / `_flush_pmksa`: the argument
/// checks, then -EOPNOTSUPP — mac80211 has no PMKSA operations; the
/// supplicant keeps its PMKSA cache itself (wpa_supplicant only logs the
/// error).
pub(super) fn pmksa(
    command: u8,
    iface: &dyn crate::WirelessNetIface,
    attrs: &[(u16, &[u8])],
) -> Result<Vec<GenlReply>, i32> {
    let station = matches!(iface.current_iftype(), IFTYPE_STATION | 8);
    match command {
        SET_PMKSA => {
            let pmkid = attr(attrs, 85).ok_or(EINVAL)?;
            if pmkid.len() < 16 {
                return Err(ERANGE);
            }
            if mac_of(attrs)?.is_none()
                && !(attr(attrs, 52).is_some()
                    && attr(attrs, 253).is_some()
                    && attr(attrs, 254).is_some())
            {
                return Err(EINVAL);
            }
            if !station {
                return Err(EOPNOTSUPP);
            }
            iface
                .set_pmksa(pmksa_entry(attrs, Some(pmkid))?)
                .map(|()| Vec::new())
                .map_err(errno_of)
        }
        DEL_PMKSA => {
            if let Some(p) = attr(attrs, 85) {
                if p.len() < 16 {
                    return Err(ERANGE);
                }
            }
            if mac_of(attrs)?.is_none() {
                if attr(attrs, 52).is_some() {
                    let fils = attr(attrs, 253).is_some() && attr(attrs, 254).is_some();
                    if !fils && !iface.supports_sae_offload() {
                        return Err(EINVAL);
                    }
                } else {
                    return Err(EINVAL);
                }
            }
            if !station {
                return Err(EOPNOTSUPP);
            }
            iface
                .del_pmksa(pmksa_entry(attrs, attr(attrs, 85))?)
                .map(|()| Vec::new())
                .map_err(errno_of)
        }
        _ => {
            // FLUSH_PMKSA: station only, then the driver's flush.
            if !station {
                return Err(EOPNOTSUPP);
            }
            iface.flush_pmksa().map(|()| Vec::new()).map_err(errno_of)
        }
    }
}

/// `struct cfg80211_pmksa` from the validated SET/DEL_PMKSA attributes.
fn pmksa_entry(attrs: &[(u16, &[u8])], pmkid: Option<&[u8]>) -> Result<crate::PmksaEntry, i32> {
    Ok(crate::PmksaEntry {
        bssid: mac_of(attrs)?,
        pmkid: pmkid.map(|p| p[..16].try_into().unwrap()),
        ssid: attr(attrs, 52).map(<[u8]>::to_vec),
    })
}

// ── control port ─────────────────────────────────────────────────────

/// Cookies for CONTROL_PORT_FRAME transmissions (`local->roc_cookie_counter`).
static CONTROL_PORT_COOKIE: AtomicU64 = AtomicU64::new(1);

/// `nl80211_tx_control_port`.
pub(super) fn tx_control_port(
    iface: Arc<dyn crate::WirelessNetIface>,
    attrs: &[(u16, &[u8])],
    context: &RequestContext<'_>,
) -> Result<Vec<GenlReply>, i32> {
    if !iface.supports_external_supplicant() {
        return Err(EOPNOTSUPP); // no CONTROL_PORT_OVER_NL80211
    }
    let (Some(frame), Some(_), Some(proto)) = (attr(attrs, 51), attr(attrs, 6), attr(attrs, 102))
    else {
        return Err(EINVAL); // "Frame, MAC or ethertype missing"
    };
    let dest = mac_of(attrs)?.ok_or(EINVAL)?;
    let proto = u16::from_ne_bytes(int_le::<2>(proto)?);
    match iface.current_iftype() {
        IFTYPE_AP => {}
        IFTYPE_STATION | 8 => {
            if iface.connected_bssid().is_none() {
                return Err(ENOTCONN);
            }
        }
        _ => return Err(EOPNOTSUPP),
    }
    no_link_id(attrs)?;
    let no_encrypt = attr(attrs, 103).is_some();
    let dont_wait = attr(attrs, 142).is_some();
    // mac80211 asks its tx_control_port hook for a cookie before queuing the
    // frame, so the returned extended-ACK cookie names the eventual status
    // event even when a completion arrives immediately.
    let cookie = (!dont_wait && iface.supports_control_port_tx_status())
        .then(|| CONTROL_PORT_COOKIE.fetch_add(1, Ordering::Relaxed));
    iface
        .tx_control_port_with_status(dest, proto, frame.to_vec(), no_encrypt, cookie)
        .map_err(errno_of)?;
    if let Some(cookie) = cookie {
        if let Some(cell) = context.ack_cookie {
            cell.set(Some(cookie));
        }
    }
    Ok(Vec::new())
}

/// `cfg80211_rx_control_port`: a received control-port frame (EAPOL, or
/// pre-authentication), the PDU after its Ethernet header, unicast to the
/// connection owner as NL80211_CMD_CONTROL_PORT_FRAME. `false` when there
/// is no owner, or the owner socket is gone (`-ENOENT` / unicast failure);
/// the driver then drops the frame as mac80211 does.
pub fn rx_control_port(
    name: &str,
    src: [u8; 6],
    proto: u16,
    pdu: &[u8],
    unencrypted: bool,
) -> bool {
    let (owner, namespace, index) = {
        let mut wdevs = WDEVS.lock();
        match wdevs.iter_mut().find(|w| w.name == name) {
            Some(w) => {
                w.refresh();
                (w.conn_owner, w.namespace, w.ifindex)
            }
            None => return false,
        }
    };
    if owner == 0 {
        return false;
    }
    let Some(index) = index else {
        return false;
    };
    let wiphy = crate::registry::list()
        .iter()
        .find(|iface| iface.name() == name)
        .and_then(|iface| crate::registry::wiphy_index(iface.wiphy_id()))
        .unwrap_or(0);
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 1, &wiphy.to_ne_bytes());
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    push_attr(&mut attrs, 153, &wdev_id(wiphy, index).to_ne_bytes());
    push_attr(&mut attrs, 6, &src);
    push_attr(&mut attrs, 102, &proto.to_ne_bytes());
    if unencrypted {
        push_attr(&mut attrs, 103, &[]);
    }
    push_attr(&mut attrs, 51, pdu);
    narf_net::netlink_generic::unicast_event(
        NL80211_FAMILY_ID,
        namespace,
        owner,
        GenlReply {
            command: CONTROL_PORT_FRAME,
            attrs,
        },
    )
    .is_ok()
}

/// `cfg80211_control_port_tx_status`: multicast the completed requested
/// control-port transmission on nl80211's MLME group. `frame` is the full
/// 802.3 data frame (destination, source, EtherType, and PDU), exactly as
/// mac80211 retains it in its ACK-status IDR.
pub fn notify_control_port_tx_status(name: &str, cookie: u64, frame: &[u8], acked: bool) {
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let Some(wiphy) = crate::registry::list()
        .iter()
        .find(|iface| iface.name() == name)
        .and_then(|iface| crate::registry::wiphy_index(iface.wiphy_id()))
    else {
        return;
    };
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    push_attr(
        &mut attrs,
        NL80211_ATTR_WDEV,
        &wdev_id(wiphy, ifindex).to_ne_bytes(),
    );
    push_attr(&mut attrs, NL80211_ATTR_FRAME, frame);
    push_attr(&mut attrs, NL80211_ATTR_COOKIE, &cookie.to_ne_bytes());
    if acked {
        push_attr(&mut attrs, NL80211_ATTR_ACK, &[]);
    }
    publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: CONTROL_PORT_FRAME_TX_STATUS,
            attrs,
        },
    );
}

/// `cfg80211_michael_mic_failure`: multicast a locally detected TKIP
/// Michael-MIC failure on nl80211's MLME group. WCN6855 can strip the IV
/// before reporting the error, so the optional key index is retained by the
/// ath11k data path while the frame sequence remains unavailable, exactly
/// like Linux's `NULL` TSC form.
pub fn notify_michael_mic_failure(name: &str, source: [u8; 6], group: bool, key_idx: Option<u8>) {
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let Some(wiphy) = crate::registry::list()
        .iter()
        .find(|iface| iface.name() == name)
        .and_then(|iface| crate::registry::wiphy_index(iface.wiphy_id()))
    else {
        return;
    };
    let mut attrs = Vec::new();
    push_attr(&mut attrs, NL80211_ATTR_WIPHY, &wiphy.to_ne_bytes());
    push_attr(&mut attrs, NL80211_ATTR_IFINDEX, &ifindex.to_ne_bytes());
    push_attr(&mut attrs, NL80211_ATTR_MAC, &source);
    // enum nl80211_key_type: GROUP = 0, PAIRWISE = 1.
    push_attr(
        &mut attrs,
        NL80211_ATTR_KEY_TYPE,
        &(if group { 0u32 } else { 1u32 }).to_ne_bytes(),
    );
    if let Some(key_idx) = key_idx {
        push_attr(&mut attrs, NL80211_ATTR_KEY_IDX, &[key_idx]);
    }
    publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: MICHAEL_MIC_FAILURE,
            attrs,
        },
    );
}

/// Whether received control-port frames of `name` go over nl80211
/// (`sdata->control_port_over_nl80211`).
pub fn control_port_over_nl80211(name: &str) -> bool {
    let mut wdevs = WDEVS.lock();
    let Some(w) = wdevs.iter_mut().find(|w| w.name == name) else {
        return false;
    };
    w.refresh();
    w.control_port_over_nl80211 && w.conn_owner != 0
}

/// `wdev_id()`: `(wiphy_idx << 32) | identifier`.  The interface's stable
/// netdev ifindex is the nonzero identifier, so sibling virtual interfaces
/// share a wiphy but never a WDEV.
pub(crate) fn wdev_id(wiphy: u32, ifindex: u32) -> u64 {
    ((wiphy as u64) << 32) | u64::from(ifindex.max(1))
}

// ── power save ───────────────────────────────────────────────────────

/// `nl80211_set_power_save` / `nl80211_get_power_save`.
pub(super) fn power_save(
    command: u8,
    iface: Arc<dyn crate::WirelessNetIface>,
    attrs: &[(u16, &[u8])],
    namespace: u64,
) -> Result<Vec<GenlReply>, i32> {
    let default = iface.power_save_default();
    let (current, index) = with_wdev(iface.name(), namespace, |w| (w.ps.or(default), w.ifindex));
    if command == GET_POWER_SAVE {
        let Some(ps) = current else {
            return Err(EOPNOTSUPP);
        };
        let mut out = Vec::new();
        push_attr(&mut out, 93, &(ps as u32).to_ne_bytes());
        return Ok(alloc::vec![GenlReply {
            command: GET_POWER_SAVE,
            attrs: out,
        }]);
    }
    let raw = attr(attrs, 93).ok_or(EINVAL)?;
    let state = u32::from_ne_bytes(int_le::<4>(raw)?);
    if state > 1 {
        return Err(ERANGE); // NLA_POLICY_RANGE(NLA_U32, DISABLED, ENABLED)
    }
    let Some(current) = current else {
        return Err(EOPNOTSUPP);
    };
    let wanted = state == 1;
    if wanted == current {
        return Ok(Vec::new());
    }
    iface.set_power_save(wanted).map_err(errno_of)?;
    if let Some(index) = index {
        with_link_wdev(iface.name(), namespace, index, |w| w.ps = Some(wanted))?;
    } else {
        with_wdev(iface.name(), namespace, |w| w.ps = Some(wanted));
    }
    Ok(Vec::new())
}

// ── regulatory ───────────────────────────────────────────────────────

/// Host-policy flags mapped to Linux enum nl80211_reg_rule_flags.
pub(super) fn regulatory_rule_flags(flags: crate::reg::RegFlags) -> u32 {
    u32::from(flags.contains(crate::reg::RegFlags::DFS)) << 4
        | u32::from(flags.contains(crate::reg::RegFlags::INDOOR_ONLY)) << 3
        | u32::from(flags.contains(crate::reg::RegFlags::NO_IR)) << 7
        | u32::from(flags.contains(crate::reg::RegFlags::NO_6GHZ_VLP_CLIENT)) << 22
        | u32::from(flags.contains(crate::reg::RegFlags::NO_6GHZ_AFC_CLIENT)) << 23
}

/// The global regulatory domain (`cfg80211_regdomain`): the deployment
/// policy NARF installed ([`crate::reg::db`]), else cfg80211's
/// `world_regdom`.
pub(super) fn global_regdom() -> crate::RegDomainInfo {
    if let Some(d) = crate::reg::db::get_domain() {
        return crate::RegDomainInfo {
            alpha2: d.country_code,
            dfs_region: 0,
            self_managed: false,
            rules: d
                .rules
                .iter()
                .map(|r| crate::RegRuleInfo {
                    flags: regulatory_rule_flags(r.flags),
                    start_khz: r.freq_start_mhz * 1000,
                    end_khz: r.freq_end_mhz * 1000,
                    max_bw_khz: r.max_bandwidth_mhz * 1000,
                    max_antenna_gain_mbi: 0,
                    max_eirp_mbm: (r.max_power_dbm.max(0) as u32) * 100,
                    dfs_cac_ms: 0,
                })
                .collect(),
        };
    }
    // REG_RULE(start, end, bw, gain, eirp, flags) of world_regdom.
    const NO_IR: u32 = 1 << 7;
    const AUTO_BW: u32 = 1 << 11;
    const NO_OFDM: u32 = 1 << 0;
    const DFS: u32 = 1 << 4;
    let r = |s: u32, e: u32, bw: u32, gain: u32, eirp: u32, flags: u32| crate::RegRuleInfo {
        flags,
        start_khz: s * 1000,
        end_khz: e * 1000,
        max_bw_khz: bw * 1000,
        max_antenna_gain_mbi: gain * 100,
        max_eirp_mbm: eirp * 100,
        dfs_cac_ms: 0,
    };
    crate::RegDomainInfo {
        alpha2: *b"00",
        dfs_region: 0,
        self_managed: false,
        rules: alloc::vec![
            r(2412 - 10, 2462 + 10, 40, 6, 20, 0),
            r(2467 - 10, 2472 + 10, 20, 6, 20, NO_IR | AUTO_BW),
            r(2484 - 10, 2484 + 10, 20, 6, 20, NO_IR | NO_OFDM),
            r(5180 - 10, 5240 + 10, 80, 6, 20, NO_IR | AUTO_BW),
            r(5260 - 10, 5320 + 10, 80, 6, 20, NO_IR | AUTO_BW | DFS),
            r(5500 - 10, 5720 + 10, 160, 6, 20, NO_IR | DFS),
            r(5745 - 10, 5825 + 10, 80, 6, 20, NO_IR),
            r(56160 + 2160 - 1080, 56160 + 2160 * 3 + 1080, 2160, 0, 0, 0),
        ],
    }
}

/// `nl80211_put_regdom`.
fn put_regdom(out: &mut Vec<u8>, d: &crate::RegDomainInfo) {
    let mut alpha2 = d.alpha2.to_vec();
    alpha2.push(0);
    push_attr(out, 33, &alpha2);
    if d.dfs_region != 0 {
        push_attr(out, 146, &[d.dfs_region]);
    }
    let mut rules = Vec::new();
    for (i, r) in d.rules.iter().enumerate() {
        let mut rule = Vec::new();
        push_attr(&mut rule, 1, &r.flags.to_ne_bytes());
        push_attr(&mut rule, 2, &r.start_khz.to_ne_bytes());
        push_attr(&mut rule, 3, &r.end_khz.to_ne_bytes());
        push_attr(&mut rule, 4, &r.max_bw_khz.to_ne_bytes());
        push_attr(&mut rule, 5, &r.max_antenna_gain_mbi.to_ne_bytes());
        push_attr(&mut rule, 6, &r.max_eirp_mbm.to_ne_bytes());
        push_attr(&mut rule, 7, &r.dfs_cac_ms.to_ne_bytes());
        // nla_nest_start_noflag(msg, i)
        push_attr(&mut rules, i as u16, &rule);
    }
    // nla_nest_start_noflag: no NLA_F_NESTED.
    push_attr(out, 34, &rules);
}

/// `nl80211_get_reg_do` (WIPHY selects that wiphy's own domain, else the
/// global one) and `nl80211_get_reg_dump` (global, then each wiphy with
/// its own domain, carrying WIPHY and `WIPHY_SELF_MANAGED_REG`).
pub(super) fn get_reg(attrs: &[u8], dump: bool, namespace: u64) -> Result<Vec<GenlReply>, i32> {
    let interfaces = crate::registry::list();
    if dump {
        let mut out = Vec::new();
        let mut global = Vec::new();
        put_regdom(&mut global, &global_regdom());
        out.push(GenlReply {
            command: GET_REG,
            attrs: global,
        });
        // One entry per wiphy (`for_each_rdev`), labelled with its `phyN`
        // index, not one per virtual interface.
        for (index, iface) in crate::registry::wiphys().iter().enumerate() {
            if !interfaces.iter().any(|candidate| {
                candidate.wiphy_id() == iface.wiphy_id()
                    && super::super::in_namespace(candidate.as_ref(), namespace)
            }) {
                continue;
            }
            let Some(d) = iface.regulatory_domain() else {
                continue;
            };
            let mut a = Vec::new();
            put_regdom(&mut a, &d);
            push_attr(&mut a, 1, &(index as u32).to_ne_bytes());
            if d.self_managed {
                push_attr(&mut a, 216, &[]);
            }
            out.push(GenlReply {
                command: GET_REG,
                attrs: a,
            });
        }
        return Ok(out);
    }
    let mut a = Vec::new();
    let mut regdom = None;
    if find_attr(attrs, 1).is_some() {
        // cfg80211_get_dev_from_info → __cfg80211_rdev_from_attrs.
        let wiphy = super::super::wiphy_from_attrs(&interfaces, attrs, namespace)?;
        // `wiphy` is a `phyN` index into the wiphys, not the interface list.
        regdom = crate::registry::wiphys()
            .get(wiphy as usize)
            .ok_or(ENODEV)?
            .regulatory_domain();
        if regdom.is_some() {
            push_attr(&mut a, 1, &(wiphy as u32).to_ne_bytes());
        }
    }
    let d = regdom.unwrap_or_else(global_regdom);
    put_regdom(&mut a, &d);
    Ok(alloc::vec![GenlReply {
        command: GET_REG,
        attrs: a,
    }])
}

/// Build the NL80211_CMD_DEAUTHENTICATE / DISASSOCIATE notification of a
/// frame received from, or sent to, the AP, then the DISCONNECT the
/// station's loss of its connection produces (`cfg80211_process_deauth` /
/// `_disassoc` → `nl80211_send_deauth` + `__cfg80211_disconnected`), and
/// clear the connection owner (`cfg80211_mlme_deauth` /
/// `__cfg80211_disconnected` → `cfg80211_disconnect` paths).
pub fn notify_mlme_disconnect(name: &str, frame: &[u8], own: [u8; 6]) {
    if frame.len() < 26 {
        return;
    }
    notify_mlme_frame(name, frame);
    let reason = u16::from_le_bytes([frame[24], frame[25]]);
    let from_ap = frame[10..16] != own;
    clear_owner(name);
    super::super::notify_disconnect(name, reason, from_ap);
}

/// `nl80211_send_deauth` / `_disassoc` alone (`cfg80211_tx_mlme_mgmt`
/// while not connected): WIPHY, IFINDEX, FRAME on the mlme group.
pub fn notify_mlme_frame(name: &str, frame: &[u8]) {
    if frame.len() < 24 {
        return;
    }
    let Some(index) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let Some(wiphy) = crate::registry::list()
        .iter()
        .find(|iface| iface.name() == name)
        .and_then(|iface| crate::registry::wiphy_index(iface.wiphy_id()))
    else {
        return;
    };
    let stype = frame[0] & 0xf0;
    let command = if stype == 0xa0 {
        DISASSOCIATE
    } else {
        DEAUTHENTICATE
    };
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 1, &wiphy.to_ne_bytes());
    push_attr(&mut attrs, 3, &index.to_ne_bytes());
    push_attr(&mut attrs, 51, frame);
    publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply { command, attrs },
    );
}

/// `cfg80211_gtk_rekey_notify`: after a low-power GTK-offload engine was
/// disabled, multicast the refreshed big-endian replay counter to the
/// userspace supplicant.  The event deliberately reuses
/// `NL80211_CMD_SET_REKEY_OFFLOAD`, precisely as Linux does.
pub fn notify_gtk_rekey(name: &str, bssid: [u8; 6], replay_counter: [u8; 8]) {
    const SET_REKEY_OFFLOAD: u8 = 79;
    const ATTR_REKEY_DATA: u16 = 122;
    const REPLAY_CTR: u16 = 3;
    const NLA_F_NESTED: u16 = 1 << 15;
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(name) else {
        return;
    };
    let Some(net) = narf_net::iface::lookup(name) else {
        return;
    };
    let Some(wiphy) = crate::registry::list()
        .iter()
        .find(|iface| iface.name() == name)
        .and_then(|iface| crate::registry::wiphy_index(iface.wiphy_id()))
    else {
        return;
    };
    let mut rekey = Vec::new();
    push_attr(&mut rekey, REPLAY_CTR, &replay_counter);
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 1, &wiphy.to_ne_bytes());
    push_attr(&mut attrs, 3, &ifindex.to_ne_bytes());
    push_attr(&mut attrs, 6, &bssid);
    push_attr(&mut attrs, ATTR_REKEY_DATA | NLA_F_NESTED, &rekey);
    publish_event(
        NL80211_FAMILY_ID,
        19,
        net.net_ns_id,
        GenlReply {
            command: SET_REKEY_OFFLOAD,
            attrs,
        },
    );
}
