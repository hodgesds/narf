//! A scripted wpa_supplicant over nl80211 against the composed ath11k
//! fake: the external-supplicant path wpa_supplicant takes on a mac80211
//! driver (SME in userspace, no handshake offload). The "supplicant" is the
//! shared `narf_wireless::eapol` / `sae` state machines driven only through
//! nl80211 messages and the PF_PACKET socket layer, the AP the fake's real
//! WPA2 / SAE authenticator; attribute layouts follow wpa_supplicant's
//! `driver_nl80211.c` (`wpa_driver_nl80211_authenticate`,
//! `_associate` / `nl80211_connect_common`, `nl80211_tx_control_port`,
//! `wpa_driver_nl80211_set_key`, `wpa_driver_nl80211_set_supp_port`).

use super::*;
use narf_net::netlink_generic::{
    build_replies_with_context, install_event_sink, install_unicast_sink, ReplyOptions,
    RequestContext,
};
use narf_wireless::eapol::{EapolRx, KeyMgmt, RsnaParams, Supplicant};

/// The supplicant's `nl_connect` socket (the connection owner) and an
/// unrelated socket.
const WPAS: u32 = 0x5150;
const OTHER: u32 = 0x7777;
const NL80211: u16 = 0x13;

static EVENTS: IrqSafeSpinLock<Vec<(u32, Vec<u8>)>> = IrqSafeSpinLock::new(Vec::new());
static UNICAST: IrqSafeSpinLock<Vec<Vec<u8>>> = IrqSafeSpinLock::new(Vec::new());

fn event_sink(_ns: u64, group: u32, msg: &[u8]) {
    EVENTS.lock().push((group, msg.to_vec()));
}

/// Only the supplicant's socket exists.
fn unicast_sink(_ns: u64, portid: u32, msg: &[u8]) -> bool {
    if portid != WPAS {
        return false;
    }
    UNICAST.lock().push(msg.to_vec());
    true
}

fn push(a: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    a.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    a.extend_from_slice(&kind.to_ne_bytes());
    a.extend_from_slice(payload);
    while a.len() % 4 != 0 {
        a.push(0);
    }
}

fn find(attrs: &[u8], kind: u16) -> Option<&[u8]> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let k = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if len < 4 || off + len > attrs.len() {
            return None;
        }
        if k == kind {
            return Some(&attrs[off + 4..off + len]);
        }
        off += (len + 3) & !3;
    }
    None
}

type UnicastSink = fn(u64, u32, &[u8]) -> bool;

/// The nl80211 side of one test: the netdev in the wireless registry,
/// event / unicast capture, restored on drop.
struct Session {
    ifindex: u32,
    name: &'static str,
    prev_event: Option<fn(u64, u32, &[u8])>,
    prev_unicast: Option<UnicastSink>,
}

impl Session {
    fn new(u: &Up) -> Result<Session, &'static str> {
        narf_scheduler::__reset_queues_for_test();
        let _ = narf_wireless::nl80211::register();
        narf_wireless::registry::unregister(u.name);
        narf_wireless::registry::register(u.netdev.clone());
        let ifindex = narf_net::netlink_route::ifindex_for_name(u.name).ok_or("ifindex")?;
        EVENTS.lock().clear();
        UNICAST.lock().clear();
        CTRL_SEEN.lock().clear();
        MLME_SEEN.lock().clear();
        Ok(Session {
            ifindex,
            name: u.name,
            prev_event: install_event_sink(event_sink),
            prev_unicast: install_unicast_sink(unicast_sink),
        })
    }

    fn ifidx(&self) -> Vec<u8> {
        let mut a = Vec::new();
        push(&mut a, 3, &self.ifindex.to_ne_bytes());
        a
    }

    /// One request from `portid` as a CAP_NET_ADMIN wpa_supplicant (with
    /// NETLINK_EXT_ACK): the replies, or the error's errno.
    fn nl(&self, cmd: u8, flags: u16, attrs: &[u8], portid: u32) -> Result<Vec<Vec<u8>>, i32> {
        let mut body = vec![cmd, 1, 0, 0];
        body.extend_from_slice(attrs);
        let mut msg = Vec::new();
        msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&NL80211.to_ne_bytes());
        msg.extend_from_slice(&flags.to_ne_bytes());
        msg.extend_from_slice(&1u32.to_ne_bytes());
        msg.extend_from_slice(&portid.to_ne_bytes());
        msg.extend_from_slice(&body);
        let ctx = RequestContext {
            init_net_admin: true,
            net_admin: true,
            portid,
            ..RequestContext::default()
        };
        let replies = build_replies_with_context(
            &msg,
            ReplyOptions {
                ext_ack: true,
                cap_ack: false,
            },
            ctx,
        )
        .map_err(|_| -1)?;
        for r in &replies {
            if u16::from_ne_bytes([r[4], r[5]]) == 2 {
                let e = -i32::from_ne_bytes(r[16..20].try_into().unwrap());
                if e != 0 {
                    return Err(e);
                }
            }
        }
        Ok(replies)
    }

    /// A do request, then the tasks it spawned run to completion.
    fn nl_run(&self, cmd: u8, attrs: &[u8], portid: u32) -> Result<Vec<Vec<u8>>, i32> {
        let r = self.nl(cmd, 5, attrs, portid);
        narf_scheduler::run_until_empty();
        r
    }

    /// The attributes of the `mlme`-group events with this command.
    fn events(&self, cmd: u8) -> Vec<Vec<u8>> {
        EVENTS
            .lock()
            .iter()
            .filter(|(g, m)| *g == 19 && m.get(16) == Some(&cmd))
            .map(|(_, m)| m[20..].to_vec())
            .collect()
    }

    /// The CONTROL_PORT_FRAME unicasts the owner received (taken).
    fn control_port_rx(&self) -> Vec<Vec<u8>> {
        core::mem::take(&mut *UNICAST.lock())
            .into_iter()
            .filter(|m| m.get(16) == Some(&129))
            .map(|m| m[20..].to_vec())
            .collect()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(p) = self.prev_event {
            install_event_sink(p);
        }
        if let Some(p) = self.prev_unicast {
            install_unicast_sink(p);
        }
        narf_wireless::registry::unregister(self.name);
    }
}

/// `nl80211_connect_common` + `nl80211_put_control_port` for a WPA2-PSK
/// (or SAE) network, as ASSOCIATE / CONNECT carry it.
fn connect_common(s: &Session, ie: &[u8], akm: u32, over_nl80211: bool) -> Vec<u8> {
    let mut a = s.ifidx();
    push(&mut a, 204, &[]); // SOCKET_OWNER
    push(&mut a, 6, &BSSID);
    push(&mut a, 38, &2437u32.to_ne_bytes()); // WIPHY_FREQ
    push(&mut a, 52, SSID);
    push(&mut a, 42, ie);
    push(&mut a, 75, &2u32.to_ne_bytes()); // WPA_VERSIONS
    push(&mut a, 73, &0x000f_ac04u32.to_ne_bytes());
    push(&mut a, 74, &0x000f_ac04u32.to_ne_bytes());
    push(&mut a, 76, &akm.to_ne_bytes());
    push(&mut a, 68, &[]); // CONTROL_PORT
    push(&mut a, 102, &0x888eu16.to_ne_bytes());
    if over_nl80211 {
        push(&mut a, 264, &[]);
        push(&mut a, 286, &[]);
    }
    a
}

/// NEW_KEY as `wpa_driver_nl80211_set_key` sends it: a nested
/// NL80211_ATTR_KEY (DATA, CIPHER, SEQ, IDX), MAC for a pairwise key.
fn new_key(
    s: &Session,
    idx: u8,
    cipher: u32,
    key: &[u8],
    seq: &[u8],
    mac: Option<&[u8; 6]>,
) -> Vec<u8> {
    let mut k = Vec::new();
    push(&mut k, 1, key);
    push(&mut k, 3, &cipher.to_ne_bytes());
    push(&mut k, 4, seq);
    push(&mut k, 2, &[idx]);
    let mut a = s.ifidx();
    push(&mut a, 80 | 0x8000, &k);
    if let Some(m) = mac {
        push(&mut a, 6, m);
    }
    a
}

/// `wpa_driver_nl80211_set_supp_port`: SET_STATION, STA_FLAGS2 =
/// {mask: AUTHORIZED, set: AUTHORIZED or 0}.
fn supp_port(s: &Session, authorized: bool) -> Vec<u8> {
    let mut a = s.ifidx();
    push(&mut a, 6, &BSSID);
    let mut f = (1u32 << 1).to_ne_bytes().to_vec();
    f.extend_from_slice(&(if authorized { 1u32 << 1 } else { 0 }).to_ne_bytes());
    push(&mut a, 67, &f);
    a
}

/// `nl80211_tx_control_port`: FRAME (the PDU), MAC (the AP), EtherType,
/// NO_ENCRYPT while no PTK is in.
fn tx_control_port(s: &Session, pdu: &[u8], no_encrypt: bool) -> Vec<u8> {
    let mut a = s.ifidx();
    push(&mut a, 102, &0x888eu16.to_ne_bytes());
    push(&mut a, 6, &BSSID);
    push(&mut a, 51, pdu);
    if no_encrypt {
        push(&mut a, 103, &[]);
    }
    a
}

/// The `NLMSGERR_ATTR_COOKIE` of an extended ACK.
fn ack_cookie(replies: &[Vec<u8>]) -> Option<u64> {
    let ack = replies
        .iter()
        .find(|r| u16::from_ne_bytes([r[4], r[5]]) == 2)?;
    if u16::from_ne_bytes([ack[6], ack[7]]) & 0x200 == 0 {
        return None;
    }
    // errno + the echoed request (not capped).
    let inner = u32::from_ne_bytes(ack[20..24].try_into().ok()?) as usize;
    let tlvs = &ack[20 + inner..];
    find(tlvs, 4)
        .and_then(|c| c.try_into().ok())
        .map(u64::from_ne_bytes)
}

/// The 802.11 frames on the TCL ring from `from` that carry EAPOL, with
/// whether they were sent Protected.
fn eapol_air(u: &Up, from: usize) -> Vec<(Vec<u8>, bool)> {
    u.dev.st.borrow().tcl_tx[from..]
        .iter()
        .filter(|t| t.frame.len() > 32 && t.frame[30..32] == [0x88, 0x8e])
        .map(|t| (t.frame[32..].to_vec(), t.frame[1] & 0x40 != 0))
        .collect()
}

/// The PSK supplicant wpa_supplicant runs for this network.
fn psk_supplicant() -> Supplicant {
    Supplicant::new(BSSID, OWN, [0; 32]).with_rsna(RsnaParams {
        key_mgmt: KeyMgmt::Psk,
        pmk: PMK.to_vec(),
        assoc_ie: super::super::mac_tests::STA_RSN_IE.to_vec(),
        ap_rsn_ie: super::super::mac_tests::AP_RSN_IE.to_vec(),
        ap_rsnxe: None,
        pairwise_key_len: 16,
        group_key_len: 16,
        mgmt_group_key_len: None,
        pmf: false,
    })
}

/// The keys the handshake yielded: (TK, (GTK index, GTK, RSC), IGTK).
type Keys = (
    Vec<u8>,
    (u8, Vec<u8>, [u8; 6]),
    Option<(u16, Vec<u8>, [u8; 6])>,
);

/// Run the 4-way handshake as wpa_supplicant: `rx` yields the EAPOL PDUs
/// the driver handed up (with "unencrypted"), `tx` sends one back. M4
/// goes out before the keys are installed. Returns the keys.
fn four_way(
    mut step: impl FnMut(),
    sup: &mut Supplicant,
    mut rx: impl FnMut() -> Vec<(Vec<u8>, bool)>,
    mut tx: impl FnMut(&[u8]) -> R,
) -> Result<Keys, &'static str> {
    for _ in 0..20 {
        step();
        for (pdu, unencrypted) in rx() {
            match sup.rx_eapol(&pdu, !unencrypted, [0x33; 32]) {
                Ok(EapolRx::Pairwise1(m2)) => tx(&m2.reply)?,
                Ok(EapolRx::Pairwise3(m3)) => {
                    tx(&m3.reply)?;
                    let tk = m3.tk.clone().ok_or("M3 without TK")?;
                    let g = m3.gtk.clone().ok_or("M3 without GTK")?;
                    let mut rsc = [0u8; 6];
                    rsc.copy_from_slice(&g.rsc[..6]);
                    let igtk = m3.igtk.as_ref().map(|i| (i.key_id, i.key.to_vec(), i.ipn));
                    return Ok((tk, (g.key_id, g.key.clone(), rsc), igtk));
                }
                Ok(EapolRx::Group1(_)) => {}
                Err(_) => return Err("supplicant refused an EAPOL frame"),
            }
        }
    }
    Err("4-way handshake did not finish")
}

fn caps_ok(s: &Session) -> R {
    let w = s.nl(1, 5, &s.ifidx(), 0).map_err(|_| "GET_WIPHY")?;
    let wiphy = &w[0][20..];
    let cmds: Vec<u32> = find(wiphy, 50)
        .map(|c| {
            c.chunks(8)
                .filter(|e| e.len() == 8)
                .map(|e| u32::from_ne_bytes(e[4..8].try_into().unwrap()))
                .collect()
        })
        .unwrap_or_default();
    ensure!(
        [37u32, 38, 39, 40, 11, 61].iter().all(|c| cmds.contains(c)),
        "SME (AUTHENTICATE/ASSOCIATE), NEW_KEY and SET_POWER_SAVE advertised"
    );
    let suites = find(wiphy, 57).ok_or("cipher suites")?;
    ensure!(
        suites
            == [
                0x000f_ac02u32.to_ne_bytes(),
                0x000f_ac04u32.to_ne_bytes(),
                0x000f_ac06u32.to_ne_bytes(),
                0x000f_ac0du32.to_ne_bytes(),
                0x000f_ac0bu32.to_ne_bytes(),
                0x000f_ac0cu32.to_ne_bytes(),
                0x000f_ac08u32.to_ne_bytes(),
                0x000f_ac09u32.to_ne_bytes(),
                0x000f_ac0au32.to_ne_bytes(),
            ]
            .concat(),
        "Linux ath11k cipher suite set"
    );
    let ext = find(wiphy, 217).ok_or("ext features")?;
    let bit = |b: usize| ext.get(b / 8).is_some_and(|o| o & (1 << (b % 8)) != 0);
    ensure!(
        bit(26) && bit(42) && bit(48) && !bit(15) && !bit(38),
        "CONTROL_PORT_OVER_NL80211 + TX status + NO_PREAUTH, no handshake offloads"
    );
    ensure!(
        find(wiphy, 143).is_some_and(|f| u32::from_ne_bytes(f.try_into().unwrap()) & (1 << 5) != 0),
        "NL80211_FEATURE_SAE"
    );
    Ok(())
}

fn scan(s: &Session) -> R {
    let mut a = s.ifidx();
    let mut ssids = Vec::new();
    push(&mut ssids, 1, &[]);
    push(&mut a, 45 | 0x8000, &ssids);
    s.nl_run(33, &a, WPAS).map_err(|_| "TRIGGER_SCAN")?;
    ensure!(
        EVENTS.lock().iter().any(|(g, m)| *g == 18 && m[16] == 34),
        "NEW_SCAN_RESULTS"
    );
    Ok(())
}

/// wpa_supplicant's SME with its own supplicant on a WPA2-PSK network:
/// AUTHENTICATE (Open) / ASSOCIATE with its RSNE and
/// CONTROL_PORT_OVER_NL80211 + SOCKET_OWNER, EAPOL unicast to the owner as
/// CONTROL_PORT_FRAME (unencrypted) and sent back the same way (M4 before
/// the PTK, so unprotected), NEW_KEY for the PTK and the GTK, then
/// SET_STATION AUTHORIZED; no in-kernel handshake ran. Before
/// authorization only EAPOL leaves the port.
fn smoke_ath11k_int_wpas_sme_wpa2_control_port() -> TestResult {
    check(|| {
        let mut u = up(wpa2_cfg())?;
        let s = Session::new(&u)?;
        caps_ok(&s)?;
        scan(&s)?;
        // wpa_clear_keys at the start: -ENOLINK, which it ignores.
        let mut k = Vec::new();
        push(&mut k, 2, &[0]);
        let mut del = s.ifidx();
        push(&mut del, 80 | 0x8000, &k);
        ensure!(
            s.nl(12, 5, &del, 0) == Err(67),
            "DEL_KEY before association -ENOLINK"
        );
        // AUTHENTICATE: no SOCKET_OWNER, on the global socket.
        let mut a = s.ifidx();
        push(&mut a, 6, &BSSID);
        push(&mut a, 38, &2437u32.to_ne_bytes());
        push(&mut a, 52, SSID);
        push(&mut a, 53, &0u32.to_ne_bytes());
        s.nl_run(37, &a, 0).map_err(|_| "AUTHENTICATE")?;
        let auth = s.events(37);
        let f = auth
            .first()
            .and_then(|e| find(e, 51))
            .ok_or("AUTHENTICATE event")?;
        ensure!(
            f[0] == 0xb0 && f[24..30] == [0, 0, 2, 0, 0, 0],
            "Open System response, success"
        );
        ensure!(
            auth[0].get(..8).is_some() && find(&auth[0], 1).is_some(),
            "WIPHY in the event"
        );
        // ASSOCIATE with EAPOL over nl80211, owned by WPAS.
        let ie = super::super::mac_tests::STA_RSN_IE.to_vec();
        s.nl_run(38, &connect_common(&s, &ie, 0x000f_ac02, true), WPAS)
            .map_err(|_| "ASSOCIATE")?;
        let assoc = s.events(38);
        let f = assoc
            .first()
            .and_then(|e| find(e, 51))
            .ok_or("ASSOCIATE event")?;
        ensure!(
            f[0] == 0x10 && f[26..28] == [0, 0],
            "Association Response, success"
        );
        ensure!(
            find(&assoc[0], 77) == Some(&ie[..]),
            "REQ_IE carries the supplicant's elements"
        );
        let connect = s.events(46);
        ensure!(
            connect
                .first()
                .is_some_and(|c| find(c, 72) == Some(&0u16.to_ne_bytes()[..])
                    && find(c, 6) == Some(&BSSID[..])),
            "CONNECT result after ASSOCIATE"
        );
        ensure!(
            s.events(125).is_empty(),
            "no PORT_AUTHORIZED: userspace's supplicant"
        );
        // The Association Request carried the RSNE as given.
        let sent = mgmt_sent(&u);
        let req = sent.iter().find(|f| f[0] == 0x00).ok_or("assoc request")?;
        ensure!(
            req.windows(ie.len()).any(|w| w == &ie[..]),
            "RSNE in the Association Request"
        );
        ensure!(u.netdev.link_up(), "carrier on at association");
        ensure!(
            !run(u.shared.lock()).vdev(0).unwrap().link.authorized,
            "port closed"
        );
        // Only the owner may tear it down.
        let mut deauth = s.ifidx();
        push(&mut deauth, 6, &BSSID);
        push(&mut deauth, 54, &3u16.to_ne_bytes());
        ensure!(
            s.nl(39, 5, &deauth, OTHER) == Err(1),
            "DEAUTHENTICATE from another socket -EPERM"
        );
        ensure!(
            s.nl(38, 5, &connect_common(&s, &ie, 0x000f_ac02, true), OTHER) == Err(1),
            "ASSOCIATE from another socket -EPERM"
        );
        // Data before authorization is dropped (only EAPOL passes):
        // "dropped frame to %pM (unauthorized port)".
        let data_on_air = |u: &Up| {
            u.dev
                .st
                .borrow()
                .tcl_tx
                .iter()
                .filter(|t| t.frame.len() > 32 && t.frame[30..32] == [0x08, 0x00])
                .count()
        };
        let eth = ipv4_frame(&GW, &OWN, 0, &[1, 2]);
        ensure!(narf_net::iface::send_on(u.name, &eth).is_ok(), "queued");
        let f = u
            .tx_cons
            .try_recv()
            .ok()
            .flatten()
            .ok_or("frame on the ring")?;
        let _ = run(u.netdev.tx_one(&f));
        pump(&u, 2);
        ensure!(
            data_on_air(&u) == 0,
            "unauthorized data never reaches the air"
        );
        // The 4-way handshake through CONTROL_PORT_FRAME.
        let tcl_from = u.dev.st.borrow().tcl_tx.len();
        let mut sup = psk_supplicant();
        let mut cookies = Vec::new();
        let rx = || {
            s.control_port_rx()
                .into_iter()
                .filter_map(|m| {
                    if find(&m, 6) != Some(&BSSID[..])
                        || find(&m, 102) != Some(&0x888eu16.to_ne_bytes()[..])
                        || find(&m, 153).is_none()
                    {
                        return None;
                    }
                    Some((find(&m, 51)?.to_vec(), find(&m, 103).is_some()))
                })
                .collect()
        };
        let mut seen = 0usize;
        let rx = || {
            let v: Vec<(Vec<u8>, bool)> = rx();
            seen += v.len();
            v
        };
        let (tk, (gidx, gtk, rsc), _) = {
            let tx = |pdu: &[u8]| -> R {
                let r = s
                    .nl(129, 5, &tx_control_port(&s, pdu, true), WPAS)
                    .map_err(|_| "CONTROL_PORT_FRAME")?;
                cookies.push(ack_cookie(&r).ok_or("cookie in the extended ACK")?);
                Ok(())
            };
            four_way(|| pump(&u, 2), &mut sup, rx, tx)?
        };
        ensure!(seen >= 2, "M1 and M3 over nl80211");
        ensure!(
            CTRL_SEEN.lock().iter().all(|c| c.3),
            "EAPOL handed up unencrypted"
        );
        ensure!(
            cookies.len() == 2 && cookies[0] != cookies[1],
            "distinct TX cookies"
        );
        // Keys, then the port.
        s.nl(
            11,
            5,
            &new_key(&s, 0, 0x000f_ac04, &tk, &[0; 6], Some(&BSSID)),
            0,
        )
        .map_err(|_| "NEW_KEY PTK")?;
        s.nl(11, 5, &new_key(&s, gidx, 0x000f_ac04, &gtk, &rsc, None), 0)
            .map_err(|_| "NEW_KEY GTK")?;
        s.nl(18, 5, &supp_port(&s, true), 0)
            .map_err(|_| "SET_STATION authorized")?;
        pump(&u, 3);
        {
            let st = u.dev.st.borrow();
            ensure!(
                st.world.ap.m2_mic_ok && st.world.ap.m2_rsn_ok && st.world.ap.m4_ok,
                "authenticator verified M2 / M4"
            );
        }
        let air = eapol_air(&u, tcl_from);
        ensure!(
            air.len() == 2 && air.iter().all(|(_, p)| !p),
            "M2 and M4 sent unprotected"
        );
        let keys = install_keys(&u);
        ensure!(keys.len() == 2, "two WMI key installs (PTK, GTK)");
        ensure!(
            keys[0].buf.windows(16).any(|w| w == &tk[..])
                && keys[1].buf.windows(16).any(|w| w == &gtk[..]),
            "the supplicant's TK then GTK"
        );
        {
            let g = run(u.shared.lock());
            let vdev = g.vdev(0).unwrap();
            ensure!(vdev.link.authorized && vdev.link.ptk, "authorized, PTK in");
        }
        ensure!(
            u.dev
                .st
                .borrow()
                .wmi
                .iter()
                .any(|c| c.cmd_id == wmi::WMI_PEER_SET_PARAM_CMDID
                    && rd32(&c.buf, 16) == wmi::peer_param::AUTHORIZE
                    && rd32(&c.buf, 20) == 1),
            "WMI_PEER_AUTHORIZE"
        );
        // KRACK: the same PTK again installs nothing.
        s.nl(
            11,
            5,
            &new_key(&s, 0, 0x000f_ac04, &tk, &[0; 6], Some(&BSSID)),
            0,
        )
        .map_err(|_| "NEW_KEY PTK again")?;
        pump(&u, 2);
        ensure!(install_keys(&u).len() == 2, "reinstalled PTK ignored");
        // Data now flows, protected.
        ensure!(narf_net::iface::send_on(u.name, &eth).is_ok(), "queued");
        let f = u
            .tx_cons
            .try_recv()
            .ok()
            .flatten()
            .ok_or("frame on the ring")?;
        run(u.netdev.tx_one(&f)).map_err(|_| "authorized data")?;
        pump(&u, 2);
        ensure!(data_on_air(&u) == 1, "authorized data on the air");
        // GET_STATION: the AP's signal.
        let mut st = s.ifidx();
        push(&mut st, 6, &BSSID);
        let r = s.nl(17, 5, &st, 0).map_err(|_| "GET_STATION")?;
        ensure!(
            find(&r[0][20..], 21).and_then(|i| find(i, 7)).is_some(),
            "STA_INFO signal"
        );
        // Deauthentication by the owner: DEAUTHENTICATE + DISCONNECT.
        EVENTS.lock().clear();
        s.nl_run(39, &deauth, WPAS).map_err(|_| "DEAUTHENTICATE")?;
        let d = s.events(39);
        let f = d
            .first()
            .and_then(|e| find(e, 51))
            .ok_or("DEAUTHENTICATE event")?;
        ensure!(
            f[0] == 0xc0 && f[10..16] == OWN && f[24..26] == [3, 0],
            "our Deauthentication, reason 3"
        );
        ensure!(!s.events(48).is_empty(), "DISCONNECT");
        ensure!(!u.netdev.link_up(), "carrier off");
        // The owner is gone: anyone may associate again.
        ensure!(s.nl(39, 5, &deauth, OTHER) != Err(1), "owner cleared");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_ath11k_int_wpas_sme_wpa2_control_port
);

/// The legacy EAPOL path: CONNECT without a PMK and without
/// CONTROL_PORT_OVER_NL80211 (the driver's SME, userspace's supplicant):
/// EAPOL arrives on the netdev (DA rewritten to ours) where a PF_PACKET
/// SOCK_DGRAM socket bound to ETH_P_PAE (wpa_supplicant's l2_packet) reads
/// it, and goes out through the same socket via the netdev; keys and port
/// by NEW_KEY / SET_STATION. Nothing reaches cfg80211's control port.
fn smoke_ath11k_int_wpas_connect_pf_packet() -> TestResult {
    use narf_net::raw_sock::{self, PacketSock};
    check(|| {
        let mut u = up(wpa2_cfg())?;
        let s = Session::new(&u)?;
        scan(&s)?;
        let sock = PacketSock::create(0, raw_sock::SOCK_DGRAM, 0x888eu16.to_be(), 1 << 16);
        sock.bind(None, s.ifindex as i32, 0x888eu16.to_be())
            .map_err(|_| "bind ETH_P_PAE")?;
        // CONNECT: no PMK, no SAE password (WPA_DRIVER_FLAGS_SME off).
        let ie = super::super::mac_tests::STA_RSN_IE.to_vec();
        let mut c = connect_common(&s, &ie, 0x000f_ac02, false);
        // A PMK would need 4WAY_HANDSHAKE_STA_PSK (-EINVAL).
        let mut with_pmk = c.clone();
        push(&mut with_pmk, 254, &PMK);
        ensure!(
            s.nl(46, 5, &with_pmk, WPAS) == Err(22),
            "PMK without the offload -EINVAL"
        );
        push(&mut c, 53, &0u32.to_ne_bytes());
        s.nl_run(46, &c, WPAS).map_err(|_| "CONNECT")?;
        ensure!(
            s.events(46)
                .first()
                .is_some_and(|c| find(c, 72) == Some(&0u16.to_ne_bytes()[..])),
            "CONNECT success"
        );
        ensure!(s.events(125).is_empty(), "no PORT_AUTHORIZED");
        let snap = narf_net::iface::lookup(u.name).ok_or("snapshot")?;
        let mut sup = psk_supplicant();
        let tcl_from = u.dev.st.borrow().tcl_tx.len();
        let rx = || {
            // netif_receive_skb of what the driver delivered.
            let frames: Vec<Vec<u8>> = core::mem::take(&mut *RX_SEEN.lock());
            let mut out = Vec::new();
            for f in frames {
                if f.len() > 14 && f[12..14] == [0x88, 0x8e] {
                    if f[..6] != OWN {
                        continue;
                    }
                    raw_sock::netif_receive(&snap, &f);
                }
            }
            while let Ok(rec) = sock.recv(false) {
                out.push((rec.data, true));
            }
            out
        };
        let netdev = u.netdev.clone();
        let shared = u.shared.clone();
        let step = || {
            for _ in 0..2 {
                run(netdev.service_once());
                run(shared.irq.wait(10));
            }
        };
        let tx_netdev = u.netdev.clone();
        let cons = &mut u.tx_cons;
        let tx = |pdu: &[u8]| -> R {
            let mut sll = vec![0u8; raw_sock::SOCKADDR_LL_LEN];
            sll[0..2].copy_from_slice(&17u16.to_ne_bytes());
            sll[2..4].copy_from_slice(&0x888eu16.to_be_bytes());
            sll[4..8].copy_from_slice(&(s.ifindex as i32).to_ne_bytes());
            sll[11] = 6;
            sll[12..18].copy_from_slice(&BSSID);
            sock.sendmsg(pdu, Some(&sll)).map_err(|_| "sendto")?;
            let f = cons
                .try_recv()
                .ok()
                .flatten()
                .ok_or("EAPOL on the TX ring")?;
            run(tx_netdev.tx_one(&f)).map_err(|_| "EAPOL TX before authorization")?;
            Ok(())
        };
        let (tk, (gidx, gtk, rsc), _) = four_way(step, &mut sup, rx, tx)?;
        ensure!(CTRL_SEEN.lock().is_empty(), "nothing over nl80211");
        s.nl(
            11,
            5,
            &new_key(&s, 0, 0x000f_ac04, &tk, &[0; 6], Some(&BSSID)),
            0,
        )
        .map_err(|_| "NEW_KEY PTK")?;
        s.nl(11, 5, &new_key(&s, gidx, 0x000f_ac04, &gtk, &rsc, None), 0)
            .map_err(|_| "NEW_KEY GTK")?;
        s.nl(18, 5, &supp_port(&s, true), 0)
            .map_err(|_| "SET_STATION")?;
        pump(&u, 3);
        ensure!(u.dev.st.borrow().world.ap.m4_ok, "4-way completed");
        ensure!(
            eapol_air(&u, tcl_from).iter().all(|(_, p)| !p),
            "EAPOL unprotected before the PTK"
        );
        ensure!(install_keys(&u).len() == 2, "PTK + GTK installed");
        ensure!(
            run(u.shared.lock()).vdev(0).unwrap().link.authorized,
            "port open"
        );
        sock.release();
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_ath11k_int_wpas_connect_pf_packet
);

/// WPA3-SAE in userspace, as wpa_supplicant runs it on a mac80211 driver:
/// AUTHENTICATE with AUTH_TYPE SAE and AUTH_DATA = transaction | status |
/// body for the H2E Commit and then the Confirm, each answered by an
/// AUTHENTICATE event with the AP's frame; ASSOCIATE with USE_MFP
/// REQUIRED and the SAE RSNE + RSNXE; the AKM-8 4-way handshake over the
/// control port, PTK / GTK / IGTK by NEW_KEY (the IGTK in software BIP).
fn smoke_ath11k_int_wpas_sae_authenticate() -> TestResult {
    use narf_wireless::sae::SaeSession;
    check(|| {
        let cfg = sae_cfg(
            &AP_RSNE_SAE,
            true,
            super::super::mac_tests::SaeAp {
                password: SAE_PW.to_vec(),
                h2e: true,
                ..Default::default()
            },
        );
        let u = up(cfg)?;
        let s = Session::new(&u)?;
        scan(&s)?;
        let auth = |data: &[u8]| {
            let mut a = s.ifidx();
            push(&mut a, 6, &BSSID);
            push(&mut a, 38, &2437u32.to_ne_bytes());
            push(&mut a, 52, SSID);
            push(&mut a, 53, &4u32.to_ne_bytes());
            push(&mut a, 156, data);
            a
        };
        // nl80211_authenticate: SAE needs AUTH_DATA; AUTH_DATA < 4 -ERANGE.
        let mut no_data = s.ifidx();
        push(&mut no_data, 6, &BSSID);
        push(&mut no_data, 38, &2437u32.to_ne_bytes());
        push(&mut no_data, 52, SSID);
        push(&mut no_data, 53, &4u32.to_ne_bytes());
        ensure!(
            s.nl(37, 5, &no_data, 0) == Err(22),
            "SAE without AUTH_DATA -EINVAL"
        );
        ensure!(
            s.nl(37, 5, &auth(&[1, 0]), 0) == Err(34),
            "short AUTH_DATA -ERANGE"
        );
        let mut sae =
            SaeSession::new_h2e_bytes(SSID, SAE_PW, OWN, BSSID).with_test_seed([0x42; 64]);
        ensure!(!sae.build_commit().is_empty(), "PWE");
        let mut data = vec![1, 0, 126, 0];
        data.extend_from_slice(&sae.commit_body(None));
        EVENTS.lock().clear();
        s.nl_run(37, &auth(&data), 0)
            .map_err(|_| "AUTHENTICATE commit")?;
        let ev = s.events(37);
        let f = ev.first().and_then(|e| find(e, 51)).ok_or("commit event")?;
        ensure!(
            f[24..30] == [3, 0, 1, 0, 126, 0],
            "AP Commit (SAE, transaction 1, status 126)"
        );
        sae.on_commit(&f[30..]).map_err(|_| "AP commit")?;
        let mut data = vec![2, 0, 0, 0];
        data.extend_from_slice(&sae.build_confirm());
        EVENTS.lock().clear();
        s.nl_run(37, &auth(&data), 0)
            .map_err(|_| "AUTHENTICATE confirm")?;
        let ev = s.events(37);
        let f = ev
            .first()
            .and_then(|e| find(e, 51))
            .ok_or("confirm event")?;
        ensure!(f[24..30] == [3, 0, 2, 0, 0, 0], "AP Confirm");
        sae.on_confirm(&f[30..]).map_err(|_| "AP confirm")?;
        let pmk = *sae.pmk().ok_or("PMK")?;
        ensure!(
            u.dev.st.borrow().world.ap.pmk == Some(pmk),
            "both sides have the PMK"
        );
        // ASSOCIATE (USE_MFP = REQUIRED; OPTIONAL is -EINVAL here).
        let mut ie = STA_RSNE_SAE.to_vec();
        ie.extend_from_slice(&RSNXE_H2E);
        let mut a = connect_common(&s, &ie, 0x000f_ac08, true);
        let mut optional = a.clone();
        push(&mut optional, 66, &2u32.to_ne_bytes());
        ensure!(
            s.nl(38, 5, &optional, WPAS) == Err(22),
            "USE_MFP OPTIONAL -EINVAL"
        );
        push(&mut a, 66, &1u32.to_ne_bytes());
        s.nl_run(38, &a, WPAS).map_err(|_| "ASSOCIATE")?;
        ensure!(
            s.events(38)
                .first()
                .and_then(|e| find(e, 51))
                .is_some_and(|f| f[26..28] == [0, 0]),
            "associated"
        );
        let mut sup = Supplicant::new(BSSID, OWN, [0; 32]).with_rsna(RsnaParams {
            key_mgmt: KeyMgmt::Sae,
            pmk: pmk.to_vec(),
            assoc_ie: ie.clone(),
            ap_rsn_ie: AP_RSNE_SAE.to_vec(),
            ap_rsnxe: Some(RSNXE_H2E.to_vec()),
            pairwise_key_len: 16,
            group_key_len: 16,
            mgmt_group_key_len: Some(16),
            pmf: true,
        });
        let rx = || {
            s.control_port_rx()
                .into_iter()
                .filter_map(|m| Some((find(&m, 51)?.to_vec(), find(&m, 103).is_some())))
                .collect()
        };
        let tx = |pdu: &[u8]| -> R {
            s.nl(129, 5, &tx_control_port(&s, pdu, true), WPAS)
                .map(|_| ())
                .map_err(|_| "CONTROL_PORT_FRAME")
        };
        let (tk, (gidx, gtk, rsc), igtk) = four_way(|| pump(&u, 2), &mut sup, rx, tx)?;
        let (iid, ikey, ipn) = igtk.ok_or("IGTK in M3")?;
        s.nl(
            11,
            5,
            &new_key(&s, 0, 0x000f_ac04, &tk, &[0; 6], Some(&BSSID)),
            0,
        )
        .map_err(|_| "NEW_KEY PTK")?;
        s.nl(11, 5, &new_key(&s, gidx, 0x000f_ac04, &gtk, &rsc, None), 0)
            .map_err(|_| "NEW_KEY GTK")?;
        // An IGTK at index 3 is -EINVAL (AES-CMAC needs 4 / 5).
        ensure!(
            s.nl(11, 5, &new_key(&s, 3, 0x000f_ac06, &ikey, &ipn, None), 0) == Err(22),
            "IGTK index 3"
        );
        s.nl(
            11,
            5,
            &new_key(&s, iid as u8, 0x000f_ac06, &ikey, &ipn, None),
            0,
        )
        .map_err(|_| "NEW_KEY IGTK")?;
        s.nl(18, 5, &supp_port(&s, true), 0)
            .map_err(|_| "SET_STATION")?;
        pump(&u, 3);
        let st = u.dev.st.borrow();
        ensure!(
            st.world.ap.km == Some(KeyMgmt::Sae) && st.world.ap.m2_mic_ok && st.world.ap.m4_ok,
            "AKM-8 4-way with the SAE PMK"
        );
        drop(st);
        ensure!(install_keys(&u).len() == 2, "IGTK not sent to the firmware");
        let m = run(u.netdev.mac.lock());
        ensure!(
            m.link().is_some_and(|l| l.sta.mfp && l.authorized),
            "PMF association, port open"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/e2e",
    smoke_ath11k_int_wpas_sae_authenticate
);

/// A connection made over nl80211 survives a firmware reset like any
/// other: mac80211's `ieee80211_reconfig` replays the associated station
/// whoever connected it, so no loss is reported (no DEAUTHENTICATE or
/// DISCONNECT), the carrier stays on and NARF does not reassociate.
fn smoke_ath11k_int_recover_nl80211_origin() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        scan6(&u)?;
        // The trait's `associate` is nl80211 CONNECT's entry point.
        let (r, err, _, _) = latched(|| run(u.netdev.associate(wpa2_req())));
        ensure!(r.is_ok() && err == 0, "connected over nl80211's path");
        LINK_SEEN.lock().clear();
        DISC_SEEN.lock().clear();
        MLME_SEEN.lock().clear();
        crash(&u, FwNotice::Reset(MhiNotify::EeRddm));
        let (_, err, _, _) = latched(|| pump(&u, 3));
        ensure!(err == 0, "nothing latched");
        ensure!(
            u.netdev.stats.recovered.load(Ordering::Relaxed) == 1,
            "recovered"
        );
        ensure!(
            u.netdev.stats.reconnects.load(Ordering::Relaxed) == 0
                && u.netdev.link_up()
                && u.netdev.connected_bssid() == Some(BSSID),
            "station replayed in place, no reassociation"
        );
        ensure!(DISC_SEEN.lock().is_empty(), "no loss reported");
        ensure!(MLME_SEEN.lock().is_empty(), "no Deauthentication");
        ensure!(LINK_SEEN.lock().is_empty(), "carrier stays on");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_int_recover_nl80211_origin
);

/// SET_POWER_SAVE / GET_POWER_SAVE on the station: `wdev->ps` defaults
/// on (CONFIG_CFG80211_DEFAULT_PS); disabling sends
/// WMI_STA_POWERSAVE_MODE(DISABLED), enabling again the inactivity time +
/// ENABLED (`ath11k_mac_vif_setup_ps`); the same state is a no-op.
fn smoke_ath11k_int_power_save() -> TestResult {
    check(|| {
        let u = up(wpa2_cfg())?;
        connect(&u)?;
        let s = Session::new(&u)?;
        let ps_cmds = |u: &Up| {
            u.dev
                .st
                .borrow()
                .wmi
                .iter()
                .filter(|c| c.cmd_id == wmi::WMI_STA_POWERSAVE_MODE_CMDID)
                .map(|c| rd32(&c.buf, 8))
                .collect::<Vec<_>>()
        };
        // The commands reach the target over HTC on the next passes.
        pump(&u, 2);
        let at_assoc = ps_cmds(&u);
        ensure!(at_assoc.last() == Some(&1), "PS enabled at association");
        let since = |u: &Up| ps_cmds(u)[at_assoc.len()..].to_vec();
        let get = || {
            s.nl(62, 5, &s.ifidx(), 0)
                .map(|r| find(&r[0][20..], 93).map(|v| v.to_vec()))
        };
        ensure!(
            get() == Ok(Some(1u32.to_ne_bytes().to_vec())),
            "GET_POWER_SAVE on"
        );
        let set = |v: u32| {
            let mut a = s.ifidx();
            push(&mut a, 93, &v.to_ne_bytes());
            s.nl(61, 5, &a, 0)
        };
        ensure!(set(2).err() == Some(34), "PS_STATE out of range -ERANGE");
        ensure!(s.nl(61, 5, &s.ifidx(), 0) == Err(22), "no PS_STATE -EINVAL");
        set(0).map_err(|_| "SET_POWER_SAVE off")?;
        pump(&u, 2);
        ensure!(since(&u) == [0], "WMI PS mode disabled");
        ensure!(
            get() == Ok(Some(0u32.to_ne_bytes().to_vec())),
            "GET_POWER_SAVE off"
        );
        set(0).map_err(|_| "same state")?;
        pump(&u, 2);
        ensure!(since(&u) == [0], "no command for the same state");
        set(1).map_err(|_| "SET_POWER_SAVE on")?;
        pump(&u, 2);
        ensure!(since(&u) == [0, 1], "enabled again");
        // GET_REG: the self-managed wiphy's domain in the dump.
        let dump = s.nl(31, 0x301, &[], 0).map_err(|_| "GET_REG dump")?;
        let regs: Vec<&Vec<u8>> = dump.iter().filter(|m| m.get(16) == Some(&31)).collect();
        ensure!(regs.len() >= 2, "global + the wiphy");
        ensure!(
            find(&regs[0][20..], 33) == Some(&b"00\0"[..]),
            "global world domain"
        );
        ensure!(
            regs[1..]
                .iter()
                .any(|m| find(&m[20..], 216).is_some() && find(&m[20..], 1).is_some()),
            "WIPHY + WIPHY_SELF_MANAGED_REG"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_int_power_save);
