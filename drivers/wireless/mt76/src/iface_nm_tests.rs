//! NetworkManager's Wi-Fi device discovery against the MT7922 interface.
//!
//! NetworkManager creates no device at all for a wireless link whose
//! `nm_wifi_utils_nl80211_new()` fails or whose `wifi_nl80211_get_mode()` is
//! unknown (`nm-wifi-factory.c: create_device` sets `*out_ignore`), and for
//! most causes logs nothing above debug level when that happens. The client
//! below repeats the exchange of NetworkManager 1.58 — libnm-platform's
//! `nl_send_auto` / `nl_recvmsgs` sequence bookkeeping included — over the
//! same generic-netlink entry point a socket uses, with the radio identity
//! the hardware reported.
use super::*;
use crate::mt7921::firmware_transport::{NicCapabilities, PhyCapabilities, Report};
use alloc::collections::VecDeque;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_net::netlink_generic::{build_replies_with_context, ReplyOptions, RequestContext};

const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const GENL_ID_CTRL: u16 = 0x10;
const NL_OK: i32 = 0;
const NL_SKIP: i32 = 1;
const NL_STOP: i32 = 2;
/// libnm's `-NME_NL_SEQ_MISMATCH`, and a marker for a read that would block.
const SEQ_MISMATCH: i32 = -100_016;
const WOULD_BLOCK: i32 = -100_011;

fn align(len: usize) -> usize {
    (len + 3) & !3
}
fn put(body: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    body.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
    body.extend_from_slice(&kind.to_ne_bytes());
    body.extend_from_slice(payload);
    body.resize(align(body.len()), 0);
}
/// libnl `nla_for_each_attr` with `nla_type()` (which masks the flag bits).
fn attrs(mut raw: &[u8]) -> Vec<(u16, &[u8])> {
    let mut out = Vec::new();
    while raw.len() >= 4 {
        let len = u16::from_ne_bytes([raw[0], raw[1]]) as usize;
        if len < 4 || len > raw.len() {
            break;
        }
        out.push((u16::from_ne_bytes([raw[2], raw[3]]) & 0x3fff, &raw[4..len]));
        raw = &raw[align(len).min(raw.len())..];
    }
    out
}
fn find<'a>(list: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    list.iter().find(|(k, _)| *k == kind).map(|(_, v)| *v)
}
fn u32_of(raw: &[u8]) -> Option<u32> {
    raw.get(..4)?.try_into().ok().map(u32::from_ne_bytes)
}

/// libnm-platform's `struct nl_sock` (`s_auto_ack` set, as `nl_socket_new`
/// always does) in front of the generic-netlink reply builder. Each reply is
/// its own datagram, as the socket layer queues them.
struct NlSock {
    seq_next: u32,
    seq_expect: u32,
    queue: VecDeque<Vec<u8>>,
}
impl NlSock {
    fn new() -> Self {
        Self {
            seq_next: 0x6b2a_0001,
            seq_expect: 0x6b2a_0001,
            queue: VecDeque::new(),
        }
    }
    /// `nl_send_auto`: NL_AUTO_SEQ, NLM_F_REQUEST and, with auto-ack, NLM_F_ACK.
    fn send_auto(&mut self, family: u16, flags: u16, command: u8, version: u8, body: &[u8]) {
        let mut message = Vec::new();
        message.extend_from_slice(&((16 + 4 + body.len()) as u32).to_ne_bytes());
        message.extend_from_slice(&family.to_ne_bytes());
        message.extend_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        message.extend_from_slice(&self.seq_next.to_ne_bytes());
        message.extend_from_slice(&0x1234u32.to_ne_bytes());
        message.extend_from_slice(&[command, version, 0, 0]);
        message.extend_from_slice(body);
        self.seq_next += 1;
        let replies = build_replies_with_context(
            &message,
            ReplyOptions::default(),
            RequestContext {
                init_net_admin: true,
                net_admin: true,
                portid: 0x1234,
                ..RequestContext::default()
            },
        )
        .unwrap_or_default();
        self.queue.extend(replies);
    }
    /// `nl_recvmsgs`. Callbacks return NL_OK / NL_SKIP / NL_STOP or a
    /// negative error; `err` absent means the default (return the errno).
    fn recvmsgs(
        &mut self,
        valid: &mut dyn FnMut(&[u8]) -> i32,
        finish: &mut dyn FnMut() -> i32,
        ack: &mut dyn FnMut() -> i32,
        mut err: Option<&mut dyn FnMut(i32) -> i32>,
    ) -> i32 {
        let mut multipart = false;
        let mut nrecv = 0;
        loop {
            let Some(datagram) = self.queue.pop_front() else {
                return WOULD_BLOCK;
            };
            let mut off = 0;
            while off + 16 <= datagram.len() {
                let len = u32::from_ne_bytes(datagram[off..off + 4].try_into().unwrap()) as usize;
                if len < 16 || off + len > datagram.len() {
                    break;
                }
                let message = &datagram[off..off + len];
                off += align(len);
                let kind = u16::from_ne_bytes([message[4], message[5]]);
                let flags = u16::from_ne_bytes([message[6], message[7]]);
                let seq = u32::from_ne_bytes(message[8..12].try_into().unwrap());
                nrecv += 1;
                if seq != self.seq_expect {
                    return SEQ_MISMATCH;
                }
                if matches!(kind, NLMSG_DONE | NLMSG_ERROR | NLMSG_NOOP | NLMSG_OVERRUN) {
                    self.seq_expect += 1;
                }
                if flags & NLM_F_MULTI != 0 {
                    multipart = true;
                }
                let verdict = match kind {
                    NLMSG_DONE => {
                        multipart = false;
                        finish()
                    }
                    NLMSG_NOOP => NL_SKIP,
                    NLMSG_OVERRUN => return -75,
                    NLMSG_ERROR => {
                        let errno = message
                            .get(16..20)
                            .map_or(-5, |raw| i32::from_ne_bytes(raw.try_into().unwrap()));
                        if errno == 0 {
                            ack()
                        } else {
                            match err.as_mut() {
                                Some(callback) => match callback(errno) {
                                    NL_STOP => return errno,
                                    other => other,
                                },
                                None => return errno,
                            }
                        }
                    }
                    _ => valid(message),
                };
                match verdict {
                    NL_OK | NL_SKIP => {}
                    NL_STOP => return nrecv,
                    error => return error,
                }
            }
            if !multipart {
                return nrecv;
            }
        }
    }
    /// `genl_ctrl_resolve`: one doit, its reply, then `nl_wait_for_ack`.
    fn genl_ctrl_resolve(&mut self, name: &str) -> Result<u16, i32> {
        let mut body = Vec::new();
        let mut value = name.as_bytes().to_vec();
        value.push(0);
        put(&mut body, 2, &value); // CTRL_ATTR_FAMILY_NAME
        self.send_auto(GENL_ID_CTRL, 0, 3, 1, &body); // CTRL_CMD_GETFAMILY
        let mut id = None;
        let result = self.recvmsgs(
            &mut |message: &[u8]| {
                id = find(&attrs(&message[20..]), 1)
                    .filter(|raw| raw.len() >= 2)
                    .map(|raw| u16::from_ne_bytes([raw[0], raw[1]]));
                NL_STOP
            },
            &mut || NL_OK,
            &mut || NL_OK,
            None,
        );
        if result < 0 {
            return Err(result);
        }
        let result = self.recvmsgs(&mut |_: &[u8]| NL_OK, &mut || NL_OK, &mut || NL_STOP, None);
        if result < 0 {
            return Err(result);
        }
        id.ok_or(-1)
    }
    /// nm-wifi-utils-nl80211.c `nl80211_send_and_recv`.
    fn nl80211(
        &mut self,
        family: u16,
        flags: u16,
        command: u8,
        body: &[u8],
        valid: &mut dyn FnMut(&[u8]),
    ) -> Result<(), i32> {
        self.send_auto(family, flags, command, 0, body);
        let done = core::cell::Cell::new(0i32);
        while done.get() == 0 {
            let result = self.recvmsgs(
                &mut |message: &[u8]| {
                    valid(message);
                    NL_SKIP
                },
                &mut || {
                    done.set(1);
                    NL_SKIP
                },
                &mut || {
                    done.set(1);
                    NL_STOP
                },
                Some(&mut |errno: i32| {
                    done.set(errno);
                    NL_SKIP
                }),
            );
            if result < 0 {
                return Err(result);
            }
        }
        if done.get() < 0 {
            Err(done.get())
        } else {
            Ok(())
        }
    }
}

/// `struct nl80211_device_info` after `nl80211_wiphy_info_handler`.
#[derive(Default)]
struct DeviceInfo {
    phy: Option<u32>,
    success: bool,
    supported: bool,
    can_scan_ssid: bool,
    freqs: Vec<u32>,
    ciphers: Vec<u32>,
    raw_band_types: Vec<u16>,
}
fn wiphy_info(message: &[u8], info: &mut DeviceInfo) {
    let top = attrs(&message[20..]);
    let Some(phy) = find(&top, 1).and_then(u32_of) else {
        return;
    };
    info.phy = Some(phy);
    if let Some(max) = find(&top, 43) {
        info.can_scan_ssid = max.first().is_some_and(|max| *max > 0);
    }
    if let Some(commands) = find(&top, 50) {
        for (_, raw) in attrs(commands) {
            // NL80211_CMD_CONNECT / NL80211_CMD_AUTHENTICATE.
            if matches!(u32_of(raw), Some(46 | 37)) {
                info.supported = true;
            }
        }
    }
    if let Some(bands) = find(&top, 22) {
        let mut raw = bands;
        while raw.len() >= 4 {
            let len = u16::from_ne_bytes([raw[0], raw[1]]) as usize;
            if len < 4 || len > raw.len() {
                break;
            }
            info.raw_band_types
                .push(u16::from_ne_bytes([raw[2], raw[3]]));
            raw = &raw[align(len).min(raw.len())..];
        }
        for (_, band) in attrs(bands) {
            let Some(freqs) = find(&attrs(band), 1) else {
                continue;
            };
            for (_, freq) in attrs(freqs) {
                if let Some(mhz) = find(&attrs(freq), 1).and_then(u32_of) {
                    info.freqs.push(mhz);
                }
            }
        }
    }
    if let Some(suites) = find(&top, 57) {
        info.ciphers
            .extend(suites.chunks_exact(4).filter_map(u32_of));
    }
    info.success = true;
}

/// The identity and capabilities the MT7922 (14c3:0616) reported on the
/// hardware this was diagnosed on.
fn mt7922() -> RadioInfo {
    RadioInfo {
        chip_id: 0x7922,
        firmware: Report {
            version: *b"____000000",
            build_date: [0; 15],
            patch_already_loaded: false,
            bytes_transferred: 892_816,
        },
        capabilities: NicCapabilities {
            mac: [0xf0, 0xa6, 0x54, 0x13, 0x95, 0x7b],
            phy: PhyCapabilities {
                ht: true,
                vht: true,
                he: true,
                max_bandwidth: 3,
                spatial_streams: 2,
                bands: 3,
                tx_ldpc: true,
                rx_ldpc: true,
                tx_stbc: true,
                rx_stbc: true,
            },
            has_6ghz: true,
            chip_capabilities: 51,
        },
        hardware_type: 0,
        world_limit_commands: 4,
        channel_configuration: Some(30),
    }
}

fn reject(_: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}
struct Published(String);
impl Drop for Published {
    fn drop(&mut self) {
        narf_wireless::registry::unregister(&self.0);
        narf_net::iface::unregister(&self.0);
    }
}
fn publish() -> Result<(Published, u32), &'static str> {
    let radio = mt7922();
    let name = narf_net::iface::register("mt76-nm%d", radio.capabilities.mac, reject);
    let published = Published(name.clone());
    let iface = Arc::new(Mt76Iface::new(name.clone(), radio).map_err(|_| "radio identity")?);
    narf_wireless::registry::register(iface);
    let ifindex =
        narf_net::netlink_route::ifindex_for_name(&name).ok_or("netdev has no ifindex")?;
    Ok((published, ifindex))
}

/// `nm_wifi_utils_nl80211_new` followed by `wifi_nl80211_get_mode`, on the
/// one synchronous generic-netlink socket NetworkManager uses for both.
///
/// With `absent_family_lookup`, the lookup of a family the kernel does not
/// have runs between the two, as `genl_get_family_id` repeats it for every
/// user of an id it still caches as 0 (mptcp_pm, wireguard). That lookup has
/// no log line of its own: when it reads a message the dump left behind it
/// fails silently and leaves its own answer queued for the mode query, which
/// then fails silently too — the device is ignored without a single warning.
fn networkmanager_creates_a_wifi_device(absent_family_lookup: bool) -> Result<(), &'static str> {
    let (_published, ifindex) = publish()?;
    let mut sock = NlSock::new();

    // nm_platform_genl_get_family_id(NMP_GENL_FAMILY_TYPE_NL80211).
    let family = sock
        .genl_ctrl_resolve("nl80211")
        .map_err(|_| "genl_ctrl_resolve(\"nl80211\") failed")?;

    // NL80211_CMD_GET_WIPHY, NLM_F_DUMP, IFINDEX + SPLIT_WIPHY_DUMP.
    let mut request = Vec::new();
    put(&mut request, 3, &ifindex.to_ne_bytes());
    put(&mut request, 174, &[]);
    let mut info = DeviceInfo {
        can_scan_ssid: true,
        ..DeviceInfo::default()
    };
    sock.nl80211(family, NLM_F_DUMP, 1, &request, &mut |message: &[u8]| {
        wiphy_info(message, &mut info)
    })
    .map_err(|error| match error {
        SEQ_MISMATCH => "GET_WIPHY dump: sequence mismatch",
        WOULD_BLOCK => "GET_WIPHY dump: no NLMSG_DONE, NetworkManager blocks",
        _ => "NL80211_CMD_GET_WIPHY request failed",
    })?;
    if !info.success {
        return Err("NL80211_CMD_GET_WIPHY request indicated failure");
    }
    if !info.supported {
        return Err("driver does not fully support nl80211 (no CONNECT/AUTHENTICATE)");
    }
    if !info.can_scan_ssid {
        return Err("driver does not support SSID scans");
    }
    if info.freqs.is_empty() {
        return Err("driver reports no supported frequencies");
    }
    // WLAN_CIPHER_SUITE_CCMP is what gives the device _NM_WIFI_DEVICE_CAP_RSN;
    // a 2.4 or 5 GHz frequency sets the FREQ_VALID capability either way.
    if !info.ciphers.contains(&0x000f_ac04) {
        return Err("driver does not report CCMP");
    }
    if ![2412, 5180, 5955]
        .iter()
        .all(|mhz| info.freqs.contains(mhz))
    {
        return Err("a firmware-reported band is missing from NL80211_ATTR_WIPHY_BANDS");
    }
    // nl80211_send_wiphy nests each band with nla_nest_start_noflag(msg,
    // band): the attribute type IS enum nl80211_band. iw prints it raw
    // ("Band 32769:" when NLA_F_NESTED leaks into it).
    if info.raw_band_types != [0, 1, 3] {
        return Err("band attribute types are not enum nl80211_band values");
    }

    if absent_family_lookup {
        match sock.genl_ctrl_resolve("narf-absent-family") {
            // nlctrl's -ENOENT, and nothing else queued.
            Err(-2) => {}
            Err(SEQ_MISMATCH) => {
                return Err("family lookup read a stale message left by the GET_WIPHY dump")
            }
            _ => return Err("lookup of an absent family did not fail with -ENOENT"),
        }
    }

    // wifi_nl80211_get_mode: NL80211_CMD_GET_INTERFACE with IFINDEX and the
    // WIPHY learned above (`_nl80211_alloc_msg` adds it once `phy != -1`).
    let mut request = Vec::new();
    put(&mut request, 3, &ifindex.to_ne_bytes());
    put(&mut request, 1, &info.phy.unwrap_or(u32::MAX).to_ne_bytes());
    let mut iftype = None;
    sock.nl80211(family, 0, 5, &request, &mut |message: &[u8]| {
        iftype = find(&attrs(&message[20..]), 5).and_then(u32_of);
    })
    .map_err(|error| match error {
        // The message NetworkManager trips over is whatever the previous
        // exchange left queued under its sequence number.
        SEQ_MISMATCH => "GET_INTERFACE: stale message from the GET_WIPHY dump (sequence mismatch)",
        WOULD_BLOCK => "GET_INTERFACE: no reply or ACK, NetworkManager blocks",
        _ => "NL80211_CMD_GET_INTERFACE request failed",
    })?;
    if iftype != Some(2) {
        return Err("interface is not NL80211_IFTYPE_STATION: NetworkManager ignores it");
    }
    if !sock.queue.is_empty() {
        return Err("messages left queued after a completed exchange");
    }
    Ok(())
}
fn mt7922_networkmanager_wifi_discovery() -> TestResult {
    match networkmanager_creates_a_wifi_device(false) {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/mt7921/networkmanager",
    mt7922_networkmanager_wifi_discovery
);
fn mt7922_networkmanager_discovery_with_absent_family_lookup() -> TestResult {
    match networkmanager_creates_a_wifi_device(true) {
        Ok(()) => TestResult::Pass,
        Err(reason) => TestResult::Fail(reason),
    }
}
kernel_test_in!(
    "drivers/wireless/mt7921/networkmanager",
    mt7922_networkmanager_discovery_with_absent_family_lookup
);
