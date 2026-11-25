//! The module build's netdev: the station shell's stack side over the KABI.
//!
//! Built in, `interface::publish` registers the shell with the kernel
//! network stack and the nl80211 wiphy registry, and the shell reports
//! carrier, received frames and disconnects by name. In the `.ko` the same
//! shell (`interface::Device`, unchanged) is published here instead:
//!
//! - **netdev** — `narf_usb_netif_register_with_context` registers
//!   `wlan%d` for the USB function. The stack's TX frames arrive in
//!   [`tx_callback`] and go to the shell's own `endpoints::send` (the
//!   built-in send hook); the shell's RX delivery
//!   (`narf_net::iface::on_rx_frame_from`, see `platform/net.rs`) lands in
//!   [`deliver`] and leaves through `narf_usb_netif_rx`.
//! - **open/stop** — the netdev is opened at registration (a module has no
//!   IFF_UP event, as for `ath11k.ko`); its provider lifetime is the
//!   shell's native emission identity (`OpenStopEvent::native_identity`).
//! - **control** — there is no wiphy: the `WIFI` family host binds sessions
//!   to bus (PCI/MMIO) device contexts only, so cfg80211 cannot reach a USB
//!   function's module. The station is driven by the same in-driver SME the
//!   built-in nl80211 path calls (`WirelessNetIface::scan` / `associate`,
//!   Open and WPA2-PSK with the driver's own 4-way handshake), from the
//!   `rtw.ssid=` / `rtw.psk=` / `rtw.passphrase=` / `rtw.scan=` module
//!   parameters ([`autoconnect`]), reconnecting after link loss.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::platform::narf_lib::sync::IrqSafeSpinLock;
use super::platform::narf_net::iface::NetIfaceSnapshot;
use super::platform::narf_net::native_emission::{Lifetime, ProviderLifetime};
use super::platform::narf_net::TxMeta;
use super::platform::narf_wireless::WirelessNetIface;
use super::platform::{self, narf_console};
use super::station;

/// The shell's own name (the stack's name is the bridge's `wlan%d`).
pub(super) const SHELL_NAME: &str = "wlan";

mod ffi {
    unsafe extern "C" {
        pub fn narf_usb_netif_register_with_context(
            dev: u64,
            mac: *const u8,
            tx_callback: usize,
            out_ifindex: *mut u32,
        ) -> i32;
        pub fn narf_usb_netif_rx(dev: u64, ifindex: u32, frame: *mut u8, len: usize) -> i32;
    }
}

const ENOBUFS: i32 = -105;
const ENODEV: i32 = -19;

fn log(args: core::fmt::Arguments<'_>) {
    narf_console::klog!("  rtw88.ko: {}\n", args);
}

/// The one station netdev.
struct Netdev {
    mac: [u8; 6],
    ifindex: AtomicU32,
    /// `endpoints` cookie of the shell (its send hook).
    cookie: u64,
    lifetime: ProviderLifetime,
    carrier: AtomicBool,
    withdrawn: AtomicBool,
    station: Arc<dyn WirelessNetIface>,
}

static NETDEV: IrqSafeSpinLock<Option<Arc<Netdev>>> = IrqSafeSpinLock::new(None);

fn netdev(name: &str) -> Option<Arc<Netdev>> {
    (name == SHELL_NAME)
        .then(|| NETDEV.lock().clone())
        .flatten()
        .filter(|n| !n.withdrawn.load(Ordering::Acquire))
}

/// `interface::publish` for the module: register `wlan%d` for the shell.
pub(super) fn publish<D: WirelessNetIface + 'static>(
    station: Arc<D>,
    mac: [u8; 6],
    cookie: u64,
) -> Result<(), station::Error> {
    let mut ifindex = 0u32;
    // SAFETY: `mac` names six readable bytes; `tx_callback` is a valid
    // extern "C" fn in this image; `ifindex` is a live local.
    let rc = unsafe {
        ffi::narf_usb_netif_register_with_context(
            platform::device(),
            mac.as_ptr(),
            tx_callback as usize,
            &mut ifindex,
        )
    };
    if rc != 0 {
        log(format_args!("netdev registration refused ({rc})"));
        super::endpoints::remove(Arc::as_ptr(&station) as *const ());
        return Err(station::Error::Profile);
    }
    *NETDEV.lock() = Some(Arc::new(Netdev {
        mac,
        ifindex: AtomicU32::new(ifindex),
        cookie,
        lifetime: ProviderLifetime::new(),
        carrier: AtomicBool::new(false),
        withdrawn: AtomicBool::new(false),
        station,
    }));
    log(format_args!("wlan netdev registered (ifindex {ifindex})"));
    Ok(())
}

/// `narf_net::iface::lookup` for the shell.
pub(crate) fn lookup(name: &str) -> Option<NetIfaceSnapshot> {
    let n = netdev(name)?;
    Some(NetIfaceSnapshot {
        name: SHELL_NAME,
        mac: n.mac,
        link_up: n.carrier.load(Ordering::Acquire),
    })
}

/// The registration's native emission identity while it is up.
pub(crate) fn identity(name: &str) -> Option<Lifetime> {
    netdev(name).map(|n| n.lifetime.observe())
}

/// Carrier (`narf_net::iface::set_link_metadata`). The netif bridge has no
/// carrier control; the module's TX path refuses frames while it is down.
pub(crate) fn set_carrier(name: &str, up: bool) -> bool {
    let Some(n) = netdev(name) else {
        return false;
    };
    if n.carrier.swap(up, Ordering::AcqRel) != up {
        log(format_args!("carrier {}", if up { "up" } else { "down" }));
    }
    true
}

/// One received Ethernet frame to the stack.
pub(crate) fn deliver(name: &str, frame: &mut [u8]) {
    let Some(n) = netdev(name) else {
        return;
    };
    // SAFETY: `frame` names `len` bytes the call may rewrite in place.
    let _ = unsafe {
        ffi::narf_usb_netif_rx(
            platform::device(),
            n.ifindex.load(Ordering::Acquire),
            frame.as_mut_ptr(),
            frame.len(),
        )
    };
}

/// The shell withdrew (`rtw_unregister_hw`). The interface itself is
/// retired with the USB context; until then it carries nothing.
pub(crate) fn withdraw(name: &str) {
    if let Some(n) = netdev(name) {
        n.withdrawn.store(true, Ordering::Release);
        n.carrier.store(false, Ordering::Release);
        n.lifetime.retire();
    }
}

/// The station lost its association (`cfg80211_disconnected`).
pub(crate) fn disconnected(name: &str, reason: u16, from_ap: bool) {
    if name == SHELL_NAME {
        log(format_args!(
            "disconnected (reason {reason}, {})",
            if from_ap { "by the AP" } else { "locally" }
        ));
    }
}

/// Provisioning reached `StationReady`: start the parameter-driven SME.
pub(super) fn station_ready() {
    let Some(n) = NETDEV.lock().clone() else {
        return;
    };
    match autoconnect::config() {
        Ok(Some(cfg)) => platform::spawn(autoconnect::run(n.station.clone(), cfg)),
        Ok(None) => log(format_args!(
            "station up; no rtw.ssid= / rtw.scan= given, nothing to join"
        )),
        Err(e) => log(format_args!("ignoring rtw.* parameters: {e}")),
    }
}

/// Netif TX: the stack hands one Ethernet frame (borrowed for this call)
/// to the shell's built-in send hook.
extern "C" fn tx_callback(_dev: u64, frame: *const u8, len: usize) -> i32 {
    let Some(n) = NETDEV.lock().clone() else {
        return ENODEV;
    };
    if frame.is_null() || len < 14 || !n.carrier.load(Ordering::Acquire) {
        return ENOBUFS;
    }
    // SAFETY: the bridge lends `len` readable bytes for the call.
    let bytes = unsafe { core::slice::from_raw_parts(frame, len) };
    match super::endpoints::send(n.cookie, bytes, TxMeta::plain()) {
        Ok(()) => 0,
        Err(()) => ENOBUFS,
    }
}

/// Bring-up control plane: scan / join from the module parameters.
///
/// | Parameter | Effect |
/// |---|---|
/// | `rtw.scan=1` | one scan once the station is up; every BSS is printed |
/// | `rtw.ssid=<ssid>` | scan for it and join the first matching BSS; rejoin after link loss |
/// | `rtw.psk=<64 hex>` | WPA2-PSK with this PMK |
/// | `rtw.passphrase=<8..63>` | WPA2-PSK with PMK = PBKDF2-SHA1(passphrase, SSID, 4096) |
///
/// Neither key → Open. `%XX` in a value is a hex escape (the command line
/// splits on whitespace). Bring-up only: the command line is readable by
/// every process through `/proc/cmdline`.
pub(super) mod autoconnect {
    use super::*;
    use crate::rtw88::platform::narf_wireless::scan::BssSecurity;
    use crate::rtw88::platform::narf_wireless::{
        AssociateRequest, BssInfo, ScanRequest, SecurityConfig,
    };
    use zeroize::Zeroizing;

    /// What the parameters ask for.
    pub(crate) struct Cfg {
        ssid: Option<Vec<u8>>,
        pmk: Option<Zeroizing<[u8; 32]>>,
    }

    fn hexval(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    fn unescape(v: &str) -> Option<Vec<u8>> {
        let b = v.as_bytes();
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                let hi = hexval(*b.get(i + 1)?)?;
                let lo = hexval(*b.get(i + 2)?)?;
                out.push(hi << 4 | lo);
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        Some(out)
    }

    fn param(name: &str) -> Option<String> {
        narf_module_rt::param::get(name)
            .ok()
            .filter(|v| !v.is_empty())
    }

    /// The parameters' request, `None` when none was given.
    pub(crate) fn config() -> Result<Option<Cfg>, &'static str> {
        let ssid = match param("ssid") {
            Some(v) => Some(unescape(&v).filter(|s| s.len() <= 32).ok_or("bad ssid")?),
            None => None,
        };
        let scan = param("scan").is_some_and(|v| v != "0");
        if ssid.is_none() {
            return Ok(scan.then_some(Cfg {
                ssid: None,
                pmk: None,
            }));
        }
        let mut pmk = None;
        if let Some(hex) = param("psk") {
            let hex = hex.as_bytes();
            if hex.len() != 64 {
                return Err("psk is not 64 hex digits");
            }
            let mut key = Zeroizing::new([0u8; 32]);
            for (i, byte) in key.iter_mut().enumerate() {
                *byte = hexval(hex[2 * i])
                    .zip(hexval(hex[2 * i + 1]))
                    .map(|(h, l)| h << 4 | l)
                    .ok_or("psk is not 64 hex digits")?;
            }
            pmk = Some(key);
        } else if let Some(pass) = param("passphrase") {
            let pass = Zeroizing::new(unescape(&pass).ok_or("bad passphrase")?);
            if !(8..=63).contains(&pass.len()) || !pass.iter().all(|c| (0x20..0x7f).contains(c)) {
                return Err("passphrase is not 8..63 printable characters");
            }
            let derived = Zeroizing::new(narf_crypto::pbkdf2_sha1::pbkdf2_hmac_sha1(
                &pass,
                ssid.as_deref().unwrap_or_default(),
                4096,
                32,
            ));
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(&derived[..32]);
            pmk = Some(key);
        }
        Ok(Some(Cfg { ssid, pmk }))
    }

    fn sec_name(s: BssSecurity) -> &'static str {
        match s {
            BssSecurity::Open => "open",
            BssSecurity::Wep => "wep",
            BssSecurity::Wpa => "wpa",
            BssSecurity::Wpa2 => "wpa2",
            BssSecurity::Wpa3 => "wpa3",
        }
    }

    fn report(list: &[BssInfo]) {
        log(format_args!("scan: {} BSS", list.len()));
        for b in list {
            log(format_args!(
                "  {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ch {} {} MHz {} \"{}\"",
                b.bssid[0],
                b.bssid[1],
                b.bssid[2],
                b.bssid[3],
                b.bssid[4],
                b.bssid[5],
                b.channel,
                b.frequency_mhz,
                sec_name(b.security),
                core::str::from_utf8(&b.ssid).unwrap_or("?")
            ));
        }
    }

    fn scan_request(cfg: &Cfg) -> ScanRequest {
        ScanRequest {
            ssids: cfg.ssid.iter().cloned().collect(),
            frequencies_mhz: Vec::new(),
            channels: Vec::new(),
            active: true,
            random_mac: None,
            colocated_6ghz: false,
            duration_tu: None,
            duration_mandatory: false,
            extra_ies: Vec::new(),
        }
    }

    /// Scan, then join `cfg.ssid` (if any) and hold the association,
    /// rejoining after link loss.
    pub(crate) async fn run(station: Arc<dyn WirelessNetIface>, cfg: Cfg) {
        loop {
            if station.connected_bssid().is_some() {
                narf_module_rt::time::sleep_ms(1_000).await;
                continue;
            }
            let list = match station.scan(scan_request(&cfg)).await {
                Ok(list) => list,
                Err(e) => {
                    log(format_args!("scan failed: {e:?}"));
                    narf_module_rt::time::sleep_ms(2_000).await;
                    continue;
                }
            };
            report(&list);
            let Some(ssid) = cfg.ssid.as_ref() else {
                return;
            };
            let wpa2 = cfg.pmk.is_some();
            let Some(bss) = list.iter().find(|b| {
                &b.ssid == ssid
                    && if wpa2 {
                        matches!(b.security, BssSecurity::Wpa2)
                    } else {
                        matches!(b.security, BssSecurity::Open)
                    }
            }) else {
                log(format_args!(
                    "no {} BSS for the ssid yet",
                    if wpa2 { "wpa2" } else { "open" }
                ));
                narf_module_rt::time::sleep_ms(2_000).await;
                continue;
            };
            let security = match &cfg.pmk {
                Some(pmk) => SecurityConfig::Wpa2 { psk: **pmk },
                None => SecurityConfig::Open,
            };
            let request = AssociateRequest {
                bssid: bss.bssid,
                ssid: ssid.clone(),
                frequency_mhz: bss.frequency_mhz,
                channel: bss.channel,
                security,
                ie: Vec::new(),
            };
            match station.associate(request).await {
                Ok(()) => log(format_args!("associated on channel {}", bss.channel)),
                Err(e) => {
                    log(format_args!("association failed: {e:?}"));
                    narf_module_rt::time::sleep_ms(2_000).await;
                }
            }
        }
    }
}
