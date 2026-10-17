//! Bring-up aid: scan / connect from the kernel command line.
//!
//! NARF's nl80211 family refuses Wi-Fi mutations (TRIGGER_SCAN,
//! CONNECT) from a socket without a delegated interface grant
//! (`network_daemon::prepare`), and no production launcher issues one
//! yet — so a bare-metal test of the station path has no userspace
//! trigger. These NARF-only parameters (no Linux equivalent; Linux uses
//! wpa_supplicant / iwd over nl80211) let the first boot on the card
//! exercise scan, connect and link-loss recovery, reporting through the
//! console and the framebuffer panel:
//!
//! | Parameter | Effect |
//! |---|---|
//! | `ath11k.scan=1` | one scan once `wlan%d` is up; every BSS is printed |
//! | `ath11k.ssid=<ssid>` | scan (active, directed at the SSID) and connect to the strongest matching 2.4 / 5 GHz BSS; reconnect after link loss |
//! | `ath11k.psk=<64 hex>` | WPA2-PSK with this PMK |
//! | `ath11k.passphrase=<8..63 chars>` | WPA2-PSK, PMK = PBKDF2-SHA1(passphrase, SSID, 4096) |
//!
//! Neither key → Open. `%XX` in a value is a hex escape (e.g. `%20` for
//! a space; the command line splits on whitespace). Bring-up only: the
//! command line is readable by every process through `/proc/cmdline`.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt::Write as _;

use narf_wireless::scan::BssSecurity;
use narf_wireless::{AssociateRequest, BssInfo, ScanRequest, SecurityConfig, WirelessError};

/// What to do once the netdev is registered.
#[derive(Clone, PartialEq, Eq)]
pub struct AutoCfg {
    /// Connect to this SSID (`None`: scan once and report).
    pub ssid: Option<Vec<u8>>,
    /// WPA2-PSK PMK; `None` = Open.
    pub pmk: Option<[u8; 32]>,
}

impl core::fmt::Debug for AutoCfg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AutoCfg")
            .field("ssid", &self.ssid)
            .field("wpa2", &self.pmk.is_some())
            .finish()
    }
}

/// Why the command line was not accepted.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CfgError {
    /// `psk` is not 64 hex digits.
    BadPsk,
    /// `passphrase` is not 8..=63 printable ASCII characters.
    BadPassphrase,
    /// `ssid` empty, longer than 32 bytes, or a bad `%` escape.
    BadSsid,
    /// A key without an SSID.
    KeyWithoutSsid,
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `%XX` unescaping.
pub fn unescape(v: &str) -> Option<Vec<u8>> {
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

/// Parse the `ath11k.*` parameters; `Ok(None)` when none asks for
/// anything.
pub fn parse(cmdline: &str) -> Result<Option<AutoCfg>, CfgError> {
    let args = narf_boot::args::KernelCmdline::new(cmdline);
    let ssid = match args.value("ath11k.ssid") {
        Some(v) => {
            let s = unescape(v).ok_or(CfgError::BadSsid)?;
            if s.is_empty() || s.len() > 32 {
                return Err(CfgError::BadSsid);
            }
            Some(s)
        }
        None => None,
    };
    let pmk = match (args.value("ath11k.psk"), args.value("ath11k.passphrase")) {
        (Some(hex), _) => {
            let h = hex.as_bytes();
            if h.len() != 64 {
                return Err(CfgError::BadPsk);
            }
            let mut pmk = [0u8; 32];
            for (i, b) in pmk.iter_mut().enumerate() {
                let hi = hexval(h[2 * i]).ok_or(CfgError::BadPsk)?;
                let lo = hexval(h[2 * i + 1]).ok_or(CfgError::BadPsk)?;
                *b = hi << 4 | lo;
            }
            Some(pmk)
        }
        (None, Some(p)) => {
            let p = unescape(p).ok_or(CfgError::BadPassphrase)?;
            // IEEE 802.11-2020 §J.4.1: 8..63 ASCII characters (32..126).
            if !(8..=63).contains(&p.len()) || p.iter().any(|&c| !(32..=126).contains(&c)) {
                return Err(CfgError::BadPassphrase);
            }
            let Some(s) = ssid.as_deref() else {
                return Err(CfgError::KeyWithoutSsid);
            };
            Some(narf_crypto::pbkdf2_sha1::wpa2_pmk(&p, s))
        }
        (None, None) => None,
    };
    if pmk.is_some() && ssid.is_none() {
        return Err(CfgError::KeyWithoutSsid);
    }
    let scan = args.value("ath11k.scan").is_some_and(|v| v != "0");
    if ssid.is_none() && !scan {
        return Ok(None);
    }
    Ok(Some(AutoCfg { ssid, pmk }))
}

/// The strongest BSS advertising `ssid` with the security the key
/// fits (WPA2 for a PMK, Open without one).
pub fn pick(bss: &[BssInfo], ssid: &[u8], wpa2: bool) -> Option<BssInfo> {
    bss.iter()
        .filter(|b| b.ssid == ssid)
        .filter(|b| match b.security {
            BssSecurity::Wpa2 => wpa2,
            BssSecurity::Open => !wpa2,
            _ => false,
        })
        .max_by_key(|b| b.rssi)
        .map(|b| BssInfo {
            bssid: b.bssid,
            ssid: b.ssid.clone(),
            channel: b.channel,
            rssi: b.rssi,
            security: b.security,
        })
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

fn log(args: core::fmt::Arguments<'_>) {
    let _ = writeln!(narf_console::Writer, "  ath11k: {}", args);
}

/// The scan request for `cfg`: active and directed at the SSID when
/// connecting (hidden SSIDs answer), passive otherwise; every enabled
/// channel.
pub fn scan_request(cfg: &AutoCfg) -> ScanRequest {
    match &cfg.ssid {
        Some(s) => ScanRequest {
            ssids: alloc::vec![s.clone()],
            channels: Vec::new(),
            active: true,
        },
        None => ScanRequest {
            ssids: Vec::new(),
            channels: Vec::new(),
            active: false,
        },
    }
}

/// The association for `bss`.
pub fn associate_request(cfg: &AutoCfg, bss: &BssInfo) -> AssociateRequest {
    AssociateRequest {
        bssid: bss.bssid,
        ssid: bss.ssid.clone(),
        channel: bss.channel,
        security: match cfg.pmk {
            Some(psk) => SecurityConfig::Wpa2 { psk },
            None => SecurityConfig::Open,
        },
    }
}

/// Print a scan result the way `iw dev wlan0 scan` summarises it.
pub fn report(name: &str, bss: &[BssInfo]) {
    log(format_args!("{}: scan: {} BSS", name, bss.len()));
    for b in bss {
        let m = b.bssid;
        log(format_args!(
            "{}:   {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ch {} {} dBm {} \"{}\"",
            name,
            m[0],
            m[1],
            m[2],
            m[3],
            m[4],
            m[5],
            b.channel,
            b.rssi,
            sec_name(b.security),
            core::str::from_utf8(&b.ssid).unwrap_or("<non-utf8>")
        ));
    }
}

/// One attempt: scan, report, pick, associate. `Ok(None)` = scan only.
pub async fn attempt<I: narf_wireless::WirelessNetIface + ?Sized>(
    dev: &I,
    cfg: &AutoCfg,
) -> Result<Option<[u8; 6]>, WirelessError> {
    let name = alloc::string::String::from(dev.name());
    let bss = dev.scan(scan_request(cfg)).await?;
    report(&name, &bss);
    let Some(ssid) = cfg.ssid.as_deref() else {
        return Ok(None);
    };
    let Some(b) = pick(&bss, ssid, cfg.pmk.is_some()) else {
        log(format_args!(
            "{}: autoconnect: no {} BSS for the SSID",
            name,
            if cfg.pmk.is_some() { "WPA2" } else { "open" }
        ));
        return Err(WirelessError::InvalidArgs);
    };
    dev.associate(associate_request(cfg, &b)).await?;
    let m = b.bssid;
    log(format_args!(
        "{}: autoconnect: connected to {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} ch {}",
        name, m[0], m[1], m[2], m[3], m[4], m[5], b.channel
    ));
    Ok(Some(b.bssid))
}

/// Retry interval while disconnected.
pub const RETRY_MS: u64 = 10_000;
/// Consecutive failed attempts before giving up.
pub const MAX_FAILURES: u32 = 6;

/// The autoconnect task: one attempt at start, then every
/// [`RETRY_MS`] while not connected (link loss reconnects), until
/// [`MAX_FAILURES`] attempts in a row failed. Scan-only configurations
/// run once.
pub async fn run<I: narf_wireless::WirelessNetIface + ?Sized>(
    dev: alloc::sync::Arc<I>,
    cfg: AutoCfg,
) {
    let mut failures = 0;
    loop {
        if dev.connected_bssid().is_none() {
            match attempt(dev.as_ref(), &cfg).await {
                Ok(None) => return,
                Ok(Some(_)) => failures = 0,
                Err(e) => {
                    failures += 1;
                    log(format_args!(
                        "{}: autoconnect attempt {} failed: {:?}",
                        dev.name(),
                        failures,
                        e
                    ));
                    if failures >= MAX_FAILURES {
                        log(format_args!("{}: autoconnect: giving up", dev.name()));
                        return;
                    }
                }
            }
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(RETRY_MS).as_instant()).await;
    }
}
