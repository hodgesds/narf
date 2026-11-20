//! `brcmfmac` cfg80211-equivalent attachment surface — stub.
//!
//! Linux's `brcmfmac` reaches the user-visible Wi-Fi knobs through the
//! cfg80211 layer (`drivers/net/wireless/.../brcmfmac/cfg80211.c`):
//! `brcmf_cfg80211_attach`, the per-interface `brcmf_cfg80211_ops`
//! (scan, connect, get_station, etc.), the BSS-list cache, and the
//! key-management hooks. NARF has no equivalent layer yet — wireless
//! at large is just the per-driver `narf-wireless` registry, and the
//! IOCTL/IOVAR wire format (Stage-3) hasn't landed for brcmfmac.
//!
//! What this file is, today: the placeholder where the cfg80211-shim
//! integration lands once the IOCTL path is wired through msgbuf. The
//! signature surface mirrors the small subset of `brcmf_cfg80211_ops`
//! that a Stage-3 follow-up will need to fill in:
//!
//!   - **scan** — `brcmf_cfg80211_scan` (cfg80211.c ~L1180).
//!   - **connect** — `brcmf_cfg80211_connect` (cfg80211.c ~L2150).
//!   - **disconnect** — `brcmf_cfg80211_disconnect` (cfg80211.c ~L2280).
//!   - **get_station** — `brcmf_cfg80211_get_station` (cfg80211.c
//!     ~L3120) — gives RSSI / TX-bytes / RX-bytes back to userspace.
//!
//! Each of these methods translates the userspace request into an
//! IOVAR / IOCTL exchange across the msgbuf ring, which is why this
//! file is empty other than the type stubs: the IOVAR encoders need
//! the Stage-3 follow-up to be useful. The constants below are kept
//! so the rest of the crate (and downstream tests) can compile against
//! a stable surface.

#![allow(dead_code)]

/// Maximum number of BSS entries the firmware will surface from a
/// single scan request. Matches Linux's `BRCMF_SCAN_MAX_BSS_RESULTS`
/// rough bound — used by the Stage-3 BSS-cache pre-allocation.
pub const SCAN_MAX_BSS_RESULTS: usize = 64;

/// Maximum number of SSID match-entries a single scan request can
/// carry. Matches `BRCMF_PNO_SCAN_COMPLETE_PIE` in Linux's cfg80211
/// scan-builder.
pub const SCAN_MAX_SSIDS: usize = 16;

/// Stub for the eventual scan-request handle. Stage-3 lands the
/// `IoctlReq` + IOVAR encoder pair behind this.
#[derive(Copy, Clone, Debug, Default)]
pub struct ScanRequest {
    pub active: bool,
    pub n_ssids: u8,
}

/// Stub for the eventual connect-request handle.
#[derive(Copy, Clone, Debug, Default)]
pub struct ConnectRequest {
    pub want_4way_handshake: bool,
    pub ssid_len: u8,
}
