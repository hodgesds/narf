// SPDX-License-Identifier: GPL-2.0-or-later
//! FullMAC Wake-on-WLAN and GTK rekey offload (Linux 7.3-rc4
//! brcmfmac/{feature,cfg80211}.c, `fwil_types.h`).
//!
//! Feature probe (`feature.c::brcmf_feat_attach`): only when the bus reports
//! `wowl_supported` (`pcie.c`: `pci_pme_capable(pdev, PCI_D3hot)`; SDIO:
//! `MMC_PM_KEEP_POWER` plus a wake IRQ) is the `wowl` iovar read
//! (`BRCMF_FEAT_WOWL`); then `wowl_cap` sets `BRCMF_FEAT_WOWL_ARP_ND` and,
//! by its bits, `BRCMF_FEAT_WOWL_ND` (`BRCMF_WOWL_PFN_FOUND`) and
//! `BRCMF_FEAT_WOWL_GTK` (`BRCMF_WOWL_GTK_FAILURE`).
//!
//! Suspend (`brcmf_cfg80211_suspend` with a `cfg80211_wowlan`) runs
//! `brcmf_configure_wowl` then `brcmf_keepalive_start(ifp, 30)`; resume
//! (`brcmf_cfg80211_resume` with `wowl.active`) reads and reports
//! `wowl_wakeind`, clears `wowl`/patterns and restores the saved PM mode.
use super::{get_var, ioctl::Direction, set_int, Error, Fullmac, Station};
use alloc::vec::Vec;
use narf_wireless::{WowlanConfig, WowlanSupport};
use zeroize::Zeroizing;

/// `fwil_types.h` WOWL bits.
pub const WOWL_MAGIC: u32 = 1 << 0;
pub const WOWL_NET: u32 = 1 << 1;
pub const WOWL_DIS: u32 = 1 << 2;
pub const WOWL_RETR: u32 = 1 << 3;
pub const WOWL_BCN: u32 = 1 << 4;
pub const WOWL_GTK_FAILURE: u32 = 1 << 10;
pub const WOWL_UNASSOC: u32 = 1 << 24;
pub const WOWL_PFN_FOUND: u32 = 1 << 27;
/// `BRCMF_WOWL_MAXPATTERNS`, `BRCMF_WOWL_MAXPATTERNSIZE` and the
/// `brcmf_wowlan_support` `pattern_min_len`/`max_pkt_offset`.
pub const MAX_PATTERNS: u8 = 16;
pub const MAX_PATTERN_SIZE: u16 = 128;
pub const MAX_PACKET_OFFSET: u16 = 1500;
/// `sizeof(struct brcmf_fil_wowl_pattern_le)`.
pub const PATTERN_HEADER: usize = 32;
/// `BRCMF_C_GET_PM`/`BRCMF_C_SET_PM`, `PM_MAX`.
pub const GET_PM: u32 = 85;
pub const SET_PM: u32 = 86;
pub const PM_MAX: u32 = 1;
/// `sizeof(struct brcmf_wowl_wakeind_le)`.
pub const WAKEIND_LEN: usize = 8;
/// `sizeof(struct brcmf_mkeep_alive_pkt_le)` (packed, no data).
pub const KEEP_ALIVE_LEN: usize = 11;
/// `sizeof(struct brcmf_gtk_keyinfo_le)`: KCK, KEK, replay counter.
pub const GTK_KEYINFO_LEN: usize = 40;

/// Firmware-reported WoWL features (`BRCMF_FEAT_WOWL` with
/// `BRCMF_FEAT_WOWL_ARP_ND`; see [`probe`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    /// `BRCMF_FEAT_WOWL_GTK`: GTK rekey offload and GTK-failure wake.
    pub gtk: bool,
    /// `BRCMF_FEAT_WOWL_ND`: firmware net-detect (not advertised: the
    /// FullMAC station has no PNO/`pfn` scheduled-scan owner).
    pub net_detect: bool,
}
impl Features {
    /// `brcmf_wiphy_wowl_params` over `brcmf_wowlan_support`.
    pub fn support(self) -> WowlanSupport {
        WowlanSupport {
            disconnect: true,
            magic_packet: true,
            gtk_rekey: self.gtk,
            gtk_rekey_failure: self.gtk,
            max_patterns: MAX_PATTERNS,
            min_pattern_len: 1,
            max_pattern_len: MAX_PATTERN_SIZE,
            max_packet_offset: MAX_PACKET_OFFSET,
            net_detect_max_match_sets: 0,
            net_detect_random_mac: false,
        }
    }
    /// The nl80211 `nl80211_set_wowlan` bounds for this wiphy: -EINVAL for
    /// a trigger or pattern outside the advertised support.
    pub fn validate(self, config: &WowlanConfig) -> Result<(), i32> {
        const EINVAL: i32 = 22;
        if config.net_detect.is_some()
            || config.gtk_rekey_failure && !self.gtk
            || config.patterns.len() > usize::from(MAX_PATTERNS)
        {
            return Err(EINVAL);
        }
        for pattern in &config.patterns {
            if pattern.pattern.is_empty()
                || pattern.pattern.len() > usize::from(MAX_PATTERN_SIZE)
                || pattern.mask.len() != pattern.pattern.len().div_ceil(8)
                || pattern.offset > u32::from(MAX_PACKET_OFFSET)
            {
                return Err(EINVAL);
            }
        }
        Ok(())
    }
}

/// `brcmf_feat_attach` WoWL probe. `None` when the bus cannot wake the host
/// from D3hot, the firmware refuses `wowl`, or `wowl_cap` is unreadable
/// (Linux then still advertises basic WoWL and toggles host ARP/ND offload
/// around suspend; NARF's station never enables ARP/ND offload, so that
/// variant is not offered).
pub async fn probe<R: Fullmac>(runtime: &mut R) -> Result<Option<Features>, Error> {
    if !runtime.wowl_supported() {
        return Ok(None);
    }
    match get_var(runtime, "wowl", 4).await {
        Ok(reply) if reply.len() == 4 => {}
        Ok(_) => return Err(Error::Malformed),
        Err(Error::Firmware(_)) => return Ok(None),
        Err(error) => return Err(error),
    }
    let cap = match get_var(runtime, "wowl_cap", 4).await {
        Ok(reply) if reply.len() == 4 => u32::from_le_bytes(reply[..4].try_into().unwrap()),
        Ok(_) => return Err(Error::Malformed),
        Err(Error::Firmware(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(Some(Features {
        gtk: cap & WOWL_GTK_FAILURE != 0,
        net_detect: cap & WOWL_PFN_FOUND != 0,
    }))
}

/// `brcmf_configure_wowl` trigger word. `connected` is
/// `BRCMF_VIF_STATUS_CONNECTED`; without it the firmware is told
/// `BRCMF_WOWL_UNASSOC`.
pub fn trigger_bits(config: &WowlanConfig, connected: bool) -> u32 {
    let mut bits = 0;
    if config.disconnect {
        bits = WOWL_DIS | WOWL_BCN | WOWL_RETR;
    }
    if config.magic_packet {
        bits |= WOWL_MAGIC;
    }
    if !config.patterns.is_empty() {
        bits |= WOWL_NET;
    }
    if config.gtk_rekey_failure {
        bits |= WOWL_GTK_FAILURE;
    }
    if !connected {
        bits |= WOWL_UNASSOC;
    }
    bits
}

/// `brcmf_config_wowl_pattern`: `wowl_pattern` body for `cmd` ("add" or
/// "clr") with the cfg80211 bitmap `mask` (one bit per pattern byte) and
/// `pattern` following the 32-byte `brcmf_fil_wowl_pattern_le`.
pub fn pattern(cmd: &[u8; 4], pattern: &[u8], mask: &[u8], offset: u32) -> Vec<u8> {
    let mask_size = pattern.len().div_ceil(8) as u32;
    let mut out = Vec::with_capacity(PATTERN_HEADER + mask_size as usize + pattern.len());
    out.extend_from_slice(cmd);
    out.extend_from_slice(&mask_size.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());
    // patternoffset counts from `masksize`, past the mask.
    out.extend_from_slice(&(PATTERN_HEADER as u32 - 4 + mask_size).to_le_bytes());
    out.extend_from_slice(&(pattern.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0; 12]); // id, reasonsize, BRCMF_WOWL_PATTERN_TYPE_BITMAP
    out.extend_from_slice(&mask[..mask_size as usize]);
    out.extend_from_slice(pattern);
    out
}

/// `brcmf_keepalive_start(ifp, 30)`: a null-data keep-alive every 30 s.
pub fn keep_alive() -> [u8; KEEP_ALIVE_LEN] {
    let mut out = [0; KEEP_ALIVE_LEN];
    out[..2].copy_from_slice(&1u16.to_le_bytes());
    out[4..8].copy_from_slice(&30_000u32.to_le_bytes());
    out
}

/// `brcmf_cfg80211_set_rekey_data`: `struct brcmf_gtk_keyinfo_le`. The
/// replay counter stays in the nl80211 (big-endian EAPOL) byte order.
pub fn gtk_keyinfo(data: &narf_wireless::GtkRekeyData) -> Zeroizing<[u8; GTK_KEYINFO_LEN]> {
    let mut out = Zeroizing::new([0; GTK_KEYINFO_LEN]);
    out[..16].copy_from_slice(&data.kck);
    out[16..32].copy_from_slice(&data.kek);
    out[32..].copy_from_slice(&data.replay_counter);
    out
}

/// `cfg80211_wowlan_wakeup` as `brcmf_report_wowl_wakeind` fills it from
/// `brcmf_wowl_wakeind_le.ucode_wakeind`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wakeup {
    pub magic_packet: bool,
    /// `BRCMF_WOWL_DIS`, `_BCN` or `_RETR` (link loss while asleep).
    pub disconnect: bool,
    /// Linux maps every `BRCMF_WOWL_NET` wake to pattern 0.
    pub pattern: Option<u8>,
    pub gtk_rekey_failure: bool,
    /// The raw firmware indication.
    pub wakeind: u32,
}

/// `brcmf_report_wowl_wakeind`: `None` is the NULL report (a wake for
/// none of MAGIC/DIS/BCN/RETR/NET/PFN_FOUND, including GTK failure alone,
/// exactly as Linux nests the GTK check).
pub fn decode_wakeind(reply: &[u8]) -> Result<Option<Wakeup>, Error> {
    let raw: [u8; 4] = reply
        .get(4..WAKEIND_LEN)
        .ok_or(Error::Malformed)?
        .try_into()
        .unwrap();
    let wakeind = u32::from_le_bytes(raw);
    if wakeind & (WOWL_MAGIC | WOWL_DIS | WOWL_BCN | WOWL_RETR | WOWL_NET | WOWL_PFN_FOUND) == 0 {
        return Ok(None);
    }
    Ok(Some(Wakeup {
        magic_packet: wakeind & WOWL_MAGIC != 0,
        disconnect: wakeind & (WOWL_DIS | WOWL_BCN | WOWL_RETR) != 0,
        pattern: (wakeind & WOWL_NET != 0).then_some(0),
        gtk_rekey_failure: wakeind & WOWL_GTK_FAILURE != 0,
        wakeind,
    }))
}

/// `cfg->wowl.active` with the PM mode saved by `brcmf_configure_wowl`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Armed {
    pre_pm: u32,
}

impl<R: Fullmac> Station<R> {
    /// Firmware-reported WoWL features, if any.
    pub fn wowl(&self) -> Option<Features> {
        self.wowl
    }
    /// WoWL is armed for the current suspend.
    pub fn wowl_armed(&self) -> bool {
        self.wowl_armed.is_some()
    }

    /// `brcmf_configure_wowl` plus `brcmf_keepalive_start(ifp, 30)`. The
    /// caller suspends the bus next. On error the firmware is returned to
    /// its awake configuration as far as it answers ([`Self::wowl_resume`]).
    pub async fn wowl_suspend(&mut self, config: &WowlanConfig) -> Result<(), Error> {
        let features = self.wowl.ok_or(Error::Unsupported)?;
        features.validate(config).map_err(|_| Error::Malformed)?;
        if self.operation || self.wowl_armed.is_some() {
            return Err(Error::Busy);
        }
        self.poll()?;
        let reply = self
            .runtime
            .command(Direction::Get, GET_PM, &[0; 4], 4)
            .await?;
        let pre_pm =
            u32::from_le_bytes(reply.get(..4).ok_or(Error::Malformed)?.try_into().unwrap());
        // From here the firmware differs from its awake configuration.
        self.wowl_armed = Some(Armed { pre_pm });
        let result = self.wowl_program(config).await;
        if result.is_err() {
            let _ = self.wowl_resume().await;
        }
        result
    }

    async fn wowl_program(&mut self, config: &WowlanConfig) -> Result<(), Error> {
        let connection = self.connection;
        let grants = connection.as_slice();
        self.checked_command(grants, &[], SET_PM, &PM_MAX.to_le_bytes())
            .await?;
        for entry in &config.patterns {
            let body = pattern(b"add\0", &entry.pattern, &entry.mask, entry.offset);
            self.checked_var(grants, &[], "wowl_pattern", &body).await?;
        }
        let bits = trigger_bits(config, self.bssid.is_some());
        let mut clear = [0u8; WAKEIND_LEN];
        clear[..6].copy_from_slice(b"clear\0");
        self.checked_var(grants, &[], "wowl_wakeind", &clear)
            .await?;
        self.checked_var(grants, &[], "wowl", &bits.to_le_bytes())
            .await?;
        self.checked_var(grants, &[], "wowl_activate", &1u32.to_le_bytes())
            .await?;
        self.checked_var(grants, &[], "mkeep_alive", &keep_alive())
            .await?;
        // brcmf_configure_wowl ends with brcmf_bus_wowl_config(true).
        self.runtime.wowl_config(true);
        Ok(())
    }

    /// `brcmf_cfg80211_resume` with `wowl.active`: the firmware wake
    /// indication, then `wowl_clear`, pattern `clr` and the saved PM mode.
    /// `Ok(None)` also when WoWL was not armed. A connected station's host
    /// port is reopened toward the retained peer (the bus suspend closed
    /// it); later firmware link events are handled as usual.
    pub async fn wowl_resume(&mut self) -> Result<Option<Wakeup>, Error> {
        let Some(armed) = self.wowl_armed.take() else {
            return Ok(None);
        };
        // brcmf_cfg80211_resume: brcmf_bus_wowl_config(false).
        self.runtime.wowl_config(false);
        let wake = match get_var(&mut self.runtime, "wowl_wakeind", WAKEIND_LEN).await {
            Ok(reply) => decode_wakeind(&reply),
            Err(error) => Err(error),
        };
        let mut result = super::set_var(&mut self.runtime, "wowl_clear", &0u32.to_le_bytes()).await;
        let clear = pattern(b"clr\0", &[], &[], 0);
        let cleared = super::set_var(&mut self.runtime, "wowl_pattern", &clear).await;
        result = result.and(cleared);
        let restored = set_int(&mut self.runtime, SET_PM, armed.pre_pm).await;
        result = result.and(restored);
        if let Some(peer) = self.bssid {
            self.runtime.set_link(Some(peer));
        }
        result?;
        wake
    }

    /// `brcmf_cfg80211_set_rekey_data`: the `gtk_key_info` iovar. Only
    /// offered with `BRCMF_FEAT_WOWL_GTK` and a current association.
    /// `keyinfo` is [`gtk_keyinfo`]'s wire form.
    pub async fn set_rekey_data(&mut self, keyinfo: &[u8; GTK_KEYINFO_LEN]) -> Result<(), Error> {
        if !self.wowl.is_some_and(|features| features.gtk) {
            return Err(Error::Unsupported);
        }
        if self.bssid.is_none() || self.operation {
            return Err(Error::Busy);
        }
        let connection = self.connection;
        // The iovar buffer carries KCK/KEK too: wipe it after the exchange.
        let mut body = Zeroizing::new(Vec::with_capacity(13 + GTK_KEYINFO_LEN));
        body.extend_from_slice(b"gtk_key_info\0");
        body.extend_from_slice(keyinfo);
        self.checked_command(connection.as_slice(), &[], 263, &body)
            .await
            .map(|_| ())
    }
}
