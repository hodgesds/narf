//! RSN (Robust Security Network) Information Element (clean-room).
//!
//! Spec: IEEE Std 802.11-2020 §9.4.2.24. Public IEEE document.
//! No GPL Linux source consulted.
//!
//! The RSN IE is what STA and AP exchange in their Beacon /
//! Association frames to negotiate ciphers + AKM (Authentication
//! and Key Management). It's the first thing a Supplicant sees
//! when picking which 4-Way / SAE handshake to run.
//!
//! ## Layout (§9.4.2.24.1)
//!
//! ```text
//!   0..1: Version (always 1, LE)
//!   2..6: Group Cipher Suite (4-byte OUI||suite-type)
//!   6..8: Pairwise Cipher Suite Count (LE)
//!   8..N: Pairwise Cipher Suite list (4 bytes each)
//!   N..M: AKM Suite Count (LE) + AKM Suite list (4 bytes each)
//!   M..M+2: RSN Capabilities (LE)
//!   ... PMKID Count + PMKID List (optional)
//!   ... Group Management Cipher Suite (optional, 4 bytes)
//! ```
//!
//! ## Suite OUI / type values (§9.4.2.24.2)
//!
//! The standard suite OUI is `00-0F-AC` (the 802.11 OUI). Suite
//! types are:
//!
//! ```text
//!   00-0F-AC:00 Use group cipher (pairwise only)
//!   00-0F-AC:01 WEP-40
//!   00-0F-AC:02 TKIP
//!   00-0F-AC:04 CCMP-128
//!   00-0F-AC:05 WEP-104
//!   00-0F-AC:06 BIP-CMAC-128
//!   00-0F-AC:08 GCMP-128
//!   00-0F-AC:09 GCMP-256
//!   00-0F-AC:0A CCMP-256
//!   00-0F-AC:0B BIP-GMAC-128
//!   00-0F-AC:0C BIP-GMAC-256
//! ```
//!
//! AKM types use the same OUI:
//!
//! ```text
//!   00-0F-AC:01 802.1X (EAP)
//!   00-0F-AC:02 PSK (WPA2-Personal)
//!   00-0F-AC:08 SAE (WPA3-Personal)
//!   00-0F-AC:09 FT-SAE (Fast Transition + SAE)
//!   00-0F-AC:0B 802.1X-Suite-B
//!   00-0F-AC:0C 802.1X-Suite-B-192
//! ```

use alloc::vec::Vec;

/// 802.11 OUI for standard cipher / AKM suites (§9.4.2.24.2).
pub const RSN_OUI: [u8; 3] = [0x00, 0x0F, 0xAC];

// ── Cipher suite types ────────────────────────────────────────────
pub const CIPHER_USE_GROUP: u8 = 0x00;
pub const CIPHER_WEP40: u8 = 0x01;
pub const CIPHER_TKIP: u8 = 0x02;
pub const CIPHER_CCMP_128: u8 = 0x04;
pub const CIPHER_WEP104: u8 = 0x05;
pub const CIPHER_BIP_CMAC_128: u8 = 0x06;
pub const CIPHER_GCMP_128: u8 = 0x08;
pub const CIPHER_GCMP_256: u8 = 0x09;
pub const CIPHER_CCMP_256: u8 = 0x0A;
pub const CIPHER_BIP_GMAC_128: u8 = 0x0B;
pub const CIPHER_BIP_GMAC_256: u8 = 0x0C;

// ── AKM types ─────────────────────────────────────────────────────
pub const AKM_DOT1X: u8 = 0x01;
pub const AKM_PSK: u8 = 0x02;
pub const AKM_FT_DOT1X: u8 = 0x03;
pub const AKM_FT_PSK: u8 = 0x04;
pub const AKM_DOT1X_SHA256: u8 = 0x05;
pub const AKM_PSK_SHA256: u8 = 0x06;
pub const AKM_TDLS: u8 = 0x07;
pub const AKM_SAE: u8 = 0x08;
pub const AKM_FT_SAE: u8 = 0x09;
pub const AKM_AP_PEERKEY: u8 = 0x0A;
pub const AKM_DOT1X_SUITE_B: u8 = 0x0B;
pub const AKM_DOT1X_SUITE_B_192: u8 = 0x0C;
pub const AKM_OWE: u8 = 0x12;

// ── RSN Capabilities bits (§9.4.2.24.4) ──────────────────────────
pub const RSN_CAP_PREAUTH: u16 = 1 << 0;
pub const RSN_CAP_NO_PAIRWISE: u16 = 1 << 1;
pub const RSN_CAP_PTKSA_REPLAY_COUNTER_MASK: u16 = 0x000C;
pub const RSN_CAP_GTKSA_REPLAY_COUNTER_MASK: u16 = 0x0030;
pub const RSN_CAP_MFP_REQUIRED: u16 = 1 << 6;
pub const RSN_CAP_MFP_CAPABLE: u16 = 1 << 7;
pub const RSN_CAP_OCV: u16 = 1 << 14;

/// 4-byte cipher / AKM suite selector (3-byte OUI || 1-byte type).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Suite {
    pub oui: [u8; 3],
    pub suite_type: u8,
}

impl Suite {
    pub const fn standard(suite_type: u8) -> Self {
        Self {
            oui: RSN_OUI,
            suite_type,
        }
    }

    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.oui);
        out.push(self.suite_type);
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        Some(Self {
            oui: [buf[0], buf[1], buf[2]],
            suite_type: buf[3],
        })
    }
}

/// Decoded RSN IE body (the 2-byte ID/length prefix is the caller's
/// concern).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsnIe {
    pub version: u16,
    pub group_cipher: Suite,
    pub pairwise_ciphers: Vec<Suite>,
    pub akms: Vec<Suite>,
    pub rsn_capabilities: u16,
    /// Optional PMKID list. Empty when the AP doesn't offer caching.
    pub pmkids: Vec<[u8; 16]>,
    /// Optional group-management cipher (only meaningful when MFP is
    /// negotiated — §9.4.2.24.5).
    pub group_management_cipher: Option<Suite>,
}

impl RsnIe {
    /// Build the canonical WPA2-Personal RSN IE: CCMP-128 group +
    /// pairwise, PSK AKM, no PMF.
    pub fn wpa2_psk_ccmp() -> Self {
        Self {
            version: 1,
            group_cipher: Suite::standard(CIPHER_CCMP_128),
            pairwise_ciphers: alloc::vec![Suite::standard(CIPHER_CCMP_128)],
            akms: alloc::vec![Suite::standard(AKM_PSK)],
            rsn_capabilities: 0,
            pmkids: Vec::new(),
            group_management_cipher: None,
        }
    }

    /// Build the canonical WPA3-Personal RSN IE: CCMP-128 group +
    /// pairwise, SAE AKM, MFP-required + capable, BIP-CMAC-128 group
    /// management cipher.
    pub fn wpa3_sae_ccmp() -> Self {
        Self {
            version: 1,
            group_cipher: Suite::standard(CIPHER_CCMP_128),
            pairwise_ciphers: alloc::vec![Suite::standard(CIPHER_CCMP_128)],
            akms: alloc::vec![Suite::standard(AKM_SAE)],
            rsn_capabilities: RSN_CAP_MFP_REQUIRED | RSN_CAP_MFP_CAPABLE,
            pmkids: Vec::new(),
            group_management_cipher: Some(Suite::standard(CIPHER_BIP_CMAC_128)),
        }
    }

    /// Encode the IE body. Caller wraps with `[ID=48, len, body]`.
    pub fn encode_body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.version.to_le_bytes());
        self.group_cipher.encode(&mut out);
        out.extend_from_slice(&(self.pairwise_ciphers.len() as u16).to_le_bytes());
        for c in &self.pairwise_ciphers {
            c.encode(&mut out);
        }
        out.extend_from_slice(&(self.akms.len() as u16).to_le_bytes());
        for a in &self.akms {
            a.encode(&mut out);
        }
        out.extend_from_slice(&self.rsn_capabilities.to_le_bytes());
        if !self.pmkids.is_empty() || self.group_management_cipher.is_some() {
            out.extend_from_slice(&(self.pmkids.len() as u16).to_le_bytes());
            for pmkid in &self.pmkids {
                out.extend_from_slice(pmkid);
            }
        }
        if let Some(gmc) = self.group_management_cipher {
            gmc.encode(&mut out);
        }
        out
    }

    /// Decode an RSN IE body. Returns `None` on truncation / version
    /// drift.
    pub fn decode_body(buf: &[u8]) -> Option<Self> {
        if buf.len() < 2 + 4 + 2 {
            return None;
        }
        let version = u16::from_le_bytes([buf[0], buf[1]]);
        if version != 1 {
            return None;
        }
        let group_cipher = Suite::decode(&buf[2..6])?;
        let pairwise_count = u16::from_le_bytes([buf[6], buf[7]]) as usize;
        let mut idx = 8usize;
        if buf.len() < idx + pairwise_count * 4 {
            return None;
        }
        let mut pairwise_ciphers = Vec::with_capacity(pairwise_count);
        for _ in 0..pairwise_count {
            pairwise_ciphers.push(Suite::decode(&buf[idx..idx + 4])?);
            idx += 4;
        }
        if buf.len() < idx + 2 {
            return None;
        }
        let akm_count = u16::from_le_bytes([buf[idx], buf[idx + 1]]) as usize;
        idx += 2;
        if buf.len() < idx + akm_count * 4 {
            return None;
        }
        let mut akms = Vec::with_capacity(akm_count);
        for _ in 0..akm_count {
            akms.push(Suite::decode(&buf[idx..idx + 4])?);
            idx += 4;
        }
        let rsn_capabilities = if buf.len() >= idx + 2 {
            let v = u16::from_le_bytes([buf[idx], buf[idx + 1]]);
            idx += 2;
            v
        } else {
            0
        };
        let mut pmkids = Vec::new();
        if buf.len() >= idx + 2 {
            let pmkid_count = u16::from_le_bytes([buf[idx], buf[idx + 1]]) as usize;
            idx += 2;
            for _ in 0..pmkid_count {
                if buf.len() < idx + 16 {
                    return None;
                }
                let mut p = [0u8; 16];
                p.copy_from_slice(&buf[idx..idx + 16]);
                pmkids.push(p);
                idx += 16;
            }
        }
        let group_management_cipher = if buf.len() >= idx + 4 {
            Suite::decode(&buf[idx..idx + 4])
        } else {
            None
        };

        Some(Self {
            version,
            group_cipher,
            pairwise_ciphers,
            akms,
            rsn_capabilities,
            pmkids,
            group_management_cipher,
        })
    }

    /// Pick the best mutually-supported pairwise cipher between
    /// supplicant + authenticator. Preference order: GCMP-256 >
    /// CCMP-256 > GCMP-128 > CCMP-128 > TKIP. Returns `None` if no
    /// overlap.
    pub fn negotiate_pairwise(local: &[Suite], peer: &[Suite]) -> Option<Suite> {
        const PREF: &[u8] = &[
            CIPHER_GCMP_256,
            CIPHER_CCMP_256,
            CIPHER_GCMP_128,
            CIPHER_CCMP_128,
            CIPHER_TKIP,
        ];
        for st in PREF {
            let cand = Suite::standard(*st);
            if local.contains(&cand) && peer.contains(&cand) {
                return Some(cand);
            }
        }
        None
    }

    /// Pick the best mutually-supported AKM. Preference: SAE > PSK-SHA256 >
    /// PSK > 802.1X-SHA256 > 802.1X.
    pub fn negotiate_akm(local: &[Suite], peer: &[Suite]) -> Option<Suite> {
        const PREF: &[u8] = &[
            AKM_SAE,
            AKM_PSK_SHA256,
            AKM_PSK,
            AKM_DOT1X_SHA256,
            AKM_DOT1X,
        ];
        for st in PREF {
            let cand = Suite::standard(*st);
            if local.contains(&cand) && peer.contains(&cand) {
                return Some(cand);
            }
        }
        None
    }
}
