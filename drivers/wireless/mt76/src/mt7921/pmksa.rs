//! The station owner's SAE PMKSA cache: what wpa_supplicant's `pmksa_cache`
//! holds for SAE when the driver runs SAE itself (a full-offload driver
//! caches it in firmware). After a full SAE exchange the PMK and PMKID are
//! kept per BSS. A later join of the same network to that BSS uses Open
//! System authentication with the PMKID instead of a new SAE exchange
//! (IEEE802.11-2020 12.6.10.3). An entry is bound to the SSID and password
//! that derived it, expires after `dot11RSNAConfigPMKLifetime` (43200 s),
//! and is dropped when the AP refuses it or userspace deletes or flushes it
//! (NL80211_CMD_DEL_PMKSA / FLUSH_PMKSA).
use alloc::vec::Vec;
use zeroize::Zeroizing;

/// wpa_supplicant `dot11RSNAConfigPMKLifetime` (12 hours), in ns.
pub(crate) const LIFETIME_NS: u64 = 43_200 * 1_000_000_000;
/// Entries kept; the oldest is evicted (wpa_supplicant
/// `dot11RSNAConfigPMKSACacheSize` default 32).
const CAPACITY: usize = 32;

/// SHA-256 over the SSID and password that derived an SAE PMK: a cached
/// PMK is used only for the same network credentials, and the password
/// itself is never retained.
pub(crate) fn binding(ssid: &[u8], password: &[u8]) -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(&(ssid.len() as u32).to_le_bytes());
    hash.update(ssid);
    hash.update(password);
    hash.finalize()
}

struct Entry {
    bssid: [u8; 6],
    binding: [u8; 32],
    pmkid: [u8; 16],
    pmk: Zeroizing<[u8; 32]>,
    expires_ns: u64,
}

/// One owner's SAE PMKSA entries.
#[derive(Default)]
pub(crate) struct Cache {
    entries: Vec<Entry>,
}

impl core::fmt::Debug for Cache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PmksaCache")
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl Cache {
    /// Record the PMKSA of a completed SAE association, replacing any
    /// entry for the same BSS.
    pub fn insert(
        &mut self,
        bssid: [u8; 6],
        binding: [u8; 32],
        pmkid: [u8; 16],
        pmk: &[u8; 32],
        now_ns: u64,
    ) {
        self.remove(bssid);
        if self.entries.len() >= CAPACITY {
            self.entries.remove(0);
        }
        self.entries.push(Entry {
            bssid,
            binding,
            pmkid,
            pmk: Zeroizing::new(*pmk),
            expires_ns: now_ns.saturating_add(LIFETIME_NS),
        });
    }

    /// The live entry for this BSS and these credentials: its PMKID and a
    /// copy of the PMK. Expired entries are dropped.
    pub fn lookup(
        &mut self,
        bssid: [u8; 6],
        binding: [u8; 32],
        now_ns: u64,
    ) -> Option<([u8; 16], Zeroizing<[u8; 32]>)> {
        self.entries.retain(|entry| entry.expires_ns > now_ns);
        self.entries
            .iter()
            .find(|entry| entry.bssid == bssid && entry.binding == binding)
            .map(|entry| (entry.pmkid, Zeroizing::new(*entry.pmk)))
    }

    /// NL80211_CMD_DEL_PMKSA by BSSID, or the AP refused the PMKID.
    pub fn remove(&mut self, bssid: [u8; 6]) {
        self.entries.retain(|entry| entry.bssid != bssid);
    }

    /// NL80211_CMD_DEL_PMKSA by PMKID.
    pub fn remove_pmkid(&mut self, pmkid: [u8; 16]) {
        self.entries.retain(|entry| entry.pmkid != pmkid);
    }

    /// NL80211_CMD_FLUSH_PMKSA.
    pub fn flush(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
