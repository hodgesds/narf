//! ixgbe RSS programming — MRQC / RSSRK / RETA.
//!
//! Grounding: Intel 82599 Datasheet rev. 2.6 (322429-007)
//! §8.2.3.7.12 (MRQC, MRQE field + RSS-field-enable bits),
//! §8.2.3.7.14 (RSSRK, 40-byte key, byte 4*n+m in bits
//! [8*m+7:8*m]), §8.2.3.7.15 (RETA, 128 entries, 4 bits per
//! entry at [3:0]/[11:8]/[19:16]/[27:24]).
//! The hash itself is the shared Toeplitz implementation in
//! `narf_net::rss` (standard 40-byte key, Microsoft conformance
//! vectors); this module only packs that key + indirection table
//! into the 82599's registers.
//!
//! Register addresses: see `super::regs` (issue #1397). The
//! datasheet dual-maps MRQC/RSSRK/RETA — native 0x0E block and
//! 82598-compat 0x05 block are the SAME physical registers —
//! and this path programs the 0x05 (Linux/compat) canonical
//! addresses from the shared authority. The addresses
//! themselves come from the datasheet; Linux's shipping map
//! (ixgbe_type.h) is cited there only as the cross-check for
//! which alias to program, not as copied code.
//!
//! Mode: MRQE = 0001b = "RSS only — single set of RSS 16 queues"
//! (§8.2.3.7.12), so RSS is valid for 1..=16 RX queues. All six
//! hash-field enables are set (TcpIPv4 bit 16, IPv4 bit 17, IPv6
//! bit 20, TcpIPv6 bit 21, UdpIPv4 bit 22, UdpIPv6 bit 23), matching
//! the tuple set `narf_net::rss::flow_tuple` extracts. The RETA is
//! the balanced table from `narf_net::rss` (128 entries round-robin
//! over the queue count), so a flow's hardware queue equals
//! `RssConfig::rx_queue` for the same frame.

use super::queues::RegBank;

/// MRQE value for RSS-only mode — re-exported from the same
/// authority (VMDq modes live there too, for the composition lane).
pub use super::regs::MRQE_RSS_ONLY;
/// Register addresses — single authority in `super::regs` (see
/// #1397); re-exported here so existing importers keep working.
/// Do NOT redefine these literals in this module.
pub use super::regs::{REG_MRQC, REG_RETA_BASE, REG_RSSRK_BASE};
/// RSS hash-field enables: TcpIPv4, IPv4, IPv6, TcpIPv6, UdpIPv4,
/// UdpIPv6 (datasheet §8.2.3.7.12, bits 31:16).
pub const MRQC_HASH_FIELDS: u32 =
    (1 << 16) | (1 << 17) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);

/// Maximum RX queues in RSS-only mode (MRQE = 0001).
pub const RSS_MAX_QUEUES: usize = 16;
/// RETA entry count (128 entries in 32 registers).
pub const RETA_ENTRIES: usize = 128;
/// RSS key length in bytes (10 key registers).
pub const RSS_KEY_LEN: usize = 40;

/// Build the MRQC word for RSS-only mode with all hash fields on.
pub const fn mrqc_word() -> u32 {
    MRQE_RSS_ONLY | MRQC_HASH_FIELDS
}

/// Pack the 40-byte RSS key into the 10 RSSRK register words.
/// Key byte 4*n+m goes to bits [8*m+7:8*m] of word n (little-endian
/// word packing per §8.2.3.7.14's K0..K3 layout).
pub fn rssrk_words(key: &[u8; RSS_KEY_LEN]) -> [u32; 10] {
    let mut words = [0u32; 10];
    for n in 0..10 {
        words[n] = u32::from_le_bytes([key[4 * n], key[4 * n + 1], key[4 * n + 2], key[4 * n + 3]]);
    }
    words
}

/// Pack a 128-entry indirection table into the 32 RETA words.
/// Entry 4*n+m goes to bits [8*m+3:8*m] of word n (4-bit entries).
pub fn reta_words(table: &[u8; RETA_ENTRIES]) -> [u32; 32] {
    let mut words = [0u32; 32];
    for n in 0..32 {
        let mut w = 0u32;
        for m in 0..4 {
            w |= ((table[4 * n + m] as u32) & 0xF) << (8 * m);
        }
        words[n] = w;
    }
    words
}

/// RSS programming state: the standard key + a balanced 128-entry
/// table over `queues` RX queues.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IxgbeRss {
    pub key: [u8; RSS_KEY_LEN],
    pub table: [u8; RETA_ENTRIES],
    pub queues: usize,
}

impl IxgbeRss {
    /// Standard configuration: the `narf_net::rss` conformance key
    /// and a balanced table over `queues` (1..=16) queues.
    pub fn standard(queues: usize) -> Result<Self, RssError> {
        if queues == 0 || queues > RSS_MAX_QUEUES {
            return Err(RssError::QueueCount);
        }
        let cfg = narf_net::rss::RssConfig::standard(queues, RETA_ENTRIES);
        let mut key = [0u8; RSS_KEY_LEN];
        key.copy_from_slice(&cfg.key[..RSS_KEY_LEN]);
        let mut table = [0u8; RETA_ENTRIES];
        table.copy_from_slice(&cfg.indirection[..RETA_ENTRIES]);
        Ok(Self { key, table, queues })
    }

    /// The `narf_net::rss::RssConfig` view of this programming, for
    /// the `HwNic`/`Interface` `rss()` surface (so the stack's
    /// TX-queue choice agrees with hardware steering).
    pub fn as_net_config(&self) -> narf_net::rss::RssConfig {
        narf_net::rss::RssConfig {
            key: self.key.to_vec(),
            indirection: self.table.to_vec(),
        }
    }

    /// RX queue the hardware steers `frame` to, via the shared
    /// Toeplitz + table path (must equal `as_net_config().rx_queue`).
    pub fn rx_queue(&self, frame: &[u8]) -> usize {
        self.as_net_config().rx_queue(frame)
    }

    /// Program MRQC + RSSRK + RETA into `bank`, in that order.
    /// Callers must have RX disabled (RXCTRL.RXEN = 0) while
    /// reprogramming filters, per the FCTRL note in §8.2.3.7.1.
    pub fn apply(&self, bank: &mut impl RegBank) {
        bank.write32(REG_MRQC, mrqc_word());
        for (n, w) in rssrk_words(&self.key).iter().enumerate() {
            bank.write32(REG_RSSRK_BASE + 4 * n as u64, *w);
        }
        for (n, w) in reta_words(&self.table).iter().enumerate() {
            bank.write32(REG_RETA_BASE + 4 * n as u64, *w);
        }
    }
}

/// [`IxgbeRss::standard`] failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RssError {
    /// Queue count outside 1..=16.
    QueueCount,
}
