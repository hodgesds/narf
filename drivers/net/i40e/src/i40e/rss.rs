//! Intel 700-series RSS resource discovery and programming.
//! Reference: Linux v7.3-rc4 i40e_main.c (pf_config_rss/config_rss_reg),
//! i40e_common.c (RSS AQ commands), libie/adminq.h and libie/pctype.h.

use super::{AqOpcode, Hardware, I40eError, MAX_QUEUE_PAIRS};

pub const CSR_END: u64 = 0x00245984;
const HENA: u64 = (1 << 31) | (1 << 33) | (1 << 41) | (1 << 43);
const REG_CTL: u64 = 0x001C0AC0;
const REG_HENA: u64 = 0x00245900;
const REG_HKEY: u64 = 0x00244800;
const REG_HLUT: u64 = 0x00240000;

/// A power-of-two TC0 allocation never covers an unallocated queue.
pub(super) fn queue_count(cpus: u16, queues: u16, limit: u16) -> Result<u16, I40eError> {
    let max = cpus.max(1).min(queues).min(limit).min(MAX_QUEUE_PAIRS);
    if max == 0 {
        return Err(I40eError::NoQueuesAllocated);
    }
    Ok(1 << (15 - max.leading_zeros()))
}

/// Prefer different online CPUs; tolerate sparse IDs and later CPU offlining.
pub(super) fn queue_cpu(queue: usize) -> u32 {
    let online = narf_scheduler::online_cpu_set().bits();
    let count = online.count_ones();
    if count == 0 {
        return 0;
    }
    let mut remaining = online;
    for _ in 0..queue % count as usize {
        remaining &= remaining - 1;
    }
    remaining.trailing_zeros()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RssCaps {
    pub table_len: usize,
    pub width: u32,
    pub rx: u32,
    pub tx: u32,
    pub vectors: u32,
}
impl RssCaps {
    pub fn parse(bytes: &[u8], count: usize) -> Result<Self, I40eError> {
        if count > bytes.len() / 32 {
            return Err(I40eError::BadRssCapabilities);
        }
        let mut caps = Self {
            table_len: 0,
            width: 0,
            rx: 0,
            tx: 0,
            vectors: 0,
        };
        for record in bytes[..count * 32].chunks_exact(32) {
            let number = u32::from_le_bytes(record[4..8].try_into().unwrap());
            match u16::from_le_bytes([record[0], record[1]]) {
                0x40 => {
                    caps.table_len = number as usize;
                    caps.width = u32::from_le_bytes(record[8..12].try_into().unwrap());
                    if !matches!(number, 128 | 512) || caps.width > 8 {
                        return Err(I40eError::BadRssCapabilities);
                    }
                }
                0x41 => caps.rx = number,
                0x42 => caps.tx = number,
                0x43 => caps.vectors = number,
                _ => {}
            }
        }
        Ok(caps)
    }
    pub fn queue_limit(self, requested: u16) -> Result<u16, I40eError> {
        let limit = self
            .rx
            .min(self.tx)
            .min(self.vectors.saturating_sub(1))
            .min(1 << self.width);
        queue_count(requested, limit.min(u16::MAX as u32) as u16, requested)
    }
}

#[derive(Clone)]
pub(super) struct RssConfig {
    pub key: [u8; 52],
}
impl Default for RssConfig {
    fn default() -> Self {
        // Standard Toeplitz conformance key, extended to the hardware's 52 bytes.
        // This is a traffic distribution key, not a cryptographic secret.
        Self {
            key: [
                0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
                0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
                0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa, 0x6d, 0x5a,
                0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d,
            ],
        }
    }
}
impl RssConfig {
    pub fn lut(&self, queues: usize, len: usize) -> alloc::vec::Vec<u8> {
        (0..len).map(|i| (i % queues) as u8).collect()
    }
    pub fn hash(&self, tuple: &[u8]) -> u32 {
        debug_assert!(tuple.len() <= 36);
        let mut window = u32::from_be_bytes(self.key[..4].try_into().unwrap());
        let mut hash = 0;
        for (byte_index, &byte) in tuple.iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    hash ^= window;
                }
                let key_bit = byte_index * 8 + bit + 32;
                window = (window << 1) | ((self.key[key_bit / 8] >> (7 - key_bit % 8)) & 1) as u32;
            }
        }
        hash
    }
    /// Stable per-flow TX selection, independent of payload and submitting CPU.
    /// Non-IP and malformed headers use queue 0. Fragments use addresses only.
    pub fn tx_queue(&self, frame: &[u8], queues: usize) -> usize {
        if queues <= 1 || frame.len() < 14 {
            return 0;
        }
        let mut kind = u16::from_be_bytes([frame[12], frame[13]]);
        let mut ip = 14;
        for _ in 0..2 {
            if !matches!(kind, 0x8100 | 0x88a8) {
                break;
            }
            if frame.len() < ip + 4 {
                return 0;
            }
            kind = u16::from_be_bytes([frame[ip + 2], frame[ip + 3]]);
            ip += 4;
        }
        let mut tuple = [0u8; 36];
        let (mut n, l4, protocol, fragmented) = match kind {
            0x0800 if frame.len() >= ip + 20 && frame[ip] >> 4 == 4 => {
                let ihl = (frame[ip] as usize & 15) * 4;
                if ihl < 20 || frame.len() < ip + ihl {
                    return 0;
                }
                tuple[..8].copy_from_slice(&frame[ip + 12..ip + 20]);
                (
                    8,
                    ip + ihl,
                    frame[ip + 9],
                    frame[ip + 6] & 0x3f != 0 || frame[ip + 7] != 0,
                )
            }
            0x86dd if frame.len() >= ip + 40 && frame[ip] >> 4 == 6 => {
                tuple[..32].copy_from_slice(&frame[ip + 8..ip + 40]);
                (32, ip + 40, frame[ip + 6], false)
            }
            _ => return 0,
        };
        if !fragmented && matches!(protocol, 6 | 17) && frame.len() >= l4 + 4 {
            tuple[n..n + 4].copy_from_slice(&frame[l4..l4 + 4]);
            n += 4;
        }
        self.hash(&tuple[..n]) as usize % queues
    }
}

impl Hardware {
    pub(super) fn rss_capabilities(&self) -> Result<RssCaps, I40eError> {
        let (bytes, wb) = self.aq_send(
            AqOpcode::ListFunctionCapabilities,
            [0; 16],
            None,
            super::AQ_BUF_BYTES as u16,
        )?;
        let count = u32::from_le_bytes(wb.params[4..8].try_into().unwrap()) as usize;
        RssCaps::parse(&bytes, count)
    }
    pub(super) fn configure_rss(&self, caps: RssCaps) -> Result<(), I40eError> {
        let queues = self.queues.len();
        let lut = self.rss.lut(queues, caps.table_len);
        // All queues are disabled here (probe or completed reset). Direct RX
        // control accesses therefore cannot race active packet classification.
        // X722 uses per-VSI key/LUT AQ commands; X710 uses PF registers.
        let x722 = matches!(self.device_id, 0x37ce..=0x37d3 | 0x0dda);
        // SAFETY: BAR length checked against CSR_END, PF is exclusively owned.
        unsafe {
            self.csr.write32(REG_HENA, 0);
            self.csr.write32(REG_HENA + 128, 0);
            let ctrl = self.csr.read32(REG_CTL) & !(1 << 16);
            self.csr.write32(
                REG_CTL,
                ctrl | if caps.table_len == 512 { 1 << 16 } else { 0 },
            );
        }
        if caps.table_len == 0 {
            return Ok(());
        }
        if x722 {
            if self.vsi.vsi_number > 0x3ff {
                return Err(I40eError::BadVsiParams);
            }
            let mut params = [0u8; 16];
            params[..2].copy_from_slice(&(self.vsi.vsi_number | 0x8000).to_le_bytes());
            self.aq_send(AqOpcode::SetRssKey, params, Some(&self.rss.key), 52)?;
            params[2] = 1; // PF lookup table
            self.aq_send(AqOpcode::SetRssLut, params, Some(&lut), lut.len() as u16)?;
        } else {
            // SAFETY: mapped registers; program all 512 LUT entries even when
            // the PF selects a 128-entry table, as Linux's register path does.
            unsafe {
                for (i, word) in self.rss.key.chunks_exact(4).enumerate() {
                    self.csr.write32(
                        REG_HKEY + i as u64 * 128,
                        u32::from_le_bytes(word.try_into().unwrap()),
                    );
                }
                for i in 0..128 {
                    let word = core::array::from_fn(|j| ((i * 4 + j) % queues) as u8);
                    self.csr
                        .write32(REG_HLUT + i as u64 * 128, u32::from_le_bytes(word));
                }
            }
        }
        // SAFETY: only non-tunnel IPv4/IPv6 TCP/UDP PCTYPEs; all other traffic
        // lands on default queue 0. HENA uses filter PCTYPE, not RX descriptor PTYPE.
        let hena = HENA
            | if x722 {
                (1 << 29) | (1 << 30) | (1 << 32) | (1 << 39) | (1 << 40) | (1 << 42)
            } else {
                0
            };
        // SAFETY: owned PF with all queues disabled and BAR offsets validated.
        unsafe {
            self.csr.write32(REG_HENA, hena as u32);
            self.csr.write32(REG_HENA + 128, (hena >> 32) as u32);
            self.csr.read32(REG_HENA);
        }
        Ok(())
    }
}

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_i40e_rss_limits_and_capability_bounds() -> TestResult {
        for (cpus, queues, vectors, expected) in [
            (64, 128, 63, 8),
            (3, 8, 8, 2),
            (8, 3, 8, 2),
            (8, 8, 1, 1),
            (0, 8, 8, 1),
        ] {
            if queue_count(cpus, queues, vectors) != Ok(expected) {
                return TestResult::Fail("queue negotiation exceeds available resources");
            }
        }
        if queue_count(8, 0, 8).is_ok() || queue_count(8, 8, 0).is_ok() {
            return TestResult::Fail("empty allocation accepted");
        }
        let mut bytes = [0u8; 128];
        for (i, (id, number)) in [(0x40u16, 512u32), (0x41, 8), (0x42, 3), (0x43, 9)]
            .iter()
            .enumerate()
        {
            bytes[i * 32..i * 32 + 2].copy_from_slice(&id.to_le_bytes());
            bytes[i * 32 + 4..i * 32 + 8].copy_from_slice(&number.to_le_bytes());
        }
        bytes[8] = 3;
        if RssCaps::parse(&bytes, 4).unwrap().queue_limit(8) != Ok(2)
            || RssCaps::parse(&bytes, 5).is_ok()
            || RssCaps::parse(&bytes[..127], 4).is_ok()
        {
            return TestResult::Fail("firmware capability count/queue bound ignored");
        }
        bytes[8] = 32;
        if RssCaps::parse(&bytes, 4).is_ok() {
            return TestResult::Fail("invalid RSS entry width accepted");
        }
        bytes[8] = 3;
        bytes[4..8].copy_from_slice(&1024u32.to_le_bytes());
        if RssCaps::parse(&bytes, 4).is_ok() {
            return TestResult::Fail("unsupported LUT length accepted");
        }
        let config = RssConfig::default();
        for queues in [1, 2, 4, 8] {
            for len in [128, 512] {
                let table = config.lut(queues, len);
                for q in 0..queues {
                    if table.iter().filter(|&&entry| entry as usize == q).count() != len / queues {
                        return TestResult::Fail(
                            "RSS indirection unbalanced or names absent queues",
                        );
                    }
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/net/i40e",
        smoke_i40e_rss_limits_and_capability_bounds
    );

    fn smoke_i40e_toeplitz_flow_stability() -> TestResult {
        let rss = RssConfig::default();
        let tuple = [66, 9, 149, 187, 161, 142, 100, 80, 0x0a, 0xea, 0x06, 0xe6];
        if rss.hash(&tuple[..8]) != 0x323e8fc2 || rss.hash(&tuple) != 0x51ccc178 {
            return TestResult::Fail("Toeplitz regression vectors changed (bit or byte ordering)");
        }
        let mut packet = crate::i40e::tests::tcp_packet(false, 64);
        packet[26..34].copy_from_slice(&tuple[..8]);
        packet[34..38].copy_from_slice(&tuple[8..]);
        let q = rss.tx_queue(&packet, 8);
        packet[54..].fill(0xaa);
        packet[18..20].copy_from_slice(&[0xff, 0xff]); // IPv4 ID is not part of the flow
        if q != 0x51ccc178 % 8 || rss.tx_queue(&packet, 8) != q {
            return TestResult::Fail("payload/IP ID changed flow queue");
        }
        let mut vlan = packet[..12].to_vec();
        vlan.extend_from_slice(&[0x81, 0, 0, 1]);
        vlan.extend_from_slice(&packet[12..]);
        if rss.tx_queue(&vlan, 8) != q {
            return TestResult::Fail("VLAN shifted flow key");
        }
        packet[20..22].copy_from_slice(&[0x20, 0]);
        let first = rss.tx_queue(&packet, 8);
        packet[20..22].copy_from_slice(&[0, 1]);
        packet[34..38].fill(0xaa);
        if rss.tx_queue(&packet, 8) != first {
            return TestResult::Fail("fragments split across TX queues");
        }
        let mut used = [false; 8];
        packet[20..22].fill(0);
        for port in 0..256u16 {
            packet[34..36].copy_from_slice(&port.to_be_bytes());
            used[rss.tx_queue(&packet, 8)] = true;
        }
        if used.contains(&false) {
            return TestResult::Fail("flow hashing fails to use all queues");
        }
        for len in 0..packet.len() {
            let _ = rss.tx_queue(&packet[..len], 8);
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/i40e", smoke_i40e_toeplitz_flow_stability);
}
