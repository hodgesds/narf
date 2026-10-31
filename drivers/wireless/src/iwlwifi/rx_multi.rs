// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained RFH_QUEUE_CONFIG v1 and RSS_CONFIG v1 wire contracts.
//! Linux fw/init.c::iwl_configure_rxq and mld/fw.c::iwl_mld_send_rss_cfg_cmd.
//! Callers must retain every DMA allocation through terminal stop proof;
//! these wire bytes supply no PCI, firmware or receive-epoch authority.
use super::boot_context::{put32, put64};
use alloc::{vec, vec::Vec};

pub(super) struct QueueDma {
    pub queue: u8,
    pub status: u64,
    pub free: u64,
    pub used: u64,
    pub free_write: u32,
}
/// Additional queues only: queue0 is already in the native context.
/// Queue numbering is consecutive, bounded by the source sync sender mask.
pub(super) fn queue_configuration(queues: &[QueueDma]) -> Result<Vec<u8>, &'static str> {
    if queues.is_empty() || queues.len() > 15 {
        return Err("RFH additional queue count outside native profile");
    }
    let mut bytes = vec![0; 4 + 32 * queues.len()];
    bytes[0] = queues.len() as u8;
    for (index, queue) in queues.iter().enumerate() {
        if usize::from(queue.queue) != index + 1
            || queue.status == 0
            || queue.status & 7 != 0
            || queue.free == 0
            || queue.free & 0xfff != 0
            || queue.used == 0
            || queue.used & 0xfff != 0
            || queue.free_write >= 512
            || queue.free_write & 7 != 0
        {
            return Err("RFH queue identity, retained DMA geometry or initial index");
        }
        let at = 4 + 32 * index;
        bytes[at] = queue.queue;
        // Linux's zeroed v1 payload leaves enable/reserved at0.
        put64(&mut bytes, at + 4, queue.status);
        put64(&mut bytes, at + 12, queue.free);
        put64(&mut bytes, at + 20, queue.used);
        put32(&mut bytes, at + 28, queue.free_write);
    }
    Ok(bytes)
}
/// A caller supplies a fresh native RSS key from the existing secure RNG.
/// Queue0 remains fallback; all six source-defined IP hash classes use the
/// exact same flow indirection. No key is derived from clocks or addresses.
pub(super) fn rss_configuration(queues: u8, key: &[u8; 40]) -> Result<[u8; 176], &'static str> {
    if !(2..=16).contains(&queues) {
        return Err("RSS needs a fallback and at least one additional RFH queue");
    }
    let mut bytes = [0; 176];
    put32(&mut bytes, 0, 1);
    bytes[4] = 0x3f;
    bytes[8..48].copy_from_slice(key);
    for (index, queue) in bytes[48..].iter_mut().enumerate() {
        *queue = 1 + (index % usize::from(queues - 1)) as u8;
    }
    Ok(bytes)
}

/// Correlated all-queue prefix proof. `queue` in observe comes from the
/// retained RFH ring that copied the packet, never from firmware payload.
/// A command ACK, an empty queue or one queue's marker cannot release DMA
/// or reopen receive admission for the other queues.
pub(super) struct Prefix {
    cookie: u32,
    waiting: u16,
    baid: Option<u8>,
    sync: bool,
}
impl Prefix {
    pub fn new(queues: u8, cookie: u32, baid: Option<u8>) -> Result<Self, &'static str> {
        Self::with_sync(queues, cookie, baid, false)
    }
    /// MVM's internal notification contains sync1; MLD uses sync0.
    /// The profile is a firmware wire fact, not receive/RF authority.
    pub fn gen2(queues: u8, cookie: u32, baid: Option<u8>) -> Result<Self, &'static str> {
        Self::with_sync(queues, cookie, baid, true)
    }
    fn with_sync(
        queues: u8,
        cookie: u32,
        baid: Option<u8>,
        sync: bool,
    ) -> Result<Self, &'static str> {
        if !(1..=16).contains(&queues) || cookie == 0 || baid.is_some_and(|id| id >= 32) {
            return Err("native RFH prefix identity or queue count");
        }
        Ok(Self {
            cookie,
            waiting: ((1u32 << queues) - 1) as u16,
            baid,
            sync,
        })
    }
    pub fn mask(&self) -> u16 {
        self.waiting
    }
    pub fn observe(&mut self, queue: u8, body: &[u8]) -> Result<bool, &'static str> {
        let count = if self.baid.is_some() { 12 } else { 8 };
        if queue >= 16
            || body.len() != count + 4
            || body[..8]
                != [
                    count as u8,
                    0,
                    0,
                    0,
                    u8::from(self.baid.is_some()),
                    0,
                    u8::from(self.sync),
                    0,
                ]
        {
            return Err("native all-RFH marker queue or wire extent/type");
        }
        if u32::from_le_bytes(body[8..12].try_into().unwrap()) != self.cookie {
            return Ok(false);
        }
        if self
            .baid
            .is_some_and(|id| body[12..16] != u32::from(id).to_le_bytes())
        {
            return Err("native all-RFH marker BAID mismatch");
        }
        let bit = 1u16 << queue;
        if self.waiting & bit == 0 {
            return Err("native RFH marker repeated or outside retained queue set");
        }
        self.waiting &= !bit;
        Ok(self.waiting == 0)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_rfh_rss_native_literals_and_exact_all_queue_prefix() -> TestResult {
        let queues = [
            QueueDma {
                queue: 1,
                status: 0x11000,
                free: 0x12000,
                used: 0x13000,
                free_write: 504,
            },
            QueueDma {
                queue: 2,
                status: 0x21000,
                free: 0x22000,
                used: 0x23000,
                free_write: 504,
            },
        ];
        let bytes = queue_configuration(&queues).unwrap();
        let key = core::array::from_fn(|i| i as u8 + 1);
        let rss = rss_configuration(3, &key).unwrap();
        if bytes.len() != 68
            || bytes[..8] != [2, 0, 0, 0, 1, 0, 0, 0]
            || bytes[8..16] != 0x11000u64.to_le_bytes()
            || bytes[16..24] != 0x12000u64.to_le_bytes()
            || bytes[24..32] != 0x13000u64.to_le_bytes()
            || bytes[32..36] != 504u32.to_le_bytes()
            || bytes[36..40] != [2, 0, 0, 0]
            || rss[..8] != [1, 0, 0, 0, 0x3f, 0, 0, 0]
            || rss[8..48] != key
            || rss[48..]
                .iter()
                .enumerate()
                .any(|(i, q)| *q != 1 + (i % 2) as u8)
        {
            return TestResult::Fail(
                "RFH/RSS native v1 literal extent, addresses, flags or indirection",
            );
        }
        let mut prefix = Prefix::new(3, 0x12345678, Some(3)).unwrap();
        let mut marker = [12, 0, 0, 0, 1, 0, 0, 0, 0x78, 0x56, 0x34, 0x12, 3, 0, 0, 0];
        marker[8] = 0x77;
        if prefix.observe(2, &marker) != Ok(false) || prefix.mask() != 7 {
            return TestResult::Fail("stale RFH marker changed prefix ownership");
        }
        marker[8] = 0x78;
        if prefix.observe(2, &marker) != Ok(false)
            || prefix.mask() != 3
            || prefix.observe(2, &marker).is_ok()
            || prefix.mask() != 3
            || prefix.observe(0, &marker) != Ok(false)
            || prefix.mask() != 2
            || prefix.observe(1, &marker) != Ok(true)
            || prefix.mask() != 0
        {
            return TestResult::Fail("RFH prefix accepted a duplicate or one queue as all queues");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/rx_queues",
        smoke_rfh_rss_native_literals_and_exact_all_queue_prefix
    );
}
