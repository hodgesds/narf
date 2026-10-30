// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Gen2 shared-memory geometry from the retained firmware, as parsed by
//! Linux fw/smem.c::iwl_parse_shared_mem_22000. Addresses remain opaque
//! values; firmware reports never become host pointers or RF authority.
use super::{Owner, Phase};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedMemory {
    lmacs: u8,
    tx_fifo: [[u32; 15]; 2],
}
impl SharedMemory {
    pub fn lmac_count(&self) -> u8 {
        self.lmacs
    }
    pub fn tx_fifo_bytes(&self, lmac: u8, fifo: u8) -> Option<u32> {
        if lmac >= self.lmacs {
            return None;
        }
        self.tx_fifo
            .get(usize::from(lmac))?
            .get(usize::from(fifo))
            .copied()
    }
    /// Gen2 EDCA FIFO BK1/BE2/VI3/VO4, with Linux's 256-byte security
    /// margin for the command/header and start of the following packet.
    /// The result still needs negotiated peer, TLC and qualified-program
    /// limits; this geometry supplies no transmit authority.
    pub fn edca_payload_ceiling(&self, lmac: u8, tid: u8) -> Option<u32> {
        let fifo = match tid {
            0 | 3 => 2,
            1 | 2 => 1,
            4 | 5 => 3,
            6 | 7 => 4,
            _ => return None,
        };
        self.tx_fifo_bytes(lmac, fifo)?.checked_sub(256)
    }
    pub(super) fn parse(version: u8, bytes: &[u8]) -> Result<Self, &'static str> {
        if version > 4
            || bytes.len() < 180
            || bytes.len() > 260
            || bytes.len() % 4 != 0
            || version == 4 && bytes.len() < 260
        {
            return Err("unsupported Gen2 shared-memory response extent/version");
        }
        let count = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        if !(1..=2).contains(&count) {
            return Err("Gen2 shared-memory response has invalid LMAC count");
        }
        let mut result = Self {
            lmacs: count as u8,
            tx_fifo: [[0; 15]; 2],
        };
        for lmac in 0..usize::from(result.lmacs) {
            // Header36, SHARED_MEM_ALLOC_LMAC72; skip txfifo_addr.
            for fifo in 0..15 {
                let at = 40 + lmac * 72 + fifo * 4;
                result.tx_fifo[lmac][fifo] =
                    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
            }
        }
        Ok(result)
    }
}

impl Owner {
    pub(super) async fn prepare_shared_memory_using(
        &mut self,
        policy: &mut impl FnMut() -> Result<narf_wireless::reg::RegulatoryDomain, &'static str>,
    ) -> Result<(), &'static str> {
        if self.power.shared_memory.is_some() {
            return Ok(());
        }
        let parsed = super::super::parse_ucode(&self.firmware)
            .map_err(|_| "invalid retained Gen2 executable")?;
        let (group, command) = if parsed.api.has_capability(80) {
            (2, 0)
        } else {
            (0, 0x25)
        };
        let version = self
            .hardware
            .version(2, 0)
            .map(|v| v.1)
            .filter(|v| *v != 99)
            .unwrap_or(0);
        if version > 4 {
            return Err("unsupported Gen2 shared-memory notification profile");
        }
        let reply = self
            .qualified_link_command(group, command, &[], policy)
            .await?;
        self.power.shared_memory = Some(SharedMemory::parse(version, &reply)?);
        Ok(())
    }
    /// Query the live firmware's geometry as a retained read-only operation.
    /// A cancelled public waiter cannot lose its command/DMA owner.
    pub(in crate::iwlwifi) async fn query_shared_memory(
        &mut self,
    ) -> Result<SharedMemory, &'static str> {
        if self.phase != Phase::Configured || self.hardware.is_failed() {
            return Err("Gen2 shared-memory query requires an idle configured owner");
        }
        let parsed = super::super::parse_ucode(&self.firmware)
            .map_err(|_| "invalid retained Gen2 executable")?;
        let extended = parsed.api.has_capability(80);
        let (group, command) = if extended { (2, 0) } else { (0, 0x25) };
        let version = self
            .hardware
            .version(2, 0)
            .map(|v| v.1)
            .filter(|v| *v != 99)
            .unwrap_or(0);
        if version > 4 {
            return Err("unsupported Gen2 shared-memory notification profile");
        }
        self.phase = Phase::ReadingSharedMemory;
        let result = async {
            let reply = self.hardware.command(group, command, &[]).await?;
            SharedMemory::parse(version, &reply.payload)
        }
        .await;
        match result {
            Ok(memory) => {
                self.power.shared_memory = Some(memory.clone());
                self.phase = Phase::Configured;
                Ok(memory)
            }
            Err(error) => {
                self.hardware.fail();
                self.phase = Phase::Failed;
                Err(error)
            }
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_mvm_shared_memory_geometry_bounds_lmac_fifo_and_margin() -> TestResult {
        // Native 22000 v4: header36 + three72-byte slots + control8.
        // These literal fields distinguish both LMACs and adjacent FIFOs.
        let mut bytes = [0; 260];
        bytes[32] = 2;
        bytes[44..64].copy_from_slice(&[
            0, 12, 0, 0, 0, 16, 0, 0, 0, 20, 0, 0, 0, 24, 0, 0, 0, 28, 0, 0,
        ]);
        bytes[116..132].copy_from_slice(&[0, 4, 0, 0, 0, 8, 0, 0, 0, 12, 0, 0, 0, 16, 0, 0]);
        let Ok(memory) = SharedMemory::parse(4, &bytes) else {
            return TestResult::Fail("native 22000 geometry refused");
        };
        if memory.lmac_count() != 2
            || memory.edca_payload_ceiling(0, 0) != Some(3840)
            || memory.edca_payload_ceiling(0, 2) != Some(2816)
            || memory.edca_payload_ceiling(0, 5) != Some(4864)
            || memory.edca_payload_ceiling(0, 7) != Some(5888)
            || memory.edca_payload_ceiling(1, 0) != Some(1792)
            || memory.edca_payload_ceiling(1, 8).is_some()
            || memory.tx_fifo_bytes(2, 0).is_some()
            || memory.tx_fifo_bytes(0, 15).is_some()
        {
            return TestResult::Fail("shared-memory LMAC/FIFO/TID or security margin changed");
        }
        for length in [0, 35, 108, 179, 180, 252, 259] {
            if SharedMemory::parse(4, &bytes[..length]).is_ok() {
                return TestResult::Fail("short v4 geometry accepted");
            }
        }
        for count in [0, 3, 255] {
            bytes[32] = count;
            if SharedMemory::parse(3, &bytes).is_ok() {
                return TestResult::Fail("invalid LMAC count accepted");
            }
        }
        bytes[32] = 1;
        bytes[48..52].copy_from_slice(&255u32.to_le_bytes());
        let memory = SharedMemory::parse(3, &bytes[..180]).unwrap();
        if memory.edca_payload_ceiling(0, 0).is_some()
            || memory.tx_fifo_bytes(1, 0).is_some()
            || SharedMemory::parse(5, &bytes).is_ok()
        {
            return TestResult::Fail("FIFO margin underflow, inactive LMAC or future API admitted");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/gen2/smem",
        smoke_mvm_shared_memory_geometry_bounds_lmac_fifo_and_margin
    );
}
