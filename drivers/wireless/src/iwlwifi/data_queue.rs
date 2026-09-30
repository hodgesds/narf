//! AX210+ TX queue with single-frame and cumulative Block Ack completion.
//! The allocation command exposes DMA
//! addresses, so the queue must be retained even if that command times out.

use alloc::{vec, vec::Vec};
use narf_io::DmaBuffer;

use super::{
    boot_context::{put16, put32, put64},
    runtime::{dma_alloc, dma_barrier, write_dma},
    transport::IwlMmio,
    tx_gen2,
};

pub const DEPTH: usize = 128;

#[derive(Debug)]
pub struct DataQueue {
    descriptors: DmaBuffer,
    byte_counts: DmaBuffer,
    pending: Vec<Option<DmaBuffer>>,
    id: Option<u16>,
    station_tid: Option<(u8, u8)>,
    aggregated: bool,
    read: u16,
    write: u16,
}

impl DataQueue {
    pub fn new() -> Result<Self, &'static str> {
        Ok(Self {
            descriptors: dma_alloc(DEPTH * 256)?,
            byte_counts: dma_alloc(2048)?,
            pending: (0..DEPTH).map(|_| None).collect(),
            id: None,
            station_tid: None,
            aggregated: false,
            read: 0,
            write: 0,
        })
    }

    pub fn configure(&mut self, station: u8, tid: u8) -> Result<[u8; 36], &'static str> {
        if station >= 32 || tid > 16 {
            return Err("invalid TX station/TID");
        }
        let mut bytes = [0; 36];
        put32(&mut bytes, 4, 1 << station);
        bytes[8] = tid;
        put32(&mut bytes, 16, DEPTH.ilog2() - 3);
        put64(&mut bytes, 20, self.byte_counts.dma_addr().raw());
        put64(&mut bytes, 28, self.descriptors.dma_addr().raw());
        self.station_tid = Some((station, tid));
        Ok(bytes)
    }

    pub fn enable_aggregation(&mut self) {
        self.aggregated = self.station_tid.is_some_and(|(_, tid)| tid < 8);
    }

    pub fn validate_ba(&self, station: u8, tid: u8, ssn: u16) -> Result<(), &'static str> {
        if !self.aggregated || self.station_tid != Some((station, tid)) {
            return Err("BA completion for unnegotiated station/TID");
        }
        self.validate_reclaim(ssn)
    }

    fn validate_reclaim(&self, ssn: u16) -> Result<(), &'static str> {
        let count = ssn.wrapping_sub(self.read) as usize;
        if count > self.write.wrapping_sub(self.read) as usize || count >= DEPTH {
            return Err("TX reclaim outside outstanding interval");
        }
        for offset in 0..count {
            if self.pending[(self.read as usize + offset) & (DEPTH - 1)].is_none() {
                return Err("TX reclaim for unowned descriptor");
            }
        }
        Ok(())
    }

    /// Validate the whole interval before releasing any device-owned buffer.
    pub fn reclaim(&mut self, ssn: u16) -> Result<(), &'static str> {
        self.validate_reclaim(ssn)?;
        while self.read != ssn {
            self.pending[self.read as usize & (DEPTH - 1)] = None;
            self.read = self.read.wrapping_add(1);
        }
        Ok(())
    }

    pub fn has_completed(&self, ssn: u16) -> bool {
        self.read.wrapping_sub(ssn) < 0x8000
    }

    pub fn next_completion(&self) -> u16 {
        self.read.wrapping_add(1)
    }

    pub fn activate(&mut self, response: &[u8]) -> Result<u16, &'static str> {
        if self.id.is_some() || response.len() != 8 {
            return Err("invalid TX allocation response");
        }
        let id = u16::from_le_bytes(response[..2].try_into().unwrap());
        if id == 0 || id >= 512 || response[2..4] != [0; 2] {
            return Err("TX queue allocation rejected");
        }
        let pointer = u16::from_le_bytes(response[4..6].try_into().unwrap());
        self.id = Some(id);
        self.read = pointer;
        self.write = pointer;
        Ok(id)
    }

    pub fn is_idle(&self) -> bool {
        self.read == self.write
    }

    pub fn has_space(&self) -> bool {
        (self.write.wrapping_sub(self.read) as usize) < DEPTH - 1
    }

    pub fn id(&self) -> Option<u16> {
        self.id
    }

    pub fn send(
        &mut self,
        mmio: &mut impl IwlMmio,
        frame: &[u8],
        header_len: usize,
        rate: Option<u32>,
    ) -> Result<u16, &'static str> {
        let id = self.id.ok_or("TX queue not activated")?;
        if frame.len() < header_len
            || frame.len() > 4095
            || !(24..=36).contains(&header_len)
            || header_len % 2 != 0
        {
            return Err("invalid TX frame geometry");
        }
        if !self.has_space() {
            return Err("TX queue full");
        }
        let slot = self.write as usize & (DEPTH - 1);
        if self.pending[slot].is_some() {
            return Err("TX slot still owned by device");
        }
        let padding = header_len.next_multiple_of(4) - header_len;
        // Short command header, 28-byte TX command, MAC header (padded
        // to a dword), followed by the payload. len excludes the padding.
        let mut bytes = vec![0; 32 + frame.len() + padding];
        bytes[0] = 0x1c;
        put16(&mut bytes, 2, ((id & 0x1f) << 8) | slot as u16);
        put16(&mut bytes, 4, frame.len() as u16);
        // Protected frames use the station's firmware CCMP key. The
        // firmware inserts IV/MIC and advances its TX packet number.
        let flags = u16::from(rate.is_some()) | if frame[1] & 0x40 != 0 { 0 } else { 2 };
        put16(&mut bytes, 6, flags);
        put32(
            &mut bytes,
            8,
            ((header_len / 2) as u32) << 8 | if padding != 0 { 1 << 13 } else { 0 },
        );
        put32(&mut bytes, 20, rate.unwrap_or(0));
        bytes[32..32 + header_len].copy_from_slice(&frame[..header_len]);
        bytes[32 + header_len + padding..].copy_from_slice(&frame[header_len..]);
        let dma = dma_alloc(bytes.len())?;
        write_dma(&dma, 0, &bytes);
        let mut descriptor = tx_gen2::TfhTfd::default();
        descriptor
            .push_tb(dma.dma_addr().raw(), 20)
            .map_err(|_| "invalid data TB0")?;
        let payload_offset = 32 + header_len + padding;
        descriptor
            .push_tb(dma.dma_addr().raw() + 20, (payload_offset - 20) as u16)
            .map_err(|_| "invalid data TB1")?;
        if frame.len() != header_len {
            descriptor
                .push_tb(
                    dma.dma_addr().raw() + payload_offset as u64,
                    (frame.len() - header_len) as u16,
                )
                .map_err(|_| "invalid data TB2")?;
        }
        let count = tx_gen2::bc_entry_ax210(frame.len() as u16, descriptor.filled_bytes())
            .map_err(|_| "invalid TX byte count")?;
        // SAFETY: fully initialized packed wire structure has no holes.
        let wire = unsafe {
            core::slice::from_raw_parts((&descriptor as *const tx_gen2::TfhTfd).cast::<u8>(), 256)
        };
        write_dma(&self.descriptors, slot * 256, wire);
        write_dma(&self.byte_counts, slot * 2, &count.tfd_offset.to_le_bytes());
        self.pending[slot] = Some(dma);
        self.write = self.write.wrapping_add(1);
        dma_barrier();
        mmio.write(
            tx_gen2::HBUS_TARG_WRPTR,
            tx_gen2::tx_doorbell(id as u32, self.write as u32),
        );
        Ok(self.write)
    }

    /// Validate the entire reclaim interval before dropping any DMA.
    /// A legacy queue advances one slot. An aggregated queue's single-frame
    /// retry can retire an interval containing earlier acknowledged frames.
    pub fn complete(&mut self, response: &[u8]) -> Result<(u16, bool), &'static str> {
        if response.len() != 48 || response[0] != 1 {
            return Err("invalid unaggregated TX response");
        }
        let id = u16::from_le_bytes(response[36..38].try_into().unwrap());
        let ssn = u32::from_le_bytes(response[44..48].try_into().unwrap()) as u16;
        if self.id != Some(id)
            || self.read == self.write
            || ssn == self.read
            || (!self.aggregated && ssn != self.read.wrapping_add(1))
        {
            return Err("TX completion outside outstanding interval");
        }
        self.reclaim(ssn)?;
        Ok((ssn, response[40] == 1))
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    struct Mmio;
    impl IwlMmio for Mmio {
        fn read(&mut self, _: u32) -> u32 {
            0
        }
        fn write(&mut self, _: u32, _: u32) {}
    }
    fn smoke_tx_adaptive_rate_and_qos_padding() -> TestResult {
        let mut q = DataQueue::new().unwrap();
        q.activate(&[17, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let mut frame = [0; 40];
        frame[0] = 0x88;
        frame[1] = 0x41;
        frame[24] = 6;
        frame[26..].fill(0x55);
        q.send(&mut Mmio, &frame, 26, None).unwrap();
        let dma = q.pending[0].as_ref().unwrap().as_slice();
        if dma[6..8] != [0, 0]
            || dma[20..24] != [0; 4]
            || dma[8..12] != (13u32 << 8 | 1 << 13).to_le_bytes()
            || dma[56..60] != [6, 0, 0, 0]
            || dma[60..74] != [0x55; 14]
        {
            return TestResult::Fail("adaptive encrypted QoS command flags/TB padding");
        }
        frame[1] = 1;
        q.send(&mut Mmio, &frame, 26, Some(0x4100)).unwrap();
        let dma = q.pending[1].as_ref().unwrap().as_slice();
        if dma[6..8] != [3, 0] || dma[20..24] != 0x4100u32.to_le_bytes() {
            return TestResult::Fail("fixed-rate plaintext management flags");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/runtime",
        smoke_tx_adaptive_rate_and_qos_padding
    );

    fn smoke_tx_credit_requires_valid_completion_across_wrap() -> TestResult {
        let mut q = DataQueue::new().unwrap();
        q.activate(&[17, 0, 0, 0, 0xfe, 0xff, 0, 0]).unwrap();
        for _ in 0..DEPTH - 1 {
            q.send(&mut Mmio, &[0; 24], 24, None).unwrap();
        }
        let write = q.write;
        if q.has_space()
            || q.send(&mut Mmio, &[0; 24], 24, None).is_ok()
            || q.write != write
            || q.pending.iter().flatten().count() != DEPTH - 1
        {
            return TestResult::Fail("full TX ring lost ownership or accepted more DMA");
        }
        let mut response = [0; 48];
        response[0] = 1;
        put16(&mut response, 36, 17);
        response[40] = 1;
        // A forged completion skipping the oldest slot cannot create credit.
        if q.complete(&response).is_ok() || q.has_space() {
            return TestResult::Fail("invalid completion created TX credit");
        }
        put32(&mut response, 44, 0xffff);
        if q.complete(&response) != Ok((0xffff, true)) || !q.has_space() {
            return TestResult::Fail("valid completion did not wake TX credit");
        }
        q.send(&mut Mmio, &[0; 24], 24, None).unwrap();
        put32(&mut response, 44, 0);
        if q.complete(&response) != Ok((0, true)) || !q.has_space() {
            return TestResult::Fail("wrapped completion lost TX credit");
        }
        q.send(&mut Mmio, &[0; 24], 24, None).unwrap();
        if q.has_space() || q.pending.iter().flatten().count() != DEPTH - 1 {
            return TestResult::Fail("TX credit was consumed more than once");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/runtime",
        smoke_tx_credit_requires_valid_completion_across_wrap
    );
}
