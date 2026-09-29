//! AX210+ unaggregated TX queue. The allocation command exposes DMA
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
            read: 0,
            write: 0,
        })
    }

    pub fn configure(&self, station: u8, tid: u8) -> Result<[u8; 36], &'static str> {
        if station >= 32 || tid > 16 {
            return Err("invalid TX station/TID");
        }
        let mut bytes = [0; 36];
        put32(&mut bytes, 4, 1 << station);
        bytes[8] = tid;
        put32(&mut bytes, 16, DEPTH.ilog2() - 3);
        put64(&mut bytes, 20, self.byte_counts.dma_addr().raw());
        put64(&mut bytes, 28, self.descriptors.dma_addr().raw());
        Ok(bytes)
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

    pub fn id(&self) -> Option<u16> {
        self.id
    }

    pub fn send(
        &mut self,
        mmio: &mut impl IwlMmio,
        frame: &[u8],
        header_len: usize,
        rate: u32,
    ) -> Result<u16, &'static str> {
        let id = self.id.ok_or("TX queue not activated")?;
        if frame.len() < header_len
            || frame.len() > 4095
            || !(24..=36).contains(&header_len)
            || header_len % 2 != 0
        {
            return Err("invalid TX frame geometry");
        }
        if self.write.wrapping_sub(self.read) as usize >= DEPTH - 1 {
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
        put16(&mut bytes, 6, if frame[1] & 0x40 != 0 { 1 } else { 3 });
        put32(
            &mut bytes,
            8,
            ((header_len / 2) as u32) << 8 | if padding != 0 { 1 << 13 } else { 0 },
        );
        put32(&mut bytes, 20, rate);
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
    /// This path deliberately never requests aggregation; one status
    /// describes one frame, and its SSN must advance exactly one slot.
    pub fn complete(&mut self, response: &[u8]) -> Result<(u16, bool), &'static str> {
        if response.len() != 48 || response[0] != 1 {
            return Err("invalid unaggregated TX response");
        }
        let id = u16::from_le_bytes(response[36..38].try_into().unwrap());
        let ssn = u32::from_le_bytes(response[44..48].try_into().unwrap()) as u16;
        if self.id != Some(id) || self.read == self.write || ssn != self.read.wrapping_add(1) {
            return Err("TX completion outside outstanding interval");
        }
        let slot = self.read as usize & (DEPTH - 1);
        if self.pending[slot].is_none() {
            return Err("TX completion for unowned slot");
        }
        self.pending[slot] = None;
        self.read = ssn;
        Ok((ssn, response[40] == 1))
    }
}
