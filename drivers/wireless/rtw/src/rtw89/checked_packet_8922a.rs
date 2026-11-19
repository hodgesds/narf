// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Bounded ordinary transport inside the original checked BE ring owner.
//! Inactive preflight never resets or adopts rings. Packet admission is a
//! distinct unsafe concrete N22O/MLME contract, never N22P/N22W metadata.
use super::*;
use crate::rtw89::{
    completion_8922a as completion, tx_8922a as tx,
    tx_transport::{self, TxQueue},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum Phase {
    Inactive,
    Opening,
    Active,
    Failed,
}
/// # Safety
/// Exact original checked function/maps and distinct current full packet plus
/// autonomous-response qualification. Every operation including DMA memory
/// and callbacks stays inside that original signed+PCI invocation. start
/// additionally requires actual BE VIF/role/CAM/CCTL/rates/crypto-off receipts;
/// helper metadata and N22W cannot supply them. stop restricts only; neither
/// stop nor Drop is reset/idle proof. A preflight-only port must refuse start.
pub(in crate::rtw89) unsafe trait Port: cold::Regs {
    fn packet_current(&mut self, phase: Phase) -> Result<(), power::Error>;
    fn peer_current(&mut self, frame: &[u8], macid: u8) -> Result<(), power::Error>;
    fn start_packets(&mut self) -> Result<(), power::Error>;
    fn stop_packets(&mut self) -> Result<(), power::Error>;
}
struct Packet<M: Memory> {
    header: M,
    body: M,
    id: u64,
    length: usize,
}
struct Pending {
    id: u64,
    channel: usize,
    ticket: tx_transport::Ticket,
    report: bool,
    macid: u8,
}
pub(in crate::rtw89) struct Transport<M: Memory> {
    phase: Phase,
    own: [u8; 6],
    queues: [TxQueue<Packet<M>>; 2],
    retired: Vec<Packet<M>>,
    issued: [u16; 2],
    pending: Option<Pending>,
    rpq_wp: u16,
}
impl<M: Memory> Drop for Transport<M> {
    fn drop(&mut self) {
        // Keep even positively completed allocations with this bounded owner.
        // Published queue resources are independently pinned by TxQueue::Drop.
        for packet in self.retired.drain(..) {
            core::mem::forget(packet);
        }
    }
}
pub(in crate::rtw89) struct Receipt {
    pub(in crate::rtw89) id: u64,
    pub(in crate::rtw89) status: u8,
    pub(in crate::rtw89) bytes: Vec<u8>,
}
#[derive(Default)]
pub(in crate::rtw89) struct Batch {
    pub(in crate::rtw89) work: usize,
    pub(in crate::rtw89) events: Vec<completion::BeEvent>,
    pub(in crate::rtw89) receipts: Vec<Receipt>,
}
fn index(channel: usize) -> usize {
    [0, 8][channel]
}
fn shape(frame: &[u8], own: [u8; 6]) -> Result<usize, Error> {
    if !(24..=2044).contains(&frame.len()) || frame[10..16] != own {
        return Err(Error::Geometry);
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 3 != 0 || fc & (0x0400 | 0x1000 | 0x2000 | 0x8000) != 0 || frame[22] & 15 != 0 {
        return Err(Error::Geometry);
    }
    match fc & 0x00fc {
        0x0008 if fc & 0x0300 == 0x0100 => Ok(0), // legacy STA ToDS data
        0x0000 | 0x0010 | 0x0040 | 0x00a0 | 0x00b0 | 0x00c0 | 0x00d0 if fc & 0x4300 == 0 => Ok(1),
        _ => Err(Error::Geometry),
    }
}
/// Complete source v2 fixed1Mbps/20MHz body and info block for the bounded
/// non-QoS, no aggregation, host sequence/security profile. No v3 field alias.
pub(in crate::rtw89) fn header(
    frame: &[u8],
    macid: u8,
    sequence: u16,
    dma: u64,
) -> Result<Vec<u8>, Error> {
    if macid >= 32 || !(24..=2044).contains(&frame.len()) {
        return Err(Error::Geometry);
    }
    let management = frame[0] & 0x0c == 0;
    let channel = if management { 8 } else { 0 };
    let qsel = if management { 0x12 } else { 0 };
    let mut body = [0u8; 32];
    let mut info = [0u8; 32];
    // core.c fill_txdesc_v2 and PCI one-entry addr_info: WD page, header
    // length in halfwords for data, source no hardware security WP offset0.
    let body0 = (1u32 << 7) | (1 << 22) | (channel << 16) | if management { 0 } else { 12 << 11 };
    body[..4].copy_from_slice(&body0.to_le_bytes());
    body[4..8].copy_from_slice(&(1u32 << 26).to_le_bytes());
    body[8..12].copy_from_slice(
        &((frame.len() as u32) | (qsel << 17) | (u32::from(macid) << 24)).to_le_bytes(),
    );
    let wifi_seq = u16::from_le_bytes([frame[22], frame[23]]) >> 4;
    body[12..16].copy_from_slice(
        &(u32::from(wifi_seq) | if management { 1 << 13 } else { 0 }).to_le_bytes(),
    );
    body[28..32].copy_from_slice(&(1u32 << 31).to_le_bytes()); // USERATE, 1Mbps rate0, BW20
    info[..4].copy_from_slice(&((1u32 << 10) | (1 << 22) | (7 << 16)).to_le_bytes()); // no fallback; retry bound7
    info[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes()); // source SPE_RPT_V1
                                                              // This measured narrow profile disables RTS and HW_RTS rather than
                                                              // allowing unbound automatic protection rates. No EHT/UL controls.
    tx::build_header_with_info(&body, Some(&info), sequence, dma, frame.len())
        .map_err(|_| Error::Geometry)
}
impl<M: Memory> Owner<M> {
    pub(in crate::rtw89) fn packet_phase(&self) -> Option<Phase> {
        self.packet.as_ref().map(|p| p.phase)
    }
    pub(in crate::rtw89) fn packet_preflight(
        &mut self,
        io: &mut impl Port,
        own: [u8; 6],
    ) -> Result<(), Error> {
        if self.packet.is_some()
            || self.state != State::Enabled
            || !crate::rtw89::efuse::mac_is_valid(own)
        {
            return Err(Error::State);
        }
        let result = (|| {
            io.packet_current(Phase::Inactive)?;
            self.dma_current(io)?;
            self.geometry()?;
            // Every pre-existing original ring remains at its original NUM
            // and physical base. Actual stopped data indices must be zero;
            // this observation never resets/reclaims or reprograms anything.
            let storage = self.storage.as_ref().ok_or(Error::State)?;
            for ch in 0..TXCH_NUM {
                let r = BE_DMA_ADDR_SET.tx[ch];
                ring_readback(
                    io,
                    r.num,
                    r.desa_l,
                    r.desa_h,
                    self.ring.len,
                    storage.tx[ch].address(),
                )?;
                if ch != 12 {
                    check(io, r.idx as u32, 0x0fff0fff, 0)?;
                }
            }
            for ch in 0..2 {
                let r = BE_DMA_ADDR_SET.rx[ch];
                ring_readback(
                    io,
                    r.num,
                    r.desa_l,
                    r.desa_h,
                    self.rx_depth,
                    storage.rx[ch].address(),
                )?;
            }
            let r = BE_DMA_ADDR_SET.rx[1];
            check(io, r.idx as u32, 0x0fff0fff, u32::from(self.rx_depth - 1))?;
            let mut retired = Vec::new();
            retired.try_reserve_exact(1024).map_err(|_| Error::Memory)?;
            let queues = [
                TxQueue::new(0, self.ring.len).map_err(|_| Error::Geometry)?,
                TxQueue::new(8, self.ring.len).map_err(|_| Error::Geometry)?,
            ];
            io.packet_current(Phase::Inactive)?;
            self.packet = Some(Transport {
                phase: Phase::Inactive,
                own,
                queues,
                retired,
                issued: [0; 2],
                pending: None,
                rpq_wp: self.rx_depth - 1,
            });
            Ok(())
        })();
        self.terminal(result)
    }
    /// # Safety
    /// Port carries actual same-owner BE MLME initialization receipts and a
    /// fresh current N22O packet/response grant; preflight alone never suffices.
    pub(in crate::rtw89) unsafe fn packet_start(
        &mut self,
        io: &mut impl Port,
    ) -> Result<(), Error> {
        let packet = self.packet.as_mut().ok_or(Error::State)?;
        if self.state != State::Enabled || packet.phase != Phase::Inactive {
            return Err(Error::State);
        }
        packet.phase = Phase::Opening;
        let result = io
            .packet_current(Phase::Inactive)
            .and_then(|()| io.start_packets())
            .and_then(|()| io.packet_current(Phase::Active));
        packet.phase = if result.is_ok() {
            Phase::Active
        } else {
            Phase::Failed
        };
        self.terminal(result.map_err(Into::into))
    }
    pub(in crate::rtw89) fn packet_submit(
        &mut self,
        io: &mut impl Port,
        frame: &[u8],
        macid: u8,
        body: M,
        header_map: M,
    ) -> Result<u64, Error> {
        let result = self.packet_submit_inner(io, frame, macid, body, header_map);
        if result.as_ref().is_err_and(|e| *e != Error::Full) {
            if let Some(packet) = self.packet.as_mut() {
                packet.phase = Phase::Failed;
            }
            return self.terminal(result);
        }
        result
    }
    fn packet_submit_inner(
        &mut self,
        io: &mut impl Port,
        frame: &[u8],
        macid: u8,
        mut body: M,
        header_map: M,
    ) -> Result<u64, Error> {
        let packet = self.packet.as_mut().ok_or(Error::State)?;
        if self.state != State::Enabled || packet.phase != Phase::Active {
            return Err(Error::State);
        }
        let ch = shape(frame, packet.own)?;
        if packet.issued[ch] >= 512 {
            return Err(Error::State);
        }
        if packet.pending.is_some() {
            return Err(Error::Full);
        }
        io.packet_current(Phase::Active)?;
        io.peer_current(frame, macid)?;
        mapping(&body, frame.len())?;
        mapping(&header_map, 78)?;
        if body
            .address()
            .checked_add(frame.len() as u64 - 1)
            .is_none_or(|end| end > tx::FRAME_DMA_MASK)
        {
            return Err(Error::Geometry);
        }
        io.dma_memory(|| body.write(0, frame))?;
        io.dma_memory(|| {
            body.sync(0, frame.len());
            Ok(())
        })?;
        let id = ((ch as u64) << 32) | (u64::from(packet.issued[ch]) + 1);
        let map = Packet {
            header: header_map,
            body,
            id,
            length: frame.len(),
        };
        let queue = &mut packet.queues[ch];
        let qsel = if ch == 0 { 0 } else { 0x12 };
        let ticket = queue.reserve(map, macid, qsel).map_err(|(_, map)| {
            drop(map);
            Error::Full
        })?;
        let result = (|| {
            let map = queue.reserved_mut(ticket).map_err(|_| Error::Ring)?;
            let bytes = header(frame, macid, ticket.sequence, map.body.address())?;
            io.dma_memory(|| map.header.write(0, &bytes))?;
            io.dma_memory(|| {
                map.header.sync(0, bytes.len());
                Ok(())
            })?;
            let mut bd = crate::rtw89::dma::TxBd {
                length: bytes.len() as u16,
                opt: crate::rtw89::dma::TXBD_OPT_LS,
                ..Default::default()
            };
            bd.set_phys(map.header.address());
            let mut raw = [0u8; 8];
            raw[..2].copy_from_slice(&bd.length.to_le_bytes());
            raw[2..4].copy_from_slice(&bd.opt.to_le_bytes());
            raw[4..].copy_from_slice(&bd.dma.to_le_bytes());
            io.packet_current(Phase::Active)?;
            io.peer_current(frame, macid)?;
            // Retain/mark issued BEFORE the first descriptor-memory effect.
            queue.publish(ticket).map_err(|_| Error::Ring)?;
            packet.issued[ch] += 1;
            packet.pending = Some(Pending {
                id,
                channel: ch,
                ticket,
                report: false,
                macid,
            });
            let ring = &mut self.storage.as_mut().ok_or(Error::State)?.tx[index(ch)];
            io.dma_memory(|| ring.write(usize::from(ticket.slot) * 8, &raw))?;
            io.dma_memory(|| {
                ring.sync(usize::from(ticket.slot) * 8, 8);
                Ok(())
            })?;
            dma_barrier();
            io.packet_current(Phase::Active)?;
            io.peer_current(frame, macid)?;
            let idx = BE_DMA_ADDR_SET.tx[index(ch)].idx as u32;
            io.write16(idx, queue.write_pointer())?;
            check(io, idx, 0xfff, u32::from(queue.write_pointer()))?;
            io.packet_current(Phase::Active)?;
            Ok(id)
        })();
        if result.is_err() {
            packet.phase = Phase::Failed;
        }
        self.terminal(result)
    }
    pub(in crate::rtw89) fn packet_poll(
        &mut self,
        io: &mut impl Port,
        budget: usize,
    ) -> Result<Batch, Error> {
        if self.state != State::Enabled || !(1..=256).contains(&budget) {
            return Err(Error::State);
        }
        let mut packet = self.packet.take().ok_or(Error::State)?;
        if packet.phase != Phase::Active {
            self.packet = Some(packet);
            return Err(Error::State);
        }
        let result = (|| {
            io.packet_current(Phase::Active)?;
            let mut batch = Batch::default();
            batch
                .events
                .try_reserve(budget)
                .map_err(|_| Error::Memory)?;
            batch.receipts.try_reserve(1).map_err(|_| Error::Memory)?;
            for ch in 0..2 {
                let raw = read(io, BE_DMA_ADDR_SET.tx[index(ch)].idx as u32)?;
                if raw & 0xfff != u32::from(packet.queues[ch].write_pointer()) {
                    return Err(Error::Ring);
                }
                let done = packet.queues[ch]
                    .observe_read_pointer(((raw >> 16) & 0xfff) as u16)
                    .map_err(|_| Error::Ring)?;
                for complete in done {
                    finish(&mut packet, io, complete, &mut batch)?;
                }
            }
            // Source NAPI order: RPQ before RXQ, preserving both eq-is-full
            // host cursors in this same original DMA owner across every call.
            for rx in [1usize, 0] {
                io.packet_current(Phase::Active)?;
                let idx = BE_DMA_ADDR_SET.rx[rx].idx as u32;
                let wp = if rx == 1 { packet.rpq_wp } else { self.rx_wp };
                let count = usize::from(
                    completion::available_be(read(io, idx)?, wp, self.rx_depth)
                        .map_err(|_| Error::Ring)?,
                )
                .min(budget - batch.work);
                for _ in 0..count {
                    io.packet_current(Phase::Active)?;
                    let wp = if rx == 1 { packet.rpq_wp } else { self.rx_wp };
                    let slot = (wp + 1) % self.rx_depth;
                    let map = &mut self.storage.as_mut().ok_or(Error::State)?.receive[rx]
                        [usize::from(slot)];
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(map.length())
                        .map_err(|_| Error::Memory)?;
                    bytes.resize(map.length(), 0);
                    io.dma_memory(|| map.read(0, &mut bytes))?;
                    if rx == 1 {
                        let records = completion::rpq_records(&bytes).map_err(|_| Error::Ring)?;
                        for record in records.chunks_exact(4) {
                            let report =
                                completion::parse_rpq_record(record).map_err(|_| Error::Ring)?;
                            let pending = packet.pending.as_mut().ok_or(Error::Ring)?;
                            let qsel = if pending.channel == 0 { 0 } else { 0x12 };
                            if pending.report
                                || report.channel as usize != index(pending.channel)
                                || report.sequence != pending.ticket.sequence
                                || report.mac_id != pending.macid
                                || report.qsel != qsel
                            {
                                return Err(Error::Ring);
                            }
                            pending.report = true;
                            let complete = packet.queues[pending.channel]
                                .observe_report(report)
                                .map_err(|_| Error::Ring)?;
                            if let Some(complete) = complete {
                                finish(&mut packet, io, complete, &mut batch)?;
                            }
                        }
                    } else {
                        match self.assembler.segment(&bytes) {
                            Ok(Some(event)) => batch.events.push(event),
                            Ok(None) => (),
                            Err(_) => {
                                self.assembler.reset();
                            }
                        }
                    }
                    io.dma_memory(|| map.write(0, &[0; 4]))?;
                    io.dma_memory(|| {
                        map.sync(0, 4);
                        Ok(())
                    })?;
                    dma_barrier();
                    io.packet_current(Phase::Active)?;
                    if rx == 1 {
                        packet.rpq_wp = slot;
                    } else {
                        self.rx_wp = slot;
                    }
                    io.write16(idx, slot)?;
                    check(io, idx, 0xfff, u32::from(slot))?;
                    io.packet_current(Phase::Active)?;
                    batch.work += 1;
                }
            }
            io.packet_current(Phase::Active)?;
            Ok(batch)
        })();
        if result.is_err() {
            packet.phase = Phase::Failed;
        }
        self.packet = Some(packet);
        self.terminal(result)
    }
}

fn finish<M: Memory>(
    packet: &mut Transport<M>,
    io: &mut impl Port,
    complete: tx_transport::Completion<Packet<M>>,
    batch: &mut Batch,
) -> Result<(), Error> {
    // Move BOTH-receipt maps back under the retained owner BEFORE fallible
    // reads/callbacks. A later fault cannot drop or replace these allocations.
    let status = complete.status;
    packet.retired.push(complete.resource);
    let map = packet.retired.last().ok_or(Error::State)?;
    let pending = packet.pending.take().ok_or(Error::Ring)?;
    if pending.id != map.id {
        return Err(Error::Ring);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(map.length)
        .map_err(|_| Error::Memory)?;
    bytes.resize(map.length, 0);
    io.packet_current(Phase::Active)?;
    io.dma_memory(|| map.body.read(0, &mut bytes))?;
    io.packet_current(Phase::Active)?;
    batch.receipts.push(Receipt {
        id: map.id,
        status,
        bytes,
    });
    Ok(())
}
