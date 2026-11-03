// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained original AP Program authority at actual input/ring publication.
//! Ring setup precedes the final fixed scope. Stop and ordinary station
//! IOCTLs retain their existing paths and receive no AP authority here.
use super::*;
use crate::brcmfmac::ap_scope::Capture;
impl<B: Bus> Runtime<B> {
    pub(crate) async fn command_ap(
        &mut self,
        command: u32,
        input: &[u8],
        maximum: usize,
        original: &Capture,
    ) -> Result<Vec<u8>, Error> {
        let ticket = self.begin_ioctl_ap(command, input, maximum, original)?;
        let mut transaction = Transaction {
            runtime: self,
            retired: false,
        };
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            transaction.runtime.poll()?;
            if let Some(result) = transaction.runtime.take_response(&ticket)? {
                transaction.retired = true;
                return result;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
        }
    }
    fn begin_ioctl_ap(
        &mut self,
        command: u32,
        input: &[u8],
        maximum: usize,
        original: &Capture,
    ) -> Result<Ticket, Error> {
        if self.failed {
            return Err(Error::Failed);
        }
        if self.down || self.pending.is_some() {
            return Err(Error::Busy);
        }
        if input.len() > INPUT || maximum > CONTROL {
            return Err(Error::Bounds);
        }
        if !original.lifecycle() || !original.native.belongs_to(&self.ap_live) {
            return Err(Error::Access);
        }
        original.current()?;
        let id = self
            .next_transaction
            .checked_add(1)
            .ok_or(Error::Exhausted)?;
        let logical = maximum.max(input.len());
        let wire_length = logical.min(INPUT);
        let resources = self.resources.as_mut().ok_or(Error::Failed)?;
        let ring = &mut resources.rings[0];
        if !ring.h2d || ring.size != 40 {
            return Err(Error::Protocol);
        }
        // The real native consumer-index read may service a backend. No
        // original Program source/key/role/policy proof is consumed before
        // that setup and then treated as a current publication authority.
        let peer = match read16(&mut self.bus, ring.rptr) {
            Ok(peer) => peer,
            Err(error) => {
                self.fail();
                return Err(error);
            }
        };
        if peer >= ring.depth {
            self.fail();
            return Err(Error::Protocol);
        }
        let next = if ring.write + 1 == ring.depth {
            0
        } else {
            ring.write + 1
        };
        if next == peer {
            return Err(Error::Busy);
        }
        let request = IoctlReq {
            hdr: CommonHdr {
                msgtype: 9,
                ifidx: 0,
                flags: 0,
                request_id: 0xfffe,
            },
            cmd: command,
            trans_id: id,
            input_buf_len: wire_length as u16,
            output_buf_len: logical as u16,
            req_buf_addr: BufAddr(resources.input.address()),
        };
        let mut entry = [0; 40];
        request.encode(&mut entry).ok_or(Error::Protocol)?;
        let mut entered = false;
        let pending = &mut self.pending;
        let response = &mut self.response;
        let transaction = &mut self.next_transaction;
        let memory = &mut resources.input;
        let bus = &mut self.bus;
        let result = original
            .publish(|| {
                entered = true;
                zero(memory)?;
                memory.write(0, input)?;
                memory.to_device(0, wire_length);
                // Original identity is retained before any write-pointer attempt.
                *transaction = id;
                *pending = Some(Pending {
                    id,
                    command,
                    maximum: logical,
                });
                *response = None;
                let offset = usize::from(ring.write) * ring.size;
                ring.memory.write(offset, &entry)?;
                ring.memory.to_device(offset, entry.len());
                bus.write_tcm(ring.wptr, &next.to_le_bytes())?;
                ring.write = next;
                bus.doorbell()?;
                Ok(Ticket { id, command })
            })
            .and_then(|result| result);
        if result.is_err() && entered {
            // Input/descriptor/index issue may be partial. Retain original
            // resources and poison; no failed waiter supplies DMA credit.
            self.fail();
        }
        result
    }
}
