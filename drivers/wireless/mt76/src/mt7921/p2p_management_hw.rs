//! Actual coherent RX-prefix/copy and independent VIF management TX.
//! Included as a child of the native Hardware backend with its owner batch.
use super::super::p2p_management_capture::{Captured, Spec};
use super::*;
impl Hardware {
    pub(super) fn configure_p2p_capture(&mut self, spec: Option<Spec>) -> Result<(), Error> {
        self.owner
            .storage
            .as_mut()
            .ok_or(Error::Busy)?
            .p2p_capture
            .close();
        let Some(spec) = spec else {
            return Ok(());
        };
        self.check()?;
        // Snapshot the finite native completed prefix BEFORE opening a new
        // source/filter/ROC generation. New arrivals do not extend this cut.
        // Routing preserves every home packet's original port/capture facts.
        let mut cuts = [0; 3];
        for (which, ring) in self
            .owner
            .storage
            .as_ref()
            .ok_or(Error::Busy)?
            .rx
            .iter()
            .enumerate()
        {
            cuts[which] = self.read(ring.base + 12)? as usize;
            if cuts[which] >= DEPTH {
                return Err(Error::Ring);
            }
        }
        for (which, cut) in cuts.into_iter().enumerate() {
            for _ in 0..DEPTH {
                if self.owner.storage.as_ref().ok_or(Error::Busy)?.rx[which].index == cut {
                    break;
                }
                let packet = self.receive_ring(which)?.ok_or(Error::Ring)?;
                let _ = self.route_packet(packet, None)?;
            }
            if self.owner.storage.as_ref().ok_or(Error::Busy)?.rx[which].index != cut {
                return Err(Error::Ring);
            }
        }
        self.check()?;
        let now = self.now_ns();
        self.owner
            .storage
            .as_mut()
            .ok_or(Error::Busy)?
            .p2p_capture
            .open_after_cut(spec, now)
    }
    pub(super) fn receive_p2p_management(&mut self) -> Result<Option<Captured>, Error> {
        self.check()?;
        if let Some(frame) = self
            .owner
            .storage
            .as_mut()
            .ok_or(Error::Busy)?
            .p2p_capture
            .pop()
        {
            return Ok(Some(frame));
        }
        for _ in 0..3 {
            let _ = self.route_rx(None)?;
        }
        Ok(self
            .owner
            .storage
            .as_mut()
            .ok_or(Error::Busy)?
            .p2p_capture
            .pop())
    }
}
