// SPDX-License-Identifier: GPL-2.0-or-later
//! One original AP scope reaches the actual whole-packet native COMMAND.
//! All readiness/response/FIFO waits remain outside that fixed scope.
use super::*;
use crate::brcmfmac::ap_scope::Capture;
struct Scope<'a>(&'a Capture);
impl narf_drivers_sdio::pio::Publication for Scope<'_> {
    fn publish(&mut self, command: &mut dyn FnMut()) -> Result<(), narf_drivers_sdio::pio::Error> {
        self.0
            .publish(command)
            .map_err(|_| narf_drivers_sdio::pio::Error::Denied)
    }
}
impl<F: SdioFunction> SdioTransport<F> {
    pub(super) fn transmit_ap_packet(
        &mut self,
        packet: &[u8],
        original: &Capture,
    ) -> Result<(), TransportError> {
        self.transmit_ap_scoped(packet, original, false)
    }
    pub(super) fn transmit_ap_control(
        &mut self,
        packet: &[u8],
        original: &Capture,
    ) -> Result<(), TransportError> {
        self.transmit_ap_scoped(packet, original, true)
    }
    fn transmit_ap_scoped(
        &mut self,
        packet: &[u8],
        original: &Capture,
        control: bool,
    ) -> Result<(), TransportError> {
        use super::super::sdpcm::{bcdc_flag, BcdcHeader, HwHeader, SwHeader};
        self.check_qualification()?;
        original.current().map_err(|_| TransportError::Denied)?;
        if !(28..=1532).contains(&packet.len()) || packet.len() % 4 != 0 {
            return Err(TransportError::LengthOverflow);
        }
        let header = HwHeader::decode(packet).map_err(|_| TransportError::BadFraming)?;
        let software = SwHeader::decode(&packet[4..12]).map_err(|_| TransportError::BadFraming)?;
        let logical = usize::from(header.length);
        if logical < 28
            || logical > packet.len()
            || packet.len() - logical > 3
            || packet[logical..].iter().any(|byte| *byte != 0)
            || software.flags != 0
            || software.next_len_16 != 0
            || software.data_offset != 12
            || software.fc_mask != 0
            || software.max_seq != 0
            || packet[10..12] != [0, 0]
        {
            return Err(TransportError::BadFraming);
        }
        if control {
            let bcdc =
                BcdcHeader::decode(&packet[12..logical]).map_err(|_| TransportError::BadFraming)?;
            if !original.lifecycle()
                || software.channel != 0
                || bcdc.status != 0
                || bcdc.flags & !(bcdc_flag::ID_MASK | bcdc_flag::SET) != 0
                || bcdc.len > super::super::runtime::MAX_CONTROL as u32
                || logical - 28 != (bcdc.len as usize).min(1502)
            {
                return Err(TransportError::BadFraming);
            }
        } else if logical < 30
            || software.channel != 2
            || packet[12] != 0x20
            || packet[13] > 7
            || packet[14..16] != [0, 0]
            || !original.transmit(&packet[16..logical])
        {
            return Err(TransportError::BadFraming);
        }
        // Status-only CARD_INT works on polling hosts too. Acknowledge only
        // the old host latch before a fresh actual dongle mailbox read.
        // These operations and all waits are outside the final Source gates.
        self.func.observe_publication(4).map_err(map_err)?;
        self.wake()?;
        self.func.clear_publication_pending().map_err(map_err)?;
        self.mailbox()?;
        if self.flow_stopped || self.rx_pending {
            // Session must apply this newly observed native prefix before
            // retrying the retained original; no target is recaptured here.
            return Err(TransportError::Busy);
        }
        self.window(0x1800_0000)?;
        // The common SDPCM logical length excludes its physical zero tail
        // (Linux sdio.c::brcmf_sdio_hdpack: hd_info.len = len - tail_pad).
        // Linux brcmf_sdio_tx_ctrlframe block-rounds only frames longer than
        // one block. Padding every AP COMMAND (control and DATA) to whole
        // actual 512-byte F2 blocks is a deliberate inference so one CMD53
        // carries one packet inside the original scope; it is neither
        // Linux-identical ordinary DATA batching (brcmf_sdio_txpkt_prep) nor
        // a physical-board measurement.
        let extent = logical.next_multiple_of(512);
        if extent > 1536 {
            return Err(TransportError::LengthOverflow);
        }
        let mut physical = zeroize::Zeroizing::new(alloc::vec![0; extent]);
        physical[..logical].copy_from_slice(&packet[..logical]);
        let result = self.func.cmd53_block_write_published(
            2,
            0x8000,
            512,
            (extent / 512) as u16,
            &physical,
            &mut Scope(original),
        );
        match result {
            // Both outcomes prove that this sole COMMAND never entered.
            Err(SdioError::Denied) => return Err(TransportError::Denied),
            Err(SdioError::Busy) => return Err(TransportError::Busy),
            Err(error) => {
                self.failed = true;
                return Err(map_err(error));
            }
            Ok(()) => {}
        }
        if original.current().is_err() {
            // The packet was issued/copied. A later source loss cannot
            // turn that real transfer into unissued retry credit.
            self.failed = true;
            return Err(TransportError::NotReady);
        }
        if let Some(sleep) = self.sleep.as_mut() {
            sleep.active_ms = now_ms();
        }
        Ok(())
    }
}
