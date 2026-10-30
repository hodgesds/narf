//! Typed AP receive delivery to the exact requesting socket. The retained
//! grant supplements actual native copy/RF/peer proof; it supplies none.
use super::*;
use alloc::{vec, vec::Vec};

#[derive(Clone, Debug)]
pub struct ApEventAuthority {
    guard: ApControlAuthority,
}
impl ApControlAuthority {
    /// Retain actual notification authority after a completed registration
    /// without holding its native-control serialization lease indefinitely.
    /// This creates no grant and cannot retarget a closed/rebound socket.
    pub fn event_authority(&self) -> Result<ApEventAuthority, WirelessError> {
        // REGISTER_FRAME is allowed before administrative UP. Capturing
        // the actual grant/identity opens no RX; publication requires UP.
        self.current()?;
        let mut guard = self.clone();
        guard.reservation = None;
        guard.reserved = false;
        let event = ApEventAuthority { guard };
        event.guard.current()?;
        Ok(event)
    }
}
impl ApEventAuthority {
    /// Registration liveness before administrative UP. This does not permit
    /// frame delivery; every typed receive method still requires UP.
    pub fn registration_current(&self) -> Result<(), WirelessError> {
        self.guard.current()
    }
    pub fn current(&self) -> Result<(), WirelessError> {
        self.guard.require_up()
    }
    pub fn check_for<I: WirelessNetIface + ?Sized>(&self, iface: &I) -> Result<(), WirelessError> {
        self.guard.check_for(iface)?;
        self.current()
    }
    /// The concrete driver must just have rechecked the native copy epoch,
    /// channel/RF owner and installed filter. This method grants no frame.
    pub fn management_received(
        &self,
        frequency_mhz: u32,
        signal_dbm: Option<i8>,
        frame: &[u8],
    ) -> Result<(), WirelessError> {
        if !(24..=4096).contains(&frame.len()) || frame[0] & 15 != 0 || frequency_mhz == 0 {
            return Err(WirelessError::InvalidArgs);
        }
        let mut attrs = self.base()?;
        attr(&mut attrs, 38, &frequency_mhz.to_ne_bytes());
        if let Some(signal) = signal_dbm {
            attr(&mut attrs, 151, &i32::from(signal).to_ne_bytes());
        }
        attr(&mut attrs, 51, frame);
        self.deliver(59, attrs)
    }
    /// The native owner independently proves the peer/cipher/replay facts.
    /// Ordinary Ethernet/IP rings never authorize this EAPOL delivery.
    pub fn control_received(
        &self,
        peer: [u8; 6],
        ethertype: u16,
        pdu: &[u8],
        unencrypted: bool,
    ) -> Result<(), WirelessError> {
        if peer == [0; 6]
            || peer[0] & 1 != 0
            || !matches!(ethertype, 0x888e | 0x88c7)
            || pdu.is_empty()
            || pdu.len() > 2304
        {
            return Err(WirelessError::InvalidArgs);
        }
        let mut attrs = self.base()?;
        attr(&mut attrs, 6, &peer);
        attr(&mut attrs, 102, &ethertype.to_ne_bytes());
        if unencrypted {
            attr(&mut attrs, 103, &[]);
        }
        attr(&mut attrs, 51, pdu);
        self.deliver(129, attrs)
    }
    fn base(&self) -> Result<Vec<u8>, WirelessError> {
        self.current()?;
        let iface = self.guard.iface.upgrade().ok_or(WirelessError::Denied)?;
        let wiphy = crate::registry::wiphy_index(iface.wiphy_id()).ok_or(WirelessError::Denied)?;
        let mut attrs = Vec::new();
        attr(&mut attrs, 1, &wiphy.to_ne_bytes());
        attr(&mut attrs, 3, &self.guard.ifindex.to_ne_bytes());
        let wdev = (u64::from(wiphy) << 32) | u64::from(self.guard.ifindex);
        attr(&mut attrs, 153, &wdev.to_ne_bytes());
        Ok(attrs)
    }
    fn deliver(&self, command: u8, attrs: Vec<u8>) -> Result<(), WirelessError> {
        self.current()?;
        // nl80211's in-tree family has the stable generic-netlink version1.
        // Notification sequence/sender are zero, as cfg80211 RX events are.
        let mut message = vec![0; 16];
        message[4..6].copy_from_slice(&crate::nl80211::NL80211_FAMILY_ID.to_ne_bytes());
        message.extend_from_slice(&[command, 1, 0, 0]);
        message.extend_from_slice(&attrs);
        let len = message.len() as u32;
        message[..4].copy_from_slice(&len.to_ne_bytes());
        self.current()?;
        self.guard
            .reply
            .deliver(message)
            .map_err(|_| WirelessError::Denied)
    }
}
fn attr(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    out.extend_from_slice(&((payload.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize((out.len() + 3) & !3, 0);
}
