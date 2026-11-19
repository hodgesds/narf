//! Exact GO group transmit PN. Real host CCMP uses native encryption bypass;
//! no firmware PN estimate or receive replay floor is reported as GTK RSC.
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};
const MAX: u64 = (1u64 << 48) - 1;
pub(super) struct Gtk {
    pub id: u8,
    key: Zeroizing<[u8; 16]>,
    own: [u8; 6],
    pn: u64,
}
impl Gtk {
    pub fn new(id: u8, key: [u8; 16], own: [u8; 6], floor: u64) -> Result<Self, &'static str> {
        if id > 3 || floor > MAX || own == [0; 6] || own[0] & 1 != 0 {
            return Err("GO host GTK identity/PN floor invalid");
        }
        Ok(Self {
            id,
            key: Zeroizing::new(key),
            own,
            pn: floor,
        })
    }
    pub fn sequence(&self) -> [u8; 6] {
        self.pn.to_le_bytes()[..6].try_into().unwrap()
    }
    pub fn raise_floor(&mut self, floor: u64) {
        self.pn = self.pn.max(floor);
    }
    pub fn protect(&mut self, frame: &mut Vec<u8>, header: usize) -> Result<(), &'static str> {
        if !matches!(header, 24 | 26)
            || frame.len() < header + 8
            || !matches!(frame[0], 8 | 0x88)
            || frame[1] & 0xc7 != 0x42
            || frame[4] & 1 == 0
            || frame[10..16] != self.own
            || frame[22] & 15 != 0
            || (header == 26) != (frame[0] == 0x88)
            || header == 26 && (frame[24] & 0xf8 != 0 || frame[25] != 0)
            || self.pn >= MAX
        {
            return Err("GO host CCMP physical group/PN owner invalid");
        }
        // Reserve before encryption/publication. Failure or cancellation
        // consumes this PN; a retry of a posted MPDU keeps its wire bytes.
        self.pn += 1;
        let priority = if header == 26 { frame[24] & 7 } else { 0 };
        let nonce = narf_wireless::ccmp::build_nonce(priority, false, &self.own, self.pn);
        let aad = narf_wireless::ccmp::build_aad(&frame[..header]);
        let mut body = frame[header..].to_vec();
        let mic = narf_crypto::aes_ccm::seal(&self.key, &nonce, &aad, &mut body)
            .map_err(|_| "GO host CCMP encryption failed")?;
        frame.truncate(header);
        frame.extend_from_slice(&narf_wireless::ccmp::build_ccmp_header(self.pn, self.id));
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&mic);
        Ok(())
    }
}
impl Drop for Gtk {
    fn drop(&mut self) {
        self.pn.zeroize();
    }
}
