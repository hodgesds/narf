//! DCN3.0's seven managed HDMI packets, in Linux DC's programming order.
//! HDMI InfoFrames use four header bytes followed by the checksum and body;
//! gamut and VTEM are data packets and do not use the InfoFrame checksum.
use super::Error;

#[derive(Clone, Copy, Debug)]
pub struct InfoPackets<'a> {
    pub avi: &'a [u8; 36],
    pub hf_vsif: Option<&'a [u8; 36]>,
    pub gamut: Option<&'a [u8; 36]>,
    pub vendor: Option<&'a [u8; 36]>,
    pub spd: Option<&'a [u8; 36]>,
    pub hdr: Option<&'a [u8; 36]>,
    pub vtem: Option<&'a [u8; 36]>,
}
impl<'a> InfoPackets<'a> {
    pub const fn new(avi: &'a [u8; 36], vendor: Option<&'a [u8; 36]>) -> Self {
        Self {
            avi,
            vendor,
            hf_vsif: None,
            gamut: None,
            spd: None,
            hdr: None,
            vtem: None,
        }
    }
    pub const fn desktop(avi: &'a [u8; 36], vendor: Option<&'a [u8; 36]>) -> Self {
        Self {
            spd: Some(&DESKTOP_SPD),
            ..Self::new(avi, vendor)
        }
    }
    pub(crate) fn ordered(&self) -> [(u32, Option<&'a [u8; 36]>); 7] {
        [
            (0, Some(self.avi)),
            (5, self.hf_vsif),
            (2, self.gamut),
            (1, self.vendor),
            (3, self.spd),
            (4, self.hdr),
            (6, self.vtem),
        ]
    }
    /// Validate the complete update before touching any packet RAM/control.
    pub fn validate(&self) -> Result<(), Error> {
        for (index, packet) in self.ordered() {
            let Some(p) = packet else {
                continue;
            };
            let expected = match index {
                0 => 0x82,
                1 | 5 => 0x81,
                2 => 0x0a,
                3 => 0x83,
                4 => 0x87,
                6 => 0x7f,
                _ => return Err(Error::Invalid),
            };
            if p[0] != expected {
                return Err(Error::Invalid);
            }
            if matches!(index, 2 | 6) {
                continue;
            }
            let len = usize::from(p[2]);
            let valid = match index {
                // AVI versions emitted by the admitted TMDS producers.
                0 => len == 13 && (2..=3).contains(&p[1]),
                1 | 5 => (3..=27).contains(&len) && p[1] == 1,
                3 => {
                    (len == 25 && p[1] == 1)
                        || (p[5..8] == [0x1a, 0, 0]
                            && matches!((p[1], len), (1, 8) | (2, 9) | (3, 16)))
                }
                4 => len == 26 && p[1] == 1,
                _ => false,
            };
            if !valid || p[3] != 0 {
                return Err(Error::Invalid);
            }
            let sum = p[..3]
                .iter()
                .chain(p[4..5 + len].iter())
                .fold(0u8, |sum, byte| sum.wrapping_add(*byte));
            if sum != 0 {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}

const fn desktop_spd() -> [u8; 36] {
    let mut p = [0; 36];
    p[0] = 0x83;
    p[1] = 1;
    p[2] = 25;
    let vendor = b"NARF";
    let product = b"NARF framekernel";
    let mut i = 0;
    while i < vendor.len() {
        p[5 + i] = vendor[i];
        i += 1;
    }
    i = 0;
    while i < product.len() {
        p[13 + i] = product[i];
        i += 1;
    }
    p[29] = 9; // HDMI_SPD_SDI_PC, include/linux/hdmi.h.
    let mut sum = p[0].wrapping_add(p[1]).wrapping_add(p[2]);
    i = 5;
    while i < 30 {
        sum = sum.wrapping_add(p[i]);
        i += 1;
    }
    p[4] = 0u8.wrapping_sub(sum);
    p
}
pub const DESKTOP_SPD: [u8; 36] = desktop_spd();
