//! Source-versioned API89 and Sc regulatory and station wire facts.
//! Linux fw/api/{nvm-reg,power,mac-cfg}.h, iwl-nvm-parse.c and mvm/link.c.
use super::boot_context::{put16, put32};
use alloc::{sync::Arc, vec::Vec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Widths {
    pub forty: bool,
    pub eighty: bool,
    pub one_sixty: bool,
}
impl Widths {
    pub fn permits(self, width: u8) -> bool {
        match width {
            0 => true,
            1 => self.forty,
            2 => self.eighty,
            3 => self.one_sixty,
            _ => false,
        }
    }
}
pub(super) struct Mcc {
    pub country: [u8; 2],
    pub channels: Arc<[u32]>,
    pub etsi_5ghz: bool,
    pub he: bool,
    pub eht: bool,
    pub widths: Widths,
}
impl Mcc {
    /// Wire shape and regulatory flag generation are independent. Linux
    /// normalizes notificationv5/v6 to its20-byte v4 struct, but interprets
    /// v6 capability bits with REG_CAPA_V2 (notv1 and notv4/v5).
    pub fn parse(version: u8, bytes: &[u8]) -> Result<Self, &'static str> {
        let (header, count_at, geo_at, capability) = match version {
            5 | 6 if bytes.len() >= 20 => (
                20,
                16,
                10,
                u32::from(u16::from_le_bytes(bytes[6..8].try_into().unwrap())),
            ),
            8 if bytes.len() >= 24 => (
                24,
                20,
                14,
                u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            ),
            _ => return Err("Intel MCC native response profile/extent unsupported"),
        };
        let country = u16::from_le_bytes(bytes[4..6].try_into().unwrap()).to_be_bytes();
        let count = u32::from_le_bytes(bytes[count_at..count_at + 4].try_into().unwrap()) as usize;
        if u32::from_le_bytes(bytes[..4].try_into().unwrap()) > 1
            || country != *b"00" && !country.iter().all(u8::is_ascii_uppercase)
            || count == 0
            || count > 115
            || bytes.len() != header + count * 4
        {
            return Err("Intel MCC native country/status/channel extent invalid");
        }
        let widths = match version {
            5 => Widths {
                forty: capability & (1 << 7) == 0,
                eighty: capability & (1 << 3) != 0,
                one_sixty: capability & (1 << 2) != 0,
            },
            6 => Widths {
                forty: capability & (1 << 8) != 0,
                eighty: capability & (1 << 4) != 0,
                one_sixty: capability & (1 << 3) != 0,
            },
            8 => Widths {
                forty: true,
                eighty: capability & (1 << 4) != 0,
                one_sixty: capability & (1 << 3) != 0,
            },
            _ => unreachable!(),
        };
        Ok(Self {
            country,
            channels: bytes[header..]
                .chunks_exact(4)
                .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                .collect::<Vec<_>>()
                .into(),
            etsi_5ghz: u16::from_le_bytes(bytes[geo_at..geo_at + 2].try_into().unwrap()) & 1 != 0,
            he: capability & (1 << if version == 8 { 13 } else { 10 }) == 0,
            eht: version == 8 && capability & (1 << 8) == 0,
            widths,
        })
    }
}

pub(super) fn power(version: u8, dbm: i8, device_wide: bool) -> Result<Vec<u8>, &'static str> {
    let length = match version {
        5 => 44,
        8 => 120,
        _ => return Err("Intel API89 TX-power profile unsupported"),
    };
    let mut bytes = alloc::vec![0;length];
    // Earlier thanv9 this common identity names MAC0, not MLD link0.
    put32(&mut bytes, 0, u32::from(device_wide));
    put16(&mut bytes, 8, (i16::from(dbm) * 8) as u16);
    Ok(bytes)
}
/// LINK_CONFIGv2 keeps flags_mask. Linux mvm/link.c accompanies the
/// requested BSS-color/MU-EDCA flag bits with their corresponding masks.
pub(super) fn he_link_mask(bytes: &mut [u8; 208]) {
    let modified = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    if modified & (1 << 5) != 0 {
        let flags = u32::from_le_bytes(bytes[148..152].try_into().unwrap());
        put32(bytes, 152, flags & ((1 << 0) | (1 << 1)));
    }
}

/// Project the independently validated single-station TLC geometry onto
/// API89 v4's station-ID/u16-MCS form, not Sc v6's mask/u32-MCS form.
pub(super) fn tlc_v4(canonical: &[u8; 44]) -> Result<[u8; 28], &'static str> {
    if canonical[..4] != [1, 0, 0, 0] || canonical[4..8] != [0; 4] {
        return Err("API89 TLC requires actual station0/PHY0");
    }
    let mut bytes = [0; 28];
    bytes[4..12].copy_from_slice(&canonical[8..16]);
    for index in 0..6 {
        let word = u32::from_le_bytes(
            canonical[16 + index * 4..20 + index * 4]
                .try_into()
                .unwrap(),
        );
        let bits = u16::try_from(word).map_err(|_| "API89 TLC MCS exceeds v4 geometry")?;
        put16(&mut bytes, 12 + index * 2, bits);
    }
    bytes[24..28].copy_from_slice(&canonical[40..44]);
    Ok(bytes)
}
