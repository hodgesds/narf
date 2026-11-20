// SPDX-License-Identifier: GPL-2.0-or-later
//! Strict native flagged-radiotap profile. Format observations grant no
//! device/configuration/receive authority; the actual retained native owner
//! must qualify the capability reply and current packet/channel independently.
//! Linux7.3-rc4 feature.{c,h}, core.c::brcmf_netif_mon_rx and msgbuf.c.
use crate::cyw43439::runtime::Error;
use alloc::vec::Vec;

/// The payload format AND native frame-type marker are both source-defined
/// by `rtap` (MONITOR_FLAG + MONITOR_FMT_RADIOTAP). MONITOR or an old FWID
/// alone does not establish this native dispatch/format contract.
pub(super) fn flagged_radiotap(capabilities: &[u8]) -> Result<bool, Error> {
    let terminator = capabilities.iter().position(|byte| *byte == 0);
    if terminator.is_none() && capabilities.len() >= 768 {
        return Err(Error::Malformed);
    }
    // Match the native bounded C string, as Linux does. Bytes after its
    // terminator are not capabilities; a short declared reply may itself
    // delimit the complete string. A full truncated buffer cannot.
    let end = terminator.unwrap_or(capabilities.len());
    let text = core::str::from_utf8(&capabilities[..end]).map_err(|_| Error::Malformed)?;
    if !text.is_ascii()
        || text
            .bytes()
            .any(|byte| byte.is_ascii_control() && !byte.is_ascii_whitespace())
    {
        return Err(Error::Malformed);
    }
    // cfg80211 advertises mode6 on MONITOR_FLAG, independently of the
    // separate MONITOR capability. Both flag+format are the exact rtap token.
    Ok(text.split_ascii_whitespace().any(|token| token == "rtap"))
}

/// Validate only the native header structure and its actually observed
/// CHANNEL identity. All original radiotap fields and MPDU bytes remain
/// verbatim; absent signal/rate/FCS/decryption metadata stays absent.
/// CHANNEL is mandatory for this bounded owner: configured RF state alone
/// cannot label a packet left in a private firmware FIFO before retuning.
pub(super) fn packet(bytes: &[u8], frequency: u16) -> Result<Vec<u8>, Error> {
    if !(18..=2048).contains(&bytes.len()) || bytes[..2] != [0, 0] {
        return Err(Error::Malformed);
    }
    let header = usize::from(u16::from_le_bytes([bytes[2], bytes[3]]));
    if !(12..=512).contains(&header) || header >= bytes.len() {
        return Err(Error::Malformed);
    }
    let first = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    if first & (1 << 3) == 0 {
        return Err(Error::Unsupported);
    }
    let mut maps = 0usize;
    let mut at = 4usize;
    loop {
        let word = bytes
            .get(at..at + 4)
            .filter(|_| at + 4 <= header)
            .ok_or(Error::Malformed)?;
        let word = u32::from_le_bytes(word.try_into().unwrap());
        maps += 1;
        at += 4;
        if word & (1 << 31) == 0 {
            break;
        }
        if maps == 8 {
            return Err(Error::Unsupported);
        }
    }
    // First-word fields0..3 precede all later/extended namespace fields.
    // Their alignments are relative to the original radiotap header start.
    if first & 1 != 0 {
        at = (at + 7) & !7;
        at = at.checked_add(8).ok_or(Error::Malformed)?;
    }
    if first & (1 << 1) != 0 {
        at += 1;
    }
    if first & (1 << 2) != 0 {
        at += 1;
    }
    at = (at + 1) & !1;
    let channel = bytes
        .get(at..at + 4)
        .filter(|_| at + 4 <= header)
        .ok_or(Error::Malformed)?;
    let observed = u16::from_le_bytes(channel[..2].try_into().unwrap());
    let flags = u16::from_le_bytes(channel[2..].try_into().unwrap());
    let band = if (2412..=2472).contains(&frequency) || frequency == 2484 {
        0x0080
    } else if (5170..=5825).contains(&frequency) {
        0x0100
    } else {
        return Err(Error::Unsupported);
    };
    if observed != frequency || flags & 0x0180 != band {
        return Err(Error::Malformed);
    }
    narf_wireless::monitor::header_len(&bytes[header..]).ok_or(Error::Malformed)?;
    Ok(bytes.to_vec())
}
