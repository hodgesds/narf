// SPDX-License-Identifier: GPL-2.0-or-later
//! Caller Probe Request elements through the firmware `vndr_ie` iovar.
//!
//! Linux `brcmf_cfg80211_scan` installs `request->ie` with
//! `brcmf_vif_set_mgmt_ie(vif, BRCMF_VNDR_IE_PRBREQ_FLAG, ...)` before each
//! escan. The firmware then appends the installed Vendor Specific elements to
//! every Probe Request it builds. The bytes are a sequence of
//! `cmd[4] count:u32 pktflag:u32 element` records (`brcmf_vndr_ie`), deleting
//! the previously installed elements before adding the new set.
//!
//! The FullMAC firmware owns the rest of the Probe Request. Linux silently
//! drops elements it cannot express (non-vendor IDs, WPA/WME vendor elements,
//! more than five elements, or entries beyond the saved 512-byte buffer). Here
//! such requests fail before any device write so that a successful scan always
//! carried exactly the caller's elements.

use super::Error;
use alloc::vec::Vec;

/// `BRCMF_VNDR_IE_PRBREQ_FLAG`.
pub(super) const PRBREQ_FLAG: u32 = 0x10;
/// `VNDR_IE_PARSE_LIMIT`.
const PARSE_LIMIT: usize = 5;
/// `IE_MAX_LEN`: size of `vif_saved_ie::probe_req_ie`.
const SAVED_LEN: usize = 512;
/// `VNDR_IE_VSIE_OFFSET`/`VNDR_IE_HDR_SIZE`.
const RECORD_HEADER: usize = 12;
/// Vendor Specific element ID.
const VENDOR_SPECIFIC: u8 = 221;
/// `VS_IE_FIXED_HDR_LEN - TLV_HDR_LEN + 1`: OUI, OUI type and one byte.
const MIN_VENDOR_BODY: usize = 5;

/// Validate caller Probe Request IEs and return them in canonical installed
/// form (the same concatenated byte string, since nothing is dropped).
pub(super) fn parse(mut ies: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    let (mut count, mut budget) = (0usize, 0usize);
    while !ies.is_empty() {
        let [id, length, ..] = *ies else {
            return Err(Error::Malformed);
        };
        let end = 2 + usize::from(length);
        let element = ies.get(..end).ok_or(Error::Malformed)?;
        if id != VENDOR_SPECIFIC {
            // Firmware `vndr_ie` has no representation for standard IDs.
            return Err(Error::Unsupported);
        }
        if usize::from(length) < MIN_VENDOR_BODY {
            return Err(Error::Malformed);
        }
        // Firmware generates WPA and WMM/WME elements itself.
        if element[2..5] == [0x00, 0x50, 0xf2] && matches!(element[5], 1 | 2) {
            return Err(Error::Unsupported);
        }
        count += 1;
        budget += end + RECORD_HEADER;
        if count > PARSE_LIMIT || budget > SAVED_LEN {
            return Err(Error::Unsupported);
        }
        out.extend_from_slice(element);
        ies = &ies[end..];
    }
    Ok(out)
}

fn records(out: &mut Vec<u8>, command: &[u8; 4], mut ies: &[u8]) {
    while !ies.is_empty() {
        let end = 2 + usize::from(ies[1]); // Canonical from `parse`.
        out.extend_from_slice(command);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&PRBREQ_FLAG.to_le_bytes());
        out.extend_from_slice(&ies[..end]);
        ies = &ies[end..];
    }
}

/// The `vndr_ie` iovar body replacing `installed` with `requested`, or
/// `None` when firmware already carries exactly the requested set.
pub(super) fn update(installed: &[u8], requested: &[u8]) -> Option<Vec<u8>> {
    if installed == requested {
        return None;
    }
    let mut out = Vec::new();
    records(&mut out, b"del\0", installed);
    records(&mut out, b"add\0", requested);
    Some(out)
}
