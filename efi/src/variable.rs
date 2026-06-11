//! UEFI variable storage codecs — UEFI 2.10 §8.2 + §32.
//!
//! Variable Attributes, well-known GUIDs (Global, Image Security
//! Database), name UCS-2 encoding, and the EFI_SIGNATURE_LIST walker
//! the kernel needs to inspect Secure Boot's `db` / `dbx`.

extern crate alloc;
use alloc::vec::Vec;

/// Variable Attributes bitfield (UEFI 2.10 §8.2.1).
pub mod attr {
    pub const NON_VOLATILE: u32 = 1 << 0;
    pub const BOOTSERVICE_ACCESS: u32 = 1 << 1;
    pub const RUNTIME_ACCESS: u32 = 1 << 2;
    pub const HARDWARE_ERROR_RECORD: u32 = 1 << 3;
    /// Deprecated in 2.x but still seen on older firmwares.
    pub const AUTHENTICATED_WRITE_ACCESS: u32 = 1 << 4;
    pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 1 << 5;
    pub const APPEND_WRITE: u32 = 1 << 6;
    pub const ENHANCED_AUTHENTICATED_ACCESS: u32 = 1 << 7;
}

/// EFI GUID — 16 bytes. Same layout as Microsoft's GUID: a 32-bit
/// `data1`, two 16-bit halves, and an 8-byte tail. Wire is mixed-
/// endian: data1/data2/data3 are little-endian; data4 is bytewise.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl Guid {
    pub const fn new(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Self {
        let mut b = [0u8; 16];
        let d1b = d1.to_le_bytes();
        b[0] = d1b[0];
        b[1] = d1b[1];
        b[2] = d1b[2];
        b[3] = d1b[3];
        let d2b = d2.to_le_bytes();
        b[4] = d2b[0];
        b[5] = d2b[1];
        let d3b = d3.to_le_bytes();
        b[6] = d3b[0];
        b[7] = d3b[1];
        b[8] = d4[0];
        b[9] = d4[1];
        b[10] = d4[2];
        b[11] = d4[3];
        b[12] = d4[4];
        b[13] = d4[5];
        b[14] = d4[6];
        b[15] = d4[7];
        Self(b)
    }
}

/// `EFI_GLOBAL_VARIABLE` GUID (`{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}`)
/// — the namespace for `BootOrder`, `Boot####`, `Lang`, `Timeout`,
/// `SecureBoot`, `SetupMode`, `PK`, `KEK`, `SignatureSupport`.
pub const EFI_GLOBAL_VARIABLE: Guid = Guid::new(
    0x8BE4_DF61,
    0x93CA,
    0x11D2,
    [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
);

/// `EFI_IMAGE_SECURITY_DATABASE_GUID`
/// (`{D719B2CB-3D3A-4596-A3BC-DAD00E67656F}`) — namespace for `db`
/// + `dbx` Secure Boot signature databases.
pub const EFI_IMAGE_SECURITY_DATABASE_GUID: Guid = Guid::new(
    0xD719_B2CB,
    0x3D3A,
    0x4596,
    [0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F],
);

/// `EFI_CERT_X509_GUID` — denotes one entry in `db`/`dbx` is an
/// X.509 certificate.
pub const EFI_CERT_X509_GUID: Guid = Guid::new(
    0xA559_3F58,
    0x094D,
    0x4D33,
    [0xAA, 0xC4, 0x39, 0xCC, 0x88, 0x2D, 0x65, 0xF7],
);

/// `EFI_CERT_SHA256_GUID` — entry is a 32-byte SHA-256 hash.
pub const EFI_CERT_SHA256_GUID: Guid = Guid::new(
    0xC1C4_1626,
    0x504C,
    0x4092,
    [0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43, 0x28],
);

/// Encode a Rust `&str` into the UCS-2 little-endian form UEFI
/// variable names use, NUL-terminated. ASCII subset only — non-ASCII
/// chars produce a single replacement `?` codepoint to keep the
/// codec safe + total.
pub fn encode_name(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2 + 2);
    for c in s.chars() {
        let cp = if c as u32 <= 0xFFFF {
            c as u16
        } else {
            b'?' as u16
        };
        out.extend_from_slice(&cp.to_le_bytes());
    }
    // NUL terminator.
    out.extend_from_slice(&[0, 0]);
    out
}

/// Decode a UCS-2 LE NUL-terminated name back to ASCII (replacing
/// non-ASCII with '?' for safety).
pub fn decode_name(buf: &[u8]) -> alloc::string::String {
    let mut out = alloc::string::String::new();
    let mut i = 0;
    while i + 2 <= buf.len() {
        let cp = u16::from_le_bytes([buf[i], buf[i + 1]]);
        if cp == 0 {
            break;
        }
        if cp <= 0x7F {
            out.push(cp as u8 as char);
        } else {
            out.push('?');
        }
        i += 2;
    }
    out
}

// ── EFI_SIGNATURE_LIST walker (UEFI 2.10 §32.4.1) ────────────────

/// One Signature List header — 28 bytes:
///
/// ```text
///   0..16:  SignatureType (GUID)
///   16..20: SignatureListSize (u32) — total list bytes
///   20..24: SignatureHeaderSize (u32) — vendor header length
///   24..28: SignatureSize (u32) — per-entry length (incl. owner GUID)
/// ```
///
/// Followed by `SignatureHeaderSize` bytes of vendor header, then
/// `(SignatureListSize - 28 - SignatureHeaderSize) /
/// SignatureSize` signature entries. Each entry begins with a
/// 16-byte SignatureOwner GUID then `SignatureSize - 16` bytes of
/// data (X.509 cert, SHA-256 hash, etc.).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SignatureListHeader {
    pub signature_type: Guid,
    pub list_size: u32,
    pub header_size: u32,
    pub entry_size: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SignatureListError {
    Short,
    /// `entry_size <= 16` — every entry must hold a SignatureOwner
    /// GUID plus at least one byte of data.
    BadEntrySize,
    /// `list_size` smaller than the header itself.
    InvalidListSize,
}

impl SignatureListHeader {
    pub fn decode(buf: &[u8]) -> Result<Self, SignatureListError> {
        if buf.len() < 28 {
            return Err(SignatureListError::Short);
        }
        let mut g = [0u8; 16];
        g.copy_from_slice(&buf[..16]);
        let h = Self {
            signature_type: Guid(g),
            list_size: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            header_size: u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
            entry_size: u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]),
        };
        if h.list_size < 28 + h.header_size {
            return Err(SignatureListError::InvalidListSize);
        }
        if h.entry_size <= 16 {
            return Err(SignatureListError::BadEntrySize);
        }
        Ok(h)
    }

    /// Number of entries this list claims to hold.
    pub fn entry_count(&self) -> u32 {
        let body = self.list_size - 28 - self.header_size;
        if self.entry_size == 0 {
            0
        } else {
            body / self.entry_size
        }
    }
}

/// Decoded signature-database entry — a SignatureOwner GUID + the
/// raw signature bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureEntry<'a> {
    pub owner: Guid,
    pub data: &'a [u8],
}

/// Iterate a single EFI_SIGNATURE_LIST. Returns the decoded header
/// and an iterator of entries. Caller can chain successive lists by
/// advancing the input by `header.list_size`.
pub fn parse_signature_list<'a>(
    buf: &'a [u8],
) -> Result<(SignatureListHeader, Vec<SignatureEntry<'a>>), SignatureListError> {
    let h = SignatureListHeader::decode(buf)?;
    let total = h.list_size as usize;
    if buf.len() < total {
        return Err(SignatureListError::Short);
    }
    let entries_start = 28 + h.header_size as usize;
    let mut entries = Vec::with_capacity(h.entry_count() as usize);
    let mut off = entries_start;
    let entry_size = h.entry_size as usize;
    while off + entry_size <= total {
        let mut owner = [0u8; 16];
        owner.copy_from_slice(&buf[off..off + 16]);
        let data = &buf[off + 16..off + entry_size];
        entries.push(SignatureEntry {
            owner: Guid(owner),
            data,
        });
        off += entry_size;
    }
    Ok((h, entries))
}
