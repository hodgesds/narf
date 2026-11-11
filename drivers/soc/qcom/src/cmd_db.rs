//! Command database (cmd-db): the bootloader-populated table that maps
//! RPMh resource names to their RSC addresses.
//!
//! Linux counterpart: `drivers/soc/qcom/cmd-db.c` (`cmd_db_read_addr`,
//! `cmd_db_get_header`). The table lives in a reserved-memory region;
//! this module only parses a byte slice, so the caller owns the mapping
//! (the `qcom,cmd-db` `reserved-memory` node is resolved by
//! [`crate::platform::pas_power`]).
//!
//! Layout (all multi-byte fields little-endian), from `cmd-db.c`:
//!
//! ```text
//! struct cmd_db_header {
//!     u32 version;
//!     u8  magic[4];              // 0xdb, 0x30, 0x03, 0x0c
//!     struct rsc_hdr header[8];  // one per slave id
//!     u32 checksum;              // unused
//!     u32 reserved;
//!     u8  data[];                // entry headers + aux data
//! };
//! struct rsc_hdr {
//!     u16 slv_id, header_offset, data_offset, cnt, version, reserved[3];
//! };
//! struct entry_header {
//!     u8  id[8];                 // NUL-padded resource name
//!     u32 priority[2];           // unused
//!     u32 addr;                  // RSC address of the resource
//!     u16 len, offset;           // aux data length / offset
//! };
//! ```
//!
//! Entry headers for slave `i` start at `data + header_offset` and
//! aux data at `data + data_offset + entry.offset`. The slave scan
//! stops at the first header with `slv_id == 0`, exactly as Linux
//! does. Nothing here has run on Qualcomm silicon; the layout above
//! is transcribed from the Linux source, and the tests build their
//! table from this text, not from the code under test.

/// Magic bytes at the head of a cmd-db table (`cmd-db.c`).
pub const CMD_DB_MAGIC: [u8; 4] = [0xdb, 0x30, 0x03, 0x0c];

/// Number of slave headers in a cmd-db table (`MAX_SLV_ID`).
const NUM_SLV: usize = 8;
/// Size of `cmd_db_header` before `data[]`: 4 + 4 + 8*12 + 4 + 4.
const HEADER_LEN: usize = 112;
/// Size of one `rsc_hdr`.
const RSC_HDR_LEN: usize = 12;
/// Size of one `entry_header`.
const ENTRY_LEN: usize = 24;

/// Parse failure for a cmd-db table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmdDbError {
    /// Fewer than [`HEADER_LEN`] bytes, or an entry read past the end.
    Truncated,
    /// The magic bytes do not match [`CMD_DB_MAGIC`].
    BadMagic,
}

/// A parsed cmd-db table over borrowed bytes.
#[derive(Copy, Clone, Debug)]
pub struct CmdDb<'a> {
    data: &'a [u8],
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    let s = b.get(off..off + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl<'a> CmdDb<'a> {
    /// Validate the magic and keep the table. Only the fixed header is
    /// checked here; entry reads bounds-check on every access.
    pub fn parse(data: &'a [u8]) -> Result<Self, CmdDbError> {
        if data.len() < HEADER_LEN {
            return Err(CmdDbError::Truncated);
        }
        if data[4..8] != CMD_DB_MAGIC {
            return Err(CmdDbError::BadMagic);
        }
        Ok(Self { data })
    }

    /// `cmd_db_read_addr`: the RSC address for resource `id`, or `None`
    /// when the id is absent (Linux returns 0 on error; `None` is the
    /// typed equivalent). The query is the id truncated to 8 bytes and
    /// NUL-padded, matching Linux's `strtomem_pad(query, id, 0)`.
    pub fn read_addr(&self, id: &str) -> Option<u32> {
        let mut query = [0u8; 8];
        let bytes = id.as_bytes();
        let n = bytes.len().min(8);
        query[..n].copy_from_slice(&bytes[..n]);
        let (hdr, ent) = self.find(&query)?;
        let _ = hdr;
        read_u32(self.data, ent + 16)
    }

    /// `cmd_db_read_aux_data`: the resource's aux data (`entry.len`
    /// bytes at `data + rsc_hdr.data_offset + entry.offset`, Linux
    /// `rsc_offset`), or `None` when the id is absent or the data runs
    /// past the table. Same id query as [`Self::read_addr`].
    pub fn read_aux_data(&self, id: &str) -> Option<&'a [u8]> {
        let mut query = [0u8; 8];
        let bytes = id.as_bytes();
        let n = bytes.len().min(8);
        query[..n].copy_from_slice(&bytes[..n]);
        let (hdr, ent) = self.find(&query)?;
        let data_offset = read_u16(self.data, hdr + 4)? as usize;
        let len = read_u16(self.data, ent + 20)? as usize;
        let offset = read_u16(self.data, ent + 22)? as usize;
        let start = HEADER_LEN + data_offset + offset;
        self.data.get(start..start + len)
    }

    /// `cmd_db_get_header` for the id query: the `(rsc_hdr, entry)`
    /// offsets, or `None` when absent or out of bounds.
    fn find(&self, query: &[u8; 8]) -> Option<(usize, usize)> {
        for i in 0..NUM_SLV {
            let hdr = 8 + i * RSC_HDR_LEN;
            let slv_id = read_u16(self.data, hdr)?;
            if slv_id == 0 {
                break;
            }
            let header_offset = read_u16(self.data, hdr + 2)? as usize;
            let cnt = read_u16(self.data, hdr + 6)? as usize;
            let entries = HEADER_LEN + header_offset;
            for j in 0..cnt {
                let ent = entries + j * ENTRY_LEN;
                let id = self.data.get(ent..ent + 8)?;
                if id == query {
                    return Some((hdr, ent));
                }
            }
        }
        None
    }
}
