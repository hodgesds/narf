//! Bulk-Only Transport and SCSI wire codec (USB MSC BOT 1.0; SBC-3, SPC-4).
//!
//! No kernel dependencies and no library calls: every builder is a `const
//! fn` that assembles its bytes in place, so module text built from it links
//! nothing but KSYMTAB exports. The built-in binder's encoders
//! (`narf-drivers-usb::msc`) are checked against these byte-for-byte.

/// Interface class / subclass / protocol of a BOT SCSI device.
pub const INTERFACE_CLASS: u8 = 0x08;
/// SCSI transparent command set.
pub const INTERFACE_SUBCLASS: u8 = 0x06;
/// Bulk-Only Transport.
pub const INTERFACE_PROTOCOL: u8 = 0x50;

/// `USBC`, little endian.
pub const CBW_SIGNATURE: u32 = 0x4342_5355;
/// `USBS`, little endian.
pub const CSW_SIGNATURE: u32 = 0x5342_5355;
/// Command Block Wrapper length.
pub const CBW_LEN: usize = 31;
/// Command Status Wrapper length.
pub const CSW_LEN: usize = 13;
/// `bmCBWFlags` direction bit: data flows device to host.
pub const CBW_FLAG_IN: u8 = 0x80;

/// `bCSWStatus`: command passed.
pub const CSW_PASSED: u8 = 0;
/// `bCSWStatus`: command failed (sense data explains why).
pub const CSW_FAILED: u8 = 1;
/// `bCSWStatus`: phase error; the device needs a reset recovery.
pub const CSW_PHASE_ERROR: u8 = 2;

pub const SCSI_TEST_UNIT_READY: u8 = 0x00;
pub const SCSI_REQUEST_SENSE: u8 = 0x03;
pub const SCSI_INQUIRY: u8 = 0x12;
pub const SCSI_READ_CAPACITY_10: u8 = 0x25;
pub const SCSI_READ_10: u8 = 0x28;
pub const SCSI_WRITE_10: u8 = 0x2A;
pub const SCSI_SYNCHRONIZE_CACHE_10: u8 = 0x35;

/// A SCSI command block (up to 16 bytes) and its used length.
///
/// Held as two little-endian words rather than `[u8; 16]`: a mostly-zero
/// byte array is filled with a `memset` call on aarch64, which module text
/// cannot link, while two words are two stores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cdb {
    words: [u64; 2],
    len: u8,
}

impl Cdb {
    /// The command bytes, zero padded to 16.
    pub const fn bytes(&self) -> [u8; 16] {
        let [a0, a1, a2, a3, a4, a5, a6, a7] = self.words[0].to_le_bytes();
        let [b0, b1, b2, b3, b4, b5, b6, b7] = self.words[1].to_le_bytes();
        [
            a0, a1, a2, a3, a4, a5, a6, a7, b0, b1, b2, b3, b4, b5, b6, b7,
        ]
    }

    /// The used length (6 or 10 here).
    pub const fn len(&self) -> u8 {
        self.len
    }

    /// Never true: every builder emits a whole command.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

const fn cdb10(op: u8, lba: u32, blocks: u16) -> Cdb {
    let [l0, l1, l2, l3] = lba.to_be_bytes();
    let [n0, n1] = blocks.to_be_bytes();
    Cdb {
        words: [
            u64::from_le_bytes([op, 0, l0, l1, l2, l3, 0, n0]),
            u64::from_le_bytes([n1, 0, 0, 0, 0, 0, 0, 0]),
        ],
        len: 10,
    }
}

const fn cdb6(op: u8, allocation: u8) -> Cdb {
    Cdb {
        words: [u64::from_le_bytes([op, 0, 0, 0, allocation, 0, 0, 0]), 0],
        len: 6,
    }
}

/// TEST UNIT READY.
pub const fn test_unit_ready() -> Cdb {
    cdb6(SCSI_TEST_UNIT_READY, 0)
}

/// REQUEST SENSE with `allocation` bytes of fixed-format sense data.
pub const fn request_sense(allocation: u8) -> Cdb {
    cdb6(SCSI_REQUEST_SENSE, allocation)
}

/// Standard INQUIRY with `allocation` bytes of response.
pub const fn inquiry(allocation: u8) -> Cdb {
    cdb6(SCSI_INQUIRY, allocation)
}

/// READ CAPACITY(10): last LBA and block length, 8 bytes back.
pub const fn read_capacity10() -> Cdb {
    cdb10(SCSI_READ_CAPACITY_10, 0, 0)
}

/// READ(10) of `blocks` blocks at `lba`.
pub const fn read10(lba: u32, blocks: u16) -> Cdb {
    cdb10(SCSI_READ_10, lba, blocks)
}

/// WRITE(10) of `blocks` blocks at `lba`.
pub const fn write10(lba: u32, blocks: u16) -> Cdb {
    cdb10(SCSI_WRITE_10, lba, blocks)
}

/// SYNCHRONIZE CACHE(10) of the whole medium.
pub const fn synchronize_cache10() -> Cdb {
    cdb10(SCSI_SYNCHRONIZE_CACHE_10, 0, 0)
}

/// The Command Block Wrapper for `cdb`, moving `data_len` bytes in the
/// direction `data_in` names, addressed to `lun`.
pub const fn cbw(tag: u32, data_len: u32, data_in: bool, lun: u8, cdb: &Cdb) -> [u8; CBW_LEN] {
    let [s0, s1, s2, s3] = CBW_SIGNATURE.to_le_bytes();
    let [t0, t1, t2, t3] = tag.to_le_bytes();
    let [d0, d1, d2, d3] = data_len.to_le_bytes();
    let b = cdb.bytes();
    [
        s0,
        s1,
        s2,
        s3,
        t0,
        t1,
        t2,
        t3,
        d0,
        d1,
        d2,
        d3,
        if data_in { CBW_FLAG_IN } else { 0 },
        lun,
        cdb.len & 0x1F,
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    ]
}

/// A decoded Command Status Wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Csw {
    pub tag: u32,
    pub residue: u32,
    pub status: u8,
}

/// Decode a CSW; `None` without the `USBS` signature.
pub const fn decode_csw(buf: &[u8; CSW_LEN]) -> Option<Csw> {
    let [s0, s1, s2, s3, t0, t1, t2, t3, r0, r1, r2, r3, status] = *buf;
    if u32::from_le_bytes([s0, s1, s2, s3]) != CSW_SIGNATURE {
        return None;
    }
    Some(Csw {
        tag: u32::from_le_bytes([t0, t1, t2, t3]),
        residue: u32::from_le_bytes([r0, r1, r2, r3]),
        status,
    })
}

/// Decode READ CAPACITY(10) data: `(last_lba, block_len)`.
pub const fn decode_read_capacity10(buf: &[u8; 8]) -> (u32, u32) {
    let [a, b, c, d, e, f, g, h] = *buf;
    (
        u32::from_be_bytes([a, b, c, d]),
        u32::from_be_bytes([e, f, g, h]),
    )
}
