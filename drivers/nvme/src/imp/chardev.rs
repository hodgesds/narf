//! NVMe controller character device (`/dev/nvme0`) — admin passthrough.
//!
//! Linux exposes each NVMe controller as a character device
//! (`drivers/nvme/host/core.c`, the `nvme` char class) whose `ioctl`
//! accepts `NVME_IOCTL_ADMIN_CMD` / `NVME_IOCTL_ADMIN64_CMD`
//! (`include/uapi/linux/nvme_ioctl.h`). `smartctl -d nvme /dev/nvme0`
//! and `nvme-cli` drive the controller entirely through that interface:
//! Identify Controller/Namespace, Get Log Page (SMART/Health, error
//! log, firmware slot), etc.
//!
//! This module implements the controller char node on top of
//! [`crate::admin_passthrough`]. The node is registered with devtmpfs as
//! `/dev/nvme0` by the probe path; its [`FileOps::ioctl_user`] decodes
//! the passthrough struct — including the nested `addr` data pointer —
//! through the fault-contained [`IoctlContext`], so this driver never
//! dereferences a process address itself.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use narf_filesystem::{FileOps, FileType, FsError, FsFuture, IoctlContext, Mode, Stat};

use super::admin::AdminSqe;

// ── ioctl numbers (uapi/linux/nvme_ioctl.h, magic 'N' = 0x4E) ─────────

/// `_IO('N', 0x40)` — return the namespace id of the opened handle.
pub const NVME_IOCTL_ID: u32 = 0x0000_4E40;
/// `_IOWR('N', 0x41, struct nvme_passthru_cmd)` (72-byte struct).
pub const NVME_IOCTL_ADMIN_CMD: u32 = 0xC048_4E41;
/// `_IOWR('N', 0x43, struct nvme_passthru_cmd)` — I/O command passthrough.
pub const NVME_IOCTL_IO_CMD: u32 = 0xC048_4E43;
/// `_IOWR('N', 0x47, struct nvme_passthru_cmd64)` (80-byte struct, u64 result).
pub const NVME_IOCTL_ADMIN64_CMD: u32 = 0xC050_4E47;

/// `sizeof(struct nvme_passthru_cmd)`.
const PASSTHRU_CMD_LEN: usize = 72;
/// `sizeof(struct nvme_passthru_cmd64)`.
const PASSTHRU_CMD64_LEN: usize = 80;
/// Offset of the `result` field in `nvme_passthru_cmd` (u32).
const RESULT_OFF_32: usize = 68;
/// Offset of the `result` field in `nvme_passthru_cmd64` (u64).
const RESULT_OFF_64: usize = 72;

/// Upper bound on a single passthrough data transfer. Mirrors the page
/// cap in [`crate::Controller::admin_passthrough`]; anything larger is
/// rejected with `EINVAL` rather than attempted.
const MAX_PASSTHRU_DATA: u32 = 2 * 1024 * 1024;

// ── nvme_passthru_cmd decode ──────────────────────────────────────────

/// The fields of `struct nvme_passthru_cmd` / `nvme_passthru_cmd64` this
/// driver acts on. Field layout (uapi/linux/nvme_ioctl.h):
///
/// ```text
/// off  size  field
///   0   1    opcode
///   1   1    flags
///   2   2    rsvd1
///   4   4    nsid
///   8   4    cdw2
///  12   4    cdw3
///  16   8    metadata
///  24   8    addr          (host data buffer pointer)
///  32   4    metadata_len
///  36   4    data_len
///  40   4    cdw10 .. 60 cdw15
///  64   4    timeout_ms
///  68   4    result        (cmd) / 72 8 result (cmd64)
/// ```
#[derive(Copy, Clone, Debug, Default)]
struct PassthruCmd {
    opcode: u8,
    nsid: u32,
    addr: u64,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}

#[inline]
fn rd_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn rd_u64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

impl PassthruCmd {
    /// Parse from the raw little-endian ioctl struct bytes.
    fn parse(buf: &[u8]) -> Self {
        Self {
            opcode: buf[0],
            nsid: rd_u32(buf, 4),
            addr: rd_u64(buf, 24),
            data_len: rd_u32(buf, 36),
            cdw10: rd_u32(buf, 40),
            cdw11: rd_u32(buf, 44),
            cdw12: rd_u32(buf, 48),
            cdw13: rd_u32(buf, 52),
            cdw14: rd_u32(buf, 56),
            cdw15: rd_u32(buf, 60),
        }
    }

    /// Build the admin SQE carried by this passthrough request. PRP
    /// addresses are programmed by [`crate::Controller::admin_passthrough`]
    /// from the DMA buffer it allocates, so they are left zero here.
    fn to_sqe(self) -> AdminSqe {
        AdminSqe {
            opcode: self.opcode,
            nsid: self.nsid,
            cdw10: self.cdw10,
            cdw11: self.cdw11,
            cdw12: self.cdw12,
            cdw13: self.cdw13,
            cdw14: self.cdw14,
            cdw15: self.cdw15,
            ..Default::default()
        }
    }
}

/// Core passthrough handler shared by the 32- and 64-bit ioctl structs.
/// `struct_len` is the ioctl struct size and `result_off`/`result_u64`
/// describe where the completion result dword is written back.
fn do_passthru(
    ctx: &dyn IoctlContext,
    arg: u64,
    struct_len: usize,
    result_off: usize,
    result_u64: bool,
) -> Result<u64, FsError> {
    // Pull the fixed-size command struct out of user memory.
    let mut raw = [0u8; PASSTHRU_CMD64_LEN];
    ctx.read(arg, &mut raw[..struct_len])?;
    let cmd = PassthruCmd::parse(&raw);

    if cmd.data_len > MAX_PASSTHRU_DATA {
        return Err(FsError::InvalidData);
    }

    // Data-transfer direction from the opcode's low two bits (NVMe Base
    // Spec §3.1.3.4): 0b01 host→controller, 0b10 controller→host, 0b11
    // bidirectional.
    let dir = cmd.opcode & 0x3;
    let to_dev = dir == 0b01 || dir == 0b11;
    let to_host = dir == 0b10 || dir == 0b11;

    // Stage the host transfer buffer. For a write (host→controller) fill
    // it from user memory first; for a read it is filled on return.
    let mut data: Vec<u8> = if cmd.data_len > 0 && cmd.addr != 0 {
        vec![0u8; cmd.data_len as usize]
    } else {
        Vec::new()
    };
    if to_dev && !data.is_empty() {
        ctx.read(cmd.addr, &mut data)?;
    }

    // Run the command. A nonzero NVMe status is reported back through the
    // ioctl return value, not as an error — smartctl inspects it.
    let sqe = cmd.to_sqe();
    let outcome = super::admin_passthrough(&sqe, &mut data).ok_or(FsError::NoDevice)?;
    let result = match outcome {
        Ok(r) => r,
        Err(_) => return Err(FsError::Io(narf_block::BlockError::IOError)),
    };

    // Controller→host: copy the device's reply back to the user buffer.
    if to_host && result.status == 0 && !data.is_empty() {
        ctx.write(cmd.addr, &data)?;
    }

    // Write the completion result dword back into the struct.
    if result_u64 {
        let bytes = (result.result as u64).to_le_bytes();
        ctx.write(arg + result_off as u64, &bytes)?;
    } else {
        let bytes = result.result.to_le_bytes();
        ctx.write(arg + result_off as u64, &bytes)?;
    }

    // Linux `nvme_submit_user_cmd` returns the NVMe status word (0 on
    // success) as the ioctl return value.
    Ok(result.status as u64)
}

// ── Char device ───────────────────────────────────────────────────────

/// `/dev/nvme<instance>` controller character device.
#[derive(Debug)]
pub struct NvmeCharDev {
    instance: u32,
}

impl NvmeCharDev {
    pub fn new(instance: u32) -> Self {
        Self { instance }
    }
}

impl FileOps for NvmeCharDev {
    // A controller char device has no byte stream: reads/writes are not
    // the interface (Linux returns -EINVAL). Report EOF / zero so a
    // stray read doesn't error spuriously.
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let n = buf.len();
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    /// `st_rdev` for the controller node. Linux allocates the `nvme` char
    /// major dynamically; we use a stable major from the LOCAL/EXPERIMENTAL
    /// range (240) with the controller instance as the minor. smartctl
    /// keys off the path, not the exact dev_t.
    fn rdev(&self) -> u64 {
        (240u64 << 8) | (self.instance as u64 & 0xFF)
    }

    fn ioctl_user<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        context: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            match cmd {
                NVME_IOCTL_ADMIN_CMD | NVME_IOCTL_IO_CMD => {
                    do_passthru(context, arg, PASSTHRU_CMD_LEN, RESULT_OFF_32, false)
                }
                NVME_IOCTL_ADMIN64_CMD => {
                    do_passthru(context, arg, PASSTHRU_CMD64_LEN, RESULT_OFF_64, true)
                }
                // The controller handle has no single namespace id; Linux
                // answers NVME_IOCTL_ID with -ENOTTY here (it is a
                // per-namespace query). Fall through to the generic
                // unknown-ioctl path.
                _ => Err(FsError::Unsupported),
            }
        })
    }
}
