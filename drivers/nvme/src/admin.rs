//! NVMe admin-command builders (clean-room).
//!
//! References (public-only):
//! - "NVM Express Base Specification, Revision 2.0c" (Oct 2022) —
//!   NVM Express Inc. Public document. §3.3.3 (SQE layout, 64
//!   bytes), §5.1 (Admin Submission Queue commands), §5.4 (Format
//!   NVM, opcode 0x80, CDW10 layout — LBAF, MSET, PI, PIL, SES),
//!   §5.21 (Sanitize, opcode 0x84, CDW10/11), §5.27 (Get Log Page,
//!   opcode 0x02), §5.31 (Set Features, opcode 0x09; FID 0x1A is
//!   "Boot Partition Write Protection Configuration").
//!   <https://nvmexpress.org/specifications/>
//! - "NVM Command Set Specification, Revision 1.0c" — for SMART /
//!   Health log page (LID 0x02) byte layout.
//!   <https://nvmexpress.org/specifications/>
//!
//! No GPL Linux source consulted.
//!
//! ## SQE layout (Base 2.0c §3.3.3, table 84)
//!
//! 64 bytes, 16 DWORDs:
//!
//! ```text
//!   DWORD 0      CDW0 (opcode | fused | psdt | cid)
//!   DWORD 1      NSID
//!   DWORD 2..3   reserved
//!   DWORD 4..5   MPTR (metadata pointer)
//!   DWORD 6..9   PRP1 / PRP2 (data pointers)
//!   DWORD 10..15 CDW10..CDW15 — command-specific
//! ```

use alloc::vec::Vec;

// ── Admin opcodes (Base 2.0c §5, table 27) ─────────────────────────

pub const OPC_DELETE_IO_SQ: u8 = 0x00;
pub const OPC_CREATE_IO_SQ: u8 = 0x01;
pub const OPC_GET_LOG_PAGE: u8 = 0x02;
pub const OPC_DELETE_IO_CQ: u8 = 0x04;
pub const OPC_CREATE_IO_CQ: u8 = 0x05;
pub const OPC_IDENTIFY: u8 = 0x06;
pub const OPC_ABORT: u8 = 0x08;
pub const OPC_SET_FEATURES: u8 = 0x09;
pub const OPC_GET_FEATURES: u8 = 0x0A;
pub const OPC_ASYNC_EVENT_REQUEST: u8 = 0x0C;
pub const OPC_NAMESPACE_MANAGEMENT: u8 = 0x0D;
pub const OPC_FIRMWARE_COMMIT: u8 = 0x10;
pub const OPC_FIRMWARE_DOWNLOAD: u8 = 0x11;
pub const OPC_DEVICE_SELF_TEST: u8 = 0x14;
pub const OPC_NAMESPACE_ATTACHMENT: u8 = 0x15;
pub const OPC_FORMAT_NVM: u8 = 0x80;
pub const OPC_SECURITY_SEND: u8 = 0x81;
pub const OPC_SECURITY_RECEIVE: u8 = 0x82;
pub const OPC_SANITIZE: u8 = 0x84;
pub const OPC_GET_LBA_STATUS: u8 = 0x86;

// ── Identify CNS values (§5.17, table 138) ─────────────────────────

pub const CNS_NAMESPACE: u8 = 0x00;
pub const CNS_CONTROLLER: u8 = 0x01;
pub const CNS_NAMESPACE_LIST: u8 = 0x02;
pub const CNS_NAMESPACE_DESCRIPTOR_LIST: u8 = 0x03;

// ── Get Log Page Log IDs (§5.16, table 132) ────────────────────────

pub const LID_ERROR_INFO: u8 = 0x01;
pub const LID_SMART_HEALTH: u8 = 0x02;
pub const LID_FW_SLOT: u8 = 0x03;
pub const LID_CHANGED_NAMESPACE_LIST: u8 = 0x04;
pub const LID_COMMANDS_SUPPORTED_AND_EFFECTS: u8 = 0x05;
pub const LID_DEVICE_SELF_TEST: u8 = 0x06;
pub const LID_TELEMETRY_HOST_INITIATED: u8 = 0x07;
pub const LID_TELEMETRY_CONTROLLER_INITIATED: u8 = 0x08;
pub const LID_SANITIZE_STATUS: u8 = 0x81;

// ── Sanitize action codes (§5.21, CDW10 bits 2..0) ─────────────────

pub const SANACT_EXIT_FAILURE_MODE: u8 = 0x01;
pub const SANACT_BLOCK_ERASE: u8 = 0x02;
pub const SANACT_OVERWRITE: u8 = 0x03;
pub const SANACT_CRYPTO_ERASE: u8 = 0x04;

// ── Format NVM Secure-Erase Settings (§5.4, CDW10 bits 11..9) ──────

pub const SES_NO_SECURE_ERASE: u8 = 0x00;
pub const SES_USER_DATA_ERASE: u8 = 0x01;
pub const SES_CRYPTO_ERASE: u8 = 0x02;

// ── Set Features Feature Identifiers (§5.31, table 287) ────────────

pub const FID_ARBITRATION: u8 = 0x01;
pub const FID_POWER_MANAGEMENT: u8 = 0x02;
pub const FID_TEMPERATURE_THRESHOLD: u8 = 0x04;
pub const FID_NUMBER_OF_QUEUES: u8 = 0x07;
pub const FID_INTERRUPT_VECTOR_CONFIG: u8 = 0x09;
pub const FID_WRITE_ATOMICITY_NORMAL: u8 = 0x0A;
pub const FID_ASYNC_EVENT_CONFIG: u8 = 0x0B;
pub const FID_HOST_BEHAVIOR_SUPPORT: u8 = 0x16;
pub const FID_SANITIZE_CONFIG: u8 = 0x17;
pub const FID_BOOT_PARTITION_WRITE_PROTECTION: u8 = 0x1A;

/// One NVMe Submission Queue Entry — the public-API mirror of the
/// internal `Sqe` struct used by the driver. We keep this in its own
/// type so admin builders compose without touching the driver's
/// private state.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct AdminSqe {
    pub opcode: u8,
    pub fuse: u8,
    pub psdt: u8,
    pub cid: u16,
    pub nsid: u32,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl AdminSqe {
    pub fn new(opcode: u8) -> Self {
        Self {
            opcode,
            ..Default::default()
        }
    }

    /// Fluent builder helper: set the command ID.
    pub fn with_cid(mut self, cid: u16) -> Self {
        self.cid = cid;
        self
    }

    /// Encode CDW0 from the (opcode, fuse, psdt, cid) field set per
    /// §3.3.3 Figure 79: CDW0 is `cid<<16 | psdt<<14 | fuse<<8 | opcode`.
    pub fn cdw0(self) -> u32 {
        ((self.cid as u32) << 16)
            | (((self.psdt as u32) & 0x03) << 14)
            | (((self.fuse as u32) & 0x03) << 8)
            | (self.opcode as u32)
    }

    /// Serialise the SQE to its 64-byte wire form (LE), exactly the
    /// bytes the controller DMAs out of the admin SQ.
    pub fn encode(self) -> [u8; 64] {
        let mut out = [0u8; 64];
        let dwords: [u32; 16] = [
            self.cdw0(),
            self.nsid,
            0,
            0,
            self.mptr as u32,
            (self.mptr >> 32) as u32,
            self.prp1 as u32,
            (self.prp1 >> 32) as u32,
            self.prp2 as u32,
            (self.prp2 >> 32) as u32,
            self.cdw10,
            self.cdw11,
            self.cdw12,
            self.cdw13,
            self.cdw14,
            self.cdw15,
        ];
        for (i, dw) in dwords.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&dw.to_le_bytes());
        }
        out
    }
}

// ── Specific admin command builders ────────────────────────────────

/// Identify Controller (CNS=0x01).
pub fn identify_controller(cid: u16, prp1: u64) -> AdminSqe {
    AdminSqe {
        opcode: OPC_IDENTIFY,
        cid,
        prp1,
        cdw10: CNS_CONTROLLER as u32,
        ..Default::default()
    }
}

/// Identify Namespace (CNS=0x00). `nsid` selects the namespace.
pub fn identify_namespace(cid: u16, nsid: u32, prp1: u64) -> AdminSqe {
    AdminSqe {
        opcode: OPC_IDENTIFY,
        cid,
        nsid,
        prp1,
        cdw10: CNS_NAMESPACE as u32,
        ..Default::default()
    }
}

/// Format NVM (§5.4). `lbaf` is the Logical Block Format index
/// (0..15), `ses` selects secure-erase behaviour.
pub fn format_nvm(cid: u16, nsid: u32, lbaf: u8, ses: u8) -> AdminSqe {
    let cdw10 = ((ses as u32) & 0x07) << 9 | ((lbaf as u32) & 0x0F);
    AdminSqe {
        opcode: OPC_FORMAT_NVM,
        cid,
        nsid,
        cdw10,
        ..Default::default()
    }
}

/// Sanitize (§5.21). `sanact` selects the action; `ause` (allow
/// unrestricted sanitize exit), `owpass` (overwrite pass count) and
/// `oipbp` (overwrite invert pattern between passes) are §5.21 CDW10
/// bit fields.
pub fn sanitize(
    cid: u16,
    sanact: u8,
    ause: bool,
    owpass: u8,
    oipbp: bool,
    overwrite_pattern: u32,
) -> AdminSqe {
    let mut cdw10 = (sanact as u32) & 0x07;
    if ause {
        cdw10 |= 1 << 3;
    }
    cdw10 |= ((owpass as u32) & 0x0F) << 4;
    if oipbp {
        cdw10 |= 1 << 8;
    }
    AdminSqe {
        opcode: OPC_SANITIZE,
        cid,
        cdw10,
        cdw11: overwrite_pattern,
        ..Default::default()
    }
}

/// Get Log Page (§5.16). `numd` is "number of dwords - 1" (so a 512
/// byte SMART/Health log requests numd = 127).
pub fn get_log_page(
    cid: u16,
    nsid: u32,
    lid: u8,
    numd: u32,
    prp1: u64,
    log_specific_id: u8,
) -> AdminSqe {
    let numdl = numd & 0xFFFF;
    let numdu = (numd >> 16) & 0xFFFF;
    let cdw10 = ((numdl) << 16) | ((log_specific_id as u32) << 8) | (lid as u32);
    let cdw11 = numdu;
    AdminSqe {
        opcode: OPC_GET_LOG_PAGE,
        cid,
        nsid,
        prp1,
        cdw10,
        cdw11,
        ..Default::default()
    }
}

/// Convenience: SMART/Health log (LID 0x02) for the controller (NSID = 0xFFFF_FFFF),
/// 512-byte payload (`numd = 127`).
pub fn get_smart_log(cid: u16, prp1: u64) -> AdminSqe {
    get_log_page(cid, 0xFFFF_FFFF, LID_SMART_HEALTH, 127, prp1, 0)
}

/// Set Features — Boot Partition Write Protection Configuration
/// (FID 0x1A, §5.31). `bpid` selects the boot partition (0 or 1);
/// `bpwps` is the Boot Partition Write Protection State (table 297).
pub fn set_features_boot_partition_wp(cid: u16, bpid: u8, bpwps: u8) -> AdminSqe {
    let cdw10 = FID_BOOT_PARTITION_WRITE_PROTECTION as u32;
    let cdw11 = ((bpid as u32) & 0x07) << 31 | ((bpwps as u32) & 0x07);
    AdminSqe {
        opcode: OPC_SET_FEATURES,
        cid,
        cdw10,
        cdw11,
        ..Default::default()
    }
}

/// Set Features — Number of Queues (FID 0x07, §5.31). `nsqr`/`ncqr`
/// are the host's *requested* count - 1 of I/O submission/completion
/// queues (controller may grant fewer; check the response CDW0).
pub fn set_features_number_of_queues(cid: u16, nsqr: u16, ncqr: u16) -> AdminSqe {
    let cdw11 = ((ncqr as u32) << 16) | (nsqr as u32);
    AdminSqe {
        opcode: OPC_SET_FEATURES,
        cid,
        cdw10: FID_NUMBER_OF_QUEUES as u32,
        cdw11,
        ..Default::default()
    }
}

/// Identify Namespace List (CNS=0x02). Returns up to 1024 NSIDs
/// (4 KiB buffer, 4 bytes per NSID) of active namespaces with NSID
/// > `start_nsid`. Per NVMe Base Spec 2.0c §5.17 (table 143):
///   - CNS=0x02 → Active Namespace ID list
///   - NSID field carries the start-NSID filter (returns NSIDs > filter)
pub fn identify_namespace_list(cid: u16, start_nsid: u32, prp1: u64) -> AdminSqe {
    AdminSqe {
        opcode: OPC_IDENTIFY,
        cid,
        nsid: start_nsid,
        prp1,
        cdw10: CNS_NAMESPACE_LIST as u32,
        ..Default::default()
    }
}

/// Get Features (§5.11, opcode 0x0A). Returns the current value of
/// feature `fid`. `sel` selects which setting to return:
///   - 0x00 = Current (what the controller is using)
///   - 0x01 = Default (factory default)
///   - 0x02 = Saved
///   - 0x03 = Supported Capabilities
///
/// Linux ref: drivers/nvme/host/admin-cmd.c:nvme_get_features
pub fn get_features(cid: u16, fid: u8, sel: u8) -> AdminSqe {
    let cdw10 = ((sel as u32 & 0x07) << 8) | (fid as u32);
    AdminSqe {
        opcode: OPC_GET_FEATURES,
        cid,
        cdw10,
        ..Default::default()
    }
}

/// Set Features — Power Management (FID 0x02, §5.31). `ps` is the
/// desired power state (0 = full performance). `wh` is the workload
/// hint (0 = no hint; values 1..7 are vendor-specific).
///
/// Linux ref: drivers/nvme/host/admin-cmd.c, nvme_set_features
pub fn set_features_power_management(cid: u16, ps: u8, wh: u8) -> AdminSqe {
    let cdw11 = ((wh as u32 & 0x07) << 5) | (ps as u32 & 0x1F);
    AdminSqe {
        opcode: OPC_SET_FEATURES,
        cid,
        cdw10: FID_POWER_MANAGEMENT as u32,
        cdw11,
        ..Default::default()
    }
}

/// Set Features — Async Event Configuration (FID 0x0B, §5.31).
/// `aec` is the AEC bitmap (NVMe 2.0c §5.31 table table 295):
///   - bit 0  = SMART / Health Critical Warnings
///   - bit 1  = Namespace Attribute Changed
///   - bit 2  = Firmware Activation Starting
///   - bit 3  = Telemetry Log Changed
///   - bit 5  = Endurance Group Event Aggregation
///
/// Linux ref: drivers/nvme/host/core.c:nvme_configure_aen
pub fn set_features_async_event_config(cid: u16, aec: u32) -> AdminSqe {
    AdminSqe {
        opcode: OPC_SET_FEATURES,
        cid,
        cdw10: FID_ASYNC_EVENT_CONFIG as u32,
        cdw11: aec,
        ..Default::default()
    }
}

/// Async Event Request (§5.2, opcode 0x0C). No CDW fields beyond the
/// standard header. Submission posts an outstanding request slot; the
/// completion arrives only when an async event fires. Per spec
/// recommendation, the host keeps ≥4 outstanding AERs at all times.
///
/// Completion CDW0 bits (from CQE.cmd_specific):
///   - bits[2:0]  = Async Event Type
///                  0x00 = Error status
///                  0x01 = SMART / Health status
///                  0x02 = Notice
///                  0x06 = NVM Command Set specific
///   - bits[15:8] = Async Event Information (event-type specific)
///   - bits[31:24] = Log Page Identifier (which log to read for detail)
///
/// Linux ref: drivers/nvme/host/core.c:nvme_async_event
pub fn async_event_request(cid: u16) -> AdminSqe {
    AdminSqe::new(OPC_ASYNC_EVENT_REQUEST).with_cid(cid)
}

// ── Identify Controller typed decoder ──────────────────────────────

/// Typed, fully-decoded IDENTIFY CONTROLLER data structure.
///
/// Layout per NVMe Base Spec 2.0c §5.17.2.1 (table 111).
/// Only fields needed for bring-up + diagnostics are named here;
/// the 4 KiB buffer is not kept — callers decode into this struct
/// then drop the DMA buffer.
///
/// Linux ref: drivers/nvme/host/nvme.h:nvme_id_ctrl
#[derive(Clone, Debug)]
pub struct IdentifyControllerData {
    /// Vendor ID (bytes 0..1).
    pub vid: u16,
    /// Subsystem Vendor ID (bytes 2..3).
    pub ssvid: u16,
    /// Serial Number, ASCII space-padded, 20 bytes (bytes 4..23).
    pub sn: [u8; 20],
    /// Model Number, ASCII space-padded, 40 bytes (bytes 24..63).
    pub mn: [u8; 40],
    /// Firmware Revision, ASCII space-padded, 8 bytes (bytes 64..71).
    pub fr: [u8; 8],
    /// Maximum Data Transfer Size — log2 pages, 0 = no limit (byte 77).
    pub mdts: u8,
    /// Controller ID (bytes 78..79).
    pub cntlid: u16,
    /// Optional Admin Command Support bitmap (bytes 260..261).
    /// Bit 0 = Security Send/Receive; bit 1 = Format NVM; bit 2 = FW Activate.
    pub oacs: u16,
    /// Abort Command Limit (byte 262): max concurrent aborts - 1.
    pub acl: u8,
    /// Asynchronous Event Request Limit (byte 263): max in-flight AERs - 1.
    pub aerl: u8,
    /// Firmware Updates (byte 264): slot count + activation sans reset.
    pub frmw: u8,
    /// Number of Power States Supported (byte 295): zero-based count.
    pub npss: u8,
    /// SQ Entry Size (byte 512): bits[3:0]=min, bits[7:4]=max (log2).
    pub sqes: u8,
    /// CQ Entry Size (byte 513).
    pub cqes: u8,
    /// Maximum Outstanding Commands (bytes 514..515).
    pub maxcmd: u16,
    /// Number of Namespaces (bytes 516..519).
    pub nn: u32,
}

impl IdentifyControllerData {
    /// Decode a 4-KiB IDENTIFY CONTROLLER buffer.
    ///
    /// Returns `None` if `buf` is shorter than the minimum 520 bytes
    /// needed to reach the `nn` field at offset 516.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 520 {
            return None;
        }
        let mut sn = [0u8; 20];
        let mut mn = [0u8; 40];
        let mut fr = [0u8; 8];
        sn.copy_from_slice(&buf[4..24]);
        mn.copy_from_slice(&buf[24..64]);
        fr.copy_from_slice(&buf[64..72]);
        Some(Self {
            vid: u16::from_le_bytes([buf[0], buf[1]]),
            ssvid: u16::from_le_bytes([buf[2], buf[3]]),
            sn,
            mn,
            fr,
            mdts: buf[77],
            cntlid: u16::from_le_bytes([buf[78], buf[79]]),
            oacs: u16::from_le_bytes([buf[260], buf[261]]),
            acl: buf[262],
            aerl: buf[263],
            frmw: buf[264],
            npss: buf[295],
            sqes: buf[512],
            cqes: buf[513],
            maxcmd: u16::from_le_bytes([buf[514], buf[515]]),
            nn: u32::from_le_bytes([buf[516], buf[517], buf[518], buf[519]]),
        })
    }

    /// True if the controller advertises Format NVM support (OACS bit 1).
    pub fn supports_format_nvm(&self) -> bool {
        (self.oacs & (1 << 1)) != 0
    }
}

/// Encode a minimal IDENTIFY CONTROLLER response buffer for testing.
/// Fields not present in `IdentifyControllerData` remain zero.
pub fn encode_identify_controller(d: &IdentifyControllerData) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; 4096];
    buf[0..2].copy_from_slice(&d.vid.to_le_bytes());
    buf[2..4].copy_from_slice(&d.ssvid.to_le_bytes());
    buf[4..24].copy_from_slice(&d.sn);
    buf[24..64].copy_from_slice(&d.mn);
    buf[64..72].copy_from_slice(&d.fr);
    buf[77] = d.mdts;
    buf[78..80].copy_from_slice(&d.cntlid.to_le_bytes());
    buf[260..262].copy_from_slice(&d.oacs.to_le_bytes());
    buf[262] = d.acl;
    buf[263] = d.aerl;
    buf[264] = d.frmw;
    buf[295] = d.npss;
    buf[512] = d.sqes;
    buf[513] = d.cqes;
    buf[514..516].copy_from_slice(&d.maxcmd.to_le_bytes());
    buf[516..520].copy_from_slice(&d.nn.to_le_bytes());
    buf
}

// ── Identify Namespace typed decoder ───────────────────────────────

/// One LBA Format entry from the IDENTIFY NAMESPACE LBAF table.
///
/// Each entry is 4 bytes at offset `128 + index * 4`.
/// Layout per NVMe Base Spec 2.0c §5.17.2.1 table 114:
///   - bits[15:0]  = LBADS metadata size in bytes (MS)
///   - bits[23:16] = LBADS: log2(LBA data size in bytes)
///   - bits[25:24] = Relative Performance (0=best)
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LbaFormat {
    /// Metadata size in bytes for this format (often 0).
    pub ms: u16,
    /// log2 of the LBA data size in bytes; data_size = 1 << lbads.
    pub lbads: u8,
    /// Relative performance: 0=best, 3=degraded.
    pub rp: u8,
}

impl LbaFormat {
    /// LBA data size in bytes for this format.
    pub fn lba_bytes(&self) -> u32 {
        if self.lbads == 0 {
            512
        } else {
            1u32 << self.lbads
        }
    }
}

/// Typed IDENTIFY NAMESPACE data structure.
///
/// Layout per NVMe Base Spec 2.0c §5.17.2.1 table 114.
///
/// Linux ref: drivers/nvme/host/nvme.h:nvme_id_ns
#[derive(Clone, Debug, Default)]
pub struct IdentifyNamespaceData {
    /// Namespace Size: total capacity in LBAs (bytes 0..7).
    pub nsze: u64,
    /// Namespace Capacity: max usable LBAs at once (bytes 8..15).
    pub ncap: u64,
    /// Namespace Utilization: currently allocated LBAs (bytes 16..23).
    pub nuse: u64,
    /// Namespace Features (byte 24): bit 0 = thin provisioning.
    pub nsfeat: u8,
    /// Number of LBA Formats (byte 25): number of LBAF entries - 1.
    pub nlbaf: u8,
    /// Formatted LBA Size (byte 26): bits[3:0] = current LBAF index.
    pub flbas: u8,
    /// Metadata Capabilities (byte 27).
    pub mc: u8,
    /// Data Protection Capabilities (byte 28).
    pub dpc: u8,
    /// Data Protection Type Settings (byte 29).
    pub dps: u8,
    /// LBA Format table, up to 16 entries (bytes 128..191).
    pub lbaf: [LbaFormat; 16],
}

impl IdentifyNamespaceData {
    /// Decode a 4-KiB IDENTIFY NAMESPACE buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 192 {
            return None;
        }
        let nsze = u64::from_le_bytes(buf[0..8].try_into().ok()?);
        let ncap = u64::from_le_bytes(buf[8..16].try_into().ok()?);
        let nuse = u64::from_le_bytes(buf[16..24].try_into().ok()?);
        let nlbaf = buf[25];
        let count = (nlbaf as usize + 1).min(16);
        let mut lbaf = [LbaFormat::default(); 16];
        for i in 0..count {
            let off = 128 + i * 4;
            let ms = u16::from_le_bytes([buf[off], buf[off + 1]]);
            let lbads = buf[off + 2];
            let rp = buf[off + 3] & 0x03;
            lbaf[i] = LbaFormat { ms, lbads, rp };
        }
        Some(Self {
            nsze,
            ncap,
            nuse,
            nsfeat: buf[24],
            nlbaf,
            flbas: buf[26],
            mc: buf[27],
            dpc: buf[28],
            dps: buf[29],
            lbaf,
        })
    }

    /// The currently-active LBA format index (FLBAS bits[3:0]).
    pub fn active_lbaf_index(&self) -> usize {
        (self.flbas & 0x0F) as usize
    }

    /// LBA size in bytes for the currently-active format.
    pub fn lba_bytes(&self) -> u32 {
        self.lbaf[self.active_lbaf_index()].lba_bytes()
    }
}

/// Encode a minimal IDENTIFY NAMESPACE response buffer for testing.
pub fn encode_identify_namespace(d: &IdentifyNamespaceData) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; 4096];
    buf[0..8].copy_from_slice(&d.nsze.to_le_bytes());
    buf[8..16].copy_from_slice(&d.ncap.to_le_bytes());
    buf[16..24].copy_from_slice(&d.nuse.to_le_bytes());
    buf[24] = d.nsfeat;
    buf[25] = d.nlbaf;
    buf[26] = d.flbas;
    buf[27] = d.mc;
    buf[28] = d.dpc;
    buf[29] = d.dps;
    for i in 0..16 {
        let off = 128 + i * 4;
        buf[off..off + 2].copy_from_slice(&d.lbaf[i].ms.to_le_bytes());
        buf[off + 2] = d.lbaf[i].lbads;
        buf[off + 3] = d.lbaf[i].rp & 0x03;
    }
    buf
}

/// Decoded Async Event completion CDW0 (from CQE.cmd_specific).
///
/// Layout per NVMe Base Spec 2.0c §5.2 table 80:
///   - bits[2:0]   = Async Event Type
///   - bits[15:8]  = Async Event Information
///   - bits[31:24] = Log Page Identifier
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AsyncEventCompletion {
    /// Event type: 0=error, 1=SMART/health, 2=notice, 6=NVM-cmd-set.
    pub event_type: u8,
    /// Event-type–specific information byte.
    pub event_info: u8,
    /// Log Page Identifier — caller should issue Get Log Page for detail.
    pub log_page_id: u8,
}

impl AsyncEventCompletion {
    /// Decode from `CQE.cmd_specific`.
    pub fn from_cdw0(cdw0: u32) -> Self {
        Self {
            event_type: (cdw0 & 0x07) as u8,
            event_info: ((cdw0 >> 8) & 0xFF) as u8,
            log_page_id: ((cdw0 >> 24) & 0xFF) as u8,
        }
    }
}

// ── SMART / Health log decoder (§5.16.1.3 NVM CS 1.0c table 16) ────

/// Selected fields out of the 512-byte SMART/Health log page.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SmartLog {
    /// Critical Warning bitmap (offset 0).
    pub critical_warning: u8,
    /// Composite temperature in Kelvin (offsets 1..3, LE).
    pub composite_temperature_k: u16,
    /// Available spare percentage (offset 3).
    pub available_spare: u8,
    /// Available spare threshold percentage (offset 4).
    pub available_spare_threshold: u8,
    /// Percentage used (offset 5).
    pub percentage_used: u8,
    /// Power on hours — first 8 bytes of a 16-byte field (offset 128).
    pub power_on_hours: u64,
    /// Number of unsafe shutdowns — first 8 bytes (offset 160).
    pub unsafe_shutdowns: u64,
    /// Media + data integrity errors — first 8 bytes (offset 176).
    pub media_errors: u64,
}

impl SmartLog {
    /// Parse a 512-byte SMART/Health log buffer.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 192 {
            return None;
        }
        let composite_temperature_k = u16::from_le_bytes([buf[1], buf[2]]);
        // The integer fields below are 16 bytes wide on the wire; we
        // only surface the lower u64.
        let power_on_hours = u64::from_le_bytes(buf[128..136].try_into().expect("len"));
        let unsafe_shutdowns = u64::from_le_bytes(buf[160..168].try_into().expect("len"));
        let media_errors = u64::from_le_bytes(buf[176..184].try_into().expect("len"));
        Some(Self {
            critical_warning: buf[0],
            composite_temperature_k,
            available_spare: buf[3],
            available_spare_threshold: buf[4],
            percentage_used: buf[5],
            power_on_hours,
            unsafe_shutdowns,
            media_errors,
        })
    }

    /// Convert composite temperature to Celsius (rounded down).
    pub fn composite_temperature_c(self) -> i32 {
        self.composite_temperature_k as i32 - 273
    }
}

/// Build a 512-byte mock SMART/Health page from a SmartLog — useful
/// for round-trip tests when the controller isn't reachable.
pub fn encode_smart_log(s: SmartLog) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; 512];
    buf[0] = s.critical_warning;
    let temp = s.composite_temperature_k.to_le_bytes();
    buf[1] = temp[0];
    buf[2] = temp[1];
    buf[3] = s.available_spare;
    buf[4] = s.available_spare_threshold;
    buf[5] = s.percentage_used;
    buf[128..136].copy_from_slice(&s.power_on_hours.to_le_bytes());
    buf[160..168].copy_from_slice(&s.unsafe_shutdowns.to_le_bytes());
    buf[176..184].copy_from_slice(&s.media_errors.to_le_bytes());
    buf
}
