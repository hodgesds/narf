//! `Vmxnet3_DriverShared` + queue-descriptor + descriptor types.
//!
//! All structures here mirror the on-wire layout the device DMAs.
//! Field shapes come from VMware's `vmxnet3_defs.h` (GPL-2.0); the
//! bitfields are flattened into plain integers because:
//!
//! 1. The Rust bit-field layout is unspecified between compilers.
//! 2. The device only cares about the in-memory image, which is the
//!    same as the Linux `__le*` image after little-endian byte order
//!    is applied (`#[repr(C)]` on a u32 in native order on x86_64).
//!
//! All offsets / sizes are pinned to byte counts the tests can assert
//! against. Field shifts/masks for the flag-packed words live in
//! [`crate::vmxnet3::regs`].
//!
//! Field names mirror the Linux header verbatim (camelCase) so a
//! reader can grep both trees together; we silence the snake_case
//! lint locally rather than re-mapping every name.
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

// ── Driver info & OS info ───────────────────────────────────────────

/// `Vmxnet3_GOSInfo` — packed 32-bit OS-information word the device
/// reads from `DriverShared.devRead.misc.driverInfo.gos`. Layout per
/// `vmxnet3_defs.h`:
///
/// ```text
///   bits[1:0]     gosBits  — 0=unknown, 1=32-bit, 2=64-bit
///   bits[5:2]     gosType  — 1=Linux, 2=Windows, …
///   bits[21:6]    gosVer
///   bits[31:22]   gosMisc
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Vmxnet3GOSInfo {
    pub bits: u32,
    pub gos_type: u32,
    pub gos_ver: u32,
    pub gos_misc: u32,
}

impl Vmxnet3GOSInfo {
    /// 64-bit no_std guest, `gosType` = 1 (Linux — vmxnet3 has no
    /// separate identifier for embedded kernels, and on every modern
    /// ESX the host treats anything that activates with `gos_type=1`
    /// + `gos_ver` set as a generic Linux-class guest).
    pub const fn for_narf() -> Self {
        Self {
            bits: super::regs::VMXNET3_DRIVER_VERSION_NUM & 0x3, // 0 = unknown is fine
            gos_type: 1,
            gos_ver: 0,
            gos_misc: 0,
        }
    }
    /// Pack into the u32 image the device reads.
    pub const fn to_raw(self) -> u32 {
        (self.bits & 0x3)
            | ((self.gos_type & 0xF) << 2)
            | ((self.gos_ver & 0xFFFF) << 6)
            | ((self.gos_misc & 0x3FF) << 22)
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3DriverInfo {
    pub version: u32,
    pub gos: u32, // packed Vmxnet3GOSInfo
    pub vmxnet3RevSpt: u32,
    pub uptVerSpt: u32,
}
const _: () = assert!(core::mem::size_of::<Vmxnet3DriverInfo>() == 16);

// ── MiscConf, IntrConf, RxFilterConf, VariableLenConfDesc ───────────

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3MiscConf {
    pub driverInfo: Vmxnet3DriverInfo,
    pub uptFeatures: u64,
    pub ddPA: u64,
    pub queueDescPA: u64,
    pub ddLen: u32,
    pub queueDescLen: u32,
    pub mtu: u32,
    pub maxNumRxSG: u16,
    pub numTxQueues: u8,
    pub numRxQueues: u8,
    pub reserved: [u32; 4],
}
// 16 + 8 + 8 + 8 + 4 + 4 + 4 + 2 + 1 + 1 + 16 = 72
const _: () = assert!(core::mem::size_of::<Vmxnet3MiscConf>() == 72);

/// `Vmxnet3_IntrConf` mirror. `modLevels` is a `u8[25]` (`VMXNET3_MAX_
/// INTRS`); reserved padding follows so the struct is 64-bit aligned.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Vmxnet3IntrConf {
    pub autoMask: u8,
    pub numIntrs: u8,
    pub eventIntrIdx: u8,
    pub modLevels: [u8; 25],
    pub intrCtrl: u32,
    pub reserved: [u32; 2],
}
const _: () = assert!(core::mem::size_of::<Vmxnet3IntrConf>() == 40);

impl Default for Vmxnet3IntrConf {
    fn default() -> Self {
        Self {
            autoMask: 0,
            numIntrs: 0,
            eventIntrIdx: 0,
            modLevels: [0; 25],
            intrCtrl: 0,
            reserved: [0; 2],
        }
    }
}

/// Multi-VLAN filter bitmap size. 4096 VLAN IDs / (4 bytes × 8 bits)
/// = 128 u32s. We never set any of these — Stage 2 leaves VLAN
/// filtering at the all-zero (no filter) state.
pub const VMXNET3_VFT_SIZE: usize = 4096 / (core::mem::size_of::<u32>() * 8);

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Vmxnet3RxFilterConf {
    pub rxMode: u32,
    pub mfTableLen: u16,
    pub _pad1: u16,
    pub mfTablePA: u64,
    pub vfTable: [u32; VMXNET3_VFT_SIZE],
}
const _: () = assert!(
    core::mem::size_of::<Vmxnet3RxFilterConf>()
        == 4 + 2 + 2 + 8 + 4 * VMXNET3_VFT_SIZE
);

impl Default for Vmxnet3RxFilterConf {
    fn default() -> Self {
        Self {
            rxMode: 0,
            mfTableLen: 0,
            _pad1: 0,
            mfTablePA: 0,
            vfTable: [0; VMXNET3_VFT_SIZE],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3VariableLenConfDesc {
    pub confVer: u32,
    pub confLen: u32,
    pub confPA: u64,
}
const _: () = assert!(core::mem::size_of::<Vmxnet3VariableLenConfDesc>() == 16);

// ── DSDevRead ──────────────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3DSDevRead {
    pub misc: Vmxnet3MiscConf,
    pub intrConf: Vmxnet3IntrConf,
    pub rxFilterConf: Vmxnet3RxFilterConf,
    pub rssConfDesc: Vmxnet3VariableLenConfDesc,
    pub pmConfDesc: Vmxnet3VariableLenConfDesc,
    pub pluginConfDesc: Vmxnet3VariableLenConfDesc,
}

// ── DriverShared head ──────────────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3DriverShared {
    pub magic: u32,
    pub size: u32,
    pub devRead: Vmxnet3DSDevRead,
    pub ecr: u32,
    pub reserved: u32,
    /// cu union — reserved1[4] / cmdInfo. Stage 2 leaves this zero.
    pub cu: [u32; 4],
    // `Vmxnet3_DSDevReadExt.intrConfExt` — REV6+ only. We don't fill
    // it; the device only reads it when negotiated revision ≥ 6.
}

// ── Queue descriptors (TxQueueDesc + RxQueueDesc) ─────────────────

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3TxQueueCtrl {
    pub txNumDeferred: u32,
    pub txThreshold: u32,
    pub reserved: u64,
}
const _: () = assert!(core::mem::size_of::<Vmxnet3TxQueueCtrl>() == 16);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3TxQueueConf {
    pub txRingBasePA: u64,
    pub dataRingBasePA: u64,
    pub compRingBasePA: u64,
    pub ddPA: u64,
    pub reserved: u64,
    pub txRingSize: u32,
    pub dataRingSize: u32,
    pub compRingSize: u32,
    pub ddLen: u32,
    pub intrIdx: u8,
    pub _pad1: u8,
    pub txDataRingDescSize: u16,
    pub _pad2: [u8; 4],
}
// 8*5 + 4*4 + 1 + 1 + 2 + 4 = 64
const _: () = assert!(core::mem::size_of::<Vmxnet3TxQueueConf>() == 64);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3QueueStatus {
    pub stopped: u8,
    pub _pad: [u8; 3],
    pub error: u32,
}
const _: () = assert!(core::mem::size_of::<Vmxnet3QueueStatus>() == 8);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UPT1TxStats {
    pub TSOPktsTxOK: u64,
    pub TSOBytesTxOK: u64,
    pub ucastPktsTxOK: u64,
    pub ucastBytesTxOK: u64,
    pub mcastPktsTxOK: u64,
    pub mcastBytesTxOK: u64,
    pub bcastPktsTxOK: u64,
    pub bcastBytesTxOK: u64,
    pub pktsTxError: u64,
    pub pktsTxDiscard: u64,
}
const _: () = assert!(core::mem::size_of::<UPT1TxStats>() == 80);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3LatencyConf {
    pub sampleRate: u16,
    pub pad: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3TxQueueTSConf {
    pub txTSRingBasePA: u64,
    pub txTSRingDescSize: u16,
    pub pad: u16,
    pub latencyConf: Vmxnet3LatencyConf,
}
const _: () = assert!(core::mem::size_of::<Vmxnet3TxQueueTSConf>() == 16);

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Vmxnet3TxQueueDesc {
    pub ctrl: Vmxnet3TxQueueCtrl,
    pub conf: Vmxnet3TxQueueConf,
    pub status: Vmxnet3QueueStatus,
    pub stats: UPT1TxStats,
    pub tsConf: Vmxnet3TxQueueTSConf,
    /// padding to 128-byte alignment (`vmxnet3_defs.h`: u8 _pad[72]).
    pub _pad: [u8; 72],
}
// 16 + 64 + 8 + 80 + 16 + 72 = 256
const _: () = assert!(core::mem::size_of::<Vmxnet3TxQueueDesc>() == 256);

impl Default for Vmxnet3TxQueueDesc {
    fn default() -> Self {
        Self {
            ctrl: Default::default(),
            conf: Default::default(),
            status: Default::default(),
            stats: Default::default(),
            tsConf: Default::default(),
            _pad: [0; 72],
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3RxQueueCtrl {
    pub updateRxProd: u8,
    pub _pad: [u8; 7],
    pub reserved: u64,
}
const _: () = assert!(core::mem::size_of::<Vmxnet3RxQueueCtrl>() == 16);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3RxQueueConf {
    pub rxRingBasePA: [u64; 2],
    pub compRingBasePA: u64,
    pub ddPA: u64,
    pub rxDataRingBasePA: u64,
    pub rxRingSize: [u32; 2],
    pub compRingSize: u32,
    pub ddLen: u32,
    pub intrIdx: u8,
    pub _pad1: u8,
    pub rxDataRingDescSize: u16,
    pub _pad2: [u8; 4],
}
// 16 + 8 + 8 + 8 + 8 + 4 + 4 + 1 + 1 + 2 + 4 = 64
const _: () = assert!(core::mem::size_of::<Vmxnet3RxQueueConf>() == 64);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct UPT1RxStats {
    pub LROPktsRxOK: u64,
    pub LROBytesRxOK: u64,
    pub ucastPktsRxOK: u64,
    pub ucastBytesRxOK: u64,
    pub mcastPktsRxOK: u64,
    pub mcastBytesRxOK: u64,
    pub bcastPktsRxOK: u64,
    pub bcastBytesRxOK: u64,
    pub pktsRxOutOfBuf: u64,
    pub pktsRxError: u64,
}
const _: () = assert!(core::mem::size_of::<UPT1RxStats>() == 80);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Vmxnet3RxQueueTSConf {
    pub rxTSRingBasePA: u64,
    pub rxTSRingDescSize: u16,
    pub pad: [u8; 6],
}
const _: () = assert!(core::mem::size_of::<Vmxnet3RxQueueTSConf>() == 16);

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Vmxnet3RxQueueDesc {
    pub ctrl: Vmxnet3RxQueueCtrl,
    pub conf: Vmxnet3RxQueueConf,
    pub status: Vmxnet3QueueStatus,
    pub stats: UPT1RxStats,
    pub tsConf: Vmxnet3RxQueueTSConf,
    pub _pad: [u8; 72],
}
// 16 + 64 + 8 + 80 + 16 + 72 = 256
const _: () = assert!(core::mem::size_of::<Vmxnet3RxQueueDesc>() == 256);

impl Default for Vmxnet3RxQueueDesc {
    fn default() -> Self {
        Self {
            ctrl: Default::default(),
            conf: Default::default(),
            status: Default::default(),
            stats: Default::default(),
            tsConf: Default::default(),
            _pad: [0; 72],
        }
    }
}

// ── TX / RX descriptors ────────────────────────────────────────────

/// `Vmxnet3_TxDesc`. The Linux header uses C bitfields; we keep the
/// underlying 32-bit words instead and stamp the bit positions via
/// `regs::TXD_*_SHIFT`.
///
/// Layout (16 bytes total):
///
/// ```text
///   offset 0..8    : addr (LE u64, buffer phys addr)
///   offset 8..12   : dword2 — len:14 | gen:1 | rsvd:17
///   offset 12..16  : dword3 — hlen:10 | om:2 | eop:1 | cq:1 | rsvd:1 | ti:1 | tci:16
/// ```
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Vmxnet3TxDesc {
    pub addr: u64,
    pub dword2: u32,
    pub dword3: u32,
}
const _: () = assert!(core::mem::size_of::<Vmxnet3TxDesc>() == 16);

impl Vmxnet3TxDesc {
    /// Build a single-buffer TX descriptor. `gen` is the driver's
    /// current generation bit; on each ring wrap the driver flips
    /// gen so the device can tell new entries from stale ones.
    pub const fn new(addr: u64, len: u32, gen: u32, eop: bool, cq: bool) -> Self {
        use super::regs::{TXD_CQ_SHIFT, TXD_EOP_SHIFT, TXD_GEN_SHIFT, TXD_LEN_MASK};
        let dword2 = (len & TXD_LEN_MASK) | ((gen & 1) << TXD_GEN_SHIFT);
        let mut dword3: u32 = 0;
        if eop {
            dword3 |= 1 << TXD_EOP_SHIFT;
        }
        if cq {
            dword3 |= 1 << TXD_CQ_SHIFT;
        }
        Self {
            addr,
            dword2,
            dword3,
        }
    }
}

/// `Vmxnet3_RxDesc`. 16 bytes.
///
/// ```text
///   offset 0..8    : addr (LE u64)
///   offset 8..12   : flags — len:14 | btype:1 | dtype:1 | rsvd:15 | gen:1
///   offset 12..16  : ext1 — reserved
/// ```
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Vmxnet3RxDesc {
    pub addr: u64,
    pub flags: u32,
    pub ext1: u32,
}
const _: () = assert!(core::mem::size_of::<Vmxnet3RxDesc>() == 16);

/// `Vmxnet3_TxCompDesc`. The device writes one per EOP TX descriptor.
/// `txdIdx` (bits[11:0] of dword0) identifies the EOP slot; `gen` at
/// dword3 bit 31 flips to indicate ownership.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Vmxnet3TxCompDesc {
    pub dword0: u32,
    pub ext2: u32,
    pub ext3: u32,
    pub dword3: u32,
}
const _: () = assert!(core::mem::size_of::<Vmxnet3TxCompDesc>() == 16);

/// `Vmxnet3_RxCompDesc`. 16 bytes, written by device for each
/// completed RX descriptor.
#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Vmxnet3RxCompDesc {
    pub dword0: u32, // rxdIdx:12, ext1:2, eop:1, sop:1, rqID:10, rssType:4, cnc:1, ext2:1
    pub rssHash: u32,
    pub dword2: u32, // len:14, err:1, ts:1, tci:16
    pub dword3: u32, // csum:16, tuc:1, udp:1, tcp:1, ipc:1, v6:1, v4:1, frg:1, fcs:1, type:7, gen:1
}
const _: () = assert!(core::mem::size_of::<Vmxnet3RxCompDesc>() == 16);
