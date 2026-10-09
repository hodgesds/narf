//! vmxnet3 register offsets, command codes, sizing constants.
//!
//! All values come from VMware's GPL-2.0 `vmxnet3_defs.h`
//! (`/home/daniel/git/linux/drivers/net/vmxnet3/vmxnet3_defs.h`).

// ── BAR1 (VD) register offsets ──────────────────────────────────────
// `vmxnet3_defs.h`: "BAR 1" enum, offsets all 8-byte aligned.

/// Vmxnet3 Revision Report Selection — bitmap of revisions the host
/// supports. Driver writes back the bit for the revision it picked.
pub const REG_VRRS: u64 = 0x00;
/// UPT Version Report Selection — bitmap of UPT versions.
pub const REG_UVRS: u64 = 0x08;
/// Driver Shared Address — low 32 bits of the `Vmxnet3_DriverShared`
/// physical address. Must be written before DSAH.
pub const REG_DSAL: u64 = 0x10;
/// Driver Shared Address — high 32 bits.
pub const REG_DSAH: u64 = 0x18;
/// Command. Write a CMD code; for "get" class commands (≥ 0xF00D0000)
/// the readback returns the reply value.
pub const REG_CMD: u64 = 0x20;
/// MAC Address — low 32 bits.
pub const REG_MACL: u64 = 0x28;
/// MAC Address — high 16 bits (low 16 of the u32 readback).
pub const REG_MACH: u64 = 0x30;
/// Interrupt Cause Register — read returns latched cause bits.
pub const REG_ICR: u64 = 0x38;
/// Event Cause Register — `VMXNET3_ECR_*` bits.
pub const REG_ECR: u64 = 0x40;
/// Device capability register window (0x48..0x80 in 8-byte slots).
pub const REG_DCR: u64 = 0x48;
/// Passthru capability register window (0x88..0xB0 in 8-byte slots).
pub const REG_PTCR: u64 = 0x88;

// ── BAR0 (PT) register offsets ──────────────────────────────────────
// "BAR 0" enum in `vmxnet3_defs.h`.

/// Interrupt Mask Register — one 8-byte slot per vector. Write 0 to
/// unmask, 1 to mask. Slot N at offset `IMR + N * 8`.
pub const REG_IMR: u64 = 0x000;
/// Tx Producer Index doorbell. Write the new producer cursor (modulo
/// ring size) to nudge the device.
pub const REG_TXPROD: u64 = 0x600;
/// Rx Producer Index for ring 1.
pub const REG_RXPROD: u64 = 0x800;
/// Rx Producer Index for ring 2.
pub const REG_RXPROD2: u64 = 0xA00;

// ── CMD codes ───────────────────────────────────────────────────────
// `vmxnet3_defs.h` enums. "Set" class starts at 0xCAFE0000; "get" at
// 0xF00D0000.

pub const VMXNET3_CMD_ACTIVATE_DEV: u32 = 0xCAFE_0000;
pub const VMXNET3_CMD_QUIESCE_DEV: u32 = 0xCAFE_0001;
pub const VMXNET3_CMD_RESET_DEV: u32 = 0xCAFE_0002;
pub const VMXNET3_CMD_UPDATE_RX_MODE: u32 = 0xCAFE_0003;
pub const VMXNET3_CMD_UPDATE_MAC_FILTERS: u32 = 0xCAFE_0004;
pub const VMXNET3_CMD_UPDATE_VLAN_FILTERS: u32 = 0xCAFE_0005;
pub const VMXNET3_CMD_UPDATE_FEATURE: u32 = 0xCAFE_0009;

pub const VMXNET3_CMD_GET_QUEUE_STATUS: u32 = 0xF00D_0000;
pub const VMXNET3_CMD_GET_STATS: u32 = 0xF00D_0001;
pub const VMXNET3_CMD_GET_LINK: u32 = 0xF00D_0002;
pub const VMXNET3_CMD_GET_PERM_MAC_LO: u32 = 0xF00D_0003;
pub const VMXNET3_CMD_GET_PERM_MAC_HI: u32 = 0xF00D_0004;
pub const VMXNET3_CMD_GET_DID_LO: u32 = 0xF00D_0005;
pub const VMXNET3_CMD_GET_DID_HI: u32 = 0xF00D_0006;

// ── Magic / version ─────────────────────────────────────────────────

/// `VMXNET3_REV1_MAGIC` — stamp at `Vmxnet3_DriverShared.magic` so the
/// device recognises the layout as the REV_1 shape.
pub const VMXNET3_REV1_MAGIC: u32 = 3_133_079_265;

/// `VMXNET3_DRIVER_VERSION_NUM` from `vmxnet3_int.h` — encodes the
/// driver version string in BCD. We mirror the Linux 1.9 value so the
/// host telemetry has a sane reading.
pub const VMXNET3_DRIVER_VERSION_NUM: u32 = 0x0109_0000;

/// `VMXNET3_INIT_GEN` — generation bit value the driver stamps on
/// every freshly-prepared descriptor.
pub const VMXNET3_INIT_GEN: u32 = 1;

// ── Descriptor field shifts ─────────────────────────────────────────
// We avoid bitfields (no_std + endian-portable) and pack with masks.

/// TX descriptor: dword2 (word 2 of the 4-word desc) GEN bit position.
pub const TXD_GEN_SHIFT: u32 = 14;
pub const TXD_EOP_SHIFT: u32 = 12;
pub const TXD_CQ_SHIFT: u32 = 13;
/// TX descriptor: length field width (14 bits).
pub const TXD_LEN_MASK: u32 = (1 << 14) - 1;

/// RX descriptor: gen at bit 31 of `flags`.
pub const RXD_GEN_SHIFT: u32 = 31;
/// RX descriptor: btype at bit 14 of `flags`.
pub const RXD_BTYPE_SHIFT: u32 = 14;
/// RX descriptor: length is 14 bits.
pub const RXD_LEN_MASK: u32 = (1 << 14) - 1;
/// RxDesc.btype = HEAD (start of frame) for ring 1.
pub const VMXNET3_RXD_BTYPE_HEAD: u32 = 0;
/// RxDesc.btype = BODY (continuation) for ring 2.
pub const VMXNET3_RXD_BTYPE_BODY: u32 = 1;

/// RxCompDesc: gen bit at bit 31 of dword 3.
pub const RCD_GEN_SHIFT: u32 = 31;
/// TxCompDesc: gen bit at bit 31 of dword 3.
pub const TCD_GEN_SHIFT: u32 = 31;

// ── Ring sizing ─────────────────────────────────────────────────────
// Linux defaults from `vmxnet3_int.h`: TX 512, RX 1024, comp ring
// matched to the ring it tracks. Stage 2 uses 256 across the board
// so a single 4 KiB page covers each ring.

pub const TX_RING_LEN: usize = 256;
pub const RX_RING_LEN: usize = 256;
pub const TX_COMP_RING_LEN: usize = 256;
pub const RX_COMP_RING_LEN: usize = 256;

/// One TX descriptor is 16 bytes (`sizeof::<Vmxnet3_TxDesc>`).
pub const TX_DESC_BYTES: usize = 16;
/// One RX descriptor is 16 bytes.
pub const RX_DESC_BYTES: usize = 16;
/// One TX completion descriptor is 16 bytes.
pub const TX_COMP_DESC_BYTES: usize = 16;
/// One RX completion descriptor is 16 bytes.
pub const RX_COMP_DESC_BYTES: usize = 16;

pub const TX_RING_BYTES: usize = TX_RING_LEN * TX_DESC_BYTES;
pub const RX_RING_BYTES: usize = RX_RING_LEN * RX_DESC_BYTES;
pub const TX_COMP_RING_BYTES: usize = TX_COMP_RING_LEN * TX_COMP_DESC_BYTES;
pub const RX_COMP_RING_BYTES: usize = RX_COMP_RING_LEN * RX_COMP_DESC_BYTES;

/// Per-RX-slot DMA buffer size. Sized for a non-jumbo frame (1518) +
/// some headroom. Linux's default = 1536 for ring 1 head buffers.
pub const RX_BUF_LEN: usize = 1536;
/// Per-TX-slot DMA scratch buffer size. Same shape: one MTU's worth.
pub const TX_BUF_LEN: usize = 1536;
/// Default MTU advertised in `Vmxnet3_MiscConf.mtu`.
pub const DEFAULT_MTU: usize = 1500;

// ── RX mode bits ────────────────────────────────────────────────────
// `vmxnet3_defs.h` enum.

pub const VMXNET3_RXM_UCAST: u32 = 0x01;
pub const VMXNET3_RXM_MCAST: u32 = 0x02;
pub const VMXNET3_RXM_BCAST: u32 = 0x04;
pub const VMXNET3_RXM_ALL_MULTI: u32 = 0x08;
pub const VMXNET3_RXM_PROMISC: u32 = 0x10;

// ── intrCtrl bits ───────────────────────────────────────────────────
// `vmxnet3_defs.h` IntrConf.intrCtrl.

/// Disable all interrupts at the device until the driver clears this
/// bit + writes IMR. Stage 0 sets this so an early activate doesn't
/// inject IRQs we haven't wired yet.
pub const VMXNET3_IC_DISABLE_ALL: u32 = 0x01;

// ── ECR bits ────────────────────────────────────────────────────────

pub const VMXNET3_ECR_RQERR: u32 = 1 << 0;
pub const VMXNET3_ECR_TQERR: u32 = 1 << 1;
pub const VMXNET3_ECR_LINK: u32 = 1 << 2;
pub const VMXNET3_ECR_DIC: u32 = 1 << 3;
pub const VMXNET3_ECR_DEBUG: u32 = 1 << 4;
