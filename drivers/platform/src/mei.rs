//! Intel MEI / HECI — the host interface to the Converged Security
//! and Manageability Engine (CSME).
//!
//! ## Reference
//!
//! Linux v7.3-rc4 `drivers/misc/mei/` (GPL-2.0; NARF is
//! GPL-2.0-or-later so adaptation is permitted), checked against
//! revision `b90c984d615e8ce2af96f5b1411a962d83fed2ad`:
//!
//! - `hw-me-regs.h` — PCI device IDs, the four MMIO registers, the
//!   H_CSR / ME_CSR_HA bit fields, and the config-space firmware
//!   status registers.
//! - `hw-me.c`      — `mei_me_hw_config`, `mei_me_hw_reset`,
//!   `mei_me_host_set_ready`, `mei_hbuf_filled_slots`,
//!   `mei_me_count_full_read_slots`, `mei_me_hbuf_write`,
//!   `mei_me_read_slots`, `mei_me_irq_thread_handler`.
//! - `hw.h`         — `struct mei_msg_hdr`, the HBM command IDs and
//!   structures, `enum mei_hbm_status`, the host-bus-message version.
//! - `hbm.c`        — `mei_hbm_prop_req`, `mei_hbm_me_cl_add`, the
//!   client connect / disconnect / flow-control requests and
//!   responses, `mei_hbm_fw_disconnect_req`, `mei_hbm_dispatch`.
//! - `client.c`     — `mei_cl_link`, `mei_cl_connect`,
//!   `mei_cl_disconnect`, `mei_cl_set_disconnected`,
//!   `mei_cl_read_start`, `mei_cl_write`, `mei_cl_irq_write`,
//!   `mei_cl_tx_flow_ctrl_creds{,_reduce}`, `mei_cl_complete`.
//! - `interrupt.c`  — `mei_irq_read_handler`, `mei_cl_irq_read_msg`,
//!   `hdr_is_valid`, `mei_irq_write_handler`, `mei_connect_timeout`.
//! - `bus.c`        — `mei_cldev_enable` / `mei_cldev_disable`,
//!   `__mei_cl_send_timeout`, `__mei_cl_recv`.
//! - `init.c`       — `mei_stop`, `mei_reset`, `mei_restart`.
//!
//! ## Hardware this targets
//!
//! The Minisforum **MS-03** exposes CSME HECI-1 at PCI `00:16.0`
//! (`8086:e370`, "Panther Lake H"), which is the interface Linux's
//! `mei_me` binds. The board also shows a second HECI-class function
//! at `00:18.0` (`8086:e35d`); that ID is **not** in Linux's
//! `mei_me_pci_tbl`, nothing binds it there, and this driver does
//! not claim it either. Meteor Lake and Arrow Lake carry their HECI-1
//! at `8086:7e70` / `7f68` / `7770`; those are the functions the GSC
//! proxy client (`crate::mei_gsc_proxy`) binds to.
//!
//! ## What the hardware looks like
//!
//! HECI is four 32-bit MMIO registers in BAR0 and two circular
//! buffers measured in 4-byte *slots*:
//!
//! | offset | register    | direction                          |
//! |--------|-------------|------------------------------------|
//! | 0x00   | `H_CB_WW`   | host → firmware write window       |
//! | 0x04   | `H_CSR`     | host control/status (read-write)   |
//! | 0x08   | `ME_CB_RW`  | firmware → host read window        |
//! | 0x0C   | `ME_CSR_HA` | firmware control/status (read-only)|
//!
//! Each CSR packs the buffer depth (bits 31:24), write pointer
//! (23:16) and read pointer (15:8) alongside the ready / reset /
//! interrupt bits. The pointers are free-running bytes: the number of
//! filled slots is `(write_ptr - read_ptr)` **in `u8` wrapping
//! arithmetic**, which is why [`filled_slots`] does the subtraction
//! with `wrapping_sub` rather than a signed compare.
//!
//! All register access goes through [`HeciRegs`]: production uses the
//! mapped BAR ([`BarRegs`]); the smokes drive the identical protocol
//! code against a register-level CSME model (`crate::mei_model`).
//!
//! ## Scope
//!
//! Link-level bring-up and the host bus message (HBM) handshake:
//!
//! 1. Map BAR0, latch the host buffer depth from `H_CSR.H_CBD`.
//! 2. Reset the link (`H_RST`), wait for `ME_CSR_HA.ME_RDY`, release
//!    the reset, then publish `H_RDY`.
//! 3. Send `HOST_START_REQ_CMD` with HBM version 2.2 and read the
//!    `HOST_START_RES_CMD` reply.
//! 4. Send `HOST_ENUM_REQ_CMD` and keep the 256-bit bitmap of
//!    firmware clients the response carries.
//! 5. Walk the bitmap with `HOST_CLIENT_PROPERTIES_REQ_CMD`, one
//!    address at a time in address order (`mei_hbm_prop_req`), and
//!    keep each client's UUID, MTU and flags.
//! 6. Read the firmware status words out of config space for the
//!    boot transcript.
//!
//! On top of that, the per-client message layer of `client.c` /
//! `bus.c`: link a host client and connect it to a firmware client
//! ([`MeiDevice::cl_connect`]), per-client TX/RX flow-control
//! credits, blocking framed send / receive with fragmentation
//! ([`MeiDevice::cl_send`] / [`MeiDevice::cl_recv`]), disconnect in
//! both directions, and teardown on device loss, protocol error and
//! power-down ([`MeiDevice::power_down`]). The `/dev/mei0` character
//! device is **not** implemented; the only consumer is the GSC proxy
//! client.
//!
//! ## Polling instead of interrupts
//!
//! The driver keeps `H_IE` clear and runs polled, the way Linux's
//! `mei_me_hw_use_polling` path does. `mei_me_irq_thread_handler`'s
//! work — drain the firmware buffer, dispatch each message, then
//! write whatever the host owes firmware once the host buffer is
//! empty — runs as [`MeiDevice`]'s service step, called under the
//! link lock from every bounded wait. No lock is held across a wait.
//!
//! ## Threat assumptions and what is refused
//!
//! The CSME is a separate security engine; the host trusts it to
//! *exist*, not to be well-formed. Every firmware message is length-
//! and state-checked before it changes host state, and anything the
//! driver has not reasoned about is refused rather than guessed at:
//!
//! - **HBM features never negotiated** — `MEI_HBM_CAPABILITIES`, the
//!   DMA ring, vtags, the GSC extended header, power-gating isolation,
//!   notifications, client DMA, dynamic client add. NARF never sends
//!   their requests (Linux sends the capability and DMA-setup requests
//!   for HBM ≥ 2.1/2.2), so a header with `extended` or `dma_ring` set
//!   or a bus message for any of them is a protocol violation: the link
//!   goes [`MeiDevState::Lost`]. Linux answers its protocol errors
//!   with a link reset; NARF does not re-run bring-up on its own (see
//!   [`MeiDevice::restart`]).
//! - **Fixed-address clients** are refused (`-EOPNOTSUPP`): they skip
//!   connect and flow control, and nothing in NARF needs one.
//! - **A properties response for a different address** than the one
//!   asked for is refused (Linux continues the walk from the address
//!   firmware reports). The walk's failure leaves the client table
//!   empty, so every connect refuses with `-ENOTTY`; it does not fail
//!   link bring-up, which keeps the pre-existing probe behaviour.
//! - **Unbounded waits.** Linux's `mei_cldev_send` / `mei_cldev_recv`
//!   wait without a timeout; a polled kernel cannot, so both are
//!   bounded by [`MeiTimeouts::cl_io_ms`] and fail with `-ETIME`
//!   (the errno Linux's `_timeout` variants return).
//! - Message payloads are never interpreted here. The host buffer is
//!   only written while empty (`mei_hbuf_acquire`), firmware-supplied
//!   lengths are bounded by the receive buffer (`-EMSGSIZE`), and an
//!   all-ones register read is device loss, not data.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_bus::{map_bar, BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::sync::IrqSafeSpinLock;

// ── PCI device IDs ──────────────────────────────────────────────────
//
// Linux `hw-me-regs.h`. Only the recent PCH generations are listed;
// the register layout below has been stable since Cannon Lake, but
// claiming a controller we have not reasoned about buys nothing.

/// Intel.
pub const MEI_VENDOR: u16 = 0x8086;

/// Cannon Lake Point H.
pub const MEI_DEV_CNP_H: u16 = 0xA360;
/// Comet Lake Point LP.
pub const MEI_DEV_CMP_LP: u16 = 0x02E0;
/// Comet Lake Point H.
pub const MEI_DEV_CMP_H: u16 = 0x06E0;
/// Tiger Lake Point LP.
pub const MEI_DEV_TGP_LP: u16 = 0xA0E0;
/// Tiger Lake Point H.
pub const MEI_DEV_TGP_H: u16 = 0x43E0;
/// Alder Lake Point S.
pub const MEI_DEV_ADP_S: u16 = 0x7AE8;
/// Alder Lake Point LP.
pub const MEI_DEV_ADP_LP: u16 = 0x7A60;
/// Alder Lake Point P.
pub const MEI_DEV_ADP_P: u16 = 0x51E0;
/// Alder Lake Point N.
pub const MEI_DEV_ADP_N: u16 = 0x54E0;
/// Raptor Lake Point S.
pub const MEI_DEV_RPL_S: u16 = 0x7A68;
/// Meteor Lake Point M.
pub const MEI_DEV_MTL_M: u16 = 0x7E70;
/// Arrow Lake Point S.
pub const MEI_DEV_ARL_S: u16 = 0x7F68;
/// Arrow Lake Point H.
pub const MEI_DEV_ARL_H: u16 = 0x7770;
/// Lunar Lake Point M.
pub const MEI_DEV_LNL_M: u16 = 0xA870;
/// Panther Lake H — the MS-03's HECI-1 at `00:16.0`.
pub const MEI_DEV_PTL_H: u16 = 0xE370;
/// Panther Lake P.
pub const MEI_DEV_PTL_P: u16 = 0xE470;
/// Wildcat Lake P.
pub const MEI_DEV_WCL_P: u16 = 0x4D70;

/// Every device ID this driver claims, in one `const` so
/// `register_pci_driver` and the match-table smoke cannot drift.
pub const SUPPORTED_DEVICE_IDS: &[u16] = &[
    MEI_DEV_CNP_H,
    MEI_DEV_CMP_LP,
    MEI_DEV_CMP_H,
    MEI_DEV_TGP_LP,
    MEI_DEV_TGP_H,
    MEI_DEV_ADP_S,
    MEI_DEV_ADP_LP,
    MEI_DEV_ADP_P,
    MEI_DEV_ADP_N,
    MEI_DEV_RPL_S,
    MEI_DEV_MTL_M,
    MEI_DEV_ARL_S,
    MEI_DEV_ARL_H,
    MEI_DEV_LNL_M,
    MEI_DEV_PTL_H,
    MEI_DEV_PTL_P,
    MEI_DEV_WCL_P,
];

/// `true` iff this driver claims `did`.
pub fn is_supported_device(did: u16) -> bool {
    SUPPORTED_DEVICE_IDS.contains(&did)
}

// ── MMIO registers (BAR0) ───────────────────────────────────────────

/// HECI puts its register block in BAR0.
pub const MEI_BAR: u8 = 0;

/// `H_CB_WW` — Host Circular Buffer Write Window. Write-only; each
/// 32-bit store pushes one slot towards firmware.
pub const REG_H_CB_WW: u64 = 0x00;
/// `H_CSR` — Host Control Status.
pub const REG_H_CSR: u64 = 0x04;
/// `ME_CB_RW` — ME Circular Buffer Read Window. Read-only; each
/// 32-bit load pops one slot from firmware.
pub const REG_ME_CB_RW: u64 = 0x08;
/// `ME_CSR_HA` — ME Control Status, Host Access. Read-only.
pub const REG_ME_CSR_HA: u64 = 0x0C;
/// `H_D0I3C` — D0i3 control.
pub const REG_H_D0I3C: u64 = 0x800;

// H_CSR fields.
/// Host circular-buffer depth, in slots (bits 31:24).
pub const H_CBD: u32 = 0xFF00_0000;
/// Host circular-buffer write pointer (bits 23:16).
pub const H_CBWP: u32 = 0x00FF_0000;
/// Host circular-buffer read pointer (bits 15:8).
pub const H_CBRP: u32 = 0x0000_FF00;
/// Host Reset.
pub const H_RST: u32 = 0x0000_0010;
/// Host Ready.
pub const H_RDY: u32 = 0x0000_0008;
/// Host Interrupt Generate — the doorbell.
pub const H_IG: u32 = 0x0000_0004;
/// Host Interrupt Status (write-1-to-clear).
pub const H_IS: u32 = 0x0000_0002;
/// Host Interrupt Enable.
pub const H_IE: u32 = 0x0000_0001;
/// Host D0i3 Interrupt Enable.
pub const H_D0I3C_IE: u32 = 0x0000_0020;
/// Host D0i3 Interrupt Status.
pub const H_D0I3C_IS: u32 = 0x0000_0040;
/// All interrupt-enable bits of `H_CSR`.
pub const H_CSR_IE_MASK: u32 = H_IE | H_D0I3C_IE;
/// All interrupt-status bits of `H_CSR`.
pub const H_CSR_IS_MASK: u32 = H_IS | H_D0I3C_IS;

// ME_CSR_HA fields — same layout, host-read-only.
/// ME circular-buffer depth (bits 31:24).
pub const ME_CBD_HRA: u32 = 0xFF00_0000;
/// ME circular-buffer write pointer (bits 23:16).
pub const ME_CBWP_HRA: u32 = 0x00FF_0000;
/// ME circular-buffer read pointer (bits 15:8).
pub const ME_CBRP_HRA: u32 = 0x0000_FF00;
/// ME Reset.
pub const ME_RST_HRA: u32 = 0x0000_0010;
/// ME Ready.
pub const ME_RDY_HRA: u32 = 0x0000_0008;
/// ME Interrupt Generate.
pub const ME_IG_HRA: u32 = 0x0000_0004;
/// ME Interrupt Status.
pub const ME_IS_HRA: u32 = 0x0000_0002;
/// ME Interrupt Enable.
pub const ME_IE_HRA: u32 = 0x0000_0001;

/// One circular-buffer slot is a `u32`. `MEI_SLOT_SIZE` in Linux.
pub const MEI_SLOT_SIZE: usize = 4;

// ── Firmware status registers (PCI config space) ────────────────────

/// `PCI_CFG_HFS_1` — the primary Host Firmware Status word.
pub const PCI_CFG_HFS_1: u16 = 0x40;
/// `PCI_CFG_HFS_1_D0I3_MSK` — firmware supports D0i3.
pub const PCI_CFG_HFS_1_D0I3: u32 = 0x8000_0000;
/// `PCI_CFG_HFS_2`.
pub const PCI_CFG_HFS_2: u16 = 0x48;
/// `PCI_CFG_HFS_3`.
pub const PCI_CFG_HFS_3: u16 = 0x60;
/// `PCI_CFG_HFS_4`.
pub const PCI_CFG_HFS_4: u16 = 0x64;
/// `PCI_CFG_HFS_5`.
pub const PCI_CFG_HFS_5: u16 = 0x68;
/// `PCI_CFG_HFS_6`.
pub const PCI_CFG_HFS_6: u16 = 0x6C;

// ── Host Bus Messages ───────────────────────────────────────────────

/// HBM version this driver advertises — `HBM_MAJOR_VERSION`.
pub const HBM_MAJOR_VERSION: u8 = 2;
/// `HBM_MINOR_VERSION`.
pub const HBM_MINOR_VERSION: u8 = 2;

/// Mask selecting the opcode out of an HBM command byte.
pub const MEI_HBM_CMD_OP_MSK: u8 = 0x7F;
/// Bit set by firmware on a response.
pub const MEI_HBM_CMD_RES_MSK: u8 = 0x80;

/// `HOST_START_REQ_CMD`.
pub const HOST_START_REQ_CMD: u8 = 0x01;
/// `HOST_START_RES_CMD`.
pub const HOST_START_RES_CMD: u8 = 0x81;
/// `HOST_STOP_REQ_CMD`.
pub const HOST_STOP_REQ_CMD: u8 = 0x02;
/// `HOST_STOP_RES_CMD`.
pub const HOST_STOP_RES_CMD: u8 = 0x82;
/// `ME_STOP_REQ_CMD` — firmware is going away.
pub const ME_STOP_REQ_CMD: u8 = 0x03;
/// `HOST_ENUM_REQ_CMD`.
pub const HOST_ENUM_REQ_CMD: u8 = 0x04;
/// `HOST_ENUM_RES_CMD`.
pub const HOST_ENUM_RES_CMD: u8 = 0x84;
/// `HOST_CLIENT_PROPERTIES_REQ_CMD`.
pub const HOST_CLIENT_PROPERTIES_REQ_CMD: u8 = 0x05;
/// `HOST_CLIENT_PROPERTIES_RES_CMD`.
pub const HOST_CLIENT_PROPERTIES_RES_CMD: u8 = 0x85;
/// `CLIENT_CONNECT_REQ_CMD`.
pub const CLIENT_CONNECT_REQ_CMD: u8 = 0x06;
/// `CLIENT_CONNECT_RES_CMD`.
pub const CLIENT_CONNECT_RES_CMD: u8 = 0x86;
/// `CLIENT_DISCONNECT_REQ_CMD` — sent by the host, and by firmware
/// when *it* drops a connection.
pub const CLIENT_DISCONNECT_REQ_CMD: u8 = 0x07;
/// `CLIENT_DISCONNECT_RES_CMD`.
pub const CLIENT_DISCONNECT_RES_CMD: u8 = 0x87;
/// `MEI_FLOW_CONTROL_CMD` — one credit for one message, either
/// direction.
pub const MEI_FLOW_CONTROL_CMD: u8 = 0x08;

/// `DRIVER_STOP_REQUEST` (`enum mei_stop_reason_types`).
pub const DRIVER_STOP_REQUEST: u8 = 0x00;

// enum mei_hbm_status / mei_cl_connect_status.
/// `MEI_HBMS_SUCCESS`.
pub const MEI_HBMS_SUCCESS: u8 = 0;
/// `MEI_HBMS_CLIENT_NOT_FOUND`.
pub const MEI_HBMS_CLIENT_NOT_FOUND: u8 = 1;
/// `MEI_HBMS_ALREADY_EXISTS` (`MEI_CL_CONN_ALREADY_STARTED`).
pub const MEI_HBMS_ALREADY_EXISTS: u8 = 2;
/// `MEI_HBMS_REJECTED` (`MEI_CL_CONN_OUT_OF_RESOURCES`).
pub const MEI_HBMS_REJECTED: u8 = 3;
/// `MEI_HBMS_INVALID_PARAMETER` (`MEI_CL_CONN_MESSAGE_SMALL`).
pub const MEI_HBMS_INVALID_PARAMETER: u8 = 4;
/// `MEI_HBMS_NOT_ALLOWED` (`MEI_CL_CONN_NOT_ALLOWED`).
pub const MEI_HBMS_NOT_ALLOWED: u8 = 5;

/// The HBM "address" every bus message is sent to and from — both
/// `me_addr` and `host_addr` are 0 for bus messages, which is what
/// distinguishes them from client traffic.
pub const MEI_HBM_ADDR: u8 = 0;

/// Bytes in the client bitmap a `HOST_ENUM_RES_CMD` carries: 256
/// firmware addresses, one bit each.
pub const MEI_CLIENTS_MAX: usize = 256;
/// Size of that bitmap in bytes.
pub const HBM_CLIENT_BITMAP_BYTES: usize = MEI_CLIENTS_MAX / 8;

/// `sizeof(struct mei_client_properties)`.
pub const MEI_CLIENT_PROPERTIES_LEN: usize = 24;
/// `sizeof(struct hbm_props_response)`: four header bytes plus the
/// properties.
pub const HBM_PROPS_RESPONSE_LEN: usize = 4 + MEI_CLIENT_PROPERTIES_LEN;
/// `sizeof(struct hbm_client_connect_request)` — also the connect /
/// disconnect response and the disconnect request.
pub const HBM_CLIENT_CONNECT_LEN: usize = 4;
/// `sizeof(struct hbm_flow_control)`: `hbm_cmd`, `me_addr`,
/// `host_addr`, five reserved bytes.
pub const HBM_FLOW_CONTROL_LEN: usize = 8;

/// `MEI_MSG_MAX_LEN_MASK` (`GENMASK(9, 0)`), applied to the host
/// buffer's byte size in `mei_cl_write` / `mei_cl_irq_write`.
pub const MEI_MSG_MAX_LEN_MASK: usize = 0x3FF;
/// Largest payload one packet carries here: the header's 9-bit
/// `length`, rounded down to a whole slot so a fragment never leaves
/// a partial slot behind. Linux relies on the host buffer depth
/// (128 slots on the parts above) to stay under 512 bytes; NARF also
/// caps it so a deeper buffer can never wrap the length field.
pub const MEI_MSG_MAX_PAYLOAD: usize = 0x1FF & !(MEI_SLOT_SIZE - 1);

/// `struct mei_msg_hdr` — one 32-bit word.
///
/// Linux declares it as a bitfield over a `u32`; the packing, from
/// least-significant bit upwards, is `me_addr:8`, `host_addr:8`,
/// `length:9`, `reserved:3`, `extended:1`, `dma_ring:1`,
/// `internal:1`, `msg_complete:1`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MeiMsgHdr {
    pub me_addr: u8,
    pub host_addr: u8,
    /// Payload length in bytes; 9 bits, so at most 511.
    pub length: u16,
    pub extended: bool,
    pub dma_ring: bool,
    pub internal: bool,
    /// Set on the last packet of a message.
    pub msg_complete: bool,
}

/// The header's three reserved bits (27:25).
pub const MEI_MSG_HDR_RESERVED: u32 = 0x0E00_0000;

impl MeiMsgHdr {
    /// Encode to the 32-bit word written into `H_CB_WW`.
    pub const fn to_u32(self) -> u32 {
        (self.me_addr as u32)
            | ((self.host_addr as u32) << 8)
            | (((self.length as u32) & 0x1FF) << 16)
            | ((self.extended as u32) << 28)
            | ((self.dma_ring as u32) << 29)
            | ((self.internal as u32) << 30)
            | ((self.msg_complete as u32) << 31)
    }

    /// Decode a header word read out of `ME_CB_RW`.
    pub const fn from_u32(w: u32) -> Self {
        Self {
            me_addr: (w & 0xFF) as u8,
            host_addr: ((w >> 8) & 0xFF) as u8,
            length: ((w >> 16) & 0x1FF) as u16,
            extended: (w >> 28) & 1 != 0,
            dma_ring: (w >> 29) & 1 != 0,
            internal: (w >> 30) & 1 != 0,
            msg_complete: (w >> 31) & 1 != 0,
        }
    }

    /// A complete, single-packet host bus message of `length` bytes.
    pub const fn bus_message(length: u16) -> Self {
        Self {
            me_addr: MEI_HBM_ADDR,
            host_addr: MEI_HBM_ADDR,
            length,
            extended: false,
            dma_ring: false,
            internal: false,
            msg_complete: true,
        }
    }

    /// `hdr_is_hbm` — a host bus message.
    pub const fn is_hbm(self) -> bool {
        self.me_addr == 0 && self.host_addr == 0
    }

    /// `hdr_is_fixed` — addressed to a fixed-address firmware client.
    pub const fn is_fixed(self) -> bool {
        self.host_addr == 0 && self.me_addr != 0
    }
}

/// `interrupt.c::hdr_is_valid`, tightened: a zero word or set reserved
/// bits are `-EBADMSG` there, and NARF also refuses the `extended` and
/// `dma_ring` forms because it never negotiates the features that
/// produce them.
pub const fn hdr_word_is_acceptable(word: u32) -> bool {
    if word == 0 || word & MEI_MSG_HDR_RESERVED != 0 {
        return false;
    }
    let hdr = MeiMsgHdr::from_u32(word);
    !hdr.extended && !hdr.dma_ring
}

/// Number of 4-byte slots a message of `bytes` occupies, rounded up.
/// `mei_data2slots` in Linux.
pub const fn data_to_slots(bytes: usize) -> u32 {
    bytes.div_ceil(MEI_SLOT_SIZE) as u32
}

/// Filled slots in a circular buffer, given its CSR word and the
/// shifts for its write / read pointers.
///
/// The pointers are free-running 8-bit counters, so the difference
/// must wrap. Comparing them as plain integers would report a
/// hugely negative (or, unsigned, hugely positive) count every time
/// the write pointer wraps past 0xFF.
pub const fn filled_slots(csr: u32, wp_shift: u32, rp_shift: u32) -> u8 {
    let write_ptr = ((csr >> wp_shift) & 0xFF) as u8;
    let read_ptr = ((csr >> rp_shift) & 0xFF) as u8;
    write_ptr.wrapping_sub(read_ptr)
}

/// Filled slots in the host (write) buffer — `mei_hbuf_filled_slots`.
pub const fn host_filled_slots(hcsr: u32) -> u8 {
    filled_slots(hcsr, 16, 8)
}

/// Filled slots in the ME (read) buffer —
/// `mei_me_count_full_read_slots`.
pub const fn me_filled_slots(mecsr: u32) -> u8 {
    filled_slots(mecsr, 16, 8)
}

/// Host buffer depth in slots, from `H_CSR.H_CBD`.
pub const fn host_buffer_depth(hcsr: u32) -> u8 {
    ((hcsr & H_CBD) >> 24) as u8
}

/// ME buffer depth in slots, from `ME_CSR_HA.ME_CBD_HRA`.
pub const fn me_buffer_depth(mecsr: u32) -> u8 {
    ((mecsr & ME_CBD_HRA) >> 24) as u8
}

/// Decoded `HOST_START_RES_CMD` payload —
/// `struct hbm_host_version_response`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HbmVersionResponse {
    /// Firmware accepted the version we proposed.
    pub host_version_supported: bool,
    /// Highest HBM version firmware supports.
    pub me_major: u8,
    pub me_minor: u8,
}

impl HbmVersionResponse {
    /// Decode the 4-byte response body. `struct hbm_version` is
    /// `{ minor_version, major_version }` — minor first.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 || buf[0] != HOST_START_RES_CMD {
            return None;
        }
        Some(Self {
            host_version_supported: buf[1] != 0,
            me_minor: buf[2],
            me_major: buf[3],
        })
    }
}

// ── Firmware client properties ──────────────────────────────────────

/// A firmware client's protocol name: `uuid_le`, in wire byte order.
pub type MeiUuid = [u8; 16];

/// `UUID_LE(a, b, c, d0..d7)`: `a`, `b` and `c` are stored little-
/// endian, `d` verbatim — the order the firmware puts on the wire.
pub const fn uuid_le(a: u32, b: u16, c: u16, d: [u8; 8]) -> MeiUuid {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let c = c.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d[0], d[1], d[2], d[3], d[4], d[5], d[6],
        d[7],
    ]
}

/// `struct mei_client_properties` (packed, 24 bytes):
///
/// | offset | field                                          |
/// |--------|------------------------------------------------|
/// | 0      | `protocol_name` (`uuid_le`)                    |
/// | 16     | `protocol_version`                             |
/// | 17     | `max_number_of_connections`                    |
/// | 18     | `fixed_address`                                |
/// | 19     | bit 0 `single_recv_buf`, bit 1 `vt_supported`  |
/// | 20     | `max_msg_length` (little-endian `u32`)         |
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct MeiClientProperties {
    pub protocol_name: MeiUuid,
    pub protocol_version: u8,
    pub max_number_of_connections: u8,
    /// Non-zero for a fixed-address client.
    pub fixed_address: u8,
    /// All connections share one receive buffer: firmware grants TX
    /// credits to the firmware client, not to each connection.
    pub single_recv_buf: bool,
    pub vt_supported: bool,
    /// The client's MTU (`mei_cl_mtu`).
    pub max_msg_length: u32,
}

impl MeiClientProperties {
    /// Decode the 24-byte structure.
    pub fn parse(b: &[u8]) -> Option<Self> {
        if b.len() < MEI_CLIENT_PROPERTIES_LEN {
            return None;
        }
        let mut protocol_name = [0u8; 16];
        protocol_name.copy_from_slice(&b[..16]);
        Some(Self {
            protocol_name,
            protocol_version: b[16],
            max_number_of_connections: b[17],
            fixed_address: b[18],
            single_recv_buf: b[19] & 0x01 != 0,
            vt_supported: b[19] & 0x02 != 0,
            max_msg_length: u32::from_le_bytes([b[20], b[21], b[22], b[23]]),
        })
    }

    /// Encode the 24-byte structure (used by the device model).
    pub fn to_bytes(self) -> [u8; MEI_CLIENT_PROPERTIES_LEN] {
        let mut b = [0u8; MEI_CLIENT_PROPERTIES_LEN];
        b[..16].copy_from_slice(&self.protocol_name);
        b[16] = self.protocol_version;
        b[17] = self.max_number_of_connections;
        b[18] = self.fixed_address;
        b[19] = (self.single_recv_buf as u8) | ((self.vt_supported as u8) << 1);
        b[20..24].copy_from_slice(&self.max_msg_length.to_le_bytes());
        b
    }
}

/// Decoded `HOST_CLIENT_PROPERTIES_RES_CMD` —
/// `struct hbm_props_response`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HbmPropsResponse {
    pub me_addr: u8,
    pub status: u8,
    /// Present when the response carried the full structure.
    pub props: Option<MeiClientProperties>,
}

impl HbmPropsResponse {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 || buf[0] != HOST_CLIENT_PROPERTIES_RES_CMD {
            return None;
        }
        let props = if buf.len() >= HBM_PROPS_RESPONSE_LEN {
            MeiClientProperties::parse(&buf[4..HBM_PROPS_RESPONSE_LEN])
        } else {
            None
        };
        Some(Self {
            me_addr: buf[1],
            status: buf[2],
            props,
        })
    }
}

/// A firmware client as the walk recorded it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MeClientInfo {
    /// Firmware address (`me_cl->client_id`).
    pub addr: u8,
    pub props: MeiClientProperties,
}

// ── Errnos ──────────────────────────────────────────────────────────

/// The negative errnos the client layer returns, as `i32` the way
/// Linux's `ssize_t` / `int` returns carry them.
pub mod errno {
    use narf_lib::errno as e;

    pub const EIO: i32 = -(e::EIO as i32);
    pub const ENOMEM: i32 = -(e::ENOMEM as i32);
    pub const EFAULT: i32 = -(e::EFAULT as i32);
    pub const EBUSY: i32 = -(e::EBUSY as i32);
    pub const ENODEV: i32 = -(e::ENODEV as i32);
    pub const EINVAL: i32 = -(e::EINVAL as i32);
    pub const EMFILE: i32 = -(e::EMFILE as i32);
    pub const ENOTTY: i32 = -(e::ENOTTY as i32);
    pub const EFBIG: i32 = -(e::EFBIG as i32);
    pub const ETIME: i32 = -(e::ETIME as i32);
    pub const EOVERFLOW: i32 = -(e::EOVERFLOW as i32);
    pub const EMSGSIZE: i32 = -(e::EMSGSIZE as i32);
    pub const EOPNOTSUPP: i32 = -(e::EOPNOTSUPP as i32);
}

/// `hbm.c::mei_cl_conn_status_to_errno`.
pub const fn cl_conn_status_to_errno(status: u8) -> i32 {
    match status {
        MEI_HBMS_SUCCESS => 0,
        MEI_HBMS_CLIENT_NOT_FOUND => errno::ENOTTY,
        MEI_HBMS_ALREADY_EXISTS => errno::EBUSY,
        MEI_HBMS_REJECTED => errno::EBUSY,
        MEI_HBMS_INVALID_PARAMETER => errno::EINVAL,
        MEI_HBMS_NOT_ALLOWED => errno::EBUSY,
        _ => errno::EINVAL,
    }
}

// ── Timeouts ────────────────────────────────────────────────────────

/// Budget for `ME_CSR_HA.ME_RDY` to come up after a link reset.
/// Linux's `MEI_HW_READY_TIMEOUT` is 2 s.
pub const HW_READY_TIMEOUT_MS: u64 = 2_000;
/// Budget for one host bus message round trip. Linux's
/// `MEI_HBM_TIMEOUT` is 1 s.
pub const HBM_TIMEOUT_MS: u64 = 1_000;
/// Budget for the host write buffer to drain enough slots.
pub const HBUF_DRAIN_TIMEOUT_MS: u64 = 100;
/// Budget for a connect or disconnect response: the client's
/// `timer_count` is `MEI_CONNECT_TIMEOUT` (3) ticks of the stall timer,
/// which runs every `MEI_STALL_TIMER_FREQ` (2 s).
pub const CONNECT_TIMEOUT_MS: u64 = 3 * 2_000;
/// NARF's bound on one blocking client send or receive. Linux's
/// `mei_cldev_send` / `mei_cldev_recv` have none; this is
/// `MKHI_RCV_TIMEOUT_SLOW` (`hw.h`), Linux's longest bounded wait for
/// a firmware client's reply.
pub const CL_IO_TIMEOUT_MS: u64 = 10_000;

/// Per-device wait budgets (Linux's `dev->timeouts`). Production uses
/// [`MeiTimeouts::LINUX`]; the smokes shrink them so their timeout
/// paths finish quickly.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MeiTimeouts {
    pub hw_ready_ms: u64,
    pub hbm_ms: u64,
    pub hbuf_drain_ms: u64,
    pub connect_ms: u64,
    pub cl_io_ms: u64,
}

impl MeiTimeouts {
    /// The budgets above.
    pub const LINUX: Self = Self {
        hw_ready_ms: HW_READY_TIMEOUT_MS,
        hbm_ms: HBM_TIMEOUT_MS,
        hbuf_drain_ms: HBUF_DRAIN_TIMEOUT_MS,
        connect_ms: CONNECT_TIMEOUT_MS,
        cl_io_ms: CL_IO_TIMEOUT_MS,
    };
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MeiError {
    BarMapFailed,
    /// BAR0 was mapped but cannot cover the register block.
    BarTooSmall,
    /// `H_CSR` read back all-ones — the device is not responding.
    DeviceGone,
    /// `H_CSR.H_CBD` reported a zero-slot host buffer.
    BadBufferDepth,
    /// `ME_RDY` never came up after the link reset.
    HwReadyTimeout,
    /// The host write buffer never freed enough slots.
    HostBufferFull,
    /// A message was longer than the host buffer can hold.
    MessageTooLong,
    /// Firmware never answered within [`HBM_TIMEOUT_MS`].
    HbmTimeout,
    /// Firmware answered with something other than the expected
    /// response opcode.
    HbmUnexpected(u8),
    /// Firmware rejected the HBM version we proposed.
    HbmVersionRejected {
        me_major: u8,
        me_minor: u8,
    },
    /// A response with the expected opcode was too short to decode.
    HbmMalformed(u8),
    /// A properties response named a different client address than
    /// the one requested.
    HbmAddressMismatch {
        asked: u8,
        got: u8,
    },
    /// Firmware answered a properties request with an error status
    /// other than `MEI_HBMS_CLIENT_NOT_FOUND` (Linux: `-EPROTO`).
    HbmStatus(u8),
    /// The link is not enabled (powered down or lost).
    LinkDown,
}

// ── Register access ─────────────────────────────────────────────────

/// The four HECI registers, as the protocol layer sees them.
///
/// Reads of the read window pop and writes of the write window push,
/// so implementations must perform exactly one device access per
/// call, in program order.
pub trait HeciRegs: Send + Sync {
    fn read32(&self, reg: u64) -> u32;
    fn write32(&self, reg: u64, value: u32);
}

/// BAR0-backed registers.
#[derive(Copy, Clone, Debug)]
pub struct BarRegs {
    mmio: MmioRegion,
}

impl BarRegs {
    /// Wrap the mapped register block.
    ///
    /// # Safety
    /// `mmio` must be this HECI function's mapped BAR0, owned by the
    /// caller for as long as the `BarRegs` (and its copies) live.
    pub unsafe fn new(mmio: MmioRegion) -> Result<Self, MeiError> {
        if mmio.len < REG_ME_CSR_HA + 4 {
            return Err(MeiError::BarTooSmall);
        }
        Ok(Self { mmio })
    }

    fn in_range(&self, reg: u64) -> bool {
        matches!(reg.checked_add(4), Some(end) if end <= self.mmio.len)
    }
}

impl HeciRegs for BarRegs {
    fn read32(&self, reg: u64) -> u32 {
        if !self.in_range(reg) {
            return u32::MAX;
        }
        // SAFETY: `new`'s contract makes `mmio` the HECI BAR0 mapping
        // and `in_range` keeps the 32-bit access inside it.
        unsafe { self.mmio.read32(reg) }
    }

    fn write32(&self, reg: u64, value: u32) {
        if !self.in_range(reg) {
            return;
        }
        // SAFETY: same as `read32`.
        unsafe { self.mmio.write32(reg, value) }
    }
}

// ── Link and client state ───────────────────────────────────────────

/// Device state — `enum mei_dev_state`, reduced to what a polled
/// driver distinguishes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MeiDevState {
    /// `MEI_DEV_INIT_CLIENTS`: the bring-up handshake is running.
    InitClients,
    /// `MEI_DEV_ENABLED`.
    Enabled,
    /// `mei_stop` ran (suspend, shutdown, or a host stop): every
    /// client is disconnected and the link is held in reset.
    PowerDown,
    /// The device stopped answering, or firmware broke the protocol.
    /// Linux resets the link; NARF disconnects every client and
    /// stays here until [`MeiDevice::restart`] builds a new device.
    Lost,
}

/// `enum file_state` — a host client's connection state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ClState {
    Initializing,
    Connecting,
    Connected,
    Disconnecting,
    DisconnectReply,
    DisconnectRequired,
    Disconnected,
}

/// A linked host client. The generation makes a handle to a host
/// address that has since been unlinked and reused refer to nothing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MeiClHandle {
    pub host_addr: u8,
    pub me_addr: u8,
    generation: u32,
}

/// `struct mei_me_client`.
#[derive(Clone, Debug)]
struct MeClient {
    addr: u8,
    props: MeiClientProperties,
    /// TX credits for a `single_recv_buf` client.
    tx_creds: u8,
    connect_count: u8,
}

/// A read callback (`struct mei_cl_cb`, `MEI_FOP_READ`).
#[derive(Debug)]
struct ReadCb {
    buf: Vec<u8>,
    /// `cb->buf.size`.
    size: usize,
    status: i32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum WriteState {
    /// Queued, nothing on the wire yet.
    Queued,
    /// At least one packet written.
    Writing,
    /// The last packet is written and firmware has drained the host
    /// buffer (`MEI_WRITE_COMPLETE`).
    Complete,
    Failed(i32),
}

/// A write callback (`MEI_FOP_WRITE`).
#[derive(Debug)]
struct WriteCb {
    data: Vec<u8>,
    /// `cb->buf_idx`.
    idx: usize,
    /// The `msg_complete` packet is on the wire.
    last_sent: bool,
    state: WriteState,
}

/// `struct mei_cl`.
#[derive(Debug)]
struct HostCl {
    id: u8,
    generation: u32,
    me_addr: u8,
    state: ClState,
    status: i32,
    tx_creds: u8,
    rx_creds: u8,
    // ctrl_wr_list: control messages owed to firmware.
    send_connect: bool,
    send_disconnect: bool,
    send_disconnect_rsp: bool,
    /// A read waiting for its flow-control message to go out.
    rd_queued: Option<ReadCb>,
    // ctrl_rd_list: requests awaiting a response.
    await_connect: bool,
    await_disconnect: bool,
    rd_pending: Option<ReadCb>,
    rd_completed: Option<ReadCb>,
    write: Option<WriteCb>,
}

impl HostCl {
    fn new(id: u8, generation: u32, me_addr: u8) -> Self {
        Self {
            id,
            generation,
            me_addr,
            state: ClState::Initializing,
            status: 0,
            tx_creds: 0,
            rx_creds: 0,
            send_connect: false,
            send_disconnect: false,
            send_disconnect_rsp: false,
            rd_queued: None,
            await_connect: false,
            await_disconnect: false,
            rd_pending: None,
            rd_completed: None,
            write: None,
        }
    }

    fn addr_equal(&self, me_addr: u8, host_addr: u8) -> bool {
        self.id == host_addr && self.me_addr == me_addr
    }

    fn flush_ctrl(&mut self) {
        self.send_connect = false;
        self.send_disconnect = false;
        self.send_disconnect_rsp = false;
        self.await_connect = false;
        self.await_disconnect = false;
        self.rd_queued = None;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum StopState {
    Idle,
    /// `HOST_STOP_REQ_CMD` owed to firmware.
    Pending,
    /// Sent; waiting for `HOST_STOP_RES_CMD`.
    Sent,
    Done,
}

/// Everything the link lock protects.
#[derive(Debug)]
struct Link {
    state: MeiDevState,
    /// `dev->rd_msg_hdr[0]`: a header already popped whose payload had
    /// not fully arrived (`mei_irq_read_handler`'s `-ENODATA`).
    rd_hdr: Option<MeiMsgHdr>,
    me_clients: Vec<MeClient>,
    hosts: Vec<HostCl>,
    /// `dev->host_clients_map`; bit 0 is reserved.
    host_map: [u64; 4],
    next_generation: u32,
    stop: StopState,
}

impl Link {
    const fn new() -> Self {
        Self {
            state: MeiDevState::InitClients,
            rd_hdr: None,
            me_clients: Vec::new(),
            hosts: Vec::new(),
            host_map: [1, 0, 0, 0],
            next_generation: 0,
            stop: StopState::Idle,
        }
    }

    fn me_client(&self, addr: u8) -> Option<&MeClient> {
        self.me_clients.iter().find(|c| c.addr == addr)
    }

    fn me_client_mut(&mut self, addr: u8) -> Option<&mut MeClient> {
        self.me_clients.iter_mut().find(|c| c.addr == addr)
    }

    fn host_index(&self, h: MeiClHandle) -> Option<usize> {
        self.hosts
            .iter()
            .position(|c| c.id == h.host_addr && c.generation == h.generation)
    }

    fn host_by_addr(&self, me_addr: u8, host_addr: u8) -> Option<usize> {
        self.hosts
            .iter()
            .position(|c| c.addr_equal(me_addr, host_addr))
    }

    fn map_test(&self, id: u8) -> bool {
        self.host_map[(id / 64) as usize] & (1 << (id % 64)) != 0
    }

    fn map_set(&mut self, id: u8, on: bool) {
        let word = &mut self.host_map[(id / 64) as usize];
        if on {
            *word |= 1 << (id % 64);
        } else {
            *word &= !(1 << (id % 64));
        }
    }

    /// `mei_cl_set_disconnected`.
    fn set_disconnected(&mut self, i: usize) {
        let cl = &mut self.hosts[i];
        if matches!(cl.state, ClState::Disconnected | ClState::Initializing) {
            return;
        }
        cl.state = ClState::Disconnected;
        // write_list / write_waiting_list / ctrl lists are freed.
        cl.write = None;
        cl.flush_ctrl();
        cl.rx_creds = 0;
        cl.tx_creds = 0;
        let me_addr = cl.me_addr;
        if let Some(me) = self.me_client_mut(me_addr) {
            me.connect_count = me.connect_count.saturating_sub(1);
            if me.connect_count == 0 {
                me.tx_creds = 0;
            }
        }
    }

    /// `mei_cl_unlink`.
    fn unlink(&mut self, i: usize) {
        let id = self.hosts[i].id;
        if id != 0 {
            self.map_set(id, false);
        }
        self.hosts.remove(i);
    }

    /// `mei_cl_all_disconnect` plus `mei_hbm_reset`'s
    /// `mei_me_cl_rm_all`: what a link reset or power-down leaves.
    fn teardown(&mut self, state: MeiDevState) {
        self.state = state;
        self.rd_hdr = None;
        for i in 0..self.hosts.len() {
            self.set_disconnected(i);
        }
        self.me_clients.clear();
    }

    /// `mei_cl_tx_flow_ctrl_creds`.
    fn tx_creds_available(&self, i: usize) -> bool {
        let cl = &self.hosts[i];
        if cl.tx_creds > 0 {
            return true;
        }
        match self.me_client(cl.me_addr) {
            Some(me) if me.props.single_recv_buf => me.tx_creds > 0,
            _ => false,
        }
    }

    /// `mei_cl_tx_flow_ctrl_creds_reduce`.
    fn tx_creds_reduce(&mut self, i: usize) -> bool {
        let me_addr = self.hosts[i].me_addr;
        let single = self
            .me_client(me_addr)
            .is_some_and(|me| me.props.single_recv_buf);
        if single {
            match self.me_client_mut(me_addr) {
                Some(me) if me.tx_creds > 0 => {
                    me.tx_creds -= 1;
                    true
                }
                _ => false,
            }
        } else {
            let cl = &mut self.hosts[i];
            if cl.tx_creds == 0 {
                return false;
            }
            cl.tx_creds -= 1;
            true
        }
    }

    /// `mei_cl_complete` for `MEI_FOP_READ`.
    fn complete_read(&mut self, i: usize) {
        let cl = &mut self.hosts[i];
        if let Some(cb) = cl.rd_pending.take() {
            cl.rd_completed = Some(cb);
            cl.rx_creds = cl.rx_creds.saturating_sub(1);
        }
    }
}

/// One packet the host owes firmware.
enum Outbound {
    Hbm([u8; HBM_FLOW_CONTROL_LEN], usize),
    Data { client: usize },
}

// ── Live driver state ───────────────────────────────────────────────

/// A probed HECI interface with its link up and the HBM handshake
/// complete.
pub struct MeiDevice<R: HeciRegs = BarRegs> {
    regs: R,
    /// The link lock: serialises the circular buffers (a message is a
    /// multi-slot write followed by a doorbell and cannot interleave)
    /// and protects client state. Never held across a wait.
    io: IrqSafeSpinLock<Link>,
    /// PCI device id.
    pub device_id: u16,
    /// Host write-buffer depth in slots, latched at config time.
    pub hbuf_depth: u8,
    /// HBM version firmware reported in `HOST_START_RES_CMD`.
    pub hbm_version: HbmVersionResponse,
    /// Firmware supports D0i3 (`PCI_CFG_HFS_1` bit 31).
    pub d0i3_supported: bool,
    /// `PCI_CFG_HFS_1` as read at probe.
    pub fw_status_1: u32,
    /// `PCI_CFG_HFS_2` as read at probe.
    pub fw_status_2: u32,
    /// Bitmap of firmware client addresses from `HOST_ENUM_RES_CMD`.
    pub clients: [u8; HBM_CLIENT_BITMAP_BYTES],
    /// Why the client-properties walk stopped, if it did not finish.
    /// The client table is empty in that case.
    pub props_error: Option<MeiError>,
    /// Wait budgets.
    pub timeouts: MeiTimeouts,
}

impl<R: HeciRegs> core::fmt::Debug for MeiDevice<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MeiDevice")
            .field("device_id", &self.device_id)
            .field("hbuf_depth", &self.hbuf_depth)
            .field("hbm_version", &self.hbm_version)
            .field("d0i3_supported", &self.d0i3_supported)
            .field("client_count", &self.client_count())
            .field("props_error", &self.props_error)
            .finish_non_exhaustive()
    }
}

impl MeiDevice<BarRegs> {
    /// Map BAR0, reset the link, and run the HBM handshake.
    ///
    /// # Safety
    /// Caller owns the device's BAR0 and config space exclusively.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, MeiError> {
        // SAFETY: forwarded — caller owns BAR0.
        let mmio = unsafe { map_bar(device, MEI_BAR) }.map_err(|_| MeiError::BarMapFailed)?;
        // SAFETY: `mmio` is the BAR0 mapping just made for a device the
        // caller owns exclusively.
        let regs = unsafe { BarRegs::new(mmio)? };
        let fw_status_1 = read_cfg32(cap, device, PCI_CFG_HFS_1);
        let fw_status_2 = read_cfg32(cap, device, PCI_CFG_HFS_2);
        Self::bring_up_with(
            regs,
            device.id.device,
            fw_status_1,
            fw_status_2,
            MeiTimeouts::LINUX,
        )
    }
}

impl<R: HeciRegs + Clone> MeiDevice<R> {
    /// `mei_restart`: run the whole bring-up handshake again on the
    /// same registers and return the resulting device. The old device
    /// is left as it is; callers swap the new one in.
    pub fn restart(&self) -> Result<Self, MeiError> {
        Self::bring_up_with(
            self.regs.clone(),
            self.device_id,
            self.fw_status_1,
            self.fw_status_2,
            self.timeouts,
        )
    }
}

impl<R: HeciRegs> MeiDevice<R> {
    /// Reset the link and run the HBM handshake over `regs`.
    pub fn bring_up_with(
        regs: R,
        device_id: u16,
        fw_status_1: u32,
        fw_status_2: u32,
        timeouts: MeiTimeouts,
    ) -> Result<Self, MeiError> {
        let hcsr = regs.read32(REG_H_CSR);
        if hcsr == 0xFFFF_FFFF {
            return Err(MeiError::DeviceGone);
        }
        // `mei_me_hw_config`: the depth does not change at runtime.
        let hbuf_depth = host_buffer_depth(hcsr);
        if hbuf_depth == 0 {
            return Err(MeiError::BadBufferDepth);
        }
        let d0i3_supported = fw_status_1 & PCI_CFG_HFS_1_D0I3 == PCI_CFG_HFS_1_D0I3;

        let mut dev = Self {
            regs,
            io: IrqSafeSpinLock::new(Link::new()),
            device_id,
            hbuf_depth,
            hbm_version: HbmVersionResponse::default(),
            d0i3_supported,
            fw_status_1,
            fw_status_2,
            clients: [0; HBM_CLIENT_BITMAP_BYTES],
            props_error: None,
            timeouts,
        };

        dev.link_reset()?;
        dev.hbm_start()?;
        dev.hbm_enumerate_clients()?;
        // A failed walk leaves no clients to connect to, but the link
        // itself is up: report it rather than failing the probe.
        dev.props_error = dev.hbm_client_properties().err();
        dev.io.lock().state = MeiDevState::Enabled;
        Ok(dev)
    }

    /// `mei_me_hw_reset` followed by `mei_me_host_set_ready`.
    ///
    /// The driver runs polled, so interrupts stay masked throughout:
    /// Linux takes the same path when `mei_me_hw_use_polling` is set.
    fn link_reset(&mut self) -> Result<(), MeiError> {
        let mut hcsr = self.regs.read32(REG_H_CSR);

        // H_RST can already be lit if a previous reset never finished;
        // asserting it again would be ignored, so clear it first.
        if hcsr & H_RST == H_RST {
            self.regs.write32(REG_H_CSR, hcsr & !H_RST);
            hcsr = self.regs.read32(REG_H_CSR);
        }

        // Assert reset + doorbell, clear any latched interrupt status,
        // and keep interrupts disabled (polled driver).
        hcsr |= H_RST | H_IG | H_CSR_IS_MASK;
        hcsr &= !H_CSR_IE_MASK;
        self.regs.write32(REG_H_CSR, hcsr);
        // Linux reads H_CSR straight back to flush the posted write.
        let _ = self.regs.read32(REG_H_CSR);
        compiler_fence(Ordering::SeqCst);

        // Firmware answers a host reset by re-asserting ME_RDY.
        let ready = narf_scheduler::responsive_spin_until(
            || self.regs.read32(REG_ME_CSR_HA) & ME_RDY_HRA == ME_RDY_HRA,
            narf_time::Deadline::after_ms(self.timeouts.hw_ready_ms),
        );
        if !ready {
            return Err(MeiError::HwReadyTimeout);
        }

        // `mei_me_hw_reset_release`: drop H_RST, keep the doorbell.
        let mut hcsr = self.regs.read32(REG_H_CSR);
        hcsr &= !H_RST;
        hcsr |= H_IG;
        self.regs.write32(REG_H_CSR, hcsr);

        // `mei_me_host_set_ready`: publish H_RDY.
        let mut hcsr = self.regs.read32(REG_H_CSR);
        hcsr |= H_IG | H_RDY;
        self.regs.write32(REG_H_CSR, hcsr);
        compiler_fence(Ordering::SeqCst);
        Ok(())
    }

    /// Empty slots in the host write buffer, or `None` on the
    /// overflow Linux reports as `-EOVERFLOW`.
    pub fn hbuf_empty_slots(&self) -> Option<u8> {
        let hcsr = self.regs.read32(REG_H_CSR);
        let filled = host_filled_slots(hcsr);
        if filled > self.hbuf_depth {
            return None;
        }
        Some(self.hbuf_depth - filled)
    }

    /// Write one complete bus message: header word, payload slots,
    /// then the `H_IG` doorbell. `payload` is zero-padded up to a
    /// slot boundary, which is what firmware expects. Bring-up only.
    fn write_message(&self, hdr: MeiMsgHdr, payload: &[u8]) -> Result<(), MeiError> {
        let slots_needed = 1 + data_to_slots(payload.len());
        if slots_needed > self.hbuf_depth as u32 {
            return Err(MeiError::MessageTooLong);
        }

        let have_room = narf_scheduler::responsive_spin_until(
            || matches!(self.hbuf_empty_slots(), Some(n) if n as u32 >= slots_needed),
            narf_time::Deadline::after_ms(self.timeouts.hbuf_drain_ms),
        );
        if !have_room {
            return Err(MeiError::HostBufferFull);
        }

        let _g = self.io.lock();
        self.push_packet(hdr, payload);
        Ok(())
    }

    /// Wait for firmware to fill its read buffer, then pop one
    /// complete message into `out`. Returns the header. Bring-up only.
    fn read_message(&self, out: &mut Vec<u8>) -> Result<MeiMsgHdr, MeiError> {
        let ready = narf_scheduler::responsive_spin_until(
            || me_filled_slots(self.regs.read32(REG_ME_CSR_HA)) > 0,
            narf_time::Deadline::after_ms(self.timeouts.hbm_ms),
        );
        if !ready {
            return Err(MeiError::HbmTimeout);
        }

        let (hdr, slots) = {
            let _g = self.io.lock();
            let hdr = MeiMsgHdr::from_u32(self.regs.read32(REG_ME_CB_RW));
            let slots = data_to_slots(hdr.length as usize);
            (hdr, slots)
        };

        // Wait for the remaining slots without holding the lock so we never
        // busy-wait with interrupts disabled.
        let complete = narf_scheduler::responsive_spin_until(
            || me_filled_slots(self.regs.read32(REG_ME_CSR_HA)) as u32 >= slots,
            narf_time::Deadline::after_ms(self.timeouts.hbm_ms),
        );
        if !complete {
            return Err(MeiError::HbmTimeout);
        }

        let _g = self.io.lock();
        out.clear();
        out.reserve(hdr.length as usize);
        for _ in 0..slots {
            let w = self.regs.read32(REG_ME_CB_RW);
            out.extend_from_slice(&w.to_le_bytes());
        }
        out.truncate(hdr.length as usize);

        // Acknowledge: firmware advances its read pointer when the
        // host rings H_IG.
        let hcsr = self.regs.read32(REG_H_CSR);
        self.regs.write32(REG_H_CSR, hcsr | H_IG);
        compiler_fence(Ordering::SeqCst);
        Ok(hdr)
    }

    /// Send one bus message and wait for the matching response
    /// opcode. Bring-up only.
    fn hbm_exchange(&self, request: &[u8], expect: u8, out: &mut Vec<u8>) -> Result<(), MeiError> {
        self.write_message(MeiMsgHdr::bus_message(request.len() as u16), request)?;
        // Firmware can interleave an unsolicited ME_STOP_REQ_CMD; skip
        // anything that is not the response we asked for rather than
        // failing the handshake on the first surprise.
        for _ in 0..4 {
            self.read_message(out)?;
            match out.first() {
                Some(&cmd) if cmd == expect => return Ok(()),
                Some(&ME_STOP_REQ_CMD) => continue,
                Some(&cmd) => return Err(MeiError::HbmUnexpected(cmd)),
                None => continue,
            }
        }
        Err(MeiError::HbmTimeout)
    }

    /// `HOST_START_REQ_CMD` — propose an HBM version and record what
    /// firmware answers.
    fn hbm_start(&mut self) -> Result<(), MeiError> {
        // struct hbm_host_version_request:
        //   { hbm_cmd, reserved, minor_version, major_version }
        let req = [HOST_START_REQ_CMD, 0, HBM_MINOR_VERSION, HBM_MAJOR_VERSION];
        let mut resp = Vec::new();
        self.hbm_exchange(&req, HOST_START_RES_CMD, &mut resp)?;
        let v = HbmVersionResponse::parse(&resp)
            .ok_or(MeiError::HbmUnexpected(resp.first().copied().unwrap_or(0)))?;
        if !v.host_version_supported {
            return Err(MeiError::HbmVersionRejected {
                me_major: v.me_major,
                me_minor: v.me_minor,
            });
        }
        self.hbm_version = v;
        Ok(())
    }

    /// `HOST_ENUM_REQ_CMD` — ask firmware which client addresses
    /// exist, and keep the bitmap.
    fn hbm_enumerate_clients(&mut self) -> Result<(), MeiError> {
        // struct hbm_host_enum_request: { hbm_cmd, flags, reserved[2] }
        let req = [HOST_ENUM_REQ_CMD, 0, 0, 0];
        let mut resp = Vec::new();
        self.hbm_exchange(&req, HOST_ENUM_RES_CMD, &mut resp)?;
        // struct hbm_host_enum_response:
        //   { hbm_cmd, reserved[3], valid_addresses[32] }
        if resp.len() >= 4 + HBM_CLIENT_BITMAP_BYTES {
            self.clients
                .copy_from_slice(&resp[4..4 + HBM_CLIENT_BITMAP_BYTES]);
        }
        Ok(())
    }

    /// `mei_hbm_prop_req` + the `HOST_CLIENT_PROPERTIES_RES_CMD` arm of
    /// `mei_hbm_dispatch`: one request per set bit, lowest address
    /// first, each answered before the next goes out.
    fn hbm_client_properties(&mut self) -> Result<(), MeiError> {
        let mut found: Vec<MeClient> = Vec::new();
        let mut resp = Vec::new();
        for addr in 0..MEI_CLIENTS_MAX {
            let addr = addr as u8;
            if !self.has_client(addr) {
                continue;
            }
            // struct hbm_props_request: { hbm_cmd, me_addr, reserved[2] }
            let req = [HOST_CLIENT_PROPERTIES_REQ_CMD, addr, 0, 0];
            self.hbm_exchange(&req, HOST_CLIENT_PROPERTIES_RES_CMD, &mut resp)?;
            let r = HbmPropsResponse::parse(&resp)
                .ok_or(MeiError::HbmMalformed(HOST_CLIENT_PROPERTIES_RES_CMD))?;
            if r.me_addr != addr {
                return Err(MeiError::HbmAddressMismatch {
                    asked: addr,
                    got: r.me_addr,
                });
            }
            match r.status {
                // Linux logs it and moves on to the next address.
                MEI_HBMS_CLIENT_NOT_FOUND => continue,
                MEI_HBMS_SUCCESS => {}
                status => return Err(MeiError::HbmStatus(status)),
            }
            let props = r
                .props
                .ok_or(MeiError::HbmMalformed(HOST_CLIENT_PROPERTIES_RES_CMD))?;
            // `mei_hbm_me_cl_add`: a UUID appears once; the later
            // address wins (`mei_me_cl_rm_by_uuid` first).
            found.retain(|c| c.props.protocol_name != props.protocol_name);
            found.push(MeClient {
                addr,
                props,
                tx_creds: 0,
                connect_count: 0,
            });
        }
        self.io.lock().me_clients = found;
        Ok(())
    }

    /// `true` if firmware advertises a client at `addr`.
    pub fn has_client(&self, addr: u8) -> bool {
        let byte = (addr / 8) as usize;
        let bit = addr % 8;
        self.clients[byte] & (1 << bit) != 0
    }

    /// How many firmware clients the enumeration reported.
    pub fn client_count(&self) -> u32 {
        self.clients.iter().map(|b| b.count_ones()).sum()
    }

    /// `true` when firmware currently reports itself ready.
    pub fn me_ready(&self) -> bool {
        self.regs.read32(REG_ME_CSR_HA) & ME_RDY_HRA == ME_RDY_HRA
    }

    /// `true` when the host side has published `H_RDY`.
    pub fn host_ready(&self) -> bool {
        self.regs.read32(REG_H_CSR) & H_RDY == H_RDY
    }

    /// Current device state.
    pub fn state(&self) -> MeiDevState {
        self.io.lock().state
    }

    /// The firmware clients the properties walk recorded (and that a
    /// connect has not since found missing).
    pub fn me_clients(&self) -> Vec<MeClientInfo> {
        self.io
            .lock()
            .me_clients
            .iter()
            .map(|c| MeClientInfo {
                addr: c.addr,
                props: c.props,
            })
            .collect()
    }

    /// `mei_me_cl_by_uuid`.
    pub fn me_client_by_uuid(&self, uuid: &MeiUuid) -> Option<MeClientInfo> {
        self.io
            .lock()
            .me_clients
            .iter()
            .find(|c| c.props.protocol_name == *uuid)
            .map(|c| MeClientInfo {
                addr: c.addr,
                props: c.props,
            })
    }

    // ── Register-level packet I/O (link lock held) ──────────────────

    /// `mei_hcsr_set_hig`: ring the doorbell without writing back the
    /// write-1-to-clear status bits.
    fn set_hig(&self) {
        let hcsr = self.regs.read32(REG_H_CSR);
        self.regs.write32(REG_H_CSR, (hcsr | H_IG) & !H_CSR_IS_MASK);
    }

    /// Header, payload slots (zero-padded), doorbell.
    fn push_packet(&self, hdr: MeiMsgHdr, payload: &[u8]) {
        self.regs.write32(REG_H_CB_WW, hdr.to_u32());
        for chunk in payload.chunks(MEI_SLOT_SIZE) {
            let mut word = [0u8; MEI_SLOT_SIZE];
            word[..chunk.len()].copy_from_slice(chunk);
            self.regs.write32(REG_H_CB_WW, u32::from_le_bytes(word));
        }
        compiler_fence(Ordering::SeqCst);
        let hcsr = self.regs.read32(REG_H_CSR);
        self.regs.write32(REG_H_CSR, hcsr | H_IG);
        compiler_fence(Ordering::SeqCst);
    }

    /// `mei_me_hbuf_write`: room check, packet, doorbell, then
    /// `-EIO` if firmware dropped ready meanwhile.
    fn hbuf_write(&self, hdr: MeiMsgHdr, payload: &[u8]) -> Result<(), i32> {
        let empty = self.hbuf_empty_slots().ok_or(errno::EOVERFLOW)?;
        if 1 + data_to_slots(payload.len()) > empty as u32 {
            return Err(errno::EMSGSIZE);
        }
        self.regs.write32(REG_H_CB_WW, hdr.to_u32());
        for chunk in payload.chunks(MEI_SLOT_SIZE) {
            let mut word = [0u8; MEI_SLOT_SIZE];
            word[..chunk.len()].copy_from_slice(chunk);
            self.regs.write32(REG_H_CB_WW, u32::from_le_bytes(word));
        }
        compiler_fence(Ordering::SeqCst);
        self.set_hig();
        compiler_fence(Ordering::SeqCst);
        if !self.me_ready() {
            return Err(errno::EIO);
        }
        Ok(())
    }

    /// Largest payload one host packet may carry: the host buffer's
    /// byte size through `MEI_MSG_MAX_LEN_MASK`, less the header, and
    /// never more than the header's length field holds.
    fn hbuf_payload_max(&self) -> usize {
        let hbuf_len = (self.hbuf_depth as usize * MEI_SLOT_SIZE) & MEI_MSG_MAX_LEN_MASK;
        hbuf_len
            .saturating_sub(MEI_SLOT_SIZE)
            .min(MEI_MSG_MAX_PAYLOAD)
    }

    // ── The service step (mei_me_irq_thread_handler) ────────────────

    /// Drain and dispatch what firmware has sent, then write what the
    /// host owes it. Bounded: at most one buffer's worth of reads and
    /// one packet per empty host buffer.
    fn service(&self, link: &mut Link) {
        self.read_pending(link);
        self.write_pending(link);
    }

    /// The device answers, and firmware is still ready; otherwise the
    /// link goes [`MeiDevState::Lost`] (`mei_me_irq_thread_handler`:
    /// "FW not ready: resetting").
    fn check_alive(&self, link: &mut Link) -> bool {
        let mecsr = self.regs.read32(REG_ME_CSR_HA);
        let hcsr = self.regs.read32(REG_H_CSR);
        if mecsr == u32::MAX || hcsr == u32::MAX || mecsr & ME_RDY_HRA == 0 {
            link.teardown(MeiDevState::Lost);
            return false;
        }
        true
    }

    /// `mei_irq_read_handler`, looped the way the threaded handler
    /// loops it.
    fn read_pending(&self, link: &mut Link) {
        if link.state != MeiDevState::Enabled || !self.check_alive(link) {
            return;
        }
        // One buffer's worth of messages per call keeps every wait loop
        // making progress even if firmware never stops sending.
        for _ in 0..u8::MAX {
            let mecsr = self.regs.read32(REG_ME_CSR_HA);
            if mecsr == u32::MAX {
                link.teardown(MeiDevState::Lost);
                return;
            }
            let mut filled = me_filled_slots(mecsr);
            // mei_me_count_full_read_slots: -EOVERFLOW → reset.
            if filled > me_buffer_depth(mecsr) {
                link.teardown(MeiDevState::Lost);
                return;
            }
            let hdr = match link.rd_hdr {
                Some(hdr) => hdr,
                None => {
                    if filled == 0 {
                        return;
                    }
                    let word = self.regs.read32(REG_ME_CB_RW);
                    filled -= 1;
                    if !hdr_word_is_acceptable(word) {
                        // "corrupted message header" → reset.
                        link.teardown(MeiDevState::Lost);
                        return;
                    }
                    let hdr = MeiMsgHdr::from_u32(word);
                    link.rd_hdr = Some(hdr);
                    hdr
                }
            };
            let len = hdr.length as usize;
            if (filled as usize) * MEI_SLOT_SIZE < len {
                // -ENODATA: keep the header, read the rest next time.
                return;
            }
            let mut data = Vec::with_capacity(len.next_multiple_of(MEI_SLOT_SIZE));
            for _ in 0..data_to_slots(len) {
                data.extend_from_slice(&self.regs.read32(REG_ME_CB_RW).to_le_bytes());
            }
            data.truncate(len);
            // mei_me_read_slots rings H_IG once the payload is out.
            self.set_hig();
            link.rd_hdr = None;
            self.dispatch(link, hdr, &data);
            if link.state != MeiDevState::Enabled {
                return;
            }
        }
    }

    /// Route one message: bus message, connected client, or nothing.
    fn dispatch(&self, link: &mut Link, hdr: MeiMsgHdr, data: &[u8]) {
        if hdr.is_hbm() {
            self.hbm_dispatch(link, data);
            return;
        }
        if let Some(i) = link.host_by_addr(hdr.me_addr, hdr.host_addr) {
            Self::cl_read_msg(link, i, hdr, data);
            return;
        }
        if hdr.is_fixed() {
            // A message for a fixed-address client nobody connected:
            // Linux discards it silently.
            return;
        }
        // "no destination client found" → -EBADMSG → reset.
        link.teardown(MeiDevState::Lost);
    }

    /// `mei_cl_irq_read_msg` without extended headers or the DMA ring.
    fn cl_read_msg(link: &mut Link, i: usize, hdr: MeiMsgHdr, data: &[u8]) {
        let connected = link.hosts[i].state == ClState::Connected;
        let cl = &mut link.hosts[i];
        let Some(cb) = cl.rd_pending.as_mut() else {
            // "pending read cb not found": discard.
            return;
        };
        if !connected {
            cb.status = errno::ENODEV;
            link.complete_read(i);
            return;
        }
        match cb.buf.len().checked_add(data.len()) {
            Some(total) if total <= cb.size => {}
            _ => {
                // "message overflow": the read completes with
                // -EMSGSIZE and the payload is dropped.
                cb.status = errno::EMSGSIZE;
                link.complete_read(i);
                return;
            }
        }
        cb.buf.extend_from_slice(data);
        if hdr.msg_complete {
            link.complete_read(i);
        }
    }

    /// The post-bring-up arms of `mei_hbm_dispatch`.
    fn hbm_dispatch(&self, link: &mut Link, data: &[u8]) {
        let Some(&cmd) = data.first() else {
            link.teardown(MeiDevState::Lost);
            return;
        };
        let need = match cmd {
            MEI_FLOW_CONTROL_CMD => HBM_FLOW_CONTROL_LEN,
            CLIENT_CONNECT_RES_CMD
            | CLIENT_DISCONNECT_RES_CMD
            | CLIENT_DISCONNECT_REQ_CMD
            | HOST_STOP_RES_CMD
            | ME_STOP_REQ_CMD => HBM_CLIENT_CONNECT_LEN,
            _ => usize::MAX,
        };
        // Linux reads whatever length firmware claims into a fixed
        // buffer and casts it; a short message here is a protocol error,
        // as is every command NARF never asked for.
        if data.len() < need || need == usize::MAX {
            link.teardown(MeiDevState::Lost);
            return;
        }
        let (me_addr, host_addr) = (data[1], data[2]);
        match cmd {
            CLIENT_CONNECT_RES_CMD => {
                // mei_hbm_cl_res(MEI_FOP_CONNECT) → mei_hbm_cl_connect_res
                let status = data[3];
                let Some(i) = link
                    .hosts
                    .iter()
                    .position(|c| c.await_connect && c.addr_equal(me_addr, host_addr))
                else {
                    return;
                };
                let cl = &mut link.hosts[i];
                cl.await_connect = false;
                if status == MEI_HBMS_SUCCESS {
                    cl.state = ClState::Connected;
                } else {
                    cl.state = ClState::DisconnectReply;
                }
                cl.status = cl_conn_status_to_errno(status);
                if status == MEI_HBMS_CLIENT_NOT_FOUND {
                    // mei_me_cl_del: the firmware client is gone.
                    link.me_clients.retain(|c| c.addr != me_addr);
                }
            }
            CLIENT_DISCONNECT_RES_CMD => {
                // mei_hbm_cl_res(MEI_FOP_DISCONNECT)
                let status = data[3];
                let Some(i) = link
                    .hosts
                    .iter()
                    .position(|c| c.await_disconnect && c.addr_equal(me_addr, host_addr))
                else {
                    return;
                };
                let cl = &mut link.hosts[i];
                cl.await_disconnect = false;
                if status == MEI_HBMS_SUCCESS {
                    cl.state = ClState::DisconnectReply;
                }
                cl.status = 0;
            }
            MEI_FLOW_CONTROL_CMD => {
                // mei_hbm_cl_tx_flow_ctrl_creds_res
                if host_addr == 0 {
                    // Single receive buffer: the credit belongs to the
                    // firmware client. Linux WARNs and drops it for a
                    // client without single_recv_buf.
                    if let Some(me) = link.me_client_mut(me_addr) {
                        if me.props.single_recv_buf {
                            me.tx_creds = me.tx_creds.saturating_add(1);
                        }
                    }
                } else if let Some(i) = link.host_by_addr(me_addr, host_addr) {
                    let cl = &mut link.hosts[i];
                    cl.tx_creds = cl.tx_creds.saturating_add(1);
                }
            }
            CLIENT_DISCONNECT_REQ_CMD => {
                // mei_hbm_fw_disconnect_req: answer, then drop the
                // connection once the answer is out.
                if let Some(i) = link.host_by_addr(me_addr, host_addr) {
                    let cl = &mut link.hosts[i];
                    cl.state = ClState::Disconnecting;
                    cl.send_disconnect_rsp = true;
                }
            }
            HOST_STOP_RES_CMD => {
                if link.stop == StopState::Sent {
                    link.stop = StopState::Done;
                } else {
                    // "stop response: state mismatch" → -EPROTO.
                    link.teardown(MeiDevState::Lost);
                }
            }
            ME_STOP_REQ_CMD => {
                // Firmware is going away. Linux answers with a host
                // stop and resets once that is acknowledged; NARF sends
                // the stop if the host buffer is free and drops the
                // link either way.
                if self.hbuf_empty_slots() == Some(self.hbuf_depth) {
                    let req = [HOST_STOP_REQ_CMD, DRIVER_STOP_REQUEST, 0, 0];
                    let _ = self.hbuf_write(MeiMsgHdr::bus_message(req.len() as u16), &req);
                }
                link.teardown(MeiDevState::Lost);
            }
            _ => link.teardown(MeiDevState::Lost),
        }
    }

    /// `mei_irq_write_handler`: only an empty host buffer is written
    /// to (`mei_hbuf_acquire`), control messages before data.
    fn write_pending(&self, link: &mut Link) {
        for _ in 0..u8::MAX {
            if link.state != MeiDevState::Enabled {
                return;
            }
            let hcsr = self.regs.read32(REG_H_CSR);
            if hcsr == u32::MAX {
                link.teardown(MeiDevState::Lost);
                return;
            }
            let filled = host_filled_slots(hcsr);
            if filled > self.hbuf_depth {
                link.teardown(MeiDevState::Lost);
                return;
            }
            if filled != 0 {
                return;
            }
            // The buffer drained: every write whose last packet is out
            // is complete (write_waiting_list).
            for cl in link.hosts.iter_mut() {
                if let Some(w) = cl.write.as_mut() {
                    if w.last_sent && w.state == WriteState::Writing {
                        w.state = WriteState::Complete;
                    }
                }
            }
            let Some((client, out)) = self.next_outbound(link) else {
                return;
            };
            let result = match out {
                Outbound::Hbm(bytes, len) => {
                    self.hbuf_write(MeiMsgHdr::bus_message(len as u16), &bytes[..len])
                }
                Outbound::Data { client } => self.write_data(link, client),
            };
            if let Err(e) = result {
                self.write_failed(link, client, e);
                return;
            }
        }
    }

    /// Pick the next packet: link-level, then per-client control
    /// (connect, disconnect, disconnect response, flow control), then
    /// data. Marks the control message as sent; the caller writes it.
    fn next_outbound(&self, link: &mut Link) -> Option<(Option<usize>, Outbound)> {
        if link.stop == StopState::Pending {
            link.stop = StopState::Sent;
            let mut b = [0u8; HBM_FLOW_CONTROL_LEN];
            b[..4].copy_from_slice(&[HOST_STOP_REQ_CMD, DRIVER_STOP_REQUEST, 0, 0]);
            return Some((None, Outbound::Hbm(b, 4)));
        }
        for i in 0..link.hosts.len() {
            let (me, host) = (link.hosts[i].me_addr, link.hosts[i].id);
            let mut b = [0u8; HBM_FLOW_CONTROL_LEN];
            b[1] = me;
            b[2] = host;
            if link.hosts[i].send_connect {
                // mei_cl_irq_connect: one connect per firmware client
                // in flight (mei_cl_is_other_connecting).
                let other = link
                    .hosts
                    .iter()
                    .enumerate()
                    .any(|(j, c)| j != i && c.await_connect && c.me_addr == me);
                if !other {
                    let cl = &mut link.hosts[i];
                    cl.send_connect = false;
                    cl.await_connect = true;
                    b[0] = CLIENT_CONNECT_REQ_CMD;
                    return Some((Some(i), Outbound::Hbm(b, HBM_CLIENT_CONNECT_LEN)));
                }
            }
            if link.hosts[i].send_disconnect {
                let cl = &mut link.hosts[i];
                cl.send_disconnect = false;
                cl.await_disconnect = true;
                b[0] = CLIENT_DISCONNECT_REQ_CMD;
                return Some((Some(i), Outbound::Hbm(b, HBM_CLIENT_CONNECT_LEN)));
            }
            if link.hosts[i].send_disconnect_rsp {
                // mei_cl_irq_disconnect_rsp, then
                // mei_cl_complete(MEI_FOP_DISCONNECT_RSP).
                link.hosts[i].send_disconnect_rsp = false;
                link.set_disconnected(i);
                b[0] = CLIENT_DISCONNECT_RES_CMD;
                return Some((None, Outbound::Hbm(b, HBM_CLIENT_CONNECT_LEN)));
            }
            if link.hosts[i].rd_queued.is_some() && link.hosts[i].rd_pending.is_none() {
                // mei_cl_irq_read: the flow-control credit goes out and
                // the read moves to rd_pending.
                let cl = &mut link.hosts[i];
                cl.rd_pending = cl.rd_queued.take();
                b[0] = MEI_FLOW_CONTROL_CMD;
                return Some((Some(i), Outbound::Hbm(b, HBM_FLOW_CONTROL_LEN)));
            }
        }
        for i in 0..link.hosts.len() {
            let cl = &link.hosts[i];
            if cl.state != ClState::Connected {
                continue;
            }
            let Some(w) = cl.write.as_ref() else {
                continue;
            };
            if w.last_sent || matches!(w.state, WriteState::Complete | WriteState::Failed(_)) {
                continue;
            }
            // The first packet needs a credit; the rest ride on it.
            if w.idx == 0 && w.state == WriteState::Queued && !link.tx_creds_available(i) {
                continue;
            }
            return Some((Some(i), Outbound::Data { client: i }));
        }
        None
    }

    /// `mei_cl_write` / `mei_cl_irq_write` for one packet into an
    /// empty host buffer: the whole remainder if it fits, else a
    /// buffer-sized fragment.
    fn write_data(&self, link: &mut Link, i: usize) -> Result<(), i32> {
        let max = self.hbuf_payload_max();
        let (me_addr, host_addr) = (link.hosts[i].me_addr, link.hosts[i].id);
        let (first, chunk_len, complete) = {
            let w = link.hosts[i].write.as_ref().ok_or(errno::EIO)?;
            let remaining = w.data.len() - w.idx;
            let first = w.state == WriteState::Queued;
            if remaining <= max {
                (first, remaining, true)
            } else {
                (first, max, false)
            }
        };
        let hdr = MeiMsgHdr {
            me_addr,
            host_addr,
            length: chunk_len as u16,
            extended: false,
            dma_ring: false,
            internal: false,
            msg_complete: complete,
        };
        {
            let w = link.hosts[i].write.as_ref().ok_or(errno::EIO)?;
            self.hbuf_write(hdr, &w.data[w.idx..w.idx + chunk_len])?;
        }
        if first && !link.tx_creds_reduce(i) {
            return Err(errno::EIO);
        }
        let w = link.hosts[i].write.as_mut().ok_or(errno::EIO)?;
        w.idx += chunk_len;
        w.state = WriteState::Writing;
        w.last_sent = complete;
        Ok(())
    }

    /// A host packet could not be written. The buffer was empty, so
    /// this is an overflow or firmware dropping ready: fail the
    /// operation that owned it and take the link down.
    fn write_failed(&self, link: &mut Link, client: Option<usize>, e: i32) {
        if let Some(i) = client {
            let cl = &mut link.hosts[i];
            cl.status = e;
            if let Some(w) = cl.write.as_mut() {
                w.state = WriteState::Failed(e);
            }
        }
        link.teardown(MeiDevState::Lost);
    }

    /// Poll `done` against the link — servicing it before every check
    /// — until it holds or `ms` elapses. The lock is taken per check,
    /// never across the wait.
    fn wait_link(&self, ms: u64, mut done: impl FnMut(&mut Link) -> bool) -> bool {
        narf_scheduler::responsive_spin_until(
            || {
                let mut link = self.io.lock();
                self.service(&mut link);
                done(&mut link)
            },
            narf_time::Deadline::after_ms(ms),
        )
    }

    // ── Client API (bus.c / client.c) ───────────────────────────────

    /// `mei_cldev_enable` for the firmware client at `me_addr`: link a
    /// host client and connect it (`mei_cl_link` + `mei_cl_connect`).
    ///
    /// Errors: `-ENOTTY` no such firmware client (also after link
    /// loss, which empties the table), `-EOPNOTSUPP` a fixed-address
    /// client (NARF), `-EMFILE` no free host address, `-ENODEV` link
    /// down, the connect-response errno (`mei_cl_conn_status_to_errno`),
    /// or `-EFAULT` when firmware never answered and the connection
    /// was disconnected (`MEI_FILE_DISCONNECT_REQUIRED`).
    pub fn cl_connect(&self, me_addr: u8) -> Result<MeiClHandle, i32> {
        let handle = {
            let mut link = self.io.lock();
            self.service(&mut link);
            let Some(me) = link.me_client(me_addr) else {
                return Err(errno::ENOTTY);
            };
            if me.props.fixed_address != 0 {
                return Err(errno::EOPNOTSUPP);
            }
            if link.state != MeiDevState::Enabled {
                return Err(errno::ENODEV);
            }
            let Some(id) = (1..=u8::MAX).find(|&id| !link.map_test(id)) else {
                return Err(errno::EMFILE);
            };
            link.next_generation = link.next_generation.wrapping_add(1);
            let generation = link.next_generation;
            link.map_set(id, true);
            let mut cl = HostCl::new(id, generation, me_addr);
            // mei_cl_set_connecting
            cl.state = ClState::Connecting;
            cl.send_connect = true;
            link.hosts.push(cl);
            if let Some(me) = link.me_client_mut(me_addr) {
                me.connect_count = me.connect_count.saturating_add(1);
            }
            self.service(&mut link);
            MeiClHandle {
                host_addr: id,
                me_addr,
                generation,
            }
        };

        let answered = self.wait_link(self.timeouts.connect_ms, |link| {
            link.host_index(handle).is_none_or(|i| {
                matches!(
                    link.hosts[i].state,
                    ClState::Connected
                        | ClState::Disconnected
                        | ClState::DisconnectRequired
                        | ClState::DisconnectReply
                )
            })
        });

        let mut link = self.io.lock();
        let Some(i) = link.host_index(handle) else {
            return Err(errno::ENODEV);
        };
        if !answered && link.hosts[i].state == ClState::Connecting {
            // mei_connect_timeout with hbm_f_dot_supported (HBM ≥ 2.0).
            link.hosts[i].state = ClState::DisconnectRequired;
        }
        if link.hosts[i].state == ClState::Connected {
            return Ok(handle);
        }
        let ret = if link.hosts[i].state == ClState::DisconnectRequired {
            link.hosts[i].flush_ctrl();
            drop(link);
            // Firmware may answer the connect late; tell it we gave up.
            let _ = self.disconnect_inner(handle);
            link = self.io.lock();
            errno::EFAULT
        } else if link.hosts[i].status == 0 {
            errno::EFAULT
        } else {
            link.hosts[i].status
        };
        if let Some(i) = link.host_index(handle) {
            link.set_disconnected(i);
            link.unlink(i);
        }
        Err(ret)
    }

    /// `__mei_cl_disconnect`: send the disconnect and wait for the
    /// reply. Leaves the host client linked.
    fn disconnect_inner(&self, handle: MeiClHandle) -> Result<(), i32> {
        {
            let mut link = self.io.lock();
            let Some(i) = link.host_index(handle) else {
                return Err(errno::ENODEV);
            };
            link.hosts[i].state = ClState::Disconnecting;
            link.hosts[i].send_disconnect = true;
            self.service(&mut link);
        }
        let answered = self.wait_link(self.timeouts.connect_ms, |link| {
            link.host_index(handle).is_none_or(|i| {
                matches!(
                    link.hosts[i].state,
                    ClState::DisconnectReply | ClState::Disconnected
                )
            })
        });
        let mut link = self.io.lock();
        if !answered {
            // mei_connect_timeout on a disconnecting client resets the
            // link, which disconnects every client and leaves this one
            // with status 0. NARF does not re-run bring-up.
            link.teardown(MeiDevState::Lost);
            return Ok(());
        }
        match link.host_index(handle) {
            Some(i) => {
                let status = link.hosts[i].status;
                link.set_disconnected(i);
                if status == 0 {
                    Ok(())
                } else {
                    Err(status)
                }
            }
            None => Ok(()),
        }
    }

    /// `mei_cldev_disable`: disconnect (unless already disconnected or
    /// the link is down, which needs no handshake) and unlink.
    pub fn cl_disconnect(&self, handle: MeiClHandle) -> Result<(), i32> {
        {
            let mut link = self.io.lock();
            let Some(i) = link.host_index(handle) else {
                return Err(errno::ENODEV);
            };
            // "Already disconnected", or "Device is powering down,
            // don't bother with disconnection".
            if link.hosts[i].state != ClState::Connected || link.state != MeiDevState::Enabled {
                link.set_disconnected(i);
                link.unlink(i);
                return Ok(());
            }
        }
        let ret = self.disconnect_inner(handle);
        let mut link = self.io.lock();
        if let Some(i) = link.host_index(handle) {
            // mei_cl_flush_queues + mei_cl_unlink
            link.hosts[i].rd_pending = None;
            link.hosts[i].rd_completed = None;
            link.set_disconnected(i);
            link.unlink(i);
        }
        ret
    }

    /// `mei_cldev_enabled`.
    pub fn cl_connected(&self, handle: MeiClHandle) -> bool {
        let link = self.io.lock();
        link.state == MeiDevState::Enabled
            && link
                .host_index(handle)
                .is_some_and(|i| link.hosts[i].state == ClState::Connected)
    }

    /// `mei_cldev_mtu`: 0 once the firmware client is gone.
    pub fn cl_mtu(&self, handle: MeiClHandle) -> usize {
        let link = self.io.lock();
        link.me_client(handle.me_addr)
            .map_or(0, |me| me.props.max_msg_length as usize)
    }

    /// `mei_cldev_send` (`__mei_cl_send` with `MEI_CL_IO_TX_BLOCKING`):
    /// send one message, fragmenting it to the host buffer, and wait
    /// until firmware has taken all of it. Returns `message.len()`.
    ///
    /// Errors: `-ENODEV` link down or not connected, `-ENOTTY` the
    /// firmware client is gone, `-EFBIG` longer than the client's MTU,
    /// `-EFAULT` disconnected before the write completed, `-ETIME` no
    /// credit or no drain within [`MeiTimeouts::cl_io_ms`] (NARF bound),
    /// `-EIO` / `-EOVERFLOW` the host buffer write failed (the link is
    /// then down).
    pub fn cl_send(&self, handle: MeiClHandle, message: &[u8]) -> Result<usize, i32> {
        let deadline_ms = self.timeouts.cl_io_ms;
        {
            let mut link = self.io.lock();
            self.service(&mut link);
            if link.state != MeiDevState::Enabled {
                return Err(errno::ENODEV);
            }
            let Some(i) = link.host_index(handle) else {
                return Err(errno::ENODEV);
            };
            if link.hosts[i].state != ClState::Connected {
                return Err(errno::ENODEV);
            }
            let Some(me) = link.me_client(handle.me_addr) else {
                return Err(errno::ENOTTY);
            };
            if message.len() > me.props.max_msg_length as usize {
                return Err(errno::EFBIG);
            }
        }
        // tx_cb_queued: one write per client at a time here.
        let slot_free = self.wait_link(deadline_ms, |link| {
            link.host_index(handle)
                .is_none_or(|i| link.hosts[i].write.is_none())
        });
        {
            let mut link = self.io.lock();
            let Some(i) = link.host_index(handle) else {
                return Err(errno::ENODEV);
            };
            if link.hosts[i].state != ClState::Connected {
                return Err(errno::ENODEV);
            }
            if !slot_free {
                return Err(errno::ETIME);
            }
            let mut data = Vec::new();
            if data.try_reserve_exact(message.len()).is_err() {
                return Err(errno::ENOMEM);
            }
            data.extend_from_slice(message);
            link.hosts[i].write = Some(WriteCb {
                data,
                idx: 0,
                last_sent: false,
                state: WriteState::Queued,
            });
            self.service(&mut link);
        }
        let finished = self.wait_link(deadline_ms, |link| {
            link.host_index(handle).is_none_or(|i| {
                let cl = &link.hosts[i];
                cl.state != ClState::Connected
                    || cl.write.as_ref().is_none_or(|w| {
                        matches!(w.state, WriteState::Complete | WriteState::Failed(_))
                    })
            })
        });
        let mut link = self.io.lock();
        let Some(i) = link.host_index(handle) else {
            return Err(errno::EFAULT);
        };
        let state = link.hosts[i].write.take().map(|w| w.state);
        match state {
            Some(WriteState::Complete) => Ok(message.len()),
            // mei_cl_write: timeout frees the queued write.
            _ if !finished => Err(errno::ETIME),
            Some(WriteState::Failed(e)) => Err(e),
            // writing_state != MEI_WRITE_COMPLETE.
            _ => Err(errno::EFAULT),
        }
    }

    /// `mei_cldev_recv` (`__mei_cl_recv`): return the next message
    /// from firmware, granting it one flow-control credit if no read
    /// is outstanding, and wait for it. A message longer than
    /// `buffer` (but within the read buffer of `max(buffer.len(),
    /// MTU)` bytes) is truncated; the return is the bytes copied.
    ///
    /// Errors: `-ENODEV` link down or not connected, `-ENOTTY` the
    /// firmware client is gone, `-EMSGSIZE` the message overflowed the
    /// read buffer, `-ETIME` nothing within [`MeiTimeouts::cl_io_ms`]
    /// (NARF bound; the credit stays outstanding, as in Linux).
    pub fn cl_recv(&self, handle: MeiClHandle, buffer: &mut [u8]) -> Result<usize, i32> {
        {
            let mut link = self.io.lock();
            self.service(&mut link);
            if link.state != MeiDevState::Enabled {
                return Err(errno::ENODEV);
            }
            let Some(i) = link.host_index(handle) else {
                return Err(errno::ENODEV);
            };
            if let Some(cb) = link.hosts[i].rd_completed.take() {
                return Self::copy_read(cb, buffer);
            }
            // mei_cl_read_start
            if link.hosts[i].state != ClState::Connected {
                return Err(errno::ENODEV);
            }
            let Some(me) = link.me_client(handle.me_addr) else {
                return Err(errno::ENOTTY);
            };
            let mtu = me.props.max_msg_length as usize;
            // "HW currently supports only one pending read": with a
            // credit already outstanding this is -EBUSY, which recv
            // treats as "wait for it".
            if link.hosts[i].rx_creds == 0 {
                // For RX always allocate at least the client's MTU.
                let size = if buffer.is_empty() {
                    0
                } else {
                    buffer.len().max(mtu)
                };
                let cl = &mut link.hosts[i];
                cl.rd_queued = Some(ReadCb {
                    buf: Vec::new(),
                    size,
                    status: 0,
                });
                cl.rx_creds = cl.rx_creds.saturating_add(1);
            }
            self.service(&mut link);
        }
        let arrived = self.wait_link(self.timeouts.cl_io_ms, |link| {
            link.host_index(handle).is_none_or(|i| {
                let cl = &link.hosts[i];
                cl.rd_completed.is_some() || cl.state != ClState::Connected
            })
        });
        if !arrived {
            return Err(errno::ETIME);
        }
        let mut link = self.io.lock();
        let Some(i) = link.host_index(handle) else {
            return Err(errno::ENODEV);
        };
        if link.hosts[i].state != ClState::Connected {
            return Err(errno::ENODEV);
        }
        match link.hosts[i].rd_completed.take() {
            Some(cb) => Self::copy_read(cb, buffer),
            None => Ok(0),
        }
    }

    fn copy_read(cb: ReadCb, buffer: &mut [u8]) -> Result<usize, i32> {
        if cb.status != 0 {
            return Err(cb.status);
        }
        let n = buffer.len().min(cb.buf.len());
        buffer[..n].copy_from_slice(&cb.buf[..n]);
        Ok(n)
    }

    /// `mei_stop`: disconnect every client without a handshake
    /// (`MEI_DEV_POWERING_DOWN`), forget the firmware clients, then put
    /// the link through `mei_me_hw_reset(dev, false)` — assert and
    /// release `H_RST` with interrupts off — and leave it down.
    pub fn power_down(&self) {
        let mut link = self.io.lock();
        link.teardown(MeiDevState::PowerDown);
        let hcsr = self.regs.read32(REG_H_CSR);
        if hcsr == u32::MAX {
            return;
        }
        let mut hcsr = hcsr;
        if hcsr & H_RST == H_RST {
            self.regs
                .write32(REG_H_CSR, (hcsr & !H_RST) & !H_CSR_IS_MASK);
            hcsr = self.regs.read32(REG_H_CSR);
        }
        hcsr |= H_RST | H_IG | H_CSR_IS_MASK;
        hcsr &= !H_CSR_IE_MASK;
        self.regs.write32(REG_H_CSR, hcsr);
        let _ = self.regs.read32(REG_H_CSR);
        compiler_fence(Ordering::SeqCst);
        // mei_me_hw_reset_release
        let hcsr = self.regs.read32(REG_H_CSR);
        self.regs
            .write32(REG_H_CSR, ((hcsr | H_IG) & !H_RST) & !H_CSR_IS_MASK);
        compiler_fence(Ordering::SeqCst);
    }

    /// `HOST_STOP_REQ_CMD` — tell firmware the host is going away.
    /// Once firmware acknowledges, the link is down
    /// (`mei_hbm_dispatch`: `HOST_STOP_RES_CMD` → `MEI_DEV_POWER_DOWN`).
    pub fn stop(&self) -> Result<(), MeiError> {
        {
            let mut link = self.io.lock();
            self.service(&mut link);
            if link.state != MeiDevState::Enabled {
                return Err(MeiError::LinkDown);
            }
            link.stop = StopState::Pending;
            self.service(&mut link);
        }
        let answered = self.wait_link(self.timeouts.hbm_ms, |link| {
            link.stop == StopState::Done || link.state != MeiDevState::Enabled
        });
        let mut link = self.io.lock();
        let acked = link.stop == StopState::Done;
        let was_enabled = link.state == MeiDevState::Enabled;
        link.stop = StopState::Idle;
        if was_enabled {
            link.teardown(MeiDevState::PowerDown);
        }
        if acked {
            Ok(())
        } else if !answered {
            Err(MeiError::HbmTimeout)
        } else {
            Err(MeiError::LinkDown)
        }
    }
}

/// Read a 32-bit word out of the device's PCI config space.
///
/// The firmware-status words live at 0x40 / 0x48 / 0x60 … which are
/// vendor-specific offsets, not capability-list entries, so they are
/// addressed directly.
fn read_cfg32(cap: &Cap<BusDeviceCap, Write>, device: &BusDevice, offset: u16) -> u32 {
    narf_bus::pci::read_config32(cap, device, offset).unwrap_or(0)
}

// ── Driver-match registration ───────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<MeiDevice>>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != MEI_VENDOR || !is_supported_device(device.id.device) {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLER.lock().is_some() {
        return Ok(());
    }
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: probe owns the device's cfg space + BARs for the
    // duration of this call.
    let dev = match unsafe { MeiDevice::<BarRegs>::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  mei: bring-up failed on {:04x}:{:04x}: {:?}",
                device.id.vendor,
                device.id.device,
                e,
            );
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    {
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  mei: HECI {:04x} hbuf={} slots, HBM {}.{}, {} clients, HFS1={:#010x}{}",
            dev.device_id,
            dev.hbuf_depth,
            dev.hbm_version.me_major,
            dev.hbm_version.me_minor,
            dev.client_count(),
            dev.fw_status_1,
            if dev.d0i3_supported { ", d0i3" } else { "" },
        );
        if let Some(e) = dev.props_error {
            let _ = writeln!(
                narf_console::Writer,
                "  mei: client-properties walk stopped: {:?}; no clients will connect",
                e,
            );
        }
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("mei-me"),
        kind: narf_drivers::BoundKind::Other,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Other.default_domain(),
    });

    let dev = Arc::new(dev);
    *CONTROLLER.lock() = Some(dev.clone());
    crate::mei_gsc_proxy::bind(&dev);
    narf_power::device_pm::register_device_pm("mei-me", pm_suspend, pm_resume);
    Ok(())
}

/// `mei_me_pci_suspend` → `mei_stop`: drop every client without a
/// handshake and hold the link in reset, then unbind the GSC proxy
/// (whose disable now just unlinks, as in `MEI_DEV_POWERING_DOWN`).
fn pm_suspend() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    let dev = CONTROLLER.lock().clone();
    if let Some(dev) = dev {
        dev.power_down();
        crate::mei_gsc_proxy::unbind();
    }
    Ok(())
}

/// `mei_me_pci_resume` → `mei_restart`: bring the link up again and
/// re-probe the GSC proxy client on the new device.
fn pm_resume() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    let old = CONTROLLER.lock().clone();
    let Some(old) = old else {
        return Ok(());
    };
    match old.restart() {
        Ok(dev) => {
            let dev = Arc::new(dev);
            *CONTROLLER.lock() = Some(dev.clone());
            crate::mei_gsc_proxy::bind(&dev);
            Ok(())
        }
        Err(e) => {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  mei: restart after resume failed: {:?}",
                e
            );
            Err(narf_power::device_pm::DeviceSuspendError::DriverError)
        }
    }
}

/// Register the MEI PCI driver — one match entry per device ID.
pub fn register_pci_driver() {
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: "mei-me",
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: MEI_VENDOR,
                device: did,
            },
            probe,
        });
    }
}

/// `true` once a HECI interface has been brought up.
pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Run `f` against the probed HECI interface, if any.
pub fn with_device<T>(f: impl FnOnce(&MeiDevice) -> T) -> Option<T> {
    let dev = CONTROLLER.lock().clone();
    dev.map(|a| f(&a))
}

#[doc(hidden)]
/// Test-only: forget the probed device so a smoke can assert
/// end-state.
pub fn __reset_for_test() {
    *CONTROLLER.lock() = None;
}
