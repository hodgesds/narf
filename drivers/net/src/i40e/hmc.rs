//! i40e Host Memory Cache (HMC) — the backing store for LAN queue
//! contexts.
//!
//! ## Reference
//!
//! Linux v7.3-rc4 (GPL-2.0; NARF is GPL-2.0-or-later so adaptation
//! is permitted):
//!
//! - `i40e_lan_hmc.c` / `.h` — `i40e_calculate_l2fpm_size`,
//!   `i40e_align_l2obj_base`, `i40e_init_lan_hmc`,
//!   `i40e_configure_lan_hmc`, `i40e_hmc_get_object_va`, and the
//!   `i40e_hmc_txq_ce_info` / `i40e_hmc_rxq_ce_info` field tables.
//! - `i40e_hmc.c` / `.h` — `i40e_add_sd_table_entry`,
//!   `I40E_SET_PF_SD_ENTRY`.
//!
//! ## What the HMC is
//!
//! On the 700 series a queue is not described by registers. Its
//! context — ring base, length, head-writeback address, buffer size,
//! and a few dozen enable bits — lives in **host memory** that the
//! device DMAs. The driver hands the device one or more backing
//! pages and tells it, per object class, where in that flat "function
//! private memory" (FPM) space each class starts and how many objects
//! it holds. The device then computes
//! `base + size * queue_index` itself.
//!
//! So bringing up a queue is: allocate a backing page, publish it as
//! a **segment descriptor** (SD) through `PFHMC_SDDATA{HIGH,LOW}` +
//! `PFHMC_SDCMD`, program the per-class base/count into the
//! `GLHMC_LAN{TX,RX}{BASE,CNT}` registers, then write the packed
//! context bytes into the right offset of that page.
//!
//! This module uses a **single direct-mode SD**, which is what Linux
//! prefers (`I40E_HMC_MODEL_DIRECT_PREFERRED`) and is by far the
//! simplest arrangement: one contiguous allocation, `sd_idx` always
//! 0, and `obj_offset_in_sd == obj_offset_in_fpm` because the whole
//! LAN object fits well inside one 2 MiB SD. A handful of queues
//! needs about a kilobyte.
//!
//! ## The bit packing
//!
//! A context is a little-endian **bit string**, not a struct. Each
//! field is `(lsb, width)` and straddles byte boundaries freely —
//! `base` is 57 bits at bit 32, `qlen` is 13 bits at bit 161. Linux
//! packs these with four separate byte/word/dword/qword helpers,
//! each masking and shifting in the containing machine word.
//!
//! [`write_ctx_field`] instead inserts bit by bit. It is slower and
//! this is a once-per-queue configuration path where that does not
//! matter; what it buys is that there is no "does the shifted field
//! still fit the containing type" question to get wrong, and it has
//! an exact inverse in [`read_ctx_field`] so the smokes can
//! round-trip every field in the real tables.

use narf_bus::MmioRegion;
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;

use super::I40eError;

// ── FPM geometry (i40e_lan_hmc.h) ───────────────────────────────────

/// `I40E_HMC_L2OBJ_BASE_ALIGNMENT` — every object class starts on a
/// 512-byte boundary within FPM.
pub const L2OBJ_BASE_ALIGNMENT: u64 = 512;
/// `I40E_HMC_OBJ_SIZE_TXQ` — bytes of context per TX queue.
pub const OBJ_SIZE_TXQ: u64 = 128;
/// `I40E_HMC_OBJ_SIZE_RXQ` — bytes of context per RX queue.
pub const OBJ_SIZE_RXQ: u64 = 32;
/// `I40E_HMC_OBJ_SIZE_FCOE_CNTX`.
pub const OBJ_SIZE_FCOE_CNTX: u64 = 64;
/// `I40E_HMC_OBJ_SIZE_FCOE_FILT`.
pub const OBJ_SIZE_FCOE_FILT: u64 = 64;

/// `I40E_HMC_DIRECT_BP_SIZE` — the FPM span one direct SD covers.
pub const DIRECT_BP_SIZE: u64 = 0x20_0000;
/// `I40E_HMC_PD_BP_BUF_ALIGNMENT` — required backing-page alignment.
pub const PD_BP_BUF_ALIGNMENT: u64 = 4096;
/// `I40E_HMC_MAX_BP_COUNT` — value stamped into `PMSDBPCOUNT`.
pub const MAX_BP_COUNT: u32 = 512;

/// `i40e_align_l2obj_base` — round `offset` up to the next 512-byte
/// boundary.
pub const fn align_l2obj_base(offset: u64) -> u64 {
    offset.div_ceil(L2OBJ_BASE_ALIGNMENT) * L2OBJ_BASE_ALIGNMENT
}

/// `i40e_calculate_l2fpm_size` — total FPM bytes for the requested
/// object counts.
///
/// Each class is padded up to a 512-byte boundary *after* it is
/// added, including the last one, which is why the FCoE terms still
/// contribute alignment even when their counts are zero.
pub const fn calculate_l2fpm_size(
    txq_num: u64,
    rxq_num: u64,
    fcoe_cntx_num: u64,
    fcoe_filt_num: u64,
) -> u64 {
    let mut size = txq_num * OBJ_SIZE_TXQ;
    size = align_l2obj_base(size);
    size += rxq_num * OBJ_SIZE_RXQ;
    size = align_l2obj_base(size);
    size += fcoe_cntx_num * OBJ_SIZE_FCOE_CNTX;
    size = align_l2obj_base(size);
    size += fcoe_filt_num * OBJ_SIZE_FCOE_FILT;
    align_l2obj_base(size)
}

// ── Registers (i40e_register.h) ─────────────────────────────────────

/// `I40E_PFHMC_SDCMD`.
pub const REG_PFHMC_SDCMD: u64 = 0x000C_0000;
/// `I40E_PFHMC_SDDATALOW`.
pub const REG_PFHMC_SDDATALOW: u64 = 0x000C_0100;
/// `I40E_PFHMC_SDDATAHIGH`.
pub const REG_PFHMC_SDDATAHIGH: u64 = 0x000C_0200;
/// `I40E_PFHMC_PDINV`.
pub const REG_PFHMC_PDINV: u64 = 0x000C_0300;

/// `PMSDVALID` — the SD entry is live.
pub const SDDATALOW_PMSDVALID: u32 = 1 << 0;
/// `PMSDTYPE` — 1 for direct mode, 0 for paged.
pub const SDDATALOW_PMSDTYPE_SHIFT: u32 = 1;
/// `PMSDBPCOUNT`.
pub const SDDATALOW_PMSDBPCOUNT_SHIFT: u32 = 2;
/// `PMSDWR` — the command is a write.
pub const SDCMD_PMSDWR: u32 = 1 << 31;

/// `I40E_GLHMC_LANQMAX` — most LAN queues this function may back.
pub const REG_GLHMC_LANQMAX: u64 = 0x000C_2008;
/// `I40E_GLHMC_LANTXOBJSZ` — log2 of the TX context size.
pub const REG_GLHMC_LANTXOBJSZ: u64 = 0x000C_2004;
/// `I40E_GLHMC_LANRXOBJSZ` — log2 of the RX context size.
pub const REG_GLHMC_LANRXOBJSZ: u64 = 0x000C_200C;

/// `I40E_GLHMC_LANTXBASE(fn)`.
pub const fn reg_glhmc_lantxbase(hmc_fn: u8) -> u64 {
    0x000C_6200 + (hmc_fn as u64) * 4
}
/// `I40E_GLHMC_LANTXCNT(fn)`.
pub const fn reg_glhmc_lantxcnt(hmc_fn: u8) -> u64 {
    0x000C_6300 + (hmc_fn as u64) * 4
}
/// `I40E_GLHMC_LANRXBASE(fn)`.
pub const fn reg_glhmc_lanrxbase(hmc_fn: u8) -> u64 {
    0x000C_6400 + (hmc_fn as u64) * 4
}
/// `I40E_GLHMC_LANRXCNT(fn)`.
pub const fn reg_glhmc_lanrxcnt(hmc_fn: u8) -> u64 {
    0x000C_6500 + (hmc_fn as u64) * 4
}
/// `I40E_GLHMC_FCOEDDPBASE(fn)`.
pub const fn reg_glhmc_fcoeddpbase(hmc_fn: u8) -> u64 {
    0x000C_6600 + (hmc_fn as u64) * 4
}
/// `I40E_GLHMC_FCOEDDPCNT(fn)`.
pub const fn reg_glhmc_fcoeddpcnt(hmc_fn: u8) -> u64 {
    0x000C_6700 + (hmc_fn as u64) * 4
}
/// `I40E_GLHMC_FCOEFBASE(fn)`.
pub const fn reg_glhmc_fcoefbase(hmc_fn: u8) -> u64 {
    0x000C_6800 + (hmc_fn as u64) * 4
}
/// `I40E_GLHMC_FCOEFCNT(fn)`.
pub const fn reg_glhmc_fcoefcnt(hmc_fn: u8) -> u64 {
    0x000C_6900 + (hmc_fn as u64) * 4
}

/// The base registers hold the FPM offset **in 512-byte units**, not
/// bytes. Writing a byte offset there points the device 512× too far
/// into FPM, which reads as a context full of zeroes.
pub const fn fpm_base_to_reg(base: u64) -> u32 {
    (base / L2OBJ_BASE_ALIGNMENT) as u32
}

// ── Context field descriptors ───────────────────────────────────────

/// One `(lsb, width)` field of a packed HMC context, named for the
/// Linux `i40e_hmc_obj_*` struct member it corresponds to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CtxField {
    /// Field name, matching the Linux struct member.
    pub name: &'static str,
    /// Bit offset from the start of the context.
    pub lsb: u16,
    /// Field width in bits.
    pub width: u8,
}

/// LAN TX queue context layout — `i40e_hmc_txq_ce_info`.
///
/// Note the `+ 128` and `+ (7 * 128)` terms in Linux: the context is
/// addressed in 128-bit "lines", so `qlen` at `33 + 128` is bit 161
/// and `crc` at `0 + 7 * 128` is bit 896. Those are pre-computed
/// here.
pub const TXQ_CTX_FIELDS: &[CtxField] = &[
    CtxField {
        name: "head",
        lsb: 0,
        width: 13,
    },
    CtxField {
        name: "new_context",
        lsb: 30,
        width: 1,
    },
    CtxField {
        name: "base",
        lsb: 32,
        width: 57,
    },
    CtxField {
        name: "fc_ena",
        lsb: 89,
        width: 1,
    },
    CtxField {
        name: "timesync_ena",
        lsb: 90,
        width: 1,
    },
    CtxField {
        name: "fd_ena",
        lsb: 91,
        width: 1,
    },
    CtxField {
        name: "alt_vlan_ena",
        lsb: 92,
        width: 1,
    },
    CtxField {
        name: "cpuid",
        lsb: 96,
        width: 8,
    },
    // line 1
    CtxField {
        name: "thead_wb",
        lsb: 128,
        width: 13,
    },
    CtxField {
        name: "head_wb_ena",
        lsb: 160,
        width: 1,
    },
    CtxField {
        name: "qlen",
        lsb: 161,
        width: 13,
    },
    CtxField {
        name: "tphrdesc_ena",
        lsb: 174,
        width: 1,
    },
    CtxField {
        name: "tphrpacket_ena",
        lsb: 175,
        width: 1,
    },
    CtxField {
        name: "tphwdesc_ena",
        lsb: 176,
        width: 1,
    },
    CtxField {
        name: "head_wb_addr",
        lsb: 192,
        width: 64,
    },
    // line 7
    CtxField {
        name: "crc",
        lsb: 896,
        width: 32,
    },
    CtxField {
        name: "rdylist",
        lsb: 980,
        width: 10,
    },
    CtxField {
        name: "rdylist_act",
        lsb: 990,
        width: 1,
    },
];

/// LAN RX queue context layout — `i40e_hmc_rxq_ce_info`.
pub const RXQ_CTX_FIELDS: &[CtxField] = &[
    CtxField {
        name: "head",
        lsb: 0,
        width: 13,
    },
    CtxField {
        name: "cpuid",
        lsb: 13,
        width: 8,
    },
    CtxField {
        name: "base",
        lsb: 32,
        width: 57,
    },
    CtxField {
        name: "qlen",
        lsb: 89,
        width: 13,
    },
    CtxField {
        name: "dbuff",
        lsb: 102,
        width: 7,
    },
    CtxField {
        name: "hbuff",
        lsb: 109,
        width: 5,
    },
    CtxField {
        name: "dtype",
        lsb: 114,
        width: 2,
    },
    CtxField {
        name: "dsize",
        lsb: 116,
        width: 1,
    },
    CtxField {
        name: "crcstrip",
        lsb: 117,
        width: 1,
    },
    CtxField {
        name: "fc_ena",
        lsb: 118,
        width: 1,
    },
    CtxField {
        name: "l2tsel",
        lsb: 119,
        width: 1,
    },
    CtxField {
        name: "hsplit_0",
        lsb: 120,
        width: 4,
    },
    CtxField {
        name: "hsplit_1",
        lsb: 124,
        width: 2,
    },
    CtxField {
        name: "showiv",
        lsb: 127,
        width: 1,
    },
    CtxField {
        name: "rxmax",
        lsb: 174,
        width: 14,
    },
    CtxField {
        name: "tphrdesc_ena",
        lsb: 193,
        width: 1,
    },
    CtxField {
        name: "tphwdesc_ena",
        lsb: 194,
        width: 1,
    },
    CtxField {
        name: "tphdata_ena",
        lsb: 195,
        width: 1,
    },
    CtxField {
        name: "tphhead_ena",
        lsb: 196,
        width: 1,
    },
    CtxField {
        name: "lrxqthresh",
        lsb: 198,
        width: 3,
    },
    CtxField {
        name: "prefena",
        lsb: 201,
        width: 1,
    },
];

/// Look a field up by name. Returns `None` for a name not in `table`.
pub fn ctx_field(table: &'static [CtxField], name: &str) -> Option<CtxField> {
    let mut i = 0;
    while i < table.len() {
        if table[i].name.as_bytes() == name.as_bytes() {
            return Some(table[i]);
        }
        i += 1;
    }
    None
}

/// Insert `value` into the little-endian bit string `ctx`.
///
/// Bits outside the field are left alone, and a value wider than
/// `field.width` is truncated rather than allowed to bleed into the
/// neighbouring field. Writes that would run past the end of `ctx`
/// are dropped — a caller that sized the buffer from
/// [`OBJ_SIZE_TXQ`] / [`OBJ_SIZE_RXQ`] cannot hit that.
pub fn write_ctx_field(ctx: &mut [u8], field: CtxField, value: u64) {
    let masked = if field.width >= 64 {
        value
    } else {
        value & ((1u64 << field.width) - 1)
    };
    for i in 0..field.width as u16 {
        let pos = field.lsb + i;
        let byte = (pos / 8) as usize;
        if byte >= ctx.len() {
            return;
        }
        let off = (pos % 8) as u32;
        let bit = ((masked >> i) & 1) as u8;
        ctx[byte] = (ctx[byte] & !(1u8 << off)) | (bit << off);
    }
}

/// Exact inverse of [`write_ctx_field`].
pub fn read_ctx_field(ctx: &[u8], field: CtxField) -> u64 {
    let mut out = 0u64;
    for i in 0..field.width as u16 {
        let pos = field.lsb + i;
        let byte = (pos / 8) as usize;
        if byte >= ctx.len() {
            break;
        }
        let off = (pos % 8) as u32;
        out |= (((ctx[byte] >> off) & 1) as u64) << i;
    }
    out
}

/// `true` iff no two fields in `table` overlap and none runs past
/// `size_bytes`. A packing table that violates either silently
/// corrupts a neighbouring field, so the smokes assert it.
pub fn table_is_disjoint(table: &[CtxField], size_bytes: u64) -> bool {
    let bits = size_bytes * 8;
    let mut i = 0;
    while i < table.len() {
        let a = table[i];
        if a.width == 0 || a.lsb as u64 + a.width as u64 > bits {
            return false;
        }
        let mut j = i + 1;
        while j < table.len() {
            let b = table[j];
            let a_end = a.lsb as u64 + a.width as u64;
            let b_end = b.lsb as u64 + b.width as u64;
            if (a.lsb as u64) < b_end && (b.lsb as u64) < a_end {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

// ── LAN HMC ─────────────────────────────────────────────────────────

/// One object class's placement within FPM.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HmcObject {
    /// Objects this function may back, from `GLHMC_LANQMAX`.
    pub max_cnt: u32,
    /// Objects the driver asked for.
    pub cnt: u32,
    /// Byte offset of the class within FPM.
    pub base: u64,
    /// Bytes per object.
    pub size: u64,
}

/// The LAN HMC for one PF: a single direct-mode backing page plus the
/// FPM placement of the TX and RX context classes.
#[derive(Debug)]
pub struct LanHmc {
    /// Direct-mode SD backing page.
    backing: DmaBuffer,
    /// TX context class.
    pub txq: HmcObject,
    /// RX context class.
    pub rxq: HmcObject,
    /// Total FPM bytes the classes occupy.
    pub l2fpm_size: u64,
    /// HMC function id — the PF id.
    pub hmc_fn_id: u8,
}

impl LanHmc {
    /// Size the LAN objects, allocate the backing page, publish the
    /// SD, and program the FPM base/count registers.
    ///
    /// # Safety
    /// `csr` must be this PF's mapped BAR0.
    pub unsafe fn bring_up(
        csr: &MmioRegion,
        hmc_fn_id: u8,
        txq_num: u32,
        rxq_num: u32,
    ) -> Result<Self, I40eError> {
        // `i40e_init_lan_hmc`: the object sizes are reported by the
        // device as log2, not as bytes.
        // SAFETY: caller-asserted mapped CSR window; these are plain
        // capability registers with no read side effects.
        let (lanqmax, tx_size_exp, rx_size_exp) = unsafe {
            (
                csr.read32(REG_GLHMC_LANQMAX),
                csr.read32(REG_GLHMC_LANTXOBJSZ),
                csr.read32(REG_GLHMC_LANRXOBJSZ),
            )
        };
        if lanqmax == 0xFFFF_FFFF {
            return Err(I40eError::HmcUnavailable);
        }
        if txq_num > lanqmax || rxq_num > lanqmax {
            return Err(I40eError::HmcTooManyQueues);
        }
        // A device reporting a different context size than the one
        // the packing tables were written against would place every
        // field at the wrong offset, so refuse rather than guess.
        let tx_size = 1u64 << (tx_size_exp & 0x3F);
        let rx_size = 1u64 << (rx_size_exp & 0x3F);
        if tx_size != OBJ_SIZE_TXQ || rx_size != OBJ_SIZE_RXQ {
            return Err(I40eError::HmcUnexpectedObjectSize);
        }

        let txq = HmcObject {
            max_cnt: lanqmax,
            cnt: txq_num,
            base: 0,
            size: tx_size,
        };
        let rxq = HmcObject {
            max_cnt: lanqmax,
            cnt: rxq_num,
            base: align_l2obj_base(txq.base + txq.cnt as u64 * txq.size),
            size: rx_size,
        };
        let l2fpm_size = calculate_l2fpm_size(txq_num as u64, rxq_num as u64, 0, 0);

        // One direct SD covers 2 MiB of FPM. Anything this driver
        // asks for is orders of magnitude smaller, and the
        // single-SD assumption is load-bearing in `object_offset`.
        if l2fpm_size > DIRECT_BP_SIZE {
            return Err(I40eError::HmcTooManyQueues);
        }

        // `alloc_coherent` hands back page-aligned buddy frames, which
        // satisfies `I40E_HMC_PD_BP_BUF_ALIGNMENT`.
        let backing = alloc_coherent(l2fpm_size as usize, DomainId::DRIVER_0)
            .map_err(|_| I40eError::NoMemory)?;
        let phys = backing.dma_addr().raw();
        if phys % PD_BP_BUF_ALIGNMENT != 0 {
            return Err(I40eError::NoMemory);
        }
        // Firmware reads the whole class range; leftover heap bytes
        // would decode as garbage context.
        for i in 0..l2fpm_size {
            // SAFETY: `backing` is an identity-mapped DMA buffer of at
            // least `l2fpm_size` bytes and `i < l2fpm_size`.
            unsafe { core::ptr::write_volatile(backing.cpu_mut_ptr_at::<u8>(i), 0) };
        }

        // `I40E_SET_PF_SD_ENTRY` for sd_index 0, direct mode.
        let val_high = (phys >> 32) as u32;
        let val_low = (phys as u32)
            | (MAX_BP_COUNT << SDDATALOW_PMSDBPCOUNT_SHIFT)
            | (1 << SDDATALOW_PMSDTYPE_SHIFT)
            | SDDATALOW_PMSDVALID;
        let val_cmd = SDCMD_PMSDWR; // sd_index 0
                                    // SAFETY: caller-asserted mapped CSR window; the three writes
                                    // are the documented SD-publish sequence and must land in
                                    // this order — SDCMD latches whatever the two data registers
                                    // hold.
        unsafe {
            csr.write32(REG_PFHMC_SDDATAHIGH, val_high);
            csr.write32(REG_PFHMC_SDDATALOW, val_low);
            csr.write32(REG_PFHMC_SDCMD, val_cmd);
        }

        // `i40e_configure_lan_hmc`: publish each class's FPM base and
        // count. FCoE is zeroed so the device does not chase a stale
        // base left over from a previous driver.
        // SAFETY: same.
        unsafe {
            csr.write32(reg_glhmc_lantxbase(hmc_fn_id), fpm_base_to_reg(txq.base));
            csr.write32(reg_glhmc_lantxcnt(hmc_fn_id), txq.cnt);
            csr.write32(reg_glhmc_lanrxbase(hmc_fn_id), fpm_base_to_reg(rxq.base));
            csr.write32(reg_glhmc_lanrxcnt(hmc_fn_id), rxq.cnt);
            csr.write32(reg_glhmc_fcoeddpbase(hmc_fn_id), 0);
            csr.write32(reg_glhmc_fcoeddpcnt(hmc_fn_id), 0);
            csr.write32(reg_glhmc_fcoefbase(hmc_fn_id), 0);
            csr.write32(reg_glhmc_fcoefcnt(hmc_fn_id), 0);
        }

        Ok(Self {
            backing,
            txq,
            rxq,
            l2fpm_size,
            hmc_fn_id,
        })
    }

    /// Byte offset of TX queue `q`'s context within the backing page.
    ///
    /// `i40e_hmc_get_object_va` takes the offset modulo the SD span;
    /// with one direct SD and an FPM smaller than 2 MiB that is the
    /// identity, so the offset into the page *is* the FPM offset.
    pub fn tx_object_offset(&self, q: u32) -> Option<u64> {
        if q >= self.txq.cnt {
            return None;
        }
        Some(self.txq.base + self.txq.size * q as u64)
    }

    /// Byte offset of RX queue `q`'s context within the backing page.
    pub fn rx_object_offset(&self, q: u32) -> Option<u64> {
        if q >= self.rxq.cnt {
            return None;
        }
        Some(self.rxq.base + self.rxq.size * q as u64)
    }

    /// Write `ctx` into the backing page at `offset`.
    fn write_object(&self, offset: u64, ctx: &[u8]) {
        for (i, b) in ctx.iter().enumerate() {
            // SAFETY: `offset + ctx.len()` is inside the backing
            // allocation — the caller obtained `offset` from
            // `tx_object_offset` / `rx_object_offset`, which bound it
            // to `base + size * cnt <= l2fpm_size`, and `ctx.len()`
            // is the class's object size.
            unsafe {
                core::ptr::write_volatile(self.backing.cpu_mut_ptr_at::<u8>(offset + i as u64), *b)
            };
        }
    }

    /// Install a packed TX context. `ctx` must be [`OBJ_SIZE_TXQ`]
    /// bytes.
    pub fn set_tx_context(
        &self,
        q: u32,
        ctx: &[u8; OBJ_SIZE_TXQ as usize],
    ) -> Result<(), I40eError> {
        let off = self.tx_object_offset(q).ok_or(I40eError::BadQueueIndex)?;
        self.write_object(off, ctx);
        Ok(())
    }

    /// Install a packed RX context. `ctx` must be [`OBJ_SIZE_RXQ`]
    /// bytes.
    pub fn set_rx_context(
        &self,
        q: u32,
        ctx: &[u8; OBJ_SIZE_RXQ as usize],
    ) -> Result<(), I40eError> {
        let off = self.rx_object_offset(q).ok_or(I40eError::BadQueueIndex)?;
        self.write_object(off, ctx);
        Ok(())
    }

    /// Physical base of the backing page, for diagnostics.
    pub fn backing_phys(&self) -> u64 {
        self.backing.dma_addr().raw()
    }
}
