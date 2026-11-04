//! ixgbe FCoE programming — Ethertype filters, FCRETA redirection,
//! FCoE RX control (CRC offload), DDP context setup/teardown, WWN
//! composition, and RX completion classification.
//!
//! Grounding: Linux ixgbe @ cbbddb6 (`ixgbe_fcoe.c`,
//! `ixgbe_fcoe.h`, `ixgbe_type.h` FCoE block). Every register
//! address, bit, and sequence below is transcribed from those
//! files, not invented. FC_FCOE_VER = 0 comes from
//! `include/scsi/fc/fc_fcoe.h` (`#define FC_FCOE_VER 0`), confirmed
//! against two independent kernel mirrors (TI trees) since the
//! local Linux tree is drivers-only and has no `include/`.
//!
//! ⚠️ DATASHEET GAP (issue #1264's stated requirement, NOT met):
//! no 82599/X540/X550 datasheet copy exists in this workspace
//! (searched: workspace top level, queue/, tools/, scratch/ — no
//! PDFs, no 82599/X540 datasheet files), so no FCoE register here
//! is datasheet-grounded. The in-tree driver cites datasheet
//! sections for other registers (e.g. RSS §8.2.3.7.12), but the
//! FCoE block has zero in-tree cross-checks (grep-confirmed: no
//! prior ETQF/FCRETA/FCRXCTRL references anywhere in-tree).
//! Re-grounding against the datasheet stays a named follow-up,
//! and the maintainer may bounce this module on that ground alone.
//!
//! SCOPE (what this module is and is not):
//! - It IS the driver-side programming surface: `configure_fcoe`
//!   (filters + redirection + RX control), DDP context
//!   setup/teardown (`ddp_context` + `program_ddp` +
//!   `invalidate_ddp`), WWN composition, and the RX completion
//!   classifier. All are fixture-testable without a consumer.
//! - It is NOT a consumer: there is no FCoE stack in-tree (the
//!   issue itself notes "no FCoE consumer in-tree"), so nothing
//!   calls `program_ddp` on a live RX completion yet, no TX
//!   FSO path exists (that needs a TX frame parser, which the
//!   tree does not have — same gap as #1262's TX sampling hook),
//!   and SAN-MAC/NVM provisioning for `wwn_compose` is unwired
//!   (the pure composition formula is implemented; the prefixes
//!   and SAN address come from NVM reads the driver does not
//!   have yet).
//! - X550 vs everything else follows Linux literally: Linux's
//!   `ixgbe_fcoe.c` special-cases only `ixgbe_mac_X550` (direct
//!   FCDDC/FCDFC context access, 32-entry FCRETA, 2048 DDP
//!   contexts). X550EM_X is NOT special-cased there (0 mentions
//!   of X550EM in `ixgbe_fcoe.c`), so it takes the indirect
//!   path, 8-entry FCRETA, and 512 contexts here too — whether
//!   silicon agrees is a datasheet question, flagged as a
//!   follow-up, not silently "fixed".
//! - Probe still brings up 1/1; `configure_fcoe` is opt-in and
//!   queue-0 behavior is untouched when it never runs.

use super::queues::RegBank;

// ── Ethertype filter registers (ixgbe_type.h) ────────────────────

/// ETQF base: ETQF(i) = 0x05128 + i*4.
pub const REG_ETQF_BASE: u64 = 0x05128;
/// ETQS base: ETQS(i) = 0x0EC00 + i*4.
pub const REG_ETQS_BASE: u64 = 0x0EC00;
/// FCoE ethertype (T11 FC-BB-5 / IEEE 802.1Q).
pub const ETH_P_FCOE: u32 = 0x8906;
/// FIP ethertype (FCoE Initialization Protocol).
pub const ETH_P_FIP: u32 = 0x8914;
/// ETQF bit 27: this filter matches FCoE frames.
pub const ETQF_FCOE: u32 = 0x0800_0000;
/// ETQF bit 31: filter enable.
pub const ETQF_FILTER_EN: u32 = 0x8000_0000;
/// ETQF bit 26: pool enable (SR-IOV).
pub const ETQF_POOL_ENABLE: u32 = 0x0400_0000;
/// ETQF pool field shift (bits 25:20).
pub const ETQF_POOL_SHIFT: u32 = 20;
/// ETQF filter index for FCoE.
pub const ETQF_FILTER_FCOE: u64 = 2;
/// ETQF filter index for FIP.
pub const ETQF_FILTER_FIP: u64 = 4;
/// ETQS bit 31: queue enable.
pub const ETQS_QUEUE_EN: u32 = 0x8000_0000;
/// ETQS RX queue field shift (bits 22:16).
pub const ETQS_RX_QUEUE_SHIFT: u32 = 16;

// ── Redirection table + RX control ───────────────────────────────

/// FCRETA base: FCRETA(i) = 0x0ED10 + i*4.
pub const REG_FCRETA_BASE: u64 = 0x0ED10;
/// FC redirection control.
pub const REG_FCRECTL: u64 = 0x0ED00;
/// FCRECTL bit 0: redirection table enable.
pub const FCRECTL_ENA: u32 = 0x1;
/// FCRETA entries on 82599/X540/X550EM_X.
pub const FCRETA_SIZE: usize = 8;
/// FCRETA entries on X550.
pub const FCRETA_SIZE_X550: usize = 32;
/// FCRETA low queue field (7 bits).
pub const FCRETA_ENTRY_MASK: u32 = 0x0000_007f;
/// FCRETA high queue field (bits 22:16, X550 only).
pub const FCRETA_ENTRY_HIGH_MASK: u32 = 0x007f_0000;
/// FCRETA high queue field shift.
pub const FCRETA_ENTRY_HIGH_SHIFT: u32 = 16;
/// FC receive control.
pub const REG_FCRXCTRL: u64 = 0x05100;
/// FCRXCTRL bit 3: enable last header in sequence (target mode).
pub const FCRXCTRL_LASTSEQH: u32 = 1 << 3;
/// FCRXCTRL bit 7: FC CRC byte ordering (CRC offload on).
pub const FCRXCTRL_FCCRCBO: u32 = 1 << 7;
/// FCRXCTRL FCoE version field shift (bits 11:8).
pub const FCRXCTRL_FCOEVER_SHIFT: u32 = 8;
/// FCoE version (fc_fcoe.h: `#define FC_FCOE_VER 0`).
pub const FC_FCOE_VER: u32 = 0;

// ── DDP context registers ────────────────────────────────────────

/// FC user descriptor pointer low (indirect path).
pub const REG_FCPTRL: u64 = 0x02410;
/// FC user descriptor pointer high (indirect path).
pub const REG_FCPTRH: u64 = 0x02414;
/// FC buffer control (indirect path).
pub const REG_FCBUFF: u64 = 0x02418;
/// FC receive DMA read/write (indirect path).
pub const REG_FCDMARW: u64 = 0x02420;
/// FC offset parameter (indirect path, always programmed 0).
pub const REG_FCPARAM: u64 = 0x051D8;
/// FC filter context (indirect path).
pub const REG_FCFLT: u64 = 0x05108;
/// FC filter read/write control (indirect path).
pub const REG_FCFLTRW: u64 = 0x05110;
/// FCDDC base (X550 direct path): FCDDC(i, xid) = 0x20000 + i*4 + xid*0x10.
pub const REG_FCDDC_BASE: u64 = 0x20000;
/// FCDFC base (X550 direct path): FCDFC(i, xid) = 0x28000 + i*4 + xid*0x10.
pub const REG_FCDFC_BASE: u64 = 0x28000;
/// FCBUFF bit 0: DMA context valid.
pub const FCBUFF_VALID: u32 = 1;
/// FCBUFF buffer-size field (bits 4:3); 4 KB code is 0.
pub const FCBUFF_BUFFSIZE_MASK: u32 = 3 << 3;
/// FCBUFF bit 7: target-mode write context.
pub const FCBUFF_WRCONTX: u32 = 1 << 7;
/// FCBUFF buffer-count field (bits 15:8).
pub const FCBUFF_BUFFCNT_MASK: u32 = 0x0000_ff00;
/// FCBUFF first-buffer offset field (bits 31:16).
pub const FCBUFF_OFFSET_MASK: u32 = 0xffff_0000;
/// FCBUFF buffer-size field shift.
pub const FCBUFF_BUFFSIZE_SHIFT: u32 = 3;
/// FCBUFF buffer-count field shift.
pub const FCBUFF_BUFFCNT_SHIFT: u32 = 8;
/// FCBUFF first-buffer offset field shift.
pub const FCBUFF_OFFSET_SHIFT: u32 = 16;
/// FCDMARW bit 14: write enable.
pub const FCDMARW_WE: u32 = 1 << 14;
/// FCDMARW bit 15: read enable (invalidation check).
pub const FCDMARW_RE: u32 = 1 << 15;
/// FCDMARW last-buffer-size field shift (bits 31:16).
pub const FCDMARW_LASTSIZE_SHIFT: u32 = 16;
/// FCFLTRW bit 14: write enable.
pub const FCFLTRW_WE: u32 = 1 << 14;
/// FCFLT bit 0: filter context valid.
pub const FCFLT_VALID: u32 = 1;
/// DDP user-buffer size (Linux splits every scatterlist into 4 KB pieces).
pub const FCBUFF_MIN: u64 = 4096;
/// Maximum user buffers in one DDP context (8-bit count field's
/// Linux cap; see the count == 256 edge noted on `DdpContext`).
pub const BUFFCNT_MAX: usize = 256;
/// DDP contexts on 82599/X540/X550EM_X (9-bit xid).
pub const DDP_MAX: u16 = 512;
/// DDP contexts on X550 (11-bit xid).
pub const DDP_MAX_X550: u16 = 2048;

// ── RX descriptor FCoE status (ixgbe_type.h) ──────────────────────

/// RXDADV error bit: FCoE EOF error.
pub const RXDADV_ERR_FCEOFE: u32 = 0x8000_0000;
/// RXDADV error field: FCERR/FDIRERR bits.
pub const RXDADV_ERR_FCERR: u32 = 0x0070_0000;
/// FCERR value meaning bad CRC.
pub const FCERR_BADCRC: u32 = 0x0010_0000;
/// RXDADV status field: FCoE packet status (bits 5:4).
pub const RXDADV_STAT_FCSTAT: u32 = 0x0000_0030;
/// FCSTAT 00: no context match.
pub const FCSTAT_NOMTCH: u32 = 0x0000_0000;
/// FCSTAT 01: context without DDP.
pub const FCSTAT_NODDP: u32 = 0x0000_0010;
/// FCSTAT 10: FCP_RSP received.
pub const FCSTAT_FCPRSP: u32 = 0x0000_0020;
/// FCSTAT 11: context with DDP.
pub const FCSTAT_DDP: u32 = 0x0000_0030;

// ── Families ─────────────────────────────────────────────────────

/// DDP programming family. Only X550 takes the direct
/// FCDDC/FCDFC path in Linux; everything else (82599, X540,
/// X550EM_X) takes the indirect FCPTR/FCBUFF path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcoeFamily {
    X550,
    Other,
}

/// Map a PCI device id to its DDP family. X550 only; see the
/// module header on X550EM_X (Linux-literal, datasheet-open).
pub fn family_for(did: u16) -> FcoeFamily {
    if did == super::IXGBE_DEV_X550 {
        FcoeFamily::X550
    } else {
        FcoeFamily::Other
    }
}

/// DDP context limit for a family (Linux's `fcoe_ddp_xid` is
/// MAX − 1 and setup rejects `xid >= that limit` — so the top
/// xid is unusable at setup even though the RX path allows
/// `xid < MAX`. Mirrored literally, including the off-by-one).
pub fn ddp_max(family: FcoeFamily) -> u16 {
    match family {
        FcoeFamily::X550 => DDP_MAX_X550,
        FcoeFamily::Other => DDP_MAX,
    }
}

/// FCRETA entry count for a family.
pub fn fcreta_size(family: FcoeFamily) -> usize {
    match family {
        FcoeFamily::X550 => FCRETA_SIZE_X550,
        FcoeFamily::Other => FCRETA_SIZE,
    }
}

// ── Errors ───────────────────────────────────────────────────────

/// FCoE configuration / DDP errors. `Ixgbe::configure_fcoe`
/// maps every variant to `IxgbeError::Other("bad FCoE config")`;
/// direct `fcoe` users match on the variant.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FcoeError {
    /// No FCoE queues given.
    NoQueues,
    /// A queue index exceeds the 7-bit FCRETA field.
    QueueOutOfRange,
    /// An SR-IOV pool number exceeds the 6-bit ETQF pool field.
    PoolOutOfRange,
    /// xid >= ddp_max − 1 (Linux setup limit, see `ddp_max`).
    XidOutOfRange,
    /// No DMA buffers given for a DDP context.
    EmptyBuffers,
    /// A zero-length DMA buffer (Linux DMA-maps these; NARF
    /// rejects them fail-closed rather than modeling a
    /// zero-length scatterlist entry).
    EmptyBuffer,
    /// More than 256 user buffers after 4 KB splitting.
    TooManyBuffers,
    /// A non-first buffer is not 4 KB aligned.
    UnalignedBuffer,
    /// A non-last buffer does not end at a 4 KB boundary.
    ShortBuffer,
    /// The last piece is exactly 4 KB, which needs the extra
    /// 1-byte buffer Linux appends — but none was supplied.
    MissingExtraBuffer,
}

// ── Configure ────────────────────────────────────────────────────

/// FCoE enable configuration. `queues` is the FCoE RX queue
/// set the FCRETA table round-robins over (and whose first
/// entry receives FIP frames); `sriov_pool` adds the ETQF
/// pool bits when SR-IOV is in use (None = no pool bits,
/// the no-SR-IOV case).
#[derive(Copy, Clone, Debug)]
pub struct FcoeConfig<'a> {
    pub queues: &'a [u32],
    pub sriov_pool: Option<u8>,
}

impl FcoeConfig<'_> {
    /// NARF validation, fail-closed. Linux masks queue indices
    /// to 7 bits (`fcoe_i &= ENTRY_MASK`) instead of rejecting;
    /// NARF rejects so a misconfigured queue can never silently
    /// steer FCoE traffic at the wrong queue. `apply` still
    /// masks defensively (Linux-literal), so validated inputs
    /// and masked inputs agree exactly.
    pub fn validate(&self) -> Result<(), FcoeError> {
        if self.queues.is_empty() {
            return Err(FcoeError::NoQueues);
        }
        for q in self.queues {
            if *q > FCRETA_ENTRY_MASK {
                return Err(FcoeError::QueueOutOfRange);
            }
        }
        if let Some(p) = self.sriov_pool {
            if p > 63 {
                return Err(FcoeError::PoolOutOfRange);
            }
        }
        Ok(())
    }

    fn etqf_word(&self, ethertype: u32, fcoe_bit: bool) -> u32 {
        let mut w = ethertype | ETQF_FILTER_EN;
        if fcoe_bit {
            w |= ETQF_FCOE;
        }
        if let Some(p) = self.sriov_pool {
            w |= ETQF_POOL_ENABLE | ((p as u32) << ETQF_POOL_SHIFT);
        }
        w
    }

    /// Program the FCoE enable sequence, in Linux's order:
    /// ETQF/ETQS FCoE filter, FCRETA table + FCRECTL enable,
    /// ETQF/ETQS FIP filter (FIP -> first FCoE queue), FCRXCTRL
    /// (CRC byte ordering on, version 0). Caller must have
    /// validated first (see `validate`); RX should be disabled
    /// while reprogramming filters, as with RSS/VLAN.
    pub fn apply(&self, bank: &mut impl RegBank, family: FcoeFamily) {
        bank.write32(
            REG_ETQF_BASE + ETQF_FILTER_FCOE * 4,
            self.etqf_word(ETH_P_FCOE, true),
        );
        bank.write32(REG_ETQS_BASE + ETQF_FILTER_FCOE * 4, 0);
        let n = self.queues.len();
        let size = fcreta_size(family);
        for i in 0..size {
            let q_low = self.queues[i % n] & FCRETA_ENTRY_MASK;
            let entry = match family {
                FcoeFamily::X550 => {
                    let q_high = self.queues[(i + size) % n] & FCRETA_ENTRY_MASK;
                    q_low | (q_high << FCRETA_ENTRY_HIGH_SHIFT)
                }
                FcoeFamily::Other => q_low,
            };
            bank.write32(REG_FCRETA_BASE + (i as u64) * 4, entry);
        }
        bank.write32(REG_FCRECTL, FCRECTL_ENA);
        bank.write32(
            REG_ETQF_BASE + ETQF_FILTER_FIP * 4,
            self.etqf_word(ETH_P_FIP, false),
        );
        bank.write32(
            REG_ETQS_BASE + ETQF_FILTER_FIP * 4,
            ETQS_QUEUE_EN | (self.queues[0] << ETQS_RX_QUEUE_SHIFT),
        );
        bank.write32(
            REG_FCRXCTRL,
            FCRXCTRL_FCCRCBO | (FC_FCOE_VER << FCRXCTRL_FCOEVER_SHIFT),
        );
    }
}

// ── DDP contexts ─────────────────────────────────────────────────

/// One caller-provided DMA-mapped buffer for a DDP context
/// (Linux's scatterlist entry after `dma_map_sg`; NARF callers
/// supply already-mapped addresses — this module never maps).
#[derive(Copy, Clone, Debug)]
pub struct DmaBuf {
    pub addr: u64,
    pub len: u64,
}

/// A computed DDP context: the user-descriptor list (4 KB
/// chunk addresses), the FCBUFF/FCDMARW/FCFLTRW words to
/// program, and whether it is a target-mode context.
/// `entries[..count]` holds the chunk addresses; the caller
/// copies them into DMA memory at `udl_dma` and then calls
/// `program_ddp`.
///
/// Linux edge, mirrored: when the chunk count reaches exactly
/// 256 with a non-full last piece, the FCBUFF count field
/// (`count & 0xff`) reads 0 — Linux writes that word verbatim.
/// A count of 256 with a full last piece is rejected instead
/// (the extra-buffer path also caps at 256).
#[derive(Clone, Debug)]
pub struct DdpContext {
    pub entries: [u64; BUFFCNT_MAX],
    pub count: usize,
    pub firstoff: u32,
    pub lastsize: u32,
    pub fcbuff: u32,
    pub fcdmarw: u32,
    pub fcfltrw: u32,
    pub target: bool,
}

/// Compute a DDP context from DMA buffers, mirroring Linux's
/// `ixgbe_fcoe_ddp_setup` chunking exactly: split every
/// buffer into 4 KB pieces; only the first piece may start
/// unaligned (its offset becomes `firstoff`); every non-last
/// piece must end at a 4 KB boundary; a last piece of exactly
/// 4 KB appends the caller's extra 1-byte buffer (Linux's
/// `extra_ddp_buffer_dma`) and sets `lastsize` to 1.
pub fn ddp_context(
    xid: u16,
    family: FcoeFamily,
    bufs: &[DmaBuf],
    target_mode: bool,
    extra_dma: Option<u64>,
) -> Result<DdpContext, FcoeError> {
    let max = ddp_max(family);
    if xid >= max - 1 {
        return Err(FcoeError::XidOutOfRange);
    }
    if bufs.is_empty() {
        return Err(FcoeError::EmptyBuffers);
    }
    let mut entries = [0u64; BUFFCNT_MAX];
    let mut j = 0usize;
    let mut firstoff = 0u32;
    let mut thisoff = 0u32;
    let mut thislen = 0u64;
    let last = bufs.len() - 1;
    for (i, b) in bufs.iter().enumerate() {
        if b.len == 0 {
            return Err(FcoeError::EmptyBuffer);
        }
        let mut addr = b.addr;
        let mut len = b.len;
        while len > 0 {
            if j >= BUFFCNT_MAX {
                return Err(FcoeError::TooManyBuffers);
            }
            thisoff = (addr & (FCBUFF_MIN - 1)) as u32;
            thislen = (FCBUFF_MIN - thisoff as u64).min(len);
            if j != 0 && thisoff != 0 {
                return Err(FcoeError::UnalignedBuffer);
            }
            if (i != last || thislen != len) && (thislen + thisoff as u64) != FCBUFF_MIN {
                return Err(FcoeError::ShortBuffer);
            }
            entries[j] = addr - thisoff as u64;
            if j == 0 {
                firstoff = thisoff;
            }
            len -= thislen;
            addr += thislen;
            j += 1;
        }
    }
    let mut lastsize = thisoff as u64 + thislen;
    let mut count = j;
    if lastsize == FCBUFF_MIN {
        if j >= BUFFCNT_MAX {
            return Err(FcoeError::TooManyBuffers);
        }
        let extra = extra_dma.ok_or(FcoeError::MissingExtraBuffer)?;
        entries[j] = extra;
        j += 1;
        count = j;
        lastsize = 1;
    }
    let mut fcbuff = (0u32 << FCBUFF_BUFFSIZE_SHIFT)
        | ((count as u32 & 0xff) << FCBUFF_BUFFCNT_SHIFT)
        | (firstoff << FCBUFF_OFFSET_SHIFT);
    if target_mode {
        fcbuff |= FCBUFF_WRCONTX;
    }
    fcbuff |= FCBUFF_VALID;
    let fcdmarw = (xid as u32) | FCDMARW_WE | ((lastsize as u32) << FCDMARW_LASTSIZE_SHIFT);
    let fcfltrw = (xid as u32) | FCFLTRW_WE;
    Ok(DdpContext {
        entries,
        count,
        firstoff,
        lastsize: lastsize as u32,
        fcbuff,
        fcdmarw,
        fcfltrw,
        target: target_mode,
    })
}

/// Program a computed DDP context. X550 writes the direct
/// FCDDC/FCDFC context; everything else writes the indirect
/// FCPTR/FCBUFF/FCDMARW + FCPARAM/FCFLT/FCFLTRW sequence.
/// Target mode ORs FCRXCTRL_LASTSEQH first (Linux does this
/// once via a mode bit on first target setup; the OR is
/// idempotent, so doing it on every target program reaches
/// the identical final state).
///
/// Caller contract (mirroring Linux's `spin_lock_bh(&fcoe->lock)`
/// around the indirect path): the caller must hold the driver
/// lock across this call — two concurrent indirect programs
/// would interleave FCPTR/FCBUFF writes.
pub fn program_ddp(
    bank: &mut impl RegBank,
    family: FcoeFamily,
    xid: u16,
    udl_dma: u64,
    ctx: &DdpContext,
) {
    if ctx.target {
        let fcrxctl = bank.read32(REG_FCRXCTRL) | FCRXCTRL_LASTSEQH;
        bank.write32(REG_FCRXCTRL, fcrxctl);
    }
    match family {
        FcoeFamily::X550 => {
            let base = REG_FCDDC_BASE + (xid as u64) * 0x10;
            bank.write32(base, udl_dma as u32);
            bank.write32(base + 4, (udl_dma >> 32) as u32);
            bank.write32(base + 8, ctx.fcbuff);
            bank.write32(base + 12, ctx.fcdmarw);
            let fbase = REG_FCDFC_BASE + (xid as u64) * 0x10;
            bank.write32(fbase, FCFLT_VALID);
            bank.write32(fbase + 4, 0);
            bank.write32(fbase + 12, ctx.fcfltrw);
        }
        FcoeFamily::Other => {
            bank.write32(REG_FCPTRL, udl_dma as u32);
            bank.write32(REG_FCPTRH, (udl_dma >> 32) as u32);
            bank.write32(REG_FCBUFF, ctx.fcbuff);
            bank.write32(REG_FCDMARW, ctx.fcdmarw);
            bank.write32(REG_FCPARAM, 0);
            bank.write32(REG_FCFLT, FCFLT_VALID);
            bank.write32(REG_FCFLTRW, ctx.fcfltrw);
        }
    }
}

/// Invalidate a DDP context after an error, mirroring Linux's
/// `ixgbe_fcoe_ddp_put` invalidation sequence. With no error
/// (`had_error == false`) nothing is written (Linux's
/// `skip_ddpinv`). Returns true when the read-back still
/// shows the context VALID — Linux then sleeps 100–150 µs
/// and the context is guaranteed invalid after; the NARF
/// caller owns that wait (no sleep in this register path).
/// In fixtures the bank models instant invalidation, so this
/// returns false after the clearing writes.
pub fn invalidate_ddp(
    bank: &mut impl RegBank,
    family: FcoeFamily,
    xid: u16,
    had_error: bool,
) -> bool {
    if !had_error {
        return false;
    }
    match family {
        FcoeFamily::X550 => {
            let fbase = REG_FCDFC_BASE + (xid as u64) * 0x10;
            bank.write32(fbase, 0);
            bank.write32(fbase + 12, (xid as u32) | FCFLTRW_WE);
            let base = REG_FCDDC_BASE + (xid as u64) * 0x10;
            bank.write32(base + 8, 0);
            bank.write32(base + 12, (xid as u32) | FCDMARW_WE);
            bank.write32(base + 12, (xid as u32) | FCDMARW_RE);
            bank.read32(base + 8) & FCBUFF_VALID != 0
        }
        FcoeFamily::Other => {
            bank.write32(REG_FCFLT, 0);
            bank.write32(REG_FCFLTRW, (xid as u32) | FCFLTRW_WE);
            bank.write32(REG_FCBUFF, 0);
            bank.write32(REG_FCDMARW, (xid as u32) | FCDMARW_WE);
            bank.write32(REG_FCDMARW, (xid as u32) | FCDMARW_RE);
            bank.read32(REG_FCBUFF) & FCBUFF_VALID != 0
        }
    }
}

// ── WWN ──────────────────────────────────────────────────────────

/// Compose a WWN from its NVM prefix and SAN MAC address,
/// mirroring Linux's `ixgbe_fcoe_get_wwn` formula
/// (`prefix << 48 | san_addr bytes`). Returns None when the
/// prefix is unset (0xffff) or the SAN address is not a valid
/// unicast Ethernet address (zero, or multicast) — the same
/// gates Linux applies before writing `*wwn`. Provisioning
/// (reading the prefixes + SAN address from NVM) is a
/// follow-up; this is the pure composition only.
pub fn wwn_compose(prefix: u16, san_addr: &[u8; 6]) -> Option<u64> {
    if prefix == 0xffff {
        return None;
    }
    if san_addr == &[0; 6] || san_addr[0] & 1 != 0 {
        return None;
    }
    Some(
        ((prefix as u64) << 48)
            | ((san_addr[0] as u64) << 40)
            | ((san_addr[1] as u64) << 32)
            | ((san_addr[2] as u64) << 24)
            | ((san_addr[3] as u64) << 16)
            | ((san_addr[4] as u64) << 8)
            | (san_addr[5] as u64),
    )
}

// ── RX completion classification ─────────────────────────────────

/// Outcome of classifying one RX completion for DDP, mirroring
/// Linux's `ixgbe_fcoe_ddp` return convention: `Bypass` (0)
/// means the data was DDPed and bypasses the upper layer;
/// `PassThrough(len)` means the upper layer still gets the
/// frame with `len` bytes of DDPed data; `Invalid` (-EINVAL)
/// means no DDP applies. The FC-frame parsing that extracts
/// the xid (EX_CTX -> ox_id, else rx_id) is FC-stack work
/// and a follow-up; this takes the already-decided
/// `has_context` (whether a DDP context is programmed for
/// the frame's xid) and the descriptor's `ddp_len` field
/// (the RSS word Linux reads the DDP length from).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxOutcome {
    Bypass,
    PassThrough(u32),
    Invalid,
}

/// Classify by descriptor status/error word and DDP length.
/// Any FCEOFE/FCERR error bit forces `Invalid` (Linux returns
/// -EINVAL before the FCSTAT switch); without a programmed
/// context the frame is `Invalid` (Linux's null-`udl` check).
pub fn classify_rx(staterr: u32, ddp_len: u32, has_context: bool) -> RxOutcome {
    if !has_context {
        return RxOutcome::Invalid;
    }
    if staterr & (RXDADV_ERR_FCEOFE | RXDADV_ERR_FCERR) != 0 {
        return RxOutcome::Invalid;
    }
    match staterr & RXDADV_STAT_FCSTAT {
        FCSTAT_DDP => RxOutcome::Bypass,
        FCSTAT_FCPRSP | FCSTAT_NODDP => {
            if ddp_len > 0 {
                RxOutcome::PassThrough(ddp_len)
            } else {
                RxOutcome::Invalid
            }
        }
        _ => RxOutcome::Invalid,
    }
}

/// CRC-offload verdict for a completion, mirroring Linux's
/// `ixgbe_fcoe_ddp` checksum assignment: a BADCRC error means
/// the stack must treat the checksum as unverified
/// (`CHECKSUM_NONE`); anything else was CRC-checked by
/// hardware (`CHECKSUM_UNNECESSARY`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CsumVerdict {
    None,
    Unnecessary,
}

/// Checksum verdict for a completion (Linux's `ixgbe_fcoe_cksum`):
/// BADCRC means the frame's checksum is bad; anything else means
/// hardware already validated it.
pub fn csum_verdict(staterr: u32) -> CsumVerdict {
    if staterr & RXDADV_ERR_FCERR == FCERR_BADCRC {
        CsumVerdict::None
    } else {
        CsumVerdict::Unnecessary
    }
}
