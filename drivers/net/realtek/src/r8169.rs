//! Realtek RTL8168 / RTL8111 family driver — PCIe Gigabit Ethernet
//! controller used on a wide swathe of consumer / laptop boards
//! (including the user's AMD Ryzen 7 PRO 8840HS Phoenix laptop).
//!
//! Stage-4 cut + Linux compared feature set: probe + reset +
//! TX/RX rings + one MSI-X vector, plus XID-decoded MAC version,
//! TX checksum (TCP/UDP, v4/v6) and TSO (v2 layout on csum-v2
//! chips, v1 layout on older chips), VLAN tag insertion on TX,
//! RX checksum decode, jumbo-sized rings / RMS / MTPS, WoL
//! register programming, and an EEE capability model. Deliberate
//! asymmetries, all Linux-faithful: RX VLAN stripping stays OFF
//! (NARF's `Frame::rx_meta` has no VLAN-tag field, so stripping
//! would discard tags); the interface MTU starts at 1500 with
//! offloads advertised, and the runtime MTU switch (#1276)
//! keeps them consistent: it validates 68..=version-max,
//! programs the jumbo Config bits (+ MTPS override on
//! VER_31..33), and republishes the offload advertisement
//! exactly where Linux's `rtl8169_fix_features` withdraws it
//! (jumbo MTU on MAC > VER_06 drops CSUM + TSO; MTU > 2047
//! drops TSO on every version), so advertised caps always
//! match the programmed hardware; RSS is not a gap here (Linux keeps
//! one RX ring on 8168). Still missing: GMII auto-negotiation
//! tuning, EEE PHY advertisement, and the 8168evl (VER_34) ERI
//! step for WoL magic packets. Per-revision 8168 PHY tables are
//! programmed by `crate::rtl8168` during bring-up.
//! (reported by `set_wol_opts`, not silently dropped).
//!
//! ## Reference
//!
//! Realtek "RTL8111B/RTL8168B Integrated Gigabit Ethernet Controller
//! for PCI Express Applications — Registers Datasheet" Rev. 1.0
//! (26 January 2006, Track ID JATR-1076-21). Public document; the
//! "B" revision register layout is the on-wire layout every later
//! 81xx variant inherits as its baseline (newer revisions add bits
//! / capabilities, but offset 0x00..0xEF stays put).
//!
//! Register surface used here (`offset`, `name`, `description`):
//!
//! | offset | name     | description                                |
//! |--------|----------|--------------------------------------------|
//! | 0x00   | IDR0..5  | MAC address (byte-readable, 4-byte writes) |
//! | 0x20   | TNPDS    | TX normal-priority desc base (64-bit)      |
//! | 0x37   | CR       | Command — RST/RE/TE                        |
//! | 0x38   | TPPoll   | TX priority polling — NPQ doorbell         |
//! | 0x3C   | IMR      | Interrupt Mask (16-bit)                    |
//! | 0x3E   | ISR      | Interrupt Status (16-bit, w1c)             |
//! | 0x40   | TCR      | TX config — MXDMA / IFG                    |
//! | 0x44   | RCR      | RX config — accept-mask / MXDMA / RXFTH    |
//! | 0x50   | 9346CR   | Config-register write-lock latch           |
//! | 0x6C   | PHYStatus| PHY status — LinkSts at bit 1              |
//! | 0xDA   | RMS      | RX max packet size (14-bit)                |
//! | 0xE0   | C+CR     | C+ Command — VLAN/csum offload toggles     |
//! | 0xE4   | RDSAR    | RX desc base (64-bit, 256-byte aligned)    |
//! | 0xEC   | MTPS     | Max TX packet size, units of 128 bytes     |
//!
//! Descriptor format (16 bytes each, native-endian; per datasheet
//! §6.1.1 Tables 51 + 55):
//!
//! ```text
//!   word0:  flags (OWN/EOR/FS/LS/...) | frame_length[15:0]
//!   word1:  VLAN tag bits + v2 offload fields (MSS / csum bits /
//!           TCPHO) — see `crate::features` for the layout
//!   word2:  buffer phys addr  low  32 bits
//!   word3:  buffer phys addr  high 32 bits
//! ```
//!
//! Bring-up sequence per §7 "Driver Programming Note": program C+CR
//! first, then CR (TE|RE), then the rest. RST is self-clearing.

use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, Ordering};

use alloc::sync::Arc;
use narf_ipc::{channel, Consumer, Producer};
use narf_net::{Frame, TxMeta, RX_RING_N, TX_RING_N};
// Driver-runtime abstraction — same import shape works for the
// kernel runtime (`feature = "kernel"`, default) and a future
// userspace runtime (`feature = "userspace"`). See
// `narf-driver-runtime` for the rationale + the cap-mediated
// userspace plumbing roadmap.
use narf_driver_runtime::{
    alloc_coherent, map_bar, BusDevice, BusDeviceCap, Cap, DmaBuffer, DomainId,
    Lock as IrqSafeSpinLock, MmioRegion, Write,
};

// ── PCI ids ─────────────────────────────────────────────────────────

/// Vendor: Realtek Semiconductor Corp.
pub const RTL_VENDOR: u16 = 0x10EC;
/// RTL8168/RTL8111 — the wired Gigabit family. Ships on most modern
/// Realtek-equipped boards regardless of internal sub-revision; the
/// PCI ID stays fixed across B/C/D/E/F/G/H/I sub-rev cuts.
pub const RTL_DEV_8168: u16 = 0x8168;

// ── Register offsets ────────────────────────────────────────────────

const REG_IDR0: u64 = 0x00;
const REG_TNPDS: u64 = 0x20;
const REG_CR: u64 = 0x37;
const REG_TPPOLL: u64 = 0x38;
const REG_IMR: u64 = 0x3C;
const REG_ISR: u64 = 0x3E;
const REG_TCR: u64 = 0x40;
const REG_RCR: u64 = 0x44;
const REG_9346CR: u64 = 0x50;
const REG_PHYSTAT: u64 = 0x6C;
const REG_RMS: u64 = 0xDA;
const REG_RDSAR: u64 = 0xE4;
const REG_MTPS: u64 = 0xEC;

// CR bits.
const CR_TE: u8 = 1 << 2;
const CR_RE: u8 = 1 << 3;
const CR_RST: u8 = 1 << 4;

// TPPoll bits.
const TPPOLL_NPQ: u8 = 1 << 6;

// 9346CR (config-write lock). Bits 7:6 = EEM. 00=normal, 11=config-
// register write-enable.
const EEM_NORMAL: u8 = 0x00;
const EEM_CONFIG_WRITE: u8 = 0xC0;

// RCR bits.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const RCR_AAP: u32 = 1 << 0; // Accept All (promiscuous)
const RCR_APM: u32 = 1 << 1; // Accept Physical Match
const RCR_AM: u32 = 1 << 2; // Accept Multicast
const RCR_AB: u32 = 1 << 3; // Accept Broadcast
                            // MXDMA[10:8] = 0b111 = unlimited, RXFTH[15:13] = 0b111 = no threshold.
const RCR_MXDMA_UNLIMITED: u32 = 0b111 << 8;
const RCR_RXFTH_NONE: u32 = 0b111 << 13;

// TCR bits. MXDMA[10:8] = 0b111 = unlimited; IFG default = 0b011 at
// bits 25:24 (96 ns at 1 Gbps — IEEE 802.3 minimum).
const TCR_MXDMA_UNLIMITED: u32 = 0b111 << 8;
const TCR_IFG_STD: u32 = 0b11 << 24;

// ISR / IMR bits we actually wire.
const INT_ROK: u16 = 1 << 0;
const INT_TOK: u16 = 1 << 2;
const INT_LINKCHG: u16 = 1 << 5;
const INT_RDU: u16 = 1 << 4;
const INT_TDU: u16 = 1 << 7;

// PHYStatus bits (same layout as the 8125 family: Linux `enum
// rtl_register_content` — bit 7 TBI_Enable, bit 6 TxFlowCtrl,
// bit 5 RxFlowCtrl, bit 4 _1000bpsF, bit 3 _100bps, bit 2
// _10bps, bit 1 LinkStatus, bit 0 FullDup). On this 1G-ceiling
// part the byte is the exact rate — no multigig rate hides
// behind the 1000M bit, so no PHY read is needed to report it.
pub const PHYSTAT_LINKSTS: u8 = 1 << 1;
pub const PHYSTAT_FULLDUP: u8 = 1 << 0;
const PHYSTAT_10BPS: u8 = 1 << 2;
const PHYSTAT_100BPS: u8 = 1 << 3;
const PHYSTAT_1000BPSF: u8 = 1 << 4;

// TX descriptor flags (word0 high bits).
const TXD_OWN: u32 = 1 << 31;
const TXD_EOR: u32 = 1 << 30;
const TXD_FS: u32 = 1 << 29;
const TXD_LS: u32 = 1 << 28;

// TX offload bits — canonical definitions live in
// `crate::features` (corrected placement: v2 GTSENV/GTTCPHO in
// word0, MSS/csum bits/TCPHO in word1). Re-exported here so
// existing users of these names keep compiling. The previous
// in-tree comments placed the v2 bits in word1, which was wrong
// and would have corrupted the MSS field; see `features.rs`.
/// Historic spelling of [`TD1_IPV4_CS`].
pub use crate::features::TD1_IPV4_CS as TD1_IPv4_CS;
pub use crate::features::{
    TD0_IP_CS, TD0_MSS_SHIFT, TD0_TCP_CS, TD0_UDP_CS, TD1_GTSENV4, TD1_GTSENV6, TD1_IPV4_CS,
    TD1_MSS_SHIFT, TD1_TCP_CS, TD1_UDP_CS, TD_LSO,
};

// RX status bits in word0 returned by hardware after a received
// frame. Source: Linux r8169_main.c; IPFail/UDPFail/TCPFail in
// the RX descriptor. The previous in-tree "OK" bits (RX_IPOK /
// RX_TCPOK / RX_UDPOK, bits 5/6/7) were frame-length bits, not
// protocol bits, and are deleted; decode through
// [`Desc::rx_csum_result`], which uses the PID/fail rule.
pub use crate::features::{
    RX_FAIL_IP as RX_IPFAIL, RX_FAIL_TCP as RX_TCPFAIL, RX_FAIL_UDP as RX_UDPFAIL,
};
pub use crate::features::{RX_PID_TCP, RX_PID_UDP};

/// RX checksum verification result decoded from `Desc.flags_len` on
/// a chip-returned RX descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RxCsumResult {
    /// Hardware did not compute a checksum for this frame.
    None,
    /// Hardware computed and verified the checksum — no errors.
    Ok,
    /// Hardware detected a checksum error.
    Fail,
}

// RX descriptor flags (word0 high bits).
const RXD_OWN: u32 = 1 << 31;
const RXD_EOR: u32 = 1 << 30;
const RXD_LS: u32 = 1 << 28;
// Frame length lives in word0 bits[13:0] in the *status* layout
// (after the NIC clears OWN). It overlaps the BufferSize field of the
// command layout but is read after the NIC has flipped OWN to 0.

// ── Sizing constants ────────────────────────────────────────────────

/// Descriptor count per ring. Datasheet §2.1 caps each ring at 1024
/// descriptors; 256 is plenty for a Stage-4 driver and lands a full
/// ring (256 * 16 = 4096 bytes) inside one `alloc_coherent` page.
pub const RING_LEN: usize = 256;
const RING_BYTES: usize = RING_LEN * 16;

/// TX watchdog timeout (Linux `dev->watchdog_timeo` is 5 s by
/// default — see the `transmit_irq_async` note; igc's supervisor
/// uses the same 5 s): a TX descriptor posted longer ago than this
/// with OWN still set is a wedged ring, not congestion.
const TX_TIMEOUT_NS: u64 = 5_000_000_000;
/// Watchdog supervisor cadence, matching igc's 10 ms maintenance tick.
const TX_WATCHDOG_POLL_NS: u64 = 10_000_000;

/// RX buffer size. Linux sizes every RX buffer on this family to
/// `R8169_RX_BUF_SIZE` (16 KiB − 1) and programs RMS to the
/// buffer bound, independent of MTU; jumbo frames are therefore
/// receivable even while the interface MTU stays 1500 (see the
/// module header on the MTU/offload trade-off).
pub const RX_BUF_LEN: usize = 16383;

/// TX slot buffer size: one slot must hold the largest frame this
/// driver will transmit — the chip's jumbo tagged frame, capped
/// here at 16 KiB (the family buffer bound).
pub const TX_BUF_LEN: usize = 16384;

/// MTPS units are 128 bytes; MTPS == 0 is reserved/illegal per
/// §2.21. The bring-up value is computed from the chip's jumbo
/// frame size (per-version override for VER_31..33), not a fixed
/// constant, so no `MTPS_DEFAULT` remains.
///
/// Max RX packet length (RMS register, 14-bit): the buffer bound
/// 16383, matching Linux's `rtl_set_rx_max_size`.

/// True when any posted TX descriptor has waited longer than
/// `timeout` cycles with OWN still set — the ring is wedged (igc
/// `Queue::stalled` shape, per-slot so a later post cannot mask
/// an older stuck one). Factored pure so the fixture pins the
/// decision the watchdog uses.
fn tx_stalled(posted_at: &[u64; RING_LEN], now: u64, timeout: u64) -> bool {
    posted_at
        .iter()
        .any(|&posted| posted != 0 && now.wrapping_sub(posted) > timeout)
}

/// Clear a slot's post time only if it still holds the stamp this
/// post recorded: a later post to the same slot (after wraparound)
/// must not have its stamp wiped by the earlier post's completion.
fn tx_note_completed(posted_at: &mut [u64; RING_LEN], slot: usize, stamped: u64) {
    if posted_at[slot] == stamped {
        posted_at[slot] = 0;
    }
}

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    NoMemory,
    /// Frame outside [1, chip max frame].
    FrameTooLong,
    /// `transmit` couldn't find a free TX descriptor.
    TxRingFull,
    /// `transmit` polled too long for OWN to clear.
    TxTimeout,
    /// `recover` polled too long for CR.RST to self-clear.
    ResetTimeout,
    /// MSI-X table couldn't be brought up.
    MsixSetup,
    /// The device is suspended for system suspend (issue #793):
    /// the datapath gates refuse TX and RX while suspended.
    Suspended,
    /// The requested TX offload cannot be programmed for this
    /// frame (unparseable transport header, SCTP, MSS/offset
    /// overflow, or TSO on a chip that cannot take it).
    UnsupportedOffload,
}

// ── Descriptor in-memory shape ──────────────────────────────────────

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub struct Desc {
    /// Bits [31..14] are flags (OWN/EOR/FS/LS/... in TX; OWN/EOR/... +
    /// frame length in RX status), bits [13..0] are buffer size or
    /// frame length depending on direction.
    pub flags_len: u32,
    pub vlan: u32,
    pub addr_lo: u32,
    pub addr_hi: u32,
}
const _: () = assert!(core::mem::size_of::<Desc>() == 16);

// ── Descriptor offload builders ─────────────────────────────────────

impl Desc {
    /// Build a TX descriptor from pre-computed offload words (see
    /// `crate::features::v1_csum_words` / `v2_tso_words` and kin).
    /// `flags_len` carries OWN | FS | LS | length plus the
    /// word0 offload bits; `vlan` carries the word1 offload bits
    /// (MSS / csum bits / TCPHO / VLAN-insert field).
    pub fn tx_with_offload(
        addr_lo: u32,
        addr_hi: u32,
        len: u16,
        words: crate::features::OffloadWords,
    ) -> Self {
        Desc {
            flags_len: TXD_OWN | TXD_FS | TXD_LS | (len as u32) | words.word0,
            vlan: words.word1,
            addr_lo,
            addr_hi,
        }
    }

    /// Decode the RX checksum result from a chip-returned
    /// descriptor, using the Linux PID/fail rule (see
    /// `crate::features::rx_csum_decode`): a checksum is trusted
    /// only when exactly one protocol-ID bit is set and no fail
    /// bit is set. The previous in-tree decode read bits 5/6/7
    /// as protocol-OK bits; those bits are frame-length bits, so
    /// it misclassified length-dependent frames.
    pub fn rx_csum_result(&self) -> RxCsumResult {
        let decoded = crate::features::rx_csum_decode(self.flags_len);
        if decoded.l4_ok {
            RxCsumResult::Ok
        } else if self.flags_len & (RX_IPFAIL | RX_TCPFAIL | RX_UDPFAIL) != 0 {
            RxCsumResult::Fail
        } else {
            RxCsumResult::None
        }
    }
}

// ── Driver state ────────────────────────────────────────────────────

/// A live RTL8168/RTL8111 Gigabit Ethernet controller. Holds the
/// MMIO mapping, the descriptor rings, and the RX buffer pool.
pub struct RtlNic {
    mmio: MmioRegion,
    /// TX descriptor ring DMA buffer (`RING_LEN * 16` bytes).
    tx_ring: DmaBuffer,
    /// Persistent per-slot TX frame buffers (audit #4 — pre-fix
    /// every tx()/tx_async() did `alloc_coherent(4096)` per
    /// frame and dropped it on return). Pool length matches
    /// RING_LEN so slot index trivially keys into the pool.
    tx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side TX producer cursor (next slot to fill).
    tx_head: IrqSafeSpinLock<u32>,
    /// Cycle counter at which each TX slot was posted (`0` = no
    /// descriptor outstanding). The watchdog treats an aged entry
    /// as a wedged ring. Stamped by `transmit` /
    /// `transmit_irq_async` after the doorbell, cleared when the
    /// slot's OWN bit clears.
    tx_posted_at: IrqSafeSpinLock<[u64; RING_LEN]>,
    /// TX stall recoveries (Linux `tx_timeout_count`): incremented
    /// by the watchdog supervisor when it fires `recover()` on a
    /// ring stalled 5 s, mirroring igc's `tx_timeouts`.
    tx_timeouts: AtomicU64,
    /// Controller resets performed by [`RtlNic::recover`].
    tx_resets: AtomicU64,
    /// Set while [`RtlNic::recover`] owns the reset sequence: TX
    /// posts fail fast instead of racing the ring reprogram (a post
    /// landing mid-reset could be zeroed with the stale ring or
    /// never rung).
    recovering: AtomicBool,
    /// TX ring epoch, advanced by [`RtlNic::recover`] on every
    /// recovery. A `transmit` whose OWN poll straddles a reset sees
    /// OWN clear because the reset zeroed the ring — not because
    /// its frame went out. The epoch distinguishes a real
    /// completion from a reset, so that caller reports `TxTimeout`
    /// instead of a success it did not earn.
    tx_epoch: AtomicU64,
    /// RX descriptor ring DMA buffer (`RING_LEN * 16` bytes).
    rx_ring: DmaBuffer,
    /// One DMA buffer per RX descriptor. Kept alive for the lifetime
    /// of the driver — descriptor `i` always points at `rx_pool[i]`.
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side RX consumer cursor.
    rx_head: IrqSafeSpinLock<u32>,
    /// MAC address read from IDR0..5 at bring-up.
    pub mac: [u8; 6],
    /// Decoded MAC version (`RTL_GIGA_MAC_VER_*` number) from the
    /// TxConfig XID at bring-up, or `None` when the XID matches
    /// no known table entry (Linux then treats the chip as
    /// csum-v2-capable by default).
    pub mac_version: Option<u32>,
    /// Whether this chip uses the v2 TX offload layout (word0
    /// GTSENV/GTTCPHO, word1 MSS/csum/TCPHO). False for VER_02..06
    /// and VER_10..17; true otherwise, including unknown XIDs.
    pub csum_v2: bool,
    /// Programmed interface MTU, the source of truth for
    /// `Interface::mtu` / `HwNic::mtu` and the offload
    /// advertisement (#1276). Starts at 1500; the
    /// [`RtlMtuControl`] hook is the only writer after
    /// bring-up, and only after validating + programming the
    /// switch — so the stored value always matches hardware.
    mtu: IrqSafeSpinLock<u32>,
    /// Last WoL option set programmed via [`RtlNic::set_wol_opts`].
    wol_opts: IrqSafeSpinLock<crate::features::WolOpts>,
    /// True when PHYStatus.LinkSts read 1 at bring-up. Probe-time
    /// snapshot only — the RX pump re-samples PHYStatus every pass
    /// and republishes transitions into iface metadata (issue #791),
    /// which is where live carrier lives; see `r8169_rx_pump`.
    pub link_up: bool,
    /// Set by `suspend`, cleared by `resume`: the datapath gates
    /// refuse TX and RX while this is set (issue #793).
    suspended: AtomicBool,
    /// IDT vector wired to MSI-X entry 0, when MSI-X is enabled.
    pub irq_vector: Option<u8>,
    /// Live MSI-X table — kept alive so the device's MSI-X enable
    /// stays sticky.
    msix: Option<narf_bus::MsixTable>,
    /// PCI address of the function this instance drives. Probe
    /// refuses a second bind of the same address (issue #795): two
    /// `RtlNic`s for one chip would drive one set of rings.
    pub addr: narf_bus::BusAddr,
    /// Interface name `publish_netdev_with_context` assigned this
    /// instance (`eth%d`). Per-instance (i40e/igc pattern): the old
    /// module-level `R8169_IFNAME` static could only name one NIC.
    ifname: crate::publish::IfName,

    // IPC integration
    pub rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

// SAFETY: `RtlNic` is only `!Send` because of the raw MMIO/DMA pointers it
// wraps (`MmioRegion`, `DmaBuffer`). Those regions are owned exclusively by
// this instance and remain valid for its whole lifetime, so the owning value
// may be moved to and accessed from another CPU without aliasing them.
unsafe impl Send for RtlNic {}
// SAFETY: every field mutated after bring-up (TX/RX cursors, IPC rings) is
// guarded by an `IrqSafeSpinLock`; the post-init read-only fields (`mmio`,
// `mac`, the descriptor rings/pools) are not written through `&self`, so
// concurrent `&RtlNic` access from multiple CPUs/IRQ contexts is data-race free.
unsafe impl Sync for RtlNic {}

impl core::fmt::Debug for RtlNic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtlNic")
            .field("mac", &self.mac)
            .field("link_up", &self.link_up)
            .field("irq_vector", &self.irq_vector)
            .finish_non_exhaustive()
    }
}

impl RtlNic {
    /// Bring up the controller: reset, read MAC, install TX + RX
    /// rings, enable receive + transmit, observe link state.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively for
    /// the duration of init.
    pub unsafe fn bring_up(
        device: &BusDevice,
        _cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Arc<Self>, NicError> {
        // RTL8168 lays its operational registers in BAR2 (MMIO);
        // BAR0 is the legacy I/O alias. We always take the MMIO BAR.
        // SAFETY: caller-asserted exclusive ownership.
        let mmio = unsafe { map_bar(device, 2) }.map_err(|_| NicError::BarMapFailed)?;

        // 1. Software reset. CR.RST self-clears once the chip has
        //    finished re-initialising the FIFOs + descriptor pointers
        //    (datasheet §2.3 Table 3).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write8(REG_CR, CR_RST);
        }
        // Wait for hardware to clear CR.RST. responsive_spin_until
        // ticks sleep_pumps so FB cursor / serial / audio stay alive
        // on a slow reset. RTL8169 CR.RST self-clears within ~1 ms
        // typical (datasheet §2.3 Table 3); 100 ms wedge threshold.
        narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { mmio.read8(REG_CR) } & CR_RST == 0,
            narf_time::Deadline::after_ms(100),
        );

        // 2. Read MAC from IDR0..5. ID registers are byte-readable
        //    but only 4-byte writable, so we read four bytes + two
        //    bytes (datasheet §2.1 Table 1).
        // SAFETY: identity-mapped.
        let mac = unsafe {
            [
                mmio.read8(REG_IDR0),
                mmio.read8(REG_IDR0 + 1),
                mmio.read8(REG_IDR0 + 2),
                mmio.read8(REG_IDR0 + 3),
                mmio.read8(REG_IDR0 + 4),
                mmio.read8(REG_IDR0 + 5),
            ]
        };

        // 3. Allocate TX + RX rings + RX buffer pool. `alloc_coherent`
        //    returns zeroed pages, which is what we need: a fresh ring
        //    has every descriptor's OWN bit clear, i.e. owned by the
        //    host. The RX-side OWN bits get flipped to NIC-owned in
        //    step 5b.
        let tx_ring =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let rx_ring =
            alloc_coherent(RING_BYTES, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?;
        let mut rx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            rx_pool.push(
                alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?,
            );
        }
        let mut tx_pool: alloc::vec::Vec<DmaBuffer> = alloc::vec::Vec::with_capacity(RING_LEN);
        for _ in 0..RING_LEN {
            tx_pool.push(
                alloc_coherent(TX_BUF_LEN, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?,
            );
        }

        // 2.5. Decode the MAC version from TxConfig's XID field
        //     BEFORE step 5a overwrites TCR. Linux reads the same
        //     register at probe (`rtl_read_mac_version`); the
        //     reset-default TCR carries the chip's XID in bits
        //     29:20 (masked to 0xfcf by the table matcher).
        // SAFETY: identity-mapped.
        let txcfg = unsafe { mmio.read32(REG_TCR) };
        let mac_version = crate::features::mac_version_from_xid(txcfg);
        let csum_v2 = crate::features::supports_csum_v2(mac_version);

        // 2.6. Program the PHY for this chip revision
        //     (`crate::rtl8168`). A failed table step is logged,
        //     not fatal: the registers it already programmed stay
        //     programmed, and the pre-existing bring-up (which
        //     programmed no PHY registers at all) still proceeds.
        //     SAFETY: identity-mapped.
        if let Err(e) = crate::rtl8168::configure_phy_8168(&mmio, mac_version, txcfg) {
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "  r8169: PHY table aborted: {:?}; continuing bring-up",
                e,
            );
        }

        // 4. C+CR first per §7 step 1. Enable RX checksum offload
        //    (the RX pump decodes it into `Frame::rx_meta`) and
        //    keep RX VLAN stripping OFF: NARF's `Frame::rx_meta`
        //    has no VLAN-tag field, so stripping would discard
        //    tags the stack needs. TX VLAN insertion is
        //    independent of this bit and is always available.
        //    NORMAL mode is preserved; INTT timing bits are
        //    preserved (Linux's `CPCMD_MASK` shape).
        // SAFETY: bring_up owns the BAR exclusively.
        unsafe {
            let mut regs = crate::features::MmioRegs(&mmio);
            crate::features::apply_cplus(&mut regs, false, true);
        }

        // 5. CR enables both TE + RE per §7 step 2. The datasheet
        //    states that TCR can only be configured once TE is set;
        //    same idiom for RCR + RE.
        // SAFETY: same.
        unsafe {
            mmio.write8(REG_CR, CR_TE | CR_RE);
        }

        // 5a. Program TX descriptor ring base + TCR. The last
        //     descriptor's EOR bit is set lazily on first transmit —
        //     it's safe to leave the ring in all-zero (host-owned)
        //     state since we touch slot 0 first and walk linearly.
        let tx_phys = tx_ring.dma_addr().raw();
        // MTPS + jumbo Config bits: the chip's jumbo frame size
        // (tagged) drives MTPS; VER_31..33 take Linux's 0x24
        // override in jumbo mode. The Config writes are gated
        // behind the 9346CR unlock (they are CONFIG registers).
        // SAFETY: identity-mapped MMIO. RDSAR / TNPDS take a 64-bit
        // value; per §2.20 the spec splits it as low-32 at offset+0
        // and high-32 at offset+4.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe {
            mmio.write32(REG_TNPDS, tx_phys as u32);
            mmio.write32(REG_TNPDS + 4, (tx_phys >> 32) as u32);
            mmio.write32(REG_TCR, TCR_MXDMA_UNLIMITED | TCR_IFG_STD);
            mmio.write8(REG_9346CR, EEM_CONFIG_WRITE);
            let mut regs = crate::features::MmioRegs(&mmio);
            let ver = mac_version.unwrap_or(0);
            let jumbo = crate::features::jumbo_config(ver, true);
            crate::features::apply_jumbo_config(&mut regs, ver, true);
            let tagged_max = max_tagged_frame(mac_version);
            let mtps = jumbo
                .mtps_override
                .unwrap_or_else(|| crate::features::mtps_for_frame(tagged_max));
            mmio.write8(REG_MTPS, mtps);
            mmio.write8(REG_9346CR, EEM_NORMAL);
        }

        // 5b. Pre-fill RX descriptors: each points at its pooled
        //     buffer + has BufferSize=RX_BUF_LEN + OWN=1 so the NIC
        //     can DMA into it. Slot RING_LEN-1 carries EOR so the
        //     internal ring pointer wraps correctly.
        let rx_ring_phys = rx_ring.dma_addr().raw();
        for (i, buf) in rx_pool.iter().enumerate().take(RING_LEN) {
            let buf_phys = buf.dma_addr().raw();
            let mut flags = RXD_OWN | (RX_BUF_LEN as u32 & 0x3FFF);
            if i == RING_LEN - 1 {
                flags |= RXD_EOR;
            }
            let d = Desc {
                flags_len: flags,
                vlan: 0,
                addr_lo: buf_phys as u32,
                addr_hi: (buf_phys >> 32) as u32,
            };
            // SAFETY: identity-mapped DMA ring page; i < RING_LEN.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(rx_ring_phys + (i * 16) as u64)
                        .kernel_mut_ptr::<Desc>(),
                    d,
                );
            }
        }
        // RMS is the buffer bound (16383), not the MTU bound —
        // Linux's `rtl_set_rx_max_size` shape. Jumbo frames are
        // therefore receivable into the 16 KiB buffers even
        // though the interface MTU stays 1500.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_RDSAR, rx_ring_phys as u32);
            mmio.write32(REG_RDSAR + 4, (rx_ring_phys >> 32) as u32);
            mmio.write16(REG_RMS, RX_BUF_LEN as u16);
        }

        // 5c. RCR — accept physical-match + multicast + broadcast,
        //     reject promiscuous + error/runt frames. MXDMA + RXFTH
        //     set to "unlimited" per §2.8 Table 8.
        // SAFETY: same.
        unsafe {
            mmio.write32(
                REG_RCR,
                RCR_APM | RCR_AM | RCR_AB | RCR_MXDMA_UNLIMITED | RCR_RXFTH_NONE,
            );
        }

        // 6. Mask all interrupts at IMR for now. MSI-X bring-up flips
        //    the bits we care about (ROK | TOK | LinkChg). We also
        //    write-1-clear any latched ISR bits so a stale event
        //    from before reset can't fire on first IRQ unmask.
        // SAFETY: same.
        unsafe {
            mmio.write16(REG_IMR, 0);
            mmio.write16(REG_ISR, 0xFFFF);
        }

        // 7. PHYStatus snapshot. The PHY sub-block runs auto-neg in
        //    the background; on a live cabled link the LinkSts bit
        //    reads 1 within ~3 seconds of reset. We capture the
        //    current state for the probe-time sample and the
        //    `Interface::link_up` snapshot; the RX pump re-samples
        //    PHYStatus every pass and republishes transitions
        //    (issue #791) — LinkChg re-evaluation lives there, not
        //    in a follow-up.
        // SAFETY: same.
        let phystat = unsafe { mmio.read8(REG_PHYSTAT) };
        let link_up = phystat & PHYSTAT_LINKSTS != 0;

        // 8. Lock the config registers back. Datasheet §2.9: leaving
        //    9346CR in EEM_CONFIG_WRITE would let writes to CONFIG0..5
        //    leak through; we never enter that mode (we don't touch
        //    CONFIG[0..5]) but we make the lock explicit for clarity.
        // SAFETY: same.
        unsafe {
            mmio.write8(REG_9346CR, EEM_NORMAL);
        }

        let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

        let rtl = Arc::new(Self {
            mmio,
            tx_ring,
            tx_pool,
            tx_head: IrqSafeSpinLock::new(0),
            tx_posted_at: IrqSafeSpinLock::new([0; RING_LEN]),
            tx_timeouts: AtomicU64::new(0),
            tx_resets: AtomicU64::new(0),
            recovering: AtomicBool::new(false),
            tx_epoch: AtomicU64::new(0),
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            mac_version,
            csum_v2,
            mtu: IrqSafeSpinLock::new(1500),
            wol_opts: IrqSafeSpinLock::new(crate::features::WolOpts::NONE),
            link_up,
            suspended: AtomicBool::new(false),
            irq_vector: None,
            msix: None,
            addr: device.addr,
            ifname: crate::publish::IfName::new(),
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn the device's only pump pair — probe spawns none, so the
        // pair fed here is the pair whose halves occupy the ring slots.
        spawn_pumps(rtl.clone(), rx_prod, tx_cons);

        // Return the `Arc` directly: unwrapping it back to `Self`
        // (the old `Arc::try_unwrap` tail) always failed — the pump
        // tasks above hold clones, so the refcount is above 1 and
        // probe could never bind even the first NIC. e1000's
        // bring_up documents the same trap (e1000.rs, bring_up
        // step 9 comment).
        Ok(rtl)
    }

    /// Bring up MSI-X with a single vector. Wires MSI-X table entry 0
    /// to deliver to this CPU + unmasks ROK | TOK | LinkChg in IMR.
    /// After this call, `narf_interrupts::wait_for_irq(self.irq_vector
    /// .unwrap()).await` resolves on every TX completion / RX arrival
    /// / link change.
    ///
    /// # Safety
    /// Caller owns the device's BAR + cfg windows exclusively.
    pub unsafe fn enable_msix(
        &mut self,
        cap: &Cap<BusDeviceCap, Write>,
        device: &BusDevice,
    ) -> Result<u8, NicError> {
        let mut table = narf_bus::enable_msix(cap, device).map_err(|_| NicError::MsixSetup)?;
        let v = narf_interrupts::vector::alloc().map_err(|_| NicError::MsixSetup)?;
        let _ = table.alloc_vector().ok_or(NicError::MsixSetup)?;
        // SAFETY: x2APIC is online by Stage-4 boot.
        let target_apic = unsafe { narf_interrupts::current_cpu_target_id() };
        // SAFETY: caller-authority over the device.
        unsafe { table.program_vector(0, target_apic, v) }.map_err(|_| NicError::MsixSetup)?;
        // SAFETY: same.
        unsafe { table.enable() }.map_err(|_| NicError::MsixSetup)?;

        // Unmask the events we care about. Stage-4: TX completion
        // (TOK), RX arrival (ROK), link change (LinkChg). Descriptor-
        // unavailable (RDU/TDU) signals back-pressure that the
        // polled paths handle by bouncing off `TxRingFull` / empty
        // RX, so we don't need them yet.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio
                .write16(REG_IMR, INT_ROK | INT_TOK | INT_LINKCHG | INT_RDU | INT_TDU);
        }

        self.irq_vector = Some(v);
        self.msix = Some(table);
        Ok(v)
    }

    /// Transmit a single Ethernet frame. Polled completion: spins on
    /// the slot's OWN bit until the NIC clears it. Frame must be in
    /// `[1, 1518]` bytes (no jumbo); the chip pads frames < 64 bytes
    /// itself per §6.1.
    pub fn transmit(&self, frame: &[u8], meta: &TxMeta) -> Result<(), NicError> {
        if self.suspended.load(Ordering::Acquire) {
            return Err(NicError::Suspended);
        }
        if frame.is_empty() || frame.len() > self.max_frame() as usize {
            return Err(NicError::FrameTooLong);
        }
        // Fail fast while recovery owns the reset sequence: a post
        // landing mid-reset could be zeroed with the stale ring.
        // TxRingFull is the honest signal — the ring is not
        // accepting posts right now, and the caller retries.
        if self.recovering.load(Ordering::Acquire) {
            return Err(NicError::TxRingFull);
        }
        // Persistent per-slot buffer (audit #4); index by slot.
        let mut head_g = self.tx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let phys = self.tx_pool[slot].dma_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked above.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile(self.tx_pool[slot].cpu_mut_ptr_at::<u8>(i as u64), *b);
            }
        }
        let ring_phys = self.tx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // Make sure the slot is ours before we scribble. If OWN is
        // still set, the NIC hasn't drained the previous send — the
        // ring is full from the host's POV.
        // SAFETY: identity-mapped DMA ring; slot < RING_LEN.
        let cur_flags = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>())
        };
        if cur_flags & TXD_OWN != 0 {
            return Err(NicError::TxRingFull);
        }

        // Select descriptor format based on offload request.
        // Offload words are computed driver-locally (frame parsing
        // + `crate::features` builders); no shared TX-path code is
        // touched. An offload the chip cannot take for this frame
        // (unparseable header, SCTP, MSS/offset overflow) is
        // `UnsupportedOffload`, never a descriptor with a guessed
        // offset. Plain frames still get VLAN insertion.
        let mut d = if let Some(mss) = meta.tso_mss {
            if mss == 0 || mss > crate::features::MSS_MAX {
                return Err(NicError::UnsupportedOffload);
            }
            let info =
                crate::features::parse_transport(frame).ok_or(NicError::UnsupportedOffload)?;
            let words = if self.csum_v2 {
                crate::features::v2_tso_words(info.ip, mss, info.offset, meta.vlan_tag)
            } else {
                crate::features::v1_tso_words(mss, meta.vlan_tag)
            }
            .ok_or(NicError::UnsupportedOffload)?;
            Desc::tx_with_offload(phys as u32, (phys >> 32) as u32, frame.len() as u16, words)
        } else if let Some(kind) = meta.csum_l4 {
            let info =
                crate::features::parse_transport(frame).ok_or(NicError::UnsupportedOffload)?;
            let words = if self.csum_v2 {
                crate::features::v2_csum_words(kind, info.ip, info.offset, meta.vlan_tag)
            } else {
                crate::features::v1_csum_words(kind, meta.vlan_tag)
            }
            .ok_or(NicError::UnsupportedOffload)?;
            Desc::tx_with_offload(phys as u32, (phys >> 32) as u32, frame.len() as u16, words)
        } else {
            Desc {
                flags_len: TXD_OWN | TXD_FS | TXD_LS | (frame.len() as u32 & 0xFFFF),
                vlan: crate::features::tx_vlan_word(meta.vlan_tag),
                addr_lo: phys as u32,
                addr_hi: (phys >> 32) as u32,
            }
        };
        if slot == RING_LEN - 1 {
            d.flags_len |= TXD_EOR;
        }
        // The NIC sees OWN=1 once we publish word0; the addr/len
        // fields must already be visible. Order: write addr/vlan/
        // length-without-OWN first, fence, then publish OWN.
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            // Write the buffer pointer + vlan first.
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 4).kernel_mut_ptr::<u32>(),
                d.vlan,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 8).kernel_mut_ptr::<u32>(),
                d.addr_lo,
            );
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr + 12).kernel_mut_ptr::<u32>(),
                d.addr_hi,
            );
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<u32>(),
                d.flags_len,
            );
        }
        compiler_fence(Ordering::SeqCst);

        // Ring the TX doorbell. NPQ tells the chip the normal-priority
        // queue has fresh work; it self-clears after the pending
        // packets drain.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write8(REG_TPPOLL, TPPOLL_NPQ);
        }

        let next_head = (*head_g + 1) % (RING_LEN as u32);
        *head_g = next_head;
        drop(head_g);

        // Post time for the watchdog (see `tx_stalled`): stamped
        // once the doorbell has rung, so a descriptor the NIC never
        // completes ages from its post, not from entry.
        let stamped = narf_time::now_cycles();
        self.tx_posted_at.lock()[slot] = stamped;
        // TX epoch at post time: if a watchdog recovery resets the
        // ring while this poll runs, OWN reads clear because the
        // reset zeroed the descriptor — the epoch check below keeps
        // that from reporting as a completion.
        let epoch = self.tx_epoch.load(Ordering::Acquire);

        // Poll for OWN → 0. With the ring serviced by NPQ this
        // typically lands in microseconds; cap the wait so a hung
        // controller surfaces as TxTimeout instead of livelock.
        // responsive_spin_until ticks sleep_pumps so the FB cursor
        // / serial drain stay alive if NPQ is slow under load.
        // 250 ms wall-clock budget covers worst-case Tx congestion.
        let owned = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA ring.
            || unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>()) } & TXD_OWN == 0,
            narf_time::Deadline::after_ms(250),
        );
        if !owned {
            return Err(NicError::TxTimeout);
        }
        // A reset during the poll zeroes the ring, so OWN reads
        // clear even though this frame never went out: the epoch
        // distinguishes a real completion from a reset.
        if epoch != self.tx_epoch.load(Ordering::Acquire) {
            return Err(NicError::TxTimeout);
        }
        // OWN cleared: the descriptor completed, so its post time
        // is void (conditional clear — a later post to this slot
        // must keep its own stamp).
        {
            let mut posted = self.tx_posted_at.lock();
            tx_note_completed(&mut posted, slot, stamped);
        }
        // (no scratch drop — buffer is persistent in tx_pool)
        Ok(())
    }

    /// Pop one received frame off the RX ring. Returns `Some(buf)`
    /// when a descriptor's OWN bit reads 0 (NIC handed it back) and
    /// `None` when the ring head is still NIC-owned.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        self.receive_with_meta().map(|(buf, _)| buf)
    }

    /// Like [`RtlNic::receive`], plus the chip's RX checksum
    /// verification result decoded from the returned descriptor.
    pub fn receive_with_meta(&self) -> Option<(alloc::vec::Vec<u8>, RxCsumResult)> {
        if self.suspended.load(Ordering::Acquire) {
            return None;
        }
        let mut head_g = self.rx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let ring_phys = self.rx_ring.dma_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // SAFETY: identity-mapped DMA ring.
        let flags_len = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>())
        };
        if flags_len & RXD_OWN != 0 {
            return None;
        }

        // Decode the RX checksum result now, before rearming
        // overwrites the descriptor.
        let csum = Desc {
            flags_len,
            vlan: 0,
            addr_lo: 0,
            addr_hi: 0,
        }
        .rx_csum_result();

        // Status layout: bits[13:0] = received frame length (incl.
        // CRC unless RCR.SECRC strips it; Stage-4 leaves SECRC off
        // so the CRC is preserved — caller can strip if they care).
        // We require LS to be set, otherwise we'd have a multi-
        // segment packet — Stage-4 drops those.
        let len = (flags_len & 0x3FFF) as usize;
        let buf_phys = self.rx_pool[slot].dma_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(len.min(RX_BUF_LEN));
        if flags_len & RXD_LS != 0 {
            let copy_len = len.min(RX_BUF_LEN);
            for i in 0..copy_len {
                // SAFETY: `buf_phys` is the identity-mapped DMA address of
                // this slot's RX buffer (`rx_pool[slot]`, `RX_BUF_LEN` bytes);
                // `i < copy_len <= RX_BUF_LEN`, so `buf_phys + i` is in range.
                // SAFETY: Valid MMIO bounds or trusted driver environment
                out.push(unsafe {
                    core::ptr::read_volatile(self.rx_pool[slot].cpu_ptr_at::<u8>(i as u64))
                });
            }
        }
        // (For non-LS descriptors we still rearm + advance — the
        //  partial frame is discarded.)

        // Rearm the descriptor: OWN=1, BufferSize=RX_BUF_LEN, EOR
        // preserved if this is the wrap slot.
        let mut new_flags = RXD_OWN | (RX_BUF_LEN as u32 & 0x3FFF);
        if slot == RING_LEN - 1 {
            new_flags |= RXD_EOR;
        }
        let d = Desc {
            flags_len: new_flags,
            vlan: 0,
            addr_lo: buf_phys as u32,
            addr_hi: (buf_phys >> 32) as u32,
        };
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(
                narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<Desc>(),
                d,
            );
        }
        compiler_fence(Ordering::SeqCst);

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        Some((out, csum))
    }

    /// Program a validated MTU switch on live hardware (Linux
    /// `rtl8169_change_mtu` shape, minus the pieces NARF does
    /// not have): Config bits via `apply_jumbo_config` under
    /// the 9346CR unlock, MTPS from the override when present
    /// (VER_31..33 only — other versions keep the bring-up
    /// jumbo-max MTPS, which already covers any MTU up to the
    /// version max). RMS is NOT touched: it stays at the 16383
    /// buffer bound, which covers every MTU up to the version
    /// max, and Linux's change_mtu does not touch it either
    /// (`rtl_set_rx_max_size` runs at hw-start only). Rings are
    /// NOT resized: RX buffers (16383) and TX slots (16384)
    /// already cover the version max. The EEE idle timer is NOT
    /// touched: Linux's change_mtu writes it only for VER_46/48
    /// (OCP, no in-tree path) and VER_61+ (the 8125 family,
    /// separate drivers). Pause capabilities need phylink,
    /// which NARF does not have; PCIe read-request size is
    /// never programmed in-tree.
    fn program_mtu(&self, program: crate::features::MtuProgram) {
        // SAFETY: probe-time controller owns the BAR exclusively;
        // the hook runs on that same controller.
        unsafe {
            self.mmio.write8(REG_9346CR, EEM_CONFIG_WRITE);
            let mut regs = crate::features::MmioRegs(&self.mmio);
            crate::features::apply_jumbo_config(
                &mut regs,
                self.mac_version.unwrap_or(0),
                program.jumbo,
            );
            if let Some(mtps) = program.config.mtps_override {
                self.mmio.write8(REG_MTPS, mtps);
            }
            self.mmio.write8(REG_9346CR, EEM_NORMAL);
        }
    }

    /// Largest frame this chip may transmit: its jumbo tagged
    /// frame, capped by the TX slot buffer size.
    pub fn max_frame(&self) -> u32 {
        max_tagged_frame(self.mac_version).min(TX_BUF_LEN as u32)
    }

    /// EEE LPI capabilities for this chip's MAC version (Linux's
    /// `rtl8169_get_lpi_caps` shape; unknown version → none).
    pub fn eee_caps(&self) -> crate::features::EeeCaps {
        crate::features::eee_lpi_caps(self.mac_version.unwrap_or(0))
    }

    /// Program Wake-on-LAN options (Linux's `__rtl8169_set_wol`
    /// shape, via `crate::features::apply_wol`). Config registers
    /// are unlocked for the sequence and re-locked after. On
    /// 8168evl (VER_34) the magic step is performed through the
    /// ERI accessor before the Config writes, matching Linux's
    /// magic-first order, so the return is `None` (no pending
    /// step) for every version.
    pub fn set_wol_opts(
        &self,
        opts: crate::features::WolOpts,
    ) -> Result<crate::features::WolPendingMagic, NicError> {
        if !opts.is_valid() {
            return Err(NicError::UnsupportedOffload);
        }
        let magic = match self.mac_version {
            Some(34) => crate::features::WolMagic::Eri0dc,
            _ => crate::features::WolMagic::Config3Bit,
        };
        let pme = match self.mac_version {
            Some(2..=6) => crate::features::WolPmeReg::Config1,
            Some(34) | Some(37) | Some(39..) => crate::features::WolPmeReg::Config2,
            _ => crate::features::WolPmeReg::None,
        };
        // SAFETY: bring_up owns the BAR; `set_wol_opts` is called
        // only on the live controller, whose MMIO is exclusively
        // owned by this instance.
        unsafe {
            self.mmio.write8(REG_9346CR, EEM_CONFIG_WRITE);
            let mut regs = crate::features::MmioRegs(&self.mmio);
            // Linux programs the magic step first
            // (`__rtl8169_set_wol`); the ERI half lands here, so
            // `apply_wol`'s `Eri0dc` pending below is already
            // performed and maps to `None`. The ERI and Config
            // registers are independent, but matching Linux's
            // order costs nothing.
            if let crate::features::WolMagic::Eri0dc = magic {
                if opts.contains(crate::features::WolOpts::MAGIC) {
                    crate::features::eri_set_bits(
                        &mut regs,
                        crate::features::ERI_MAGIC_ADDR,
                        crate::features::ERI_MAGIC_PACKET_V2,
                    );
                } else {
                    crate::features::eri_clear_bits(
                        &mut regs,
                        crate::features::ERI_MAGIC_ADDR,
                        crate::features::ERI_MAGIC_PACKET_V2,
                    );
                }
            }
            let pending = crate::features::apply_wol(&mut regs, opts, magic, pme);
            let pending = match pending {
                crate::features::WolPendingMagic::Eri0dc(_) => {
                    crate::features::WolPendingMagic::None
                }
                other => other,
            };
            self.mmio.write8(REG_9346CR, EEM_NORMAL);
            *self.wol_opts.lock() = opts;
            Ok(pending)
        }
    }

    /// Last WoL option set programmed via [`RtlNic::set_wol_opts`].
    pub fn wol_opts(&self) -> crate::features::WolOpts {
        *self.wol_opts.lock()
    }

    /// Read the PHY-status register. Useful for tests; bit 1 = link.
    pub fn phy_status(&self) -> u8 {
        // SAFETY: identity-mapped MMIO.
        unsafe { self.mmio.read8(REG_PHYSTAT) }
    }

    /// Read + write-1-clear the ISR. The IRQ handler / async waiter
    /// path uses this to drain pending events before re-arming.
    pub fn ack_isr(&self) -> u16 {
        // SAFETY: identity-mapped MMIO.
        let s = unsafe { self.mmio.read16(REG_ISR) };
        // Datasheet §2.6: write 1 to clear.
        // SAFETY: same.
        unsafe {
            self.mmio.write16(REG_ISR, s);
        }
        s
    }

    /// TX stall recoveries (Linux `tx_timeout_count`).
    pub fn tx_timeouts(&self) -> u64 {
        self.tx_timeouts.load(Ordering::Relaxed)
    }

    /// Controller resets performed by [`RtlNic::recover`].
    pub fn tx_resets(&self) -> u64 {
        self.tx_resets.load(Ordering::Relaxed)
    }

    /// One watchdog pass (shared by the supervisor task and the
    /// fixture): if the link is up and a TX descriptor has waited
    /// past the timeout, count the timeout and recover. Returns
    /// true when recovery fired.
    fn check_tx_watchdog_at(&self, now: u64) -> bool {
        if self.recovering.load(Ordering::Acquire) {
            return false;
        }
        if !r8169_link_sample(self.phy_status()).carrier {
            return false;
        }
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        if !tx_stalled(&self.tx_posted_at.lock(), now, timeout) {
            return false;
        }
        self.tx_timeouts.fetch_add(1, Ordering::Relaxed);
        self.recover().is_ok()
    }

    /// TX-timeout recovery (Linux `rtl8169_tx_timeout` +
    /// `rtl8169_hw_reset` shape): software-reset the chip and
    /// reprogram the rings and config from the bring-up values.
    /// The TX cursor is reset — descriptors posted before the
    /// reset will never complete — and the RX descriptors are
    /// re-primed from the pool. A reset that never self-clears
    /// reports `ResetTimeout` and leaves the device stopped; a
    /// concurrent recovery reports `TxRingFull` without touching
    /// the device. The PHY table (`rtl8168`) is not re-run: CR.RST
    /// is a MAC reset and Linux's reset path does not re-program
    /// the PHY either; IDR keeps its EEPROM-loaded MAC.
    pub fn recover(&self) -> Result<(), NicError> {
        if self.recovering.swap(true, Ordering::AcqRel) {
            return Err(NicError::TxRingFull);
        }
        // Advance the TX epoch before the reset: any `transmit`
        // whose OWN poll straddles the reset sees OWN clear because
        // the reset zeroed the ring, not because its frame went out
        // — the epoch lets it report `TxTimeout` instead of a
        // success it did not earn.
        self.tx_epoch.fetch_add(1, Ordering::Release);
        let result = self.recover_inner();
        self.recovering.store(false, Ordering::Release);
        if result.is_ok() {
            self.tx_resets.fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    fn recover_inner(&self) -> Result<(), NicError> {
        // 1. Mask interrupts, clear any latched causes, and stop
        // the TX/RX units.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write16(REG_IMR, 0);
            self.mmio.write16(REG_ISR, 0xFFFF);
            self.mmio.write8(REG_CR, 0);
        }
        // 2. Software reset. CR.RST self-clears once the chip has
        // finished re-initialising the FIFOs + descriptor pointers
        // (datasheet §2.3 Table 3); ~1 ms typical, 100 ms is the
        // wedge threshold (same bound as bring-up).
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write8(REG_CR, CR_RST);
        }
        let cleared = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped MMIO.
            || unsafe { self.mmio.read8(REG_CR) } & CR_RST == 0,
            narf_time::Deadline::after_ms(100),
        );
        if !cleared {
            return Err(NicError::ResetTimeout);
        }
        // 3. C+CR first per §7 step 1 (bring-up step 4), then CR
        // enables TE + RE per §7 step 2.
        // SAFETY: identity-mapped MMIO.
        unsafe {
            let mut regs = crate::features::MmioRegs(&self.mmio);
            crate::features::apply_cplus(&mut regs, false, true);
            self.mmio.write8(REG_CR, CR_TE | CR_RE);
        }
        // 4. Zero the TX ring (a stale OWN bit would make a fresh
        // post look ring-full) and reprogram the TX base + TCR +
        // jumbo Config + MTPS (bring-up step 5a).
        // SAFETY: coherent DMA ring via the kernel direct map.
        unsafe {
            for i in 0..RING_BYTES {
                core::ptr::write_volatile(self.tx_ring.cpu_mut_ptr_at::<u8>(i as u64), 0);
            }
        }
        let tx_phys = self.tx_ring.dma_addr().raw();
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_TNPDS, tx_phys as u32);
            self.mmio.write32(REG_TNPDS + 4, (tx_phys >> 32) as u32);
            self.mmio
                .write32(REG_TCR, TCR_MXDMA_UNLIMITED | TCR_IFG_STD);
            self.mmio.write8(REG_9346CR, EEM_CONFIG_WRITE);
            let mut regs = crate::features::MmioRegs(&self.mmio);
            let ver = self.mac_version.unwrap_or(0);
            let jumbo = crate::features::jumbo_config(ver, true);
            crate::features::apply_jumbo_config(&mut regs, ver, true);
            let tagged_max = max_tagged_frame(self.mac_version);
            let mtps = jumbo
                .mtps_override
                .unwrap_or_else(|| crate::features::mtps_for_frame(tagged_max));
            self.mmio.write8(REG_MTPS, mtps);
            self.mmio.write8(REG_9346CR, EEM_NORMAL);
        }
        // 5. Re-prime the RX descriptors from the pool and
        // reprogram the RX base + RMS + RCR (bring-up steps 5b–5c).
        let rx_ring_phys = self.rx_ring.dma_addr().raw();
        for (i, buf) in self.rx_pool.iter().enumerate().take(RING_LEN) {
            let buf_phys = buf.dma_addr().raw();
            let mut flags = RXD_OWN | (RX_BUF_LEN as u32 & 0x3FFF);
            if i == RING_LEN - 1 {
                flags |= RXD_EOR;
            }
            let d = Desc {
                flags_len: flags,
                vlan: 0,
                addr_lo: buf_phys as u32,
                addr_hi: (buf_phys >> 32) as u32,
            };
            // SAFETY: identity-mapped DMA ring page; i < RING_LEN.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(rx_ring_phys + (i * 16) as u64)
                        .kernel_mut_ptr::<Desc>(),
                    d,
                );
            }
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write32(REG_RDSAR, rx_ring_phys as u32);
            self.mmio
                .write32(REG_RDSAR + 4, (rx_ring_phys >> 32) as u32);
            self.mmio.write16(REG_RMS, RX_BUF_LEN as u16);
            self.mmio.write32(
                REG_RCR,
                RCR_APM | RCR_AM | RCR_AB | RCR_MXDMA_UNLIMITED | RCR_RXFTH_NONE,
            );
        }
        // 6. Re-arm the interrupt mask when MSI-X is up (bring-up
        // leaves IMR = 0 for the polled path; `enable_msix` flips
        // the bits it needs).
        if self.irq_vector.is_some() {
            // SAFETY: identity-mapped MMIO.
            unsafe {
                self.mmio
                    .write16(REG_IMR, INT_ROK | INT_TOK | INT_LINKCHG | INT_RDU | INT_TDU);
            }
        }
        // 7. Reset the software cursors now that the rings are
        // fresh, and republish link from live PHY status.
        *self.tx_head.lock() = 0;
        *self.rx_head.lock() = 0;
        self.tx_posted_at.lock().fill(0);
        crate::publish::publish_link(self.ifname(), r8169_link_sample(self.phy_status()));
        Ok(())
    }

    /// Re-evaluate the link state from PHYStatus. Returns the new
    /// `link_up` value and stamps it into `self.link_up`.
    pub fn refresh_link_state(&mut self) -> bool {
        // SAFETY: identity-mapped MMIO.
        let phystat = unsafe { self.mmio.read8(REG_PHYSTAT) };
        let up = phystat & PHYSTAT_LINKSTS != 0;
        self.link_up = up;
        up
    }

    /// Suspend the device for system suspend (issue #793): mask
    /// interrupts, acknowledge pending causes, stop the TX/RX DMA
    /// engines via the shared `pm` plan, and publish link down. A
    /// second suspend is a no-op success. The PHY stays powered
    /// (its autoneg advertisement persists), and the descriptor
    /// rings persist — only the CR EN bits gate DMA.
    pub fn suspend(&self) -> Result<(), NicError> {
        if self.suspended.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        crate::pm::suspend_plan(&crate::pm::MmioBank::new(&self.mmio), crate::pm::IMR_LEGACY);
        crate::publish::publish_link(self.ifname(), crate::publish::LinkSample::DOWN);
        Ok(())
    }

    /// Resume a suspended device (issue #793): re-kick the PHY so
    /// the link re-negotiates after the DMA stop, restore the DMA
    /// engines + interrupt mask via the shared `pm` plan, and
    /// republish link from live PHYStatus. Resuming a running
    /// device is a no-op success. The PHY re-kick is best-effort:
    /// a failed MDIO read leaves the advertisement as it was, and
    /// the link still comes back on its own.
    pub fn resume(&self) -> Result<(), NicError> {
        if !self.suspended.load(Ordering::Acquire) {
            return Ok(());
        }
        let phy = crate::phy_access::PhyAccess::new(&self.mmio);
        if let Ok(bmcr) = phy.phyar_read(crate::phy_access::MII_BMCR_REG) {
            if let Some(word) = crate::phy_access::bmcr_restart_value(bmcr) {
                let _ = phy.phyar_write(crate::phy_access::MII_BMCR_REG, word);
            }
        }
        crate::pm::resume_plan(
            &crate::pm::MmioBank::new(&self.mmio),
            crate::pm::IMR_LEGACY,
            (INT_ROK | INT_TOK | INT_LINKCHG | INT_RDU | INT_TDU) as u32,
            self.irq_vector.is_some(),
        );
        self.suspended.store(false, Ordering::Release);
        crate::publish::publish_link(self.ifname(), r8169_link_sample(self.phy_status()));
        Ok(())
    }

    /// Async-friendly transmit. Stages the frame into the ring (no
    /// polling), rings the doorbell, and awaits MSI-X delivery via
    /// [`narf_interrupts::wait_for_irq`] before draining the TX
    /// completion. Mirrors `virtio-blk`'s `read_sector_irq_async`
    /// pattern: build the waiter BEFORE doorbell so a synchronously-
    /// delivered completion can't slip past us.
    ///
    /// Caller must have brought MSI-X up via [`enable_msix`]; on a
    /// controller without MSI-X this returns `MsixSetup`.
    pub async fn transmit_irq_async(&self, frame: &[u8]) -> Result<(), NicError> {
        if self.suspended.load(Ordering::Acquire) {
            return Err(NicError::Suspended);
        }
        if frame.is_empty() || frame.len() > self.max_frame() as usize {
            return Err(NicError::FrameTooLong);
        }
        // Fail fast while recovery owns the reset sequence (see
        // `transmit`).
        if self.recovering.load(Ordering::Acquire) {
            return Err(NicError::TxRingFull);
        }
        let v = self.irq_vector.ok_or(NicError::MsixSetup)?;
        // 500 ms TX-completion deadline. Linux r8169 uses a
        // per-queue watchdog set via dev->watchdog_timeo (5s
        // default); 500ms here is conservative for the per-call
        // path. On timeout we don't return an error — the caller
        // gets back from .await and proceeds with the assumption
        // that OWN may not be cleared; subsequent transmit_irq
        // calls will detect TxRingFull and back off.
        let waiter = narf_interrupts::wait_for_irq_until(v, narf_time::Deadline::after_ms(500));

        // Stage frame into the persistent per-slot buffer (audit
        // #4); same shape as polled `transmit`, minus the OWN-clear
        // spin at the end.
        let slot;
        let desc_addr;
        let phys;
        {
            let mut head_g = self.tx_head.lock();
            slot = (*head_g) as usize % RING_LEN;
            phys = self.tx_pool[slot].dma_addr().raw();
            // SAFETY: identity-mapped DMA buffer; bounds-checked by
            // FrameTooLong guard.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            unsafe {
                for (i, b) in frame.iter().enumerate() {
                    core::ptr::write_volatile(
                        narf_memory::PhysAddr::new(phys + i as u64).kernel_mut_ptr::<u8>(),
                        *b,
                    );
                }
            }
            desc_addr = self.tx_ring.dma_addr().raw() + (slot * 16) as u64;
            // SAFETY: identity-mapped DMA ring.
            let cur_flags = unsafe {
                core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>())
            };
            if cur_flags & TXD_OWN != 0 {
                return Err(NicError::TxRingFull);
            }
            let mut flags = TXD_OWN | TXD_FS | TXD_LS | (frame.len() as u32 & 0xFFFF);
            if slot == RING_LEN - 1 {
                flags |= TXD_EOR;
            }
            // SAFETY: same.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr + 4).kernel_mut_ptr::<u32>(),
                    0u32,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr + 8).kernel_mut_ptr::<u32>(),
                    phys as u32,
                );
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr + 12).kernel_mut_ptr::<u32>(),
                    (phys >> 32) as u32,
                );
            }
            compiler_fence(Ordering::SeqCst);
            // SAFETY: same.
            unsafe {
                core::ptr::write_volatile(
                    narf_memory::PhysAddr::new(desc_addr).kernel_mut_ptr::<u32>(),
                    flags,
                );
            }
            compiler_fence(Ordering::SeqCst);
            *head_g = (*head_g + 1) % (RING_LEN as u32);
        }

        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write8(REG_TPPOLL, TPPOLL_NPQ);
        }

        // Post time for the watchdog (see `tx_stalled`).
        let stamped = narf_time::now_cycles();
        self.tx_posted_at.lock()[slot] = stamped;
        // TX epoch at post time (see `transmit`): a reset during
        // the IRQ wait zeroes the ring, so a clear OWN is not a
        // completion.
        let epoch = self.tx_epoch.load(Ordering::Acquire);

        // Wait for MSI-X. The chip raises TOK once the descriptor's
        // OWN clears; ack_isr() drains the latched event so the next
        // wait_for_irq fires on a fresh edge.
        let _ = waiter.await;
        let _ = self.ack_isr();
        // A reset during the IRQ wait zeroes the ring, so a clear
        // OWN is not a completion: the frame was dropped with the
        // ring, and `TxTimeout` is the honest answer (unlike a plain
        // IRQ timeout, which still returns Ok per the note above).
        if epoch != self.tx_epoch.load(Ordering::Acquire) {
            return Err(NicError::TxTimeout);
        }
        // This path never polls OWN itself: check the slot once the
        // IRQ wait resolves, and clear the post time only when the
        // chip has actually taken the descriptor.
        // SAFETY: identity-mapped DMA ring.
        let flags = unsafe {
            core::ptr::read_volatile(narf_memory::PhysAddr::new(desc_addr).kernel_ptr::<u32>())
        };
        if flags & TXD_OWN == 0 {
            let mut posted = self.tx_posted_at.lock();
            tx_note_completed(&mut posted, slot, stamped);
        }
        // (no scratch drop — buffer is persistent in tx_pool)
        Ok(())
    }

    /// Async-friendly receive. Awaits MSI-X delivery and then drains
    /// the next ready RX descriptor. Returns `None` when MSI-X
    /// fires but no descriptor's OWN bit was clear (spurious /
    /// LinkChg-only event), and the caller should re-await.
    pub async fn receive_irq_async(&self) -> Option<alloc::vec::Vec<u8>> {
        let v = self.irq_vector?;
        // 250 ms RX-wake deadline. On timeout the caller (RX pump)
        // re-polls — same shape as Linux's NAPI poll budget /
        // soft-IRQ fallback when the device goes idle.
        let waiter = narf_interrupts::wait_for_irq_until(v, narf_time::Deadline::after_ms(250));
        // Race-free: a synchronously-delivered ROK won't be lost
        // because the waiter snapshots the fire_count before we
        // start polling.
        if let Some(buf) = self.receive() {
            // Already-pending data — consume the IRQ that fired
            // (or didn't) so the next await sees a clean edge.
            let _ = self.ack_isr();
            drop(waiter);
            return Some(buf);
        }
        let _ = waiter.await;
        let _ = self.ack_isr();
        self.receive()
    }
}

impl RtlNic {
    /// This instance's published interface name (`eth%d`), or `""`
    /// before probe publishes it. Per-instance state (i40e/igc
    /// pattern); the pumps and the registry adapter read the name
    /// off the device they serve, never a module-level static.
    pub fn ifname(&self) -> &'static str {
        self.ifname.get()
    }
}

// ── Driver-match registration ────────────────────────────────────────

/// Every probed controller, by probe order. The index is the cookie
/// the kernel-side stack's send path resolves through
/// [`r8169_send_frame`] — the i40e `CONTROLLERS` pattern, so a
/// second RTL8168 on the same machine probes, binds, and carries
/// traffic instead of being dropped by a singleton slot (issue
/// #795). The vec never shrinks, so a live controller's cookie
/// stays valid for the kernel lifetime.
static CONTROLLERS: IrqSafeSpinLock<alloc::vec::Vec<Arc<RtlNic>>> =
    IrqSafeSpinLock::new(alloc::vec::Vec::new());

/// `SendCtxFn` registered with `narf_net::iface` at probe time. Routes
/// the kernel-side TCP stack's outbound frames through
/// `RtlNic::transmit`; the cookie is the controller's index in
/// `CONTROLLERS`. The `Arc` is cloned out rather than holding the
/// IRQ-masking `CONTROLLERS` lock across `transmit` (same reasoning
/// as e1000's send path).
fn r8169_send_frame(cookie: u64, frame: &[u8], meta: narf_net::TxMeta) -> Result<(), ()> {
    let ctrl = controller(cookie as usize).ok_or(())?;
    ctrl.transmit(frame, &meta).map_err(|_| ())
}

/// Decode a PHYStatus byte into a publication sample. The byte
/// carries the full rate on this 1G-ceiling part (10/100/1000
/// bits + duplex), so speed and duplex are reported from it
/// directly (issue #790) — unlike the multigig family, no rate
/// hides behind the 1000M bit and no PHY read is needed.
fn r8169_link_sample(status: u8) -> crate::publish::LinkSample {
    if status & PHYSTAT_LINKSTS == 0 {
        return crate::publish::LinkSample::DOWN;
    }
    let speed_mbps = if status & PHYSTAT_1000BPSF != 0 {
        Some(1000)
    } else if status & PHYSTAT_100BPS != 0 {
        Some(100)
    } else if status & PHYSTAT_10BPS != 0 {
        Some(10)
    } else {
        None
    };
    crate::publish::LinkSample {
        carrier: true,
        speed_mbps,
        duplex: Some(if status & PHYSTAT_FULLDUP != 0 {
            narf_net::iface::LinkDuplex::Full
        } else {
            narf_net::iface::LinkDuplex::Half
        }),
        // PHYStatus reports no media state; r8169 parts are fixed
        // copper, not caged modules (issue #791).
        media_available: None,
        phy_type: None,
    }
}

impl narf_power::device_pm::DevicePmOps for RtlNic {
    fn suspend(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.suspend()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
    fn resume(&self) -> Result<(), narf_power::device_pm::DevicePmError> {
        self.resume()
            .map_err(|_| narf_power::device_pm::DevicePmError::DriverError)
    }
}

/// Probe entry — installed via `bus::register_pci_driver`. A second
/// probe of the SAME function is a no-op success (the old idempotent
/// behaviour): the bus re-walks devices, and rebuilding a second
/// `RtlNic` for the same silicon would let two instances drive one
/// chip's rings. A second FUNCTION binds as a new instance instead
/// of being dropped (issue #795).
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLERS.lock().iter().any(|c| c.addr == device.addr) {
        return Ok(());
    }
    // MEM_SPACE + BUS_MASTER are both required: the chip DMAs the
    // descriptor rings + frame buffers, and we map BAR2 as MMIO.
    // INTX_DISABLE silences the legacy line so MSI-X can take over
    // cleanly later.
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;

    // SAFETY: `bring_up` programs the controller's BARs/DMA rings; the
    // `cap`+`device` pair handed to us by the PCI probe grants exclusive
    // configuration authority over exactly this device, and we have just
    // enabled MEM_SPACE | BUS_MASTER above, so the MMIO/DMA accesses it
    // performs are valid.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev = match unsafe { RtlNic::bring_up(&device, &cap) } {
        Ok(d) => d,
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    // Retain before any ring DMA address reaches the device; the
    // index is this instance's send-path cookie (see `CONTROLLERS`).
    let index = {
        let mut g = CONTROLLERS.lock();
        g.push(dev.clone());
        g.len() - 1
    };

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("r8169"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Publish to the kernel-side stack (issue #784): a dynamic `eth%d`
    // name + carrier metadata via the shared helper, keyed by the
    // `CONTROLLERS` index so each port's send path resolves to its
    // own NIC (i40e pattern). The frame-ring registration below stays.
    let mac = dev.mac;
    let status = dev.phy_status();
    let name = crate::publish::publish_netdev_with_context(
        mac,
        index as u64,
        r8169_send_frame,
        r8169_link_sample(status),
    );
    dev.ifname.set(name);

    // Device-PM registration (#793): system suspend fans out
    // through `RtlNic::suspend` / `RtlNic::resume` via the
    // `DevicePmOps` impl above. The registry is idempotent on the
    // interface name. There is no r8169 detach path to withdraw
    // the entry from yet — the CONTROLLER slot is never drained
    // either, so the entry lives as long as the device does.
    narf_power::device_pm::register_device_pm_ops(dev.ifname(), dev.clone());

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(
            &auth,
            Rtl8168Nic {
                nic: dev.clone(),
                name: "eth3",
            },
        );
    }

    // Runtime MTU switch (#1276): install the DeviceControl hook
    // so `try_set_mtu` validates + programs the switch instead
    // of only changing registry metadata, and publish the
    // initial (MTU 1500) offload advertisement. The stack reads
    // entry.offloads, and this driver never published one
    // before, so the stack ran software offload even at MTU
    // 1500 despite the driver's claimed Interface::offloads —
    // bind now publishes what the driver already claimed.
    if let Some(ctrl) = controller(index) {
        let name = ctrl.ifname();
        let _ = narf_net::iface::set_device_control(
            name,
            Arc::new(RtlMtuControl {
                controller: ctrl.clone(),
                name,
            }),
        );
        let initial = crate::features::mtu_transition(ctrl.mac_version, 1500)
            .map(offloads_for_program)
            .unwrap_or(narf_net::OffloadCapabilities {
                tx_checksum: true,
                rx_checksum: true,
                max_tso_bytes: TX_BUF_LEN as u32,
                vlan_insert: true,
            });
        narf_net::iface::set_offloads(name, initial);
    }

    // No pump spawn here: `bring_up` spawned the device's single RX/TX
    // pump pair, fed by the channel pair whose halves occupy the
    // `rx_ipc_ring`/`tx_ipc_ring` slots (igc's discipline). A second
    // pair spawned from probe would drain the same descriptor ring
    // while its mirror sink's consumer is overwritten away — silently
    // losing frames an attached ring consumer must see.

    Ok(())
}

fn spawn_pumps(
    device: Arc<RtlNic>,
    rx_prod: Producer<Frame, RX_RING_N>,
    tx_cons: Consumer<Frame, TX_RING_N>,
) {
    let d1 = device.clone();
    narf_scheduler::spawn(async move {
        r8169_rx_pump(d1, rx_prod).await;
    });

    let d2 = device.clone();
    narf_scheduler::spawn(async move {
        r8169_tx_pump(d2, tx_cons).await;
    });

    let d3 = device;
    narf_scheduler::spawn(async move {
        r8169_watchdog_pump(d3).await;
    });
}

async fn r8169_rx_pump(device: Arc<RtlNic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    // Carrier refresh (issue #791): the production datapath is polled
    // (probe never enables MSI-X, so the LinkChg bit in the ISR has no
    // consumer), which makes this pump the family's link observer.
    // `phy_status()` is an `&self` MMIO read — unlike
    // `refresh_link_state(&mut self)`, it is safe to call while pumps
    // hold Arc clones. A transition republishes the iface metadata;
    // the cached `Interface::link_up` snapshot is left as-is.
    let mut last_sample = r8169_link_sample(device.phy_status());
    loop {
        let sample = r8169_link_sample(device.phy_status());
        if sample != last_sample {
            last_sample = sample;
            crate::publish::publish_link(device.ifname(), sample);
        }
        if let Some((pkt, csum)) = device.receive_with_meta() {
            let dma_buf =
                alloc_coherent(pkt.len(), DomainId::DRIVER_0).expect("Frame alloc failed");
            let mut frame = Frame::new(dma_buf, pkt.len() as u32);
            frame.payload_mut().copy_from_slice(&pkt);
            // RX checksum verification from the descriptor: only
            // `Ok` marks the checksums verified; `Fail` and `None`
            // both leave the flags clear so the stack re-checks.
            let mut rx_meta = narf_net::RxMeta::default();
            if csum == RxCsumResult::Ok {
                rx_meta.csum_l3 = true;
                rx_meta.csum_l4 = true;
            }
            frame.set_rx_meta(rx_meta);
            // RX fan-out (issue #784), e1000's `dispatch_rx_frame`
            // shape via the shared helper: an attached ring consumer
            // gets a pristine pre-dispatch copy; the original goes to
            // the kernel stack in place. The mirror is non-blocking —
            // a full/closed ring drops its copy, never the stack's
            // packet.
            let name = device.ifname();
            crate::publish::dispatch_rx(
                name,
                &mut frame,
                crate::publish::rx_mirror_attached(name),
                |mirror| {
                    let _ = rx_prod.try_send(mirror);
                },
            );
        }
        narf_scheduler::yield_now().await;
    }
}

async fn r8169_tx_pump(device: Arc<RtlNic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload(), &TxMeta::plain());
    }
}

/// TX-timeout supervisor (igc maintenance-task shape): every 10 ms
/// run one watchdog pass; a ring stalled 5 s with carrier up is
/// recovered and counted. The pass itself gates on an in-flight
/// recovery, so this loop is only a timer.
async fn r8169_watchdog_pump(device: Arc<RtlNic>) {
    let tick = narf_time::ns_to_cycles(TX_WATCHDOG_POLL_NS);
    loop {
        narf_time::sleep_cycles(tick).await;
        device.check_tx_watchdog_at(narf_time::now_cycles());
    }
}

/// Register the driver with the bus's match table. Single match —
/// `(0x10EC, 0x8168)` covers the entire RTL8168 / RTL8111 family
/// since Realtek keeps the PCI ID stable across silicon revisions.
pub fn register_pci_driver() {
    narf_bus::register_pci_driver(narf_bus::PciMatch {
        name: "r8169",
        kind: narf_bus::MatchKind::VendorDevice {
            vendor: RTL_VENDOR,
            device: RTL_DEV_8168,
        },
        probe,
    });
}

/// One probed port, as the net stack sees it.
///
/// This owns its `Arc<RtlNic>` rather than looking the controller up
/// in a module-level static. That is what makes multiple ports work:
/// `Interface::rx_ring` / `tx_ring` return references borrowed from
/// `&self`, so an interface with no storage of its own has to hand
/// back a `static` — and every instance would then share one pair of
/// rings, with the second port's frames landing in the first port's
/// queue (i40e's `I40eNicIface` pattern).
#[derive(Debug)]
pub struct Rtl8168Nic {
    /// This port's controller; the rings are borrowed out of it.
    nic: Arc<RtlNic>,
    /// Pre-publish fallback name, used by [`narf_net::Interface::name`]
    /// before probe publishes the dynamic `eth%d` name.
    name: &'static str,
}

/// `OffloadCapabilities` matching a validated MTU program: TX
/// checksum + TSO follow the program; RX checksum and VLAN
/// insertion are never touched by Linux's `fix_features` rules
/// and stay advertised.
fn offloads_for_program(program: crate::features::MtuProgram) -> narf_net::OffloadCapabilities {
    narf_net::OffloadCapabilities {
        tx_checksum: program.tx_checksum,
        rx_checksum: true,
        max_tso_bytes: if program.tso { TX_BUF_LEN as u32 } else { 0 },
        vlan_insert: true,
    }
}

/// Current (TX checksum, TSO) advertisement for `nic`, derived from
/// its programmed MTU (Linux `rtl8169_fix_features` rules, via
/// `features::mtu_transition`). A stored MTU that somehow fails
/// validation withdraws TX offload (fail-closed — unreachable, since
/// the hook only stores validated values).
fn current_tx_offloads(nic: &RtlNic) -> (bool, bool) {
    let mtu = *nic.mtu.lock();
    crate::features::mtu_transition(nic.mac_version, mtu)
        .map(|p| (p.tx_checksum, p.tso))
        .unwrap_or((false, false))
}

/// Linux `EINVAL` for a rejected MTU (see `netlink_route.rs`).
const EINVAL: i32 = 22;

/// `iface::DeviceControl` for the r8169 family: a proposed MTU
/// change validates against the version range, programs the
/// hardware switch, and republishes the offload advertisement
/// so it always matches the programmed hardware. Any other
/// metadata change passes through untouched (same MTU ⇒
/// no-op Ok), and a rejected MTU leaves registry metadata
/// unchanged (the `configure_device` contract: the hook runs
/// before commit). The hook compares against the controller's
/// programmed MTU, not the registry's, so a commit that lost a
/// race to a rebind self-heals on the next `try_set_mtu` to
/// the same value.
#[derive(Debug)]
pub struct RtlMtuControl {
    controller: Arc<RtlNic>,
    name: &'static str,
}

impl narf_net::iface::DeviceControl for RtlMtuControl {
    fn configure(&self, config: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
        if config.mtu == *self.controller.mtu.lock() {
            return Ok(());
        }
        let program = crate::features::mtu_transition(self.controller.mac_version, config.mtu)
            .map_err(|_| EINVAL)?;
        self.controller.program_mtu(program);
        *self.controller.mtu.lock() = program.mtu;
        narf_net::iface::set_offloads(self.name, offloads_for_program(program));
        Ok(())
    }
}

impl narf_net::Interface for Rtl8168Nic {
    fn name(&self) -> &str {
        // The dynamic `eth%d` name once published (issue #784); the
        // old frame-ring name before probe gets that far.
        let n = self.nic.ifname();
        if n.is_empty() {
            self.name
        } else {
            n
        }
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        *self.nic.mtu.lock()
    }
    fn link_up(&self) -> bool {
        self.nic.link_up
    }
    fn offloads(&self) -> narf_net::OffloadCapabilities {
        // The TSO byte cap is the TX slot buffer: a TSO packet is
        // one frame copied into one slot. (Whether the chip takes
        // the v2 or v1 descriptor layout is a controller property,
        // not an interface capability; Linux's TSO6-vs-TSO4 split
        // follows the same version rule.) TX offload follows the
        // programmed MTU (#1276); RX checksum + VLAN insertion
        // are never withdrawn by the fix_features rules.
        let mtu = *self.nic.mtu.lock();
        crate::features::mtu_transition(self.nic.mac_version, mtu)
            .map(offloads_for_program)
            .unwrap_or(narf_net::OffloadCapabilities {
                tx_checksum: false,
                rx_checksum: true,
                max_tso_bytes: 0,
                vlan_insert: true,
            })
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        // Ring consumer attached: enable the RX mirror (e1000's
        // `rx_mirror_enabled` moment), keyed by this port's own
        // published name.
        crate::publish::note_rx_mirror_attached(self.nic.ifname());
        &self.nic.rx_ipc_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.nic.tx_ipc_ring
    }
}

impl crate::HwNic for Rtl8168Nic {
    fn name(&self) -> &'static str {
        let n = self.nic.ifname();
        if n.is_empty() {
            self.name
        } else {
            n
        }
    }
    fn mac(&self) -> [u8; 6] {
        self.nic.mac
    }
    fn mtu(&self) -> u32 {
        *self.nic.mtu.lock()
    }
    fn link_up(&self) -> bool {
        self.nic.link_up
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::RealtekRtl8168
    }
    fn caps(&self) -> crate::NicCaps {
        let (tx_checksum, tso) = current_tx_offloads(&self.nic);
        let mut caps = crate::NicCaps::RX_CSUM | crate::NicCaps::VLAN_TAGGING;
        if tx_checksum {
            caps = caps | crate::NicCaps::TX_CSUM;
        }
        if tso {
            caps = caps | crate::NicCaps::TSO;
        }
        caps
    }
    fn ring_capacity(&self) -> usize {
        RING_LEN
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        <Self as narf_net::Interface>::rx_ring(self)
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        <Self as narf_net::Interface>::tx_ring(self)
    }
}

/// Largest tagged frame a chip of this MAC version may transmit:
/// its jumbo MTU as a frame, plus one VLAN tag. Unknown version
/// takes Linux's 9K default.
fn max_tagged_frame(version: Option<u32>) -> u32 {
    let ver = version.unwrap_or(0);
    crate::features::frame_for_mtu(crate::features::jumbo_max_mtu(ver)) + 4
}

/// Number of probed controllers (issue #795).
pub fn instance_count() -> usize {
    CONTROLLERS.lock().len()
}

/// `true` once at least one controller has been probed.
pub fn is_probed() -> bool {
    !CONTROLLERS.lock().is_empty()
}

/// The probed controller at `index`, if it exists. The index is the
/// cookie probe assigned (see `CONTROLLERS`); it is stable for the
/// kernel lifetime because the vec never shrinks.
pub fn controller(index: usize) -> Option<Arc<RtlNic>> {
    CONTROLLERS.lock().get(index).cloned()
}

/// Test-side accessor: run `f` against the probed controller at
/// `index` (i40e shape).
pub fn with_controller<R>(index: usize, f: impl FnOnce(&RtlNic) -> R) -> Option<R> {
    CONTROLLERS.lock().get(index).map(|a| f(a))
}

/// Mutable accessor — used by tests that want to switch on MSI-X
/// after probe.
pub fn with_controller_mut<R>(index: usize, f: impl FnOnce(&mut RtlNic) -> R) -> Option<R> {
    CONTROLLERS
        .lock()
        .get_mut(index)
        .map(|a| f(Arc::get_mut(a).expect("RtlNic static has multiple owners")))
}

#[cfg(any(test, feature = "builtin"))]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::{
        alloc_coherent, channel, tx_note_completed, tx_stalled, Desc, DmaBuffer, DomainId, Frame,
        IrqSafeSpinLock, MmioRegion, RtlNic, TxMeta, CR_RE, CR_TE, RCR_AB, RCR_AM, RCR_APM,
        RCR_MXDMA_UNLIMITED, RCR_RXFTH_NONE, REG_CR, REG_IMR, REG_RCR, REG_RDSAR, REG_RMS, REG_TCR,
        REG_TNPDS, RING_BYTES, RING_LEN, RXD_EOR, RXD_OWN, RX_BUF_LEN, RX_RING_N, TCR_IFG_STD,
        TCR_MXDMA_UNLIMITED, TX_BUF_LEN, TX_RING_N, TX_TIMEOUT_NS,
    };

    #[cfg(target_arch = "x86_64")]
    fn smoke_r8169_link_sample_decodes() -> TestResult {
        use super::{
            r8169_link_sample, PHYSTAT_1000BPSF, PHYSTAT_100BPS, PHYSTAT_10BPS, PHYSTAT_FULLDUP,
            PHYSTAT_LINKSTS,
        };
        use narf_net::iface::LinkDuplex;
        // The bytes are built from the PHYStatus map in this
        // file (0x6C: bit 1 LinkSts, bit 0 FullDup, bit 2 10M,
        // bit 3 100M, bit 4 1000M): only those bits prove a rate.
        let up_1g = r8169_link_sample(PHYSTAT_LINKSTS | PHYSTAT_FULLDUP | PHYSTAT_1000BPSF);
        if !up_1g.carrier
            || up_1g.speed_mbps != Some(1000)
            || up_1g.duplex != Some(LinkDuplex::Full)
        {
            return TestResult::Fail("r8169 1G full-duplex PHYStatus word decoded wrong");
        }
        let up_100h = r8169_link_sample(PHYSTAT_LINKSTS | PHYSTAT_100BPS);
        if !up_100h.carrier
            || up_100h.speed_mbps != Some(100)
            || up_100h.duplex != Some(LinkDuplex::Half)
        {
            return TestResult::Fail("r8169 100M half-duplex PHYStatus word decoded wrong");
        }
        let up_10 = r8169_link_sample(PHYSTAT_LINKSTS | PHYSTAT_FULLDUP | PHYSTAT_10BPS);
        if up_10.speed_mbps != Some(10) {
            return TestResult::Fail("r8169 10M PHYStatus word decoded wrong");
        }
        // Link up with no speed bit: carrier is real, the rate
        // is not proven — never a guessed rate.
        let up_norate = r8169_link_sample(PHYSTAT_LINKSTS | PHYSTAT_FULLDUP);
        if !up_norate.carrier || up_norate.speed_mbps.is_some() {
            return TestResult::Fail("r8169 link-up without a speed bit must not guess a rate");
        }
        // Every speed bit without LinkSts must not read as up.
        let no_link =
            r8169_link_sample(PHYSTAT_FULLDUP | PHYSTAT_1000BPSF | PHYSTAT_100BPS | PHYSTAT_10BPS);
        if no_link.carrier || no_link.speed_mbps.is_some() {
            return TestResult::Fail("r8169 PHYStatus without LinkSts must read as down");
        }
        if r8169_link_sample(0) != crate::publish::LinkSample::DOWN {
            return TestResult::Fail("r8169 zero PHYStatus must read as DOWN");
        }
        TestResult::Pass
    }
    #[cfg(target_arch = "x86_64")]
    kernel_test_in!("drivers/net/r8169", smoke_r8169_link_sample_decodes);

    fn smoke_r8169_tx_stall_detection() -> TestResult {
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        let mut posted = [0u64; RING_LEN];
        if tx_stalled(&posted, 1_000_000, timeout) {
            return TestResult::Fail("r8169 idle TX ring reported stalled");
        }
        let now = 10_000_000u64;
        posted[5] = now;
        if tx_stalled(&posted, now + timeout, timeout) {
            return TestResult::Fail("r8169 TX stall fired at exactly the timeout");
        }
        if !tx_stalled(&posted, now + timeout + 1, timeout) {
            return TestResult::Fail("r8169 TX stall did not fire past the timeout");
        }
        // A second, later post does not mask the older stuck one...
        posted[6] = now + 100;
        if !tx_stalled(&posted, now + timeout + 1, timeout) {
            return TestResult::Fail("r8169 later TX post masked the stuck descriptor");
        }
        // ...and completing the oldest clears the stall once nothing
        // aged remains.
        tx_note_completed(&mut posted, 5, now);
        if tx_stalled(&posted, now + timeout + 1, timeout) {
            return TestResult::Fail("r8169 TX stall survived completing the stuck slot");
        }
        // A completion stamped for a different post leaves the
        // current post's stamp alone.
        tx_note_completed(&mut posted, 6, now);
        if posted[6] == 0 {
            return TestResult::Fail("r8169 completion cleared a different post's stamp");
        }
        tx_note_completed(&mut posted, 6, now + 100);
        if tx_stalled(&posted, now + timeout + 1, timeout) {
            return TestResult::Fail("r8169 empty TX ring reported stalled");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/r8169", smoke_r8169_tx_stall_detection);

    /// Fake RTL8168 for the TX-timeout fixture: a 4 KiB MMIO backing
    /// page plus a sleep-pump that emulates the two hardware
    /// behaviours recovery depends on — CR.RST self-clear
    /// (datasheet §2.3 Table 3) and TX descriptor completion (OWN
    /// clear) once the test arms it. Built from the spec (register
    /// offsets, reset semantics), never from the implementation's
    /// constants.
    static FIXTURE_MMIO: AtomicU64 = AtomicU64::new(0);
    static FIXTURE_COMPLETE_TX: AtomicBool = AtomicBool::new(false);
    static FIXTURE_PUMP_REGISTERED: AtomicBool = AtomicBool::new(false);

    fn fixture_pump() {
        let base = FIXTURE_MMIO.load(Ordering::Acquire);
        if base == 0 {
            return;
        }
        // SAFETY: fixture-owned fake MMIO; base is published by the
        // fixture and cleared on drop. The backing page is 4 KiB, so
        // every register offset below is in bounds.
        unsafe {
            let cr = core::ptr::read_volatile((base + super::REG_CR) as *const u8);
            if cr & super::CR_RST != 0 {
                core::ptr::write_volatile((base + super::REG_CR) as *mut u8, cr & !super::CR_RST);
            }
            if FIXTURE_COMPLETE_TX.load(Ordering::Acquire) {
                let tnpds_lo =
                    core::ptr::read_volatile((base + super::REG_TNPDS) as *const u32) as u64;
                let tnpds_hi =
                    core::ptr::read_volatile((base + super::REG_TNPDS + 4) as *const u32) as u64;
                let ring = (tnpds_hi << 32) | tnpds_lo;
                if ring != 0 {
                    for slot in 0..super::RING_LEN {
                        let desc = narf_memory::PhysAddr::new(
                            ring + (slot * core::mem::size_of::<Desc>()) as u64,
                        );
                        // SAFETY: fixture-owned DMA ring; slot bounded.
                        let word0 = desc.kernel_ptr::<u32>();
                        if core::ptr::read_volatile(word0) & super::TXD_OWN != 0 {
                            let word0_mut = desc.kernel_mut_ptr::<u32>();
                            let flags = core::ptr::read_volatile(word0_mut);
                            core::ptr::write_volatile(word0_mut, flags & !super::TXD_OWN);
                        }
                    }
                }
            }
        }
    }

    struct TxTimeoutFixture {
        device: RtlNic,
        _mmio_mem: DmaBuffer,
    }

    impl TxTimeoutFixture {
        fn new() -> Self {
            // 4 KiB fake BAR2 (register window is 0x00..0xEF).
            let mut mem = alloc_coherent(4096, DomainId::DRIVER_0).unwrap();
            mem.as_mut_slice().fill(0);
            let csr = MmioRegion {
                phys: mem.phys_addr(),
                virt: mem.as_mut_ptr() as u64,
                len: mem.len() as u64,
                kind: narf_bus::BarKind::Mmio32 {
                    prefetchable: false,
                },
            };
            // SAFETY: fixture-owned MMIO backing.
            unsafe {
                csr.write8(super::REG_PHYSTAT, super::PHYSTAT_LINKSTS);
            }
            FIXTURE_MMIO.store(csr.virt, Ordering::Release);
            if !FIXTURE_PUMP_REGISTERED.swap(true, Ordering::AcqRel) {
                narf_scheduler::sleep_pumps::register_nested_only(fixture_pump);
            }
            let tx_ring = alloc_coherent(RING_BYTES, DomainId::DRIVER_0).unwrap();
            let rx_ring = alloc_coherent(RING_BYTES, DomainId::DRIVER_0).unwrap();
            let mut tx_pool = alloc::vec::Vec::with_capacity(RING_LEN);
            for _ in 0..RING_LEN {
                tx_pool.push(alloc_coherent(TX_BUF_LEN, DomainId::DRIVER_0).unwrap());
            }
            let mut rx_pool = alloc::vec::Vec::with_capacity(RING_LEN);
            for _ in 0..RING_LEN {
                rx_pool.push(alloc_coherent(RX_BUF_LEN, DomainId::DRIVER_0).unwrap());
            }
            let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
            let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();
            let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
            let device = RtlNic {
                mmio: csr,
                tx_ring,
                tx_pool,
                tx_head: IrqSafeSpinLock::new(0),
                tx_posted_at: IrqSafeSpinLock::new([0; RING_LEN]),
                tx_timeouts: AtomicU64::new(0),
                tx_resets: AtomicU64::new(0),
                recovering: AtomicBool::new(false),
                tx_epoch: AtomicU64::new(0),
                rx_ring,
                rx_pool,
                rx_head: IrqSafeSpinLock::new(0),
                mac,
                mac_version: None,
                csum_v2: false,
                mtu: IrqSafeSpinLock::new(1500),
                wol_opts: IrqSafeSpinLock::new(crate::features::WolOpts::NONE),
                link_up: true,
                suspended: AtomicBool::new(false),
                irq_vector: None,
                msix: None,
                // Fixture-owned MMIO backing is this instance's address;
                // no second fixture shares it, so the probe-time
                // duplicate-bind refusal can never fire here.
                addr: narf_bus::BusAddr::Mmio(mem.phys_addr()),
                ifname: crate::publish::IfName::new(),
                rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
                tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
            };
            // Bring-up register program (steps 4–5c), minus the IRQ
            // install and the PHY table: C+CR, CR, TX/RX rings.
            let tx_phys = device.tx_ring.dma_addr().raw();
            let rx_ring_phys = device.rx_ring.dma_addr().raw();
            // SAFETY: fixture-owned fake MMIO.
            unsafe {
                let mut regs = crate::features::MmioRegs(&device.mmio);
                crate::features::apply_cplus(&mut regs, false, true);
                device.mmio.write8(REG_CR, CR_TE | CR_RE);
                device.mmio.write32(REG_TNPDS, tx_phys as u32);
                device.mmio.write32(REG_TNPDS + 4, (tx_phys >> 32) as u32);
                device
                    .mmio
                    .write32(REG_TCR, TCR_MXDMA_UNLIMITED | TCR_IFG_STD);
                device
                    .mmio
                    .write8(super::REG_9346CR, super::EEM_CONFIG_WRITE);
                let mut regs = crate::features::MmioRegs(&device.mmio);
                let ver = device.mac_version.unwrap_or(0);
                let jumbo = crate::features::jumbo_config(ver, true);
                crate::features::apply_jumbo_config(&mut regs, ver, true);
                let tagged_max = super::max_tagged_frame(device.mac_version);
                let mtps = jumbo
                    .mtps_override
                    .unwrap_or_else(|| crate::features::mtps_for_frame(tagged_max));
                device.mmio.write8(super::REG_MTPS, mtps);
                device.mmio.write8(super::REG_9346CR, super::EEM_NORMAL);
            }
            // Prime the RX descriptors from the pool (bring-up step 5b).
            for (i, buf) in device.rx_pool.iter().enumerate().take(RING_LEN) {
                let buf_phys = buf.dma_addr().raw();
                let mut flags = RXD_OWN | (RX_BUF_LEN as u32 & 0x3FFF);
                if i == RING_LEN - 1 {
                    flags |= RXD_EOR;
                }
                let d = Desc {
                    flags_len: flags,
                    vlan: 0,
                    addr_lo: buf_phys as u32,
                    addr_hi: (buf_phys >> 32) as u32,
                };
                // SAFETY: fixture-owned DMA ring.
                unsafe {
                    core::ptr::write_volatile(
                        narf_memory::PhysAddr::new(rx_ring_phys + (i * 16) as u64)
                            .kernel_mut_ptr::<Desc>(),
                        d,
                    );
                }
            }
            // SAFETY: fixture-owned fake MMIO.
            unsafe {
                device.mmio.write32(REG_RDSAR, rx_ring_phys as u32);
                device
                    .mmio
                    .write32(REG_RDSAR + 4, (rx_ring_phys >> 32) as u32);
                device.mmio.write16(REG_RMS, RX_BUF_LEN as u16);
                device.mmio.write32(
                    REG_RCR,
                    RCR_APM | RCR_AM | RCR_AB | RCR_MXDMA_UNLIMITED | RCR_RXFTH_NONE,
                );
                device.mmio.write16(REG_IMR, 0);
            }
            core::mem::drop(rx_prod);
            core::mem::drop(tx_cons);
            Self {
                device,
                _mmio_mem: mem,
            }
        }
    }

    impl Drop for TxTimeoutFixture {
        fn drop(&mut self) {
            FIXTURE_COMPLETE_TX.store(false, Ordering::Release);
            FIXTURE_MMIO.store(0, Ordering::Release);
        }
    }

    fn smoke_r8169_tx_timeout_recovery_fixture() -> TestResult {
        let fixture = TxTimeoutFixture::new();
        let device = &fixture.device;
        let frame = [0xAAu8; 64];
        // 1. Stall: the fake device never completes the descriptor,
        // so the synchronous post times out — the wedged ring, as
        // the field sees it.
        if device.transmit(&frame, &TxMeta::plain()).is_ok() {
            return TestResult::Fail("r8169 TX completed against a wedged fake device");
        }
        let timeout = narf_time::ns_to_cycles(TX_TIMEOUT_NS);
        let posted = device.tx_posted_at.lock()[0];
        if posted == 0 {
            return TestResult::Fail("r8169 TX post did not stamp a post time");
        }
        // 2. The watchdog does not fire inside the grace period...
        if device.check_tx_watchdog_at(posted + timeout) {
            return TestResult::Fail("r8169 watchdog fired at exactly the timeout");
        }
        if device.tx_resets() != 0 || device.tx_timeouts() != 0 {
            return TestResult::Fail("r8169 watchdog counted a recovery it did not fire");
        }
        // ...but fires past it, resets the controller, and the ring
        // comes back.
        if !device.check_tx_watchdog_at(posted + timeout + 1) {
            return TestResult::Fail("r8169 watchdog did not fire past the timeout");
        }
        if device.tx_timeouts() != 1 || device.tx_resets() != 1 {
            return TestResult::Fail("r8169 watchdog recovery was not counted");
        }
        // The recovery advanced the TX epoch exactly once, so a
        // `transmit` whose OWN poll straddled the reset cannot
        // mistake the zeroed ring for a completion.
        if device.tx_epoch.load(Ordering::Relaxed) != 1 {
            return TestResult::Fail("r8169 recovery did not advance the TX epoch");
        }
        // SAFETY: fixture-owned fake MMIO.
        unsafe {
            let tnpds_lo = device.mmio.read32(REG_TNPDS) as u64;
            let tnpds_hi = device.mmio.read32(REG_TNPDS + 4) as u64;
            if (tnpds_hi << 32) | tnpds_lo != device.tx_ring.dma_addr().raw() {
                return TestResult::Fail("r8169 recovery left a stale TX ring base");
            }
            if device.mmio.read8(REG_CR) & (CR_TE | CR_RE) != (CR_TE | CR_RE) {
                return TestResult::Fail("r8169 recovery left TX/RX disabled");
            }
            if device.mmio.read32(REG_TCR) & TCR_MXDMA_UNLIMITED == 0 {
                return TestResult::Fail("r8169 recovery left TCR unprogrammed");
            }
            let rdsar_lo = device.mmio.read32(REG_RDSAR) as u64;
            let rdsar_hi = device.mmio.read32(REG_RDSAR + 4) as u64;
            if (rdsar_hi << 32) | rdsar_lo != device.rx_ring.dma_addr().raw() {
                return TestResult::Fail("r8169 recovery left a stale RX ring base");
            }
        }
        if tx_stalled(&device.tx_posted_at.lock(), posted + timeout + 1, timeout) {
            return TestResult::Fail("r8169 TX stall survived the recovery");
        }
        // 3. Traffic resumes: with the fake device completing
        // descriptors again, a fresh post completes.
        FIXTURE_COMPLETE_TX.store(true, Ordering::Release);
        if device.transmit(&frame, &TxMeta::plain()).is_err() {
            return TestResult::Fail("r8169 TX did not resume after recovery");
        }
        // The completed frame cleared its post time, so nothing
        // aged remains for the watchdog to fire on.
        if device.check_tx_watchdog_at(narf_time::now_cycles()) {
            return TestResult::Fail("r8169 watchdog fired on an empty ring");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/net/r8169", smoke_r8169_tx_timeout_recovery_fixture);
}
