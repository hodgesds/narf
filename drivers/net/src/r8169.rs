//! Realtek RTL8168 / RTL8111 family driver — PCIe Gigabit Ethernet
//! controller used on a wide swathe of consumer / laptop boards
//! (including the user's AMD Ryzen 7 PRO 8840HS Phoenix laptop).
//!
//! Stage-4 cut: probe + reset + TX/RX rings + one MSI-X vector. No
//! GMII auto-neg tuning, no EEE/WOL, no jumbo, no checksum offload,
//! no VLAN, no multi-queue.
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
//!   word1:  VLAN tag bits             (we leave 0)
//!   word2:  buffer phys addr  low  32 bits
//!   word3:  buffer phys addr  high 32 bits
//! ```
//!
//! Bring-up sequence per §7 "Driver Programming Note": program C+CR
//! first, then CR (TE|RE), then the rest. RST is self-clearing.

use core::sync::atomic::{compiler_fence, Ordering};

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
const REG_CPLUSCR: u64 = 0xE0;
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
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
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

// PHYStatus bits.
const PHYSTAT_LINKSTS: u8 = 1 << 1;

// TX descriptor flags (word0 high bits).
const TXD_OWN: u32 = 1 << 31;
const TXD_EOR: u32 = 1 << 30;
const TXD_FS: u32 = 1 << 29;
const TXD_LS: u32 = 1 << 28;

// TX v1 offload bits (word0; older chips RTL8168b and earlier).
// Source: Linux r8169_main.c around line 588.
/// v1 LSO enable (large-send offload). Bit 27 of word0.
pub const TD_LSO: u32 = 1 << 27;
/// v1 MSS field shift within word0 (bits[26:16]). Mask = 0x07FF_0000.
pub const TD0_MSS_SHIFT: u32 = 16;
/// v1 TCP checksum insert (word0 bit 16). Set alongside TD_LSO.
pub const TD0_TCP_CS: u32 = 1 << 16;
/// v1 IP checksum insert (word0 bit 18).
pub const TD0_IP_CS: u32 = 1 << 18;

// TX v2 offload bits (word1/vlan field; RTL8168c+ chips).
// Source: Linux r8169_main.c around line 597.
/// v2 GTS IPv4 large-send (word1 bit 26).
pub const TD1_GTSENV4: u32 = 1 << 26;
/// v2 GTS IPv6 large-send (word1 bit 25).
pub const TD1_GTSENV6: u32 = 1 << 25;
/// v2 MSS field shift in word1 (bits[28:18]). Mask = 0x1FFC_0000.
pub const TD1_MSS_SHIFT: u32 = 18;
/// v2 IPv4 header checksum insert (word1 bit 29).
#[allow(non_upper_case_globals)] // TODO(narf): mirrors the datasheet register/bit name
pub const TD1_IPv4_CS: u32 = 1 << 29;
/// v2 TCP checksum insert (word1 bit 30).
pub const TD1_TCP_CS: u32 = 1 << 30;
/// v2 UDP checksum insert (word1 bit 31).
pub const TD1_UDP_CS: u32 = 1 << 31;

// RX status bits in word0 returned by hardware after a received frame.
// Source: Linux r8169_main.c; IPFail/UDPFail/TCPFail in rx descriptor.
/// RX: IP checksum failed (bit 16 of the returned flags_len word).
pub const RX_IPFAIL: u32 = 1 << 16;
/// RX: UDP checksum failed (bit 15).
pub const RX_UDPFAIL: u32 = 1 << 15;
/// RX: TCP checksum failed (bit 14).
pub const RX_TCPFAIL: u32 = 1 << 14;
/// RX: IP protocol present (bit 5). Set => hardware attempted IP csum.
pub const RX_IPOK: u32 = 1 << 5;
/// RX: TCP protocol present (bit 6). Set => hardware attempted L4 csum.
pub const RX_TCPOK: u32 = 1 << 6;
/// RX: UDP protocol present (bit 7). Set => hardware attempted L4 csum.
pub const RX_UDPOK: u32 = 1 << 7;

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

/// RX buffer size. 2 KiB matches what the RCR datasheet expects for
/// non-jumbo traffic; the driver doesn't program any RX-buffer-size
/// register on this chip — buffer size is per-descriptor — so we
/// just set RMS to a value that bounds an RX frame at ≤ 2 KiB.
pub const RX_BUF_LEN: usize = 2048;

/// MTPS units are 128 bytes. 0x3B → 7552 bytes; 0x0C → 1536 bytes.
/// We pick 0x3B so a single TX descriptor can carry up to 7440 bytes
/// without TX underrun (even though we restrict frames to 1518 in
/// `transmit`). MTPS == 0 is reserved/illegal per §2.21.
const MTPS_DEFAULT: u8 = 0x3B;

/// Max RX packet length (RMS register, 14-bit). Set to 1536 so a
/// 1518-byte Ethernet frame + alignment padding fits cleanly.
const RMS_DEFAULT: u16 = 1536;

// ── Errors ──────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NicError {
    BarMapFailed,
    NoMemory,
    /// Frame outside [1, 1518].
    FrameTooLong,
    /// `transmit` couldn't find a free TX descriptor.
    TxRingFull,
    /// `transmit` polled too long for OWN to clear.
    TxTimeout,
    /// MSI-X table couldn't be brought up.
    MsixSetup,
}

// ── Descriptor in-memory shape ──────────────────────────────────────

#[repr(C, align(16))]
#[derive(Copy, Clone, Debug, Default)]
pub(crate) struct Desc {
    /// Bits [31..14] are flags (OWN/EOR/FS/LS/... in TX; OWN/EOR/...
    /// + frame length in RX status), bits [13..0] are buffer size or
    /// frame length depending on direction.
    pub flags_len: u32,
    pub vlan: u32,
    pub addr_lo: u32,
    pub addr_hi: u32,
}
const _: () = assert!(core::mem::size_of::<Desc>() == 16);

// ── Descriptor offload builders ─────────────────────────────────────

impl Desc {
    /// Build a TX descriptor with v2-path IP + TCP checksum offload.
    /// The v2 csum bits live in `vlan` (word1); `flags_len` carries the
    /// standard OWN | FS | LS | buffer-length encoding.
    pub fn tx_with_csum(addr_lo: u32, addr_hi: u32, len: u16) -> Self {
        Desc {
            flags_len: TXD_OWN | TXD_FS | TXD_LS | (len as u32),
            vlan: TD1_IPv4_CS | TD1_TCP_CS,
            addr_lo,
            addr_hi,
        }
    }

    /// Build a TX descriptor for TSO (v2 path). MSS is packed into
    /// `vlan` bits[28:18] alongside the GTS-enable bit (TD1_GTSENV4).
    /// Source: Linux r8169_main.c `rtl8169_tso_csum_v2`.
    pub fn tx_with_tso(addr_lo: u32, addr_hi: u32, len: u16, mss: u16) -> Self {
        Desc {
            flags_len: TXD_OWN | TXD_FS | TXD_LS | (len as u32),
            vlan: TD1_GTSENV4 | TD1_IPv4_CS | TD1_TCP_CS | ((mss as u32) << TD1_MSS_SHIFT),
            addr_lo,
            addr_hi,
        }
    }

    /// Decode the RX checksum result from a chip-returned descriptor.
    ///
    /// On RX, after the chip clears OWN, `flags_len` carries the error
    /// indicator bits at specific positions. The *OK* bits (IPOK /
    /// TCPOK / UDPOK) tell us the hardware attempted csum verification;
    /// the *FAIL* bits (RX_IPFAIL / RX_TCPFAIL / RX_UDPFAIL) indicate
    /// a bad result. If no OK bits are set the frame had no checksummed
    /// protocol and we return None. Source: Linux r8169_main.c
    /// `rtl8169_rx_csum`.
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    pub fn rx_csum_result(&self) -> RxCsumResult {
        let ip_done = self.flags_len & RX_IPOK != 0;
        let tcp_done = self.flags_len & RX_TCPOK != 0;
        let udp_done = self.flags_len & RX_UDPOK != 0;
        if !ip_done && !tcp_done && !udp_done {
            return RxCsumResult::None;
        }
        let ip_fail = self.flags_len & RX_IPFAIL != 0;
        let tcp_fail = self.flags_len & RX_TCPFAIL != 0;
        let udp_fail = self.flags_len & RX_UDPFAIL != 0;
        if ip_fail || tcp_fail || udp_fail {
            RxCsumResult::Fail
        } else {
            RxCsumResult::Ok
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
    /// RX descriptor ring DMA buffer (`RING_LEN * 16` bytes).
    rx_ring: DmaBuffer,
    /// One DMA buffer per RX descriptor. Kept alive for the lifetime
    /// of the driver — descriptor `i` always points at `rx_pool[i]`.
    rx_pool: alloc::vec::Vec<DmaBuffer>,
    /// Driver-side RX consumer cursor.
    rx_head: IrqSafeSpinLock<u32>,
    /// MAC address read from IDR0..5 at bring-up.
    pub mac: [u8; 6],
    /// True when PHYStatus.LinkSts read 1 at bring-up. We don't yet
    /// re-poll on LinkChg interrupts.
    pub link_up: bool,
    /// IDT vector wired to MSI-X entry 0, when MSI-X is enabled.
    pub irq_vector: Option<u8>,
    /// Live MSI-X table — kept alive so the device's MSI-X enable
    /// stays sticky.
    msix: Option<narf_bus::MsixTable>,

    // IPC integration
    rx_ipc_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ipc_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

unsafe impl Send for RtlNic {}
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
    ) -> Result<Self, NicError> {
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
            tx_pool.push(alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| NicError::NoMemory)?);
        }

        // 4. C+CR first per §7 step 1. We disable VLAN-detag + RX
        //    checksum offload — the upper layer doesn't yet consume
        //    these, and a clean zero is the predictable default.
        // SAFETY: identity-mapped.
        unsafe {
            mmio.write16(REG_CPLUSCR, 0);
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
        let tx_phys = tx_ring.phys_addr().raw();
        // SAFETY: identity-mapped MMIO. RDSAR / TNPDS take a 64-bit
        // value; per §2.20 the spec splits it as low-32 at offset+0
        // and high-32 at offset+4.
        unsafe {
            mmio.write32(REG_TNPDS, tx_phys as u32);
            mmio.write32(REG_TNPDS + 4, (tx_phys >> 32) as u32);
            mmio.write32(REG_TCR, TCR_MXDMA_UNLIMITED | TCR_IFG_STD);
            mmio.write8(REG_MTPS, MTPS_DEFAULT);
        }

        // 5b. Pre-fill RX descriptors: each points at its pooled
        //     buffer + has BufferSize=RX_BUF_LEN + OWN=1 so the NIC
        //     can DMA into it. Slot RING_LEN-1 carries EOR so the
        //     internal ring pointer wraps correctly.
        let rx_ring_phys = rx_ring.phys_addr().raw();
        for i in 0..RING_LEN {
            let buf_phys = rx_pool[i].phys_addr().raw();
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
                core::ptr::write_volatile((rx_ring_phys + (i * 16) as u64) as *mut Desc, d);
            }
        }
        // SAFETY: identity-mapped MMIO.
        unsafe {
            mmio.write32(REG_RDSAR, rx_ring_phys as u32);
            mmio.write32(REG_RDSAR + 4, (rx_ring_phys >> 32) as u32);
            mmio.write16(REG_RMS, RMS_DEFAULT);
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
        //    current state — a follow-up wires LinkChg-driven
        //    re-evaluation.
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
            rx_ring,
            rx_pool,
            rx_head: IrqSafeSpinLock::new(0),
            mac,
            link_up,
            irq_vector: None,
            msix: None,
            rx_ipc_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ipc_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        });

        // Spawn pumps
        spawn_pumps(rtl.clone(), rx_prod, tx_cons);

        Ok(Arc::try_unwrap(rtl).map_err(|_| NicError::NoMemory)?)
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
        if frame.is_empty() || frame.len() > 1518 {
            return Err(NicError::FrameTooLong);
        }
        // Persistent per-slot buffer (audit #4); index by slot.
        let mut head_g = self.tx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let phys = self.tx_pool[slot].phys_addr().raw();
        // SAFETY: identity-mapped DMA buffer; bounds-checked above.
        unsafe {
            for (i, b) in frame.iter().enumerate() {
                core::ptr::write_volatile((phys + i as u64) as *mut u8, *b);
            }
        }
        let ring_phys = self.tx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // Make sure the slot is ours before we scribble. If OWN is
        // still set, the NIC hasn't drained the previous send — the
        // ring is full from the host's POV.
        // SAFETY: identity-mapped DMA ring; slot < RING_LEN.
        let cur_flags = unsafe { core::ptr::read_volatile(desc_addr as *const u32) };
        if cur_flags & TXD_OWN != 0 {
            return Err(NicError::TxRingFull);
        }

        // Select descriptor format based on offload request.
        let d = if let Some(mss) = meta.tso_mss {
            let mut d =
                Desc::tx_with_tso(phys as u32, (phys >> 32) as u32, frame.len() as u16, mss);
            if slot == RING_LEN - 1 {
                d.flags_len |= TXD_EOR;
            }
            d
        } else if meta.csum_l4.is_some() {
            let mut d = Desc::tx_with_csum(phys as u32, (phys >> 32) as u32, frame.len() as u16);
            if slot == RING_LEN - 1 {
                d.flags_len |= TXD_EOR;
            }
            d
        } else {
            let mut flags = TXD_OWN | TXD_FS | TXD_LS | (frame.len() as u32 & 0xFFFF);
            if slot == RING_LEN - 1 {
                flags |= TXD_EOR;
            }
            Desc {
                flags_len: flags,
                vlan: 0,
                addr_lo: phys as u32,
                addr_hi: (phys >> 32) as u32,
            }
        };
        // The NIC sees OWN=1 once we publish word0; the addr/len
        // fields must already be visible. Order: write addr/vlan/
        // length-without-OWN first, fence, then publish OWN.
        // SAFETY: identity-mapped DMA ring.
        unsafe {
            // Write the buffer pointer + vlan first.
            core::ptr::write_volatile((desc_addr + 4) as *mut u32, d.vlan);
            core::ptr::write_volatile((desc_addr + 8) as *mut u32, d.addr_lo);
            core::ptr::write_volatile((desc_addr + 12) as *mut u32, d.addr_hi);
        }
        compiler_fence(Ordering::SeqCst);
        // SAFETY: same.
        unsafe {
            core::ptr::write_volatile(desc_addr as *mut u32, d.flags_len);
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

        // Poll for OWN → 0. With the ring serviced by NPQ this
        // typically lands in microseconds; cap the wait so a hung
        // controller surfaces as TxTimeout instead of livelock.
        // responsive_spin_until ticks sleep_pumps so the FB cursor
        // / serial drain stay alive if NPQ is slow under load.
        // 250 ms wall-clock budget covers worst-case Tx congestion.
        let owned = narf_scheduler::responsive_spin_until(
            // SAFETY: identity-mapped DMA ring.
            || unsafe { core::ptr::read_volatile(desc_addr as *const u32) } & TXD_OWN == 0,
            narf_time::Deadline::after_ms(250),
        );
        if !owned {
            return Err(NicError::TxTimeout);
        }
        // (no scratch drop — buffer is persistent in tx_pool)
        Ok(())
    }

    /// Pop one received frame off the RX ring. Returns `Some(buf)`
    /// when a descriptor's OWN bit reads 0 (NIC handed it back) and
    /// `None` when the ring head is still NIC-owned.
    pub fn receive(&self) -> Option<alloc::vec::Vec<u8>> {
        let mut head_g = self.rx_head.lock();
        let slot = (*head_g) as usize % RING_LEN;
        let ring_phys = self.rx_ring.phys_addr().raw();
        let desc_addr = ring_phys + (slot * 16) as u64;

        // SAFETY: identity-mapped DMA ring.
        let flags_len = unsafe { core::ptr::read_volatile(desc_addr as *const u32) };
        if flags_len & RXD_OWN != 0 {
            return None;
        }

        // Status layout: bits[13:0] = received frame length (incl.
        // CRC unless RCR.SECRC strips it; Stage-4 leaves SECRC off
        // so the CRC is preserved — caller can strip if they care).
        // We require LS to be set, otherwise we'd have a multi-
        // segment packet — Stage-4 drops those.
        let len = (flags_len & 0x3FFF) as usize;
        let buf_phys = self.rx_pool[slot].phys_addr().raw();

        let mut out = alloc::vec::Vec::with_capacity(len.min(RX_BUF_LEN));
        if flags_len & RXD_LS != 0 {
            let copy_len = len.min(RX_BUF_LEN);
            // SAFETY: identity-mapped DMA buffer.
            for i in 0..copy_len {
                out.push(unsafe { core::ptr::read_volatile((buf_phys + i as u64) as *const u8) });
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
            core::ptr::write_volatile(desc_addr as *mut Desc, d);
        }
        compiler_fence(Ordering::SeqCst);

        *head_g = (*head_g + 1) % (RING_LEN as u32);
        Some(out)
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

    /// Re-evaluate the link state from PHYStatus. Returns the new
    /// `link_up` value and stamps it into `self.link_up`.
    pub fn refresh_link_state(&mut self) -> bool {
        // SAFETY: identity-mapped MMIO.
        let phystat = unsafe { self.mmio.read8(REG_PHYSTAT) };
        let up = phystat & PHYSTAT_LINKSTS != 0;
        self.link_up = up;
        up
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
        if frame.is_empty() || frame.len() > 1518 {
            return Err(NicError::FrameTooLong);
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
            phys = self.tx_pool[slot].phys_addr().raw();
            // SAFETY: identity-mapped DMA buffer; bounds-checked by
            // FrameTooLong guard.
            unsafe {
                for (i, b) in frame.iter().enumerate() {
                    core::ptr::write_volatile((phys + i as u64) as *mut u8, *b);
                }
            }
            desc_addr = self.tx_ring.phys_addr().raw() + (slot * 16) as u64;
            // SAFETY: identity-mapped DMA ring.
            let cur_flags = unsafe { core::ptr::read_volatile(desc_addr as *const u32) };
            if cur_flags & TXD_OWN != 0 {
                return Err(NicError::TxRingFull);
            }
            let mut flags = TXD_OWN | TXD_FS | TXD_LS | (frame.len() as u32 & 0xFFFF);
            if slot == RING_LEN - 1 {
                flags |= TXD_EOR;
            }
            // SAFETY: same.
            unsafe {
                core::ptr::write_volatile((desc_addr + 4) as *mut u32, 0u32);
                core::ptr::write_volatile((desc_addr + 8) as *mut u32, phys as u32);
                core::ptr::write_volatile((desc_addr + 12) as *mut u32, (phys >> 32) as u32);
            }
            compiler_fence(Ordering::SeqCst);
            // SAFETY: same.
            unsafe {
                core::ptr::write_volatile(desc_addr as *mut u32, flags);
            }
            compiler_fence(Ordering::SeqCst);
            *head_g = (*head_g + 1) % (RING_LEN as u32);
        }

        // SAFETY: identity-mapped MMIO.
        unsafe {
            self.mmio.write8(REG_TPPOLL, TPPOLL_NPQ);
        }

        // Wait for MSI-X. The chip raises TOK once the descriptor's
        // OWN clears; ack_isr() drains the latched event so the next
        // wait_for_irq fires on a fresh edge.
        let _ = waiter.await;
        let _ = self.ack_isr();
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

// ── Driver-match registration ────────────────────────────────────────

static CONTROLLER: IrqSafeSpinLock<Option<Arc<RtlNic>>> = IrqSafeSpinLock::new(None);

/// Probe entry — installed via `bus::register_pci_driver`. Idempotent:
/// returns `Ok(())` when the controller is already brought up.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if CONTROLLER.lock().is_some() {
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

    // SAFETY: caller-authority over the device for the duration of
    // bring_up.
    let (rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let (tx_prod, tx_cons) = channel::<Frame, TX_RING_N>();

    let dev = match unsafe { RtlNic::bring_up(&device, &cap) } {
        Ok(d) => Arc::new(d),
        Err(_) => return Err(narf_bus::ProbeError::BadDevice),
    };

    {
        let d = unsafe { &mut *(Arc::as_ptr(&dev) as *mut RtlNic) };
        *d.rx_ipc_ring.lock() = Some(rx_cons);
        *d.tx_ipc_ring.lock() = Some(tx_prod);
    }

    *CONTROLLER.lock() = Some(dev.clone());

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from("r8169"),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    // Stage-4 registry (cap-gated)
    let auth = match narf_net::trusted_net_authority() {
        Some(a) => a.derive().ok(),
        None => None,
    };
    if let Some(auth) = auth {
        let _ = narf_net::registry().register(&auth, Rtl8168Nic);
    }

    // Spawn pumps
    spawn_pumps(dev, rx_prod, tx_cons);

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

    let d2 = device;
    narf_scheduler::spawn(async move {
        r8169_tx_pump(d2, tx_cons).await;
    });
}

async fn r8169_rx_pump(device: Arc<RtlNic>, mut rx_prod: Producer<Frame, RX_RING_N>) {
    loop {
        if let Some(pkt) = device.receive() {
            let dma_buf =
                alloc_coherent(pkt.len(), DomainId::DRIVER_0).expect("Frame alloc failed");
            let mut frame = Frame::new(dma_buf, pkt.len() as u32);
            frame.payload_mut().copy_from_slice(&pkt);
            let _ = rx_prod.send(frame).await;
        }
        narf_scheduler::yield_now().await;
    }
}

async fn r8169_tx_pump(device: Arc<RtlNic>, mut tx_cons: Consumer<Frame, TX_RING_N>) {
    while let Ok(frame) = tx_cons.recv().await {
        let _ = device.transmit(frame.payload(), &TxMeta::plain());
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

/// `true` once `probe` has installed a controller.
#[derive(Debug)]
pub struct Rtl8168Nic;

impl narf_net::Interface for Rtl8168Nic {
    fn name(&self) -> &str {
        "eth3"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.link_up).unwrap_or(false)
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.rx_ipc_ring.lock().take();
            }
        });
        &RING
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        static RING: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> =
            IrqSafeSpinLock::new(None);
        with_controller(|c| {
            let mut r = RING.lock();
            if r.is_none() {
                *r = c.tx_ipc_ring.lock().take();
            }
        });
        &RING
    }
}

impl crate::HwNic for Rtl8168Nic {
    fn name(&self) -> &'static str {
        "eth3"
    }
    fn mac(&self) -> [u8; 6] {
        with_controller(|c| c.mac).unwrap_or([0; 6])
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        with_controller(|c| c.link_up).unwrap_or(false)
    }
    fn model(&self) -> crate::NicModel {
        crate::NicModel::RealtekRtl8168
    }
    fn caps(&self) -> crate::NicCaps {
        crate::NicCaps::NONE
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

pub fn is_probed() -> bool {
    CONTROLLER.lock().is_some()
}

/// Test-side accessor: run `f` against the probed controller.
pub fn with_controller<R>(f: impl FnOnce(&RtlNic) -> R) -> Option<R> {
    CONTROLLER.lock().as_ref().map(|a| f(a))
}

/// Mutable accessor — used by tests that want to switch on MSI-X
/// after probe.
pub fn with_controller_mut<R>(f: impl FnOnce(&mut RtlNic) -> R) -> Option<R> {
    CONTROLLER
        .lock()
        .as_mut()
        .map(|a| f(Arc::get_mut(a).expect("RtlNic static has multiple owners")))
}
