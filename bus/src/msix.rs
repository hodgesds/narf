//! MSI-X vector allocation + programming path for PCIe devices.
//!
//! Spec: `bus/specification/spec.md` §3 + §5. Stage 3 landed the
//! discovery + enable surface (cap walk + table-size sniff). Stage 4
//! grows that into actual LAPIC-directed delivery on x86_64:
//! `program_vector` does the BAR-mapped table write (msg_addr +
//! msg_data + vector_control), and `enable` flips the
//! Message-Control "MSI-X enable" bit so the device starts using the
//! programmed entries.
//!
//! On aarch64 the same `program_vector` API will eventually emit a
//! GIC ITS doorbell (`GITS_TRANSLATER` address + EventID), but the
//! Stage-4 cut here is x86_64-only; aarch64 callers get an
//! `Unsupported` error.
//!
//! Cap-gating: `enable_msix` takes the `Cap<BusDevice, Write>` the
//! caller got from `claim_device_cap`. The `MsixTable` is `!Copy`; the
//! `&mut self` on `alloc_vector` is the type-level one-writer gate —
//! two drivers can't race on the same table because only one holds
//! ownership of the handle.

use core::fmt;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_capabilities::{Cap, CapError, Write};
use narf_memory::PhysAddr;

use crate::bar::{map_bar, BarError};
use crate::device::{BusDevice, BusKind};
use crate::registry::BusDeviceCap;

/// PCI Express capability-list ID for MSI-X. Per PCIe spec §7.7.2.
pub const MSIX_CAP_ID: u8 = 0x11;

/// Offset of the Capabilities Pointer in type-0 config space.
const CAP_POINTER_OFFSET: u64 = 0x34;
/// Status register (offset 0x06) — bit 4 signals "capabilities list
/// present". Without it, walking the cap pointer is undefined behaviour.
const STATUS_OFFSET: u64 = 0x06;
const STATUS_CAP_LIST_BIT: u16 = 1 << 4;

/// A reserved MSI-X vector.
///
/// Stage 3 stores placeholder `address` / `data` fields — real
/// LAPIC-directed-MSI on x86_64 and GIC ITS doorbell on aarch64 land
/// when `interrupts/` grows the vector allocator (Stage 4). The
/// `vector` slot index is however authoritative: once handed out, it
/// stays reserved for the lifetime of the owning `MsixTable`.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct MsixVector {
    /// Index into the device's MSI-X table (0..N-1).
    pub vector:  u16,
    /// MSI address the device writes to raise the IRQ. Stage-3 stub
    /// value; Stage-4 populates with the real LAPIC / GIC-ITS address.
    pub address: u64,
    /// MSI data payload. Stage-3 stub; Stage-4 populates with the real
    /// vector number / EventID.
    pub data:    u32,
}

impl fmt::Debug for MsixVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MsixVector")
            .field("vector",  &self.vector)
            .field("address", &format_args!("{:#x}", self.address))
            .field("data",    &format_args!("{:#x}", self.data))
            .finish()
    }
}

/// Errors that can surface while enabling MSI-X on a device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsixError {
    /// The device has no MSI-X capability (ID 0x11) in its cap list —
    /// common for legacy-PCI devices and every virtio-mmio transport.
    CapabilityNotFound,
    /// The caller tried to reserve more vectors than the table holds.
    TableOverflow,
    /// MSI-X is not enabled yet — `enable_msix` must run first.
    NotEnabled,
    /// The `Cap<BusDevice, Write>` has been revoked.
    AuthorityRevoked,
    /// Device has no PCIe cfg window (e.g. a virtio-mmio transport);
    /// MSI-X applies only to PCIe devices.
    NotPcie,
    /// `program_vector` was given a vector index >= the table size.
    VectorOutOfRange,
    /// The BAR named by `MsixTable::bir()` couldn't be mapped (BAR
    /// unimplemented / unprogrammed / out-of-range).
    BarMapFailed,
    /// MSI-X programming is not implemented on this arch (aarch64
    /// stays a stub until the GIC ITS doorbell path lands).
    Unsupported,
}

impl From<CapError> for MsixError {
    fn from(_: CapError) -> Self { MsixError::AuthorityRevoked }
}

impl From<BarError> for MsixError {
    fn from(_: BarError) -> Self { MsixError::BarMapFailed }
}

/// Snapshot of a device's MSI-X table after `enable_msix`. Holding
/// this type is the type-level proof that the device had MSI-X
/// discovered and that the caller holds a live authority cap at the
/// point of discovery; `alloc_vector` is the one-writer gate via
/// `&mut self`.
#[derive(Debug)]
pub struct MsixTable {
    /// Index of the BAR that maps the MSI-X table.
    bir:           u8,
    /// Byte offset inside the BAR where the table begins.
    table_offset:  u32,
    /// Total entries in the table (N, per MSI-X Message Control bits 10..0).
    size:          u16,
    /// Next free slot; reservations are monotonic within a table.
    next_free:     u16,
    /// Snapshot of the PCIe function the caller claimed. Stored so
    /// vector programming knows which config window to hit.
    cfg_phys:      PhysAddr,
    /// BusDevice the table was discovered against. Stored so
    /// `program_vector` can call `map_bar` without making the caller
    /// thread the device through a second time.
    device:        BusDevice,
    /// Offset in cfg-space of the MSI-X capability header. Stage-4
    /// uses this in `enable` to flip the Message-Control "MSI-X
    /// enable" bit (bit 15 at cap_ptr + 2).
    cap_offset:    u64,
}

impl MsixTable {
    /// BAR index the MSI-X table lives in.
    #[inline]
    pub const fn bir(&self) -> u8 { self.bir }
    /// Byte offset of the table relative to its BAR's base.
    #[inline]
    pub const fn table_offset(&self) -> u32 { self.table_offset }
    /// Total vector count in the table.
    #[inline]
    pub const fn size(&self) -> u16 { self.size }
    /// Remaining free vector slots.
    #[inline]
    pub const fn free(&self) -> u16 { self.size - self.next_free }
    /// Physical address of the owning function's cfg window.
    #[inline]
    pub const fn cfg_phys(&self) -> PhysAddr { self.cfg_phys }

    /// Reserve the next free vector slot.
    ///
    /// Returns `None` when the table is full. The returned
    /// `MsixVector`'s `address` / `data` fields are Stage-3 placeholder
    /// values — Stage-4 `interrupts/` will populate the real LAPIC /
    /// GIC-ITS doorbell address + payload at programming time.
    pub fn alloc_vector(&mut self) -> Option<MsixVector> {
        if self.next_free >= self.size { return None; }
        let v = self.next_free;
        self.next_free += 1;
        Some(MsixVector {
            vector:  v,
            // Stage 3 placeholder: marks "unprogrammed" unambiguously.
            // Stage-4 will replace these with the LAPIC MSI address
            // (`0xfee0_0000 | ...`) or the GIC ITS doorbell as
            // appropriate.
            address: 0,
            data:    0,
        })
    }

    /// Reserve `n` vectors in one shot. All-or-nothing: returns
    /// `Err(TableOverflow)` if the table can't fit them.
    pub fn alloc_block(&mut self, n: u16) -> Result<(), MsixError> {
        if self.free() < n { return Err(MsixError::TableOverflow); }
        self.next_free += n;
        Ok(())
    }

    /// Program a previously-allocated MSI-X table entry to deliver
    /// IRQs to a target CPU's LAPIC at vector `irq_vector`.
    ///
    /// LAPIC-directed MSI on x86_64 (Intel SDM Vol 3 §10.11.1):
    ///   - Address: `0xFEE0_0000 | (target_apic_id << 12)` with bits
    ///     12..=11 of the field encoding redirection-hint / dest-mode
    ///     left at 0 (physical, no redirection).
    ///   - Data: bits 7..0 = vector, bits 10..8 = delivery-mode (0 =
    ///     Fixed), bits 14 = level, 15 = trigger-mode (0 / 0 for
    ///     edge-triggered Fixed delivery).
    ///
    /// The MSI-X table entry layout (PCIe §6.1.4) is four naturally
    /// aligned u32s, total 16 bytes: `[msg_addr_lo, msg_addr_hi,
    /// msg_data, vector_control]`. `vector_control` bit 0 is the
    /// per-entry mask; we clear it here so the entry starts unmasked.
    ///
    /// The caller must have `enable_msix`-discovered the table on
    /// `self.device`, and `enable()` must run before MSI delivery
    /// actually starts (Message-Control's enable bit is the global
    /// gate). Programming entries while disabled is the documented
    /// PCIe-recommended order.
    ///
    /// On aarch64 this is a stub that returns `Unsupported` until the
    /// GIC ITS doorbell path lands.
    ///
    /// # Safety
    /// - The caller owns the device's BAR for the duration of this
    ///   call (no other writer to the MSI-X table).
    /// - `vector_idx` must have come from `alloc_vector` against
    ///   `self`, otherwise this writes into a slot another driver may
    ///   eventually claim.
    pub unsafe fn program_vector(
        &mut self,
        vector_idx: u16,
        target_apic_id: u32,
        irq_vector: u8,
    ) -> Result<MsixVector, MsixError> {
        if vector_idx >= self.size { return Err(MsixError::VectorOutOfRange); }

        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (target_apic_id, irq_vector);
            return Err(MsixError::Unsupported);
        }

        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: caller holds the device exclusively. map_bar
            // does the size-detection write/restore against cfg-space.
            let region = unsafe { map_bar(&self.device, self.bir)? };

            // LAPIC MSI address: 0xFEE0_0000 | (apic_id << 12).
            // Bits 11..=4 are the destination APIC id for the
            // physical / no-redirection case; we use bits 19..=12 for
            // the standard 8-bit destination ID and leave the upper
            // bits at zero (extended dest-id requires interrupt-
            // remapping, which we don't gate on).
            let msg_addr_lo: u32 = 0xFEE0_0000 | ((target_apic_id & 0xFF) << 12);
            let msg_addr_hi: u32 = 0;
            // Data: vector in bits 7..0, delivery-mode 000 = Fixed,
            // level 0, trigger-mode 0 (edge). The remaining bits stay
            // zero.
            let msg_data:    u32 = irq_vector as u32;
            // Vector control bit 0 = mask. Clear to unmask the entry.
            let vec_ctrl:    u32 = 0;

            let entry_off = self.table_offset as u64 + (vector_idx as u64) * 16;
            // SAFETY: entry_off + 16 <= bar.size by spec — table_offset
            // is u32-aligned and the table sits inside the BAR; map_bar
            // returned `region.len` as the BAR size.
            unsafe {
                region.write32(entry_off,      msg_addr_lo);
                region.write32(entry_off + 4,  msg_addr_hi);
                region.write32(entry_off + 8,  msg_data);
                region.write32(entry_off + 12, vec_ctrl);
            }

            Ok(MsixVector {
                vector:  vector_idx,
                address: ((msg_addr_hi as u64) << 32) | (msg_addr_lo as u64),
                data:    msg_data,
            })
        }
    }

    /// Flip the MSI-X capability's "MSI-X enable" bit (Message
    /// Control bit 15). After this returns, programmed entries
    /// actually deliver. PCIe-recommended order: program first, then
    /// enable.
    ///
    /// # Safety
    /// Caller owns the device's cfg-space exclusively.
    pub unsafe fn enable(&mut self) -> Result<(), MsixError> {
        let off = self.cap_offset + 2;
        // SAFETY: cap_offset came from the cap-list walk in
        // `enable_msix` and is < 0x100; same window we read from
        // during discovery.
        let mc = unsafe { cfg_read16(self.cfg_phys, off) };
        // SAFETY: same window; setting bit 15 is the documented
        // global-enable.
        unsafe { cfg_write16(self.cfg_phys, off, mc | (1 << 15)); }
        Ok(())
    }

    /// `true` once `enable()` has flipped the MSI-X enable bit. Reads
    /// the cap header live so re-enables are reflected.
    pub fn is_enabled(&self) -> bool {
        // SAFETY: cap_offset is the cached value from discovery, which
        // confirmed it lives inside this function's cfg window.
        let mc = unsafe { cfg_read16(self.cfg_phys, self.cap_offset + 2) };
        (mc & (1 << 15)) != 0
    }
}

/// Enable MSI-X on a PCIe device.
///
/// Walks the capability list at offset 0x34 looking for ID 0x11
/// (MSI-X), reads its Message Control word to get the table size, and
/// the table offset / BIR from the Table register. The Message-Control
/// "enable" bit (bit 15) is not flipped yet — Stage-3 scope stops at
/// discovery; Stage-4 will do the actual write during per-vector
/// programming, paired with masking bits.
///
/// Cap-gated: `cap.check_live()` is the epoch gate per
/// `capabilities/` §3–§4.
pub fn enable_msix(
    cap:    &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Result<MsixTable, MsixError> {
    cap.check_live()?;

    let cfg_phys = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. }     => return Err(MsixError::NotPcie),
    };

    // SAFETY: the BusDevice came out of the registry, which only
    // records functions whose cfg window is inside the identity-mapped
    // ECAM region. 2-byte / 1-byte MMIO reads against an aligned
    // offset are well-defined.
    let status = unsafe { cfg_read16(cfg_phys, STATUS_OFFSET) };
    if (status & STATUS_CAP_LIST_BIT) == 0 {
        return Err(MsixError::CapabilityNotFound);
    }

    // SAFETY: same window.
    let mut cap_ptr = (unsafe { cfg_read8(cfg_phys, CAP_POINTER_OFFSET) }) as u64;
    // Bottom two bits are reserved per PCI spec 3.0 §6.7 and must be
    // masked off when treating the pointer as an offset.
    cap_ptr &= 0xFC;

    // The cap list is bounded to the 256-byte type-0 header; a
    // malformed pointer could otherwise loop forever. 48 cap headers
    // is a generous upper bound — far more than any real device.
    let mut hops = 0u32;
    while cap_ptr != 0 && hops < 48 {
        // SAFETY: cap_ptr < 0x100 per the mask + the walk bound.
        let id   = unsafe { cfg_read8(cfg_phys, cap_ptr)     };
        // SAFETY: same.
        let next = unsafe { cfg_read8(cfg_phys, cap_ptr + 1) };

        if id == MSIX_CAP_ID {
            // MSI-X capability layout (PCIe 7.7.2):
            //   +0: Cap ID + Next Cap Ptr
            //   +2: Message Control (u16)        — bits 10..0 = N-1
            //   +4: Table (u32)                  — BIR (low 3) + offset
            //   +8: Pending Bit Array (u32)
            // SAFETY: still inside the 256-byte config window.
            let msg_ctrl = unsafe { cfg_read16(cfg_phys, cap_ptr + 2) };
            let table    = unsafe { cfg_read32(cfg_phys, cap_ptr + 4) };

            // N-1 encoding: the actual table size is (msg_ctrl & 0x7FF) + 1.
            let size         = ((msg_ctrl & 0x07FF) as u16) + 1;
            let bir          = (table & 0x7) as u8;
            let table_offset = table & !0x7;
            return Ok(MsixTable {
                bir,
                table_offset,
                size,
                next_free: 0,
                cfg_phys,
                device:     *device,
                cap_offset: cap_ptr,
            });
        }

        cap_ptr = (next as u64) & 0xFC;
        hops += 1;
    }

    Err(MsixError::CapabilityNotFound)
}

/// Test-only helper: build an `MsixTable` from synthetic metadata
/// without walking any live config space. Used by the `smoke_bus_msix`
/// tests to exercise the `alloc_vector` arithmetic without depending
/// on a particular device's capability layout.
#[doc(hidden)]
pub fn __synth_msix_table(size: u16) -> MsixTable {
    use crate::addr::{BusAddr, PcieAddr};
    use crate::device::{BusKind, DeviceId};
    let addr = PcieAddr::new(0, 0, 0, 0);
    MsixTable {
        bir:          0,
        table_offset: 0,
        size,
        next_free:    0,
        cfg_phys:     PhysAddr::new(0),
        device:       BusDevice {
            addr: BusAddr::Pcie(addr),
            id:   DeviceId { vendor: 0, device: 0, class: 0 },
            kind: BusKind::Pcie { addr, cfg_phys: PhysAddr::new(0) },
        },
        cap_offset:   0,
    }
}

// ── helpers ─────────────────────────────────────────────────────────

/// Read a single byte out of an identity-mapped PCIe config window.
///
/// # Safety
/// `cfg` + `off` must lie inside the function's 4-KiB cfg window.
#[inline]
unsafe fn cfg_read8(cfg: PhysAddr, off: u64) -> u8 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller promises the byte is readable.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u8) };
    compiler_fence(Ordering::SeqCst);
    v
}

/// Read an aligned 16-bit word out of an identity-mapped PCIe config
/// window.
///
/// # Safety
/// `cfg` + `off` must lie inside the function's 4-KiB cfg window and
/// be 2-byte aligned.
#[inline]
unsafe fn cfg_read16(cfg: PhysAddr, off: u64) -> u16 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller promises the word is readable + aligned.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u16) };
    compiler_fence(Ordering::SeqCst);
    v
}

/// Read an aligned 32-bit word out of an identity-mapped PCIe config
/// window.
///
/// # Safety
/// `cfg` + `off` must lie inside the function's 4-KiB cfg window and
/// be 4-byte aligned.
#[inline]
unsafe fn cfg_read32(cfg: PhysAddr, off: u64) -> u32 {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller promises the dword is readable + aligned.
    let v = unsafe { core::ptr::read_volatile((cfg.raw() + off) as *const u32) };
    compiler_fence(Ordering::SeqCst);
    v
}

/// Write an aligned 16-bit word into an identity-mapped PCIe config
/// window.
///
/// # Safety
/// `cfg` + `off` must lie inside the function's 4-KiB cfg window and
/// be 2-byte aligned. Caller owns the device exclusively.
#[inline]
unsafe fn cfg_write16(cfg: PhysAddr, off: u64, value: u16) {
    compiler_fence(Ordering::SeqCst);
    // SAFETY: caller promises the slot is writable + aligned.
    unsafe { core::ptr::write_volatile((cfg.raw() + off) as *mut u16, value); }
    compiler_fence(Ordering::SeqCst);
}
