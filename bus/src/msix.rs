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
    pub vector: u16,
    /// MSI address the device writes to raise the IRQ. Stage-3 stub
    /// value; Stage-4 populates with the real LAPIC / GIC-ITS address.
    pub address: u64,
    /// MSI data payload. Stage-3 stub; Stage-4 populates with the real
    /// vector number / EventID.
    pub data: u32,
}

impl fmt::Debug for MsixVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MsixVector")
            .field("vector", &self.vector)
            .field("address", &format_args!("{:#x}", self.address))
            .field("data", &format_args!("{:#x}", self.data))
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
    fn from(_: CapError) -> Self {
        MsixError::AuthorityRevoked
    }
}

impl From<BarError> for MsixError {
    fn from(_: BarError) -> Self {
        MsixError::BarMapFailed
    }
}

/// Snapshot of a device's MSI-X table after `enable_msix`. Holding
/// this type is the type-level proof that the device had MSI-X
/// discovered and that the caller holds a live authority cap at the
/// point of discovery; `alloc_vector` is the one-writer gate via
/// `&mut self`.
#[derive(Debug)]
pub struct MsixTable {
    /// Index of the BAR that maps the MSI-X table.
    bir: u8,
    /// Byte offset inside the BAR where the table begins.
    table_offset: u32,
    /// Total entries in the table (N, per MSI-X Message Control bits 10..0).
    size: u16,
    /// Next free slot; reservations are monotonic within a table.
    next_free: u16,
    /// Snapshot of the PCIe function the caller claimed. Stored so
    /// vector programming knows which config window to hit.
    cfg_phys: PhysAddr,
    /// BusDevice the table was discovered against. Stored so
    /// `program_vector` can call `map_bar` without making the caller
    /// thread the device through a second time.
    device: BusDevice,
    /// Offset in cfg-space of the MSI-X capability header. Stage-4
    /// uses this in `enable` to flip the Message-Control "MSI-X
    /// enable" bit (bit 15 at cap_ptr + 2).
    cap_offset: u64,
}

impl MsixTable {
    /// BAR index the MSI-X table lives in.
    #[inline]
    pub const fn bir(&self) -> u8 {
        self.bir
    }
    /// Byte offset of the table relative to its BAR's base.
    #[inline]
    pub const fn table_offset(&self) -> u32 {
        self.table_offset
    }
    /// Total vector count in the table.
    #[inline]
    pub const fn size(&self) -> u16 {
        self.size
    }
    /// Remaining free vector slots.
    #[inline]
    pub const fn free(&self) -> u16 {
        self.size - self.next_free
    }
    /// Physical address of the owning function's cfg window.
    #[inline]
    pub const fn cfg_phys(&self) -> PhysAddr {
        self.cfg_phys
    }

    /// Reserve the next free vector slot.
    ///
    /// Returns `None` when the table is full. The returned
    /// `MsixVector`'s `address` / `data` fields are Stage-3 placeholder
    /// values — Stage-4 `interrupts/` will populate the real LAPIC /
    /// GIC-ITS doorbell address + payload at programming time.
    pub fn alloc_vector(&mut self) -> Option<MsixVector> {
        if self.next_free >= self.size {
            return None;
        }
        let v = self.next_free;
        self.next_free += 1;
        Some(MsixVector {
            vector: v,
            // Stage 3 placeholder: marks "unprogrammed" unambiguously.
            // Stage-4 will replace these with the LAPIC MSI address
            // (`0xfee0_0000 | ...`) or the GIC ITS doorbell as
            // appropriate.
            address: 0,
            data: 0,
        })
    }

    /// Reserve `n` vectors in one shot. All-or-nothing: returns
    /// `Err(TableOverflow)` if the table can't fit them.
    pub fn alloc_block(&mut self, n: u16) -> Result<(), MsixError> {
        if self.free() < n {
            return Err(MsixError::TableOverflow);
        }
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
    /// On aarch64 the `target_apic_id` argument is reinterpreted as
    /// the GIC ITS DeviceID (24 bits, opaque to the caller — drivers
    /// pick a sequential id per device) and `irq_vector` is the
    /// EventID written to `GITS_TRANSLATER`. The caller is responsible
    /// for issuing the ITS `MAPD` + `MAPTI` commands beforehand via
    /// `narf_interrupts::aarch64::its::map_event`.
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
        if vector_idx >= self.size {
            return Err(MsixError::VectorOutOfRange);
        }

        // SAFETY: caller holds the device exclusively. map_bar
        // does the size-detection write/restore against cfg-space.
        let region = unsafe { map_bar(&self.device, self.bir)? };

        // aarch64-only: register the (DeviceID, EventID) → LPI
        // translation in the GIC ITS before the device fires its
        // first MSI. Without this, a write to GITS_TRANSLATER has
        // no entry and the IRQ is silently dropped. On x86_64 the
        // LAPIC delivers directly so no analog is needed.
        #[cfg(target_arch = "aarch64")]
        {
            let device_id = crate::pci::requester_id(&self.device).ok_or(MsixError::NotPcie)?;
            let event_id = irq_vector as u32;
            let lpi = narf_interrupts::aarch64::its::LPI_BASE + irq_vector as u32;
            let collection = (target_apic_id & 0xFFFF) as u16;
            // SAFETY: ITS is initialised at boot; lpi is bounded by
            // its::NUM_LPIS.
            unsafe {
                narf_interrupts::aarch64::its::map_event(
                    device_id as u32,
                    event_id,
                    lpi,
                    collection,
                )
                .map_err(|_| MsixError::Unsupported)?;
            }
        }

        let (msg_addr, msg_data) = msi_message(target_apic_id, irq_vector);
        let msg_addr_lo = msg_addr as u32;
        let msg_addr_hi = (msg_addr >> 32) as u32;

        // Vector control bit 0 = mask. Clear to unmask the entry.
        let vec_ctrl: u32 = 0;

        let entry_off = self.table_offset as u64 + (vector_idx as u64) * 16;
        // SAFETY: entry_off + 16 <= bar.size by spec — table_offset
        // is u32-aligned and the table sits inside the BAR; map_bar
        // returned `region.len` as the BAR size.
        unsafe {
            region.write32(entry_off, msg_addr_lo);
            region.write32(entry_off + 4, msg_addr_hi);
            region.write32(entry_off + 8, msg_data);
            region.write32(entry_off + 12, vec_ctrl);
        }

        Ok(MsixVector {
            vector: vector_idx,
            address: msg_addr,
            data: msg_data,
        })
    }

    /// Program a contiguous block of `n_vectors` MSI-X table entries
    /// starting at `start_idx`, each delivering `irq_base + i` to the
    /// same target. Useful for per-CPU IO queues in storage / NIC
    /// drivers — a single call sets up N completions in one go.
    ///
    /// Returns a Vec of the resulting `MsixVector`s. Errors at the
    /// first failing entry; entries before that have already been
    /// written and the table-control "enable" bit hasn't been
    /// flipped, so the caller can recover by writing the masked
    /// vector_control.
    ///
    /// # Safety
    /// Same preconditions as `program_vector` — exclusive ownership
    /// of the device + each `start_idx + i` came from `alloc_vector`
    /// or `alloc_block` against this table.
    pub unsafe fn program_vector_block(
        &mut self,
        start_idx: u16,
        n_vectors: u16,
        target_apic_id: u32,
        irq_base: u8,
    ) -> Result<alloc::vec::Vec<MsixVector>, MsixError> {
        if start_idx as u32 + n_vectors as u32 > self.size as u32 {
            return Err(MsixError::VectorOutOfRange);
        }
        let mut out = alloc::vec::Vec::with_capacity(n_vectors as usize);
        for i in 0..n_vectors {
            let irq = irq_base
                .checked_add(i as u8)
                .ok_or(MsixError::VectorOutOfRange)?;
            // SAFETY: forwarded; per-vector_idx in range by check above.
            let v = unsafe { self.program_vector(start_idx + i, target_apic_id, irq) }?;
            out.push(v);
        }
        Ok(out)
    }

    /// Mask MSI-X entry `idx`. Sets vector_control bit 0 in the
    /// BAR-mapped table; further IRQs for that entry are suppressed
    /// until `unmask_vector` runs.
    ///
    /// # Safety
    /// Caller owns the device exclusively; `idx < self.size`.
    pub unsafe fn mask_vector(&self, idx: u16) -> Result<(), MsixError> {
        if idx >= self.size {
            return Err(MsixError::VectorOutOfRange);
        }
        // SAFETY: caller-owned device; map_bar reproducible.
        let region = unsafe { map_bar(&self.device, self.bir)? };
        let entry_off = self.table_offset as u64 + (idx as u64) * 16;
        // SAFETY: entry_off + 16 <= bar.size by spec (MsixTable was
        // built from the spec-mandated table size).
        unsafe {
            region.write32(entry_off + 12, 1);
        }
        Ok(())
    }

    /// Unmask MSI-X entry `idx` — clears vector_control bit 0.
    ///
    /// # Safety
    /// Same as `mask_vector`.
    pub unsafe fn unmask_vector(&self, idx: u16) -> Result<(), MsixError> {
        if idx >= self.size {
            return Err(MsixError::VectorOutOfRange);
        }
        // SAFETY: caller-owned device.
        let region = unsafe { map_bar(&self.device, self.bir)? };
        let entry_off = self.table_offset as u64 + (idx as u64) * 16;
        // SAFETY: same.
        unsafe {
            region.write32(entry_off + 12, 0);
        }
        Ok(())
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
        unsafe {
            cfg_write16(self.cfg_phys, off, mc | (1 << 15));
        }
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
    cap: &Cap<BusDeviceCap, Write>,
    device: &BusDevice,
) -> Result<MsixTable, MsixError> {
    cap.check_live()?;

    let cfg_phys = match device.kind {
        BusKind::Pcie { cfg_phys, .. } => cfg_phys,
        BusKind::VirtioMmio { .. } => return Err(MsixError::NotPcie),
    };

    // SAFETY: caller-checked cap; pci_cap::find_cap walks the
    // standard PCI cap list with a bounded hop count.
    let cap_ptr = match unsafe { crate::pci_cap::find_cap(device, MSIX_CAP_ID) } {
        Ok(Some(off)) => off,
        Ok(None)
        | Err(crate::pci_cap::CapError::NoCapList)
        | Err(crate::pci_cap::CapError::NotPcie) => return Err(MsixError::CapabilityNotFound),
    };

    // MSI-X capability layout (PCIe 7.7.2):
    //   +0: Cap ID + Next Cap Ptr
    //   +2: Message Control (u16)        — bits 10..0 = N-1
    //   +4: Table (u32)                  — BIR (low 3) + offset
    //   +8: Pending Bit Array (u32)
    // SAFETY: cap_ptr was returned by find_cap and points at a valid MSI-X
    // capability; cap_ptr+2 (Message Control) lies inside the 256-byte config
    // window at cfg_phys, whose ownership the caller asserted.
    let msg_ctrl = unsafe { cfg_read16(cfg_phys, cap_ptr + 2) };
    // SAFETY: cap_ptr+4 (Table BIR/offset dword) is the next field of the same
    // MSI-X capability and likewise lies inside the config window at cfg_phys.
    let table = unsafe { cfg_read32(cfg_phys, cap_ptr + 4) };

    let size = ((msg_ctrl & 0x07FF) as u16) + 1;
    let bir = (table & 0x7) as u8;
    let table_offset = table & !0x7;
    Ok(MsixTable {
        bir,
        table_offset,
        size,
        next_free: 0,
        cfg_phys,
        device: *device,
        cap_offset: cap_ptr,
    })
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
        bir: 0,
        table_offset: 0,
        size,
        next_free: 0,
        cfg_phys: PhysAddr::new(0),
        device: BusDevice {
            addr: BusAddr::Pcie(addr),
            id: DeviceId {
                vendor: 0,
                device: 0,
                class: 0,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: BusKind::Pcie {
                addr,
                cfg_phys: PhysAddr::new(0),
            },
        },
        cap_offset: 0,
    }
}

/// Compute the `(msi_addr, msg_data)` pair for an MSI delivery.
///
/// x86_64: LAPIC-directed MSI per Intel SDM Vol 3 §10.11.1.
/// aarch64: GIC ITS doorbell + EventID. The caller wires the EventID
/// → LPI translation through `narf_interrupts::aarch64::its::map_event`
/// before calling `program_vector`.
#[inline]
fn msi_message(target: u32, vector_or_event: u8) -> (u64, u32) {
    #[cfg(target_arch = "x86_64")]
    {
        // 0xFEE0_0000 | (apic_id << 12) ; data = vector.
        let addr = 0xFEE0_0000u64 | ((target as u64 & 0xFF) << 12);
        (addr, vector_or_event as u32)
    }
    #[cfg(target_arch = "aarch64")]
    {
        // GIC ITS doorbell PA + EventID.
        let _ = target;
        (
            narf_interrupts::aarch64::its::doorbell_pa(),
            vector_or_event as u32,
        )
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (target, vector_or_event);
        (0, 0)
    }
}

// ── helpers ─────────────────────────────────────────────────────────

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
    unsafe {
        core::ptr::write_volatile((cfg.raw() + off) as *mut u16, value);
    }
    compiler_fence(Ordering::SeqCst);
}
