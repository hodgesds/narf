//! AF_BYPASS / AF_XDP-equivalent socket state + dispatcher.
//!
//! NARF's userspace surface for kernel-bypass networking. Mirrors
//! Linux AF_XDP (`linux/net/xdp/xsk.c`) but with NARF-native
//! divergences:
//!
//! - No `mmap(2)` of raw bytes. The kernel returns
//!   `Cap<{Fill,Rx,Tx,Completion}Ring, Invoke>` from
//!   `setsockopt(XDP_*_RING)` and userspace drives them through
//!   `narf_ipc::Ring` rather than poking shared pages.
//! - UMEM is registered via `setsockopt(XDP_UMEM_REG, &reg)`
//!   carrying a size/frame_size pair; the kernel mints a
//!   `Cap<UmemRegion, Invoke>` + returns it through the per-socket
//!   state.
//! - `bind(2)` accepts a NARF-specific sockaddr_xdp: `(iface_name,
//!   queue_id, flags)`. Wire shape: 16-byte iface name + u32
//!   queue_id + u32 flags = 24 bytes.
//!
//! Linux refs:
//! - `linux/net/xdp/xsk.c::xsk_setsockopt` — option dispatch.
//! - `linux/Documentation/networking/af_xdp.rst` — userspace model.

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

pub use narf_net::bypass::xdp::{
    XdpDesc, XdpStatistics, XDP_PGOFF_RX_RING, XDP_PGOFF_TX_RING, XDP_UMEM_PGOFF_COMPLETION_RING,
    XDP_UMEM_PGOFF_FILL_RING,
};
use narf_net::bypass::xdp::{
    XDP_RING_CONSUMER_OFF, XDP_RING_DESC_OFF, XDP_RING_FLAGS_OFF, XDP_RING_PRODUCER_OFF,
};
use narf_net::bypass::{FlowKey, Umem, UmemSlot, XdpSocket as KernelXdpSocket, XdpSocketParts};

// ── Address family + ABI constants ──────────────────────────────────

/// Standard Linux `AF_XDP` address family (`include/linux/socket.h`).
pub const AF_XDP: u16 = 44;

/// NARF-specific AF for the bypass socket. Picks 45 because Linux's
/// AF_XDP is 44 and 45 is currently free in the Linux numbering;
/// keeps the wire ABI close to Linux's so a port doesn't have to
/// rewrite family handling code.
pub const AF_BYPASS: u16 = 45;

/// XDP setsockopt level (Linux: `SOL_XDP = 283`). We mirror.
pub const SOL_XDP: u32 = 283;

/// XDP socket options. Names + numbers match Linux's
/// `linux/include/uapi/linux/if_xdp.h` so a libxdp-style port
/// recognises them.
pub const XDP_MMAP_OFFSETS: u32 = 1;
pub const XDP_RX_RING: u32 = 2;
pub const XDP_TX_RING: u32 = 3;
pub const XDP_UMEM_REG: u32 = 4;
pub const XDP_UMEM_FILL_RING: u32 = 5;
pub const XDP_UMEM_COMPLETION_RING: u32 = 6;
pub const XDP_STATISTICS: u32 = 7;
pub const XDP_OPTIONS: u32 = 8;

/// Wire-shape XDP_UMEM_REG payload. Mirrors Linux's
/// `struct xdp_umem_reg`. `addr` is the user vaddr; NARF doesn't
/// use it for now (alloc happens in the kernel) but keeps the
/// field for ABI compat.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct XdpUmemReg {
    /// User-space base virtual address of the UMEM. Ignored on
    /// NARF — alloc is kernel-side — kept for ABI compat.
    pub addr: u64,
    /// Total size in bytes.
    pub len: u64,
    /// Frame size (power of two; 2048 or 4096).
    pub chunk_size: u32,
    /// Headroom reserved before each frame's payload — ignored.
    pub headroom: u32,
    /// Bit flags. Ignored.
    pub flags: u32,
}

/// Wire-shape sockaddr_xdp body. Family is carried separately by
/// the syscall ABI. Linux uses
/// `struct sockaddr_xdp { __u16 sxdp_family; __u16 sxdp_flags;
/// __u32 sxdp_ifindex; __u32 sxdp_queue_id; __u32
/// sxdp_shared_umem_fd; }` — we serialise the iface name as a
/// 16-byte field instead of an ifindex (NARF doesn't index NICs).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SockAddrXdp {
    pub flags: u16,
    pub queue_id: u32,
    /// 16-byte fixed-size iface name. Trailing NUL-padded.
    pub iface_name: [u8; 16],
}

// ── XdpSocket state ────────────────────────────────────────────────

/// Userspace-facing socket state. One per `socket(AF_BYPASS,
/// SOCK_RAW, 0)` fd. The kernel-side `XdpSocket` (the four-ring
/// owner) is held in `kernel_parts` after `setsockopt(XDP_UMEM_REG)`
/// completes.
pub struct XdpSocketState {
    /// Set after `setsockopt(XDP_UMEM_REG)`.
    pub umem: IrqSafeSpinLock<Option<Arc<Umem>>>,
    /// Created after the first `XDP_RX_RING` / `XDP_TX_RING` /
    /// `XDP_UMEM_FILL_RING` / `XDP_UMEM_COMPLETION_RING` call. The
    /// four rings are created together at the first of these calls;
    /// subsequent ones are no-ops.
    pub kernel_parts: IrqSafeSpinLock<Option<XdpSocketParts>>,
    /// Set after `bind(2)`.
    pub bound: AtomicBool,
    pub iface_name: IrqSafeSpinLock<Option<String>>,
    /// Claim id returned from `bypass::register_flow`. Cleared on
    /// close.
    pub claim_seq: IrqSafeSpinLock<Option<u32>>,
}

impl core::fmt::Debug for XdpSocketState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XdpSocketState")
            .field("bound", &self.bound.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl Default for XdpSocketState {
    fn default() -> Self {
        Self::new()
    }
}

impl XdpSocketState {
    pub const fn new() -> Self {
        Self {
            umem: IrqSafeSpinLock::new(None),
            kernel_parts: IrqSafeSpinLock::new(None),
            bound: AtomicBool::new(false),
            iface_name: IrqSafeSpinLock::new(None),
            claim_seq: IrqSafeSpinLock::new(None),
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────

/// XDP socket op errors. Mirrors `crate::socket::SockError` shape
/// for the dispatcher to translate into errno.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XdpOpError {
    InvalidArg,
    AlreadyRegistered,
    UmemNotRegistered,
    RingsNotCreated,
    BindFailed,
    AccessDenied,
}

// ── setsockopt dispatch ────────────────────────────────────────────

/// Apply `XDP_UMEM_REG`. Registers a fresh UMEM and stashes the
/// `Arc<Umem>` (the user-facing cap is the one stored on the Umem
/// itself, retrievable via [`Umem::cap`]).
pub fn handle_umem_reg(state: &XdpSocketState, reg: &XdpUmemReg) -> Result<(), XdpOpError> {
    handle_umem_reg_with_owner(state, reg, None)
}

pub fn handle_umem_reg_with_owner(
    state: &XdpSocketState,
    reg: &XdpUmemReg,
    owner: Option<Arc<dyn narf_filesystem::FileOps>>,
) -> Result<(), XdpOpError> {
    if state.umem.lock().is_some() {
        return Err(XdpOpError::AlreadyRegistered);
    }
    if reg.len > u64::from(u32::MAX) || reg.headroom != 0 || reg.flags != 0 {
        return Err(XdpOpError::InvalidArg);
    }
    let size = reg.len as u32;
    let chunk = reg.chunk_size;
    if reg.addr != 0
        && (reg.addr & 0xfff != 0
            || crate::handlers::validate_user_range(reg.addr, size as usize).is_err())
    {
        return Err(XdpOpError::InvalidArg);
    }
    let umem = Umem::register(size, chunk).map_err(|_| XdpOpError::InvalidArg)?;
    if reg.addr != 0 {
        if reg.addr < narf_memory::AddressSpace::USER_HALF_END {
            let Some(as_ref) = crate::handlers::active_user_as() else {
                return Err(XdpOpError::InvalidArg);
            };
            let map_len = (u64::from(size) + 4095) & !4095;
            let pages = (map_len >> 12) as usize;
            for idx in 0..pages {
                let page_va = reg.addr + (idx as u64) * 4096;
                let Some(region) = as_ref.lookup(narf_memory::VirtAddr::new(page_va)) else {
                    return Err(XdpOpError::InvalidArg);
                };
                let region_idx = ((page_va - region.base.as_u64()) >> 12) as usize;
                if let Some(phys) = region
                    .phys
                    .get(region_idx)
                    .map(|p| p.raw())
                    .filter(|&p| p != 0)
                {
                    let src_ptr = narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>();
                    let copy_off = idx * 4096;
                    let copy_len = (size as usize).saturating_sub(copy_off).min(4096);
                    if copy_len > 0 {
                        // SAFETY: `src_ptr` is the direct-map alias of a live 4096-byte frame,
                        // and `umem.desc().base_virt + copy_off` lies within the `size`-byte UMEM.
                        unsafe {
                            core::ptr::copy_nonoverlapping(
                                src_ptr,
                                (umem.desc().base_virt as *mut u8).add(copy_off),
                                copy_len,
                            );
                        }
                    }
                }
            }
            if !try_remap_user_umem(&as_ref, reg.addr, size, &umem, owner) {
                return Err(XdpOpError::InvalidArg);
            }
        } else {
            let mut scratch = alloc::vec![0u8; chunk as usize];
            for frame_idx in 0..umem.nb_frames() {
                let user_off = reg.addr + u64::from(frame_idx) * u64::from(chunk);
                // SAFETY: user range was validated above and `scratch` is `chunk` bytes.
                if unsafe { crate::handlers::copy_from_user(&mut scratch, user_off) }.is_err() {
                    return Err(XdpOpError::InvalidArg);
                }
                if umem.write_frame_bytes(frame_idx, 0, &scratch).is_none() {
                    return Err(XdpOpError::InvalidArg);
                }
            }
            umem.set_kernel_mirror_addr(reg.addr);
        }
    }
    *state.umem.lock() = Some(umem);
    Ok(())
}

fn try_remap_user_umem(
    as_ref: &Arc<narf_memory::AddressSpace>,
    addr: u64,
    size: u32,
    umem: &Arc<Umem>,
    owner: Option<Arc<dyn narf_filesystem::FileOps>>,
) -> bool {
    let map_len = (u64::from(size) + 4095) & !4095;
    let pages = (map_len >> 12) as usize;
    let base_phys = umem.desc().base_phys;
    let mut backing = narf_memory::region_backing::RegionBacking::new();
    backing.resize(pages, narf_memory::PhysAddr::new(0));
    for idx in 0..pages {
        if backing.reserve_slot(idx).is_err() {
            return false;
        }
        if let Some(slot) = backing.get_mut(idx) {
            *slot = narf_memory::PhysAddr::new(base_phys + (idx as u64) * 4096);
        }
    }
    let perms = narf_memory::RegionPerms::READ
        | narf_memory::RegionPerms::WRITE
        | narf_memory::RegionPerms::SHARED
        | narf_memory::RegionPerms::EXTERNAL_REFS
        | narf_memory::RegionPerms::LOCK_EXEMPT
        | narf_memory::RegionPerms::PINNABLE_RAM;
    let region = narf_memory::Region {
        base: narf_memory::VirtAddr::new(addr),
        len: map_len,
        perms,
        phys: backing,
    };
    let lifetime: Option<Arc<dyn narf_filesystem::MmapLifetime>> = Some(umem.clone());
    as_ref
        .with_vma_transaction(|| {
            narf_memory::with_address_space_shared_mapping_transaction(as_ref.identity(), || {
                if let Some(ops) = owner {
                    crate::mapped_file::publish_current_mapping(
                        as_ref.identity(),
                        crate::mapped_file::MappingOwnerRegistration {
                            base: addr,
                            len: map_len,
                            file_offset: 0,
                            ops,
                            lifetime,
                            writeback_phys: None,
                            private_copy: false,
                            replace: true,
                            zero_from: None,
                            provenance: None,
                        },
                        || {
                            // SAFETY: `region` is backed by pinned UMEM physical pages and
                            // `with_vma_transaction` holds the address-space VMA lock.
                            unsafe {
                                as_ref.replace_shared_region_locked_limited_receipt(
                                    region,
                                    false,
                                    u64::MAX,
                                    true,
                                )
                            }
                        },
                        |receipt| {
                            // SAFETY: `receipt` was produced by `replace_shared_region_locked_limited_receipt`
                            // under the active VMA transaction lock.
                            match unsafe { as_ref.materialize_mapping_locked(receipt) } {
                                Ok(()) => Ok(()),
                                Err(err) => {
                                    // SAFETY: `receipt` belongs to the failed materialization in this transaction.
                                    let _ = unsafe { as_ref.rollback_mapping_locked(receipt) };
                                    Err(err)
                                }
                            }
                        },
                    )
                } else {
                    // SAFETY: `region` is backed by pinned UMEM physical pages and
                    // `with_vma_transaction` holds the address-space VMA lock.
                    let receipt = unsafe {
                        as_ref.replace_shared_region_locked_limited_receipt(
                            region,
                            false,
                            u64::MAX,
                            true,
                        )?
                    };
                    // SAFETY: `receipt` was produced by `replace_shared_region_locked_limited_receipt`
                    // under the active VMA transaction lock.
                    match unsafe { as_ref.materialize_mapping_locked(receipt) } {
                        Ok(()) => Ok(receipt),
                        Err(err) => {
                            // SAFETY: `receipt` belongs to the failed materialization in this transaction.
                            let _ = unsafe { as_ref.rollback_mapping_locked(receipt) };
                            Err(err)
                        }
                    }
                }
            })
        })
        .is_ok()
}

/// Apply any of `XDP_RX_RING` / `XDP_TX_RING` / `XDP_UMEM_FILL_RING`
/// / `XDP_UMEM_COMPLETION_RING`. NARF creates all four rings at
/// once at the first such call (matches the AF_XDP usage pattern
/// where userspace sets all four sizes in sequence then binds).
pub fn handle_ring_setup(state: &XdpSocketState, value: u32) -> Result<(), XdpOpError> {
    handle_ring_setup_named(state, XDP_RX_RING, value)
}

pub fn handle_ring_setup_named(
    state: &XdpSocketState,
    opt_name: u32,
    entries: u32,
) -> Result<(), XdpOpError> {
    if entries == 0
        || entries > narf_net::bypass::xdp::XDP_RING_N as u32
        || !entries.is_power_of_two()
    {
        return Err(XdpOpError::InvalidArg);
    }
    let mut g = state.kernel_parts.lock();
    if g.is_none() {
        let umem = match state.umem.lock().clone() {
            Some(u) => u,
            None => return Err(XdpOpError::UmemNotRegistered),
        };
        *g = Some(KernelXdpSocket::create(umem));
    }
    if let Some(parts) = g.as_ref() {
        if !parts.socket.set_ring_entries(opt_name, entries) {
            return Err(XdpOpError::InvalidArg);
        }
    }
    Ok(())
}

/// Apply `bind(2)` with a sockaddr_xdp body. Registers a default
/// (wildcard) flow claim against the socket's kernel-side handle
/// and marks the socket bound. A more specific claim can be added
/// later via `setsockopt(SOL_XDP, XDP_OPTIONS)` once that lands.
pub fn handle_bind(state: &XdpSocketState, addr: &SockAddrXdp) -> Result<(), XdpOpError> {
    if addr.flags & !6 != 0 || addr.flags & 6 == 6 {
        return Err(XdpOpError::InvalidArg);
    }
    if state.bound.load(Ordering::Acquire) {
        return Err(XdpOpError::AlreadyRegistered);
    }
    // Trim NUL from the iface name.
    let n = addr
        .iface_name
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(addr.iface_name.len());
    let iface_str = match core::str::from_utf8(&addr.iface_name[..n]) {
        Ok(s) => s.to_string(),
        Err(_) => return Err(XdpOpError::InvalidArg),
    };
    let parts_owned = state.kernel_parts.lock().is_some();
    if !parts_owned {
        return Err(XdpOpError::RingsNotCreated);
    }
    // Take a clone of the kernel Arc<XdpSocket> without moving the
    // parts.
    let kernel_socket = {
        let g = state.kernel_parts.lock();
        g.as_ref().map(|p| p.socket.clone())
    };
    let kernel_socket = match kernel_socket {
        Some(s) => s,
        None => return Err(XdpOpError::RingsNotCreated),
    };
    if let Ok(settings) = narf_net::nic::with_control(&iface_str, |d| d.settings()) {
        if addr.queue_id >= u32::from(settings.channels) {
            return Err(XdpOpError::InvalidArg);
        }
    }
    struct Attempt {
        socket: Arc<KernelXdpSocket>,
        committed: bool,
    }
    impl Drop for Attempt {
        fn drop(&mut self) {
            if !self.committed {
                self.socket.unbind();
            }
        }
    }
    let mut attempt = Attempt {
        socket: kernel_socket.clone(),
        committed: false,
    };
    kernel_socket
        .bind(iface_str.clone(), addr.queue_id)
        .map_err(|_| XdpOpError::BindFailed)?;
    if addr.flags & 4 != 0 {
        narf_net::bypass::classifier::reserve_native(
            &iface_str,
            addr.queue_id,
            kernel_socket.clone(),
        )
        .map_err(|_| XdpOpError::BindFailed)?;
        if narf_net::nic::with_control(&iface_str, |c| {
            c.bind_xsk(
                u16::try_from(addr.queue_id).map_err(|_| 22)?,
                Some(kernel_socket.clone()),
            )
        })
        .is_err()
        {
            if kernel_socket.is_closed() {
                // The driver may still own DMA leases after a failed restart.
                // Keep its claim until recovery proves the queue stopped.
                *state.iface_name.lock() = Some(iface_str);
                state.bound.store(true, Ordering::Release);
                attempt.committed = true;
            } else {
                narf_net::bypass::classifier::release_native(&iface_str, addr.queue_id);
            }
            return Err(XdpOpError::BindFailed);
        }
        *state.iface_name.lock() = Some(iface_str);
        state.bound.store(true, Ordering::Release);
        attempt.committed = true;
        return Ok(());
    }
    let seq = narf_net::bypass::register_flow(FlowKey::default(), kernel_socket)
        .map_err(|_| XdpOpError::BindFailed)?;
    *state.claim_seq.lock() = Some(seq);
    *state.iface_name.lock() = Some(iface_str);
    state.bound.store(true, Ordering::Release);
    attempt.committed = true;
    Ok(())
}

/// Pop one RX descriptor from the kernel's RX ring. Returns the
/// frame bytes (copied out of UMEM into an owned Vec — TODO map
/// the UMEM frame into user space when narf-mmap matures). The
/// frame slot must be returned to FILL by the caller via
/// [`return_to_fill`].
pub fn try_recv(
    state: &XdpSocketState,
) -> Result<Option<(UmemSlot, alloc::vec::Vec<u8>)>, XdpOpError> {
    let mut g = state.kernel_parts.lock();
    let parts = g.as_mut().ok_or(XdpOpError::RingsNotCreated)?;
    let umem = state
        .umem
        .lock()
        .clone()
        .ok_or(XdpOpError::UmemNotRegistered)?;
    let slot = match parts.rx_cons.try_recv() {
        Ok(Some(v)) => UmemSlot::unpack(v),
        _ => match parts.socket.pop_rx_mmap() {
            Some(s) => s,
            None => return Ok(None),
        },
    };
    let bytes = umem
        .frame_bytes(slot.frame_idx)
        .ok_or(XdpOpError::AccessDenied)?;
    let payload = bytes[..slot.len as usize].to_vec();
    Ok(Some((slot, payload)))
}

/// Re-post a previously-received frame index to FILL so the kernel
/// can refill it on a later RX.
pub fn return_to_fill(state: &XdpSocketState, slot: UmemSlot) -> Result<(), XdpOpError> {
    let mut g = state.kernel_parts.lock();
    let parts = g.as_mut().ok_or(XdpOpError::RingsNotCreated)?;
    parts
        .fill_prod
        .try_send(
            UmemSlot {
                frame_idx: slot.frame_idx,
                len: 0,
            }
            .pack(),
        )
        .map_err(|_| XdpOpError::InvalidArg)
}

/// Push a TX descriptor onto the kernel's TX ring. Userspace must
/// have staged the frame bytes into UMEM at `slot.frame_idx`
/// already (this is the zero-copy contract).
pub fn send_tx(state: &XdpSocketState, slot: UmemSlot) -> Result<(), XdpOpError> {
    let mut g = state.kernel_parts.lock();
    let parts = g.as_mut().ok_or(XdpOpError::RingsNotCreated)?;
    parts
        .tx_prod
        .try_send(slot.pack())
        .map_err(|_| XdpOpError::InvalidArg)
}

/// Drain one COMPLETION entry. Userspace calls this after `send_tx`
/// to reclaim the frame slot once the driver has finished sending.
pub fn try_completion(state: &XdpSocketState) -> Result<Option<UmemSlot>, XdpOpError> {
    let mut g = state.kernel_parts.lock();
    let parts = g.as_mut().ok_or(XdpOpError::RingsNotCreated)?;
    match parts.comp_cons.try_recv() {
        Ok(Some(v)) => Ok(Some(UmemSlot::unpack(v))),
        _ => Ok(parts.socket.pop_comp_mmap()),
    }
}

/// Kick TX processing on `send` / `sendto` / `sendmsg` / `poll` (`xsk_sendmsg`).
/// For native zero-copy queues (`XDP_ZEROCOPY`), triggers the NIC's `kick_xsk`
/// hook; for software-bound queues, drains queued TX descriptors through
/// `narf_net::iface::send_on` and publishes completion descriptors.
pub fn kick_tx(state: &XdpSocketState) -> Result<(), XdpOpError> {
    if !state.bound.load(Ordering::Acquire) {
        return Err(XdpOpError::BindFailed);
    }
    let socket = {
        let g = state.kernel_parts.lock();
        g.as_ref()
            .map(|p| p.socket.clone())
            .ok_or(XdpOpError::RingsNotCreated)?
    };
    let Some(iface) = state.iface_name.lock().clone() else {
        return Err(XdpOpError::BindFailed);
    };
    if state.claim_seq.lock().is_none() {
        let _ = narf_net::nic::with_control(&iface, |c| c.kick_xsk(socket.queue_id() as u16));
        return Ok(());
    }
    let umem = socket.umem().clone();
    while let Some(slot) = socket.pop_tx() {
        if let Some(bytes) = umem.frame_bytes(slot.frame_idx) {
            let len = (slot.len as usize).min(bytes.len());
            let payload = bytes[..len].to_vec();
            drop(bytes);
            if narf_net::iface::send_on(&iface, &payload).is_ok() {
                let _ = socket.push_completion(slot);
            }
        }
    }
    Ok(())
}

/// Serialize `struct xdp_mmap_offsets` (128-byte v2 or 96-byte v1) for
/// `getsockopt(SOL_XDP, XDP_MMAP_OFFSETS)` per `~/git/linux/net/xdp/xsk.c:1803-1828`
/// (`ecd997b0189a`).
pub fn write_mmap_offsets(_state: &XdpSocketState, buf: &mut [u8]) -> Result<usize, XdpOpError> {
    let write_ring_v2 = |dst: &mut [u8]| {
        dst[0..8].copy_from_slice(&(XDP_RING_PRODUCER_OFF as u64).to_ne_bytes());
        dst[8..16].copy_from_slice(&(XDP_RING_CONSUMER_OFF as u64).to_ne_bytes());
        dst[16..24].copy_from_slice(&(XDP_RING_DESC_OFF as u64).to_ne_bytes());
        dst[24..32].copy_from_slice(&(XDP_RING_FLAGS_OFF as u64).to_ne_bytes());
    };
    let write_ring_v1 = |dst: &mut [u8]| {
        dst[0..8].copy_from_slice(&(XDP_RING_PRODUCER_OFF as u64).to_ne_bytes());
        dst[8..16].copy_from_slice(&(XDP_RING_CONSUMER_OFF as u64).to_ne_bytes());
        dst[16..24].copy_from_slice(&(XDP_RING_DESC_OFF as u64).to_ne_bytes());
    };
    if buf.len() >= 128 {
        for i in 0..4 {
            write_ring_v2(&mut buf[i * 32..(i + 1) * 32]);
        }
        Ok(128)
    } else if buf.len() >= 96 {
        for i in 0..4 {
            write_ring_v1(&mut buf[i * 24..(i + 1) * 24]);
        }
        Ok(96)
    } else {
        Err(XdpOpError::InvalidArg)
    }
}

/// Serialize `struct xdp_statistics` (48-byte v2 or 24-byte v1) for
/// `getsockopt(SOL_XDP, XDP_STATISTICS)` per `~/git/linux/net/xdp/xsk.c:1759-1802`
/// (`ecd997b0189a`).
pub fn write_statistics(state: &XdpSocketState, buf: &mut [u8]) -> Result<usize, XdpOpError> {
    let stats = {
        let g = state.kernel_parts.lock();
        g.as_ref()
            .map(|p| p.socket.statistics())
            .unwrap_or_default()
    };
    if buf.len() >= 48 {
        buf[0..8].copy_from_slice(&stats.rx_dropped.to_ne_bytes());
        buf[8..16].copy_from_slice(&stats.rx_invalid_descs.to_ne_bytes());
        buf[16..24].copy_from_slice(&stats.tx_invalid_descs.to_ne_bytes());
        buf[24..32].copy_from_slice(&stats.rx_ring_full.to_ne_bytes());
        buf[32..40].copy_from_slice(&stats.rx_fill_ring_empty_descs.to_ne_bytes());
        buf[40..48].copy_from_slice(&stats.tx_ring_empty_descs.to_ne_bytes());
        Ok(48)
    } else if buf.len() >= 24 {
        buf[0..8].copy_from_slice(&stats.rx_dropped.to_ne_bytes());
        buf[8..16].copy_from_slice(&stats.rx_invalid_descs.to_ne_bytes());
        buf[16..24].copy_from_slice(&stats.tx_invalid_descs.to_ne_bytes());
        Ok(24)
    } else {
        Err(XdpOpError::InvalidArg)
    }
}

/// Resolve `mmap(2)` backing frames for an `AF_XDP` / `AF_BYPASS` socket fd.
pub fn mmap_backing(
    state: &XdpSocketState,
    offset: u64,
    len: usize,
) -> Result<narf_filesystem::MmapBacking, narf_filesystem::FsError> {
    let socket = {
        let g = state.kernel_parts.lock();
        g.as_ref()
            .map(|p| p.socket.clone())
            .ok_or(narf_filesystem::FsError::InvalidPath)?
    };
    if len != 4096 {
        return Err(narf_filesystem::FsError::InvalidPath);
    }
    let phys = socket
        .ring_phys_addr(offset)
        .ok_or(narf_filesystem::FsError::InvalidPath)?;
    socket.enable_mmap_rings();
    Ok(narf_filesystem::MmapBacking {
        frames: alloc::vec![phys],
        lifetime: Some(socket as Arc<dyn narf_filesystem::MmapLifetime>),
        memory_type: narf_memory::MemoryType::WriteBack,
    })
}

/// Close hook — unregister the per-flow claim before the socket
/// goes away so a later socket can claim the same flow.
pub fn close(state: &XdpSocketState) {
    let socket = state.kernel_parts.lock().as_ref().map(|p| p.socket.clone());
    if let Some(socket) = socket.as_ref() {
        socket.close();
    }
    if state.bound.load(Ordering::Acquire) && state.claim_seq.lock().is_none() {
        if let Some(socket) = socket {
            if let Some(name) = socket.bound_iface() {
                let detached = narf_net::nic::with_control(&name, |c| {
                    c.bind_xsk(socket.queue_id() as u16, None)
                })
                .is_ok();
                if detached {
                    narf_net::bypass::classifier::release_native(&name, socket.queue_id());
                }
            }
        }
    }
    if let Some(seq) = state.claim_seq.lock().take() {
        narf_net::bypass::unregister_flow(seq);
    }
}

/// Parse either a standard Linux 16-byte `struct sockaddr_xdp` (14-byte body:
/// `sxdp_flags: u16`, `sxdp_ifindex: u32`, `sxdp_queue_id: u32`,
/// `sxdp_shared_umem_fd: u32`) or NARF's 24-byte `SockAddrXdp` (22-byte body:
/// `flags: u16`, `queue_id: u32`, `iface_name: [u8; 16]`).
pub fn parse_sockaddr_xdp(body: &[u8]) -> Option<SockAddrXdp> {
    if body.len() >= 22 {
        let name_slice = &body[6..22];
        let nul_pos = name_slice
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_slice.len());
        if nul_pos > 0 && name_slice[..nul_pos].iter().all(|&b| b.is_ascii_graphic()) {
            let flags = u16::from_ne_bytes([body[0], body[1]]);
            let queue_id = u32::from_ne_bytes([body[2], body[3], body[4], body[5]]);
            let mut iface_name = [0u8; 16];
            iface_name.copy_from_slice(name_slice);
            return Some(SockAddrXdp {
                flags,
                queue_id,
                iface_name,
            });
        }
    }
    if body.len() >= 14 {
        let flags = u16::from_ne_bytes([body[0], body[1]]);
        let ifindex = u32::from_ne_bytes([body[2], body[3], body[4], body[5]]);
        let queue_id = u32::from_ne_bytes([body[6], body[7], body[8], body[9]]);
        let shared_umem_fd = u32::from_ne_bytes([body[10], body[11], body[12], body[13]]);
        // `XDP_SHARED_UMEM` (flag 1) is not yet supported; non-shared binds ignore `sxdp_shared_umem_fd`.
        if flags & 1 != 0 {
            let _ = shared_umem_fd;
            return None;
        }
        let name = if ifindex == 1 {
            String::from("lo")
        } else {
            narf_net::iface::by_index_in(0, ifindex)?.name
        };
        if name.len() >= 16 {
            return None;
        }
        let mut iface_name = [0u8; 16];
        iface_name[..name.len()].copy_from_slice(name.as_bytes());
        return Some(SockAddrXdp {
            flags,
            queue_id,
            iface_name,
        });
    }
    None
}

/// Parse a 24-, 28-, or 32-byte `struct xdp_umem_reg` body into the typed shape.
pub fn parse_xdp_umem_reg(body: &[u8]) -> Option<XdpUmemReg> {
    if !matches!(body.len(), 24 | 28 | 32) {
        return None;
    }
    let addr = u64::from_ne_bytes([
        body[0], body[1], body[2], body[3], body[4], body[5], body[6], body[7],
    ]);
    let len = u64::from_ne_bytes([
        body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
    ]);
    let chunk_size = u32::from_ne_bytes([body[16], body[17], body[18], body[19]]);
    let headroom = u32::from_ne_bytes([body[20], body[21], body[22], body[23]]);
    let flags = if body.len() >= 28 {
        u32::from_ne_bytes([body[24], body[25], body[26], body[27]])
    } else {
        0
    };
    if body.len() == 32 && body[28..32] != [0, 0, 0, 0] {
        return None;
    }
    Some(XdpUmemReg {
        addr,
        len,
        chunk_size,
        headroom,
        flags,
    })
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    #[derive(Debug)]
    struct FailedRestart;
    impl narf_net::iface::DeviceControl for FailedRestart {
        fn configure(&self, _: &narf_net::iface::DeviceConfig) -> Result<(), i32> {
            Ok(())
        }
        fn nic(&self) -> Option<&dyn narf_net::nic::NicControl> {
            Some(self)
        }
    }
    impl narf_net::nic::NicControl for FailedRestart {
        fn bind_xsk(&self, _: u16, socket: Option<Arc<KernelXdpSocket>>) -> Result<(), i32> {
            if let Some(socket) = socket {
                socket.close();
                Err(5)
            } else {
                Err(16)
            }
        }
    }
    fn send(_: &[u8], _: narf_net::TxMeta) -> Result<(), ()> {
        Ok(())
    }
    struct Interface(String);
    impl Drop for Interface {
        fn drop(&mut self) {
            narf_net::bypass::classifier::release_native(&self.0, 0);
            narf_net::iface::unregister(&self.0);
        }
    }
    fn smoke_xdp_failed_restart_preserves_queue_claim() -> TestResult {
        let iface = Interface(narf_net::iface::register(
            "xsk-fail%d",
            [2, 1, 2, 3, 4, 6],
            send,
        ));
        narf_net::iface::set_device_control(&iface.0, Arc::new(FailedRestart));
        let state = XdpSocketState::new();
        if handle_umem_reg(
            &state,
            &XdpUmemReg {
                len: 4096,
                chunk_size: 2048,
                ..XdpUmemReg::default()
            },
        )
        .is_err()
            || handle_ring_setup(&state, 64).is_err()
        {
            return TestResult::Fail("UMEM setup failed");
        }
        let mut addr = SockAddrXdp {
            flags: 4,
            ..SockAddrXdp::default()
        };
        addr.iface_name[..iface.0.len()].copy_from_slice(iface.0.as_bytes());
        if handle_bind(&state, &addr) != Err(XdpOpError::BindFailed) {
            return TestResult::Fail("failed restart reported success");
        }
        let socket = state.kernel_parts.lock().as_ref().unwrap().socket.clone();
        if !socket.is_closed() || socket.bound_iface().as_deref() != Some(&iface.0) {
            return TestResult::Fail("failed DMA ownership was made reusable");
        }
        close(&state);
        let challenger = KernelXdpSocket::create(state.umem.lock().as_ref().unwrap().clone());
        if narf_net::bypass::classifier::reserve_native(&iface.0, 0, challenger.socket.clone())
            .is_ok()
        {
            return TestResult::Fail("second socket stole a queue before DMA drain");
        }
        // Model the successful recovery fence: only now can another socket own it.
        narf_net::bypass::classifier::release_native(&iface.0, 0);
        if narf_net::bypass::classifier::reserve_native(&iface.0, 0, challenger.socket).is_err() {
            return TestResult::Fail("recovered queue remained unavailable");
        }
        socket.unbind();
        if socket.bind(iface.0.clone(), 0).is_ok() {
            return TestResult::Fail("closed socket was rebound");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "syscall_abi",
        smoke_xdp_failed_restart_preserves_queue_claim
    );
}
