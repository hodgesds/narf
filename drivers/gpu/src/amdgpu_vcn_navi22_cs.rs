//! Client command submission on the Navi22 media rings: VCN 3.0 decode and
//! encode (instance 0) and JPEG 3.0, through the generic `AMDGPU_CS` path
//! (`amdgpu_navi22_cs` routes `AMDGPU_HW_IP_VCN_DEC/ENC/JPEG` here).
//!
//! What runs before a job reaches the ring, as Linux `amdgpu_cs.c` does for
//! these rings:
//!
//! - `no_user_fence`: a job carrying `AMDGPU_CHUNK_ID_FENCE` is refused
//!   (`amdgpu_cs_p2_ib`, "MM engine doesn't support user fences").
//! - decode: `vcn_v3_0_ring_patch_cs_in_place` scans each IB's PACKET0
//!   register/value pairs for a message submission (DATA0, DATA1, then CMD
//!   with value 0) and `vcn_v3_0_dec_msg` checks every message: 8-byte
//!   aligned, at least 4 dwords inside its mapping, the header's size inside
//!   the mapping, and for a create message every buffer index inside the
//!   claimed length and every create buffer inside the mapping. Linux runs
//!   the scan only for instance 1 (to move non-H.264/HEVC/VP9 sessions to
//!   instance 0, `vcn_v3_0_limit_sched`); here every decode job runs on
//!   instance 0 and the checks always run — stricter, never looser.
//! - decode sessions: `amdgpu_uvd_cs_msg`'s handle discipline applied to
//!   the VCN message header (msg[3] type, msg[4] stream handle): a create
//!   claims a free handle (in use: EINVAL, table full: ENOSPC), decode needs
//!   a handle this client created (another client's: EINVAL, unknown:
//!   ENOENT), destroy frees the client's own handle. Linux VCN 3.0 has no
//!   such table; NARF keeps one so one client cannot drive or tear down
//!   another's firmware session. A client's handles are forgotten when its
//!   address space closes (`amdgpu_uvd_free_handles` on postclose).
//! - JPEG: `amdgpu_jpeg_dec_parse_cs` on a kernel copy of each IB (PACKETJ
//!   type 0/3 to the JPEG register window outside the atomic range, or the
//!   NOP), executed from the copy at VMID 0 with data at the client's VMID.
//! - encode: nothing (Linux has no parser for the VCN 3.0 encode rings).
//!
//! The decoder reads messages in place, as Linux does: a client that
//! rewrites its own message after the check only affects its own VMID's
//! memory. The VMID's page tables remain the isolation boundary.
use alloc::vec::Vec;

use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_navi22_submit::{Ib, MediaRing, RingState, VmRef};
use crate::amdgpu_uapi as uapi;
use crate::amdgpu_vcn_navi22::cmd;

/// `RDECODE_MSG_CREATE` (vcn_v3_0.c); decode and destroy are Mesa's
/// `RDECODE_MSG_DECODE` / `RDECODE_MSG_DESTROY` (radeon_vcn_dec.h).
pub const MSG_CREATE: u32 = 0; // linux: RDECODE_MSG_CREATE@vcn
pub const MSG_DECODE: u32 = 1; // linux: n/a (Mesa RDECODE_MSG_DECODE)
pub const MSG_DESTROY: u32 = 2; // linux: n/a (Mesa RDECODE_MSG_DESTROY)
/// `RDECODE_MESSAGE_CREATE`: the buffer-index id of a create buffer.
pub const MESSAGE_CREATE: u32 = 1; // linux: RDECODE_MESSAGE_CREATE@vcn
/// Session handles one card tracks (`AMDGPU_MAX_UVD_HANDLES`).
pub const MAX_SESSIONS: usize = 40; // linux: n/a (AMDGPU_MAX_UVD_HANDLES, amdgpu_uvd.h)
/// Largest decode IB scanned for messages: Mesa's are tens of dwords.
pub const DEC_IB_MAX_DWORDS: u32 = 0x4000; // linux: n/a (NARF bound on the in-place scan)
/// `JPEG_REG_RANGE_START/END`, `JPEG_ATOMIC_RANGE_START/END` (amdgpu_jpeg.h).
const JPEG_REG_START: u32 = 0x4000; // linux: n/a (JPEG_REG_RANGE_START, amdgpu_jpeg.h)
const JPEG_REG_END: u32 = 0x41c2; // linux: n/a (JPEG_REG_RANGE_END, amdgpu_jpeg.h)
const JPEG_ATOMIC_START: u32 = 0x4120; // linux: n/a (JPEG_ATOMIC_RANGE_START, amdgpu_jpeg.h)
const JPEG_ATOMIC_END: u32 = 0x412a; // linux: n/a (JPEG_ATOMIC_RANGE_END, amdgpu_jpeg.h)
/// `CP_PACKETJ_NOP`.
const PACKETJ_NOP: u32 = 0x6000_0000; // linux: CP_PACKETJ_NOP@soc15d
/// Bound on waiting out a media ring's throttle before EBUSY.
const THROTTLE_NS: u64 = 10_000_000_000; // linux: n/a (NARF policy)

/// Why a decode message or JPEG IB was refused (all -EINVAL in Linux).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgError {
    /// "VCN messages must be 8 byte aligned!"
    Misaligned,
    /// "VCN messages must be at least 4 DWORDs!"
    TooShort,
    /// "VCN message header does not fit in BO!"
    HeaderOverflow,
    /// "VCN message has too many buffers!"
    TooManyBuffers,
    /// "VCN message buffer exceeds BO bounds!"
    BufferOutOfBounds,
    /// The message lies in no mapping of the client (`amdgpu_cs_find_mapping`).
    Unmapped,
    /// `vcn_v3_0_limit_sched` with VCN0 harvested: no AV1-capable instance.
    NeedsVcn0,
    /// `amdgpu_jpeg_dec_parse_cs`: a packet outside the allowed set.
    JpegPacket,
}

/// One checked decode message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    /// msg[3]: create / decode / destroy.
    pub kind: u32,
    /// msg[4]: the stream handle.
    pub handle: u32,
}

/// `vcn_v3_0_ring_patch_cs_in_place`: the message addresses one decode IB
/// hands the VCPU (DATA0, DATA1, then CMD with value 0), in order.
pub fn dec_ib_messages(ib: &[u32]) -> Vec<u64> {
    let (data0, data1, command) = (
        cmd::packet0(cmd::INTERNAL_DATA0),
        cmd::packet0(cmd::INTERNAL_DATA1),
        cmd::packet0(cmd::INTERNAL_CMD),
    );
    let (mut lo, mut hi) = (0u32, 0u32);
    let mut out = Vec::new();
    for pair in ib.chunks(2) {
        let (reg, val) = (pair[0], pair.get(1).copied().unwrap_or(0));
        if reg == data0 {
            lo = val;
        } else if reg == data1 {
            hi = val;
        } else if reg == command && val == 0 {
            out.push(u64::from(hi) << 32 | u64::from(lo));
        }
    }
    out
}

/// `vcn_v3_0_dec_msg` for the message at `addr` (hole already stripped),
/// with `avail` bytes of its mapping from `addr` on (`end - addr`) and
/// `read(byte offset from addr)` its dwords. `vcn0_harvested` is
/// `harvest_config & AMDGPU_VCN_HARVEST_VCN0`.
pub fn check_dec_msg(
    addr: u64,
    avail: u64,
    read: impl Fn(u64) -> Option<u32>,
    vcn0_harvested: bool,
) -> Result<Message, MsgError> {
    if addr & 7 != 0 {
        return Err(MsgError::Misaligned);
    }
    if avail < 16 {
        return Err(MsgError::TooShort);
    }
    let word = |dw: u64| read(dw * 4).ok_or(MsgError::Unmapped);
    let size = word(1)?;
    if u64::from(size) > avail {
        return Err(MsgError::HeaderOverflow);
    }
    let kind = word(3)?;
    // msg[4], the stream handle, is read for the session table only; a
    // message too short to carry it reads 0, which the table refuses.
    let handle = if avail >= 20 { word(4)? } else { 0 };
    let message = Message { kind, handle };
    if kind != MSG_CREATE {
        return Ok(message);
    }
    let len_dw = u64::from(size / 4);
    let buffers = u64::from(word(2)?);
    // Linux computes `6 + num_buffers * 4` in 32 bits; 64 here cannot wrap.
    if buffers > len_dw || 6 + buffers * 4 > len_dw {
        return Err(MsgError::TooManyBuffers);
    }
    for i in 0..buffers {
        let entry = 6 + i * 4;
        if word(entry)? != MESSAGE_CREATE {
            continue;
        }
        let (offset, size) = (word(entry + 1)?, word(entry + 2)?);
        let end = u64::from(offset).checked_add(u64::from(size));
        if size < 4 || offset.checked_add(size).is_none() || end.is_none_or(|e| e > avail) {
            return Err(MsgError::BufferOutOfBounds);
        }
        let codec = read(u64::from(offset)).ok_or(MsgError::Unmapped)?;
        // "H264, HEVC and VP9 can run on any instance"; the rest needs VCN0.
        if !matches!(codec, 0x7 | 0x10 | 0x11) && vcn0_harvested {
            return Err(MsgError::NeedsVcn0);
        }
    }
    Ok(message)
}

/// `amdgpu_jpeg_dec_parse_cs`.
pub fn parse_jpeg_ib(ib: &[u32]) -> Result<(), MsgError> {
    let valid = |reg: u32| {
        (JPEG_REG_START..=JPEG_REG_END).contains(&reg)
            && !(JPEG_ATOMIC_START..=JPEG_ATOMIC_END).contains(&reg)
    };
    for pair in ib.chunks(2) {
        let packet = pair[0];
        let (reg, res, cond, kind) = (
            packet & 0x3ffff,
            (packet >> 18) & 0x3f,
            (packet >> 24) & 0xf,
            (packet >> 28) & 0xf,
        );
        if res != 0 {
            return Err(MsgError::JpegPacket);
        }
        match kind {
            0 if cond == 0 && valid(reg) => {}
            3 if cond == 3 && valid(reg) => {}
            6 if packet == PACKETJ_NOP => {}
            _ => return Err(MsgError::JpegPacket),
        }
    }
    Ok(())
}

/// Decode session handles and the client (address-space owner) of each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sessions {
    slots: [(u32, u64); MAX_SESSIONS],
}
/// Why a session operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// Handle 0, a handle in use, another client's handle, or an unknown
    /// message type (-EINVAL).
    Invalid,
    /// No free handle (-ENOSPC).
    Full,
    /// Decode of a handle never created (-ENOENT).
    Unknown,
}
impl Default for Sessions {
    fn default() -> Self {
        Self::new()
    }
}
impl Sessions {
    pub const fn new() -> Self {
        Self {
            slots: [(0, 0); MAX_SESSIONS],
        }
    }
    fn find(&self, handle: u32) -> Option<usize> {
        self.slots.iter().position(|s| s.0 == handle)
    }
    /// Apply one message of client `owner` (`amdgpu_uvd_cs_msg`).
    pub fn apply(&mut self, message: Message, owner: u64) -> Result<(), SessionError> {
        let handle = message.handle;
        if handle == 0 || owner == 0 {
            return Err(SessionError::Invalid);
        }
        match message.kind {
            MSG_CREATE => {
                if self.find(handle).is_some() {
                    return Err(SessionError::Invalid);
                }
                let free = self.find(0).ok_or(SessionError::Full)?;
                self.slots[free] = (handle, owner);
                Ok(())
            }
            MSG_DECODE => match self.find(handle) {
                Some(i) if self.slots[i].1 == owner => Ok(()),
                Some(_) => Err(SessionError::Invalid),
                None => Err(SessionError::Unknown),
            },
            MSG_DESTROY => match self.find(handle) {
                Some(i) if self.slots[i].1 == owner => {
                    self.slots[i] = (0, 0);
                    Ok(())
                }
                Some(_) => Err(SessionError::Invalid),
                // Linux frees whatever matches and succeeds.
                None => Ok(()),
            },
            _ => Err(SessionError::Invalid),
        }
    }
    /// Drop every handle of `owner` (its address space closed).
    pub fn forget(&mut self, owner: u64) {
        for slot in self.slots.iter_mut().filter(|s| s.1 == owner) {
            *slot = (0, 0);
        }
    }
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| s.0 != 0).count()
    }
}

/// `amdgpu_ctx_get_entity` for the media IPs: one entity each
/// (`amdgpu_ctx_num_entities`), the decode ring, encode ring 0 (Linux picks
/// one encode ring per entity, `drm_sched_pick_best`) and the JPEG ring.
pub const fn media_ring(ip_type: u32, ip_instance: u32, ring: u32) -> Option<MediaRing> {
    match (ip_type, ip_instance, ring) {
        (uapi::AMDGPU_HW_IP_VCN_DEC, 0, 0) => Some(MediaRing::Dec),
        (uapi::AMDGPU_HW_IP_VCN_ENC, 0, 0) => Some(MediaRing::Enc(0)),
        (uapi::AMDGPU_HW_IP_VCN_JPEG, 0, 0) => Some(MediaRing::Jpeg),
        _ => None,
    }
}
/// First ticket ring id of the media rings in `amdgpu_navi22_cs`.
pub const FIRST_ID: usize = 4; // linux: n/a (NARF ticket ring id)

#[derive(Debug)]
struct Registered {
    rings: u8,
    reader: crate::amdgpu_vcn_navi22::MediaFenceReader,
    states: [RingState; 4],
    vcn0_harvested: bool,
}
static MEDIA: IrqSafeSpinLock<Option<Registered>> = IrqSafeSpinLock::new(None);
static SESSIONS: IrqSafeSpinLock<Sessions> = IrqSafeSpinLock::new(Sessions::new());

/// The `amdgpu_navi22_cs` ring id of a media IP, when its ring takes jobs.
pub fn ring_id(ip_type: u32, ip_instance: u32, ring: u32) -> Option<usize> {
    let ring = media_ring(ip_type, ip_instance, ring)?;
    let rings = MEDIA.lock().as_ref().map_or(0, |m| m.rings);
    (rings & (1 << ring.index()) != 0).then_some(FIRST_ID + ring.index())
}
/// Media ring `index`'s completed sequence (0 while none is registered).
pub fn completed(index: usize) -> Result<u32, ()> {
    let reader = MEDIA.lock().as_ref().map(|m| m.reader);
    let (Some(reader), Some(&ring)) = (reader, MediaRing::ALL.get(index)) else {
        return Ok(0);
    };
    match reader.completed(ring) {
        Ok(value) => Ok(value.unwrap_or(0)),
        Err(_) => Err(()),
    }
}
/// Rings published to `AMDGPU_INFO` (bit `MediaRing::index()`).
pub fn rings() -> u8 {
    MEDIA.lock().as_ref().map_or(0, |m| m.rings)
}

/// Offer `boot`'s verified media rings to clients (with the owner held,
/// from `amdgpu_navi22_cs::register`). Sessions start empty: a recovery
/// rebuilt the firmware, which lost every session.
pub fn register(boot: &crate::amdgpu_navi22_boot::ColdBoot) {
    use core::fmt::Write;
    *SESSIONS.lock() = Sessions::new();
    let Some((rings, reader)) = boot.client_media() else {
        unregister();
        return;
    };
    // Every client ring is instance 0's, so VCN0 is never harvested here;
    // `vcn_v3_0_limit_sched`'s refusal stays in `check_dec_msg`.
    *MEDIA.lock() = Some(Registered {
        rings,
        reader,
        states: [RingState::new(); 4],
        vcn0_harvested: false,
    });
    crate::amdgpu_info::publish_navi22_media_rings(rings);
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: navi22 media rings for clients {rings:#x} (dec/enc0/enc1/jpeg)"
    );
}
/// Withdraw the media rings (recovery or shutdown).
pub fn unregister() {
    *MEDIA.lock() = None;
    *SESSIONS.lock() = Sessions::new();
    crate::amdgpu_info::publish_navi22_media_rings(0);
}
/// An address space closed: its sessions go with it.
pub fn forget_owner(owner: u64) {
    if owner != 0 {
        SESSIONS.lock().forget(owner);
    }
}

/// `count` dwords at client VA `va`, read by the CPU through the buffer
/// the mapping holds; the range must lie inside that one mapping.
fn read_words(vm: &crate::amdgpu_vm::VmState, va: u64, count: u32) -> Result<Vec<u32>, FsError> {
    let mapping = vm.lookup(va).ok_or(FsError::InvalidData)?;
    let object = vm.mapped_object(va).ok_or(FsError::InvalidData)?;
    let end = va
        .checked_add(u64::from(count) * 4)
        .ok_or(FsError::InvalidData)?;
    if end > mapping.va.saturating_add(mapping.size) {
        return Err(FsError::InvalidData);
    }
    let base = mapping.offset + (va - mapping.va);
    let mut out = Vec::new();
    out.try_reserve_exact(count as usize)
        .map_err(|_| FsError::OutOfMemory)?;
    for k in 0..u64::from(count) {
        out.push(load_u32(&object, base + k * 4).ok_or(FsError::InvalidData)?);
    }
    Ok(out)
}
fn load_u32(object: &crate::amdgpu_gem::GemObject, offset: u64) -> Option<u32> {
    // Buffers are page multiples, so the aligned 8 bytes are inside it.
    let pair = object.load_u64(offset & !7)?;
    Some((pair >> ((offset & 4) * 8)) as u32)
}

/// Check every decode message of a job and collect its session operations.
fn dec_messages(
    vm: &crate::amdgpu_vm::VmState,
    ibs: &[Ib],
    vcn0_harvested: bool,
) -> Result<Vec<Message>, FsError> {
    let mut messages = Vec::new();
    for ib in ibs {
        if ib.dwords > DEC_IB_MAX_DWORDS {
            return Err(FsError::InvalidData);
        }
        for addr in dec_ib_messages(&read_words(vm, ib.va, ib.dwords)?) {
            let addr = crate::amdgpu_vm::strip_hole(addr);
            let mapping = vm.lookup(addr).ok_or(FsError::InvalidData)?;
            let object = vm.mapped_object(addr).ok_or(FsError::InvalidData)?;
            let avail = mapping.va.saturating_add(mapping.size) - addr;
            let base = mapping.offset + (addr - mapping.va);
            let read = |at: u64| {
                (at + 4 <= avail)
                    .then(|| load_u32(&object, base + at))
                    .flatten()
            };
            messages.push(
                check_dec_msg(addr, avail, read, vcn0_harvested)
                    .map_err(|_| FsError::InvalidData)?,
            );
        }
    }
    Ok(messages)
}

/// Apply `messages` of `owner` to the session table all or nothing; the
/// returned table is what to restore if the job never reaches the ring.
fn claim_sessions(messages: &[Message], owner: u64) -> Result<Option<Sessions>, FsError> {
    if messages.is_empty() {
        return Ok(None);
    }
    let mut table = SESSIONS.lock();
    let before = *table;
    let mut next = before;
    for &m in messages {
        next.apply(m, owner).map_err(|e| match e {
            SessionError::Invalid => FsError::InvalidData,
            SessionError::Full => FsError::NoSpace,
            SessionError::Unknown => FsError::NotFound,
        })?;
    }
    *table = next;
    Ok(Some(before))
}

/// Queue a validated `AMDGPU_CS` job on media ring id `id` (from
/// [`ring_id`]) under `vm_ref`, the VM the kernel-queue path chose. Returns
/// the ring's fence sequence.
pub async fn submit(
    vm: &crate::amdgpu_vm::VmState,
    submission: &crate::amdgpu_cs::Submission,
    vm_ref: VmRef,
    id: usize,
    wait: impl Fn(u32) -> bool,
) -> Result<u32, FsError> {
    let ring = *MediaRing::ALL
        .get(id.wrapping_sub(FIRST_ID))
        .ok_or(FsError::InvalidData)?;
    let vcn0_harvested = {
        let media = MEDIA.lock();
        let m = media.as_ref().ok_or(FsError::NoDevice)?;
        if m.rings & (1 << ring.index()) == 0 {
            return Err(FsError::InvalidData);
        }
        m.vcn0_harvested
    };
    // amdgpu_cs_p2_ib: "MM engine doesn't support user fences".
    if submission.user_fence.is_some() {
        return Err(FsError::InvalidData);
    }
    let ibs: Vec<Ib> = submission
        .ibs
        .iter()
        .map(|ib| Ib {
            va: ib.va_start,
            dwords: ib.length_dw,
        })
        .collect();
    crate::amdgpu_navi22_submit::validate_media(vm_ref, &ibs).map_err(|_| FsError::InvalidData)?;
    let mut copies = Vec::new();
    let mut messages = Vec::new();
    match ring {
        MediaRing::Dec => messages = dec_messages(vm, &ibs, vcn0_harvested)?,
        MediaRing::Jpeg => {
            let total: u64 = ibs.iter().map(|ib| u64::from(ib.dwords) * 4).sum();
            if total > crate::amdgpu_vcn_navi22::JPEG_IB_SLOT {
                return Err(FsError::InvalidData);
            }
            for ib in &ibs {
                let words = read_words(vm, ib.va, ib.dwords)?;
                parse_jpeg_ib(&words).map_err(|_| FsError::InvalidData)?;
                copies.push(words);
            }
        }
        MediaRing::Enc(_) => {}
    }
    let restore = claim_sessions(&messages, vm.owner())?;
    let result = queue(ring, vm_ref, submission.ctx_id, &ibs, &copies, &wait).await;
    if result.is_err() {
        if let Some(before) = restore {
            *SESSIONS.lock() = before;
        }
    }
    result
}

async fn queue(
    ring: MediaRing,
    vm_ref: VmRef,
    ctx_id: u32,
    ibs: &[Ib],
    copies: &[Vec<u32>],
    wait: &impl Fn(u32) -> bool,
) -> Result<u32, FsError> {
    use crate::amdgpu_navi22_boot::Error as Boot;
    use crate::amdgpu_vcn_navi22::Error as Vcn;
    let deadline = narf_time::monotonic_ns().saturating_add(THROTTLE_NS);
    loop {
        let throttle = {
            let mut owner = crate::amdgpu_navi22_platform::owner().await;
            let boot = owner.as_mut().ok_or(FsError::NoDevice)?;
            let mut state = {
                let media = MEDIA.lock();
                media.as_ref().ok_or(FsError::NoDevice)?.states[ring.index()]
            };
            let result =
                boot.submit_media(ring, &mut state, vm_ref, u64::from(ctx_id), ibs, copies);
            if result.is_ok() {
                if let Some(m) = MEDIA.lock().as_mut() {
                    m.states[ring.index()] = state;
                }
            }
            match result {
                Ok(seq) => return Ok(seq),
                Err(Boot::Media(Vcn::Busy)) => match boot.media_fences(ring) {
                    Ok((_, throttle)) => throttle,
                    Err(_) => return Err(FsError::NoDevice),
                },
                Err(Boot::Media(Vcn::Invalid | Vcn::Unsupported)) => {
                    return Err(FsError::InvalidData)
                }
                Err(_) => return Err(FsError::NoDevice),
            }
        };
        // Two jobs in flight: wait for the older without the owner.
        while !wait(throttle) {
            if narf_time::monotonic_ns() >= deadline {
                return Err(FsError::Busy);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(100).as_instant()).await;
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_vcn_navi22_cs_tests.rs"]
mod tests;
