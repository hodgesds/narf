//! GSP RPC rings + init handshake — the final live-boot step.
//!
//! Sets up the shared host↔GSP message queues, sends the two init
//! RPCs (SET_SYSTEM_INFO + SET_REGISTRY), and runs the receive loop
//! that drains the CPU sequencer until GSP_INIT_DONE. Grounded against
//! `/usr/src/linux` `rm/r535/gsp.c::{r535_gsp_shared_init,
//! r535_gsp_rpc_*}` + nova-core `gsp/cmdq.rs`.
//!
//! ## Cross-wiring (the easy part to get wrong)
//!
//! Two 256 KiB queues share one DMA region. The read/write pointers
//! are **page indices** stored in the queue headers, and producer/
//! consumer sides are cross-linked between the two queues:
//!
//! - host→GSP cmdq: host advances `cmdq.tx.writePtr`; to know how many
//!   slots GSP has freed it reads `msgq.rx.readPtr`.
//! - GSP→host msgq: GSP advances `msgq.tx.writePtr`; the host advances
//!   `cmdq.rx.readPtr` as it consumes.
//!
//! The pure ring math + header layout are unit-tested; the send /
//! receive / handshake are hardware. The cross-wiring + handshake
//! ordering are the parts most worth confirming against silicon.

#![allow(dead_code)]

use alloc::vec::Vec;

use narf_driver_runtime::MmioRegion;
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::id::DomainId;

use crate::gsp::{
    build_rpc_message, parse_rpc_message, rpc_message_slots, GSP_DOORBELL_OFFSET,
    NV_VGPU_MSG_EVENT_GSP_INIT_DONE, NV_VGPU_MSG_EVENT_GSP_RUN_CPU_SEQUENCER,
    NV_VGPU_MSG_FUNCTION_GSP_SET_SYSTEM_INFO, NV_VGPU_MSG_FUNCTION_SET_REGISTRY,
};
use crate::gsp_args::{
    build_libos_args, build_rmargs, create_pte_array, shared_region_pte_count, GSP_PAGE_SIZE,
    GSP_QUEUE_MSG_COUNT, GSP_QUEUE_SIZE, LIBOS_LOG_SIZE,
};
use crate::gsp_payload::{build_default_registry, build_system_info};
use crate::gsp_seq::{decode_all, execute};

// ── Shared-region geometry (pure) ────────────────────────────────

/// The self-mapping PTE array occupies one page (`shared_region_pte_
/// count() * 8` bytes, page-aligned → 4 KiB for 129 entries).
pub const PTES_SIZE: usize = GSP_PAGE_SIZE as usize;
/// Byte offset of the cmdq within the shared region.
pub const CMDQ_OFFSET: usize = PTES_SIZE;
/// Byte offset of the msgq within the shared region.
pub const MSGQ_OFFSET: usize = PTES_SIZE + GSP_QUEUE_SIZE as usize;
/// Total shared-region size (ptes + two queues).
pub const SHARED_SIZE: usize = PTES_SIZE + 2 * GSP_QUEUE_SIZE as usize;
/// First entry begins one page into a queue (`entryOff`).
pub const ENTRY_OFF: usize = GSP_PAGE_SIZE as usize;
/// Page-index slots per queue.
pub const MSG_COUNT: u32 = GSP_QUEUE_MSG_COUNT;

// Pointer offsets within a queue's header block.
const TX_WRITEPTR: usize = 16; // msgqTxHeader.writePtr
const RX_READPTR: usize = 32; // msgqRxHeader.readPtr (rxHdrOff)

/// Occupied slots: `(wptr + count - rptr) % count`.
pub const fn ring_used(wptr: u32, rptr: u32, count: u32) -> u32 {
    let u = wptr.wrapping_add(count).wrapping_sub(rptr);
    if u >= count {
        u - count
    } else {
        u
    }
}

/// Free slots (one kept empty to disambiguate full from empty).
pub const fn ring_free(wptr: u32, rptr: u32, count: u32) -> u32 {
    count - 1 - ring_used(wptr, rptr, count)
}

/// Build a 32-byte `msgqTxHeader`. Cite `r535_gsp_shared_init`:
/// version 0, size, msgSize = page, msgCount, writePtr 0, flags 1,
/// rxHdrOff = 32, entryOff = page.
pub fn msgq_tx_header(size: u32, msg_count: u32) -> [u8; 32] {
    let mut b = [0u8; 32];
    let p = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    p(&mut b, 0, 0); // version
    p(&mut b, 4, size); // size
    p(&mut b, 8, GSP_PAGE_SIZE as u32); // msgSize
    p(&mut b, 12, msg_count); // msgCount
    p(&mut b, 16, 0); // writePtr
    p(&mut b, 20, 1); // flags
    p(&mut b, 24, RX_READPTR as u32); // rxHdrOff
    p(&mut b, 28, ENTRY_OFF as u32); // entryOff
    b
}

// ── Live rings (hardware) ────────────────────────────────────────

/// Owns the shared RPC region + the rmargs / libos / log buffers for
/// the GSP's lifetime. The caller keeps it alive alongside the
/// [`crate::gsp_image::GspImage`].
pub struct GspRings {
    shared: DmaBuffer,
    _rmargs: DmaBuffer,
    _libos: DmaBuffer,
    _logs: [DmaBuffer; 3],
    /// DMA address of the libos args page (goes to the GSP mailboxes).
    pub libos_dma: u64,
    cmd_seq: u32,
}

impl core::fmt::Debug for GspRings {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GspRings")
            .field("libos_dma", &self.libos_dma)
            .field("cmd_seq", &self.cmd_seq)
            .finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RingError {
    Alloc,
    CmdqFull,
    /// A reply could not be parsed (torn write / bad firmware).
    BadReply,
    /// GSP_INIT_DONE was not seen within the budget.
    InitTimeout,
    /// The CPU sequencer failed.
    Sequencer,
}

impl GspRings {
    /// Allocate + initialise the shared region, rmargs, libos, and log
    /// buffers. Does not touch the GSP yet.
    pub fn init() -> Result<Self, RingError> {
        let mut shared =
            alloc_coherent(SHARED_SIZE, DomainId::DRIVER_0).map_err(|_| RingError::Alloc)?;
        let shared_dma = shared.dma_addr().raw();
        let pte_count = shared_region_pte_count() as usize;
        {
            let buf = shared.as_mut_slice();
            // Self-mapping PTE array: ptes[i] = shared_dma + i*page.
            for i in 0..pte_count {
                let v = shared_dma + (i as u64) * GSP_PAGE_SIZE;
                buf[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
            }
            // cmdq + msgq tx headers (rx readPtr stays 0).
            let hdr = msgq_tx_header(GSP_QUEUE_SIZE as u32, MSG_COUNT);
            buf[CMDQ_OFFSET..CMDQ_OFFSET + 32].copy_from_slice(&hdr);
            buf[MSGQ_OFFSET..MSGQ_OFFSET + 32].copy_from_slice(&hdr);
        }

        // Log buffers (each carries a PTE sub-array at byte +8).
        let mut logs = Vec::new();
        for _ in 0..3 {
            let mut lb = alloc_coherent(LIBOS_LOG_SIZE as usize, DomainId::DRIVER_0)
                .map_err(|_| RingError::Alloc)?;
            let dma = lb.dma_addr().raw();
            {
                let s = lb.as_mut_slice();
                let n = (LIBOS_LOG_SIZE / GSP_PAGE_SIZE) as usize;
                let mut ptes = alloc::vec![0u64; n];
                create_pte_array(&mut ptes, dma, LIBOS_LOG_SIZE);
                for (i, p) in ptes.iter().enumerate() {
                    // PTE array begins at byte +8 in the log buffer.
                    s[8 + i * 8..8 + i * 8 + 8].copy_from_slice(&p.to_le_bytes());
                }
            }
            logs.push(lb);
        }

        // rmargs (GSP_ARGUMENTS_CACHED).
        let mut rmargs = alloc_coherent(GSP_PAGE_SIZE as usize, DomainId::DRIVER_0)
            .map_err(|_| RingError::Alloc)?;
        let rmargs_dma = rmargs.dma_addr().raw();
        rmargs.as_mut_slice().copy_from_slice(&build_rmargs(
            shared_dma,
            shared_region_pte_count(),
            CMDQ_OFFSET as u64,
            MSGQ_OFFSET as u64,
        ));

        // libos args naming the three logs + rmargs.
        let mut libos = alloc_coherent(GSP_PAGE_SIZE as usize, DomainId::DRIVER_0)
            .map_err(|_| RingError::Alloc)?;
        let libos_dma = libos.dma_addr().raw();
        libos.as_mut_slice().copy_from_slice(&build_libos_args(
            logs[0].dma_addr().raw(),
            logs[1].dma_addr().raw(),
            logs[2].dma_addr().raw(),
            rmargs_dma,
        ));

        let logs: [DmaBuffer; 3] = logs.try_into().map_err(|_| RingError::Alloc)?;
        Ok(Self {
            shared,
            _rmargs: rmargs,
            _libos: libos,
            _logs: logs,
            libos_dma,
            cmd_seq: 0,
        })
    }

    /// # Safety
    /// `self.shared` is live DMA memory; `off` is 4-aligned + in range.
    unsafe fn rd_u32(&self, off: usize) -> u32 {
        // SAFETY: caller's responsibility.
        unsafe { core::ptr::read_volatile(self.shared.cpu_mut_ptr::<u8>().add(off) as *const u32) }
    }

    /// # Safety
    /// Same.
    unsafe fn wr_u32(&self, off: usize, v: u32) {
        // SAFETY: caller's responsibility.
        unsafe {
            core::ptr::write_volatile(self.shared.cpu_mut_ptr::<u8>().add(off) as *mut u32, v)
        }
    }

    /// Queue an RPC into the cmdq and ring the doorbell.
    ///
    /// # Safety
    /// `bar0` is the mapped BAR0 window; the GSP owns the consumer side.
    pub unsafe fn send(
        &mut self,
        bar0: &MmioRegion,
        function: u32,
        payload: &[u8],
    ) -> Result<(), RingError> {
        let slots = rpc_message_slots(payload.len());
        // SAFETY: valid DMA memory.
        let (wptr, gsp_consumed) = unsafe {
            (
                self.rd_u32(CMDQ_OFFSET + TX_WRITEPTR),
                self.rd_u32(MSGQ_OFFSET + RX_READPTR),
            )
        };
        if ring_free(wptr, gsp_consumed, MSG_COUNT) < slots {
            return Err(RingError::CmdqFull);
        }
        let entry = CMDQ_OFFSET + ENTRY_OFF + (wptr as usize) * GSP_PAGE_SIZE as usize;
        let seq = self.cmd_seq;
        self.cmd_seq = self.cmd_seq.wrapping_add(1);
        {
            let buf = self.shared.as_mut_slice();
            let end = entry + slots as usize * GSP_PAGE_SIZE as usize;
            build_rpc_message(function, seq, payload, &mut buf[entry..end])
                .map_err(|_| RingError::CmdqFull)?;
        }
        let new_wptr = (wptr + slots) % MSG_COUNT;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: valid DMA memory; then doorbell.
        unsafe {
            self.wr_u32(CMDQ_OFFSET + TX_WRITEPTR, new_wptr);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            bar0.write32(GSP_DOORBELL_OFFSET, 0);
        }
        Ok(())
    }

    /// Poll the msgq for one message; returns its `(function, payload)`
    /// or `None` if none arrived within `budget`.
    ///
    /// # Safety
    /// `bar0`/`self.shared` live; GSP owns the producer side.
    pub unsafe fn recv(&mut self, budget: u32) -> Option<(u32, Vec<u8>)> {
        // SAFETY: valid DMA memory.
        let host_rptr = unsafe { self.rd_u32(CMDQ_OFFSET + RX_READPTR) };
        let mut used = 0;
        for _ in 0..budget {
            // SAFETY: valid DMA memory.
            used = ring_used(
                unsafe { self.rd_u32(MSGQ_OFFSET + TX_WRITEPTR) },
                host_rptr,
                MSG_COUNT,
            );
            if used != 0 {
                break;
            }
            core::hint::spin_loop();
        }
        if used == 0 {
            return None;
        }
        let entry = MSGQ_OFFSET + ENTRY_OFF + (host_rptr as usize) * GSP_PAGE_SIZE as usize;
        let (hdr, payload, elem_count) = {
            let buf = self.shared.as_slice();
            let slice = &buf[entry..];
            let (hdr, payload) = parse_rpc_message(slice).ok()?;
            let elem_count =
                u32::from_le_bytes([slice[40], slice[41], slice[42], slice[43]]).max(1);
            (hdr, payload.to_vec(), elem_count)
        };
        let new_rptr = (host_rptr + elem_count) % MSG_COUNT;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: valid DMA memory.
        unsafe { self.wr_u32(CMDQ_OFFSET + RX_READPTR, new_rptr) };
        Some((hdr.function, payload))
    }

    /// The full init handshake: send SET_SYSTEM_INFO + SET_REGISTRY,
    /// then drain the msgq (running any CPU sequencer) until
    /// GSP_INIT_DONE. `sysinfo` is the [`build_system_info`] payload.
    ///
    /// # Safety
    /// `bar0` live; the GSP has been started (booter ran, RISC-V
    /// active); caller owns the GSP + SEC2 Falcons.
    pub unsafe fn run_handshake(
        &mut self,
        bar0: &MmioRegion,
        sysinfo: &[u8],
        app_version: u32,
        budget: u32,
    ) -> Result<(), RingError> {
        let registry = build_default_registry();
        // SAFETY: caller's responsibility.
        unsafe {
            self.send(bar0, NV_VGPU_MSG_FUNCTION_GSP_SET_SYSTEM_INFO, sysinfo)?;
            self.send(bar0, NV_VGPU_MSG_FUNCTION_SET_REGISTRY, &registry)?;
        }
        let libos_dma = self.libos_dma;
        for _ in 0..budget {
            // SAFETY: caller's responsibility.
            let Some((function, payload)) = (unsafe { self.recv(budget) }) else {
                continue;
            };
            if function == NV_VGPU_MSG_EVENT_GSP_INIT_DONE {
                return Ok(());
            }
            if function == NV_VGPU_MSG_EVENT_GSP_RUN_CPU_SEQUENCER {
                // payload: bufferSizeDWord, cmdIndex, regSaveArea[8], cmds[].
                if payload.len() < 0x28 {
                    return Err(RingError::BadReply);
                }
                let cmd_dwords =
                    u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let cmds =
                    decode_all(&payload[0x28..], cmd_dwords).map_err(|_| RingError::Sequencer)?;
                for cmd in &cmds {
                    // SAFETY: caller owns the Falcons + BAR0.
                    unsafe { execute(cmd, bar0, libos_dma, app_version, budget) }
                        .map_err(|_| RingError::Sequencer)?;
                }
            }
            // Other events are intermediate; keep draining.
        }
        Err(RingError::InitTimeout)
    }
}

/// Build the SET_SYSTEM_INFO payload for a card. Thin wrapper over
/// [`build_system_info`] so the orchestration has one call site.
#[allow(clippy::too_many_arguments)]
pub fn system_info_payload(
    bar0_phys: u64,
    bar1_phys: u64,
    bar2_phys: u64,
    pci_bus: u8,
    pci_devfn: u8,
    max_user_va: u64,
) -> [u8; crate::gsp_payload::GSP_SYSTEM_INFO_SIZE] {
    build_system_info(
        bar0_phys,
        bar1_phys,
        bar2_phys,
        pci_bus,
        pci_devfn,
        max_user_va,
    )
}
