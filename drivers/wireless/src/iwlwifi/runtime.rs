//! Owned DMA transport for AX210/Bz/Sc. Buffers belong to the transport
//! until a matching completion, or until bus mastering is stopped.

use alloc::{vec, vec::Vec};
use core::sync::atomic::{compiler_fence, Ordering};
use narf_io::DmaBuffer;
use narf_lib::id::DomainId;

use super::{boot_context, rx, rx_rfh, transport::IwlMmio, tx_gen2, ParsedUcode};

pub const RX_DEPTH: usize = 512;
pub const COMMAND_DEPTH: usize = 128;
pub const RX_BUFFER_BYTES: usize = 4096;

/// Order coherent DMA against the peripheral, including on aarch64
/// where an inner-shareable CPU atomic barrier alone is insufficient.
pub fn dma_barrier() {
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "aarch64")]
    // SAFETY: an outer-shareable barrier changes no memory or registers.
    unsafe {
        core::arch::asm!("dmb osh", options(nostack, preserves_flags))
    };
    #[cfg(not(target_arch = "aarch64"))]
    core::sync::atomic::fence(Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
}

pub(super) fn dma_alloc(size: usize) -> Result<DmaBuffer, &'static str> {
    narf_io::alloc_coherent(size, DomainId::DRIVER_0).map_err(|_| "iwlwifi DMA allocation failed")
}

pub(super) fn write_dma(buffer: &DmaBuffer, offset: usize, bytes: &[u8]) {
    assert!(offset <= buffer.len() && bytes.len() <= buffer.len() - offset);
    // SAFETY: bounds checked above; caller owns the host write side and
    // publishes only after the copy. The source is ordinary host memory.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.as_mut_ptr().add(offset), bytes.len())
    };
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub header: rx::RxPacketHeader,
    pub payload: Vec<u8>,
}

/// Extract notifications/responses without treating padding or a short
/// packet as a valid payload. len_n_flags excludes its own four bytes.
pub fn packets(bytes: &[u8]) -> Result<Vec<Packet>, &'static str> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset + 8 <= bytes.len() {
        let header = rx::parse_rx_header(&bytes[offset..]).ok_or("short RX header")?;
        if header.len_n_flags == 0x5555_0000 || header.len_n_flags == 0 {
            break;
        }
        let length = (header.len_n_flags & 0x3fff) as usize;
        if length < 4 || length + 4 > bytes.len() - offset {
            return Err("invalid RX packet length");
        }
        result.push(Packet {
            header,
            payload: bytes[offset + 8..offset + 4 + length].to_vec(),
        });
        offset += (length + 4).next_multiple_of(64);
    }
    Ok(result)
}

#[derive(Debug)]
pub struct ReceiveQueue {
    free: DmaBuffer,
    used: DmaBuffer,
    status: DmaBuffer,
    buffers: Vec<DmaBuffer>,
    tracker: rx_rfh::CompletionTracker<RX_DEPTH>,
    format: rx_rfh::CompletionFormat,
    read: usize,
    write: usize,
    advertised: usize,
    tags: [u16; RX_DEPTH],
}

impl ReceiveQueue {
    pub fn new(format: rx_rfh::CompletionFormat) -> Result<Self, &'static str> {
        let mut queue = Self {
            free: dma_alloc(RX_DEPTH * 16)?,
            used: dma_alloc(RX_DEPTH * format.size())?,
            status: dma_alloc(2)?,
            buffers: Vec::with_capacity(RX_DEPTH - 1),
            tracker: rx_rfh::CompletionTracker::new(format),
            format,
            read: 0,
            write: 0,
            advertised: 0,
            tags: [0; RX_DEPTH],
        };
        // One descriptor remains empty to distinguish full from empty.
        for _ in 0..RX_DEPTH - 1 {
            queue.buffers.push(dma_alloc(RX_BUFFER_BYTES)?);
        }
        for index in 0..queue.buffers.len() {
            queue.restock(index);
        }
        Ok(queue)
    }

    fn restock(&mut self, index: usize) {
        let tag = (index + 1) as u16;
        let mut descriptor = [0; 16];
        boot_context::put16(&mut descriptor, 0, tag);
        boot_context::put64(&mut descriptor, 8, self.buffers[index].dma_addr().raw());
        // Clear the previous packet so padding cannot replay stale data.
        // SAFETY: this buffer has returned to the host, or is not yet
        // published. No device can own it until the next doorbell.
        unsafe { core::ptr::write_bytes(self.buffers[index].as_mut_ptr(), 0, RX_BUFFER_BYTES) };
        write_dma(&self.free, self.write * 16, &descriptor);
        self.tags[self.write] = tag;
        self.write = (self.write + 1) & (RX_DEPTH - 1);
    }

    pub fn publish(&mut self, mmio: &mut impl IwlMmio) -> Result<(), &'static str> {
        let next = self.write & !7;
        if next == self.advertised {
            return Ok(());
        }
        while self.advertised != next {
            self.tracker
                .post(self.tags[self.advertised])
                .map_err(|_| "double-posted RX buffer")?;
            self.advertised = (self.advertised + 1) & (RX_DEPTH - 1);
        }
        dma_barrier();
        let (register, value) = self.format.doorbell(0, next as u16);
        mmio.write(register, value);
        Ok(())
    }

    /// Bounded batch; take a single write-back snapshot and validate
    /// every tag before forming a packet slice. Repost only after the
    /// batch, so a duplicate completion cannot reclaim the same buffer.
    pub fn drain(&mut self, mmio: &mut impl IwlMmio) -> Result<Vec<Packet>, &'static str> {
        // SAFETY: status is aligned coherent memory owned for the whole
        // device lifetime, and hardware updates this u16 atomically.
        let closed = u16::from_le(unsafe {
            core::ptr::read_volatile(self.status.as_mut_ptr().cast::<u16>())
        }) as usize;
        dma_barrier();
        let closed = closed & (RX_DEPTH - 1);
        let mut output = Vec::new();
        let mut returned = Vec::new();
        while self.read != closed && returned.len() < 64 {
            let mut descriptor = [0u8; 32];
            for (i, byte) in descriptor[..self.format.size()].iter_mut().enumerate() {
                // SAFETY: validated ring slot; DMA completed before the
                // status snapshot. Volatile snapshot avoids torn reuse.
                *byte = unsafe {
                    core::ptr::read_volatile(
                        self.used
                            .as_mut_ptr()
                            .add(self.read * self.format.size() + i),
                    )
                };
            }
            let buffer = self
                .tracker
                .complete(&descriptor[..self.format.size()])
                .map_err(|_| "invalid RFH completion")?;
            if buffer.buffer_index >= self.buffers.len() {
                return Err("unallocated RX buffer tag");
            }
            if !buffer.discard {
                // Complete packet copies precede any restock/doorbell.
                output.extend(packets(
                    &self.buffers[buffer.buffer_index].as_slice()[..RX_BUFFER_BYTES],
                )?);
            }
            returned.push(buffer.buffer_index);
            self.read = (self.read + 1) & (RX_DEPTH - 1);
        }
        for index in returned {
            self.restock(index);
        }
        self.publish(mmio)?;
        Ok(output)
    }
}

#[derive(Debug)]
struct PendingCommand {
    _dma: DmaBuffer,
    sequence: u16,
    command: u8,
    group: u8,
}

impl Drop for PendingCommand {
    fn drop(&mut self) {
        // This runs only after matching completion or DMA shutdown.
        // SEC_KEY payloads must not remain in recycled coherent pages.
        for offset in 0..self._dma.len() {
            // SAFETY: the owned allocation is live and no longer device-owned.
            unsafe {
                core::ptr::write_volatile(self._dma.as_mut_ptr().add(offset), 0);
            }
        }
    }
}

#[derive(Debug)]
pub struct CommandQueue {
    descriptors: DmaBuffer,
    pending: Vec<Option<PendingCommand>>,
    // The hardware pointer is 16 bits; the response sequence carries
    // only its low eight bits. DMA slots wrap at the allocated depth.
    write: u16,
    outstanding: usize,
}

impl CommandQueue {
    pub fn new() -> Result<Self, &'static str> {
        Ok(Self {
            descriptors: dma_alloc(COMMAND_DEPTH * 256)?,
            pending: (0..COMMAND_DEPTH).map(|_| None).collect(),
            write: 0,
            outstanding: 0,
        })
    }

    pub fn send(
        &mut self,
        mmio: &mut impl IwlMmio,
        group: u8,
        command: u8,
        version: u8,
        payload: &[u8],
    ) -> Result<u16, &'static str> {
        let slot = self.write as usize & (COMMAND_DEPTH - 1);
        if self.outstanding >= COMMAND_DEPTH - 1 || self.pending[slot].is_some() {
            return Err("command queue full");
        }
        if payload.len() > u16::MAX as usize - 8 {
            return Err("command too large");
        }
        let sequence = self.write & 0xff; // command queue is queue 0
        let mut bytes = zeroize::Zeroizing::new(vec![0; payload.len() + 8]);
        bytes[0] = command;
        bytes[1] = group;
        boot_context::put16(&mut bytes, 2, sequence);
        boot_context::put16(&mut bytes, 4, payload.len() as u16);
        bytes[7] = version;
        bytes[8..].copy_from_slice(payload);
        let dma = dma_alloc(bytes.len())?;
        write_dma(&dma, 0, &bytes);
        let mut tfd = tx_gen2::TfhTfd::default();
        let first = bytes.len().min(20);
        tfd.push_tb(dma.dma_addr().raw(), first as u16)
            .map_err(|_| "invalid command TB0")?;
        if bytes.len() > first {
            tfd.push_tb(
                dma.dma_addr().raw() + first as u64,
                (bytes.len() - first) as u16,
            )
            .map_err(|_| "invalid command TB1")?;
        }
        // SAFETY: TfhTfd is a fully initialized packed wire struct,
        // exactly 256 bytes, without padding or uninitialized fields.
        let wire = unsafe {
            core::slice::from_raw_parts((&tfd as *const tx_gen2::TfhTfd).cast::<u8>(), 256)
        };
        write_dma(&self.descriptors, slot * 256, wire);
        self.pending[slot] = Some(PendingCommand {
            _dma: dma,
            sequence,
            command,
            group,
        });
        self.outstanding += 1;
        self.write = self.write.wrapping_add(1);
        dma_barrier();
        mmio.write(tx_gen2::HBUS_TARG_WRPTR, self.write as u32);
        Ok(sequence)
    }

    /// Reclaim only the command identified by a firmware response.
    /// Unsolicited notifications (sequence bit 15) never free TX memory.
    pub fn complete(&mut self, header: rx::RxPacketHeader) -> Result<bool, &'static str> {
        if header.sequence & 0x8000 != 0 {
            return Ok(false);
        }
        if header.sequence & 0x7f00 != 0 {
            return Ok(false);
        }
        let slot = header.sequence as usize & (COMMAND_DEPTH - 1);
        let Some(pending) = self.pending[slot].as_ref() else {
            return Err("response for empty command slot");
        };
        if pending.sequence != header.sequence
            || pending.command != header.cmd
            || !(pending.group == header.group_id || (pending.group == 1 && header.group_id == 0))
        {
            return Err("command response identity mismatch");
        }
        self.pending[slot] = None;
        self.outstanding -= 1;
        Ok(true)
    }
}

/// All allocations that firmware can reach through the boot context.
/// Retain paging, info/scratch, and rings until the device is stopped.
#[derive(Debug)]
pub struct BootImage {
    pub context: DmaBuffer,
    pub scratch: DmaBuffer,
    pub iml: DmaBuffer,
    pub iml_len: usize,
    _info: DmaBuffer,
    _sections: Vec<DmaBuffer>,
}

impl BootImage {
    pub fn set_pnvm(&mut self, chunks: &[&[u8]], fragmented: bool) -> Result<(), &'static str> {
        if chunks.is_empty() || chunks.len() > 64 {
            return Err("invalid PNVM chunks");
        }
        let total = chunks
            .iter()
            .try_fold(0u32, |sum, chunk| sum.checked_add(chunk.len() as u32))
            .ok_or("PNVM size overflow")?;
        let address;
        if fragmented {
            let mut addresses = [0; 64 * 8];
            for (i, chunk) in chunks.iter().enumerate() {
                let buffer = dma_alloc(chunk.len())?;
                write_dma(&buffer, 0, chunk);
                boot_context::put64(&mut addresses, i * 8, buffer.dma_addr().raw());
                self._sections.push(buffer);
            }
            let descriptors = dma_alloc(addresses.len())?;
            write_dma(&descriptors, 0, &addresses);
            address = descriptors.dma_addr().raw();
            self._sections.push(descriptors);
        } else {
            if chunks.len() != 2 {
                return Err("unfragmented PNVM requires two chunks");
            }
            let buffer = dma_alloc(total as usize)?;
            let mut offset = 0;
            for chunk in chunks {
                write_dma(&buffer, offset, chunk);
                offset += chunk.len();
            }
            address = buffer.dma_addr().raw();
            self._sections.push(buffer);
        }
        let mut config = [0; 16];
        boot_context::put64(&mut config, 0, address);
        boot_context::put32(&mut config, 8, total);
        write_dma(&self.scratch, 16, &config);
        dma_barrier();
        Ok(())
    }

    pub fn new(
        parsed: &ParsedUcode<'_>,
        hw_rev: u16,
        rx: &ReceiveQueue,
        command: &CommandQueue,
    ) -> Result<Self, &'static str> {
        let iml_bytes = parsed.api.iml.ok_or("firmware has no IML TLV")?;
        let map = boot_context::section_map(parsed)?;
        let iml = dma_alloc(iml_bytes.len())?;
        write_dma(&iml, 0, iml_bytes);
        let scratch = dma_alloc(boot_context::SCRATCH_BYTES)?;
        let info = dma_alloc(4096)?;
        let context = dma_alloc(boot_context::CONTEXT_BYTES)?;
        let mut scratch_bytes = boot_context::scratch(hw_rev, rx.free.dma_addr().raw());
        let mut sections = Vec::with_capacity(map.len());
        for (index, offset) in map {
            let payload = parsed.rt_sections[index].payload;
            let buffer = dma_alloc(payload.len())?;
            write_dma(&buffer, 0, payload);
            boot_context::put64(&mut scratch_bytes, offset, buffer.dma_addr().raw());
            sections.push(buffer);
        }
        write_dma(&scratch, 0, &scratch_bytes);
        let queues = boot_context::BootQueues {
            free: rx.free.dma_addr().raw(),
            used: rx.used.dma_addr().raw(),
            status: rx.status.dma_addr().raw(),
            command: command.descriptors.dma_addr().raw(),
            rx_depth: RX_DEPTH as u16,
            command_depth: COMMAND_DEPTH as u16,
        };
        write_dma(
            &context,
            0,
            &boot_context::context(queues, info.dma_addr().raw(), scratch.dma_addr().raw())?,
        );
        Ok(Self {
            context,
            scratch,
            iml,
            iml_len: iml_bytes.len(),
            _info: info,
            _sections: sections,
        })
    }
}

#[derive(Debug)]
struct Resources {
    rx: ReceiveQueue,
    commands: CommandQueue,
    boot: BootImage,
    data: Vec<super::data_queue::DataQueue>,
}

/// Serialized by an async mutex in the interface. Command waits drive
/// RX themselves; they never depend on a pump blocked on that mutex.
pub struct Hardware {
    mmio: super::IwlMmioImpl,
    resources: core::mem::ManuallyDrop<Resources>,
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    format: rx_rfh::CompletionFormat,
    interrupts: Option<super::iwl_msix::Interrupts>,
    pub notifications: alloc::collections::VecDeque<Packet>,
    responses: alloc::collections::VecDeque<Packet>,
    tx_completed: alloc::collections::VecDeque<(u16, u16, bool)>,
    versions: Vec<u8>,
    armed: bool,
    failed: bool,
}

impl core::fmt::Debug for Hardware {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IwlHardware")
            .field("armed", &self.armed)
            .field("failed", &self.failed)
            .finish()
    }
}

impl Hardware {
    pub fn new(
        device: narf_bus::BusDevice,
        cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        region: narf_bus::MmioRegion,
        parsed: &ParsedUcode<'_>,
        format: rx_rfh::CompletionFormat,
    ) -> Result<Self, &'static str> {
        // Stop inherited DMA before allocating buffers or rejecting an
        // unsupported firmware profile. Early initialization failures must
        // not leave a previous boot's bus-master state running.
        narf_bus::pci::clear_command(&cap, &device, narf_bus::pci::cmd::BUS_MASTER)
            .map_err(|_| "cannot disable inherited Wi-Fi DMA")?;
        let mut mmio = super::IwlMmioImpl(region);
        let rx = ReceiveQueue::new(format)?;
        let commands = CommandQueue::new()?;
        let boot = BootImage::new(
            parsed,
            mmio.read(super::regs::CSR_HW_REV) as u16,
            &rx,
            &commands,
        )?;
        Ok(Self {
            mmio,
            resources: core::mem::ManuallyDrop::new(Resources {
                rx,
                commands,
                boot,
                data: Vec::new(),
            }),
            device,
            cap,
            format,
            interrupts: None,
            notifications: alloc::collections::VecDeque::new(),
            responses: alloc::collections::VecDeque::new(),
            tx_completed: alloc::collections::VecDeque::new(),
            versions: parsed.api.commands.to_vec(),
            armed: false,
            failed: false,
        })
    }

    pub fn version(&self, group: u8, command: u8) -> Option<(u8, u8)> {
        self.versions
            .chunks_exact(4)
            .find(|entry| entry[0] == command && entry[1] == group)
            .map(|entry| (entry[2], entry[3]))
    }

    pub fn has_pending_rx(&self) -> bool {
        // SAFETY: coherent status allocation remains live until DMA stop;
        // hardware publishes this aligned u16 after completion descriptors.
        let closed = u16::from_le(unsafe {
            core::ptr::read_volatile(self.resources.rx.status.as_mut_ptr().cast::<u16>())
        }) as usize
            & (RX_DEPTH - 1);
        self.resources.rx.read != closed
    }

    pub fn irq_vector(&self) -> Option<u8> {
        self.interrupts
            .as_ref()
            .map(super::iwl_msix::Interrupts::vector)
    }

    /// Capture the IRQ count before polling completions, including when
    /// the command caller owns the device mutex across this wait.
    pub fn activity(&self) -> super::iwl_msix::Activity {
        super::iwl_msix::Activity::new(self.irq_vector(), 10)
    }

    async fn sample_delay() {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(1_000_000)).await;
    }

    async fn poll_register(
        &mut self,
        register: u32,
        mask: u32,
        expected: u32,
        ms: u64,
    ) -> Result<(), &'static str> {
        let deadline = narf_time::Deadline::after_ms(ms);
        loop {
            let value = self.mmio.read(register);
            if value == u32::MAX {
                return Err("Wi-Fi device disappeared");
            }
            if value & mask == expected {
                return Ok(());
            }
            if deadline.expired() {
                return Err("Wi-Fi register timeout");
            }
            Self::sample_delay().await;
        }
    }

    pub async fn start(&mut self, parsed: &ParsedUcode<'_>) -> Result<[u8; 6], &'static str> {
        use super::regs::*;
        use narf_bus::pci::{self, cmd};
        pci::clear_command(&self.cap, &self.device, cmd::BUS_MASTER)
            .map_err(|_| "cannot disable stale Wi-Fi DMA")?;
        pci::set_command(&self.cap, &self.device, cmd::MEM_SPACE | cmd::INTX_DISABLE)
            .map_err(|_| "cannot enable Wi-Fi PCI memory access")?;
        let control = self.mmio.read(CSR_HW_IF_CONFIG_REG);
        self.mmio.write(CSR_HW_IF_CONFIG_REG, control | (1 << 22));
        self.poll_register(CSR_HW_IF_CONFIG_REG, 1 << 22, 1 << 22, 50)
            .await?;
        self.mmio.write(0x88, 1 << 5); // OS_ALIVE mailbox
                                       // Reset before publishing DMA addresses, then retake ownership.
                                       // Bz reset lives in GP_CNTRL; older devices use CSR_RESET.
        let (reset, bit, delay_ms) = if self.format == rx_rfh::CompletionFormat::Bz {
            (CSR_GP_CNTRL, 1 << 31, 20)
        } else {
            (CSR_RESET, 1 << 7, 6)
        };
        let value = self.mmio.read(reset);
        self.mmio.write(reset, value | bit);
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(delay_ms * 1_000_000)).await;
        let control = self.mmio.read(CSR_HW_IF_CONFIG_REG);
        self.mmio.write(CSR_HW_IF_CONFIG_REG, control | (1 << 22));
        self.poll_register(CSR_HW_IF_CONFIG_REG, 1 << 22, 1 << 22, 50)
            .await?;
        self.mmio.write(0x88, 1 << 5);
        self.mmio.write(CSR_INT_MASK, 0);
        self.mmio.write(CSR_INT, u32::MAX);
        // APM workarounds: disable L0s RX, maximize FH wait threshold,
        // and permit the management bus to wake the PCIe link.
        for (register, bits) in [
            (0x100, 1 << 23),
            (0x240, 0xffff0000),
            (CSR_HW_IF_CONFIG_REG, 1 << 19),
        ] {
            let value = self.mmio.read(register);
            self.mmio.write(register, value | bits);
        }

        // Bz moved reset and clock handshakes into GP_CNTRL. Keep the
        // MAC access request asserted while the transport runs.
        let (request, ready) = if self.format == rx_rfh::CompletionFormat::Bz {
            (1 << 6 | 1 << 21, 1 << 20)
        } else {
            (1 << 2 | 1 << 3, 1)
        };
        let gp = self.mmio.read(CSR_GP_CNTRL);
        self.mmio.write(CSR_GP_CNTRL, gp | request);
        self.poll_register(CSR_GP_CNTRL, ready, ready, 25).await?;

        if self.interrupts.is_none() {
            self.interrupts = Some(super::iwl_msix::Interrupts::new(
                &self.cap,
                &self.device,
                self.mmio.0,
            )?);
        }
        // AX210/Bz/Sc use the UMAC interrupt selector, with peripherals
        // relocated by 0x300000. Reset clears the selector/IVARs,
        // so reprogram on every start while retaining the owned vector.
        super::transport::prph_write_ax210(&mut self.mmio, 0xD05C00, 1 << 25);
        self.interrupts
            .as_mut()
            .unwrap()
            .enable(self.format == rx_rfh::CompletionFormat::Bz)?;

        let boot = &self.resources.boot;
        let regions = super::transport::Gen3BootRegions {
            ctxt_info_phys: boot.context.dma_addr().raw(),
            iml_phys: boot.iml.dma_addr().raw(),
            iml_size: boot.iml_len as u32,
        };
        pci::set_command(&self.cap, &self.device, cmd::BUS_MASTER)
            .map_err(|_| "cannot enable Wi-Fi PCI bus mastering")?;
        self.armed = true;
        self.resources.rx.publish(&mut self.mmio)?;
        dma_barrier();
        super::transport::boot_gen3(&mut self.mmio, &regions);
        let alive = self.wait_notification(0, 1, 2000).await?;
        let alive_version = self
            .version(0, 1)
            .or_else(|| self.version(1, 1))
            .map(|v| v.1);
        let expected = match alive_version {
            Some(7) => 144,
            Some(8) => 152,
            _ => return Err("unsupported ALIVE notification version"),
        };
        if alive.payload.len() != expected || alive.payload[..2] != 0xcafeu16.to_le_bytes() {
            return Err("invalid firmware ALIVE notification");
        }
        let sku = core::array::from_fn(|i| {
            u32::from_le_bytes(alive.payload[116 + i * 4..120 + i * 4].try_into().unwrap())
        });
        if sku != [0; 3] {
            let pnvm = parsed.api.pnvm.ok_or("firmware needs external PNVM")?;
            let hw = self.mmio.read(CSR_HW_REV);
            let rf = self.mmio.read(0x9c);
            let chunks = super::pnvm::select(
                pnvm,
                sku,
                ((hw >> 4) & 0xfff) as u16,
                ((rf >> 12) & 0xfff) as u16,
            )?;
            self.resources
                .boot
                .set_pnvm(&chunks, parsed.api.has_capability(32))?;
            // Bz and Sc have a 0x300000 UMAC peripheral offset.
            let offset = 0x300000;
            super::transport::prph_write_ax210(&mut self.mmio, 0xA05C04 + offset, 1 << 20);
            let complete = self.wait_notification(0x0c, 0xfe, 250).await?;
            if complete.payload.len() < 4 || complete.payload[..4] != [0; 4] {
                return Err("PNVM initialization failed");
            }
        }
        self.command(2, 3, &4u32.to_le_bytes()).await?; // INIT_EXTENDED_CFG: PHY follows
        let version = self.version(1, 0x6a).map(|v| v.0).unwrap_or(1);
        let size = match version {
            1 => 12,
            3 => 28,
            _ => return Err("unsupported PHY configuration version"),
        };
        let mut phy = vec![0; size];
        boot_context::put32(&mut phy, 0, parsed.api.phy_config);
        boot_context::put32(&mut phy, 4, parsed.api.calibration[0]);
        boot_context::put32(&mut phy, 8, parsed.api.calibration[1]);
        self.command(1, 0x6a, &phy).await?;
        self.wait_notification(0, 4, 2000).await?;
        let base = if self.format == rx_rfh::CompletionFormat::Bz {
            0x30
        } else {
            0x380
        };
        for delta in [8, 0] {
            let a = self.mmio.read(base + delta);
            let b = self.mmio.read(base + delta + 4);
            let mac = [
                (a >> 24) as u8,
                (a >> 16) as u8,
                (a >> 8) as u8,
                a as u8,
                (b >> 8) as u8,
                b as u8,
            ];
            if mac[0] & 1 == 0 && mac != [0; 6] {
                return Ok(mac);
            }
        }
        Err("Wi-Fi hardware has no valid MAC address")
    }

    pub fn poll(&mut self) -> Result<(), &'static str> {
        let result = self.poll_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn poll_inner(&mut self) -> Result<(), &'static str> {
        if self.failed {
            return Err("Wi-Fi transport failed");
        }
        if let Some(interrupts) = &self.interrupts {
            let causes = interrupts.take_causes();
            if causes.fatal(self.format == rx_rfh::CompletionFormat::Bz) {
                return Err("Wi-Fi firmware/device error");
            }
            if causes.hw & (1 << 7) != 0
                && self.mmio.read(super::regs::CSR_GP_CNTRL) & (1 << 27) == 0
            {
                return Err("Wi-Fi hardware radio disabled");
            }
        }
        for packet in self.resources.rx.drain(&mut self.mmio)? {
            if packet.header.group_id == 0 && packet.header.cmd == 0xc5 {
                if !matches!(self.version(0, 0xc5).map(|v| v.1), Some(4 | 6 | 7)) {
                    return Err("unsupported compressed BA notification");
                }
                super::aggregation::complete_tx_ba(&mut self.resources.data, &packet.payload)?;
                continue;
            }
            if packet.header.group_id == 0 && packet.header.cmd == 0x1c {
                if packet.payload.len() < 38 {
                    return Err("short TX completion");
                }
                let id = u16::from_le_bytes(packet.payload[36..38].try_into().unwrap());
                let queue = self
                    .resources
                    .data
                    .iter_mut()
                    .find(|q| q.id() == Some(id))
                    .ok_or("TX completion for unknown queue")?;
                let first = queue.next_completion();
                let (ssn, success) = queue.complete(&packet.payload)?;
                if self.tx_completed.len() == 256 {
                    return Err("unconsumed TX completion overflow");
                }
                self.tx_completed
                    .push_back((id, if success { ssn } else { first }, success));
                continue;
            }
            if self.resources.commands.complete(packet.header)? {
                if self.responses.len() == COMMAND_DEPTH {
                    self.responses.pop_front();
                }
                self.responses.push_back(packet);
            } else {
                if self.notifications.len() == 256 {
                    self.notifications.pop_front();
                }
                self.notifications.push_back(packet);
            }
        }
        Ok(())
    }

    pub async fn allocate_tx(&mut self, station: u8, tid: u8) -> Result<u16, &'static str> {
        if self.version(5, 0x17).map(|v| v.0) != Some(3) {
            return Err("unsupported queue allocation version");
        }
        let mut queue = super::data_queue::DataQueue::new()?;
        let body = queue.configure(station, tid)?;
        let index = self.resources.data.len();
        // Pin BEFORE publishing the allocation command. Timeout does
        // not prove the device failed to fetch the queue addresses.
        self.resources.data.push(queue);
        let reply = self.command(5, 0x17, &body).await?;
        let id = self.resources.data[index].activate(&reply.payload)?;
        if self.resources.data[..index]
            .iter()
            .any(|q| q.id() == Some(id))
        {
            self.failed = true;
            return Err("firmware reused an active queue ID");
        }
        Ok(id)
    }

    pub fn check_aggregation_api(&self) -> Result<(), &'static str> {
        if self.version(5, 0x16).map(|v| v.0) != Some(2)
            || !matches!(self.version(0, 0xc5).map(|v| v.1), Some(4 | 6 | 7))
        {
            return Err("firmware has no supported Block Ack API");
        }
        Ok(())
    }

    pub fn enable_aggregation(&mut self) -> Result<(), &'static str> {
        self.check_aggregation_api()?;
        for queue in &mut self.resources.data {
            queue.enable_aggregation();
        }
        Ok(())
    }

    pub async fn remove_tx(&mut self, id: u16, station: u8, tid: u8) -> Result<(), &'static str> {
        let index = self
            .resources
            .data
            .iter()
            .position(|q| q.id() == Some(id))
            .ok_or("unknown TX queue")?;
        let mut body = [0; 36];
        boot_context::put32(&mut body, 0, 1);
        boot_context::put32(
            &mut body,
            4,
            1u32.checked_shl(station as u32).ok_or("invalid station")?,
        );
        boot_context::put32(&mut body, 8, tid as u32);
        self.command(5, 0x17, &body).await?;
        self.resources.data.remove(index);
        Ok(())
    }

    pub fn fail(&mut self) {
        self.failed = true;
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// Reinitialize after a cancelled control operation or firmware
    /// failure. Old allocations are freed only after DMA stop and BME
    /// disable, exactly as on final teardown.
    pub async fn restart(&mut self, parsed: &ParsedUcode<'_>) -> Result<[u8; 6], &'static str> {
        self.failed = true;
        if let Some(interrupts) = &mut self.interrupts {
            interrupts.mask();
        }
        self.mmio.write(super::regs::CSR_INT_MASK, 0);
        if self.armed {
            let (register, request, done) = if self.format == rx_rfh::CompletionFormat::Bz {
                (super::regs::CSR_GP_CNTRL, 1 << 29, 1 << 28)
            } else {
                (super::regs::CSR_RESET, 1 << 9, 1 << 8)
            };
            let value = self.mmio.read(register);
            self.mmio.write(register, value | request);
            self.poll_register(register, done, done, 100).await?;
        }
        narf_bus::pci::clear_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
            .map_err(|_| "cannot disable DMA for recovery")?;
        let rx = ReceiveQueue::new(self.format)?;
        let commands = CommandQueue::new()?;
        let boot = BootImage::new(
            parsed,
            self.mmio.read(super::regs::CSR_HW_REV) as u16,
            &rx,
            &commands,
        )?;
        let resources = Resources {
            rx,
            commands,
            boot,
            data: Vec::new(),
        };
        // SAFETY: DMA stop was acknowledged and PCI BME is clear.
        // All fallible allocations precede this replacement.
        unsafe {
            core::mem::ManuallyDrop::drop(&mut self.resources);
        }
        self.resources = core::mem::ManuallyDrop::new(resources);
        self.armed = false;
        self.failed = false;
        self.notifications.clear();
        self.responses.clear();
        self.tx_completed.clear();
        self.start(parsed).await
    }

    /// Stop submitting encrypted data before replacing a station key; all
    /// frames using the previous key must have terminal TX completions.
    pub async fn drain_transmits(&mut self) -> Result<(), &'static str> {
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            let activity = self.activity();
            self.poll()?;
            self.retire_transmits();
            if self
                .resources
                .data
                .iter()
                .all(super::data_queue::DataQueue::is_idle)
            {
                return Ok(());
            }
            if deadline.expired() {
                self.failed = true;
                return Err("TX drain before key replacement timed out");
            }
            activity.await;
        }
    }

    /// Discard RX MPDUs and reorder releases captured across a key/session
    /// transition. Other firmware notifications remain available.
    pub fn discard_key_transition_rx(&mut self) -> Result<(), &'static str> {
        for _ in 0..RX_DEPTH / 64 + 1 {
            self.poll()?;
            self.notifications
                .retain(|p| p.header.group_id != 0 || !matches!(p.header.cmd, 0xc1..=0xc3));
            if !self.has_pending_rx() {
                return Ok(());
            }
        }
        self.failed = true;
        Err("RX did not quiesce across key replacement")
    }

    pub fn enqueue_transmit(
        &mut self,
        id: u16,
        frame: &[u8],
        header_len: usize,
        rate: Option<u32>,
    ) -> Result<(), &'static str> {
        if self.failed {
            return Err("Wi-Fi transport failed");
        }
        let queue = self
            .resources
            .data
            .iter_mut()
            .find(|q| q.id() == Some(id))
            .ok_or("unknown TX queue")?;
        queue.send(&mut self.mmio, frame, header_len, rate)?;
        Ok(())
    }

    /// The caller owns the async device mutex, so no other submission or
    /// completion waiter can consume this queue's newly available credit.
    /// Polling here drains DMA even while the background RX task is excluded.
    pub(super) async fn wait_tx_space(&mut self, id: u16) -> Result<(), &'static str> {
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            let activity = self.activity();
            self.poll()?;
            self.retire_transmits();
            let queue = self
                .resources
                .data
                .iter()
                .find(|q| q.id() == Some(id))
                .ok_or("unknown TX queue")?;
            if queue.has_space() {
                return Ok(());
            }
            if deadline.expired() {
                self.failed = true;
                return Err("TX queue credit timed out");
            }
            activity.await;
        }
    }

    /// Best-effort network packets do not have a waiting future. DMA
    /// has already been reclaimed by validated TX responses in poll().
    pub fn retire_transmits(&mut self) {
        self.tx_completed.clear();
    }

    pub async fn transmit(
        &mut self,
        id: u16,
        frame: &[u8],
        header_len: usize,
        rate: Option<u32>,
    ) -> Result<(), &'static str> {
        self.wait_tx_space(id).await?;
        let queue = self
            .resources
            .data
            .iter_mut()
            .find(|q| q.id() == Some(id))
            .ok_or("unknown TX queue")?;
        let ssn = queue.send(&mut self.mmio, frame, header_len, rate)?;
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            let activity = self.activity();
            self.poll()?;
            if let Some(index) = self
                .tx_completed
                .iter()
                .position(|entry| entry.0 == id && entry.1 == ssn)
            {
                return if self.tx_completed.remove(index).unwrap().2 {
                    Ok(())
                } else {
                    Err("frame transmission failed")
                };
            }
            // A compressed BA cumulatively retires successful frames. A
            // failed MPDU is retried singly and reported through TX_CMD.
            if self
                .resources
                .data
                .iter()
                .find(|q| q.id() == Some(id))
                .is_some_and(|q| q.has_completed(ssn))
            {
                return Ok(());
            }
            if deadline.expired() {
                self.failed = true;
                return Err("TX completion timed out");
            }
            activity.await;
        }
    }

    pub async fn command(
        &mut self,
        group: u8,
        command: u8,
        payload: &[u8],
    ) -> Result<Packet, &'static str> {
        if self.failed {
            return Err("Wi-Fi transport failed");
        }
        let version = self
            .version(group, command)
            .map(|v| v.0)
            .filter(|v| *v != 99)
            .unwrap_or(0);
        let sequence =
            self.resources
                .commands
                .send(&mut self.mmio, group, command, version, payload)?;
        self.responses
            .retain(|packet| packet.header.sequence != sequence);
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            let activity = self.activity();
            self.poll()?;
            if let Some(index) = self
                .responses
                .iter()
                .position(|packet| packet.header.sequence == sequence)
            {
                return Ok(self.responses.remove(index).unwrap());
            }
            if deadline.expired() {
                self.failed = true; // pending DMA stays pinned until stop
                return Err("firmware command timed out");
            }
            activity.await;
        }
    }

    pub async fn wait_notification(
        &mut self,
        group: u8,
        command: u8,
        ms: u64,
    ) -> Result<Packet, &'static str> {
        let deadline = narf_time::Deadline::after_ms(ms);
        loop {
            let activity = self.activity();
            self.poll()?;
            if let Some(index) = self
                .notifications
                .iter()
                .position(|p| p.header.group_id == group && p.header.cmd == command)
            {
                return Ok(self.notifications.remove(index).unwrap());
            }
            if deadline.expired() {
                return Err("firmware notification timed out");
            }
            activity.await;
        }
    }
}

impl Drop for Hardware {
    fn drop(&mut self) {
        use super::regs::*;
        if let Some(interrupts) = &mut self.interrupts {
            interrupts.mask();
        }
        // Disable host interrupts first, then wait for the device's DMA
        // engine to acknowledge stop before releasing any allocation.
        let stopped = if !self.armed {
            true
        } else {
            self.mmio.write(CSR_INT_MASK, 0);
            let (register, request, done) = if self.format == rx_rfh::CompletionFormat::Bz {
                (CSR_GP_CNTRL, 1 << 29, 1 << 28)
            } else {
                (CSR_RESET, 1 << 9, 1 << 8)
            };
            let value = self.mmio.read(register);
            self.mmio.write(register, value | request);
            narf_scheduler::responsive_spin_until(
                || {
                    let status = self.mmio.read(register);
                    status != u32::MAX && status & done != 0
                },
                narf_time::Deadline::after_ms(100),
            )
        };
        let disabled =
            narf_bus::pci::clear_command(&self.cap, &self.device, narf_bus::pci::cmd::BUS_MASTER)
                .is_ok();
        if stopped && disabled {
            // SAFETY: this is the only drop, and hardware has acknowledged
            // DMA stop (or was never given addresses), with PCI BME off.
            unsafe { core::mem::ManuallyDrop::drop(&mut self.resources) };
        } else {
            // A bounded leak is preferable to DMA into reallocated pages.
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "iwlwifi: DMA stop failed; quarantining allocations"
            );
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "runtime_tests.rs"]
mod tests;
