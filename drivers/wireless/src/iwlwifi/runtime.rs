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
    /// Immutable RFH copy-time owner. Closed-port captures never acquire a
    /// later key/association epoch merely because parsing was delayed.
    pub receive_epoch: Option<u64>,
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
            receive_epoch: None,
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
            free: dma_alloc(RX_DEPTH * format.free_size())?,
            used: dma_alloc(RX_DEPTH * format.size())?,
            status: dma_alloc(16)?,
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
        if self.format == rx_rfh::CompletionFormat::Qu {
            let descriptor =
                super::context_v1::free_descriptor(self.buffers[index].dma_addr().raw(), tag)
                    .expect("coherent page alignment and bounded tag");
            write_dma(&self.free, self.write * 8, &descriptor);
        } else {
            write_dma(&self.free, self.write * 16, &descriptor);
        }
        self.tags[self.write] = tag;
        self.write = (self.write + 1) & (RX_DEPTH - 1);
    }

    pub fn publish(&mut self, mmio: &mut impl IwlMmio) -> Result<(), &'static str> {
        if !mmio.authorized() {
            return Err("Wi-Fi authority revoked");
        }
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
        if !mmio.authorized() {
            return Err("Wi-Fi authority revoked");
        }
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
    #[cfg(any(test, feature = "kernel-test"))]
    trace: Option<model::TxTrace>,
}

impl CommandQueue {
    pub fn new() -> Result<Self, &'static str> {
        Ok(Self {
            descriptors: dma_alloc(COMMAND_DEPTH * 256)?,
            pending: (0..COMMAND_DEPTH).map(|_| None).collect(),
            write: 0,
            outstanding: 0,
            #[cfg(any(test, feature = "kernel-test"))]
            trace: None,
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
        if !mmio.authorized() {
            return Err("Wi-Fi authority revoked");
        }
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
        #[cfg(any(test, feature = "kernel-test"))]
        if let Some(trace) = &self.trace {
            trace.published(
                0,
                self.write,
                &self.pending[slot]
                    .as_ref()
                    .ok_or("private command DMA absent")?
                    ._dma,
                &self.descriptors,
                slot,
                mmio.read(tx_gen2::HBUS_TARG_WRPTR),
            )?;
        }
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
    pub scratch: Option<DmaBuffer>,
    pub iml: Option<DmaBuffer>,
    pub iml_len: usize,
    _info: Option<DmaBuffer>,
    prepare: Option<super::gen2_prepare::Owner>,
    phy_config: u32,
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
        write_dma(
            self.scratch.as_ref().ok_or("Gen2 has no PNVM scratch")?,
            16,
            &config,
        );
        dma_barrier();
        Ok(())
    }

    pub fn new(
        parsed: &ParsedUcode<'_>,
        hw_rev: u16,
        rx: &ReceiveQueue,
        command: &CommandQueue,
    ) -> Result<Self, &'static str> {
        if rx.format == rx_rfh::CompletionFormat::Qu {
            return Self::gen2(parsed, hw_rev, rx, command);
        }
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
            scratch: Some(scratch),
            iml: Some(iml),
            iml_len: iml_bytes.len(),
            _info: Some(info),
            prepare: None,
            phy_config: parsed.api.phy_config,
            _sections: sections,
        })
    }
    fn gen2(
        parsed: &ParsedUcode<'_>,
        hw_rev: u16,
        rx: &ReceiveQueue,
        command: &CommandQueue,
    ) -> Result<Self, &'static str> {
        if super::gen2_profile::firmware_api(parsed) != super::gen2_profile::API {
            return Err("unsupported Gen2 firmware API");
        }
        let queues = boot_context::BootQueues {
            free: rx.free.dma_addr().raw(),
            used: rx.used.dma_addr().raw(),
            status: rx.status.dma_addr().raw(),
            command: command.descriptors.dma_addr().raw(),
            rx_depth: RX_DEPTH as u16,
            command_depth: COMMAND_DEPTH as u16,
        };
        let mut bytes =
            super::context_v1::header(hw_rev, queues).map_err(|_| "invalid Gen2 boot queues")?;
        let map = super::context_v1::section_map(parsed).map_err(|_| "invalid Gen2 sections")?;
        let mut sections = Vec::with_capacity(map.len());
        for (index, offset) in map {
            let payload = parsed.rt_sections[index].payload;
            let buffer = dma_alloc(payload.len())?;
            super::context_v1::set_section(
                &mut bytes,
                offset,
                buffer.dma_addr().raw(),
                payload.len(),
            )
            .map_err(|_| "invalid Gen2 section mapping")?;
            write_dma(&buffer, 0, payload);
            sections.push(buffer);
        }
        let context = dma_alloc(super::context_v1::CONTEXT_BYTES)?;
        if !super::context_v1::dma_extent(
            context.dma_addr().raw(),
            super::context_v1::CONTEXT_BYTES,
        ) {
            return Err("Gen2 context crosses 4GiB");
        }
        write_dma(&context, 0, &bytes);
        Ok(Self {
            context,
            scratch: None,
            iml: None,
            iml_len: 0,
            _info: None,
            prepare: Some(super::gen2_prepare::Owner::default()),
            phy_config: parsed.api.phy_config,
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
struct Gen2PrepareIo<'a>(&'a mut super::IwlMmioImpl);
impl super::gen2_prepare::Io for Gen2PrepareIo<'_> {
    fn read(&mut self, address: u32) -> Result<u32, super::gen2_prepare::Error> {
        if !self.0.authorized() {
            return Err(super::gen2_prepare::Error::Access);
        }
        Ok(self.0.read(address))
    }
    fn write(&mut self, address: u32, value: u32) -> Result<(), super::gen2_prepare::Error> {
        if !self.0.authorized() {
            return Err(super::gen2_prepare::Error::Access);
        }
        self.0.write(address, value);
        if self.0.authorized() {
            Ok(())
        } else {
            Err(super::gen2_prepare::Error::Access)
        }
    }
    fn now_us(&self) -> u64 {
        narf_time::wall::monotonic_ns() / 1000
    }
    async fn delay_us(&mut self, us: u64) {
        narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(us.saturating_mul(1000))).await;
    }
}

/// A validated terminal TX_CMD response without acknowledgement. The frame
/// and its DMA are already retired; only the peer's receipt is absent.
pub const TX_FAILED: &str = "frame transmission failed";

pub struct Hardware {
    mmio: super::IwlMmioImpl,
    resources: core::mem::ManuallyDrop<Resources>,
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    format: rx_rfh::CompletionFormat,
    sc_identity: Option<super::firmware_identity::Sc>,
    interrupts: Option<super::iwl_msix::Interrupts>,
    pub notifications: alloc::collections::VecDeque<Packet>,
    responses: alloc::collections::VecDeque<Packet>,
    tx_completed: alloc::collections::VecDeque<(u16, u16, bool)>,
    versions: Vec<u8>,
    armed: bool,
    failed: bool,
    station_stop: Option<alloc::sync::Arc<core::sync::atomic::AtomicBool>>,
    /// Protected MPDUs published to data/management queues. Each consumes
    /// at most one fresh firmware TX PN (retries reuse it), so differences
    /// bound the PN range a pairwise key can have used.
    protected_tx: u64,
    rx_epoch: rx_epoch::State,
    sources: Option<source::Assets>,
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
    pub(super) fn bind_station_stop(
        &mut self,
        stop: alloc::sync::Arc<core::sync::atomic::AtomicBool>,
    ) {
        self.station_stop = Some(stop);
    }
    pub(super) fn authority(&self, master: bool) -> Authority {
        let native = true;
        #[cfg(any(test, feature = "kernel-test"))]
        let native = native && self.device.id.vendor != 0xffff;
        Authority {
            device: self.device,
            cap: self.cap,
            master,
            native,
        }
    }
    pub(super) fn new(
        device: narf_bus::BusDevice,
        cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        region: narf_bus::MmioRegion,
        parsed: &ParsedUcode<'_>,
        format: rx_rfh::CompletionFormat,
        sc_identity: Option<super::firmware_identity::Sc>,
    ) -> Result<Self, &'static str> {
        let sc = super::chip_config_for_pci_id(device.id.vendor, device.id.device)
            .is_some_and(|chip| chip.mac == super::MacFamily::ScA0);
        if sc && sc_identity.is_none() {
            return Err("Sc startup requires selected hardware identity");
        }
        if !sc && sc_identity.is_some() {
            return Err("Sc firmware binding on another PCI profile");
        }
        // Stop inherited DMA before allocating buffers or rejecting an
        // unsupported firmware profile. Early initialization failures must
        // not leave a previous boot's bus-master state running.
        super::mmio::set_master(&device, &cap, false)?;
        let mut mmio = super::IwlMmioImpl::new(region, cap);
        if let Some(identity) = sc_identity {
            identity.check(&mut mmio)?;
        }
        if format == rx_rfh::CompletionFormat::Qu {
            super::gen2_profile::select(
                device.id.device,
                mmio.read(super::regs::CSR_HW_REV),
                mmio.read(0x9c),
            )
            .map_err(|_| "unsupported Gen2 PCI/MAC/RF profile")?;
            if parsed.api.versions(0, 1).map(|v| v.1) != Some(6)
                || parsed.api.versions(0xc, 2) != Some((1, 4))
            {
                return Err("unsupported MVM initialization command versions");
            }
        }
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
            sc_identity,
            interrupts: None,
            notifications: alloc::collections::VecDeque::new(),
            responses: alloc::collections::VecDeque::new(),
            tx_completed: alloc::collections::VecDeque::new(),
            versions: parsed.api.commands.to_vec(),
            armed: false,
            failed: false,
            station_stop: None,
            protected_tx: 0,
            rx_epoch: rx_epoch::State::default(),
            sources: None,
        })
    }

    pub(super) fn gen2_profile(&mut self) -> Result<super::gen2_profile::Profile, &'static str> {
        if self.format != rx_rfh::CompletionFormat::Qu {
            return Err("MVM owner requires 22000 transport");
        }
        super::gen2_profile::select(
            self.device.id.device,
            self.mmio.read(super::regs::CSR_HW_REV),
            self.mmio.read(0x9c),
        )
        .map_err(|_| "unsupported Gen2 identity")
    }
    /// Actual live PCI/MAC/RF facts for binding signed platform power inputs.
    /// Read-only identity is never transmit or calibration authority.
    pub(super) fn gen2_power_facts(
        &mut self,
    ) -> Result<(super::gen2_profile::Profile, [u8; 16]), &'static str> {
        if self.format != rx_rfh::CompletionFormat::Qu || !self.mmio.authorized() {
            return Err("MVM power identity unavailable");
        }
        let revision = self.mmio.read(super::regs::CSR_HW_REV);
        let radio = self.mmio.read(0x9c);
        let profile = super::gen2_profile::select(self.device.id.device, revision, radio)
            .map_err(|_| "MVM power identity changed or disappeared")?;
        let mut facts = [0; 16];
        for (offset, value) in [
            (0, self.device.id.vendor),
            (2, self.device.id.device),
            (4, self.device.id.subsystem_vendor),
            (6, self.device.id.subsystem_id),
        ] {
            facts[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        facts[8..12].copy_from_slice(&revision.to_le_bytes());
        facts[12..].copy_from_slice(&radio.to_le_bytes());
        Ok((profile, facts))
    }

    pub(super) fn matches_firmware(&self, parsed: &ParsedUcode<'_>) -> bool {
        if self.format != rx_rfh::CompletionFormat::Qu
            || self.versions != parsed.api.commands
            || self.resources.boot.phy_config != parsed.api.phy_config
        {
            return false;
        }
        let Ok(map) = super::context_v1::section_map(parsed) else {
            return false;
        };
        map.len() == self.resources.boot._sections.len()
            && map
                .into_iter()
                .zip(&self.resources.boot._sections)
                .all(|((index, _), buffer)| {
                    let payload = parsed.rt_sections[index].payload;
                    buffer.as_slice().get(..payload.len()) == Some(payload)
                })
    }

    pub fn version(&self, group: u8, command: u8) -> Option<(u8, u8)> {
        self.versions
            .chunks_exact(4)
            .find(|entry| entry[0] == command && entry[1] == group)
            .map(|entry| (entry[2], entry[3]))
    }

    pub fn runtime_configuration(
        &self,
    ) -> Result<super::station_api::RuntimeConfiguration, &'static str> {
        super::station_api::runtime_configuration(
            self.device.id.device,
            self.version(1, 0x9b).ok_or("missing BT coexistence API")?.0,
            self.version(2, 1).ok_or("missing SoC configuration API")?.0,
            self.version(1, 0x77).ok_or("missing device power API")?.0,
        )
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
        use core::{
            future::{poll_fn, Future},
            pin::pin,
        };
        let assets = self.source_assets()?;
        let pci = self.cap;
        let result = {
            let mut future = pin!(self.start_inner(parsed));
            poll_fn(|cx| {
                assets
                    .invoke(|| {
                        super::mmio::invoke(&pci, || future.as_mut().poll(cx))
                            .map_err(|_| "Intel startup PCI authority revoked")
                    })
                    .unwrap_or_else(|e| core::task::Poll::Ready(Err(e)))
            })
            .await
        };
        if result.is_err() {
            self.fail();
        }
        result
    }

    async fn start_inner(&mut self, parsed: &ParsedUcode<'_>) -> Result<[u8; 6], &'static str> {
        use super::regs::*;
        if super::chip_config_for_pci_id(self.device.id.vendor, self.device.id.device)
            .is_some_and(|chip| chip.mac == super::MacFamily::ScA0)
            && self.sc_identity.is_none()
        {
            return Err("Sc startup requires selected hardware identity");
        }
        if let Some(identity) = self.sc_identity {
            identity.check(&mut self.mmio)?;
        }
        super::mmio::set_master(&self.device, &self.cap, false)?;
        if self.format == rx_rfh::CompletionFormat::Qu {
            let hw_rev = self.mmio.read(CSR_HW_REV);
            let profile =
                super::gen2_profile::select(self.device.id.device, hw_rev, self.mmio.read(0x9c))
                    .map_err(|_| "unsupported Gen2 PCI/MAC/RF profile")?;
            let owner = self
                .resources
                .boot
                .prepare
                .as_mut()
                .ok_or("missing Gen2 preparation owner")?;
            let mut io = Gen2PrepareIo(&mut self.mmio);
            // SAFETY: Hardware exclusively retains the native function/cap,
            // PCI BME was verified off above, and all boot/queue mappings stay
            // owned. No DMA memory is released; no workers exist during boot.
            unsafe {
                owner
                    .prepare(&mut io, profile, hw_rev, parsed.api.phy_config)
                    .await
            }
            .map_err(|_| "Gen2 APM/NIC preparation failed")?;
        } else {
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
        }

        if self.interrupts.is_none() {
            self.interrupts = Some(self.mmio.interrupts(&self.device)?);
        }
        // AX210/Bz/Sc use the UMAC interrupt selector, with peripherals
        // relocated by 0x300000. Reset clears the selector/IVARs,
        // so reprogram on every start while retaining the owned vector.
        if self.format == rx_rfh::CompletionFormat::Qu {
            super::transport::prph_write(&mut self.mmio, 0xA05C00, 1 << 25);
        } else {
            super::transport::prph_write_ax210(&mut self.mmio, 0xD05C00, 1 << 25);
        }
        self.interrupts
            .as_mut()
            .unwrap()
            .enable(self.format == rx_rfh::CompletionFormat::Bz)?;

        if let Some(identity) = self.sc_identity {
            identity.check(&mut self.mmio)?;
        }
        super::mmio::set_master(&self.device, &self.cap, true)?;
        self.armed = true;
        self.resources.rx.publish(&mut self.mmio)?;
        dma_barrier();
        let boot = &self.resources.boot;
        if self.format == rx_rfh::CompletionFormat::Qu {
            super::context_v1::publish(&mut self.mmio, boot.context.dma_addr().raw())
                .map_err(|_| "invalid Gen2 context address")?;
            let profile = super::gen2_profile::select(
                self.device.id.device,
                self.mmio.read(CSR_HW_REV),
                self.mmio.read(0x9c),
            )
            .map_err(|_| "unsupported Gen2 PCI/MAC/RF profile")?;
            super::gen2_prepare::Owner::rom_ltr(&mut Gen2PrepareIo(&mut self.mmio), profile)
                .map_err(|_| "Gen2 ROM LTR configuration failed")?;
            super::context_v1::release(&mut self.mmio)
                .map_err(|_| "Gen2 CPU release authority revoked")?;
        } else {
            let regions = super::transport::Gen3BootRegions {
                ctxt_info_phys: boot.context.dma_addr().raw(),
                iml_phys: boot
                    .iml
                    .as_ref()
                    .ok_or("missing Gen3 IML")?
                    .dma_addr()
                    .raw(),
                iml_size: boot.iml_len as u32,
            };
            super::transport::start_gen3(&mut self.mmio, &regions, self.format);
        }
        self.finish_boot(parsed).await
    }
    async fn finish_boot(&mut self, parsed: &ParsedUcode<'_>) -> Result<[u8; 6], &'static str> {
        use super::regs::*;
        let alive = self.wait_notification(0, 1, 2000).await?;
        let alive_version = self
            .version(0, 1)
            .or_else(|| self.version(1, 1))
            .map(|v| v.1);
        let expected = match (self.format, alive_version) {
            (rx_rfh::CompletionFormat::Qu, Some(6)) => 144,
            (rx_rfh::CompletionFormat::Qu, _) => return Err("unsupported MVM ALIVE version"),
            (_, Some(7)) => 144,
            (_, Some(8)) => 152,
            _ => return Err("unsupported ALIVE notification version"),
        };
        if alive.payload.len() != expected || alive.payload[..2] != 0xcafeu16.to_le_bytes() {
            return Err("invalid firmware ALIVE notification");
        }
        let sku = core::array::from_fn(|i| {
            u32::from_le_bytes(alive.payload[116 + i * 4..120 + i * 4].try_into().unwrap())
        });
        if self.format != rx_rfh::CompletionFormat::Qu && sku != [0; 3] {
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
        if self.format == rx_rfh::CompletionFormat::Qu {
            // MVM unified image: allow firmware to populate NVM, then signal
            // completion. Do not send MLD's separate PHY configuration flow.
            self.command(2, 3, &2u32.to_le_bytes()).await?;
            self.command(0xc, 0, &[0; 4]).await?;
            self.wait_notification(0, 4, 2000).await?;
        } else {
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
        }
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
        let result = self
            .source_fence()
            .and_then(|source| source.invoke(|| self.poll_inner()));
        if result.is_err() {
            self.fail();
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
        let capture = self.rx_epoch.capture();
        for mut packet in self.resources.rx.drain(&mut self.mmio)? {
            packet.receive_epoch = capture;
            if packet.header.group_id == 0 && packet.header.cmd == 0xc5 {
                if !matches!(self.version(0, 0xc5).map(|v| v.1), Some(4 | 6 | 7)) {
                    return Err("unsupported compressed BA notification");
                }
                if self.format == rx_rfh::CompletionFormat::Qu {
                    super::aggregation::validate_gen2_tx_ba(&packet.payload)?;
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
                    return Err("native Intel notification ownership overflow");
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
        let mut queue = super::data_queue::DataQueue::for_format(self.format)?;
        #[cfg(any(test, feature = "kernel-test"))]
        queue.trace_for_model(self.resources.commands.trace.clone());
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

    pub(super) fn gen2_tx_aggregation(
        &mut self,
        id: u16,
        enabled: bool,
    ) -> Result<(), &'static str> {
        if self.format != rx_rfh::CompletionFormat::Qu
            || !matches!(self.version(0, 0xc5).map(|v| v.1), Some(4 | 6 | 7))
        {
            return Err("unsupported Gen2 compressed BA contract");
        }
        self.resources
            .data
            .iter_mut()
            .find(|q| q.id() == Some(id))
            .ok_or("unknown Gen2 aggregate queue")?
            .gen2_aggregation(enabled)
    }

    /// One retained bounded batch. Every descriptor owns a separate DMA buffer;
    /// native TX_CMD singles and compressed-BA prefixes are the only reclaimers.
    pub(super) async fn transmit_gen2_batch(
        &mut self,
        id: u16,
        frames: &[(Vec<u8>, u32)],
    ) -> Result<(), &'static str> {
        if frames.is_empty()
            || frames.len() > 8
            || !self.idle_tx_binding(id, 0, 0)
            || !self
                .resources
                .data
                .iter()
                .any(|q| q.id() == Some(id) && q.aggregated())
        {
            return Err("invalid Gen2 aggregate batch owner");
        }
        self.tx_completed.retain(|entry| entry.0 != id);
        for (frame, assist) in frames {
            if self
                .station_stop
                .as_ref()
                .is_some_and(|s| s.load(Ordering::Acquire))
            {
                return Err("MVM batch closed before native publication");
            }
            self.enqueue_transmit_assisted(id, frame, 26, None, *assist)?;
        }
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            let activity = self.activity();
            self.poll()?;
            // A failed single identifies the oldest failed frame; subsequent
            // frames in that same reclaim interval were already acknowledged.
            // Failure never authorizes resubmission or a successful batch.
            if self.tx_completed.iter().any(|e| e.0 == id && !e.2) {
                return Err("Gen2 aggregate native single retry failed");
            }
            self.tx_completed.retain(|e| e.0 != id);
            if self.idle_tx_binding(id, 0, 0) {
                return Ok(());
            }
            if deadline.expired() {
                self.failed = true;
                return Err("Gen2 aggregate terminal prefix timeout");
            }
            activity.await;
        }
    }

    pub async fn remove_tx(&mut self, id: u16, station: u8, tid: u8) -> Result<(), &'static str> {
        self.remove_idle_tx(id, station, tid).await
    }

    /// Retire an unused prerequisite queue only after its exact firmware
    /// remove receipt. Caller cancellation retains both queue DMA and the
    /// command allocation. Active station teardown uses its separate drain.
    pub(super) async fn remove_idle_tx(
        &mut self,
        id: u16,
        station: u8,
        tid: u8,
    ) -> Result<(), &'static str> {
        if self.failed || self.version(5, 0x17).map(|v| v.0) != Some(3) {
            return Err("unsupported or failed idle TX queue retirement");
        }
        let index = self
            .resources
            .data
            .iter()
            .position(|q| q.id() == Some(id))
            .ok_or("unknown idle TX queue")?;
        let mut body = [0; 36];
        boot_context::put32(&mut body, 0, 1);
        boot_context::put32(
            &mut body,
            4,
            1u32.checked_shl(u32::from(station))
                .ok_or("invalid idle TX station")?,
        );
        boot_context::put32(&mut body, 8, u32::from(tid));
        // Reserve before publication: dropping the waiter cannot reopen
        // packet admission, replay REMOVE or let ADD reuse this native ID.
        self.resources.data[index].begin_remove(station, tid)?;
        let reply = self.command(5, 0x17, &body).await?;
        // fw/api/datapath.h documents the API-v2 iwl_tx_queue_cfg_rsp
        // for allocation/config/removal, not an empty status-less ACK.
        // REMOVE must name this retained queue and report success. Its
        // initial-write-pointer field belongs to ADD and is not adopted
        // when retiring an idle queue.
        let response = &reply.payload;
        if response.len() != 8
            || u16::from_le_bytes(response[..2].try_into().unwrap()) != id
            || response[2..4] != [0; 2]
            || response[6..8] != [0; 2]
        {
            self.failed = true;
            return Err("invalid idle TX queue remove receipt");
        }
        self.resources.data.remove(index);
        Ok(())
    }

    /// Bz and later hardware include the SNAP header in the RX
    /// `CHECKSUM_COMPLETE` raw sum (`iwl_mvm_create_skb`); AX210 does not.
    pub(super) fn rx_checksum_includes_snap(&self) -> Option<bool> {
        match self.format {
            rx_rfh::CompletionFormat::Qu => None,
            rx_rfh::CompletionFormat::Ax210 => Some(false),
            rx_rfh::CompletionFormat::Bz => Some(true),
        }
    }

    fn count_protected(&mut self, frame: &[u8]) {
        if frame.get(1).is_some_and(|fc| fc & 0x40 != 0) {
            self.protected_tx = self.protected_tx.saturating_add(1);
        }
    }

    /// Monotonic count of published protected MPDUs (see `protected_tx`).
    pub(super) fn protected_transmits(&self) -> u64 {
        self.protected_tx
    }

    pub fn fail(&mut self) {
        self.failed = true;
        self.rx_epoch.deny();
    }
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// Reinitialize after a cancelled control operation or firmware
    /// failure. Old allocations are freed only after DMA stop and BME
    /// disable, exactly as on final teardown.
    /// System-suspend transport stop, following Linux
    /// `pcie/gen1_2/trans-gen2.c::_iwl_trans_pcie_gen2_stop_device`:
    /// mask interrupts, stop the bus master and wait for its acknowledgement
    /// (`iwl_pcie_apm_stop_master`), software-reset the NIC
    /// (`iwl_trans_pcie_sw_reset`) and clear PCI bus mastering. Allocations
    /// are retained (DMA is provably stopped) until the resume restart
    /// replaces them, or final teardown frees them.
    pub async fn stop_for_suspend(&mut self) -> Result<(), &'static str> {
        self.fail();
        if let Some(interrupts) = &mut self.interrupts {
            interrupts.mask();
        }
        self.mmio.write(super::regs::CSR_INT_MASK, 0);
        let bz = self.format == rx_rfh::CompletionFormat::Bz;
        if self.armed {
            let (register, request, done) = if bz {
                (super::regs::CSR_GP_CNTRL, 1 << 29, 1 << 28)
            } else {
                (super::regs::CSR_RESET, 1 << 9, 1 << 8)
            };
            let value = self.mmio.read(register);
            self.mmio.write(register, value | request);
            self.poll_register(register, done, done, 100).await?;
        }
        // CSR_GP_CNTRL_REG_FLAG_SW_RESET (bit 31) on Bz+, else
        // CSR_RESET_REG_FLAG_SW_RESET (bit 7).
        let (register, reset) = if bz {
            (super::regs::CSR_GP_CNTRL, 1 << 31)
        } else {
            (super::regs::CSR_RESET, 1 << 7)
        };
        let value = self.mmio.read(register);
        self.mmio.write(register, value | reset);
        super::mmio::set_master(&self.device, &self.cap, false)?;
        self.armed = false;
        self.notifications.clear();
        self.responses.clear();
        self.tx_completed.clear();
        Ok(())
    }

    pub async fn restart(&mut self, parsed: &ParsedUcode<'_>) -> Result<[u8; 6], &'static str> {
        self.fail();
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
        super::mmio::set_master(&self.device, &self.cap, false)?;
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
        self.rx_epoch.reset_after_dma_stop();
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

    pub(super) fn transmit_space(&self, id: u16) -> Result<bool, &'static str> {
        if self.failed {
            return Err("Wi-Fi transport failed");
        }
        if !self.mmio.authorized() {
            return Err("Wi-Fi authority revoked");
        }
        self.resources
            .data
            .iter()
            .find(|queue| queue.id() == Some(id))
            .map(super::data_queue::DataQueue::has_space)
            .ok_or("unknown TX queue")
    }

    pub fn enqueue_transmit(
        &mut self,
        id: u16,
        frame: &[u8],
        header_len: usize,
        rate: Option<u32>,
    ) -> Result<(), &'static str> {
        self.enqueue_transmit_assisted(id, frame, header_len, rate, 0)
    }

    pub fn enqueue_transmit_assisted(
        &mut self,
        id: u16,
        frame: &[u8],
        header_len: usize,
        rate: Option<u32>,
        assist: u32,
    ) -> Result<(), &'static str> {
        if self.failed {
            return Err("Wi-Fi transport failed");
        }
        let sources = self.source_fence()?;
        let queue = self
            .resources
            .data
            .iter_mut()
            .find(|q| q.id() == Some(id))
            .ok_or("unknown TX queue")?;
        sources.invoke(|| queue.send_assisted(&mut self.mmio, frame, header_len, rate, assist))?;
        self.count_protected(frame);
        Ok(())
    }

    /// An unused prerequisite queue must still belong to the exact peer/TID.
    pub(super) fn idle_tx_binding(&self, id: u16, station: u8, tid: u8) -> bool {
        !self.failed
            && self
                .resources
                .data
                .iter()
                .any(|queue| queue.id() == Some(id) && queue.ready_binding(station, tid))
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
        self.transmit_owned(id, frame, header_len, rate, false, 0)
            .await
    }

    /// Data transmission with checksum `offload_assist` bits prepared by
    /// [`super::csum::prepare_tx`].
    pub async fn transmit_assisted(
        &mut self,
        id: u16,
        frame: &[u8],
        header_len: usize,
        rate: Option<u32>,
        assist: u32,
    ) -> Result<(), &'static str> {
        self.transmit_owned(id, frame, header_len, rate, false, assist)
            .await
    }

    /// The close owner's own final management frame (Linux mac80211
    /// `ieee80211_set_disassoc(tx=true)`). Host stop forbids every other
    /// publication; it cannot forbid the frame which implements that stop.
    pub async fn transmit_closing(
        &mut self,
        id: u16,
        frame: &[u8],
        header_len: usize,
        rate: Option<u32>,
    ) -> Result<(), &'static str> {
        self.transmit_owned(id, frame, header_len, rate, true, 0)
            .await
    }

    async fn transmit_owned(
        &mut self,
        id: u16,
        frame: &[u8],
        header_len: usize,
        rate: Option<u32>,
        closing: bool,
        assist: u32,
    ) -> Result<(), &'static str> {
        self.wait_tx_space(id).await?;
        if !closing
            && self
                .station_stop
                .as_ref()
                .is_some_and(|stop| stop.load(Ordering::Acquire))
        {
            return Err("MVM station closed before native packet publication");
        }
        let sources = self.source_fence()?;
        let queue = self
            .resources
            .data
            .iter_mut()
            .find(|q| q.id() == Some(id))
            .ok_or("unknown TX queue")?;
        let ssn = sources
            .invoke(|| queue.send_assisted(&mut self.mmio, frame, header_len, rate, assist))?;
        self.count_protected(frame);
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
                    Err(TX_FAILED)
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
        // All reached MVM/MLD callers pass bare opcodes/WIDE_IDs. Their
        // command-ID version is0 even when the payload layout is v3/v5/v12.
        // fw/api/cmdhdr.h extracts wire version only from ID bits16..23;
        // pcie/gen1_2/tx-gen2.c copies those bits into hdr_wide.version.
        // This is independent of Qu/AX210/Bz completion formats. An actual
        // explicitly versioned command ID must use the explicit API below;
        // payload version discovery never synthesizes command-ID bits.
        self.command_with_header_version(group, command, payload, 0)
            .await
    }

    /// The wire header's version comes from command-ID bits16..23, not the
    /// firmware's payload-layout lookup (Linux fw/api/cmdhdr.h and
    /// pcie/gen1_2/tx-gen2.c). Retained MVM link control uses WIDE_ID, version0.
    pub(super) async fn command_with_header_version(
        &mut self,
        group: u8,
        command: u8,
        payload: &[u8],
        version: u8,
    ) -> Result<Packet, &'static str> {
        if self.failed {
            return Err("Wi-Fi transport failed");
        }
        let sources = self.source_fence()?;
        let sequence = sources.invoke(|| {
            self.resources
                .commands
                .send(&mut self.mmio, group, command, version, payload)
        })?;
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

/// Read-only retained PCI publication authority; the model-only constructor
/// still invokes its real object-table capability and never reads physical PCI.
#[derive(Clone)]
pub(super) struct Authority {
    device: narf_bus::BusDevice,
    cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    master: bool,
    native: bool,
}
impl Authority {
    pub(super) fn invoke<T>(
        &self,
        operation: impl FnOnce() -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        super::mmio::invoke(&self.cap, || {
            if self.native {
                use narf_bus::pci::{
                    self,
                    cmd::{BUS_MASTER, INTX_DISABLE, MEM_SPACE},
                };
                let command = pci::read_command(&self.cap, &self.device)
                    .map_err(|_| "MVM PCI command unavailable")?;
                let required = MEM_SPACE | INTX_DISABLE | if self.master { BUS_MASTER } else { 0 };
                if command & required != required {
                    return Err("MVM PCI publication command lost");
                }
            }
            operation()
        })
        .map_err(|_| "MVM PCI authority revoked")?
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
        let disabled = super::mmio::set_master(&self.device, &self.cap, false).is_ok();
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

#[cfg(any(test, feature = "kernel-test"))]
#[path = "runtime_model.rs"]
pub(super) mod model;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "runtime_gen2_tests.rs"]
mod gen2_tests;

#[cfg(any(test, feature = "kernel-test"))]
#[path = "runtime_retirement_tests.rs"]
mod retirement_tests;

#[path = "runtime_rx_epoch.rs"]
pub(super) mod rx_epoch;

#[path = "runtime_source.rs"]
pub(super) mod source;
