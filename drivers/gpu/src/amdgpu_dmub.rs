//! DCN 3.1.4 DMUB command transport. ABI checked against Linux
//! display/dmub/inc/dmub_cmd.h and dmub_dcn31.c/dmub_dcn314.c.
//!
//! Attachment requires an already running DAL firmware and a mailbox wholly
//! inside the mapped VRAM aperture. This does not load firmware or reset DMCUB.
use crate::amdgpu::AmdGpu;
use core::sync::atomic::{fence, Ordering};
use narf_bus::MmioRegion;

use super::amdgpu_dmub_firmware as firmware;
use alloc::vec::Vec;
use narf_capabilities::{Cap, CapError, CapOp, Read};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirmwareError {
    Unsupported,
    Registry(narf_firmware::FirmwareError),
    Image(firmware::Error),
}

/// An immutable copy read through firmware capabilities. Holding it does not mean
/// the GPU is running the image; only the eventual boot handshake can do that.
#[derive(Debug)]
pub struct Firmware {
    bytes: Vec<u8>,
}

struct OpenFirmware;
impl CapOp<narf_firmware::FirmwareRegistry, Read> for OpenFirmware {
    type Output = Result<Vec<u8>, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self::Output, CapError> {
        let blob = match narf_firmware::open(firmware::DCN314_FIRMWARE, cap) {
            Ok(blob) => blob,
            Err(error) => return Ok(Err(FirmwareError::Registry(error))),
        };
        blob.invoke(CopyFirmware)
    }
}
struct CopyFirmware;
impl CapOp<narf_firmware::FirmwareBlob, Read> for CopyFirmware {
    type Output = Result<Vec<u8>, FirmwareError>;
    fn execute(
        self,
        cap: &Cap<narf_firmware::FirmwareBlob, Read>,
    ) -> Result<Self::Output, CapError> {
        Ok((|| {
            let view = narf_firmware::view_of(cap).map_err(FirmwareError::Registry)?;
            // Validate sizes before allocating; no borrowed registry slice
            // escapes the capability invocation into later staging work.
            firmware::Image::parse(view.bytes).map_err(FirmwareError::Image)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(view.bytes.len())
                .map_err(|_| FirmwareError::Registry(narf_firmware::FirmwareError::OutOfMemory))?;
            bytes.extend_from_slice(view.bytes);
            Ok(bytes)
        })())
    }
}
impl Firmware {
    /// Choose firmware from exact IP discovery, independently of the coarse
    /// PCI family table. DCN 3.5 requires a different hardware boot sequence.
    pub fn open(
        gpu: &AmdGpu,
        authority: &Cap<narf_firmware::FirmwareRegistry, Read>,
    ) -> Result<Self, FirmwareError> {
        dcn314_ip(gpu).map_err(|_| FirmwareError::Unsupported)?;
        let bytes = authority.invoke(OpenFirmware).map_err(|_| {
            FirmwareError::Registry(narf_firmware::FirmwareError::AuthorityRevoked)
        })??;
        Ok(Self { bytes })
    }
    /// Borrow the validated copy, without retaining a registry memory view.
    /// This is data already read, not authority to replace running firmware.
    pub fn image(&self) -> Result<firmware::Image<'_>, FirmwareError> {
        firmware::Image::parse(&self.bytes).map_err(FirmwareError::Image)
    }
    pub fn prepare<'a>(&'a self, vbios: &'a [u8]) -> Result<firmware::Prepared<'a>, FirmwareError> {
        self.image()?
            .prepare_dcn314(vbios)
            .map_err(FirmwareError::Image)
    }
}

pub(crate) fn dcn314_ip(gpu: &AmdGpu) -> Result<&crate::amdgpu_discovery::IpBlock, Error> {
    let mut blocks = gpu
        .ip_blocks
        .iter()
        .filter(|b| b.hw_id == crate::amdgpu_discovery::HW_ID_DCN && b.instance == 0);
    let ip = blocks.next().ok_or(Error::Unsupported)?;
    if blocks.next().is_some() || (ip.major, ip.minor, ip.revision) != (3, 1, 4) {
        return Err(Error::Unsupported);
    }
    Ok(ip)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    NotReady,
    Invalid,
    Busy,
    Timeout,
    Firmware(u8),
    Aux(u8),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Channel {
    Legacy = 0,
    Dpia = 1,
}
#[derive(Debug)]
pub struct Dmub {
    regs: MmioRegion,
    fb: MmioRegion,
    base: u64,
    inbox: u64,
    outbox: u64,
    inbox_size: u32,
    outbox_size: u32,
    write: u32,
    read: u32,
    poisoned: bool,
}
impl Dmub {
    /// # Safety
    /// Caller exclusively owns the GPU's DMUB mailbox for the returned
    /// object's lifetime, including power management and firmware replacement.
    pub unsafe fn attach(gpu: &AmdGpu) -> Result<Self, Error> {
        let ip = dcn314_ip(gpu)?;
        if ip.num_bases < 3 {
            return Err(Error::Unsupported);
        }
        let base = ip.base_addrs[2] as u64 * 4;
        // SAFETY: inherited mapping and exclusive mailbox ownership.
        unsafe { Self::attach_regions(gpu.regs, gpu.fb_bar, base) }
    }
    /// # Safety
    /// Valid DCN314 mappings and exclusive DMUB ownership must outlive Self.
    pub(crate) unsafe fn attach_regions(
        regs: MmioRegion,
        fb: MmioRegion,
        base: u64,
    ) -> Result<Self, Error> {
        if base.checked_add(0x478 * 4).is_none_or(|end| end > regs.len) {
            return Err(Error::Invalid);
        }
        let mut d = Self {
            regs,
            fb,
            base,
            inbox: 0,
            outbox: 0,
            inbox_size: 0,
            outbox_size: 0,
            write: 0,
            read: 0,
            poisoned: false,
        };
        if d.reg(0x1f6) & (1 << 16) == 0 || d.reg(0x1e3) & 3 != 3 {
            return Err(Error::NotReady);
        }
        let window_base = d.reg(0x1a9) & 0x1fff_ffff;
        let top = d.reg(0x1b1);
        if top & (1 << 31) == 0 {
            return Err(Error::NotReady);
        }
        let window_end = (top & 0x1fff_ffff) as u64;
        let address = d.reg(0x1bd) as u64 | ((d.reg(0x1be) as u64 & 0xffff) << 32);
        // Read the DCN314 aperture base from this IP's discovery window;
        // legacy MC offsets are not valid on every Phoenix revision.
        let fb_base = ((d.reg(0x475) & 0x00ff_ffff) as u64) << 24;
        let fb_top = (((d.reg(0x476) & 0x00ff_ffff) as u64) + 1) << 24;
        if fb_top <= fb_base || address >= fb_top {
            return Err(Error::Invalid);
        }
        let offset = address.checked_sub(fb_base).ok_or(Error::Invalid)?;
        let inbox_base = d.reg(0x1d4) & 0x1fff_ffff;
        let outbox_base = d.reg(0x1dc) & 0x1fff_ffff;
        d.inbox_size = d.reg(0x1d5);
        d.outbox_size = d.reg(0x1dd);
        d.inbox = mailbox_offset(
            offset,
            window_base,
            window_end,
            inbox_base,
            d.inbox_size,
            fb.len,
        )?;
        d.outbox = mailbox_offset(
            offset,
            window_base,
            window_end,
            outbox_base,
            d.outbox_size,
            fb.len,
        )?;
        if d.inbox < d.outbox + d.outbox_size as u64 && d.outbox < d.inbox + d.inbox_size as u64 {
            return Err(Error::Invalid);
        }
        d.write = d.reg(0x1d6);
        let read = d.reg(0x1d7);
        d.read = d.reg(0x1df);
        let write = d.reg(0x1de);
        if !valid_pointer(d.write, d.inbox_size)
            || !valid_pointer(read, d.inbox_size)
            || !valid_pointer(d.read, d.outbox_size)
            || !valid_pointer(write, d.outbox_size)
        {
            return Err(Error::Invalid);
        }
        if d.write != read {
            return Err(Error::Busy);
        }
        Ok(d)
    }
    fn reg(&self, offset: u64) -> u32 {
        // SAFETY: constructor validated the entire DCN mailbox register bank.
        unsafe { self.regs.read32(self.base + offset * 4) }
    }
    fn write_reg(&self, offset: u64, value: u32) {
        // SAFETY: constructor validated the register bank and caller owns DMUB.
        unsafe { self.regs.write32(self.base + offset * 4, value) };
    }
    fn read_slot(&self, offset: u64) -> [u8; 64] {
        let mut bytes = [0; 64];
        for (i, word) in bytes.chunks_exact_mut(4).enumerate() {
            // SAFETY: constructor/pointer checks bound this whole ring entry.
            word.copy_from_slice(&unsafe { self.fb.read32(offset + i as u64 * 4) }.to_le_bytes());
        }
        bytes
    }
    fn outbox(&mut self) -> Result<Option<[u8; 64]>, Error> {
        let write = self.reg(0x1de);
        if !valid_pointer(write, self.outbox_size) {
            self.poisoned = true;
            return Err(Error::Invalid);
        }
        if self.read == write {
            return Ok(None);
        }
        fence(Ordering::Acquire);
        let command = self.read_slot(self.outbox + self.read as u64);
        self.read = (self.read + 64) % self.outbox_size;
        fence(Ordering::Release);
        self.write_reg(0x1df, self.read);
        Ok(Some(command))
    }
    pub async fn command(&mut self, command: [u8; 64]) -> Result<[u8; 64], Error> {
        if self.poisoned {
            return Err(Error::NotReady);
        }
        if command[3] > 60 {
            return Err(Error::Invalid);
        }
        let next = (self.write + 64) % self.inbox_size;
        let read = self.reg(0x1d7);
        if !valid_pointer(read, self.inbox_size) {
            self.poisoned = true;
            return Err(Error::Invalid);
        }
        if next == read {
            return Err(Error::Busy);
        }
        let slot = self.inbox + self.write as u64;
        for (i, word) in command.chunks_exact(4).enumerate() {
            // SAFETY: driver owns the unposted slot; bounded mailbox mapping.
            unsafe {
                self.fb.write32(
                    slot + i as u64 * 4,
                    u32::from_le_bytes(word.try_into().unwrap()),
                )
            };
        }
        // Linux flushes the entire command from the WC framebuffer before
        // ringing WPTR. A CPU fence alone does not flush posted PCI writes.
        let _ = self.read_slot(slot);
        fence(Ordering::SeqCst);
        self.write = next;
        self.poisoned = true;
        self.write_reg(0x1d6, next);
        let deadline = narf_time::Deadline::after_ms(200);
        loop {
            let read = self.reg(0x1d7);
            if read == next {
                fence(Ordering::Acquire);
                let reply = self.read_slot(slot);
                if reply[0] != command[0] || reply[1] != command[1] || reply[3] != command[3] {
                    return Err(Error::Invalid);
                }
                self.poisoned = false;
                return Ok(reply);
            }
            if !valid_pointer(read, self.inbox_size) || deadline.expired() {
                self.poisoned = true;
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
    pub async fn enable_notifications(&mut self) -> Result<(), Error> {
        // Discard boot firmware's pending replies before the first request.
        for _ in 0..self.outbox_size / 64 {
            if self.outbox()?.is_none() {
                break;
            }
        }
        let mut command = header(71, 0, 4);
        command[4] = 1;
        self.command(command).await.map(|_| ())
    }
    pub async fn hpd(&mut self, instance: u8, channel: Channel) -> Result<bool, Error> {
        let mut command = header(82, 0, 12);
        command[4] = instance;
        command[8..12].copy_from_slice(&(channel as u32).to_le_bytes());
        let reply = self.command(command).await?;
        if reply[12..16] != [0; 4] {
            return Err(Error::Firmware(reply[12]));
        }
        Ok(reply[5] != 0)
    }
    /// Returns (is USB-C PHY, DP Alt disabled, four DP lanes).
    pub async fn typec_phy(&mut self, phy: u8) -> Result<(bool, bool, bool), Error> {
        let mut command = header(128, 26, 4);
        command[4] = phy;
        let reply = self.command(command).await?;
        if reply[2] & 1 == 0 {
            return Err(Error::Firmware(0xff));
        }
        Ok((reply[5] != 0, reply[6] != 0, reply[7] != 0))
    }
    pub async fn aux(
        &mut self,
        channel: Channel,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), Error> {
        let command = aux_command(channel, instance, action, address, data)?;
        self.command(command).await?;
        self.poisoned = true;
        let deadline = narf_time::Deadline::after_ms(200);
        loop {
            for _ in 0..32 {
                let Some(reply) = self.outbox()? else {
                    break;
                };
                if reply[0] != 1 || reply[8] != instance {
                    continue;
                }
                let result = aux_reply(&reply, action, data);
                if result != Err(Error::Invalid) {
                    self.poisoned = false;
                }
                return result;
            }
            if deadline.expired() {
                // AUX replies have no usable request ID. Never submit another
                // AUX after timeout and risk assigning this late reply to it.
                self.poisoned = true;
                return Err(Error::Timeout);
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_ms(1).as_instant()).await;
        }
    }
}
fn valid_pointer(value: u32, size: u32) -> bool {
    value < size && value % 64 == 0
}
fn mailbox_offset(
    offset: u64,
    base: u32,
    end: u64,
    ring: u32,
    size: u32,
    aperture: u64,
) -> Result<u64, Error> {
    if !(128..=16384).contains(&size)
        || size % 64 != 0
        || ring < base
        || ring as u64 + size as u64 > end
    {
        return Err(Error::Invalid);
    }
    let start = offset
        .checked_add((ring - base) as u64)
        .ok_or(Error::Invalid)?;
    if start
        .checked_add(size as u64)
        .is_none_or(|end| end > aperture)
    {
        return Err(Error::Invalid);
    }
    Ok(start)
}
fn header(kind: u8, sub: u8, length: u8) -> [u8; 64] {
    let mut command = [0; 64];
    command[0] = kind;
    command[1] = sub;
    command[3] = length;
    command
}
fn aux_command(
    channel: Channel,
    instance: u8,
    action: u8,
    address: u32,
    data: &[u8],
) -> Result<[u8; 64], Error> {
    if (data.is_empty() && action >= 0x80)
        || data.len() > 16
        || address > 0xfffff
        || !matches!(action, 0 | 0x10 | 0x20 | 0x40 | 0x50 | 0x60 | 0x80 | 0x90)
    {
        return Err(Error::Invalid);
    }
    let mut command = header(70, 0, 36);
    command[4] = instance;
    command[8..10].copy_from_slice(&4000u16.to_le_bytes());
    command[12..16].copy_from_slice(&(channel as u32).to_le_bytes());
    command[16] = u8::from(action < 0x80);
    command[17] = action;
    command[18] = data.len() as u8;
    command[20..24].copy_from_slice(&address.to_le_bytes());
    if action & 0x10 == 0 {
        command[24..24 + data.len()].copy_from_slice(data);
    }
    Ok(command)
}
fn aux_reply(reply: &[u8; 64], action: u8, data: &mut [u8]) -> Result<(), Error> {
    if reply[3] < 28 || reply[3] > 60 {
        return Err(Error::Invalid);
    }
    if reply[9] != 0 {
        return Err(Error::Firmware(reply[9]));
    }
    let status = if reply[12] & 0xf0 != 0 {
        reply[12] >> 4
    } else {
        reply[12] & 15
    };
    if status != 0 {
        return Err(Error::Aux(status));
    }
    let length = reply[13] as usize;
    if length > 16 || (action & 0x10 != 0 && length != data.len()) {
        return Err(Error::Invalid);
    }
    if action & 0x10 == 0 && length != 0 && (length != 1 || reply[16] as usize != data.len()) {
        return Err(Error::Invalid);
    }
    if action & 0x10 != 0 {
        data.copy_from_slice(&reply[16..16 + length]);
    }
    Ok(())
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn dmub_firmware_requires_exact_discovery_and_live_authority() -> TestResult {
        use crate::amdgpu::{ChipInfo, Family, AMD_VENDOR, PHOENIX_HAWKPOINT1};
        use crate::amdgpu_discovery::{IpBlock, HW_ID_DCN, MAX_BASE_ADDRS};
        let region = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let mut gpu = AmdGpu {
            fb_bar: region,
            regs: region,
            chip: ChipInfo {
                vid: AMD_VENDOR,
                did: PHOENIX_HAWKPOINT1,
                family: Family::Phoenix,
                asic: "phoenix",
                fw_name: "amdgpu/unused.bin",
                fw_list: &[],
            },
            vram: Default::default(),
            mode: None,
            fw_loaded: false,
            ip_blocks: alloc::vec![],
        };
        let (write, read) = narf_firmware::bootstrap_authority();
        write.revoke();
        if !matches!(Firmware::open(&gpu, &read), Err(FirmwareError::Unsupported)) {
            return TestResult::Fail("PCI family used as a substitute for DCN discovery");
        }
        let ip = IpBlock {
            hw_id: HW_ID_DCN,
            instance: 0,
            major: 3,
            minor: 1,
            revision: 4,
            sub_revision: 0,
            variant: 0,
            base_addrs: [0; MAX_BASE_ADDRS],
            num_bases: 3,
        };
        gpu.ip_blocks.push(ip);
        if !matches!(
            Firmware::open(&gpu, &read),
            Err(FirmwareError::Registry(
                narf_firmware::FirmwareError::AuthorityRevoked
            ))
        ) {
            return TestResult::Fail("firmware preparation ignored revoked registry authority");
        }
        gpu.ip_blocks.push(ip);
        if dcn314_ip(&gpu).is_ok() {
            return TestResult::Fail("ambiguous DCN discovery accepted");
        }
        gpu.ip_blocks.pop();
        gpu.ip_blocks[0].minor = 5;
        gpu.ip_blocks[0].revision = 0;
        if !matches!(Firmware::open(&gpu, &read), Err(FirmwareError::Unsupported)) {
            return TestResult::Fail("DCN35 used the DCN314 firmware path");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub",
        dmub_firmware_requires_exact_discovery_and_live_authority
    );

    fn dmub_mailbox_completion_wrap_and_cancel() -> TestResult {
        use core::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        let mut regs = alloc::vec![0u32; 0x201];
        let mut fb = alloc::vec![0u32; 64];
        let region = |ptr, len| MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: ptr,
            len,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        let reg = region(regs.as_mut_ptr() as u64, regs.len() as u64 * 4);
        let vram = region(fb.as_mut_ptr() as u64, fb.len() as u64 * 4);
        let mut dmub = Dmub {
            regs: reg,
            fb: vram,
            base: 0,
            inbox: 0,
            outbox: 128,
            inbox_size: 128,
            outbox_size: 128,
            write: 0,
            read: 0,
            poisoned: false,
        };
        let mut cx = Context::from_waker(Waker::noop());
        for next in [64u32, 0, 64] {
            let slot = dmub.write as u64;
            let mut request = alloc::boxed::Box::pin(dmub.hpd(2, Channel::Dpia));
            if !matches!(request.as_mut().poll(&mut cx), Poll::Pending) {
                return TestResult::Fail("command completed before firmware consumed it");
            }
            // SAFETY: model-owned register/VRAM arrays outlive the transport.
            unsafe {
                if reg.read32(0x1d6 * 4) != next
                    || vram.read32(slot) != u32::from_le_bytes([82, 0, 0, 12])
                {
                    return TestResult::Fail("posted DMUB command/doorbell ABI");
                }
                vram.write32(slot + 4, 2 | (1 << 8));
                reg.write32(0x1d7 * 4, next);
            }
            if narf_scheduler::block_on_spin(request) != Ok(true) {
                return TestResult::Fail("completed HPD response or mailbox wrap");
            }
        }
        let mut request = alloc::boxed::Box::pin(dmub.hpd(2, Channel::Dpia));
        if !matches!(request.as_mut().poll(&mut cx), Poll::Pending) {
            return TestResult::Fail("pending cancellation setup");
        }
        drop(request);
        if narf_scheduler::block_on_spin(dmub.hpd(2, Channel::Dpia)) != Err(Error::NotReady) {
            return TestResult::Fail("cancelled request permitted stale-reply reuse");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu-dmub",
        dmub_mailbox_completion_wrap_and_cancel
    );
    fn dmub_aux_abi_and_reply_validation() -> TestResult {
        let c = aux_command(Channel::Dpia, 3, 0x90, 0x202, &[0; 6]).unwrap();
        if c[..4] != [70, 0, 0, 36]
            || c[4] != 3
            || c[12] != 1
            || c[17] != 0x90
            || c[18] != 6
            || c[20..24] != [2, 2, 0, 0]
        {
            return TestResult::Fail("DMUB AUX wire ABI");
        }
        let mut reply = header(1, 0, 28);
        reply[13] = 6;
        reply[16..22].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        let mut out = [0; 6];
        if aux_reply(&reply, 0x90, &mut out).is_err() || out != [1, 2, 3, 4, 5, 6] {
            return TestResult::Fail("AUX reply payload");
        }
        reply[13] = 17;
        if aux_reply(&reply, 0x90, &mut out).is_ok()
            || aux_command(Channel::Dpia, 0, 0x90, 0x100000, &[0]).is_ok()
        {
            return TestResult::Fail("AUX bounds");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu-dmub", dmub_aux_abi_and_reply_validation);
    fn dmub_mailbox_bounds() -> TestResult {
        if mailbox_offset(4096, 0x4000000, 0x4004000, 0x4002000, 8192, 65536) != Ok(12288)
            || mailbox_offset(0, 100, 1000, 0, 128, 4096).is_ok()
            || mailbox_offset(u64::MAX, 0, 16384, 0, 8192, u64::MAX).is_ok()
            || valid_pointer(8192, 8192)
            || valid_pointer(3, 8192)
        {
            return TestResult::Fail("untrusted ring range/pointer accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/amdgpu-dmub", dmub_mailbox_bounds);
}
