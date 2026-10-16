//! Retained CONNAC2 firmware transport, adapted from local Linux ecd997b0189a:
//! mt76_connac_mcu.{c,h}, mt7921/{pci,pci_mcu,mcu}.c and mt792x_dma.c.
//! This boots ROM patch + WM only; association and data queues are separate.
use super::fwdl;
use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{future::poll_fn, ops::Range, task::Poll};

#[cfg(target_arch = "x86_64")]
#[path = "firmware_transport_hw.rs"]
mod hardware;
#[cfg(target_arch = "x86_64")]
pub use hardware::Transport;

#[cfg(target_arch = "x86_64")]
static BOOT_OWNER: narf_lib::mutex::Mutex<Option<Transport>> = narf_lib::mutex::Mutex::new(None);

/// Boot-only retained transport diagnostics, independent of radio readiness.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootStatus {
    Absent,
    Running,
    Retained(State),
}

/// Inspect without waiting on the boot runner's owner lock.
#[cfg(target_arch = "x86_64")]
pub fn boot_status() -> BootStatus {
    match BOOT_OWNER.try_lock() {
        None => BootStatus::Running,
        Some(owner) => owner.as_ref().map_or(BootStatus::Absent, |owner| {
            BootStatus::Retained(owner.state())
        }),
    }
}

#[cfg(target_arch = "x86_64")]
pub(super) fn start_boot() -> narf_init::InitResult {
    use core::fmt::Write;
    use narf_init::InitResult;
    let Some(mut owner) = BOOT_OWNER.try_lock() else {
        return InitResult::Error("MT76 owner busy");
    };
    if owner.is_some() {
        return InitResult::Error("MT76 firmware already attempted");
    }
    match super::pci::claim_firmware_transport() {
        Ok(None) => return InitResult::NotPresent,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "mt76: firmware preparation refused: {error:?}"
            );
            return InitResult::Error("MT76 firmware preflight");
        }
        Ok(Some(transport)) => *owner = Some(transport),
    }
    let Some(transport) = owner.as_mut() else {
        return InitResult::Error("MT76 owner missing");
    };
    // Before executor polling, regular Mutex (no IRQ spinlock) retained.
    // This future is self-waking and never depends on another executor task.
    let result = narf_scheduler::block_on_spin(transport.run());
    let _ = writeln!(
        narf_console::Writer,
        "mt76: firmware {result:?}; retained {:?}; WLAN data path not enabled",
        transport.state()
    );
    if result.is_ok() {
        InitResult::Ok
    } else {
        InitResult::Error("MT76 firmware startup (owner retained)")
    }
}

const COMMAND_HEADER: usize = 64;
const MAX_FRAME: usize = 4096;
const TIMEOUT_MS: u64 = 3000;
const MAX_EVENTS: usize = 32;
const MAX_IMAGE: usize = 16 * 1024 * 1024;

// Shared by the physical backend and cancellation models. A published owner
// cannot infer device quiescence from Rust future/owner lifetime alone.
#[derive(Debug)]
struct Retained<T> {
    storage: Option<T>,
    published: bool,
}
impl<T> Drop for Retained<T> {
    fn drop(&mut self) {
        if self.published {
            if let Some(storage) = self.storage.take() {
                core::mem::forget(storage);
            }
        }
    }
}

/// Firmware/transport failure. A started failure cannot be replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    InvalidFirmware,
    UnsupportedFirmware,
    Allocation,
    DmaAddress,
    Authority,
    Bounds,
    DeviceGone,
    Register,
    Timeout,
    Ring,
    MalformedEvent,
    EventOverflow,
    Rejected(u8),
}
/// Last operation reached by a single firmware boot attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Quiesce,
    Initialize,
    DriverOwn,
    Restart,
    RomReady,
    PatchSemaphore,
    PatchDownload,
    PatchFinish,
    PatchRelease,
    RamDownload,
    StartFirmware,
    FirmwareReady,
    Shutdown,
}
/// Firmware observations, not an operational WLAN interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub version: [u8; 10],
    pub build_date: [u8; 15],
    pub patch_already_loaded: bool,
    pub bytes_transferred: usize,
}
/// Session state survives cancellation of its borrowed run future.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Running(Stage),
    Ready(Report),
    Failed { stage: Stage, error: Error },
    Stopped,
}
#[derive(Clone, Debug)]
struct Region {
    addr: u32,
    mode: u32,
    bytes: Range<usize>,
}
/// Owned, fully validated firmware; preparation performs no device writes.
#[derive(Clone, Debug)]
pub struct Firmware {
    patch: Arc<[u8]>,
    ram: Arc<[u8]>,
    patch_regions: Vec<Region>,
    ram_regions: Vec<Region>,
    version: [u8; 10],
    build_date: [u8; 15],
    override_addr: u32,
}
impl Firmware {
    /// Validate every table, range and mode before any firmware command.
    pub fn prepare(patch: &[u8], ram: &[u8]) -> Result<Self, Error> {
        if patch.len() > MAX_IMAGE || ram.len() > MAX_IMAGE {
            return Err(Error::InvalidFirmware);
        }
        let hdr = fwdl::parse_patch_header(patch).map_err(|_| Error::InvalidFirmware)?;
        let table_end = (hdr.n_region as usize)
            .checked_mul(fwdl::PATCH_SEC_SIZE)
            .and_then(|size| size.checked_add(fwdl::PATCH_HDR_SIZE))
            .ok_or(Error::InvalidFirmware)?;
        if hdr.n_region == 0 || hdr.n_region > 64 || table_end > patch.len() {
            return Err(Error::InvalidFirmware);
        }
        let mut patch_regions = Vec::new();
        for region in fwdl::iter_patch_sections(patch, &hdr).map_err(|_| Error::InvalidFirmware)? {
            let region = region.map_err(|_| Error::InvalidFirmware)?;
            let start = region.offset as usize;
            let end = start
                .checked_add(region.len as usize)
                .ok_or(Error::InvalidFirmware)?;
            if start < table_end
                || end > patch.len()
                || region.len == 0
                || region.len > region.size
                || region.addr.checked_add(region.len).is_none()
            {
                return Err(Error::InvalidFirmware);
            }
            let info = region.sec_key_idx;
            let mode = if info == u32::MAX {
                1 << 31
            } else {
                match info >> 24 {
                    0 => 1 << 31,
                    1 => (1 << 31) | 1 | 8 | ((info & 3) << 1),
                    2 => (1 << 31) | 1 | 8 | 64,
                    _ => return Err(Error::UnsupportedFirmware),
                }
            };
            patch_regions.push(Region {
                addr: region.addr,
                mode,
                bytes: start..end,
            });
        }
        let tail = fwdl::parse_fw_trailer(ram).map_err(|_| Error::InvalidFirmware)?;
        let end = ram
            .len()
            .checked_sub(fwdl::FW_TRAILER_SIZE + usize::from(tail.n_region) * fwdl::FW_REGION_SIZE)
            .ok_or(Error::InvalidFirmware)?;
        if tail.n_region == 0 || tail.n_region > 64 {
            return Err(Error::InvalidFirmware);
        }
        let mut offset = 0usize;
        let mut ram_regions = Vec::new();
        let mut override_addr = 0;
        for region in fwdl::iter_fw_regions(ram, &tail).map_err(|_| Error::InvalidFirmware)? {
            let region = region.map_err(|_| Error::InvalidFirmware)?;
            let next = offset
                .checked_add(region.len as usize)
                .ok_or(Error::InvalidFirmware)?;
            if next > end || region.addr.checked_add(region.len).is_none() {
                return Err(Error::InvalidFirmware);
            }
            if region.feature_set & !0x77 != 0
                || region.decomp_len != 0
                || region.decomp_blk_sz != 0
            {
                return Err(Error::UnsupportedFirmware);
            }
            if region.feature_set & 64 == 0 {
                if region.len == 0 {
                    return Err(Error::InvalidFirmware);
                }
                if region.feature_set & 32 != 0 {
                    override_addr = region.addr;
                }
                let mode = (1 << 31)
                    | u32::from(region.feature_set & 6)
                    | if region.feature_set & 1 != 0 { 9 } else { 0 }
                    | if region.feature_set & 16 != 0 { 64 } else { 0 };
                ram_regions.push(Region {
                    addr: region.addr,
                    mode,
                    bytes: offset..next,
                });
            }
            offset = next;
        }
        if ram_regions.is_empty() {
            return Err(Error::InvalidFirmware);
        }
        Ok(Self {
            patch: patch.into(),
            ram: ram.into(),
            patch_regions,
            ram_regions,
            version: tail.fw_ver,
            build_date: tail.build_date,
            override_addr,
        })
    }
    /// Copy verified registry payloads into this session's immutable ownership.
    pub fn open(
        did: u16,
        auth: &narf_capabilities::Cap<narf_firmware::FirmwareRegistry, narf_capabilities::Read>,
    ) -> Result<Self, Error> {
        let (patch, ram) = super::pci::firmware_blobs_for(did);
        let p = narf_firmware::open(patch, auth).map_err(|_| Error::InvalidFirmware)?;
        let r = narf_firmware::open(ram, auth).map_err(|_| Error::InvalidFirmware)?;
        let p = narf_firmware::view_of(&p).map_err(|_| Error::Authority)?;
        let r = narf_firmware::view_of(&r).map_err(|_| Error::Authority)?;
        Self::prepare(p.bytes, r.bytes)
    }
}

fn command_frame(command: u8, seq: u8, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if seq == 0 || seq > 15 || payload.len() > MAX_FRAME - COMMAND_HEADER {
        return Err(Error::Bounds);
    }
    let mut frame = vec![0; COMMAND_HEADER + payload.len()];
    let len = frame.len();
    frame[..4].copy_from_slice(&((len as u32) | (2 << 23) | (0x20 << 25)).to_le_bytes());
    frame[4..8].copy_from_slice(&((1u32 << 31) | (1 << 16)).to_le_bytes());
    frame[32..34].copy_from_slice(&((len - 32) as u16).to_le_bytes());
    frame[34..36].copy_from_slice(&0x8000u16.to_le_bytes());
    frame[36] = command;
    frame[37] = 0xa0;
    frame[38] = 3;
    frame[39] = seq;
    frame[COMMAND_HEADER..].copy_from_slice(payload);
    Ok(frame)
}

trait Backend {
    fn progress(&mut self, _stage: Stage) {}
    fn now_ns(&self) -> u64;
    fn check(&self) -> Result<(), Error>;
    fn quiesce(&mut self) -> Result<(), Error>;
    fn idle(&mut self) -> Result<bool, Error>;
    fn initialize(&mut self) -> Result<(), Error>;
    fn request_driver_own(&mut self) -> Result<(), Error>;
    fn driver_owned(&mut self) -> Result<bool, Error>;
    fn fw_state(&mut self) -> Result<u32, Error>;
    fn submit(&mut self, scatter: bool, frame: &[u8]) -> Result<(), Error>;
    fn tx_complete(&mut self, scatter: bool) -> Result<bool, Error>;
    fn receive(&mut self) -> Result<Option<Vec<u8>>, Error>;
    fn release(&mut self) -> Result<(), Error>;
}
#[derive(Debug)]
struct Session<B: Backend> {
    backend: B,
    firmware: Firmware,
    state: State,
    seq: u8,
    events: VecDeque<Vec<u8>>,
    transferred: usize,
    boot_started: Option<u64>,
}
impl<B: Backend> Session<B> {
    fn new(backend: B, firmware: Firmware) -> Self {
        Self {
            backend,
            firmware,
            state: State::Prepared,
            seq: 0,
            events: VecDeque::new(),
            transferred: 0,
            boot_started: None,
        }
    }
    fn stage(&mut self, stage: Stage) {
        self.state = State::Running(stage);
        self.backend.progress(stage);
    }
    async fn wait<T>(
        &mut self,
        ms: u64,
        mut f: impl FnMut(&mut B) -> Result<Option<T>, Error>,
    ) -> Result<T, Error> {
        let start = self.backend.now_ns();
        poll_fn(|cx| {
            if let Err(error) = self.backend.check() {
                return Poll::Ready(Err(error));
            }
            let now = self.backend.now_ns();
            if self
                .boot_started
                .is_some_and(|began| now.saturating_sub(began) >= 30_000_000_000)
                || now.saturating_sub(start) >= ms * 1_000_000
            {
                return Poll::Ready(Err(Error::Timeout));
            }
            match f(&mut self.backend) {
                Ok(Some(value)) => Poll::Ready(Ok(value)),
                Err(error) => Poll::Ready(Err(error)),
                Ok(None) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        })
        .await
    }
    async fn send(&mut self, scatter: bool, frame: &[u8]) -> Result<(), Error> {
        self.backend.check()?;
        if self
            .boot_started
            .is_some_and(|began| self.backend.now_ns().saturating_sub(began) >= 30_000_000_000)
        {
            return Err(Error::Timeout);
        }
        self.backend.submit(scatter, frame)?;
        self.wait(TIMEOUT_MS, |backend| {
            backend.tx_complete(scatter).map(|done| done.then_some(()))
        })
        .await
    }
    async fn command(&mut self, cmd: u8, body: &[u8], response: bool) -> Result<u8, Error> {
        self.seq = self.seq % 15 + 1;
        let seq = self.seq;
        let frame = command_frame(cmd, seq, body)?;
        self.send(false, &frame).await?;
        if !response {
            return Ok(0);
        }
        let start = self.backend.now_ns();
        loop {
            let remaining = (TIMEOUT_MS * 1_000_000)
                .saturating_sub(self.backend.now_ns().saturating_sub(start));
            if remaining < 1_000_000 {
                return Err(Error::Timeout);
            }
            let event = self.wait(remaining / 1_000_000, Backend::receive).await?;
            if event.len() < 32 {
                return Err(Error::MalformedEvent);
            }
            let size = usize::from(u16::from_le_bytes([event[24], event[25]]));
            if size < 8 || size + 24 > event.len() {
                return Err(Error::MalformedEvent);
            }
            if event[29] != seq || event[30] & 4 != 0 {
                if self.events.len() == MAX_EVENTS {
                    return Err(Error::EventOverflow);
                }
                self.events.push_back(event);
                continue;
            }
            if cmd == 0x10 || cmd == 0x07 {
                if !matches!(event[28], 1 | 4) || size + 24 < 33 {
                    return Err(Error::MalformedEvent);
                }
                return Ok(event[32]);
            }
            if size < 12 || event[28] != 1 {
                return Err(Error::MalformedEvent);
            }
            return Ok(0);
        }
    }
    async fn download(&mut self, source: &[u8], region: &Region) -> Result<(), Error> {
        let mut body = [0; 12];
        fwdl::encode_target_address_len_req(
            region.addr,
            region.bytes.len() as u32,
            region.mode,
            &mut body,
        )
        .ok_or(Error::Bounds)?;
        let cmd = if matches!(region.addr, 0x200000 | 0x900000) {
            5
        } else {
            1
        };
        self.command(cmd, &body, true).await?;
        for chunk in source[region.bytes.clone()].chunks(MAX_FRAME) {
            self.seq = self.seq % 15 + 1; // Linux advances even for headerless FW_SCATTER.
            self.send(true, chunk).await?;
            self.transferred += chunk.len();
        }
        Ok(())
    }
    async fn run(&mut self) -> Result<Report, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.boot_started = Some(self.backend.now_ns());
        let result = self.boot().await;
        match result {
            Ok(report) => {
                self.state = State::Ready(report);
                Ok(report)
            }
            Err(error) => {
                let stage = match self.state {
                    State::Running(stage) => stage,
                    _ => Stage::Initialize,
                };
                self.state = State::Failed { stage, error };
                Err(error)
            }
        }
    }
    async fn boot(&mut self) -> Result<Report, Error> {
        self.stage(Stage::Quiesce);
        self.backend.check()?;
        self.backend.quiesce()?;
        self.wait(100, |b| b.idle().map(|idle| idle.then_some(())))
            .await?;
        self.stage(Stage::Initialize);
        self.backend.initialize()?;
        self.stage(Stage::DriverOwn);
        self.backend.request_driver_own()?;
        self.wait(500, |b| b.driver_owned().map(|ready| ready.then_some(())))
            .await?;
        self.stage(Stage::Restart);
        self.command(4, &[1, 0, 0, 0], false).await?;
        self.stage(Stage::RomReady);
        self.wait(1000, |b| {
            b.fw_state().map(|state| (state & 7 == 1).then_some(()))
        })
        .await?;
        self.stage(Stage::PatchSemaphore);
        let sem = self.command(0x10, &1u32.to_le_bytes(), true).await?;
        let patch_already_loaded = sem == 1;
        if sem != 1 && sem != 2 {
            return Err(Error::Rejected(sem));
        }
        // Clone immutable ownership so no blob borrow spans a mutable session borrow.
        let firmware = self.firmware.clone();
        if !patch_already_loaded {
            self.stage(Stage::PatchDownload);
            for region in &firmware.patch_regions {
                self.download(&firmware.patch, region).await?;
            }
            self.stage(Stage::PatchFinish);
            let status = self.command(7, &[0; 4], true).await?;
            if status != 0 {
                return Err(Error::Rejected(status));
            }
            self.stage(Stage::PatchRelease);
            let status = self.command(0x10, &0u32.to_le_bytes(), true).await?;
            if status != 3 {
                return Err(Error::Rejected(status));
            }
        }
        self.stage(Stage::RamDownload);
        for region in &firmware.ram_regions {
            self.download(&firmware.ram, region).await?;
        }
        self.stage(Stage::StartFirmware);
        let mut body = [0; 8];
        fwdl::encode_fw_start_req(
            u32::from(firmware.override_addr != 0),
            firmware.override_addr,
            &mut body,
        )
        .ok_or(Error::Bounds)?;
        self.command(2, &body, true).await?;
        self.stage(Stage::FirmwareReady);
        self.wait(1500, |b| {
            b.fw_state().map(|state| (state & 3 == 3).then_some(()))
        })
        .await?;
        Ok(Report {
            version: firmware.version,
            build_date: firmware.build_date,
            patch_already_loaded,
            bytes_transferred: self.transferred,
        })
    }
    async fn shutdown(&mut self) -> Result<(), Error> {
        if self.state == State::Stopped {
            return Ok(());
        }
        self.boot_started = None;
        self.stage(Stage::Shutdown);
        let result = async {
            self.backend.check()?;
            self.backend.quiesce()?;
            self.wait(100, |b| b.idle().map(|idle| idle.then_some(())))
                .await?;
            self.backend.release()
        }
        .await;
        match result {
            Ok(()) => {
                self.state = State::Stopped;
                Ok(())
            }
            Err(error) => {
                self.state = State::Failed {
                    stage: Stage::Shutdown,
                    error,
                };
                Err(error)
            }
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[path = "firmware_transport_tests.rs"]
mod tests;
