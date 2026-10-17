//! Persistent boot log on the FAT boot medium.
//!
//! NARF has no log that survives a reboot, so a bare-metal boot without a
//! serial port loses everything that scrolled off the screen. With
//! `narf.bootlog=<token>` on the command line, this module saves the kernel
//! log store (`narf_console::klog`) to `/narf-boot-<n>.log` on the USB stick
//! the machine booted from, so it can be read back under another OS.
//!
//! Safety of the user's disks is the overriding rule:
//!
//! - Only USB mass-storage block devices (`usb-msc*`) are ever candidates.
//!   Internal NVMe/SATA/SD disks are never opened by this module, not even
//!   for reading.
//! - The candidate must hold a FAT filesystem whose root carries
//!   [`MARKER_FILE`] containing exactly the command-line token. The image
//!   recipe writes both the marker and the `limine.conf` cmdline onto the
//!   same ESP, so a match positively identifies the medium NARF booted from.
//! - Each boot creates one new file and only ever appends to it, at most
//!   [`MAX_LOG_BYTES`]; at most [`MAX_LOGS`] files are created per medium.
//!   Nothing else on the volume is written except the FAT metadata the new
//!   file needs.
//! - Absent `narf.bootlog=` (or `narf.bootlog=off`) the module does nothing.
//!
//! Timing. The stick is only bound once the USB supervisor task runs, which
//! is after the last boot initcall (the discrete-GPU firmware handoff
//! included). Everything logged before that is still in the log store and is
//! written retroactively on arming. A hang *before* the executor starts is
//! therefore not captured; the screen remains the log for that window.
//! After arming the log is flushed every [`EARLY_FLUSH_MS`] for the first
//! [`EARLY_WINDOW_MS`], then every [`LATE_FLUSH_MS`]. The panic report and a
//! deliberate reboot/power-off get one final bounded flush through
//! `narf_console::set_persist_hook`; a fatal CPU exception (the TCB trap
//! printer) does not.

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_block::BlockDevice;
use narf_filesystem::{FileOps, FsError, FsInstance};
use narf_lib::sync::IrqSafeSpinLock;

use crate::volume::FatVolume;

/// Kernel argument: `narf.bootlog=<token>` enables, `off` (or absence)
/// disables.
pub const ARG: &str = "narf.bootlog";
/// Test-only kernel argument: `narf.bootlog.selftest=panic` panics right
/// after the first flush, to exercise the panic-path flush.
pub const SELFTEST_ARG: &str = "narf.bootlog.selftest";
/// Root-directory marker file holding the token (8.3 name: no LFN needed).
pub const MARKER_FILE: &str = "NARFLOG.ID";
/// Per-boot file size bound, header and truncation note included.
pub const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
/// Highest `<n>` in `narf-boot-<n>.log`; beyond it the medium is full.
pub const MAX_LOGS: u32 = 32;
/// Token length bounds (inclusive).
pub const TOKEN_MIN: usize = 8;
pub const TOKEN_MAX: usize = 64;
/// How long to keep looking for the boot medium after the task starts.
pub const DISCOVERY_MS: u64 = 120_000;
/// Poll period while looking for the medium.
const DISCOVERY_POLL_MS: u64 = 250;
/// Flush period right after arming, and how long that window lasts.
pub const EARLY_FLUSH_MS: u64 = 1_000;
pub const EARLY_WINDOW_MS: u64 = 60_000;
/// Flush period afterwards.
pub const LATE_FLUSH_MS: u64 = 5_000;
/// Bytes exported from the log store per file write.
const CHUNK: usize = 16 * 1024;
/// Upper bound on one final (panic/reboot) flush.
const FINAL_FLUSH_MS: u64 = 3_000;
/// Consecutive write failures before the session is abandoned.
const MAX_WRITE_FAILURES: u32 = 3;
/// Appended once when [`MAX_LOG_BYTES`] is reached.
const CAP_NOTE: &[u8] = b"\n[bootlog: size limit reached; later lines were not saved]\n";

/// Parsed `narf.bootlog=` value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Config {
    Disabled,
    Enabled { token: String },
}

/// Parse the `narf.bootlog=` value. A malformed token is an error rather
/// than "disabled", so a typo is visible on the console.
pub fn parse_config(value: Option<&str>) -> Result<Config, &'static str> {
    let Some(value) = value else {
        return Ok(Config::Disabled);
    };
    if value.eq_ignore_ascii_case("off") || value == "0" {
        return Ok(Config::Disabled);
    }
    if !(TOKEN_MIN..=TOKEN_MAX).contains(&value.len()) {
        return Err("token must be 8..=64 characters");
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("token may only hold [A-Za-z0-9_-]");
    }
    Ok(Config::Enabled {
        token: String::from(value),
    })
}

/// Only USB mass-storage devices (whole disk or partition) are candidates.
pub fn candidate_allowed(device_name: &str) -> bool {
    device_name.starts_with("usb-msc")
}

/// The marker's first line, trimmed, must equal the token exactly.
pub fn marker_matches(contents: &[u8], token: &str) -> bool {
    let line = contents
        .split(|&b| b == b'\n' || b == b'\r')
        .next()
        .unwrap_or(&[]);
    let line = core::str::from_utf8(line).unwrap_or("").trim();
    !token.is_empty() && line == token
}

/// `<n>` of a `narf-boot-<n>.log` name (case-insensitive, as FAT is).
pub fn log_index(name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    let digits = lower.strip_prefix("narf-boot-")?.strip_suffix(".log")?;
    if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The next free index after every existing log, or `None` when that would
/// exceed [`MAX_LOGS`].
pub fn next_log_index<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<u32> {
    let last = names.into_iter().filter_map(log_index).max().unwrap_or(0);
    let next = last.checked_add(1)?;
    (next <= MAX_LOGS).then_some(next)
}

/// File name for index `n`.
pub fn log_name(n: u32) -> String {
    format!("narf-boot-{n}.log")
}

/// Why a medium could not be armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Fs(FsError),
    /// [`MAX_LOGS`] files already exist; delete old logs to continue.
    TooManyLogs,
}

impl From<FsError> for Error {
    fn from(error: FsError) -> Self {
        Self::Fs(error)
    }
}

/// One boot's append-only log file.
pub struct Session {
    file: Arc<dyn FileOps>,
    /// `<n>` of the file.
    pub index: u32,
    offset: u64,
    cap: u64,
    full: bool,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("index", &self.index)
            .field("offset", &self.offset)
            .field("cap", &self.cap)
            .field("full", &self.full)
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Bytes written so far.
    pub fn len(&self) -> u64 {
        self.offset
    }

    /// True before anything has been written.
    pub fn is_empty(&self) -> bool {
        self.offset == 0
    }

    /// True once the size bound has been reached.
    pub fn is_full(&self) -> bool {
        self.full
    }

    /// Append `bytes`, honouring the size bound: the part that does not fit
    /// is dropped and [`CAP_NOTE`] written once in its place. Returns the
    /// number of `bytes` consumed (all of them, also when dropped).
    pub async fn append(&mut self, bytes: &[u8]) -> Result<usize, FsError> {
        if self.full || bytes.is_empty() {
            return Ok(bytes.len());
        }
        let note = CAP_NOTE.len() as u64;
        let room = self.cap.saturating_sub(self.offset).saturating_sub(note);
        let take = (bytes.len() as u64).min(room) as usize;
        if take > 0 {
            self.write_all(&bytes[..take]).await?;
        }
        if take < bytes.len() {
            self.write_all(CAP_NOTE).await?;
            self.full = true;
        }
        Ok(bytes.len())
    }

    async fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), FsError> {
        while !bytes.is_empty() {
            let n = self.file.write(self.offset, bytes).await?;
            if n == 0 {
                return Err(FsError::NoSpace);
            }
            self.offset += n as u64;
            bytes = &bytes[n..];
        }
        Ok(())
    }
}

/// Every root-directory name on `volume`.
async fn root_names<B: BlockDevice + 'static>(
    volume: &Arc<FatVolume<B>>,
) -> Result<Vec<String>, FsError> {
    let root = volume.root();
    let mut names = Vec::new();
    // A FAT32 root may hold any number of entries; bound the walk anyway.
    for _ in 0..256 {
        let page = root.enumerate_async(names.len(), 64).await?;
        if page.is_empty() {
            break;
        }
        names.extend(page.into_iter().map(|(name, _)| name));
    }
    Ok(names)
}

/// True when `volume`'s root carries [`MARKER_FILE`] holding `token`. Reads
/// only; this is how the boot medium is positively identified.
pub async fn marker_present<B: BlockDevice + 'static>(
    volume: &Arc<FatVolume<B>>,
    token: &str,
) -> Result<bool, FsError> {
    let root = volume.root();
    let marker = match root.lookup_async(MARKER_FILE).await {
        Ok(marker) => marker,
        Err(FsError::NotFound) => return Ok(false),
        Err(error) => return Err(error),
    };
    let mut contents = [0u8; TOKEN_MAX + 8];
    let n = marker.read(0, &mut contents).await?;
    Ok(marker_matches(&contents[..n], token))
}

/// Check `volume` for the boot-medium marker and, when it matches, create
/// the next log file (header written). `Ok(None)`: not the boot medium.
pub async fn open_session<B: BlockDevice + 'static>(
    volume: &Arc<FatVolume<B>>,
    token: &str,
    cap: u64,
    header: &[u8],
) -> Result<Option<Session>, Error> {
    let root = volume.root();
    if !marker_present(volume, token).await? {
        return Ok(None);
    }
    let names = root_names(volume).await?;
    let index = next_log_index(names.iter().map(String::as_str)).ok_or(Error::TooManyLogs)?;
    let file = root.create(&log_name(index)).await?;
    let mut session = Session {
        file,
        index,
        offset: 0,
        cap,
        full: false,
    };
    session.append(header).await?;
    Ok(Some(session))
}

// ── Live boot session ────────────────────────────────────────────────

/// The armed session plus the next log-store record to export. Taken out
/// while a flush runs so no lock is held across an `.await`.
struct Live {
    session: Session,
    cursor: u64,
    device: &'static str,
}

static LIVE: IrqSafeSpinLock<Option<Live>> = IrqSafeSpinLock::new(None);
/// One flush at a time: the periodic task, the panic path and reboot.
static FLUSHING: AtomicBool = AtomicBool::new(false);

struct FlushGuard;

impl FlushGuard {
    fn acquire() -> Option<Self> {
        FLUSHING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for FlushGuard {
    fn drop(&mut self) {
        FLUSHING.store(false, Ordering::Release);
    }
}

/// Export every pending record (plus `extra`) to the live session.
/// `wait == false` never spins on the log-store lock. Returns bytes written,
/// or `None` when no session is live or another flush is running.
async fn flush_live(wait: bool, extra: Option<&[u8]>) -> Option<Result<usize, FsError>> {
    let _guard = FlushGuard::acquire()?;
    let mut live = LIVE.try_lock()?.take()?;
    let mut written = 0usize;
    let mut result = Ok(());
    while !live.session.is_full() {
        let Some(chunk) = narf_console::klog::export_since(live.cursor, CHUNK, wait) else {
            break;
        };
        if chunk.next_seq == live.cursor {
            break;
        }
        if chunk.lost != 0 {
            let note = format!(
                "[bootlog: {} log records were overwritten before they could be saved; \
                 boot with a larger log_buf_len=]\n",
                chunk.lost
            );
            if let Err(error) = live.session.append(note.as_bytes()).await {
                result = Err(error);
                break;
            }
        }
        if let Err(error) = live.session.append(&chunk.text).await {
            result = Err(error);
            break;
        }
        written += chunk.text.len();
        live.cursor = chunk.next_seq;
    }
    if let (Ok(()), Some(extra)) = (&result, extra) {
        result = live.session.append(extra).await.map(|_| ());
        written += extra.len();
    }
    *LIVE.lock() = Some(live);
    Some(result.map(|()| written))
}

/// Poll `fut` with a no-op waker until it completes or `deadline` passes.
/// For the final-flush paths, which cannot rely on the executor or on
/// interrupts; the storage futures they drive are self-polling.
fn poll_bounded<F: core::future::Future>(
    fut: F,
    deadline: narf_time::Deadline,
) -> Option<F::Output> {
    use core::pin::pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    fn clone(_: *const ()) -> RawWaker {
        raw()
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: every vtable entry is a no-op that never reads the (null) data
    // pointer, and clone returns another such waker.
    let waker = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
        if deadline.expired() {
            return None;
        }
        core::hint::spin_loop();
    }
}

/// `narf_console::PersistHook`: final bounded flush on panic (with the
/// panic report) and before a deliberate reboot/power-off.
fn persist_hook(msg: Option<&[u8]>) {
    let deadline = narf_time::Deadline::after_ms(FINAL_FLUSH_MS);
    let extra: &[u8] = msg.unwrap_or(b"[bootlog: final flush before reboot/power-off]\n");
    // Never spin on the log-store lock from the panic path.
    let _ = poll_bounded(flush_live(msg.is_none(), Some(extra)), deadline);
}

/// Mount `dev` privately (never in the VFS) and try to arm it.
///
/// The mount and the marker check only read. Under `narf.disks=boot-only`
/// the device is read-only at the block layer until the marker matches;
/// only then is its disk recorded as the boot medium
/// ([`narf_block::disk_policy::trust_boot_medium`]) and the log file
/// created.
async fn probe(
    name: &'static str,
    disk: narf_block::disk_policy::DiskId,
    dev: Arc<dyn narf_block::BlockDeviceSync>,
    token: &str,
    header: &[u8],
) -> Result<Option<Session>, Error> {
    use narf_block::fs_detect::{detect_filesystem, FsType};
    if !matches!(detect_filesystem(&dev), Ok(Some(FsType::Fat))) {
        return Ok(None);
    }
    let volume = FatVolume::mount(
        narf_block::SyncBlock::new(dev),
        narf_lib::id::DomainId::DRIVER_0,
    )
    .await?;
    if !marker_present(&volume, token).await? {
        return Ok(None);
    }
    narf_block::disk_policy::trust_boot_medium(name, disk);
    open_session(&volume, token, MAX_LOG_BYTES, header).await
}

async fn sleep_ms(ms: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(ms).as_instant()).await;
}

fn header() -> Vec<u8> {
    let mut header = String::new();
    let _ = writeln!(
        header,
        "NARF persistent boot log ({}). Times are seconds since boot.",
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(header, "cmdline: {}", narf_boot::cmdline());
    header.into_bytes()
}

/// Upper bound on waiting for the root mount before probing (root policies).
const ROOT_SETTLE_MS: u64 = 300_000;

async fn run(token: String) {
    use narf_console::Writer;
    let header = header();
    // Under `narf.disks=root-ro|root-rw`, probe the stick only once the root
    // is mounted (or has failed): the root mount reads every disk to prove
    // its UUID unique, and must not queue behind the stick's FAT mount. The
    // log is written retroactively, so nothing is lost by waiting.
    if narf_block::disk_policy::policy().is_root_policy() {
        let settle = narf_time::Deadline::after_ms(ROOT_SETTLE_MS);
        while !narf_block::disk_policy::root_mount_settled() && !settle.expired() {
            sleep_ms(DISCOVERY_POLL_MS).await;
        }
    }
    let deadline = narf_time::Deadline::after_ms(DISCOVERY_MS);
    let mut tried: Vec<&'static str> = Vec::new();
    let armed = 'discover: loop {
        for entry in narf_block::block_devices() {
            if !candidate_allowed(entry.name) || tried.contains(&entry.name) {
                continue;
            }
            tried.push(entry.name);
            match probe(entry.name, entry.disk, entry.dev.clone(), &token, &header).await {
                Ok(Some(session)) => break 'discover Some((entry.name, session)),
                Ok(None) => {}
                Err(error) => {
                    let _ = writeln!(Writer, "bootlog: {}: not armed: {error:?}", entry.name);
                }
            }
        }
        if deadline.expired() {
            break None;
        }
        sleep_ms(DISCOVERY_POLL_MS).await;
    };
    let Some((device, session)) = armed else {
        let _ = writeln!(
            Writer,
            "bootlog: no USB FAT volume with a matching /{MARKER_FILE} after {} s; \
             persistent log disabled",
            DISCOVERY_MS / 1000
        );
        return;
    };
    let _ = writeln!(
        Writer,
        "bootlog: saving the kernel log to {device}:/{} (limit {} KiB)",
        log_name(session.index),
        MAX_LOG_BYTES / 1024
    );
    *LIVE.lock() = Some(Live {
        session,
        cursor: 0,
        device,
    });
    narf_console::set_persist_hook(persist_hook);
    let armed_at = narf_time::Deadline::after_ms(EARLY_WINDOW_MS);
    let selftest_panic = narf_boot::args().value(SELFTEST_ARG) == Some("panic");
    let mut failures = 0u32;
    loop {
        match flush_live(true, None).await {
            Some(Ok(_)) if selftest_panic => {
                // Proves the panic-path flush end to end (QEMU usb-image check).
                panic!("bootlog: {SELFTEST_ARG}=panic: deliberate panic after the first flush");
            }
            Some(Ok(_)) => failures = 0,
            Some(Err(error)) => {
                failures += 1;
                let _ = writeln!(Writer, "bootlog: write failed: {error:?}");
                if failures >= MAX_WRITE_FAILURES {
                    LIVE.lock().take();
                    let _ = writeln!(Writer, "bootlog: persistent log stopped");
                    return;
                }
            }
            None => {}
        }
        let full = LIVE
            .lock()
            .as_ref()
            .is_some_and(|live| live.session.is_full());
        if full {
            let _ = writeln!(
                Writer,
                "bootlog: {device}: size limit reached; persistent log stopped"
            );
            return;
        }
        let period = if armed_at.expired() {
            LATE_FLUSH_MS
        } else {
            EARLY_FLUSH_MS
        };
        sleep_ms(period).await;
    }
}

/// Name of the device the live session writes to, if armed.
pub fn armed_device() -> Option<&'static str> {
    LIVE.lock().as_ref().map(|live| live.device)
}

/// `Stage::Late` initcall body: parse the argument and start the task.
pub fn start() -> narf_init::InitResult {
    use narf_console::Writer;
    let token = match parse_config(narf_boot::args().value(ARG)) {
        Ok(Config::Disabled) => return narf_init::InitResult::NotPresent,
        Ok(Config::Enabled { token }) => token,
        Err(why) => {
            let _ = writeln!(Writer, "bootlog: {ARG}= ignored: {why}");
            return narf_init::InitResult::Error("bad narf.bootlog= token");
        }
    };
    let _ = writeln!(
        Writer,
        "bootlog: waiting up to {} s for the USB boot medium (/{MARKER_FILE}){}",
        DISCOVERY_MS / 1000,
        if narf_block::disk_policy::policy().is_root_policy() {
            ", after the root is mounted"
        } else {
            ""
        }
    );
    narf_scheduler::spawn_stackful(run(token));
    narf_init::InitResult::Ok
}
