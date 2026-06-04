//! `/dev/tpm0` and `/dev/tpmrm0` FileOps bridges.
//!
//! ## /dev/tpm0 — raw TPM access
//!
//! Serialises each open fd with a per-node mutex: write submits a TPM 2.0
//! command via the installed transport and stores the pending response;
//! read returns that response. `poll_readiness` returns `POLL_IN` when a
//! response is pending, `POLL_OUT` always. Only one command can be in
//! flight at a time (write fails with `FsError::Busy` if a response is
//! still unread). This matches Linux `tpm-dev-common.c:tpm_common_write`
//! (line 175) which rejects a second write while `response_length != 0`.
//!
//! ## /dev/tpmrm0 — resource-manager pass-through
//!
//! Same write/read/poll semantics as `/dev/tpm0` for v1. Additionally
//! tracks allocated transient handles (TPM object handles in the range
//! `0x8000_0000..0xBFFF_FFFF`) observed in `TPM2_Load` responses, and
//! issues `TPM2_FlushContext` for each handle on drop. This prevents
//! transient-handle leaks when multiple tasks open the RM device
//! concurrently. A full RM (session virtualisation, handle remapping) is
//! deferred.
//!
//! ## Transport injection
//!
//! Hardware bring-up wires a `TpmTransport` implementation via
//! `register_transport()`. Until a transport is installed, both device
//! nodes return `FsError::Io(BlockError::IOError)` on write.
//!
//! ## Linux references
//!
//! - `drivers/char/tpm/tpm-dev.c:tpm_open` / `tpm_release` / `tpm_read` /
//!   `tpm_write` — per-fd buffer serialisation model.
//! - `drivers/char/tpm/tpm-dev-common.c:tpm_common_read` (line 128),
//!   `tpm_common_write` (line 161), `tpm_common_poll` (line 211).
//! - `drivers/char/tpm/tpm2-space.c:tpm2_save_context`,
//!   `tpm2_load_context` — RM transient-handle lifecycle.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::BlockError;
use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_IN, POLL_OUT};
use narf_lib::sync::IrqSafeSpinLock;

// ── Transport trait ───────────────────────────────────────────────────

/// Synchronous TPM command/response channel.
///
/// Implementors wrap either the CRB or TIS transport (or a mock) and
/// hide the MMIO details behind a single `submit` call. The bridge
/// calls `submit` from within its `write` handler; no async I/O is
/// needed for polling-mode transports (both CRB and TIS are poll-loop).
pub trait TpmTransport: Send + Sync {
    /// Submit `cmd` to the TPM and return the response bytes.
    ///
    /// On success returns a `Vec<u8>` containing the complete TPM
    /// response (10-byte header + body). On transport-level failure
    /// returns `Err(())` (the bridge maps this to `FsError::Io`).
    fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, ()>;
}

// ── Global transport slot ─────────────────────────────────────────────

static TPM_TRANSPORT: IrqSafeSpinLock<Option<Arc<dyn TpmTransport>>> = IrqSafeSpinLock::new(None);

/// Register (or replace) the TPM transport.  Called by the CRB/TIS
/// probe layer after the hardware is confirmed alive.
pub fn register_transport(t: Arc<dyn TpmTransport>) {
    *TPM_TRANSPORT.lock() = Some(t);
}

/// Unregister the TPM transport (e.g. on driver tear-down).
pub fn unregister_transport() {
    *TPM_TRANSPORT.lock() = None;
}

fn get_transport() -> Option<Arc<dyn TpmTransport>> {
    TPM_TRANSPORT.lock().clone()
}

// ── TPM buffer size ───────────────────────────────────────────────────

/// Maximum command/response buffer size.
/// Linux tpm.h: `#define TPM_BUFSIZE 4096`.
pub const TPM_BUFSIZE: usize = 4096;

// ── Transient-handle range (TPM 2.0 Part 2 §6.8) ─────────────────────

/// Minimum transient-object handle value.
const TRANSIENT_FIRST: u32 = 0x8000_0000;
/// Maximum transient-object handle value.
const TRANSIENT_LAST: u32 = 0xBFFF_FFFF;

fn is_transient(handle: u32) -> bool {
    handle >= TRANSIENT_FIRST && handle <= TRANSIENT_LAST
}

// ── Build TPM2_FlushContext command ───────────────────────────────────

/// Build `TPM2_FlushContext(flushHandle)` — Part 3 §28.4.
/// Command code 0x0165.
fn flush_context_cmd(handle: u32) -> Vec<u8> {
    use crate::tpm2::{begin_command, finalise, TPM_ST_NO_SESSIONS};
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, 0x0000_0165);
    buf.extend_from_slice(&handle.to_be_bytes());
    finalise(&mut buf);
    buf
}

// ── Per-device state ─────────────────────────────────────────────────

/// State shared by all `read`/`write`/`poll_readiness` calls on one
/// node.  Linux `file_priv` holds equivalent fields (tpm-dev.h:32).
struct TpmDevState {
    /// Pending response bytes (empty = no response queued).
    response: Vec<u8>,
    /// `false` when the response has not yet been read.
    response_read: bool,
}

impl TpmDevState {
    fn new() -> Self {
        Self {
            response: Vec::new(),
            response_read: true,
        }
    }
}

// ── /dev/tpm0 ─────────────────────────────────────────────────────────

/// `/dev/tpm0` — raw TPM access without resource management.
///
/// Linux ref: `drivers/char/tpm/tpm-dev.c`.
pub struct DevTpm0 {
    state: IrqSafeSpinLock<TpmDevState>,
}

impl DevTpm0 {
    pub fn new() -> Self {
        Self {
            state: IrqSafeSpinLock::new(TpmDevState::new()),
        }
    }
}

impl Default for DevTpm0 {
    fn default() -> Self {
        Self::new()
    }
}

impl FileOps for DevTpm0 {
    /// Submit a TPM 2.0 command and store the response.
    ///
    /// Rejects writes when a response is still pending (the previous
    /// response must be consumed via `read` first). Validates the
    /// minimum header length (≥6 bytes with a valid size field).
    ///
    /// Linux ref: `tpm_common_write` (tpm-dev-common.c:161).
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();

        // Validate command buffer size.
        if len > TPM_BUFSIZE {
            return Box::pin(async move { Err(FsError::Io(BlockError::IOError)) });
        }
        if len < 6 {
            return Box::pin(async move { Err(FsError::Io(BlockError::IOError)) });
        }
        let declared = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
        if len < declared {
            return Box::pin(async move { Err(FsError::Io(BlockError::IOError)) });
        }

        // Reject if a previous response is unread.
        {
            let st = self.state.lock();
            if !st.response_read && !st.response.is_empty() {
                return Box::pin(async move { Err(FsError::Busy) });
            }
        }

        // Clone command bytes for the transport call.
        let cmd: Vec<u8> = buf[..declared].to_vec();

        let transport = match get_transport() {
            Some(t) => t,
            None => return Box::pin(async move { Err(FsError::Io(BlockError::IOError)) }),
        };

        // Submit synchronously; store response.
        match transport.submit(&cmd) {
            Ok(resp) => {
                let mut st = self.state.lock();
                st.response = resp;
                st.response_read = false;
                Box::pin(async move { Ok(len) })
            }
            Err(()) => Box::pin(async move { Err(FsError::Io(BlockError::IOError)) }),
        }
    }

    /// Return the pending response into `buf`.
    ///
    /// Clears the response after a successful read (partial reads consume
    /// bytes from the front and keep the rest pending, matching Linux
    /// `tpm_common_read` offset tracking at tpm-dev-common.c:128).
    ///
    /// Returns 0 (EOF) when no response is pending.
    ///
    /// Linux ref: `tpm_common_read` (tpm-dev-common.c:128).
    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let mut st = self.state.lock();
        if st.response_read || st.response.is_empty() {
            return Box::pin(async move { Ok(0) });
        }
        let off = offset as usize;
        if off >= st.response.len() {
            st.response_read = true;
            st.response.clear();
            return Box::pin(async move { Ok(0) });
        }
        let src = &st.response[off..];
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        // If we reached the end of the response, mark it consumed.
        if off + n >= st.response.len() {
            st.response_read = true;
            st.response.clear();
        }
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    /// `POLL_IN` when a response is pending; `POLL_OUT` always.
    ///
    /// Linux ref: `tpm_common_poll` (tpm-dev-common.c:211).
    fn poll_readiness(&self) -> u32 {
        let st = self.state.lock();
        let has_response = !st.response_read && !st.response.is_empty();
        if has_response {
            POLL_IN | POLL_OUT
        } else {
            POLL_OUT
        }
    }
}

// ── /dev/tpmrm0 ──────────────────────────────────────────────────────

/// `/dev/tpmrm0` — resource-manager-mediated TPM access.
///
/// v1: thin pass-through with transient-handle tracking. On drop (close),
/// any transient handles observed in `TPM2_Load` responses are flushed
/// via `TPM2_FlushContext`. A full RM with session virtualisation and
/// handle remapping is deferred.
///
/// Linux ref: `drivers/char/tpm/tpm2-space.c`.
pub struct DevTpmRm0 {
    state: IrqSafeSpinLock<TpmDevState>,
    /// Transient handles allocated during this open fd's lifetime.
    /// Flushed on drop (close). Linux tpm2-space.c tracks these in
    /// `tpm_space.context_tbl` (line 25).
    transient_handles: IrqSafeSpinLock<Vec<u32>>,
}

impl DevTpmRm0 {
    pub fn new() -> Self {
        Self {
            state: IrqSafeSpinLock::new(TpmDevState::new()),
            transient_handles: IrqSafeSpinLock::new(Vec::new()),
        }
    }

    /// Extract a transient handle from a `TPM2_Load` response if the
    /// response code is `TPM_RC_SUCCESS` and the handle field falls in
    /// the transient range.
    ///
    /// `TPM2_Load` response layout (Part 3 §12.4):
    /// - bytes 0..9  — header (tag, size, response code)
    /// - bytes 10..13 — objectHandle (u32 BE) if success
    fn track_load_response(&self, resp: &[u8]) {
        if resp.len() < 14 {
            return;
        }
        let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
        if rc != 0 {
            return;
        }
        let handle = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
        if is_transient(handle) {
            self.transient_handles.lock().push(handle);
        }
    }

    /// Flush all tracked transient handles via `TPM2_FlushContext`.
    /// Best-effort: individual failures are silently ignored so that
    /// close always completes. Linux tpm2-space.c:tpm2_flush_space
    /// (line 60) does the same.
    fn flush_all_transients(&self) {
        let handles: Vec<u32> = {
            let mut g = self.transient_handles.lock();
            core::mem::take(&mut *g)
        };
        let transport = match get_transport() {
            Some(t) => t,
            None => return,
        };
        for handle in handles {
            let cmd = flush_context_cmd(handle);
            let _ = transport.submit(&cmd);
        }
    }
}

impl Default for DevTpmRm0 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DevTpmRm0 {
    /// Flush transient handles on close — mirrors Linux `tpm2_flush_space`
    /// called from `tpm_common_release` (tpm-dev-common.c:223).
    fn drop(&mut self) {
        self.flush_all_transients();
    }
}

impl FileOps for DevTpmRm0 {
    /// Submit a command; track transient handle allocations in responses.
    ///
    /// After a successful `TPM2_Load`, the response objectHandle is
    /// appended to `transient_handles` so it can be flushed on close.
    ///
    /// Linux ref: `tpm_common_write` (tpm-dev-common.c:161).
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();

        if len > TPM_BUFSIZE {
            return Box::pin(async move { Err(FsError::Io(BlockError::IOError)) });
        }
        if len < 6 {
            return Box::pin(async move { Err(FsError::Io(BlockError::IOError)) });
        }
        let declared = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
        if len < declared {
            return Box::pin(async move { Err(FsError::Io(BlockError::IOError)) });
        }

        {
            let st = self.state.lock();
            if !st.response_read && !st.response.is_empty() {
                return Box::pin(async move { Err(FsError::Busy) });
            }
        }

        let cmd: Vec<u8> = buf[..declared].to_vec();

        // Detect TPM2_Load so we can track any resulting transient handle.
        // TPM_CC_LOAD = 0x0000_0157; command code at bytes 6..9.
        let is_load =
            declared >= 10 && u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) == 0x0000_0157;

        let transport = match get_transport() {
            Some(t) => t,
            None => return Box::pin(async move { Err(FsError::Io(BlockError::IOError)) }),
        };

        match transport.submit(&cmd) {
            Ok(resp) => {
                if is_load {
                    self.track_load_response(&resp);
                }
                let mut st = self.state.lock();
                st.response = resp;
                st.response_read = false;
                Box::pin(async move { Ok(len) })
            }
            Err(()) => Box::pin(async move { Err(FsError::Io(BlockError::IOError)) }),
        }
    }

    fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let mut st = self.state.lock();
        if st.response_read || st.response.is_empty() {
            return Box::pin(async move { Ok(0) });
        }
        let off = offset as usize;
        if off >= st.response.len() {
            st.response_read = true;
            st.response.clear();
            return Box::pin(async move { Ok(0) });
        }
        let src = &st.response[off..];
        let n = src.len().min(buf.len());
        buf[..n].copy_from_slice(&src[..n]);
        if off + n >= st.response.len() {
            st.response_read = true;
            st.response.clear();
        }
        Box::pin(async move { Ok(n) })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        let st = self.state.lock();
        let has_response = !st.response_read && !st.response.is_empty();
        if has_response {
            POLL_IN | POLL_OUT
        } else {
            POLL_OUT
        }
    }
}

// ── Registration helpers for devfs ───────────────────────────────────

/// Install `/dev/tpm0` and `/dev/tpmrm0` into devfs.
///
/// Constructs fresh `DevTpm0` and `DevTpmRm0` nodes and registers them
/// via `narf_filesystem::register_tpm`.  Called from the TPM driver
/// initcall after the transport is confirmed alive.
///
/// Linux ref: `tpm_chip_alloc` → `tpm_add_char_device`
/// (`drivers/char/tpm/tpm-chip.c:319`).
pub fn register_dev_nodes() {
    narf_filesystem::register_tpm(
        Arc::new(DevTpm0::new()) as Arc<dyn narf_filesystem::FileOps>,
        Arc::new(DevTpmRm0::new()) as Arc<dyn narf_filesystem::FileOps>,
    );
}
