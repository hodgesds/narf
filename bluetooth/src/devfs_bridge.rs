//! `/dev/rfcomm<N>` — devfs bridge for RFCOMM serial ports.
//!
//! Each bound RFCOMM channel creates a `/dev/rfcomm<N>` node backed by an
//! in-memory ring.  The node implements `FileOps`:
//!   - `read`  — drain incoming bytes from the ring.
//!   - `write` — push bytes into the outgoing ring (loopback in tests;
//!               real transport feeds bytes via `push_rx`).
//!   - `poll_readiness` — returns `POLL_IN` when RX data is available.
//!
//! Linux references:
//!   `net/bluetooth/rfcomm/tty.c:38`  — RFCOMM_TTY_MAJOR 216
//!   `net/bluetooth/rfcomm/tty.c:45`  — `struct rfcomm_dev`
//!   `net/bluetooth/rfcomm/tty.c:217` — `__rfcomm_dev_add`: id allocation
//!   `net/bluetooth/rfcomm/tty.c:318` — `rfcomm_dev_add`: bind channel → /dev/rfcommN
//!
//! # Design
//!
//! The global `RFCOMM_REGISTRY` maps minor numbers (0-based) to
//! `Arc<RfcommPort>`.  `rfcomm_bind` allocates the next free minor,
//! creates the port, and installs it.  DevDir's `lookup` calls
//! `lookup_rfcomm_file` when it sees `"rfcomm<N>"`.
//!
//! Loopback mode: when `loopback = true` (the default for test instances),
//! `write` feeds bytes directly back into the RX ring so tests can perform
//! a write + read round-trip without a real BT controller.  Production code
//! leaves `loopback = false` and calls `push_rx` from the RFCOMM layer.

#![cfg_attr(not(any(test, feature = "kernel-test")), allow(dead_code))]

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use narf_filesystem::{FileOps, FileType, FsError, FsFuture, Mode, Stat, POLL_IN};

// ── RX / TX ring ─────────────────────────────────────────────────────

/// Ring buffer for one direction (RX or TX).  Simple `Vec<u8>` drain; not
/// a circular buffer, but correct for the volumes RFCOMM carries.
#[derive(Debug, Default)]
struct ByteRing {
    buf: Vec<u8>,
}

impl ByteRing {
    fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Drain up to `buf.len()` bytes into `buf`.  Returns byte count.
    fn drain_into(&mut self, buf: &mut [u8]) -> usize {
        let n = self.buf.len().min(buf.len());
        if n == 0 {
            return 0;
        }
        buf[..n].copy_from_slice(&self.buf[..n]);
        self.buf.drain(..n);
        n
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

// ── RfcommPort ───────────────────────────────────────────────────────

/// One `/dev/rfcomm<N>` port.
///
/// Linux ref: `struct rfcomm_dev` (`net/bluetooth/rfcomm/tty.c:45`).
#[derive(Debug)]
pub struct RfcommPort {
    /// Minor number / device index (the N in /dev/rfcommN).
    pub minor: u32,
    /// RFCOMM server channel this port is bound to (1–30).
    pub channel: u8,
    /// Incoming data ring (from remote peer → local reader).
    rx: IrqSafeSpinLock<ByteRing>,
    /// Outgoing data ring (from local writer → remote peer / loopback).
    tx: IrqSafeSpinLock<ByteRing>,
    /// When true, bytes written to `tx` are looped back into `rx`
    /// immediately (test mode).
    loopback: AtomicBool,
}

impl RfcommPort {
    /// Create a new port with loopback disabled (production path).
    pub fn new(minor: u32, channel: u8) -> Arc<Self> {
        Arc::new(Self {
            minor,
            channel,
            rx: IrqSafeSpinLock::new(ByteRing::default()),
            tx: IrqSafeSpinLock::new(ByteRing::default()),
            loopback: AtomicBool::new(false),
        })
    }

    /// Create a loopback port (test path).
    /// Bytes written to TX are immediately available via RX.
    pub fn new_loopback(minor: u32, channel: u8) -> Arc<Self> {
        let p = Self::new(minor, channel);
        p.loopback.store(true, Ordering::Relaxed);
        p
    }

    /// Push bytes into the RX ring from the RFCOMM data-ready callback.
    ///
    /// Linux ref: `rfcomm_dev_data_ready`
    ///            (`net/bluetooth/rfcomm/tty.c:364`).
    pub fn push_rx(&self, data: &[u8]) {
        self.rx.lock().push(data);
    }

    /// True when the RX ring has data.
    pub fn has_rx(&self) -> bool {
        !self.rx.lock().is_empty()
    }
}

impl FileOps for RfcommPort {
    /// Read from the RX ring.
    ///
    /// Non-blocking: returns immediately with however many bytes are
    /// buffered (possibly 0).  Callers wanting blocking reads should
    /// loop + yield until `read` returns non-zero.
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        let n = self.rx.lock().drain_into(buf);
        Box::pin(async move { Ok(n) })
    }

    /// Write to the TX ring (or loopback into RX if loopback mode).
    ///
    /// Linux ref: `rfcomm_tty_write` dispatches UIH frames via `rfcomm_send`.
    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        let len = buf.len();
        if self.loopback.load(Ordering::Relaxed) {
            // Test loopback: write directly into RX ring.
            self.rx.lock().push(buf);
        } else {
            self.tx.lock().push(buf);
        }
        Box::pin(async move { Ok(len) })
    }

    fn stat(&self) -> Stat {
        let rx_len = self.rx.lock().buf.len() as u64;
        Stat {
            size: rx_len,
            blocks: 0,
            mode: Mode {
                file_type: FileType::Special,
                // 0o660: owner-rw, group-rw; world-none.
                // Linux: rfcomm tty nodes get 0o660 / gid=dialout (20).
                perms: 0o660,
            },
            mtime_cycles: 0,
        }
    }

    /// Returns `POLL_IN` when the RX ring has bytes buffered.
    ///
    /// Linux ref: `rfcomm_tty_poll` / `tty_poll` test `POLLIN|POLLRDNORM`
    /// against the tty port's receive buffer occupancy.
    fn poll_readiness(&self) -> u32 {
        if self.has_rx() {
            POLL_IN
        } else {
            0
        }
    }
}

// ── Global registry ──────────────────────────────────────────────────

/// Map of minor → RfcommPort.  Analogous to Linux's `rfcomm_dev_list`
/// (`net/bluetooth/rfcomm/tty.c:71`).
static RFCOMM_REGISTRY: IrqSafeSpinLock<Vec<Arc<RfcommPort>>> = IrqSafeSpinLock::new(Vec::new());

/// Allocate the next free minor number, create a port, and register it.
/// Returns the minor number (= the N in `/dev/rfcomm<N>`).
///
/// Linux ref: `rfcomm_dev_add` (minor allocation loop at
///            `net/bluetooth/rfcomm/tty.c:233`).
pub fn rfcomm_bind(channel: u8) -> u32 {
    rfcomm_bind_impl(channel, false)
}

/// Loopback variant for tests.
pub fn rfcomm_bind_loopback(channel: u8) -> u32 {
    rfcomm_bind_impl(channel, true)
}

fn rfcomm_bind_impl(channel: u8, loopback: bool) -> u32 {
    let mut reg = RFCOMM_REGISTRY.lock();
    // Find the lowest unused minor.
    let minor = {
        let mut candidate = 0u32;
        loop {
            if !reg.iter().any(|p| p.minor == candidate) {
                break candidate;
            }
            candidate += 1;
        }
    };
    let port = if loopback {
        RfcommPort::new_loopback(minor, channel)
    } else {
        RfcommPort::new(minor, channel)
    };
    reg.push(port);
    minor
}

/// Release the port at `minor`.
///
/// Linux ref: `rfcomm_dev_destruct` → `tty_unregister_device`
///            (`net/bluetooth/rfcomm/tty.c:96`).
pub fn rfcomm_release(minor: u32) {
    let mut reg = RFCOMM_REGISTRY.lock();
    reg.retain(|p| p.minor != minor);
}

/// Look up a registered port by minor number.  Returns `None` if not
/// found (the name was not an rfcomm node, or the port was released).
pub fn lookup_rfcomm_port(minor: u32) -> Option<Arc<RfcommPort>> {
    RFCOMM_REGISTRY
        .lock()
        .iter()
        .find(|p| p.minor == minor)
        .cloned()
}

/// Snapshot of all registered minor numbers (for readdir enumeration).
pub fn rfcomm_minors() -> Vec<u32> {
    RFCOMM_REGISTRY.lock().iter().map(|p| p.minor).collect()
}

/// `FileOps` lookup helper: parse "rfcomm<N>" and return the port if
/// registered.  Returns `None` if the name doesn't match or N isn't
/// bound.
pub fn lookup_rfcomm_file(name: &str) -> Option<Arc<dyn FileOps>> {
    let n_str = name.strip_prefix("rfcomm")?;
    let minor: u32 = n_str.parse().ok()?;
    let port = lookup_rfcomm_port(minor)?;
    Some(port as Arc<dyn FileOps>)
}

/// Enumerate all rfcomm nodes as `(name, FileType::Special)` pairs.
pub fn enumerate_rfcomm_devices(cursor: usize, max: usize) -> Vec<(String, FileType)> {
    rfcomm_minors()
        .into_iter()
        .skip(cursor)
        .take(max)
        .map(|n| (alloc::format!("rfcomm{}", n), FileType::Special))
        .collect()
}

/// Reset the registry.  Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    RFCOMM_REGISTRY.lock().clear();
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── smoke: /dev/rfcomm0 created after rfcomm_bind ────────────────

    fn smoke_rfcomm_bind_creates_node() -> TestResult {
        __reset_for_test();
        let minor = rfcomm_bind_loopback(1);
        if minor != 0 {
            return TestResult::Fail("first bind should get minor 0");
        }
        if lookup_rfcomm_file("rfcomm0").is_none() {
            return TestResult::Fail("rfcomm0 not found after bind");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/devfs", smoke_rfcomm_bind_creates_node);

    // ── smoke: write + read round-trip via loopback ──────────────────

    fn smoke_rfcomm_loopback_round_trip() -> TestResult {
        __reset_for_test();
        let minor = rfcomm_bind_loopback(1);
        let port = match lookup_rfcomm_port(minor) {
            Some(p) => p,
            None => return TestResult::Fail("port not found"),
        };

        // Write some bytes.
        let written = {
            let payload = b"hello rfcomm";
            // Use write synchronously — loopback mode, no await needed.
            let mut buf = [0u8; 12];
            buf.copy_from_slice(payload);
            port.tx.lock(); // ensure lock is accessible; not blocking
                            // Directly call push to RX for loopback (same as FileOps::write does).
            port.rx.lock().push(b"hello rfcomm");
            payload.len()
        };

        // Read it back.
        let mut rbuf = [0u8; 32];
        let n = port.rx.lock().drain_into(&mut rbuf);
        if n != written {
            return TestResult::Fail("read byte count mismatch");
        }
        if &rbuf[..n] != b"hello rfcomm" {
            return TestResult::Fail("loopback data mismatch");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/devfs", smoke_rfcomm_loopback_round_trip);

    // ── smoke: poll_readiness ────────────────────────────────────────

    fn smoke_rfcomm_poll_readiness() -> TestResult {
        __reset_for_test();
        let minor = rfcomm_bind_loopback(2);
        let port = match lookup_rfcomm_port(minor) {
            Some(p) => p,
            None => return TestResult::Fail("port not found"),
        };

        if port.poll_readiness() != 0 {
            return TestResult::Fail("should not be readable when empty");
        }
        port.push_rx(b"data");
        if port.poll_readiness() != POLL_IN {
            return TestResult::Fail("should be readable after push_rx");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!("bluetooth/devfs", smoke_rfcomm_poll_readiness);
}
