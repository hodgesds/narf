//! Host half of net-smoke's TCP robustness phases (guest half:
//! `verification/data/musl-demo/netserve_smoke_x86_64.c`, section 8).
//!
//! Two kinds of peer serve the guest:
//!
//! * **SLIRP phases** — servers on `127.0.0.1:17790..=17799`, which the
//!   guest reaches as `10.0.2.2:<port>` through QEMU's user-mode network.
//!   SLIRP terminates TCP, so these exercise NARF against SLIRP's BSD TCP:
//!   sequence wrap (> 4 GiB each way in the long run), zero windows in both
//!   directions, large reads/writes and their socket-API semantics,
//!   connection churn, keepalive, half-close and a reset mid-transfer.
//! * **Namespace phases** — a Linux TCP peer (`10.0.3.1`) inside an
//!   unprivileged user + network namespace (`unshare -rn`), wired to the
//!   guest's second NIC (e1000) through a tap device that this process
//!   relays to QEMU's `-netdev stream` unix socket. `tc netem` on the tap
//!   (and on an ifb mirror of its ingress) adds delay, loss, reordering and
//!   duplication, which a TCP relay behind SLIRP cannot inject. Linux
//!   negotiates SACK, timestamps and window scaling, so these phases test
//!   window scaling under a high bandwidth-delay product, recovery from
//!   loss (fast retransmit, SACK, RTO with back-off), keepalive against a
//!   dead peer, resets, and loss aimed at the sequence wrap.
//!
//! Every stream is the `rword` pattern: byte `i` of a stream seeded `s` is
//! byte `i & 7` of `splitmix64(i >> 3, s)`. Each phase sends the guest a
//! 64-byte config (eight little-endian u64s); the layout per phase and the
//! ports MUST match the C side.
//!
//! `XTASK_NET_SMOKE_LONG=1` selects the long sizes (> 4 GiB wraps, minutes
//! of paced streaming, 20 000-connection churn with a TIME-WAIT wait).
//! `XTASK_NET_SMOKE_ROBUST=<slirp-mask>,<ns-mask>` restricts the phases
//! (hex or decimal bitmasks; see `robust_phases` in the C file).

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

pub const SLIRP_WRAP: u64 = 1;
pub const SLIRP_ZWIN_RX: u64 = 2;
pub const SLIRP_ZWIN_TX: u64 = 4;
pub const SLIRP_BIGIO: u64 = 8;
pub const SLIRP_CHURN: u64 = 16;
pub const SLIRP_MISC: u64 = 32;
pub const NS_BDP: u64 = 1;
pub const NS_LOSS: u64 = 2;
pub const NS_BLACKOUT: u64 = 4;
pub const NS_KEEPALIVE: u64 = 8;
pub const NS_RST: u64 = 16;
pub const NS_ZWIN: u64 = 32;
pub const NS_WRAP: u64 = 64;

const CTRL_PORT: u16 = 17799;
const WRAP_PORT: u16 = 17790;
const ZRX_PORT: u16 = 17791;
const ZTX_PORT: u16 = 17792;
const BIGIO_PORT: u16 = 17793;
const CHURN_CTL_PORT: u16 = 17794;
/// Host-side forward to the guest's churn server (`:7795`).
pub const CHURN_FWD_PORT: u16 = 17795;
pub const CHURN_GUEST_PORT: u16 = 7795;
const CHURN_PORT: u16 = 17796;
const MISC_PORT: u16 = 17797;

const NS_BDP_PORT: u16 = 17810;
const NS_LOSS_PORT: u16 = 17811;
const NS_BLACKOUT_PORT: u16 = 17812;
const NS_KEEPALIVE_PORT: u16 = 17813;
const NS_RST_PORT: u16 = 17814;
const NS_ZWIN_PORT: u16 = 17815;
const NS_WRAP_PORT: u16 = 17816;

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;

// ── The stream pattern ──────────────────────────────────────────────────

#[inline]
fn rword(k: u64, s: u64) -> u64 {
    let mut z = k
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(s.wrapping_mul(0xD1B5_4A32_D192_ED03))
        .wrapping_add(1);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn rfill(buf: &mut [u8], off: u64, s: u64) {
    let mut i = 0usize;
    while i < buf.len() {
        let o = off + i as u64;
        let w = rword(o >> 3, s).to_le_bytes();
        let start = (o & 7) as usize;
        let n = (8 - start).min(buf.len() - i);
        buf[i..i + n].copy_from_slice(&w[start..start + n]);
        i += n;
    }
}

/// Offset (within `buf`) of the first byte that is not the stream's.
fn rcheck(buf: &[u8], off: u64, s: u64) -> Option<usize> {
    let mut i = 0usize;
    while i < buf.len() {
        let o = off + i as u64;
        let w = rword(o >> 3, s).to_le_bytes();
        let start = (o & 7) as usize;
        let n = (8 - start).min(buf.len() - i);
        if buf[i..i + n] != w[start..start + n] {
            for k in 0..n {
                if buf[i + k] != w[start + k] {
                    return Some(i + k);
                }
            }
        }
        i += n;
    }
    None
}

fn cfg_bytes(v: &[u64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for (i, x) in v.iter().take(8).enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
    }
    out
}

fn send_stream(w: &mut impl Write, len: u64, seed: u64, chunk: usize) -> std::io::Result<()> {
    let mut buf = vec![0u8; chunk];
    let mut off = 0u64;
    while off < len {
        let n = chunk.min((len - off) as usize);
        rfill(&mut buf[..n], off, seed);
        w.write_all(&buf[..n])?;
        off += n as u64;
    }
    Ok(())
}

/// Read and verify `len` bytes of stream `seed`; then require EOF if asked.
fn recv_stream(r: &mut impl Read, len: u64, seed: u64, want_eof: bool) -> Result<(), String> {
    let mut buf = vec![0u8; 1 << 20];
    let mut got = 0u64;
    while got < len {
        let want = buf.len().min((len - got) as usize);
        match r.read(&mut buf[..want]) {
            Ok(0) => return Err(format!("early EOF at {got} of {len}")),
            Ok(n) => {
                if let Some(k) = rcheck(&buf[..n], got, seed) {
                    return Err(format!("byte mismatch at offset {}", got + k as u64));
                }
                got += n as u64;
            }
            Err(e) => return Err(format!("read error at {got} of {len}: {e}")),
        }
    }
    if want_eof {
        match r.read(&mut buf[..1]) {
            Ok(0) => {}
            Ok(_) => return Err(format!("data past the end ({len} bytes)")),
            Err(e) => return Err(format!("no EOF after {len} bytes: {e}")),
        }
    }
    Ok(())
}

// ── Socket options std does not expose ──────────────────────────────────

#[repr(C)]
struct Linger {
    l_onoff: i32,
    l_linger: i32,
}

extern "C" {
    fn setsockopt(fd: i32, level: i32, name: i32, val: *const core::ffi::c_void, len: u32) -> i32;
    fn getsockopt(
        fd: i32,
        level: i32,
        name: i32,
        val: *mut core::ffi::c_void,
        len: *mut u32,
    ) -> i32;
    fn ioctl(fd: i32, req: u64, ...) -> i32;
}

const SOL_SOCKET: i32 = 1;
const SO_RCVBUF: i32 = 8;
const SO_LINGER: i32 = 13;
const IPPROTO_TCP: i32 = 6;
const TCP_INFO: i32 = 11;

/// Receive buffer for the SLIRP-side servers that make the guest's window
/// close by pausing. Those servers sit behind SLIRP on loopback, where the
/// MSS is ~64 KiB: a buffer much below that keeps Linux's receiver
/// silly-window avoidance from ever advertising a usable window, so SLIRP's
/// host socket crawls on zero-window probes (a 4 KiB buffer moves ~40 KB/s)
/// and the guest's window stays closed for a minute even while we read.
const SMALL_LO_RCVBUF: i32 = 64 << 10;

fn set_rcvbuf(fd: &impl AsRawFd, bytes: i32) {
    // SAFETY: `fd` is an open socket; the option value is a live i32 of the
    // length passed.
    unsafe {
        setsockopt(
            fd.as_raw_fd(),
            SOL_SOCKET,
            SO_RCVBUF,
            (&bytes as *const i32).cast(),
            4,
        );
    }
}

/// `SO_LINGER {1, 0}`: the next close sends an RST.
fn set_linger_zero(fd: &impl AsRawFd) {
    let l = Linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: `fd` is an open socket; `l` is a `struct linger` of the size
    // passed.
    unsafe {
        setsockopt(
            fd.as_raw_fd(),
            SOL_SOCKET,
            SO_LINGER,
            (&l as *const Linger).cast(),
            core::mem::size_of::<Linger>() as u32,
        );
    }
}

/// `tcpi_rcv_mss` (offset 20 of `struct tcp_info`).
fn tcp_rcv_mss(fd: &impl AsRawFd) -> u32 {
    let mut info = [0u8; 232];
    let mut len = info.len() as u32;
    // SAFETY: `fd` is an open TCP socket; `info`/`len` describe a writable
    // buffer of `len` bytes.
    let rc = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            IPPROTO_TCP,
            TCP_INFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 || len < 24 {
        return 0;
    }
    u32::from_ne_bytes([info[20], info[21], info[22], info[23]])
}

// ── Configuration ───────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct RobustConfig {
    pub long: bool,
    pub slirp: u64,
    pub ns: u64,
}

impl RobustConfig {
    pub fn from_env() -> Self {
        let long = std::env::var("XTASK_NET_SMOKE_LONG").is_ok_and(|v| v == "1");
        let (mut slirp, mut ns) = (0x3f, if long { 0x7f } else { 0x3f });
        if let Ok(sel) = std::env::var("XTASK_NET_SMOKE_ROBUST") {
            let parse = |s: &str| {
                let s = s.trim();
                s.strip_prefix("0x")
                    .map(|h| u64::from_str_radix(h, 16))
                    .unwrap_or_else(|| s.parse())
                    .unwrap_or(0)
            };
            let mut parts = sel.split(',');
            slirp = parts.next().map(parse).unwrap_or(0);
            ns = parts.next().map(parse).unwrap_or(0);
        }
        Self { long, slirp, ns }
    }
}

/// Failures and progress notes from every host-side server thread.
#[derive(Clone, Default)]
pub struct Report {
    inner: Arc<Mutex<Vec<String>>>,
}

impl Report {
    fn fail(&self, msg: String) {
        println!("xtask net-smoke: robust host FAIL: {msg}");
        if let Ok(mut v) = self.inner.lock() {
            v.push(msg);
        }
    }

    pub fn failures(&self) -> Vec<String> {
        self.inner.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

fn note(msg: &str) {
    println!("xtask net-smoke: robust host: {msg}");
}

fn bind(port: u16) -> Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("binding robust-phase server 127.0.0.1:{port}"))
}

/// Run `f` per accepted connection, each on its own thread, forever.
fn serve(
    l: TcpListener,
    report: &Report,
    name: &'static str,
    f: fn(TcpStream, &Report) -> Result<(), String>,
) {
    let report = report.clone();
    std::thread::spawn(move || {
        for conn in l.incoming() {
            let Ok(conn) = conn else { continue };
            let report = report.clone();
            std::thread::spawn(move || {
                if let Err(e) = f(conn, &report) {
                    report.fail(format!("{name}: {e}"));
                }
            });
        }
    });
}

fn io<T>(r: std::io::Result<T>, what: &str) -> Result<T, String> {
    r.map_err(|e| format!("{what}: {e}"))
}

fn read_byte(s: &mut TcpStream) -> Result<u8, String> {
    let mut b = [0u8; 1];
    io(s.read_exact(&mut b), "reading a control byte")?;
    Ok(b[0])
}

fn wait_eof(s: &mut TcpStream) -> Result<(), String> {
    let mut b = [0u8; 4096];
    loop {
        match s.read(&mut b) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(format!("waiting for EOF: {e}")),
        }
    }
}

/// Full duplex: send `down` bytes (seed `seed`) while verifying `up` bytes
/// (seed `seed + 1`) up to EOF, then answer 'K'.
fn duplex(mut s: TcpStream, down: u64, up: u64, seed: u64) -> Result<(), String> {
    // A stall fails with the offset reached instead of hanging the run.
    let _ = s.set_read_timeout(Some(Duration::from_secs(90)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(90)));
    let mut w = io(s.try_clone(), "cloning")?;
    let sent = Arc::new(AtomicU64::new(0));
    let progress = sent.clone();
    let tx = std::thread::spawn(move || -> std::io::Result<()> {
        let mut buf = vec![0u8; 256 << 10];
        let mut off = 0u64;
        while off < down {
            let n = buf.len().min((down - off) as usize);
            rfill(&mut buf[..n], off, seed);
            w.write_all(&buf[..n])?;
            off += n as u64;
            progress.store(off, Ordering::Relaxed);
        }
        Ok(())
    });
    let rx = recv_stream(&mut s, up, seed + 1, true);
    let txr = tx.join().map_err(|_| "sender panicked".to_string())?;
    txr.map_err(|e| {
        format!(
            "sending the down stream stopped at {} of {down}: {e}",
            sent.load(Ordering::Relaxed)
        )
    })?;
    rx.map_err(|e| format!("up stream: {e}"))?;
    io(s.write_all(b"K"), "verdict")?;
    Ok(())
}

// ── SLIRP phase servers ─────────────────────────────────────────────────

static LONG: AtomicBool = AtomicBool::new(false);
static SEED: AtomicU64 = AtomicU64::new(0x51);

fn long() -> bool {
    LONG.load(Ordering::Relaxed)
}

fn next_seed() -> u64 {
    SEED.fetch_add(0x1000, Ordering::Relaxed)
}

fn wrap_server(mut s: TcpStream, _r: &Report) -> Result<(), String> {
    // Past 4 GiB each way, both sequence spaces wrap whatever the ISNs.
    let len = if long() { 4 * GIB + GIB / 2 } else { 256 * MIB };
    let seed = next_seed();
    io(s.write_all(&cfg_bytes(&[len, len, seed])), "config")?;
    let t0 = Instant::now();
    duplex(s, len, len, seed)?;
    note(&format!(
        "wrap: {len} bytes each way verified in {:.1?}",
        t0.elapsed()
    ));
    Ok(())
}

fn zwin_rx_server(mut s: TcpStream, _r: &Report) -> Result<(), String> {
    // total, burst, pause ms, seed, long pause ms (every 4th), resume limit ms
    let (total, burst, pause, long_pause) = if long() {
        (96 * MIB, 8 * MIB, 5_000, 70_000)
    } else {
        (24 * MIB, 4 * MIB, 1_500, 3_000)
    };
    let seed = next_seed();
    io(
        s.write_all(&cfg_bytes(&[total, burst, pause, seed, long_pause, 2_000])),
        "config",
    )?;
    let t0 = Instant::now();
    io(send_stream(&mut s, total, seed, 64 << 10), "streaming")?;
    note(&format!(
        "zwin-rx: streamed {total} bytes to a pausing reader in {:.1?}",
        t0.elapsed()
    ));
    Ok(())
}

fn zwin_tx_server(mut s: TcpStream, _r: &Report) -> Result<(), String> {
    // The guest sends `total`; we read in bursts with pauses. A tiny receive
    // buffer makes SLIRP's window close soon after we stop reading.
    set_rcvbuf(&s, SMALL_LO_RCVBUF);
    let pauses: Vec<u64> = if long() {
        vec![10_000, 10_000, 70_000, 10_000, 30_000, 10_000]
    } else {
        vec![2_000, 2_000, 4_000]
    };
    let total = if long() { 64 * MIB } else { 24 * MIB };
    let seed = next_seed();
    let poll_ms = pauses.iter().max().copied().unwrap_or(0) + 130_000;
    io(s.write_all(&cfg_bytes(&[total, seed, poll_ms])), "config")?;
    let burst = total / (pauses.len() as u64 + 1);
    let mut buf = vec![0u8; 64 << 10];
    let mut got = 0u64;
    let mut worst_gap = Duration::ZERO;
    let mut next_pause = 0usize;
    let mut last = Instant::now();
    let t0 = Instant::now();
    while got < total {
        if next_pause < pauses.len() && got >= burst * (next_pause as u64 + 1) {
            std::thread::sleep(Duration::from_millis(pauses[next_pause]));
            next_pause += 1;
            last = Instant::now();
        }
        let want = buf.len().min((total - got) as usize);
        let n = io(s.read(&mut buf[..want]), "reading")?;
        if n == 0 {
            return Err(format!("early EOF at {got} of {total}"));
        }
        if let Some(k) = rcheck(&buf[..n], got, seed) {
            return Err(format!("byte mismatch at offset {}", got + k as u64));
        }
        got += n as u64;
        let gap = last.elapsed();
        if gap > worst_gap {
            worst_gap = gap;
        }
        last = Instant::now();
    }
    wait_eof(&mut s)?;
    note(&format!(
        "zwin-tx: received {total} bytes across {} pauses in {:.1?}; longest wait for data after resuming {:.1?}",
        pauses.len(),
        t0.elapsed(),
        worst_gap
    ));
    // After the reader resumes, the sender's persist timer (or the
    // receiver's own window update) must restart the flow promptly; Linux's
    // probe interval tops out at TCP_RTO_MAX (120 s), but the reopened
    // window is reported at once by SLIRP's ACK of the next probe.
    let longest_pause = Duration::from_millis(pauses.iter().max().copied().unwrap_or(0));
    if worst_gap > longest_pause + Duration::from_secs(5) {
        return Err(format!(
            "the stream stalled {worst_gap:.1?} after a reader pause (longest pause {longest_pause:.1?})"
        ));
    }
    io(s.write_all(b"K"), "verdict")
}

fn bigio_server(mut s: TcpStream, _r: &Report) -> Result<(), String> {
    let mode = read_byte(&mut s)?;
    let seed = next_seed();
    io(s.write_all(&cfg_bytes(&[seed])), "config")?;
    match mode {
        1 => {
            recv_stream(&mut s, 16 * MIB, seed, false)?;
            io(s.write_all(b"K"), "verdict")
        }
        2 => {
            // Trickle 16 MiB, then 3 + 5 bytes 200 ms apart.
            let mut buf = vec![0u8; 64 << 10];
            let mut off = 0u64;
            while off < 16 * MIB {
                rfill(&mut buf, off, seed);
                io(s.write_all(&buf), "trickle")?;
                off += buf.len() as u64;
                if off % MIB == 0 {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
            let mut tail = [0u8; 8];
            rfill(&mut tail, off, seed);
            io(s.write_all(&tail[..3]), "tail")?;
            std::thread::sleep(Duration::from_millis(200));
            io(s.write_all(&tail[3..]), "tail")?;
            wait_eof(&mut s)
        }
        3 => {
            let mut buf = vec![0u8; 100_000];
            rfill(&mut buf, 0, seed);
            io(s.write_all(&buf), "SIOCINQ bytes")?;
            if read_byte(&mut s)? != b'G' {
                return Err("bigio 3: bad go byte".into());
            }
            Ok(())
        }
        4 => {
            set_rcvbuf(&s, SMALL_LO_RCVBUF);
            std::thread::sleep(Duration::from_millis(1500));
            recv_stream(&mut s, 4 * MIB, seed, false)?;
            io(s.write_all(b"K"), "verdict")?;
            wait_eof(&mut s)
        }
        5 => wait_eof(&mut s),
        m => Err(format!("unknown bigio mode {m}")),
    }
}

fn churn_len(id: u64) -> u64 {
    100 + (id % 4) * 16384
}

fn churn_server(mut s: TcpStream, _r: &Report) -> Result<(), String> {
    let mut req = [0u8; 64];
    io(s.read_exact(&mut req), "request")?;
    let id = u32::from_le_bytes([req[0], req[1], req[2], req[3]]) as u64;
    io(send_stream(&mut s, churn_len(id), id, 64 << 10), "response")?;
    if id % 2 == 1 {
        // The guest closes first.
        wait_eof(&mut s)?;
    }
    Ok(())
}

fn churn_ctl(mut s: TcpStream, _r: &Report) -> Result<(), String> {
    let count: u64 = if long() { 20_000 } else { 2_000 };
    io(s.write_all(&cfg_bytes(&[count, long() as u64])), "config")?;
    if read_byte(&mut s)? != b'S' {
        return Err("bad churn start byte".into());
    }
    let t0 = Instant::now();
    for i in 0..count {
        let mut c = None;
        for _ in 0..50 {
            match TcpStream::connect(("127.0.0.1", CHURN_FWD_PORT)) {
                Ok(x) => {
                    c = Some(x);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(100)),
            }
        }
        let mut c = c.ok_or(format!("churn: connect {i} to the guest failed"))?;
        let _ = c.set_read_timeout(Some(Duration::from_secs(20)));
        let mut req = [0u8; 64];
        req[..4].copy_from_slice(&(i as u32).to_le_bytes());
        io(c.write_all(&req), "churn request")?;
        recv_stream(&mut c, churn_len(i), i + 1_000_000, i % 2 == 1)
            .map_err(|e| format!("churn fetch {i} from the guest: {e}"))?;
        // Even: we close first. Odd: the guest closed first (EOF seen).
        drop(c);
    }
    note(&format!(
        "churn: {count} fetches from the guest server in {:.1?}",
        t0.elapsed()
    ));
    io(s.write_all(b"K"), "verdict")?;
    wait_eof(&mut s)
}

fn misc_server(mut s: TcpStream, _r: &Report) -> Result<(), String> {
    let mode = read_byte(&mut s)?;
    let seed = next_seed();
    io(s.write_all(&cfg_bytes(&[seed])), "config")?;
    match mode {
        1 => {
            if read_byte(&mut s)? != b'R' {
                return Err("keepalive: bad ready byte".into());
            }
            std::thread::sleep(Duration::from_secs(6));
            io(s.write_all(b"ping"), "keepalive ping")?;
            wait_eof(&mut s)
        }
        2 => {
            recv_stream(&mut s, MIB, seed, true).map_err(|e| format!("half-close 2: {e}"))?;
            io(
                send_stream(&mut s, 8 * MIB, seed + 1, 64 << 10),
                "half-close 2 response",
            )
        }
        3 => {
            io(
                send_stream(&mut s, MIB, seed, 64 << 10),
                "half-close 3 send",
            )?;
            io(s.shutdown(Shutdown::Write), "half-close 3 shutdown")?;
            recv_stream(&mut s, 8 * MIB, seed + 1, true).map_err(|e| format!("half-close 3: {e}"))
        }
        4 => {
            let stop = Arc::new(AtomicBool::new(false));
            let mut w = io(s.try_clone(), "clone")?;
            let st = stop.clone();
            let tx = std::thread::spawn(move || {
                let mut buf = vec![0u8; 16 << 10];
                let mut off = 0u64;
                while !st.load(Ordering::Relaxed) && off < 256 * MIB {
                    rfill(&mut buf, off, seed);
                    if w.write_all(&buf).is_err() {
                        break;
                    }
                    off += buf.len() as u64;
                }
            });
            if read_byte(&mut s)? != b'A' {
                return Err("rst 4: bad abort byte".into());
            }
            stop.store(true, Ordering::Relaxed);
            let _ = tx.join();
            set_linger_zero(&s);
            drop(s);
            Ok(())
        }
        m => Err(format!("unknown misc mode {m}")),
    }
}

/// Start every SLIRP-phase server. The guest's control fetch (`:17799`)
/// learns which phases run.
pub fn start_slirp_servers(cfg: RobustConfig, ns_ok: bool, report: &Report) -> Result<()> {
    LONG.store(cfg.long, Ordering::Relaxed);
    let ctrl = bind(CTRL_PORT)?;
    let ns_mask = if ns_ok { cfg.ns } else { 0 };
    let slirp_mask = cfg.slirp;
    std::thread::spawn(move || {
        for conn in ctrl.incoming() {
            let Ok(mut conn) = conn else { continue };
            let _ = conn.write_all(&cfg_bytes(&[slirp_mask, ns_mask]));
        }
    });
    serve(bind(WRAP_PORT)?, report, "wrap", wrap_server);
    serve(bind(ZRX_PORT)?, report, "zwin-rx", zwin_rx_server);
    serve(bind(ZTX_PORT)?, report, "zwin-tx", zwin_tx_server);
    serve(bind(BIGIO_PORT)?, report, "bigio", bigio_server);
    serve(bind(CHURN_CTL_PORT)?, report, "churn", churn_ctl);
    serve(bind(CHURN_PORT)?, report, "churn fetch", churn_server);
    serve(bind(MISC_PORT)?, report, "misc", misc_server);
    Ok(())
}

/// Guest tokens of the enabled phases, in order, with a per-phase timeout.
pub fn expected_tokens(cfg: RobustConfig, ns_ok: bool) -> Vec<(&'static str, u64)> {
    let l = cfg.long;
    let mut out = Vec::new();
    let s = cfg.slirp;
    let ns = if ns_ok { cfg.ns } else { 0 };
    let mut add = |on: bool, tok: &'static str, short: u64, longt: u64| {
        if on {
            out.push((tok, if l { longt } else { short }));
        }
    };
    add(s & SLIRP_WRAP != 0, "netserve-wrap-ok", 300, 3600);
    add(s & SLIRP_ZWIN_RX != 0, "netserve-zwin-rx-ok", 180, 900);
    add(s & SLIRP_ZWIN_TX != 0, "netserve-zwin-tx-ok", 180, 900);
    add(s & SLIRP_BIGIO != 0, "netserve-bigio-ok", 180, 180);
    add(s & SLIRP_CHURN != 0, "netserve-churn-ok", 300, 1800);
    add(s & SLIRP_MISC != 0, "netserve-misc-ok", 180, 180);
    add(ns & NS_BDP != 0, "netserve-ns-bdp-ok", 300, 300);
    add(ns & NS_LOSS != 0, "netserve-ns-loss-ok", 300, 1200);
    add(ns & NS_BLACKOUT != 0, "netserve-ns-blackout-ok", 300, 300);
    add(ns & NS_KEEPALIVE != 0, "netserve-ns-keepalive-ok", 180, 180);
    add(ns & NS_RST != 0, "netserve-ns-rst-ok", 180, 180);
    add(ns & NS_ZWIN != 0, "netserve-ns-zwin-ok", 300, 300);
    add(ns & NS_WRAP != 0, "netserve-ns-wrap-ok", 600, 3600);
    out.push(("netserve-robust-ok", 120));
    out
}

// ── The namespace peer ──────────────────────────────────────────────────

/// Handle on the `unshare -rn` peer process: its stdout lines (failures
/// are `net-peer-fail:`), and the child to kill.
pub struct NsPeer {
    child: std::process::Child,
    pub lines: Arc<Mutex<Vec<String>>>,
}

impl NsPeer {
    pub fn failures(&self) -> Vec<String> {
        self.lines
            .lock()
            .map(|v| {
                v.iter()
                    .filter(|l| l.starts_with("net-peer-fail:"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for NsPeer {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Spawn the namespace peer listening on unix socket `sock` (QEMU's
/// `-netdev stream` connects to it). `None` (with a printed reason) when the
/// host has no unprivileged user + net namespaces, `unshare`, `ip` or `tc`.
pub fn spawn_ns_peer(sock: &std::path::Path, cfg: RobustConfig) -> Option<NsPeer> {
    let _ = std::fs::remove_file(sock);
    let exe = std::env::current_exe().ok()?;
    let mut cmd = std::process::Command::new("unshare");
    cmd.args(["-rn", "--"])
        .arg(exe)
        .arg("net-peer")
        .arg("--sock")
        .arg(sock)
        .arg("--mask")
        .arg(format!("{}", cfg.ns))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());
    if cfg.long {
        cmd.arg("--long");
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            println!("xtask net-smoke: namespace peer unavailable (unshare: {e})");
            return None;
        }
    };
    let out = child.stdout.take()?;
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<bool>();
    {
        let lines = lines.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let mut ready_tx = Some(ready_tx);
            for line in std::io::BufReader::new(out).lines() {
                let Ok(line) = line else { break };
                println!("xtask net-smoke: {line}");
                if line.starts_with("net-peer: ready") {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(true);
                    }
                }
                if line.starts_with("net-peer: unavailable") {
                    if let Some(tx) = ready_tx.take() {
                        let _ = tx.send(false);
                    }
                }
                if let Ok(mut v) = lines.lock() {
                    v.push(line);
                }
            }
            if let Some(tx) = ready_tx.take() {
                let _ = tx.send(false);
            }
        });
    }
    match ready_rx.recv_timeout(Duration::from_secs(20)) {
        Ok(true) => Some(NsPeer { child, lines }),
        _ => {
            println!("xtask net-smoke: namespace peer did not come up; namespace phases skipped");
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

fn sh(args: &[&str]) -> Result<()> {
    let out = std::process::Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("running {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "{} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Replace both directions' impairment with `netem <spec>` (empty = none).
fn netem(spec: &str) {
    for dev in ["tap0", "ifb0"] {
        let _ = std::process::Command::new("tc")
            .args(["qdisc", "del", "dev", dev, "root"])
            .output();
        if !spec.is_empty() {
            let mut a = vec![
                "tc", "qdisc", "add", "dev", dev, "root", "netem", "limit", "20000",
            ];
            a.extend(spec.split_whitespace());
            if let Err(e) = sh(&a) {
                println!("net-peer-fail: {e}");
            }
        }
    }
}

/// Loss aimed at the sequence wrap: segments whose sequence number lies
/// within 1 MiB of 2^32 lose `wrap_loss`, everything else `base`.
fn netem_wrap(base: &str, wrap_loss: &str) {
    for dev in ["tap0", "ifb0"] {
        let _ = std::process::Command::new("tc")
            .args(["qdisc", "del", "dev", dev, "root"])
            .output();
        let steps: Vec<Vec<String>> = vec![
            "qdisc add DEV root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0".into(),
            format!("qdisc add DEV parent 1:1 handle 10: netem limit 20000 loss {base}"),
            format!("qdisc add DEV parent 1:2 handle 20: netem limit 20000 loss {wrap_loss}"),
            // TCP sequence number: IPv4 header (20) + 4.
            "filter add DEV parent 1: protocol ip prio 1 u32 match ip protocol 6 0xff match u32 0xfff00000 0xfff00000 at 24 flowid 1:2".into(),
            "filter add DEV parent 1: protocol ip prio 2 u32 match ip protocol 6 0xff match u32 0x00000000 0xfff00000 at 24 flowid 1:2".into(),
        ]
        .into_iter()
        .map(|s: String| {
            std::iter::once("tc".to_string())
                .chain(s.replace("DEV", dev).split_whitespace().map(String::from))
                .collect()
        })
        .collect();
        for st in steps {
            let a: Vec<&str> = st.iter().map(String::as_str).collect();
            if let Err(e) = sh(&a) {
                println!("net-peer-fail: {e}");
            }
        }
    }
}

/// Packets the wrap band (1:2) dropped on `dev`, from `tc -s qdisc`.
fn wrap_band_drops(dev: &str) -> u64 {
    let out = std::process::Command::new("tc")
        .args(["-s", "qdisc", "show", "dev", dev])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let mut in_band = false;
    for line in out.lines() {
        if line.starts_with("qdisc") {
            in_band = line.contains("parent 1:2");
        } else if in_band {
            if let Some(i) = line.find("dropped ") {
                let rest = &line[i + 8..];
                let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                return n.parse().unwrap_or(0);
            }
        }
    }
    0
}

const TUNSETIFF: u64 = 0x4004_54ca;
const IFF_TAP: i16 = 0x0002;
const IFF_NO_PI: i16 = 0x1000;

fn open_tap(name: &str) -> Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context("opening /dev/net/tun")?;
    let mut ifr = [0u8; 40];
    ifr[..name.len()].copy_from_slice(name.as_bytes());
    ifr[16..18].copy_from_slice(&(IFF_TAP | IFF_NO_PI).to_ne_bytes());
    // SAFETY: `f` is an open tun fd and `ifr` is a 40-byte `struct ifreq`
    // TUNSETIFF reads and writes in place.
    let rc = unsafe { ioctl(f.as_raw_fd(), TUNSETIFF, ifr.as_mut_ptr()) };
    if rc != 0 {
        bail!("TUNSETIFF {name}: {}", std::io::Error::last_os_error());
    }
    Ok(f)
}

/// Frames larger than this (a 1500-byte MTU plus the Ethernet header) are
/// dropped by the relay, as a real switch port would, and counted.
const MAX_FRAME: usize = 1514;

/// `xtask net-peer`: runs inside `unshare -rn`. Sets up tap0 (10.0.3.1/24)
/// with an ifb mirror of its ingress for netem, relays tap0 to QEMU's
/// stream socket, and serves the namespace phases in order.
pub fn net_peer_main(sock: &std::path::Path, mask: u64, long_run: bool) -> Result<()> {
    let setup = || -> Result<std::fs::File> {
        sh(&["ip", "link", "set", "lo", "up"])?;
        sh(&["ip", "tuntap", "add", "tap0", "mode", "tap"])?;
        sh(&["ip", "addr", "add", "10.0.3.1/24", "dev", "tap0"])?;
        sh(&["ip", "link", "set", "tap0", "up"])?;
        sh(&["ip", "link", "add", "ifb0", "type", "ifb"])?;
        sh(&["ip", "link", "set", "ifb0", "up"])?;
        sh(&[
            "tc", "qdisc", "add", "dev", "tap0", "handle", "ffff:", "ingress",
        ])?;
        sh(&[
            "tc", "filter", "add", "dev", "tap0", "parent", "ffff:", "matchall", "action",
            "mirred", "egress", "redirect", "dev", "ifb0",
        ])?;
        open_tap("tap0")
    };
    let tap = match setup() {
        Ok(t) => t,
        Err(e) => {
            println!("net-peer: unavailable: {e:#}");
            return Ok(());
        }
    };
    let listener = std::os::unix::net::UnixListener::bind(sock)
        .with_context(|| format!("binding {}", sock.display()))?;
    // Bind every phase port now so the guest never races a listener.
    let mut listeners = Vec::new();
    for port in [
        NS_BDP_PORT,
        NS_LOSS_PORT,
        NS_BLACKOUT_PORT,
        NS_KEEPALIVE_PORT,
        NS_RST_PORT,
        NS_ZWIN_PORT,
        NS_WRAP_PORT,
    ] {
        listeners.push((port, TcpListener::bind(("10.0.3.1", port))?));
    }
    println!("net-peer: ready");
    let (qemu, _) = listener
        .accept()
        .context("accepting QEMU's stream connection")?;
    println!("net-peer: QEMU connected");
    let oversize = Arc::new(AtomicU64::new(0));
    // Guest → tap: QEMU's stream framing is a 4-byte big-endian length.
    {
        let mut q = qemu.try_clone()?;
        let mut t = tap.try_clone()?;
        let oversize = oversize.clone();
        std::thread::spawn(move || {
            let mut frame = vec![0u8; 65536];
            loop {
                let mut len = [0u8; 4];
                if q.read_exact(&mut len).is_err() {
                    break;
                }
                let n = u32::from_be_bytes(len) as usize;
                if n > frame.len() || q.read_exact(&mut frame[..n]).is_err() {
                    break;
                }
                if n > MAX_FRAME {
                    if oversize.fetch_add(1, Ordering::Relaxed) == 0 {
                        println!("net-peer: guest sent a {n}-byte frame (> {MAX_FRAME}); dropping");
                    }
                    continue;
                }
                let _ = t.write(&frame[..n]);
            }
        });
    }
    {
        let mut q = qemu;
        let mut t = tap;
        std::thread::spawn(move || {
            let mut frame = vec![0u8; 65536 + 4];
            loop {
                let n = match t.read(&mut frame[4..]) {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };
                frame[..4].copy_from_slice(&(n as u32).to_be_bytes());
                if q.write_all(&frame[..n + 4]).is_err() {
                    break;
                }
            }
        });
    }
    LONG.store(long_run, Ordering::Relaxed);
    let fail = |m: String| println!("net-peer-fail: {m}");
    for (port, l) in listeners {
        let bit = match port {
            NS_BDP_PORT => NS_BDP,
            NS_LOSS_PORT => NS_LOSS,
            NS_BLACKOUT_PORT => NS_BLACKOUT,
            NS_KEEPALIVE_PORT => NS_KEEPALIVE,
            NS_RST_PORT => NS_RST,
            NS_ZWIN_PORT => NS_ZWIN,
            _ => NS_WRAP,
        };
        if mask & bit == 0 {
            continue;
        }
        let r = match port {
            NS_BDP_PORT => peer_bdp(&l),
            NS_LOSS_PORT => peer_loss(&l),
            NS_BLACKOUT_PORT => peer_blackout(&l),
            NS_KEEPALIVE_PORT => peer_keepalive(&l),
            NS_RST_PORT => peer_rst(&l),
            NS_ZWIN_PORT => peer_zwin(&l),
            _ => peer_wrap(&l),
        };
        netem("");
        match r {
            Ok(msg) => println!("net-peer: {msg}"),
            Err(e) => fail(e),
        }
        let big = oversize.load(Ordering::Relaxed);
        if big > 0 {
            fail(format!(
                "the guest sent {big} frames larger than the 1500-byte MTU (port {port})"
            ));
            oversize.store(0, Ordering::Relaxed);
        }
    }
    println!("net-peer: done");
    // Keep relaying until xtask kills us.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn accept_mode(l: &TcpListener) -> Result<(TcpStream, u8), String> {
    let (mut s, _) = io(l.accept(), "accept")?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(120)));
    let mode = read_byte(&mut s)?;
    Ok((s, mode))
}

fn peer_bdp(l: &TcpListener) -> Result<String, String> {
    // 40 ms each way: an 80 ms RTT, where an unscaled 64 KiB window caps a
    // flow at ~800 KB/s.
    netem("delay 40ms");
    let (mut s, _) = accept_mode(l)?;
    let (down, up) = (32 * MIB, 16 * MIB);
    let seed = next_seed();
    io(s.write_all(&cfg_bytes(&[down, up, seed])), "config")?;
    io(send_stream(&mut s, down, seed, 256 << 10), "download")?;
    recv_stream(&mut s, up, seed + 1, true).map_err(|e| format!("ns-bdp upload: {e}"))?;
    let mss = tcp_rcv_mss(&s);
    io(s.write_all(b"K"), "verdict")?;
    if mss > 1448 {
        return Err(format!(
            "ns-bdp: guest segments carried {mss} payload bytes; with timestamps the MSS is 1448"
        ));
    }
    Ok(format!("ns-bdp ok (peer rcv_mss {mss})"))
}

fn peer_loss(l: &TcpListener) -> Result<String, String> {
    netem("delay 2ms loss 1% duplicate 1% reorder 25% 50%");
    let (mut s, _) = accept_mode(l)?;
    let len = if long() { 256 * MIB } else { 32 * MIB };
    let seed = next_seed();
    io(s.write_all(&cfg_bytes(&[len, len, seed])), "config")?;
    let t0 = Instant::now();
    duplex(s, len, len, seed).map_err(|e| format!("ns-loss: {e}"))?;
    Ok(format!(
        "ns-loss ok ({len} bytes each way in {:.1?})",
        t0.elapsed()
    ))
}

fn peer_blackout(l: &TcpListener) -> Result<String, String> {
    let (mut s, _) = accept_mode(l)?;
    let len = 16 * MIB;
    let seed = next_seed();
    io(s.write_all(&cfg_bytes(&[len, len, seed])), "config")?;
    let mut w = io(s.try_clone(), "clone")?;
    // Blackout 1: 3 s with 4 MiB of the download sent.
    let tx = std::thread::spawn(move || -> std::io::Result<()> {
        send_stream(&mut w, 4 * MIB, seed, 64 << 10)?;
        netem("loss 100%");
        std::thread::sleep(Duration::from_secs(3));
        netem("");
        let mut buf = vec![0u8; 64 << 10];
        let mut off = 4 * MIB;
        while off < len {
            rfill(&mut buf, off, seed);
            w.write_all(&buf)?;
            off += buf.len() as u64;
        }
        Ok(())
    });
    // Blackout 2: 3 s once 12 MiB of the upload arrived.
    recv_stream(&mut s, 12 * MIB, seed + 1, false)
        .map_err(|e| format!("ns-blackout upload: {e}"))?;
    netem("loss 100%");
    std::thread::sleep(Duration::from_secs(3));
    netem("");
    let mut buf = vec![0u8; 1 << 20];
    let mut got = 12 * MIB;
    while got < len {
        let want = buf.len().min((len - got) as usize);
        let n = io(s.read(&mut buf[..want]), "ns-blackout upload")?;
        if n == 0 {
            return Err(format!("ns-blackout: upload EOF at {got}"));
        }
        if let Some(k) = rcheck(&buf[..n], got, seed + 1) {
            return Err(format!(
                "ns-blackout: upload mismatch at {}",
                got + k as u64
            ));
        }
        got += n as u64;
    }
    wait_eof(&mut s)?;
    let sent = tx
        .join()
        .map_err(|_| "ns-blackout: sender panicked".to_string())?;
    io(sent, "ns-blackout download")?;
    io(s.write_all(b"K"), "verdict")?;
    Ok("ns-blackout ok".into())
}

fn peer_keepalive(l: &TcpListener) -> Result<String, String> {
    let (mut s, _) = accept_mode(l)?;
    io(s.write_all(&cfg_bytes(&[0])), "config")?;
    if read_byte(&mut s)? != b'B' {
        return Err("ns-keepalive: bad byte".into());
    }
    io(s.write_all(b"A"), "ack")?;
    std::thread::sleep(Duration::from_millis(300));
    // The peer vanishes: nothing in, nothing out.
    netem("loss 100%");
    std::thread::sleep(Duration::from_secs(16));
    netem("");
    drop(s);
    Ok("ns-keepalive: link restored".into())
}

fn peer_rst(l: &TcpListener) -> Result<String, String> {
    let mut problems = Vec::new();
    let is_reset = |e: &std::io::Error| {
        matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        )
    };
    loop {
        let (mut s, mode) = accept_mode(l)?;
        let seed = next_seed();
        io(s.write_all(&cfg_bytes(&[seed])), "config")?;
        match mode {
            1 => {
                // The guest reads 1 MiB then closes with SO_LINGER 0.
                let w = send_stream(&mut s, 64 * MIB, seed, 64 << 10);
                let verdict = match w {
                    Err(e) if is_reset(&e) => Ok(()),
                    Err(e) => Err(format!(
                        "linger-0 close: write failed with {e}, not a reset"
                    )),
                    Ok(()) => {
                        let mut b = [0u8; 1];
                        match s.read(&mut b) {
                            Err(e) if is_reset(&e) => Ok(()),
                            Ok(0) => Err("linger-0 close arrived as a FIN, not an RST".into()),
                            r => Err(format!("linger-0 close: read gave {r:?}")),
                        }
                    }
                };
                if let Err(e) = verdict {
                    problems.push(e);
                }
            }
            2 => {
                let mut buf = vec![0u8; 65536];
                rfill(&mut buf, 0, seed);
                io(s.write_all(b"g"), "sync")?;
                io(s.write_all(&buf), "unread data")?;
                let mut b = [0u8; 1];
                match s.read(&mut b) {
                    Err(e) if is_reset(&e) => {}
                    Ok(0) => problems.push(
                        "close() with unread data sent a FIN; Linux tcp_close sends an RST".into(),
                    ),
                    r => problems.push(format!("close() with unread data: read gave {r:?}")),
                }
            }
            3 => {
                io(
                    send_stream(&mut s, 2 * MIB, seed, 64 << 10),
                    "pre-abort data",
                )?;
                std::thread::sleep(Duration::from_millis(500));
                set_linger_zero(&s);
                drop(s);
            }
            4 => {
                io(
                    s.write_all(if problems.is_empty() { b"K" } else { b"F" }),
                    "verdict",
                )?;
                return if problems.is_empty() {
                    Ok("ns-rst ok".into())
                } else {
                    Err(format!("ns-rst: {}", problems.join("; ")))
                };
            }
            m => return Err(format!("ns-rst: unknown mode {m}")),
        }
    }
}

fn peer_zwin(l: &TcpListener) -> Result<String, String> {
    // A small receive buffer so our window closes quickly when we pause.
    let (mut s, _) = accept_mode(l)?;
    set_rcvbuf(&s, 16384);
    let (down, up, pause) = (16 * MIB, 16 * MIB, 3_000u64);
    let seed = next_seed();
    io(s.write_all(&cfg_bytes(&[down, up, seed, pause])), "config")?;
    let t0 = Instant::now();
    io(send_stream(&mut s, down, seed, 64 << 10), "download")?;
    let down_t = t0.elapsed();
    // Read the upload with three 3 s pauses.
    let mut buf = vec![0u8; 64 << 10];
    let mut got = 0u64;
    let mut pauses = 0u64;
    let t1 = Instant::now();
    while got < up {
        if pauses < 3 && got >= (pauses + 1) * (up / 4) {
            std::thread::sleep(Duration::from_millis(pause));
            pauses += 1;
        }
        let want = buf.len().min((up - got) as usize);
        let n = io(s.read(&mut buf[..want]), "upload")?;
        if n == 0 {
            return Err(format!("ns-zwin: upload EOF at {got}"));
        }
        if let Some(k) = rcheck(&buf[..n], got, seed + 1) {
            return Err(format!("ns-zwin: upload mismatch at {}", got + k as u64));
        }
        got += n as u64;
    }
    wait_eof(&mut s)?;
    let up_t = t1.elapsed();
    io(s.write_all(b"K"), "verdict")?;
    // Three 3 s pauses each way; persist probing must restart each flow
    // within a few seconds.
    let limit = Duration::from_secs(9 + 20);
    if down_t > limit || up_t > limit {
        return Err(format!(
            "ns-zwin: stalled — download {down_t:.1?}, upload {up_t:.1?} with 9 s of pauses"
        ));
    }
    Ok(format!(
        "ns-zwin ok (download {down_t:.1?}, upload {up_t:.1?})"
    ))
}

fn peer_wrap(l: &TcpListener) -> Result<String, String> {
    netem_wrap("0.01%", "20%");
    let (mut s, _) = accept_mode(l)?;
    let len = if long() { 4 * GIB + GIB / 2 } else { 512 * MIB };
    let seed = next_seed();
    io(s.write_all(&cfg_bytes(&[len, len, seed])), "config")?;
    let t0 = Instant::now();
    duplex(s, len, len, seed).map_err(|e| format!("ns-wrap: {e}"))?;
    let (d_tap, d_ifb) = (wrap_band_drops("tap0"), wrap_band_drops("ifb0"));
    if long() && (d_tap == 0 || d_ifb == 0) {
        return Err(format!(
            "ns-wrap: no segment near the wrap was dropped (to guest {d_tap}, from guest {d_ifb})"
        ));
    }
    Ok(format!(
        "ns-wrap ok ({len} bytes each way in {:.1?}; wrap-band drops: to guest {d_tap}, from guest {d_ifb})",
        t0.elapsed()
    ))
}
