//! Deterministic HTTP/3 acceptance for a live QEMU distro guest.
//!
//! The fixture deliberately implements only the server half needed for this
//! smoke: HTTP/3 control/QPACK streams plus a static-table `:status = 200`
//! response. The guest remains the real HTTP/3 implementation (stock curl),
//! so the check crosses the actual NARF virtio-net → SLIRP UDP path.

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::sync::{oneshot, Notify};

const STREAMS: usize = 16;
const CONNECTIONS: usize = 8;
const BODY: &[u8] = b"narf-h3-ok\n";

/// Options for the live CachyOS HTTP/3 acceptance check.
#[derive(clap::Args)]
pub struct Args {
    /// Host interface on which the guest SSH forward is reachable.
    #[arg(long, default_value = "127.0.0.1")]
    ssh_host: String,

    /// Host TCP port forwarded to the guest's SSH service.
    #[arg(long, default_value_t = 2222)]
    ssh_port: u16,

    /// User in the disposable test image that runs curl.
    #[arg(long, default_value = "narf")]
    ssh_user: String,
}

#[derive(Default)]
struct SharedStats {
    connections: AtomicUsize,
    requests: AtomicUsize,
    first_batch_arrived: AtomicUsize,
    first_batch_ready: Notify,
    error: Mutex<Option<String>>,
}

impl SharedStats {
    fn record_error(&self, error: impl std::fmt::Display) {
        let Ok(mut slot) = self.error.lock() else {
            return;
        };
        if slot.is_none() {
            *slot = Some(error.to_string());
        }
    }

    fn error(&self) -> Option<String> {
        self.error.lock().ok().and_then(|slot| slot.clone())
    }
}

#[derive(Debug)]
struct Metrics {
    connections: usize,
    requests: usize,
}

struct H3Server {
    port: u16,
    stop: Option<oneshot::Sender<()>>,
    result: Receiver<Result<Metrics>>,
}

impl H3Server {
    fn start() -> Result<Self> {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let (stop_tx, stop_rx) = oneshot::channel();
        thread::spawn(move || {
            let result = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("build HTTP/3 fixture runtime")
                .and_then(|runtime| runtime.block_on(run_server(ready_tx, stop_rx)));
            let _ = result_tx.send(result);
        });
        let port = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .context("HTTP/3 fixture did not become ready")??;
        Ok(Self {
            port,
            stop: Some(stop_tx),
            result: result_rx,
        })
    }

    fn finish(mut self) -> Result<Metrics> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        self.result
            .recv_timeout(Duration::from_secs(10))
            .context("HTTP/3 fixture did not stop")?
    }
}

async fn run_server(
    ready: SyncSender<Result<u16>>,
    mut stop: oneshot::Receiver<()>,
) -> Result<Metrics> {
    let stats = Arc::new(SharedStats::default());
    let endpoint =
        quinn::Endpoint::server(server_config()?, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .context("bind HTTP/3 fixture UDP socket")?;
    let port = endpoint.local_addr()?.port();
    let _ = ready.send(Ok(port));

    loop {
        tokio::select! {
            maybe_incoming = endpoint.accept() => {
                let Some(incoming) = maybe_incoming else {
                    break;
                };
                let stats = stats.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(incoming, stats.clone()).await {
                        stats.record_error(error);
                    }
                });
            }
            _ = &mut stop => break,
        }
    }

    endpoint.close(quinn::VarInt::from_u32(0), b"smoke complete");
    // The SSH command only succeeds after curl has received every body. A
    // short grace period lets the async handler record its final counters.
    tokio::time::sleep(Duration::from_millis(200)).await;
    if let Some(error) = stats.error() {
        bail!("HTTP/3 fixture: {error}");
    }
    Ok(Metrics {
        connections: stats.connections.load(Ordering::Acquire),
        requests: stats.requests.load(Ordering::Acquire),
    })
}

fn server_config() -> Result<quinn::ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("create HTTP/3 fixture certificate")?;
    let certificate = rustls::pki_types::CertificateDer::from(certified.cert);
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key.into())
        .context("configure HTTP/3 fixture TLS")?;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(crypto).context("configure QUIC TLS")?,
    )))
}

async fn serve_connection(incoming: quinn::Incoming, stats: Arc<SharedStats>) -> Result<()> {
    let connection = incoming.await.context("accept QUIC connection")?;
    stats.connections.fetch_add(1, Ordering::AcqRel);
    let _critical_streams = open_critical_streams(&connection).await?;
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let stats = stats.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_request(send, recv, stats.clone()).await {
                        stats.record_error(error);
                    }
                });
            }
            // curl closes each short-lived connection immediately after it
            // has received its body. Those peer close/reset outcomes are
            // normal; the aggregate request and connection counters below
            // remain the assertion that the full exchange actually happened.
            Err(quinn::ConnectionError::ApplicationClosed { .. })
            | Err(quinn::ConnectionError::ConnectionClosed(_))
            | Err(quinn::ConnectionError::Reset)
            | Err(quinn::ConnectionError::LocallyClosed) => return Ok(()),
            Err(error) => return Err(error).context("accept HTTP/3 request stream"),
        }
    }
}

/// Open the three HTTP/3 critical unidirectional streams. They intentionally
/// stay alive until their connection ends: closing any one is a protocol error
/// and would let a test pass only because curl had fallen back or given up.
async fn open_critical_streams(connection: &quinn::Connection) -> Result<Vec<quinn::SendStream>> {
    let mut control = connection.open_uni().await?;
    // Stream type = control (0), then an empty SETTINGS frame (type 4,
    // length 0). The fixture requires no optional HTTP/3 settings.
    control.write_all(&[0x00, 0x04, 0x00]).await?;
    let mut encoder = connection.open_uni().await?;
    encoder.write_all(&[0x02]).await?; // QPACK encoder stream type.
    let mut decoder = connection.open_uni().await?;
    decoder.write_all(&[0x03]).await?; // QPACK decoder stream type.
    Ok(vec![control, encoder, decoder])
}

async fn serve_request(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    stats: Arc<SharedStats>,
) -> Result<()> {
    // A GET carries its HEADERS then FIN. Reading it proves the client reached
    // the request stream; the fixture need not decode QPACK request headers.
    let _request = recv
        .read_to_end(64 * 1024)
        .await
        .context("read HTTP/3 request")?;

    // Hold the first 16 responses until all 16 requests have arrived. This
    // forces the parallel curl phase to exercise simultaneous streams rather
    // than merely issuing 16 serial requests on a reusable connection.
    let position = stats.first_batch_arrived.fetch_add(1, Ordering::AcqRel) + 1;
    if position <= STREAMS {
        stats.first_batch_ready.notify_waiters();
        while stats.first_batch_arrived.load(Ordering::Acquire) < STREAMS {
            stats.first_batch_ready.notified().await;
        }
    }

    // HEADERS frame, three-byte QPACK block:
    //   required-insert-count = 0, delta-base = 0,
    //   indexed static-table entry 25 (`:status = 200`).
    let mut response = Vec::with_capacity(5 + 2 + BODY.len());
    response.extend_from_slice(&[0x01, 0x03, 0x00, 0x00, 0xd9]);
    response.extend_from_slice(&[0x00, BODY.len() as u8]); // DATA frame.
    response.extend_from_slice(BODY);
    send.write_all(&response)
        .await
        .context("write HTTP/3 response")?;
    send.finish().context("finish HTTP/3 response")?;
    stats.requests.fetch_add(1, Ordering::AcqRel);
    Ok(())
}

struct AskPass(PathBuf);

impl AskPass {
    fn create(password: &str) -> Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "narf-http3-askpass-{}-{nonce}.sh",
            std::process::id()
        ));
        let body = format!("#!/bin/sh\nprintf '%s\\n' {}\n", shell_quote(password));
        std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))?;
        let mut permissions = std::fs::metadata(&path)?.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions)?;
        Ok(Self(path))
    }
}

impl Drop for AskPass {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\\"'\\\"'"))
}

fn guest_script(port: u16) -> String {
    let urls = (0..STREAMS)
        .map(|index| format!("\"$base/stream/{index:02}\""))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        r#"set -eu
base='https://10.0.2.2:{port}'
out="$(mktemp)"
trap 'rm -f "$out" "$out".*' EXIT

# HTTP/3 multiplexing: all {STREAMS} GETs must complete while the fixture
# deliberately holds them until every request stream has arrived.
curl --disable --http3-only --insecure --fail --silent --show-error --max-time 30 \
  --parallel --parallel-max {STREAMS} {urls} >"$out"
[ "$(grep -c '^narf-h3-ok$' "$out")" -eq {STREAMS} ]

# Independent client processes prevent connection reuse. Their exact count is
# verified by the host fixture after all eight complete.
pids=''
for index in 0 1 2 3 4 5 6 7; do
  (curl --disable --http3-only --insecure --fail --silent --show-error --max-time 30 \
      "$base/connection/$index" >"$out.$index") &
  pids="$pids $!"
done
for pid in $pids; do
  wait "$pid"
done
for reply in "$out".[0-7]; do
  [ "$(cat "$reply")" = 'narf-h3-ok' ]
done
printf 'NARF-HTTP3-SMOKE: OK streams={STREAMS} connections={CONNECTIONS}\n'
"#
    )
}

fn run_guest(args: &Args, password: &str, port: u16) -> Result<()> {
    let askpass = AskPass::create(password)?;
    let target = format!("{}@{}", args.ssh_user, args.ssh_host);
    let mut child = Command::new("ssh")
        .args([
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-p",
        ])
        .arg(args.ssh_port.to_string())
        .arg(target)
        .arg("sh -s")
        .env("SSH_ASKPASS", &askpass.0)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "narf-http3-smoke")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("launch SSH for HTTP/3 smoke")?;
    let script = guest_script(port);
    child
        .stdin
        .take()
        .context("HTTP/3 smoke SSH has no stdin")?
        .write_all(script.as_bytes())
        .context("send HTTP/3 smoke script to guest")?;
    let output = child
        .wait_with_output()
        .context("wait for guest HTTP/3 smoke")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        bail!(
            "guest HTTP/3 smoke failed ({:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status.code()
        );
    }
    if !stdout.contains("NARF-HTTP3-SMOKE: OK") {
        bail!(
            "guest HTTP/3 smoke returned no success marker\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
    print!("{stdout}");
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    Ok(())
}

/// Run the HTTP/3 transport and multiplexing acceptance test.
pub fn run(args: &Args) -> Result<()> {
    let password = std::env::var("XTASK_HTTP3_SMOKE_SSH_PASSWORD").map_err(|_| {
        anyhow!(
            "set XTASK_HTTP3_SMOKE_SSH_PASSWORD for the disposable guest account; \
             it is intentionally not stored in the repository"
        )
    })?;
    let server = H3Server::start()?;
    println!(
        "xtask http3-smoke: fixture on 127.0.0.1:{}; guest uses 10.0.2.2:{}",
        server.port, server.port
    );
    let guest = run_guest(args, &password, server.port);
    let metrics = server.finish();
    guest?;
    let metrics = metrics?;
    let expected_connections = CONNECTIONS + 1;
    let expected_requests = STREAMS + CONNECTIONS;
    if metrics.connections != expected_connections || metrics.requests != expected_requests {
        bail!(
            "HTTP/3 topology mismatch: got {} connection(s), {} request(s); \
             expected {expected_connections} connection(s), {expected_requests} request(s)",
            metrics.connections,
            metrics.requests
        );
    }
    println!(
        "xtask http3-smoke: OK — {STREAMS} parallel streams on one QUIC connection, \
         then {CONNECTIONS} independent connections"
    );
    Ok(())
}
