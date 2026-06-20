# mt-echo — multi-queue NIC benchmark workload for NARF

A multithreaded `SO_REUSEPORT` TCP server plus a host-side load
generator, built to **exercise a multi-queue virtio-net NIC + RSS
under NARF in parallel across CPU cores**.

## Why this exists (and why redis can't do it)

`redis-server` is single-threaded: every client connection is serviced
on one core, so a single RX queue does all the work and the extra
queues of a multi-queue NIC sit idle. It cannot demonstrate the value
of MQ virtio-net or RSS.

`mt-echo` is the opposite. It runs **N worker threads, each with its
OWN listening socket bound to the same port via `SO_REUSEPORT`**. The
kernel (and, with a real multi-queue NIC, the NIC's RSS hash) steers
different TCP flows to different listening sockets, so different
threads on different cores consume RX **in parallel**. With MQ enabled
each flow lands on its own RX queue → its own IRQ/core. That is what
lets throughput AND latency scale with queue count — the whole point.

## Files

| File | What it is |
|------|------------|
| `mt_echo_server.c` | The guest server. N pthreads, each `socket`+`SO_REUSEPORT`+`bind`+`listen`+ own `epoll` accept/serve loop. Tiny fixed reply (`"OK\n"`), no global lock on the hot path, `TCP_NODELAY`. |
| `loadgen.c` | Host load generator. Opens C persistent connections across T client threads, loops request→response for D seconds, reports aggregate **req/s** + latency **p50/p99/p99.9** (µs) from a 1µs-resolution histogram. |
| `Makefile` / `build.sh` | Build both. Server is **fully static against musl**, placed for NARF's user VA. |
| `run_local.sh` | LOCAL validation: runs server+loadgen on `127.0.0.1` at 1/2/4/8 server threads and prints the throughput/latency scaling table. |

## Build

```sh
./build.sh          # builds + verifies the server is a static ELF
# or
make                # server (via build.sh) + loadgen
make verify         # build server + assert static
```

Requirements: `musl-gcc` (here `/usr/local/bin/musl-gcc`) and a host C
compiler. Outputs:

- `mt_echo_server_x86_64` — static musl x86_64 ELF (runs under NARF
  *and* natively on Linux, since it's a valid Linux ELF).
- `loadgen` — host dynamic build.

Verified static:

```
$ file mt_echo_server_x86_64
mt_echo_server_x86_64: ELF 64-bit LSB executable, x86-64, ... statically linked, stripped
$ ldd mt_echo_server_x86_64
        not a dynamic executable
```

### Static-link recipe note

The committed `verification/data/musl-demo/hello_musl_x86_64` was built
on a toolchain whose GCC defaulted to **non-PIE**, so plain `-static
-no-pie` worked. THIS host's GCC defaults to PIE and its
`musl-gcc.specs` hardcodes the PIE startup objects (`Scrt1.o` /
`crtbeginS.o`), which can't be linked at NARF's high text address
(`-Ttext-segment=0x8000001000`) — `_start`'s PC32 reloc against
`_DYNAMIC` overflows. `build.sh` therefore drives the non-PIE crt
explicitly (`-nostartfiles` + `crt1.o`/`crti.o`/`crtn.o`),
`-mcmodel=large` (high VA absolute relocs), and
`-Wl,--defsym=_DYNAMIC=0x8000001000` (same trick `REGEN_pthread.sh`
uses; `_DYNAMIC` is never dereferenced in a static no-PIE binary, it
just has to resolve near `.text`). See the header comment in
`build.sh`.

## Run the server

```sh
mt_echo_server_x86_64 [PORT] [THREADS]
#   PORT    default 7000  (or env MT_ECHO_PORT)
#   THREADS default 4     (or env MT_ECHO_THREADS)
```

When all N listeners are up it prints the readiness marker
**`mt-echo: listening port=<P> threads=<N>`** on stdout (then flushes).
A harness greps for this exactly like the redis path greps for
`Ready to accept connections`.

## Run the load generator

```sh
loadgen <host> <port> <connections> <duration_sec> [client_threads] [reqbytes]
```

Prints one machine-parseable line to stdout:

```
RESULT host=... port=... conns=... threads=... secs=... requests=... \
       errors=... rps=... p50_us=... p99_us=... p999_us=...
```

## Local scaling validation

```sh
./run_local.sh [PORT] [CONNS] [DURATION] [CLIENT_THREADS]
```

Runs the server at 1/2/4/8 threads on `127.0.0.1` and shows req/s
rising with server thread count on this multicore host. See the bottom
of this file for a sample result.

## Running under NARF (implemented)

The server is embedded in the kernel image and boot-spawned, and an
xtask subcommand drives `loadgen` against it. (This mirrors the
`redis-bench` flow: `build/xtask/src/main.rs`
`boot_narf_redis`/`redis_bench_cmd`.)

**How it's wired:**
- `mt_echo_server_x86_64` is committed at
  `verification/data/musl-demo/`, embedded via `NARF_MT_ECHO_ELF`
  (`verification/build.rs` + `verification/src/lib.rs`).
- A `mt-echo` cargo feature (`frame/Cargo.toml`, implies `qemu-net`)
  makes `frame/src/bare_main.rs` spawn the server on `0.0.0.0:7000`
  **instead of** redis. Worker count comes from the kernel cmdline
  `mt_echo_threads=N` (default = CPU count) — passed via QEMU `-append`
  (`XTASK_QEMU_APPEND`), so a thread sweep needs **no kernel rebuild**.
- `cargo run -p xtask -- mt-echo-bench --arch=x86_64` builds the host
  `loadgen`, boots NARF per `XTASK_MT_ECHO_THREADS` (CSV sweep), waits
  for the `mt-echo: listening` marker, runs `loadgen`, and prints an
  rps + p50/p99/p99.9 table.

**Reproduction (real multi-queue tap):**
```sh
# one-time host tap (persistent), gateway IP NARF expects:
ip tuntap add tap0 mode tap multi_queue        # if not already present
ip addr add 10.0.2.2/24 dev tap0; ip link set tap0 up

NARF_QEMU_SMP=8 \
XTASK_QEMU_ACCEL=kvm XTASK_QEMU_TAP=tap0 XTASK_QEMU_QUEUES=4 \
XTASK_MT_ECHO_THREADS=4 XTASK_MT_ECHO_CONNS=50 XTASK_MT_ECHO_SECS=5 \
  cargo run -p xtask -- mt-echo-bench --arch=x86_64
```
Knobs: `XTASK_MT_ECHO_THREADS` (server-worker CSV sweep, default 4),
`XTASK_MT_ECHO_CONNS` (50), `XTASK_MT_ECHO_SECS` (5),
`XTASK_MT_ECHO_CLIENT_THREADS` (default `min(conns,64)` — fewer caps
offered concurrency and under-measures the server), `XTASK_QEMU_QUEUES`
(virtio-net queue pairs, tap only), `NARF_QEMU_SMP`.

## Measured under NARF (debug kernel, KVM, tap0 multi_queue, 50 conns/5s)

Off-box over a **real multi-queue NIC** (not SLIRP). 0 errors throughout.

| config | rps | p50 | p99 |
|---|---|---|---|
| SLIRP (single-queue, q=1) | ~16k | ~470µs | ~1.3ms |
| tap q=4, before RX poll-backoff fix | ~4k | ~450µs | **~22.7ms** |
| tap q=4, after fix, SMP=5 | ~57–65k | ~800µs | ~1.8ms |
| tap q=4, **SMP=8** | **~74k** | ~650µs | ~1.3ms |

Findings (all in `docs/redis-perf-plan.md`):
1. **RX poll-backoff was the tap killer**: poll-only queue forwarders
   slept `PUMP_CYCLES` (~22ms at the KVM TSC) when an RSS-fed queue
   briefly idled → 9× throughput / 25× tail once gated on NIC-wide
   activity.
2. **The loadgen's client-thread count caps it**: 16 threads × ~410µs
   RTT ≈ 39k looked like a NARF ceiling but wasn't; one thread per
   connection lifted it to ~60–74k.
3. **Removing the global TCB_TABLE RX lock** (sharded 4-tuple index):
   correct (5138 kernel-tests) but throughput-neutral at 50 conns.
4. **Forwarder CPU placement**: tried, **reverted** — at SMP=8 it
   measured slightly *worse* (69k vs 74k index-only). The BSP forwarder
   isn't the bottleneck at this scale.
5. **The real lever is worker cores**: SMP 5→8 took q=4/t=4 from 59k to
   74k. Earlier "flat thread scaling" was core starvation, not RX.

## NARF vs Linux (same binary, stock Linux kernel, same MQ tap)

`mt-echo-bench` now boots a Linux baseline too (`boot_linux_mt_echo`:
the SAME static binary under a stock kernel, SAME multi-queue tap +
vCPUs, `ethtool -L eth0 combined N` to activate Linux's queues). It runs
NARF then Linux per config (sequentially — they share `10.0.2.15`) and
prints a side-by-side table. (Tap-only; opt out with
`XTASK_MT_ECHO_NO_LINUX`.)

q=4, SMP=8, KVM, 50 conns / 5s, 0 errors both:

| threads | NARF rps | Linux rps | N/L | NARF p99 | Linux p99 |
|---|---|---|---|---|---|
| 1 | 71.8k | 77.8k | **0.92×** | 1279µs | 841µs |
| 2 | 72.7k | 110.5k | 0.66× | 1307µs | 734µs |
| 4 | 72.0k | 110.4k | 0.65× | 1320µs | 685µs |

**The gap is scaling, not single-thread speed.** NARF is near-parity at
1 thread (0.92×), but **Linux scales 1→2 threads (78k→110k) while NARF
stays flat at ~72k for any thread count** — NARF's RX dispatch is
single-cored (the N per-queue forwarders time-share the BSP), so worker
threads can't outrun what the one BSP forwarder feeds. Lifting this needs
RX dispatch spread across cores with forwarders and workers on disjoint
core sets (see `docs/redis-perf-plan.md`).

## Sample LOCAL result

On this 32-core host, `127.0.0.1`, `loadgen` pinned with the server to
the same core set. Throughput rises and p50 latency falls as the
number of server threads (= number of `SO_REUSEPORT` listeners) grows —
the parallel-RX-consumption behaviour MQ + RSS is meant to exploit.

Moderate load (64 conns, 16 client threads, cores 0-15):

```
server_threads=1   requests=410480  rps=102618  p50_us=149 p99_us=225 p999_us=296
server_threads=2   requests=800426  rps=200103  p50_us=101 p99_us=155 p999_us=227
server_threads=4   requests=1148845 rps=287206  p50_us=48  p99_us=188 p999_us=563
server_threads=8   requests=1050376 rps=262590  p50_us=52  p99_us=180 p999_us=254
```

Heavier load (256 conns, 24 client threads, cores 0-23) — pushes past
the 4-thread knee so 8 threads keeps scaling:

```
server_threads=1   requests=385970  rps=96491   p50_us=226 p99_us=521 p999_us=553
server_threads=4   requests=920670  rps=230164  p50_us=66  p99_us=335 p999_us=383
server_threads=8   requests=1341025 rps=335251  p50_us=60  p99_us=218 p999_us=354
```

1→8 server threads: **~3.5x throughput**, **p50 226µs→60µs**, **p99
521µs→218µs**, zero errors. Single-threaded (`server_threads=1`) is the
redis-equivalent floor; everything above it is the value a multi-queue
NIC can expose under NARF. (At light load the 8-thread case plateaus
only because the *client* side / core budget saturates first — raise
`CONNS`/`CLIENT_THREADS` and the core allotment to push further.)
