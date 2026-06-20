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

## Intended NARF-vs-Linux-over-tap wiring (for xtask)

This mirrors the existing `redis-bench` flow
(`build/xtask/src/main.rs`: `boot_narf_redis` / `boot_linux_redis` /
`run_redis_benchmark`). **Do not** hand-edit those here — this section
is the spec for whoever wires it in.

1. **Embed the server in NARF** (same path redis takes):
   - Drop `mt_echo_server_x86_64` next to the other guest binaries in
     `verification/data/musl-demo/` (or a sibling), add a
     `cargo:rerun-if-changed` + `include_bytes!` entry in
     `verification/build.rs` + `verification/src/lib.rs` (e.g.
     `NARF_MT_ECHO_ELF`), and have `frame/src/bare_main.rs` spawn it —
     exactly like `netserve` / `redis-server` are spawned today
     (search `NARF_NETSERVE_SMOKE_ELF`, the redis spawn near line
     3647). Spawn it bound on `0.0.0.0:<guest_port>` with a thread
     count matching the guest vCPU count (`MT_ECHO_THREADS` or argv[2]).

2. **Boot NARF over the tap** (the MQ scenario):
   - Reuse `boot_narf_redis`'s structure but:
     - wait for `mt-echo: listening` instead of
       `Ready to accept connections`;
     - set `NARF_QEMU_SMP=<n>` (MQ needs multiple vCPUs to land flows
       on multiple cores) instead of forcing `=1`;
     - use **tap mode** (`XTASK_QEMU_TAP=1`), guest `10.0.2.15`, host
       `tap0` `10.0.2.2`. Host tap setup:
       ```sh
       ip tuntap add tap0 mode tap
       ip addr add 10.0.2.2/24 dev tap0
       ip link set tap0 up
       ```
     - enable multi-queue virtio-net on the QEMU device
       (`-device virtio-net-pci,...,mq=on,vectors=<2N+2>` + a
       multi-queue `-netdev tap,...,queues=<N>`), so RSS actually has
       multiple queues to steer into. (Single-queue = the redis
       situation; the point of this workload is `queues>1`.)

3. **Drive the load from the host**:
   ```sh
   loadgen 10.0.2.15 <guest_port> <connections> <duration> <client_threads>
   ```
   Parse the `RESULT ... rps= p50_us= p99_us= p999_us=` line.

4. **Linux baseline**: mirror `boot_linux_redis` — same
   `mt_echo_server_x86_64` binary, busybox `init` that brings up
   `eth0 10.0.2.15` and `exec`s the server, same QEMU + multi-queue
   virtio-net + tap, just a stock Linux kernel. Run the IDENTICAL
   `loadgen` invocation and print NARF-guest-vs-Linux-host side by
   side.

5. **The MQ scaling sweep** (what proves MQ's value): for
   `queues ∈ {1,2,4,8}` (with `server_threads == queues` and
   `vCPUs >= queues`), run the same `loadgen` and chart rps + p99 vs
   queue count. Single-queue is the redis-equivalent floor; throughput
   and p99 should improve as queues rise — the result redis cannot
   show.

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
