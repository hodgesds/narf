# Scaling the network stack to 100–400 Gb/s

Status: research and proposal, written against commit `61f6f1e08`. Every
`file:line` below is at that commit. Nothing here changes an interface; the
decisions in §8 are for the maintainers to make.

## 1. Summary

NARF was measured at about 300 Mb/s down and 700 Mb/s up on a 1 Gb/s I225
link. Four commits fixed the worst 1 Gb/s defects. This document is about what
stands between the stack and 100–400 Gb/s, which is a different question: at
1 Gb/s a full-size frame arrives every 12 µs and a core has about 37,000
cycles for it; at 100 Gb/s the frame arrives every 123 ns and the same core has
369.

Four findings matter more than the rest.

1. **Every received frame does global work.** Before a frame reaches GRO it
   takes the one interface-registry lock twice, clones the interface record
   (two heap allocations) twice, and takes two global classifier locks. That
   work cannot be shared out across cores: whatever one hold costs, the
   machine as a whole receives at most one frame per hold. At 1 Gb/s the lock
   is busy 2 % of the time and invisible. At 100 Gb/s it would need to be held
   for more than a second per second. In the harness, four receiving CPUs
   deliver 2.2 to 2.4 times what one does, not four times.
2. **Each payload byte is touched about seventeen times on receive.** It is
   copied four times (GRO aggregate, socket buffer, kernel bounce buffer, user
   memory), re-copied about one and a half times as the GRO buffer grows,
   summed twice in software although the NIC already verified it, and
   accompanied by nearly four bytes of zero-fill. At 100 Gb/s that is about
   200 GB/s of memory traffic for one direction, which is the whole memory
   bandwidth of a server socket and three times a desktop's. Linux touches the
   same byte once.
3. **Nothing in the stack scales with connections or cores.** A timer scan
   visits every connection every millisecond. Established-flow lookup is a
   tree under a spinlock. One connection's lock is taken 13 to 22 times per
   segment. There is no receive steering, no transmit backpressure, no pacing,
   and loss recovery resends the whole window after a timeout.
4. **Nothing is sized from the card.** Ring length, poll budget, interrupt
   moderation, queue count, buffer size, socket buffer limits and window scale
   are constants chosen for the cards at hand. The stack reads exactly two
   numbers from a device: its MTU (and not even that for the IPv4 MSS) and its
   largest TSO frame.

There is also a structural finding. The specifications say the kernel has no
L3/L4 stack and that a userspace daemon runs TCP over zero-copy rings. The
code has an in-kernel TCP/IP stack of about 20,000 lines that carries all
traffic, no daemon, and frame rings that nothing reads. §8 lays out the
options. The
recommendation is to make the in-kernel stack the stated architecture, scale
it per CPU, and keep the frame-ring path as the opt-in bypass it already is.

The plan in §9 has four stages. The first is days to weeks of contained
changes and removes the per-frame global work. The second replaces byte-queue
socket buffers with buffer references and is a redesign of the TCP data
structures. The third makes the stack per-CPU. The fourth needs 100 Gb/s
hardware and a driver that does not exist yet.

A measurement harness (`net/src/scale_bench.rs`, §10) makes progress visible
without fast hardware. Its numbers come from a QEMU guest and are labelled
"harness, non-protocol" throughout: they rank bottlenecks and show
before/after ratios on one machine. They are not performance claims.

## 2. What exists and what the specifications say

`net/specification/spec.md` states the intended architecture three times: §1
("NARF's kernel has no L3/L4 stack"), §4 ("No L3+ parsing happens in the
kernel") and §8.1 ("no in-kernel TCP/IP stack at v1.0"). `AGENTS.md` repeats
it. The same specification then documents the in-kernel TCP socket calls in
§3.7 and calls the path "the legacy in-kernel IPv4 path" in §3.1.

What the code does:

- **All traffic uses the in-kernel stack.** `tcp_stack::init` installs the
  only receive handlers (`net/src/tcp_stack.rs:775-776`). TCP is
  `net/src/tcp/` (about 8,200 lines), with IPv4, IPv6, UDP, ICMP, netfilter,
  conntrack, routing and ARP beside it.
- **No stack daemon exists.** Nothing in `userspace/`, `user-runtime/`,
  `init/` or `modules/` attaches to a frame ring. `stack::attach`,
  `attach_registered` and `control_registered` (`net/src/stack.rs:568-593`)
  have only test callers.
- **Frame rings are populated and never read.** Drivers register SPSC rings
  (`RX_RING_N = TX_RING_N = 1024`, `net/src/lib.rs:195-198`), but no non-test
  code takes `rx_ring()` or `tx_ring()`. If a consumer did attach it would get
  a mirror, not a diversion: `mirror_rx` allocates a coherent buffer and
  copies each frame (`drivers/net/core/src/publish.rs:319-327`) while the
  kernel stack still processes it.
- **The bypass path is real but small.** `AF_XDP` and the native `AF_BYPASS`
  are reachable from `socket(2)` (`userspace/src/socket.rs:2037`). Rings are
  capped at 64 entries (`net/src/bypass/xdp.rs:111`). Zero-copy binding works
  on igc only (`drivers/net/igc/src/control.rs:553-580`); other drivers return
  `EOPNOTSUPP` (`net/src/nic.rs:341-347`).
- **Userspace loopback bypasses the stack.** A `connect()` to an address with
  an in-process listener builds a pair of 64 KiB byte rings
  (`userspace/src/socket.rs:10031-10142`, `:11624`). TCP, UDP and ICMP to
  local addresses never reach `lo`. `iperf3 -c 127.0.0.1` therefore measures
  that ring, not TCP.
- **IPv6 receive from a NIC is not wired.** `dispatch_l3` matches ARP and IPv4
  and drops the rest (`net/src/tcp_stack.rs:368-374`).
  `ipv6_stack::rx_frame` (`net/src/ipv6_stack.rs:1479`) has only test
  callers. IPv6 transmit works and applies no netfilter.

## 3. Data-path cost model

The model follows a byte through each path and records, per stage, the locks
taken, the allocations made and the passes over the payload. The reference
driver is igc, because it is the one on the hardware; other drivers differ
only in the first rows and are covered in §6.4 and §7.

All locks named here are `IrqSafeSpinLock`: test-and-set with interrupts off.

### 3.1 TCP receive

| # | Stage | Where | Locks | Allocations | Payload passes |
|---|---|---|---|---|---|
| 1 | Pump wakes (MSI-X or 10 ms), polls up to 64 descriptors | `drivers/net/igc/src/igc.rs:1899-1977` | per poll: queue RX (`queue.rs:828`), device stats (`igc.rs:1921`), `IFACES` via `note_rx_drop` even for zero drops (`igc.rs:1922`) | result `Vec` | — |
| 2 | Take the filled buffer, post a fresh one | `queue.rs:940-941` → `io/src/lib.rs:713-780` | page allocator | one 4 KiB page per frame, always from node 0 (`io/src/lib.rs:738`) | zero-fill of 4,096 B per frame (`io/src/lib.rs:766`) |
| 3 | Checksum verdict and RSS hash decoded, then dropped | `queue.rs:948-952`; `igc.rs:1947-1948`, `:2126` | mirror list (`publish.rs:241`) | — | — |
| 4 | Count the frame | `net/src/iface.rs:2503` → `:1229` → `:1207-1215` | `IFACES`, linear name scan | — | — |
| 5 | Resolve the ingress interface | `net/src/tcp_stack.rs:249` → `iface.rs:1174-1178`, `:1700-1748` | `IFACES`, linear name scan | 2 (`name`, `stats.name`) | — |
| 6 | Classifier, packet tap | `tcp_stack.rs:251-253`, `:267-274`, `:336-340` | `DAEMON_CLAIMS`, `CLAIMS` (`bypass/classifier.rs:136-137`) | 1 name clone, 2 for a second snapshot clone | — |
| 7 | GRO offer | `tcp_stack.rs:399-410`; `net/src/gro.rs:256-311` | per-CPU table | first segment: frame `Vec` + name `String` (`gro.rs:330-332`) | software checksum (`gro.rs:130`, `:146`); copy into the aggregate (`gro.rs:291`, `:332`); about 1.5× more as the `Vec` doubles |
| 8 | GRO flush, per aggregate | `gro.rs:224-242`; `tcp_stack.rs:415-421` | `IFACES` per released frame (`tcp_stack.rs:418`) | 2 | checksum recomputed over the aggregate, then never read (`tcp_stack.rs:405`) |
| 9 | Netfilter PRE_ROUTING | `tcp_stack.rs:561`; `net/src/netfilter/mod.rs:330-355` | 7 global, 4 per-flow | 1 hook-list clone | — |
| 10 | Local-delivery decision | `net/src/ip_local.rs:125-141` | `IFACES`, then `IFACE_ADDRS` and `BINDINGS` per interface | 1 + 2 per interface, plus address clones | — |
| 11 | Netfilter LOCAL_IN | `tcp_stack.rs:617-619` | 2 global | 1 | — |
| 12 | Flow lookup | `net/src/tcp/core.rs:3708`, `:910-913` | one of 32 shard locks over a `BTreeMap`; IPv6 one global lock (`:809`) | — (`Arc` refcount written) | — |
| 13 | TCP input | `core.rs:4050-4125`, `:4439-4475` | connection lock 13–14 times | — | copy into `VecDeque<u8>` (`net/src/tcp/socket_buf.rs:337`) |
| 14 | ACK, per aggregate | `core.rs:2954-2981`, `:431-497` | connection lock 5 more; `ROUTE_TABLE`; `IFACES` twice; netfilter 9 global | route clone 2, snapshot 2, options, header, frame, 2 hook lists | — |
| 15 | Wake the reader | `core.rs:4469-4473`; `net/src/readiness.rs:57-66`; `userspace/src/handlers/core.inc.rs:424-460` | 11–13, including the connection lock 3 more times; one global atomic | — | — |
| 16 | `read`/`recv` | `userspace/src/handlers/sys_read.rs:237-265`; `core.rs:2182-2224` | fd shard, socket state, `TCB_TABLE` shard, connection lock across the copy | bounce buffer sized to the request | zero-fill of the bounce buffer; copy to it (`core.rs:2201`); copy to user (`sys_read.rs:248`) |

Counting row 13: `process_in_state` locks for the PAWS check, the timestamp
update and the state read (`core.rs:4079`, `:4105`, `:4112`).
`handle_in_established` then locks in `rcv_window` (`:4971`), `handle_ack`
(`:4649`), `enqueue_recv` (`:4887`), `complete_deferred_accept` (`:4410`),
`schedule_ack` (`:5030`, and `:5046` when the ACK is delayed), four times in
`pump_send` (`:3539`, `:389`, `:3550`, `:3682`) and once more to read the
connection id (`:4472`). `send_ack` adds five (`:2955`, `:2960`, `:2970`,
`:439`, `:457`) and the wake three.

`send_ack` resolves the route under the connection lock. The guard in
`match iface_for_tcb(&arc.lock())` (`core.rs:2955`) lives for the whole
statement, so `ROUTE_TABLE`, `IFACES` and two allocations nest inside it.
Data segments use a per-connection cached egress; ACKs, retransmits and
resets do not.

Per payload byte, with igc and GRO on:

| Pass | Bytes per payload byte | Kind |
|---|---|---|
| Receive-buffer zero-fill (4,096 B page per 1,448 B payload) | 2.83 | write |
| GRO checksum verify | 1 | read |
| Copy into the GRO aggregate | 1 | copy |
| Re-copy as the aggregate `Vec` doubles to 96 KiB | ≈1.5 | copy |
| GRO checksum recompute at flush | 1 | read |
| Copy into the socket buffer | 1 | copy |
| Bounce-buffer zero-fill (sized to the request) | ≥1 | write |
| Socket buffer to bounce buffer | 1 | copy |
| Bounce buffer to user | 1 | copy |

That is 5.5 copy passes, 2 read passes and 3.8 write passes.

### 3.2 TCP transmit

| # | Stage | Where | Locks | Allocations | Payload passes |
|---|---|---|---|---|---|
| 1 | `write`/`send` copies from user | `userspace/src/handlers/sys_socket_recv.rs:424-473`; `compat.inc.rs:3932-3941` | fd shard, socket state; `IO_ACCOUNTING` (global) for `write` | bounce buffer up to 1 MiB | zero-fill, then copy from user |
| 2 | Queue in the send buffer | `core.rs:2130-2163`; `socket_buf.rs:88-95` | `TCB_TABLE` shard; connection lock across the copy | `VecDeque` growth | copy |
| 3 | `pump_send` cuts the whole usable window into chunks | `core.rs:3537-3686` | connection lock across every copy | one `Vec` per chunk, up to 64 KiB each | copy |
| 4 | `send_data` builds the frame | `core.rs:3011-3071`, `:2777-2883` | connection lock 6 times per segment, once across the frame copy (`:3045`) | interface-record clone (2), options, header; a frame `Vec` when the pool cannot serve | copy; software checksum when the device has no TX checksum |
| 5 | Netfilter LOCAL_OUT + POST_ROUTING | `core.rs:445-450`; `tcp_stack.rs:824-850` | 9 global, 4 per-flow | 2 | — |
| 6 | Driver hand-off | `iface.rs:1600-1635`, `:1659-1667` | `IFACES` for the TX counter; igc: settings lock for a software Toeplitz hash per frame (`igc.rs:981-984`), queue TX lock | — | none with an owned pool buffer; else `alloc_coherent` + copy (`igc.rs:961-969`) |
| 7 | ACK arrives | `core.rs:4639-4811` | connection lock; walks the whole retransmit queue, up to 256 entries (`:4724`) | — | — |

Four copies and one zero-fill per byte, five copies when the driver has no
owned-frame path or its pool is empty. igc's pool is 8 buffers per queue
(`igc.rs:1643-1644`).

Three properties of this path matter more than its copy count.

- **No backpressure.** The driver's verdict is discarded: `let _ =
  dev.xmit_frame(f, meta);` (`core.rs:491-494`). A full ring drops the frame
  and TCP finds out by timeout. `pump_send` hands the driver the entire usable
  window in one call, so a 4 MiB send buffer is 2,900 MSS frames against a
  256-descriptor ring.
- **No pacing.** Segments leave as fast as the loop runs. Congestion control
  is CUBIC or Reno (`net/src/tcp/congestion.rs:309`, `:371`); `setsockopt`
  accepts "bbr" and silently runs CUBIC.
- **Loss recovery restarts from the left edge.** A timeout rewinds to
  `snd_una` and resends everything (`core.rs:3306-3308`). Fast retransmit
  resends one segment (`:4833-4877`). The SACK scoreboard is consulted for
  one question, whether `snd_una` itself was SACKed. There is no RACK or tail
  loss probe, and the minimum RTO is 200 ms (`retransmit.rs:52`).

Every data chunk carries PSH (`core.rs:3664-3668`). Without TSO that is every
segment, and a receiver's GRO (Linux's, and NARF's own at `gro.rs:322`) does
not hold a pushed segment. A NARF sender without TSO defeats GRO at its peer.

### 3.3 UDP

UDP matters because QUIC carries its own transport over it, so nothing below
the socket is coalesced by the stack.

Receive follows rows 1–6 and 9–11 of §3.1, then `handle_udp`
(`tcp_stack.rs:664-704`) sums the datagram in software (`:685-691`) and
`deliver_wire` (`userspace/src/socket/inet_dgram.rs:542`) queues it. Per
datagram to a userspace socket: `IFACES` five times; one global socket table
lock, `INET_DGRAM_BOUND` (`inet_dgram.rs:49-53`); about 23 allocations with
two interfaces; three copies. The wake is `readiness::notify(0)`
(`inet_dgram.rs:497-499`), which locks all 32 waker shards and wakes every
task parked in `epoll` or `poll` in the system (`core.inc.rs:502-515`).

Queue bounds: in-kernel sockets hold 128 datagrams
(`net/src/udp_sock.rs:108`); userspace sockets hold 212,992 bytes charged at
payload + 576 (`userspace/src/socket.rs:1321`, `inet_dgram.rs:44`), about
110 full-size datagrams. A full queue drops the newest silently.

Transmit, per `sendto`: `IFACES` nine times, `ROUTE_TABLE` four times, the
global socket table once, netfilter nine global locks, about 50 allocations
with two interfaces, three copies and a software checksum
(`net/src/udp_sock.rs:617-865`). UDP never requests TX checksum offload:
`L4CsumKind::Udp` has no producer.

Batching: `recvmmsg` and `sendmmsg` loop over the single-message path
(`sys_socket_recvmmsg.rs:55-75`, `sys_socket_sendmmsg.rs:32-41`).
`UDP_SEGMENT` is plumbed end to end but segmented in software, one allocation,
copy and checksum per segment (`net/src/udp_gso.rs:83-115`); it is never
offered to a NIC because `TxMeta` and `OffloadCapabilities` have no field for
it. There is no receive coalescing for UDP. `net/src/quic.rs` is a codec with
no non-test caller.

### 3.4 Loopback

There are two loopbacks, and neither is a stack measurement today.

Userspace connections to local addresses use the socket layer's byte rings
(§2). They exercise no TCP, IP or netfilter code.

The stack's own `lo` (`net/src/iface.rs:760-774`) copies the frame, counts it
under `IFACES`, and calls the receive handler inline on the sender's stack.
A per-CPU flag makes a nested send return `Err`. Any frame the stack emits
while delivering a loopback frame — a SYN-ACK, an ACK, data released by an
ACK — is sent from inside that delivery, so it meets the flag and is dropped,
and the sender ignores the error. `lo` advertises no offloads and the IPv4
MSS is 1,460 regardless of the 64 KiB loopback MTU. The harness probes a
handshake on `lo`: the connection is still in SYN-SENT 50 ms after `connect`
returns (§10.1).

Linux queues loopback frames to the per-CPU backlog (`loopback_xmit` in
`drivers/net/loopback.c`), which is why a reply never recurses. The fix here
is the same shape: a per-CPU queue drained by the outermost caller.

### 3.5 Forwarding

`ip_forward::try_forward` (`net/src/ip_forward.rs:76`) is reached after the
full receive prefix. It is off by default. Per packet it takes a global
sysctl lock, the route table and `IFACES`, runs two netfilter hooks, copies
the packet twice before the driver copies it a third time, and allocates a
closure. There is no flow cache, bridge, veth or tun/tap device.

### 3.6 Netfilter with no rules loaded

The default hooks have no early exit. `HookTable::dispatch` clones the hook
list under a global lock on every call (`netfilter/mod.rs:330-337`).
Conntrack is consulted for every packet at PRE_ROUTING and LOCAL_OUT
(`conntrack.rs:466-525`) through two global tree locks. The filter repeats
that lookup before it checks whether any chain exists (`filter.rs:222-242`).

Conntrack holds 4,096 flows (`conntrack.rs:28`). `reap_expired`
(`conntrack.rs:248`) has no non-test caller, so entries never expire: the
table fills, and from then on every new flow evicts by scanning all 4,096
entries, locking each, under a global lock (`conntrack.rs:191-211`).

### 3.7 The earlier audit's claims

| Claim | Verdict |
|---|---|
| 3–4 copies per received byte | Low. Four full copies with GRO, about 1.5 more from buffer growth, two checksum passes and 3.8 bytes of zero-fill (§3.1). |
| A 2 KiB coherent allocation per frame | Correct for igc; it is a 4 KiB page, zero-filled. i40e and ixgbe allocate and zero 16 KiB per frame. virtio-net and e1000 recycle. |
| `IFACES` taken twice per frame with a `String`-cloning snapshot | Correct before GRO. A third per IP packet (`ip_local.rs:125`), a fourth per GRO flush, two more per ACK. |
| Connection lock taken about 8 times per segment | Low. 13–14 for a segment that triggers no ACK, 18–19 with one, three more for the wake. |
| NIC checksum verdict discarded | Correct, and structural: the receive handler type is `fn(&str, &mut [u8])` (`iface.rs:2473`). No driver can pass a verdict, a hash or a queue number. |

### 3.8 Work that has landed since: transmit backpressure

Branch `claude/igc-throughput` (tip `68e1a6479`, three commits past this
document's base, under review) changes two rows of this model. Line numbers
in this subsection are at that tip.

- **Transmit.** `net/src/txq.rs` adds a per-queue contract: `TxQueue` (Linux
  `struct netdev_queue`), `TxQueueGeometry { ring_len, max_frame_descs }`
  read from the physical ring, and the `TxBackpressure` trait a driver
  implements (queue count, flow-to-queue selection, link speed, `try_xmit`).
  Stop and wake thresholds derive from the ring geometry. Each connection is
  charged for what it has in the device (`TxAccount`, `TxCharge`) and limited
  as `tcp_small_queue_check` limits it: the larger of two segments and about
  a millisecond at the pacing rate, capped by `net.ipv4.tcp_limit_output_bytes`
  (`tsq_limit`, `txq.rs:342`). The sender takes one segment per lock hold and
  un-sends it if the queue refuses (`pump_send_queued`,
  `net/src/tcp/core.rs:3831`), so a full ring no longer loses data.
- **Receive.** `iface::rx_batch` (`net/src/iface.rs:2602`) resolves the
  ingress device once per poll and folds the counters in when the batch
  ends, so rows 4 and 5 of §3.1 become per poll for a driver that uses it.

Only igc implements either. What that branch leaves for scale, in its
author's words and checked against the code:

| Still missing | Where |
|---|---|
| Adaptive byte limits (BQL). The contract already carries bytes and packets per completion, so it can be added without touching a driver. | `txq.rs:37-40` |
| Pacing or a queueing discipline. Control frames rely on descriptors reserved below the stop threshold. | `txq.rs:31-35` |
| Doorbell batching: the queued sender passes `more = false` for every frame or super-frame. | `core.rs:4083` |
| A check that a segment is still in the device before a timeout resends it (Linux `skb_still_in_host_queue`). | `core.rs`, RTO path |
| `record_tx_result` still takes `IFACES` once per transmitted frame. | `iface.rs:1584`, `:1603` |
| The cached egress is still cloned, heap strings included, on every `pump_send` and `send_data`. | `core.rs:404` |
| Receive still takes `IFACES` twice per poll (lookup, counter flush) rather than not at all. | `iface.rs:2605`, `:2639-2654` |
| Link speed is reported through the contract and nothing reads it. | `txq.rs:79` |
| No other driver implements the contract. | — |

The harness injects through `on_native_rx_timestamped`, the per-frame entry
point every other driver still uses. When that branch lands, a second
pktgen variant should inject through `rx_batch` so both paths are measured.

## 4. The arithmetic

### 4.1 Frames and aggregates per second

A full-size frame occupies MTU + 38 bytes on the wire (Ethernet header, FCS,
preamble, inter-frame gap). With timestamps a segment carries MTU − 52
payload bytes.

| Link | Frames/s, MTU 1500 | Frames/s, MTU 9000 | 64 KiB aggregates/s (45 segments) | 185 KB aggregates/s (BIG TCP, 127 segments) |
|---|---|---|---|---|
| 1 Gb/s | 81,274 | 13,830 | 1,806 | 640 |
| 10 Gb/s | 812,744 | 138,305 | 18,061 | 6,400 |
| 25 Gb/s | 2,031,860 | 345,762 | 45,152 | 15,999 |
| 100 Gb/s | 8,127,438 | 1,383,049 | 180,610 | 63,996 |
| 400 Gb/s | 32,509,753 | 5,532,197 | 722,439 | 255,982 |

With jumbo frames a 64 KiB aggregate is 7 segments, so 100 Gb/s is 197,578
aggregates per second. Jumbo frames cut per-frame work 5.9 times and leave
per-aggregate work unchanged.

### 4.2 Cycle budgets

Cycles available per frame, at 3.0 GHz per core, MTU 1500:

| Link | 1 core | 4 cores | 16 cores | 32 cores | 64 cores |
|---|---|---|---|---|---|
| 1 Gb/s | 36,912 | — | — | — | — |
| 10 Gb/s | 3,691 | 14,765 | — | — | — |
| 25 Gb/s | 1,476 | 5,906 | 23,624 | — | — |
| 100 Gb/s | 369 | 1,476 | 5,906 | 11,812 | 23,624 |
| 400 Gb/s | 92 | 369 | 1,477 | 2,953 | 5,906 |

Per 64 KiB aggregate the budget is 45 times larger: 16,610 cycles on one core
at 100 Gb/s. The design consequence is the one Linux drew. Work done per
frame must be a few hundred cycles and must not touch shared state. Work done
per aggregate can afford a protocol state machine. Work done per byte must be
one pass.

A cache miss to DRAM is about 300 cycles. At 100 Gb/s on one core, one miss
per frame spends the whole budget. An uncontended lock acquisition with
interrupts off is some tens of cycles; a contended one that moves its cache
line between cores is a miss.

### 4.3 Memory bandwidth

100 Gb/s is 12.5 GB/s of payload; 400 Gb/s is 50 GB/s. One copy pass reads
and writes that much.

From §3.1, receive on igc with GRO reads each payload byte 7.5 times and
writes 9.3 bytes per payload byte. At 100 Gb/s that is 94 GB/s read and
116 GB/s written. For scale, and as stated assumptions rather than
measurements: one core sustains on the order of 10 GB/s through `memcpy` once
buffers exceed its cache; a dual-channel DDR5 desktop moves 60–90 GB/s in
total; an eight-channel server socket moves 200–300 GB/s.

So the receive path as written needs about the whole memory bandwidth of a
server socket to carry 100 Gb/s, and cannot carry 400 Gb/s on any machine.
Some of those passes stay in cache, which lowers the DRAM traffic but not the
core time.

The per-flow consequence is sharper, because one flow's bytes are handled by
one core. Seventeen passes at 10 GB/s each bound a single flow near 5 Gb/s
before any per-packet cost. One pass bounds it near 80 Gb/s. That ratio, not
any individual lock, is why §9 puts buffer references ahead of per-CPU
scaling.

Transmit is four to five copies and one zero-fill: about 60 GB/s read and
70 GB/s written at 100 Gb/s.

### 4.4 Which shared lock saturates first

A lock held for `h` seconds per acquisition, `n` times per frame, admits at
most `1/(n·h)` frames per second machine-wide, however many cores there are.

| Lock | Scope | Acquisitions | What is done under it | At 100 Gb/s, MTU 1500 |
|---|---|---|---|---|
| `IFACES` (`iface.rs:736`) | one, all namespaces | 2 per frame before GRO; 1–2 per aggregate; 2 per ACK | name scan; snapshot with 2 allocations | 16–17 million/s |
| `CLAIMS`, `DAEMON_CLAIMS` (`classifier.rs:136-137`) | one each | 1 each per frame before GRO | table probe | 16 million/s |
| Mirror list (`publish.rs:241`) | one | 1 per frame on drivers using `publish` | list scan | 8 million/s |
| Netfilter slots, conntrack, filter, NAT | one each | 9 per packet delivered, 9 per packet sent | list clone; two tree lookups | 3 million/s with GRO; 73 million/s for UDP receive alone |
| `ROUTE_TABLE` (`route.rs:159`) | one, all namespaces | 1 per ACK; 4 per UDP send | linear scan, 2 allocations | 0.2 million/s with GRO |
| `CONN_INDEX` shard (`core.rs:805`) | 32 shards; IPv6 one lock | 1 per aggregate | tree lookup | fine until flows per shard grow |
| `readiness::GEN` (`readiness.rs:26`) | one cache line | written per wake | — | bounces between every receiving core |

`IFACES` saturates first. A lookup that scans by name and allocates twice
under the lock plausibly holds it for 150–300 ns; the harness measures the
resulting per-frame cost rather than this estimate. At two acquisitions per
frame and 250 ns together, the machine-wide ceiling is 4 million frames per
second, about 48 Gb/s at MTU 1500, with perfect hand-off. Test-and-set locks
with interrupts off do not hand off perfectly; contended, they degrade well
below that. At 1 Gb/s the same lock is busy 2 % of the time.

Without GRO — every UDP datagram, so all of QUIC — the netfilter locks
saturate at roughly the same point.

The harness shows the effect at small scale (§10.1, non-protocol): four
receiving CPUs deliver 2.2 to 2.4 times what one does for TCP and 1.6 times
for UDP, and the interface layer alone, with no stack behind it, costs about
2,600 cycles per frame once four CPUs contend for it.

### 4.5 Allocator calls

On igc each received frame costs a page allocation and free, two interface
snapshots (four `String` allocations and frees), a name clone and a share of
the GRO buffer growth: 12 or more allocator operations per frame, about
100 million per second at 100 Gb/s. Each aggregate adds two hook-list clones,
an interface snapshot per interface, and for its ACK about ten more. The
harness reports slab operations per packet directly: through the model NIC,
which allocates nothing itself on receive, it counts 41 per TCP packet
without GRO, 12 with it and 32 per UDP datagram (harness, non-protocol;
allocations plus frees up to 4 KiB).

### 4.6 Timers

`tick_all` (`core.rs:5141-5174`) runs once a millisecond on whichever CPU
wins a compare-and-swap. It collects every connection id into a `Vec`, then
for each takes a table shard lock and the connection lock six times
(`tick_retransmit`, `core.rs:3251-3269`). The cost is linear in connections
whether or not any timer is due. The harness measures 41 ns per idle
connection at 1,000 connections and 74 ns at 10,000 (harness, non-protocol),
rising as they stop fitting in cache. At that cost 13,500 connections fill
the millisecond and one core does nothing else; 100,000 need more than 7 ms
of work per 1 ms tick.

### 4.7 Windows and buffers

A flow cannot exceed window ÷ round-trip time.

| Limit | Value | Where | Rate at 0.1 ms RTT | at 1 ms | at 10 ms |
|---|---|---|---|---|---|
| Receive window, autotuned maximum (`tcp_rmem[2]` ÷ 2) | 3 MiB | `lib/src/sysctl.rs:116`; `tcp/autotune.rs:173` | 250 Gb/s | 25 Gb/s | 2.5 Gb/s |
| Largest window the scale can express (65,535 << 7) | 8 MiB | `tcp/options.rs:50` | 670 Gb/s | 67 Gb/s | 6.7 Gb/s |
| Send buffer, autotuned maximum (`tcp_wmem[2]`) | 4 MiB | `lib/src/sysctl.rs:120` | 335 Gb/s | 33 Gb/s | 3.3 Gb/s |
| `SO_SNDBUF` ceiling once an application sets it (the receive window gets half) | 425,984 B | `userspace/src/socket/sockopt.rs:186-187` | 34 Gb/s | 3.4 Gb/s | 0.34 Gb/s |

On a LAN these are not the binding limit. Across a data centre or a WAN they
are: 100 Gb/s at 10 ms needs a 125 MB window, a scale of at least 11, and
buffer maxima to match. There is no global accounting to make large maxima
safe: no `tcp_mem`, no memory-pressure state, no bound across sockets.

## 5. Gap analysis

Each row says what Linux does, what NARF has, and the ceiling the gap
imposes. Linux symbols were checked against a v7.1-rc5 tree. The last column
answers the sizing question of §6: what the value should come from.

| Area | Linux | NARF | Ceiling imposed | Sized from |
|---|---|---|---|---|
| Receive steering (RSS, RPS, RFS, aRFS) | Queue count `netif_set_real_num_rx_queues` = min(CPUs, hardware), default from `netif_get_num_default_rss_queues`; software steering `get_rps_cpu`, `set_rps_cpu`, `rps_may_expire_flow` (`net/core/dev.c`) | RSS programmed by igc, i40e, virtio-net, rtl8127 only; queue counts capped by constants (4, 8, 4, 8); the hash is dropped before the stack; no software steering; readers are never placed near their flow | One core per constant-many queues; cross-CPU wake per aggregate | Hardware queue count, MSI-X vectors, online CPUs |
| Transmit queue selection (XPS) | `netdev_pick_tx`, `__netif_set_xps_queue` | Per-frame software Toeplitz under a device lock (igc, i40e); round-robin or flow hash over pools (virtio-net) | Lock and hash per frame | TX queue count, CPU of the sender |
| Per-CPU state | Per-CPU counters with `u64_stats_update_begin`; per-CPU backlog, page-pool caches, GRO lists | Per-CPU GRO tables only. Counters under `IFACES`; pools behind one lock each | The `IFACES` ceiling of §4.4 | Online CPUs |
| Established-flow lookup | Lockless RCU hash sized from RAM: `__inet_lookup_established` (`net/ipv4/inet_hashtables.c`); early demux `tcp_v4_early_demux` | `BTreeMap` behind 32 spinlocks, IPv6 behind one; `Arc` refcount written per lookup | Shard contention and a shared-line write per aggregate | RAM (table size) |
| Socket lock and backlog | Owner flag plus backlog: `tcp_v4_rcv` → `tcp_add_backlog` when `sock_owned_by_user`; drained in `__release_sock` | Interrupt-disabling spinlock per connection, 13–22 acquisitions per segment, held across payload copies with interrupts off | Reader and receive path exclude each other for whole copies; no user copy may happen under it | — |
| Buffer recycling | `page_pool_create`, `page_pool_alloc_netmems` per queue, NUMA-aware, recycling in NAPI context; `napi_build_skb`; `skb_attempt_defer_free` | igc, i40e, ixgbe allocate and zero per frame; virtio-net and e1000 recycle; `DmaPool` is a locked `Vec` (`io/src/pool.rs:50`) | 2.8 to 11 bytes zeroed per payload byte; allocator rate of §4.5 | Ring size, MTU, NUMA node |
| Header-data split, page flipping | `tcp_data_split` ring parameter (`net/ethtool/rings.c`); `tcp_zerocopy_receive` | None; payload always copied | One copy per byte is the floor | Device capability |
| Checksum offload | RX verdict in `skb->ip_summed`, honoured by `tcp_v4_rcv`; TX partial checksum | RX verdict has no channel; TX for TCP only on six drivers; UDP never | Two read passes per byte on receive; one on UDP send | Device capability, per protocol |
| TSO, GSO | `tcp_gso_segment`; IPv4 and IPv6; size from `netif_set_tso_max_size`, `netif_set_gso_max_size` | IPv4 only on the stack side (`core.rs:3560-3562`); fixed 128-byte headroom (`:3568`); software fallback copies per segment | IPv6 sends one frame per MSS | Device `max_tso_bytes`, segment and fragment limits |
| GRO | `dev_gro_receive` with 8 buckets × `MAX_GRO_SKBS` 8 = 64 flows per NAPI; `tcp_gro_receive`, `tcp4_gro_receive`, `tcp6_gro_receive`, `inet_gro_receive`, `ipv6_gro_receive`; merges by reference (`skb_gro_receive`) | 8 flows per CPU, linear scan with a name compare (`gro.rs:35`, `:271-274`); IPv4 TCP only; merges by copy; verifies and recomputes checksums | Three passes per byte; collapses beyond 8 concurrent flows per CPU | Poll budget, flow count |
| Hardware GRO, LRO | `mlx5e_skb_from_cqe_shampo` | None | Per-frame budget of §4.2 applies in full | Device capability |
| UDP GSO, GRO, USO | `udp_send_skb` with `UDP_SEGMENT`, `__udp_gso_segment`, `udp_gro_receive`, `udp4_ufo_fragment` | Software `UDP_SEGMENT` only; no receive coalescing; no device offload | QUIC runs at the per-frame budget with nine global locks per datagram each way | Device capability |
| BIG TCP | `netif_set_gso_ipv4_max_size`; `GRO_LEGACY_MAX_SIZE` and `GSO_MAX_SIZE` in `netdevice.h` | Aggregates capped at 65,000 bytes (`gro.rs:37`) and 64 KiB TSO | 2.8 times more aggregates than necessary at 100 Gb/s | Device and peer limits |
| Transmit backpressure and batching | BQL: `netdev_tx_sent_queue`, `netdev_tx_completed_queue`, `dql_completed` (`lib/dynamic_queue_limits.c`); TSQ: `tcp_small_queue_check`, `tcp_tsq_handler`, `tcp_wfree`; `netdev_xmit_more`; queue stop and wake | At this base: driver result discarded, whole window pushed per call. On `claude/igc-throughput`: stop/wake and TSQ for igc (§3.8); no BQL, no `more` batching, other drivers unchanged | At base, loss at the first full ring and recovery by 200 ms timeout. With §3.8, fixed thresholds and one doorbell per frame | Ring geometry (done for igc); measured completion rate |
| Queueing and pacing | `fq_enqueue`, `fq_dequeue` (`net/sched/sch_fq.c`); `tcp_pacing_check`, `tcp_update_skb_after_send`; TSO sized by `tcp_tso_autosize` | None; `SO_MAX_PACING_RATE` stored and ignored | Window-sized bursts into the ring and the path | Measured delivery rate |
| NAPI, moderation, busy poll | `net_rx_action` budget; `napi_complete_done`; `net_dim` (`lib/dim/net_dim.c`); `igc_update_itr`; `napi_busy_loop`, `sk_busy_loop`; `napi_threaded_poll` | Every driver hand-rolls its loop; `net/src/napi.rs` (`poll`, `complete`, `AdaptiveItr`) has no caller; fixed moderation; busy-poll options stored and ignored | Interrupt rate and latency fixed for one card | Link speed, measured rate |
| Zero-copy send | `msg_zerocopy_realloc`, `skb_zerocopy_iter_stream`; `tcp_splice_read`; page-reference `sendfile` | `MSG_ZEROCOPY` ignored; `sendfile` is a 64 KiB bounce loop; native `SockSendZc` copies | Four to five copies per byte | — |
| Zero-copy receive | `tcp_zerocopy_receive`; `io_zcrx_recv` (`io_uring/zcrx.c`); `xsk_rcv` | `TCP_ZEROCOPY_RECEIVE` rejected; no io_uring; AF_XDP zero-copy on igc with 64-entry rings | Copy floor on the socket path | — |
| kTLS | `tls_sw_sendmsg`, `tls_device_sendmsg` | `TCP_ULP` returns `ENOENT` | TLS stays in userspace, defeating `sendfile` | Device capability |
| Congestion control and loss recovery | `cubictcp_cong_avoid`, `bbr_main`; `tcp_sacktag_write_queue`, `tcp_rack_mark_lost`, `tcp_send_loss_probe`; header prediction in `tcp_rcv_established` | CUBIC and Reno; go-back-N on timeout; one segment per fast retransmit; no fast path | One loss at 100 Gb/s costs a timeout and a window | — |
| Window and buffers | Scale from `tcp_rmem[2]` up to `TCP_MAX_WSCALE` 14 (`tcp_select_initial_window`); maxima from RAM in `tcp_init`; `tcp_rcv_space_adjust`, `tcp_rcvbuf_grow`, `tcp_sndbuf_expand` | Scale 7 always; fixed 6 MiB and 4 MiB maxima; autotuning present | §4.7 | RAM, measured rate |
| Segment size | `tcp_mtu_to_mss`, `tcp_sync_mss`, `tcp_current_mss` from the route MTU | IPv4 MSS is 1,460 whatever the MTU (`tcp/options.rs:55-58`) | Jumbo frames are never used by IPv4 TCP | Device and path MTU |
| Timers | Per-socket timers on the per-CPU wheel: `inet_csk_reset_xmit_timer`, `tcp_write_timer`, `tcp_delack_timer`, `tcp_keepalive_timer`; cost follows expirations | Full scan every millisecond (§4.6) | A few thousand connections per core | — |
| Accept | `inet_csk_accept`; `reuseport_select_sock`; SYN queue bounded | Reuseport by flow hash works; no SYN-queue bound (`core.rs:3948`); about 45–50 lock acquisitions per accept; binds in a linear `Vec` | Connection rate, not throughput | Online CPUs |
| epoll | Ready list fed by `ep_poll_callback`; exclusive wake | Ready list fed by callbacks, wake-one, `EPOLLEXCLUSIVE` present. A global generation counter is written per wake, and any key-0 notify wakes every parked task | Wake storms under UDP load | — |
| NUMA | Per-node pools and IRQ affinity | DMA pages always from node 0 (`io/src/lib.rs:738`) | Remote-node memory on every frame of a NIC on another node | Device NUMA node |
| Jumbo frames | Driver MTU range | Drivers accept 9,000+; i40e and ixgbe use 10 KiB buffers at any MTU; the IPv4 MSS ignores it | See segment size | Device MTU range |
| Flow control | Pause and PFC through ethtool and DCB | igc updates pause on link change; no PFC | Tail loss under incast | Device capability |
| Conntrack bypass | `nf_flow_offload_ip_hook`, `flow_offload_add`; no hooks cost when none registered | No early exit; no flowtable; conntrack never expires (§3.6) | §4.4 for UDP | Rule presence |
| Memory accounting | `tcp_init_mem`, `__sk_mem_schedule`, `tcp_under_memory_pressure`, `tcp_prune_queue` | None | Large buffer maxima are unsafe | RAM |
| Statistics | Per-CPU, lock-free | Under `IFACES`; `/proc/net/snmp` and `netstat` TCP rows are zeros; `sock_diag` carries no `tcp_info` | §4.4; and nothing to diagnose with | — |

## 6. Sizing from the card

The stack should reach whatever the installed NIC offers by deriving its
sizing from the device and from measured rates. Today it does neither.

### 6.1 Hard-coded constants on the data path

"Derive" means read once from the device or host. "Adapt" means adjust at run
time from measured rates, as Linux does.

**Stack**

| Constant | Value | Where | Should come from | Linux |
|---|---|---|---|---|
| Initial socket buffers | 256 KiB each | `tcp/socket_buf.rs:49-51` | Adapt (already autotuned upward) | `tcp_rcv_space_adjust`, `tcp_sndbuf_expand` |
| `tcp_rmem[2]`, `tcp_wmem[2]` | 6 MiB, 4 MiB | `lib/src/sysctl.rs:116-120` | Derive from RAM | `tcp_init`: min(32 MiB, free pages ÷ 128) |
| Window scale | 7 | `tcp/options.rs:50` | Derive from the receive maximum | `tcp_select_initial_window` |
| IPv4 MSS | 1,460 | `tcp/options.rs:55-58` | Derive from the egress MTU | `tcp_mtu_to_mss`, `tcp_sync_mss` |
| `SO_RCVBUF`/`SO_SNDBUF` clamp | 212,992 | `userspace/src/socket/sockopt.rs:186-187` | The `rmem_max` sysctl, which exists and is ignored | `sk_setsockopt` |
| GRO flows per CPU | 8 | `gro.rs:35` | Derive from poll budget | `GRO_HASH_BUCKETS` × `MAX_GRO_SKBS` |
| GRO aggregate | 65,000 B | `gro.rs:37` | Derive from the device's GRO limit | `netif_set_gso_ipv4_max_size` |
| TSO headroom | 128 B | `tcp/core.rs:3568` | Derive from the actual header length | `tcp_tso_segs` |
| TSO burst size | whole window | `tcp/core.rs:3608-3623` | Adapt to the pacing rate | `tcp_tso_autosize` |
| Flow-table shards | 32 | `tcp/core.rs:729`, `:762` | Derive from RAM and CPUs | `inet_ehash` sizing in `tcp_init` |
| Retransmit records | 256 | `tcp/core.rs:169` | Remove with buffer references | — |
| Timer scan period | 1 ms | `tcp/core.rs:5151` | Remove with a timer wheel | `__mod_timer` |
| Delayed ACK, minimum RTO | 40 ms, 200 ms | `tcp/core.rs:148`; `retransmit.rs:52` | Adapt to measured RTT | `tcp_delack_timer`, RTT-based ATO |
| Conntrack entries | 4,096 | `netfilter/conntrack.rs:28` | Derive from RAM | `nf_conntrack_max` |
| UDP queue | 128 datagrams; 212,992 B | `udp_sock.rs:108`; `userspace/src/socket.rs:1321` | Bytes, from `rmem_default` | `udp_queue_rcv_skb` |
| Listen backlog cap | 128 | `lib/src/sysctl.rs:86` | Sysctl (already) | `somaxconn` 4096 |
| Frame-ring depth | 1,024, compile-time | `net/src/lib.rs:195-198` | Derive from the device ring | — |
| Ethtool limits | rings 64..=4096; RSS table exactly 128; ≤ 4 channels; link modes to 2.5G | `net/src/nic.rs:49-72`, `:11`; `ethtool.rs:449` | Derive from the device | Driver `get_ringparam`, `get_channels` |
| AF_XDP ring | 64 | `bypass/xdp.rs:111` | User request, bounded by UMEM | `xsk` ring setup |
| Loopback MTU | 64 KiB | `iface.rs:791` | Constant is right; the MSS must follow it | `loopback_setup` |

**igc** (the full per-driver table is in §6.4)

| Constant | Value | Where | Should come from | Linux |
|---|---|---|---|---|
| Ring length | 256 | `igc/src/queue.rs:45` | Derive from link speed, within the device range | `igc_ethtool` ring parameters |
| RX buffer | 2,048 B | `queue.rs:46` | Derive from MTU | `igc_set_rx_buffer_len` |
| Poll budget | 64 | `igc.rs:1920` | One stack-wide value | NAPI weight via `netif_napi_add_weight_locked` |
| Moderation | 166 µs | `igc.rs:598`, `:921-924` | Adapt | `igc_update_itr`, `igc_set_itr`, `net_dim` |
| Pump fallback | 10 ms | `igc.rs:1913` | Remove once IRQs are trusted; else scale with moderation | — |
| Pump tasks | 4, on the first 4 online CPUs | `igc.rs:1899-1905`, `:513-519` | min(CPUs, queues), spread by NUMA node | `netif_set_real_num_rx_queues`, `cpumask_local_spread` |
| Queue pairs | `online.clamp(1, 4)` | `igc.rs:558` | Device queue count | as above |
| TX pool | 8 × 65,535 B per queue | `igc.rs:1643-1644` | Derive from the ring | — |
| Doorbell threshold | fewer than 20 free | `queue.rs:722` | Derive from the ring | `netdev_xmit_more` |
| Watchdog | 5 s | `igc.rs:2033` | Constant is fine | `dev_watchdog` |

### 6.2 What a driver must export

`drivers/net/specification/spec.md` §3 defines no device-capabilities
contract. It names `submit_tx_batch` and `recv_rx_batch` as the canonical
API; neither exists in the code.

What a driver can tell the stack today:

| Export | How | Read by |
|---|---|---|
| MAC, current MTU | registration, `set_mtu` | stack |
| Carrier, speed, duplex | `publish_link` → `set_link_metadata` (`iface.rs:1988`) | ethtool, sysfs, procfs. Nothing sizes from speed. |
| `tx_checksum`, `max_tso_bytes` | `iface::set_offloads` (`iface.rs:368`) | TCP (`core.rs:377-378`, `:3041-3042`, `:3565`) |
| `rx_checksum`, `vlan_insert` | same | ethtool feature bits only |
| TX queue count | number of pools passed to `enable_zero_copy_tx*` | pool selection; the only way the stack learns a queue count |
| `num_rx_queues`, `num_tx_queues`, `rss`, `queue_affinity`, `ring_capacity`, `caps` | `Interface` and `HwNic` traits | nothing |
| Rings, channels, coalescing, RSS table | `NicControl::settings` (igc only) | ethtool only |
| Per-frame `RxMeta` | `Frame::set_rx_meta` | only `timestamp_ns`, only from igc |

Two channels diverge: i40e, rtl8125, rtl8126, rtl8127 and aqc113 declare
offloads only through the trait method nothing reads, so the stack sends them
plain frames.

Not expressible in any type: maximum ring size, hardware queue maximum,
MSI-X vector count, NUMA node, MTU range, RX buffer size, fragment limits,
RSS key or table size, separate IPv4 and IPv6 TSO, UDP segmentation, hardware
GRO, header split.

The proposal is one structure, filled at probe and republished when the link
renegotiates, that the stack reads instead of constants:

```rust
pub struct DeviceLimits {
    pub link: LinkSample,              // speed, duplex, carrier; changes at run time
    pub numa_node: Option<u16>,
    pub msix_vectors: u16,
    pub rx_queues: QueueRange,         // hardware maximum and current
    pub tx_queues: QueueRange,
    pub rss: Option<RssLimits>,        // key length, indirection size, hash types
    pub rx_ring: RingRange,            // min, max, default descriptors
    pub tx_ring: RingRange,
    pub mtu: MtuRange,
    pub rx_buffer_bytes: u32,
    pub tx: TxOffloads,                // csum per protocol, TSO v4/v6, USO, max bytes,
                                       // max segments, max fragments
    pub rx: RxOffloads,                // csum verdict, hash, HW-GRO, header split, timestamps
    pub coalesce: CoalesceRange,       // min/max usecs, adaptive supported
}
```

This is an interface change to `drivers/net/` and `net/`: §3 of both
specifications must be updated in the same change. Receive metadata needs its
own channel as well: the handler must take the queue number and `RxMeta`
with the frame.

### 6.3 What derives from what

- **Queues and pumps:** min(online CPUs, hardware queues, MSI-X vectors − 1),
  one pump per queue on the queue's interrupt CPU, CPUs chosen on the
  device's NUMA node first.
- **Ring length:** enough to absorb one scheduling quantum at line rate.
  256 descriptors at 100 Gb/s over 16 queues is 0.5 ms of traffic per queue.
- **Poll budget and moderation:** adapt. Start from link speed; move with
  the measured packet and byte rate per interrupt.
- **Buffer pools:** ring length × queues, sized to MTU, on the device's node.
- **Segment size:** egress MTU, then path MTU.
- **Aggregate sizes:** the device's TSO and GRO limits; the pacing rate once
  there is one.
- **Socket buffers and window scale:** RAM for the maxima, measured
  throughput per round trip for the current value.
- **Flow tables, conntrack:** RAM.
- **Transmit queue limits:** adapt from completions, per queue.

### 6.4 Driver constants

| Driver | Ring | RX buffer | Queues | Budget | Moderation | Device values read and then clamped |
|---|---|---|---|---|---|---|
| virtio-net | ≤ 128 (one-page ring, `net_pci.rs:1506`) | 4,096 B pooled | ≤ 4 (`:334`) | fast-poll 64 rounds | none | max pairs, queue size, MTU, RSS table |
| igc | 256 | 2,048 B per frame | ≤ 4 | 64 | 166 µs fixed | MSI-X size |
| e1000 | 256 | 16 KiB persistent | 1 | 64 | ITR 195 fixed | none |
| igb | RX 256, TX 8 | 10 KiB persistent | 1 of 2–8 | 64 | EITR 648 fixed | none |
| vmxnet3 | 256 | 1,536 B | 1 | 64, 1 ms poll | interrupts off | none |
| i40e | 64 (`ring.rs:56`) | 9,728 B, 16 KiB zeroed per frame | ≤ 8 (`i40e.rs:293`) | 64 | 50/122 µs fixed | queue limits, MSI-X, RSS table size |
| ixgbe | 32 (`queues.rs:262`) | 10 KiB, 16 KiB zeroed per frame | 1 | 1 frame per loop | none written | none |
| rtl8127 | 256 | 16,383 B, two copies | ≤ 8 RX, 1 TX | 1 frame per yield | polled | MSI-X size |
| aqc113 | 256 | 2,048 B, two copies | 1 | 1 frame per yield | polled | none |

Link speed is read and published by every hardware driver except virtio-net.
No driver and no stack code sizes anything from it.

## 7. Drivers

| Driver | Link | Passes packets | Queues live | Offloads the stack can use | Tested against |
|---|---|---|---|---|---|
| virtio-net | host-limited | yes | ≤ 4 pairs, RSS if offered | TX checksum, TSO v4/v6 64 KiB, `more`, software GRO, owned-frame TX | QEMU device, in CI |
| igc | 2.5 G | yes | ≤ 4, RSS | TX checksum, TSO, VLAN, `more`, software GRO, owned-frame TX | register model; the physical I225 |
| e1000/e1000e | 1 G | yes | 1 | `more`, software GRO, owned-frame TX | QEMU device |
| igb | 1 G | yes | 1 | none | QEMU device, opt-in |
| vmxnet3 | host-limited | yes, polled at 1 ms | 1 | none | QEMU device, opt-in |
| i40e | 10/25/40 G | in code; never on silicon | ≤ 8, RSS | none reach the stack (no `set_offloads`) | in-tree firmware model |
| ixgbe | 10 G | single queue; silicon unverified | 1 | TX checksum, TSO v4 4 KiB | register model |
| rtl8127, aqc113 | 10 G | in code; silicon only | 8 RX / 1; 1 | none | layout checks |
| r8169, rtl8125, rtl8126 | 1–5 G | in code | 1 | r8169 only | layout checks |
| mlx5 | 25–100 G | **no** | — | — | encoders only |
| bnxt, enic, cxgb4 | 10–100 G | no; probe refuses | — | — | — |
| tg3, atheros, forcedeth, rtl8139 | ≤ 1 G | no, doubtful, untested, unused | — | — | — |
| ice (E810) | 100 G | does not exist | | | |

mlx5 cannot pass a packet. Its pumps are stubs (`mlx5/src/mlx5.rs:1615-1627`),
it registers no interface with the stack, and its queue-creation, completion
and event methods (`create_cq`, `poll_cq`, `handle_eq_irq`, `post_send`,
`post_recv` and the rest) have no caller at all, test or otherwise. The
command set lacks the firmware bring-up opcodes (`ENABLE_HCA`, page
management, `INIT_HCA`) and send/receive queue creation.

**Shortest path to a measurement at 25 Gb/s or more: virtio-net with
vhost-net on a multi-queue tap, on this host, NARF sending first.** No driver
for a fast physical card is closer. The host has KVM and `/dev/vhost-net`;
its only wired NIC is the I225. What stands in the way, in order:

1. `cargo xtask` never passes `vhost=on`
   (`build/xtask/src/main.rs:2017`); `XTASK_QEMU_TAP` and `XTASK_QEMU_QUEUES`
   exist and no job sets them.
2. The driver drops received TCP frames that lack `DATA_VALID`, including
   `NEEDS_CSUM` ones (`drivers/virtio/src/net_pci.rs:3373-3410`). A host
   stack sending into a tap produces exactly those. This is read from the
   code and from how Linux `tun` behaves; it has not been run.
3. Queue pairs capped at 4, ring depth at 128, 32 frames in flight per pair
   (`net_pci.rs:334`, `:1506`, `:496`).
4. The receive direction is further away: guest TSO is not negotiated
   (`net_pci.rs:387`), so the host delivers MTU-sized frames, each summed in
   software.

For a physical measurement, i40e is nearest: a 25 or 40 Gb/s card and a
peer, a `set_offloads` call, a buffer pool in place of the per-frame 16 KiB
allocation, rings deeper than 64 and a queue cap above 8. It has never run
on hardware. 100 Gb/s means writing the mlx5 data path or an `ice` driver:
months, with hardware on the desk.

## 8. Architecture: three options

This is a decision for the maintainers. The facts are in §2; the options and
their costs follow.

### Option A — the in-kernel stack, made per-CPU

Declare what exists to be the architecture and scale it the way Linux scaled
its own: per-CPU state, lockless lookup, a socket lock with a backlog,
buffers passed by reference from the ring to the socket, one copy to
userspace.

- *What it keeps:* the stack every application uses today, its 300 tests,
  netfilter, rtnetlink, the Linux socket surface.
- *What it costs:* stages 1–3 of §9. The specification changes: §1, §4 and
  §8.1 of `net/specification/spec.md` and the project summary in `AGENTS.md`
  say the opposite. L3/L4 parsing in Ring 0 enlarges the code that runs with
  kernel authority, although not the TCB as `AGENTS.md` defines it.
- *Domain crossings:* driver and stack are separate domains, so a receive
  batch crosses once in each direction per poll. On PKS that is a write to
  `IA32_PKRS` with fences on both sides, of the order of a hundred cycles and
  not yet measured here. The laptops this project targets are AMD, which has
  no PKS, so the fallback is a PCID-tagged page-table switch: several hundred
  cycles plus TLB effects. Per poll of 64 frames either is noise. Per frame
  neither is affordable at 100 Gb/s, which is the constraint this option
  must respect: cross per batch, never per packet.
- *A constraint it shares with B:* packet buffers must be readable in the
  driver's domain, the stack's domain and, for zero-copy, the application.
  Changing a page's protection key per packet means a page-table update and a
  TLB shoot-down. So packet memory has to live in a pool domain mapped by all
  parties, a decision that belongs to `security-model/`.

### Option B — the userspace stack daemon the specification promises

Move TCP/IP out of the kernel into a daemon that owns the frame rings, as
§3.5 and §8.1 of the specification describe.

- *What it gives:* a stack bug cannot corrupt the kernel. Zero copies between
  NIC and stack. A stack can be restarted or replaced.
- *What it costs:* it is a new system, not a migration.
  - No daemon exists, and the rings carry a mirror, not a diversion.
  - Every Linux application reaches sockets through the kernel's syscall
    surface. Each `send`, `recv`, `epoll_wait` and `accept` then needs a
    kernel-to-daemon hop: either a context switch per call (1–2 µs, a
    thousand times the 100 Gb/s per-frame budget unless batched) or
    shared-memory socket buffers between the syscall shim and the daemon,
    which is the same buffer-ownership design as Option A plus a second
    protection boundary.
  - Flows must be steered NIC queue → daemon thread → application thread.
    That is two cross-CPU hops per aggregate where Option A has one.
  - Netfilter, conntrack, routing, rtnetlink, packet sockets and `procfs`
    all read stack state in-kernel today and would each need a protocol.
- *What it does not avoid:* every item in §5. The per-CPU, zero-copy,
  batching, pacing and timer work is identical in userspace. Systems that
  made this design fast (Google's Snap, Fuchsia's Netstack3, DPDK stacks) did
  that work too, and reached their best numbers with a native API rather
  than BSD sockets.

### Option C — both, with roles stated (recommended)

Make the in-kernel stack the Linux-compatible path (Option A), and keep the
frame-ring bypass as the opt-in path for applications that bring their own
stack, which is what §8.4 of the specification already describes and what
`net/src/bypass/` already implements.

This is the recommendation, for four reasons.

1. Everything users run goes through the in-kernel stack. The measured
   300/700 Mb/s is that stack's number.
2. The ceiling is in copies, locks and allocations (§4). Those are fixable
   in place, in stages, with tests and a harness that already exist.
3. Option B removes none of that work and adds a boundary between the stack
   and every Linux application.
4. The design's own primitives still apply. A `Frame` whose ownership moves
   from the driver's ring to the socket queue to the application is
   Narf-Ring ownership transfer; Option A's buffer-reference stage is that
   mechanism used inside the kernel. The native async ABI can later hand an
   application buffer handles instead of bytes, which gives NARF the
   zero-copy receive Linux needed `io_uring` to get.

What Option C needs decided: that the specification is amended rather than
the code; which domain the stack runs in (there is no `NET` domain among the
sixteen); and the pool-domain question above.

## 9. Staged plan

Each stage names the link speed at which the stack stops being the limit,
what changes and where, what it depends on, and what the harness should show.
Speeds are targets to be confirmed by measurement, not predictions.

Every stage has the same exit criterion beside its own: **no constant tuned
for one card.** A constant that remains must be either derived from
`DeviceLimits` or the host, adapted at run time, or listed with a reason.

### Stage 0 — measurement (done here, plus days)

- The harness of §10.
- Make the stack observable: real TCP rows in `/proc/net/snmp` and `netstat`
  (per-CPU counters); `INET_DIAG_INFO` so `ss -ti` works
  (`net/src/netlink_diag.rs`); `ethtool -S` beyond igc.

### Stage 1 — remove per-frame global work (1 → 10 Gb/s)

Contained changes; each is days. Together, three to five weeks for one
person. None touches the TCB.

| Change | Scope |
|---|---|
| Interface handle. Drivers get a handle at registration and pass it on receive; counters become per-CPU; no name lookups or snapshots on the data path; local-address checks read an RCU set. (`rx_batch` on `claude/igc-throughput` makes the lookup per poll for igc; this removes it.) | `net/src/iface.rs`, `tcp_stack.rs`, `ip_local.rs`, `ifaddr.rs`; `drivers/net/core/src/publish.rs`; each driver's receive call |
| Receive metadata. The handler takes queue number and `RxMeta`; the stack trusts a verified checksum; GRO stops verifying and stops recomputing. | `net/src/iface.rs`, `tcp_stack.rs`, `gro.rs`; drivers |
| Receive buffer pools per queue for igc, i40e, ixgbe; no per-frame allocation or zero-fill. | `drivers/net/{igc,i40e,ixgbe}`; `io/src/pool.rs` |
| Fast exits: an atomic "any rule" per netfilter hook, conntrack only when a rule needs state, the same for bypass claims. Conntrack expiry called. | `net/src/netfilter/`, `bypass/classifier.rs` |
| TCP: one lock acquisition per segment; cached egress for ACKs and retransmits; no interface clone per send; PSH only at the end of a write; MSS from the MTU; window scale and buffer maxima derived. | `net/src/tcp/core.rs`, `options.rs`, `autotune.rs`; `lib/src/sysctl.rs` |
| Transmit backpressure as a stack contract. The contract exists on `claude/igc-throughput` (§3.8). What a 100 Gb/s-capable version still needs: every multi-queue driver implementing it; byte limits adapted from completions; doorbell batching across a burst; a wake that lands on the sender's CPU; per-CPU transmit counters. | `net/src/txq.rs`, `iface.rs`, `tcp/core.rs`; drivers |
| Syscall layer: no zero-fill; bounce buffers sized to what will move; a blocked writer does not re-copy. | `userspace/src/handlers/sys_read.rs`, `sys_write.rs`, `sys_socket_recv.rs`, `sys_socket_send.rs` |
| `DeviceLimits` (§6.2) and its first consumers: queue count, ring length, poll budget, moderation by link speed. | `drivers/net/specification/spec.md` §3, `net/specification/spec.md` §3; `net/src/nic.rs`; drivers |
| Correctness: a deferral queue for `lo`; IPv6 receive dispatch, with a decision on its firewall path. | `net/src/iface.rs`, `tcp_stack.rs` |

*Harness after this stage:* `rx-tcp` slab operations per packet near zero;
`rx-tcp` cycles per packet down severalfold; scaling at 4 CPUs near linear
where today it is not; `card` lines show no ring refusals and no
retransmits; the `lo` probe connects.

*Own exit criterion:* ring, budget, moderation, queue count and MSS no longer
appear as literals in igc or the stack.

### Stage 2 — one copy each way (10 → 25 Gb/s per flow)

A redesign of the TCP data structures; one to two months. This is the
largest single item and the one that decides the per-flow ceiling (§4.3).

- **Socket queues hold buffer references.** `RecvBuf` becomes a queue of
  frames with offsets; GRO links segments instead of copying them; out-of-
  order data is a tree of the same. `SendBuf` becomes page-backed chunks; a
  frame is a header plus payload fragments; a retransmit references the same
  pages.
- **A socket lock that permits a user copy.** Copying straight between user
  memory and those buffers cannot happen under an interrupt-disabling
  spinlock. This needs Linux's discipline: an owner flag and a backlog, with
  the receive path queueing to the backlog when a syscall owns the
  connection.
- **Drivers send fragments.** Multi-descriptor transmit; TSO for IPv6;
  checksum offload for IPv6 and UDP. `TxMeta` and `DeviceLimits` gain the
  segmentation type and fragment limits.
- **Scope:** `net/src/tcp/socket_buf.rs`, `core.rs`, `gro.rs`, `gso.rs`;
  `net/src/lib.rs` (`Frame`); the read and write handlers in `userspace/`;
  every driver's transmit path.
- **TCB-adjacent:** yes, for one decision. Packet memory shared across
  domains (§8) is a `security-model/` and `memory/` domain-manager question.
  It needs a safety argument and two maintainers. The rest of the stage is
  outside the TCB.
- **Depends on:** stage 1's receive metadata and interface handle.

*Harness after this stage:* `hairpin` cycles per byte for `rx+ack` and
`read` approach the cost of one copy; goodput rises by the ratio of passes
removed.

*Own exit criterion:* aggregate sizes come from device limits; no fixed
65,000 or 64 KiB.

### Stage 3 — scale across cores (25 → 100 Gb/s aggregate)

Two to four months, largely parallel work once stage 2's locking exists.

| Change | Scope |
|---|---|
| Queues = min(CPUs, hardware); a pump per queue on its interrupt CPU; the hash carried up; flows steered to the reader's CPU | drivers; `net/src/rss.rs`, `napi.rs` (both exist, mostly unused); `interrupts/` |
| Lockless established lookup: an RCU hash sized from RAM (`rcu/` QSBR fits a run-to-completion receive path) | `net/src/tcp/core.rs` |
| Timers on a per-CPU wheel; the millisecond scan removed; TIME-WAIT as a small record | `net/src/tcp/core.rs`; `time/` |
| Small queues, pacing, byte queue limits, `more` batching from `pump_send`; TSO sized from the pacing rate | `net/src/tcp/`; `net/src/iface.rs`; drivers |
| SACK-based recovery, RACK, tail loss probe; go-back-N removed | `net/src/tcp/` |
| Adaptive moderation; one shared poll loop (`net/src/napi.rs`); busy poll | drivers; `net/src/napi.rs` |
| Wake path: no global generation counter; no wake-all | `net/src/readiness.rs`; `userspace/` |
| Memory accounting and pressure | `net/src/tcp/`; `lib/src/sysctl.rs` |
| UDP: batching in `recvmmsg`/`sendmmsg`, receive coalescing, segmentation offload, per-socket wake | `net/src/udp_sock.rs`, `udp_gso.rs`; `userspace/src/socket/inet_dgram.rs` |
| A driver that can carry it: virtio-net multi-queue over vhost, then i40e on hardware; the mlx5 data path begun | `drivers/virtio`, `drivers/net/i40e`, `drivers/net/mlx5`; `build/xtask` |

- **TCB-adjacent:** steering a woken reader toward its flow's CPU may need a
  placement hint in the executor core (`scheduler/`). If it does, that change
  carries the TCB review bar. Everything else uses existing scheduler
  interfaces.
- **Depends on:** stage 2's socket lock (lockless lookup needs it);
  stage 1's `DeviceLimits`.

*Harness after this stage:* scaling efficiency near 100 % to every core;
`timer-sweep` irrelevant because cost follows expirations; `card 100G` shows
a queue's line-rate share within one core.

*Own exit criterion:* nothing is sized by a CPU count or queue count literal.

### Stage 4 — 100 → 400 Gb/s

Quarters, and it needs hardware. Per-frame work must leave the CPU.

- Hardware GRO, header-data split, BIG TCP for IPv4 and IPv6.
- Zero-copy to and from applications: buffer-handle receive through the
  native ABI; `MSG_ZEROCOPY`, `sendfile` and `splice` by page reference;
  `TCP_ZEROCOPY_RECEIVE` or an equivalent for Linux binaries.
- kTLS, in software and then on the NIC.
- NUMA placement of pools, queues and interrupts.
- A complete 100 Gb/s driver: the mlx5 data path or `ice`.
- The bypass path with zero-copy on that driver and rings beyond 64 entries.
- **TCB-adjacent:** mapping packet pages into an application touches the
  `memory/` domain manager and `capabilities/` (buffer handles as
  capabilities). Safety argument and two maintainers.
- **Depends on:** stages 2 and 3.

### Risks

- **Measurement.** Until a fast link exists every number is from a guest on a
  shared host. The harness ranks; it does not prove a rate.
- **Regression.** Stages 1 and 2 rewrite the hottest paths of a stack with
  about 300 targeted tests. Stage 2 changes data structures those tests reach
  into directly.
- **Concurrency of work.** `tcp/core.rs`, `iface.rs` and igc are being edited
  by others now. Stage 1 lands as small changes for that reason.
- **Domains.** The pool-domain decision (§8) gates zero-copy. On AMD the
  crossing is a page-table switch.
- **Drivers.** i40e, ixgbe and the 10 Gb/s Realtek and Marvell drivers have
  never run on silicon.
- **Specification.** Until §1, §4 and §8.1 are amended, every stage is work
  on a path the specification says should not exist.

## 10. The harness

`net/src/scale_bench.rs`, kernel-test only, subsystem `net/scale`. It uses
public entry points and the existing `__install_test_tcb_in` seam; it adds no
code or counter to a production path. The kernel-test boot skips the
boot-time network init (`install_net_stack`,
`frame/src/cross_crate_init.rs:312`), so the harness installs the receive
handlers and default netfilter hooks itself, as that function does.

- **`scale_rx_tcp_pktgen`** injects pre-built TCP flows into
  `iface::on_native_rx_timestamped`, the per-frame call a NIC pump makes, on
  1, 2 and 4 CPUs at once, with GRO off and on. After each 64-frame burst it
  flushes GRO as a driver does and reads the socket. It reports packets per
  second, cycles per packet split into stack and read, cycles per byte,
  scaling efficiency against one CPU, ACKs emitted per thousand packets, and
  slab operations per packet.
- **`scale_rx_udp_pktgen`** does the same with 1,200-byte datagrams.
- **`scale_tcp_hairpin`** joins a sender and a receiver connection through a
  model NIC whose transmit hook is a bounded descriptor ring. Every byte goes
  `send` → `pump_send` → ring → wire → receive → ACK → `recv`. With an
  unlimited wire it is the stack-only loopback ceiling on 1, 2 and 4 flows;
  it reports goodput, cycles per byte for each leg, bytes per frame handed to
  the driver, doorbells, ring refusals and retransmits.
- **`scale_card_profiles`** runs both with a `CardProfile`: link speed, MTU,
  queue count, ring length, poll budget, moderation interval, TSO limit. The
  profile sets how many queues are modelled, how many frames arrive per poll,
  how deep the transmit ring is and how fast the wire drains it. One run
  models a 1 Gb/s I225, a 25 Gb/s card, a 100 Gb/s card and the same with
  jumbo frames. Adding a card is one table row.
- **`scale_timer_sweep`** times the per-connection timer visit over 1,000 and
  10,000 idle connections.
- **`scale_lo_handshake_probe`** records whether a TCP handshake over the
  stack's own `lo` completes.

Slab operations count allocations plus frees of objects up to 4 KiB, summed
over all CPUs; larger allocations go to the page allocator and are not
counted. Lock acquisitions are not counted at run time, because there is no
lock statistics facility; §3 counts them from the code.

Run it with:

```
cargo xtask test --arch=x86_64 --subsystem net/scale --kernel-tests-only
```

The results are the `NETBENCH scale/...` lines printed after the summary.

### 10.1 Base output

Recorded at `61f6f1e08` plus the harness, from one boot. **Harness,
non-protocol**: a KVM guest with 16 virtual CPUs on a 6-core, 12-thread host
shared with other builds. Use the ratios, not the magnitudes. Every line is a
harness number; the suffix saying so is trimmed here.

```
NETBENCH scale/rx-tcp cpus=1 burst=64 payload=1460: 0.457 Mpps 5.33 Gb/s | 10105 cyc/pkt stack + 158 read (7.02 cyc/B) | scaling 100% | tx 515 per 1000 pkts | slab ops 41.2/pkt | delivered 100%
NETBENCH scale/rx-tcp cpus=2 burst=64 payload=1460: 0.774 Mpps 9.04 Gb/s | 11930 cyc/pkt stack + 180 read (8.29 cyc/B) | scaling 84% | tx 515 per 1000 pkts | slab ops 41.2/pkt | delivered 100%
NETBENCH scale/rx-tcp cpus=4 burst=64 payload=1460: 0.995 Mpps 11.62 Gb/s | 18616 cyc/pkt stack + 230 read (12.90 cyc/B) | scaling 54% | tx 515 per 1000 pkts | slab ops 41.2/pkt | delivered 100%
NETBENCH scale/rx-tcp-gro cpus=1 burst=64 payload=1460: 1.355 Mpps 15.83 Gb/s | 3301 cyc/pkt stack + 159 read (2.36 cyc/B) | scaling 100% | tx 46 per 1000 pkts | slab ops 11.7/pkt | delivered 100%
NETBENCH scale/rx-tcp-gro cpus=2 burst=64 payload=1460: 2.329 Mpps 27.21 Gb/s | 3856 cyc/pkt stack + 170 read (2.75 cyc/B) | scaling 85% | tx 46 per 1000 pkts | slab ops 11.7/pkt | delivered 100%
NETBENCH scale/rx-tcp-gro cpus=4 burst=64 payload=1460: 3.225 Mpps 37.66 Gb/s | 5619 cyc/pkt stack + 198 read (3.98 cyc/B) | scaling 59% | tx 46 per 1000 pkts | slab ops 11.7/pkt | delivered 100%
NETBENCH scale/rx-udp cpus=1 burst=64 payload=1200: 0.644 Mpps 6.18 Gb/s | 7013 cyc/pkt stack + 266 read (6.06 cyc/B) | scaling 100% | tx 0 per 1000 pkts | slab ops 32.0/pkt | delivered 100%
NETBENCH scale/rx-udp cpus=2 burst=64 payload=1200: 0.957 Mpps 9.19 Gb/s | 9524 cyc/pkt stack + 271 read (8.16 cyc/B) | scaling 74% | tx 0 per 1000 pkts | slab ops 32.0/pkt | delivered 100%
NETBENCH scale/rx-udp cpus=4 burst=64 payload=1200: 1.055 Mpps 10.13 Gb/s | 17499 cyc/pkt stack + 280 read (14.81 cyc/B) | scaling 40% | tx 0 per 1000 pkts | slab ops 32.0/pkt | delivered 100%
NETBENCH scale/timer-sweep connections=1000: 195 cyc, 41 ns per connection per scan; a 1 ms scan fills one core at 24390 connections
NETBENCH scale/timer-sweep connections=10000: 351 cyc, 74 ns per connection per scan; a 1 ms scan fills one core at 13513 connections
NETBENCH scale/lo-handshake: connect to 127.0.0.1 is in-progress when connect returns, in-progress after 50 ms
NETBENCH scale/hairpin-tso flows=1: 9.17 Gb/s goodput, 273 of 273 MiB queued were delivered | cyc/B send 0.48 card-model 0.46 rx+ack 2.99 read 0.13 | scaling 100% | 16419 B/frame, 4406 of 17521 frames TSO, 13185 doorbells | ring refused 0 retransmits 0
NETBENCH scale/hairpin-tso flows=2: 16.68 Gb/s goodput, 497 of 497 MiB queued were delivered | cyc/B send 0.51 card-model 0.49 rx+ack 3.34 read 0.14 | scaling 90% | 16418 B/frame, 8017 of 31862 frames TSO, 23985 doorbells | ring refused 0 retransmits 0
NETBENCH scale/hairpin-tso flows=4: 26.52 Gb/s goodput, 790 of 790 MiB queued were delivered | cyc/B send 0.58 card-model 0.50 rx+ack 4.39 read 0.17 | scaling 72% | 16412 B/frame, 12776 of 50692 frames TSO, 38196 doorbells | ring refused 0 retransmits 0
NETBENCH scale/hairpin-notso flows=1: 2.20 Gb/s goodput, 65 of 69 MiB queued were delivered | cyc/B send 0.70 card-model 0.21 rx+ack 15.91 read 0.14 | scaling 100% | 975 B/frame, 0 of 75554 frames TSO, 28925 doorbells | ring refused 0 retransmits 0
NETBENCH scale/hairpin-notso flows=2: 3.82 Gb/s goodput, 114 of 118 MiB queued were delivered | cyc/B send 2.34 card-model 0.23 rx+ack 16.88 read 0.15 | scaling 86% | 1022 B/frame, 0 of 126775 frames TSO, 44683 doorbells | ring refused 0 retransmits 0
NETBENCH scale/hairpin-notso flows=4: 5.70 Gb/s goodput, 170 of 179 MiB queued were delivered | cyc/B send 4.12 card-model 0.27 rx+ack 21.72 read 0.21 | scaling 64% | 1025 B/frame, 0 of 189802 frames TSO, 66514 doorbells | ring refused 0 retransmits 0
NETBENCH scale/card 1G-I225 link=1000Mb/s mtu=1500 queues=4 ring=256 budget=64 itr=166us: line rate 81274 pps, 20318 pps/queue, 3 frames/poll, a stalled pump overflows the ring in 12599 us (arithmetic)
NETBENCH scale/card 1G-I225 rx: 4 of 4 queues modelled, 14301 cyc/pkt at 3 frames/poll, 5814 cyc/pkt at a full budget; one core takes 806770 pps = 3970% of a queue's line-rate share; the link needs 1 such cores; delivered 100%
NETBENCH scale/card 1G-I225 tx: one flow 0.97 Gb/s = 97% of the link | 8473 B/frame, 3623 doorbells for 3701 frames | ring refused 0 retransmits 0
NETBENCH scale/card 25G link=25000Mb/s mtu=1500 queues=8 ring=1024 budget=64 itr=50us: line rate 2031859 pps, 253982 pps/queue, 12 frames/poll, a stalled pump overflows the ring in 4031 us (arithmetic)
NETBENCH scale/card 25G rx: 4 of 8 queues modelled, 7389 cyc/pkt at 12 frames/poll, 5770 cyc/pkt at a full budget; one core takes 812986 pps = 320% of a queue's line-rate share; the link needs 3 such cores; delivered 100%
NETBENCH scale/card 25G tx: one flow 9.21 Gb/s = 36% of the link | 16419 B/frame, 13245 doorbells for 17601 frames | ring refused 0 retransmits 0
NETBENCH scale/card 100G link=100000Mb/s mtu=1500 queues=16 ring=4096 budget=64 itr=8us: line rate 8127438 pps, 507964 pps/queue, 4 frames/poll, a stalled pump overflows the ring in 8063 us (arithmetic)
NETBENCH scale/card 100G rx: 4 of 16 queues modelled, 11882 cyc/pkt at 4 frames/poll, 5796 cyc/pkt at a full budget; one core takes 809245 pps = 159% of a queue's line-rate share; the link needs 11 such cores; delivered 100%
NETBENCH scale/card 100G tx: one flow 9.17 Gb/s = 9% of the link | 16419 B/frame, 13188 doorbells for 17525 frames | ring refused 0 retransmits 0
NETBENCH scale/card 100G-9k link=100000Mb/s mtu=9000 queues=16 ring=4096 budget=64 itr=8us: line rate 1383049 pps, 86440 pps/queue, 1 frames/poll, a stalled pump overflows the ring in 47385 us (arithmetic)
NETBENCH scale/card 100G-9k rx: 4 of 16 queues modelled, 28183 cyc/pkt at 1 frames/poll, 12252 cyc/pkt at a full budget; one core takes 382863 pps = 442% of a queue's line-rate share; the link needs 4 such cores; delivered 100%
NETBENCH scale/card 100G-9k tx: one flow 15.45 Gb/s = 15% of the link | 16438 B/frame, 22122 doorbells for 29484 frames | ring refused 0 retransmits 0
```

What it says, as ratios:

- **Per packet.** Receive without GRO costs about 10,300 cycles per
  1,460-byte packet on one CPU, with 41 slab operations and an ACK every
  second packet. With GRO it costs about 3,500 cycles and 12 slab
  operations. The 100 Gb/s budget of §4.2 is 369 cycles per frame on one
  3 GHz core.
- **Scaling.** Two CPUs reach 84–85 % of twice one CPU. Four reach 54–59 %
  of four times one, and cycles per packet rise from 3,300 to 5,600 with GRO
  and from 10,100 to 18,600 without. Each worker has its own flows, its own
  connections and its own GRO table; what they share is the global state of
  §4.4. UDP has no GRO to hide behind and falls to 40 %: four CPUs deliver
  1.06 Mpps where one delivers 0.64.
- **Burst length.** At 3 frames per poll a frame costs 14,300 cycles against
  5,800 at a full budget, because the per-aggregate work is spread over
  fewer frames. Moderation tuned for one card's rate is a per-packet cost at
  another's.
- **End to end.** One flow through the whole stack moves 9.2 Gb/s with TSO
  and 2.2 Gb/s without. Receive and its ACKs take three quarters of the
  cycles per byte with TSO (2.99 of 4.06) and more than nine tenths without
  (15.9 of 17.0). Four flows on four CPUs reach 72 % and 64 % of four times
  one.
- **Per card.** One flow fills the 1 Gb/s link (97 %), reaches 36 % of a
  25 Gb/s link and 9 % of a 100 Gb/s link. On receive one core handles 40
  times a queue's share of the 1 Gb/s link, 3.2 times at 25 Gb/s and 1.6
  times at 100 Gb/s over 16 queues, at the contention of four queues;
  sixteen would share the same locks.
- **Timers.** The scan costs 41–74 ns per idle connection, so 13,500 to
  24,000 connections fill the millisecond.
- **`lo`.** The handshake does not complete: still in progress 50 ms after
  `connect` returns.

No profile shows a ring refusal. With TSO a window is a handful of frames, so
the model ring never fills; the missing backpressure of §3.2 appears when a
window is thousands of MSS-sized frames against a 256-descriptor ring. A
profile with TSO off would show it and is worth adding.

One more number came from a boot that went wrong. The kernel-test image does
not run the boot-time network init, and before the harness installed the
receive handlers itself every injected frame was counted under `IFACES`,
counted again as having no handler, and dropped. That is the interface layer
with no stack behind it, and on four CPUs at once it cost about 2,600 cycles
per frame.

### 10.2 The protocol-grade version

`verification/specification/spec.md` §8 governs any number presented as
performance. For this harness that means, on hardware:

- Boot the kernel-test image with `test_subsystem=net/scale` on a machine
  with a dedicated core per worker, frequency pinned, SMT and turbo off.
- Collect at least 30 runs per configuration, 100 if the coefficient of
  variation exceeds 5 %.
- Report the median with a 95 % bootstrap confidence interval (10,000
  resamples) and p95, p99 and p99.9. Never a mean alone or a single run.
- Compare before and after with Welch's t-test and Mann–Whitney U, both
  required to agree, with Benjamini–Hochberg correction at q = 0.05 across
  the suite, and treat a change as blocking only if it is significant and
  beyond the declared δ.

`build/xtask/src/bench_stats.rs` already implements those statistics for the
BPF benchmarks. A `net-scale-bench` command that boots, parses `NETBENCH`
lines and feeds them to it is the remaining piece.

### 10.3 On the desktop today

These run on the booted system with its 1 Gb/s link.

Loopback, for the socket layer only (it does not exercise TCP, §2):

```
iperf3 -s -D
iperf3 -c 127.0.0.1 -t 10
iperf3 -c 127.0.0.1 -t 10 -P 4
```

Against a Linux peer on the LAN running `iperf3 -s`:

```
iperf3 -c PEER -t 30 -i 1 -J > tx.json           # NARF sends
iperf3 -c PEER -t 30 -i 1 -R -J > rx.json        # NARF receives
iperf3 -c PEER -t 30 -P 4                        # four flows, four queues
iperf3 -c PEER -t 30 -P 4 -R
iperf3 -c PEER -u -b 0 -l 1200 -t 10             # UDP at QUIC datagram size
iperf3 -c PEER -u -b 0 -l 1200 -t 10 -R
```

Capture on NARF, before and after each run:

```
cat /proc/net/dev /proc/interrupts /proc/net/tcp /proc/net/sockstat
cat /proc/sys/net/ipv4/tcp_rmem /proc/sys/net/ipv4/tcp_wmem
ethtool -S eth0        # igc: per-queue packets, rx drops, alloc_failed, tx rejects
ethtool -k eth0        # GRO and TSO as actually set
ethtool -c eth0; ethtool -g eth0; ethtool -l eth0
```

What to read where:

- `iperf3 -J` records congestion window, RTT and retransmits per interval
  from `getsockopt(TCP_INFO)`, which is real.
- `ss -tim` on NARF shows no per-connection detail: `sock_diag` carries no
  `tcp_info`. Run `ss -tin dst NARF_IP` and `nstat -az` on the Linux peer
  instead; the peer sees NARF's retransmissions, reordering and window.
- `/proc/net/snmp` and `/proc/net/netstat` TCP rows are zeros on NARF, and
  `/proc/net/softnet_stat` does not exist.
- `/proc/interrupts` per-queue counts show whether four queues are in use
  and what the interrupt rate is against the 166 µs moderation.

## 11. Not verified

What was run for this document: clippy for `narf-net`, and one boot of the
`net/scale` tests (after a first boot that exposed the missing stack init).
No other test suite, no regression run, no before/after comparison, and
nothing on hardware.

- Nothing in §3–§7 was measured on hardware. The lock hold times in §4.4,
  the memory-bandwidth figures in §4.3 and the cache-miss cost in §4.2 are
  stated assumptions.
- Whether e1000's TSO is effectively disabled by the feature code
  (`net/src/ethtool/features.rs:105-107`), and whether igc returns a pool
  buffer when an owned post fails, were read, not run.
- Whether a vhost tap delivers host TCP with `NEEDS_CSUM`, and so whether
  virtio-net drops it, comes from knowledge of Linux `tun`, not a run.
- That mlx5 firmware needs `ENABLE_HCA`/`INIT_HCA` before object creation,
  and ixgbe needs `DMATXCTL`, come from memory of vendor documents.
- The cost of a domain crossing on either backend has not been measured.
- Linux per-core throughput figures are the commonly reported range, not
  measurements made for this document.
