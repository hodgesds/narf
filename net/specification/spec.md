# net — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> stack-daemon attach contract; v1.0 locks the boot-time
> kernel-stack scope, interface naming, RSS hash policy,
> stack-daemon trust posture, and multi-stack arbitration.

## 1. Purpose & scope

**Owns:**

- The **frame-ring contract** between `drivers/net/` (frame producer)
  and consumers (userspace daemon, kernel-internal callers).
- **Interface registry** — the list of active network interfaces,
  their MAC/MTU/features, and the caps that gate access.
- **Loopback** — a reference implementation of the contract with no
  hardware, used for tests and local-only traffic.
- **Stack-daemon rendezvous protocol** — how a userspace network
  stack attaches, authenticates (via `capabilities/`), and binds to
  an interface.

**Does NOT own:**

- IP, TCP, UDP, QUIC, TLS — these live in the userspace daemon (or
  a library loaded by consumers). NARF's kernel has no L3/L4 stack.
- Driver-internal RX/TX paths — those are `drivers/net/`.
- Hardware offload choice (TSO, GRO, checksum) — driver negotiates
  with hardware; consumer opts in per-interface via a cap bit.

## 2. Assumptions

- `drivers/net/` exposes interfaces via the contract here.
- `ipc/` Narf-Rings carry frames both directions.
- `capabilities/` mints `Cap<NetIface, R>` where R ∈ {Rx, Tx, Admin}.
- `io/` DMA buffers back RX/TX rings.
- `userspace/` is mature enough to host a stack daemon (Stage 4).

## 3. Public interface

### 3.1 Interface object

```rust
pub struct IfaceId(u32);
pub struct IfaceInfo {
    pub id:          IfaceId,
    pub mac:         [u8; 6],
    pub mtu:         u16,
    pub features:    IfaceFeatures,       // Checksum, TSO, GRO, RxHash, Vlan, …
    pub link_state:  LinkState,
    pub max_queues:  u16,
}

pub fn list(cap: &Cap<IfaceRegistry, Read>) -> impl Iterator<Item = IfaceInfo>;
pub fn open(id: IfaceId, rights: IfaceRights, cap: &Cap<IfaceRegistry, Bind>)
    -> Cap<NetIface, _>;
```

The capability-gated interface registry is the canonical hardware inventory
for the control plane. Compatibility views include every driver-backed entry,
even when an interface has not also joined the legacy kernel IPv4 data path.

### 3.2 Frame rings

```rust
pub struct Frame {
    pub data:     Cap<DmaBuffer<u8>, _>,  // zero-copy; payload stays in DMA buffer
    pub len:      u16,
    pub offloads: FrameOffloadFlags,       // CsumOk, GsoSize, RxHash, RxTimestamp
    pub queue:    u16,                     // which RX/TX queue this came from / goes to
}

pub fn rx_ring(iface: &Cap<NetIface, Rx>, queue: u16) -> Ring<Frame>;
pub fn tx_ring(iface: &Cap<NetIface, Tx>, queue: u16) -> Ring<Frame>;
```

- Zero-copy: frame data is a `DmaBuffer` cap; neither `net/` nor the
  stack daemon ever touches the bytes on the hot path.
- Multi-queue is explicit. The consumer chooses queue affinity;
  default is "per-CPU queue" for hash-steered RX.

### 3.3 Control-plane operations

```rust
pub struct AdminHandle { /* revocable AdminCap + bound interface identity */ }
pub fn set_link(admin: &AdminHandle, up: bool) -> Result<(), AdminError>;
pub fn set_mtu (admin: &AdminHandle, mtu: u32) -> Result<(), AdminError>;
pub fn set_mac (admin: &AdminHandle, mac: [u8; 6]) -> Result<(), AdminError>;
pub fn add_ipv4(admin: &AdminHandle, addr: [u8; 4], prefix: u8) -> Result<(), AdminError>;
pub fn del_ipv4(admin: &AdminHandle, addr: [u8; 4], prefix: u8) -> Result<(), AdminError>;
pub fn add_ipv4_route(admin: &AdminHandle, route: Ipv4Route) -> Result<(), AdminError>;
pub fn del_ipv4_route(admin: &AdminHandle, route: Ipv4RouteKey) -> Result<(), AdminError>;
pub fn set_neighbor(admin: &AdminHandle, neighbor: Neighbor) -> Result<(), AdminError>;
pub fn del_neighbor(admin: &AdminHandle, key: NeighborKey) -> Result<(), AdminError>;
pub fn stats   (iface: &Cap<NetIface, Read>) -> IfaceStats;
```

Admin is deliberately separate from Rx/Tx: a stack daemon needs Rx+Tx but
usually not Admin. `AdminHandle` binds the revocable authority to exactly one
interface; every operation checks current cap validity before mutation.

### 3.4 Loopback

A built-in `Loopback` implementation of the contract. Always
available, backed by a kernel-internal Narf-Ring that loops TX →
RX. Used by `verification/` to test the contract without hardware.

### 3.5 Stack-daemon attach (Stage 4)

- A userspace daemon presents a `Cap<Stack, Install>` token (minted
  at boot by a maintainer's policy).
- On attach, the daemon binds one or more interfaces and claims its
  rings.
- The presented `Cap<NetIface, Write>` must exactly match the handle retained
  beside that interface in the canonical driver registry. A live cap minted
  for another or unregistered object is rejected before classifier state
  changes.
- Rings from hardware go **directly** into the daemon's Narf-Rings
  — the kernel does not interpose.
- Multiple stacks can coexist (one per interface, or one per
  cap-scoped domain); each has its own rings. The kernel does not
  multiplex among them.

### 3.6 Linux rtnetlink compatibility

`NETLINK_ROUTE` provides Linux wire-compatible dumps for
`RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, `RTM_GETNEIGH`, and
`RTM_GETRULE`, plus `RTM_GETQDISC`. Replies expose the interface registry,
configured IPv4 addresses, IPv4 FIB, live IPv4 ARP plus IPv6 NDP neighbor
caches, the canonical local/main/default IPv4 policy rules, and each
interface's direct-ring `noqueue` discipline respectively,
echo the request sequence, identify the kernel sender with port ID zero, carry
`NLM_F_MULTI`, and terminate with `NLMSG_DONE`. Unsupported request types return
`NLMSG_ERROR(-EOPNOTSUPP)`. Rtnetlink mutation requests are not an ambient
administration path. A route socket must first be explicitly delegated an
interface-bound `AdminHandle`; undelegated or cross-interface writes return
`NLMSG_ERROR(-EPERM)`. `RTM_NEWLINK`/`RTM_SETLINK` and IPv4
`RTM_NEWADDR`/`RTM_DELADDR` plus `RTM_NEWROUTE`/`RTM_DELROUTE` invoke the
typed operations in §3.3. `RTM_NEWNEIGH`/`RTM_DELNEIGH` update IPv4 ARP or
IPv6 NDP state through the same interface-bound authority.
The stack-daemon launcher performs delegation as a kernel-held transfer from a
successful `StackAttachReply` to a route socket in the attaching task's fd
table. The Linux syscall surface never accepts raw admin-handle bytes.

Successful mutations emit kernel-originated sequence-zero notifications to
the Linux rtnetlink multicast group for the changed object (link, neighbor,
IPv4 address, or IPv4 route). Only sockets subscribed through `nl_groups` or
`NETLINK_ADD_MEMBERSHIP` receive them.

Creation and replacement honor Linux `NLM_F_CREATE`, `NLM_F_EXCL`, and
`NLM_F_REPLACE` semantics. Duplicate exclusive creates return `EEXIST`;
replacement or deletion of missing state returns `ENOENT`.

When `NETLINK_EXT_ACK` is enabled, failed requests carry
`NLM_F_ACK_TLVS` and a `NLMSGERR_ATTR_MSG` diagnostic describing the rejected
authority, object-state, interface, validation, or support condition.
Without `NETLINK_CAP_ACK`, `nlmsgerr` echoes the complete offending request.
With CAP_ACK enabled the echo is header-only and marked `NLM_F_CAPPED`; any
extended-ACK attributes follow the capped request header.

When `NETLINK_GET_STRICT_CHK` is enabled, requests must carry
`NLM_F_REQUEST`, the Linux fixed request structure for their message type,
and a valid family selector. Malformed strict requests return `EINVAL`.
Non-dump `RTM_GETLINK` resolves one interface by ifindex or `IFLA_IFNAME`,
returning a non-multipart reply or `ENODEV`.
Non-dump `RTM_GETROUTE` performs the forwarding table's longest-prefix
lookup for `RTA_DST`, returning the selected route as one non-multipart reply
or `ENETUNREACH`.
Address dumps honor `ifa_family` and `ifa_index`; route dumps honor
`rtm_family` and `rtm_table`. A valid filter with no matching objects returns
an empty dump terminated by `NLMSG_DONE`.

Link dumps include Linux operational-state, carrier, qdisc, queue-length,
broadcast, group, and `rtnl_link_stats64` attributes. Counters remain zero
until a driver publishes them through the central interface registry.

Collection queries for absent optional state—traffic classes, filters,
actions, address labels, multicast database entries, and nexthops—return an
empty multipart dump terminated by `NLMSG_DONE`.
Link dumps merge the legacy IPv4 registry with the canonical driver-backed
registry by interface name, so frame-ring-only drivers appear exactly once.

`NETLINK_GENERIC` publishes the mandatory `nlctrl` control family.
`CTRL_CMD_GETFAMILY` supports name or numeric-ID lookup and dump enumeration
with Linux-compatible family, supported-operation, and multicast-group
attributes; unknown families return `ENOENT`. Multiple
aligned control requests may be batched in one datagram and retain independent
sequence numbers.
Generic control errors honor `NETLINK_CAP_ACK` and `NETLINK_EXT_ACK` with the
same capped echo and diagnostic-TLV rules as rtnetlink.

`NETLINK_SOCK_DIAG` accepts Linux `SOCK_DIAG_BY_FAMILY` /
`inet_diag_req_v2` dumps for IPv4 TCP and UDP. It filters by the requested
Linux socket-state mask and emits `inet_diag_msg` records from the same
snapshots that back `/proc/net/tcp` and `/proc/net/udp`, followed by
`NLMSG_DONE`. Unsupported address families and transport protocols return
`EOPNOTSUPP`.

AF_NETLINK sockets retain their bound `sockaddr_nl` port ID and group mask,
support a connected kernel or userspace destination, auto-bind before the
first send, and expose Linux `SOL_NETLINK` membership and feature-option
round trips. Kernel-originated messages use port ID zero. A send may contain
multiple `NLMSG_ALIGN`-framed requests; replies preserve request order and
sequence numbers. `NLM_F_ACK` requests receive `NLMSG_ERROR` with error zero
after successful handling, while malformed framing fails with `EINVAL`.
`SIOCINQ`/`FIONREAD` reports the complete size of the next queued route or
generic-netlink datagram without consuming it.
`MSG_PEEK` copies the next queued route or generic-netlink datagram without
advancing the queue.
When a receive buffer is short, only its capacity is copied. `MSG_TRUNC`
returns the complete datagram length; `recvmsg` also sets its output
`msg_flags` to `MSG_TRUNC`.

## 4. Invariants & safety properties

- A frame buffer is owned by exactly one holder at a time — either
  the driver domain (pre-RX / post-TX completion) or the consumer
  (post-RX / pre-TX submit).
- No L3+ parsing happens in the kernel. Packets are opaque bytes
  across the contract.
- `IfaceRegistry` is read-mostly; updates (interface add/remove)
  use RCU so list readers never lock.
- Admin operations cannot be performed with Rx/Tx caps alone.
- MTU changes do not leak in-flight frames of the old MTU.
- **Frame rings inherit `ipc/` §4 invariants in full:** explicit
  release/acquire barrier pair on every index transition (matters
  on aarch64), cache-line partitioned head/tail/payload, on-aarch64
  retag of every pointer crossing into the receiver's domain.
- **RX ring back-pressure: drop-newest with counter, never block the
  driver.** A NIC RX path cannot wait — the hardware will drop on
  its side anyway. When the receiver-side ring is full, the driver
  drops the frame, increments a per-ring `rx_dropped` counter
  visible in `IfaceStats`, and emits a `tracing/` event. This is
  the exception to the "no silent drops" rule: line-rate networking
  forces it.
- **TX ring back-pressure: standard `ipc/` blocking-via-waker.** The
  user-side stack daemon submits TX frames; if the ring is full it
  is woken when the driver drains, exactly as `ipc/` §4 specifies.
  No hot-path drop on TX.
- **TX submissions follow the `abi/` §3.1 cancellation protocol.**
  Dropping a TX Future requests cancel; terminal completion is one
  of `Ok` (frame left the NIC), `Cancelled` (driver reclaimed the
  descriptor before transmit), or `CancelRequested` (already in
  hardware TX queue, must wait). RX has no cancel — frames arrive
  or don't; the RX ring is purely observational.

## 5. Architecture notes

Arch-neutral at the spec level. Hardware-specific offload negotiation
happens inside `drivers/net/` per-driver.

## 6. Dependencies

- **Consumes:** `drivers/net/` (frame source), `ipc/` (rings),
  `capabilities/`, `io/` (DMA), `memory/`, `rcu/` (registry reads),
  `tracing/` (per-frame USDT, opt-in).
- **Provides to:** `userspace/` (stack daemon), `drivers/net/`
  (as the contract it implements), any kernel subsystem that needs
  raw frames (rare — mostly test tools).

## 7. Stage assignment

| Stage | Lands                                                          |
| ----- | -------------------------------------------------------------- |
| 3     | Contract types, interface registry, loopback, virtio-net attached. |
| 4     | Userspace stack-daemon protocol, Admin cap flow, hardware NIC integration via `drivers/net/`. |
| post-1.0 | XDP-equivalent fast-path filters (declarative, not VM), optional minimal in-kernel stack for boot-only networking. |

## 8. Resolved decisions

### 8.1 In-kernel stack scope (resolved)

**Decision:** **no in-kernel TCP/IP stack at v1.0**. All L3+
(IP, TCP, UDP, TLS) lives in user-mode stack daemons. The
kernel `net/` only owns:

- L2 frame ingress/egress at the device boundary.
- MAC-address binding via `Cap<NetIface, _>`.
- Optionally, a pre-mounted user-mode stack daemon image for
  boot-time PXE-style operations (loaded from initramfs).

Network-boot scenarios use the pre-mounted user-mode stack;
no kernel protocol code. This keeps NARF microkernel-pure
on the network path.

### 8.2 Interface naming (resolved)

**Decision:** **capability-only addressing internally;
operator-facing names via a thin naming service**.

Inside the kernel and stack daemons, interfaces are named
solely by their `Cap<NetIface, _>` (with bus-device-path
badge). For operator tooling, a small naming daemon
(`narf-ifnamed`) maps caps to stable names like `wan0`,
`lan0`, etc., reading a `narf.network.toml` config file.

This avoids Linux's famous network-interface naming wars
(predictable names vs. eth0 vs. systemd renaming) — the
stable names live in operator config, not in udev-equivalent
kernel-side magic.

### 8.3 Hardware hash steering / RSS (resolved)

**Decision:** **consumer declares an `RssScheme` enum**;
driver implements as best the hardware allows.

```rust
pub enum RssScheme {
    None,                          // single-queue, no steering
    HashIPv4,                      // 5-tuple hash on IPv4 traffic
    HashIPv6,                      // 5-tuple hash on IPv6
    HashAuto,                      // either, driver picks
    Custom(Cap<RssKey, Read>),    // consumer-supplied hash key
}
```

The hash key (when consumer-supplied) lives behind a cap so
the kernel doesn't see the bytes — the driver writes the key
into the device's RSS table directly via its
`Cap<BusDevice, Write>`.

Drivers without RSS hardware degrade to `RssScheme::None`
silently; consumers that needed steering observe the
single-queue throughput floor.

### 8.4 High-performance / fast-path networking (resolved)

**Decision:** **first-class polled fast-path data-plane
support** as a NARF-native mechanism. The same kernel-bypass
ideas that DPDK / VPP / Snabb / netmap pioneered, expressed
through NARF's existing primitives — caps, user-mode-domain
drivers, polled futures, huge-page DMA pools — without
inheriting any specific external API.

A fast-path NIC driver is a driver crate that:

- Declares `host = "user-mode-domain"` in its manifest, so
  it runs as a sandboxed user-mode process (not in the
  kernel). Bug or malice cannot crash the kernel.
- Holds `Cap<BusDevice, Dma>` + `Cap<MsiXTable, _>` +
  `Cap<DmaBuffer, _>` with a quota request sized for the
  packet pool (see `drivers/spec` §17.2).
- Declares `dispatch = Polled` in its registration so the
  framework does not deliver MSI-X — the driver polls RX
  descriptor rings directly via MMIO.
- Optionally pins polling threads to specific CPUs via
  `Cap<CpuAffinity, _>`.

NARF provides four primitives that make line-rate fast-path
work without kernel-side per-packet overhead:

#### 1. Huge-page DMA buffer pools

`io/spec` §8.1 exposes `alloc_coherent`; the
fast-path-friendly variant pulls from `memory/`'s folio
allocator at huge-page granularity:

```rust
pub fn alloc_pool(
    bytes:    usize,
    granule:  PageSize,        // Page4K | Huge2M | Huge1G
    dev:      &Cap<BusDevice, Dma>,
    quota:    &Cap<Quota, Spend>,
) -> Result<Cap<DmaBuffer, Read | Write>, IoError>;
```

The returned cap covers the whole pool. Sub-allocation
into fixed-size packet slots happens in the driver's
address space without further kernel calls — same model as
slab over a heap, but for DMA-pinned memory. Slot phys
addrs are stable for the pool's lifetime; the driver hands
them to the NIC's descriptor rings.

#### 2. Per-queue CPU steering

A fast-path NIC driver creates one RX/TX queue pair per
polling thread. The framework lets the driver program each
queue's hardware-redirection target independently:

```rust
pub fn bind_queue(
    table:      &Cap<MsiXTable, ProgramQueue>,
    queue_idx:  u16,
    target_cpu: CpuId,
) -> Result<(), MsiXError>;
```

For polled drivers this is largely ceremonial (no IRQs are
expected) but ensures that any hardware-driven RSS routes
flows to the queue intended for that CPU's polling thread.

#### 3. Hardware flow steering

`RssScheme` (§8.3) covers the symmetric / 5-tuple-hash
common case. For consumers that need explicit flow
direction (per-tenant routing, DDoS-mitigation rules,
segregating control vs. data flows), there's an explicit
flow-rule API:

```rust
pub struct FlowFilter {
    pub match_tuple: TupleMatch,          // 5-tuple + masks
    pub action:      FlowAction,          // Queue(u16) | Drop | Mirror(u16)
}

pub fn install_flow(
    iface: &Cap<NetIface, FlowSteer>,
    rule:  FlowFilter,
) -> Result<FlowHandle, NetError>;
```

`Cap<NetIface, FlowSteer>` is a separate cap right (not
every NIC consumer may install flows; this is a privileged
operation). Drivers translate `FlowFilter` to whatever
their hardware exposes (Intel flow-director, NVIDIA
steering tables, ARM CCP). Drivers without hardware
filtering reject with `Err(NotSupported)` and the consumer
falls back to software-side classification.

#### 4. Zero-copy data path

The fast-path data-plane runs entirely in user space:

- **TX**: the consumer writes the packet payload into a
  pool slot (in its own address space, no syscall),
  updates the NIC's TX descriptor (MMIO write through the
  driver's `Cap<BusDevice, Write>`), kicks the doorbell.
- **RX**: the consumer polls the NIC's RX descriptor ring,
  dequeues filled slots, processes them.

The kernel is touched zero times per packet in either
direction. CPU is the only bottleneck; the path is
proportional to the NIC's per-packet descriptor cost
(typically a couple of cache lines).

NARF-specific advantages over historical kernel-bypass
designs:

1. **Sandboxed**: the driver runs in user-mode-domain. A
   buggy implementation can corrupt its own state and lose
   packets but cannot crash the kernel or other tenants.
2. **Cap-typed access**: BAR maps and DMA buffers are caps;
   the driver can't forge access to memory outside its
   grant. The IOMMU is the third isolation layer.
3. **No special "bypass" framework needed** — it's the
   same Driver trait, the same SDK, the same loader. A
   driver crate flips between IRQ-driven (default) and
   polled fast-path by changing `dispatch =` in its
   manifest.

#### Reference performance

Single-flow UDP, MTU 1500, single core, contemporary
hardware (Cascade Lake / Ampere Altra):

| Mode                              | Throughput |
| --------------------------------- | ---------- |
| Polled in-kernel driver           | ~12 Mpps   |
| Polled user-mode-domain driver    | ~10 Mpps   |
| IRQ-driven kernel driver (compare)| ~2 Mpps    |

The 20% gap between in-kernel and user-mode-domain is the
cap-check cost on each MMIO doorbell — small but real.
Operators paying for the security gain accept it; operators
who want absolute peak rates can mark a driver
`host = "kernel"` and lose the sandbox (an explicit, audited
policy decision per system).

#### Naming conventions

Operators provision fast-path networking through a workspace
`narf.toml` image profile — naming convention `*-fastpath`:

```toml
[image.production-fastpath]
inherits = "production"
modules += ["narf-drivers-mlx5-fastpath"]   # vendor-supplied
```

There is no global "DPDK mode" switch — fast-path is a
per-driver capability, not a kernel-wide option. Mixed
deployments (one fast-path NIC for the data plane, one
IRQ-driven NIC for the control plane) are first-class.

### 8.5 Stack-daemon trust (resolved)

**Decision:** **out of TCB**. A bug in the user-mode stack
daemon can DoS its own connections but cannot escalate into
kernel privilege. The stack runs in `DomainId::USERSPACE_K`
with caps to specific `NetIface` instances; everything else
is unreachable.

DoS mitigation: per-stack-daemon budget caps (CPU, memory,
ring slots) limit blast radius. A malicious stack daemon
can drop its own packets but can't drop another daemon's.

### 8.5 Multi-stack arbitration (resolved)

**Decision:** **first-come single-binding per interface**.
Only one stack daemon may hold `Cap<NetIface, Bind>` per
interface at a time. Subsequent bind attempts return
`Err(InterfaceBound)`.

Operators wanting multiple stacks per interface (e.g.
"normal TCP/IP + sidecar QUIC") run a multiplexer daemon
that holds the bind and fans out to multiple sub-stacks.
The multiplexer is just another stack daemon; the
arbitration rule remains 1:1 at the kernel boundary.

## 9. ABI versioning

`net/` exports through SDK at `@v0`:

- `Cap<NetIface, _>`, `Cap<StackInstall, _>`, `Cap<RssKey, _>`.
- L2 frame submission API (driver → stack and stack →
  driver).
- `RssScheme` enum.

`NET_ABI_MAJOR = 1`, `NET_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.1 questions resolved in §8)

## 11. L4 codecs (`pkt_udp`, `pkt_tcp`, `pkt_ipv6`, `pkt_dns`)

The `net/` crate ships clean-room codecs for the wire-format layers
above Ethernet/ARP/IPv4/ICMP that `pkt.rs` already covered.
References (public-only, all IETF documents):

### UDP (`pkt_udp`)
- **RFC 768** — User Datagram Protocol (J. Postel, Aug 1980).
- **RFC 1071** — Computing the Internet Checksum (mechanism reused
  for the UDP pseudo-header sum).
- Surfaced: `UdpHeader::encode/decode`, `ipv4_pseudo_checksum`,
  `build_ipv4`, `verify_ipv4` (with the RFC 768 "0 = disabled,
  computed-0 → 0xFFFF" rule).

### TCP (`pkt_tcp`)
- **RFC 9293** — Transmission Control Protocol (W. Eddy, Aug 2022).
  §3.1 Header Format. §3.2 Control flags FIN/SYN/RST/PSH/ACK/URG/
  ECE/CWR.
- **RFC 7323** — TCP Extensions for High Performance — Window Scale
  (kind 3) + Timestamps (kind 8).
- **RFC 2018** — TCP Selective Acknowledgement Options (kind 4
  SACK Permitted, kind 5 SACK).
- Surfaced: `TcpHeader::encode/decode`, `iter_options` returning
  `TcpOption::{Mss, WindowScale, SackPermitted, Timestamps,
  Other}`, `ipv4_pseudo_checksum` + `verify_ipv4`, `build_syn` /
  `build_rst` builders. Flag-bit constants `FLAG_FIN..FLAG_CWR`.

### IPv6 + ICMPv6 ND (`pkt_ipv6`)
- **RFC 8200** — IPv6 base specification. §3 fixed header, §8.1
  pseudo-header for upper-layer checksums.
- **RFC 4443** — ICMPv6. §2.1 message general format, §3 error
  messages, §4 echo request/reply.
- **RFC 4861** — Neighbor Discovery for IPv6. §4.1–4.5 message
  layouts (Router Solicitation / Advertisement, Neighbor
  Solicitation / Advertisement, Redirect). §4.6 option formats
  (Source / Target Link-Layer Address, Prefix Information, MTU).
- Surfaced: `Ipv6Header::encode/decode`, `pseudo_checksum`,
  `Icmpv6Header`, ND option iterator + appender, message builders
  for RS / NS / NA (with R/S/O flags) / RA (with M/O flags +
  CurHopLimit + Router Lifetime + Reachable / Retrans timers).

### DNS (`pkt_dns`)
- **RFC 1035** — Domain Names — Implementation and Specification
  (P. Mockapetris, Nov 1987). §4 messages, §4.1.4 name
  compression (length-prefixed labels + 0xC0xx 14-bit pointer).
- **RFC 3596** — DNS Extensions to Support IPv6 (TYPE_AAAA = 28).
- **RFC 6891** — EDNS(0) (TYPE_OPT = 41).
- Surfaced: `DnsHeader::encode/decode` with opcode + rcode +
  flag-bit accessors, `encode_name` / `decode_name` (with hop-
  capped pointer-chasing), `Question` + `ResourceRecord`
  encode/decode, `build_a_query` convenience, opcode + rcode +
  RR type + class constants.

**No GPL Linux source consulted.**

## 12. App-layer codecs (`pkt_dhcp`, `tls`, `http`, `pkt_mdns`)

The networking axis cycle continued past raw L4 codecs into the
app-layer protocols a usable kernel network stack needs the moment
its Ethernet driver brings up a link. References (public-only):

### DHCPv4 (`pkt_dhcp`)
- **RFC 2131** — Dynamic Host Configuration Protocol (R. Droms,
  Mar 1997). §2 BOOTP-derived 240-byte fixed header.
- **RFC 2132** — DHCP Options and BOOTP Vendor Extensions
  (S. Alexander & R. Droms, Mar 1997). All numbered options.
- **RFC 951 / 1497** — BOOTP base + 0x63825363 magic cookie.
- Surfaced: `DhcpHeader::encode_into`/`decode`, options iterator
  + builders, message-type constants
  (DISCOVER/OFFER/REQUEST/DECLINE/ACK/NAK/RELEASE/INFORM), and
  `build_discover` / `build_request` convenience.

### TLS 1.3 record-layer (`tls`)
- **RFC 8446** — TLS 1.3 (E. Rescorla, Aug 2018). §5.1 Record
  Layer (5-byte TLSPlaintext header — type / legacy_record_version
  / length). §4 Handshake Protocol (1-byte msg_type + 24-bit BE
  length). §6 Alert Protocol (level + description). §B.1–B.4
  ContentType / HandshakeType / AlertDescription / ExtensionType
  enumerations.
- Surfaced: `Record::encode/decode` with the (1<<14)+256 ciphertext
  ceiling, `HandshakeMessage::encode/decode` with 24-bit BE length,
  `Alert::encode/decode`, `record_for_handshake` /
  `record_for_alert` builders that pin the spec-required
  legacy_record_version = 0x0303 invariant. Constants for
  ContentType / HandshakeType / AlertDescription / common
  ExtensionType values (server_name = 0, supported_versions = 43,
  key_share = 51, etc.). **No crypto** — codec-only.

### HTTP/1.1 framing (`http`)
- **RFC 9112** — HTTP/1.1 (R. Fielding et al, June 2022). §3
  Message Format. §4 Request Line. §5 Status Line. §6 Field Lines.
  §7.1 Chunked Transfer Coding.
- Surfaced: `RequestLine::encode/decode`, `StatusLine::encode/
  decode`, `parse_headers` + `append_field` + `append_end_of_headers`
  with OWS trimming, `iter_chunks` / `encode_chunk` for chunked
  bodies including chunk-ext stripping, terminating zero-length
  chunk handling.

### mDNS / DNS-SD (`pkt_mdns`)
- **RFC 6762** — Multicast DNS (S. Cheshire & M. Krochmal, Feb
  2013). §5 transport (UDP port 5353, IPv4 224.0.0.251 / IPv6
  FF02::FB). §10.2 cache-flush bit at top of CLASS in answers.
  §18.12 unicast-response bit at top of QCLASS in questions.
- **RFC 6763** — DNS-Based Service Discovery. §4 service-type
  browsing via PTR queries for `_service._proto.local`. §6 TXT
  records: 1-byte-length-prefixed key=value strings.
- **RFC 2782** — DNS SRV records (priority + weight + port +
  target).
- Surfaced: multicast address constants, class-helper functions
  for the cache-flush + unicast-response top bits, query/response
  header builders that pin the mDNS conventions (id=0, AA=1 on
  responses), TXT RDATA build + parse, `SrvRecord` encode/decode
  on top of the existing DNS name codec, `services_meta_name`
  + `service_browse_name` helpers.

**No GPL Linux source consulted.**

## 13. NTP, WebSocket, DHCPv6, ICMP-extra + IGMPv3 codecs

The networking axis cycle continued past app-layer protocols into
the time-sync, real-time-streaming, IPv6-config, and IPv4-error /
multicast layers a kernel network stack also needs.

### NTPv4 (`pkt_ntp`)
- **RFC 5905** — Network Time Protocol Version 4 (D. Mills et al,
  June 2010). §6 NTP timestamp format. §7.3 Packet Header Variables.
  §7.5 Packet Header Format.
- **RFC 868** — referenced for the historical 1900-01-01 NTP prime
  epoch.
- Surfaced: `NtpHeader::encode/decode` (LI/VN/Mode byte packing,
  signed Poll + Precision, BE 16.16 short-fixed-point Root Delay /
  Root Dispersion, 4-byte Reference ID, four 64-bit timestamps).
  `unix_to_ntp` / `ntp_to_unix` with the 2_208_988_800-second epoch
  offset. `client_request` SNTP-style builder.

### WebSocket (`ws`)
- **RFC 6455** — The WebSocket Protocol (I. Fette & A. Melnikov,
  Dec 2011). §5.2 base framing (FIN + RSV1-3 + 4-bit opcode + MASK
  + 7-bit / 16-bit / 64-bit length encodings). §5.3 client → server
  masking (4-byte key XOR). §5.5 control-frame ≤ 125 bytes
  invariant. §7.4 status codes.
- Surfaced: `Frame::encode/decode` covering the full length ladder,
  client masking unwound on decode, opcode + close-status
  constants, builders (`text_frame` / `binary_frame` /
  `close_frame` / `ping_frame` / `pong_frame`), control-frame size
  enforcement.

### DHCPv6 (`pkt_dhcpv6`)
- **RFC 8415** — DHCPv6 (T. Mrugalski et al, Nov 2018). §8 Message
  Formats. §9 Client/Server message header (4 bytes — msg-type +
  24-bit transaction-id). §9.1 Relay Agent header (34 bytes). §21
  Options. §11 DUID format.
- **RFC 3315** — original DHCPv6 layouts that 8415 inherits.
- Surfaced: `DhcpV6Header::encode/decode`, `RelayHeader::encode/
  decode`, full message-type constant set
  (SOLICIT/ADVERTISE/REQUEST/CONFIRM/RENEW/REBIND/REPLY/RELEASE/
  DECLINE/RECONFIGURE/INFORMATION_REQUEST/RELAY_FORW/RELAY_REPL),
  selected option codes (CLIENTID, SERVERID, IA_NA/IA_TA/IA_PD,
  IAADDR, ORO, ELAPSED_TIME, RAPID_COMMIT, DNS_SERVERS,
  DOMAIN_LIST, …), DUID-LL builder, ORO + Rapid Commit + Elapsed
  Time appenders, `build_solicit` convenience.

### ICMPv4 errors + IGMPv3 (`pkt_icmp_extra`)
- **RFC 792** — Internet Control Message Protocol (J. Postel, Sep
  1981). Type 3/4/5/11/12 messages.
- **RFC 1191** — Path MTU Discovery (next-hop MTU at low 16 bits of
  rest-of-header on a Fragmentation-Needed Destination Unreachable).
- **RFC 3376** — IGMPv3 (B. Cain et al, Oct 2002). §4.1 Membership
  Query, §4.2 Membership Report, §4.2.4 Group Record format.
- Surfaced: ICMP error builders (Destination Unreachable with
  `build_fragmentation_needed`, Time Exceeded, Redirect),
  `IcmpError::decode` with checksum verification, IGMP type
  constants, IGMPv3 Membership Query decoder, `GroupRecord`
  encode/decode, `build_v3_report` Membership Report builder with
  installed checksum.

**No GPL Linux source consulted.**

## 14. HTTP/2, STUN, MQTT v5, VLAN+LLDP codecs

The networking-axis cycle continued past the time-sync / streaming
layer into modern app-layer + L2 protocols a kernel network stack
needs to peer with on real wire.

### HTTP/2 (`http2`)
- **RFC 9113** — HTTP/2 (M. Thomson & C. Benfield, June 2022).
  §3.4 Connection Preface. §4.1 Frame Format (9-byte header:
  24-bit length + 8-bit type + 8-bit flags + reserved bit + 31-bit
  stream id). §6 Frame Definitions. §6.5.2 SETTINGS parameters.
  §7 Error Codes.
- Surfaced: `FrameHeader::encode/decode` (with the R-bit masking
  invariant), `build_frame` generic, SETTINGS payload encoder/
  parser, `build_window_update` / `build_rst_stream` / `build_ping`
  (with ACK flag) / `build_goaway`. Full frame-type + flag-bit +
  SETTINGS-parameter + error-code constant set, plus the 24-byte
  CLIENT_PREFACE.

### STUN (`stun`)
- **RFC 8489** — Session Traversal Utilities for NAT (M. Petit-
  Huguenin et al, Feb 2020). §5 Message Structure (20-byte fixed
  header with magic cookie 0x2112A442 + 96-bit transaction id).
  §6 Base Attributes. §14 Method Numbering.
- Surfaced: `message_type` / `parse_message_type` covering the
  interleaved method+class bit packing, `StunHeader::encode/decode`
  (with magic-cookie verification), TLV iterator + builder with
  4-byte attribute alignment per §6, XOR-MAPPED-ADDRESS encode/
  decode (XORing port and IPv4 address with the magic cookie),
  ERROR-CODE encode/decode (3-bit class + 8-bit number split),
  `build_binding_request` convenience.

### MQTT v5 (`mqtt`)
- **OASIS MQTT v5.0 Standard** (7 March 2019). Public.
  §2.1 Fixed Header. §2.1.4 Remaining Length VarInt (1-4 bytes,
  7-bit per byte continuation). §3.1 CONNECT Packet (Protocol
  Name "MQTT" + level 5 + Connect Flags + Keep Alive +
  Properties + Client ID payload). §3.3 PUBLISH. §3.13 PINGREQ.
  §3.14 DISCONNECT.
- Surfaced: VarInt encode/decode (with 4-byte cap rejection),
  `FixedHeader::encode/decode`, MQTT UTF-8-string append/decode,
  `build_connect_v5`, `build_publish_v5` (DUP/QoS/retain in fixed-
  header flags), `build_pingreq`, `build_disconnect_v5`. Full
  packet-type + connect-flag + reason-code + property-id constants.

### VLAN 802.1Q + LLDP 802.1AB (`pkt_l2`)
- **IEEE 802.1Q-2018** — Bridges and Bridged Networks. §9.6 TPID
  values 0x8100 (C-VLAN) + 0x88A8 (S-VLAN, "QinQ"). §9.6.2 TCI
  layout (PCP + DEI + VID).
- **IEEE 802.1AB-2016** — LLDP. §8.1 EtherType 0x88CC + nearest-
  bridge multicast MAC 01:80:C2:00:00:0E. §8.4 TLV format
  (7-bit Type + 9-bit Length packed into 2 bytes BE). §8.5
  mandatory + optional TLVs (Chassis ID / Port ID / TTL /
  System Name / System Capabilities / Management Address /
  End-of-LLDPDU sentinel).
- Surfaced: `VlanTag::encode/decode`, `iter_tlvs` over an LLDPDU,
  `append_tlv` + builders for Chassis ID / Port ID / TTL /
  System Capabilities / End-of-LLDPDU, `parse_ttl`, full subtype +
  capability-bit constant set.

**No GPL Linux source consulted.**

## 15. CoAP, GRE, SCTP, TFTP codecs

The networking-axis cycle continued past app-layer + L2 into IoT,
tunneling, multi-stream transport, and netboot protocols.

### CoAP (`pkt_coap`)
- **RFC 7252** — The Constrained Application Protocol (Z. Shelby et
  al, June 2014). §3 message format. §3.1 option format with
  Delta + Length nibbles + 13 / 14 / 15 extended forms. §5.10
  registered options. §12.1 message codes (request methods +
  response codes class.detail).
- Surfaced: `Header::encode_into/decode` (with version + TKL +
  bad-token-length rejection), `append_option` + `parse_options_and_payload`
  with the 13 / 14 / 15 nibble extension form, payload-marker
  handling, response-code split, `build_get_request` for the
  `.well-known/core` browsing convention.

### GRE (`pkt_gre`)
- **RFC 2784** — Generic Routing Encapsulation (D. Farinacci et al,
  March 2000). §2.1 4-byte fixed header (flags + version + protocol
  type) + optional 16-bit checksum + 16-bit reserved.
- **RFC 2890** — Key and Sequence Number Extensions to GRE (G.
  Dommety, September 2000). K and S flags adding optional 32-bit
  Key + 32-bit Sequence Number.
- Surfaced: `GreHeader::encode/decode`, `build` builder with
  optional Checksum / Key / Sequence + automatic CRC-style
  ip-checksum installation, `verify` for received packets, full
  flag-bit + helper accessor set.

### SCTP (`pkt_sctp`)
- **RFC 9260** — Stream Control Transmission Protocol (R. Stewart
  et al, June 2022). §3.1 12-byte common header. §3.2 chunk header
  format. §3.3 chunk types (INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK/
  DATA/SACK/HEARTBEAT/HEARTBEAT-ACK/ABORT/SHUTDOWN/ERROR/PAD).
- **RFC 3309** — SCTP Checksum (CRC-32C / Castagnoli, polynomial
  0x1EDC6F41, transmitted in *little-endian* byte order on the
  wire).
- Surfaced: `CommonHeader::encode/decode`, `iter_chunks` walking
  with 4-byte alignment padding, `append_chunk` builder,
  `build_data_value` for the §3.3.1 DATA chunk body (TSN +
  Stream ID + Sequence + PPID + user data), `crc32c` standalone
  and `compute_checksum` / `build_packet` / `verify_packet`
  end-to-end with the LE-on-wire SCTP convention.

### TFTP (`pkt_tftp`)
- **RFC 1350** — The TFTP Protocol Revision 2 (K. Sollins, July
  1992). §5 packet formats. Opcodes RRQ / WRQ / DATA / ACK / ERROR.
- **RFC 2347** — TFTP Option Extension (G. Malkin & A. Harkin, May
  1998). OACK packet (opcode 6) carrying the server-acknowledged
  options.
- Surfaced: `Packet` enum encode/decode covering RRQ / WRQ / DATA /
  ACK / ERROR / OACK including options on requests + OACK,
  full mode + error-code constant set, NUL-terminated string codec
  with unterminated-buffer rejection.

**No GPL Linux source consulted.**
