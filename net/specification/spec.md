# net — Specification

> Status: **Outline v0.1** (Stage 3 → 4). Contract-heavy; minimal code.

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
pub fn set_link(iface: &Cap<NetIface, Admin>, up: bool) -> impl Future<Output=()>;
pub fn set_mtu (iface: &Cap<NetIface, Admin>, mtu: u16) -> impl Future<Output=()>;
pub fn set_mac (iface: &Cap<NetIface, Admin>, mac: [u8; 6]) -> impl Future<Output=()>;
pub fn stats   (iface: &Cap<NetIface, Read>) -> IfaceStats;
```

Admin is deliberately separate from Rx/Tx: a stack daemon needs
Rx+Tx but usually not Admin.

### 3.4 Loopback

A built-in `Loopback` implementation of the contract. Always
available, backed by a kernel-internal Narf-Ring that loops TX →
RX. Used by `verification/` to test the contract without hardware.

### 3.5 Stack-daemon attach (Stage 4)

- A userspace daemon presents a `Cap<Stack, Install>` token (minted
  at boot by a maintainer's policy).
- On attach, the daemon binds one or more interfaces and claims its
  rings.
- Rings from hardware go **directly** into the daemon's Narf-Rings
  — the kernel does not interpose.
- Multiple stacks can coexist (one per interface, or one per
  cap-scoped domain); each has its own rings. The kernel does not
  multiplex among them.

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

## 8. Open questions

- **Minimal in-kernel stack.** For PXE-ish boot-time operations
  (firmware update, network-boot) we may need *some* in-kernel IP +
  UDP. Scope if/when; not Stage 1–4.
- **Interface naming.** `eth0`-style Linux conventions, or capability-
  only addressing (no names at all)? The latter is purer; the former
  is easier to debug.
- **Hardware hash steering.** How the consumer declares its
  preferred RSS scheme without leaking hash state into the kernel.
- **Stack daemon trust.** Is the stack in or out of the TCB? Out is
  the microkernel answer; but a bug in the stack can still DoS.
- **Multi-stack arbitration** when multiple daemons try to bind the
  same interface.
