# net — Design Notes

> 2026-04-22. Author: Claude Sonnet 4.6 (design-phase analysis).

---

## Load-bearing decisions

**The kernel has zero L3/L4 code — by policy, not by accident.** §1 makes this explicit: no IP, TCP, UDP in the kernel. This is the right call architecturally (kernel TCB stays minimal), but it has a hard operational implication that the spec soft-pedals: before a userspace stack daemon attaches (Stage 4), there is *no* networked operation possible. PXE boot, remote console, network-based crash dump, time sync — all require the daemon to be up. The spec acknowledges a "minimal in-kernel stack for boot-only networking" as post-1.0, but the operational window between boot and daemon-up is a real gap that affects the Stage 1–3 development workflow (no remote QEMU console over IP, no netdump before the stack daemon lands).

**Frame ownership is strict single-holder, but the contract does not specify the transfer barrier.** §4 states "a frame buffer is owned by exactly one holder at a time." The zero-copy model requires that the DMA buffer backing the `Frame` is visible to the new holder immediately after the cap transfer. On x86_64 with TSO this is mostly automatic; on aarch64 with weaker memory ordering, transferring a `Cap<DmaBuffer<u8>, _>` does not automatically create a happens-before edge between the driver's final write to the buffer and the daemon's first read. The ordering semantics of the Narf-Ring ownership transfer must include a release/acquire barrier pair, and the spec does not specify this.

**Multi-stack coexistence is described but arbitration is entirely deferred.** §3.5 says "multiple stacks can coexist (one per interface, or one per cap-scoped domain); each has its own rings. The kernel does not multiplex among them." The unstated corollary: if two stack daemons both hold `Cap<NetIface, Rx>` for the same interface, the hardware NIC's RSS hash steers each packet to exactly one queue, so the kernel never has to multiplex — but there is also no kernel mechanism to prevent two daemons binding the same queue. The capability system must enforce queue-to-daemon exclusivity, and the spec does not say whether queue binding consumes the cap (making it non-duplicable) or merely gates access.

**Interface naming is deferred but load-bearing for debug.** §8 asks "capability-only addressing (no names at all)?" The purist answer is correct for a production security model; the practical answer is that a developer who types the wrong capability handle has no way to diagnose "that's the loopback, not eth0." The initial development tooling for Stage 3 will need some human-readable handle mapping, even if only for diagnostic tools. Deferring this entirely means tracing/observability output for network events will have `IfaceId(3)` instead of a meaningful name, which slows debugging.

---

## Divergences from precedent

**AF_XDP vs. Narf-Ring:** Linux's AF_XDP is the closest precedent for zero-copy kernel-to-userspace frame delivery. AF_XDP uses a UMEM shared-memory region with four rings (FILL, COMPLETION, RX, TX). Narf-Ring uses the general IPC ring with ownership-transfer semantics. The difference is that AF_XDP's UMEM is pre-registered and the kernel can DMA directly into it; NARF's model assumes the DMA buffer is already a `Cap<DmaBuffer<u8>, _>` that was allocated by `io/`. This is architecturally cleaner but it means the DMA buffer lifecycle (allocation, DMA completion, ownership transfer, reuse) is more complex than AF_XDP's simple descriptor-in-UMEM model. In particular, the driver must signal DMA completion *before* transferring cap ownership — the sequencing is implicit in AF_XDP (COMPLETION ring) but must be explicit in NARF.

**Fuchsia Netstack3:** Netstack3 runs in a Fuchsia component with its own capability handles (FIDL channels). The key lesson from Netstack3 is that capability overhead per packet is not acceptable on the hot path — Fuchsia batches operations aggressively. NARF's per-frame `Cap<DmaBuffer<u8>, _>` implies a cap lookup on every frame RX. If the cap table is in a separate domain (which it must be for security), every frame delivery touches at least two domains: the driver domain and the cap table domain. That is two potential PKRS writes per frame. At 10 Gbps, 64-byte frames = ~14.8 million frames/sec; at 50–200 cycles per WRMSR, that is significant. The spec must acknowledge that per-frame cap checks require the cap lookup to be fast-pathed (perhaps inlined into the ring hot path with a pre-validated handle).

**seL4 + LwIP vs. NARF's smoltcp-capable architecture:** seL4's networking story delegates to a userspace server that wraps LwIP. The operational model is similar to NARF's stack daemon, but LwIP is a C library with no ownership semantics. NARF's native-Rust daemon can use smoltcp (zero-allocation, event-driven, 0-clause BSD) which matches the architectural philosophy much better. The smoltcp research summary confirms ~3.7–7.9 Gbps in loopback; this needs to be the baseline perf gate for the loopback implementation in Stage 3.

**The XDP-equivalent filter path is post-1.0 but the need is Stage 3.** AF_XDP's killer feature is programmable packet steering without a kernel ABI change. NARF defers an "XDP-equivalent" to post-1.0, but the Stage 3 loopback and virtio-net path will immediately need some steering for multi-queue RSS. Without a filter hook, all queue steering must be done by the hardware NIC and configured via Admin caps — which is less flexible than XDP. The spec should acknowledge this and declare that hardware RSS is the *only* supported steering model for 1.0, so the design does not accidentally grow an unvetted in-kernel filter path.

---

## Proposed spec changes

- **§4 Invariants — add memory ordering requirement for cap transfer:** "Ownership transfer of a `Cap<DmaBuffer<u8>, _>` via the Narf-Ring must establish a happens-before edge: the sender must use a release store as the final step of the ring push; the receiver must use an acquire load as the first step of the ring pop. This guarantees DMA-written bytes are visible before the new owner reads them on all supported architectures."

- **§3.2 Frame rings — document the DMA completion sequencing:** Add an explicit note: "The driver domain must ensure DMA completion is observed (via `io/` completion callback) before transferring the `Cap<DmaBuffer<u8>, _>` into the RX ring. Transferring before completion creates a data race on aarch64 even with the acquire/release discipline."

- **§3.5 Stack-daemon attach — specify queue exclusivity:** "Binding a queue via `rx_ring` / `tx_ring` consumes the queue slot from the `Cap<NetIface, Rx/Tx>` in the sense that a second binding of the same queue index must fail. The kernel must enforce queue-to-daemon exclusivity at the capability layer, not just by convention." Add an error variant `QueueAlreadyBound`.

- **§8 Open questions — promote interface naming to Stage 3 decision:** Require that Stage 3 diagnostics output at minimum a human-readable alias for each `IfaceId`, even if not enforced at the ABI level. Propose: a `IfaceInfo::name` field of `BoundedString<16>` set at registration, purely informational, with no security properties.

- **§7 Stage assignment — add per-frame cap overhead benchmark gate:** At Stage 3 exit, require a perf gate: "Narf-Ring frame round-trip through loopback at minimum 1 Gbps (64-byte frames) with full cap checks enabled." This gates that per-frame cap lookup is not a bottleneck before production drivers land.

- **§1 Purpose & scope — document pre-daemon operational gap:** Add: "Before the stack daemon attaches (Stage 4), no network operation is available except loopback. Any Stage 1–3 tooling requiring network connectivity must use serial console or QEMU host-only paths."

---

## Open invariants / cross-subsystem hazards

**`io/` §? (DMA buffer lifecycle):** The `Cap<DmaBuffer<u8>, _>` type is defined in `net/`'s interface but the buffer is owned and allocated by `io/`. `io/` must export a `DmaBuffer` cap type that `net/` can reference without depending on `io/`'s internals. The direction of dependency (net → io) is in §6, but the cap type definition location is not. If `io/` defines `DmaBuffer` and `net/` uses it in its public ring types, then `net/` has a hard compile-time dependency on `io/` that complicates Stage 3 sequencing (both land in Stage 3 but one must come first).

**`capabilities/` §3 — multi-rights cap on a single iface:** `Cap<NetIface, _>` parameterizes over a rights type. But Rx and Tx are often needed together. The spec says "Admin is separate from Rx/Tx" but does not specify whether a single cap can carry multiple rights (e.g., `Cap<NetIface, Rx | Tx>`) or whether two separate caps are required. This matters for the daemon's bootstrap: at stack-daemon attach, what bundle of caps does the kernel mint? Needs resolution at `capabilities/` §3.

**`rcu/` (registry reads):** §6 says the `IfaceRegistry` uses RCU. This means drivers calling `register_zone` / de-registering an interface must use RCU-safe data structures. A virtio-net device that is hot-unplugged during active RX will have its `IfaceInfo` in the RCU-protected list while a reader holds a guard. The reclamation side — when is it safe to free the `IfaceInfo` and drop the DMA queues — depends on `rcu/`'s domain-aware defer_drop, which is Stage 2+. This creates a Stage 3 ordering dependency: `net/` needs RCU reclamation for interface removal, but the full RCU story lands across Stage 2 and 3.

**`tracing/` per-frame USDT:** §6 notes per-frame USDT as opt-in. Given that flight-recorder `record` is targeted at ≤20 cycles, embedding a USDT at every frame push/pop is feasible. But the tracing spec §4 says "markers never allocate, take a lock held outside their own handler, or panic." The frame hot path must never call into the tracer synchronously, only into the flight-recorder's lock-free write. The distinction needs to be enforced via the `ProbeAction` type, not just documented.

---

## Additional opinionated commentary

The frame-ring contract is the right abstraction — it mirrors AF_XDP's FILL/COMPLETION/RX/TX model but in a capability-typed idiom. The real risk is that "zero kernel interposition" is an ambition that collides with the capability check on every frame. At 100 Gbps, a frame check cannot be a cap table lookup — it must be reduced to a hardware-validated token check that costs at most a few cycles. The spec should acknowledge this now and plan for either: (a) bulk capability validation at queue-bind time (validate once, fast-path thereafter using a CPU-local shadow of the validated token), or (b) a trusted-path designation for queues where the cap was validated at bind time and the hot path is unsynchronized. This is not a novel idea — io_uring does exactly this with its registered file/buffer tables — but NARF needs to name the pattern before Stage 3 or the network stack will be visibly slower than Linux AF_XDP for no architectural reason.
