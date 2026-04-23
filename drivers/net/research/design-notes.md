# drivers/net — Design Notes

> Created: 2026-04-22

---

## Load-bearing decisions

**Raw-frame Narf-Ring is the entire kernel-to-consumer contract.** The spec owns the RX/TX path and terminates at a frame ring. The IP stack lives in userspace. This is the correct split for a framekernel. But it means the latency of the critical path is: NIC DMA → driver domain → Narf-Ring ownership transfer → userspace stack daemon. That is two domain crossings (NIC domain → `net/` contract → userspace) before a packet is even parsed. For a 10 GbE NIC at minimum frame sizes (~84-byte frames), that is ~1.5 million frames/sec. At 2 domain crossings per frame, the overhead budget is ~333 ns per crossing before NARF is already DMA-bound. This is achievable with UIPI and zero-copy, but *only if* the ownership transfer through Narf-Ring is truly zero-copy and the UIPI path avoids the scheduler. The spec asserts this but does not verify it.

**Descriptor ring validation on every wake.** §4 says "Descriptor rings validate every writable field before trusting." For the E1000 (82574L), the RX descriptor has a 16-byte structure: buffer address + length + flags + status. Validating 64 descriptors per wake = 1024 bytes read, plus branches. At 1M wake/sec this is non-trivial. Linux's e1000 driver validates lazily (trusts hardware-written status). NARF's adversarial model is different — a misbehaving NIC in its domain *should* be caught — but the cost must be measured. The spec should distinguish: validation against memory safety (always mandatory) vs. validation against hardware misbehaviour (may be configurable per trust level).

**UIPI for IRQs into the driver's domain.** This is stated as the preferred interrupt delivery mechanism. But UIPI on x86_64 (SENDUIPI/UIRET, Intel Sapphire Rapids+) is available only on recent silicon. On QEMU before 2023, UIPI is not simulated. The spec says "where available" but does not define the non-UIPI fallback path for the driver interrupt path. If the fallback is a normal kernel trap into the driver domain via `interrupts/`, that is a significant latency difference and the driver's async model must handle both. The spec needs to make the fallback path explicit.

**Single real-HW target TBD.** The spec lists E1000, IGC, and MLX5 as candidates. These have dramatically different DMA models: E1000 uses legacy descriptor rings with software polling; IGC uses advanced descriptors with RSS; MLX5 uses Work Queues (WQs) with Completion Queues (CQs) and an entirely different programming model. Choosing the target determines the entire driver architecture. Delaying this past Stage 3 design means the Stage 4 implementation will be designed for the wrong interface.

---

## Divergences from precedent

**No kernel-internal TCP/IP stack, ever.** Linux has a full in-kernel network stack. Redox has in-kernel smoltcp. NARF explicitly excludes L3/L4. This is the right call for a framekernel. The risk is that it makes NARF dependent on a userspace stack daemon being always-available. For embedded or safety-critical deployments, an optional in-kernel loopback path (below the frame ring, in `net/`) might be needed — but the spec says `net/` owns "loopback implementation," suggesting a loopback that still goes through the ring. That is slower than a bypass and probably not suitable for high-frequency kernel-to-kernel IPC. The `ipc/` Narf-Ring *is* the kernel-to-kernel path; the network stack is for external communication. This should be stated explicitly to prevent future pressure to add smoltcp in-kernel.

**Ownership transfer per frame (not per batch).** The Narf-Ring model moves one buffer at a time via ownership transfer. DPDK and Linux XDP both batch: a single "transfer" moves 32–64 descriptors. At high packet rates, per-frame ownership transfer has cache footprint that scales linearly with packet rate. The 82574L datasheet confirms that the NIC processes descriptors in bursts. NARF's Narf-Ring should support batch ownership transfer — submit N frames in one ring operation — or the driver will be bottlenecked on ring protocol overhead before NIC DMA bandwidth is saturated.

**No RSS/multi-queue policy in spec.** §8 lists RSS/multi-queue as an open question. But the 82574L has 4 RX queues, and the E1000 family's entire performance scaling depends on RSS directing flows to per-CPU queues. Without multi-queue, a NARF NIC driver on an SMP host will funnel all traffic through one CPU, which DPDK benchmarks show saturates a single core at ~3 Mpps — well below the NIC's capability. The spec should commit to multi-queue as a Stage 4 requirement, not an open question.

---

## Proposed spec changes

- §2 Assumptions: Add: "If UIPI is unavailable, `interrupts/` delivers RX/TX IRQs to the driver domain via a kernel-mediated notification with latency ≤ X µs (TBD under `verification/` benchmarks). The driver's async model must be identical in both paths." — *makes UIPI optional without making the fallback invisible.*

- §3 Public interface: Extend `submit_tx(buf)` to `submit_tx_batch(bufs: &[BufRef]) -> Future<BatchResult>` and `recv_rx_batch(max: usize) -> Future<Vec<Frame>>`. Single-frame interfaces are a performance anti-pattern for any NIC above 1 GbE. The interface should be batch-first, with single-frame as a degenerate case. — *prevents a future forced redesign at Stage 4.*

- §4 Invariants: Split descriptor validation into two levels: (A) memory-safety validation — buffer addresses are within the driver's DMA cap, mandatory, no performance escape hatch; (B) protocol-correctness validation — descriptor flags are sane, configurable via trust level. A NIC in a trusted QEMU environment gets level A only; a NIC on a hostile PCIe bus gets A+B. — *makes security vs. performance trade-off explicit and policy-driven.*

- §7 Stage assignment: Commit to E1000 (82574L) as the Stage 4 real-HW target. It is the simplest PCIe NIC, QEMU emulates it, and it has complete open documentation. Other targets (IGC, MLX5) are post-1.0. — *eliminates a late-stage architecture decision that blocks Stage 4 design.*

- §8 Open questions: Close the "poll-mode vs. interrupt-driven default" question: interrupt-driven with adaptive coalescing is the default; poll-mode is an opt-in via a mount-time-equivalent driver config flag. Interrupt-per-packet at >100 kpps wastes more CPU than a coalescing budget; the 82574L ITR register supports this. — *prevents a flag-day when the driver proves too slow under load.*

---

## Open invariants / cross-subsystem hazards

**`drivers/net/` ↔ `ipc/` batch ownership semantics.** The Narf-Ring is designed around single-item ownership transfer. If the net driver needs to batch 32 frames per "push," the ring protocol must either support multi-item atomic transfers or the driver sends 32 individual transfers. The latter has 32× the ring coordination overhead. `ipc/`'s spec does not address batch semantics. This needs resolution before Stage 3, when virtio-net (which sends/receives in 16–256 frame batches) is implemented.

**`drivers/net/` ↔ `interrupts/` interrupt storm handling.** The seL4 device driver summary specifically flags interrupt storms as a pitfall: "A misbehaving device may fire interrupts faster than the driver can service them." The 82574L can fire ITR interrupts at up to 100 kHz if ITR is set to minimum. NARF's async executor must either implement interrupt rate limiting at the `interrupts/` layer before delivery to the driver, or the driver must disable its own IRQ line (requires write access to the IRQ mask register — which is in MMIO, which the driver has). The capability for "disable my own IRQ" should be explicit in `DriverEnv`, not assumed.

**`drivers/net/` ↔ `net/` frame-ring contract.** The `net/` subsystem defines the frame-ring contract. `drivers/net/` is supposed to implement it. But the spec says `drivers/net/` "implements" the contract while `net/` "defines" it. If `net/`'s contract changes (e.g., adds a VLAN tag field), all concrete net drivers must change simultaneously. This is a tight coupling. The contract version must be part of the cap negotiation at driver start, not assumed identical across subsystem versions.

---

## Additional opinionated commentary

The 82574L is old enough (circa 2009) that it makes a good development target — but it has no support for TSO on modern kernel paths (Linux treats it as a legacy device). Targeting it means NARF will have a GbE ceiling on network performance until Stage 4+ adds a modern NIC. That is fine for Stage 4, but the driver architecture chosen for E1000 must not be E1000-specific. The DPDK PMD abstraction is the right mental model: a driver-agnostic "poll mode driver" interface above which the frame ring sits, with the E1000 as the first implementation. If NARF designs the net driver as "the E1000 driver" rather than "a net driver backed by E1000," porting to IGC will require a rewrite.
