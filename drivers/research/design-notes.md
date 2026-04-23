# drivers (framework) — Design Notes

> Created: 2026-04-22

---

## Load-bearing decisions

**One PKS/MTE domain per driver is the assumed model.** The spec says `memory/` allocates a "dedicated domain" per driver, but never states what happens when 13 non-TCB domains are exhausted. With 16 PKS keys total, TCB using 1, KEYS using 1, CRYPTO possibly 1, tracer using 1, that leaves ~12 for actual drivers. A real system has more than 12 drivers. The spec hand-waves this with "shared vs. per-driver domains" in §8 as an open question — but it is not just a question, it is a design constraint that determines whether the isolation claim in §4 ("driver storage is in its own domain") is true at all. This must be resolved before Stage 2.

**Manifest is both a compile-time macro and a runtime-parsed TOML.** The dual format creates two sources of truth: the `#[driver(...)]` proc-macro and the `.toml` file. If they diverge, one will silently win. The spec does not say which takes precedence or whether they are required to be identical. In Fuchsia DFv2, the manifest is the canonical form; code is derived from it. NARF should pick one as authoritative. The compile-time macro approach is more LTO-friendly; the TOML approach is more hot-reload-friendly. This is actually the answer to the open question about the ELF-microprogram model.

**Driver panics terminate the domain, not the kernel.** This is the central fault-containment claim. But the spec does not say what happens to in-flight Narf-Rings whose peer is the dead driver. Ownership semantics of `ipc/` mean the ring's head buffer is either owned by the dead driver or by a consumer. If the dead driver owned a batch of Narf-Ring slots (the "received ownership" side), those slots are now unreachable. `ipc/` and `capabilities/` must define a teardown protocol — but neither spec mentions it. This is the most dangerous unaddressed invariant in the framework spec.

**Capability bootstrap at load time is the entire trust model.** `DriverEnv` carries the caps the kernel granted based on the manifest. If the manifest verification (via `crypto/`) passes a forgery — because the trust root is compromised — the driver gets whatever caps it claims. There is no runtime re-attestation. Once a driver is running, its cap set is frozen at load time. This is correct for stability but means a driver cannot legitimately acquire new caps to respond to hot-plug (a new NVMe namespace appears mid-run). This is a fundamental tension the spec leaves to "driver hot-reload: required or defer?"

---

## Divergences from precedent

**Framework lives in-kernel, not a separate process.** Fuchsia's driver manager is a user-space component. seL4 drivers are user-space processes. NARF's driver framework is in-kernel — drivers run in domains but within the kernel address space. This is the framekernel choice. The performance case is clear (no address-space context switches). The correctness case depends entirely on PKS/MTE hardware enforcement being bug-free. The Fuchsia research summary warns: "uncontrolled packing creates blast-radius risks." In NARF's model, a PKS side-channel between domains is a kernel-level vulnerability, not a user-process compromise.

**`start()` returns `impl Future`, not a blocking call.** This is correct for the async executor model, but the Fuchsia DFv2 summary specifically flags "blocking in driver initialization" as a pitfall. In NARF, a driver that awaits something in `start()` that never resolves (e.g., a missing bus device) will hold an executor slot indefinitely. The seL4 model forces capability grant before start — NARF should do the same with a hard timeout on `start()` Future completion. The spec does not mention startup timeouts at all.

**Feature negotiation is driver-specific, not framework-level.** Unlike Fuchsia's typed bind rules (metadata-driven, validated at index time), NARF's manifest caps are free-form strings (`"BusDevice"`, `"BlockDeviceBackend"`). This is dangerous: the framework has no way to enforce that a driver claiming `"BusDevice"` is actually the right kind of bus device. The DFv2 summary warns: "Resist the temptation to use string patterns or dynamic evaluation." NARF's manifest cap names should be a closed enum at the framework level, not open strings.

---

## Proposed spec changes

- §2 Assumptions: Add explicit domain-budget assumption. State: "The system has at least `N_drivers + 4` free PKS/MTE domains where N_drivers is the number of concurrently loaded drivers with dedicated domains." This forces `memory/` to document the domain budget and prevents silent over-commitment. — *makes the isolation claim falsifiable.*

- §3 Public interface (manifest): Change `caps_required` from free-form strings to a typed `CapKind` enum defined in `capabilities/`. A manifest declaring an unknown cap name must fail signature verification before load, not produce a runtime error. — *prevents cap-name typos from silently granting no access.*

- §3 Public interface (Driver trait): Add `fn startup_timeout() -> Duration` to the `Driver` trait. The executor kills the `start()` Future if it does not complete within this budget and marks the driver as failed. Default: 1 second. — *prevents executor starvation from misbehaving init paths.*

- §4 Invariants: Add: "When a driver domain is terminated (panic or explicit teardown), all Narf-Ring slots owned by that driver are reclaimed to the allocating domain with a `RingError::PeerDead` status. No slot can be orphaned." Requires `ipc/` to define the reclamation API, but the invariant belongs here because the framework owns teardown. — *closes the dead-driver ring-leak hazard.*

- §4 Invariants: Add: "A driver may not hold more than one PKS/MTE domain concurrently." Without this, a poorly-written driver framework call could escape isolation by acquiring a second domain key via a capability. — *tightens domain isolation invariant.*

- §8 Open questions: Resolve the ELF-microprogram / hot-reload question as a binary. Either: (A) drivers are static PIE ELFs loaded at boot, no hot-reload in Stage 1–4; or (B) hot-reload is in scope and the framework must support re-entry with cap revocation. Deciding this changes the manifest format, the load-time ABI, and whether `capabilities/` needs a "driver ID" scoping for derived caps. Deferring past Stage 3 means two incompatible designs will collide. — *avoids a Stage 3 flag-day.*

---

## Open invariants / cross-subsystem hazards

**`drivers/` ↔ `memory/` domain starvation.** As noted above, no spec defines how many domains are available and who wins when supply runs out. This is a `memory/ §...` gap but the symptom surfaces first in `drivers/` when the Nth driver fails to start with an opaque "no domain available" error. Needs a domain allocation table in `memory/` with `drivers/` as a consumer.

**`drivers/` ↔ `ipc/` teardown protocol.** Dead driver leaves ring slots in an unknown ownership state. `ipc/` §... (ownership transfer semantics) does not define what happens when a ring endpoint dies. Either `ipc/` defines `notify_peer_dead` or `capabilities/` revocation cascade covers it — but neither spec currently says. The `rcu/` deferred-drop mechanism is likely the right tool: when the driver domain is torn down, all its cap references are dropped under an RCU grace period, which naturally signals ring peers.

**`drivers/` ↔ `interrupts/` UIPI lifecycle.** UIPI vectors are bound to the driver's domain. If the driver domain is torn down and the UIPI vector is not unregistered, a subsequent interrupt to that vector has no handler. The spec says `interrupts/` "can bind an IRQ" but nothing in `drivers/` says who unbinds it during teardown. The teardown path (part of `quiesce()`) must include a UIPI un-registration step, but the spec's `quiesce()` signature carries no `env: DriverEnv` — the driver's handles are lost by the time teardown completes if quiesce() has already returned.

---

## Additional opinionated commentary

The manifest `TOML + proc-macro` hybrid is a mistake. Pick one. If NARF is LTO'd as a single binary with drivers compiled in, the proc-macro is the right canonical form, and the TOML is generated from it for tooling. If NARF eventually supports out-of-tree drivers loaded as PIE ELFs (the hot-reload path), the TOML is canonical and the proc-macro is a convenience wrapper. Trying to maintain both leads to the Linux Kconfig + Kbuild divergence problem. Given the ELF-microprogram direction in §8, the TOML should be canonical. The proc-macro should just be sugar that generates a well-typed manifest struct validated at compile time against the same schema.
