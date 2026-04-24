# Stage 3 Implementation Order

Derived from the v1.0 spec dependency graph. This is the minimum
sequence in which the critical path lands without back-tracking,
alongside the three side tracks a small team can parallelise behind
isolated git worktrees.

**Stage 3 exit criterion** (from `ROADMAP.md`): A VirtIO device,
running in its own PKS domain, moves a buffer through a Narf-Ring to
another domain using only capability invocations, with no copy and no
Ring-0 trap on the fast path.

## Current status

Composition landed end-to-end, both arches green: x86_64 56/56,
aarch64 47/47 + 1 structurally-sound skip (`smoke_virtio_mmio_probe`
has no attached virtio backend in the current xtask QEMU line).
`smoke_exit_gate_buffer_handoff` + `smoke_exit_gate_revoked_cap_rejected`
compose the criterion. Real PKS/MTE enforcement on the buffer pages,
real virtio device I/O, real IOMMU programming, and a user-mode
consumer via `abi/` submissions are Stage 4 items — see per-subsystem
READMEs for the full deferral list.

Wave legend below: ✓ = landed, → = Stage 4.

## Critical path — wave ordering

The rationale is: rings need caps to name their endpoints; the ABI
needs both rings and the cap table to exist; drivers are the first
composed consumer of all three.

- ✓ **Wave 0 — `capabilities/` type-level skeleton.**
  `CapSlot` / `Cap<T, R>` / `Rights` sealed trait / `CapError` /
  `CapKind` enum. No runtime cap table yet; `invoke` returns
  `unimplemented!()`. Unblocks the `ipc/` endpoint-cap signatures
  (`Cap<Ring<T>, Send>`, `Cap<Ring<T>, Recv>`) so Wave 1 can land
  with the real types rather than placeholders.
- ✓ **Wave 1 — `ipc/` Narf-Ring SPSC.** Producer/consumer with
  cache-line-partitioned head/tail/payload, explicit release/acquire
  pair per index transition, 2-bit wrap generation, aarch64 pointer
  retag hook (stub until Wave 3 cross-domain tests exercise it),
  `Result<T, RecvError>` on `recv`. SPSC first — MPSC is an open
  question per `ipc/` §8, punt to Stage 4.
- ✓ **Wave 2 — per-task cap table + `abi/` rings.** `capabilities/`
  gains the per-task `CapSlot` array in its own domain
  (`DomainId::CAPS`), `invoke` is real, epoch revocation bumps the
  object-side `u32` per `capabilities/` §3. `abi/` defines
  `Submission` / `Completion` / `OpCode`, the slow-path `bootstrap`
  syscall, and the cancellation protocol in `abi/` §3.1. Rings from
  Wave 1 become the transport.
- ✓ **Wave 3 — driver framework + first virtio driver.** `drivers/`
  framework implements the `Driver` trait, manifest parsing against
  `CapKind`, domain assignment, `DriverEnv`, lifecycle
  (start/quiesce/teardown). `drivers/virtio/` adopts it, claims a
  `Cap<BusDevice, _>` from `bus/` (which the side track delivers),
  and moves one virtio-blk or virtio-net buffer through a
  Narf-Ring end-to-end. That's the exit gate.

## Topo-sorted task list (critical path)

### Wave 0 — `capabilities/` skeleton

1. `CapSlot` — `#[repr(C, align(16))]` with `generation`, `index`,
   `rights`, `type_tag`. No atomics yet (Wave 2 makes it
   CMPXCHG16B-updatable per `capabilities/` §3).
2. `Rights` sealed trait + `Read` / `Write` / `Grant` / `Invoke`
   marker types.
3. `Cap<T, R>` struct with `PhantomData<(T, R)>`.
4. `CapError` enum (`Revoked`, `DomainMismatch`, `TypeMismatch`,
   `RightsTooWeak`).
5. `CapKind` enum — stable `#[repr(u32)]` wire tags for every cap
   type that crosses a manifest or audit boundary.
6. `derive` / `badge` / `revoke` / `invoke` stubs returning
   `unimplemented!()`; compile-time `SubsetOf<R>` check wired.

### Wave 1 — `ipc/` Narf-Ring SPSC

7. Ring header layout: producer head, consumer tail, wrap generation,
   overflow flag — each on its own cache line per `ipc/` §4.
8. `Ring<T: RingMsg>` + slot array; `RingMsg` trait seals the payload
   (`#[repr(C)]` POD + move-only handle).
9. `Producer::send` with release fence on publish; x86_64 TSO-friendly
   release, aarch64 `STLR`.
10. `Consumer::recv` returning `impl Future<Output = Result<T, RecvError>>`;
    acquire fence, aarch64 `LDAR`; waker plumbed into `scheduler/`.
11. Back-pressure: `Err(Full)` + `send_blocking` helper that registers
    a waker; consumer-side overflow flag refuses further `send`.
12. aarch64 pointer-retag hook on the slot write path (stub — real
    retag lands in Wave 3 when cross-domain moves exist).
13. `verification/` kernel tests: SPSC round-trip, full/empty
    transitions, waker correctness, wrap-generation sanity.

### Wave 2 — cap table + ABI rings

14. Per-task `CapSlot` array allocated in `DomainId::CAPS` at task
    spawn; the slot count is config-time-fixed for Stage 3.
15. `invoke` implementation: atomic load of object epoch
    (CMPXCHG16B / LDXP-STXP for the 128-bit slot per `capabilities/`
    §3), compare against slot generation, dispatch to `CapOp`.
16. `revoke` bumps the object epoch — O(1) invalidation of every
    derived / badged cap pointing at it.
17. `abi/`: `Submission` / `Completion` `#[repr(C)]` structs, `OpCode`
    enumeration stub, `NarfStatus` with `Cancelled` /
    `CancelRequested` / `CapRevoked`.
18. Slow-path `bootstrap` entry — `svc`/`syscall` handler that mints
    SQ + CQ ring caps and the read-only config-page cap.
19. Cancellation protocol: dropping a submission `Future` sends
    `OpCode::Cancel` through the ring; resources release only on
    terminal completion per `abi/` §3.1.
20. `verification/` tests: bootstrap round-trip, invoke after revoke
    returns `CapRevoked`, cancellation produces a terminal completion.

### Wave 3 — driver framework + virtio exit gate

21. `drivers/` manifest parser: TOML + `#[driver(...)]` macro,
    `caps_required` resolved against `CapKind` at signature-verify time.
22. `Driver` trait + `DriverEnv` — caps, MMIO maps, IRQ handles.
23. Lifecycle state machine (Loaded → Started → Quiescing →
    Torn-Down); panic containment so a driver fault takes only its
    domain down.
24. `drivers/virtio/` skeleton: claim `Cap<BusDevice, _>` from
    `bus/`, map BARs in its dedicated domain, register doorbell IRQ.
25. virtio-blk (or virtio-net) front half — one request Narf-Ring
    from the driver's domain to a consumer test task in another
    domain; payload is zero-copy, driver never touches the consumer's
    memory directly.
26. `verification/` exit-gate test: submit a buffer through the
    ring, verify the consumer sees it, verify no Ring-0 entry on
    the fast path (use `tracing/` probe counters from the `tracing/`
    side track if landed; otherwise a plain atomic counter on the
    trap-entry stub suffices).

## Parallel side tracks

Each runs in its own git worktree. None depend on any Wave above;
they integrate at merge time. Scope discipline: no edits to
`capabilities/`, `ipc/`, `abi/`, `scheduler/`, `frame/`, `arch/`, or
`memory/` — stub and flag instead.

### Side track A — `rcu/` QSBR + Epoch variants

- **Scope:** Promote the Stage-1 stub into real QSBR and Epoch
  reclamation: per-CPU reader counter, global epoch, `defer_drop`
  queue, `sync()` that actually waits a grace period, executor
  `report_quiescent` honoured. Spec: `rcu/specification/spec.md`
  §3.3 + §3.4 + §3.7.
- **Dependencies:** Stage-2 scheduler (already landed), Stage-2
  `memory/` per-CPU storage (already landed). No Wave-N dependency.
- **Exit-gate check:** `cargo xtask test --arch=x86_64` and
  `--arch=aarch64` both green; `smoke_rcu_qsbr_reclaims` and
  `smoke_rcu_epoch_defer_drop` pass.
- **Files touched:** `rcu/src/**`, `Cargo.toml` workspace member line,
  `verification/src/lib.rs` (new `kernel_test!` entries).
- **Out of scope:** Hazard-pointer variant (fine to stub), sleepable
  variant (cap-gated — needs cap table from Wave 2; do not block on
  it). Per-domain reclamation-worker Future depends on `scheduler/`
  domain changes: stub.

### Side track B — `bus/` boot-time enumeration

- **Scope:** PCIe ECAM walk on x86_64 (MCFG from ACPI), devicetree
  `/soc` + `/pci` walk on aarch64. `DeviceInfo` / `DeviceLocation` /
  BAR sizing / capability list parse. RCU-backed device registry
  (uses stub `rcu/` API until side track A lands — either is fine).
  Spec: `bus/specification/spec.md` §3.1–§3.2 + §5.
- **Dependencies:** `memory/` MMIO map (landed), `boot/` ACPI RSDP
  + DT pointer in `BootInfo` (landed). Claim API depends on Wave-2
  `capabilities/` — stub `claim` to return a placeholder.
- **Exit-gate check:** both arches build; `smoke_bus_enumerates_virtio`
  passes under QEMU (QEMU exposes virtio-blk + virtio-net on both
  arches by default).
- **Files touched:** `bus/src/**`, `Cargo.toml` workspace member line,
  `verification/src/lib.rs`.
- **Out of scope:** MSI-X allocation (needs `interrupts/` Stage-3
  work), hot-plug, IOMMU-group coordination, ACS chain check. Leave
  `acs_clean: bool` hardcoded to `false` with a TODO pointing at
  `bus/` §5 x86_64.

### Side track C — `tracing/` USDT + `.note.narf.probes`

- **Scope:** `usdt!(provider, name, args…)` marker macro that emits a
  single `nop` at the call site plus an ELF note entry in
  `.note.narf.probes` describing provider/name/argument register map.
  Codegen for the note section (linker script add, build.rs glue in
  the macro crate). Spec: `tracing/specification/spec.md` §3.1 + §5.
- **Dependencies:** `arch/` patch primitive (landed in Stage 1 as a
  stub — OK to keep the stub; arming is a Stage-3 follow-up that
  lives in the main track or a later wave).
- **Exit-gate check:** both arches build with a `usdt!` site in a
  test crate; `readelf -n` shows the `.note.narf.probes` entry;
  `smoke_usdt_note_present` parses the note at runtime and matches
  the site metadata.
- **Files touched:** `tracing/src/**`, `tracing/macros/**` (new
  proc-macro crate if needed), linker scripts under
  `build/linker/*.ld`, `Cargo.toml` workspace members.
- **Out of scope:** Dynamic probes (§3.2), `FnTime` (§3.2.1),
  flight-recorder rings (§3.3 — Stage-1 has the stub), tracer task
  (§3.4). Do not modify `arch/` patch code; arming is not a Stage-3
  side-track concern.

## Stage 3 exit gate

1. The Wave-3 virtio test passes on both x86_64 and aarch64.
2. One buffer moves driver-domain → consumer-domain purely through
   `Cap::invoke` — the driver holds no pointer into the consumer's
   memory.
3. The fast-path hot loop (submission → completion) records zero
   `Ring-0` traps (syscall vector counter unchanged across the
   exercise).
4. All three side-track exit checks green.
5. `cargo xtask test --arch=x86_64` and `cargo xtask test
   --arch=aarch64` both produce `Pass`.

## What deliberately does not land in Stage 3

- Sleepable RCU (cap-gated) — spec-complete, cap infrastructure
  arrives in Wave 2 but the variant itself is a Stage-3 follow-up or
  a later side track.
- Hazard pointers — Stage-3 scope per ROADMAP, but the virtio exit
  gate does not require them; sequence after the gate if time allows.
- `io/` IOMMU programming past the minimum needed for virtio (QEMU's
  default virtio transport works without an IOMMU).
- `filesystem/`, `block/`, `net/` — Stage-3 subsystems in the matrix
  but each is its own multi-wave project beyond the exit criterion.
  Track separately.
- MSI-X allocation + PCIe Native Hot Plug in `bus/` — Stage-3 per
  ROADMAP, lands after the virtio gate.

## Critical-path analysis

```
  capabilities (types) ── ipc (ring) ── cap-table+abi ── drivers ── virtio gate
                                              │
                                              └── (bus side track supplies claim)
```

Wave 2 is the highest-risk chunk: the 128-bit atomic `CapSlot` update
(CMPXCHG16B / LDXP-STXP) has to land correctly first time or every
`invoke` later is suspect. Land Wave 2's atomic path with a dedicated
test before Wave 3 starts.

The side tracks are fully parallel: none of them touch the critical
path's files. The only shared surface is `Cargo.toml` — see
`STAGE3_INTEGRATION.md`.
