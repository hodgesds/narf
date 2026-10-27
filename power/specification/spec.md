# power — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined
> CPU/device PM + governors; v1.0 locks the tickless idle
> policy, the energy model coupling with `scheduler/`, the
> AML-evaluation posture (no AML), the modern-standby strategy,
> and SCMI integration.

## 1. Purpose & scope

**Owns:**

- **CPU idle** — selection of C-state / WFI variant on idle, exit
  latency accounting, idle-time bookkeeping.
- **Frequency scaling (DVFS)** — P-state / operating-performance-
  point (OPP) selection, governor (latency vs. throughput vs.
  energy-aware), thermal-capped ceiling.
- **Suspend / resume** — S3 mem-suspend (x86_64), platform-equivalent
  on aarch64. Freeze user tasks, quiesce drivers, save state, enter
  low-power, restore.
- **Thermal management** — thermal zone monitoring, throttle
  triggers, emergency shutdown.
- **Runtime power management** — per-device PM states (D0/D1/D2/D3
  on PCIe; driver-specific elsewhere) and quiesce/wake lifecycle.
- **Governor framework** — pluggable policy objects (`governor`
  trait) that decide among C-states / P-states.

**Does NOT own:**

- Per-device power logic — each driver implements its quiesce/wake
  methods. `power/` orchestrates; drivers execute.
- CPU hot-plug mechanics — `scheduler/` §3.5. `power/` uses it.
- Time after suspend (clock fast-forward) — `time/` handles re-sync.

## 2. Assumptions

- `scheduler/` can quiesce CPUs and take them offline per §3.5.
- `time/` can pause / re-synchronise clocks around suspend/resume.
- `arch/` exposes C-state / P-state / thermal primitives.
- `drivers/` framework can iterate devices and call
  `Driver::quiesce` / `resume`.
- `tracing/` can log power transitions (with sufficient budget).

## 3. Public interface

### 3.1 Idle

```rust
pub fn idle_enter() -> !;                   // called by scheduler at empty runq
pub fn register_cstate(info: CstateInfo);   // arch backend populates at boot

pub trait IdleGovernor: Send + Sync + 'static {
    fn name(&self) -> &'static str;
    fn select_idle_state(&self, latency_budget_us: u64,
                         predicted_idle_us: u64) -> CStateIdx;
}
pub fn install_idle_governor<G: IdleGovernor>(
    cap: &Cap<IdleGov, Grant>, g: G) -> Result<(), PowerError>;
pub fn install_idle_governor_struct_ops<M: CapType>(
    cap: &Cap<M, Grant>, generation: u64,
    g: Arc<dyn IdleGovernor>) -> Result<(), PowerError>;
pub fn detach_idle_governor_struct_ops(generation: u64) -> bool;

pub struct CstateInfo {
    pub depth:         u8,                  // 0 = C0 (running); higher = deeper
    pub exit_latency:  Duration,            // worst-case
    pub target_residency: Duration,
    pub power_uw:      u32,                 // typical
    pub enter:         fn(),                // arch-specific instruction sequence
}
```

Default governor: **predictive**, picking the deepest C-state whose
`target_residency` is less than the predicted idle time (EWMA over
recent idle durations + upcoming hrtimer deadline from `time/`).

**`time/` `next_deadline()` contract.** `idle_enter` queries
`time::next_deadline()` to bound the C-state choice. That call is
required to be O(1) with bounded worst-case latency strictly less
than the shortest C-state's `enter` cost; the spec is enforced in
`time/` §3.2 via a per-CPU "next deadline" cache updated on every
`timer_oneshot` / `timer_cancel`. A regression in that contract
flips us into spending more time picking a C-state than we save by
entering one.

The live idle-governor slot is Arc-backed. Selection clones the active Arc
under the slot lock and invokes it after releasing that lock; install and
detach drop displaced implementations after releasing it. Struct-ops installs
carry a generation, and detach succeeds only for the currently live generation.
After any native or BPF policy returns, `select_idle_state` rechecks the live
state's exit latency and target residency against the supplied budgets and
falls back to a valid C0. Policy output is therefore a recommendation rather
than authority to enter a stale or unsafe state.

### 3.2 DVFS

```rust
pub struct Opp { pub freq_khz: u32, pub voltage_uv: u32 }

pub fn set_cpu_governor(g: impl Governor);
pub fn current_opp(cpu: CpuId) -> Opp;
pub fn request_min_freq(cpu: CpuId, khz: u32, cap: &Cap<FreqHint, Set>);

pub enum Policy { Performance, Balanced, Powersave, Userspace }
pub fn set_policy_current(policy: Policy) -> Result<(), CpuFreqError>;
pub fn set_epp_current(epp: u8) -> Result<(), CpuFreqError>;
pub fn current_perf(cpu: CpuId) -> Option<PerfState>;

pub trait Governor {
    fn tick(&mut self, load: LoadSnapshot) -> Opp;
    fn name(&self) -> &'static str;
}
```

Built-in governors: `Performance`, `Powersave`, `EnergyAware`
(scheduler-informed). Pluggability is opt-in via `Cap<Governor, Install>`.

On x86_64, `Balanced` is the default schedutil-style policy over Intel
HWP or AMD CPPC. One hard-pinned worker per online CPU samples that CPU's
scheduler run queue every 100 ms and writes only that CPU's request MSR.
The syscall bridge rejects remote-CPU policy/EPP writes until an IPI
rendezvous path can execute the operation on the named CPU.
`Performance` requests highest with a nominal floor and EPP 0;
`Powersave` caps max at nominal with EPP 255; `Userspace` leaves desired performance autonomous
while accepting explicit range/EPP control. CPPC performance values are
unitless 0..=255 hints, not frequencies.

### 3.3 Suspend / resume

```rust
pub async fn suspend(target: SuspendTarget, cap: &Cap<Power, Suspend>) -> SuspendOutcome;

pub trait AsyncSystemPm: Send + Sync {
    fn prepare_suspend(&self) -> SystemPmFuture<'_>;
    fn resume_from_suspend(&self) -> SystemPmFuture<'_>;
}
pub fn register_async_system_pm(name: &str, ops: Arc<dyn AsyncSystemPm>);
pub async fn suspend_async(cap: &Cap<Power, Invoke>) -> Result<(), SuspendError>;

pub enum SuspendTarget { Freeze, StandbyS1, SuspendToRamS3, SuspendToDiskS4 }
pub enum SuspendOutcome { WokeUp(Cause), Aborted(Reason) }
```

Flow:

1. Freeze user tasks (scheduler refuses to pick them).
2. Call `quiesce` on every driver in reverse-start order.
3. Save remaining CPU state and enter low-power state (arch-specific).
4. On wake: restore arch state, resume drivers, unfreeze tasks,
   hand `time/` the suspend duration so it can jump forward the
   wall clock without violating monotonic.

`system_pm::AsyncSystemPm` is the interrupt-live bracket around the existing
synchronous `device_pm::DevicePmOps` fan-out. Registration is parent → child;
`prepare_suspend` runs child → parent, and the matching resume runs parent →
child after the synchronous fan-out has restored PCI/platform delivery. The
registry snapshots its entries and releases its lock before every await. A
failed prepare must leave its own device usable; the coordinator resumes every
earlier successful hook before it returns `SuspendError::Aborted`.

`suspend::suspend_async(&Cap<Power, Invoke>)` is the required entry point for
drivers whose suspend protocol waits on firmware interrupts. `suspend` remains
the no-await compatibility path for ordinary `DevicePmOps` implementations.
Both paths abort with `SuspendError::Aborted` when a device callback fails,
including `Busy` from outstanding work, run the applicable resume callbacks to
undo partial quiescing, and return the phase to `Idle` without blanking the
framebuffer or entering platform sleep. `arm_s3_resume` uses the synchronous
compatibility path and does not suspend devices twice.

Suspend-to-idle (the `Freeze` target above) is implemented in `s2idle`:

```rust
pub fn suspend_to_idle(cap: &Cap<Power, Invoke>) -> Result<(), SuspendError>;
pub async fn suspend_to_idle_async(cap: &Cap<Power, Invoke>) -> Result<(), SuspendError>;
pub fn s2idle_supported() -> bool;
pub fn note_wake_event(source: WakeSource);
pub fn enable_production_s2idle(cap: &Cap<Power, Invoke>) -> Result<bool, SuspendError>;
```

s2idle shares the S3 transition claim, phase observable, `device_pm` /
`system_pm` fan-outs, framebuffer hooks, and production-gating posture (test
arm, cap-gated opt-in, `S2IDLE_VALIDATED` boot token). It differs where the
semantics differ: no `\_S3_` / FADT requirement (`s2idle_supported()` needs
an arch park primitive plus a wake source deliverable under the park mask),
no CPU context save or resume trampoline (the
CPU never loses power — execution stays in the caller's frame), no TSC
snapshot, no `\_PTS` / FACS / PM1 write. The platform step masks every IRQ
vector except the wake allowlist (`wake_irq_allowlist()`: the vector the
platform installed the ACPI SCI handler on, recorded in `narf_acpi` by the
install path — not a FADT-derived value) and
parks via `narf_arch::idle_halt_then_disable` until a wake source latches an
event with `note_wake_event`. An unarmed request walks the phases and returns
`NotImplemented`, exactly like unarmed S3.

Platform scope: the s2idle park is x86_64-only today. No aarch64 wake source
exists yet — the allowlist is empty there, so the park snapshot would mask
every SPI (INTID 32..=255) while the wake latch's only setters are IRQ
handlers, and a production park could never observe a wake event.
`s2idle_supported()` therefore returns `false` on aarch64 until an aarch64
wake source (allowlist entry plus a latching handler) lands (#868); the
`/sys/power/state` surface below inherits the gate, so `freeze` is neither
listed nor accepted there. The park machinery itself is arch-neutral and
stays exercised on aarch64 through the bounded test entry only.

Userspace requests a sleep state through `/sys/power/state`
(`sysfs_bridge::populate_power_state`), the kernel's only userspace suspend
trigger:

```rust
pub enum SleepState { Freeze, Mem }            // sleep_request
pub fn request_sleep(state: SleepState) -> Result<(), SleepRequestError>;
pub fn set_sleep_request_hook(hook: SleepRequestHook);
```

`show` lists exactly the supported states (`freeze` iff `s2idle_supported()`,
`mem` iff `s3_supported()`); `store` takes the first whitespace-delimited
token and returns `EINVAL` for an unknown or unsupported state, `ENODEV` when
no request consumer is installed, and `EPERM` when the consumer refuses. The
attr is root-owned 0644 like every writable sysfs attr — that mode/ownership
pair is the write-access decision, the analogue of the reboot handler's
CAP_SYS_BOOT gate. The store only *queues* the request with the policy path
(the composition-installed hook forwards to the power service, whose executor
owns the `Cap<Power, Invoke>` and executes the transition from task context);
the write therefore returns once the request is queued rather than blocking
until resume as Linux's does — a deliberate divergence required by the
capability model, since the writer holds no Power cap.

As built: the hook is installed by the platform power-service
composition (`drivers/platform`, Stage::Late, alongside the action
executor), and the wake latch's production callers are the
platform EC SCI funnel (`PlatformEvent` → the matching
`WakeSource`, latched before the event fans out to subscribers),
the button drivers (power / sleep press), and the lid driver
(open only — a close requests suspend through the service, it is
not a wake source). With no composition installed the store keeps
its fail-closed shape: a supported state's write is refused
`ENODEV`, never silently dropped.

#### Suspend image and key custody (suspend service, S4)

The S4 image machinery of the power-suspend security design
(§5's "S4 via `hibernate` image" made concrete) lives in
`suspend_service`. The service is the only component that holds
unwrapped key material, under the `VkBytes` custody discipline of
`block/` (design §1.4): secrets live in `Secret32` — minted only
in `DomainId::KEYS` (or `FRAME`, the same forward-compatible gate
`VkBytes` documents), yielded only to a closure, zeroized on drop,
never `Clone`.

```rust
// suspend_service: custody anchors (design §3.2). Real anchors are
// separate lanes — FIDO token, TPM sealing, Argon2id passphrase;
// this surface is all the service ever knows about them.
pub trait KeyCustodyAnchor: Send + Sync {
    fn kind(&self) -> AnchorKind;   // Token | Tpm | Tee | Dice | Passphrase | Test
    fn wrap(&self, ctx: &WrapCtx, secret: &Secret32)
        -> Result<WrappedSlot, AnchorError>;
    fn unwrap(&self, ctx: &UnwrapCtx, slot: &WrappedSlot)
        -> Result<Secret32, AnchorError>;
    fn epoch(&self) -> Option<u64>;                       // default None
    fn advance_epoch(&self) -> Result<Option<u64>, AnchorError>;
}

pub struct SuspendService<E: KeyEntropy> { /* … */ }
impl SuspendService<HwKeyEntropy> { pub fn production() -> Self; }
impl<E: KeyEntropy> SuspendService<E> {
    pub fn create_epoch(&mut self) -> Result<u64, ServiceError>;
    pub fn enroll(&mut self, anchor: &dyn KeyCustodyAnchor)
        -> Result<SlotRecord, ServiceError>;
    pub fn revoke_slot(&mut self, epoch: u64, kind: AnchorKind,
                       params: &[u8]) -> Result<(), ServiceError>;
    pub fn rotate_epoch(&mut self, anchors: &[&dyn KeyCustodyAnchor])
        -> Result<u64, ServiceError>;
    pub fn retire_epoch(&mut self, epoch: u64) -> Result<(), ServiceError>;
    pub fn seal_image(&mut self, store: &mut dyn ImageStore,
                      policy: RecordedPolicy, image: &[u8])
        -> Result<[u8; 16], ServiceError>;
    pub fn open_with_anchor(&self, store: &dyn ImageStore,
                            anchor: &dyn KeyCustodyAnchor)
        -> Result<OpenedImage, ServiceError>;
    pub fn open_off(&self, store: &dyn ImageStore)
        -> Result<OpenedImage, ServiceError>;
    pub fn slot_area(&self) -> SlotArea;
}

// Reader trust order (design §6.2): no type before TrustedImage
// can yield plaintext.
pub fn parse_claims(store: &dyn ImageStore) -> Result<ImageClaims, ServiceError>;
pub fn open_with_sms(store: &dyn ImageStore, claims: ImageClaims,
                     sms: &Secret32) -> Result<OpenedImage, ServiceError>;
impl OpenedImage {
    pub fn verify_all(self, store: &dyn ImageStore)
        -> Result<TrustedImage, ServiceError>;
}
impl TrustedImage {
    pub fn read_chunk(&self, store: &dyn ImageStore, index: u64,
                      out: &mut Vec<u8>) -> Result<(), ServiceError>;
}

pub struct RecordedPolicy { pub level: PolicyLevel, pub policy_epoch: u64 }
pub enum PolicyLevel { Off, Passphrase, Token, TokenTpm, Tpm }
```

```rust
// suspend_service::hooks: the state-hook contract (design §5).
// Hooks hand plaintext in and get plaintext back, inside the call;
// no key material ever crosses this API — the service derives
// per-hook keys from the SMK (image mode) / SMS (anchor mode)
// with the hook's name as the HKDF info label.
pub trait SuspendStateHook: Send + Sync {
    fn name(&self) -> &str;                    // also the HKDF label
    fn critical(&self) -> bool;                // default false
    fn seal(&self, ctx: &mut SealCtx) -> Result<(), SealError>;
    fn unseal(&self, ctx: &mut UnsealCtx) -> Result<(), SealError>;
}
impl SealCtx<'_> {
    pub fn seal_image(&mut self, plaintext: &[u8]) -> Result<BlobRef, SealError>;
    pub fn seal_anchor(&mut self, plaintext: &[u8]) -> Result<BlobRef, SealError>;
}
impl UnsealCtx {
    pub fn take_image(&mut self) -> BlobOutcome;   // Restored | Missing | Invalid
    pub fn take_anchor(&mut self) -> BlobOutcome;
}

pub fn register_suspend_state_hook(hook: Arc<dyn SuspendStateHook>);  // replace-by-name
impl<E: KeyEntropy> SuspendService<E> {
    pub fn seal_image_with_hooks(&mut self, store: &mut dyn ImageStore,
        policy: RecordedPolicy, image: &[u8],
        hooks: &[Arc<dyn SuspendStateHook>])
        -> Result<([u8; 16], SealFanoutReport), ServiceError>;
    pub fn seal_image_registered(&mut self, store: &mut dyn ImageStore,
        policy: RecordedPolicy, image: &[u8])
        -> Result<([u8; 16], SealFanoutReport), ServiceError>;
}
pub fn run_unseal_fanout(trusted: &TrustedImage, store: &dyn ImageStore,
    sms: &Secret32, hooks: &[Arc<dyn SuspendStateHook>],
    device_resumed: &dyn Fn(&str) -> bool)
    -> Result<UnsealFanoutReport, UnsealFanoutError>;
```

**State-hook contract (design §5).** Drivers and core libraries
whose state does not live in the bulk image (device-internal
state, NVRAM/TPM-resident state, key custody that refuses to ride
on the bulk key alone) register a `SuspendStateHook`. The seal
fan-out runs in reverse registration order after device quiesce,
inside `seal_image_with_hooks`; any seal error aborts the suspend
(`ServiceError::HookSealAborted`) before the writer runs, so an
aborted seal commits no image. State is capped at 64 KiB per hook
per mode (`MAX_HOOK_STATE_LEN`). Hook blobs live in the image's
hook region: a `u32` count, then per blob `u16 name_len ‖ name ‖
u8 mode ‖ u32 sealed_len ‖ ciphertext ‖ tag`, each blob
ChaCha20-Poly1305-sealed under its per-hook key with nonce
`image_id[..12]` and AAD `image_id ‖ mode ‖ name` — a blob copied
to another image, renamed, or re-moded fails verification. The
unseal fan-out runs in forward order from a `TrustedImage`, after
the device resume fan-out: **every blob is AEAD-opened into
staging before any hook's `unseal` runs**, so a tampered blob for
a `critical` hook aborts the fan-out before a single callback,
and a tampered blob for a non-critical hook reaches it only as
`BlobOutcome::Invalid` (no bytes — the hook must refuse and
re-establish). A hook whose device did not resume (the
coordinator's `device_resumed` predicate over the `device_pm`
resume report) is skipped, not failed. Anchor-mode blobs are
bound to the SMS epoch: after a rotation they no longer open and
surface as `Invalid`, which anchor hooks treat as the
re-establish signal (design §5.2 rule 2).

**Key hierarchy (design §3.1).** A per-epoch *slot master secret*
(SMS, 32B) is wrapped once per enrolled factor into a slot record;
each image draws a fresh per-image key (SMK, 32B) wrapped under
`HKDF-SHA256(SMS, "narf-suspend/slot-epoch" ‖ epoch)`, so an
epoch's material can never unwrap another epoch's images and
rotation invalidates every previous wrapping in one move. Image
and manifest keys are HKDF leaves under the SMK
(`"narf-suspend/image"`, `"narf-suspend/manifest"`); per-hook keys
derive as `"narf-suspend/hook/" ‖ name` (image mode) and
`"narf-suspend/hook-anchor/" ‖ name` (anchor mode) — the seam the
state-hook registry (design §5) consumes. Key generation draws
**only** from `narf-crypto`'s seed-grade key-material surface
(crypto §3.2) and refuses — `ServiceError::EntropyUnavailable`,
no fallback, no partial epoch — when no healthy seed-grade source
exists. Sealing draws the same way for every policy, OFF included.

**Image format (design §3.3).** On the pre-configured suspend
partition, byte ranges via `ImageStore` (production: `BlockStore`
over a registered partition device behind `narf-block`'s
`BlockDeviceSync`): a 4 KiB header page, then the tag manifest
(page-padded), the hook region (the state-hook registry's sealed
blobs; length 0 for a hookless seal), then the image in 1 MiB
AEAD chunks. The header page's
*preamble* is plaintext claims — magic `NARFSUS1`, format version,
image id, SMS epoch, recorded-policy level code, policy epoch,
the epoch's slot records, the SMK wrap nonce and wrapped SMK, in
that order — and is believed for nothing but factor selection.
The page's final 72 bytes are the *sealed body* (chunk count,
image length, hook region length, manifest root) sealed under the
manifest key with the entire preamble as AAD: any tampered
preamble byte — the recorded policy above all — fails the header
seal wholesale. Each chunk is ChaCha20-Poly1305-sealed under the
image key with nonce `0u32 ‖ chunk_index` and AAD
`image_id ‖ chunk_index`; the manifest root is a SHA-256 Merkle
root over the chunk tags. The governing policy is therefore the
*recorded* one, authenticated, never the machine's current
configuration (design §10.3). OFF-policy images run the identical
machinery under a published derivation (`off_policy_sms`): the
format stays uniform and the header honestly records OFF.
Slot records also persist outside images in the partition's slot
area (`SlotArea`, design §10.2) — the secret-free mirror the
resume environment finds slots through; its codec is strict and
total (caps before allocation, trailing garbage refused).

**Seams, deliberately minimal.** `parse_claims` / `OpenedImage`
are the resume environment's entry surface (it also consumes
`decode_hook_region` + `TrustedImage::read_hook_region` to stage
hook blobs); `RecordedPolicy` is what the policy engine
administers. Policy levels and floors are a separate lane (design
§12); this section specifies the service, the format, the custody
contract, and the state-hook contract. The resume environment
that consumes the reader pipeline is specified next.

#### Resume environment (S4 resume)

The early context of design §6 (`power/src/suspend_service/resume.rs`
+ `early_blk.rs`). It stands up before any restored state is
trusted, and its whole interface is one function:

- `attempt_resume(store, anchors, prompt) -> Result<VerifiedResume, ResumeRefusal>`
  drives the normative trust order of design §6.2: parse the
  header claims (`parse_claims`); announce the attempt under the
  *claimed* policy through the `ResumePrompt` seam (production:
  `ConsolePrompt` over the early console) — claims are announced
  as attempts, never as facts; satisfy the recorded policy
  through the `KeyCustodyAnchor` seam (OFF via the published
  derivation; a wrapped image via the first anchor whose kind
  matches an enrolled slot and whose unwrap succeeds — the first
  successful unwrap decides, and there is no fallback between
  policy paths); verify the whole image (`verify_all`); only
  then mint the handoff value.
- `VerifiedResume` is the only output restored state may be built
  from. It wraps the pipeline's `TrustedImage`, so chunk delivery
  re-verifies against the manifest at read time, and exposes the
  authenticated policy record, image/chunk extents, the
  authenticated hook-region length, and the per-hook key
  derivation the state-hook registry consumes at unseal.
- `ResumeRefusal` classes exist for boot routing: `NoImage`
  (header magic mismatch — the ordinary cold-boot case),
  `UnsupportedVersion`, `FactorUnavailable` (no provided anchor
  implements a kind the recorded policy needs; never a cue to
  try a weaker policy), `FactorRefused` (matching anchors all
  refused or failed), `AuthenticationFailed` (one class for SMK
  unwrap, header seal, manifest, and chunk failures — the resume
  path is not an oracle for which check failed), and `Service`
  (structural/store failures, carried verbatim). On every
  refusal, no part of the image has been delivered to anyone.

The image is read through the **early block reader**
(`early_blk.rs`, design §6.3): a polled, read-only virtio-blk
reader for the pre-scheduler context — one device, one queue,
one request in flight, no interrupts — because the running block
layer is part of what a resume restores. Its surface:

- `EarlyTransport`, the hardware seam: 32-bit register accesses
  over the virtio-mmio window (VirtIO 1.2 §4.2.2) plus DMA byte
  copies into the queue window. All queue memory crosses this
  seam as little-endian byte accesses.
- `PolledBlkReader::open(transport, dma_base, dma_len)` performs
  the §2.1 handshake accepting only `VIRTIO_F_VERSION_1`, programs
  queue 0 in the DMA window, and reads the §5.2.4 capacity.
  Legacy-version devices, non-block devices, refused features,
  unusable queues, and zero capacity are typed `EarlyBlkError`
  refusals; completion and reset polls are bounded, so a wedged
  device is a `Timeout` refusal, never a hang. The reader
  implements `ImageStore` offset-generally and refuses writes:
  the resume side only ever reads ciphertext.
- Transport scope: virtio-mmio. A PCI common-config front end
  slots behind `EarlyTransport` without touching the
  queue/request core; it is a named follow-on, as is boot wiring
  (partition discovery, early window mapping, calling
  `attempt_resume` from the boot path).

### 3.4 Thermal

Two layers, one registration path.

**Generic registry** (`power/src/thermal.rs`): zones with warn/crit
bands (millidegrees C), `ThermalEvent` publication on the
`power.thermal` bus topic, and the active-cooling governor — the
installed `CoolingPolicy` (default `StepPolicy`: Normal → 0,
Warm → 128, Critical → 255) drives every registered `CoolingDevice`
inline on a band crossing.

```rust
pub fn init();   // create registry + install StepPolicy; safe to call
                 // more than once — re-init clears the zone tables
pub fn register_zone(cap: &Cap<Thermal, Grant>, name: &str,
                     warn_milli: i32, crit_milli: i32)
    -> Result<u32, ThermalError>;
pub fn register_cooling_device(cap: &Cap<Thermal, Grant>,
    dev: Arc<dyn CoolingDevice>) -> Result<(), ThermalError>;
pub fn record_temp(zone: u32, milli_c: i32)
    -> Result<ThermalState, ThermalError>;
pub fn read_temp(zone: u32) -> Result<i32, ThermalError>;
pub fn zone_count() -> usize;
pub fn zones_snapshot() -> Vec<(String, i32, ThermalState)>;
pub fn subscribe(reg: &Cap<TopicRegistry, Read>)
    -> Result<Subscriber<ThermalEvent>, ThermalError>;
pub fn install_active_cooling<P: CoolingPolicy>(
    cap: &Cap<Thermal, Grant>, policy: P) -> Result<(), ThermalError>;

pub trait CoolingDevice: Send + Sync + core::fmt::Debug {
    fn name(&self) -> &'static str;
    fn set_level(&self, level: u8);   // 0 = off, 255 = max
}
```

**ACPI layer** (`power/src/acpi_thermal.rs`): the single ACPI
thermal implementation. It owns zone modelling — `enumerate()`
(ThermalZone nodes ∪ `PNP0C0F` devices, deduplicated), the full
trip-point table (`_CRT`/`_HOT`/`_PSV`/`_AC0..=_AC9`/`_TC1`/`_TC2`)
and `classify()` precedence (ACPI 6.5 §11.4). `drivers/platform`
carries no zone model of its own (#910). Temperature and trip-point
objects are evaluated as ACPI objects in either firmware shape — a
Method returning deciKelvin or a Name holding it (the common DSDT
shape for `_CRT`/`_PSV`/`_ACx`); a methods-only read silently
produces an empty trip table (#986).

The bridge between the layers is the only registration/sampling path:

```rust
// power::acpi_thermal — crit ← _CRT | _HOT | i32::MAX,
// warn ← _PSV | _AC0 | crit/2; sensorless zones skipped;
// registration failures logged, never swallowed.
pub fn register_with_generic_registry(cap: &Cap<Thermal, Grant>) -> usize;
pub fn sample_all() -> usize;  // evaluate _TMP, record_temp per bridged zone
```

**Composition order (load-bearing).** `thermal::init()` runs from
power's `thermal-registry` initcall at **Stage::PostCore**, before
the Stage::Subsys producers register into it (#907):
`drivers/platform`'s `acpi-thermal` initcall calls the bridge and
spawns the single 5 s poll task over `sample_all()`; its `acpi-fan`
initcall registers `AcpiFan` cooling devices. Both producers log
registration failures; the fan log prints "no PNP0C0B fans
discovered" only when discovery genuinely found none.

### 3.5 Runtime PM for devices

```rust
pub trait RuntimePm {
    /// State-preserving quiesce. Use for S1 / retention-class
    /// suspends where device registers stay powered. Driver may
    /// stop processing but does not need to save/restore state.
    async fn quiesce_freeze(&mut self, target: SuspendTarget) -> Result<(), PmError>;

    /// Power-loss quiesce. Use for S3 / S4 / D3-cold where device
    /// power is removed. Driver must save what it needs to
    /// reinitialise on `resume`. The corresponding `resume` runs the
    /// full bring-up sequence, not just an unblock.
    async fn quiesce_reset(&mut self, target: SuspendTarget) -> Result<(), PmError>;

    async fn resume(&mut self)  -> Result<(), PmError>;
    fn latency_hint(&self) -> Duration;
}
```

Drivers implementing `RuntimePm` can be autosuspended after an
idle timeout, with wake on the next request. Gated behind
`Cap<Device, PmControl>`.

The implemented autosuspend controller is `runtime_pm`, a port of Linux
`drivers/base/power/runtime.c`:

```rust
pub enum RpmStatus { Active, Resuming, Suspended, Suspending }
pub enum RpmError { Again, Busy, Access, Invalid, InProgress, NotPermitted, Failed, Cancelled }
pub enum RpmOk { Done, Already, Queued }
pub type RpmFuture<'a> = Pin<Box<dyn Future<Output = Result<(), RpmError>> + Send + 'a>>;

pub trait RuntimePmOps: Send + Sync {           // dev_pm_ops runtime half
    fn runtime_suspend(&self) -> RpmFuture<'_>;
    fn runtime_resume(&self) -> RpmFuture<'_>;
    fn runtime_idle(&self) -> RpmFuture<'_>;     // default Ok
}
pub trait RpmEnv: Send + Sync {                  // pm_wq + suspend_timer + clock
    fn now_ns(&self) -> u64;
    fn queue_work(&self, dev: Arc<RuntimePmDevice>);
    fn arm_timer(&self, dev: Arc<RuntimePmDevice>, expires_ns: u64);
}
pub struct SchedulerEnv;                          // executor tasks + timer wheel
pub struct ManualEnv;                             // fake clock for tests

impl RuntimePmDevice {
    pub fn new(name: &str, ops: Option<Arc<dyn RuntimePmOps>>,
               parent: Option<Arc<RuntimePmDevice>>, env: Arc<dyn RpmEnv>) -> Arc<Self>;
    pub fn set_active(&self) -> Result<(), RpmError>;     // while disabled
    pub fn set_suspended(&self) -> Result<(), RpmError>;
    pub fn enable(&self);
    pub async fn disable(self: &Arc<Self>);
    pub fn ignore_children(&self, enable: bool);
    pub async fn forbid(self: &Arc<Self>) -> Result<RpmOk, RpmError>;
    pub fn set_forbidden_active(&self) -> Result<(), RpmError>;
    pub fn allow(self: &Arc<Self>);
    pub async fn use_autosuspend(self: &Arc<Self>, use_it: bool);
    pub async fn set_autosuspend_delay(self: &Arc<Self>, delay_ms: i32);
    pub fn mark_last_busy(&self);
    pub fn get_noresume(&self);
    pub fn put_noidle(&self);
    pub async fn get_sync(self: &Arc<Self>) -> Result<RpmOk, RpmError>;
    pub async fn resume_and_get(self: &Arc<Self>) -> Result<RpmOk, RpmError>;
    pub fn get(self: &Arc<Self>) -> Result<RpmOk, RpmError>;          // + async resume
    pub fn get_if_active(&self) -> Result<bool, RpmError>;
    pub fn put(self: &Arc<Self>) -> Result<RpmOk, RpmError>;          // + async idle
    pub async fn put_sync(self: &Arc<Self>) -> Result<RpmOk, RpmError>;
    pub fn put_autosuspend(self: &Arc<Self>) -> Result<RpmOk, RpmError>;
    pub fn request_idle / request_resume / request_autosuspend(self: &Arc<Self>) -> Result<RpmOk, RpmError>;
    pub async fn idle / suspend / autosuspend / resume(self: &Arc<Self>) -> Result<RpmOk, RpmError>;
    pub fn autosuspend_expiration(&self) -> u64;
    pub fn state(&self) -> RpmState;
    pub async fn run_work(self: &Arc<Self>);      // pm_runtime_work (called by the env)
    pub fn timer_fn(self: &Arc<Self>);            // pm_suspend_timer_fn (called by the env)
}
pub async fn active_auto(dev: &Arc<RuntimePmDevice>) -> (RpmActiveRef, Result<RpmOk, RpmError>);
```

Semantics follow `rpm_idle` / `rpm_suspend` / `rpm_resume` exactly:
`rpm_check_suspend_allowed` order (runtime_error → disabled → usage →
active children → pending resume → already suspended), autosuspend
expiry `last_busy + delay` with the timer re-armed while `last_busy`
moves, transient (`Again`/`Busy`) versus sticky callback errors, deferred
resume of a suspending device, `RPM_ASYNC` requests carried out by the
environment's work item, and the parent rules: a child's resume holds a
usage reference on its parent and resumes it first (failure is `Busy`),
an active child counts in its parent's `child_count`, and a completed
child suspend queues an idle check on the parent. `put_autosuspend` marks
the device busy, as in current Linux. The state lock is never held across
an await: callbacks run unlocked and synchronous callers park on a waker
list. Dropping a future while its device callback runs records the sticky
`Cancelled` error and wakes every waiter; `set_active`/`set_suspended`
while disabled clear it. `RpmActiveRef` is the RAII
`get_sync … put_autosuspend` pair.

`runtime_pm_pci` is the PCI bus layer (`pci_pm_runtime_*`):

```rust
pub trait PciPmIo: Send + Sync { power_state, set_power_state, save_state,
                                 restore_state, delay_ms (async) }
pub struct EcamPciPm;                              // bus::pci helpers, type-0 header
pub trait PciPlatformPm: Send + Sync { d3cold_supported, power_off, power_on }
pub struct PciRuntimePm;                           // RuntimePmOps around a driver
impl PciRuntimePm { pub fn save_state(&self) -> Result<(), PciError>; pub fn current(&self) -> PciTarget; }
pub fn register_pci_device(name, cap, device, driver, platform, env) -> Result<PciRuntimeNode, RpmError>;
pub fn register_with_io(name, io, driver, platform, parent, env) -> Result<PciRuntimeNode, RpmError>;
pub fn bridge_node(bridge: &BusDevice, env: &Arc<dyn RpmEnv>) -> Option<Arc<RuntimePmDevice>>;
```

Suspend runs the driver's `runtime_suspend`; on success, unless the driver
saved state itself (`PciRuntimePm::save_state`) or left the function out
of D0, the layer saves config state and moves the function to D3hot (10 ms
async settle), then to D3cold when a `PciPlatformPm` can remove power.
NARF evaluates no AML (§8.3), so no in-tree platform offers D3cold.
Resume powers the function up (platform power-on, D0, settle), refuses an
all-ones function, restores state, then runs the driver's
`runtime_resume`. An unbound function only saves/restores and stays in D0.
`register_pci_device` leaves the new device as `pci_pm_init` and probe do
(active, enabled, forbidden, probe reference held) and parents it on a
shared node per upstream bridge, which is active and forbidden like an
unbound Linux bridge. The older `DeviceRuntimePm` registry above remains
the bare suspend/resume fan-out without usage counting.

### 3.6 System transitions

```rust
pub fn reboot() -> !;
pub fn power_off() -> !;
```

On x86_64, `power_off` evaluates `\_S5_` and writes the firmware-provided
SLP_TYPa/b values to PM1 control with SLP_EN. Sleep types are opaque
platform encodings: `(0, 0)` is valid and must not be replaced merely because
it is zero. A legacy `(5, 0)` fallback is used only when `_S5` cannot be
evaluated. PM1 writes preserve every non-sleep control bit. On aarch64,
`power_off` invokes PSCI `SYSTEM_OFF` through the architecture-selected HVC or
SMC conduit. Both entry points halt forever if the platform call unexpectedly
returns.

Before the platform call every transition runs, in this order
(`system::before_transition`): (1) the pre-shutdown filesystem sync
(`install_pre_shutdown_sync(fn())`, installed by `narf_userspace`:
`narf_filesystem::sync_all::sync_all`, i.e. every mounted filesystem's
`syncfs`, then one flush per disk this boot may have written); (2) the
persistent-log flush; (3) the device shutdown hooks
(`register_shutdown_hook`, reverse registration order; NVMe Flush + CC.SHN).
A transition requested from interrupt context is refused and turned into an
orderly power-off request; a second concurrent transition parks.
`power_off_synced() -> !` skips step (1) for a caller that already synced.

```rust
// orderly: Linux orderly_poweroff / hw_protection_shutdown
pub fn orderly::orderly_poweroff(reason: OrderlyReason, sync_budget_ms: Option<u64>) -> bool; // IRQ-safe
pub fn orderly::hw_protection_shutdown(reason: &str, ms_until_forced: u64);
// button: ACPI power button as an input device (Linux acpi_button)
pub fn button::report_power_button() -> PressOutcome;
```

The orderly worker (spawned by a Stage::Late initcall) syncs every filesystem
from task context, bounded by the request's budget (default 60 s), then calls
`power_off_synced`. `hw_protection_shutdown` additionally arms a forced
power-off if no transition has started within twice the budget. The ACPI
power button reports `KEY_POWER` press + release on its own evdev device;
with no reader open on it (no logind) it requests the orderly power-off. No
power-off ever runs in the notifying (IRQ / SCI subscriber) context.

**Why two quiesce variants.** A driver that has only a single
`quiesce` method must conservatively assume power loss, which means
running the full save sequence on every retention-class suspend —
expensive and pointless. The split lets the framework call the cheap
path for S1 and the expensive path only when needed, and makes the
power-loss assumption explicit at the ABI rather than hiding in
driver implementation.

### 3.7 Power service (event → policy → action)

```rust
// service: the actor between platform power events and §3.3's core
pub enum PowerAction { Suspend, Freeze, PowerOff }
pub enum ButtonAction { Ignore, Suspend, PowerOff }
pub struct PowerPolicy {
    pub suspend_on_lid_close: bool,          // default true
    pub sleep_button: ButtonAction,          // default Suspend
    pub power_button: ButtonAction,          // default Ignore (§3.6 owns the key)
    pub warn_on_critical_battery: bool,      // default true
}
pub fn set_policy(cap: &Cap<Power, Grant>, p: PowerPolicy) -> Result<(), PowerError>;
pub fn policy() -> PowerPolicy;

pub trait ActionExecutor: Send + Sync { fn execute(&self, action: PowerAction); }
pub fn install_action_executor(cap: &Cap<Power, Grant>, e: Arc<dyn ActionExecutor>) -> Result<(), PowerError>;
pub fn install_warning_hook(cap: &Cap<Power, Grant>, h: Arc<dyn Fn() + Send + Sync>) -> Result<(), PowerError>;

pub fn on_lid_changed(closed: bool);         // IRQ-safe intake
pub fn on_ac_changed(state: AcAdapterState);
pub fn on_power_button_press();
pub fn on_sleep_button_press();
pub fn request_action(action: PowerAction);  // policy-free direct request

pub struct StateProviders { /* ac_adapter, lid, battery, cpu/gpu temp closures */ }
pub fn register_state_providers(cap: &Cap<Power, Grant>, p: StateProviders) -> Result<(), PowerError>;
pub fn snapshot() -> LaptopStateSnapshot;
pub fn start_worker();                       // Stage::Late initcall
```

The service holds no `Cap`: configuration is cap-gated, execution is
delegated to the installed `ActionExecutor`, whose owner holds the
authority (the platform composition mints the suspend
`Cap<Power, Invoke>` at its call site). Intake only records the
request as a bit in an atomic mask and wakes the worker — duplicate
requests coalesce, and no action ever runs in the notifying (IRQ /
SCI subscriber) context. The worker (or any task-context caller of
`pump_pending`) executes pending actions in Suspend → Freeze →
PowerOff order — the sleeps run first, and a power-off queued
alongside them is served on the next pump, after resume. With no
executor installed, requests stay pending rather than being
dropped; installing an executor wakes the worker.

Userspace sleep requests (§3.3) enter through the same queue: the
platform composition root (`drivers/platform` power-service
wiring, Stage::Late) installs the `sleep_request` hook, which maps
`SleepState::Freeze` → `PowerAction::Freeze` and
`SleepState::Mem` → `PowerAction::Suspend` via `request_action`.
The executor's `Freeze` arm mints a `Cap<Power, Invoke>` and calls
`s2idle::suspend_to_idle`, parallel to the `Suspend` arm's
`s3_enter` — the two sleep states are distinct actions because
they run distinct cores, and neither may silently stand in for
the other.

`snapshot()` fuses the registered `StateProviders` (closures that
may evaluate AML — never invoked under the service lock), falls
back to event-cached AC / lid state, drains the button-press
counters into the snapshot exactly once, and edge-triggers the
warning hook on a transition into `LaptopStateSnapshot::
is_running_low_on_battery()` when policy enables it. The §3.3
production-S3 arm/validated gates are unchanged: the service
requests suspend, the core still decides.

The platform battery provider behind `StateProviders.battery`
is itself multi-source. The composition root
(`drivers/platform` power-service wiring) evaluates the ACPI
control-method battery (`PNP0C0A`, `_BIF`/`_BST`) first; on
machines whose battery subsystem is an ACPI Smart Battery
Subsystem (`ACPI0002`, ACPI §10.1) — which has no control-method
battery at all — it falls back to the SBS driver
(`drivers/platform` `sbs`), which speaks the Smart Battery Data
Specification command set over the SMBus host (battery at 0x0B,
selector / system manager at 0x0A, charger at 0x09) and maps the
result into the same `(BatteryInfo, BatteryState)` pair,
including the `CAPACITY_MODE` 10 mW scaling and the selector
routing for multi-battery subsystems. Consumers of `snapshot()`
see one battery abstraction regardless of which transport
produced it. An SBS battery that fails validation (NAK,
implausible values, a nonzero status error code, a malformed
block string) is reported absent by the provider — never
published with fabricated values.

## 4. Invariants & safety properties

- Suspend never returns without either `WokeUp` or `Aborted`;
  wedging is impossible (caller owns the timeout).
- C-state exit latency accounting is honest — we never enter a
  state whose worst-case exit would miss the next timer deadline.
- Thermal emergency shutdown is idempotent and signal-safe.
- DVFS changes are bounded: no transition takes longer than its
  declared `transition_latency`.
- Per-CPU HWP/CPPC registers are enabled, read, and written only while
  executing on their owning CPU. A BSP loop must never impersonate remote
  CPUs; remote updates require a pinned worker or CPU rendezvous.
- Firmware capability tuples must satisfy
  `lowest <= nominal <= highest` and `highest != 0` before any request is
  programmed. Invalid tuples disable the backend on that CPU.
- Monotonic time never goes backwards across suspend/resume.
  Wall time jumps forward by the measured suspend duration.
- Per-driver `suspend` must be callable from the runtime or
  system-wide paths; must tolerate concurrent invocation being
  serialised by `power/`.
- Runtime PM never holds its state lock across an await, and a device
  callback's failure, cancellation or refusal leaves the status consistent:
  a refused suspend is `Active`, a failed resume `Suspended`, a cancelled
  transition carries a sticky error until the driver re-establishes the
  state. A parent is never runtime-suspended while a child that does not
  have it ignore children is active.
- An `AsyncSystemPm` implementation must never retain an IRQ-safe lock across
  an await. Every hook whose prepare completed receives exactly one paired
  resume attempt, including when a later prepare or the synchronous fan-out
  aborts the transition.

## 5. Architecture notes

### x86_64
- **C-states:** MWAIT + CPUID leaf 5 for supported states; newer
  CPUs expose via ACPI `_CST` objects. Default: MWAIT-based.
- **P-states:** Intel HWP (Hardware P-States) preferred; fallback
  to ACPI `_PSS`. AMD CPPC analogous.
- **Suspend:** ACPI S3 via `FADT`'s `PM1a_CNT` block; S4 via
  `hibernate` image written to a pre-configured partition.
- **Thermal:** MSR-based package temperature + ACPI thermal zones.

### aarch64
- **C-states / idle:** WFI for shallow; PSCI `CPU_SUSPEND` with
  implementation-defined state IDs for deeper.
- **P-states:** platform-specific; often CPPC via PCC mailbox on
  SystemReady boards.
- **Suspend:** PSCI `SYSTEM_SUSPEND`; `SYSTEM_OFF` / `SYSTEM_RESET`
  for shutdown/reboot.
- **Thermal:** platform-defined; often via PCC or an SCMI
  coprocessor.

## 6. Dependencies

- **Consumes:** `arch/` (C-state / P-state primitives, PSCI),
  `scheduler/` (freeze tasks, CPU hot-plug), `time/` (clock fast-
  forward), `drivers/` (iterate + quiesce), `capabilities/`,
  `interrupts/` (disable / re-enable around suspend),
  `tracing/` (power events), `frame/` (emergency shutdown).
- **Provides to:** `scheduler/` (EnergyAware governor reads + hints),
  `drivers/` (runtime PM harness), `userspace/` (suspend cap for
  a session manager in Stage 4).

## 7. Stage assignment

| Stage | Lands                                                        |
| ----- | ------------------------------------------------------------ |
| 2     | C-state registration + simple idle governor (WFI / MWAIT C1). |
| 3     | DVFS governor framework, Performance / Powersave governors, per-driver runtime PM trait. |
| 4     | Suspend-to-RAM (S3 / PSCI), thermal zones + throttling, EnergyAware governor coupled to `scheduler/`. |
| post-1.0 | S4 hibernate, deep platform states, battery / AC integration on laptop-class targets. |

## 8. Resolved decisions

### 8.1 Tickless idle (resolved)

**Decision:** **opt-in tickless via `narf.power.tickless=1`
boot param**, off by default. When enabled, an idle CPU
disarms its periodic timer and reprograms only when the
nearest scheduled wake (timer, hrtimer, sleep) requires it.

Cost to `time/`: tickless CPUs produce no per-tick
`timekeeper` snapshot updates; `monotonic_ns()` still works
(reads the per-call TSC + last-tick anchor; staleness bounded
by re-arm latency). Wall-clock readers may see microsecond-
range jitter; acceptable per `time/spec` §8.1.

Default is off for v1.0 — the per-tick scheduler-budget
accounting and tracing-event timestamps are slightly more
predictable with ticks. Datacenter / DPDK-style workloads
can opt in.

### 8.2 E-core / P-core energy model (resolved)

**Decision:** **`power/` exposes per-class energy curves
that `scheduler/` consumes**. Each `CpuClass` (`Performance`,
`Efficient`, `Mixed`) has a model:

```rust
pub struct EnergyCurve {
    pub perf_at_freq:    fn(MHz) -> PerfScore,    // monotonic
    pub power_at_freq:   fn(MHz) -> Milliwatt,    // monotonic
    pub min_freq:        MHz,
    pub max_freq:        MHz,
    pub idle_power:      Milliwatt,
}
```

The scheduler picks the (cpu_class, freq) tuple that
minimises `power / perf` for each task subject to its
deadline / interactivity hint. RT tasks are treated as
"max perf at any energy"; Idle tasks as "min energy at any
perf."

The energy curves are populated from CPUID (x86_64) /
PSCI/SCMI (aarch64) at boot. Platforms without published
curves get a heuristic default (linear power vs. freq).

### 8.3 AML evaluation (resolved)

**Decision:** **NARF does not execute AML**, mirroring
`bus/spec` §11.1. This loses some PM features on legacy
platforms (S3 wake notifications, dynamic DVFS tables on
older Intel) but keeps the kernel free of an AML interpreter
attack surface.

PM info comes from:
- ACPI tables: FADT, MADT, SRAT, MCFG, HPET (no AML).
- ACPI _PSS / _CST tables that are static-data variants.
- Devicetree `cpu-supply`, `operating-points`, `power-domains`
  on aarch64.
- SCMI for runtime-negotiated PM on SCMI-capable platforms.

Platforms that require AML for PM functionality run with
reduced PM support (no DVFS, no per-device runtime PM).
Mainstream server x86_64 + modern aarch64 SoCs are fine; old
desktop ACPI-heavy systems are second-class.

### 8.4 S3 vs modern standby (resolved)

**Decision:** **modern standby (S0ix / connected standby) is
v1.0 default**; legacy S3 is supported as a fallback.

Modern-standby flow:
1. User initiates suspend.
2. NARF freezes user processes.
3. Drivers receive `Driver::quiesce()` → enter D3hot/D3cold
   per their PM hooks.
4. Kernel waits for wake events (network packet, lid open,
   timer alarm) on idle CPUs in deepest C-state.
5. On wake, the inverse — drivers exit D-state, processes
   thaw.

S3 (RAM-only suspend with full CPU power-off) is supported
where the platform offers it; the flow is the same with
deeper sleep.

The driver-side hooks (`Driver::quiesce`, `Driver::resume`,
`DState` transitions) are already in `drivers/spec`; this
spec just wires them to the system-level transition.

### 8.5 SCMI integration (resolved)

**Decision:** **SCMI is a bus-like service under `bus/`**,
not a separate top-level subsystem. SCMI-attached devices
(thermal sensors, DVFS controllers, reset controllers,
voltage regulators) appear as `BusDevice`s with `BusKind::Scmi`
and matched by their SCMI protocol id.

A small `narf-drivers-scmi-transport` driver owns the
shared-memory mailbox to the SCMI server (firmware), and
specific protocol drivers (e.g.
`narf-drivers-scmi-perf` for performance-domain DVFS) bind
to it via `bus/`'s match-table.

This keeps the framework uniform — SCMI is just another bus
— and lets PM features evolve as ordinary driver code.

## 9. ABI versioning

`power/` exports through SDK at `@v0`:

- `DState` enum (D0..D3Cold).
- `Cap<DevicePm, _>`, `Cap<FreqHint, _>`, `Cap<Power, _>`.
- `DeviceRuntimePm::transition(target: DState)`.
- `EnergyCurve` accessor.

`POWER_ABI_MAJOR = 1`, `POWER_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.1 questions resolved in §8)
