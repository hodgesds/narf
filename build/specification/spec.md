# build — Specification

> Status: **v1.0** (Stage 1 design lock). v0.2 specified the
> compiler-fence discipline for LTO; v1.0 locks the toolchain
> pinning policy, the linker selection, the
> reorder-hazard audit gate, and the FDO/BOLT integration
> path.

## 1. Purpose & scope

**Owns:** Cargo workspace layout, `build-std` configuration, linker scripts
per arch, xtask commands (`run`, `test`, `qemu`, `image`), Global LTO config,
and CI compiler-cache integration.

**Does NOT own:** Release management, CI test policy, debian-style packaging.

## 2. Assumptions

- Nightly Rust toolchain (`build-std` is unstable).
- `rust-src` component available.
- QEMU with KVM on host for faster iteration; TCG fallback.

## 3. Public interface

- Commands with common kernel build arguments accept
  `--composition FILE`, repeatable `--builtin-crate MANIFEST`, and repeatable
  `--module-crate MANIFEST`. The versioned composition selects Cargo packages
  outside the NARF workspace as linked built-ins or ABI-stamped modules. All
  generated Cargo manifests, registrars, lockfiles, and artifacts live below
  `target/narf-compositions/`; source manifests are never rewritten.
- Built-ins are dependencies of a generated standalone copy of the frame
  manifest and compile in the same Cargo graph. A generated registrar calls
  the selected direct entry as the body of its declared init stage (the entry
  must not register another call into that same stage), with a compile-time
  `DomainId` argument when requested. Modules build through the relocatable
  `.ko` pipeline, are staged for QEMU/x86_64 media, and produce
  `modules_load` plus per-path `modules_domains` boot arguments. Public keys
  selected by signed module entries augment the build-time module trust store.
- `cargo xtask build-module --manifest-path PATH --package NAME ...` builds an
  out-of-tree module without adding it to the repository workspace.

- `NARF_FIRMWARE_TRUSTED_KEYS=/absolute/path/keys.txt` embeds firmware
  verification public keys (one 64-digit hex Ed25519 key per line).
  Firmware bootstrap installs them before signed-blob discovery.
- `cargo xtask pack-firmware --name NAME --payload FILE --signature SIG
  --public-key KEY` verifies an externally signed BLAKE3 payload digest
  and stages the NRFW blob in `target/firmware/NAME`. `SIG` and `KEY` are
  raw 64- and 32-byte files. Without both options, the blob is unsigned.
- `cargo xtask wifi-firmware --source /lib/firmware [--profile ID,...]
  [--report FILE] [--require-assets]` inventories the fixed-name payloads
  in `verification/data/wifi-firmware/profiles.json`. It resolves raw/zstd
  files and contained file aliases, reports decompressed lengths/SHA256 and
  canonical registry keys, and lists external board/calibration/policy gates.
  Missing files permit the next candidate; existing corrupt, empty, oversized
  or escaping inputs fail. `--require-assets` fails for missing required
  payloads; conditional PNVM and board qualification remain explicit manual
  gates. A JSON report must be a new file outside the source tree. Inventory
  does not verify signatures, parse firmware or establish hardware readiness.
- `cargo xtask import-firmware --vendor iwlwifi` accepts linux-firmware's
  flat `iwlwifi-*.ucode/.pnvm` names and stages `iwlwifi/<name>` registry keys.
  The importer retains board NVRAM `.txt` files, filters documentation after
  stripping `.zst`, bounds decoded payloads and zstd windows, and imports only
  file aliases resolving inside the source root. It emits unsigned developer
  NRFW wrappers without inventing firmware versions from the host kernel.
  Audit and import share a deterministic order: canonical raw, canonical zstd,
  then Intel flat raw/zstd aliases. An existing invalid primary stops fallback.
  Production blobs still use externally signed `pack-firmware` and trusted
  public keys; neither tool qualifies board-power or regulatory artifacts.

- `cargo xtask run --arch=x86_64 [--release]` — build + QEMU boot. Optimized
  builds strip debug-only ELF sections by default while retaining ordinary
  symbols; `--debug` retains full debuginfo for GDB and crash diagnosis.
- `XTASK_STAGE_BIN=/host/path[:guest/path] cargo xtask run-interactive ...`
  adds one executable host file to the generated initramfs. With no guest path
  it is installed as `/usr/bin/<basename>`, and the boot shell searches
  `/bin` followed by `/usr/bin`. Destinations hidden by boot-init mounts (for
  example `/bin`) are rejected instead of producing a misleading `ENOENT` at
  `execve`; staged entries retain mode `0755`.
- `cargo xtask run --arch=x86_64 --passthrough-device 03:00.0
  --passthrough-device 03:00.1` — attach host PCI functions to the guest with
  QEMU `vfio-pci`. The repeatable option is an xtask/QEMU boot option, not a
  guest kernel command-line parameter. Before launch, xtask requires KVM,
  active host IOMMU groups, every requested endpoint bound to `vfio-pci`,
  complete IOMMU-group assignment, and BAR sizes compatible with NARF's mapped
  physical windows. It never unbinds or rebinds host hardware. PCI passthrough
  is currently x86_64-only. A passed-through display removes the explicit
  Bochs and VirtIO display devices as well as the default VGA adapter.
  The `max` and KVM `host` CPU models default to `phys-bits=40` so q35's
  64-bit PCI BAR placements stay below NARF's 1 TiB mapping ceiling;
  explicit physical-address-width overrides are retained.
- `cargo xtask run --arch=x86_64 --gpu-backend=virgl --display=gtk,gl=on`
  — opt into QEMU's OpenGL-backed virtio-gpu device. The default remains
  `--gpu-backend=auto`: graphical runs prefer VirGL when QEMU advertises the
  GL device and otherwise fall back to `virtio-2d`; headless runs stay on 2D.
  Selecting VirGL does not by itself make a guest renderer available: the
  guest must also negotiate
  `VIRTIO_GPU_F_VIRGL` and expose the matching render-node UAPI.
- GTK displays automatically enable QEMU's `grab-on-hover=on` unless the
  caller explicitly provides a `grab-on-hover=` option. This routes the host
  keyboard and pointer to the guest's virtio input devices as soon as the
  pointer enters the window; `Ctrl-Alt-G` still releases the grab.
- On x86_64, a VirGL-backed VirtIO fixture (`full` or `virtio-only`) and a
  graphical 2D `virtio-only` fixture pass QEMU `-vga none`, leaving virtio-gpu
  as the sole display adapter. This keeps KWin's DRM/render-node selection on
  the 1af4:1050 device rather than QEMU's default Bochs VGA fallback; in the
  2D `virtio-only` case it also makes GTK present the virtio-gpu scanout rather
  than the legacy VGA text console. Headless 2D and full-profile 2D fixtures
  retain their legacy display coverage.
- `cargo xtask test --arch=aarch64` — boot + run all kernel tests.
  The host launcher places the module initramfs above the actual kernel ELF
  physical PT_LOAD memory end (including BSS), aligned to 1 MiB and below the
  DTB. A native Rust FDT helper updates both `/chosen/linux,initrd-{start,end}`
  properties and the loader uses the same address. Missing/malformed ranges,
  overflow and insufficient space fail before QEMU; the dummy kernel used for
  DTB generation is never used to infer the real image's occupied memory.
- GPU validation uses native Rust kernel tests through
  `cargo xtask test --arch=x86_64 --subsystem drivers/gpu` (and aarch64).
  Driver builds/tests do not extract Linux/Mesa functions, invoke host C shims,
  or compile temporary Rust source slices for reference comparison. Fixed
  hardware data and reviewed Rust vectors retain their provenance; physical
  hardware and external userspace interoperability require separate acceptance.
- Wi-Fi firmware parser tests construct small, explicit wire inputs in Rust.
  No extracted metadata binaries, regeneration step or local vendor firmware
  installation is required. `cargo xtask wifi-fixtures board-manifest` encodes
  explicit deployment facts as unsigned NBSP v1 data for the existing
  `pack-firmware` signing flow. It does not invent board calibration or grant
  device authority. The former metadata `check`, `write` and `extract` commands
  are removed.
- `cargo xtask test --arch=x86_64 --subsystem userspace` — run that subsystem
  and its `/`-delimited children, then perform the normal whole-kernel boot
  smoke. Comma-separated filters select the union of those subtrees.
- `cargo xtask test --arch=x86_64 --exclude-subsystem drivers/gpu` — remove
  that subsystem subtree from whatever the include filter (or the full
  suite) selects; the two filters compose, and both thread onto the kernel
  cmdline (`test_subsystem=` / `test_subsystem_exclude=`). CI's primary
  kernel-test invocation always excludes `drivers/gpu`; that group runs in
  the dedicated `kernel-test-gpu` job, gated by the affected plan's
  `run_gpu_tests` output, so an intermittent GPU-fixture hang cannot stall
  the primary suite.
- `cargo xtask test --arch=x86_64 --split` — run the kernel-test phase as
  one QEMU boot per subsystem group instead of a single boot. The guest
  harness runs tests as direct synchronous calls, so a hung test never
  returns control and no in-guest watchdog can preempt it; in one boot a
  single hang burns the phase's whole 2400 s cap and every later test's
  result is lost. Each split boot is capped by
  `XTASK_QEMU_GROUP_TIMEOUT_SECS` (default 900, ≈2.25× the slowest
  group's measured guest time — the btrfs subtree at ≈400 s on x86_64
  TCG). Groups are the `--subsystem` entries when one is given, else a
  fixed partition of the suite whose final group is the exact complement
  of the others, so coverage is unchanged; caller excludes apply to every
  group. A boot killed at the cap, or one that dies without a summary,
  is accounted from the tests that completed plus exactly one failure
  for the in-flight test, whose reason names the timeout — a timeout is
  a failure, never a skip. xtask aggregates the groups into the same
  `── summary: P pass, F fail, S skip ──` and `── failing tests ──`
  lines the guest prints, and the phase-2 boot-smoke and postflight run
  once, afterwards, as in the single-boot form.
- `cargo xtask net-smoke --arch=x86_64` runs live host-to-guest TCP and UDP
  echoes plus a guest-originated DNS query over virtio-net. `cargo xtask
  e1000-module-net-smoke --arch=x86_64` runs the identical exchanges over an
  exclusively module-owned QEMU 82540EM: xtask builds and ABI-stamps
  `e1000.ko`, stages it in an initramfs, selects `driver2` at boot load, and
  suppresses the built-in e1000 registration for that fixture. `cargo xtask
  igb-net-smoke --arch=x86_64` runs the same exchanges over the built-in IGB
  driver and QEMU's 82576 `igb` model, with no competing virtio-net device.
- QEMU network backends are selectable without source changes.
  `XTASK_QEMU_TAP=<ifname>` attaches virtio-net to a pre-created TAP, or e1000
  when `--hw-profile=legacy-only` makes that selection unambiguous.
  `XTASK_QEMU_LEGACY_TAP=<ifname>` explicitly selects the e1000 TAP in any
  hardware profile. TAP selection takes precedence over the corresponding
  `XTASK_QEMU_HOSTFWD` / `XTASK_QEMU_LEGACY_HOSTFWD` SLIRP configuration.
- `cargo xtask affected --base REF --head REF --event EVENT` computes CI jobs,
  directly changed packages, reverse-dependent packages, and kernel subsystem
  filters from Cargo metadata and Rust registration tokens. PRs use their head
  and base SHAs; pushes compare the event's before/after SHAs directly, including force pushes. Nightly, manual,
  `--force-full`/`ci-full`, infrastructure, hub-crate, and unknown-input changes
  retain full-test fallbacks. Failed diffs or inventory scans also fall back.
  Embedded userspace images are build inputs to `narf-verification`, even
  though their manifests are outside the kernel workspace.
  `--github` emits Actions outputs; the default is JSON. `changed_crates`
  contains direct workspace owners; `crates` contains affected test owners.
  `clippy_crates` and `host_clippy_crates` are JSON arrays of lint targets.
  `subsystems` is a JSON array (a comma-separated string for Actions); an empty
  filter with `run_kernel_test=true` means all tests. Prefix compaction may
  shorten a filter only when it adds no unselected registration; a 1024-byte
  filter budget replaces the former arbitrary tag-count limit.
  `run_large_memory`, `run_xapic`, `run_virtio_mmio`, `run_user_mode`, and
  `run_uefi` gate secondary configurations independently; `run_gpu_tests`
  gates the dedicated GPU kernel-test job. Kernel lint and test
  jobs retain both architectures. Shared compiler/configuration changes and
  explicit full runs lint all packages; ordinary crate edits lint direct
  owners even when their tests require a full run.
- `cargo xtask clippy-changed --arch=x86_64 --packages '["narf-audio"]'`
  lints selected packages with `--no-deps` in Cargo-resolved production,
  container, and user-mode-e2e feature contexts. The pinned nightly's unit
  graph separates target features from host build-script features; metadata
  alone merges those contexts and can wrongly enable `std` on bare metal.
  Identical selected-package
  and direct-dependency feature sets are checked once. Dependencies still
  compile. `--arch=host` checks selected host tools with `--all-targets`;
  `--dry-run` prints commands without running Clippy. Debug kernel linking
  remains a boot-job check, independent of package lint selection.
- QEMU's HDA and VirtIO sound devices use distinct audio backends. A shared
  mixer can stall HDA DMA after a VirtIO test leaves an idle playback voice;
  the combined `audio` subsystem run covers this ordering regression.
- `cargo xtask test --arch=x86_64 --subsystem userspace --kernel-tests-only`
  — run only the selected in-kernel tests. This is for secondary CI
  configuration shards after a primary invocation for that architecture has
  already completed the production-init boot and host-side btrfs
  interoperability postflight; the default remains the full two-phase gate.
- Successful kernel-test and boot-smoke QEMU phases keep serial output
  captured and print concise summaries by default. With
  `XTASK_QEMU_SERIAL_TEE=1`, the captured stream is also flushed to stdout as
  it arrives so CI exposes guest progress without changing result parsing. A
  failure or timeout emits a bounded 64-KiB diagnostic tail. Abnormal emulator
  termination is reported with the platform exit-status description
  (including the Unix signal when present), not only the optional numeric exit
  code. Child timeouts use polling rather than process-wide signal handlers,
  so sandboxed runners remain supported.
- `cargo xtask boot-smoke --arch=<arch>` accepts success only when the guest
  emits its clean-exit marker and QEMU then exits naturally with status zero
  through ACPI S5 on x86_64 or PSCI `SYSTEM_OFF` on aarch64. The x86
  `isa-debug-exit` test device returns status one and therefore cannot satisfy
  this platform-shutdown gate.
- `XTASK_QEMU_SERIAL_LOG=/path/to/serial.log` optionally copies the kernel-test
  QEMU stdout stream to a host file while tests run. The file is truncated at
  the start of that phase; normal concise summaries and timeout diagnostics
  remain enabled. It may be combined with `XTASK_QEMU_SERIAL_TEE=1`. Neither
  option adds guest-side instrumentation.
- The second, whole-kernel phase of `cargo xtask test` strips both
  `kernel-test` and features that transitively select that harness
  (`user-mode-e2e`, `user-mode-testbin`, and `narf-libc-validate`) so it
  always exercises the production init path.
- `cargo xtask systemd-pid1 --arch=x86_64` — boot a systemd rootfs as real
  PID 1 for a bounded capture. The command enables the `qemu-net` static
  configuration, exposing `vnet0` as `10.0.2.15/24` with QEMU SLIRP gateway
  `10.0.2.2`, so graphical distro boots have an immediately usable network.
  `XTASK_SYSTEMD_PID1_SUCCESS_MARKER` and
  `XTASK_SYSTEMD_PID1_FAILURE_MARKER` optionally make serial substrings into
  fail-fast integration assertions; the run fails if an expected success
  marker is absent at the timeout. `XTASK_SYSTEMD_PID1_NET_CHECK=1` turns the
  boot into a network acceptance run: xtask serves a token on an ephemeral
  host port, threads `narf_net_check`/`narf_net_check_port=` onto the kernel
  cmdline, and the rootfs's `narf-net-check.service` gate (staged by
  `REGEN_fedora_kde_rootfs.sh`) proves vnet0 is visible, TCP round-trips to
  the host across SLIRP, DNS resolves through `10.0.2.3`, and
  `unshare(CLONE_NEWNET)` both works and isolates (the same host round-trip
  must fail inside a fresh netns); its single `NARF-NET-CHECK:` verdict line
  becomes the default success/failure marker pair.
- `cargo xtask iso-boot --arch=x86_64` — build the removable-media
  image, boot it through a read-only OVMF pflash + Limine's
  `BOOTX64.EFI`, and require
  the real-init clean-exit marker with no kernel panic.
- `cargo xtask iso-boot --arch=aarch64` — build a FAT ESP containing
  `EFI/BOOT/BOOTAA64.EFI`, generate and attach QEMU's `virt` DTB with
  ACPI disabled so AAVMF publishes the EFI DTB table, and require the
  same clean-exit marker. Before the image is published, the exact kernel's
  BLAKE2b-512 digest is bound into the loader; an unbound loader fails closed.
- `cargo xtask host-test` — run the fast host unit-test allowlist.
  Only hardware-independent crates belong here; privileged, linker-script,
  and device integration coverage remains under `xtask test`.
- `cargo xtask crate-release list|bump|check` manages crates.io preparation
  without uploading. A publishable package opts in with an explicit
  `[package].version` and `package.metadata.narf.release-managed = true`;
  workspace-inherited versions are never rewritten. `bump --package NAME`
  advances only that crate's patch version, repeatable `--set NAME=VERSION`
  supports an exact independent version, and `--changed-since-tags` selects
  crates whose owned files changed after `crate/NAME/vCURRENT`. Missing
  publication tags are reported and skipped. A bump adds or repairs registry
  requirements on the selected crate's internal path dependencies and expands
  to a release-managed dependent only when its existing requirement excludes
  the new version. `check` verifies those requirements, constructs the crate
  archive with checkout-local patches for not-yet-published internal crates,
  enforces crates.io's archive-size limit, and never uploads, commits, tags,
  or pushes.
- `cargo xtask bpf-bench --arch=x86_64 --baseline <record.json>` — collect the
  BPF suite and compare each compatible metric with a previous green-main
  §8.8 record. `--release-baseline <record.json>` adds the cumulative
  slow-cooking check. Both comparisons require the same runner, accelerator,
  guest architecture, unit, direction, inner-iteration count, warmup, and work
  declaration. An unverified run prints only advisory diagnostics and emits no
  JSON record; a dirty source tree may emit a non-publishable record carrying
  its dirty bit so an
  uncommitted candidate cannot be mistaken for the named commit. The runner
  rejects a missing or inconsistent guest end marker, a declared/sample count
  mismatch, N below 30, and N below 100 when observed CV exceeds 5%. Guest
  `irq_masked` and `tick_reliable` flags are part of the publishability gate,
  not informational metadata, and the publication path requires exactly 10,000
  bootstrap resamples. The host observes temperature and hardware throttle
  counters for 30 seconds before launch. An explicitly allowed development run
  may print advisory statistics but emits no JSON performance record.
- `cargo xtask image --arch=x86_64 --bootloader=limine` — produce bootable ISO.
- `cargo xtask grub-image --arch=x86_64` — produce
  `target/grub-x86_64/boot/narf-frame-grub`, a direct-GRUB Multiboot2
  artifact. The canonical image build first materialises NARF's compact,
  loadable KASLR table; this compatibility artifact then removes only the
  ordinary non-loadable ELF relocation sections that GRUB rejects. The bundle
  also contains its initramfs and a mergeable `grub.cfg` stanza. On BIOS the
  stanza loads that ELF directly; on x86_64 UEFI it chainloads the bundled
  Limine EFI app from `target/grub-x86_64/esp/`, which also contains the
  canonical kernel, initramfs, and Limine configuration for installation to
  the ESP.
- `packaging/build-release.sh --version X.Y.Z [--arch x86_64|aarch64]
  [--uefi-loader FILE] [--limine-efi FILE] [--limine-tool FILE]
  [--secure-boot-key FILE
  --secure-boot-cert FILE]` — wrap the canonical architecture-specific kernel
  and bound EFI loader in native distribution packages, install an isolated
  `/EFI/NARF` payload and BLS Type #1 entry through `narf-uefi`, and emit a
  checksummed release manifest. x86_64 enrolls the exact Limine configuration
  digest and places the kernel BLAKE2b-512 digest in its boot path; it retains
  direct legacy-BIOS GRUB boot. aarch64 binds that digest into NARF's loader.
  Optional signing uses administrator/distribution inputs through `sbsign` and
  verifies the output with `sbverify`; private keys never enter package staging.
  UEFI GRUB chainloads the payload; systemd-boot, rEFInd, and CachyOS Limine
  consume their native discovery/registration paths.
- `cargo install --path build/cargo-narf` installs the optional source-tree
  frontend. `cargo narf package` drives reproducible native package generation;
  both package/install commands expose the architecture, loader, and optional
  signing inputs; `cargo narf install` delegates the resulting artifact to
  apt/dpkg, dnf/rpm, or pacman rather than writing `/boot` or the ESP directly.
- `narf-uefi install --sign-with-sbctl` explicitly opts an installation into
  the host's existing `sbctl` database key. That preference persists for
  package upgrades; `--no-sbctl-sign` removes it. The helper never creates or
  enrolls Secure Boot keys and refuses to publish an unsigned loader when
  firmware reports active Secure Boot.
- Kernel ELFs on both architectures carry a deterministic SHA-1 GNU build-ID;
  linker symbols `__build_id_note_start` and `__build_id_note_end` delimit the
  retained note for `/sys/kernel/notes`.
- The x86_64 ELF uses a 256 MiB physical load base for both PVH and
  Multiboot2. The complete load span includes `.bss`; it must avoid firmware
  reservations, not just place the entry point in free RAM. In particular,
  the Gigabyte B650I AORUS ULTRA reserves `[0x099ff000, 0x0a000000)`, which
  a production image at the former 32 MiB base overlapped. The fixed base
  also clears Secure Boot OVMF's low ACPI NVS/SMM reservations; it does not
  guarantee compatibility with every physical memory map.
- Workspace: single Cargo workspace so Global LTO spans everything.

## 4. Invariants & safety properties

- Release builds must use `lto = "fat"` across the whole workspace.
- `panic = "abort"`; no unwinding in the kernel.
- Reproducibility: identical inputs produce identical binaries
  (`-Z remap-path-prefix`, `SOURCE_DATE_EPOCH`).
- CI keeps Cargo target directories job-local and shares content-addressed
  rustc outputs through `sccache`. Cargo incremental compilation is disabled
  while the wrapper is active; registry and git sources are cached separately.
  This avoids restoring large immutable target snapshots across jobs while
  still reusing objects whose source, target, toolchain, features, and flags
  match.
- **Fat LTO + domain switches is a correctness hazard.** With whole-
  program LTO, LLVM sees the inline asm / intrinsic that writes PKRS
  (x86_64) or `SCTLR_EL1.TCF` (aarch64) as just another memory-barrier-
  less operation. It is free to sink a load across the write or hoist
  a store past it, silently observing the wrong domain's rights at
  the wrong time. This must be prevented at the source level — LTO
  flags alone cannot fix it.
- **Every domain-switch intrinsic is wrapped in an `asm!` block with
  the `"memory"` clobber** *plus* an explicit
  `core::sync::atomic::compiler_fence(Ordering::SeqCst)` before and
  after. The `"memory"` clobber alone is insufficient under fat LTO
  because LLVM can still hoist / sink pure-register operations around
  the asm block when it proves they do not touch memory — but it
  cannot prove that about a post-domain-switch load, because the
  *meaning* of the load changed. The double-fence discipline is what
  tells LLVM that correctness depends on no reorder.
- **Any inline asm that the codegen could plausibly reorder around** —
  TLB invalidations (`INVLPG`, `DSB ISHST`), cache maintenance (`CLFLUSHOPT`,
  `DC CVAC`), MMIO writes to doorbell pages, `WRMSR` to security-
  relevant MSRs (PKRS, CR3, TCR_ELx) — uses the same discipline.
  `arch/` owns the wrapper functions; callers must not reach around
  to raw asm.
- **`build/` emits the required CPU-feature flags to rustc** so the
  above intrinsics are even available. PKS requires
  `-C target-feature=+pks` (gated behind a nightly feature); MTE
  requires `+mte`. Missing flags produce a compile-time error in
  `arch/` wrappers rather than silent emit-nothing behaviour.

## 5. Architecture notes

### x86_64
- Target: `x86_64-unknown-none`.
- Linker script places kernel at `-2GiB` (kernel high-half).
- Bootloader: Limine by default; multiboot2 supported.

### aarch64
- Kernel target: `aarch64-unknown-none`; EFI loader target:
  `aarch64-unknown-uefi`.
- Linker script places kernel per platform (QEMU virt at `0x4008_0000`).
- Bootloader: U-Boot/direct FDT or the AA64 removable-media EFI loader;
  devicetree consumed by `boot/`.

## 6. Dependencies

- **Consumes:** nothing inside NARF.
- **Provides to:** everything; `xtask` is the entry point for every other
  subsystem's tests.

## 7. Stage assignment

Stage 1; extended each stage as new targets/tests appear.

## 8. Resolved decisions

### 8.1 Toolchain pinning (resolved)

**Decision:** **pin a specific nightly per kernel release**,
recorded in `rust-toolchain.toml`. Bumps happen at
each minor kernel release after CI validates the new
toolchain.

Rolling pin was rejected because nightly Rust changes can
introduce miscompiles on `unsafe` code paths (the kernel's
asm wrappers historically have caught nightly regressions).
A pinned toolchain means CI is reproducible and historical
builds remain buildable.

The pin file plus the `Cargo.lock` plus the `narf.toml` give
a fully-reproducible build from any commit.

### 8.2 Linker selection (resolved)

**Decision:** **`lld` from `llvm-tools-preview` (Rust-bundled)
as primary**, with `mold` as an opt-in for faster local dev
builds.

`lld` is what `cargo` resolves to with `-Z linker-flavor=lld`
on bare-metal targets; it handles all the relocations the
kernel uses (PIE for the loadable-driver path,
section-merging for the `narf.tests` distributed slice).

`mold` is faster for incremental dev builds but doesn't
handle aarch64 PIE relocations as completely as `lld` at the
versions we target. `mold` is allowed via `narf.build.linker=mold`
but CI uses `lld`.

`cargo-binutils` is rejected (deprecated in favour of
`llvm-tools-preview`).

### 8.3 FDO / BOLT (resolved)

**Decision:** **post-Stage-4 work, behind a build flag**.

Profile-guided optimisation flow:
1. Build a profiling kernel with `narf.build.profile_gen=1`.
2. Run the verification benchmark suite to gather profiles.
3. Build a release kernel with `narf.build.profile_use=<dir>`.
4. Optionally apply `bolt` to re-order hot functions for
   I-cache locality.

Each step is invocable from `xtask`. Stage 5 deliverable.

For v1.0 we ship without FDO/BOLT — the perf gain is nice
but not load-bearing. The mechanism is designed so it can
be turned on later without refactoring.

### 8.4 LTO reorder-hazard audit gate (resolved)

**Decision:** **mandatory CI gate** that statically verifies
`compiler_fence` wrappers are the only path to:

- PKRS write (`WRMSR IA32_PKRS`).
- TCF / GCR write on aarch64.
- CR3 write.
- TLB invalidation (`INVLPG`, `TLBI`).

Implementation: a post-link pass that walks the linked
kernel ELF, finds every `wrmsr` / `mrs` / `invlpg` /
`tlbi` instruction, and verifies it's bracketed by
`compiler_fence` wrapper functions exported from `narf-arch`.
Any direct emission outside the wrappers fails CI.

The gate is a small Rust binary in `xtask check-fence-discipline`,
run on every PR. Cost: ~5 seconds on a release-mode kernel.

This pays off every release: it catches the "developer
inlined a raw asm! to PKRS for one weird edge case"
class of regression at PR time, not at deploy time.

## 9. ABI versioning

`build/`'s outputs (the kernel ELF, the `.narfmod` artefacts,
the manifest format) define the on-disk ABI. The container
formats are versioned per their respective specs:

- Kernel ELF format: standard ELF + NARF note types
  (per `observability/spec` §8.4).
- `.narfmod`: per `drivers/spec` §5.
- `narf.toml` (workspace manifest): per `drivers/spec` §6.

`build/` itself doesn't have an exported ABI surface — it's a
build-time tool. Reproducible builds are the "ABI" guarantee:
two builds of the same commit + toolchain produce
byte-identical outputs.

## 10. Open questions

(none — all v0.2 questions resolved in §8)
