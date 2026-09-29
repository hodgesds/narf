# NARF status

This page tracks milestone progress and the boundaries of its proof.
Subsystem specifications define the contracts; run the commands below for
current test results.

## Stage progression

| Stage | State | Evidence and limit |
| --- | --- | --- |
| 1 · Skeleton | Closed | x86_64 and aarch64 QEMU boot, serial output, executor, and timer work landed. |
| 2 · Barrier | Closed for the original PKS/MTE path | Domain switching and fault tests landed. Later PCID fallback coverage is tracked separately. |
| 3 · Flow | Composition gate met | `smoke_exit_gate_buffer_handoff` and `smoke_exit_gate_revoked_cap_rejected` exercise the ring, DMA buffer, and capability path. They are not a proof that a real VirtIO device transfers a protected buffer across domains on both architectures. |
| 4 · Compatibility | In-tree shell gate met; compatibility continues | Interactive `echo hello world` follows serial IRQ → input ring → shell → UART. Linux-compatible musl programs, storage, networking, and graphics have additional QEMU proofs. The original relibc-specific criterion is not the closure proof. |
| 5 · Silicon | In progress | Driver and diagnostic foundations exist; the selected AMD laptop end-to-end gate has not been demonstrated. |

## Exercised paths

- **Kernel on QEMU:** `cargo xtask run` and `cargo xtask test` support x86_64
  and aarch64. The suite reports pass, fail, and skip totals at exit.
- **Interactive userspace on x86_64 QEMU:** `cargo xtask run-interactive`
  exercises the in-tree shell and coreutils. The musl demo harness covers
  Linux syscall and device ABI cases; `oci_smoke` exercises the container
  path. A dynamically linked Alpine BusyBox has also run from an ext2 rootfs
  under `chroot`; that rootfs is generated locally and is not an automatic CI
  case. See [docs/PERSONAS.md](docs/PERSONAS.md) and
  [docs/DESKTOP_LINUX_PLAN.md](docs/DESKTOP_LINUX_PLAN.md).
- **Storage and network on QEMU:** NVMe, virtio block and network, and
  several emulated PCI NIC paths are in-tree. The block registry, VFS,
  ext2/Btrfs implementations, TCP/UDP stack, and Linux-facing file and
  socket interfaces are implemented. Individual device and filesystem
  coverage depends on the attached QEMU profile and test case.
- **Graphics on x86_64 QEMU:** `/dev/fb0`, evdev, DRM/KMS modesetting,
  libdrm, and a multi-client Wayland path have runnable demonstrations.
  VirtGPU VirGL ioctls and presentation paths are implemented in-tree;
  this does not establish native AMDGPU display on a laptop.
- **Boot media:** `cargo xtask image` builds boot media and `iso-boot`
  checks UEFI boot in QEMU. These are distinct from a successful USB boot
  on the target laptops.

## Isolation and hardware limits

- x86_64 selects PKS when available and otherwise has a PCID page-table
  backend. PKS fault tests run under suitable QEMU configurations. PCID's
  confined-slot policy has structural tests, but the PCID enforcement path
  has not run on the available hardware runners. See
  [docs/DOMAIN_BACKENDS.md](docs/DOMAIN_BACKENDS.md).
- aarch64 has MTE paths and tests. Without MTE, its planned page-table
  fallback is not installed, so boot can continue without domain enforcement.
- Domain protection applies to resources correctly mapped or tagged for a
  domain. Untagged or shared ordinary kernel memory is not automatically
  confined. The Stage 3 composition smokes therefore must not be read as an
  end-to-end isolation proof for every device buffer.

## Current work

1. **Stage 5 laptop proof:** boot from USB on Renoir/Lucienne or Phoenix
   HawkPoint1; exercise native AMDGPU modeset, keyboard and touchpad,
   Wi-Fi, and persistent NVMe storage. AMDGPU, ACPI EC, I²C-HID,
   wireless, TSC calibration, and framebuffer diagnostics have foundations
   in-tree, but the complete gate remains open.
   The iwlwifi Sc/BE211 work now includes an MLD station path with owned
   firmware/PNVM boot DMA, RFH receive rings, command/data TX queues,
   passive scans, Open/WPA2-PSK association, CCMP key/replay handling,
   and kernel Ethernet routing. Software regressions cover wire layouts,
   malformed completions, DMA ownership and authenticated EAPOL retries.
   Delegated nl80211 scan/connect controls and signed deployment regulatory
   policy loading are wired in, with build-time public-key provisioning
   and detached-signature firmware packing. Automatic wireless-daemon
   launch/delegation, silicon, and userspace-tool interoperability remain
   unfinished or unverified. See
   [the implemented driver contract](drivers/wireless/specification/spec.md#31-implemented-iwlwifi-mld-station-profile).
2. **Compatibility and desktop:** extend tested Linux ABI and graphical
   application coverage on QEMU. Use runnable cases in
   [docs/DESKTOP_LINUX_PLAN.md](docs/DESKTOP_LINUX_PLAN.md) and the feature
   boundaries in [docs/PERSONAS.md](docs/PERSONAS.md), rather than treating
   the Stage 4 shell result as full Linux compatibility.
3. **Isolation validation:** run PCID and real-device cross-domain tests on
   capable hardware, and complete the non-MTE aarch64 fallback if that
   platform is to claim enforced domains. The backend-specific limitations
   are recorded in [docs/DOMAIN_BACKENDS.md](docs/DOMAIN_BACKENDS.md).

## Reproduce the main checks

```sh
cargo xtask run --arch=x86_64
cargo xtask run --arch=aarch64
cargo xtask test --arch=x86_64
cargo xtask test --arch=aarch64
cargo xtask run-interactive --arch=x86_64 --cmd "echo hello world" --expect "hello world"
cargo xtask musl-demo --arch=x86_64
cargo xtask iso-boot --arch=x86_64 --release
```

The musl demo cases may need generated binaries and rootfs images; see
[docs/RUNNING_ON_LINUX.md](docs/RUNNING_ON_LINUX.md) and the scripts under
`verification/data/musl-demo/`. For build, formatting, and review gates,
follow [process/specification/spec.md](process/specification/spec.md).
