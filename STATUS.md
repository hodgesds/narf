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

## i40e recovery, RSS and offloads

The i40e runtime negotiates up to eight queue pairs with separate completion
workers/MSI-X routes, firmware VSI queue mapping and IPv4/IPv6 TCP/UDP RSS.
Checksum/TSO metadata remains supported. Automatic recovery keeps the interface
and IPC rings registered while draining users, resetting the PF and rebuilding
AQ/HMC, queues, filters, RSS and interrupts. Failed reset retains DMA; failed
rebuild retries with capped backoff. See `drivers/net/` §3.1 for resource limits,
recovery status and the aarch64 ITS steering constraint.

Memory-backed firmware, descriptor and IRQ tests cover rebuild failure/retry
and DMA ownership without resetting a host device. Physical X710 validation
remains pending; the development host is a live router.

## Phoenix native audio

Native HDA analog playback/capture and ACP 6.3 PDM microphone capture are
implemented against `/usr/src/linux`. The sound-card/PCM/mixer file surfaces
now delegate to owned hardware DMA. ACP probe requires revision 0x63, a PDM
pin configuration and ACPI microphone properties; enumeration does not start
recording. HDA routes BIOS-described analog paths and handles headphone
speaker automute. Timeout paths retain DMA until the hardware is quiescent.

Fake-device tests cover command transport, DMA accounting, capture overrun
and failed-stop retention. QEMU HDA exercises playback across buffer wrap,
capture and capability revocation. Physical Lenovo 50ee validation is pending.
The shared sound bridge implements Linux ALSA PCM/control ioctls, mmap data
and pointer synchronization, poll readiness and Linux errno translation.
An unmodified alsa-lib probe exercises HDA/VirtIO playback and HDA capture
through those syscalls, including linked pause, boundary-mode playback and
user controls with TLV/events. The implemented ALSA contract is listed in
[sound §3.1](drivers/sound/specification/spec.md#31-linux-alsa-pcm-and-control-abi).
SoundWire, HDMI/DP audio, vendor smart-amplifier quirks and system power-transition
reinitialization remain open. See
[audio's implemented contract](audio/specification/spec.md).

## Desktop audio: stock PipeWire and WirePlumber

Unmodified Fedora 43 PipeWire 1.4 and WirePlumber 0.5 run on the Fedora KDE
image and get as far as a complete audio graph. The gate that drives them,
what each of its stages establishes, and how to run it are in
[verification/data/pipewire-compat](verification/data/pipewire-compat/README.md).

Working and asserted end to end: both QEMU cards reach systemd-udevd's
database with the properties `spa_alsa_udev` requires (`SOUND_INITIALIZED`,
`ID_PATH`, PCI identity from hwdb); the desktop user opens the nodes;
WirePlumber attaches as a second process over the PipeWire protocol and builds
ACP card profiles (five on HDA, three on VirtIO), selects a best profile,
finds HDA's hardware volume control, activates analog input and output routes,
exports a sink per card plus a source, and sets the default sink and source.
`wpctl status` lists them as a desktop would see them.

Five Linux-ABI defects found by that path are fixed:

- `/dev/snd/*` owner, mode and ACL now live on the devtmpfs NODE rather than
  the per-lookup `FileOps`, and the nodes are published root-owned at 0600 as
  `sound/sound_core.c` plus `drivers/base/devtmpfs.c` do. udev's `GROUP="audio"`
  chown was previously discarded, so every non-root ALSA client reported "no
  soundcards found" and no desktop session could play a sound.
- `/proc/<pid>/root` is rendered in the READER's root frame, as Linux
  `d_path()` does. The stored prefix is host-view, so a chrooted reader —
  which is every process in this image — was handed a name that resolved to
  nothing.
- `/proc/{self,<pid>}/{root,cwd,exe}` are FOLLOWABLE at `open` and at a path
  `stat`, trailing slash included, and a `stat` whose symlink target leaves
  its own filesystem now crosses the mount the way `open` already did. An
  absolute magic-link target restarts at the owning filesystem's mount root,
  so the walk never left procfs. PipeWire's access module opens
  `/proc/<peer-pid>/root` to look for `.flatpak-info` and reads a failed open
  as "this client is sandboxed", so every client hung at connect. The same
  shape through devtmpfs also made `/dev/fd/<n>` unresolvable, which is how
  bash implements process substitution (`cmd < <(other)`); the VFS expansion
  now stops at a proc-fd magic link instead of expanding its readlink TEXT,
  which for an anonymous descriptor is `pipe:[12345]` and names nothing.
- `/proc/<pid>/task/` is named by thread id instead of repeating the group's
  pid once per thread, and each thread directory now carries a per-thread
  `stat` and a per-thread, writable `comm` (0644, as `tid_base_stuff` has it).
  Together that is what `ps -L` and `top -H` read, and what glibc's
  `pthread_setname_np` writes: the gate sees seven distinctly named
  WirePlumber threads where before procps aborted with "fatal library error,
  reap".
- HDA advertises only the formats its codec reports. `capabilities()` returned
  a fixed `S16_LE | S32_LE` while `configure_paths` enforced the converter's
  `AC_PAR_PCM` word, so on a 16-bit-only codec — QEMU's hda-duplex among them
  — `HW_REFINE` offered S32_LE and `HW_PARAMS` then rejected it. alsa-lib
  cannot recover from that: PipeWire negotiates the widest format on offer and
  its ALSA node dies with `set_hw_params: Invalid argument`, leaving a sink
  that never takes a quantum. The format set is now queried once at probe,
  from the same word the enforcement reads.

One defect remains open, and the gate reports it on every run rather than
failing on it: **WirePlumber's main thread burns ~100% of one CPU once the
graph is built**, while the PipeWire daemon stays at 0% and every functional
stage passes. The vDSO monotonic clock, `poll`/`epoll` blocking semantics,
`POLLERR`/`POLLHUP` handling, poll-over-epoll with GLib's exact mask,
level-not-cleared-on-consume for eventfd/socketpair/timerfd, ALSA control-fd
readiness, and GLib itself (a bare `gdbus monitor` idles at 0%) have all been
measured in-guest and ruled out; it produces no log output at trace level, so
it is a silent dispatch loop. Narrowing it further wants a tracer, and
`strace -p` cannot attach because `wait4(__WALL)` does not consider a ptrace
tracee that is not a child. Those two are coupled and the ptrace/wait4 gap is
the next step. Details and the full elimination list are in
[verification/data/pipewire-compat](verification/data/pipewire-compat/README.md).

## USB-C and Phoenix USB4

UCSI ACPI connector discovery, firmware state notifications, per-NHI native
USB4 config rings/topology and USB3/DP tunnel programming are implemented
against `/usr/src/linux`. Native ownership requires ACPI `_OSC`; PCIe and
XDomain control are not requested. DP tunneling currently supports one RBR
path per domain, and native USB4 system suspend/replay remains unsupported.
Memory-backed tests exercise DMA ownership, acknowledgements, path drainage
and rollback without touching host devices.

The AMD DCN 3.1.4 DMUB transport can attach to running DAL firmware for HPD,
AUX and EDID discovery. Firmware preparation now selects the DCN314 blob
from IP discovery, validates DMCUB containers and metadata, separates PSP
packaging, and stages a bounded seven-window image in RAM. An explicit
direct-load lifecycle now reserves from caller-owned VRAM, stops DMCUB,
uploads/flushes the image, programs cache windows and validates boot readiness.
Failed stop/cancellation retains memory until shutdown is verified. Loader
ownership excludes the attach worker, firmware replacement and suspend.
GPU probe now retains a bounded, device-matched VBIOS snapshot from ACPI VFCT
or the APU VRAM shadow, using corrected PCI/ATOM header and directory parsing.
DMUB preparation can consume that snapshot. An explicit boot-memory path now
builds a pool with permanent exclusions from VBIOS reservations, current DMUB
windows and caller-supplied boot/client ranges; it never infers ownership
from BAR capacity.
A Phoenix PSP 13.0.4 GPCOM ring now installs the TMR and loads DMCUB through
the PSP, leaving the secure instruction and stack windows under PSP ownership;
Phoenix rejects the legacy firmware-load helpers so nothing races that ring.
The boot handoff assembles the owner: it records the boot framebuffer geometry,
refuses a GPU with live firmware, a live mode or any VM context, inventories
every enabled linear-RGB surface and cursor including latched and draining
addresses, and rejects DCC/YUV/stereo layouts rather than overlooking metadata.
The Late worker takes this owned path when it succeeds and otherwise falls back
to attaching to running firmware.
DisplayPort link training and the DIO link encoder are implemented: async
8b/10b clock recovery and equalization program source and sink as one
transaction, fall back only on recovery/equalization failure, clamp lanes to
the reported Type-C pin assignment, and leave a transparent USB4 DPIA to train
its own remote PHY.
The DCN314 stream pipeline is now implemented end to end. A fixed-point port
of DML derives the detile geometry, the required clocks, the urgent, p-state and
stutter watermarks and the prefetch schedule, and encodes them into the HUBP
request, latency and throttle registers, refusing any value a field cannot hold.
The display clock manager latches the firmware's own DPM table and applies
clocks in Linux's order; the clock generator divides them per pipe and routes a
tunnelled stream's clock. The timing generator, hub pixel pipe, DPP, combiner,
output formatter and DisplayPort stream encoder are all programmed, and a
bring-up sequence drives them in the enable-stream order, trains the link, and
unblanks the pipe, encoder and formatter last. A completed stream publishes its
scanout for the framebuffer layer to adopt.
The platform inventory the sequence needs is now read from the platform's own
tables: the display topology and each connector's transmitter and hot-plug line,
the memory type, channel count and data rate, the DCHUB reference clock and the
DENTIST VCO. None of it is defaulted — the memory configuration multiplies into
every watermark and the reference clock scales every latency register — and a
table that is missing, the wrong revision or self-inconsistent fails closed. A
native DisplayPort route is derived and validated against the board rather than
trusted from the sink's index.
The Late worker now arms the bring-up once per boot for the first native
DisplayPort sink the board can answer for, claiming only a pipe that is blanked
with its timing generator stopped and zeroing the surface before any pixel is
sent. A failure leaves the display alone and falls back to the previous
attach-only behaviour; suspend stops the stream before the firmware.
Tunnelled USB4 sinks are driven too. A tunnelled link has no board-wired
transmitter, so one is borrowed from the five DIGs, preferring those the board
wired to no connector; a wired transmitter is still usable while its own
connector is idle, which the backend enable bit decides rather than a guess.
A tunnelled stream negotiates its host router's bandwidth before the link comes
up, rounding a request up to a whole allocation step and refusing a mode the
tunnel cannot carry rather than clamping it down to a starved allocation; the
bandwidth is handed back when the stream stops. The console follows a lit external
display through an observer the framebuffer layer installs, and returns to the
boot framebuffer when the stream goes away. A stream survives suspend: the mode it
was validated for is retained and replayed on resume, with the clock levels
re-latched and the surface re-cleared.
**The one remaining gap is silicon.** Physical Lenovo 50ee USB-C/USB4 validation
is pending; nothing in this path has run on real hardware, so the watermarks,
deadlines and link training are unconfirmed.
See the USBPD, Thunderbolt and GPU subsystem specifications for the supported
interfaces and limits.

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
- **Runtime modules:** xtask builds and stages a real rustc `.ko`; the kernel
  smoke stamps the live export-table ABI, resolves the compiler's native
  relocation against `narf_printk`, executes init/exit in the declared
  `target_domain`, and unloads it. Production policy verifies a fixed
  Ed25519-over-BLAKE3 trailer against build-time public keys; unsigned modules
  require an explicit developer/CI feature. Versioned LZ4 module envelopes are
  bounded to 32 MiB and authenticated before decompression. The SMP unload
  grace period remains open.
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
   MSI-X completion delivery, active/passive scans, Open/WPA2-PSK association,
   CCMP replay protection and pairwise/group rekey, WMM/four AC rings,
   HT20/40 and VHT20/40/80 negotiation (up to two spatial streams),
   firmware rate adaptation and TX A-MPDU completion, RX Block Ack
   negotiation/reordering, standalone RX A-MSDU deaggregation,
   TX queue backpressure, and kernel Ethernet
   routing. Software regressions cover wire layouts,
   malformed completions, DMA ownership, authenticated EAPOL retries,
   channel-span limits, BA sequence wrap and replay checks after reordering.
   Delegated nl80211 scan/connect controls and signed deployment regulatory
   policy loading are wired in, with build-time public-key provisioning
   and detached-signature firmware packing. Explicit network-service launch
   now delegates interface authority before the process runs, including to
   its ordinary netlink sockets and forked children, while preserving IP
   frame ownership. Boot service selection, silicon validation and real
   supplicant interoperability remain open. See
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
