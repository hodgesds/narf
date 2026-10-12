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

## Loadable e1000 datapath

The copy-mode module ABI now has an exclusive live-wire proof. `cargo xtask
e1000-module-net-smoke --arch=x86_64` builds and ABI-stamps `e1000.ko`, stages
it in the initramfs, loads it into the operator-selected `driver2` frame before
PCI probing, and suppresses the built-in e1000 registration for that fixture.
The module-owned QEMU 82540EM passes host-to-guest TCP and UDP echoes plus a
guest-originated DNS query through SLIRP. The ordinary kernel-test module suite
continues to cover load/unload, capability gates, domain placement, DMA handle
lifetime, and deterministic descriptor injection.

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
it is a silent dispatch loop. Narrowing it further wants a tracer. A tracer is
now eligible to wait for a tracee it did not fork, but the tracee's attach-stop
is never reported to it, so `strace -p` blocks in `wait4` instead of answering
`No child processes` — reporting that stop is the next step. Details and the
full elimination list are in
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
- **Native UEFI installation:** x86_64 and aarch64 native packages install an
  isolated `/EFI/NARF` payload plus a Boot Loader Specification entry. CI boots
  the x86_64 package through OVMF, installed-style GRUB, config-bound Limine,
  and its hash-bound kernel; AAVMF boots the aarch64 package through NARF's
  kernel-bound loader. Secure Boot CI enrolls an ephemeral certificate, boots
  the signed x86_64 chain, and requires a one-byte kernel modification to be
  rejected. GRUB, systemd-boot, rEFInd, CachyOS Limine, distribution signing,
  and persistent local `sbctl` signing are implemented without changing UEFI
  NVRAM or the host's default entry. Production key enrollment, rotation, and
  revocation remain administrator/distribution policy.

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

The `feat/amdgpu-navi48-bringup` branch targets RX 9070 XT / Navi48, the
leading named AMD card in the September 2026 Steam PC survey (1.42%). PCI
`1002:7550` has distinct RDNA4 identity, discovery-checked IP selection,
separate physical/CPU-visible VRAM accounting and SMUIO14 ROM access. Legacy
APU/engine/display paths refuse this generation before touching hardware.

Implemented: GDDR6 training; PSP14 SOS/GPCOM/TMR; mandatory graphics/media
firmware parsing, upload and autoload; GC12 RS64 counter programming and pipe
reset with inherited-queue exclusion; SMU14 board-table transfer and initial
GFX/thermal policy; GC12 harvested CU/SA/RB inventory and device-query reporting;
GMC12/MMHUB4.1 owned VMID0 translations; SDMA7 translated
VRAM write/copy/fence verification; and DCN4 DMUB shared state, authenticated
window validation, startup and version/capability/HPD/AUX mailbox support.
GC12 setup now retains the native RLC clear-state image, applies ASIC-revision
golden settings, configures VMID0 shader/context controls and starts RS64
processors with inactive-queue checks and bounded idle confirmation.
DCN4 board routing reads ATOM v1.4/v1.5, preserves distinct AUX/HPD/transmitter
identities and bounds the four channels using DCN4 backend register geometry.
The retained owner supports native DP/eDP DPCD/extended-capability and complete
segmented EDID discovery, including bounded DEFER retries, per-port errors and
cancellation quarantine. HDMI now reads complete segmented EDID through DCN4's
native I2C arbitrator/FIFO with board-resolved DDC pins, 100 kHz clock setup,
fresh completion checks and bounded waits. Terminal sink errors restore pins
and release ownership; uncertain failure/cancellation blocks reuse and raw AUX.
Native link/scanout programming remains open.
The retained DCN4 clock owner now validates its separate DAL mailbox, queries
native clock ranges and applies checked DISP/DPP/DTB floors with both mailbox
and per-clock completion acknowledgements. It pins DCF/UCLK conservatively,
disables UCLK switching, preserves thermal protection and rejects every live
legacy/HPO/FRL display consumer before changing DPM, including timing generators
whose disable request is not yet acknowledged. Partial transitions and
cancellation retain state without replay. Platform clock preparation is
serialized after the kernel engine proofs. Native DCCG now prepares all four
DPP dividers, DPREF-derived DP pixel DTOs, DTB-derived FRL DTOs, and TMDS
dividers with the bounded DENTIST FIFO workaround. Matching global clocks,
retired consumers and readback are required; partial failures retain ownership
and block global-clock changes. Native HPO DP/FRL stream-clock routing now
requires matching current pipe clocks and divider readback, preserving each
DTO's reference. Reprogramming a pipe first parks all actual routes feeding
from it, including inherited routes. Native OTG now prepares disabled fixed
progressive RGB timing on all four pipes, with matching live pipe clocks,
clock-on acknowledgements, native HPO routing, odd-timing divider handling and
PSTATE/global-sync fields. Timing retirement disconnects ODM and requires both
current-master and busy acknowledgements. Partial/cancelled transitions retain
ownership and block clock changes; timing retirement never releases scanout
memory. The retained timing owner also stages native OPP full-range RGB
formatting at 8/10/12 bpc and a black DPG pattern, clears inherited color offsets,
and requires OPP clock acknowledgement. It records pending double-buffer state
without claiming active blanking while timing is disabled. An explicit internal
black-timing start now requires positive stopped-fetcher witnesses on every
HUBP and live clock/timing/formatter readback. Native VTG-before-OTG sequencing
waits for current-master acknowledgement, blank-buffer latching and a fresh
frame-counter transition under one bounded deadline. Running timing blocks
clock changes until acknowledged retirement; failure/cancellation quarantine
the owner and retain every scanout allocation. TMDS still needs a native PHY
PLL proof. Native inherited-plane retirement now disconnects all MPC routes,
waits for MPCC/HUBP drain, blanks powered planes and disables their fetch clocks.
Already-off HUBPs require native PGFSM acknowledgement and remain untouched.
Blank startup accepts native TTU behavior and checks the independent 3D-LUT
fetcher. Pending flips, synchronization, metadata/LUT loads and uncertain power
states block retirement before writes; failure/cancellation retain resources.
Native HUBP DOMAIN0–3 power transitions now require a fully stopped, detached
display tree. The retained owner brackets each gate request with DC IP request
ownership and waits for PGFSM acknowledgement before touching a powered-on
HUBP. It initializes that HUBP to blank/drained readiness with its fetch clock
disabled; power-off requires fresh drain evidence. Pending fetch transactions,
uncertain power, lost writes and cancellation block reuse. All backing memory
stays retained. Surface/VM/bandwidth preparation and framebuffer scanout remain
open; these power transitions still require validation on the physical card.
Native DCN4 surface staging now allocates and retains linear XRGB/XBGR8888
framebuffers, clears row/page padding cooperatively, and programs native pitch,
format, crossbar and viewport fields. Address publication follows an HDP flush
and writes the high address before the low flip trigger. Fetch stays blank and
drained; a pending flip is not reported as completed scanout. Bounded row uploads
check live configuration and flush CPU writes. Partial failures retain published
backing and block reuse. DCN VM/apertures, bandwidth/deadline/watermark programming,
DPP/MPC composition and visible framebuffer activation remain open.
Native legacy/HPO DisplayPort stream blanking now waits for actual video-stop
acknowledgement before resetting or disabling FIFOs. It handles inherited
disable-in-progress state, keeps timing and link clocks available for PHY
retirement, and quarantines the owner on timeout, failure or cancellation.
Native DP frontend retirement now shuts down blank DIO/HPO encoders and waits
for their clock-off witnesses. DIO retirement checks real backend routes,
requires connected backends stopped and removes only the selected frontend
bits; unrelated live outputs stay untouched. Clock programming now rejects
enabled frontends/FIFOs and outstanding frontend/stream clocks even when video
is blank. Active packet/metadata work blocks retirement, and partial failures
or cancellation retain all resources. Direct external legacy DP SST now has a
board-routed DMUB v1.7 transmitter-disable path. It preserves the frontend until
firmware clears backend enable and clock-on witnesses, then clears training and
panel state. Invalid routes, active packet/FEC work and independent HPO/FRL links
reject before commands. Failure/cancellation retain display and transport
ownership and block reuse; backend clocks independently block clock programming.
This proves digital backend-off, not analog PHY power gating. Native HPO digital
link retirement now resolves the board PHY mux, independent stream mappings and
root-clock source, requires all mapped streams stopped, drains all six timeslot
rows with ACT and waits for DPHY and link-clock shutdown acknowledgements.
Ambiguous routes, active work and unsupported modes reject before writes;
partial failures and cancellation quarantine the owner. A separate direct HPO
DP PHY shutdown now sends native DMUB v1.7 DISABLE with explicit SST/MST signal,
requires all four lanes disabled with data/clock/handshake activity clear and
TX-clock-off readback, then parks only the selected root-clock route. Shared
PHY/root routes and live digital work reject before commands. Failure or
cancellation retains ownership; lane/TX activity independently blocks global
and pipe clock changes. These checks still require silicon validation and do
not prove analog power gating. Native TMDS HDMI frontend retirement now clears
all 15 generic packet schedules, acknowledges their buffered updates, resets
stream attributes and stops the FIFO/frontend with DISPCLK/SYMCLK/TMDS clock-off
witnesses before disconnecting selected routes. Live audio/metadata, ambiguous
routing and pending transactions reject before writes; failures and cancellation
quarantine the owner. Backend/PHY/OTG clocks stay retained for the TMDS timing
symclk dependency. A separate TMDS timing-retirement operation now requires
all frontends detached, validates stable TMDS backend/PHY state, stops one OTG,
clears latched underflow and acknowledges its OTG/input clocks off. It preserves
other timing generators and every PHY; fresh consumer checks remain mandatory
before transmitter shutdown. Failure/cancellation retain and quarantine the owner.
Direct external TMDS transmitter shutdown now checks all timing and frontend
consumers stopped, parks only frontend symclk routes using the selected PHY,
and sends the native HDMI DMUB DISABLE command. Independent hardware witnesses
must acknowledge backend, all four lanes and TX clocks stopped; mailbox
consumption alone cannot complete shutdown. Already-disabled backends require
complete off readback without replay. Other outputs stay retained, late route
or consumer changes fail, and failure/cancellation block owner reuse. This
proves digital/lane/clock shutdown, not analog power gating or memory retirement.
Native FRL frontend retirement now drains all generic packet schedules through
the actual HDMI/VUPDATE buffer status, disables FIFO then tribyte encoding and
requires all three stream clocks off. Native DME4, immediate packets, audio/ACR,
reset state and input/clock routes are checked before writes and across waits.
Already-retired streams stay untouched; failures and cancellation quarantine
ownership. Link/PHY/timing, general-control configuration and independent
AFMT/VPG owners remain retained. Shared clock guards now include FRL clock-on
and reset state plus digital-link enable/reset/clock activity.
Native FRL digital-link retirement now resolves the unique board PHY route,
requires a stopped frontend and matching character/forced-clock routes, selects
zero training patterns and disables the link with acknowledged clock-off before
restoring compression. Partial inherited shutdown, shared routing and late
producer/configuration changes reject; failure/cancellation quarantine ownership.
PHY output, root clocks, timing and unrelated outputs stay retained. The FRL
character-clock root independently blocks shared clock changes after link stop.
Direct external FRL PHY shutdown now uses the native firmware FRL mode and
requires all four lane-disable and TX-clock-off witnesses before parking the
character-clock root. Shared PHY clock consumers, unacknowledged DTOs, TMDS
timing and pending transitions reject before commands. Live DTB/DPREF timing,
forced input clocks and other outputs remain retained. Already-stopped PHYs
skip firmware replay; late changes, failure and cancellation quarantine the
owner. This proves lane/clock shutdown, not analog power gating or memory reuse.
Direct external legacy DP SST now has a native untrained PHY enable operation
with 1/2/4 lanes at RBR through HBR3, after matching applied display clocks.
Native backend setup and board HPD/mux routing precede firmware ENABLE.
Independent physical lane, TX-clock and backend-clock witnesses are required;
lane reversal is supported and unused lanes must remain disabled. A matching
shutdown operation verifies this owner's unchanged untrained PHY and waits for
backend/lane/clock stop before cleanup. Active consumers, stale routes and
incomplete hardware transitions reject; cancellation/failure retain ownership
and block replay. Model tests cover routes, rates, lane mappings and failures.
Native direct DP SST training now requests and verifies sink D0, reads live
base/extended capabilities and drives source TPS1/TPS2/3/4 plus matching sink
training over the board AUX channel. Firmware applies uniform clamped voltage/
pre-emphasis requests; bounded CR/EQ loops require every active lane and interlane
alignment. Source/PHY checks and fresh sink configuration/power/link status after
5 ms of native idle prevent stale completion. Matching trained-link shutdown
acknowledges sink D3 before PHY retirement. Cancellation/failure retain ownership
and block replay; known CR/EQ failures exit training when transport remains sound.
Model tests cover routing, patterns, rates, lane counts, adjustment/retry limits,
every await cancellation, lost writes and late changes. No native scanout or
silicon validation is claimed. Automatic rate/lane fallback, LTTPRs, MST/FEC,
fixed-drive retimers and board-specific SSC control remain open.
Native blank legacy DP frontend setup now uses independent OTG/frontend/PHY
routes, RGB MSA attributes at 8/10/12 bpc, DPREF-derived pixel packing and native
frontend/FIFO reset acknowledgements. It checks retained live clock references,
source/OPP state and fresh sink lock before reporting readiness. Matching
frontend shutdown waits for clocks off before detaching routes and returning
to the trained link; cancellation/failure retain ownership and block replay.
Native legacy DP black video now starts the matching staged OTG/OPP pattern,
requires fresh frame progress, seeds M/N and follows steering/video/resync FIFO
startup with native priming delays and independent acknowledgements. Fresh sink
lock, source/route/clock checks and subsequent frame progress precede completion.
All memory fetchers stay stopped. Matching shutdown waits for video-off before
steering reset and native timing retirement, then returns to the prepared
frontend for restart or link shutdown. Failure/cancellation quarantine the
owner and retain resources. Model coverage includes all independent routes,
lost acknowledgements, stalled frames, late changes and every async phase.
Physical output remains unvalidated; native surface scanout remains open.
eDP, remaining sink/MST/audio teardown and USB-C/ACPI PHY interlocks still need
their sequences. Remaining PHY/link and plane programming, surface scanout
enable, active-stream transitions, bandwidth/watermarks and complete native
modesetting remain open. Implemented paths have model tests, not silicon validation.
MES12 now has separate eight-byte-aligned command and MQD builders, kernel queue
map/unmap packets and two-fence completion/error decoding, checked against Linux
C layouts. Its retained unified-firmware owner starts both pipes, configures
PCIe BAR2 doorbells, maps the scheduler through KIQ and verifies native command
completion plus full ring drain. The boot sequence includes this firmware-queue
handshake; it grants no application queues or user VMIDs yet. Native kernel
graphics and compute MQDs now map through the scheduler and execute bounded
WRITE_DATA proofs into the two owned translated VRAM pages, requiring confirmed
fences, complete 32-bit RPTR drain and all expected data words. Cancellation
and failure retain all published queue memory and prevent replay.
Native OSSSYS7 interrupt rings now retain their own VRAM, reject inherited
writers before training, and initialize after GMC. Bounded fair draining
decodes full SOC21 vectors, handles wraparound and detects overflow before
acknowledging entries; errors quarantine backing and stop owned writers when
authority permits. The final boot handoff now transfers IH to an independent
async service, so display work cannot block draining. A checked x86 MSI route
uses the actual APIC ID, enables delivery after handler/config readback, and
retains uncertain routes/vectors. The service snapshots IRQ counts before
draining and uses a watchdog; unsupported routing uses timer-driven polling.
ARM hardware MSI awaits real ITS ITT backing. Bounded diagnostic history records
evictions and sticky VM-fault data; it does not complete user fences.
An executor task now follows boot with native graphics/compute RELEASE_MEM
proofs, requiring a fresh fence, full RPTR drain and exactly one matching
kernel-context EOP vector per queue. Configured MSI additionally requires CPU
delivery for each proof; polling is reported separately. Faults, cancellation
and missing evidence leave retained diagnostic state and prevent replay.
This path has software models; physical MSI delivery remains unverified.
After both GC12 proofs drain, the same executor task now verifies SDMA0's native
fence/TRAP path. It requires fresh fence memory, matching hardware/writeback
RPTRs, exactly one kernel SDMA0/queue0 trap and CPU delivery for configured MSI.
The service owns SDMA trap enables and masks them after recognized faults;
raw-history eviction cannot erase the completion count. Diagnostics retain
the separate SDMA interrupt result, including failure/cancellation state.
Negative models cover missing evidence, wrong contexts, revoked authority and
cancelled submissions; this adds no application submission or recovery API.
The independent service now arms native VMID0 protection faults in both hubs
and the owned graphics/compute command exception sources. It decodes VM fault
addresses and queue identities, snapshots hub status before acknowledgement,
and masks owned sources after a fault. Typed diagnostics survive raw-history
eviction, and VM or command faults prevent the EOP proof from succeeding.
Setup/MMIO/revocation failures retain uncertain owners and mask CPU delivery
where possible. No fault replay, automatic reset or allocation reuse is implied.
The boot coordinator retains all hardware owners through failures and
cancellation. The final framebuffer handoff selects Navi48, blocks legacy
controller/PM access after preparation and quarantines the primary framebuffer
on incomplete startup. Read-only preparation failures restore CPU writers.

Still open: physical MSI delivery verification, remaining SDMA/shader/media/poison
fault-source dispatch, GC12 rendering and shader
dispatch, production GPU VM and userspace submission, VCN5 video queues, native DCN4 clock/bandwidth/link
and scanout programming, reset/suspend/resume, and physical RX 9070 XT testing.
The verified DMA proof covers only two kernel-owned VRAM pages. The driver
continues to report acceleration unavailable; model/QEMU tests do not prove
working silicon, native modesetting or Mesa/Vulkan support.

Current main includes discrete PCIe probe support
for RX 6750 XT / Navi 22: bounded discovery reads beyond BAR0, separate total
and CPU-visible VRAM sizes, Resizable BAR-independent APU identity, and the
Navi 22 userspace family query. The `navy_flounder_sos.bin` parser and an
explicit PSP 11.0.11 asynchronous bootstrap now handle KDB/SPL/system/SOS
using owned, aligned VRAM with cancellation quarantine. The PSP11 GPCOM ring
now resolves Navi22's register banks and GMC10 address ranges, installs trusted
memory from the SOS container's embedded TOC, and preserves device-owned
reservations through cancellation or failed teardown. A bounded SMC v2.0 parser
now separates microcode from PowerPlay metadata; the ring can load that SMC
once after TMR setup. An explicit SMU11 cold-start handshake checks Navi22's
interface and running firmware version using its discrete-GPU mailbox layout.
The graphics firmware path now prepares the complete SDMA/CP/RLC set, separates
MEC jump tables and RLC subimages, and submits PSP autoload only after all
required payloads complete. Partial load failures/cancellation prevent replay
and preserve device-owned VRAM. A bounded CP-idle/RLC-boot-complete check now
follows PSP acknowledgement and retains raw status for failed-boot diagnostics.
An explicit `ColdBoot` session prepares all required firmware, owns the entire
SOS → PSP/TMR → SMC/SMU → graphics/RLC sequence, and can transfer its live PSP
owner after success. Failure/cancellation records the stage and prevents replay.
Navi22 now has a read-only GMC10/DCN3.0 VRAM plan, including full-aperture
firmware tails, inherited DMUB windows and the two GDDR6 training exchange
buffers. It validates the two address translations and clips exclusions only
when creating the CPU-visible allocator; secondary GPUs need no boot framebuffer.
An explicit GDDR6 cold-training owner now preserves the affected 32 MiB of
VRAM, honors PSP runtime training policy, waits with a three-second deadline, restores only after terminal PSP
completion, and validates/caches the P2C result. The firmware coordinator can
run this before SOS; cancelled/failed training prevents replay and retains the
preimage. CPU framebuffer writers must remain stopped during this path.
Probe now retains a validated Navi22 VBIOS from the SMUIO ROM read registers
when VFCT has no image, preserving the index latch and checking authority per
chunk. This supplies the board's reservation metadata without enabling a PCI
ROM BAR; acquisition failures are identified on the console.
The Navi22 pool plan now inventories all six DCN3.0 pipes and rejects inherited
active GFXHUB/MMHUB contexts. The cold-boot session owns its register metadata
and can run after releasing the controller spinlock, including in a spawned task.
The final boot framebuffer initcall now prepares and runs the firmware sequence
after firmware discovery, before executor/userspace startup. It pauses console
and pump writes, retains the entire owner, and quarantines the primary
framebuffer after a started failure. A successful claim excludes legacy MMIO
access while retaining DRM identity queries. Navi22 refuses the APU suspend
path until a discrete resume sequence exists.
Board PowerPlay preparation now selects the VBIOS or SMC table according to
FirmwareInfo, overlays the ATOM board wiring and applies the exact ASUS C3
quirks before startup. After the SMU handshake, the boot sequence uploads that
table through an owned, flushed VRAM buffer and retains the published buffer
across success, rejection and cancellation. PSP SCPM ownership or malformed
runtime policy refuses this transfer before SMU commands; policy delegation
is not implemented.
After RLC boot, the coordinator now runs board calibration and enables a
restricted GFX DPM policy with firmware power/current/temperature protection
and automatic fan control. It verifies the enabled feature mask and reports
the board's GFX frequency limits. Missing protections fail preflight; unexpected
enabled features, rejection or cancellation prevent further bring-up/replay.
Memory/display/link DPM and deep power states remain disabled until their
owners can supply display and lifecycle constraints.
The required firmware set now includes VCN and DMCUB. PSP receives those after
RLC autoload, and their reported entry addresses must lie inside the retained
TMR. Missing/malformed media images prevent startup before device writes;
partial upload failures preserve ownership and prevent replay. Firmware load
does not yet start VCN queues.
Production cold boot now initializes GC/MMHUB VMID0 with a bounded VRAM-only
test aperture after the protected power policy is active. Both hubs validate
idle contexts and matching framebuffer geometry, use owned VRAM page tables
and fault fallback, and wait for bounded TLB acknowledgements. User VMIDs and
host DMA stay disabled; failed/cancelled starts retain the backing pages.
SDMA0 now has a cold-start path on GC 10.3.2 and an owned VRAM ring. Production
boot runs a translated WRITE/COPY/FENCE test after GMC setup and checks both
read-pointer paths and all copied words. Reset and completion waits are bounded;
fault/cancel paths retain the ring and prevent replay. Software models exercise
packet decoding, register units, corruption, revocation and reset cancellation.
DCN3.0 DMUB now has an owned lifecycle: stop inherited firmware before PSP
upload, retain its authenticated instruction/stack windows, program owned
VBIOS/mailbox/trace/state storage and await a fresh firmware-ready status.
Navi22's reset registers are checked independently from Phoenix's. Unsupported
firmware layouts, invalid secure-window bounds, stop/boot timeouts, revocation
and cancellation refuse further startup without reclaiming published storage.
The retained owner now also drives DCN3.0 inbox1/outbox1: startup verifies the
running firmware version and queries capabilities, with HDP flush/invalidation
around PCIe VRAM traffic. Serialized native HPD and AUX/I2C-over-AUX operations
preserve unrelated notifications and reject stale replies. Software models
cover ring wraparound, cache ordering, malformed pointers/replies, cancellation,
timeouts, revocation and notification overflow; real-card validation is pending.
Native display block owners now resolve Navi22's six-pipe DCN3.0 profile,
including its OTG/ODM field differences, HUBP detile field and DisplayPort DIG
reset sequence. The DPP/OPP/MPC and shared DCCG paths retain explicit bounds;
Phoenix-only pixel/DPIA clock muxes are refused on Navi22. The Navi22 DAL clock
owner now reads board limits and the display PLL, enables bounded display DPM
through the retained SMU, pins memory/fabric clocks and programs DENTIST only
after every stream retires. Register models cover rounding, rejection,
revocation, cancellation and divider completion. GDDR6 mode calculations and
full modeset coordination are still pending. Native routing now resolves
AUX and HPD independently through the board GPIO LUT, follows display-table
relative record offsets, and rejects ambiguous routes. The Navi22 backend probe
uses the DCN30 enable register and includes the sixth transmitter.
These are software-tested foundations; training resume,
VCN startup, display-aware DPM and OS thermal interrupt handling,
hardware boot, general GPU mappings/GFX10 queue initialization, production
SDMA submissions/interrupts and DCN3.0
modesetting remain open. See the
[PCIe probe contract](drivers/gpu/specification/spec.md#amd-discrete-pcie-probe-and-vram).

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
