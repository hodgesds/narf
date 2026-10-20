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

## WCN6855 source alignment

The ath11k WCN6855 source path now includes Linux-shaped per-TID TXQs with
the 4096-flow fq/CoDel scheduler, ECN handling and requested-TX-status drops,
cfg80211's TKIP `MICHAEL_MIC_FAILURE` notification, and Linux-style managed
station recovery: external-SME, Open and completed in-kernel RSN vdev/peer/
BSS/EDCA/key replay without new auth or assoc frames (BA sessions reset).
Beaconing AP/GO recovery likewise replays beacon and MBSSID state, group
keys, clients, PTKs and authorization; shared-radio reconfiguration wakes
queues only after every live vdev is rebuilt. `GET_STATION` now reports
monitor-status PPDU combined/chain RSSI, Linux-style raw-RSSI EWMA,
RX/TX duration and detailed HTT TX rate telemetry. Monitor mode, TX A-MSDU,
AQL and airtime-fairness are not listed as open WCN6855 work because Linux
ath11k does not expose those capabilities for this hardware. This is
source-level implementation progress only: no build, emulation, or hardware
validation was run while the equivalence work remained in progress.

## MT7921/MT7922 firmware bringup

The x86_64 MT76 late init path now owns coherent WM/FWDL/MCU DMA rings and
performs ROM restart, patch semaphore negotiation, patch/RAM download and
firmware-ready verification. Post-firmware MCU commands obtain the real MAC
and PHY, read EFUSE hardware identity, select embedded world country limits,
select on-chip calibration and initialize MAC/WTBL/RTS. Unified device command
framing now matches the local Linux reference. Waits are bounded and report the current stage;
failed or cancelled attempts retain published DMA until verified shutdown.
The retained RX ring and MCU scan path now support passive 2.4 GHz scans on
channels 1–11. Successful radio initialization registers a wireless
interface with the real MAC and supported regulatory channels.
The private cut-through management TX backend retains each payload until
both descriptor completion and firmware token release. RX routing separates
forwarded normal frames, MCU responses and TX releases on all rings.
Live join dispatch is integrated with regulatory authorization, channel/power
switching via `MCU_EXT_CMD_CHANNEL_SWITCH`, open-authentication/association MLME
handshakes, and IEEE 802.11i WPA2-PSK 4-way handshakes (M1..M4) with HMAC-SHA1 MIC
verification/generation. WTBL station records commit temporal keys with
tag 0x12 (`STA_REC_KEY_V2`), cipher 6 (`MCU_CIPHER_AES_CCMP`), and `PORT_SECURE`.
The datapath encapsulates 802.3 Ethernet frames into CONNAC2 32-byte TXDs on WFDMA data rings,
translates 802.11 LLC/SNAP to Ethernet on RX, and pumps frames through `narf_ipc`
producer/consumer rings with link state updates.
The targeted QEMU suite passes 99 tests with one skip (99 pass, 0 fail, 1 skip),
including live WPA2 join dispatch, STA_REC key installation, and Ethernet transport.
Both-architecture Clippy and `cargo fmt` pass cleanly. Physical MT7922
silicon validation on AMD Zen2/Phoenix hardware remains open to close the Stage 5 Wi-Fi gate.

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
SoundWire, vendor smart-amplifier quirks and system power-transition
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
backing and block reuse.
Native DCN4 memory preparation now binds framebuffer base/top/offset and VMID0
to the retained GMC owner, checking both memory hubs before and after setup.
It uses the owned physical VRAM page-table root, disables AGP, waits for native
context readiness, and configures the selected blank HUBP's system aperture
and L1 translation. All scanout backing stays owned; lost writes, revocation,
timeouts, changed geometry and cancellation cannot report readiness. Fetch
remains stopped.
Native DCN4 DPP preparation now stages unscaled full-frame RGB conversion,
identity color processing and the unity-scaling line buffer against retained
surface, VM, clock and timing owners. Scaler/iSHARP memory wake waits are bounded;
pending double-buffer updates are recorded without claiming a latch. DPP clock
and HUBP fetch remain disabled and MPC stays detached. Lost writes, revoked
authority, stale configuration and cancellation quarantine the owner. Native
bandwidth/deadline/watermark programming, MPC route activation, visible framebuffer
activation and physical-card validation remain open.
Native opaque RGB MPC preparation now binds to the retained surface/DPP/VM and
timing owners, selects global opaque alpha and unity gains, bypasses inherited
output and movable color transforms, and matches the OPP output depth. Current
color selectors are recorded without claiming they latched; routes stay detached.
Native requestor preparation stages bounded physical-RGB fetch geometry and
partitions the 21-segment display return buffer into the native 320-KiB DET
default plus 1-MiB compbuf. Shrinks acknowledge CURRENT before any growth;
timeouts, cancellation, stale owners and lost writes retain every allocation
and quarantine the owner. All four pipes use native DCN4 request fields,
8-KiB chunks, no MALL, and disabled fetch after setup. This establishes storage
and request geometry; DLG/TTU/watermarks and visible scanout are still pending.
Native single-pipe scanout admission ports Linux DML21's DCN4 mode-support
and mode-programming path to fixed point for the implemented shape (one DP SST
timing, one full-frame linear 32-bpp surface, 320-KiB DET, UCLK switching
disabled, Linux's stutter blank reservation kept). It derives DISPCLK/DPPCLK
minimums, global sync, HUBP DLG/TTU values, watermarks and arbiter values, or
names the failing check. A host harness builds Linux DML21 and verifies 126
shared vectors, which kernel tests also check; three deliberate divergences
reject modes Linux would program beyond hardware limits. Plans are not yet
bound to live owners or programmed, and board inputs are not yet read from PMFW.
Admission inputs now come from the live board: PMFW UMC channel count and
DC-mode clock caps (which also cap the pinned floors), the DENTIST VCO, and the
DCHUB reference from the global timer and VBIOS crystal. Deadline preparation
re-admits a plan, binds it to the current timing, sync, signal, surface, DET,
clocks and reference, then programs and reads back HUBP DLG/TTU fields, both
DCHUBBUB watermark sets and arbiter state with fetch stopped. Self-refresh is
force-disallowed; UCLK switching stays disabled in PMFW. Route connection,
fetch enable and visible activation remain open.
Native single-pipe scanout start/stop now runs on the black DP SST stream:
under one OTG master-update lock it releases the DPG, connects the MPCC route,
re-arms the address and unblanks the HUBP, then requires EARLIEST_INUSE to
report the owned surface, cleared pending bits and two fresh frames without
underflow. Stop returns to black, detaches, waits for MPCC idle and drained
requests before blanking and gating clocks, and re-verifies the staged pipe so
it can restart. A read-only health check recognises exactly the owned live
fetch while every other HUBP stays stopped; underflow is recorded and returns
the pipe to black through the same drain, or quarantines it if that cannot be
proven. These paths are model-tested only; no sink has shown the image.
`ColdBoot::modeset_display` now chains EDID/DPCD sink selection, admission,
clocks, surface fill and every preparation through DP training to visible
scanout, with `stop_modeset` reversing it. Only the selection is model-tested;
the chain itself still needs a board, and inherited GOP retirement is separate.
A successful platform modeset publishes the live surface as the external
scanout; the console adopts it and flushes CPU writes through HDP via a
published, non-blocking hook. Stop withdraws it before any teardown.
Live pipes can now flip between two owned buffers: the back address is
written under the OTG lock and the flip completes only when EARLIEST_INUSE
reports it, after which every retained report moves to the new front.
`amdgpu.native_display` opts the boot handoff into retiring the GOP's DP SST
output and running the native modeset; it is off by default because no board
has validated it.
Adopting an external scanout (DCN314 or Navi48), or restoring the boot
framebuffer, now installs a kernel mapping of the published physical range
instead of dereferencing the physical address.
DRM clients' presented frames now reach an adopted Navi48/DCN314 scanout
through that mapping (CPU copy, then the published HDP flush).
A native 64x64 premultiplied ARGB hardware cursor can be shown and moved on a
live Navi48 pipe, programmed under the cursor VUPDATE lock as Linux does.
The fb pointer (console and compositor) uses it on an adopted Navi48 scanout
instead of compositing a sprite.
DP link training now falls back: a cleanly refused link is stopped (sink D3,
PHY off), and the modeset retries lower rates, then fewer lanes.
A running Navi48 modeset can now be checked. HPD comes from the debounced
DCN401 HPD block, and lane lock is read from the sink. A lost link retrains,
and an unplugged sink is torn down without AUX to it. With the opt-in native
display, a 1 s monitor retrains, tears down and relights on replug.
CPU scanout leases now let withdrawal
wait for fb drawing, cursor/status access and DRM fallback copies. Publication
and the writer drain stay under the display owner lock across flips, preventing
reuse of the former front while a CPU view remains. IRQ delivery stays enabled
during drawing, with preemption pinned until the CPU memory fence and lease
release. Cancellation retains pending epochs. After successful teardown, the
monitor now releases the pipe's current and parked front/back/cursor buffers
through `release_display_surfaces`: fresh fetch/route/power/transaction checks,
HDP/PCIe drain, a second check and dependent-report invalidation precede reuse.
Other displays remain owned; failures retain reservations. Replug allocates
fresh buffers without accumulating geometry-specific VRAM. Low-level callers
can still retain buffers until explicit release, and link retraining keeps its
surfaces. Reclamation is model-tested; physical transitions remain unvalidated.
Teardown now checkpoints completed native steps in the retained owner, allowing
the same modeset to resume a preflight rejection without replaying prior audio,
scanout or link work. Intent is recorded before CPU withdrawal; the monitor
finishes interrupted retirement before reactivation and publishes the CRTC
inactive meanwhile. Cancelled CPU drains can resume, but cancellation inside
a native phase blocks replay even when that phase spans several owners.
Native failure guards still block uncertain operations; arbitrary partial
activation and physical recovery validation remain open. Per-pipe startup now
records an unpublished activation before staging. A returned failure attempts
timing/DSC/plane retirement and fresh surface release when native owners prove
the output stopped; completed cleanup steps survive preflight rejection.
Pending cleanup blocks relighting/preferred-mode fallback and is retried before
monitor topology work. TMDS, legacy DP SST/MST, UHBR and FRL startup now checkpoint
completed link/frontend/video/scanout phases, so a later preflight rejection
unwinds the completed work before timing/plane retirement and fresh release.
This includes audio rejection after live fetch and scanout underflow recovered
to black video. MST also checkpoints payload completion before video, retaining
shared-link ownership until payload/frontend cleanup completes. A separate MST
payload-transaction marker survives failure/cancellation before or after list
updates; it blocks replay, teardown and session loss while ownership is uncertain.
TMDS records sink cleanup before the first SCDC transaction, so a returned
failure before native-link completion restores legacy sink configuration and
retires staging without inventing a link owner. Timing retirement also resets
the UHBR/FRL output mux to DIO only after master/busy clear, with readback before
retirement is published. Native failure guards remain binding; cancelled startup,
uncertain MST payload transactions, uncheckpointed active work and
shared-clock recovery remain open, with uncertain memory retained.
The device owner now also retains every completed Modeset through later-pipe
startup, asynchronous platform adoption and failed/cancelled teardown. A dropped
configuration or exited monitor cannot lose those live stream handles. The next
monitor pass restores missing handles and schedules normal withdrawal/retirement,
rejecting conflicting incarnations before changing caller records. New
configurations remain blocked until these streams stop. Native cancellation
quarantine and fresh surface-release checks remain binding.
Live FRL monitoring now handles SCDC FRL_Start, FLT_Update and Source_Test_Update
at a 200 ms fallback cadence. Source-test patterns/FFE updates preserve owned
video/fetch; interrupted firmware work quarantines the display. Ordinary
retrain requests stay pending until full configuration retirement and fresh
admission/training, including supported rate fallback. Physical FRL transitions
and source-test acceptance remain unvalidated. Native FRL now also supports
YCbCr 4:2:0 at sink-declared 8/10/12-bpc depths, with format-aware capacity and
training fallback, half-width encoder counts, AVI colorimetry and shared OPP/MPC
subsampling/BT.709 conversion. The pixel DTO keeps the full pixel rate; live
format checks reject stale compression or encoding state. Y420VDB modes stay
4:2:0, and Y420CMDB modes use RGB when it fits. The single-OPP 4096-pixel limit
remains; physical transitions are still open.
FRL DSC (model-tested, not hardware-validated) follows amdgpu_dm: a stream is
compressed only when no uncompressed encoding fits, with the EDID HF-VSDB DSC
caps, DC's HDMI slice/bpp rules, the compressed FRL capacity check and DSC
padding borrow bit-exact against Linux built on the host (2970 capacity, 3000
configuration and 890 CVTEM vectors). Lighting programs the DSC engines, the
HPO encoder's DSC mode and CVTEM PPS (generic packets 5-10), then the OPTC
after training; teardown reverses it. 7680x4320@60 on a 4x12G DSC sink picks
4x6G with 8 slices at 159/16 bpp. FRL DSC is 8-bpc RGB/4:2:0 only.
DP MST DSC (model-tested, not hardware-validated) on 8b/10b and UHBR follows
amdgpu_dm's fairness search (1500 link vectors through Linux's own functions),
drm_dp_mst_dsc_aux_for_port (virtual DPCD, passthrough, Synaptics/Realtek
quirk) and dm_helpers_dp_write_dsc_enable over remote DPCD; payload PBN uses
the compressed bandwidth and each stream sends its own PPS. Two 4K144 sinks
behind one HBR3 x4 branch both compress at equal bpp. MST DSC streams carry no
audio; Synaptics cascaded workarounds and PCON FRL DSC are not ported.
FRL now carries LPCM through AFMT4, lane-rate ACR and the pipe's Azalia endpoint.
Admission/training reserve the sink's supported LPCM bandwidth; SD timings use
layout 0. Audio starts after scanout and stops before it, preserving the
video-owned InfoFrame. Fresh register checks and retained owners prevent reuse
after partial failures. Shared audio DTO selection includes FRL on DPREFCLK.
Register/protocol tests cover all six rates, RGB/4:2:0 depths, bandwidth limits,
clock sharing and failed teardown; audible output remains unverified.
HDCP/protected output is tracked separately in
`drivers/gpu/research/navi48-protected-output.md`, including TA firmware,
protocol, credential authorization, isolation and physical acceptance gates.
It remains unsupported and unadvertised; existing crypto helpers and retirement
exclusions do not implement protected scanout.
The board/monitor acceptance ledger is
`drivers/gpu/research/navi48-display-acceptance.md`. It separates software models
from physical boot/hotplug/modeset/disable evidence. No board routes or physical
passes have been supplied; eDP/USB-C applicability remains undetermined.
Physical DP/HDMI connectors now retain EDIDs and independently admitted modes
while disabled or unadmitted. Link selection and full joint DML bound these
lists, including fitting alternatives to an unsupported preferred mode. Empty
configurations query board limits without active floors or stream allocation.
KMS publishes dark sinks without a CRTC mode, invalidates replacement EDIDs and
reprobes disabled ports on HPD rise. This still uses whole-configuration relights.
The lit Navi48 display is published as DRM KMS state on the amdgpu card, with
the sink's real EDID and exact timing (disconnected on unplug). SETCRTC
accepts only that timing, and the base amdgpu DRM version 3.0.0 claims no
render ABI. Flip events remain software-paced.
Navi48 DP SST displays now support VRR (FreeSync / DP Adaptive-Sync) as
amdgpu_dm does: EDID range + DPCD MSA_TIMING_PAR_IGNORED give the connector's
"vrr_capable", a VRR-supported stream sets IGNORE_MSA_TIMING_PARAM, and the
CRTC's "VRR_ENABLED" reprograms OTG DRR live (optc401_set_drr totals from
mod_freesync, a manual trigger per flip). HDMI/MST VRR, BTR/LFC and the
FreeSync infopacket are gaps. Model-tested only; not run on an RX 9070 XT.
Navi48 color management and HDR follow amdgpu_dm on DCN 4.0.1: CRTC CTM
(MPC gamut remap), GAMMA_LUT (OGAM PWL from Linux's color_gamma/cm3 math,
bit-exact against host-built Linux) and legacy SETGAMMA/GETGAMMA (sRGB
pre-degamma ROM), applied live under the OTG lock; connector Colorspace
(output CSC, blank, AVI C/EC/Q, DP MSA and VSC SDP) and HDR_OUTPUT_METADATA
(HDMI DRM InfoFrame, DP HDR SDP, live metadata updates). No DEGAMMA_LUT on
DCN 4.0.1, as Linux. Gaps: HDR/VSC on UHBR and FRL, MST, DP above 8 bpc.
Model-tested only; not run on an RX 9070 XT.
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
Native TMDS HDMI startup now exists for one 8-bpc RGB stream up to 340 MHz:
DMUB SET_PIXEL_CLOCK for the transmitter's PHY PLL, link-encoder setup, the
DIGX stream setup and HDMI stream attributes, frontend routing and FIFO, then
the DMUB transmitter ENABLE with lane, TX-clock and clock-on witnesses. Black
video starts and stops with AVMUTE handling, scanout runs on HDMI video, and the
link stops back to a reusable owner. The AVI InfoFrame (Linux's RGB fields,
VIC 0) is sent as VPG generic packet 0. Modeset now lights an HDMI sink (HDMI
VSDB required, at most 340 MHz) when no DP sink answers, with HPD polling,
unplug teardown, replug and an HDMI-A KMS connector. Sink selection also parsed
the whole multi-block EDID as one base block, so a monitor with any extension
(nearly all) was never selected; it now parses the base block. HDMI 2.0
modes above 340 MHz (e.g. 4K60) now run scrambled when the EDID declares SCDC
and a covering HF rate: native DDC gained SCDC register reads/writes, the sink
is configured before the link starts and returned to legacy on stop. HDMI deep
colour (10/12 bpc RGB, opt-in with `amdgpu.max_bpc`) scales the TMDS character
clock as Linux does. HDMI audio's display half (audio DTO, ACR, AFMT channel
status, Azalia endpoint/ELD, Audio InfoFrame) is programmed after scanout for
sinks declaring audio. The native HD-Audio runtime now binds Linux's ATI
HDMI NS controller IDs (through 0xab40) with snooping off: CORB, RIRB, BDL
and sample rings get explicit cache maintenance. The ATI HDMI codec
(0x1002aa01) is driven like Linux's atihdmi for LPCM up to 7.1: zero downmix,
per-channel remap (rev3+), the CEA channel allocation for the sink's speakers,
channel count, slot map and allocation (which feeds the hardware Audio
InfoFrame), ramp rate, HBR off and converter DIGEN. The codec's ELD is
rebuilt as Linux's get_eld_ati does and exposed as the `ELD` control with an
`HDMI/DP,pcm=0 Jack`; pin sense is polled, playback routes to the ports with
a valid ELD and is limited to their channels/sample sizes/shared rates
(44.1–192 kHz), and a port that gains a sink mid-stream is set up again.
Linux's IEC958 Playback Con/Pro Mask, Default and Switch controls and the
`Playback Channel Map` control (with its CHMAP TLV) are exposed: the AES0
non-audio bit makes the next prepare IEC 61937 passthrough (stream-order
slots, no ramp, HBR for 8-channel non-PCM, TYPE bit in converter and SDnFMT),
and user channel maps choose the CA and slot map under hdmi_chmap_ctl_put's
state rules (pairwise validation before codec rev3).
Legacy DP SST LPCM now shares the DIO stream with DSC PPS. Startup and live
checks require fresh PPS/clock/master witnesses, and audio stop preserves those
video-owned resources while disabling audio packets and the endpoint. Modeset
keeps DSC sink audio capabilities and uses normal audio-first teardown/retrain.
UHBR SST now carries LPCM through the HPO stream's APG and Azalia endpoint.
LPCM rate filtering uses Linux's fixed-point blanking budget with the native
programmed minimum width; selection and training fallback keep only supported
rates. Reset assertion/deassertion use bounded async waits, retain cancelled
owners, and recheck transport/audio before APG enable. Audio-first teardown and
retrain preserve video ownership; shared DTO and endpoint checks include UHBR.
Models cover all stream instances, rates and lane counts, reset timeout/cancel,
partial writes, late drift, clock sharing and shutdown; 1701 arithmetic vectors
match the Linux routines under that native-width contract.
Legacy MST now carries LPCM through each stream's DIO AFMT and DP endpoint.
Remote EDID rates are filtered by Linux's blanking budget (2268 reference
vectors); startup requires a completed manager payload and fresh SAT/VC and
transport witnesses. Partial writes and failed shutdown retain audio/payload
ownership. Models cover independent routes, all RGB depths, stale allocations,
endpoint collisions, shared DTO and two-stream link-owner handover. Teardown
stops audio before scanout/video and payload removal.
Every native endpoint (TMDS, FRL, legacy/UHBR DP SST, legacy/UHBR MST) advertises
the sink's valid compressed SADs and HBR from Linux's 8-channel 192-kHz
bandwidth probe; FRL reserves the highest SAD rate/channels like
get_audio_check. UHBR MST LPCM uses the stream's HPO APG and, as Linux
does, the 128b/132b SST budget (whole link, timing blank), started only on a
completed manager payload whose SAT row stays a witness; physical
audio is untested. FRL LPCM and HDMI 4:2:0 have model coverage
as described above. None of it has run on hardware.
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
The native frontend payload guard now accounts for DSC's compressed bits per
pixel and slice overhead instead of rejecting it as uncompressed RGB. Actual
trained rate/lanes and FEC's capacity reduction bound both kinds of stream;
DSC requires the supported 8-bpc RGB/FEC path (SST or MST). A native regression exercises
DSC fitting one RBR lane when RGB does not, including the FEC capacity boundary.
Legacy DSC training can now fall back among rate/lane settings that carry its
unchanged admitted PPS and bpp. Alternative DP modes carry DSC into joint DML
with real board limits and must fit the trained link after fallback. Retraining
refreshes retained and published mode lists beside current siblings and drops
invalid queued requests. When no link carrying the staged PPS trains, the
port's link is verified like Linux's dp_verify_link_cap and the configuration
is selected and admitted again against it, so DSC bpp/slices are recomputed
for the reduced link. A refused link-loss retrain is journaled and retired
through ordinary teardown, then relit against the verified link (model-tested).
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
A typed SOC21 decoder now covers every GC12 completion, fault and poison
source, DCN401 display events, VCN5 media and SMU sources. A dispatch table
wakes registered owners (CP slot, SDMA queue or user doorbell, with VMID/PASID
and a generation) so they re-check their own fences; a 100 ms watchdog bounds
lost interrupts and is counted separately. Faults go to the owning queue or
context, `recover` starts a new generation after the owner resets its queue,
and poison or service failure (including device removal) releases every
waiter with a terminal error. Kernel queues are registered; there are no
application owners yet. Model-tested only.
IH ring0 overflow is now recovered as Linux does (resume after WPTR, pulse
the overflow clear). A batch racing an overflow is discarded, all owners are
woken to re-check their fences, and both VM fault latches are swept so a
fault whose vector was overwritten is still captured and attributed.
Overflow storms and ring1 overflow still fail closed.
The interrupt worker now counts MSI, empty-MSI, watchdog, watchdog-with-work
and polled drains separately, the evidence a physical MSI test needs. DCN401
hot-plug, flip, VUPDATE, vblank, VLINE and DMUB vectors are counted per
instance for the display owner, and the native display monitor now waits on
hot-plug vectors with its 1 s poll as fallback; it arms each lightable
port's DCN HPD (and DP HPD-RX) interrupt and acknowledges raised ones like
Linux's hpd0_ack.
The retained SMU14 owner now reads PMFW telemetry (Linux's SMU14.0.2 metrics
table: edge/hotspot/memory/VR temperatures, fan RPM/PWM, socket/board power,
VDDGFX, current clocks, activity and throttler status), the running feature
mask and PPT limit, and decodes board thermal/fan/power limits. Throttlers,
firmware CTF and fan control stay PMFW-owned; protection loss is detectable.
GFXCLK performance levels use PMFW soft limits only, leaving display clocks
pinned. Deep sleep has an SMU-side, disabled-by-default hook: memory/fabric
low power still needs display admission/watermark recalculation first.
After boot, a 1 s monitor publishes this as a Linux-shaped `amdgpu` hwmon
device (temperatures with critical/emergency limits, read-only automatic fan
PWM/RPM, VDDGFX, power and PPT cap, sclk/mclk) and logs throttling, lost
protection and software-shutdown temperatures. Narf reports, not powers off.
Model-tested only; nothing here has run on an RX 9070 XT.
The boot coordinator retains all hardware owners through failures and
cancellation. The final framebuffer handoff selects Navi48, blocks legacy
controller/PM access after preparation and quarantines the primary framebuffer
on incomplete startup. Read-only preparation failures restore CPU writers.

A Navi48 stream too fast for one pipe (pixel clock above the DISPCLK
maximum) or too wide for one DSC or 4:2:0 formatter now runs on two pipes as
ODM 2:1: DML21 admission decides it as Linux's auto policy does (matched
against Linux on new ODM, ODM+DSC and ODM 4:2:0 vector sets), the modeset
gives it a free pipe, and the timing, both OPPs and DSCs, both HUBP/DPP/MPCC
halves, deadlines, flips and the cursor are programmed across the pair
(implementation and register models; no hardware run).

Navi48 primary planes now take XRGB/ARGB/XBGR/ABGR 8888 and 2101010, RGB565
and the four FP16 orders end to end (ADDFB2/GETPLANE/SETCRTC/PAGE_FLIP/atomic
TEST_ONLY, DML21 admission at 2/4/8 bytes matched against Linux on a new
format vector set, HUBP/DPP/MPC words as Linux programs them, premultiplied
alpha per amdgpu_dm's default); a format change relights the display.
Register models and QEMU only; no hardware run.

Navi48 planes now scale and stack as amdgpu_dm exposes them on DCN 4.0.1:
the primary is placed and scaled through a port of DC's SPL (viewport,
recout, ratios, taps, polyphase/EASF filters; every register word matched
against host-built Linux SPL on 230 vectors) and the DSCL program, and up to
three overlay planes (possible on every CRTC, XRGB/ARGB/XBGR/ABGR8888 and
RGB565) take free pipes, blended above or below the primary through MPCC
trees built as mpc1_insert_plane does, with alpha, pixel blend mode, zpos
and rotation (0/180; 90/270 refused) properties. DML21 admits the planes
jointly (matched against Linux on 654 scaled and multi-plane
configurations); the KMS checks follow amdgpu_dm's (24x12 viewport, 16x up,
6:1 down, primary required, zpos normalization) on ATOMIC, TEST_ONLY and the
new SETPLANE, configurations short of pipes are refused, a plane change
relights the display and framebuffer updates of several planes flip at one
VUPDATE. Register models and QEMU only; no hardware run.

Navi48 planes now take GFX12 tiled and DCC framebuffers and NV12/P010 on
every plane, as amdgpu_dm exposes them on DCN 4.0.1: the 17 GFX12 modifiers
(12 DCC variants, 4 swizzles, LINEAR) in IN_FORMATS / IN_FORMATS_ASYNC,
ADDFB2 with per-plane handles/pitches/offsets/modifiers and amdgpu's size
checks, GEM_METADATA tiling flags converted for ADDFB2 without modifiers
(modifier list, blobs and ADDFB2 decisions matched against Linux's own
functions built on the host, 2454 vectors); HUBP swizzle, DCC enable, luma
and chroma pitch/address; SPL 4:2:0 chroma scaling (124 new vectors against
host-built Linux SPL); the YCbCr post CSC from COLOR_ENCODING/COLOR_RANGE
(120 vectors against Linux's tables and switches); DML21 admission of
tiled, DCC and two-surface 4:2:0 planes with their RQ, chroma DLG/TTU and
mcache plans (618 new configurations against host-built Linux DML21). Tiled
and 4:2:0
framebuffers are staged and CPU-copied whole. Register models and QEMU only;
no hardware run.

DP MST now also runs over 128b/132b links: a branch that codes UHBR trains
MST at its best UHBR rate (as Linux's decide_mst_link_settings does), streams
share the owner's HPO link encoder with all 64 slots from slot 0, and each
stream's HPO encoder is prepared blank, given its payload (SAT rows with ACT,
the VC rate and blanking width matched against Linux's fixed-point
arithmetic) and only then unblanked; teardown blanks, removes the payload and
stops the stream. Its LPCM rides the stream's HPO APG once the payload
completed (implementation and register models; no hardware run).

Navi48 DP SST DSC now also runs over 128b/132b: a mode no uncompressed link
carries is compressed for the sink's maximum (UHBR) link as amdgpu_dm's
policy does (8K60 and 4K240 at 16 bpp on 4 x UHBR10, configurations matched
against Linux's dc_dsc_compute_config on the host), lights on the lowest
128b/132b setting its compressed bandwidth needs, and wide streams use two
DSCs under ODM 2:1. The HPO stream marks the format compressed, enables sink
decoding and sends the PPS through its VPG (GSP11, VBID[6]) before a VC
payload sized for the compressed bandwidth; fallback keeps the PPS. DML21
plans match Linux with DP2P0 encoders. UHBR DSC carries no audio, MST DSC
stays unsupported, and HDMI FRL DSC remains open (EDID DSC caps, compressed
FRL capacity, CVTEM PPS). Implementation and register models; no hardware run.

Native 8b/10b DP MST now reaches the platform display monitor and KMS for one
branch, beside every board port: KMS routes any connector (board port or end
device) to any of the four CRTCs, as SETCRTC/atomic CRTC_ID set it or
automatically in connector order, and board sinks and end devices light as
one jointly admitted configuration. End-device EDIDs feed
joint mode admission and per-stream payload allocation. Disabling the display
that trained the link transfers ownership to a surviving stream; only the
last stops the PHY. Disabled, unreadable or unadmitted devices leave output
gaps, and switching every CRTC off keeps them off. Shared-link loss relights
the configuration. Downstream hotplug now stops payloads using the old routes,
reprobes and relights, retaining output slots by root/branch GUID, route and
port across branch reordering and removal/replug. All-off and empty branches
keep their managers enabled; physical removal drops them without AUX waits.
Changed EDIDs invalidate stale modes. New disabled monitors now publish their
EDID and independently admitted timings without starting a stream: remaining
MST slots, path PBN and joint DML bound the offered modes. All-off branches query
board clock limits without installing clock floors or allocating scanout, and
KMS keeps the CRTC mode unset until enabled. Ordinary disables retain admitted
modes without restarting siblings. Resource notifications now trigger fresh,
port-bound bandwidth queries. Existing payloads are added back before comparing
capacity, avoiding relights caused by our own allocations. Capacity changes retire
old streams before reprobe/re-admission. Every shared path hop constrains payload
and dark-mode admission; zero PBN rejects new modes. Incomplete resource queries
retain the session and refuse replay. MST DSC and more than one branch
remain open; no physical validation.
The MST manager now also exposes bounded idle notification polling over
DMUB AUX, retains fragmented messages across transaction/poll boundaries and
applies queue backpressure. Connection notices drive topology reconciliation
in the display monitor. Probes have depth/branch limits and retain incomplete
sessions after cancellation instead of allowing replay.

Navi48 compute recovery now falls back from a timed-out HQD dequeue to an
RS64 MEC pipe reset, clearing all four pipe-0 HQDs while reset is held and
preserving other MEC controls. RLC safe mode brackets recovery; unexpected
active sibling queues and uncertain register writes refuse recovery.
A drained MES suspension rejection now runs detect-only hung-queue reporting;
only owned HQDs permit MMIO, while malformed or undrained results quarantine
MES. Cancellation during the MMIO reset retains the owners and
prevents replay. The existing remap and fence test must still complete before
job memory can retire. Register models and Linux-header checks cover this
path; physical recovery remains unverified.

Navi48 ring recovery now replays healthy contexts' pending jobs under their
original client tickets. Reset test fences cannot release replay buffers or
VMIDs; forced VM/PASID/context setup precedes replay. Explicit whole-device
recovery uses SMU14 mode1, PCI/ReBAR/MSI restoration and ATOM ASIC_Init v2.1,
then fresh firmware, IH, queues and interrupt proofs. Old owners remain
quarantined; contexts report lost VRAM, old readers/interrupt handles are
invalidated, and power/display monitors restart with fresh generations and
modesets. Cancellation
or failure is terminal. Automatic whole-device recovery remains disabled:
the caller must exclude CPU VRAM/GOP/mmap access. Boots needing GDDR6 training
replay refuse this path before hardware changes.

The optional `amdgpu.shader_proof` boot diagnostic now dispatches a fixed
gfx1201 wave32 shader on both retained kernel GC12 queues, after the GC12
and SDMA interrupt proofs drain. It makes only the owned code PTE executable,
programs native logical SH resource state, and checks all 32 lane results,
the output page's poison guards, exact fences, ring drain and fresh matching
EOP/CPU-delivery evidence. Failure/cancellation blocks further GC12 work and
retains storage. Whole-device recovery repeats the requested proof before
publishing its new submitter. Independent LLVM assembly, Linux-header checks
and execution/failure models cover this path; physical execution is unverified.
It does not enable Mesa acceleration or exercise draw state or client VMIDs.

Navi48 interrupt handoff now accepts the client VMIDs initialized by its own
GMC owner. The previous monitor required them disabled, contradicting cold
boot's client-context setup and preventing native service handoff. Fresh
same-device checks require every client context to retain the owned empty
root, VA range and nonretrying control before arming. Fault IRQs now cover
all sixteen VMIDs on both hubs; containment and partial-write cleanup mask
the same owned set while preserving translation policy and EOP enables.
GMC-to-monitor integration and negative register models cover this path;
physical handoff remains unverified.

Contained Navi48 faults now use coordinated graphics/compute/SDMA0 recovery.
Client retirement and submissions freeze before all three reset/fence tests;
late IVs and VM latches remain diagnostic evidence. A generation-bound receipt
guards source re-arming, unchanged controls are verified, and old interrupt
handles are invalidated. Guilty contexts are excluded and healthy jobs replay
under stable tickets before all ledgers reopen together. Cancellation or any
uncertain stage keeps memory pinned; poison, kernel VM faults and unsupported
owners require explicit device recovery. Hardware acceptance remains pending.

Native GC12 and SDMA0 client slots now request an HDP flush on their own
ring and wait for the engine-specific NBIO acknowledgement before IB
execution, including submissions that reuse a VMID without a VM flush.
Linux-header checks pin both supported NBIO layouts and packet fields;
models cover packet ordering and blocked GC12 acknowledgement.

Navi48 now has a retained VCN5.0.0 static-power unified-ring owner and an
opt-in `amdgpu.media_proof` power/transport/retirement cycle. Owned firmware
windows, NBIF doorbells, fresh fence/RPTR completion, byte shared-state
updates and VCPU/LMI shutdown follow the local Linux reference. SMU14 media
power commands require fresh protection/static-clock checks. Cancellation
or uncertainty retains memory and blocks clients. Source-119 dispatch now
wakes a registered VCN owner; a fresh proof requires fence/RPTR/trap and,
with an MSI route, CPU delivery. Registration stays retained on uncertainty
and is retired only after proven shutdown/power-down, so shared fault re-arm
cannot overlook a live media owner. Register/queue models cover these paths;
codec streams, JPEG and physical IRQ acceptance remain open, with no codec
capabilities advertised.

The VCN5 backend can now publish owned client IB frames with MMHUB4.1
flush/semaphore ordering, the MMHUB PASID LUT, HDP visibility and native
fences. Masked ring pointers and backpressure match Linux; once published,
a job always returns a sequence so its resources remain retained through
later errors. Models cover packet fields, ring wrap/full and revocation at
publication. The opt-in `amdgpu.navi48_media` now retains the proven owner
and exposes the unified VCN_ENC queue with a separate MMHUB VMID pool and
generic CS resource retention; user fences are refused. Before publication,
the native session IB test now runs Linux's fixed encode/decode create/destroy
messages in separately retained context/IB/message storage, requiring new
fence/RPTR/trap/CPU evidence and unchanged command-page guards. Its pending
phase closes clients, and cancellation/failure retains every allocation.
Rust builders match unchanged Linux constructors in a host capture harness.
The opt-in `amdgpu.decode_proof` now submits a pinned IGT AVC picture fixture
in a separately retained guarded arena, requiring new completion evidence and
the upstream output checksum. Page-wise initialization/readback cooperates
with the executor. Diagnostics retain the pending/result phase, failures keep
all backing pinned and requested tests repeat after media recovery. Descriptor
builders and fixture bytes match unchanged IGT source; device models exercise
missing/wrong output, guards, partial execution and cancellation. Real picture
decoding remains pending physical acceptance, with codec profiles unadvertised.
The opt-in `amdgpu.encode_proof` adds fixed NV12 create/IDR/close tasks in a
separate retained arena, with the full declared output range backed and guarded.
Fresh completion, bounded matching SPS/PPS/IDR headers and intact command/input
storage are required before publication and after recovery. Builders and input
match pinned IGT source; synthetic model headers verify ownership and parsing,
while physical encoding, complete bitstream conformance and picture quality
remain acceptance work. This proof advertises no codec capability.
The opt-in `amdgpu.jpeg_proof` adds a retained JPEG5 static-power JRBC and IB
transport/interrupt/retirement cycle. It preserves VCN's shared NBIO range,
uses separately reserved GPCOM fence dwords and requires DMA-clean evidence
before memory reuse. A registered exact-source JPEG owner participates in
fault containment; incomplete recovery cannot omit it. Transport models and
unchanged Linux constructor checks support this stage. JPEG picture execution,
native clients and physical acceptance remain open.
The additional `amdgpu.jpeg_decode_proof` submits pinned IGT JPEG5 picture
commands in a separate guarded arena and requires a fresh native completion
plus the active luma/chroma checksum. Input, command and output guards remain
checked; failure/cancellation retains all backing and requested picture proofs
repeat after recovery. Models test synthetic pixels, not JPEG decoding;
physical picture execution and native JPEG clients remain open.
Native JPEG clients now follow: `amdgpu.navi48_media` keeps JPEG0 running as
`AMDGPU_HW_IP_VCN_JPEG` ring 4 with Linux-style kernel-copied VMID0 IBs (plus
a stricter privileged-register filter), client decoder VMIDs on MMHUB engine 1,
retained per-job copy slots, JPEG-only ring reset with innocent replay, and a
fifth recovery owner retired before VCN restarts. Model-tested only.
Fault recovery
requires all four retirements and renewed owners, followed by a new media
interrupt and session IB proof before ledger commit. Media restart cancels old codec
contexts instead of replaying their IBs. Fence readers skip frozen media
and drain before power changes and reopening retirement. Dispatch follows
known PASIDs across VMID changes and limits unknown latches to their hub.
Models cover the fourth owner, exact ring gating, Linux INFO_HW_IP alignment
and cancelled-session lifetimes. Known-stream codec validation, JPEG and
physical acceptance remain open.

Recovery attribution now follows the nonzero PASID carried in a client IV,
so a late fault cannot blame the address space that reused its VMID. Latches
and PASID-less vectors conservatively cancel work only on their own hub;
attribution overflow requires device recovery. Logical client tickets skip
the CS ABI's reserved zero handle when wrapping. GC12, SDMA7 and VCN5 fence
samples now check presence around the read and revalidate authority. Failed
current-generation sampling marks device loss before waking waiters and keeps
allocations pinned; old readers cannot fail a replacement device.

Still open: physical MSI delivery and reset/replay acceptance, GC12 rendering
and application shader execution, GPU VM/userspace and DCN4
clock/bandwidth/link/scanout hardware acceptance, VCN5 known-stream video,
THM/SMU thermal interrupts and software-CTF shutdown,
memory/fabric DPM relaxation (display admission/watermark rework first),
reset/suspend/resume, and physical RX 9070 XT testing.
The verified DMA proof covers only two kernel-owned VRAM pages. The driver
continues to report acceleration unavailable; model/QEMU tests do not prove
working silicon, native modesetting or Mesa/Vulkan support.

Navi22 third-review fixes (software-model tested only): DRM ioctl user copies
apply `access_ok` and fault-guarded copies (EFAULT); NVMe/AHCI bring-up
failures stop the controller before freeing DMA; AHCI port bring-up is bounded
per HBA and sets GHC.IE only after the IRQ route; host-install xtask media
default to `narf.disks=boot-only`; DMUB-routed retrain/unplug tables, a non-IRQ
DMUB route lock, a TABLE_MS cap, same-EDID HPD long pulses keep the stream.

RX 6000 software follow-ups now publish the strapped atomfirmware VRAM
module's type/width, common GPU/slot PCIe capabilities, SMU UCLK limits (or
fixed boot MCLK), and Linux's per-GC MALL sizes. Live allowed-register reads
serialize through the retained owner with GFXOFF held. Native ring admission
is FIFO and cancellation-safe; fence IRQs wake per-client waiters. Separate
pre-IB VM writebacks avoid treating whole-job completion as flush completion,
while active job fences still prevent premature VMID reuse. Submitters use
the pre-restart fence generation and reject stale owners after reset.

Ordinary VRAM-preferred creation now permits Linux's GTT fallback when VRAM
is unavailable, preserving reported preferences and discardable-domain rules.
Visible client VRAM now supports pressure eviction to GTT and promotion back
to VRAM with data preserved. GEM_SET_PLACEMENT records atomic preferences;
validation applies them when address leases and reservation fences permit
migration. Same-card PRIME/shared handles, exported fds and BO lists no longer
pin placement by themselves: identity stays shared while backing changes.
Registered GPU VMs can be rebound after all affected ring jobs and reservation
fences settle, under a card gate excluding queue publication and VA mutation.
PTEs keep their virtual addresses and existing table allocations; TLB sequences
advance before submissions resume. Strict VRAM creation retries can reclaim
mapped buffers, and CS validates listed buffers' placement preferences.
Cancellation while waiting leaves leases and PTEs untouched. Unregistered VM
mappings, deferred CPU user-fence writes and legacy raw leases remain pinned.
Completion retirement now samples callbacks outside its lock, allowing native
progress queries to re-enter retirement safely. Migration regressions cover
shared PRIME identity, CPU leases, multiple VMs and offsets, split mappings,
busy-job/reservation cancellation and re-entrant retirement.
RX6000 invisible VRAM now has ordered kernel SDMA clears and bidirectional
staged migration to/from GTT (promotion requires NO_CPU_ACCESS). Failed and
cancelled copies preserve old PTEs; queued copies retain both allocations and
source KERNEL fences until actual DMA completion. Recovery replays requests,
refreshing upload staging, and never mistakes reset/loss for completion. CPU
BAR access requires current PCI authority, power and reset exclusion. CS
rechecks kernel fences after admission and promotion; GEM/PRIME mmap cannot
bypass NO_CPU_ACCESS after a move to GTT. Published GEM/PRIME CPU mappings
are now revocable: moves freeze every CPU alias across known address spaces
(failure-atomic, allocation-free commit, exact leaf restore), rebinding CPU
and GPU aliases together. Unpublished mappings, address leases and unknown
fork-child aliases refuse safely; device mappings never become mlocked.
Regressions cover multi-space scatter/partial/PROT_NONE aliases, census and
pin refusals, injected rmap preparation failure, commit rollback,
fork/split/mremap, syscall-level mmap publication and relocation, VRAM<->GTT
moves of published views, late fences, allocation failure and fork-gap
retention.
RX 6000 (RDNA2: Navi21/22/23/24) current state — the summary to read first;
the entries below are a dated log.
- Implemented and model-tested (register/fake-engine models, QEMU suites):
  native startup for 40 PCI IDs (PSP/SOS, SMU11, GMC/GART/per-client VMs,
  IH, SDMA, GFX/compute kernel queues, VCN/JPEG), DCN3.0 HDMI/DP modesets
  with DML30 admission, HDMI audio, the Mesa render ABI (CS, GEM, VA, PRIME,
  syncobjs, VA-API/Vulkan video rings), full buffer migration (shared,
  GPU-mapped, CPU-mapped, invisible VRAM), power telemetry and thermal
  shutdown, hang detection and mode1 recovery.
- On by default, each with an off switch: native display, accel, hardware
  cursor, power saving (each feature still admission-gated; GFXOFF stays
  refused until the CS path declares its GC MMIO GFXOFF-safe) and automatic
  recovery (`amdgpu.gpu_recovery=0`; at most 3 per boot, because each one
  quarantines VRAM).
- Runtime controls: `power_dpm_force_performance_level` (`auto|low|high`,
  GFXCLK only) and `pp_features` (Linux's PMFW table; policy-owned bits only),
  on `card<N>/` and `card<N>/device/`.
- Open: any boot on RX 6000 silicon; multi-display presentation on secondary
  CRTCs (opt-in until then); GDDR6 short-training resume (training boots
  cannot recover); VCN dynamic power gating; declaring CS GC MMIO
  GFXOFF-safe; user CPU mappings of VRAM are not revoked during a reset
  (Linux behaviour).

RX 6000 runtime power controls and recovery: the DRM card exposes writable
`power_dpm_force_performance_level` (SMU11 SoftMax/SoftMin on GFXCLK, as
`smu_v11_0_set_soft_freq_limited_range`) and `pp_features`
(`smu_cmn_get_pp_feature_mask` text over sienna_cichlid's 43 mapped bits; a
written mask may toggle only power-policy features and re-plans the power
saving through its admission gates; power saving can now be re-applied after
removal). Writes validate synchronously and apply in a serialized task.
Automatic mode1 recovery after a detected hang is on by default (Linux
`amdgpu.gpu_recovery`), capped at three per boot; the fb console pauses for
the reset through a recovery hook and the power controls republish after it.
`smoke_sync_all_reaches_every_superblock_once` now judges its report against
a pre-fixture baseline, so mounts or disks left by earlier tests no longer
fail it. Model tests only.

RX 6000 defaults: native HDMI/DP display, native client submission (accel),
the DCN3.0 hardware cursor and every power-saving feature are now requested by
default, each with an off switch (`amdgpu.native_display=0`,
`amdgpu.rdna2_accel=0`, `amdgpu.rdna2_hw_cursor=0`, `amdgpu.rdna2_pg=none`);
earlier "opt-in" notes below describe the previous defaults. Power features
still pass every display-admission and driver gate (`HARDWARE_VALIDATED`
stays false; the default list is an implicit opt-in). Multi-display stays
opt-in until secondary CRTCs can present. A failed native modeset leaves the
screen dark, and there is no automatic hang recovery, so first hardware boots
should keep the off switches at hand. Firmware: `xtask import-firmware` now
follows linux-firmware alias symlinks; re-imported from 20260916, all twelve
Navi22 payloads match the distribution and the conformance gate passes.
Memory/filesystem/userspace/GPU/framebuffer suites passed 3333 x86_64 and
2593 aarch64 (zero failures; 22 and 8 environment skips) with clean
production boots and btrfs postflights; debug builds and targeted Clippy pass
on both architectures. Not validated on physical RX6000 hardware.
Invisible-VRAM validation passed 1771 x86_64 and 1263 aarch64 GPU/framebuffer
tests (zero failures; five and one environment skips), with clean production
boots and btrfs postflight. Final RDNA2 reruns passed 42 and 40 tests after
adding the pre-copy CPU-writer lease check. Debug builds, all three targeted
Clippy contexts on both architectures, formatting and Linux constants/parser
checks passed. The full firmware identity check still reports three imported
payloads differing from the installed distribution copies (SDMA, TA and VCN);
those local firmware files were not changed by this work.
GEM mmap now resolves
scattered GTT backing page by page. This is a bounded driver placement policy,
not full Linux TTM parity. Linux conformance covers VRAM module C layouts,
cache sizes and the compiled GC MMR allow-list as well as the existing family
inventory. Broad GPU/framebuffer suites passed 1767 x86_64 and 1259 aarch64
tests, with production boots and btrfs postflight clean on both architectures.
Debug kernels and targeted GPU/fb Clippy passed on both architectures. Final
migration-focused reruns passed 66 x86_64 and 42 aarch64 tests. Six
host profile/metadata tests, Linux C metadata/SMU layouts, formatting and
constant conformance checks passed. Fence regressions cover valid all-ones
writebacks, reserved-zero avoidance for CP/SDMA, exact rollback and JPEG IB
slot parity across sequence wrap. A final 130-test aarch64 RDNA2/media rerun
passed after the media wrap fix.

RX 6000 follow-ups now share clock-gating policy across Navi21/22/23/24,
with per-ASIC Linux CG/PG flags, discovered one-to-four-engine SDMA traversal,
and revision-selected SMUIO ROM behavior. Telemetry selects metrics V1/V2/V3
using each ASIC's firmware thresholds and resolves compatible SMU11 THM/SMUIO
banks for sensors and thermal alerts. Driver-interface diagnostics now use the
profile's interface version. Native modules have canonical `amdgpu_rdna2_*`
paths with the previous Navi22 paths retained as aliases. Boot options use
`amdgpu.rdna2_{accel,multi,hw_cursor,pg}`, retaining legacy names; explicit
canonical power values take precedence, and invalid lists enable nothing.
Conformance now checks Linux CG/PG flags, interface versions, 48 metrics
selections and SMUIO ROM backend selection, plus V3 and Beige Goby C layouts.
Family models cover gating, every discovered SDMA engine, metrics transfers,
thermal alerts, malformed banks and boot-option compatibility. Physical
validation and the existing default-off/admission prerequisites remain unchanged.
Validation: 1757 x86_64 and 1249 aarch64 GPU/framebuffer tests passed, with
production boot and btrfs postflight clean on both architectures. Targeted
Clippy passed on both architectures; formatting, constant checks, four host
profile/option tests and the Linux C metrics-layout probe passed.

RX 6000 native startup now covers 40 exact Linux PCI IDs across Navi21,
Navi22, Navi23 and Navi24. Shared profiles select ASIC-specific firmware and
validate discovered IPs before firmware upload or hardware initialization.
The coordinator covers PSP/SOS, board power policy, GMC/GPUVM, queues, IH,
DMUB, display and recovery, preserving upstream's boxed recovery ownership.

Production SDMA supports one through four contiguous discovered engines,
including distinct doorbells, IH routes, fences and ticket slots for SDMA2/3.
Graphics selects each ASIC's Linux golden sequence (43/42/36/32 rows).
OSSSYS 5.0.0–5.0.3 uses revision-specific self-IV programming. SMC 2.1 selects
power tables by exact VBIOS board ID; power parsing accepts both original and
current Beige Goby layouts without guessing board offsets.

DCN 3.0/3.0.2/3.0.3 enforce six/five/two display resources and select their DML
parameters. Navi24 omits the removed plane/DSC power-gating registers and
encoder rings; its video capabilities contain H.264, HEVC and VP9 decode.
HDMI and DisplayPort modesets pass register-model tests on all four profiles.
Linux conformance checks exact PCI IDs, firmware names/IP selections, hub
registers, golden sequences and 450 common DMUB definitions. Installed firmware
containers parse for all four ASICs. The GPU suite passed 1712 tests with no
failures on x86_64; the aarch64 GPU suite passed 1204 tests with no failures.
The final startup/DSC enablement subset passed 45 tests. Production boot and
btrfs postflight passed on both architectures; release builds, targeted Clippy,
formatting and constant checks passed. Physical testing beyond the existing
Navi22 path remains outstanding. Existing `amdgpu.navi22_*` boot options and module names are retained
for the shared path as compatibility aliases.

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
partial upload failures preserve ownership and prevent replay. VCN queues
start later, after the fence stage (below).
Production cold boot now initializes GC/MMHUB VMID0 with a bounded VRAM-only
test aperture after the protected power policy is active. Both hubs validate
idle contexts and matching framebuffer geometry, use owned VRAM page tables
and fault fallback, and wait for bounded TLB acknowledgements. Failed or
cancelled starts retain the backing pages. A following GART stage repoints
VMID0 at a 512 MiB VRAM-resident GART (boot pages retained) and arms user
contexts 1–15 on an empty root. The hub owner binds pinned system DMA pages
into the GART and creates per-client GMC10 four-level VMs with Linux PDE/PTE
encodings, engine-17 invalidation on both hubs, and VMC/UTCL2 fault
attribution; register-model tests cover isolation, timeouts, cancellation and
revocation. Not hardware-validated; GEM/CS now run client IBs on these
per-client VMs (below).
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
uses the DCN30 enable register and includes the sixth transmitter. Navi22 kernel
queues now follow Linux's non-MES GC 10.3 path: BAR2 doorbells, golden/CAM/
constants/RLC CSB setup, the direct gfx ring with clear-state, KIQ-mapped
compute (v10 MQD, MAP_QUEUES) and production SDMA on both engines, each with
ring and IB/fence tests after `DmubStart`. Navi22 `AMDGPU_INFO` now answers
DEV_INFO, HW_IP_INFO/COUNT, FW_VERSION, READ_MMR_REG (GB_ADDR_CONFIG) and
MEMORY as Linux does for GC 10.3.2, from a cold-boot harvest sample, the
loaded firmware headers and the PCI revision; ACCEL_WORKING and ring masks
sit behind one switch, now wired: the card registers a generic
`amdgpu_cs::Submitter` and client VRAM heap, so the shared CS/GEM/VA path runs
client IBs on the Navi22 kernel queues (per-client GFXHUB VMIDs 1–7 from
the generic `amdgpu_vmid_grab` manager: flush only when a space's VMID, root
or TLB sequence changes, PASID→VMID IH LUT writes so faults reach the
client's GPUVM_FAULT; fences, two in flight per ring), with user fences, GEM_METADATA, PRIME, DRM 3.64.0 and
GET_CLIENT; proven in register/fake-engine models only (ABI audit:
`drivers/gpu/research/navi22-mesa-abi.md`). The generic sync ABI (shared with
Navi48) now matches Linux: timeline syncobjs (`DRM_CAP_SYNCOBJ_TIMELINE` = 1,
TIMELINE_WAIT/QUERY/TRANSFER/TIMELINE_SIGNAL/EVENTFD, CS timeline chunks),
syncobj and sync_file fds, WAIT_FENCES, FENCE_TO_HANDLE, BO_LIST and
Linux's implicit-sync rules (model-tested against Navi22- and Navi48-shaped
engines). Fences poll with an IH notify hook;
register models cover encodings, rejection, timeouts and cancellation only.
Production cold boot now resets a posted card before any firmware stage, as
Linux does whenever the VBIOS left SOS running: PMFW (or PSP) mode1 reset,
PCI config restore including Resizable BAR sizes, then bootloader and MEMSIZE
waits. Without it the sequence would load SMC/graphics/DMCUB over the
VBIOS-started SOS and PMFW, a state Linux never initializes from.
`ResetOnInit` then posts as `amdgpu_device_need_post` does: when BIOS_SCRATCH_7
lacks ATOM_S7_ASIC_INIT_COMPLETE (after a mode1 reset, or on a never-posted
card; always after a recovery reset) it runs ATOM ASIC_Init from the retained
VBIOS through the stepped `amdgpu_atom_vm` (now with IIO programs, Linux's
sub-dword/SHL/SHR/MUL32/DIV32 semantics and cooperative DELAY sleeps) and
requires the bit afterwards; a GOP-posted card with the bit set is not posted.
`drivers/gpu/tools/atom-trace` replays ASIC_Init from a dumped ROM on the host.
OSSSYS 5.0.3 IH ring 0 now follows navi10_ih_irq_init with a VRAM ring
reached through VMID0, MSI-X/MSI delivery with polling fallback, and
overflow-safe task-context drains. It routes IVs to generation-tagged
subscribers that receive a terminal error on device loss. Boot enables it
after the memory hubs and proves delivery with an SDMA0 TRAP.
PMFW telemetry now uses the retained SMU11 table buffer (V1/V2 metrics by
PMFW version, Linux-checked layouts) and feeds a read-only hwmon node shared
with Navi48 (temperatures, fan, power, clocks); fan control stays automatic.
The SMU11 THM L2H/H2L, GPIO19 CTF and SMU-to-driver interrupts are armed and
handled as smu_v11_0 does, including the delayed SW CTF check and power-off.
Kernel-queue hang detection (2 s fence-progress timeout per ring) is active
and logging; mode1 device recovery with a full cold-boot re-init now runs
automatically after a hang (see the RX 6000 current-state entry; training
boots still refuse it).
GFXOFF, clock/power gating, memory/fabric DPM and deep sleep were disabled on
every default boot at this point (all are now requested by default; see the
RX 6000 defaults entry above). Linux's sequences for them are implemented and model-tested
(gfx_v10_0 MGCG/CGCG/3D CGCG under RLC safe mode, mmhub_v2_0/athub_v2_1/
hdp_v5_0/navi10_ih/sdma_v5_2/smuio CG with nv.c's navy_flounder flags,
`amdgpu_gfx_off_ctrl` GFXOFF with its 100 ms delay and disable references,
runtime PMFW feature bits, DCN3.0 PMFW watermark table, UCLK/FCLK floors). They
run for the features `amdgpu.rdna2_pg=` names (all of them by default) that the
policy admits. GFXOFF stays refused until the CS path declares its GC MMIO
GFXOFF-safe; GC clock gating needs only RLC safe mode; the watermark-dependent
features (hub CG/PG, memory/fabric DPM, deep sleep) follow the live DML30
admission of the native display, and the boot log names each refusal.
VCN 3.0 now starts both discovered instances after the fence stage (Linux's
static, power-gating-disabled path with PSP-loaded TMR images, VCPU reset
retries, decode/encode ring and IB tests, IH-routed fences) plus JPEG 3.0 with
a ring test; PSP loads one VCN image per unharvested instance (type 13/58)
from the discovery harvest table, and media failures leave the boot degraded.
While accel is on (the default; `amdgpu.rdna2_accel=0` disables it), VCN
decode/encode and JPEG are client IPs on the
generic CS path (`amdgpu_vcn_navi22_cs`): Linux's ring frames with a
ring-side MMHUB VM flush under the client VMID, `vcn_v3_0_dec_msg`
message checks, per-client decode sessions, JPEG `parse_cs` on a kernel
copy, IH-routed fences; HW_IP_INFO/COUNT and VIDEO_CAPS answer Linux's
values for the RX 6750 XT (VCN1 harvested). The Mesa recipe now builds
radeonsi VA-API and RADV Vulkan video; the amd-gl image carries vainfo,
ffmpeg, reference clips and `/mesa-amd-video.sh`. Register models only.
Navi22 display AUX/DDC/HPD is now native, as Linux drives DCN3.0
(`dc_is_dmub_outbox_supported` is false there): the DCE AUX engine with
`dce_aux_transfer_with_retries` policy, I2C-over-AUX, the hardware I2C engine
for HDMI DDC/SCDC, and HPD sense/filter/ack. After firmware readiness the boot
logs every board connector's HPD state and EDID. DMUB AUX/HPD is refused unless
explicitly allowed. Register models only; no physical EDID read yet.
A native DCN3.0 DML port (`amdgpu_dml30`) admits one unscaled linear plane
and derives DLG/TTU/RQ and HUBBUB watermark values, checked against host
vectors computed from the Linux DML30 formulas.
A native HDMI TMDS path (default; `amdgpu.native_display=0` keeps the GOP)
lights the first
connected HDMI sink on pipe 0 with a test pattern: DCN init, HUBBUB/DML30
deadlines, the DAL clocks and the VBIOS PixelClock/STREAM_SETUP/transmitter
tables (sent to DMCUB as `DMUB_CMD__VBIOS` commands while DMUB runs, as
DCN3.0's `dmub_command_table`; the `atom.c`-faithful interpreter is the logged
fallback), then fetch and unblank. Model-tested per block; never run on
hardware. HPD/AUX/DDC engines are armed with native display (the default) or
`amdgpu.display_probe`; SMU interface mismatches, a fused-off or hung DMCUB,
stuck HUBP blanks and ASIC_Init's S7 bit are logged, not fatal, as in Linux.
The lit pipe is presented natively: console/status publication with the
`scanout_access` withdraw-before-teardown contract, DCN3.0 HUBP VSYNC page
flips completed from EARLIEST_INUSE (pflip/vupdate IH sources armed), a
256x256 DCN3.0 cursor (default; `amdgpu.rdna2_hw_cursor=0` disables), KMS on the amdgpu card (DP-1..3, HDMI-A-1;
DML30-admitted modes, SETCRTC/atomic/TEST_ONLY, disable, vblank, flip
events) and a monitor that relights after GPU recovery. Register models only.
Navi22 HDMI 2.0 (`amdgpu_dcn30_hdmi`): TMDS above 340 MHz scrambles (1/4
clock channel) after Linux's `write_scdc_data` (SCDC over native DDC; legacy
TMDS_Config 0 on every SCDC sink at enable and disable/unplug), opt-in 10/12-bpc
deep colour (`amdgpu.max_bpc`, FMT SPATIAL8/10 dither), YCbCr 4:2:0 for
Y420VDB/CMDB modes (OTG container, FMT, YCbCr709 OCSC, DPG black), Broadcast
RGB limited (OCSC), CTA VIC/HDMI-VIC vendor InfoFrames and HDMI_6GB_EN from the
VBIOS encoder caps. Register/DDC models only.
Navi22 multi-display (`amdgpu_navi22_multi`): up to four KMS CRTCs light as
one DC context — joint DML30 admission of every stream (`plan_joint`, at the
lowest supporting UCLK state; 234 host vectors from Linux's own DML30 C,
single/multi-stream, cursor, ODM, DSC), clocks and watermarks once, PHY PLL
sharing for identical HDMI timings, ODM 2:1 where one pipe cannot carry a
stream, DSC with FEC on DP SST (`amdgpu_dcn30_dsc`, training through the
shared DP link layer) and 8b/10b DP MST through the shared sideband manager
(`amdgpu_dcn30_mst`). Secondary CRTCs route automatically only with
`amdgpu.rdna2_multi` (still opt-in); only CRTC 0 presents (the others show
static scanouts).
Register models only; never run on hardware.
For bare-metal runs, `cargo xtask usb-image` builds a UEFI stick whose kernel
appends its log to `/narf-boot-<n>.log` on that stick (`narf.bootlog=`,
marker-gated, USB-only, bounded) and boots with `narf.disks=boot-only`: every
other disk is read-only at the block layer (writes refused, logged once) and
skipped by the boot-time mounts, and ext/btrfs mount a read-only device without
any repair or log-replay write (`usb-image --qemu` hashes decoy NVMe/SATA disks
before and after). NVMe I/O now builds PRP lists up to the controller's MDTS,
so the host's standard 128-entry GPTs are partition-scanned, and AHCI binds by
class (`01:06:01`, the AMD 600-series `1022:43f6`) with Linux's HBA
save/reset/restore and per-port COMRESET bring-up; both stay read-only under
`boot-only` (AMD AHCI untested: QEMU has only ICH9). A secondary card's cold boot keeps the iGPU
console live and ends with a per-stage summary (see
[docs/BOOTING_ON_CACHYOS.md](docs/BOOTING_ON_CACHYOS.md#rx-6750-xt-bring-up-boot)).
DCN3.0 HDMI and DP SST LPCM audio (`amdgpu_dcn30_audio`) follows Linux DC
(`dce_audio.c`, `dcn30_afmt.c`, `enc3_se_*_audio_*`, `dce110_*_audio_stream`):
audio wall-clock DTO0/DTO1, AFMT/ACR, the Audio InfoFrame and the Azalia
endpoint ELD from the EDID, behind a start-after-unblank / stop-before-blank
hook. The HD-Audio side binds 1002:ab28 (ATI HDMI NS, no snoop); a model of
the host's six-port R6xx HDMI codec (rev 0x100800) checks that endpoint `e`
reports jack and ELD on pin `3 + 2e` and routes playback there. Register
models only.
Mesa 26.2.4 radeonsi + RADV (ACO-only, llvmpipe fallback kept) now builds
reproducibly for NARF's musl userspace and stages into a rootfs; the
`mesa-amd-smoke` passes inside NARF under QEMU with no AMD GPU (clean
decline, software fallback renders) and the same binaries render on a Linux
amdgpu host ([Mesa AMD](docs/MESA_AMD.md)). libdrm_amdgpu's `GET_CLIENT` on
primary nodes is the first NARF gap Mesa hits.
The firmware path now follows Linux on the GOP-booted (SOS not alive) cold
path: KM-type PSP rings on every PSP generation, LOAD_TOC → SMC → SETUP_TMR
(PMFW-centralized C-states), DCN3.0's own FB register offsets, Linux's GART
placement at MC 0 (12272 MiB VRAM model), MEMSIZE-derived FB end, tolerated
GOP VMID0/DMUB windows/stopped-OTG pipes, an MP1 firmware-ready poll, Linux
(or longer) PSP/SMU/training deadlines, warn-only PSP status, golden settings
before SDMA plus the GC 10.3 power brake, and a non-fatal DMUB start after the
queue stages using the GMC aperture.
These were software-tested foundations. User command submission, media
submission, display-aware DPM gating and DCN3.0 modesetting have since landed
(register and fake-engine models only); GDDR6 training resume, VCN dynamic
power gating (DPG) and any hardware boot remain open. See the
[PCIe probe contract](drivers/gpu/specification/spec.md#amd-discrete-pcie-probe-and-vram). The native path now follows Linux's global order end to end (model-tested over one combined register fake, failure/cancellation per step), retires a live GOP stream like `dcn30_init_hw`, enables OPTC/OTG clocks, lights DP SST (native-AUX 8b/10b training with fallback, DP DTO, MSA/VSC) on any of the six pipes/routes, and quarantines underflows black. HPD/HPD_RX now arrive over the IH ring (DCE src 9) and wake the display monitor, with polling kept as the fallback. A host-side Linux conformance gate (`drivers/gpu/tools/navi22-conformance.sh`) checks about 2.5k annotated Navi22 constants against the exact Linux headers and discovery segments. It also checks NARF's firmware parsers against Linux's parsing of the real blobs. The DP link layer now follows Linux DC (`amdgpu_dcn30_dp_link`): capabilities with LTTPR transparent/non-transparent modes per the VBIOS DCE_INFO bits, TPS3/TPS4 by sink capability, adjust and post-LT adjust requests, destructive link verification with Linux's fallback order, the least verified link per stream, and DP modes in KMS bounded by the verified link; the monitor tears an unplugged display down without AUX, re-detects on HPD changes (dark connectors keep their EDID inventory), and retrains on HPD-RX/polled link loss. Register/AUX models only.

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
