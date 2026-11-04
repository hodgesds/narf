# fb — Framebuffer Scanout Abstraction

`narf-fb` is the framebuffer scanout layer. It sits between the
kernel's display drivers (bochs-display, virtio-gpu) and anything that
wants to push pixels — the in-kernel draw protocol, a userspace test
binary, a future Wayland-shaped compositor — and gives them a single,
backend-independent surface to draw through. Its central
responsibility is to decide which scanout is active and to hand out a
safe writer over it.

A scanout backend is any device that can present a linear buffer to
the display. This crate defines the trait each backend implements —
exposing dimensions, pixel format, and a flush hook that is a no-op on
bochs but becomes a transfer-and-flush sequence on virtio-gpu — and a
picker that chooses among the available backends. After pause/test policy,
it prefers the generic boot/adopted mapping and native AMD scanout, then
reachable bochs, ready virtio-gpu and native Intel. On top of
the active scanout it provides a writer offering bounds-checked fill,
blit, and flush primitives.

Access is mediated by the capability system rather than left open. The
scanout is represented by a capability type with distinct read and
write rights: a read capability can only query dimensions, while a
write capability grants full draw access, and the writer's constructor
requires the write capability so unauthorized callers cannot
instantiate one. No syscalls live in this crate; a bootstrap authority
mints the initial write capability during bring-up, and later
producers narrow their rights through the capability lattice. The
crate also contains the producer/consumer plumbing for an in-kernel
draw command ring (fill/blit/flush commands drained by a worker task),
a framebuffer device bridge, cursor handling, a status panel, and the
GOP/VBE firmware-framebuffer paths.

The crate is `no_std` and one of the more connected in the tree: it
depends on `narf-graphics` for pixel primitives, on the bochs/virtio
GPU drivers for backends, and on `narf-capabilities`, `narf-ipc`,
`narf-shmem`, `narf-memory`, `narf-scheduler`, `narf-userspace`, and
`narf-filesystem` to wire the scanout into the capability model, the
device filesystem, and the userspace draw path. A `kernel-test`
feature lets it suppress live status-panel repaints while a test
installs a synthetic scanout.

For Navi22 and Navi48, a final synchronous boot initcall pauses the early console and
cached writers while the GPU firmware owner trains GDDR6 and boots firmware.
It is registered during Subsys so firmware scans and ordinary Late setup run
first; it completes before executor polling or userspace framebuffer mappings.
Preflight failures restore access. Once hardware startup begins, a failure on
the primary GPU leaves framebuffer access unavailable pending recovery; serial
logging continues. This boot-only handoff cannot revoke runtime mmap writers.
See the [GPU handoff contract](../drivers/gpu/specification/spec.md#navi-22-boot-ownership-and-framebuffer-handoff).
Navi48 selects its PSP14/SMU14/GMC12/SDMA7/DCN4 owner and preserves the same
preflight rollback and primary-framebuffer quarantine behavior.

Runtime generic scanout replacement uses `narf_drivers_gpu::scanout_access`
epochs. FbWriter drawing, cursor/status views and DRM fallback copies retain
their mapping until the last CPU access finishes. Navi48 withdrawal and flips
drain retired epochs before teardown or back-buffer reuse. Leases keep IRQs
enabled but prevent task preemption until a device-memory fence completes;
they must not cross a yield or await. Raw framebuffer views require the same
lease or independent ownership of the backing. A failed boot restoration
clears the mapping so cached writers become empty. This CPU barrier does not
prove hardware fetch retirement. Navi48's monitor combines it with native
fetch/route/power checks and an HDP/PCIe drain before releasing current and
parked display-only VRAM reservations after successful teardown.

Framebuffer device mmap backings request WC, matching device scanout mappings;
the address-space owner keeps RAM-backed scanout leaves WB. The devfs proxy
forwards the complete backing and its attributes. Rebased native AMD generic
scanouts continue to expose no physical fbdev mmap backing.

DRM's kernel copy path can also present into the permanent boot framebuffer
through its current kernel mapping. The live physical range and geometry must
still match the original boot publication, and the copy retains a scanout epoch
lease. This supports a UEFI GOP selected ahead of a virtual display driver;
it does not expose a userspace mmap. Adopted external displays continue to
require the native owner's live publication, and boot GPU quarantine refuses
all copy targets.

Serial/headless Intel LNL/PTL takeover uses a permanent boot-publication gate.
Boot framebuffer registration records history before publication; withdrawal
and pause cannot erase it. Exclusion succeeds only before any boot framebuffer
or graphics console was published, with no paused/current boot backend, and
prevents subsequent generic boot registration. The Subsys installer runs before
Late GT startup; initial graphical-boot takeover is refused. Later independently
owned GPU adoption keeps its existing publisher/backing checks. See the
[publication interface](../graphics/specification/spec.md#3-public-interface)
and [GPU contract](../drivers/gpu/specification/spec.md#intel-headless-lnlptl-main-gt-execution).
