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
picker that chooses among the available backends. The picker prefers
bochs when its BAR is reachable, because it has the lowest latency and
no command queue, and falls back to virtio-gpu otherwise. On top of
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
