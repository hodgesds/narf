# shmem — Userspace-Mappable Shared-Memory Objects

`narf-shmem` provides shared-memory regions that a process can map
into its own address space and that kernel-side consumers can read
through the identity map, so the two sides see the same physical
frames without a copy. A named object is a kernel-allocated, page-
aligned region of coherent frames owned by a process. Its handle is
the public name — the gate is a capability typed read-only or
read-write — and userspace brings the region into its address space
with a map syscall. There is also an anonymous shared-mapping
backing used for `MAP_SHARED` without a public handle, which tracks
per-page references in a sharded registry instead.

The point of the crate is zero-copy sharing between userspace
producers and in-kernel consumers. The motivating consumers are the
audio subsystem's transmit ring and the framebuffer's blit source:
userspace fills a region it mapped, and the kernel reads the pixel or
PCM data out of the same frames. A two-step create-then-map pattern
lets a caller hand a region to a kernel consumer without ever paying
for a userspace mapping, while the one-step path maps immediately for
callers that want to touch the bytes themselves.

Architecturally the crate follows the registry pattern used
elsewhere in the kernel: a static registry of live regions, a
monotonic handle-id allocator, and — importantly — an exit-observer
reaper hooked into the userspace process machinery, so that a
process's regions are reclaimed when it exits. Removal (explicit
destroy or process exit) retires the public handle but leaves
existing mappings valid until their final per-page reference drops,
which keeps teardown correct when multiple parties still hold the
frames. Per-region accounting ties a locked region's memory charge to
the owning user's lock limit. A per-handle frame cap bounds each
region's size, sized comfortably for today's consumers — audio
buffers, small blit sources such as icons and glyph atlases, and
ring-shaped command queues — and liftable when a larger use case
appears.

This crate is the kernel-side object and its lifecycle; the thin
user-facing wrapper that calls the shmem syscalls lives in the user
runtime SDK. It depends on the capability, memory, userspace, and
I/O layers and registers its reaper through the init machinery. It is
`no_std`.
