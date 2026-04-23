# filesystem — Research

## Primary sources

- **Linux VFS documentation** — reference for vocabulary and
  design-space exploration, even though NARF diverges on namespaces.
  <https://docs.kernel.org/filesystems/vfs.html>
- **POSIX.1-2024** — file operation semantics baseline for the
  relibc shim, not for core.
- **virtiofs specification** — shared-host-FS transport we expect to
  use early.
  <https://www.kernel.org/doc/html/latest/filesystems/virtiofs.html>

## Secondary sources

- **Plan 9 filesystem model** — everything-is-a-file pushed to its
  limit; influential even though NARF doesn't adopt it wholesale.
- **Fuchsia Filesystem documentation** — capability-oriented VFS,
  closest philosophical sibling to NARF's approach.
  <https://fuchsia.dev/fuchsia-src/concepts/filesystems>
- **Theseus OS FS design** — single-address-space Rust OS FS;
  interesting memory-safety framing.
- **ZFS ARC, Linux page cache** — prior art on unified caches if we
  pursue one.
- **littlefs** — small-footprint flash-safe filesystem, interesting
  for embedded targets. <https://github.com/littlefs-project/littlefs>
- **Rust `fuser`** — FUSE bindings; may help prototype FS drivers on
  Linux before bringing them in-tree.

## Distilled summaries

- `summaries/linux-vfs.md` — VFS architecture lessons for capability-based filesystems
- `summaries/virtiofs-spec.md` — VirtioFS paravirtualized shared filesystem

## Fetched this round (2026-04-22)

- `summaries/linux-vfs.md` — Linux VFS documentation
- `summaries/virtiofs-spec.md` — virtiofs specification

## Open research questions

- Encoding path caps: is a path just a dir-cap + relative string, or
  do we intern resolved paths for faster re-open?
- Dentry-cache equivalent — worth it or not?
- How to prevent "cap inflation" (many ambient open caps) while
  still being usable for normal programs.
- Performance of per-FS domains vs. shared-FS domain for similar
  filesystems.
