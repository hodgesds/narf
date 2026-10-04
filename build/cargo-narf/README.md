# build/cargo-narf — Native Package Build / Install Frontend

`cargo-narf` is an optional `cargo narf` subcommand frontend for building
and installing NARF as a native distribution package. Where `xtask` is the
developer-facing build and test orchestrator, `cargo-narf` targets the
other end of the pipeline: turning a built kernel into a `.deb`, `.rpm`,
Arch, Gentoo, or tarball artifact and, on request, handing it to the host
package manager to install.

## What it does

It exposes three concerns at a high level: packaging a release into one or
more native formats, installing a built package through the host's native
package tooling, and detecting which package format the current host wants
(read from `os-release`). The `auto` format resolves to the host's native
format so the same invocation produces the right artifact on each distro,
and a reproducible-build timestamp can be pinned so artifacts are
byte-stable.

This crate is deliberately thin: it shells out to the real build (or
packages an already-built canonical kernel artifact) and to the system
package manager rather than reimplementing either. It is not part of the
inner development loop — day-to-day work goes through `build/xtask` — and
exists so NARF can be delivered through the same channels a distribution
kernel would be.
