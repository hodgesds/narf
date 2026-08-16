# cargo-narf

`cargo-narf` builds NARF kernel artifacts into native Linux distribution
packages and installs them through the host package manager. It is a thin
frontend over the release tooling in the NARF source tree; it does not write
directly to `/boot`.

```sh
cargo install cargo-narf
git clone https://github.com/hodgesds/narf.git
cd narf
cargo narf detect
cargo narf install --version 0.1.0 --dry-run
```

Run commands inside a NARF checkout or pass `--repo /path/to/narf`. Supported
native outputs are Debian/Ubuntu `.deb`, Fedora/RPM `.rpm`, Arch
`.pkg.tar.zst`, and generation-only Gentoo ebuilds. See the repository's
[packaging guide](https://github.com/hodgesds/narf/blob/main/packaging/README.md)
for prerequisites, package contents, removal, and bootloader limitations.
