#!/bin/bash
set -ex

export CARGO_TERM_COLOR=always
export RUSTFLAGS=""
export XTASK_QEMU_NO_BALLOON=1
export NARF_QEMU_MEM_MB=2048

echo "Running fmt"
cargo fmt --all -- --check

echo "Running host tests"
# Single source of truth for the host-test gate; also what CI's host-tests job
# runs. Covers narf-lib, narf-hid, the BPF host-testable crates, and the
# isolated login-core workspace.
cargo xtask host-test

echo "Running clippy (x86_64)"
cargo clippy -p narf-frame --target x86_64-unknown-none -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 --features boot-smoke,cgroup-all -- -D warnings

echo "Running clippy (aarch64)"
cargo clippy -p narf-frame --target aarch64-unknown-none -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 --features boot-smoke,cgroup-all -- -D warnings

# Clippy the TEST code too. The two stages above build with
# `boot-smoke,cgroup-all`, which compiles none of the `kernel-test`-gated
# modules — and in a project where the in-kernel test suites are a first-class
# deliverable, that left the majority of the test code unlinted. It had already
# drifted: `bpf/src/idreg.rs` and two sites in `drivers/gpu` were failing
# `-D warnings` under this feature set while every gate we ran stayed green.
echo "Running clippy (x86_64, kernel-test)"
cargo clippy -p narf-frame --target x86_64-unknown-none -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 --features kernel-test,cgroup-all -- -D warnings

echo "Running clippy (aarch64, kernel-test)"
cargo clippy -p narf-frame --target aarch64-unknown-none -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 --features kernel-test,cgroup-all -- -D warnings

echo "Running boot-smoke (x86_64)"
cargo xtask boot-smoke --arch=x86_64

echo "Running boot-smoke (aarch64)"
cargo xtask boot-smoke --arch=aarch64

echo "Running musl-demo (x86_64)"
XTASK_RI_PROMPT_TIMEOUT_SECS=900 XTASK_RI_ECHO_TIMEOUT_SECS=900 cargo xtask musl-demo --arch=x86_64

echo "Running net-smoke (x86_64)"
XTASK_RI_PROMPT_TIMEOUT_SECS=900 cargo xtask net-smoke --arch=x86_64

echo "Running kernel-test (x86_64)"
# Full runtime feature set so the container / PID-namespace / linux-compat
# kernel tests (e.g. the pid_ns translation suite) actually EXECUTE — cgroup-all
# alone leaves `container`+`linux-compat`-gated tests compiled-but-unregistered.
XTASK_QEMU_TIMEOUT_SECS=2400 XTASK_BOOT_SMOKE_TIMEOUT_SECS=1200 cargo xtask test --arch=x86_64 --features cgroup-all,container,linux-compat

echo "Running feature checks"
cargo check -p narf-userspace --no-default-features
cargo check -p narf-userspace --no-default-features --features 'linux-compat'
cargo check -p narf-userspace --no-default-features --features 'container'
cargo check -p narf-userspace --no-default-features --features 'linux-compat,container'
cargo check -p narf-userspace --no-default-features --features 'cgroup'
cargo check -p narf-userspace --no-default-features --features 'linux-compat,container,cgroup'

# The same sweep for the KERNEL crate, which the userspace-only checks above
# cannot cover: `narf-frame` is where cross-crate hook installation lives, so a
# feature that forwards to one dependency but not another breaks *here* and
# nowhere else. `container,cgroup` did exactly that — `frame`'s `cgroup` reached
# `narf-userspace` and `narf-filesystem` but not `narf-scheduler`, so
# `cross_crate_init` compiled calls to items that were configured out. It built
# under `cgroup-all` (which reaches scheduler via `narf-filesystem/cgroup-memory`)
# and under `container` alone, so every gate we ran was green while the
# documented Fedora/systemd boot command was broken.
#
# `cargo check` on the kernel target needs the build-std flags; these are the
# same ones the clippy stages above use.
KFLAGS="-Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128"
for f in 'container' 'cgroup' 'container,cgroup' 'cgroup-all' 'container,cgroup-all,linux-compat'; do
  echo "  narf-frame --features $f"
  # shellcheck disable=SC2086
  cargo check -p narf-frame --target x86_64-unknown-none $KFLAGS --features "$f"
done

echo "ALL CI TESTS PASSED"
