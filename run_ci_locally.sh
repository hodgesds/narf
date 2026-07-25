#!/bin/bash
set -ex

export CARGO_TERM_COLOR=always
export RUSTFLAGS=""
export XTASK_QEMU_NO_BALLOON=1
export NARF_QEMU_MEM_MB=2048

echo "Running fmt"
cargo fmt --all -- --check

echo "Running login-core tests"
cargo test --manifest-path userspace/login-core/Cargo.toml

echo "Running clippy (x86_64)"
cargo clippy -p narf-frame --target x86_64-unknown-none -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 --features boot-smoke,cgroup-all -- -D warnings

echo "Running clippy (aarch64)"
cargo clippy -p narf-frame --target aarch64-unknown-none -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 --features boot-smoke,cgroup-all -- -D warnings

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

echo "ALL CI TESTS PASSED"
