#!/bin/bash
set -eu

export CARGO_TERM_COLOR=always
export RUSTFLAGS=""
export XTASK_QEMU_NO_BALLOON=1
export NARF_QEMU_MEM_MB=2048

# By default this reproduces the FULL CI gate. Pass `--affected` to run only
# the jobs `cargo xtask affected` says the working-tree diff can touch (the
# same computation CI's `changes` job uses), so local pre-push checks match
# what CI will actually run on the PR. `--base <ref>` overrides the diff base
# (default origin/main).
AFFECTED=0
BASE="origin/main"
for arg in "$@"; do
  case "$arg" in
    --affected) AFFECTED=1 ;;
    --base=*) BASE="${arg#--base=}" ;;
    -h|--help)
      echo "usage: $0 [--affected] [--base=<git-ref>]"
      echo "  (no args)   run the full CI gate"
      echo "  --affected  run only the jobs affected by the diff vs --base"
      exit 0
      ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

FULL=true
RUN_CLIPPY=true
RUN_BOOT_SMOKE=true
RUN_MUSL=true
RUN_NET=true
RUN_KERNEL_TEST=true
RUN_FEATURE_MATRIX=true
ARCHES='["x86_64","aarch64"]'
SUBS=""

if [ "$AFFECTED" = 1 ]; then
  echo "Computing affected jobs vs $BASE ..."
  # `--event pull_request` so local pruning matches a PR (push/main forces
  # full). `--format github` prints `name=value` lines to stdout.
  PLAN="$(cargo xtask affected --format github --event pull_request --base "$BASE")"
  echo "$PLAN"
  get() { printf '%s\n' "$PLAN" | grep "^$1=" | cut -d= -f2-; }
  FULL="$(get full)"
  RUN_CLIPPY="$(get run_clippy)"
  RUN_BOOT_SMOKE="$(get run_boot_smoke)"
  RUN_MUSL="$(get run_musl_demo)"
  RUN_NET="$(get run_net_smoke)"
  RUN_KERNEL_TEST="$(get run_kernel_test)"
  RUN_FEATURE_MATRIX="$(get run_feature_matrix)"
  ARCHES="$(get clippy_arches)"
  SUBS="$(get subsystems)"
fi

# should <bool>  → true when a full run is requested or the gate is set.
should() { [ "$FULL" = "true" ] || [ "$1" = "true" ]; }
# arch_on <arch> → true when that arch is in the affected arch set.
arch_on() { printf '%s' "$ARCHES" | grep -q "\"$1\""; }

set -x

# ── always-on: cheap and catch everything (incl. the affected unit tests) ──
echo "Running fmt"
cargo fmt --all -- --check

echo "Running host tests"
# Single source of truth for the host-test gate; also what CI's host-tests job
# runs. Covers narf-lib, narf-hid, the BPF host-testable crates, xtask (which
# includes the `affected` unit tests), and the isolated login-core workspace.
cargo xtask host-test

if should "$RUN_CLIPPY"; then
  echo "Running clippy (x86_64)"
  cargo clippy -p narf-frame --target x86_64-unknown-none -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 --features boot-smoke,cgroup-all -- -D warnings

  if arch_on aarch64; then
    echo "Running clippy (aarch64)"
    cargo clippy -p narf-frame --target aarch64-unknown-none -Zbuild-std=core,compiler_builtins,alloc -Zbuild-std-features=compiler-builtins-mem,compiler-builtins-no-f16-f128 --features boot-smoke,cgroup-all -- -D warnings
  fi
fi

if should "$RUN_BOOT_SMOKE"; then
  echo "Running boot-smoke (x86_64)"
  cargo xtask boot-smoke --arch=x86_64

  if arch_on aarch64; then
    echo "Running boot-smoke (aarch64)"
    cargo xtask boot-smoke --arch=aarch64
  fi
fi

if should "$RUN_MUSL"; then
  echo "Running musl-demo (x86_64, all groups)"
  XTASK_RI_PROMPT_TIMEOUT_SECS=900 XTASK_RI_ECHO_TIMEOUT_SECS=900 cargo xtask musl-demo --arch=x86_64
fi

if should "$RUN_NET"; then
  echo "Running net-smoke (x86_64)"
  XTASK_RI_PROMPT_TIMEOUT_SECS=900 cargo xtask net-smoke --arch=x86_64
fi

if should "$RUN_KERNEL_TEST"; then
  echo "Running kernel-test (x86_64)"
  # Full runtime feature set so the container / PID-namespace / linux-compat
  # kernel tests (e.g. the pid_ns translation suite) actually EXECUTE — cgroup-all
  # alone leaves `container`+`linux-compat`-gated tests compiled-but-unregistered.
  # In --affected mode a non-empty subsystem filter runs only the relevant tests.
  if [ -n "$SUBS" ] && [ "$FULL" != "true" ]; then
    XTASK_QEMU_TIMEOUT_SECS=2400 XTASK_BOOT_SMOKE_TIMEOUT_SECS=1200 cargo xtask test --arch=x86_64 --features cgroup-all,container,linux-compat --subsystem "$SUBS"
  else
    XTASK_QEMU_TIMEOUT_SECS=2400 XTASK_BOOT_SMOKE_TIMEOUT_SECS=1200 cargo xtask test --arch=x86_64 --features cgroup-all,container,linux-compat
  fi
fi

if should "$RUN_FEATURE_MATRIX"; then
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
fi

set +x
echo "ALL CI TESTS PASSED"
