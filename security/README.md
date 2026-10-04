# security — KSPP-Style Hardening Aggregator

`security` is the kernel's security-posture crate: a small, `no_std`,
dependency-light layer that sits *above* the per-arch and per-subsystem
hardening mechanisms and gives the rest of the kernel a single place to
reason about policy. It does not implement the hardening primitives
themselves — SMEP/SMAP/CET on x86_64, PAC/MTE on aarch64, W^X, KASLR,
read-only-after-init, and stack-frame canaries all live in their own
`arch/` and `memory/` modules — but it collects their state and layers a
few cross-cutting policies on top. The framing is explicitly comparative:
Linux exposes roughly forty hardening knobs through
`kernel-parameters.txt` and even kernel developers struggle to enumerate
which are live on a given boot, so this crate surfaces the actual
silicon-and-software combination once, in one place, for anyone to read.

Three concerns live here. The first is the **boot-time posture report**:
the security-init path fills in a single summary describing which
hardening floors are mandatory and which optional enables are active —
including the KPTI posture (native single-page-table operation on
Meltdown-immune parts versus page-table isolation on vulnerable Intel).
Observability can then report "which knobs are live" without each
subsystem rediscovering its own state at runtime. The second is
**pointer redaction**: rather than Linux's system-wide `kptr_restrict`
runtime knob and `%pK` format specifier, NARF makes redaction a
capability check. Kernel-half virtual addresses (at or above the
architecture's kernel-VA cutoff — bit 47 on x86_64, bit 55 on aarch64)
are stripped from any diagnostic whose reader cannot prove it holds the
kernel-debug capability; user-half pointers, which do not leak kernel
layout, pass through. The third is **capability-leak detection**, a
debug-only guard tied to NARF's `Cap<T, Right>` privilege model. A write
-capable capability held across an `.await` boundary and resumed in a
different domain is a layout-leak vector (a Spectre-v1-style attack
against the dispatcher, since the scheduler does not guarantee
task-to-domain affinity); the runtime assert here detects that bad
ownership flow, spiritually analogous to Linux's lockdep, and is a no-op
in release builds. A compile-time lint attribute is the intended
long-term defence, and this module is its receiver.

The crate is deliberately `no_std` and stable: it pulls in neither
`alloc` nor arch-specific intrinsics, so per-arch enabling stays in
`arch/`. It depends only on `narf-lib` and the kernel test harness.
