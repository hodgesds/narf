# Linux pipe compatibility and design review

Status: page-buffer implementation validated on
`test/pipe-syscall-linux-coverage`. Human/security review remains pending.
The compatibility boundaries below are not claims of measured performance
or exhaustive Linux parity.

## Reference and oracle

Reference checkout: `/usr/src/linux-7.3-rc4`; host kernel: `7.3.0-rc4`.

* `fs/pipe.c`: SHA-256
  `2ef3a1b0868271a2acd0a8071ca4088bd29fae1d552dbc9f8599612c5e4b4a0d`.
* `fs/splice.c`: SHA-256
  `0007b8585f867bd2945368fe36912b9d6301e5bce3d75c610a2609f42dbabf3e`.

`userspace/pipe-test/src/main.rs` is a libc-independent raw Linux syscall
fixture. The same assertions run as a host Linux executable and as a real
NARF user process on x86_64 and aarch64. The guest harness checks a completion
marker written only after every assertion passes; a premature exit cannot
count as success.

```sh
rustc --edition=2021 userspace/pipe-test/src/main.rs -o /tmp/narf-pipe-linux
/tmp/narf-pipe-linux
cargo xtask test --arch=x86_64 --features user-mode-e2e --subsystem verification/pipe-abi
cargo xtask test --arch=aarch64 --features user-mode-e2e --subsystem verification/pipe-abi
```

## Validation (2026-09-27)

* Host Linux: every raw-syscall fixture group passes, including six caught-signal
  cases (read, partial write, and zero-progress write, each with/without restart).
  Twenty consecutive functional runs pass with the start handshake and
  monotonic deadline; signal acknowledgment still requires the interrupted PC.
* Complete QEMU suites with `--features user-mode-e2e`: x86_64 **8668 pass,
  0 fail, 84 skip**; aarch64 **6614 pass, 0 fail, 42 skip**.
* Release and debug builds pass on both architectures. Clippy passes with
  `-D warnings` for the frame dependency graph including `kernel-test` and
  `user-mode-e2e`, on both targets.
  Host `--all-targets` Clippy also passes for `narf-lib` and the pipe fixture.
* Host `narf-lib` unit tests: **39 pass**; one ignored doctest. Workspace and
  standalone fixture formatting, diff whitespace, and safety-argument TOML
  plus invariant-reference checks pass.

The literal bare-metal `clippy --all-targets` command cannot build Rust's
host-style `test` crate (`E0463`). Kernel unit tests instead run in QEMU through
`kernel-test`; this limitation is recorded rather than calling that command
green. Musl-only fixtures without the optional toolchain and unavailable
hardware/features remain explicitly skipped by the normal harness.

## Behavior covered

* Creation flags, integer truncation, invalid pointers, descriptor exhaustion,
  descriptor reservation rollback, CLOEXEC and shared file-status flags.
* Scalar and vectored I/O, access direction, empty/live versus EOF, fault
  handling, atomic small writes, partial large writes, and page-slot fullness.
* Packet truncation, multi-page packets, packet flags across partial splice
  and tee, runtime O_DIRECT changes, and merge rights after shared transfers.
* Capacity queries/resizing, FIONREAD, non-seekability, poll and epoll levels,
  duplicated descriptors, final close, blocked reads and child exit.
* Splice, tee, vmsplice, sendfile and copy_file_range validation and errno
  ordering, zero counts, bad modes, offsets, empty/full and broken peers.
* SIGPIPE pending state and EPIPE with unchanged source buffers.
* Blocking scalar/vector writes larger than capacity, multiple-reader and multiple-writer wake
  continuation, and caught-signal interruption/SA_RESTART. Interrupted writes
  with committed data return that prefix exactly once, even with SA_RESTART.
  Writes blocked before making progress restart only with SA_RESTART; signal
  wake registration precedes the pending-signal check to prevent lost wakeups.
* Native memfd/tmpfs page imports, shared data after tee, file closure/unlink,
  and per-buffer commit after scalar/vector user faults.
* Named FIFO rendezvous, FIONREAD, resizing, packet I/O, and transfers between
  named and anonymous endpoints.
* vmsplice page-offset/slot accounting, shared data, and backing survival
  across source unmap and descriptor closure, fork COW, and shared RAM mappings.

## Design invariants under review

1. A pipe owns buffer descriptors with a retained page, offset, length,
   packet flag and merge right. Capacity limits descriptors, not free bytes.
2. Only the original mergeable tail can append beyond its published range.
   Tee copies no payload and gives the destination no merge right. Partial
   splice preserves the source's append right; whole splice transfers it.
3. Published owned-page ranges are immutable. Imported user pages are
   externally mutable; guarded assembly copies read them without forming a
   Rust reference to user-writable memory.
4. Pin acquisition retains physical backing while its authoritative mapping
   or file lock is held. Base-page pins release through the frame allocator;
   huge-page pins release through the huge-page pool. Device mappings are
   excluded. No pin is inferred from a detached Region snapshot. Base-page
   fork recognizes pin references separately from existing COW sharing.
5. Payload ownership uses per-pipe sleepable mutexes. Two-pipe operations take
   them in address order. Descriptor lookup locks are released before waiting.
6. Poll and final close do not take the payload mutex. Queue guards publish
   occupancy before unlock; per-pipe publication locks re-sample that state
   before notifying waiters so delayed publications cannot restore stale levels.
7. A read/actor commits only a fully copied buffer prefix. Errors after earlier
   progress return that progress; a short packet read alone discards its tail.
8. A completed transfer smaller than PIPE_BUF can nominate the exact selected
   exclusive waiter for a revalidated syscall-exit handoff. Bulk transfers use
   ordinary targeted wakes. This is a scheduling hint, not an unconditional
   sched_yield; Linux uses WF_SYNC wakeups rather than promising a handoff.
   Remaining data/space relays another exclusive waiter without manufacturing
   a poll edge.

## Performance review boundaries

There is no global pipe queue lock. Descriptor lookup still uses the existing
32 cache-line-separated map shards and per-description/table locks. Backing
allocation, shared-memory ownership and scheduler wakeups retain their own
subsystem synchronization; per-pipe locking is not a claim of an entirely
lock-free syscall path.

The buffer model removes eager 64-KiB payload allocation per empty pipe and
payload copies from pipe-to-pipe splice/tee. One exclusively owned drained page
can be reused for subsequent writes. Vector reads operate on page fragments
without a payload-sized staging allocation. Ordinary and packet pipes share
the same bounded ring implementation as named FIFOs.

Throughput/latency parity requires the statistical protocol in
`verification/specification/spec.md` §8. Functional QEMU runtimes are not
performance evidence.

## Provenance

Agent: OpenAI Codex, GPT-6.

Originating prompt: “lets make a new branch off of main to ensure we have
proper pipe related syscall coverage. we should check the errno return values
to ensure they functionally match linux and have proper userspace tests for
all types of pipe operations”. Follow-up scope: compare against upstream or
the local Linux checkout; achieve Linux parity in performance and design,
without correctness issues or gaps, with the full implementation on this branch.

The signal-interruption fixture also exposed a missing aarch64 Linux restorer
path and restart-pending SVC handling. The branch adds guarded Linux frame
construction/return, GPR/FPSIMD restoration and EL0-state validation. Vector
entry now also saves SP_EL0 and FP/SIMD state before Rust; vector return
restores them after Rust. The fixture checks the signal's saved PC to
acknowledge actual pipe interruption and deliberately clobbers a vector
register in the handler to verify restoration. This
supports the restorer-based path exercised by the fixture; it is not a claim
of complete Linux signal-extension support (SVE/SME/GCS).

The combined x86_64 suite also exposed a stale-PCID kernel-alias permission
after executable-memory reclamation: the fatal page-table walk showed writable
entries while the CPU reported a write-protection fault. Kernel-alias permission
changes now retire inactive non-global PCID translations as well as global
range entries. A two-address-space regression checks restoration before reuse.

Full-suite integration also corrects old byte-capacity assumptions in five
pipe ABI tests and gives each address space in the aarch64 preemption fixture
its own reference to the shared result page. The latter prevents double-free
corruption in subsequent userspace tests; the harness keeps a separate reference
until all result checks finish.

Coverage does not establish private hugetlb fork/pin snapshot parity. NARF's
existing private-hugetlb fork copies the child eagerly rather than implementing
Linux huge-page COW; retained huge-page lifetime is a separate guarantee.

The user authorized unsigned commits and will perform the security review at
the end. Maintainer review and merge remain separate from implementation.
