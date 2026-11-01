# Fingerprint reader chip-class scaffold — specification

## 1. Purpose & scope

This crate is the fingerprint readers' identity layer: the single
VID/PID match authority for the whole tree (issue #918), USB
device-descriptor parsing per USB 2.0 §9.6.1, and a probe-and-log
entry point. It owns no transport: endpoint discovery, xHCI
configuration, and `/dev/fp0` publication live in
`narf_drivers_usb::fingerprint`, which maps this crate's `Family`
to its transport vendor. Vendor protocols (enroll, capture, match)
are a userspace daemon's job by design; the kernel stays
transport-only.

## 2. Assumptions

- The table is sourced from libfprint's public device lists
  (BSD-licensed reference); no codec internals are imported.
- A (VID, PID) pair identifies a reader family; the pair is the
  whole match key (PID `0x00A2` legitimately appears under two
  VIDs — Synaptics `0x06CB` and Validity `0x138A`).
- The table is short (31 entries); a linear scan is the lookup,
  and a hashmap would just add startup cost.

## 3. Public interface

- `FINGERPRINT_DEVICES: &[FingerprintDevice]` — the single match
  authority. 31 entries: Synaptics Prometheus 8 (5 scaffold + 3
  live-table carryover, sub-family unverified — flagged at the
  table), Synaptics MIS-older 2, Goodix 9 (4 + 5 carryover),
  Validity 6, Elan 6 (5 + 1 carryover). Each entry carries
  `vid`, `pid`, `family`, and a human-readable `name`.
- `Family` — `SynapticsPrometheus | SynapticsMisOlder | Goodix |
  Validity | Elan`, with `Family::label()` (kebab-case, for the
  probe-log line).
- `match_vid_pid(vid, pid) -> Option<&'static FingerprintDevice>`
  — linear scan; `None` is the normal case for every other USB
  device and must not be treated as an error.
- `probe_from_descriptors(device_desc, cfg_desc) ->
  Option<&'static FingerprintDevice>` — parses VID/PID from the
  device descriptor (USB 2.0 §9.6.1 offsets), matches, bumps
  `FINGERPRINT_PROBED_COUNT`, and logs
  `fingerprint: detected <family>:<pid> "<name>" (<N> interfaces)`.
  Test-only: `__reset_for_test()`.
- `register_initcalls()` — Stage::Device initcall announcing the
  table size at boot. The table is `const`; there is no
  per-controller setup.

## 4. Invariants

- Exactly one match table exists in the tree. No second table may
  be introduced in a consumer crate: consumers map `Family`, they
  do not re-list VID/PIDs. (The pre-#918 tree violated this with
  a second 17-entry table in the USB binder; the two agreed on
  only 8 of a 31-device union and left Validity unbindable.)
- No duplicate (VID, PID) pairs in the table (pinned by
  `smoke_match_table_no_duplicate_vid_pid_pairs`).
- Table size and per-family counts are pinned by
  `smoke_match_table_size_matches_union`; any entry change
  updates the smoke in the same PR.
- Carryover entries whose sub-family or series is unverified are
  flagged at the table and in the PR that added them; a flagged
  label may be corrected without touching behaviour, because the
  USB binder maps both Synaptics families to the same transport
  arm.

## 5. Architecture notes (x86_64, aarch64)

No arch-specific code: pure `no_std` table lookup and descriptor
parsing. The crate's only production footprint is the
`register_initcalls` announce line wired in
`frame/src/bare_main.rs`; the live bind path reads the table
through `match_vid_pid` from the USB crate.

## 6. Dependencies

`narf-lib`, `narf-console` (probe log), `narf-init` (initcall),
`narf-kernel-test` (smokes). The crate depends on no driver
crate, so consumers (notably `narf-drivers-usb`) can depend on
it without a cycle.

## 7. Stage assignment

Stage 0 (identity/probe) of the fingerprint programme; the
transport built on it in the USB crate is the Stage-0 bind path.
Full software implementation (vendor protocols, daemon ABI,
lifecycle) is tracked by the fingerprint audit tracker (#917)
and its per-gap issues (#918–#924).

## 8. Open questions

- The three Synaptics live-table carryovers (`0x06CB:00C6`,
  `0x00DC`, `0x00FF`) carry `SynapticsPrometheus` by convention;
  their Prometheus vs MIS-older sub-family is unverified (the
  live table did not distinguish). Correcting the labels needs
  the libfprint source, not a guess.
- A third VID/PID list exists in `drivers/input/src/wbdi.rs`
  (`KNOWN_FP_IDS`, mirroring the pre-#918 live table, zero
  production callers). Reconciling it belongs to the WBDI lane
  (#919), not to this crate.
- No SPI/I2C fingerprint transports exist (#924); this table is
  USB VID/PID only.
