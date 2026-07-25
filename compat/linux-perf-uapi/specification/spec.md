# Linux perf UAPI specification

## 1. Purpose & scope

Provide architecture-neutral constants and `#[repr(C)]` wire types from
Linux `include/uapi/linux/perf_event.h`. This crate describes ABI shape only;
it does not promise that NARF implements every described feature.

## 2. Assumptions

Linux integer types map to Rust fixed-width integer types of equal size and
alignment on NARF's supported 64-bit architectures.

## 3. Public interface

The crate exports `PerfEventAttr`, `PerfEventHeader`, attribute-size constants,
event/config constants, sample/read-format bits, attribute flag bits, and
record type/misc constants.

## 4. Invariants

`PerfEventAttr` is 144 bytes through Linux `PERF_ATTR_SIZE_VER9`; offsets and
all exported numeric values are ABI-stable. Unions and bitfields are exposed
as their underlying integer storage.

## 5. Architecture notes

The definitions are shared by x86_64 and aarch64. PMU event interpretation is
owned by architecture backends, not this crate.

## 6. Dependencies

No runtime dependencies. Canonical source:
`/usr/src/hodgesds-linux/include/uapi/linux/perf_event.h`, licensed
GPL-2.0 WITH Linux-syscall-note.

## 7. Stage assignment

Stage 4 compatibility.

## 8. Open questions

Automated regeneration from a pinned Linux UAPI revision may replace the
currently reviewed Rust transcription.
