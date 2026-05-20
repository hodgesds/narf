# AMDGPU scaffold audit (2026-05-20)

Snapshot of `drivers/gpu/src/amdgpu*.rs` at the start of the
"yeah let's see how far we get" arc. Targets: Phoenix HawkPoint1
(Zen4 + RDNA3.5, DCN 3.5, GFX 11.x) and Renoir / Lucienne /
Cezanne (Zen2 + Vega8, DCN 2.0, GFX 9.x).

Total scaffold: ~3,400 LOC across 11 files.

## Module-by-module status

| module                       | LOC | status     | what's there |
|------------------------------|-----|------------|--------------|
| `amdgpu.rs`                  | 738 | **mixed**  | PCI probe + BAR map + MM_INDEX/MM_DATA + VRAM aperture read all real. `passive_mode` (read UEFI-left OTG timing) real. `load_firmware` (PSP MP0 mailbox handshake) coded but FAILS CLOSED for Phoenix / Renoir / Navi2 / Navi3 because `Family::mp0_base()` returns `None` for them. `set_mode` is a TODO stub. |
| `amdgpu_offsets.rs`          | 146 | scaffold   | Runtime registry for per-family register block offsets (MP0, DCN HUBP/OPP/OTG, SMU, GC). Empty until bootstrap registers values. Once IP discovery lands, populated automatically. |
| `amdgpu_atombios.rs`         | 249 | parse-only | ATOMBIOS table-of-contents parse. Bytecode interpreter explicitly deferred — see line 31 "Stage-8 doesn't include the bytecode interpreter". Linux's `atom.c` (~1700 LOC, ~50 opcodes) is the reference. |
| `amdgpu_atom_dcn.rs`         | ?   | parse-only | DCN init data table decode. |
| `amdgpu_atom_encoder_caps.rs`| ?   | parse-only | EncoderCaps record iter + decode. |
| `amdgpu_atom_gpiopin.rs`     | ?   | parse-only | GPIO pin LUT decode (used for DDC bus probe). |
| `amdgpu_dcn.rs`              | 377 | codec-only | HUBP/OPP/OTG (offset, value) sequence builder via `build_modeset`. Doesn't execute MMIO — produces a `ModesetSequence` the driver core would write. Per-family base resolution goes through `amdgpu_offsets` (empty for our targets until IP discovery). |
| `amdgpu_pm4.rs`              | 179 | builder    | PM4 packet builder for GFX command submission. No submission path. |
| `amdgpu_pptable.rs`          | 169 | parse-only | PowerPlay table (SMU PPTable) parser. |
| `amdgpu_pptable_subtables.rs`| 223 | parse-only | PPTable subtable shapes. |
| `amdgpu_ring.rs`             | 164 | shell      | Generic ring buffer abstraction. No submission engine. |
| `amdgpu_rlc.rs`              | 189 | parse-only | RLC microcode header parser + autoload iter. |
| `amdgpu_ucode.rs`            | 128 | parse-only | Generic ucode header parser + payload extractor. |

Smoke coverage: 58 smokes in `drivers/gpu/src/tests.rs`, ~39
touching amdgpu paths. Solid for the structural surface.

## Keystone gap: IP discovery

Modern AMD silicon (Renoir, Navi 22, Navi 3x, Phoenix, Strix)
publishes an **IP Discovery Binary** at the top of VRAM that
enumerates every IP block on the chip with its MMIO base
address. Without this:

- `Family::mp0_base()` returns `None` → `load_firmware` fails
  closed. PSP can't load. Nothing downstream works.
- `amdgpu_offsets::offsets_of(family)` returns the default
  (zero) for HUBP / OPP / OTG / SMU / GC → DCN modeset can't
  emit valid (offset, value) pairs.

So **IP discovery is the keystone** for the modern-silicon path.
A worktree agent is on this (task #38). Linux reference:
`drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c`. Once landed,
every other piece can use `find_ip(blocks, HW_ID_MP0, 0).map(|b|
b.base_addrs[0])` instead of the hardcoded `mp0_base()` lookup
table.

## Dependency graph for downstream work

```
IP discovery (#38) ─┬──→ PSP load_firmware (#40) ─→ SMU handshake (#46)
                   │                                       │
                   ├──→ DCN base addresses                 │
                   │                                       ▼
                   └──→ ATOMBIOS bytecode interp (#41) ───→ DCN 2.0 modeset (#42)
                                                                │
                                       EDID/DDC (#44) ──────────┤
                                                                ▼
                                                       DP/HDMI link training (#45)
                                                                │
                                                                ▼
                                                       DCN 3.5 delta (#43)
                                                                │
                                                       (Phoenix scanout works)

GFX engine + PM4 submission (#47) gated on #38 + #40 + #46.
```

`#NN` references task IDs in the current session's task list.

## Realistic per-session scope

- Each named piece above (PSP, ATOMBIOS, DCN 2.0, EDID, link
  training, DCN 3.5 delta, SMU, GFX) is at least one full
  session. Some (DCN 2.0, ATOMBIOS interpreter) are multiple.
- Linux's `amdgpu/` is ~2 million lines for context. A complete
  feature-parity port would be many person-years. Targeting
  "modeset + scanout works on both laptops" is the bounded
  arc — gets us to a NARF-managed display pipeline replacing
  Limine FB handover, with brightness / multi-monitor / mode
  switch / hotplug. ~50-100k LOC of focused work.
- Each session lands one or two pieces with smoke coverage and
  commits incrementally. The whole arc is open-ended; we stop
  wherever the value/effort curve flattens.

## What's wrong with the existing scaffold (corrections to make)

1. `Family::mp0_base()` should consult IP discovery first, then
   fall back to the hardcoded table — wired by the IP discovery
   agent landing.
2. `amdgpu_dcn::build_modeset` returns `None` when offsets
   aren't registered. Once IP discovery populates HUBP/OPP/OTG
   bases, switch to a discovery-first lookup that doesn't go
   through the registry round-trip.
3. The `# Stage-1 scope` doc-comment in `amdgpu.rs` (line ~43)
   predates the current arc and reads stale. Refresh once IP
   discovery lands.
4. `set_mode` is a stub — see task #42.

## Source posture

The original scaffold predates the 2026-05-20 relicense and
opens with "No GPL Linux `amdgpu` source consulted". That
historical statement stays accurate for the existing 3,400 LOC.
New work (post-relicense, GPL-2.0-or-later) cites Linux
`drivers/gpu/drm/amd/amdgpu/` freely.
