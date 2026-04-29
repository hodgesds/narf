# compat/win — Research

Reading list for the Win32-on-NARF compat layer.

## PE / COFF format
- Microsoft, *PE Format* — the canonical reference for PE32+
  headers, sections, imports, and relocations.
- Matt Pietrek, *An In-Depth Look into the Win32 Portable
  Executable File Format* (MSDN Magazine, Mar 2002 / Feb 2002) —
  the two-part article every PE loader implementer reads first.

## Win32 ABI
- Microsoft, *x64 calling convention* — register usage, shadow
  space, prologue/epilogue contract.
- Microsoft, *ARM64 ABI conventions* — divergence from AAPCS64
  for Win32 ARM64 (very small).

## Prior art
- WINE source tree (`dlls/ntdll`, `dlls/kernel32`, `loader/`) —
  the reference implementation. We will not vendor WINE; we'll
  read it for behavioural parity on edge cases.
- ReactOS — clean-room NT reimplementation; useful for understanding
  the PEB/TEB layout from a non-Microsoft perspective.
- DXVK — Direct3D 9/10/11 → Vulkan translation. Relevant once we
  get to graphics.

## NARF-internal pointers
- `userspace/specification/spec.md` — the underlying process model
  every WinProcess wraps.
- `abi/specification/spec.md` — submission/completion rings every
  thunk eventually lands on.
- `capabilities/specification/spec.md` — cap rules a Win32 thunk
  has to honour despite the foreign API surface.
