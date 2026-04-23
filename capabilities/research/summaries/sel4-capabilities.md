# seL4 Capabilities (CSpace, CDT, invocation)

**Primary source:** seL4 Reference Manual (current),
§2 "Capabilities", §3 "System Calls", §4 "Invocations".

> Distilled for NARF design. Reading notes.

## The model in one paragraph

Every kernel-managed object (page, endpoint, thread, untyped memory
block, …) is referenced by **capabilities** — unforgeable tokens held
in per-task **CNodes**. A thread invokes the kernel by naming a
capability and an operation on it. The kernel has no ambient authority
namespace — the only way to do anything is to present a cap.

## CSpace

- Each thread has a **CSpace**: a tree of **CNodes** (arrays of cap slots).
- A capability is addressed by (CSpace root, index, guard bits) — much
  like a segmented page walk over cap space.
- CSpaces can be deep, wide, or both; the OS chooses the topology.

## Cap types

seL4 ships a fixed set of primitive cap types — thread, endpoint
(IPC rendezvous), notification, frame (a physical page), CNode,
untyped memory, IRQ handler, IO port, etc. **Untyped** is the
interesting one: it's a chunk of physical memory that can be *retyped*
into other objects via the `Retype` invocation — this is how the
kernel allocates without a heap.

## Derivation and badges

Two distinct concepts:

- **Derivation** creates a child cap with rights ⊆ parent. Example:
  a read-write frame cap can be derived into a read-only frame cap.
  Parent and child are linked in the **CDT** (Capability Derivation Tree).
- **Badging** attaches a 64-bit badge word to an endpoint cap. The
  badge is visible to the receiver on send, and is how "who is calling"
  is communicated — the sender *can't* forge a badge because only the
  kernel mints badged caps from an unbadged master cap.

## CDT (Capability Derivation Tree)

- The CDT is a per-kernel data structure tracking parent/child for every
  derived cap.
- **Revoke(c)** destroys every descendant of `c` (but keeps `c` itself).
- **Delete(c)** destroys a single cap; the kernel may have to walk the
  CDT to fix up children.
- CDT storage is O(number of caps) — not free, but bounded. This is the
  main cost NARF has to decide whether to pay.

## Invocation

- A syscall says "invoke cap at CSpace index X with opcode O and
  arguments A".
- The kernel walks X's CSpace to find the cap, checks it's valid,
  dispatches to the handler for the cap's type.
- For endpoint caps, invocation is an IPC send/recv. The receiver sees
  the sender's badge (if any).
- Invocations carry up to N more caps as "message caps" — this is how
  caps get transferred between tasks.

## Why it matters for NARF

- NARF's `Cap<T, R>` is conceptually identical to a seL4 cap — a typed
  reference with specific rights. The derivation rule (child rights ⊆
  parent rights) and the "you can't forge one" guarantee carry over.
- **Decision point**: CDT vs. a simpler refcount + badges scheme.
  - CDT pros: clean mass revocation (`Revoke` → cut a subtree).
  - CDT cons: memory cost per cap; complicated allocation.
  - Refcount pros: cheap per cap.
  - Refcount cons: mass revocation becomes a scan of every cap table.
  - NARF lean: CDT for kernel objects, plus Rust-level linear typing on
    the in-memory cap handle so many mis-uses become compile errors
    instead of runtime CDT invariant breaches.
- **Retype discipline**: if NARF adopts seL4-style untyped memory, the
  kernel never has a heap — very attractive for TCB minimality. Counter-
  point: async executors *want* a heap for task storage. We probably
  end up with "the TCB has no heap, but a sanctioned allocator lives in
  a domain above untyped."
- **Badged endpoints ↔ Narf-Rings**: a badged endpoint in seL4 is very
  close to a per-sender Narf-Ring producer cap. Same security story:
  the receiver trusts the kernel-supplied identifier, not the sender.

## Open questions this raises for NARF

- Are NARF Narf-Ring endpoints the only IPC primitive, or do we also
  have a seL4-style synchronous endpoint for low-rate control paths?
- How much of the CDT do we actually need if invocations are async?
  Revocation in an async world might be expressible as a cap-version
  stamp rather than a tree walk.
- Untyped memory analogue: does `memory/` expose NARF-untyped, or does
  the Frame hide allocation behind a capability-gated `alloc_object<T>`?
