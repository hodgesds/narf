# bpf/btf — BPF Type Format Blob Parser

`narf-bpf-btf` reads the BPF Type Format (BTF) blob that a userspace loader
hands the kernel through `BPF_BTF_LOAD`. Every real loader — libbpf, bpftool,
systemd's BPF bits — ships a BTF section alongside its programs and expects to
load it and get a descriptor back, so accepting the blob is a hard
loader-compatibility requirement. This crate is the part of the subsystem that
parses and validates that blob and builds a type graph from it.

## What it is not

Crucially, this is not NARF's type system. A conventional BPF implementation
carries kfunc argument semantics inside BTF — in parameter-name suffixes and a
hardcoded list of special BTF type ids — but NARF derives those semantics from
Rust types through its `kfunc!` macro and a link-section registry instead. BTF
here is therefore purely a compatibility surface: a loader can submit a blob
and receive a descriptor, but nothing in the verifier consumes it. That framing
is why this crate is a small fraction of the size of the equivalent Linux code.
Several Linux BTF facilities are deliberately absent and staying absent — the
value pretty-printing path, in-kernel CO-RE relocation candidate finding, and
split or module BTF — because nothing in NARF calls them; a blob that would
require them is rejected rather than half-understood.

## Threat model

The blob arrives from userspace and every field in it is attacker-chosen, so a
parser bug here is a kernel panic or worse driven directly by a syscall
argument. The crate is written defensively against exactly that: it forbids
unsafe code and carries no dependencies; every offset and length is combined
with checked arithmetic in a wide integer type before use rather than with
wrapping addition in a narrow one; every access into blob-derived data goes
through fallible lookups rather than indexing or unwrapping; the whole-graph
walk is an explicit-stack depth-first traversal rather than recursion, because
its depth is a function of the attacker-supplied blob; and type-reference
cycles that would make a type walk non-terminating are detected and rejected
before any consumer can walk the graph.

## The shape of a blob

A BTF blob is a header followed by a type section and a string section, with
the two sections required to tile the space after the header exactly — no gap,
no overlap, nothing left over, and the string section last. Enforcing that
exact tiling removes a whole class of ambiguity about which bytes the producer
intended, and mirrors the rule the reference implementation applies. Points
where NARF's behaviour intentionally differs from Linux — chiefly the error
numbers returned for the unsupported-feature rejections — are pinned with
in-source markers at their sites.

## Relationships and no_std

This crate sits at the edge of the BPF subsystem as a loader-facing validator;
the parent `narf-bpf` runtime invokes it to service `BPF_BTF_LOAD`, and no
other BPF crate depends on its output. It is `no_std`, has zero dependencies,
and forbids unsafe code, so it is fully host-testable.
