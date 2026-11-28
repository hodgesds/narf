# kallsyms — Specification

## 1. Purpose & scope

Owns the byte format of the kernel symbol table stored in the image's
`.kallsyms` section, its build-time encoder and its run-time decoder. Does
not own symbol selection from an ELF (`build/cargo-narf/src/kallsyms.rs`), access
to the image's reservation (`narf_observability::kallsyms`) or the policy on
who may see addresses (`filesystem/` §3.14, `kallsyms_show_value`).

## 2. Assumptions

The table is written by the build, but the decoder treats it as untrusted
bytes: a stale, truncated or corrupt reservation must yield an error, never a
panic or an out-of-bounds read. All symbols lie in `[_text, _text + 4 GiB)`.

## 3. Public interface

Constants: `MAGIC` (`"KSYM"`), `VERSION` (1), `HEADER_LEN` (64),
`KSYM_NAME_LEN` (512, Linux's), `MAX_NAME` (511), `BLOCK` (16 names per
front-coding block), `TOKENS` (256), `MAX_NAMES` (2^24).

Layout, little-endian, no alignment requirement. Header: `magic u32`,
`version u16`, `header_len u16`, `num_syms u32`, `num_names u32`,
`text_link u64` (link-time `_text`), then u32 offsets of `offsets`, `types`,
`name_index`, `markers`, `names` (+ its length), `token_index`,
`token_bytes` (+ its length), and the total length. Regions:

| region        | contents |
|---------------|----------|
| `offsets`     | `u32 × num_syms`: symbol address − `_text`, ascending |
| `types`       | `u8 × num_syms`: `nm(1)` letter |
| `name_index`  | `u24 × num_syms`: index into the sorted unique names |
| `markers`     | `u32 × ⌈num_names/16⌉`: byte offset of each name block |
| `names`       | per name: `uleb(prefix)`, `uleb(ntok)`, `ntok` token codes |
| `token_index` | `u32 × 257`: token `c` is `token_bytes[idx[c]..idx[c+1]]` |
| `token_bytes` | expanded token strings; empty = unused code |

A name's `prefix` is the number of leading bytes it shares with the previous
name of its block (0 for a block's first). Tokens are Linux's best-pair
tokens: codes used as literals by some name expand to themselves; the rest,
assigned from 255 down, expand to a pair of earlier codes, pre-expanded.

Decoder (`no_std`, no allocation):

```rust
impl<'a> Table<'a> {
    pub fn parse(blob: &'a [u8]) -> Result<Self, Error>;  // validates all but the name stream
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
    pub fn num_names(&self) -> usize;
    pub fn text_link(&self) -> u64;
    pub fn entry(&self, index: usize) -> Option<Entry>;   // address order
    pub fn iter(&self) -> impl Iterator<Item = Entry> + '_;
    pub fn name(&self, name_index: u32, out: &mut NameBuf) -> Result<(), Error>;
    pub fn lookup(&self, offset: u64) -> Option<(Entry, Option<u32>)>;  // first alias, size
}
pub struct Entry { pub index: usize, pub offset: u32, pub kind: u8, pub name_index: u32 }
pub enum Error { Truncated, BadMagic, BadVersion, Malformed }
```

Encoder (`alloc` feature, host):

```rust
pub fn encode(text_link: u64, symbols: Vec<Symbol>) -> Result<(Vec<u8>, Stats), EncodeError>;
pub fn truncate_name(name: &str) -> &str;   // <= MAX_NAME bytes, on a char boundary
```

Symbols are ordered by Linux's `compare_symbols`: address, then non-weak
before weak, real symbols before linker-script bounds (`__start_*`,
`__*_end`, …), fewer leading underscores, then input order.

## 4. Invariants

No unsafe code. The decoder never panics and never reads outside the blob.
Encoding is deterministic (no hash-map iteration order). The token
algorithm's output equals `scripts/kallsyms.c`'s for the same strings. The
table contains no absolute address, so it is valid at any KASLR slide.

## 5. Architecture notes

Architecture-neutral; the same format on x86_64 and aarch64.

## 6. Dependencies

Only `core` (and `alloc` for the encoder). Used by `build/cargo-narf` (encoder)
and `observability/` (decoder).

## 7. Stage assignment

Stage 5: native-hardware profiling (`perf`, `bpftrace`, `crash`).

## 8. Open questions

Module symbols (`\t[module]` lines) once loadable modules publish symbol
tables; a name-sorted index for `kallsyms_lookup_name` if a kernel consumer
needs name → address.
