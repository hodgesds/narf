//! Fuzz target: the BTF blob parser.
//!
//! Surface: `narf_bpf_btf::Btf::parse` plus the per-type walks the
//! verifier performs on a parsed graph (`size_of`,
//! `skip_modifiers`, string-table lookups). The blob arrives
//! verbatim as the `BPF_BTF_LOAD` syscall argument — userspace
//! hands the kernel a self-describing type graph with offsets
//! into its own string and type sections, which is the classic
//! parser shape for offset-arithmetic bugs. The crate's own docs
//! already promise "never panics, for any input"; this target is
//! the machine that holds it to that promise continuously
//! instead of only at the hand-written negative tests.
//!
//! This cone is host-proven: narf-bpf-btf is in the CI host-test
//! gate (`cargo xtask host-test`) precisely because its input
//! comes straight from a syscall argument.
//!
//! Invariant: never panic, never read out of bounds. A `BtfError`
//! naming the failed check is the correct outcome for a malformed
//! blob.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(btf) = narf_bpf_btf::Btf::parse(data.to_vec()) {
        // Walk the decoded graph the way the verifier does: every
        // type's size and modifier chain, plus string lookups at
        // offsets the input itself suggests. All bounded by the
        // parser's own type count.
        for id in 1..=btf.nr_types() {
            let _ = btf.type_by_id(id);
            let _ = btf.size_of(id);
            let _ = btf.skip_modifiers(id);
        }
        if data.len() >= 4 {
            let off = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let _ = btf.name(off);
            let _ = btf.name(off % 1024);
        }
    }
});
