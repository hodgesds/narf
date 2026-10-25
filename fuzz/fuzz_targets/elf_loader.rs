//! Fuzz target: the ELF64 loader parser.
//!
//! Surface: `narf_userspace::elf::parse` — the first code that
//! touches an execve'd binary's bytes. Fully attacker-controlled
//! input (any user can exec any file they can write), parsed in
//! kernel context before any sandbox exists. Listed explicitly in
//! verification/specification/spec.md §7's initial targets.
//!
//! Invariant: never panic, never read out of bounds, for any byte
//! string. A structured `ElfError` is the correct outcome for a
//! malformed image. On a successful parse the loader's own output
//! contract is also asserted — every segment's file range must lie
//! inside the input and `mem_size` must cover `file_size` — because
//! the downstream loader trusts those properties when it starts
//! copying bytes into frames.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // libFuzzer inputs are bounded by -max_len in the nightly job;
    // the parser additionally caps its program-header table walk
    // at Linux's 64 KiB, so work per input is bounded by the input
    // size itself.
    if let Ok(image) = narf_userspace::parse_elf(data) {
        let len = data.len() as u64;
        for seg in &image.segments {
            let end = seg
                .file_off
                .checked_add(seg.file_size)
                .expect("parser produced a segment whose file range overflows");
            assert!(
                end <= len,
                "parser produced a segment extending past the image"
            );
            assert!(
                seg.mem_size >= seg.file_size,
                "parser produced a segment with mem_size < file_size"
            );
        }
    }
});
