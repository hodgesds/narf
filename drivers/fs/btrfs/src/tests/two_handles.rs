//! The soak integrity worker's sequence at the btrfs layer: two handles of
//! one file, overlapping writes through either.

use super::*;
use narf_filesystem::FsInstance;

const PAGE: u64 = 4096;
const LEN: u64 = 96 * PAGE;

/// Replay the first `ops` operations of the mapped-file integrity replay
/// (`smoke_btrfs_integrity_replay`, same generator and seed) at the btrfs
/// layer: a pwrite is a write of its range; a mapped store, which the
/// flusher writes back a whole page at a time, a write of the whole pages it
/// touches; a read or a fresh mapping, a read checked against the model; an
/// fsync or a writeback, a commit. Every operation must succeed or be
/// refused with ENOSPC — never fail with NotFound, which is what a write
/// got once a commit had failed and taken the file's creation with it — and
/// every read must return the model's bytes.
fn replay(sparse: &[u8], ops: usize, label: &str) -> Result<usize, &'static str> {
    use core::fmt::Write as _;
    let vol = mount_sparse(sparse).map_err(|_| "replay: fixture did not mount")?;
    let root = vol.root();
    let seed = alloc::vec![0x11u8; LEN as usize];
    let file = poll_once(root.create("narf.txt"))
        .and_then(|r| r.ok())
        .ok_or("replay: create failed")?;
    if !matches!(poll_once(file.write(0, &seed)), Some(Ok(n)) if n == seed.len()) {
        return Err("replay: seeding failed");
    }
    drop(file);
    let open = || {
        poll_once(root.lookup_async("narf.txt"))
            .and_then(|r| r.ok())
            .ok_or("replay: lookup failed")
    };
    let handles = [open()?, open()?];
    let mut model = seed;
    let mut state: u64 = 0x5eed_1234_abcd_9876;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for op in 0..ops {
        let kind = next() % 12;
        let from = next() % LEN;
        let span = 1 + next() % (12 * PAGE);
        let to = (from + span).min(LEN);
        let byte = (next() % 254 + 1) as u8;
        let h = (next() % 2) as usize;
        let outcome: Result<(), FsError> = match kind {
            0..=5 => {
                let (a, b) = if kind <= 2 {
                    (from, to)
                } else {
                    (from & !(PAGE - 1), to.next_multiple_of(PAGE).min(LEN))
                };
                model[from as usize..to as usize].fill(byte);
                let body = model[a as usize..b as usize].to_vec();
                match poll_once(handles[h].write(a, &body)) {
                    Some(Ok(n)) if n == body.len() => Ok(()),
                    Some(Ok(_)) => Err(FsError::InvalidData),
                    Some(Err(e)) => Err(e),
                    None => Err(FsError::InvalidData),
                }
            }
            6..=9 => {
                let (a, b) = if kind == 9 {
                    let page = from & !(PAGE - 1);
                    (page, page + PAGE)
                } else {
                    (from, to)
                };
                let mut buf = alloc::vec![0u8; (b - a) as usize];
                match poll_once(handles[h].read(a, &mut buf)) {
                    Some(Ok(n)) if n == buf.len() && buf == model[a as usize..b as usize] => Ok(()),
                    _ => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "btrfs-replay: {label}: op {op} read of [{a}, {b}) through handle {h} differs from the model"
                        );
                        return Err("replay: a read differs from the model");
                    }
                }
            }
            _ => match poll_once(vol.sync_to_disk()) {
                Some(Ok(())) => Ok(()),
                Some(Err(e)) => Err(e),
                None => Err(FsError::InvalidData),
            },
        };
        match outcome {
            Ok(()) => {}
            Err(FsError::NoSpace) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "btrfs-replay: {label}: ENOSPC at op {op} (kind {kind})"
                );
                return Ok(op);
            }
            Err(error) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "btrfs-replay: {label}: op {op} (kind {kind}, [{from}, {to}), handle {h}) failed: {error:?}"
                );
                return Err("replay: an operation failed other than with ENOSPC");
            }
        }
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("replay: the final commit failed");
    }
    Ok(ops)
}

/// The integrity replay's operations at the btrfs layer, on the
/// free-space-tree fixture (the allocator a root uses) for 600 operations,
/// and on the primary fixture (no free-space tree) until it runs out of
/// space: there the 52nd operation, a write, once failed with ENOENT after
/// an earlier commit had failed for space and been abandoned.
fn smoke_btrfs_two_handle_replay() -> TestResult {
    match replay(FIXTURE_FST_SPARSE, 600, "free-space tree") {
        Ok(_) => {}
        Err(e) => return TestResult::Fail(e),
    }
    match replay(FIXTURE_SPARSE, 600, "no free-space tree") {
        Ok(_) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_two_handle_replay);
