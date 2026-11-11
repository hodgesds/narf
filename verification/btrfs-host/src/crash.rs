//! Crash consistency: replay prefixes of the recorded device stream with the
//! volatile write cache's possible outcomes, and require each crashed image
//! to be a clean btrfs that NARF remounts with exactly a committed state.
//!
//! Device model (an NVMe drive with a volatile write cache, the user's
//! root): at a cut after event `k`, every write before the last completed
//! flush is durable, as is every completed FUA write. Each other (volatile)
//! write is independently lost, kept, or torn at LBA granularity; for every
//! sector the newest persisted write wins. That covers every outcome a
//! reordering cache can leave behind at power loss (reordering is only
//! observable as which subset reached the media). FUA writes are never torn
//! (btrfs, like Linux, treats a superblock write as atomic).

use std::collections::BTreeMap;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::dev::{sb_generation, Ev, RecDev, SB_LEN, SB_OFFSETS};
use crate::host::block_on;
use crate::linux;
use crate::model::{diff, Cmp, FlatTree};
use crate::workload::{CommitRec, Rng};

pub struct Input<'a> {
    pub base: &'a Path,
    pub log: &'a [Ev],
    pub commits: &'a [CommitRec],
    pub base_gen: u64,
    pub base_state: Vec<FlatTree>,
    pub lba: u32,
    pub fsid: [u8; 16],
    pub nodesize: u32,
    pub root_subvol: &'a str,
    pub others: &'a [&'a str],
}

#[derive(Clone, Debug)]
pub struct Opts {
    pub cuts: usize,
    pub exhaustive: bool,
    pub seed: u64,
    pub jobs: usize,
    pub workdir: PathBuf,
}

#[derive(Default, Debug)]
pub struct Report {
    pub cuts: usize,
    pub flush_boundaries: usize,
    pub torn: usize,
    pub dropped: usize,
    pub gens_seen: BTreeMap<u64, usize>,
    pub failures: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
enum Variant {
    All,
    None,
    Random,
}

fn apply(f: &std::fs::File, off: u64, data: &[u8]) {
    f.write_all_at(data, off).unwrap();
}

/// Which variant and which cut points to run.
fn choose_cuts(log: &[Ev], opts: &Opts, rng: &mut Rng) -> Vec<(usize, Variant)> {
    let flushes: Vec<usize> = log
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, Ev::Flush))
        .map(|(i, _)| i)
        .collect();
    let mut points: Vec<(usize, Variant)> = Vec::new();
    // Right before and right after every flush (the window is then full or
    // empty), plus random points inside windows with random cache outcomes.
    for &f in &flushes {
        points.push((f, Variant::All));
        points.push((f + 1, Variant::All));
        points.push((f, Variant::None));
    }
    points.push((log.len(), Variant::All));
    let windows = flushes.len() + 1;
    let random = if opts.exhaustive {
        2 * windows
    } else {
        opts.cuts
    };
    for _ in 0..random {
        points.push((rng.below(log.len() as u64 + 1) as usize, Variant::Random));
    }
    if !opts.exhaustive && points.len() > opts.cuts {
        // Keep an even spread of boundary points plus the random ones.
        let (mut boundary, rand): (Vec<_>, Vec<_>) = points
            .into_iter()
            .partition(|(_, v)| !matches!(v, Variant::Random));
        let keep_b = opts.cuts.div_ceil(2).min(boundary.len());
        let step = boundary.len() as f64 / keep_b.max(1) as f64;
        let mut picked: Vec<(usize, Variant)> = (0..keep_b)
            .map(|i| boundary[(i as f64 * step) as usize])
            .collect();
        // Always the very end (a clean shutdown's image).
        picked.push(boundary.pop().unwrap());
        picked.extend(rand.into_iter().take(opts.cuts - keep_b));
        points = picked;
    }
    points.sort_by_key(|p| p.0);
    points.dedup_by_key(|p| {
        (
            p.0,
            matches!(p.1, Variant::Random) as u8 + matches!(p.1, Variant::None) as u8 * 2,
        )
    });
    points
}

pub fn run(inp: &Input, opts: &Opts) -> Report {
    let mut rep = Report::default();
    let mut rng = Rng::new(opts.seed ^ 0xc4a5);
    let cuts = choose_cuts(inp.log, opts, &mut rng);
    rep.flush_boundaries = inp.log.iter().filter(|e| matches!(e, Ev::Flush)).count();
    std::fs::create_dir_all(&opts.workdir).unwrap();
    let durable = opts.workdir.join("durable.img");
    linux::clone_file(inp.base, &durable);
    let dfile = std::fs::OpenOptions::new()
        .write(true)
        .open(&durable)
        .unwrap();
    let mut applied = 0usize;

    // gen → acceptable per-subvolume states.
    let mut states: BTreeMap<u64, Vec<Vec<FlatTree>>> = BTreeMap::new();
    states
        .entry(inp.base_gen)
        .or_default()
        .push(inp.base_state.clone());
    for c in inp.commits {
        states
            .entry(c.gen)
            .or_default()
            .extend(c.candidates.iter().cloned());
    }

    let mut checks: Vec<(std::process::Child, PathBuf, String)> = Vec::new();
    let reap =
        |checks: &mut Vec<(std::process::Child, PathBuf, String)>, rep: &mut Report, all: bool| {
            while !checks.is_empty() && (all || checks.len() >= opts.jobs) {
                let (child, img, what) = checks.remove(0);
                if let Err(e) = linux::wait_check(child, &what) {
                    rep.failures.push(format!("{what}: {e}"));
                    let keep = img.with_extension("failed.img");
                    let _ = std::fs::rename(&img, &keep);
                } else {
                    let _ = std::fs::remove_file(&img);
                }
            }
        };
    let started = Instant::now();
    for (n, &(k, variant)) in cuts.iter().enumerate() {
        if rep.failures.len() >= 8 {
            break;
        }
        let last_flush = inp.log[..k].iter().rposition(|e| matches!(e, Ev::Flush));
        let durable_end = last_flush.unwrap_or(0);
        for ev in &inp.log[applied.max(0)..durable_end.max(applied)] {
            if let Ev::Write { off, data, .. } = ev {
                apply(&dfile, *off, data);
            }
        }
        applied = applied.max(durable_end);

        let img = opts.workdir.join(format!("cut{n:04}.img"));
        linux::clone_file(&durable, &img);
        let f = std::fs::OpenOptions::new().write(true).open(&img).unwrap();
        let mut expect_gen = inp.base_gen;
        for ev in &inp.log[..k] {
            if let Ev::Write {
                off,
                data,
                fua: true,
            } = ev
            {
                if *off == SB_OFFSETS[0] && data.len() as u64 == SB_LEN {
                    expect_gen = sb_generation(data);
                }
            }
        }
        let window_start = last_flush.map_or(0, |f| f + 1);
        for ev in &inp.log[window_start..k] {
            let Ev::Write { off, data, fua } = ev else {
                continue;
            };
            if *fua {
                apply(&f, *off, data);
                continue;
            }
            match variant {
                Variant::All => apply(&f, *off, data),
                Variant::None => rep.dropped += 1,
                Variant::Random => match rng.below(4) {
                    0 | 1 => apply(&f, *off, data),
                    2 => rep.dropped += 1,
                    _ => {
                        rep.torn += 1;
                        let s = inp.lba as usize;
                        for (i, sector) in data.chunks(s).enumerate() {
                            if rng.chance(50) {
                                apply(&f, *off + (i * s) as u64, sector);
                            }
                        }
                    }
                },
            }
        }
        drop(f);
        let what = format!(
            "cut {n} (event {k}/{}, {variant:?}, gen {expect_gen})",
            inp.log.len()
        );
        rep.cuts += 1;
        *rep.gens_seen.entry(expect_gen).or_default() += 1;

        let mut sb = vec![0u8; SB_LEN as usize];
        std::fs::File::open(&img)
            .unwrap()
            .read_exact_at(&mut sb, SB_OFFSETS[0])
            .unwrap();
        if sb_generation(&sb) != expect_gen {
            rep.failures.push(format!(
                "{what}: primary superblock generation {}",
                sb_generation(&sb)
            ));
            continue;
        }
        // Linux's verdict runs in the background on this copy; NARF gets its
        // own (it writes when it mounts).
        let narf_img = opts.workdir.join(format!("cut{n:04}-narf.img"));
        linux::clone_file(&img, &narf_img);
        reap(&mut checks, &mut rep, false);
        checks.push((linux::spawn_check(&img, false), img, what.clone()));

        let Some(want) = states.get(&expect_gen) else {
            rep.failures.push(format!(
                "{what}: no modelled state for generation {expect_gen}"
            ));
            continue;
        };
        match narf_verify(inp, &narf_img, want, n % 4 == 0) {
            Ok(()) => {
                let _ = std::fs::remove_file(&narf_img);
            }
            Err(e) => {
                rep.failures.push(format!("{what}: {e}"));
                let _ = std::fs::rename(&narf_img, narf_img.with_extension("failed.img"));
            }
        }
        if opts.exhaustive && n % 50 == 49 {
            eprintln!(
                "    crash: {}/{} cuts, {:.0?}",
                n + 1,
                cuts.len(),
                started.elapsed()
            );
        }
    }
    reap(&mut checks, &mut rep, true);
    let _ = std::fs::remove_file(&durable);
    rep
}

/// Mount the crashed image as the next boot would, compare every subvolume
/// to one acceptable state, and optionally write on and re-check it.
fn narf_verify(
    inp: &Input,
    img: &Path,
    want: &[Vec<FlatTree>],
    write_after: bool,
) -> Result<(), String> {
    let dev = Arc::new(RecDev::open(img, inp.lba, inp.fsid, inp.nodesize));
    crate::narf::register_root(dev.clone(), &inp.fsid)?;
    let views = crate::narf::mount_root_rw(&inp.fsid, inp.root_subvol, inp.others)?;
    let mut got = Vec::new();
    for v in &views {
        got.push(crate::narf::walk(&v.root())?.0);
    }
    let cmp = Cmp {
        perms: true,
        xattrs: true,
        dir_perms: true,
    };
    let mut best: Option<Vec<String>> = None;
    for cand in want {
        let d: Vec<String> = cand
            .iter()
            .zip(&got)
            .flat_map(|(w, g)| diff(w, g, cmp, 6))
            .collect();
        if d.is_empty() {
            best = None;
            break;
        }
        if best.as_ref().is_none_or(|b| d.len() < b.len()) {
            best = Some(d);
        }
    }
    if let Some(d) = best {
        return Err(format!(
            "NARF remount differs from every state committed at that generation ({} candidates):\n  {}",
            want.len(),
            d.join("\n  ")
        ));
    }
    if write_after {
        // The recovered filesystem must stay writable and consistent.
        let root = views[0].root();
        block_on(async {
            let f = root.create("post-crash-write").await?;
            f.write(0, &vec![0x5a; 20000]).await?;
            root.syncfs().await
        })
        .map_err(|e| format!("post-crash write: {e:?}"))?;
    }
    drop(views);
    crate::narf::reset();
    if !dev.violations().is_empty() {
        return Err(format!("request-shape violations: {:?}", dev.violations()));
    }
    if write_after {
        linux::check(img, false).map_err(|e| format!("after post-crash write: {e}"))?;
    }
    Ok(())
}
