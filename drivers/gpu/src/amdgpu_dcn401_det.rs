//! CalculateDETBufferSize from Linux DML21's dml2_core_dcn4_calcs.c,
//! with DC's minimize_det_reallocation and without DET overrides.
use super::*;

/// Assign per-HUBP DET and return (unbounded requesting, compressed KiB).
/// Call on the ForceSingleDPP geometry before choosing MPC, and again on
/// the final geometry before any latency or mode-programming calculation.
pub(super) fn allocate(shapes: &mut [Shape]) -> (bool, u32) {
    if shapes.iter().any(|s| s.phantom) {
        // CalculateDETBufferSize excludes phantoms from the budgets. Their
        // swath/burst model uses 1 MiB; the actual HUBP gets zero DET.
        let mut main: Vec<Shape> = shapes.iter().copied().filter(|s| !s.phantom).collect();
        let result = allocate(&mut main);
        let mut main = main.into_iter();
        for s in shapes {
            if s.phantom {
                s.set_det(0);
            } else {
                *s = main.next().unwrap();
            }
        }
        return result;
    }
    let pipes: u32 = shapes.iter().map(|s| s.dpps).sum();
    let unbounded = pipes == 1
        && shapes
            .iter()
            .all(|s| s.c.is_none() && s.plane.swizzle != Swizzle::Linear);
    let swaths = |s: &Shape| {
        u64::from(s.y.full_swath_bytes) + u64::from(s.c.map_or(0, |c| c.full_swath_bytes))
    };
    if unbounded {
        let det = 128
            .max(ceil_to(2 * swaths(&shapes[0]), u64::from(SEGMENT_KBYTES) * 1024) as u32 / 1024);
        shapes[0].set_det(det);
        return (true, CONFIG_RETURN_KBYTES.saturating_sub(det));
    }

    let mut sizes = [0u32; MAX_PLANES];
    let mut pool = MAX_DET_KBYTES;
    for (i, s) in shapes.iter().enumerate() {
        let max_min = DET_KBYTES - if s.c.is_some() { SEGMENT_KBYTES } else { 0 };
        let full = swaths(s);
        let two = 128.max(ceil_to(2 * full, u64::from(SEGMENT_KBYTES) * 1024) as u32 / 1024);
        let min = if two <= max_min {
            two
        } else {
            128.max(ceil_to(full, u64::from(SEGMENT_KBYTES) * 1024) as u32 / 1024)
        };
        if s.dpps * min <= pool {
            sizes[i] = min;
            pool -= s.dpps * min;
        }
    }

    // DML intentionally truncates each plane's MB/s before adding it to
    // TotalBandwidthPerStream. Preserve that and the order of rounding:
    // IdealDETBudget compares against the per-pipe minimum, while only the
    // additional budget is divided across that plane's DPPs.
    let mut rates = [0u32; MAX_STREAMS];
    let mut bandwidth = [0u32; MAX_STREAMS];
    let mut read = [0.0; MAX_PLANES];
    for (i, s) in shapes.iter().enumerate() {
        rates[s.stream] = s.t.pixel_clock_khz;
        let bw = |u: &Surf| {
            f64::from(u.swath_single) * f64::from(u.bpp)
                / (f64::from(s.t.h_total) / f64::from(s.t.pixel_clock_khz) * 1000.0)
                * ratio_f(u.v_ratio)
        };
        read[i] = bw(&s.y) + s.c.as_ref().map_or(0.0, bw);
        bandwidth[s.stream] += read[i] as u32;
    }
    let total: u64 = rates.iter().map(|r| u64::from(*r)).sum();
    let budgets: [u32; MAX_STREAMS] = core::array::from_fn(|i| {
        (f64::from(rates[i]) * f64::from(MAX_DET_KBYTES) / total as f64) as u32
    });
    let mut remaining = budgets;
    let mut minimize = true;
    for (i, s) in shapes.iter().enumerate() {
        match remaining[s.stream].checked_sub(sizes[i] * s.dpps) {
            Some(rest) => remaining[s.stream] = rest,
            None => {
                minimize = false;
                break;
            }
        }
    }
    if minimize {
        for (i, s) in shapes.iter().enumerate() {
            let ideal =
                (read[i] / f64::from(bandwidth[s.stream]) * f64::from(budgets[s.stream])) as u32;
            if ideal > sizes[i] {
                let delta = (ideal - sizes[i]).min(remaining[s.stream]);
                sizes[i] += delta / s.dpps;
                remaining[s.stream] -= delta;
            }
            sizes[i] = sizes[i] / SEGMENT_KBYTES * SEGMENT_KBYTES;
        }
    } else {
        // A stream's pixel-rate budget cannot cover its minimums. DC falls
        // back to global bandwidth distribution, smallest surface first.
        let total: f64 = read[..shapes.len()].iter().sum();
        let mut assigned = [false; MAX_PLANES];
        let mut left = total;
        for (i, s) in shapes.iter().enumerate() {
            assigned[i] =
                f64::from(s.dpps * sizes[i]) / f64::from(MAX_DET_KBYTES) >= read[i] / total;
            if assigned[i] {
                left -= read[i];
            }
        }
        for _ in 0..shapes.len() {
            let mut next = None;
            for i in 0..shapes.len() {
                if !assigned[i] && next.is_none_or(|j| read[i] < read[j]) {
                    next = Some(i);
                }
            }
            let Some(i) = next else { break };
            let quantum = shapes[i].dpps * SEGMENT_KBYTES;
            let piece = ((f64::from(pool) * read[i] / left / f64::from(quantum) + 0.5) as u32
                * quantum)
                .min(pool / quantum * quantum);
            sizes[i] += piece / shapes[i].dpps;
            pool -= piece;
            assigned[i] = true;
            left -= read[i];
        }
    }
    for (i, s) in shapes.iter_mut().enumerate() {
        s.set_det(sizes[i]);
    }
    (false, SEGMENT_KBYTES)
}
