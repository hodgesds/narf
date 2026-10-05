//! Side-effect-free constraint solving. Enumerate format/rate/channel/period
//! count, then intersect the monotonic bounds on period frames. This handles
//! coupled byte/time/frame constraints without probing hardware or allocating
//! DMA during HW_REFINE.
use super::*;
use crate::{format::*, hardware::PcmCapabilities};

pub(super) const HW_BYTES: usize = 608;
// Interleaved mmap/read/write, planar read/write, pause/resume. No hardware linked-start,
// or noninterleaved mmap capability is advertised.
pub(super) const INFO: u32 = 1 | 2 | 0x20 | 0x100 | 0x200 | 0xc0000 | 0x2000_0000;

pub(super) fn format_id(format: SampleFormat) -> u32 {
    match format {
        SampleFormat::S16LE => 2,
        SampleFormat::S20LE => 25,
        SampleFormat::S24LE => 6,
        SampleFormat::S32LE => 10,
    }
}
fn mask_has(b: &[u8], index: usize, bit: u32) -> bool {
    get32(b, 4 + index * 32 + (bit as usize / 32) * 4) & (1 << (bit % 32)) != 0
}
fn mask_set(b: &mut [u8], index: usize, bit: u32) {
    let at = 4 + index * 32 + (bit as usize / 32) * 4;
    put32(b, at, get32(b, at) | (1 << (bit % 32)));
}
#[derive(Clone, Copy)]
struct Range {
    lo: u64,
    hi: u64,
}
impl Range {
    fn read(b: &[u8], i: usize) -> Result<Self, FsError> {
        let at = 260 + i * 12;
        let flags = get32(b, at + 8);
        let lo = get32(b, at) as u64 + u64::from(flags & 1 != 0);
        let hi = (get32(b, at + 4) as u64)
            .checked_sub(u64::from(flags & 2 != 0))
            .ok_or(FsError::InvalidData)?;
        if flags & 8 != 0 || lo > hi {
            return Err(FsError::InvalidData);
        }
        Ok(Self { lo, hi })
    }
    fn contains(self, v: u64) -> bool {
        (self.lo..=self.hi).contains(&v)
    }
}
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}
fn bound(lo: &mut u64, hi: &mut u64, r: Range, mult: u64, div: u64) {
    *lo = (*lo).max((r.lo * div).div_ceil(mult));
    *hi = (*hi).min(((r.hi + 1) * div).div_ceil(mult).saturating_sub(1));
}
fn values(p: HwParams) -> [u64; 12] {
    let frame = p.channels.count() as u64 * p.format.bytes_per_sample() as u64;
    let period = p.period_size as u64;
    let buffer = period * p.periods as u64;
    [
        p.format.bytes_per_sample() as u64 * 8,
        frame * 8,
        p.channels.count() as u64,
        p.rate.hz() as u64,
        period * 1_000_000 / p.rate.hz() as u64,
        period,
        period * frame,
        p.periods as u64,
        buffer * 1_000_000 / p.rate.hz() as u64,
        buffer,
        buffer * frame,
        0,
    ]
}
pub(super) fn refine(
    b: &mut [u8],
    caps: &PcmCapabilities,
    choose: bool,
) -> Result<Option<(HwParams, u32)>, FsError> {
    if b.len() != HW_BYTES {
        return Err(FsError::InvalidData);
    }
    let mut ranges = [Range { lo: 0, hi: 0 }; 12];
    for (i, r) in ranges.iter_mut().enumerate() {
        *r = Range::read(b, i)?;
    }
    let access = [0, 3, 4]
        .into_iter()
        .filter(|v| mask_has(b, 0, *v))
        .collect::<Vec<_>>();
    if access.is_empty() || !mask_has(b, 2, 0) || !ranges[11].contains(0) {
        return Err(FsError::InvalidData);
    }
    let mut masks = [0u8; 100];
    let mut min = [u64::MAX; 12];
    let mut max = [0u64; 12];
    let mut selected = None;
    for &format in &caps.formats {
        if !mask_has(b, 1, format_id(format))
            || !ranges[0].contains(format.bytes_per_sample() as u64 * 8)
        {
            continue;
        }
        for &rate in &caps.rates {
            if !ranges[3].contains(rate.hz() as u64) {
                continue;
            }
            for &channels in &caps.channels {
                let frame = channels.count() as u64 * format.bytes_per_sample() as u64;
                if !ranges[2].contains(channels.count() as u64) || !ranges[1].contains(frame * 8) {
                    continue;
                }
                let first = (caps.periods.0 as u64).max(ranges[7].lo);
                let last = (caps.periods.1 as u64).min(ranges[7].hi);
                for count in first..=last {
                    let mut lo = caps.period_frames.0 as u64;
                    let mut hi = caps.period_frames.1 as u64;
                    bound(&mut lo, &mut hi, ranges[5], 1, 1);
                    bound(&mut lo, &mut hi, ranges[6], frame, 1);
                    bound(&mut lo, &mut hi, ranges[4], 1_000_000, rate.hz() as u64);
                    bound(&mut lo, &mut hi, ranges[9], count, 1);
                    bound(&mut lo, &mut hi, ranges[10], count * frame, 1);
                    bound(
                        &mut lo,
                        &mut hi,
                        ranges[8],
                        count * 1_000_000,
                        rate.hz() as u64,
                    );
                    bound(
                        &mut lo,
                        &mut hi,
                        Range {
                            lo: caps.buffer_bytes.0 as u64,
                            hi: caps.buffer_bytes.1 as u64,
                        },
                        count * frame,
                        1,
                    );
                    let align = caps.period_byte_alignment.max(1) as u64;
                    let step = align / gcd(align, frame);
                    lo = lo.div_ceil(step) * step;
                    hi = hi / step * step;
                    if lo == 0 || lo > hi {
                        continue;
                    }
                    let p = HwParams {
                        format,
                        rate,
                        channels,
                        period_size: lo as u32,
                        periods: count as u32,
                    };
                    selected.get_or_insert((p, access[0]));
                    for period in [lo, hi] {
                        for (i, v) in values(HwParams {
                            period_size: period as u32,
                            ..p
                        })
                        .into_iter()
                        .enumerate()
                        {
                            min[i] = min[i].min(v);
                            max[i] = max[i].max(v);
                        }
                    }
                    mask_set(&mut masks, 1, format_id(format));
                }
            }
        }
    }
    let Some((params, chosen_access)) = selected else {
        return Err(FsError::InvalidData);
    };
    if choose {
        masks.fill(0);
        mask_set(&mut masks, 0, chosen_access);
        mask_set(&mut masks, 1, format_id(params.format));
        min = values(params);
        max = min;
    } else {
        for a in access {
            mask_set(&mut masks, 0, a);
        }
    }
    mask_set(&mut masks, 2, 0);
    let old = b.to_vec();
    b[4..100].copy_from_slice(&masks[4..100]);
    let mut changed = 0;
    for i in 0..3 {
        if old[4 + i * 32..36 + i * 32] != b[4 + i * 32..36 + i * 32] {
            changed |= 1 << i;
        }
    }
    for i in 0..12 {
        let at = 260 + i * 12;
        put32(b, at, min[i] as u32);
        put32(b, at + 4, max[i] as u32);
        put32(b, at + 8, 4);
        if old[at..at + 12] != b[at..at + 12] {
            changed |= 1 << (8 + i);
        }
    }
    put32(b, 512, 0);
    put32(b, 516, get32(&old, 516) | changed);
    put32(b, 520, INFO);
    put32(
        b,
        524,
        match params.format {
            SampleFormat::S20LE => 20,
            SampleFormat::S24LE => 24,
            _ => params.format.bytes_per_sample() as u32 * 8,
        },
    );
    put32(b, 528, params.rate.hz());
    put32(b, 532, 1);
    put64(b, 536, 0);
    Ok(choose.then_some((params, chosen_access)))
}
