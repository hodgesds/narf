//! Linux dynamic CLOCKFD dispatch for precision hardware clock descriptors.
use super::*;
use crate::errno::wire::{EACCES, EFAULT, EINVAL, EOPNOTSUPP, EPERM};
use alloc::sync::Arc;
fn dynamic(id: i32) -> bool {
    id < 0 && id & 7 == 3
}
pub(crate) fn clock(id: i32, write: bool) -> Result<Arc<dyn narf_time::phc::HardwareClock>, i64> {
    let fd = (!(id >> 3)) as u32;
    let (ops, flags) = crate::fd::with_table(current_task_id(), |t| {
        t.get(fd)
            .map(|e| (e.ops.clone(), t.status_flags(fd).unwrap_or(0)))
    })
    .flatten()
    .ok_or(EINVAL)?;
    if write && flags & 3 == 0 {
        return Err(EACCES);
    }
    ops.hardware_clock().ok_or(EINVAL)
}
pub(super) fn gettime(id: i32, ptr: u64) -> Option<i64> {
    if !dynamic(id) {
        return None;
    }
    Some(
        (|| {
            let clock = clock(id, false)?;
            let ns = clock.read_ns().map_err(|e| -i64::from(e))?;
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&((ns / 1_000_000_000) as i64).to_ne_bytes());
            bytes[8..].copy_from_slice(&((ns % 1_000_000_000) as i64).to_ne_bytes());
            // SAFETY: guarded user copy validates the output timespec.
            unsafe { copy_to_user(ptr, &bytes) }.map_err(|_| EFAULT)?;
            Ok::<i64, i64>(0)
        })()
        .unwrap_or_else(|e| e),
    )
}
pub(super) fn getres(id: i32, ptr: u64) -> Option<i64> {
    if !dynamic(id) {
        return None;
    }
    Some(
        (|| {
            let _ = clock(id, false)?;
            if ptr != 0 {
                let mut bytes = [0u8; 16];
                bytes[8..].copy_from_slice(&1i64.to_ne_bytes());
                // SAFETY: guarded user copy validates the optional timespec.
                unsafe { copy_to_user(ptr, &bytes) }.map_err(|_| EFAULT)?;
            }
            Ok::<i64, i64>(0)
        })()
        .unwrap_or_else(|e| e),
    )
}
pub(super) fn settime(id: i32, ptr: u64) -> Option<i64> {
    if !dynamic(id) {
        return None;
    }
    Some(
        (|| {
            let clock = clock(id, true)?;
            let mut bytes = [0u8; 16];
            // SAFETY: guarded user copy validates the input timespec.
            unsafe { copy_from_user(&mut bytes, ptr) }.map_err(|_| EFAULT)?;
            let sec = i64::from_ne_bytes(bytes[..8].try_into().unwrap());
            let ns = i64::from_ne_bytes(bytes[8..].try_into().unwrap());
            if sec < 0 || !(0..1_000_000_000).contains(&ns) {
                return Err(EINVAL);
            }
            if !capable(CAP_SYS_TIME) {
                return Err(EPERM);
            }
            let time = (sec as u64)
                .checked_mul(1_000_000_000)
                .and_then(|v| v.checked_add(ns as u64))
                .ok_or(EINVAL)?;
            clock.set_ns(time).map_err(|e| -i64::from(e))?;
            Ok::<i64, i64>(0)
        })()
        .unwrap_or_else(|e| e),
    )
}
pub(super) fn adjtime(id: i32, ptr: u64) -> Option<i64> {
    if !dynamic(id) {
        return None;
    }
    Some(
        (|| {
            let mut bytes = [0u8; TIMEX_SZ];
            // SAFETY: Linux reads the complete timex before resolving the clock.
            unsafe { copy_from_user(&mut bytes, ptr) }.map_err(|_| EFAULT)?;
            let modes = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
            let clock = clock(id, modes != 0)?;
            if modes != 0 && !capable(CAP_SYS_TIME) {
                return Err(EPERM);
            }
            if modes & !(0x100 | 2 | 0x2000 | 0x1000) != 0 {
                return Err(EOPNOTSUPP);
            }
            let mut delta = 0i64;
            if modes & 0x100 != 0 {
                let sec = timex_i64(&bytes, TIMEX_OFF_TIME_SEC);
                let sub = timex_i64(&bytes, TIMEX_OFF_TIME_USEC);
                let nano = modes & 0x2000 != 0;
                if !(0..if nano { 1_000_000_000 } else { 1_000_000 }).contains(&sub) {
                    return Err(EINVAL);
                }
                delta = sec
                    .checked_mul(1_000_000_000)
                    .and_then(|v| v.checked_add(sub * if nano { 1 } else { 1000 }))
                    .ok_or(EINVAL)?;
            }
            let ppb = if modes & 2 != 0 {
                let freq = timex_i64(&bytes, TIMEX_OFF_FREQ);
                i32::try_from((freq as i128 * 1000) / 65536).map_err(|_| EINVAL)?
            } else {
                clock.frequency_ppb()
            };
            if modes != 0 {
                clock.adjust(delta, ppb).map_err(|e| -i64::from(e))?;
            }
            timex_put_i64(
                &mut bytes,
                TIMEX_OFF_FREQ,
                i64::from(clock.frequency_ppb()) * 65536 / 1000,
            );
            // SAFETY: guarded copy validates the output timex after driver success.
            unsafe { copy_to_user(ptr, &bytes) }.map_err(|_| EFAULT)?;
            Ok::<i64, i64>(0)
        })()
        .unwrap_or_else(|e| e),
    )
}
