//! Userspace-owned controls. OPERATIONS serializes changes; the separate data
//! mutex is never held over backend I/O. Copies use the calling process context.
use super::*;
struct Element {
    card: u32,
    info: Vec<u8>,
    count: u32,
    access: u32,
    stride: usize,
    values: Vec<u8>,
    names: Vec<u8>,
    tlv: Vec<u8>,
}
impl Element {
    fn id(&self, offset: u32) -> [u8; 64] {
        let mut b = [0; 64];
        b.copy_from_slice(&self.info[..64]);
        put32(&mut b, 0, get32(&self.info, 0) + offset);
        put32(&mut b, 60, get32(&self.info, 60) + offset);
        b
    }
    fn offset(&self, b: &[u8]) -> Option<u32> {
        let num = get32(b, 0);
        let at = if num != 0 {
            num.checked_sub(get32(&self.info, 0))?
        } else {
            if b[4..16] != self.info[4..16] || name(b) != name(&self.info) {
                return None;
            }
            get32(b, 60).checked_sub(get32(&self.info, 60))?
        };
        (at < self.count).then_some(at)
    }
    fn allocation(&self) -> usize {
        320 + self.values.len() + self.names.len() + self.tlv.len()
    }
}
static ELEMENTS: Mutex<Vec<Element>> = Mutex::new(Vec::new());
// Monotonic IDs avoid aliasing queued events when a control is removed/replaced.
static NEXT_NUMID: AtomicU64 = AtomicU64::new(65536);
const QUOTA: usize = 8 * 1024 * 1024;
static REMOVED_CARDS: IrqSafeSpinLock<Vec<u32>> = IrqSafeSpinLock::new(Vec::new());
struct Cleanup;
impl Drop for Cleanup {
    fn drop(&mut self) {
        reap();
    }
}
fn reap() {
    let Some(mut elements) = ELEMENTS.try_lock() else {
        return;
    };
    let mut removed = REMOVED_CARDS.lock();
    if removed.is_empty() {
        return;
    }
    elements.retain(|e| !removed.contains(&e.card));
    LOCKS.lock().retain(|l| !removed.contains(&l.0));
    removed.clear();
}
pub(super) fn remove_card(card: u32) {
    REMOVED_CARDS.lock().push(card);
    // If an ioctl owns the data mutex, its Cleanup runs after that guard is
    // released. Hot-unplug therefore cannot strand an in-flight allocation.
    reap();
}
pub(super) async fn ids(card: u32) -> Vec<[u8; 64]> {
    let _cleanup = Cleanup;
    let elements = ELEMENTS.lock().await;
    elements
        .iter()
        .filter(|e| e.card == card)
        .flat_map(|e| (0..e.count).map(|i| e.id(i)))
        .collect()
}
fn lock_info(c: &Control, num: u32) -> Option<(u32, u32, u64, u32)> {
    LOCKS
        .lock()
        .iter()
        .find(|l| l.0 == c.card && l.1 == num)
        .copied()
}
fn owned_elsewhere(c: &Control, num: u32) -> bool {
    lock_info(c, num).is_some_and(|l| l.2 != c.id)
}
fn remove(c: &Control, elements: &mut Vec<Element>, id: &[u8]) -> Result<(), FsError> {
    let index = elements
        .iter()
        .position(|e| e.card == c.card && e.offset(id).is_some());
    let Some(index) = index else {
        let native = crate::mixer(c.card).map_err(sound_error)?.list_controls();
        return Err(if resolve(&native, id).is_ok() {
            FsError::InvalidData
        } else {
            FsError::NotFound
        });
    };
    let e = &elements[index];
    if (0..e.count).any(|i| owned_elsewhere(c, get32(&e.info, 0) + i)) {
        return Err(FsError::Busy);
    }
    let e = elements.remove(index);
    for i in 0..e.count {
        let id = e.id(i);
        let num = get32(&id, 0);
        LOCKS.lock().retain(|l| l.0 != c.card || l.1 != num);
        notify(c.card, id, u32::MAX);
    }
    Ok(())
}
pub(super) async fn modify(
    c: &Control,
    nr: u8,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let mut b = input(ctx, arg, if nr == 0x19 { 64 } else { 272 })?;
    let _cleanup = Cleanup;
    let mut elements = ELEMENTS.lock().await;
    let live = crate::list_cards();
    elements.retain(|e| live.iter().any(|c| c.index == e.card));
    if nr == 0x19 {
        remove(c, &mut elements, &b)?;
        return Ok(0);
    }
    if name(&b).is_empty() || name(&b).len() == 44 {
        return Err(FsError::InvalidData);
    }
    if nr == 0x18 {
        put32(&mut b, 0, 0);
        remove(c, &mut elements, &b)?;
    }
    let count = get32(&b, 76).max(1);
    let kind = get32(&b, 64) as usize;
    let values = get32(&b, 72) as usize;
    if count > 1028
        || !(1..=6).contains(&kind)
        || values == 0
        || values > [0, 128, 128, 128, 512, 1, 64][kind]
        || (kind == 3 && get32(&b, 80) == 0)
        || get32(&b, 60).checked_add(count - 1).is_none()
    {
        return Err(FsError::InvalidData);
    }
    let stride = [0, 8, 8, 4, 1, 176, 8][kind] * values;
    let mut access = get32(&b, 68);
    if access == 0 {
        access = 3;
    }
    access &= 3 | 256 | 32;
    access |= 1 << 29;
    if access & 32 != 0 {
        access |= 1 << 28;
    }
    let names_len = if kind == 3 {
        get32(&b, 160) as usize
    } else {
        0
    };
    if names_len > 65536 {
        return Err(FsError::InvalidData);
    }
    let used: usize = elements
        .iter()
        .filter(|e| e.card == c.card)
        .map(Element::allocation)
        .sum();
    if used + 320 + stride * count as usize + names_len > QUOTA {
        return Err(FsError::OutOfMemory);
    }
    let names = if kind == 3 {
        let names = input(ctx, get64(&b, 152), names_len)?;
        let mut rest = names.as_slice();
        for _ in 0..get32(&b, 80) {
            let len = rest
                .iter()
                .position(|x| *x == 0)
                .ok_or(FsError::InvalidData)?;
            if len == 0 || len >= 64 {
                return Err(FsError::InvalidData);
            }
            rest = &rest[len + 1..];
        }
        names
    } else {
        Vec::new()
    };
    // Linux rejects overlapping index ranges, even when neither base matches.
    let native = crate::mixer(c.card).map_err(sound_error)?.list_controls();
    let start = get32(&b, 60);
    let end = start + count - 1;
    if native.iter().any(|id| {
        let id = wire_id(*id);
        id[4..16] == b[4..16] && name(&id) == name(&b) && (start..=end).contains(&get32(&id, 60))
    }) || elements.iter().any(|e| {
        e.card == c.card
            && e.info[4..16] == b[4..16]
            && name(&e.info) == name(&b)
            && u64::from(start) < u64::from(get32(&e.info, 60)) + u64::from(e.count)
            && get32(&e.info, 60) <= end
    }) {
        return Err(FsError::Busy);
    }
    let num = NEXT_NUMID.fetch_add(count as u64, Ordering::Relaxed);
    if num + count as u64 > u32::MAX as u64 {
        return Err(FsError::OutOfMemory);
    }
    put32(&mut b, 0, num as u32);
    let mut stored = b.clone();
    stored[164..].fill(0);
    if kind == 3 {
        put64(&mut stored, 152, 0);
    }
    let e = Element {
        card: c.card,
        info: stored,
        count,
        access,
        stride,
        values: alloc::vec![0;stride*count as usize],
        names,
        tlv: Vec::new(),
    };
    for i in 0..count {
        LOCKS
            .lock()
            .push((c.card, num as u32 + i, c.id, ctx.process_id()));
        notify(c.card, e.id(i), 4);
    }
    elements.push(e);
    if let Err(error) = ctx.write(arg, &b) {
        remove(c, &mut elements, &b)?;
        return Err(error);
    }
    Ok(0)
}
pub(super) async fn element(
    c: &Control,
    nr: u8,
    b: &mut [u8],
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Option<Result<u64, FsError>> {
    let _cleanup = Cleanup;
    let mut elements = ELEMENTS.lock().await;
    let (e, offset) = elements
        .iter_mut()
        .filter(|e| e.card == c.card)
        .find_map(|e| e.offset(b).map(|i| (e, i)))?;
    let result = (|| {
        let id = e.id(offset);
        let num = get32(&id, 0);
        b[..64].copy_from_slice(&id);
        match nr {
            0x11 => {
                let item = get32(b, 84);
                b.copy_from_slice(&e.info);
                b[..64].copy_from_slice(&id);
                let lock = lock_info(c, num);
                put32(
                    b,
                    68,
                    e.access | lock.map_or(0, |l| 512 | if l.2 == c.id { 1024 } else { 0 }),
                );
                put32(b, 76, lock.map_or(0, |l| l.3));
                if get32(b, 64) == 3 {
                    let item = item.min(get32(b, 80) - 1);
                    put32(b, 84, item);
                    b[88..152].fill(0);
                    let name = e.names.split(|b| *b == 0).nth(item as usize).unwrap();
                    b[88..88 + name.len()].copy_from_slice(name);
                }
                ctx.write(arg, b)?;
            }
            0x12 => {
                if e.access & 1 == 0 {
                    return Err(FsError::OperationNotPermitted);
                }
                b[64..].fill(0);
                let at = offset as usize * e.stride;
                b[72..72 + e.stride].copy_from_slice(&e.values[at..at + e.stride]);
                ctx.write(arg, b)?;
            }
            0x13 => {
                if e.access & 2 == 0 || owned_elsewhere(c, num) {
                    return Err(FsError::OperationNotPermitted);
                }
                let kind = get32(&e.info, 64);
                let count = get32(&e.info, 72) as usize;
                for i in 0..count {
                    let (value, min, max, step) = match kind {
                        1 => (get64(b, 72 + i * 8) as i64, 0, 1, 0),
                        2 | 6 => (
                            get64(b, 72 + i * 8) as i64,
                            get64(&e.info, 80) as i64,
                            get64(&e.info, 88) as i64,
                            get64(&e.info, 96),
                        ),
                        3 => (
                            get32(b, 72 + i * 4) as i64,
                            0,
                            (get32(&e.info, 80) - 1) as i64,
                            0,
                        ),
                        _ => break,
                    };
                    if value < min || value > max || (step != 0 && value as u64 % step != 0) {
                        return Err(FsError::InvalidData);
                    }
                }
                let at = offset as usize * e.stride;
                if e.values[at..at + e.stride] != b[72..72 + e.stride] {
                    e.values[at..at + e.stride].copy_from_slice(&b[72..72 + e.stride]);
                    notify(c.card, id, 1);
                }
                ctx.write(arg, b)?;
            }
            0x14 => {
                let mut locks = LOCKS.lock();
                if locks.iter().any(|l| l.0 == c.card && l.1 == num) {
                    return Err(FsError::Busy);
                }
                locks.push((c.card, num, c.id, ctx.process_id()));
            }
            0x15 => {
                let mut locks = LOCKS.lock();
                let i = locks
                    .iter()
                    .position(|l| l.0 == c.card && l.1 == num)
                    .ok_or(FsError::InvalidData)?;
                if locks[i].2 != c.id {
                    return Err(FsError::OperationNotPermitted);
                }
                locks.remove(i);
            }
            _ => unreachable!(),
        }
        Ok(0)
    })();
    Some(result)
}
pub(super) async fn tlv(
    c: &Control,
    nr: u8,
    arg: u64,
    ctx: &dyn IoctlContext,
) -> Result<u64, FsError> {
    let b = input(ctx, arg, 8)?;
    let num = get32(&b, 0);
    let len = get32(&b, 4) as usize;
    if num == 0 || len < 8 {
        return Err(FsError::InvalidData);
    }
    let _cleanup = Cleanup;
    let mut elements = ELEMENTS.lock().await;
    let used: usize = elements
        .iter()
        .filter(|e| e.card == c.card)
        .map(Element::allocation)
        .sum();
    let Some(e) = elements.iter_mut().find(|e| {
        e.card == c.card && num >= get32(&e.info, 0) && num - get32(&e.info, 0) < e.count
    }) else {
        let ids = crate::mixer(c.card).map_err(sound_error)?.list_controls();
        return Err(if ids.iter().any(|id| id.index + 1 == num) {
            FsError::NoDeviceAddress
        } else {
            FsError::NotFound
        });
    };
    let access = match nr {
        0x1a => 16,
        0x1b => 32,
        _ => 64,
    };
    if e.access & access == 0 {
        return Err(FsError::NoDeviceAddress);
    }
    let ptr = arg.checked_add(8).ok_or(FsError::BadAddress)?;
    if nr == 0x1a {
        if len < e.tlv.len() {
            return Err(FsError::NoSpace);
        }
        ctx.write(ptr, &e.tlv)?;
        return Ok(0);
    }
    if owned_elsewhere(c, num) {
        return Err(FsError::OperationNotPermitted);
    }
    if len > 128 * 1024 {
        return Err(FsError::InvalidData);
    }
    if used - e.tlv.len() + len > QUOTA {
        return Err(FsError::OutOfMemory);
    }
    let tlv = input(ctx, ptr, len)?;
    if tlv == e.tlv {
        return Ok(0);
    }
    let mask = 8 | if e.tlv.is_empty() { 2 } else { 0 };
    e.tlv = tlv;
    e.access |= 16;
    for i in 0..e.count {
        notify(c.card, e.id(i), mask);
    }
    Ok(1)
}
