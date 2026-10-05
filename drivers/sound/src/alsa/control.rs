use super::*;
use crate::mixer::{ControlId, ControlValue};
use alloc::{
    boxed::Box,
    collections::VecDeque,
    sync::{Arc, Weak},
};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_filesystem::{FsFuture, POLL_IN};
use narf_lib::{readiness::Readiness, sync::IrqSafeSpinLock};
mod user;
use narf_lib::mutex::Mutex;
// Serializes resolution, ownership checks and mutations across open files.
static OPERATIONS: Mutex<()> = Mutex::new(());
struct Event {
    id: [u8; 64],
    mask: u32,
}
struct Events {
    subscribed: bool,
    queue: VecDeque<Event>,
}
pub(crate) struct Control {
    card: u32,
    id: u64,
    events: IrqSafeSpinLock<Events>,
    ready: Readiness,
    active: AtomicBool,
}
impl core::fmt::Debug for Control {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AlsaControl")
            .field("card", &self.card)
            .finish()
    }
}
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static CLIENTS: IrqSafeSpinLock<Vec<Weak<Control>>> = IrqSafeSpinLock::new(Vec::new());
static LOCKS: IrqSafeSpinLock<Vec<(u32, u32, u64, u32)>> = IrqSafeSpinLock::new(Vec::new());
pub(crate) fn changed(card: u32, id: ControlId) {
    notify(card, wire_id(id), 1);
}
fn notify(card: u32, id: [u8; 64], mask: u32) {
    let clients = {
        let mut list = CLIENTS.lock();
        list.retain(|c| c.strong_count() != 0);
        list.clone()
    };
    for weak in clients {
        if let Some(client) = weak.upgrade() {
            if client.card == card {
                let mut events = client.events.lock();
                if events.subscribed {
                    if let Some(event) = events
                        .queue
                        .iter_mut()
                        .find(|e| get32(&e.id, 0) == get32(&id, 0))
                    {
                        event.mask |= mask;
                    } else {
                        events.queue.push_back(Event { id, mask });
                    }
                    client.ready.set(POLL_IN | 0x40, 0);
                }
            }
        }
    }
}
fn wire_id(id: ControlId) -> [u8; 64] {
    let mut b = [0; 64];
    put32(&mut b, 0, id.index + 1);
    put32(&mut b, 4, 2);
    string(&mut b, 16, 44, id.kind.name());
    b
}
fn resolve(ids: &[ControlId], b: &[u8]) -> Result<ControlId, FsError> {
    let num = get32(b, 0);
    ids.iter()
        .copied()
        .find(|id| {
            if num != 0 {
                num == id.index + 1
            } else {
                get32(b, 4) == 2
                    && get32(b, 8) == 0
                    && get32(b, 12) == 0
                    && get32(b, 60) == 0
                    && name(b) == name(&wire_id(*id))
            }
        })
        .ok_or(FsError::NotFound)
}
impl Drop for Control {
    fn drop(&mut self) {
        LOCKS.lock().retain(|(_, _, owner, _)| *owner != self.id);
    }
}
impl Control {
    pub(crate) fn new(card: u32) -> Arc<Self> {
        let c = Arc::new(Self {
            card,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            events: IrqSafeSpinLock::new(Events {
                subscribed: false,
                queue: VecDeque::new(),
            }),
            ready: Readiness::new(0),
            active: AtomicBool::new(false),
        });
        CLIENTS.lock().push(Arc::downgrade(&c));
        c
    }
    pub(crate) fn readiness(&self) -> &Readiness {
        &self.ready
    }
    pub(crate) fn active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    pub(crate) fn read<'a>(&'a self, out: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.active.store(true, Ordering::Release);
            let mut events = self.events.lock();
            if !events.subscribed {
                return Err(FsError::BadFileState);
            }
            if out.len() < 72 {
                return Err(FsError::InvalidData);
            }
            let mut n = 0;
            for record in out.chunks_exact_mut(72) {
                let Some(id) = events.queue.pop_front() else {
                    break;
                };
                record.fill(0);
                put32(record, 4, id.mask);
                record[8..72].copy_from_slice(&id.id);
                n += 72;
            }
            if events.queue.is_empty() {
                self.ready.set(0, POLL_IN | 0x40);
            }
            if n == 0 {
                Err(FsError::WouldBlock)
            } else {
                Ok(n)
            }
        })
    }
    pub(crate) fn ioctl<'a>(
        &'a self,
        cmd: u32,
        arg: u64,
        ctx: &'a dyn IoctlContext,
    ) -> FsFuture<'a, u64> {
        Box::pin(async move {
            self.active.store(true, Ordering::Release);
            if (cmd >> 8) & 255 != u32::from(b'U') {
                return Ok((-25i64) as u64);
            }
            let nr = (cmd & 255) as u8;
            let (dir, size) = match nr {
                0 => (2, 4),
                1 => (2, 376),
                2 => (3, 24),
                0x10 => (3, 80),
                0x11 | 0x17 | 0x18 => (3, 272),
                0x12 | 0x13 => (3, 1224),
                0x14 | 0x15 => (1, 64),
                0x16 => (3, 4),
                0x19 => (3, 64),
                0x1a..=0x1c => (3, 8),
                0x20 | 0x40 | 0x43 => (3, 4),
                0x30 => (2, 4),
                0x31 => (3, 288),
                0x32 | 0x42 => (1, 4),
                0xd0 => (3, 4),
                0xd1 => (2, 4),
                _ => return Ok((-25i64) as u64),
            };
            if cmd != command(b'U', nr, dir, size) {
                return Ok((-25i64) as u64);
            }
            let card = crate::list_cards()
                .into_iter()
                .find(|c| c.index == self.card)
                .ok_or(FsError::NoDevice)?;
            let _operation = OPERATIONS.lock().await;
            match nr {
                0 => ctx.write(arg, &0x0002_000au32.to_ne_bytes())?,
                1 => {
                    let mut b = alloc::vec![0;376];
                    put32(&mut b, 0, self.card);
                    string(&mut b, 8, 16, card.id);
                    string(&mut b, 24, 16, card.driver);
                    string(&mut b, 40, 32, card.name);
                    string(&mut b, 72, 80, card.name);
                    string(&mut b, 168, 80, card.name);
                    ctx.write(arg, &b)?;
                }
                2 => {
                    let b = input(ctx, arg, 24)?;
                    if get32(&b, 0) != 1 {
                        return Err(FsError::InvalidData);
                    }
                    if get64(&b, 16) != 0 && get32(&b, 4) != 0 {
                        ctx.write(get64(&b, 16), &[0])?;
                    }
                    ctx.write(
                        arg.checked_add(8).ok_or(FsError::BadAddress)?,
                        &1u32.to_ne_bytes(),
                    )?;
                }
                0x10 => {
                    let mut b = input(ctx, arg, 80)?;
                    let offset = get32(&b, 0) as usize;
                    let space = get32(&b, 4) as usize;
                    let mut ids: Vec<[u8; 64]> = crate::mixer(self.card)
                        .map_err(sound_error)?
                        .list_controls()
                        .into_iter()
                        .map(wire_id)
                        .collect();
                    ids.extend(user::ids(self.card).await);
                    let selected = ids
                        .iter()
                        .skip(offset)
                        .take(space)
                        .copied()
                        .collect::<Vec<_>>();
                    let mut data = Vec::with_capacity(selected.len() * 64);
                    for id in &selected {
                        data.extend_from_slice(id);
                    }
                    if !data.is_empty() {
                        ctx.write(get64(&b, 16), &data)?;
                    }
                    put32(&mut b, 8, selected.len() as u32);
                    put32(&mut b, 12, ids.len() as u32);
                    b[24..].fill(0);
                    ctx.write(arg, &b)?;
                }
                0x11..=0x15 => {
                    let mut b = input(ctx, arg, size as usize)?;
                    if let Some(result) = user::element(self, nr, &mut b, arg, ctx).await {
                        return result;
                    }
                    let mx = crate::mixer(self.card).map_err(sound_error)?;
                    let id = resolve(&mx.list_controls(), &b)?;
                    b[..64].copy_from_slice(&wire_id(id));
                    match nr {
                        0x11 => {
                            let metadata = mx.control_info(id).map_err(sound_error)?;
                            b[64..].fill(0);
                            put32(&mut b, 64, if metadata.is_boolean { 1 } else { 2 });
                            let lock = LOCKS
                                .lock()
                                .iter()
                                .find(|(card, index, _, _)| {
                                    *card == self.card && *index == id.index + 1
                                })
                                .copied();
                            let access = if metadata.is_read_only { 1 | 4 } else { 3 };
                            put32(
                                &mut b,
                                68,
                                access
                                    | lock.map_or(0, |(_, _, owner, _)| {
                                        512 | if owner == self.id { 1024 } else { 0 }
                                    }),
                            );
                            put32(&mut b, 76, lock.map_or(0, |(_, _, _, pid)| pid));
                            put32(&mut b, 72, metadata.channels as u32);
                            put64(&mut b, 80, metadata.value_min as i64 as u64);
                            put64(&mut b, 88, metadata.value_max as i64 as u64);
                            put64(&mut b, 96, metadata.step as i64 as u64);
                            ctx.write(arg, &b)?;
                        }
                        0x12 => {
                            b[64..].fill(0);
                            match mx.get_control_value(id).map_err(sound_error)? {
                                ControlValue::Boolean(v) => put64(&mut b, 72, u64::from(v)),
                                ControlValue::Integer { left, right } => {
                                    put64(&mut b, 72, left as i64 as u64);
                                    put64(&mut b, 80, right as i64 as u64);
                                }
                            }
                            ctx.write(arg, &b)?;
                        }
                        0x13 => {
                            if id.kind.is_read_only() {
                                return Err(FsError::OperationNotPermitted);
                            }
                            if LOCKS.lock().iter().any(|(card, index, owner, _)| {
                                *card == self.card && *index == id.index + 1 && *owner != self.id
                            }) {
                                return Err(FsError::OperationNotPermitted);
                            }
                            let value = if id.kind.is_boolean() {
                                let value = get64(&b, 72);
                                if value > 1 {
                                    return Err(FsError::InvalidData);
                                }
                                ControlValue::Boolean(value != 0)
                            } else {
                                let left = i32::try_from(get64(&b, 72) as i64)
                                    .map_err(|_| FsError::InvalidData)?;
                                let right = i32::try_from(get64(&b, 80) as i64)
                                    .map_err(|_| FsError::InvalidData)?;
                                ControlValue::Integer { left, right }
                            };
                            mx.set_control_value(id, value).map_err(sound_error)?;
                            ctx.write(arg, &b)?;
                        }
                        0x14 => {
                            let mut locks = LOCKS.lock();
                            if locks.iter().any(|(card, index, _, _)| {
                                *card == self.card && *index == id.index + 1
                            }) {
                                return Err(FsError::Busy);
                            }
                            locks.push((self.card, id.index + 1, self.id, ctx.process_id()));
                        }
                        0x15 => {
                            let mut locks = LOCKS.lock();
                            let Some(i) = locks.iter().position(|(card, index, _, _)| {
                                *card == self.card && *index == id.index + 1
                            }) else {
                                return Err(FsError::InvalidData);
                            };
                            if locks[i].2 != self.id {
                                return Err(FsError::OperationNotPermitted);
                            }
                            locks.remove(i);
                        }
                        _ => unreachable!(),
                    }
                }
                0x16 => {
                    let b = input(ctx, arg, 4)?;
                    let value = get32(&b, 0) as i32;
                    let subscribed = {
                        let mut events = self.events.lock();
                        if value >= 0 {
                            events.subscribed = value != 0;
                            if !events.subscribed {
                                events.queue.clear();
                                self.ready.set(0, POLL_IN | 0x40);
                            }
                        }
                        events.subscribed
                    };
                    if value < 0 {
                        ctx.write(arg, &u32::from(subscribed).to_ne_bytes())?;
                    }
                }
                0x17..=0x19 => return user::modify(self, nr, arg, ctx).await,
                0x1a..=0x1c => return user::tlv(self, nr, arg, ctx).await,
                0x20 | 0x40 | 0x43 => {
                    let _ = input(ctx, arg, 4)?;
                    ctx.write(arg, &(-1i32).to_ne_bytes())?;
                }
                0x30 => {
                    let b = input(ctx, arg, 4)?;
                    let previous = get32(&b, 0) as i32;
                    let next = previous
                        .checked_add(1)
                        .filter(|n| {
                            *n >= 0 && (*n as u32) < card.playback_count.max(card.capture_count)
                        })
                        .unwrap_or(-1);
                    ctx.write(arg, &next.to_ne_bytes())?;
                }
                0x31 => {
                    let b = input(ctx, arg, 288)?;
                    if get32(&b, 8) > 1 {
                        return Err(FsError::InvalidData);
                    }
                    if get32(&b, 0) >= card.playback_count.max(card.capture_count) {
                        return Err(FsError::NoDeviceAddress);
                    }
                    if (get32(&b, 8) == 0 && card.playback_count == 0)
                        || (get32(&b, 8) == 1 && card.capture_count == 0)
                    {
                        return Err(FsError::NotFound);
                    }
                    if get32(&b, 4) != 0 {
                        return Err(FsError::NoDeviceAddress);
                    }
                    ctx.write(arg, &info(self.card, get32(&b, 0), get32(&b, 8) != 0)?)?;
                }
                0x32 | 0x42 => {
                    // Linux accepts any preference. Each native NARF PCM
                    // device has a single exclusive substream.
                    let _ = input(ctx, arg, 4)?;
                }
                0xd0 => return Ok((-92i64) as u64), // snd_ctl_ioctl: ENOPROTOOPT
                0xd1 => ctx.write(arg, &0u32.to_ne_bytes())?,
                _ => unreachable!(),
            }
            Ok(0)
        })
    }
}

fn name(id: &[u8]) -> &[u8] {
    let b = &id[16..60];
    &b[..b.iter().position(|x| *x == 0).unwrap_or(44)]
}
pub(crate) fn remove_card(card: u32) {
    user::remove_card(card);
    LOCKS.lock().retain(|l| l.0 != card);
}
