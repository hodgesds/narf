//! Software-linked stream actions. Group membership is weak; an open file or
//! in-flight action owns its streams. All members are validated before triggers.
use super::*;
static GROUPS: Mutex<Vec<Vec<Weak<Pcm>>>> = Mutex::new(Vec::new());
fn contains(group: &[Weak<Pcm>], pcm: &Pcm) -> bool {
    group.iter().any(|w| core::ptr::eq(w.as_ptr(), pcm))
}
fn prune(groups: &mut Vec<Vec<Weak<Pcm>>>) {
    for group in groups.iter_mut() {
        let live = |w: &Weak<Pcm>| {
            w.upgrade()
                .is_some_and(|p| !p.closed.load(Ordering::Acquire))
        };
        let lost = group.iter().any(|w| !live(w));
        group.retain(live);
        for pcm in group.iter().filter_map(Weak::upgrade) {
            if lost {
                pcm.peer_closed.store(true, Ordering::Release);
                if let Some(mut r) = pcm.runtime.try_lock() {
                    let _ = r.stop();
                    r.state = SETUP;
                    r.publish();
                    pcm.update_ready(&r);
                    pcm.peer_closed.store(false, Ordering::Release);
                }
            }
            if group.len() < 2 {
                pcm.linked.store(false, Ordering::Release);
            }
        }
    }
    groups.retain(|g| g.len() >= 2);
}
fn owned(pcm: &Pcm) -> Result<Arc<Pcm>, FsError> {
    STREAMS
        .lock()
        .iter()
        .find(|w| core::ptr::eq(w.as_ptr(), pcm))
        .and_then(Weak::upgrade)
        .ok_or(FsError::BadFileState)
}
impl Pcm {
    pub(super) async fn link_ioctl(
        &self,
        nr: u8,
        arg: u64,
        ctx: &dyn IoctlContext,
    ) -> Result<u64, FsError> {
        let target = if nr == 0x60 {
            let file = ctx.file(arg as i32).map_err(|_| FsError::BadFileState)?;
            let pcm =
                crate::devfs_bridge::pcm_from_file(file.as_ref()).ok_or(FsError::BadFileState)?;
            if core::ptr::eq(self, pcm.as_ref()) {
                return Err(FsError::InvalidData);
            }
            Some(pcm)
        } else {
            None
        };
        let mut groups = GROUPS.lock().await;
        prune(&mut groups);
        let source = groups.iter().position(|g| contains(g, self));
        if let Some(target) = target {
            let mut a = self.runtime.lock().await;
            self.activate(&mut a)?;
            let mut b = target.runtime.lock().await;
            target.activate(&mut b)?;
            if a.state == OPEN || a.state != b.state {
                return Err(FsError::BadFileState);
            }
            if groups.iter().any(|g| contains(g, &target)) {
                return Ok((-114i64) as u64);
            }
            if let Some(index) = source {
                groups[index].push(Arc::downgrade(&target));
            } else {
                groups.push(alloc::vec![
                    Arc::downgrade(&owned(self)?),
                    Arc::downgrade(&target)
                ]);
            }
            self.linked.store(true, Ordering::Release);
            target.linked.store(true, Ordering::Release);
        } else {
            let Some(index) = source else {
                return Ok((-114i64) as u64);
            };
            groups[index].retain(|w| !core::ptr::eq(w.as_ptr(), self));
            self.linked.store(false, Ordering::Release);
            prune(&mut groups);
        }
        Ok(0)
    }
    pub(super) async fn maybe_start_group(&self, capture_bytes: u64) -> Result<(), FsError> {
        if !self.linked.load(Ordering::Acquire) {
            return Ok(());
        }
        let start = {
            let r = self.runtime.lock().await;
            r.state == PREPARED
                && if self.capture {
                    r.frame_bytes() != 0
                        && capture_bytes / r.frame_bytes() as u64 >= r.start_threshold
                } else {
                    r.access != 0 && r.appl != 0 && r.appl >= r.start_threshold
                }
        };
        if start {
            self.group_action(0x42, 0, true).await?;
        }
        Ok(())
    }
    pub(super) async fn group_action(
        &self,
        nr: u8,
        arg: u64,
        nonblock: bool,
    ) -> Result<u64, FsError> {
        let mut groups = GROUPS.lock().await;
        prune(&mut groups);
        let peers = if let Some(group) = groups.iter().find(|g| contains(g, self)) {
            group.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
        } else {
            alloc::vec![owned(self)?]
        };
        let mut runtimes = Vec::with_capacity(peers.len());
        for pcm in &peers {
            let mut r = pcm.runtime.lock().await;
            pcm.activate(&mut r)?;
            // Explicit group actions suppress per-file automatic start while
            // collecting commits and refreshing hardware position.
            let threshold = r.start_threshold;
            r.start_threshold = u64::MAX;
            pcm.service(&mut r);
            r.start_threshold = threshold;
            runtimes.push(r);
        }
        for (pcm, r) in peers.iter().zip(&runtimes) {
            let error = match nr {
                0x40 if r.state == RUNNING || (r.state == DRAINING && !pcm.capture) => {
                    Some(FsError::Busy)
                }
                0x40 if r.params.is_none() => Some(FsError::BadFileState),
                0x41 if !matches!(r.state, PREPARED | RUNNING | PAUSED | SUSPENDED) => {
                    Some(FsError::BadFileState)
                }
                0x42 if r.state != PREPARED => Some(FsError::BadFileState),
                0x42 if !pcm.capture && r.appl <= r.hw && r.stop_threshold < r.boundary => {
                    Some(FsError::StreamXrun)
                }
                0x43 if r.state == OPEN => Some(FsError::BadFileState),
                0x44 if matches!(r.state, OPEN | SUSPENDED | DISCONNECTED) => {
                    Some(FsError::BadFileState)
                }
                0x45 if !r.pause_supported => Some(FsError::NotImplemented),
                0x45 if r.state != if arg != 0 { RUNNING } else { PAUSED } => {
                    Some(FsError::BadFileState)
                }
                0x47 if r.state != SUSPENDED => Some(FsError::BadFileState),
                0x48 if !matches!(r.state, RUNNING | XRUN) => Some(FsError::BadFileState),
                _ => None,
            };
            if let Some(error) = error {
                return Err(error);
            }
        }
        let result: Result<(), FsError> = (|| {
            for (pcm, r) in peers.iter().zip(runtimes.iter_mut()) {
                match nr {
                    0x40 => {
                        r.prepare()?;
                        // Linux initializes silence during PREPARE, before
                        // userspace can populate a boundary-mode mmap ring.
                        pcm.silence(r);
                    }
                    0x41 => {
                        r.stream.as_mut().unwrap().reset().map_err(sound_error)?;
                        r.hw = r.stream.as_ref().unwrap().pointer();
                        r.appl = r.hw;
                        r.submitted = r.hw;
                        r.control.as_ref().unwrap().store64(0, r.appl % r.boundary);
                        r.silence_start = r.hw;
                        r.silence_filled = 0;
                        pcm.silence(r);
                    }
                    0x42 => {
                        r.stream
                            .as_mut()
                            .unwrap()
                            .trigger_start()
                            .map_err(sound_error)?;
                        r.state = RUNNING;
                        r.trigger_ns = r.timestamp();
                    }
                    0x43 => {
                        r.stop()?;
                        r.state = SETUP;
                    }
                    0x44 => {
                        if r.state == PAUSED {
                            r.stream
                                .as_mut()
                                .unwrap()
                                .pause(false)
                                .map_err(sound_error)?;
                            r.state = RUNNING;
                        }
                        if pcm.capture {
                            pcm.service(r);
                            r.stop()?;
                            r.state = if r.avail(true) != 0 { DRAINING } else { SETUP };
                        } else if matches!(r.state, SETUP | XRUN) || r.appl <= r.hw {
                            r.stop()?;
                            r.state = SETUP;
                        } else {
                            if r.state == PREPARED {
                                r.stream
                                    .as_mut()
                                    .unwrap()
                                    .trigger_start()
                                    .map_err(sound_error)?;
                            }
                            r.state = DRAINING;
                            pcm.service(r);
                        }
                    }
                    0x45 => {
                        let paused = arg != 0;
                        r.stream
                            .as_mut()
                            .unwrap()
                            .pause(paused)
                            .map_err(sound_error)?;
                        r.state = if paused { PAUSED } else { RUNNING };
                    }
                    0x47 => {
                        if r.suspended_state == RUNNING
                            || (r.suspended_state == DRAINING && !pcm.capture)
                        {
                            r.stream
                                .as_mut()
                                .unwrap()
                                .pause(false)
                                .map_err(sound_error)?;
                        }
                        r.state = r.suspended_state;
                    }
                    0x48 => r.xrun(),
                    _ => unreachable!(),
                }
            }
            Ok(())
        })();
        if result.is_err() {
            for r in &mut runtimes {
                r.xrun();
            }
        }
        if peers.iter().any(|p| p.closed.load(Ordering::Acquire)) {
            for r in &mut runtimes {
                let _ = r.stop();
                r.state = SETUP;
            }
        }
        for (pcm, r) in peers.iter().zip(&runtimes) {
            r.publish();
            pcm.update_ready(r);
        }
        let draining = nr == 0x44
            && peers
                .iter()
                .zip(&runtimes)
                .any(|(p, r)| !p.capture && r.state == DRAINING);
        drop(runtimes);
        drop(groups);
        result?;
        if draining {
            if nonblock {
                return Err(FsError::WouldBlock);
            }
            for pcm in &peers {
                if !pcm.capture {
                    pcm.wait_drain(false).await?;
                }
            }
        }
        Ok(0)
    }
}
impl Drop for Pcm {
    fn drop(&mut self) {
        if let Some(mut groups) = GROUPS.try_lock() {
            prune(&mut groups);
        }
    }
}
pub(crate) async fn suspend_card(card: u32) -> Result<(), FsError> {
    let mut groups = GROUPS.lock().await;
    prune(&mut groups);
    let mut peers: Vec<_> = STREAMS
        .lock()
        .iter()
        .filter_map(Weak::upgrade)
        .filter(|p| p.card == card)
        .collect();
    // Suspending a member quiesces its linked group, including other cards.
    // Otherwise RESUME would encounter a mixture of RUNNING and SUSPENDED.
    for group in groups.iter() {
        if group
            .iter()
            .filter_map(Weak::upgrade)
            .any(|p| p.card == card)
        {
            for peer in group.iter().filter_map(Weak::upgrade) {
                if !peers.iter().any(|p| Arc::ptr_eq(p, &peer)) {
                    peers.push(peer);
                }
            }
        }
    }
    let mut runtimes = Vec::with_capacity(peers.len());
    for peer in &peers {
        runtimes.push(peer.runtime.lock().await);
    }
    let result: Result<(), FsError> = (|| {
        for (pcm, r) in peers.iter().zip(runtimes.iter_mut()) {
            if r.legacy || matches!(r.state, SUSPENDED | OPEN) {
                continue;
            }
            if r.state == RUNNING || (r.state == DRAINING && !pcm.capture) {
                r.stream
                    .as_mut()
                    .unwrap()
                    .pause(true)
                    .map_err(sound_error)?;
            }
            r.suspended_state = r.state;
            r.state = SUSPENDED;
        }
        Ok(())
    })();
    if result.is_err() {
        for r in &mut runtimes {
            if !r.legacy && r.params.is_some() {
                r.xrun();
            }
        }
    }
    for (pcm, r) in peers.iter().zip(&runtimes) {
        r.publish();
        pcm.update_ready(r);
    }
    result
}

// Called without an individual runtime guard. A busy group action will publish
// its own states; the next pump retries deferred XRUN propagation.
pub(super) fn refresh(pcm: &Pcm) {
    let Some(mut groups) = GROUPS.try_lock() else {
        return;
    };
    prune(&mut groups);
    let Some(group) = groups.iter().find(|g| contains(g, pcm)) else {
        return;
    };
    let peers: Vec<_> = group.iter().filter_map(Weak::upgrade).collect();
    if peers
        .iter()
        .any(|p| p.runtime.try_lock().is_some_and(|r| r.state == XRUN))
    {
        for peer in peers {
            peer.peer_xrun.store(true, Ordering::Release);
            if let Some(mut r) = peer.runtime.try_lock() {
                if !matches!(r.state, OPEN | SETUP | XRUN) {
                    r.xrun();
                    peer.update_ready(&r);
                }
                peer.peer_xrun.store(false, Ordering::Release);
            }
        }
    }
}
