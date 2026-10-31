// SPDX-License-Identifier: GPL-2.0-or-later
//! Replacement of a stopped RTL8188EE native generation.
use super::*;
use core::future::Future;

/// The physical owner reloads authenticated firmware, allocates fresh rings,
/// executes LLT/radio calibration and installs current signed channel policy.
/// No previous RSNA, packet ring or receive epoch is restored by this hook.
pub(crate) trait Rebuild<I: Port<Buffer = M>, M: Memory>: Environment {
    fn power_down(&self) -> impl Future<Output = Result<(), Error>> + Send {
        core::future::ready(Err(Error::State))
    }
    fn rebuild(
        &self,
        retained: Arc<Mutex<Option<Prepared<I, M>>>>,
        factory: Arc<Factory>,
        channel: u8,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

struct RebuildAttempt<'a> {
    close: &'a dyn Close,
    lifecycle: &'a lifecycle::Lifecycle,
    generation: u64,
    committed: bool,
}
impl Drop for RebuildAttempt<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.close.abort_generation(self.generation);
        }
        self.lifecycle.rebuilding.store(false, Ordering::Release);
    }
}

impl<I, M, E> Device<I, M, E>
where
    I: Port<Buffer = M> + 'static,
    M: Memory + 'static,
    E: Rebuild<I, M> + 'static,
{
    /// Only the retained supervisor awaits this operation. Public request
    /// cancellation cannot discard an in-flight card-disable/enable exchange.
    pub(super) async fn recover_once(&self) -> Result<bool, Error> {
        let _control = self.lifecycle.control.lock().await;
        self.recover_locked().await
    }
    /// Caller holds the control mutex, including channel-change preparation.
    pub(super) async fn recover_locked(&self) -> Result<bool, Error> {
        if self.removed.load(Ordering::Acquire) || self.lifecycle.suspended.load(Ordering::Acquire)
        {
            return Err(Error::State);
        }
        if !self.admission.closed.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.lifecycle
            .sleep_complete
            .store(false, Ordering::Release);
        let generation = {
            let publication = self.admission.publication.lock();
            // Closing precedes advancing the generation. A new generation
            // observed by a late producer therefore also observes closure.
            self.admission.closed.store(true, Ordering::Release);
            self.admission.abort.store(true, Ordering::Release);
            let next = self.lifecycle.advance();
            self.lifecycle.rebuilding.store(true, Ordering::Release);
            self.commit_close(publication);
            match next {
                Ok(generation) => generation,
                Err(reason) => {
                    self.lifecycle.rebuilding.store(false, Ordering::Release);
                    return Err(reason);
                }
            }
        };
        let mut attempt = RebuildAttempt {
            close: self,
            lifecycle: &self.lifecycle,
            generation,
            committed: false,
        };

        let retired = {
            let mut storage = self.prepared.lock().await;
            if let Some(old) = storage.as_mut() {
                old.abort_station();
                self.withdraw_interrupts(old);
                if !old.retire().await {
                    // The old mappings stay in retained storage. No new
                    // ring owner or firmware publication can replace them.
                    return Err(Error::State);
                }
            } else {
                // MSI is armed at frontend publication, before firmware and
                // Prepared exist. Bootstrap failure still owns that vector.
                self.environment.deliver(false);
            }
            // Old callbacks may still be completing from owned packet
            // copies. Drain them before clearing the TX queue or reopening
            // this persistent logical interface for a replacement owner.
            self.lifecycle.drain_publications().await?;
            let mut state = self.state.lock().await;
            state.clear();
            state.epoch = 0;
            storage.take()
        };
        drop(retired);

        let prepared = self
            .environment
            .rebuild(
                self.prepared.clone(),
                self.factory.clone(),
                self.lifecycle.channel.load(Ordering::Acquire),
            )
            .await;
        if let Err(reason) = prepared {
            self.park_failed_rebuild().await;
            return Err(reason);
        }
        let opened = async {
            let mut storage = self.prepared.lock().await;
            let owner = storage.as_mut().ok_or(Error::State)?;
            self.state.lock().await.clear();
            {
                let _publication = self.admission.publication.lock();
                if self.removed.load(Ordering::Acquire)
                    || self.lifecycle.suspended.load(Ordering::Acquire)
                    || self.lifecycle.generation() != generation
                {
                    return Err(Error::State);
                }
                self.admission.abort.store(false, Ordering::Release);
                self.admission.closed.store(false, Ordering::Release);
            }
            // The prepared mutex excludes all normal packet progress until
            // the actual fresh station service is ready. Rebuilding also
            // keeps synchronous drains out of partially prepared state.
            self.ready(owner).await?;
            if owner.station_phase() != station::Phase::Passive {
                return Err(Error::State);
            }
            Ok(())
        }
        .await;
        if let Err(reason) = opened {
            self.park_failed_rebuild().await;
            return Err(reason);
        }
        attempt.committed = true;
        self.lifecycle.inactive.store(false, Ordering::Release);
        Ok(true)
    }

    /// Cleanup is attempted even when a new image or policy fails after
    /// publication; an exhausted retry budget must not leave DMA running.
    async fn park_failed_rebuild(&self) {
        self.close();
        let mut storage = self.prepared.lock().await;
        if let Some(owner) = storage.as_mut() {
            owner.abort_station();
            self.withdraw_interrupts(owner);
            if owner.retire().await {
                storage.take();
            }
        }
    }
}
