// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained additional-RFH/RSS startup owner.
//! It is deliberately separate from station/key/publication ownership.
use super::*;
use zeroize::Zeroizing;

pub(super) const QUEUES: u8 = 3; // fallback0 and two independently hashed data queues
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Idle,
    Unsupported,
    Preparing,
    Ready,
}
#[derive(Default)]
pub(super) struct State {
    phase: Phase,
    _key: Option<Zeroizing<[u8; 40]>>,
    mq_api: bool,
}
impl State {
    pub(super) fn new(parsed: &ParsedUcode<'_>) -> Self {
        Self {
            mq_api: parsed.api.has_capability(68),
            ..Self::default()
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn reset(&mut self) {
        self.phase = Phase::Idle;
        self._key = None;
    }
}
impl Hardware {
    pub(in crate::iwlwifi) fn receive_queue_count(&self) -> u8 {
        1 + self.resources.extra_rx.len() as u8
    }
    /// Only idle/native station startup calls this owner. Every new ring
    /// remains retained after publication, including cancelled/error paths.
    /// Its key/table never change during a live connection or key epoch.
    pub(in crate::iwlwifi) async fn prepare_receive_queues(&mut self) -> Result<(), &'static str> {
        if self.failed {
            return Err("failed native RFH/RSS transport");
        }
        match self.receive_queues.phase {
            Phase::Ready | Phase::Unsupported => return Ok(()),
            Phase::Preparing => {
                return Err("RFH/RSS startup still owns an uncertain native command")
            }
            Phase::Idle => {}
        }
        let rfh = self.command_version(5, 0x0d);
        let rss = self.command_version(0, 0xb3);
        // Linux fw/init.c and mvm/mld fw.c send these fixed structs
        // without version lookups. Shipped Qu/API77 omits both entries;
        // Sc/c103 reports RFH2 and omits RSS. The actual capability68
        // supplies the new-RX protocol fact when inventory is omitted.
        let declared = self.receive_queues.mq_api
            || self.format != rx_rfh::CompletionFormat::Qu && rfh == Some(1) && rss == Some(1);
        let rfh_compatible = match rfh {
            None | Some(99) => self.receive_queues.mq_api,
            Some(1) => true,
            Some(2) => self.format == rx_rfh::CompletionFormat::Bz,
            _ => false,
        };
        let rss_compatible = match rss {
            None | Some(99) => self.receive_queues.mq_api,
            Some(1) => true,
            _ => false,
        };
        if !declared
            || !rfh_compatible
            || !rss_compatible
            || self.format == rx_rfh::CompletionFormat::Qu && !self.receive_queues.mq_api
        {
            self.receive_queues.phase = Phase::Unsupported;
            return Ok(());
        }
        self.source_fence()?.invoke(|| Ok(()))?;
        if self.failed || !self.resources.data.is_empty() || !self.resources.extra_rx.is_empty() {
            return Err("RFH/RSS preparation requires an idle fresh native transport");
        }
        let mut key = Zeroizing::new([0; 40]);
        if narf_crypto::try_fill_random_bytes(&mut *key).is_err() {
            // A receive optimization cannot invent a clock-derived secret
            // or block passive discovery. Keep this transport's immutable
            // single-queue owner; a fresh post-reset transport may retry.
            self.receive_queues.phase = Phase::Unsupported;
            return Ok(());
        }
        let mut additional = Vec::new();
        for queue in 1..QUEUES {
            let mut rx = ReceiveQueue::for_queue(self.format, queue)?;
            rx.prepare_configuration()?;
            additional.push(rx);
        }
        let addresses: Vec<_> = additional
            .iter()
            .map(|queue| super::super::rx_multi::QueueDma {
                queue: queue.id,
                status: queue.status.dma_addr().raw(),
                free: queue.free.dma_addr().raw(),
                used: queue.used.dma_addr().raw(),
                free_write: queue.advertised as u32,
            })
            .collect();
        let configure = super::super::rx_multi::queue_configuration(&addresses)?;
        let rss = Zeroizing::new(super::super::rx_multi::rss_configuration(QUEUES, &key)?);
        self.resources.extra_rx = additional;
        self.receive_queues.phase = Phase::Preparing;
        self.receive_queues._key = Some(key);
        let result = async {
            let configured = self.command(5, 0x0d, &configure).await?;
            if !configured.payload.is_empty() {
                return Err("native additional-RFH receipt extent");
            }
            if let Some(interrupts) = &mut self.interrupts {
                interrupts.receive_queues(QUEUES)?;
            }
            #[cfg(any(test, feature = "kernel-test"))]
            let trace = self.resources.commands.trace.clone();
            for queue in &mut self.resources.extra_rx {
                queue.publish(&mut self.mmio)?;
                #[cfg(any(test, feature = "kernel-test"))]
                if let Some(trace) = &trace {
                    trace.receive_queue(queue)?;
                }
            }
            let configured = self.command(0, 0xb3, &*rss).await?;
            if !configured.payload.is_empty() {
                return Err("native RSS configuration receipt extent");
            }
            self.source_fence()?.invoke(|| Ok(()))?;
            self.receive_queues.phase = Phase::Ready;
            Ok(())
        }
        .await;
        if result.is_err() {
            self.fail();
        }
        result
    }
}
