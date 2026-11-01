// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained MLD shared-memory query. Geometry is an optimization bound,
//! never an address to dereference or permission to emit.
use super::*;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Phase {
    #[default]
    Idle,
    Reading,
    Unsupported,
    Ready,
}
#[derive(Default)]
pub(super) struct State {
    extended: bool,
    cdb: bool,
    phase: Phase,
    memory: Option<super::super::Gen2SharedMemory>,
}
impl State {
    pub(super) fn new(parsed: &ParsedUcode<'_>) -> Self {
        Self {
            extended: parsed.api.has_capability(80),
            cdb: parsed.api.has_capability(40),
            ..Self::default()
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn reset(&mut self) {
        self.phase = Phase::Idle;
        self.memory = None;
    }
}
impl Hardware {
    /// Linux mld/mld.h: actual CDB support redirects every non2.4GHz link to
    /// LMAC1. An absent FIFO/LMAC in the real response cannot be invented.
    pub(in crate::iwlwifi) fn station_lmac(&self, band: super::super::native_band::Band) -> u8 {
        u8::from(self.shared_memory.cdb && band != super::super::native_band::Band::Two)
    }
    pub(in crate::iwlwifi) async fn station_shared_memory(
        &mut self,
    ) -> Result<Option<super::super::Gen2SharedMemory>, &'static str> {
        self.source_fence()?.invoke(|| Ok(()))?;
        if self.format != rx_rfh::CompletionFormat::Bz && !self.is_mvm89() {
            self.shared_memory.phase = Phase::Unsupported;
            return Ok(None);
        }
        match self.shared_memory.phase {
            Phase::Ready => return Ok(self.shared_memory.memory.clone()),
            Phase::Unsupported => return Ok(None),
            Phase::Reading => {
                return Err("MLD shared-memory query still owns an uncertain receipt")
            }
            Phase::Idle => {}
        }
        let version = self
            .version(2, 0)
            .map(|v| v.1)
            .filter(|v| *v != 99)
            .unwrap_or(0);
        if version > 4 {
            self.shared_memory.phase = Phase::Unsupported;
            return Ok(None);
        }
        let (group, command) = if self.shared_memory.extended {
            (2, 0)
        } else {
            (0, 0x25)
        };
        self.shared_memory.phase = Phase::Reading;
        let response = match self.command(group, command, &[]).await {
            Ok(reply) => reply,
            Err(reason) => {
                self.fail();
                return Err(reason);
            }
        };
        match super::super::Gen2SharedMemory::parse(version, &response.payload) {
            Ok(memory) => {
                if let Err(reason) = self.source_fence().and_then(|f| f.invoke(|| Ok(()))) {
                    self.fail();
                    return Err(reason);
                }
                self.shared_memory.memory = Some(memory.clone());
                self.shared_memory.phase = Phase::Ready;
                Ok(Some(memory))
            }
            Err(_) => {
                // Linux warns and leaves geometry unavailable. No batching
                // follows; ordinary station traffic keeps its existing path.
                self.shared_memory.phase = Phase::Unsupported;
                Ok(None)
            }
        }
    }
}
