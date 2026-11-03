// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact original nondeep LPS program scope, separate from awake RF grants.
use super::{
    firmware_transport::Error,
    power_policy::Gate,
    publication::Publication,
    qualification::{self, Kind, PAYLOAD},
    station_control::ReceiveEpoch,
};
use alloc::sync::Arc;

pub(super) static KIND: Kind = Kind {
    tag: b'Z', stem: "lps",
    source: b"Linux7.3-rc4 rtw88 ps.c rtw_enter_lps_core/rtw_leave_lps_core nondeep LPS_DEEP_NONE; original firmware Info features/subindex, port0 legacyCCK1 noWMM noHT noBA; source reserved dummy0 PSPoll1 QoSNull2 Null3 128bytepages TXD48 sourceNAV/HWSEQ/BTNULL and native persistent beacon DMA, ENSWBCN1 disableBCNfunc disableBCNQ_DL; actual fresh BCNVALID complete then disarm restore; H2C0x00 locations,0x20 LPS1 RLBM1 SMARTPS2 AWAKE1 RFoff0 then ACTIVE0 RLBM0 SMARTPS0 AWAKE1 ALLON12; actual TCR604bit7 entry and clear at wake plus fresh original C2H32 when firmwareSIG/LPS_C2H and actual original RF/TXAGC/automatic-response readbacks before entry/finalawake; discard stale native RX prefix before wake command, original PCI function/UP/key/peer immutable across requested1..100ms nondeep residence plus source-bounded poll/retry sequences and all awaits; confirmed actual native TXBD+CCX/MACempty before sleep and final current source before doorbell; complete nondeep RFoff/on and automatic PSPoll/Null/ACK retry/transient/thermal/supply/BT program bounded by exact base envelope, no independent awake-recipe substitution; noLCLK noPG noWoW noASPM; attestation payload1 thenzero",
    admit: |did, p: &[u8; PAYLOAD]| matches!(did, 0xc821 | 0xc822)
        && p[0] == 1 && p[1..].iter().all(|b| *b == 0),
};

/// This retained source is consumed only inside the exact original owner's
/// publication path. Its epoch/UP checks can deny; they grant no RF rights.
pub(super) struct Bound {
    grant: Arc<qualification::Grant>,
    gate: Gate,
    publication: Publication,
    epoch: ReceiveEpoch,
    host: narf_net::native_emission::Lifetime,
}
impl Bound {
    pub(super) fn new(
        grant: Arc<qualification::Grant>,
        gate: Gate,
        publication: Publication,
        epoch: ReceiveEpoch,
        host: narf_net::native_emission::Lifetime,
    ) -> Result<Self, Error> {
        if !grant.is(&KIND) || !host.current() || !epoch.current() {
            return Err(Error::State);
        }
        grant.check(&gate)?;
        let bound = Self {
            grant,
            gate,
            publication,
            epoch,
            host,
        };
        bound.invoke(|| Ok(()))?;
        Ok(bound)
    }
    pub(super) fn matches(&self, gate: &Gate) -> bool {
        self.grant.matches(gate) && gate.own() == self.gate.own() && gate.did() == self.gate.did()
    }
    pub(super) fn did(&self) -> u16 {
        self.gate.did()
    }
    pub(super) fn invoke<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        let current = || self.host.current() && self.epoch.current();
        if !current() {
            return Err(Error::Access);
        }
        self.publication.invoke(|| {
            self.grant.invoke(&self.gate, || {
                if !current() {
                    return Err(Error::Access);
                }
                op()
            })
        })
    }
}
