//! Explicit native ROC cancellation obtains actual retirement, not merely
//! the no-response abort's command publication. Wired with its next fixture.
use super::*;
impl<B: Backend> Session<B> {
    pub(in crate::mt7921::firmware_transport) async fn cancel_p2p_roc(
        &mut self,
        authority: Arc<RadioControlAuthority>,
        cookie: u64,
    ) -> Result<(), Error> {
        self.check_p2p_request(&authority)?;
        authority.require_mode(10).map_err(|_| Error::Authority)?;
        if !authority.has_reservation() {
            return Err(Error::Authority);
        }
        let owner = self.p2p_owner.as_ref().ok_or(Error::Busy)?;
        let lease = owner
            .cnm
            .lease()
            .filter(|lease| lease.cookie == cookie)
            .ok_or(Error::Bounds)?;
        let roc = owner.roc.as_ref().ok_or(Error::Busy)?;
        let notify = match lease.phase {
            Phase::Granted { interval_ms, .. } if roc.activated => Some((
                roc.source.clone(),
                Receipt {
                    cookie,
                    frequency_mhz: lease.frequency_mhz,
                    duration_ms: interval_ms,
                },
            )),
            _ => None,
        };
        self.p2p_owner.as_mut().ok_or(Error::Busy)?.pending = Some(authority.clone());
        let result = async {
            // Stop sends the exact owned abort, disables the actual BSS/DEV
            // and verifies WFSYS reset plus native DMA retirement. An abort
            // ACK/progress record alone cannot make this return success.
            self.stop_p2p_device_owned().await?;
            authority.current().map_err(|_| Error::Authority)?;
            self.start_p2p_device(authority.clone()).await?;
            self.commit_p2p_device(&authority)?;
            if let Some((source, receipt)) = notify {
                if source.current().is_ok() {
                    source
                        .roc_expired(receipt.cookie, receipt.frequency_mhz, receipt.duration_ms)
                        .map_err(|_| Error::Authority)?;
                }
            }
            authority.current().map_err(|_| Error::Authority)?;
            self.backend.check()?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => Ok(()),
            Err(error) => Err(self.p2p_failure(error).await),
        }
    }
}
