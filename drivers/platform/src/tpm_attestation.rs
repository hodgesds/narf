//! Attestation composition (#945): AK provisioning and guarded
//! quote production over the registered TPM device.
//!
//! This crate owns the production TPM transport (see `crate::tpm`),
//! so it is also where attestation is *composed* — the protocol
//! pieces live with their owners and are only assembled here:
//!
//! - `TPM2_Quote` + the TPMS_ATTEST structures + the verifier:
//!   `narf_tpm` (`TpmDevice::quote`, `narf_tpm::attest`).
//! - The extended provisioning commands (CreatePrimary,
//!   EvictControl, ReadPublic, FlushContext) and the AK template:
//!   the `narf_drivers_tpm::tpm2` extension surface.
//! - The guard: `frame::measure`'s EXTEND_OBSERVED flag, consulted
//!   through the measurement hooks frame installs into
//!   `narf_tpm::attest` at measured boot.
//!
//! ## AK provisioning
//!
//! `ensure_ak` probes the persistent AK handle with
//! `TPM2_ReadPublic`; on any failure it provisions: CreatePrimary
//! in the endorsement hierarchy with the TCG EK Credential
//! Profile AK template (ECC P-256, restricted signing,
//! ECDSA/SHA-256 — `narf_drivers_tpm::tpm2::objects::
//! ecc_ak_template`), then EvictControl under owner authority to
//! persist it, then FlushContext on the transient copy. A primary
//! is deterministic in (hierarchy, template), so re-provisioning
//! after an eviction re-derives the same key; the persistent
//! handle is the identity a verifier pins.
//!
//! EK certification and credential activation are deliberately
//! not here: they are fleet-enrollment machinery (a CA, an EK
//! certificate chain), and #945's scope is the local attestation
//! path — provision, quote, publish, verify.
//!
//! ## The quote guard
//!
//! `attestation_quote` refuses with `TpmError::Denied` unless the
//! measurement hooks report at least one PCR extend observed this
//! boot. A quote over an untouched PCR set would present an empty
//! measurement history with a TPM signature on it — the exact
//! forgery-shaped artifact `frame::measure` maintains
//! EXTEND_OBSERVED to prevent. The hooks fail closed when
//! uninstalled, so a boot whose measured-boot pass never ran
//! cannot quote either.

extern crate alloc;

use alloc::vec::Vec;
use narf_tpm::{TpmDevice, TpmError};

/// The persistent handle the attestation key lives at. The
/// 0x8101xxxx range is the TCG-assigned persistent-handle space
/// for platform/attestation objects (the EK sits at 0x81010001 in
/// EK-profile tooling; the AK takes the next slot).
pub const AK_PERSISTENT_HANDLE: u32 = 0x8101_0002;

/// Everything a remote party needs to verify a quote: the raw
/// attestation bytes and signature (as produced), their parsed
/// form, and the AK's public area + names (as ReadPublic reports
/// them — the values a verifier pins at enrollment).
#[derive(Debug)]
pub struct QuoteBundle {
    pub attest_bytes: Vec<u8>,
    pub info: narf_tpm::attest::AttestInfo,
    pub signature: narf_tpm::attest::Signature,
    pub ak_public: Vec<u8>,
    pub ak_name: Vec<u8>,
    pub ak_qualified_name: Vec<u8>,
}

/// Read an object's public area + names via `TPM2_ReadPublic`
/// (the `narf_drivers_tpm` extended builder/parser over the
/// canonical device's raw submit). The RC is categorized by the
/// canonical parser first, so an absent handle surfaces as
/// `TpmError::Rc(TpmRc::Handle)`, not a framing error.
pub async fn read_public(
    dev: &dyn TpmDevice,
    handle: u32,
) -> Result<narf_drivers_tpm::tpm2::commands::ReadPublicOutputs, TpmError> {
    let req = narf_drivers_tpm::tpm2::commands::read_public(handle);
    let resp = dev.submit_raw(&req).await?;
    let _ = narf_tpm::commands::ResponseParser::new(&resp)?;
    narf_drivers_tpm::tpm2::commands::parse_read_public_response(&resp)
        .map_err(|_| TpmError::BadResponse)
}

/// Ensure an attestation key exists at [`AK_PERSISTENT_HANDLE`],
/// provisioning it if not. Returns the persistent handle.
///
/// Idempotent: a present AK is detected via ReadPublic and left
/// untouched (no primary re-derivation, no NV wear). Provisioning
/// cross-checks the created primary's reported name against the
/// name computed from its public area — a device that answers
/// CreatePrimary with inconsistent outputs has not provisioned
/// the key the template names, and the composition fails rather
/// than persist it.
pub async fn ensure_ak(dev: &dyn TpmDevice) -> Result<u32, TpmError> {
    if read_public(dev, AK_PERSISTENT_HANDLE).await.is_ok() {
        return Ok(AK_PERSISTENT_HANDLE);
    }
    let template = narf_drivers_tpm::tpm2::objects::ecc_ak_template();
    let req = narf_drivers_tpm::tpm2::commands::create_primary(
        narf_drivers_tpm::tpm2::TPM_RH_ENDORSEMENT,
        &[],
        &template,
    );
    let resp = dev.submit_raw(&req).await?;
    let _ = narf_tpm::commands::ResponseParser::new(&resp)?;
    let (transient, outputs) =
        narf_drivers_tpm::tpm2::commands::parse_create_primary_response(&resp)
            .map_err(|_| TpmError::BadResponse)?;
    match narf_tpm::attest::object_name(&outputs.out_public) {
        Some(name) if name == outputs.name => {}
        _ => return Err(TpmError::BadResponse),
    }
    let req = narf_drivers_tpm::tpm2::commands::evict_control(
        narf_drivers_tpm::tpm2::TPM_RH_OWNER,
        transient,
        AK_PERSISTENT_HANDLE,
    );
    let resp = dev.submit_raw(&req).await?;
    let _ = narf_tpm::commands::ResponseParser::new(&resp)?;
    // The persistent copy is the AK now; drop the transient one so
    // handle space (and later ReadPublic answers) stay unambiguous.
    // Best-effort: a failed flush leaves a duplicate transient
    // handle, never a wrong AK.
    let req = narf_drivers_tpm::tpm2::commands::flush_context(transient);
    let _ = dev.submit_raw(&req).await;
    Ok(AK_PERSISTENT_HANDLE)
}

/// Produce a quote over `selections` bound to `qualifying_data`
/// (the verifier's nonce), signed by the provisioned AK.
///
/// Refuses (`TpmError::Denied`) when no PCR extend has been
/// observed this boot — see the module doc's guard section.
pub async fn attestation_quote(
    dev: &dyn TpmDevice,
    qualifying_data: &[u8],
    selections: &[(u16, &[u8])],
) -> Result<QuoteBundle, TpmError> {
    if !narf_tpm::attest::extends_observed() {
        return Err(TpmError::Denied);
    }
    let handle = ensure_ak(dev).await?;
    let public = read_public(dev, handle).await?;
    let quote = dev
        .quote(
            handle,
            qualifying_data,
            (
                narf_tpm::tpm2::TPM_ALG_ECDSA,
                narf_tpm::tpm2::TPM_ALG_SHA256,
            ),
            selections,
        )
        .await?;
    Ok(QuoteBundle {
        attest_bytes: quote.attest_bytes,
        info: quote.info,
        signature: quote.signature,
        ak_public: public.out_public,
        ak_name: public.name,
        ak_qualified_name: public.qualified_name,
    })
}
