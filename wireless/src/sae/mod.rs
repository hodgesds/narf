//! WPA3-SAE (Simultaneous Authentication of Equals) — Dragonfly handshake.
//!
//! ## Module layout
//!
//! - [`dragonfly`] — the generic `EccGroup` / `MacPrimitive` state
//!   machine and the P-256 hunting-and-pecking backend (whose PWE is
//!   [`pt::pwe_hunt_and_peck`]). Its own key derivation is a
//!   structural model, not 802.11's: drivers use [`session`].
//! - [`pt`] — the PWE derivations of hostap `sae.c`: IEEE 802.11-2020
//!   §12.4.4.2.3 Hash-to-Element (PT from `(ssid, password)`, PWE per
//!   MAC pair; SSWU from `narf_crypto::p256::hash_to_curve`) and the
//!   §12.4.4.2.2 hunting-and-pecking loop.
//! - [`groups`] — the IANA "Transform Type 4 - DH Group" IDs SAE
//!   selects between (P-256 / P-384 / P-521 …).
//! - [`session`] — the [`SaeSession`] handshake driver (H2E or
//!   hunting-and-pecking PWE) with the `try_build_commit` / `on_commit` /
//!   `build_confirm` / `on_confirm` API used by drivers, pinned to the
//!   IEEE 802.11-2020 Annex J.10 vectors hostap's `sae_tests` checks.
//!
//! ## Which PWE path to use
//!
//! The original SAE PWE derivation (§12.4.4.2.2) is a side-channel
//! liability — its iteration count depends (statistically) on the
//! password. IEEE 802.11-2020 §12.4.4.2.3 introduces H2E as the
//! replacement (the SSWU map is constant-time). New
//! deployments **must** prefer H2E; the legacy loop in [`dragonfly`]
//! is kept for compatibility with the existing smokes and for routers
//! that haven't shipped H2E yet.
//!
//! The status code that signals H2E support on the wire is
//! `SAE_STATUS_HASH_TO_ELEMENT` (126) per §12.4.7.5.
//!
//! ## Reference implementations
//!
//! - hostap `src/common/sae.c` (`sae_h2e_pt_*` / `sae_derive_pwe_h2e`)
//!   is the canonical implementation. NARF is GPL-2.0-or-later post
//!   2026-05-20, so it can be (and is) cited directly. Code here is
//!   independently written from spec.
//! - Linux `net/wireless/sme.c` drives SAE for cfg80211 — the user
//!   space side talks to wpa_supplicant; the kernel mostly forwards
//!   Authentication frames.

pub mod dragonfly;
pub mod groups;
pub mod pk;
pub mod pt;
pub mod session;

// Re-export the legacy surface so existing call sites
// (`crate::sae::Sae`, `crate::sae::CommitFrame`, ...) keep working.
pub use dragonfly::{
    CommitFrame, ConfirmFrame, EccGroup, HmacSha256, HuntAndPeck, MacPrimitive, P256Group, Sae,
    SaeError, SaeState, SAE_SEQ_COMMIT, SAE_SEQ_CONFIRM, SAE_STATUS_HASH_TO_ELEMENT,
    SAE_STATUS_SUCCESS, SAE_STATUS_UNSUPPORTED_GROUP,
};

pub use groups::SaeGroup;
pub use pt::{pt_h2e, pt_h2e_bytes, pwe_from_pt, pwe_hunt_and_peck};
pub use session::SaeSession;
