//! Codec layer — vendor-agnostic AFG bring-up + Realtek-specific
//! init sequences + per-laptop quirks.

pub mod generic;
pub mod quirks;
pub mod realtek;

// Re-export the verb encoder + the Codec address + a small handful
// of types that the rest of the crate consumes.
pub use generic::{
    encode_verb, Codec, CodecKind, CodecVerbBus, PinDevice, VerbError, Widget, WidgetKind,
    PARAM_AUDIO_WIDGET_CAPS, PARAM_CONN_LIST_LEN, PARAM_FUNCTION_GROUP, PARAM_PIN_CAPS,
    PARAM_REVISION_ID, PARAM_SUB_NODE_COUNT, PARAM_VENDOR_ID, VERB_GET_PARAMETER,
    VERB_SET_AMP_GAIN_MUTE, VERB_SET_COEF_INDEX, VERB_SET_EAPD_BTL, VERB_SET_PIN_WIDGET_CONTROL,
    VERB_SET_POWER_STATE, VERB_SET_PROC_COEF, VERB_SET_UNSOLICITED_RESPONSE,
};
pub use realtek::{RealtekChip, REALTEK_VENDOR_ID};
