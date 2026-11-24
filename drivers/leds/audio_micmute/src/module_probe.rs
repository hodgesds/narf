//! Loadable `audio-micmute` trigger frontend (module build only).
//!
//! Registers the trigger through `narf_led_register_trigger`; the
//! compute callback reads the core mic-mute bit through
//! `narf_led_audio_mic_muted` (which defaults `false` until the
//! lane-4 sound feed lands — do not invent a feed here).

unsafe extern "C" {
    fn narf_led_register_trigger(
        name: *const u8,
        name_len: usize,
        compute: usize,
        cookie: u64,
    ) -> i32;
    fn narf_led_unregister_trigger(name: *const u8, name_len: usize) -> i32;
    fn narf_led_audio_mic_muted() -> u8;
}

/// Trigger name in the LED core's registry.
const TRIGGER_NAME: &[u8] = b"audio-micmute";

/// Trigger compute callback: `max_brightness` while the mic is
/// muted, `0` while unmuted. `ticks` is unused (a level trigger,
/// not a pattern).
extern "C" fn compute(_cookie: u64, max: u32, _ticks: u32) -> u32 {
    // SAFETY: no pointers cross; the export reads a core atomic.
    let muted = unsafe { narf_led_audio_mic_muted() } != 0;
    crate::trigger::micmute_brightness(muted, max)
}

/// Register the trigger (module init).
pub fn register() {
    // SAFETY: the name bytes are static; the compute callback stays
    // mapped while registered (unload removes it first).
    let _ = unsafe {
        narf_led_register_trigger(
            TRIGGER_NAME.as_ptr(),
            TRIGGER_NAME.len(),
            compute as usize,
            0,
        )
    };
}

/// Unregister the trigger (module exit). Refused with `-EBUSY`
/// while a LED's current trigger is this trigger — the loader
/// backstop force-reverts those LEDs instead, so unload never
/// strands a LED on a dead trigger.
pub fn exit() {
    // SAFETY: the name bytes are static.
    let _ = unsafe { narf_led_unregister_trigger(TRIGGER_NAME.as_ptr(), TRIGGER_NAME.len()) };
}
