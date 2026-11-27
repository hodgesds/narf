//! The mic-mute level computation (pure, testable in both builds).
//!
//! Level, not a pattern: the LED is on while the mic is muted, off
//! otherwise — Linux's `ledtrig_audio_mute` for the mic-mute bit
//! (`drivers/leds/trigger/ledtrig-audio.c`). The module's `compute`
//! callback reads the bit through the KABI
//! (`narf_led_audio_mic_muted`) and calls this; the core clamps the
//! result to `[0, max_brightness]` (the computation never exceeds
//! it anyway).

/// LED brightness for the mic-mute state: `max_brightness` while
/// muted, `0` while unmuted.
pub fn micmute_brightness(muted: bool, max_brightness: u32) -> u32 {
    if muted {
        max_brightness
    } else {
        0
    }
}
