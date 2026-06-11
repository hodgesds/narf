//! A2DP — Advanced Audio Distribution Profile (source + sink roles).
//!
//! This module implements the A2DP-specific layer that sits on top of
//! the AVDTP session ([`crate::profiles::avdtp`]) and the AVDTP codec
//! layer ([`crate::avdtp`]).
//!
//! ## Architecture
//!
//! ```text
//!  A2DP Source/Sink
//!    │
//!    ├── SEP table  (local stream endpoints: SBC Source, SBC Sink)
//!    ├── Capability negotiation (intersect local + remote SBC caps)
//!    └── Stream-start state machine (driven by callers via A2dpSource)
//! ```
//!
//! References:
//! - "Advanced Audio Distribution Profile, Version 1.4" — Bluetooth SIG.
//!   §4.3 (SBC codec configuration table 4.1), §4.6 (Source role
//!   procedure), §4.7 (Sink role procedure).
//! - Audio/Video Distribution Transport Protocol Specification 1.3
//!   §8.6 (SEP Discover), §8.7 (Get Capabilities).
//! - Linux BlueZ `profiles/audio/a2dp.c` consulted for codec-config
//!   intersection logic (GPL-2.0-or-later, NARF relicense 2026-05-20).

use alloc::vec::Vec;

use crate::avdtp::{
    sbc_media_codec_capability, SbcCapability, StreamEndPoint, CAT_MEDIA_TRANSPORT, MEDIA_AUDIO,
    SBC_ALLOC_LOUDNESS, SBC_ALLOC_SNR, SBC_BLOCK_12, SBC_BLOCK_16, SBC_BLOCK_4, SBC_BLOCK_8,
    SBC_CHAN_DUAL, SBC_CHAN_JOINT_STEREO, SBC_CHAN_MONO, SBC_CHAN_STEREO, SBC_FREQ_16000,
    SBC_FREQ_32000, SBC_FREQ_44100, SBC_FREQ_48000, SBC_SUBBANDS_4, SBC_SUBBANDS_8, SEP_TYPE_SINK,
    SEP_TYPE_SOURCE,
};

// ── SEID assignments ─────────────────────────────────────────────────

/// Local SEID for the SBC audio source endpoint.
pub const LOCAL_SEID_SBC_SOURCE: u8 = 0x01;
/// Local SEID for the SBC audio sink endpoint.
pub const LOCAL_SEID_SBC_SINK: u8 = 0x02;

// ── SBC capability defaults ───────────────────────────────────────────

/// Default local SBC capability advertised from the Source SEP.
/// Supports 44.1 kHz + 48 kHz, Joint Stereo + Stereo, all block
/// lengths, 8 subbands, Loudness allocation.  Bitpool 2..=53 covers
/// the mandatory range (A2DP §4.3.2 table 4.1).
pub const LOCAL_SBC_SOURCE_CAPS: SbcCapability = SbcCapability {
    frequency: SBC_FREQ_44100 | SBC_FREQ_48000,
    channel_mode: SBC_CHAN_JOINT_STEREO | SBC_CHAN_STEREO | SBC_CHAN_DUAL | SBC_CHAN_MONO,
    block_length: SBC_BLOCK_16 | SBC_BLOCK_12 | SBC_BLOCK_8 | SBC_BLOCK_4,
    subbands: SBC_SUBBANDS_8 | SBC_SUBBANDS_4,
    allocation: SBC_ALLOC_LOUDNESS | SBC_ALLOC_SNR,
    min_bitpool: 2,
    max_bitpool: 53,
};

/// Default local SBC capability advertised from the Sink SEP.
/// Same bitmap range as the source — we accept the full mandatory set.
pub const LOCAL_SBC_SINK_CAPS: SbcCapability = SbcCapability {
    frequency: SBC_FREQ_44100 | SBC_FREQ_48000,
    channel_mode: SBC_CHAN_JOINT_STEREO | SBC_CHAN_STEREO | SBC_CHAN_DUAL | SBC_CHAN_MONO,
    block_length: SBC_BLOCK_16 | SBC_BLOCK_12 | SBC_BLOCK_8 | SBC_BLOCK_4,
    subbands: SBC_SUBBANDS_8 | SBC_SUBBANDS_4,
    allocation: SBC_ALLOC_LOUDNESS | SBC_ALLOC_SNR,
    min_bitpool: 2,
    max_bitpool: 53,
};

// ── SEP table ─────────────────────────────────────────────────────────

/// One local Stream End Point entry.
#[derive(Clone, Debug)]
pub struct LocalSep {
    pub sep: StreamEndPoint,
    pub sbc_caps: SbcCapability,
}

/// The local SEP table (Source + Sink).
pub fn local_sep_table() -> [LocalSep; 2] {
    [
        LocalSep {
            sep: StreamEndPoint {
                seid: LOCAL_SEID_SBC_SOURCE,
                in_use: false,
                media_type: MEDIA_AUDIO,
                tsep: SEP_TYPE_SOURCE,
            },
            sbc_caps: LOCAL_SBC_SOURCE_CAPS,
        },
        LocalSep {
            sep: StreamEndPoint {
                seid: LOCAL_SEID_SBC_SINK,
                in_use: false,
                media_type: MEDIA_AUDIO,
                tsep: SEP_TYPE_SINK,
            },
            sbc_caps: LOCAL_SBC_SINK_CAPS,
        },
    ]
}

// ── SBC capability negotiation ────────────────────────────────────────

/// Result of [`negotiate_sbc`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NegotiateResult {
    /// Negotiation succeeded; use the returned configuration.
    Ok(SbcCapability),
    /// No common frequency bit between local and remote.
    NoCommonFrequency,
    /// No common channel mode bit.
    NoCommonChannelMode,
    /// No common block length bit.
    NoCommonBlockLength,
    /// No common subbands bit.
    NoCommonSubbands,
    /// No common allocation method bit.
    NoCommonAllocation,
    /// Bitpool ranges don't overlap.
    NoCommonBitpool,
}

/// Compute the SBC configuration to propose to the remote peer.
///
/// Strategy (A2DP §4.3.2, mandatory SBC configuration rules):
/// 1. Intersect bitmask fields; pick the single "best" bit from the
///    intersection using a fixed preference order.
/// 2. Clamp bitpool to the overlap of `[local.min, local.max]` and
///    `[remote.min, remote.max]`; use the remote maximum as target.
///
/// Preference order:
/// - Frequency: 48000 > 44100 > 32000 > 16000.
/// - Channel mode: Joint Stereo > Stereo > Dual > Mono.
/// - Block length: 16 > 12 > 8 > 4.
/// - Subbands: 8 > 4.
/// - Allocation: Loudness > SNR.
pub fn negotiate_sbc(local: &SbcCapability, remote: &SbcCapability) -> NegotiateResult {
    let common_freq = local.frequency & remote.frequency;
    let freq = pick_best(
        common_freq,
        &[
            SBC_FREQ_48000,
            SBC_FREQ_44100,
            SBC_FREQ_32000,
            SBC_FREQ_16000,
        ],
    );
    let freq = match freq {
        Some(f) => f,
        None => return NegotiateResult::NoCommonFrequency,
    };

    let common_chan = local.channel_mode & remote.channel_mode;
    let chan = pick_best(
        common_chan,
        &[
            SBC_CHAN_JOINT_STEREO,
            SBC_CHAN_STEREO,
            SBC_CHAN_DUAL,
            SBC_CHAN_MONO,
        ],
    );
    let chan = match chan {
        Some(c) => c,
        None => return NegotiateResult::NoCommonChannelMode,
    };

    let common_block = local.block_length & remote.block_length;
    let block = pick_best(
        common_block,
        &[SBC_BLOCK_16, SBC_BLOCK_12, SBC_BLOCK_8, SBC_BLOCK_4],
    );
    let block = match block {
        Some(b) => b,
        None => return NegotiateResult::NoCommonBlockLength,
    };

    let common_subbands = local.subbands & remote.subbands;
    let subbands = pick_best(common_subbands, &[SBC_SUBBANDS_8, SBC_SUBBANDS_4]);
    let subbands = match subbands {
        Some(s) => s,
        None => return NegotiateResult::NoCommonSubbands,
    };

    let common_alloc = local.allocation & remote.allocation;
    let allocation = pick_best(common_alloc, &[SBC_ALLOC_LOUDNESS, SBC_ALLOC_SNR]);
    let allocation = match allocation {
        Some(a) => a,
        None => return NegotiateResult::NoCommonAllocation,
    };

    // Bitpool: overlap of [local.min..=local.max] and [remote.min..=remote.max].
    let bp_min = local.min_bitpool.max(remote.min_bitpool);
    let bp_max = local.max_bitpool.min(remote.max_bitpool);
    if bp_min > bp_max {
        return NegotiateResult::NoCommonBitpool;
    }

    NegotiateResult::Ok(SbcCapability {
        frequency: freq,
        channel_mode: chan,
        block_length: block,
        subbands,
        allocation,
        min_bitpool: bp_min,
        max_bitpool: bp_max,
    })
}

/// Pick the first bit in `preference` that is set in `mask`.
fn pick_best(mask: u8, preference: &[u8]) -> Option<u8> {
    preference.iter().find(|&&bit| mask & bit != 0).copied()
}

// ── Service-capability blob builder ──────────────────────────────────

/// Build the Set Configuration service-capability blob for an SBC
/// Source stream (Media Transport entry + Media Codec entry).
///
/// This is the `capabilities` blob passed to
/// [`crate::avdtp::set_configuration_command`].
pub fn build_source_config_blob(cfg: &SbcCapability) -> Vec<u8> {
    // Media Transport capability (§8.21.1): category + length=0.
    let mut out = alloc::vec![CAT_MEDIA_TRANSPORT, 0x00];
    // Media Codec capability (§8.21.5).
    out.extend(sbc_media_codec_capability(MEDIA_AUDIO, *cfg));
    out
}

// ── A2DP source stream-start state machine ────────────────────────────

/// State of the A2DP source role stream-start procedure.
///
/// The caller drives this forward by calling the appropriate method
/// and writing the returned bytes to the AVDTP signalling channel.
/// Inbound AVDTP accept messages are processed by
/// [`crate::profiles::avdtp::Session::feed`] and result in state
/// transitions there; `A2dpSource` tracks the higher-level audio layer
/// state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SourceState {
    /// No A2DP session in progress.
    Idle,
    /// L2CAP connected; AVDTP discovery in progress.
    Discovering,
    /// Remote SEPs discovered; awaiting capability query.
    AwaitingCaps,
    /// Capabilities received; negotiation complete; awaiting Set Config.
    NegotiationDone,
    /// Set Config sent; awaiting Open.
    WaitingOpen,
    /// Open sent; awaiting Start.
    WaitingStart,
    /// Stream started; audio data may now flow.
    Streaming,
    /// Stream closed / aborted.
    Closed,
}

/// A2DP source role controller.
#[derive(Debug)]
pub struct A2dpSource {
    pub state: SourceState,
    /// Selected SBC configuration (set after negotiation).
    pub config: Option<SbcCapability>,
}

impl Default for A2dpSource {
    fn default() -> Self {
        Self::new()
    }
}

impl A2dpSource {
    pub fn new() -> Self {
        Self {
            state: SourceState::Idle,
            config: None,
        }
    }

    /// Notify that the L2CAP/AVDTP signalling channel is connected.
    /// Returns the initial AVDTP Discover command to send.
    pub fn on_connected(&mut self, session: &mut super::avdtp::Session) -> Vec<u8> {
        self.state = SourceState::Discovering;
        session.discover()
    }

    /// Called after `Session::feed` transitions to `Configuring`
    /// following a successful Discover response.  Picks the first
    /// audio-media SINK SEP from `remote_seps` and requests its
    /// capabilities.  Returns the Get Capabilities command bytes.
    pub fn on_discovered(&mut self, session: &mut super::avdtp::Session) -> Option<Vec<u8>> {
        let seid = session
            .remote_seps
            .iter()
            .find(|s| s.media_type == MEDIA_AUDIO && s.tsep == SEP_TYPE_SINK)
            .map(|s| s.seid)?;
        self.state = SourceState::AwaitingCaps;
        Some(session.get_capabilities(seid))
    }

    /// Called after Get Capabilities response.  Negotiates SBC config
    /// and, if successful, stores it and returns the Set Configuration
    /// command bytes.
    pub fn on_caps(
        &mut self,
        session: &mut super::avdtp::Session,
        remote_caps: &SbcCapability,
    ) -> Option<Vec<u8>> {
        let cfg = match negotiate_sbc(&LOCAL_SBC_SOURCE_CAPS, remote_caps) {
            NegotiateResult::Ok(c) => c,
            _ => return None,
        };
        self.config = Some(cfg);
        let blob = build_source_config_blob(&cfg);
        self.state = SourceState::NegotiationDone;
        let cmd = session.set_configuration(&blob);
        self.state = SourceState::WaitingOpen;
        Some(cmd)
    }

    /// Send Open after Set Configuration is accepted.
    pub fn on_configured(&mut self, session: &mut super::avdtp::Session) -> Vec<u8> {
        self.state = SourceState::WaitingOpen;
        session.open()
    }

    /// Send Start after Open is accepted.
    pub fn on_opened(&mut self, session: &mut super::avdtp::Session) -> Vec<u8> {
        self.state = SourceState::WaitingStart;
        session.start()
    }

    /// Mark stream as active.
    pub fn on_started(&mut self) {
        self.state = SourceState::Streaming;
    }

    /// Encode one PCM block into an SBC frame, ready for AVDTP push.
    ///
    /// Bridge into `narf_audio::sbc`: maps the negotiated A2DP SBC
    /// capability bits (frequency / channel mode / blocks / subbands /
    /// allocation / bitpool) into an `sbc::Header` and runs the
    /// encoder over `pcm`. Caller is responsible for prepending the
    /// RTP / AVDTP media payload header before writing to L2CAP.
    ///
    /// Reference: A2DP 1.4 §4.6.5 "Source role behaviour while in
    /// streaming state" — PCM frames in, SBC media bytes out.
    pub fn encode_pcm(&mut self, pcm: &[i16]) -> Option<alloc::vec::Vec<u8>> {
        if self.state != SourceState::Streaming {
            return None;
        }
        let cfg = self.config?;
        let h = narf_audio::sbc::Header {
            sampling_frequency: avdtp_freq_to_sbc(cfg.frequency)?,
            blocks: avdtp_blocks_to_sbc(cfg.block_length)?,
            channel_mode: avdtp_chan_to_sbc(cfg.channel_mode)?,
            allocation_method: if cfg.allocation == SBC_ALLOC_SNR {
                1
            } else {
                0
            },
            subbands: if cfg.subbands == SBC_SUBBANDS_8 { 1 } else { 0 },
            bitpool: cfg.max_bitpool,
            crc: 0,
        };
        let mut enc = narf_audio::sbc::Sbc::new(h);
        let mut buf = alloc::vec![0u8; enc.frame_bytes()];
        enc.encode(pcm, &mut buf).ok()?;
        Some(buf)
    }
}

/// AVDTP frequency bit → SBC frequency code (0..3).
fn avdtp_freq_to_sbc(f: u8) -> Option<u8> {
    match f {
        SBC_FREQ_16000 => Some(0),
        SBC_FREQ_32000 => Some(1),
        SBC_FREQ_44100 => Some(2),
        SBC_FREQ_48000 => Some(3),
        _ => None,
    }
}
/// AVDTP block-length bit → SBC blocks code (0..3).
fn avdtp_blocks_to_sbc(b: u8) -> Option<u8> {
    match b {
        SBC_BLOCK_4 => Some(0),
        SBC_BLOCK_8 => Some(1),
        SBC_BLOCK_12 => Some(2),
        SBC_BLOCK_16 => Some(3),
        _ => None,
    }
}
/// AVDTP channel-mode bit → SBC channel_mode code (0..3).
fn avdtp_chan_to_sbc(c: u8) -> Option<u8> {
    match c {
        SBC_CHAN_MONO => Some(0),
        SBC_CHAN_DUAL => Some(1),
        SBC_CHAN_STEREO => Some(2),
        SBC_CHAN_JOINT_STEREO => Some(3),
        _ => None,
    }
}
