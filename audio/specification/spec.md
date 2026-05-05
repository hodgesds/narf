# audio — Specification

> Status: **v1.0** (Stage 4 design lock).
>
> High-performance, zero-copy audio subsystem for the NARF ecosystem.
> Optimized for low-latency playback/capture and hardware-assisted mixing.

## 1. Purpose & scope

**Owns:**
- The **Audio Interface Trait** (`AudioIface`) for PCM and MIDI.
- **Audio Capabilities** (`AudioCap<T, R>`) gating access to playback, capture, and effects.
- **Audio Registry** — discovery of HDA, USB, and VirtIO sound devices.
- **StreamRings** — specialized Narf-Rings for isochronous audio data.

**Does NOT own:**
- Soft-mixers, equalizers, or 3D spatialization — these live in a userspace "Audio Server".
- Codec-specific verbs (HDA-specific) — handled by the underlying driver.

## 2. Design Principles

1. **Isochronous-First**: Audio streams are time-sensitive. Narf-Rings for audio (`StreamRing`) are prioritized by the scheduler.
2. **Zero-Copy Pipeline**: Data flows from Userspace → `StreamRing` → Hardware DMA without CPU copy.
3. **Capability-Gated**: Recording audio requires an explicit `CaptureCap`.

## 3. Public Interface

### 3.1 Device Information

```rust
pub struct AudioInfo {
    pub id:           AudioId,
    pub name:         String,
    pub channels:     u16,
    pub formats:      AudioFormats,      // S16LE, S24LE, F32LE, etc.
    pub sample_rates: Vec<u32>,          // 44100, 48000, 96000, 192000
    pub caps:         AudioHwCaps,       // Multi-stream, Hardware-mixing
}
```

### 3.2 Stream Management

```rust
pub struct StreamConfig {
    pub format:      AudioFormat,
    pub rate:        u32,
    pub channels:    u16,
    pub period_size: usize,              // Buffer size in frames
}

pub async fn open_stream(
    cap: &Cap<AudioIface, Playback>,
    cfg: StreamConfig,
) -> Result<StreamRing, AudioError>;
```

## 4. Hardware Isolation

Following the **Framekernel** architecture:
- Audio drivers (HDA, USB) run in dedicated PKS/MTE domains.
- `StreamRing` buffers are provided via `io/spec` as `DmaBuffer` caps.
- The **Audio Server** (userspace) manages multiple client streams and mixes them into a single `StreamRing` for the hardware, or uses hardware-mixing capabilities where available.

## 5. Security: The Audio Server

- Userspace applications do not talk to hardware directly. They talk to the **Audio Server** via IPC.
- Only the Audio Server holds `Cap<AudioIface, Admin>`.
- `CaptureCap` is a high-privilege resource, audited by the security model.

## 6. Stage Assignment

- **Stage 4 (now)**: Specification lock and `narf-audio` crate refinement.
- **Stage 5**: Intel HDA driver bring-up and basic PCM playback.
- **Stage 6**: USB Audio Class 2.0 and low-latency MIDI support.

## 7. Dependencies

- **Consumes**: `drivers/`, `capabilities/`, `io/`, `ipc/`.
- **Provides to**: Userspace audio daemons (PipeWire-equivalent).
