# pwm — Specification

> Status: **v0.1** (Draft).
>
> Clean-room Pulse Width Modulation (PWM) control model for the NARF ecosystem.
> Provides precise timing and power control for peripherals via capability-gated channels.

## 1. Purpose & scope

**Owns:**
- The **PWM Device Trait** (`PwmDevice`) for hardware-agnostic control.
- **PWM Capabilities** (`Cap<PwmCapType, R>`) gating access to individual channels or whole devices.
- **PWM Configuration Model** — duty cycle, frequency, and polarity.

**Does NOT own:**
- High-level motor controllers (stepper/servo logic) — these consume PWM caps.
- Complex waveform generators (unless implemented as PWM patterns).

## 2. Design Principles

1. **Precision Timing**: PWM parameters (frequency, duty cycle) are treated as real-time constraints.
2. **Capability Isolation**: Access to a PWM channel is a typed capability. One application cannot interfere with another's PWM channel on the same controller if they lack the relevant cap.
3. **Atomic Configuration**: Updates to PWM parameters should be atomic to prevent glitching.

## 3. Public Interface

### 3.1 PWM Parameters

```rust
pub struct PwmConfig {
    pub frequency_hz: u32,
    pub duty_cycle_ns: u64,
    pub polarity:      Polarity,
}

pub enum Polarity {
    Normal,
    Inversed,
}
```

### 3.2 PWM Device Trait

```rust
pub trait PwmDevice {
    fn set_config(&self, channel: u32, config: &PwmConfig) -> Result<(), PwmError>;
    fn enable(&self, channel: u32) -> Result<(), PwmError>;
    fn disable(&self, channel: u32) -> Result<(), PwmError>;
    fn channel_count(&self) -> u32;
}
```

### 3.3 Controller Registry

```rust
pub fn register_controller(phandle: u32, dev: Arc<dyn PwmDevice>);
pub fn lookup_controller(phandle: u32) -> Option<Arc<dyn PwmDevice>>;
pub fn unregister_controller(phandle: u32);
```

PWM controller drivers register the `PwmDevice` they drive under
the controller node's Devicetree phandle, so DT-described consumers
(a `pwm-fan` node whose `pwms` specifier carries that phandle, an
LED, a backlight) can resolve the controller the board description
points at. One phandle, one controller; last registration wins.
A consumer probe that runs before its controller registers gets
`None` and must treat that as a retryable miss (deferred probe),
not a hard failure — controller drivers register no later than
Stage::Device for their consumers to bind at boot.

## 4. Capability Gating

- `Cap<PwmCapType, Write>`: Authority to change configuration and enable/disable a PWM channel.
- `Cap<PwmCapType, Read>`: Authority to read current PWM state.
- Channels can be identified via the `index` in the `CapSlot` or a separate field if mapped to a device.

## 5. Security

- PWM access is restricted by the capability model.
- Malicious or buggy duty cycle settings are mitigated by higher-level "Safety Wrapper" drivers that hold the raw PWM cap and expose a narrowed interface.

## 6. Dependencies

- **Consumes**: `capabilities/`, `lib/`.
- **Provides to**: Motor drivers, LED controllers, Fan controllers.
