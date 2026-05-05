# i3c — Specification

> Status: **v0.1** (Stage 4 design draft).
>
> High-performance, async-first MIPI I3C subsystem for the NARF ecosystem.
> Standardizes sensor and peripheral access with support for In-Band Interrupts
> (IBI) and zero-copy data transfer.

## 1. Purpose & scope

**Owns:**
- The **I3C Interface Trait** (`I3cDevice`) for bus management and data transfer.
- **I3C Capabilities** (`I3cCap<T, R>`) gating access to specific target devices on the bus.
- **IBI Dispatcher** — routing asynchronous notifications from devices to driver futures.
- **HCI Register Abstractions** — standardized interface for I3C Host Controllers.

**Does NOT own:**
- High-level sensor drivers (e.g., Accelerometer, Light Sensor) — these consume `I3cCap`.
- Legacy I2C-only controllers (unless exposed through an I3C-HCI bridge).

## 2. Design Principles

1. **Granular Access**: A driver only gets access to the specific I3C device(s) it needs, identified by their Provisioned ID (PID) or Dynamic Address.
2. **Interrupt-Native**: Leverages I3C's In-Band Interrupts to provide `async` event handling without dedicated hardware IRQ pins.
3. **Zero-Copy DMA**: Supports the I3C HCI DMA mode for high-throughput sensor data.

## 3. Public Interface

### 3.1 Device Trait

```rust
#[async_trait]
pub trait I3cBus: Send + Sync {
    /// Performs a transfer to/from a specific target device.
    async fn transfer(&self, addr: u8, ops: &mut [I3cOp]) -> Result<(), I3cError>;

    /// Registers an async waker for an In-Band Interrupt (IBI).
    fn register_ibi_waker(&self, addr: u8, waker: Waker);
}
```

### 3.2 I3C Capabilities

```rust
pub enum I3cRight {
    /// Allows reading from a specific device.
    Read,
    /// Allows writing to a specific device.
    Write,
    /// Allows receiving In-Band Interrupts.
    Notify,
    /// Full bus management (Dynamic Address Assignment, etc.)
    Admin,
}

pub type Cap<I3cDevice, R> = ...;
```

## 4. Operation: In-Band Interrupts (IBI)

I3C allows target devices to pull the SDA line low to request service.
The `narf-i3c` subsystem exposes this as an async stream:

```rust
pub async fn wait_for_ibi(cap: &Cap<I3cDevice, Notify>) -> Result<IbiPayload, I3cError>;
```

The kernel's IBI dispatcher matches the incoming address to the registered waker, enabling low-latency response to sensor events.

## 5. Security & Isolation

- **Domain Isolation**: I3C host drivers run in their own PKS/MTE domains.
- **Address Validation**: The `i3c/` crate validates that all `transfer()` calls target addresses authorized by the provided `I3cCap`.
- **Hot-Join Policy**: Devices requesting a Dynamic Address via Hot-Join are audited by the security model before being admitted to the bus registry.

## 6. Stage Assignment

- **Stage 4 (now)**: Specification and initial `I3cBus` trait.
- **Stage 5**: Basic HCI driver (PIO mode) and Dynamic Address Assignment (DAA).
- **Stage 6**: DMA mode and advanced HDR (High Data Rate) modes.

## 7. Dependencies

- **Consumes**: `drivers/`, `capabilities/`, `io/`, `lib/`.
- **Provides to**: Sensor Drivers, Human Interface Daemons.
