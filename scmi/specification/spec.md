# scmi — Specification

> Status: **v0.1** (Stage 3 draft). Clean-room SCMI control
> for ARM-style platform management.

## 1. Purpose & scope

**Owns:**
- **SCMI Protocol implementation** — Clock, Power Domain, Performance, and Sensor protocols.
- **SCMI Message construction** — format and parse SCMI messages over a transport.
- **Platform Management** — abstract interface for clocks, power domains, and performance states.

**Does NOT own:**
- SCMI Transport — implemented by separate transport drivers (e.g., SMC, Mailbox).
- Device-specific logic — handled by drivers consuming SCMI capabilities.

## 2. Assumptions
- A transport mechanism (SMC, Mailbox, or Shared Memory) is available.
- The platform firmware implements the SCMI specification (ARM DEN0056).

## 3. Public interface

### 3.1 Clock Management
```rust
pub trait ScmiClock {
    async fn get_count(&self) -> Result<u32, ScmiError>;
    async fn get_attributes(&self, clock_id: u32) -> Result<ClockAttributes, ScmiError>;
    async fn set_rate(&self, clock_id: u32, rate: u64) -> Result<(), ScmiError>;
    async fn get_rate(&self, clock_id: u32) -> Result<u64, ScmiError>;
    async fn enable(&self, clock_id: u32, enable: bool) -> Result<(), ScmiError>;
}
```

### 3.2 Power Domain Management
```rust
pub trait ScmiPowerDomain {
    async fn get_count(&self) -> Result<u32, ScmiError>;
    async fn get_attributes(&self, domain_id: u32) -> Result<PowerDomainAttributes, ScmiError>;
    async fn set_state(&self, domain_id: u32, state: u32) -> Result<(), ScmiError>;
    async fn get_state(&self, domain_id: u32) -> Result<u32, ScmiError>;
}
```

### 3.3 Performance State Management
```rust
pub trait ScmiPerformance {
    async fn get_count(&self) -> Result<u32, ScmiError>;
    async fn get_attributes(&self, domain_id: u32) -> Result<PerfAttributes, ScmiError>;
    async fn set_level(&self, domain_id: u32, level: u32) -> Result<(), ScmiError>;
    async fn get_level(&self, domain_id: u32) -> Result<u32, ScmiError>;
}
```

## 4. Invariants & safety properties
- All SCMI operations are asynchronous to avoid blocking the caller during firmware communication.
- Capability-based access ensures only authorized tasks can modify platform states.

## 5. Architecture notes
- The subsystem provides traits that are implemented by the SCMI protocol engine.
- Communication with firmware is decoupled from the protocol logic via a transport abstraction.

## 6. Dependencies
- **Consumes:** `narf-lib`, `narf-scheduler`, `narf-capabilities`.
- **Provides to:** `power/`, `drivers/`.
