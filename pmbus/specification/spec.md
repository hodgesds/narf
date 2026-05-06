# PMBus Power Telemetry Specification

## Overview
This document specifies the interface for ATX 3.x power supply telemetry via PMBus (Power Management Bus) over I2C/SMBus. It provides real-time monitoring of voltage, current, and temperature.

## Capabilities
Telemetry access is governed by the `PmBus` capability (`CapKind::PmBus`).

## Data Formats
PMBus uses a variety of data formats, primarily:
- **Direct Format**: A 16-bit signed integer with coefficients.
- **Linear Format**: A 11-bit mantissa and 5-bit exponent.

## Commands
The following standard PMBus commands are supported for monitoring:

| Command | Code | Description | Unit |
|---------|------|-------------|------|
| READ_VIN | 0x88 | Input voltage | Volts |
| READ_IIN | 0x89 | Input current | Amperes |
| READ_VOUT | 0x8B | Output voltage | Volts |
| READ_IOUT | 0x8C | Output current | Amperes |
| READ_TEMPERATURE_1 | 0x8D | Temperature sensor 1 | Celsius |
| READ_POUT | 0x96 | Output power | Watts |
| READ_PIN | 0x97 | Input power | Watts |

## Interface Traits
The `narf-pmbus` crate exposes traits for hardware-agnostic monitoring.

### `PmBusMonitor`
Async trait for reading telemetry values.
- `read_voltage()`
- `read_current()`
- `read_temperature()`
- `read_power()`
