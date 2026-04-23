# console — Research

## Primary sources

- **NS 16550 UART datasheet** (or clones).
- **Arm PL011 Technical Reference Manual**.
  <https://developer.arm.com/documentation/ddi0183/latest/>

## Secondary sources

- **`uart_16550` crate (rust-osdev)**. <https://docs.rs/uart_16550>
- **`tock/arm-pl011` driver** — readable Rust PL011 example.
- **Linux `drivers/tty/serial/8250/*` and `drivers/tty/serial/amba-pl011.c`**.
- **The `log` / `tracing` Rust ecosystems**.

## Distilled summaries

- (None needed at Stage 1.)

## Open research questions

- Is "panic sink" the right integration point for a future tracing
  framework, or do we want a separate `panic_log/` structure?
