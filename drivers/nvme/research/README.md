# drivers/nvme — Research

## Primary sources

- **NVM Express Base Specification 2.0**.
  <https://nvmexpress.org/specifications/>
- **NVM Express PCIe Transport Specification 1.0**.

## Secondary sources

- **SPDK NVMe driver** — user-space, high-perf reference.
  <https://spdk.io/doc/nvme.html>
- **Linux `drivers/nvme/host/pci.c`** — mainline reference.
- **Rust `vroom` NVMe driver** — no_std Rust NVMe precedent.

## Distilled summaries

- `summaries/nvm-express-spec.md` — NVMe 2.0 architecture and NARF design patterns

## Fetched this round (2026-04-22)

- `summaries/nvm-express-spec.md` — NVM Express specification

## Open research questions

- How much of the admin set is required pre-boot to trust the device?
- Telemetry / health-log polling cadence without burning cycles.
