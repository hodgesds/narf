# scsi — T10 SCSI command + sense decoders

> Status: **v0.1**.

Adds a clean-room codec for the T10 SCSI command-block + response
shape that USB Mass Storage / UAS / AHCI / virtio-scsi consumers
share. The driver-specific transport layers (BOT / UAS / SCSI ATA
PASS-THROUGH) build on top of these CDB constructors and response
parsers.

## Sources (public only)

All code is derived strictly from the references below.
**No GPL Linux source consulted.**

- **INCITS T10 SCSI Block Commands - 3 (SBC-3), Revision 36** —
  T10 working group. Public document. §5.10 READ(10), §5.30
  WRITE(10), §5.16 READ CAPACITY(10), §5.16.2 READ CAPACITY(16).
- **INCITS T10 SCSI Primary Commands - 4 (SPC-4), Revision 37** —
  T10 working group. Public. §6.5 INQUIRY (standard 36-byte
  response: device-type byte + RMB flag + version + response-data-
  format + additional-length + 8-byte vendor + 16-byte product
  + 4-byte revision). §4.5.3 (Sense Data fixed format). §4.5.6
  (sense-key enumeration).
- **INCITS T10 SCSI Architecture Model - 5 (SAM-5)** — public.
  §5.3.1 table 9 (status byte values).

## Surface

- CDB builders: `inquiry` (with EVPD flag), `read_capacity_10`,
  `read_capacity_16`, `read_10` / `write_10` (with FUA), `request_sense`.
- Response decoders: `InquiryData::parse` (standard 36-byte form),
  `parse_read_capacity_10`, `parse_read_capacity_16`,
  `FixedSense::parse` covering response code, sense key,
  information bytes, ASC + ASCQ.
- Constants: `OP_*` opcodes, `STATUS_*` status-byte values,
  `SENSE_KEY_*` sense keys, `PDT_*` peripheral device types
  (block / sequential / CD-DVD / enclosure / …).
