# block — Research

## Primary sources

- **NVM Express Base Specification 2.0** — sets the vocabulary for
  modern block I/O (already referenced from `drivers/nvme/`).
- **SCSI Block Commands (SBC-4)** — legacy reference, largely for
  terminology (LBA, flush).
- **Linux `Documentation/block/`** — multi-queue design documents,
  scheduler descriptions.
  <https://docs.kernel.org/block/index.html>
- **"A Study of Linux I/O Schedulers" (various)** — comparative
  background on mq-deadline, BFQ, Kyber.

## Secondary sources

- **Linux `block/blk-mq.c`** — multi-queue dispatch implementation.
- **SPDK bdev layer** — userspace block abstraction; similar
  zero-copy spirit to NARF's design.
  <https://spdk.io/doc/bdev.html>
- **Zoned Namespace Command Set (NVMe TP 4053)** — for when we decide
  whether to support ZNS.
- **io_uring block path** — how kernel block integrates with async
  submission.

## Distilled summaries

- (None at Stage 1. Add an mq-deadline summary if we adopt a
  derivative algorithm.)

## Fetched this round

- summaries/linux-block-subsystem.md — Multi-queue architecture, I/O scheduling, and immutable request descriptors
- summaries/spdk-bdev.md — Virtual block device stacking, lockless queues, and resource bounds

## Open research questions

- Request merging — worth the CPU cost for NVMe-class devices? (Linux
  found diminishing returns.)
- How to expose device-specific hints (NVMe write streams, FDP) to
  filesystem without leaking abstractions.
- Benchmarking methodology for tail-latency guarantees under mixed
  QoS workloads — feed into `verification/`.
