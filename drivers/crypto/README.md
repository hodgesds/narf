# drivers/crypto — AMD CCP Crypto Co-Processor Driver

`drivers/crypto` is the driver for the AMD CCP (Crypto Co-Processor), the
hardware crypto engine embedded in AMD SoCs alongside the Platform
Security Processor. The CCP and PSP share one PCI function (vendor
0x1022); the two drivers partition BAR2 between them — the PSP driver owns
the mailbox registers high in the BAR, while this driver touches only the
command-queue range at the base. The crate offloads symmetric crypto to
silicon: it implements the CCP v5 queue engine with AES-128/192/256 in
CBC/ECB/CTR/XTS/GCM modes and the SHA-1/224/256/384/512 hash family.

The driver models the CCP v5 register and descriptor layout directly. Up
to five command queues each occupy a 0x1000-byte window with control,
head/tail pointer, and interrupt/status registers; work is submitted as
32-byte command descriptors (eight little-endian words) that pack the
engine selector, function bits, data length, and source/destination
address fields — with SHA commands reusing the destination words to carry
the running hash length. The supported silicon spans Raven/Picasso (CCP
v5a), Renoir/Lucienne and Cezanne (v5b), and Phoenix HawkPoint1 (v5b),
matched by PCI device id. The register and descriptor definitions are
referenced against Linux's `ccp-dev-v5.c`, `ccp-dev.h`, and `sp-pci.c`,
cited under NARF's relicensing record.

The crate is `no_std` with `alloc`, forbids unchecked `unsafe`, and
depends only on `narf-lib` and the kernel test harness. As a hardware
driver it provides accelerated primitives for consumers such as the TPM
and storage-encryption paths; it does not define cryptographic policy.
