# drivers/soc — SoC platform layers

SoC platform support: the services that sit between the devicetree
(or other platform enumeration) and an on-chip peripheral driver.
Each child crate has its own README with the details.

| crate | what it is |
|---|---|
| [`qcom/`](qcom/README.md) | Qualcomm SoC platform layer: devicetree platform-device resolution, Secure Channel Manager (SCM) calls into TrustZone, the MDT/MBN split-firmware loader, SMEM, SMP2P, the TCSR hardware mutex, outgoing IPC kicks, GCC reset/clock bits, and two Hexagon remoteproc loaders (host-reset Q6 WCSS and TrustZone-authenticated PAS). |
