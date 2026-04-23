# SLSA (Supply-chain Levels for Software Artifacts)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## SLSA Framework for NARF Build Provenance

SLSA (Supply-chain Levels for Software Artifacts) provides a framework for certifying that software artifacts (binaries, releases) are built from audited source and not tampered with en route to consumers. NARF should adopt SLSA as part of its long-term release infrastructure, especially critical given the kernel's privileged role.

## SLSA Levels and NARF Roadmap

**Level 1 (Provenance Exists)**: Automate builds and publish a provenance statement (metadata describing source commit, build environment, outputs). NARF can achieve Level 1 immediately: GitHub Actions auto-builds on each tag; publish in-toto metadata linking commit hash to binary hash.

**Level 2 (Hosted Build Service)**: Use a trusted CI system (GitHub Actions) with access controls. NARF is at Level 2 today if builds are non-hermetic (developer secrets, local toolchain state, could affect output). Move to Level 2 proper by using Docker containers for hermetic builds.

**Level 3 (Hardened Builds)**: Require signed commits, enforce branch protection, publish build logs. NARF should require GPG-signed commits; maintain public GitHub settings showing "require code review" + "require status checks to pass".

**Level 4 (Hermetic, Reproducible)**: Prove that rebuilding the same source by a different builder produces byte-identical binaries. NARF should publish build Dockerfiles and reproducibility statements once Stage 1 reaches stability.

## Key Mechanisms

**In-Toto Attestations**: Link commits → build artifacts → releases. When NARF tags a release, the CI should emit an in-toto statement: "I (GitHub Actions build-xxxx) built commit abc123 and produced artifact narf-0.1.tar.gz with hash xyz". Sign this statement with a CI signing key, publish it alongside the release.

**Artifact Hash Pinning**: When distributing NARF (e.g., in a crate or Cargo.toml), specify not just the version but optionally the expected hash. Consumers can verify they received the expected binary without re-executing the build.

**Dependency Declarations**: SLSA requires tracking build inputs (compiler version, dependencies, secrets used). NARF's Cargo.lock file locks dependency versions; document the exact compiler invocation (rustc --version, LLVM backend) in release notes.

## Invariants to Maintain

- **Provenance Completeness**: Every released artifact has a corresponding in-toto attestation linking source to binary
- **Build Isolation**: Builds run in ephemeral environments; previous builds cannot contaminate new ones
- **Supply Chain Visibility**: Consumers can trace NARF back to source commits and audit the build path

## Performance Trade-offs

Implementing SLSA Level 3-4 requires:
- Hermetic build environments (Docker, Nix, Bazel) — adds ~5 min per build
- Reproducibility verification CI job — adds cost but catches build-system non-determinism
- In-toto metadata generation and signing — negligible cost but expands artifacts by ~1 KB

The payoff is trust: users can verify they're running the kernel you claim to have published, not a trojanized variant slipped in by a compromised distribution server.

## Pitfalls to Avoid

- **Build Key Compromise**: If the signing key for in-toto statements is stored in GitHub Secrets without rotation, a single leaked token allows forging provenance. Rotate quarterly.
- **Transitive Trust**: SLSA proves NARF's build; it doesn't prove upstream dependencies (rustc, musl) are uncompromised. Use supply-chain tools like `cargo-supply-chain` to audit deps.
- **Level Inflation**: Don't claim Level 4 reproducibility without regularly rebuilding and comparing binaries. One-time reproducibility is chance; repeated builds prove determinism.

## Recommendation

Phase SLSA adoption: Level 1 (now), Level 2 (before 0.1.0), Level 3 (before 1.0.0), Level 4 (maintenance phase). Document the current level in README. When releasing, publish in-toto attestations to the GitHub release page; link from advisories to the provenance statement.

https://slsa.dev/
