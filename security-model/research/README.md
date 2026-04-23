# security-model — Research

## Primary sources

- **seL4 whitepaper — "From L3 to seL4: What Have We Learnt in 20 Years
  of L4 Microkernels?" (Heiser, Elphinstone, 2016)**
  <https://trustworthy.systems/publications/full_text/Heiser_Elphinstone_16.pdf>
- **"Capability Myths Demolished" (Miller, Yee, Shapiro, 2003)** — the
  canonical rebuttal to common misunderstandings of the capability model.
  <http://srl.cs.jhu.edu/pubs/SRL2003-02.pdf>
- **KeyKOS / EROS papers (Hardy, Shapiro, et al.)** — capability OS
  precedent NARF's Rust-type enforcement descends from.
  <https://www.cis.upenn.edu/~KeyKOS/>
- **Intel PKS whitepaper** — supervisor protection keys.
  <https://www.intel.com/content/www/us/en/developer/articles/technical/protection-keys-for-supervisor-pages-pks.html>

## Secondary sources

- NIST SP 800-160 — Systems Security Engineering — general threat-modelling vocabulary.
- Microsoft STRIDE — lightweight threat-modelling framework.
- "Spectre returns! Speculation attacks using the return stack buffer" — for the speculative-side-channel open question.

## Distilled summaries

- [`../../capabilities/research/summaries/sel4-capabilities.md`](../../capabilities/research/summaries/sel4-capabilities.md)
  — shared with `capabilities/`.
- [`../../memory/research/summaries/intel-pks.md`](../../memory/research/summaries/intel-pks.md)
  — shared with `memory/`.
- [`../../memory/research/summaries/arm-mte.md`](../../memory/research/summaries/arm-mte.md)
  — shared with `memory/`.

## Fetched this round

### 2026-04-22
- No new summaries (all primary sources already shared with other subsystems or blocked by fetch)

## Open research questions

- Capability revocation cost — how does seL4's CDT approach scale, and do
  we need it or a simpler badge scheme?
- PKS on first-generation SPR silicon — are there errata we must work around?
