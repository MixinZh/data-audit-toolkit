# Neutral signal map

Use this toolkit for consistency categories such as duplicate or conflicting
table structure, reported-value mismatches, label mapping mismatches, bounded
numeric patterns, embedded instruction-like content, and repeated image tiles.
These are deterministic observations or leads for review, not conclusions about
why a pattern exists.

Keep four layers distinct: **data show** for computed comparisons, **source
says** for literal supplied statements, **reviewer inference** for a bounded
lead, and **not checked** for unsupported or unavailable comparison. Before
escalating, check source context and plausible benign explanations such as
rounding, aggregation, duplicate export columns, disclosed reuse, low
resolution, incomplete source material, or a parsing/resource limit.

Classification is part of the signal contract:

- `consistency_lead` is reserved for a comparison whose stated prerequisites
  were met. Reported numeric values use their displayed decimal or scientific
  precision rather than near-exact float equality.
- `informational` currently includes terminal-digit concentration,
  percentage-quantization constraints, reverse-calculation chains, embedded
  instruction-like content, and exact repeated image tiles. These signals are
  visible for context but are not counted as default consistency leads.
- `not_checked` records an unsupported, blocked, unavailable, or unresolved
  comparison.

The packaged synthetic benchmark is a regression suite. It does not establish
real-world precision, recall, false-positive rate, or independent validation for
any signal.

The [UK Government Data Quality Framework](https://www.gov.uk/government/publications/the-government-data-quality-framework/the-government-data-quality-framework)
supports documenting data-quality responsibilities and assurance. The
[W3C PROV-O recommendation](https://www.w3.org/TR/prov-o/) supports recording
provenance and relationships among entities, activities, and agents. The
[U.S. GAO Assessing Data Reliability guide](https://www.gao.gov/products/GAO-20-283G)
supports assessing whether data are sufficiently reliable for their intended
use. These transferable principles inform documentation and review discipline;
none of these sources endorses this project.
