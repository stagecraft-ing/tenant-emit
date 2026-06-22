# Governed artifact reads

tenant-emit is emit-only: it produces a certificate but does not produce its own
corpus artifacts. Its `specs/` corpus is governed by the **pinned spec-spine
library** (the dogfood pattern), and spec-spine's compiled artifacts under
`.derived/` are consumed **only** through `spec-spine` subcommands
(`npx --no-install spec-spine registry`, `... index`), never via ad-hoc
`jq`/grep over the JSON. The corpus binding the emitter writes into a certificate
(spec 220 FR-007) is likewise read, never recomputed: the CorpusAttestation is
hashed through the public reader seam `spec_spine_core::attest::attestation_hash`,
never re-derived. Typed reads make schema drift fail at the deserializer with a
clean error instead of silently encoding stale assumptions.
