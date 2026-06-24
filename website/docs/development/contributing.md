---
id: contributing
title: Contributing
sidebar_position: 4
---

# Contributing

When contributing to `tenant-emit`, please adhere to the following guidelines and invariants.

## Load-Bearing Invariants

Any pull request must preserve these invariants:

1. **Emit-only**: Never add a `verify-*` verb or a dependency on the verifier.
2. **Round-trip**: Changes to the certificate content must preserve the offline round-trip with `tenant-tail`.
3. **Version Pin**: The certificate version must remain pinned to `1.5.0`. Do not bump it to match the upstream OAP version.
4. **Read-never-recompute**: Do not alter `clippy.toml` or `deny.toml` to bypass the ban on `spec-spine` attestation emission functions.

## House Style

The project has a strict house style for published prose, comments, and code:

**No em dashes (U+2014) are permitted anywhere in the repository.**

Use a colon, a comma, parentheses, or two separate sentences instead. A pre-commit hook blocks file writes that introduce U+2014.

## Reading Derived Artifacts

When working with the compiled specification artifacts in the `.derived/` directory, always read them through `spec-spine` subcommands. Do not use ad-hoc scripts (`jq`, `python`, `sed`) to parse the JSON files directly.
