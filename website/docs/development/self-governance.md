---
id: self-governance
title: Self-Governance
sidebar_position: 3
---

# Self-Governance

`tenant-emit` is a governed project. Its own source code and architecture are governed by a specification corpus located in the `specs/` directory.

## The Dogfooding Pattern

The project uses the `spec-spine` compiler to govern itself, a pattern known as dogfooding.

The `spec-spine` compiler is pinned as a devDependency in the repository.

## Compiling the Corpus

During CI, and before committing changes to the specifications, the corpus must be compiled and linted.

```bash
# Ensure Node.js dependencies are installed
npm ci

# Compile the specs
npx --no-install spec-spine compile

# Check the index
npx --no-install spec-spine index check

# Lint the corpus
npx --no-install spec-spine lint --fail-on-warn
```

This process generates the derived artifacts in the `.derived/` directory. These artifacts are committed to the repository to provide a deterministic, cross-platform proof of the specification state.

## Determinism

The CI pipeline includes a determinism workflow that runs `spec-spine compile` on multiple operating systems (Linux x86_64, Linux aarch64, macOS arm64, Windows x86_64) and asserts that the resulting derived JSON trees are byte-for-byte identical across all platforms.
