---
id: overview
title: Release Overview
sidebar_position: 1
---

# Release Overview

The release and distribution of `tenant-emit` is fully automated via GitHub Actions (`.github/workflows/release.yml`). The process is triggered by pushing a tag matching `v*`.

## The Build Matrix

The release workflow compiles the Rust binary for five supported targets:

1. `x86_64-unknown-linux-gnu` (Linux x86_64, glibc)
2. `aarch64-unknown-linux-gnu` (Linux arm64, glibc)
3. `x86_64-apple-darwin` (macOS x86_64)
4. `aarch64-apple-darwin` (macOS arm64)
5. `x86_64-pc-windows-msvc` (Windows x86_64)

These builds produce release archives (`.tar.gz` for Unix, `.zip` for Windows) containing the `tenant-emit` binary.

## Three Publish Legs

From these identical release archives, the workflow executes three idempotent publish legs:

1. **crates.io**: Publishes the three Rust crates (`tenant-emit-types`, `tenant-emit-core`, `tenant-emit-cli`).
2. **npm**: Assembles platform-specific optional packages from the archives and publishes them alongside the main `tenant-emit` wrapper package.
3. **PyPI**: Assembles five platform wheels and one source distribution (sdist) from the archives and publishes them.

This design ensures that all three ecosystems distribute the exact same compiled binaries. There is no second Rust build during the npm or PyPI publish steps.

## Idempotency

The publish jobs are designed to be idempotent. They skip any version that is already live on the respective registry. This makes it safe to re-run a release tag if a specific leg fails due to a network issue.
