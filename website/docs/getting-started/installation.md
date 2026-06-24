---
id: installation
title: Installation
sidebar_position: 1
---

# Installation

`tenant-emit` is distributed as a prebuilt binary across multiple ecosystems. No Rust toolchain is required to install or run it.

Choose the package manager that matches your project's ecosystem.

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs>
  <TabItem value="npm" label="npm (TypeScript/JS)" default>
    Install `tenant-emit` as an exact-version devDependency, ideally pinned next to `spec-spine` and `tenant-tail`.
    
    ```bash
    npm i -D tenant-emit
    ```
    
    This installs a thin launcher and an optional platform package (`@tenant-emit/cli-<os>-<cpu>`) containing the prebuilt binary. You can run it via `npx`:
    
    ```bash
    npx --no-install tenant-emit build-certificate <run-dir> ...
    ```
  </TabItem>
  
  <TabItem value="pypi" label="PyPI (Python)">
    You can run `tenant-emit` via `uvx` without explicitly installing it, or install it as a persistent tool.
    
    ```bash
    # Run directly with no install
    uvx tenant-emit build-certificate <run-dir> ...
    
    # Or install as a persistent tool
    uv tool install tenant-emit
    
    # Or install into a project/venv
    pip install tenant-emit
    ```
    
    This is a binary distribution, not a Python binding. pip/uv selects the wheel matching your host platform tag and installs the binary onto your `PATH`.
  </TabItem>
  
  <TabItem value="cargo" label="crates.io (Rust)">
    If you are on an unsupported platform (like Alpine Linux / musl) or prefer to build from source, use Cargo.
    
    ```bash
    cargo install tenant-emit-cli
    ```
    
    This compiles the `tenant-emit` binary from source and places it in your Cargo bin directory.
  </TabItem>
</Tabs>

## Supported Platforms

The prebuilt binaries distributed via npm and PyPI support the following targets:

| Host | npm optional dependency | PyPI wheel platform tag | Release triple |
|---|---|---|---|
| macOS arm64 | `@tenant-emit/cli-darwin-arm64` | `macosx_11_0_arm64` | `aarch64-apple-darwin` |
| macOS x86_64 | `@tenant-emit/cli-darwin-x64` | `macosx_10_12_x86_64` | `x86_64-apple-darwin` |
| Linux x86_64 (glibc) | `@tenant-emit/cli-linux-x64` | `manylinux_2_17_x86_64` | `x86_64-unknown-linux-gnu` |
| Linux arm64 (glibc) | `@tenant-emit/cli-linux-arm64` | `manylinux_2_17_aarch64` | `aarch64-unknown-linux-gnu` |
| Windows x86_64 | `@tenant-emit/cli-win32-x64` | `win_amd64` | `x86_64-pc-windows-msvc` |

Linux binaries require **glibc**. Alpine/musl hosts have no wheel or npm optional dependency and must use `cargo install tenant-emit-cli` or a glibc-based image.
