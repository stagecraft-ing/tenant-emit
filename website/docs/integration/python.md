---
id: python
title: Python Projects
sidebar_position: 2
---

# Integration: Python

For Python projects, `tenant-emit` is distributed via PyPI as a binary wheel. It is not a Python binding; there is no native extension, and the Rust engine is never called from Python code.

## Installation and Usage

You can use `uv` or `pip` to run or install the tool.

### Using `uvx` (No explicit install)

The cleanest way to run `tenant-emit` in a Python CI pipeline is via `uvx`, which fetches and executes the tool without modifying your project environment.

```bash
uvx tenant-emit build-certificate .factory/runs/latest \
  --tenant-mode \
  --signer-subject "ci-bot" \
  --signer-identity-provider "gitlab" \
  --stage-ids auto \
  --require-operator-key
```

### Persistent Installation

You can install it globally as a tool:

```bash
uv tool install tenant-emit
```

Or install it into your project's virtual environment:

```bash
pip install tenant-emit
```

## How the Wheel Works

The project publishes five platform wheels, one per supported target (macOS arm64/x86_64, Linux x86_64/aarch64 glibc, Windows x86_64). Each wheel carries the prebuilt binary in its scripts directory.

When you run `pip install`, pip selects the wheel matching your host platform tag and installs the binary onto your `PATH`. On a supported host, there is no Python in the run path and no network request beyond fetching the wheel itself.

### Unsupported Hosts

If you are on an unsupported host (like Alpine Linux / musl), pip will fall back to the source distribution (sdist). The sdist does not build the Rust engine. Instead, it installs a tiny Python script that prints an unsupported-platform message and exits with status `1`, advising you to use `cargo install tenant-emit-cli`.
