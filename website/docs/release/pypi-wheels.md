---
id: pypi-wheels
title: PyPI Wheel Selection
sidebar_position: 3
---

# PyPI Wheel Selection

The Python distribution of `tenant-emit` relies on PyPI wheels to deliver prebuilt binaries.

## The Wheel Strategy

The project publishes five platform-specific wheels. Each wheel contains the prebuilt `tenant-emit` binary placed in the wheel's `scripts` directory.

The wheels are tagged with specific platform identifiers:

- `macosx_11_0_arm64`
- `macosx_10_12_x86_64`
- `manylinux_2_17_x86_64`
- `manylinux_2_17_aarch64`
- `win_amd64`

When you run `pip install tenant-emit`, pip checks your system's platform tags and downloads the matching wheel. The binary is then extracted directly onto your `PATH`.

## The sdist Fallback

If pip cannot find a wheel that matches your system (for example, if you are running Alpine Linux which uses musl libc instead of glibc), it falls back to downloading the Source Distribution (sdist).

In many Python projects, the sdist will attempt to compile a native extension from source. **`tenant-emit` does not do this.**

Instead, the sdist installs a tiny Python script as the `tenant-emit` console script. When executed, this script detects the host platform, prints an "unsupported platform" message to `stderr`, and exits with status `1`. It advises the user to use `cargo install tenant-emit-cli` to build the tool from source.
