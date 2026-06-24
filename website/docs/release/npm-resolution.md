---
id: npm-resolution
title: npm Platform Resolution
sidebar_position: 2
---

# npm Platform Resolution

The npm distribution of `tenant-emit` uses optional dependencies to deliver the correct native binary for your operating system and architecture.

## The Wrapper Package

When you run `npm install tenant-emit`, you are installing a thin JavaScript wrapper package. This package contains no Rust code and no binaries.

Instead, its `package.json` declares five `optionalDependencies`:

- `@tenant-emit/cli-darwin-arm64`
- `@tenant-emit/cli-darwin-x64`
- `@tenant-emit/cli-linux-x64`
- `@tenant-emit/cli-linux-arm64`
- `@tenant-emit/cli-win32-x64`

## Install-Time Resolution

During installation, npm evaluates your host's OS and CPU architecture. It downloads the specific optional package that matches your system and skips the rest.

If you are on an unsupported platform (e.g., FreeBSD, or a musl-based Linux like Alpine), npm will not download any of the optional packages.

## Run-Time Resolution

When you execute `npx tenant-emit`, the JavaScript launcher (`bin/tenant-emit.js`) runs.

The launcher checks the current OS and CPU, determines which optional package should have been installed, and attempts to execute the binary bundled inside it.

If the optional package is missing (either because the platform is unsupported, or because `npm install --no-optional` was used), the launcher prints a clear error message explaining why the binary cannot be found and advising the user to use `cargo install` if they are on an unsupported host.
