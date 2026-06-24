---
id: run-directory
title: Run Directory Layout
sidebar_position: 5
---

# Run Directory Layout

`tenant-emit` is a post-hoc tool. It does not orchestrate a pipeline; instead, it scans a finished run directory to reconstruct the certificate.

## The `.factory/runs/<run-id>` Tree

The standard layout for a run directory is `.factory/runs/<run-id>/`. Inside this directory, each stage of the pipeline produces its own subdirectory containing its artifacts.

```text
.factory/runs/run-it-001/
├── s0-preflight/
│   └── preflight.txt
├── tenant-codegen/
│   └── app.rs
├── tenant-bundle/
│   └── bundle.tar
└── s5-ui-specification/
    └── build-spec.yaml
```

## Stage Discovery

When `tenant-emit` runs, it needs to know which stage directories to scan.

By default, if you do not specify stage IDs, the emitter will look for the standard upstream OAP stages (`s0` through `s5`).

In a tenant context, you will typically use the `--stage-ids auto` flag. This instructs the emitter to perform filesystem discovery, scanning every subdirectory of the run directory in lexicographic order.

```bash
tenant-emit build-certificate .factory/runs/run-it-001 --stage-ids auto
```

For the tree above, this would discover `s0-preflight`, `s5-ui-specification`, `tenant-bundle`, and `tenant-codegen`.

Alternatively, you can provide a comma-separated list of exact stage IDs to enforce a specific order:

```bash
tenant-emit build-certificate .factory/runs/run-it-001 --stage-ids "s0-preflight,tenant-codegen,tenant-bundle"
```

## The Build Spec

If a frozen build specification exists at `s5-ui-specification/build-spec.yaml`, the emitter will automatically lift its hash and record it in the `buildSpec.hash` field of the certificate.
