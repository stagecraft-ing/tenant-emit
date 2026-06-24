---
id: custom-stages
title: Custom Stage IDs
sidebar_position: 4
---

# Custom Stage IDs

`tenant-emit` reconstructs the governance certificate by scanning stage directories within the run directory and hashing their artifacts.

## Auto-Discovery

The most common approach in a tenant context is to let the emitter discover the stages automatically.

```bash
tenant-emit build-certificate <run-dir> --stage-ids auto
```

When `--stage-ids auto` is used, the emitter scans the run directory and processes every subdirectory in **lexicographic order**.

For example, given this directory structure:
```text
.factory/runs/run-123/
├── build/
├── lint/
└── test/
```

The stages will be recorded in the certificate in the order: `build`, `lint`, `test`.

## Explicit Stage Ordering

If your pipeline requires a specific logical order that differs from lexicographic sorting, or if you want to explicitly restrict which directories are considered stages, you can provide a comma-separated list to the `--stage-ids` flag.

```bash
tenant-emit build-certificate <run-dir> --stage-ids "lint,test,build"
```

The emitter will process exactly those directories, in that exact order. If a specified directory does not exist, the emitter will record it as an empty stage.

## OAP Default Stages

If the `--stage-ids` flag is omitted entirely, the emitter defaults to the upstream OAP stage list (`s0` through `s5`). This is usually incorrect for a tenant pipeline, which is why `--stage-ids auto` is highly recommended for tenant emission.
