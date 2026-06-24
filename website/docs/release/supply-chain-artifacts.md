---
id: supply-chain-artifacts
title: Supply Chain Artifacts
sidebar_position: 4
---

# Supply Chain Artifacts

To ensure the integrity and provenance of the distributed binaries, the release workflow generates several supply chain artifacts for every build target.

## Sidecars and SBOMs

For each of the five release triples, the workflow produces:

1. **The Archive**: A `.tar.gz` or `.zip` containing the binary.
2. **Checksum**: A `.sha256` sidecar file containing the SHA-256 hash of the archive.
3. **SBOM**: A CycloneDX Software Bill of Materials detailing the exact Rust dependencies compiled into the binary.

These artifacts are attached to the GitHub Release.

## SLSA Provenance

The release workflow uses GitHub Actions' native attestation features to generate SLSA (Supply-chain Levels for Software Artifacts) build provenance.

This cryptographic attestation proves that the binaries attached to the release were compiled by the official `.github/workflows/release.yml` workflow running on GitHub's infrastructure, and traces them back to the exact git commit SHA.

The npm and PyPI publish legs also utilize ecosystem-specific provenance features (e.g., PyPI Trusted Publishing) to attest the final packages published to those registries.
