---
id: quickstart
title: Quickstart
sidebar_position: 2
---

# Quickstart

This guide walks through a complete end-to-end emission of a governance certificate from a sample run directory.

## 1. Prepare a sample run directory

`tenant-emit` reconstructs the certificate by scanning a finished factory run directory. Let's create a minimal one.

```bash
mkdir -p .factory/runs/run-it-001/s0-preflight
mkdir -p .factory/runs/run-it-001/tenant-codegen
mkdir -p .factory/runs/run-it-001/tenant-bundle

echo "preflight ok" > .factory/runs/run-it-001/s0-preflight/preflight.txt
echo "fn main(){}" > .factory/runs/run-it-001/tenant-codegen/app.rs
echo "<bytes>" > .factory/runs/run-it-001/tenant-bundle/bundle.tar
```

## 2. Set the operator signing key

Emission requires an operator-supplied Ed25519 signing key. Set it in your environment:

```bash
# A sample base64-encoded 32-byte Ed25519 seed for testing
export OAP_SIGNING_KEY="AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
```

:::warning
The Ed25519 signing key is a sensitive tenant secret. It must be held outside the repository and outside any agent's write scope. Never commit it to source control.
:::

## 3. Emit the certificate

Run `build-certificate` against the directory. We will use `--tenant-mode` (which requires a signer), provide an identity, and enforce the operator key requirement.

```bash
npx --no-install tenant-emit build-certificate .factory/runs/run-it-001 \
  --tenant-mode \
  --signer-subject "bart@tenant.example" \
  --signer-identity-provider "rauthy@tenant-org" \
  --stage-ids auto \
  --require-operator-key
```

You should see output indicating success:

```text
governance certificate written: .factory/runs/run-it-001/governance-certificate.json (status=Success, stages=3, hash=...)
```

## 4. Inspect the result

The output is a signed `governance-certificate.json` file in the run directory. The shape will look like this (abbreviated):

```json
{
  "certificateVersion": "1.5.0",
  "pipelineRunId": "run-it-001",
  "timestamp": "2026-06-24T00:00:00Z",
  "status": "Success",
  "intent": {
    "requirementsHash": ""
  },
  "buildSpec": {
    "hash": ""
  },
  "stages": [
    {
      "stageId": "s0-preflight",
      "artifactHashes": {
        "preflight.txt": "..."
      }
    },
    {
      "stageId": "tenant-bundle",
      "artifactHashes": {
        "bundle.tar": "..."
      }
    },
    {
      "stageId": "tenant-codegen",
      "artifactHashes": {
        "app.rs": "..."
      }
    }
  ],
  "verification": {
    "compile": "Skipped",
    "test": "Skipped",
    "lint": "Skipped",
    "typecheck": "Skipped",
    "securityScan": "Skipped"
  },
  "proofChain": {
    "recordCount": 0,
    "chainIntegrity": "Empty"
  },
  "signer": {
    "subject": "bart@tenant.example",
    "identityProvider": "rauthy@tenant-org"
  },
  "certificateHash": "...",
  "signingPublicKey": "...",
  "certSignature": "...",
  "signingAttestation": {
    "kind": "operator"
  }
}
```

Notice that the `stageId` array was discovered lexicographically (`s0-preflight`, `tenant-bundle`, `tenant-codegen`) because we passed `--stage-ids auto`.

## 5. Verify the certificate

The emitted certificate is designed to be verified offline using [`tenant-tail`](https://github.com/statecrafting/tenant-tail).

```bash
npx --no-install tenant-tail verify-certificate .factory/runs/run-it-001/governance-certificate.json
```

Because `tenant-emit` and `tenant-tail` share the same exact certificate structure, the certificate will round-trip perfectly and verify cleanly.
