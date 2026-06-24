---
id: typescript-js
title: TypeScript / JS Projects
sidebar_position: 1
---

# Integration: TypeScript / JS

For Node.js, TypeScript, or general JavaScript projects, `tenant-emit` is distributed as an npm package containing prebuilt binaries.

## Installation

Install the package as an exact-version `devDependency`. It is highly recommended to pin it alongside `spec-spine` and `tenant-tail`.

```bash
npm install --save-dev --save-exact tenant-emit
```

This installs a thin JavaScript launcher and automatically resolves the correct optional platform package (e.g., `@tenant-emit/cli-darwin-arm64`) containing the native binary for your host.

## Usage in Scripts

You can invoke the CLI directly in your `package.json` scripts or via `npx` in your CI pipeline.

```json
{
  "scripts": {
    "emit-cert": "tenant-emit build-certificate .factory/runs/latest --tenant-mode --signer-subject $CI_ACTOR --signer-identity-provider github --stage-ids auto --require-operator-key"
  }
}
```

Or in a CI workflow step:

```yaml
- name: Emit Governance Certificate
  run: npx --no-install tenant-emit build-certificate .factory/runs/latest \
         --tenant-mode \
         --signer-subject ${{ github.actor }} \
         --signer-identity-provider "github-actions" \
         --stage-ids auto \
         --require-operator-key
  env:
    OAP_SIGNING_KEY: ${{ secrets.OAP_SIGNING_KEY }}
```

Using `--no-install` with `npx` ensures that CI uses the exact pinned version from your `node_modules` rather than accidentally downloading a newer version at runtime.
