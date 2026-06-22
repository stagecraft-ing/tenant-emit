# tenant-emit (npm)

Prebuilt-binary npm distribution of the `tenant-emit` emit-only CLI. No Rust
toolchain required: `npm i -D tenant-emit` installs the matching
`@tenant-emit/cli-<os>-<cpu>` optional dependency and a thin launcher
(`bin/tenant-emit.js`) exec's it.

```sh
npm i -D tenant-emit
npx --no-install tenant-emit build-certificate <run-dir> --tenant-mode --signer-subject <s> --signer-identity-provider <p> [--corpus-attestation <att>] --require-operator-key
```

Pin it as an exact-version devDependency next to `spec-spine`; `npm ci` verifies
the sha512 lockfile integrity of the package and its `@tenant-emit/cli-*`
subpackages. One pin covers the verb.

This wrapper mirrors spec-spine's `npm/` shape exactly (launcher + platform
resolver + publish-time platform-package generator). The platform packages and
the binaries they carry are assembled from the release archives at publish time
and are never committed.

See the repo root `README.md` and OAP spec 220-tenant-emit-governance-certificate
for the toolkit's scope and status.
