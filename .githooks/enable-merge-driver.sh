#!/usr/bin/env bash
# One-command, idempotent enablement of the `tenant-emit-derived-regen` git merge
# driver in THIS clone. Run once per clone: the driver registration lives in
# per-clone `.git/config`, which is not committed, so each clone (you may keep
# several) must enable it locally. Worktrees created off a clone inherit the
# clone's config, so one run covers every worktree under it.
#
#   ./.githooks/enable-merge-driver.sh
#
# Disable:
#   git config --unset merge.tenant-emit-derived-regen.driver
#   git config --unset merge.tenant-emit-derived-regen.name
#
# The path to driver assignment (`.derived/**/*.json` ->
# `merge=tenant-emit-derived-regen`, covering spec-spine 0.5.0's per-spec /
# per-package shards) lives in committed `.gitattributes`, and the driver itself is
# `.githooks/merge-derived-index.sh`; both travel with the repo. This script only
# wires the non-committed registration that connects them. Safe to re-run;
# `git config` overwrites idempotently.
#
# Mirror of spec-spine's `.githooks/enable-merge-driver.sh`, rebranded for
# tenant-emit (the governing binary is still the pinned spec-spine library).

set -eu

root="$(git rev-parse --show-toplevel)"
cd "$root"

git config merge.tenant-emit-derived-regen.name "regenerate tenant-emit derived artifacts on conflict"
git config merge.tenant-emit-derived-regen.driver ".githooks/merge-derived-index.sh %O %A %B %P"

echo "[enable-merge-driver] tenant-emit-derived-regen registered in $root/.git/config"
echo "  name:      $(git config --get merge.tenant-emit-derived-regen.name)"
echo "  driver:    $(git config --get merge.tenant-emit-derived-regen.driver)"
echo "  registry:  $(git check-attr merge .derived/spec-registry/by-spec/example.json)"
echo "  index:     $(git check-attr merge .derived/codebase-index/by-package/example.json)"
echo "[enable-merge-driver] derived-artifact conflicts will now auto-regenerate on merge/rebase."
