#!/usr/bin/env bash
#
# Point this clone at the hooks tracked in .githooks.
#
# `git config --local core.hooksPath .githooks` only affects the current clone;
# run this once after cloning. Undo with `git config --local --unset core.hooksPath`.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

chmod +x .githooks/pre-push tools/linux_check.sh
git config --local core.hooksPath .githooks

echo "installed: core.hooksPath=.githooks"
echo "the pre-push hook runs tools/linux_check.sh for Python/test/dependency changes"
echo "bypass one push with: SKIP_LINUX_CHECK=1 git push"
