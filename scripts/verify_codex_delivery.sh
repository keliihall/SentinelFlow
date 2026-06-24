#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

branch="$(git branch --show-current)"
head_sha="$(git rev-parse HEAD)"
origin_sha="$(git rev-parse origin/main)"

printf 'current branch: %s\n' "$branch"
printf 'HEAD: %s\n' "$head_sha"
printf 'origin/main: %s\n' "$origin_sha"
printf 'git status --short:\n'
git status --short

git fetch origin main

head_sha="$(git rev-parse HEAD)"
origin_sha="$(git rev-parse origin/main)"

printf 'post-fetch HEAD: %s\n' "$head_sha"
printf 'post-fetch origin/main: %s\n' "$origin_sha"

if [[ "$head_sha" != "$origin_sha" ]]; then
  printf 'HEAD does not match origin/main; refusing delivery.\n' >&2
  exit 1
fi

node scripts/check_p5_6_boundary.js

git show origin/main:scripts/p5_6_gates.sh | grep "P56-G10" || exit 1
git show origin/main:.github/workflows/ci.yml | grep "scripts/p5_6_gates.sh" || exit 1
