#!/usr/bin/env bash
set -euo pipefail

mkdir -p docs/archive

archive_if_exists() {
  local file="$1"
  if [ -f "$file" ]; then
    git mv "$file" "docs/archive/$(basename "$file")"
  fi
}

archive_if_exists docs/YC-RFS-EVOLUTION.md
archive_if_exists docs/INTERNATIONAL-DEBATE.md
archive_if_exists docs/DEBATE-RESULTS.md
archive_if_exists docs/GTM-DEBATE-RESULTS.md
archive_if_exists docs/RESEARCH-PHASE-10.5-11-SUPPLEMENT.md
archive_if_exists docs/PHASE-10-GLOBAL-SCHEMA-DECOUPLING.md
archive_if_exists docs/COMPETITIVE-GAP-ANALYSIS.md

echo "Archived old planning docs into docs/archive/. Review before committing."
