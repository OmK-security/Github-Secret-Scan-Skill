#!/usr/bin/env bash
# Rebuilds the fake repo, runs three scanners, scores them. Needs: git, openssl, python3,
# and: pip install detect-secrets trufflehog3
set -u
cd "$(dirname "$0")/.."
OUT=testrun; export OUT
rm -rf "$OUT"; mkdir -p "$OUT"
python3 -I test/build_test_repo.py "$OUT/repo"
python3 -I scripts/secret_scan_fallback.py "$OUT/repo" --json "$OUT/fallback.json" >/dev/null 2>&1
( cd "$OUT/repo" && detect-secrets scan --all-files > ../ds.json )
( cd "$OUT/repo" && trufflehog3 --no-entropy -f json -o ../th3_rules.json . >/dev/null 2>&1
  trufflehog3 -f json -o ../th3_entropy.json . >/dev/null 2>&1 )
python3 -I test/score.py
