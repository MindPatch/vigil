#!/usr/bin/env bash
# Real-world precision check: download real npm package tarballs (NO install,
# NO execution — just tarball extract + static scan) and report how many of
# these *known-good* popular packages Vigil wrongly flags (BLOCK/INVESTIGATE).
#
# Usage:  bench/real_corpus.sh [package ...]
# Falls back to a built-in top-popular list if no args are given.
#
# This is the number that sells: false positives on the top packages.

set -u
VIGIL="${VIGIL:-./target/release/vigil}"
REGISTRY="https://registry.npmjs.org"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PKGS=("$@")
if [ ${#PKGS[@]} -eq 0 ]; then
  PKGS=(express lodash react chalk debug axios commander react-dom \
        webpack vue rxjs moment classnames uuid yargs chokidar \
        node-fetch dotenv jsonwebtoken bcrypt)
fi

flagged=0
clean=0
errors=0
declare -a FLAGGED_NAMES=()

echo "Real-corpus precision check — ${#PKGS[@]} popular packages"
echo "=========================================================="

for pkg in "${PKGS[@]}"; do
  enc="${pkg//\//%2f}"
  meta="$(curl -fsSL "$REGISTRY/$enc" 2>/dev/null)" || { echo "  ?? $pkg (registry fetch failed)"; errors=$((errors+1)); continue; }
  ver="$(printf '%s' "$meta" | grep -o '"latest":"[^"]*"' | head -1 | sed 's/.*:"//;s/"//')"
  tarball="$(printf '%s' "$meta" | grep -o "\"tarball\":\"[^\"]*${ver//./\\.}\.tgz\"" | head -1 | sed 's/.*:"//;s/"//')"
  [ -z "$tarball" ] && tarball="$(printf '%s' "$meta" | grep -o '"tarball":"[^"]*"' | tail -1 | sed 's/.*:"//;s/"//')"
  [ -z "$tarball" ] && { echo "  ?? $pkg (no tarball)"; errors=$((errors+1)); continue; }

  dir="$WORK/$enc"; mkdir -p "$dir"
  curl -fsSL "$tarball" -o "$dir/p.tgz" 2>/dev/null || { echo "  ?? $pkg (download failed)"; errors=$((errors+1)); continue; }
  tar -xzf "$dir/p.tgz" -C "$dir" 2>/dev/null

  out="$("$VIGIL" "$dir" --format json --quiet 2>/dev/null)"
  read -r verdict score < <(printf '%s' "$out" | python3 -c 'import sys,json
try:
    d=json.load(sys.stdin); print(d.get("verdict","PASS"), d.get("score",0))
except Exception:
    print("PARSE_ERR", -1)')
  : "${verdict:=PASS}"; : "${score:=0}"
  if [ "$verdict" = "PARSE_ERR" ]; then echo "  ?? $pkg (json parse failed)"; errors=$((errors+1)); continue; fi

  if [ "$verdict" = "BLOCK" ] || [ "$verdict" = "INVESTIGATE" ]; then
    echo "  FP $pkg@$ver -> $verdict (score $score)"
    flagged=$((flagged+1)); FLAGGED_NAMES+=("$pkg@$ver:$verdict")
  else
    echo "  OK $pkg@$ver -> $verdict (score $score)"
    clean=$((clean+1))
  fi
done

total=$((flagged+clean))
echo "=========================================================="
if [ "$total" -gt 0 ]; then
  spec=$(awk "BEGIN{printf \"%.1f\", $clean/$total*100}")
  echo "Clean: $clean/$total (${spec}% specificity)   False positives: $flagged   Errors: $errors"
else
  echo "No packages scanned (network errors: $errors)"
fi
[ "$flagged" -eq 0 ]
