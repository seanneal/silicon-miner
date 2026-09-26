#!/bin/bash
# measure.sh — idle powermetrics baseline + miner power sample
# Needs sudo for powermetrics. If sudo fails, run binary alone and report.
set -euo pipefail
cd "$(dirname "$0")"

BATCH="${1:-2000000}"
BIN="./miner_test"
SAMPLE_SEC=3

if [[ ! -x "$BIN" ]]; then
  echo "Building miner_test..."
  make
fi

have_pm=0
if command -v powermetrics >/dev/null 2>&1; then
  # Non-interactive sudo check — do not hang
  if sudo -n true 2>/dev/null; then
    have_pm=1
  else
    echo "NOTE: sudo/powermetrics needs a password (sudo -n failed)."
    echo "NOTE: Running binary without energy sampling. Re-run with passwordless sudo or interactive sudo."
  fi
else
  echo "NOTE: powermetrics not found; energy metrics skipped."
fi

extract_pkg_w() {
  # Best-effort parse of "Combined Power" / "CPU Power" / "Package Power" milliwatts or watts
  awk '
    BEGIN { mw = -1 }
    /Combined Power/ || /CPU Power/ || /Package Power/ || /CPU Die Power/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^[0-9]+(\.[0-9]+)?$/) {
          v=$i
          # If unit token nearby says mW, convert
          u=$(i+1)
          if (u ~ /mW/) v = v/1000.0
          if (v > mw) mw = v
        }
      }
    }
    END {
      if (mw < 0) print "na"
      else printf "%.3f\n", mw
    }
  '
}

idle_w="na"
run_w="na"

if [[ "$have_pm" -eq 1 ]]; then
  echo "=== Idle baseline (${SAMPLE_SEC}s) ==="
  idle_log=$(mktemp)
  sudo -n powermetrics --samplers cpu_power -i 1000 -n "$SAMPLE_SEC" 2>/dev/null | tee "$idle_log" || true
  idle_w=$(extract_pkg_w < "$idle_log")
  echo "IDLE_BASELINE_W=${idle_w}"

  echo "=== Miner run + power sample ==="
  run_log=$(mktemp)
  # Sample while miner runs: start powermetrics in background, run miner, stop
  sudo -n powermetrics --samplers cpu_power -i 500 -n 20 > "$run_log" 2>/dev/null &
  pm_pid=$!
  # Give powermetrics a moment
  sleep 0.3
  out=$("$BIN" "$BATCH" | tee /dev/stderr) || true
  wait "$pm_pid" 2>/dev/null || true
  run_w=$(extract_pkg_w < "$run_log")
  rm -f "$idle_log" "$run_log"

  hs=$(echo "$out" | awk -F= '/^H\/s=/{print $2; exit}')
  if [[ -z "${hs:-}" || "$hs" == "" ]]; then hs=0; fi

  echo "PKG_POWER_W=${run_w}"
  if [[ "$idle_w" != "na" && "$run_w" != "na" ]]; then
    # Absolute package power during run; delta vs idle as context
    python3 - "$run_w" "$idle_w" "$hs" <<'PY'
import sys
run_w=float(sys.argv[1]); idle_w=float(sys.argv[2]); hs=float(sys.argv[3])
delta=max(0.0, run_w-idle_w)
print(f"ABS_PKG_W={run_w:.3f}")
print(f"IDLE_W={idle_w:.3f}")
print(f"DELTA_W={delta:.3f}")
if hs>0:
    print(f"W_PER_HASH={run_w/hs:.6e}")
    print(f"J_PER_HASH={run_w/hs:.6e}")  # J/hash = W / (hash/s)
    print(f"DELTA_W_PER_HASH={delta/hs:.6e}")
else:
    print("W_PER_HASH=na")
    print("J_PER_HASH=na")
PY
  else
    echo "ABS_PKG_W=${run_w}"
    echo "W_PER_HASH=na"
    echo "J_PER_HASH=na"
  fi
else
  echo "=== Miner run (no energy) ==="
  "$BIN" "$BATCH"
  echo "ENERGY: unavailable (sudo/powermetrics blocked or missing)"
fi
