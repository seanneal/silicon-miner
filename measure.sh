#!/bin/bash
# measure.sh — idle powermetrics baseline + multi-thread miner power sample
# Needs sudo for powermetrics. If sudo fails, run the soak alone and report.
#
# The work window is an offline --soak (not a 2M-nonce blip) so package power
# is sampled while hashes are in flight. Pass the same thread count the soak uses.
#
#   ./measure.sh
#   ./measure.sh --threads 4
#   ./measure.sh --threads 4 --seconds 20
#   THREADS=4 SECONDS=15 ./measure.sh
#
set -euo pipefail
cd "$(dirname "$0")"

THREADS="${THREADS:-}"
SOAK_SEC="${SECONDS:-10}"
BIN="./miner_test"
INTERVAL_MS=500

while [[ $# -gt 0 ]]; do
  case "$1" in
    --threads)
      THREADS="${2:-}"
      shift 2
      ;;
    --seconds)
      SOAK_SEC="${2:-10}"
      shift 2
      ;;
    *)
      echo "Usage: $0 [--threads N] [--seconds SEC]" >&2
      exit 2
      ;;
  esac
done

if [[ ! "$SOAK_SEC" =~ ^[0-9]+$ ]] || [[ "$SOAK_SEC" -lt 1 ]]; then
  echo "SECONDS must be a positive integer" >&2
  exit 2
fi

if [[ ! -x "$BIN" ]]; then
  echo "Building miner_test..."
  make
fi

# Cover the soak plus a short startup margin.
N_SAMPLES=$(( SOAK_SEC * 1000 / INTERVAL_MS + 4 ))

have_pm=0
if command -v powermetrics >/dev/null 2>&1; then
  if sudo -n true 2>/dev/null; then
    have_pm=1
  else
    echo "NOTE: sudo/powermetrics needs a password (sudo -n failed)."
    echo "NOTE: Running soak without energy sampling. Re-run with passwordless sudo or interactive sudo."
  fi
else
  echo "NOTE: powermetrics not found; energy metrics skipped."
fi

extract_pkg_w() {
  awk '
    BEGIN { mw = -1 }
    /Combined Power/ || /CPU Power/ || /Package Power/ || /CPU Die Power/ {
      for (i=1;i<=NF;i++) {
        if ($i ~ /^[0-9]+(\.[0-9]+)?$/) {
          v=$i
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

miner_cmd=("$BIN" --soak "$SOAK_SEC" --report 2)
if [[ -n "$THREADS" ]]; then
  miner_cmd+=(--threads "$THREADS")
fi
echo "MEASURE_CMD=${miner_cmd[*]}"
echo "MEASURE_THREADS=${THREADS:-default}"
echo "MEASURE_SOAK_SEC=${SOAK_SEC}"

idle_w="na"
run_w="na"

if [[ "$have_pm" -eq 1 ]]; then
  echo "=== Idle baseline (3s) ==="
  idle_log=$(mktemp)
  sudo -n powermetrics --samplers cpu_power -i 1000 -n 3 2>/dev/null | tee "$idle_log" || true
  idle_w=$(extract_pkg_w < "$idle_log")
  echo "IDLE_BASELINE_W=${idle_w}"

  echo "=== Miner soak + power sample ==="
  run_log=$(mktemp)
  sudo -n powermetrics --samplers cpu_power -i "$INTERVAL_MS" -n "$N_SAMPLES" > "$run_log" 2>/dev/null &
  pm_pid=$!
  sleep 0.3
  out=$("${miner_cmd[@]}" | tee /dev/stderr) || true
  wait "$pm_pid" 2>/dev/null || true
  run_w=$(extract_pkg_w < "$run_log")
  rm -f "$idle_log" "$run_log"

  hs=$(echo "$out" | awk -F= '/^SOAK_AVG_H\/s=/{v=$2} /^H\/s=/{if (v=="") v=$2} END{print v}')
  thr=$(echo "$out" | awk -F= '/^THREADS=/{print $2; exit}')
  if [[ -z "${hs:-}" ]]; then hs=0; fi

  echo "PKG_POWER_W=${run_w}"
  echo "MEASURE_THREADS_EFFECTIVE=${thr:-${THREADS:-default}}"
  if [[ "$idle_w" != "na" && "$run_w" != "na" ]]; then
    python3 - "$run_w" "$idle_w" "$hs" <<'PY'
import sys
run_w=float(sys.argv[1]); idle_w=float(sys.argv[2]); hs=float(sys.argv[3])
delta=max(0.0, run_w-idle_w)
print(f"ABS_PKG_W={run_w:.3f}")
print(f"IDLE_W={idle_w:.3f}")
print(f"DELTA_W={delta:.3f}")
if hs>0:
    print(f"W_PER_HASH={run_w/hs:.6e}")
    print(f"J_PER_HASH={run_w/hs:.6e}")  # J/hash = W / (hash/s) over the soak window
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
  echo "=== Miner soak (no energy) ==="
  "${miner_cmd[@]}"
  echo "ENERGY: unavailable (sudo/powermetrics blocked or missing)"
fi
