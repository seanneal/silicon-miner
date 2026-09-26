# silicon-miner results (Apple Silicon)

Educational SHA-256d miner for Mac M1 / Apple Silicon. Hash path is pure ARM64 crypto-extension assembly (`SHA256H` / `SHA256H2` / `SHA256SU0` / `SHA256SU1`). Goal is correctness and maximizing silicon use, not profit.

All numbers below are from **2026-09-26** unless noted. Machine for real H/s and energy: **MacBookPro18,3** (M1 Pro). qemu-aarch64 runs are correctness-only and are **not** Apple Silicon throughput.

## How to read these numbers

| Kind | What it measures | Notes |
|------|------------------|-------|
| Offline timed batch | Midstate hash loop (`miner_test` / `--metrics`) | Highest raw H/s; no Stratum |
| Offline soak (`--soak`) | Sustained offline hashing | Thermal/steady-state without pool |
| Absolute energy (`measure.sh`) | Package watts during work window | Needs `sudo` for `powermetrics` |
| Live Stratum soak (`--testnet`) | notify → hash → submit on a real pool | Lower H/s than offline (jobs, shares, submit) |

**Energy definition (v1):** report absolute package W, W/hash, and J/hash from `powermetrics` (or equivalent) during the work window. Idle baseline is context only. Shared-SoC caveat is a footnote, not a reason to omit absolute numbers.

Footnote: Apple Silicon package power is Combined Power for a shared SoC (CPU + GPU + other). Numbers are still absolute package metrics for the work window.

---

## 1. Correctness

| Check | Result |
|-------|--------|
| Genesis self-test | **PASS** |
| Genesis digest | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` |
| Genesis nonce | `0x7c2bac1d` |
| qemu-aarch64 self-test (crypto-ext asm, not C hash) | **PASS** (genesis nonce `7c2bac1d`) |

---

## 2. Single-thread offline H/s (evolution)

Approximate single-core midstate loop on MacBookPro18,3:

| Stage | Approx H/s | Notes |
|-------|------------|-------|
| Initial midstate + crypto-ext skeleton | ~20.7 MH/s | Early harness baseline |
| Dual-lane (staged K out of resident regs) | ~24–25 MH/s class | Before multi-thread C harness |
| Multi-thread branch, **1 thread** timed batch | ~22.6 MH/s | Post threads + dual-lane schedule (`cursor/multithread-schedule-30c7`) |

Single-thread figures vary with run length, thermal state, and pin settings. Use the multi-thread table for peak raw throughput.

---

## 3. Multi-thread offline timed batches (Mac)

Branch at measure: `cursor/multithread-schedule-30c7` (later squash-merged to `main` as PR #1 / `86fe9cf`). Self-test: **PASS**.

| Threads | Approx H/s | Notes |
|---------|------------|-------|
| 1 | ~22.6 MH/s | Timed batch |
| 4 | ~94 MH/s | Timed batch |
| 6 (default / short 2M nonces) | ~72 MH/s | Short run; not a long soak |
| 8 | ~141 MH/s | Timed batch; highest offline H/s recorded so far |

These are **offline midstate** figures (no Stratum). Do not compare directly to the live soak without noting the path difference.

---

## 4. Absolute package energy (Mac)

Command path: `./measure.sh` → soak under `powermetrics`.

| Field | Value |
|-------|-------|
| Date | 2026-09-26 |
| Machine | MacBookPro18,3 |
| Mode | Work-window absolute package (single-thread class run) |
| `ABS_PKG_W` | **16.259 W** |
| `IDLE_W` (context) | 1.051 W |
| Hash rate during sample | **23,410,158 H/s** (~23.4 MH/s) |
| `W_PER_HASH` | **6.945×10⁻⁷ W/hash** |
| `J_PER_HASH` | **6.945×10⁻⁷ J/hash** (= W / (hash/s)) |

Multi-thread energy via `./measure.sh --threads N` was enabled in E3 but a multi-thread peak energy capture is **not yet recorded** in this file.

---

## 5. Live Stratum testnet soak (realistic)

| Field | Value |
|-------|-------|
| Date | 2026-09-26 |
| Endpoint | `tn3.btclab.dev:3333` (Stratum V1) |
| Duration | **120 s** (`--seconds 120`, `--max-shares 0`) |
| Threads | **6** |
| Pin | on (E1 QoS + affinity tags) |
| Sustained H/s | **~39.0 MH/s** |
| Hashes | ≈ **4.68×10⁹** |
| Jobs seen | **4** |
| Pool vardiff | **0.001 → 0.08** |
| Shares accepted | **585** |
| Shares rejected | **3** |
| Shares submitted | **588** |
| `jobs_staged_while_hashing` | **1** (E4 overlap) |
| Async submit (E5) | in play (workers keep hashing through submit RTT) |
| Result | **PASS** |

Rejects were consistent with stale work on job change, not bad digests.

**Interpretation:** ~39 MH/s is the best **live Stratum soak** so far. Offline batches at 4T/8T are higher because they do not pay job/share/submit overhead.

---

## 6. Engineering vs formal experiments (status)

Landed on `main` (PR #1 squash merge `86fe9cf`, 2026-09-26):

| ID | Item | Kind | Status |
|----|------|------|--------|
| — | Multi-thread C nonce ranges | eng | Done / on main |
| — | Dual-lane asm schedule | eng | Done / on main |
| E1 | P-core pin (`--pin` / `--no-pin`) | eng | Done / exercised on Mac |
| E2 | Offline `--soak` | eng | Done |
| E3 | Multi-thread `measure.sh` | eng | Done (MT peak watts TBD) |
| E4 | Job midstate staging while hashing | eng | Done / soak saw `staged_overlap=1` |
| E5 | Async share submit | eng | Done / soak exercised path |
| E6 | `exp/sha-pipe-schedule` | **formal experiment fork** | Not started |
| E7 | `exp/dual-job` | **formal experiment fork** | Not started |

Protocol: E6 and E7 each get their own branch, measure, and decision. Do not stack them.

---

## 7. Out of scope / deferred

- **Mainnet / AntPool:** deferred until Emshon provides worker+password and explicit yes in SiliconMiner chat.
- **Spending BTC / paid pools:** never without that yes.
- **qemu H/s:** correctness only; never quote as M1 throughput.

---

## 8. Reproduce (Mac)

```sh
git pull
make
./miner_test                  # self-test + timed batch
./miner_test --threads 4 5000000
./miner_test --soak 60 --threads 4 --report 2
sudo ./measure.sh --threads 4 --seconds 20
./miner_test --testnet --seconds 120 --max-shares 0 --threads 6 --suggest-diff 0.001
```

Keep the machine awake for long runs (`caffeinate -dims` or equivalent).

---

*Append new rows when benches or soaks land; prefer exact harness/`measure.sh` fields over rounded chat summaries.*

---

## 9. TIME_SPLIT (wall accounting)

The timed batch, `--soak`, and the testnet summary now print `TIME_SPLIT`, `TIME_SPLIT_PCT`, `TIME_SPLIT_CPU`, `TIME_SPLIT_FLIGHT`, `TIME_SPLIT_OVERLAP`, and `TIME_SPLIT_CLOCK`. How to read them is in the README section "Reading TIME_SPLIT".

Unmeasured on MacBookPro18,3 until an offline soak and a testnet soak are re-run on that machine. This note does not add H/s figures. The 2026-09-26 offline and live numbers above stand until that re-run.
