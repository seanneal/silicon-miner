# silicon-miner results (Apple Silicon)

Educational SHA-256d miner for Mac M1 / Apple Silicon. Hash path is pure ARM64 crypto-extension assembly (`SHA256H` / `SHA256H2` / `SHA256SU0` / `SHA256SU1`). Goal is correctness and maximizing silicon use, not profit.

All numbers below are from **2026-09-26** unless noted. Machine for real H/s and energy: **MacBookPro18,3** (M1 Pro). qemu-aarch64 runs are correctness-only and are **not** Apple Silicon throughput.

## How to read these numbers

| Kind | What it measures | Notes |
|------|------------------|-------|
| Offline timed batch | Midstate hash loop (`_sha256d_mine_midstate`, `miner_test` / `--metrics`) | Highest raw H/s; no Stratum |
| Offline soak (`--soak`) | Sustained `_sha256d_mine_midstate` | Thermal/steady-state without pool |
| Absolute energy (`measure.sh`) | Package watts during work window | v1 metric: W, W/hash, J/hash. Needs `sudo` for `powermetrics` |
| Live Stratum soak (`--testnet`) | Header build, then per-nonce `sha256_compress` / `sha256d_asm_one`, then submit | Lower H/s than offline (jobs, shares, submit). The share hasher is the compress entry |

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

**Interpretation:** ~39 MH/s is this early live Stratum soak. Offline batches at 4T/8T are higher because they do not pay job/share/submit overhead.

Later same-day live soaks (different vardiff and share counts) are in sections 9 and 10. The post–wake-pipe soak is in section 10.

---

## 6. Engineering vs formal experiments (status)

Landed on `main` (PR #1 squash merge `86fe9cf`, 2026-09-26). TIME_SPLIT accounting landed (PR #3, `6d37fb6`, 2026-09-26). Wake-on-complete landed (PR #6, `36b83c5`, 2026-09-26); the post-fix Mac soak is in section 10. Step 1 (share check + finish-the-slice) landed (PR #8, `a4ad0ba`, 2026-09-27); the Mac soak is in section 11. Step 2 (default threads = all physical cores) landed (PR #10, `6312feb`, 2026-09-27); the Mac 8T soaks are in section 12. E6 (SHA-pipe schedule A/B) was measured in PR #12 and closed without merge; schedule A stays on `main`. E7 (dual-job) was squash-merged as PR #13 / `8c5287f` (2026-09-27); Mac numbers are in section 13. `--dual-job` still defaults off.

| ID | Item | Kind | Status |
|----|------|------|--------|
| — | Multi-thread C nonce ranges | eng | Done / on main |
| — | Dual-lane asm schedule | eng | Done / on main |
| — | TIME_SPLIT wall accounting | eng | Done / on main (PR #3); Mac live soak in section 9 |
| — | TIME_SPLIT_GAPS (split `other`) | eng | Mac soaks in section 10 (PR #5 pre-fix; PR #6 post-fix) |
| — | In-flight wake-on-complete | eng | Done / on main (PR #6); Mac soak in section 10 |
| — | Step 1 share check + finish slice | eng | Done / on main (PR #8); Mac soak in section 11 |
| — | Default threads = `hw.physicalcpu` (P+E) | eng | Done / on main (PR #10); Mac 8T soaks in section 12 |
| E1 | P-core pin (`--pin` / `--no-pin`) | eng | Done / exercised on Mac. Slots past perflevel0 use UTILITY QoS (section 12) |
| E2 | Offline `--soak` | eng | Done |
| E3 | Multi-thread `measure.sh` | eng | Done (MT peak watts TBD) |
| E4 | Job midstate staging while hashing | eng | Done / soak saw `staged_overlap=1` |
| E5 | Async share submit | eng | Done / soak exercised path |
| E6 | SHA-pipe schedule A/B (`exp/sha-pipe-schedule`) | formal experiment, closed | Measured 2026-09-27 CT (PR #12, HEAD `550c0c1`). Offline 1T was flat (schedule A **25.061 MH/s** vs B **24.957 MH/s**, **−0.42%**). Abandoned. Closed without merge. Prefer schedule A, which is what `main` ships. |
| E7 | Dual-job hot midstates | feature on `main`, default off | Measured 2026-09-27 CT (MacBookPro18,3, experiment HEAD `7e8f4e7`). Emshon approved the merge. Squash-merged to `main` as PR #13 / `8c5287f`. `--dual-job off` is the default; `--dual-job on` is the treatment. Numbers in section 13. |

E6 and E7 were measured on separate branches and were not stacked. E6 schedule B was abandoned. E7 is on `main` with the flag defaulting off.

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
./miner_test                  # self-test + timed batch (default threads = hw.physicalcpu)
./miner_test --threads 4 5000000
./miner_test --soak 60 --threads 4 --report 2
sudo ./measure.sh --threads 4 --seconds 20
./miner_test --testnet --seconds 120 --max-shares 0 --threads 6 --suggest-diff 0.001
```

Keep the machine awake for long runs (`caffeinate -dims` or equivalent).

Omitting `--threads` uses `hw.physicalcpu` (8 on this 6P+2E Mac). `--threads 6` is the old P-core-only count.

---

*Append new rows when benches or soaks land; prefer exact harness/`measure.sh` fields over rounded chat summaries.*

---

## 9. TIME_SPLIT (wall accounting)

The timed batch, `--soak`, and the testnet summary print `TIME_SPLIT`, `TIME_SPLIT_PCT`, `TIME_SPLIT_CPU`, `TIME_SPLIT_FLIGHT`, `TIME_SPLIT_OVERLAP`, and `TIME_SPLIT_CLOCK`. How to read them is in the README section "Reading TIME_SPLIT".

### Live Stratum TIME_SPLIT soak (MacBookPro18,3)

Measured 2026-09-26 on branch `cursor/time-split-accounting-73ac` (merged to `main` as PR #3). This run is separate from the section 5 soak (different vardiff and share counts).

| Field | Value |
|-------|-------|
| Endpoint | `tn3.btclab.dev:3333` |
| Duration | **120 s** |
| Flags | `--threads 6`, `--max-shares 0`, `--suggest-diff 0.001` |
| H/s | **38499823** (~38.5 MH/s) |
| Hashes | **4620075128** |
| Jobs seen | **4** |
| `jobs_staged_while_hashing` | **1** |
| Difficulty | ended **0.04** (vardiff **0.001 → 0.04**) |
| Shares | **528** submitted / **528** accepted / **0** rejected |
| Result | **PASS** |

Harness lines:

```
TIME_SPLIT hash_s=73.5287 share_s=7.2885 poll_s=0.0000 midstate_s=0.0030 submit_s=0.0002 other_s=39.1821
TIME_SPLIT_PCT hash=61.27 share=6.07 poll=0.00 midstate=0.00 submit=0.00 other=32.65
TIME_SPLIT_CPU hash_s=349.0774 share_s=34.6022 submit_s=0.0010
TIME_SPLIT_FLIGHT flight_s=80.8174
TIME_SPLIT_OVERLAP poll_busy_s=0.1119 poll_wait_s=119.5809 midstate_s=0.0000 submit_s=0.0510
TIME_SPLIT_CLOCK=mach_absolute_time*mach_timebase_info
```

Same-build offline timed batch (comparison only): ~84.3 MH/s @ 6T (`H/s=84285052` on 2M nonces).

**Interpretation:** poll/midstate/submit idle-path ≈0%; share-check ~6% wall; ~33% wall still in other (batch gaps / unlabeled).

`TIME_SPLIT_GAPS` now names that remainder (setup, teardown, share restart, cancel restart, end drain, status, unexplained). Mac numbers for those fields are not in this section — see section 10.

---

## 10. TIME_SPLIT_GAPS (other split)

Implemented on top of section 9. The harness prints `TIME_SPLIT_GAPS`, `TIME_SPLIT_GAPS_PCT`, `TIME_SPLIT_GAPS_DETAIL`, and `BATCHES` with the existing `TIME_SPLIT` lines (timed batch, `--soak`, and the testnet summary). How to read them is in the README section "Reading TIME_SPLIT".

The new fields partition `other_s`. They do not rename `TIME_SPLIT` / `TIME_SPLIT_PCT` / `TIME_SPLIT_CPU` / `TIME_SPLIT_FLIGHT` / `TIME_SPLIT_OVERLAP`.

### Live Stratum soak (MacBookPro18,3) — PR #5

Measured 2026-09-26 on the TIME_SPLIT_GAPS build (PR #5, merged to `main`). 120 s on tn3, 6 threads. This is the pre-wake-fix soak. Do not reuse section 9's `other_s=39.1821` as these gap fields.

| Field | Value |
|-------|-------|
| Endpoint | tn3 @ 6T |
| Duration | **120 s** |
| H/s | **~65 MH/s** |
| `TIME_SPLIT_PCT` | hash=**65.11** share=**8.81** other=**26.08** |
| `TIME_SPLIT_GAPS` | teardown=**25.94%** of wall; other named gaps ≈ 0 |
| `TIME_SPLIT_GAPS_DETAIL` | wake_s=**31.03** join_s=**0.09** |
| `BATCHES` | started=**3799** early_share=**777** full=**3021** avg_flight_s=**0.0233** hashes_per_flight≈**2.05e6** |

**Interpretation:** teardown is almost all `wake_s`. After a ~23 ms flight the main thread was still inside the ~20 ms in-flight `select`, so it noticed the batch ~8 ms late. That tail times thousands of batches is ~26% of wall. Job / midstate / submit were not the gap.

This ~65 MH/s row is the pre-fix soak. In the wake-pipe (PR #6), the last finishing worker writes a self-pipe that the same in-flight `select` watches, so main wakes when the batch ends instead of waiting out the poll timeout. Stratum overlap (E4/E5) stays: socket readability still wakes that `select`, and midstate staging plus async submit are unchanged. The Mac re-measure is the next subsection.

### Live Stratum soak (MacBookPro18,3) — post–PR #6 wake-pipe

Measured 2026-09-26 CT on MacBookPro18,3. Branch soaked: `cursor/batch-wake-pipe-8661` (squash-merged to `main` as PR #6 / `36b83c5`). Same command as the PR #5 soak above.

```sh
caffeinate -dims ./miner_test --testnet --seconds 120 --max-shares 0 --threads 6 --suggest-diff 0.001
```

| Field | Value |
|-------|-------|
| Endpoint | `tn3.btclab.dev:3333` |
| Duration | **120.02 s** (`elapsed_s=120.02`) |
| Threads | **6** |
| H/s | **57765393** (~57.8 MH/s) |
| Hashes | **6932998022** |
| Jobs seen | **5** |
| `jobs_staged_while_hashing` | **4** |
| Difficulty | ended **0.16** (vardiff) |
| Shares | **780** submitted / **778** accepted / **2** rejected |
| `TIME_SPLIT_PCT` | hash=**82.71** share=**17.01** other=**0.28** |
| `TIME_SPLIT_GAPS_PCT` | batch_setup=**0.13** teardown=**0.14**; other named gaps ≈ 0 |
| `TIME_SPLIT_GAPS_DETAIL` | wake_s=**0.1107** join_s=**0.0577** |
| `BATCHES` | started=**3372** early_share=**651** early_clean=**3** full=**2718** avg_flight_s=**0.0355** hashes_per_flight=**2056049** |
| Result | **PASS** |

Harness lines:

```
TIME_SPLIT hash_s=99.2738 share_s=20.4109 poll_s=0.0000 midstate_s=0.0033 submit_s=0.0003 other_s=0.3316
TIME_SPLIT_PCT hash=82.71 share=17.01 poll=0.00 midstate=0.00 submit=0.00 other=0.28
TIME_SPLIT_CPU hash_s=457.8899 share_s=94.1431 submit_s=0.0014
TIME_SPLIT_FLIGHT flight_s=119.6850
TIME_SPLIT_OVERLAP poll_busy_s=0.1903 poll_wait_s=119.4737 midstate_s=0.0000 submit_s=0.0748
TIME_SPLIT_GAPS batch_setup_s=0.1503 teardown_s=0.1695 share_restart_s=0.0010 cancel_restart_s=0.0000 end_drain_s=0.0000 status_s=0.0000 unexplained_s=0.0109
TIME_SPLIT_GAPS_PCT batch_setup=0.13 teardown=0.14 share_restart=0.00 cancel_restart=0.00 end_drain=0.00 status=0.00 unexplained=0.01
TIME_SPLIT_GAPS_DETAIL wake_s=0.1107 join_s=0.0577
BATCHES started=3372 early_share=651 early_clean=3 full=2718 avg_flight_s=0.0355 hashes_per_flight=2056049
```

**Interpretation:** The wake tax is gone. Against the PR #5 pre-fix soak above (~65 MH/s, other **26.08%**, wake_s=**31.03**): wake_s **31.03 s → 0.11 s** and other **26% → 0.28%**. Teardown is **0.14%** of wall (wake_s=0.1107, join_s=0.0577). Absolute H/s on this run was **~57.8 MH/s**, with share-check at **~17%** of wall (vardiff ended at **0.16**, 780 submits), versus **~65 MH/s** on the pre-fix soak (share **8.81%** of wall).

Offline comparison commands (not a substitute for the live gap split):

```sh
./miner_test --threads 6 2000000
./miner_test --soak 120 --threads 6 --report 2
```

---

## 11. Step 1 — share-path wall and early-share batches

Ordinary engineering (not E6 / E7). Merged to `main` as PR #8 (`a4ad0ba`, 2026-09-27). Asm hash path (`sha256d_mine.s`) was not changed. Mac numbers below are from MacBookPro18,3 (6P+2E), 2026-09-27 CT. qemu H/s is not used here.

What #8 changed:

- The per-nonce share check compares `bswap32(digest[7])` to the top target word and reads the rest of the target only on a tie. It is the same Bitcoin integer compare as the old 32-byte walk (selftest oracle).
- A live share is queued and that worker finishes its nonce range. Siblings are not cancelled. The batch does not roll extranonce2 just because a share hit; the nonce cursor continues on the same header until wrap, a new job, or `clean_jobs`.
- `TIME_SPLIT` / `TIME_SPLIT_GAPS` / `BATCHES` still print. `share_restart_s` stays the short-batch fallback, not the common share path.
- `--suggest-diff 0.001` is unchanged so a one-share proof still returns quickly. For a quieter H/s soak, pass `--suggest-diff 1`. That is only `mining.suggest_difficulty`; the check still uses the pool's `set_difficulty`. The soaks below used `0.001`, the same command as section 10.

Both live runs:

```sh
caffeinate -dims ./miner_test --testnet --seconds 120 --max-shares 0 --threads 6 --suggest-diff 0.001
```

Offline rows are a 2M-nonce timed batch (`./miner_test --threads N 2000000`), not the live soak.

### Same-day baseline (main, before #8)

Measured 2026-09-27 CT on `main` before PR #8. This is the same-day comparison point. Section 10 (2026-09-26, ~57.8 MH/s, `early_share=651`) is the previous day.

| Field | Value |
|-------|-------|
| Machine | MacBookPro18,3 (6P+2E) |
| Offline 2M, 6T | **72698193** (~72.7 MH/s) |
| Offline 2M, 8T | **88094085** (~88.1 MH/s) |
| Live command | `--testnet --seconds 120 --max-shares 0 --threads 6 --suggest-diff 0.001` |
| Live H/s | **56696392** (~56.7 MH/s) |
| Hashes | **6803691663** |
| Threads | **6** |
| Difficulty | ended **0.08** (vardiff) |
| Shares | **777** accepted / **779** submitted |
| `TIME_SPLIT_PCT` | hash=**82.06** share=**17.67** other=**0.27** |
| `TIME_SPLIT_GAPS_DETAIL` | wake_s=**0.0941** join_s=**0.0664** |
| `BATCHES` | started=**3309** early_share=**633** early_clean=**2** full=**2674** avg_flight_s=**0.0362** hashes_per_flight=**2056117** |

Reported lines:

```
TIME_SPLIT_PCT hash=82.06 share=17.67 other=0.27
TIME_SPLIT_GAPS_DETAIL wake_s=0.0941 join_s=0.0664
BATCHES started=3309 early_share=633 early_clean=2 full=2674 avg_flight_s=0.0362 hashes_per_flight=2056117
```

### Step 1 soak (PR #8)

Measured 2026-09-27 CT on `cursor/share-path-step1-dbd2`, squash-merged to `main` as PR #8 / `a4ad0ba`. Same live command as the baseline above.

| Field | Value |
|-------|-------|
| Machine | MacBookPro18,3 (6P+2E) |
| Offline 2M, 6T | **62739193** (~62.7 MH/s) |
| Offline 2M, 8T | **90991811** (~91.0 MH/s) |
| Live command | `--testnet --seconds 120 --max-shares 0 --threads 6 --suggest-diff 0.001` |
| Live H/s | **57614710** (~57.6 MH/s) |
| Hashes | **6913834498** |
| Threads | **6** |
| Difficulty | ended **0.16** (vardiff) |
| Shares | **788** accepted / **788** submitted |
| `TIME_SPLIT_PCT` | hash=**85.84** share=**13.77** other=**0.39** |
| `TIME_SPLIT_GAPS_DETAIL` | wake_s=**0.2129** join_s=**0.0730** |
| `BATCHES` | started=**3297** early_share=**0** early_clean=**2** full=**3295** avg_flight_s=**0.0363** hashes_per_flight=**2097008** |
| Result | **PASS** (merged) |

Reported lines:

```
TIME_SPLIT_PCT hash=85.84 share=13.77 other=0.39
TIME_SPLIT_GAPS_DETAIL wake_s=0.2129 join_s=0.0730
BATCHES started=3297 early_share=0 early_clean=2 full=3295 avg_flight_s=0.0363 hashes_per_flight=2097008
```

**Ops win vs the same-day baseline:** live H/s **+1.6%** (56.7 → 57.6 MH/s; 56696392 → 57614710) and `early_share` **633 → 0**. `hashes_per_flight` moved from **2056117** to **2097008**, next to the full `2<<20` assignment (2097152). Share-check wall moved **17.67% → 13.77%** and hash **82.06% → 85.84%**. The Step 1 run ended at a higher vardiff (**0.16** vs **0.08**) and still accepted every submit (788/788).

The offline 6T timed batch (**72.7 → 62.7 MH/s**) is short-bench noise against that baseline, not the live result. Offline 8T was **88.1 → 91.0 MH/s** on the same kind of short batch. Wake stayed a fraction of a second (wake_s **0.0941 → 0.2129**). This soak predates the E6 measurement and the E7 merge (sections 6 and 13).

---

## 12. Step 2 — default workers on all physical cores

Ordinary engineering (not E6 / E7). Merged to `main` as PR #10 (`6312feb`, 2026-09-27). Asm hash path (`sha256d_mine.s`) was not changed. Mac numbers below are from MacBookPro18,3 (6P+2E), 2026-09-27 CT. qemu H/s is not used here.

What this change does:

- Default worker count is `hw.physicalcpu` (all physical cores), then `hw.ncpu`, then `sysconf(_SC_NPROCESSORS_ONLN)`. On this machine that is **8**. `hw.perflevel0.physicalcpu` (**6**, P-cores only) is no longer the default. `--threads N` still overrides.
- Pin stays on. Worker slots below the P-core count still request `QOS_CLASS_USER_INTERACTIVE`. Slots at or past that count request `QOS_CLASS_UTILITY` so the scheduler can place them on efficiency cores instead of eight threads all asking for six P-cores. Including E-cores is the H/s win and can worsen W/hash.

The first 8T row below was measured with explicit `--threads 8` on `main` after #8, before the QoS split. On that build every worker still requested `QOS_CLASS_USER_INTERACTIVE`. It is the evidence that eight workers beat the Step 1 six-thread soak. The post-merge confirm, later in this section, is the default (no `--threads`) on the QoS-split build: six performance-core workers and two utility workers.

Sysctl on the soak machine:

| Key | Value |
|-----|-------|
| `hw.perflevel0.physicalcpu` | **6** (P-cores) |
| `hw.perflevel1.physicalcpu` | **2** (E-cores) |
| `hw.ncpu` | **8** |

Same soak shape as section 11. Step 1 passed `--threads 6`. Step 2 passed `--threads 8` because the default was still the P-core count:

```sh
caffeinate -dims ./miner_test --testnet --seconds 120 --max-shares 0 --suggest-diff 0.001
```

### Step 1 baseline (6T, after #8)

Same soak as section 11. Repeated here as the comparison point.

| Field | Value |
|-------|-------|
| Live H/s | **57614710** (~57.6 MH/s) |
| Threads | **6** |
| Shares | **788** accepted / **788** submitted |
| `TIME_SPLIT_PCT` | hash=**85.84** share=**13.77** other=**0.39** |
| `BATCHES` | started=**3297** early_share=**0** hashes_per_flight=**2097008** |

### Step 2 live soak (8T explicit, all performance-core QoS, main after #8)

First 8T measure. Kept as the pre-merge comparison. Every worker requested `QOS_CLASS_USER_INTERACTIVE`.

| Field | Value |
|-------|-------|
| Machine | MacBookPro18,3 (6P+2E) |
| Live command | `--testnet --seconds 120 --max-shares 0 --threads 8 --suggest-diff 0.001` |
| Live H/s | **71724915** (~71.7 MH/s) |
| Hashes | **8607004160** |
| Threads | **8** |
| Difficulty | ended **0.16** (vardiff) |
| Shares | **1013** accepted / **1018** submitted |
| `TIME_SPLIT_PCT` | hash=**86.94** share=**12.68** other=**0.38** |
| `TIME_SPLIT_GAPS_DETAIL` | wake_s=**0.1599** join_s=**0.1192** |
| `BATCHES` | started=**4105** early_share=**0** early_clean=**2** full=**4103** avg_flight_s=**0.0291** hashes_per_flight=**2096712** |

Reported lines:

```
TIME_SPLIT_PCT hash=86.94 share=12.68 other=0.38
TIME_SPLIT_GAPS_DETAIL wake_s=0.1599 join_s=0.1192
BATCHES started=4105 early_share=0 early_clean=2 full=4103 avg_flight_s=0.0291 hashes_per_flight=2096712
```

**Ops win vs the Step 1 6T soak:** live H/s **+24.5%** (57.6 → 71.7 MH/s; 57614710 → 71724915). Hash wall stayed in the mid-80s (85.84% → 86.94%). Share wall went 13.77% → 12.68%. `early_share` stayed **0**. `hashes_per_flight` stayed next to the full `2<<20` assignment (2096712 vs 2097152). Wake stayed a fraction of a second (wake_s **0.1599**, join_s **0.1192**). Vardiff still ended at **0.16**.

### Step 2 confirm (default 8T, QoS split, branch of #10)

Measured 2026-09-27 CT on `cursor/default-all-physical-cpus-206e` (the QoS-split build merged as PR #10). No `--threads` override. Startup reported `THREADS=8 (default hw.physicalcpu)` and pin of **6** `QOS_CLASS_USER_INTERACTIVE` plus **2** `QOS_CLASS_UTILITY`.

```sh
caffeinate -dims ./miner_test --testnet --seconds 120 --max-shares 0 --suggest-diff 0.001
```

| Field | Value |
|-------|-------|
| Machine | MacBookPro18,3 (6P+2E) |
| Branch | `cursor/default-all-physical-cpus-206e` |
| Live command | `--testnet --seconds 120 --max-shares 0 --suggest-diff 0.001` (no `--threads`) |
| Threads | **8** (`default hw.physicalcpu`) |
| Pin | **6** P-core interactive + **2** E-core utility |
| Live H/s | **80160173** (~80.2 MH/s) |
| Hashes | **9621017344** |
| Difficulty | **0.16** |
| Shares | **1098** accepted / **1099** submitted |
| `TIME_SPLIT_PCT` | hash=**90.03** share=**9.55** other=**0.42** |
| `TIME_SPLIT_GAPS_DETAIL` | wake_s=**0.1708** join_s=**0.1243** |
| `BATCHES` | started=**4588** early_share=**0** early_clean=**1** full=**4587** avg_flight_s=**0.0260** hashes_per_flight=**2096996** |

Reported lines:

```
THREADS=8 (default hw.physicalcpu)
TIME_SPLIT_PCT hash=90.03 share=9.55 other=0.42
TIME_SPLIT_GAPS_DETAIL wake_s=0.1708 join_s=0.1243
BATCHES started=4588 early_share=0 early_clean=1 full=4587 avg_flight_s=0.0260 hashes_per_flight=2096996
```

**Ops win vs the first 8T soak above (~71.7 MH/s, all workers on performance-core QoS):** live H/s **+11.8%** (71.7 → 80.2 MH/s; 71724915 → 80160173). Hash wall moved **86.94% → 90.03%** and share wall **12.68% → 9.55%**. `early_share` stayed **0**. `hashes_per_flight` stayed next to the full assignment (2096996 vs 2097152). Wake stayed a fraction of a second (wake_s **0.1708**, join_s **0.1243**). Difficulty stayed **0.16**. This is the default-thread confirm of the QoS split, not a replacement of the 71.7 row.

### Offline 2M-nonce (noisy)

Explicit `--threads 8` before the QoS split: **H/s=77561467** (~77.6 MH/s).

Default 8T on the QoS-split build (no `--threads`, `./miner_test 2000000`): **H/s=70836580** (~70.8 MH/s).

Short offline batches move around. Section 11 already recorded 8T timed batches at **88094085** (~88.1 MH/s) and **90991811** (~91.0 MH/s) the same day. **77.6** and **70.8 MH/s** are more short samples, not live regressions. The 120 s Stratum soaks are the comparison. E6 was not in this soak. Dual-job (E7) landed later and was not on this build; its numbers are in section 13.

---

## 13. E7 dual-job (on main, default off)

Squash-merged to `main` as PR #13 (`8c5287f`, 2026-09-27) after Emshon approved. Default remains `--dual-job off`. `--dual-job on` is the treatment. E6 (SHA-pipe schedule B) is a separate experiment: measured flat in PR #12 and closed without merge, so `main` keeps schedule A. No mainnet, AntPool, or BTC spend. No energy numbers are filled in here.

### Hypothesis

E4 builds the next header's midstate into a side buffer while a batch hashes, but every worker is still on **one** job. When that job's nonce window ends, or a notify retires it, the cores wait out join, the switch, and the next `pthread_create`.

E7 keeps **two midstate slots hot**. A worker whose slot cannot feed it claims the other slot and keeps calling the existing asm. Offline that asm is `_sha256d_mine_midstate`. On testnet the share scan is still `sha256d_asm_one` (`sha256_compress`) plus the same C target check. `--dual-job off` (the default) is the single-job path. `--dual-job on` is the treatment, in the same binary.

`underfeed` counts a slot whose armed window had fewer nonces than workers. `switches` counts a worker moving from one slot to the other. `install_while_live` counts a new header installed while the other slot was still hot. `idle_s` is average time workers waited with neither slot claimable. `jobs_staged_while_hashing` is still the count of distinct new job ids installed while the other slot was hot.

### Expected effect size

These are bounds for the coordinator, not measurements.

The current default-thread baseline is section 12: 120 s on tn3, no `--threads` (`hw.physicalcpu`, 8 on MacBookPro18,3), `other` **0.42%** of wall, share **9.55%**, `early_share` **0**. Step 1 already finishes the slice after a share, so dual-job does not change that policy or the MSW target check. A handful of job changes in 120 s is still well under 1% of wall.

| Run | Expected H/s vs control | Why |
|-----|-------------------------|-----|
| Live tn3, 120 s, default threads | **about 0% to +1%** | Only the job-boundary wait is recoverable. A **0% to −2%** move is plausible if slot handoff shows up on the per-nonce scan. |
| Offline timed batch (one span) | **about −2% to +1%** | Control is one asm call per thread. Treatment is the same span split across two slots. |
| Offline `--soak` | **about 0% to +10%** | Control create/joins every 1M-nonce chunk. Treatment keeps the threads and refills the drained slot while the other slot is still hashing. |

### How to measure (Mac)

Leave the machine awake (`caffeinate -dims` or equivalent). Omit `--threads` so the harness uses its default (`hw.physicalcpu`, P+E). qemu H/s is not this table. The live command matches section 12, including `--suggest-diff 0.001`.

```sh
# control
./miner_test --dual-job off
./miner_test --dual-job off --soak 120 --report 2
caffeinate -dims ./miner_test --dual-job off --testnet --seconds 120 --max-shares 0 --suggest-diff 0.001

# treatment
./miner_test --dual-job on
./miner_test --dual-job on --soak 120 --report 2
caffeinate -dims ./miner_test --dual-job on --testnet --seconds 120 --max-shares 0 --suggest-diff 0.001
```

Read `H/s`, `TIME_SPLIT` / `TIME_SPLIT_GAPS` / `BATCHES`, and on treatment the `DUAL_JOB` line (`switches`, `underfeed`, `install_while_live`, `idle_s`). Compare the live row to section 12 (~80.2 MH/s, other 0.42%, 8 threads). A `--suggest-diff 1` soak is optional; it is not the cell below.

Correctness (not throughput): qemu-aarch64 self-test **PASS** for `--dual-job off` and `--dual-job on`, genesis nonce `7c2bac1d`.

### Results (MacBookPro18,3)

Measured 2026-09-27 CT, HEAD `7e8f4e7b581d5effff240fd883f3ff1829768b8b`. Default threads are 8 (`hw.physicalcpu`). qemu H/s is not in these cells. Energy was not measured.

Summary (default 8T). Timed-batch `other` / `idle_s` / switches are the 8T treatment `DUAL_JOB` line; soak and live `other` are that run's `TIME_SPLIT` other.

| Mode | Offline timed batch H/s | Offline soak 120 s H/s | Live tn3 120 s H/s | `TIME_SPLIT` other % (soak / live) | `idle_s` (timed / soak / live) | switches (timed / soak / live) | underfeed | install_while_live (timed / soak / live) |
|------|-------------------------|------------------------|--------------------|-----------------------------------|--------------------------------|--------------------------------|-----------|------------------------------------------|
| control `--dual-job off` | 75171014 (~75.2 MH/s) | 101124149 (~101.1 MH/s) | 68997622 (~69.0 MH/s) | 0.71% / 0.34% | n/a | n/a | n/a | n/a |
| treatment `--dual-job on` | 93707539 (~93.7 MH/s, +24.7%) | 125091135 (~125.1 MH/s, +23.70%) | 100343446 (~100.3 MH/s, +45.43% vs this control) | 17.35% / 4.91% | 0.0000 / 20.8258 / 5.9124 | 1 / 77768 / 85892 | 0 / 0 / 0 | 0 / 0 / 4 |

| Energy | control | treatment |
|--------|---------|-----------|
| `ABS_PKG_W` | not measured | not measured |
| `W_PER_HASH` | not measured | not measured |
| `J_PER_HASH` | not measured | not measured |

#### Offline timed 2M

| Mode | H/s | vs paired control |
|------|-----|-------------------|
| control 1T `--dual-job off` | **24203112** | — |
| treatment 1T `--dual-job on` | **24102193** | **−0.42%** (flat) |
| control default 8T `--dual-job off` | **75171014** (~75.2 MH/s) | — |
| treatment default 8T `--dual-job on` | **93707539** (~93.7 MH/s) | **+24.7%** (short-bench noise; prefer the soaks) |

8T treatment:

```
DUAL_JOB mode=on slots=2 switches=1 underfeed=0 install_while_live=0 idle_s=0.0000
```

#### Offline soak 120 s, default 8T

| Mode | SOAK_AVG_H/s | `TIME_SPLIT` other | BATCHES | `DUAL_JOB` |
|------|--------------|--------------------|---------|------------|
| `--dual-job off` | **101124149** (~101.1 MH/s) | **0.71%** | started=**11573** early_share=**0** full=**11573** | n/a |
| `--dual-job on` | **125091135** (~125.1 MH/s, **+23.70%**) | **17.35%** | started=**14317** early_share=**0** early_clean=**1** full=**14316** | switches=**77768** underfeed=**0** install_while_live=**0** idle_s=**20.8258** |

```
control:
SOAK_AVG_H/s=101124149
TIME_SPLIT_PCT other=0.71
BATCHES started=11573 early_share=0 full=11573

treatment:
SOAK_AVG_H/s=125091135
TIME_SPLIT_PCT other=17.35
BATCHES started=14317 early_share=0 early_clean=1 full=14316
DUAL_JOB mode=on slots=2 switches=77768 underfeed=0 install_while_live=0 idle_s=20.8258
```

#### Live tn3 120 s, `--suggest-diff 0.001`, default 8T, `caffeinate`

```sh
caffeinate -dims ./miner_test --dual-job off --testnet --seconds 120 --max-shares 0 --suggest-diff 0.001
caffeinate -dims ./miner_test --dual-job on --testnet --seconds 120 --max-shares 0 --suggest-diff 0.001
```

| Field | control `--dual-job off` | treatment `--dual-job on` |
|-------|--------------------------|---------------------------|
| H/s | **68997622** (~69.0 MH/s) | **100343446** (~100.3 MH/s, **+45.43%** vs this control) |
| Shares | **920** accepted / **924** submitted (**4** rejected) | **1489** accepted / **1492** submitted (**3** rejected) |
| Jobs | seen=**6** staged=**5** | seen=**3** staged=**2** |
| Difficulty | ended **0.16** | ended **0.16** |
| `TIME_SPLIT_PCT` | hash=**87.38** share=**12.28** other=**0.34** | hash=**86.10** share=**8.99** other=**4.91** |
| Gaps | wake_s=**0.1130** join_s=**0.1239** | wake_s=**0.0000** join_s=**0.0001** unexplained≈**5.8905** |
| `BATCHES` | started=**3949** early_share=**0** early_clean=**3** full=**3946** avg_flight_s=**0.0303** hashes_per_flight=**2096948** | started=**5744** early_share=**0** early_clean=**4** full=**5740** avg_flight_s=**114.1216** hashes_per_flight=**2096532** |
| Dual-job | `dual_job=off` | switches=**85892** underfeed=**0** install_while_live=**4** idle_s=**5.9124** |

```
control:
TIME_SPLIT_PCT hash=87.38 share=12.28 other=0.34
TIME_SPLIT_GAPS wake_s=0.1130 join_s=0.1239
BATCHES started=3949 early_share=0 early_clean=3 full=3946 avg_flight_s=0.0303 hashes_per_flight=2096948
dual_job=off

treatment:
TIME_SPLIT_PCT hash=86.10 share=8.99 other=4.91
TIME_SPLIT_GAPS wake_s=0.0000 join_s=0.0001 unexplained≈5.8905
BATCHES started=5744 early_share=0 early_clean=4 full=5740 avg_flight_s=114.1216 hashes_per_flight=2096532
DUAL_JOB mode=on slots=2 switches=85892 underfeed=0 install_while_live=4 idle_s=5.9124
```

### Decision

Offline soak (**+23.7%**, 101.1 → 125.1 MH/s) is the cleaner offline signal. The default-8T timed batch (**+24.7%**) is short-bench noise; the 1T pair was flat (**−0.42%**).

Live treatment is **+45.43%** versus this control (69.0 → 100.3 MH/s; 68997622 → 100343446). This control sits below the section 12 Step 2 confirm (**80160173**, ~80.2 MH/s). Against that baseline, treatment is about **+25%** (~100.3 vs ~80.2).

Treatment `TIME_SPLIT` / `BATCHES` show elevated `other` (soak **17.35%**, live **4.91%**), elevated `idle_s` (soak **20.8258**, live **5.9124**), and live `avg_flight_s`≈**114**. That is likely dual-job accounting skew: workers stay live across slot switches, so one flight covers the run. Treat it as an instrumentation caveat, not as proof that wall time was wasted. Live unexplained≈**5.8905** lines up with `idle_s`=**5.9124**. `underfeed` was **0** on the 8T timed batch, the offline soak, and the live soak.

**Decision:** Emshon approved the merge. Squash-merged to `main` as PR #13 / `8c5287f` (2026-09-27). Default stays `--dual-job off`. Treatment is `--dual-job on`. Numbers above are from the pre-merge measure (HEAD `7e8f4e7`).

### Post-merge confirm soak

A later Mac soak on `main` (`8c5287f`) with `--dual-job on`, about **60 s**, printed about **95.8 MH/s**, `early_share` **0**, `underfeed` **0**, and share wall about **9%**. Same class as the section 13 live treatment (~100 MH/s) and above the Step 2 confirm (~80 MH/s).
