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

**Interpretation:** ~39 MH/s is this early live Stratum soak. Offline batches at 4T/8T are higher because they do not pay job/share/submit overhead.

Later same-day live soaks (different vardiff and share counts) are in sections 9 and 10. The post–wake-pipe soak is in section 10.

---

## 6. Engineering vs formal experiments (status)

Landed on `main` (PR #1 squash merge `86fe9cf`, 2026-09-26). TIME_SPLIT accounting landed (PR #3, `6d37fb6`, 2026-09-26). Wake-on-complete landed (PR #6, `36b83c5`, 2026-09-26); the post-fix Mac soak is in section 10. Step 1 (share check + finish-the-slice) landed (PR #8, `a4ad0ba`, 2026-09-27); the Mac soak is in section 11. Step 2 (default threads = all physical cores) is this change; the Mac 8T soak is in section 12.

| ID | Item | Kind | Status |
|----|------|------|--------|
| — | Multi-thread C nonce ranges | eng | Done / on main |
| — | Dual-lane asm schedule | eng | Done / on main |
| — | TIME_SPLIT wall accounting | eng | Done / on main (PR #3); Mac live soak in section 9 |
| — | TIME_SPLIT_GAPS (split `other`) | eng | Mac soaks in section 10 (PR #5 pre-fix; PR #6 post-fix) |
| — | In-flight wake-on-complete | eng | Done / on main (PR #6); Mac soak in section 10 |
| — | Step 1 share check + finish slice | eng | Done / on main (PR #8); Mac soak in section 11 |
| — | Default threads = `hw.physicalcpu` (P+E) | eng | This change; Mac 8T soak in section 12 |
| E1 | P-core pin (`--pin` / `--no-pin`) | eng | Done / exercised on Mac. Slots past perflevel0 use UTILITY QoS (section 12) |
| E2 | Offline `--soak` | eng | Done |
| E3 | Multi-thread `measure.sh` | eng | Done (MT peak watts TBD) |
| E4 | Job midstate staging while hashing | eng | Done / soak saw `staged_overlap=1` |
| E5 | Async share submit | eng | Done / soak exercised path |
| E6 | `exp/sha-pipe-schedule` | **formal experiment fork** | Measured (section 13). Leave #12 unmerged |
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

The offline 6T timed batch (**72.7 → 62.7 MH/s**) is short-bench noise against that baseline, not the live result. Offline 8T was **88.1 → 91.0 MH/s** on the same kind of short batch. Wake stayed a fraction of a second (wake_s **0.0941 → 0.2129**). E6 and E7 were not started.

---

## 12. Step 2 — default workers on all physical cores

Ordinary engineering (not E6 / E7). Asm hash path (`sha256d_mine.s`) was not changed. Mac numbers below are from MacBookPro18,3 (6P+2E), 2026-09-27 CT. qemu H/s is not used here.

What this change does:

- Default worker count is `hw.physicalcpu` (all physical cores), then `hw.ncpu`, then `sysconf(_SC_NPROCESSORS_ONLN)`. On this machine that is **8**. `hw.perflevel0.physicalcpu` (**6**, P-cores only) is no longer the default. `--threads N` still overrides.
- Pin stays on. Worker slots below the P-core count still request `QOS_CLASS_USER_INTERACTIVE`. Slots at or past that count request `QOS_CLASS_UTILITY` so the scheduler can place them on efficiency cores instead of eight threads all asking for six P-cores. Including E-cores is the H/s win and can worsen W/hash.

The live 8T row below was measured with explicit `--threads 8` on `main` after #8, before this QoS split. On that build every worker still requested `QOS_CLASS_USER_INTERACTIVE`. It is the evidence that eight workers beat the Step 1 six-thread soak. The default after this change matches that worker count.

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

### Step 2 live soak (8T explicit, main after #8)

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

### Offline 2M-nonce (noisy)

`./miner_test --threads 8 2000000` on this pull: **H/s=77561467** (~77.6 MH/s).

Short offline batches move around. Section 11 already recorded 8T timed batches at **88094085** (~88.1 MH/s) and **90991811** (~91.0 MH/s) the same day. **77.6 MH/s** is another short sample, not a live regression. The 120 s Stratum soak is the comparison. E6 starts in section 13. E7 is not in that experiment.

---

## 13. E6 — SHA-pipe schedule A/B (`exp/sha-pipe-schedule`)

Formal experiment fork. Mac numbers below are from 2026-09-27 CT. Leave PR #12 unmerged. E7 is not in this change. qemu H/s is not an Apple Silicon number.

### Hypothesis

Firestorm (M1 P-core) has one SHA unit. Public timings (Dougall Johnson, firestorm-simd):

| Instruction | Latency | Reciprocal throughput | Unit |
|-------------|---------|------------------------|------|
| `SHA256H` / `SHA256H2` | 4 cycles if the destination feeds the next op's first source; 5 cycles into source 2 or the message operand | 2 (one every two cycles) | u14 only |
| `SHA256SU0` | 2 | 1 | u14 only |
| `SHA256SU1` | 3 | 1 | u14 only |

`SU0`/`SU1` cannot dual-issue beside `H`/`H2`. A scheduled dual-lane round-group is 4 hash ops × 2 cycles + 4 schedule ops × 1 cycle = 12 cycles of that pipe, and both arms issue exactly those ops. The pipe is already full. A large win is not available from reordering.

What can still move is a 1-cycle bubble. Schedule A (main) issues both lanes together:

```
SU0_A, SU0_B, H_A, H_B, SU1_A, SU1_B, H2_A, H2_B
```

Lane A's `SHA256H2` starts only after both `H` ops and both `SU1` ops. The next round's `SHA256H` reads that `H2` result as source 2. If that forward is the 5-cycle path, `H2` issued late waits one cycle past the 12-cycle budget.

Schedule B (this experiment) is lane-major. Each round-group finishes lane A before lane B:

```
SU0_A, H_A, SU1_A, H2_A, SU0_B, H_B, SU1_B, H2_B
```

Hash-only groups (no message schedule) are `H_A, H2_A, H_B, H2_B`. `H2` issues in the throughput slot right after that lane's `H`, so the q1 result is ready while the other lane still holds u14. Operands and instruction counts match schedule A. Only the issue order inside the dual-lane loop changes. The single-lane odd tail and `_sha256_compress` are the same in both arms.

**Expected:** a small single-digit percent on the offline dual-lane hash path, or flat. Not a new throughput ceiling.

### Method

| Arm | Flag | Symbol |
|-----|------|--------|
| A, baseline (current main asm) | `--sha-sched a` (default) | `_sha256d_mine_midstate` |
| B, lane-major | `--sha-sched b` | `_sha256d_mine_midstate_e6b` |

C only selects the entry point. The hash path stays pure ARM64 asm. Offline timed batches, `--soak`, and `--metrics` use that entry. The testnet scan still hashes with `_sha256_compress` plus the C target check in both arms, because a share needs the digest and the mine loop only equality-compares. A live A/B is a check that the scan path did not move; it is not the SHA-pipe treatment. Startup prints `SHA_SCHED=A` or `SHA_SCHED=B`.

Self-test (both arms, every run): genesis nonce `7c2bac1d` on lane A, lane B, the dual-loop back-edge, the odd tail, a miss, and the single-lane count of 1. Share-target checks and `TIME_SPLIT` counters are unchanged.

Context the coordinator stated after Step 1 (#8) and Step 2 (#10), for comparison only: live default about **80.2 MH/s at 8 threads**, share wall about **9.5%**. Section 12's recorded 8T soak is **71.7 MH/s** on an earlier same-day run. This section does not replace that row.

### qemu correctness (not H/s)

Run on this branch under `qemu-aarch64-static -cpu max` (`make` / `./miner_test.aarch64 --threads 2`, and the same with `--sha-sched b`). qemu H/s is not recorded. Apple Silicon throughput is the tables below.

| Check | Result |
|-------|--------|
| Genesis asm self-test (`SELFTEST: PASS`, nonce `7c2bac1d`) | **PASS** |
| Schedule A and B dual-lane / single-lane genesis (`SELFTEST: E6 schedule A and B genesis OK (nonce=7c2bac1d)`) | **PASS** on both `--sha-sched a` and `--sha-sched b` |
| Share-target self-test (342 cases) and threaded share scan | **PASS** |
| `TIME_SPLIT` / `TIME_SPLIT_GAPS` counters armed | **PASS** |
| `RESULT` | **PASS** |

### Mac offline (2026-09-27 CT)

Machine: **Seans-MacBook-Pro**. HEAD `550c0c1706682233e43121942d6e79625f830373`. Short 2M-nonce batches. 1T is one thread. Default is 8 threads.

```sh
./miner_test --sha-sched a --threads 1 2000000
./miner_test --sha-sched b --threads 1 2000000
./miner_test --sha-sched a 2000000
./miner_test --sha-sched b 2000000
```

| Arm | Threads | H/s | `SHA_SCHED` | Notes |
|-----|---------|-----|-------------|-------|
| A | 1 | **25061086** (25.061 MH/s) | A | `TIMING hit=0 elapsed=0.079805 s threads=1` |
| B | 1 | **24956949** (24.957 MH/s) | B | `elapsed=0.080138 s` |
| A | default 8 | **117591721** (117.592 MH/s) | A | `elapsed=0.017008 s` |
| B | default 8 | **124385845** (124.386 MH/s) | B | `elapsed=0.016079 s` |
| B vs A, 1T | 1 | **−0.42%** | | 24956949 vs 25061086. Flat / tiny loss for B |
| B vs A, default | 8 | **+5.78%** | | 124385845 vs 117591721. Short-bench noise; not a win |

### Mac live soak (2026-09-27 CT)

Same machine and HEAD. tn3, 120 s, `--suggest-diff 0.001`, `THREADS=8` (6 performance cores at interactive QoS, 2 efficiency cores at utility QoS). Both soaks printed `SHA_SCHED`. The CLI notes `--sha-sched` selects the offline mine entry; the testnet scan stays on `_sha256_compress`.

```sh
caffeinate -dims ./miner_test --sha-sched a --testnet --seconds 120 --max-shares 0 --suggest-diff 0.001
caffeinate -dims ./miner_test --sha-sched b --testnet --seconds 120 --max-shares 0 --suggest-diff 0.001
```

| Field | Schedule A | Schedule B |
|-------|------------|------------|
| Machine | Seans-MacBook-Pro | Seans-MacBook-Pro |
| `SHA_SCHED` | **A** | **B** |
| Threads | **8** (default; 6P interactive + 2E utility) | **8** (default; 6P interactive + 2E utility) |
| Live H/s | **67977975** (67.978 MH/s) | **63599780** (63.600 MH/s) |
| Hashes | not in the reported lines | not in the reported lines |
| Difficulty ended | **~0.16** | **~0.08** |
| Shares accepted / submitted | **967 / 969** (2 rejected) | **844 / 846** (2 rejected) |
| `TIME_SPLIT_PCT` hash / share / other | **86.99 / 12.65 / 0.36** | **87.53 / 12.13 / 0.34** |
| `TIME_SPLIT_GAPS_DETAIL` wake_s / join_s | not in the reported lines | not in the reported lines |
| `BATCHES` | started=**3890** full=**3889** early_share=**0** | started=**3640** full=**3638** early_share=**0** |
| B vs A live H/s | **−6.44%** (63599780 vs 67977975) | |

### Interpretation

Offline 1T is the schedule-sensitive signal: A and B are flat (B **−0.42%**, 25.061 → 24.957 MH/s). Offline default 8T moved **+5.78%** on a ~17 ms batch. That short bench is too noisy to claim a win (sections 11 and 12 already show 8T timed batches swinging by tens of MH/s).

The live soaks printed `SHA_SCHED`, and the scan hash in both arms is still `_sha256_compress`. The live **−6.44%** (67.978 → 63.600 MH/s) is not a clean E6 treatment effect. Pool difficulty also differed: A ended near **0.16**, B near **0.08**. Share wall stayed near 12% either way (12.65% and 12.13%). `early_share` stayed **0**.

**Do not merge B as ordinary engineering.** Prefer A, the current main schedule. Coordinator will leave #12 unmerged. The experiment PR stays open with these numbers.
