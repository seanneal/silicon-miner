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

Landed on `main` (PR #1 squash merge `86fe9cf`, 2026-09-26). TIME_SPLIT accounting landed (PR #3, `6d37fb6`, 2026-09-26). Wake-on-complete landed (PR #6, `36b83c5`, 2026-09-26); the post-fix Mac soak is in section 10.

| ID | Item | Kind | Status |
|----|------|------|--------|
| — | Multi-thread C nonce ranges | eng | Done / on main |
| — | Dual-lane asm schedule | eng | Done / on main |
| — | TIME_SPLIT wall accounting | eng | Done / on main (PR #3); Mac live soak in section 9 |
| — | TIME_SPLIT_GAPS (split `other`) | eng | Mac soaks in section 10 (PR #5 pre-fix; PR #6 post-fix) |
| — | In-flight wake-on-complete | eng | Done / on main (PR #6); Mac soak in section 10 |
| — | Step 1 share check + finish slice | eng | Section 11; Mac soak **PLACEHOLDER** |
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

Ordinary engineering (not E6 / E7). Added 2026-09-27. Asm hash path (`sha256d_mine.s`) was not changed.

What changed, so the coordinator soak has a baseline to compare with section 10:

- The per-nonce share check compares `bswap32(digest[7])` to the top target word and reads the rest of the target only on a tie. It is the same Bitcoin integer compare as the old 32-byte walk (selftest oracle).
- A live share is queued and that worker finishes its nonce range. Siblings are not cancelled. The batch does not roll extranonce2 just because a share hit; the nonce cursor continues on the same header until wrap, a new job, or `clean_jobs`.
- `TIME_SPLIT` / `TIME_SPLIT_GAPS` / `BATCHES` still print. `early_share` on a live soak should drop (slices are no longer cut short by a hit). `share_restart_s` stays the short-batch fallback, not the common share path.
- `--suggest-diff 0.001` is unchanged so a one-share proof still returns quickly. For a quieter H/s soak, pass `--suggest-diff 1`. That is only `mining.suggest_difficulty`; the check still uses the pool's `set_difficulty`.

### Mac soak — PLACEHOLDER

Coordinator fill-in. Do not treat qemu or this VM as Apple Silicon H/s.

Same shape as section 10 so the share-path delta is comparable:

```sh
caffeinate -dims ./miner_test --testnet --seconds 120 --max-shares 0 --threads 6 --suggest-diff 0.001
```

Quieter soak (fewer submits while vardiff climbs), still an honest pool target:

```sh
caffeinate -dims ./miner_test --testnet --seconds 120 --max-shares 0 --threads 6 --suggest-diff 1
```

| Field | Value |
|-------|-------|
| Machine | MacBookPro18,3 |
| Branch | PLACEHOLDER |
| Endpoint | PLACEHOLDER |
| Duration | PLACEHOLDER |
| Threads | PLACEHOLDER |
| H/s | PLACEHOLDER |
| Difficulty | PLACEHOLDER |
| Shares | PLACEHOLDER |
| `TIME_SPLIT_PCT` | PLACEHOLDER |
| `TIME_SPLIT_GAPS` | PLACEHOLDER |
| `TIME_SPLIT_GAPS_DETAIL` | PLACEHOLDER |
| `BATCHES` | PLACEHOLDER (`early_share` expected well below section 10's 651/3372 if the finish-the-slice path is doing the work) |
| Result | PLACEHOLDER |

Harness lines (paste under this heading):

```
PLACEHOLDER
TIME_SPLIT ...
TIME_SPLIT_PCT ...
TIME_SPLIT_CPU ...
TIME_SPLIT_FLIGHT ...
TIME_SPLIT_OVERLAP ...
TIME_SPLIT_GAPS ...
TIME_SPLIT_GAPS_PCT ...
TIME_SPLIT_GAPS_DETAIL ...
BATCHES ...
```

**Expected direction vs section 10 (not a measurement):** share-check wall down from 17.01%, hash fraction up, `hashes_per_flight` nearer the full `2<<20` assignment (2097152), `early_share` near 0 aside from real cancels. Offline 6T reference on main was ~72.7 MH/s (2M nonce timed); live section 10 was ~57.8 MH/s.
