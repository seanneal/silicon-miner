# silicon-miner

Educational **Apple Silicon / M1** SHA-256d midstate miner.

**Learning only — not for profit.** Testnet Stratum is supported for education. No mainnet AntPool, no BTC spend.

## Layout (flat)

| File | Role |
|------|------|
| `sha256d_mine.s` | Pure ARM64 Crypto Extension hash path (`SHA256H` / `H2` / `SU0` / `SU1`) |
| `harness.c` | Tests, timing, metrics, CLI, testnet mine loop (no hash logic) |
| `stratum.c` / `stratum.h` | Bitcoin Stratum V1 client (subscribe / authorize / notify / submit) |
| `Makefile` | Build / clean / metrics / testnet |
| `measure.sh` | Optional energy sample via `powermetrics` (needs sudo) |
| `README.md` | This file |

## Build & run (Apple Silicon Mac)

Requires `as`/`clang` with `-arch arm64` (Xcode Command Line Tools).

```sh
make                 # builds miner_test
./miner_test         # self-test + timed batch (default)
./miner_test 5000000 # custom nonce count for H/s
./miner_test --threads 4 5000000
make clean
```

## Threads

`--threads N` splits a nonce span across N workers in C. Each worker calls `_sha256d_mine_midstate` on a disjoint range (even slices, so the asm stays on the dual-lane path). `N=1` is the original single call.

Default N is `hw.perflevel0.physicalcpu` (Apple Silicon performance cores), then `hw.ncpu`, then `sysconf(_SC_NPROCESSORS_ONLN)`.

Timing, `--metrics`, `--soak`, and the testnet loop all take `--threads`. Stratum share checks are a target inequality, so that search uses the same partition but hashes each slice with the existing asm compress (`sha256_compress` via `sha256d_asm_one`). `--metrics` prints `THREADS` and `ASM_H/s`.

## P-core pin (macOS)

Default `--pin`. `--no-pin` turns it off. There is no public API to bind a thread to a CPU index. Each mining thread does both of these:

1. `pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE)` so the scheduler prefers performance cores.
2. `thread_policy_set(..., THREAD_AFFINITY_POLICY)` with a distinct tag `1..N`. Tag 0 means no affinity. Distinct tags ask the scheduler to spread workers across L2 cache domains instead of packing them onto one core.

Startup prints `PIN=on` or `PIN=off` or `PIN=na` (Linux). `PIN_QOS_RC` and `PIN_AFFINITY_RC` are on stderr.

## Offline soak

Sustained local hashing, no pool. Periodic H/s is the instantaneous rate since the previous line; `H/s_avg` is from the start. Use this to compare a short batch with a multi-minute run.

```sh
./miner_test --soak 60
./miner_test --soak 180 --threads 4 --report 2
```

`--soak` cannot be combined with `--testnet`. Testnet duration is still `--seconds`.

## Linux check (not an M1 bench)

The hash path is Mach-O and uses Apple `@PAGE` syntax. On Linux, `make` rewrites that syntax to ELF, cross-assembles with `aarch64-linux-gnu-gcc`, and runs under `qemu-aarch64-static -cpu max`. Self-test must pass. Any H/s from that run is qemu, not Apple Silicon.

## Bitcoin testnet mining (Stratum)

Connects to a **public testnet3** Stratum, builds headers from `mining.notify`, hashes with the asm midstate path, and submits shares.

```sh
# BTCLab testnet3 (default). Username must be a tb1… address (`.` is rejected).
# Uses a built-in throwaway mining-only address + mining.suggest_difficulty 0.001
# so a CPU can prove an accepted share in seconds.
make testnet
# or:
./miner_test --testnet --seconds 90 --max-shares 1 --threads 4

# Custom endpoint / user:
./miner_test --stratum tn3.btclab.dev:3333 \
  --user tb1q… --pass x --suggest-diff 0.001 --seconds 120
```

**Notes**

- Default endpoint: `stratum+tcp://tn3.btclab.dev:3333` (bare TCP, no TLS).
- BTCLab docs mention user `.` / pass `x`; in practice authorize requires a real `tb1…` address. A throwaway testnet address is fine for mining-only.
- Default mining username is throwaway testnet P2WPKH `tb1qhpe5prj25dsaxjnhq0ukj689xrcy8ede76p2up` (mining-only; not a savings wallet).
- Fallback pool `testnet3.solopool.com:3332` also accepts `tb1…` (and honors `mining.suggest_difficulty`).
- Default pool difficulty without suggest is often **16384** (~weeks at ~25 MH/s). Always pass `--suggest-diff` for CPU education runs.
- Hash path stays **pure asm**; C does Stratum, merkle/header setup, and share-target checks.
- While workers hash, the main thread polls the socket. A new `mining.notify` is parsed and its midstate is built into a side buffer during that hash. `clean_jobs` cancels the in-flight scan so stale work stops; a non-clean notify finishes the current batch, then switches to the already-built header. The summary field `jobs_staged_while_hashing` counts notifies staged before the batch ended.
- A worker that finds a share queues it immediately and stops only its own slice. The main thread writes `mining.submit` on the next poll (`stratum_submit_async`) and counts the reply later. The other workers keep hashing through that round-trip.
- Live session note: notify parsing must fully skip long `coinb1`/`coinb2` strings before reading `version`/`nbits`/`ntime` (truncated scan previously left ntime empty → pool “Difficulty too low”).

## Metrics

**No-power harness metrics** (recommended; no sudo):

```sh
make metrics
# or: ./miner_test --metrics
```

Prints `.text` size, `THREADS`, `ASM_H/s`, `CC_H/s`, and easy-target `TTFN_S`.

**Optional energy** (needs sudo for `powermetrics`). The sample window is an offline multi-thread soak, not a short nonce batch, so package watts are taken while hashes are in flight. `W_PER_HASH` and `J_PER_HASH` use absolute package power over `SOAK_AVG_H/s` (`J/hash = W / (hash/s)`).

```sh
./measure.sh
./measure.sh --threads 4
./measure.sh --threads 4 --seconds 20
```

## What the asm exports

| Symbol | Role |
|--------|------|
| `_sha256_compress` | One 64-byte block; state in/out |
| `_sha256d_genesis_selftest` | FIPS "abc" + genesis midstate mine; `0` = PASS |
| `_sha256d_mine_midstate` | Dual-lane midstate loop. Next-group schedule sits under `SHA256H`/`H2`; cached midstate/IV are added in place |

## Constraints

- Hash path is **pure ARM64 assembly** — no C in the hash path
- C is harness + Stratum only
- **No mainnet pools / AntPool / paid mining**
