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
make clean
```

## Bitcoin testnet mining (Stratum)

Connects to a **public testnet3** Stratum, builds headers from `mining.notify`, hashes with the asm midstate path, and submits shares.

```sh
# BTCLab testnet3 (default). Username must be a tb1… address (`.` is rejected).
# Uses a built-in throwaway mining-only address + mining.suggest_difficulty 0.001
# so a CPU can prove an accepted share in seconds.
make testnet
# or:
./miner_test --testnet --seconds 90 --max-shares 1

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
- Live session note: notify parsing must fully skip long `coinb1`/`coinb2` strings before reading `version`/`nbits`/`ntime` (truncated scan previously left ntime empty → pool “Difficulty too low”).

## Metrics

**No-power harness metrics** (recommended; no sudo):

```sh
make metrics
# or: ./miner_test --metrics
```

Prints `.text` size, `ASM_H/s`, `CC_H/s`, and easy-target `TTFN_S`.

**Optional energy** (needs sudo for `powermetrics`):

```sh
./measure.sh
```

## What the asm exports

| Symbol | Role |
|--------|------|
| `_sha256_compress` | One 64-byte block; state in/out |
| `_sha256d_genesis_selftest` | FIPS "abc" + genesis midstate mine; `0` = PASS |
| `_sha256d_mine_midstate` | Dual-lane midstate loop, K-window staging, nonce splice, digest compare |

## Constraints

- Hash path is **pure ARM64 assembly** — no C in the hash path
- C is harness + Stratum only
- **No mainnet pools / AntPool / paid mining**
