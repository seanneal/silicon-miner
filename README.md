# silicon-miner

Educational **Apple Silicon / M1** SHA-256d midstate miner skeleton.

**Learning only — not for profit.** No Stratum, no pools, no networking, no BTC spend.

## Layout (flat)

| File | Role |
|------|------|
| `sha256d_mine.s` | Pure ARM64 Crypto Extension hash path (`SHA256H` / `H2` / `SU0` / `SU1`) |
| `harness.c` | Tests, timing, metrics (no hash logic) |
| `Makefile` | Build / clean / metrics |
| `measure.sh` | Optional energy sample via `powermetrics` (needs sudo) |
| `README.md` | This file |

## Build & run (Apple Silicon Mac)

Requires `as`/`clang` with `-arch arm64` (Xcode Command Line Tools).

```sh
make                 # builds miner_test
./miner_test         # self-test + timed batch
./miner_test 5000000 # custom nonce count for H/s
make clean
```

## Metrics

**No-power harness metrics** (recommended; no sudo):

```sh
make metrics
# or: ./miner_test --metrics
```

Prints:

1. **`.text` size** of `sha256d_mine.o` (`TEXT_SIZE_BYTES=…`)
2. **`ASM_H/s`** — dual-lane midstate miner throughput
3. **`CC_H/s`** — CommonCrypto `CC_SHA256`×2 baseline on the same 80-byte header work
4. **`TTFN_S`** — wall time to first nonce under a documented fake easy target  
   (`(digest[7] & 0xff000000) == 0`, ~1/256; not real nBits)

**Optional energy** (needs passwordless or interactive sudo for `powermetrics`):

```sh
./measure.sh
./measure.sh 2000000
```

If sudo/powermetrics is unavailable, the script still runs the binary and skips energy.

## What the asm exports

| Symbol | Role |
|--------|------|
| `_sha256_compress` | One 64-byte block; state in/out |
| `_sha256d_genesis_selftest` | FIPS "abc" + genesis midstate mine; `0` = PASS |
| `_sha256d_mine_midstate` | Dual-lane midstate loop, K-window staging, nonce splice, digest compare |

## Design notes (v1 + items 2–3)

**In `.s`:**

- **K staging:** `LK256` in `__TEXT,__const`; 4-vector sliding window in `v28–v31`, reloaded every 4 round-groups
- **Dual-lane:** two nonces interleaved to hide SHA256H latency
- Pre-REV32 fixed block1 words; nonce-only W3 splice; odd leftover = single-lane K-staged path
- **Second-SHA:** fixed pad W8–W15 + IV cached; full W16+ pre-extend is not valid (digest-dependent). Amortizations: K0–15 reload overlapped with midstate adds; rounds 8–15 shared pad+K WK; skip no-op `sha256su0` at W24–27 when W8–11 are zero/pad

## Test vector

Genesis header → SHA-256d internal LE digest  
`6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000`  
(display byte-reversed `000000000019d668…`).

## Constraints

- Hash path is **pure ARM64 assembly** — no C in the hash path
- C is only the harness (tests, timing, metrics glue)
- **No pools / Stratum / networking**
