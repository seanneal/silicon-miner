/*
 * harness.c — C only outside the hash path.
 * Tests, timing, metrics glue, threads, and optional testnet Stratum mining loop.
 * Hash path remains pure ARM64 asm (sha256d_mine.s). Workers call
 * _sha256d_mine_midstate on disjoint nonce ranges. Stratum share checks are a
 * target inequality, so that loop partitions the same way and hashes each
 * slice with the existing asm compress (sha256d_asm_one).
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#include <pthread/qos.h>
#include <CommonCrypto/CommonDigest.h>
#endif

#include "stratum.h"

/* Asm exports (Mach-O underscore applied by assembler; C sees unprefixed) */
extern void sha256_compress(uint32_t state[8], const uint8_t block[64]);
extern int  sha256d_genesis_selftest(void);
extern int  sha256d_mine_midstate(const uint32_t midstate[8],
                                  const uint32_t w_be[16],
                                  uint32_t nonce_start,
                                  uint32_t nonce_count,
                                  const uint32_t expect[8],
                                  uint32_t *found_nonce);

static const uint32_t SHA_IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

/* Genesis header (80 bytes) */
static const uint8_t GENESIS_HEADER[80] = {
    0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x3b,0xa3,0xed,0xfd, 0x7a,0x7b,0x12,0xb2, 0x7a,0xc7,0x2c,0x3e,
    0x67,0x76,0x8f,0x61, 0x7f,0xc8,0x1b,0xc3, 0x88,0x8a,0x51,0x32, 0x3a,0x9f,0xb8,0xaa,
    0x4b,0x1e,0x5e,0x4a, 0x29,0xab,0x5f,0x49, 0xff,0xff,0x00,0x1d, 0x1d,0xac,0x2b,0x7c
};

/* Internal LE digest as SHA words */
static const uint32_t GENESIS_DIGEST[8] = {
    0x6fe28c0au, 0xb6f1b372u, 0xc1a6a246u, 0xae63f74fu,
    0x931e8365u, 0xe15a089cu, 0x68d61900u, 0x00000000u
};

/* Never-match target for timed batches (all bits set) */
static const uint32_t TARGET_NEVER[8] = {
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu,
    0xffffffffu, 0xffffffffu, 0xffffffffu, 0xffffffffu
};

/*
 * FAKE_TARGET (easy-target TTFN): accept a SHA-256d digest when
 *   (digest[7] & 0xff000000u) == 0
 * i.e. the high byte of internal word 7 is zero (~1/256 nonces).
 * Not a real Bitcoin nBits target — educational only.
 */
#define FAKE_TARGET_MASK  0xff000000u
#define FAKE_TARGET_DESC  "(digest[7] & 0xff000000) == 0  (~1/256, high byte of word7 zero)"

/* Default educational throwaway testnet P2WPKH (mining-only; do not treat as funded). */
#define DEFAULT_TESTNET_USER "tb1qhpe5prj25dsaxjnhq0ukj689xrcy8ede76p2up"
#define DEFAULT_TESTNET_HOST "tn3.btclab.dev"
#define DEFAULT_TESTNET_PORT 3333

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int sig) { (void)sig; g_stop = 1; }

static void be_words_from_block(uint32_t w_be[16], const uint8_t block[64]) {
    for (int i = 0; i < 16; i++) {
        w_be[i] = ((uint32_t)block[i*4+0] << 24) |
                  ((uint32_t)block[i*4+1] << 16) |
                  ((uint32_t)block[i*4+2] << 8)  |
                  ((uint32_t)block[i*4+3]);
    }
}

/* Midstate = one asm compress of header[0:64] from IV (C only sets up; asm hashes) */
static void compute_midstate(uint32_t mid[8], const uint8_t header80[80]) {
    memcpy(mid, SHA_IV, sizeof(SHA_IV));
    sha256_compress(mid, header80); /* first 64 bytes */
}

static void build_block1_wbe(uint32_t w_be[16], const uint8_t header80[80]) {
    uint8_t block1[64];
    memset(block1, 0, 64);
    memcpy(block1, header80 + 64, 16);
    block1[16] = 0x80;
    /* bit length 80*8 = 640 = 0x280 */
    block1[62] = 0x02;
    block1[63] = 0x80;
    be_words_from_block(w_be, block1);
}

static double monotonic_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

/* Best-effort P-core / QoS hint on macOS. Thread affinity APIs are limited. */
static void try_pcore_affinity(void) {
#ifdef __APPLE__
    int rc = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    if (rc != 0) {
        fprintf(stderr, "NOTE: pthread_set_qos_class_self_np unavailable/failed (%d)\n", rc);
    } else {
        fprintf(stderr, "NOTE: QoS USER_INTERACTIVE set (best-effort P-core hint)\n");
    }
#else
    fprintf(stderr, "NOTE: P-core affinity not applicable on this OS\n");
#endif
}

static void dump_words(const char *label, const uint32_t w[8]) {
    printf("%s", label);
    for (int i = 0; i < 8; i++) printf("%08x", w[i]);
    printf("\n");
}

static void store_be32(uint8_t *p, uint32_t w) {
    p[0] = (uint8_t)(w >> 24);
    p[1] = (uint8_t)(w >> 16);
    p[2] = (uint8_t)(w >> 8);
    p[3] = (uint8_t)(w);
}

/*
 * One SHA-256d via asm compress only (midstate + block1 with nonce + second SHA).
 * Used for easy-target scanning and Stratum share search; dual-lane mine stays equality-gated.
 */
static void sha256d_asm_one(const uint32_t mid[8], const uint32_t w_be[16],
                            uint32_t nonce, uint32_t digest[8]) {
    uint8_t block1[64];
    memset(block1, 0, 64);
    for (int i = 0; i < 16; i++)
        store_be32(block1 + i * 4, w_be[i]);
    /*
     * Splice nonce into W3 (bytes 12..15). Bitcoin header stores nonce LE;
     * mine path does rev(nonce) into the CE W word — equivalent to writing
     * LE bytes here so sha256_compress's rev32 yields the same W3.
     */
    store_be32(block1 + 12, __builtin_bswap32(nonce));

    uint32_t st[8];
    memcpy(st, mid, 32);
    sha256_compress(st, block1);

    uint8_t block2[64];
    memset(block2, 0, 64);
    for (int i = 0; i < 8; i++)
        store_be32(block2 + i * 4, st[i]);
    block2[32] = 0x80;
    /* bit length 32*8 = 256 */
    block2[62] = 0x01;
    block2[63] = 0x00;

    memcpy(digest, SHA_IV, 32);
    sha256_compress(digest, block2);
}

static int easy_target_hit(const uint32_t digest[8]) {
    return (digest[7] & FAKE_TARGET_MASK) == 0;
}

#define MAX_MINE_THREADS 256

/* QoS hint per worker. Main thread still logs the one-time note. */
static void worker_qos_hint(void) {
#ifdef __APPLE__
    (void)pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
#endif
}

static int clamp_threads(int threads) {
    if (threads < 1) return 1;
    if (threads > MAX_MINE_THREADS) return MAX_MINE_THREADS;
    return threads;
}

/* Performance cores on Apple Silicon, else hw.ncpu, else online processors. */
static int default_thread_count(const char **src) {
#ifdef __APPLE__
    int n = 0;
    size_t sz = sizeof n;
    if (sysctlbyname("hw.perflevel0.physicalcpu", &n, &sz, NULL, 0) == 0 && n > 0) {
        if (src) *src = "default hw.perflevel0.physicalcpu";
        return clamp_threads(n);
    }
    sz = sizeof n;
    if (sysctlbyname("hw.ncpu", &n, &sz, NULL, 0) == 0 && n > 0) {
        if (src) *src = "default hw.ncpu";
        return clamp_threads(n);
    }
#endif
    long nproc = sysconf(_SC_NPROCESSORS_ONLN);
    if (nproc < 1) nproc = 1;
    if (src) *src = "default sysconf(_SC_NPROCESSORS_ONLN)";
    return clamp_threads((int)nproc);
}

/*
 * Split `count` successive nonces (uint32 wrap) into contiguous slices.
 * Earlier slices stay even so each worker remains on the dual-lane asm path.
 * A leftover odd nonce is appended to the last non-empty slice.
 * Returns the number of non-empty slices.
 */
static int partition_nonce_ranges(uint32_t start, uint32_t count, int nthreads,
                                  uint32_t *starts, uint32_t *counts) {
    if (count == 0) return 0;
    nthreads = clamp_threads(nthreads);
    if ((uint32_t)nthreads > count) nthreads = (int)count;

    uint32_t pairs = count >> 1;
    uint32_t pair_base = pairs / (uint32_t)nthreads;
    uint32_t pair_rem = pairs % (uint32_t)nthreads;
    uint32_t cursor = start;
    int used = 0;
    for (int i = 0; i < nthreads; i++) {
        uint32_t pc = pair_base + ((uint32_t)i < pair_rem ? 1u : 0u);
        uint32_t c = pc << 1;
        if (i == nthreads - 1 && (count & 1u))
            c += 1u;
        if (c == 0)
            continue;
        starts[used] = cursor;
        counts[used] = c;
        cursor += c;
        used++;
    }
    return used;
}

static int ranges_cover_ok(uint32_t start, uint32_t count, int nthreads) {
    uint32_t starts[MAX_MINE_THREADS];
    uint32_t counts[MAX_MINE_THREADS];
    int used = partition_nonce_ranges(start, count, nthreads, starts, counts);
    if (count == 0) return used == 0;
    uint32_t expect = start;
    uint32_t sum = 0;
    for (int i = 0; i < used; i++) {
        if (counts[i] == 0) return 0;
        /* Only the tail slice may be odd — keeps the rest on dual-lane. */
        if (i + 1 < used && (counts[i] & 1u)) return 0;
        if (starts[i] != expect) return 0;
        expect += counts[i];
        sum += counts[i];
    }
    return sum == count && used >= 1;
}

static int selftest_partition(void) {
    const uint32_t starts[] = {0u, 1u, 0xfffffffeu, 0x7c2bac1du};
    const uint32_t counts[] = {0u, 1u, 2u, 3u, 7u, 8u, 100u, 65536u};
    const int nts[] = {1, 2, 3, 4, 8};
    for (unsigned si = 0; si < sizeof starts / sizeof starts[0]; si++) {
        for (unsigned ci = 0; ci < sizeof counts / sizeof counts[0]; ci++) {
            for (unsigned ni = 0; ni < sizeof nts / sizeof nts[0]; ni++) {
                if (!ranges_cover_ok(starts[si], counts[ci], nts[ni])) {
                    printf("SELFTEST: FAIL (partition start=%08x count=%u threads=%d)\n",
                           starts[si], counts[ci], nts[ni]);
                    return 1;
                }
            }
        }
    }
    printf("SELFTEST: nonce partition OK\n");
    return 0;
}

typedef struct {
    const uint32_t *mid;
    const uint32_t *w_be;
    uint32_t nonce_start;
    uint32_t nonce_count;
    const uint32_t *expect;
    uint32_t found;
    int hit;
} mine_slice_t;

typedef struct {
    const uint32_t *mid;
    const uint32_t *w_be;
    const uint8_t *target;
    uint32_t nonce_start;
    uint32_t nonce_count;
    uint32_t found;
    int hit;
    uint32_t hashed;
} scan_slice_t;

typedef struct {
    int hit;
    uint32_t nonce;
    uint64_t hashes;
} scan_result_t;

static void *mine_slice_worker(void *arg) {
    mine_slice_t *s = (mine_slice_t *)arg;
    worker_qos_hint();
    uint32_t found = 0;
    s->hit = sha256d_mine_midstate(s->mid, s->w_be, s->nonce_start, s->nonce_count,
                                   s->expect, &found);
    s->found = found;
    return NULL;
}

static void *scan_slice_worker(void *arg) {
    scan_slice_t *s = (scan_slice_t *)arg;
    worker_qos_hint();
    uint32_t dig[8];
    s->hit = 0;
    s->found = 0;
    s->hashed = 0;
    for (uint32_t i = 0; i < s->nonce_count; i++) {
        if ((i & 4095u) == 0 && g_stop) break;
        uint32_t nonce = s->nonce_start + i;
        sha256d_asm_one(s->mid, s->w_be, nonce, dig);
        s->hashed++;
        if (stratum_hash_meets_target(dig, s->target)) {
            s->hit = 1;
            s->found = nonce;
            break;
        }
    }
    return NULL;
}

/* Spawn workers; on create failure, run the rest on this thread. Join all. */
static void run_workers(int n, void *(*fn)(void *), void *base, size_t stride) {
    pthread_t tids[MAX_MINE_THREADS];
    unsigned char started[MAX_MINE_THREADS];
    if (n < 1) return;
    if (n > MAX_MINE_THREADS) n = MAX_MINE_THREADS;
    memset(started, 0, (size_t)n);
    int inline_from = n;
    for (int i = 0; i < n; i++) {
        void *arg = (unsigned char *)base + (size_t)i * stride;
        if (pthread_create(&tids[i], NULL, fn, arg) != 0) {
            fprintf(stderr, "NOTE: pthread_create failed at worker %d; running remainder inline\n", i);
            inline_from = i;
            break;
        }
        started[i] = 1;
    }
    for (int i = inline_from; i < n; i++) {
        void *arg = (unsigned char *)base + (size_t)i * stride;
        fn(arg);
    }
    for (int i = 0; i < n; i++) {
        if (started[i]) pthread_join(tids[i], NULL);
    }
}

static int earlier_hit(int any, uint32_t best_off, uint32_t start, uint32_t found) {
    if (!any) return 1;
    return (uint32_t)(found - start) < best_off;
}

/*
 * Equality-gated mine. threads<=1 (or a single slice) calls
 * sha256d_mine_midstate directly so the one-thread path stays the same.
 * On multiple hits, the earliest nonce in search order wins.
 */
static int mine_midstate_n(const uint32_t mid[8], const uint32_t w_be[16],
                           uint32_t nonce_start, uint32_t nonce_count,
                           const uint32_t expect[8], uint32_t *found_nonce,
                           int threads) {
    if (nonce_count == 0) return 0;
    threads = clamp_threads(threads);

    uint32_t starts[MAX_MINE_THREADS];
    uint32_t counts[MAX_MINE_THREADS];
    int used = partition_nonce_ranges(nonce_start, nonce_count, threads, starts, counts);
    if (used <= 1) {
        return sha256d_mine_midstate(mid, w_be, nonce_start, nonce_count,
                                     expect, found_nonce);
    }

    mine_slice_t slices[MAX_MINE_THREADS];
    for (int i = 0; i < used; i++) {
        slices[i].mid = mid;
        slices[i].w_be = w_be;
        slices[i].nonce_start = starts[i];
        slices[i].nonce_count = counts[i];
        slices[i].expect = expect;
        slices[i].found = 0;
        slices[i].hit = 0;
    }
    run_workers(used, mine_slice_worker, slices, sizeof slices[0]);

    int any = 0;
    uint32_t best = 0;
    uint32_t best_off = 0;
    for (int i = 0; i < used; i++) {
        if (!slices[i].hit) continue;
        uint32_t off = slices[i].found - nonce_start;
        if (earlier_hit(any, best_off, nonce_start, slices[i].found)) {
            any = 1;
            best = slices[i].found;
            best_off = off;
        }
    }
    if (any && found_nonce) *found_nonce = best;
    return any;
}

/*
 * Stratum share scan. Same nonce partition as mine_midstate_n.
 * Each worker hashes with sha256d_asm_one (asm compress) and the C target check,
 * because _sha256d_mine_midstate only equality-compares a full digest.
 */
static scan_result_t scan_share_n(const uint32_t mid[8], const uint32_t w_be[16],
                                  const uint8_t target[32],
                                  uint32_t nonce_start, uint32_t nonce_count,
                                  int threads) {
    scan_result_t r;
    r.hit = 0;
    r.nonce = 0;
    r.hashes = 0;
    if (nonce_count == 0) return r;
    threads = clamp_threads(threads);

    uint32_t starts[MAX_MINE_THREADS];
    uint32_t counts[MAX_MINE_THREADS];
    int used = partition_nonce_ranges(nonce_start, nonce_count, threads, starts, counts);

    scan_slice_t slices[MAX_MINE_THREADS];
    for (int i = 0; i < used; i++) {
        slices[i].mid = mid;
        slices[i].w_be = w_be;
        slices[i].target = target;
        slices[i].nonce_start = starts[i];
        slices[i].nonce_count = counts[i];
        slices[i].found = 0;
        slices[i].hit = 0;
        slices[i].hashed = 0;
    }
    if (used <= 1) {
        scan_slice_worker(&slices[0]);
    } else {
        run_workers(used, scan_slice_worker, slices, sizeof slices[0]);
    }

    uint32_t best_off = 0;
    for (int i = 0; i < used; i++) {
        r.hashes += slices[i].hashed;
        if (!slices[i].hit) continue;
        if (earlier_hit(r.hit, best_off, nonce_start, slices[i].found)) {
            r.hit = 1;
            r.nonce = slices[i].found;
            best_off = slices[i].found - nonce_start;
        }
    }
    return r;
}

static int selftest_threaded_genesis(int threads) {
    uint32_t mid[8], w_be[16], found = 0;
    compute_midstate(mid, GENESIS_HEADER);
    build_block1_wbe(w_be, GENESIS_HEADER);

    uint32_t start = 0x7c2bac1du - 5u;
    int hit = mine_midstate_n(mid, w_be, start, 8u, GENESIS_DIGEST, &found, threads);
    if (hit != 1 || found != 0x7c2bac1du) {
        printf("SELFTEST: FAIL (threaded genesis threads=%d hit=%d found=%08x)\n",
               threads, hit, found);
        return 1;
    }

    /* Nonce sits in lane B of one dual-lane pair; extra threads must not split it wrong. */
    hit = mine_midstate_n(mid, w_be, 0x7c2bac1du - 1u, 2u, GENESIS_DIGEST, &found, threads);
    if (hit != 1 || found != 0x7c2bac1du) {
        printf("SELFTEST: FAIL (lane-B pair threads=%d hit=%d found=%08x)\n",
               threads, hit, found);
        return 1;
    }

    hit = mine_midstate_n(mid, w_be, 0u, 64u, TARGET_NEVER, &found, threads);
    if (hit != 0) {
        printf("SELFTEST: FAIL (threaded never-target threads=%d)\n", threads);
        return 1;
    }
    printf("SELFTEST: threaded midstate OK (threads=%d)\n", threads);
    return 0;
}

static int selftest_scan_once(int threads) {
    uint32_t mid[8], w_be[16], dig[8];
    compute_midstate(mid, GENESIS_HEADER);
    build_block1_wbe(w_be, GENESIS_HEADER);

    uint8_t target_all[32];
    memset(target_all, 0xff, sizeof target_all);
    scan_result_t sr = scan_share_n(mid, w_be, target_all, 100u, 128u, threads);
    if (!sr.hit || sr.nonce != 100u) {
        printf("SELFTEST: FAIL (scan all-target threads=%d hit=%d nonce=%08x hashes=%llu)\n",
               threads, sr.hit, sr.nonce, (unsigned long long)sr.hashes);
        return 1;
    }

    uint8_t target_zero[32];
    memset(target_zero, 0, sizeof target_zero);
    sr = scan_share_n(mid, w_be, target_zero, 0u, 32u, threads);
    if (sr.hit || sr.hashes != 32u) {
        printf("SELFTEST: FAIL (scan zero-target threads=%d hit=%d hashes=%llu)\n",
               threads, sr.hit, (unsigned long long)sr.hashes);
        return 1;
    }

    uint32_t easy = 0xffffffffu;
    const uint32_t limit = 4096u;
    for (uint32_t n = 0; n < limit; n++) {
        sha256d_asm_one(mid, w_be, n, dig);
        if (easy_target_hit(dig)) {
            easy = n;
            break;
        }
    }
    if (easy == 0xffffffffu) {
        printf("SELFTEST: FAIL (no easy-target nonce within %u)\n", limit);
        return 1;
    }
    uint8_t hash[32];
    for (int i = 0; i < 8; i++)
        store_be32(hash + i * 4, dig[i]);
    uint8_t target_exact[32];
    for (int i = 0; i < 32; i++)
        target_exact[31 - i] = hash[i];
    sr = scan_share_n(mid, w_be, target_exact, easy, 64u, threads);
    if (!sr.hit || sr.nonce != easy) {
        printf("SELFTEST: FAIL (scan exact threads=%d hit=%d nonce=%08x exp=%08x)\n",
               threads, sr.hit, sr.nonce, easy);
        return 1;
    }
    printf("SELFTEST: threaded share scan OK (threads=%d nonce=%08x)\n", threads, easy);
    return 0;
}

/* Parse Mach-O `size -m` (__text) or SysV `size -A` (.text). */
static long parse_text_size(FILE *fp, int sysv) {
    char line[256];
    long text_bytes = -1;
    int any = 0;
    while (fgets(line, sizeof line, fp)) {
        if (!any) {
            printf("TEXT_SIZE_RAW:\n");
            any = 1;
        }
        fputs(line, stdout);
        if (!sysv) {
            /* Section (__TEXT, __text): 3412 */
            if (strstr(line, "__text")) {
                char *colon = strrchr(line, ':');
                if (colon) text_bytes = strtol(colon + 1, NULL, 10);
            }
        } else if (strncmp(line, ".text", 5) == 0 &&
                   (line[5] == ' ' || line[5] == '\t')) {
            text_bytes = strtol(line + 5, NULL, 10);
        }
    }
    return text_bytes;
}

/* Print hash-path text size of sha256d_mine.o (prove the hot path is asm). */
static void print_text_size(void) {
    long text_bytes = -1;
    FILE *fp = popen("size -m sha256d_mine.o 2>/dev/null", "r");
    if (fp) {
        text_bytes = parse_text_size(fp, 0);
        int st = pclose(fp);
        if (st != 0) text_bytes = -1;
    }
    if (text_bytes < 0) {
        fp = popen("size -A sha256d_mine.o 2>/dev/null", "r");
        if (fp) {
            text_bytes = parse_text_size(fp, 1);
            pclose(fp);
        }
    }
    if (text_bytes >= 0)
        printf("TEXT_SIZE_BYTES=%ld\n", text_bytes);
    else {
        printf("TEXT_SIZE_BYTES=na\n");
        printf("TEXT_SIZE_NOTE=size sha256d_mine.o failed (run from build dir after make)\n");
    }
}

#ifdef __APPLE__
/* CommonCrypto baseline: full SHA-256d of 80-byte header (nonce spliced). */
static double bench_commoncrypto_hs(const uint8_t header80[80], uint32_t batch) {
    uint8_t hdr[80];
    memcpy(hdr, header80, 80);
    uint8_t d1[CC_SHA256_DIGEST_LENGTH];
    uint8_t d2[CC_SHA256_DIGEST_LENGTH];

    double t0 = monotonic_seconds();
    for (uint32_t n = 0; n < batch; n++) {
        hdr[76] = (uint8_t)(n >> 24);
        hdr[77] = (uint8_t)(n >> 16);
        hdr[78] = (uint8_t)(n >> 8);
        hdr[79] = (uint8_t)(n);
        CC_SHA256(hdr, 80, d1);
        CC_SHA256(d1, CC_SHA256_DIGEST_LENGTH, d2);
    }
    double t1 = monotonic_seconds();
    double dt = t1 - t0;
    if (dt < 1e-9) dt = 1e-9;
    (void)d2;
    return (double)batch / dt;
}
#endif

static void run_metrics(uint32_t batch, const uint32_t mid[8], const uint32_t w_be[16],
                        const uint8_t header80[80], int threads) {
    printf("\n=== METRICS (no-power harness) ===\n");
    printf("THREADS=%d\n", threads);
#ifndef __APPLE__
    printf("NOTE: H/s is this host's run of the asm path, not an Apple Silicon bench\n");
#endif

    print_text_size();

    uint32_t found = 0;
    printf("ASM_TIMING: hashing %u nonces on %d thread(s) (dual-lane mine, expect no hit)...\n",
           batch, threads);
    double t0 = monotonic_seconds();
    int hit = mine_midstate_n(mid, w_be, 0u, batch, TARGET_NEVER, &found, threads);
    double t1 = monotonic_seconds();
    double dt = t1 - t0;
    if (dt < 1e-9) dt = 1e-9;
    double asm_hs = (double)batch / dt;
    printf("ASM_H/s=%.0f  threads=%d (hit=%d elapsed=%.6f s)\n", asm_hs, threads, hit, dt);

#ifdef __APPLE__
    double cc_hs = bench_commoncrypto_hs(header80, batch);
    printf("CC_H/s=%.0f  (CommonCrypto CC_SHA256 x2 on 80-byte header)\n", cc_hs);
#else
    printf("CC_H/s=na  (CommonCrypto only on Apple)\n");
    (void)header80;
#endif

    printf("FAKE_TARGET=%s\n", FAKE_TARGET_DESC);
    printf("TTFN: scanning from nonce 0 for first easy-target hit...\n");
    uint32_t dig[8];
    uint32_t ttfn_nonce = 0xffffffffu;
    double t_start = monotonic_seconds();
    const uint32_t ttfn_limit = 16u * 1024u * 1024u;
    for (uint32_t n = 0; n < ttfn_limit; n++) {
        sha256d_asm_one(mid, w_be, n, dig);
        if (easy_target_hit(dig)) {
            ttfn_nonce = n;
            break;
        }
    }
    double t_end = monotonic_seconds();
    double ttfn_s = t_end - t_start;
    if (ttfn_nonce == 0xffffffffu) {
        printf("TTFN_S=na  (no hit within %u nonces)\n", ttfn_limit);
    } else {
        printf("TTFN_S=%.9f  nonce=0x%08x  tried=%u\n",
               ttfn_s, ttfn_nonce, ttfn_nonce + 1);
        dump_words("TTFN_DIGEST=", dig);
    }

    printf("METRICS_SUMMARY TEXT_SIZE_BYTES (see above) THREADS=%d ASM_H/s=%.0f CC_H/s=",
           threads, asm_hs);
#ifdef __APPLE__
    printf("%.0f", cc_hs);
#else
    printf("na");
#endif
    if (ttfn_nonce == 0xffffffffu)
        printf(" TTFN_S=na\n");
    else
        printf(" TTFN_S=%.9f\n", ttfn_s);
}

static int run_selftest(int threads) {
    if (selftest_partition() != 0)
        return 1;

    int st = sha256d_genesis_selftest();
    if (st != 0) {
        printf("SELFTEST: FAIL (code %d)\n", st);
        uint32_t mid[8], w_be[16], found = 0;
        compute_midstate(mid, GENESIS_HEADER);
        build_block1_wbe(w_be, GENESIS_HEADER);
        dump_words("midstate_got=", mid);
        printf("midstate_exp=bc909a336358bff090ccac7d1e59caa8c3c8d8e94f0103c896b187364719f91b\n");
        int hit = sha256d_mine_midstate(mid, w_be, 0x7c2bac1du, 1, GENESIS_DIGEST, &found);
        printf("direct_mine hit=%d found=%08x\n", hit, found);
        return 1;
    }
    printf("SELFTEST: PASS\n");

    uint32_t mid[8], w_be[16], found = 0;
    compute_midstate(mid, GENESIS_HEADER);
    build_block1_wbe(w_be, GENESIS_HEADER);
    if (sha256d_mine_midstate(mid, w_be, 0x7c2bac1du, 1, GENESIS_DIGEST, &found) != 1 ||
        found != 0x7c2bac1du) {
        printf("SELFTEST: FAIL (harness midstate path)\n");
        dump_words("midstate=", mid);
        return 1;
    }
    printf("SELFTEST: midstate+genesis nonce OK (found=%08x)\n", found);

    {
        uint32_t dig[8];
        sha256d_asm_one(mid, w_be, 0x7c2bac1du, dig);
        if (memcmp(dig, GENESIS_DIGEST, 32) != 0) {
            printf("SELFTEST: FAIL (sha256d_asm_one vs genesis)\n");
            dump_words("got=", dig);
            dump_words("exp=", GENESIS_DIGEST);
            return 1;
        }
    }

    if (selftest_threaded_genesis(1) != 0)
        return 1;
    if (threads != 1 && selftest_threaded_genesis(threads) != 0)
        return 1;
    if (selftest_scan_once(1) != 0)
        return 1;
    if (threads != 1 && selftest_scan_once(threads) != 0)
        return 1;
    return 0;
}

/*
 * Testnet Stratum mine loop:
 *  connect → suggest_diff → authorize → jobs → midstate asm hash → submit shares
 */
static int run_testnet(const char *host, int port, const char *user, const char *pass,
                       double suggest_diff, int seconds, int max_shares, int threads) {
    printf("\n=== TESTNET STRATUM ===\n");
    printf("endpoint=%s:%d user=%s suggest_diff=%.8g duration=%ds threads=%d\n",
           host, port, user, suggest_diff, seconds, threads);

    stratum_client_t client;
    if (stratum_connect(&client, host, port, user, pass, suggest_diff) != 0) {
        printf("RESULT: FAIL (stratum connect/auth)\n");
        return 1;
    }

    if (!client.have_job) {
        printf("STRATUM: waiting for first job...\n");
        for (int i = 0; i < 100 && !client.have_job && !g_stop; i++)
            stratum_poll(&client, 100);
    }
    if (!client.have_job) {
        printf("RESULT: FAIL (no job received)\n");
        stratum_close(&client);
        return 1;
    }

    uint8_t target[32];
    stratum_share_target(client.difficulty, target);
    double expect_s = client.difficulty * 4294967296.0 / 25e6; /* rough at 25 MH/s */
    printf("STRATUM: difficulty=%.8g expect_share@25MH/s=%.2fs\n",
           client.difficulty, expect_s);
    printf("STRATUM: target=");
    for (int i = 0; i < 32; i++) printf("%02x", target[i]);
    printf("\n");

    uint64_t hashes = 0;
    uint64_t extranonce2 = 0;
    uint32_t nonce_cursor = 0;
    uint64_t job_seq = 0;
    uint32_t mid[8], w_be[16];
    uint8_t header80[80];
    int header_ready = 0;
    double t0 = monotonic_seconds();
    double t_last_report = t0;
    /*
     * Per-round nonce span. With N>1, scale so each worker still sees about
     * one 64Ki batch, capped so a new job is noticed within ~1M nonces.
     */
    uint32_t scan_batch = 65536u;
    if (threads > 1) {
        uint64_t scaled = (uint64_t)scan_batch * (unsigned)threads;
        if (scaled > 1024ull * 1024ull) scaled = 1024ull * 1024ull;
        scan_batch = (uint32_t)scaled;
    }
    printf("STRATUM: scan_batch=%u threads=%d\n", scan_batch, threads);

    while (!g_stop) {
        double now = monotonic_seconds();
        if (seconds > 0 && (now - t0) >= (double)seconds) break;
        if (max_shares > 0 && (int)client.shares_accepted >= max_shares) break;

        stratum_poll(&client, 0);

        if (!client.have_job) {
            stratum_poll(&client, 50);
            continue;
        }

        /* New job → reset extranonce2 / nonce cursor */
        if (client.job.seq != job_seq) {
            job_seq = client.job.seq;
            extranonce2 = 0;
            nonce_cursor = 0;
            header_ready = 0;
            stratum_share_target(client.difficulty, target);
            printf("STRATUM: new job id=%s diff=%.8g\n",
                   client.job.job_id, client.difficulty);
        }

        /* Rebuild midstate when job or extranonce2 changed */
        if (!header_ready) {
            if (stratum_build_header(&client, extranonce2, 0, header80) != 0) {
                fprintf(stderr, "STRATUM: build_header failed\n");
                break;
            }
            compute_midstate(mid, header80);
            build_block1_wbe(w_be, header80);
            header_ready = 1;
        }

        /* Share search: disjoint slices, asm compress + C target check. */
        scan_result_t sr = scan_share_n(mid, w_be, target, nonce_cursor, scan_batch, threads);
        hashes += sr.hashes;
        if (sr.hit) {
            printf("SHARE_CANDIDATE nonce=0x%08x en2=%llu job=%s\n",
                   sr.nonce, (unsigned long long)extranonce2, client.job.job_id);
            int rc = stratum_submit(&client, extranonce2, client.job.ntime, sr.nonce);
            printf("SHARE_SUBMIT rc=%d accepted=%llu rejected=%llu\n",
                   rc,
                   (unsigned long long)client.shares_accepted,
                   (unsigned long long)client.shares_rejected);
            extranonce2++;
            nonce_cursor = 0;
            header_ready = 0;
        }
        if (!sr.hit) {
            uint64_t next = (uint64_t)nonce_cursor + scan_batch;
            if (next >= 0x100000000ULL) {
                /* nonce space exhausted for this extranonce2 — roll */
                extranonce2++;
                nonce_cursor = 0;
                header_ready = 0;
            } else {
                nonce_cursor = (uint32_t)next;
            }
        }

        now = monotonic_seconds();
        if (now - t_last_report >= 2.0) {
            double dt = now - t0;
            double hs = (dt > 1e-9) ? (double)hashes / dt : 0.0;
            printf("STATUS connected=1 jobs=%llu hashes=%llu H/s=%.0f threads=%d "
                   "diff=%.8g shares_ok=%llu shares_bad=%llu en2=%llu\n",
                   (unsigned long long)client.jobs_seen,
                   (unsigned long long)hashes, hs, threads, client.difficulty,
                   (unsigned long long)client.shares_accepted,
                   (unsigned long long)client.shares_rejected,
                   (unsigned long long)extranonce2);
            t_last_report = now;
        }

        /* dual-lane H/s probe once early (equality mine, not the share target) */
        static int probed = 0;
        if (!probed && hashes > scan_batch) {
            uint32_t found = 0;
            const uint32_t probe_n = 2000000u;
            double a0 = monotonic_seconds();
            mine_midstate_n(mid, w_be, 0u, probe_n, TARGET_NEVER, &found, threads);
            double a1 = monotonic_seconds();
            double adt = a1 - a0;
            if (adt < 1e-9) adt = 1e-9;
            printf("ASM_DUAL_LANE_H/s=%.0f threads=%d\n", (double)probe_n / adt, threads);
            probed = 1;
        }
    }

    double t1 = monotonic_seconds();
    double dt = t1 - t0;
    if (dt < 1e-9) dt = 1e-9;
    double hs = (double)hashes / dt;

    printf("\n=== TESTNET SUMMARY ===\n");
    printf("endpoint=%s:%d\n", host, port);
    printf("authorized=%d\n", (int)client.authorized);
    printf("jobs_seen=%llu\n", (unsigned long long)client.jobs_seen);
    printf("difficulty=%.8g\n", client.difficulty);
    printf("hashes=%llu\n", (unsigned long long)hashes);
    printf("H/s=%.0f\n", hs);
    printf("threads=%d\n", threads);
    printf("shares_submitted=%llu\n", (unsigned long long)client.shares_submitted);
    printf("shares_accepted=%llu\n", (unsigned long long)client.shares_accepted);
    printf("shares_rejected=%llu\n", (unsigned long long)client.shares_rejected);
    printf("elapsed_s=%.2f\n", dt);
    printf("expect_share_s@this_rate=%.2f\n",
           client.difficulty * 4294967296.0 / (hs > 1.0 ? hs : 1.0));

    stratum_close(&client);

    if (client.shares_accepted > 0) {
        printf("RESULT: PASS (share accepted)\n");
        return 0;
    }
    if (client.jobs_seen > 0 && hashes > 0) {
        printf("RESULT: PASS (live jobs processed; no share in window — diff may be high)\n");
        return 0;
    }
    printf("RESULT: FAIL\n");
    return 1;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage:\n"
        "  %s                     genesis self-test + timed batch\n"
        "  %s --metrics [N]       metrics harness\n"
        "  %s --threads N         worker count (default: P-cores or hw.ncpu)\n"
        "  %s --testnet           mine BTCLab testnet3 (suggest_diff=0.001)\n"
        "  %s --stratum HOST:PORT --user USER [--pass PASS] [--suggest-diff D]\n"
        "                         [--seconds N] [--max-shares N] [--threads N]\n"
        "\n"
        "Educational testnet only. No mainnet / AntPool.\n",
        argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    uint32_t batch = 2000000;
    int metrics_mode = 0;
    int testnet_mode = 0;
    const char *stratum_host = DEFAULT_TESTNET_HOST;
    int stratum_port = DEFAULT_TESTNET_PORT;
    const char *user = DEFAULT_TESTNET_USER;
    const char *pass = "x";
    double suggest_diff = 0.001;
    int seconds = 60;
    int max_shares = 1;
    int have_stratum = 0;
    int threads = 0;
    int threads_set = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--metrics") == 0 || strcmp(argv[i], "metrics") == 0) {
            metrics_mode = 1;
        } else if (strcmp(argv[i], "--testnet") == 0) {
            testnet_mode = 1;
            have_stratum = 1;
        } else if (strcmp(argv[i], "--stratum") == 0 && i + 1 < argc) {
            have_stratum = 1;
            testnet_mode = 1;
            char *hp = argv[++i];
            char *colon = strrchr(hp, ':');
            if (colon) {
                *colon = '\0';
                stratum_host = hp;
                stratum_port = atoi(colon + 1);
            } else {
                stratum_host = hp;
            }
        } else if (strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            user = argv[++i];
        } else if (strcmp(argv[i], "--pass") == 0 && i + 1 < argc) {
            pass = argv[++i];
        } else if (strcmp(argv[i], "--suggest-diff") == 0 && i + 1 < argc) {
            suggest_diff = strtod(argv[++i], NULL);
        } else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            seconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--max-shares") == 0 && i + 1 < argc) {
            max_shares = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            threads = atoi(argv[++i]);
            threads_set = 1;
        } else if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            batch = (uint32_t)strtoul(argv[i], NULL, 10);
            if (batch == 0) batch = 2000000;
        } else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    const char *thread_src = "cli --threads";
    if (!threads_set)
        threads = default_thread_count(&thread_src);
    threads = clamp_threads(threads);

    printf("silicon-miner educational harness\n");
    printf("=================================\n");
    printf("THREADS=%d (%s)\n", threads, thread_src);
    try_pcore_affinity();

    if (run_selftest(threads) != 0) {
        printf("ENERGY_PLACEHOLDER_IDLE_W=na\n");
        printf("ENERGY_PLACEHOLDER_PKG_W=na\n");
        printf("ENERGY_PLACEHOLDER_W_PER_HASH=na\n");
        printf("ENERGY_PLACEHOLDER_J_PER_HASH=na\n");
        return 1;
    }

    if (have_stratum || testnet_mode) {
        signal(SIGINT, on_sigint);
        signal(SIGTERM, on_sigint);
        return run_testnet(stratum_host, stratum_port, user, pass,
                           suggest_diff, seconds, max_shares, threads);
    }

    uint32_t mid[8], w_be[16], found = 0;
    compute_midstate(mid, GENESIS_HEADER);
    build_block1_wbe(w_be, GENESIS_HEADER);

    if (metrics_mode) {
        run_metrics(batch, mid, w_be, GENESIS_HEADER, threads);
        printf("RESULT: PASS\n");
        return 0;
    }

#ifndef __APPLE__
    printf("NOTE: H/s is this host's run of the asm path, not an Apple Silicon bench\n");
#endif
    printf("TIMING: hashing %u nonces from 0x00000000 on %d thread(s) (expect no hit)...\n",
           batch, threads);
    double t0 = monotonic_seconds();
    int hit = mine_midstate_n(mid, w_be, 0u, batch, TARGET_NEVER, &found, threads);
    double t1 = monotonic_seconds();
    double dt = t1 - t0;
    if (dt < 1e-9) dt = 1e-9;
    double hs = (double)batch / dt;
    printf("TIMING: hit=%d  elapsed=%.6f s  threads=%d  H/s=%.0f\n", hit, dt, threads, hs);
    printf("H/s=%.0f\n", hs);
    printf("threads=%d\n", threads);

    printf("ENERGY_PLACEHOLDER_IDLE_W=na\n");
    printf("ENERGY_PLACEHOLDER_PKG_W=na\n");
    printf("ENERGY_PLACEHOLDER_W_PER_HASH=na\n");
    printf("ENERGY_PLACEHOLDER_J_PER_HASH=na\n");

    printf("RESULT: PASS\n");
    return 0;
}
