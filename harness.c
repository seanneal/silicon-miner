/*
 * harness.c — C only outside the hash path.
 * Tests, timing, metrics glue, threads, and optional testnet Stratum mining loop.
 * Hash path remains pure ARM64 asm (sha256d_mine.s). Workers call
 * _sha256d_mine_midstate on disjoint nonce ranges. Stratum share checks are a
 * target inequality, so that loop partitions the same way and hashes each
 * slice with the existing asm compress (sha256d_asm_one).
 * TIME_SPLIT (mono_clock.h) accounts wall time around those calls.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdatomic.h>
#include "mono_clock.h"

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

/* Default on. --no-pin clears it. macOS only; Linux reports PIN=na. */
static int g_pin_cores = 1;
/* Set by the testnet loop so a clean_jobs notify stops stale hashing. */
static _Atomic int g_scan_cancel = 0;
static _Atomic int g_scan_finished = 0;

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

/*
 * TIME_SPLIT
 * ----------
 * Per-slice buckets, summed on the main thread after join. The hot nonce
 * loop only writes its own slice. No lock around the hash.
 *
 * Exclusive wall (TIME_SPLIT / TIME_SPLIT_PCT sum to elapsed):
 *   hash_s + share_s + submit-from-workers = time a worker batch was in
 *     flight, split by that batch's CPU ticks (asm vs C check vs enqueue).
 *   poll_s, midstate_s, submit_s (main-thread writes) = work done while
 *     no batch was in flight, so it stalls the next hash.
 *   other_s = the rest of the wall clock (status lines, select after the
 *     workers have already finished, pool-reply drain).
 *
 * TIME_SPLIT_OVERLAP is main-thread poll / midstate / submit that ran
 * while a batch was in flight. It is concurrent with hash and is not
 * part of the 100% line.
 *
 * TIME_SPLIT_CPU is the sum across threads (hash can exceed wall).
 *
 * Clock: see mono_clock.h. On macOS that is mach_absolute_time converted
 * with mach_timebase_info. Elsewhere it is clock_gettime(CLOCK_MONOTONIC).
 */
static _Atomic int g_time_split_on = 0;
static _Atomic uint64_t g_tick_overhead = 0;

static uint64_t g_cpu_hash_ticks;
static uint64_t g_cpu_share_ticks;
static uint64_t g_cpu_submit_ticks;
static uint64_t g_flight_wall_ns;
static uint64_t g_stall_poll_ns;
static uint64_t g_stall_mid_ns;
static uint64_t g_stall_submit_ns;
static uint64_t g_overlap_poll_busy_ns;
static uint64_t g_overlap_poll_wait_ns;
static uint64_t g_overlap_mid_ns;
static uint64_t g_overlap_submit_ns;
/* How many instrumented share-scan slices were summed. Self-test checks it. */
static uint64_t g_scan_slices_timed;
/* Main thread only. Set while a testnet scan batch is running. */
static int g_in_flight;

static int time_split_on(void) {
    return atomic_load_explicit(&g_time_split_on, memory_order_acquire);
}

static uint64_t tick_overhead(void) {
    return atomic_load_explicit(&g_tick_overhead, memory_order_relaxed);
}

static uint64_t calibrate_tick_overhead(void) {
    enum { N = 64 };
    uint64_t v[N];
    for (int i = 0; i < N; i++) {
        uint64_t a = mono_ticks();
        uint64_t b = mono_ticks();
        v[i] = b - a;
    }
    for (int i = 1; i < N; i++) {
        uint64_t x = v[i];
        int j = i;
        while (j > 0 && v[j - 1] > x) {
            v[j] = v[j - 1];
            j--;
        }
        v[j] = x;
    }
    return v[N / 2];
}

static void time_split_reset(void) {
    (void)mono_ns();
    atomic_store_explicit(&g_tick_overhead, calibrate_tick_overhead(), memory_order_relaxed);
    g_cpu_hash_ticks = 0;
    g_cpu_share_ticks = 0;
    g_cpu_submit_ticks = 0;
    g_flight_wall_ns = 0;
    g_stall_poll_ns = 0;
    g_stall_mid_ns = 0;
    g_stall_submit_ns = 0;
    g_overlap_poll_busy_ns = 0;
    g_overlap_poll_wait_ns = 0;
    g_overlap_mid_ns = 0;
    g_overlap_submit_ns = 0;
    g_scan_slices_timed = 0;
    g_in_flight = 0;
    atomic_store_explicit(&g_time_split_on, 1, memory_order_release);
}

static void time_split_off(void) {
    atomic_store_explicit(&g_time_split_on, 0, memory_order_release);
}

static void account_mid_ns(uint64_t dt) {
    if (!time_split_on()) return;
    if (g_in_flight) g_overlap_mid_ns += dt;
    else g_stall_mid_ns += dt;
}

static void account_submit_ns(uint64_t dt) {
    if (!time_split_on()) return;
    if (g_in_flight) g_overlap_submit_ns += dt;
    else g_stall_submit_ns += dt;
}

static double ns_to_s(uint64_t ns) {
    return (double)ns / 1e9;
}

static double ticks_to_s(uint64_t ticks) {
    return (double)mono_ticks_to_ns(ticks) / 1e9;
}

static void time_split_print(double wall_s) {
    if (wall_s < 1e-9) wall_s = 1e-9;

    double hash_cpu = ticks_to_s(g_cpu_hash_ticks);
    double share_cpu = ticks_to_s(g_cpu_share_ticks);
    double submit_cpu = ticks_to_s(g_cpu_submit_ticks);
    double worker = hash_cpu + share_cpu + submit_cpu;
    double flight = ns_to_s(g_flight_wall_ns);
    if (flight > wall_s) flight = wall_s;

    double hash_s, share_s, submit_flight;
    if (worker > 0.0 && flight > 0.0) {
        hash_s = flight * (hash_cpu / worker);
        share_s = flight * (share_cpu / worker);
        submit_flight = flight * (submit_cpu / worker);
    } else if (flight > 0.0) {
        hash_s = flight;
        share_s = 0.0;
        submit_flight = 0.0;
    } else {
        hash_s = 0.0;
        share_s = 0.0;
        submit_flight = 0.0;
    }

    double poll_s = ns_to_s(g_stall_poll_ns);
    double mid_s = ns_to_s(g_stall_mid_ns);
    double submit_s = ns_to_s(g_stall_submit_ns) + submit_flight;
    double sum = hash_s + share_s + poll_s + mid_s + submit_s;
    if (sum > wall_s && sum > 0.0) {
        double scale = wall_s / sum;
        hash_s *= scale;
        share_s *= scale;
        poll_s *= scale;
        mid_s *= scale;
        submit_s *= scale;
        sum = wall_s;
    }
    double other_s = wall_s - sum;
    if (other_s < 0.0) other_s = 0.0;

    double pct = 100.0 / wall_s;
    printf("TIME_SPLIT hash_s=%.4f share_s=%.4f poll_s=%.4f midstate_s=%.4f submit_s=%.4f other_s=%.4f\n",
           hash_s, share_s, poll_s, mid_s, submit_s, other_s);
    printf("TIME_SPLIT_PCT hash=%.2f share=%.2f poll=%.2f midstate=%.2f submit=%.2f other=%.2f\n",
           hash_s * pct, share_s * pct, poll_s * pct, mid_s * pct, submit_s * pct, other_s * pct);
    printf("TIME_SPLIT_CPU hash_s=%.4f share_s=%.4f submit_s=%.4f\n",
           hash_cpu, share_cpu, submit_cpu);
    printf("TIME_SPLIT_FLIGHT flight_s=%.4f\n", flight);
    printf("TIME_SPLIT_OVERLAP poll_busy_s=%.4f poll_wait_s=%.4f midstate_s=%.4f submit_s=%.4f\n",
           ns_to_s(g_overlap_poll_busy_ns), ns_to_s(g_overlap_poll_wait_ns),
           ns_to_s(g_overlap_mid_ns), ns_to_s(g_overlap_submit_ns));
    printf("TIME_SPLIT_CLOCK=%s\n", mono_clock_name());
}

/*
 * Pin one mining thread.
 * macOS has no public "bind to CPU index" API. Two documented knobs:
 *   1. pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE) — scheduler
 *      prefers performance cores.
 *   2. thread_policy_set(THREAD_AFFINITY_POLICY) with a non-zero tag —
 *      threads that share a tag prefer the same L2 cache; distinct tags
 *      (1..N, one per worker) ask the scheduler to spread them.
 * Tag 0 means "no affinity", so tags start at 1. index is the worker slot.
 */
static void apply_worker_pin(int index) {
#ifdef __APPLE__
    if (!g_pin_cores) return;
    if (index < 0) index = 0;
    (void)pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    thread_affinity_policy_data_t pol;
    pol.affinity_tag = index + 1;
    thread_port_t th = pthread_mach_thread_np(pthread_self());
    (void)thread_policy_set(th, THREAD_AFFINITY_POLICY,
                            (thread_policy_t)&pol, THREAD_AFFINITY_POLICY_COUNT);
#else
    (void)index;
#endif
}

static void report_pin_policy(int threads) {
#ifdef __APPLE__
    if (!g_pin_cores) {
        printf("PIN=off\n");
        fprintf(stderr, "PIN_NOTE=--no-pin; workers are not affinity-tagged\n");
        return;
    }
    int qos_rc = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    thread_affinity_policy_data_t pol;
    pol.affinity_tag = 1;
    thread_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t aff_rc = thread_policy_set(th, THREAD_AFFINITY_POLICY,
                                              (thread_policy_t)&pol,
                                              THREAD_AFFINITY_POLICY_COUNT);
    printf("PIN=on\n");
    fprintf(stderr,
            "PIN_METHOD=QOS_CLASS_USER_INTERACTIVE + THREAD_AFFINITY_POLICY tags=1..%d\n"
            "PIN_QOS_RC=%d PIN_AFFINITY_RC=%d\n"
            "PIN_NOTE=QoS requests performance cores; distinct affinity tags spread workers. "
            "Not a hard CPU-index pin (no public API for that).\n",
            threads, qos_rc, (int)aff_rc);
#else
    (void)threads;
    printf("PIN=na\n");
    fprintf(stderr, "PIN_NOTE=THREAD_AFFINITY_POLICY and QoS are macOS-only\n");
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

/* Kept so a reader sees pin happens inside the worker, not only on main. */
static void worker_qos_hint(int pin_index) {
    apply_worker_pin(pin_index);
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
    int pin_index;
    int timed;
    uint64_t t_start_ns;
    uint64_t t_end_ns;
    uint64_t hash_ticks;
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
    int pin_index;
    _Atomic int *finished; /* optional; testnet background scan */
    /* Set only for the live Stratum scan. A hit is queued from this worker
     * so the other slices keep hashing through the pool round-trip. */
    const char *job_id;
    const char *ntime;
    uint64_t en2;
    int timed;
    uint64_t t_start_ns;
    uint64_t t_end_ns;
    uint64_t hash_ticks;
    uint64_t share_ticks;
    uint64_t submit_ticks;
} scan_slice_t;

typedef struct {
    int hit;
    uint32_t nonce;
    uint64_t hashes;
} scan_result_t;

static int share_q_push(const char *job_id, const char *ntime, uint64_t en2, uint32_t nonce);

static void *mine_slice_worker(void *arg) {
    mine_slice_t *s = (mine_slice_t *)arg;
    worker_qos_hint(s->pin_index);
    uint32_t found = 0;
    int timing = time_split_on();
    uint64_t t0 = 0;
    if (timing) {
        s->t_start_ns = mono_ns();
        t0 = mono_ticks();
    }
    s->hit = sha256d_mine_midstate(s->mid, s->w_be, s->nonce_start, s->nonce_count,
                                   s->expect, &found);
    s->found = found;
    if (timing) {
        s->hash_ticks = mono_ticks() - t0;
        s->t_end_ns = mono_ns();
        s->timed = 1;
    }
    return NULL;
}

static void *scan_slice_worker(void *arg) {
    scan_slice_t *s = (scan_slice_t *)arg;
    worker_qos_hint(s->pin_index);
    uint32_t dig[8];
    s->hit = 0;
    s->found = 0;
    s->hashed = 0;
    s->timed = 0;
    s->hash_ticks = 0;
    s->share_ticks = 0;
    s->submit_ticks = 0;
    s->t_start_ns = 0;
    s->t_end_ns = 0;

    int timing = time_split_on();
    uint64_t ov = timing ? tick_overhead() : 0;
    uint64_t t_enter = 0;
    uint64_t hash_raw = 0;
    uint64_t submit_ticks = 0;
    uint32_t timed_n = 0;
    if (timing) {
        s->t_start_ns = mono_ns();
        t_enter = mono_ticks();
    }

    for (uint32_t i = 0; i < s->nonce_count; i++) {
        if (g_stop || atomic_load_explicit(&g_scan_cancel, memory_order_relaxed))
            break;
        uint32_t nonce = s->nonce_start + i;
        if (timing) {
            uint64_t a = mono_ticks();
            sha256d_asm_one(s->mid, s->w_be, nonce, dig);
            hash_raw += mono_ticks() - a;
            timed_n++;
        } else {
            sha256d_asm_one(s->mid, s->w_be, nonce, dig);
        }
        s->hashed++;
        if (stratum_hash_meets_target(dig, s->target)) {
            s->hit = 1;
            s->found = nonce;
            if (s->job_id) {
                if (timing) {
                    uint64_t d0 = mono_ticks();
                    (void)share_q_push(s->job_id, s->ntime, s->en2, nonce);
                    submit_ticks += mono_ticks() - d0;
                } else {
                    (void)share_q_push(s->job_id, s->ntime, s->en2, nonce);
                }
            }
            break;
        }
    }

    if (timing) {
        /* hash_raw includes one clock read per nonce. Pull that back out
         * so share_check is the C target compare (and the cancel load),
         * not the timer. See calibrate_tick_overhead. */
        uint64_t total = mono_ticks() - t_enter;
        uint64_t pull = (uint64_t)timed_n * ov;
        s->hash_ticks = hash_raw > pull ? hash_raw - pull : 0;
        s->submit_ticks = submit_ticks;
        uint64_t used = hash_raw + submit_ticks + pull;
        s->share_ticks = total > used ? total - used : 0;
        s->t_end_ns = mono_ns();
        s->timed = 1;
    }

    if (s->finished)
        atomic_fetch_add_explicit(s->finished, 1, memory_order_release);
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

static void account_mine_slices(const mine_slice_t *s, int n) {
    if (!time_split_on() || n < 1) return;
    uint64_t lo = UINT64_MAX;
    uint64_t hi = 0;
    int any = 0;
    for (int i = 0; i < n; i++) {
        if (!s[i].timed) continue;
        any = 1;
        if (s[i].t_start_ns < lo) lo = s[i].t_start_ns;
        if (s[i].t_end_ns > hi) hi = s[i].t_end_ns;
        g_cpu_hash_ticks += s[i].hash_ticks;
    }
    if (any && hi > lo) g_flight_wall_ns += hi - lo;
}

static void account_scan_slices(const scan_slice_t *s, int n) {
    if (!time_split_on() || n < 1) return;
    uint64_t lo = UINT64_MAX;
    uint64_t hi = 0;
    int any = 0;
    for (int i = 0; i < n; i++) {
        if (!s[i].timed) continue;
        any = 1;
        g_scan_slices_timed++;
        if (s[i].t_start_ns < lo) lo = s[i].t_start_ns;
        if (s[i].t_end_ns > hi) hi = s[i].t_end_ns;
        g_cpu_hash_ticks += s[i].hash_ticks;
        g_cpu_share_ticks += s[i].share_ticks;
        g_cpu_submit_ticks += s[i].submit_ticks;
    }
    if (any && hi > lo) g_flight_wall_ns += hi - lo;
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
        apply_worker_pin(0);
        if (!time_split_on()) {
            return sha256d_mine_midstate(mid, w_be, nonce_start, nonce_count,
                                         expect, found_nonce);
        }
        uint64_t t_start = mono_ns();
        uint64_t a = mono_ticks();
        int hit = sha256d_mine_midstate(mid, w_be, nonce_start, nonce_count,
                                        expect, found_nonce);
        g_cpu_hash_ticks += mono_ticks() - a;
        uint64_t t_end = mono_ns();
        if (t_end > t_start) g_flight_wall_ns += t_end - t_start;
        return hit;
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
        slices[i].pin_index = i;
        slices[i].timed = 0;
        slices[i].t_start_ns = 0;
        slices[i].t_end_ns = 0;
        slices[i].hash_ticks = 0;
    }
    run_workers(used, mine_slice_worker, slices, sizeof slices[0]);
    account_mine_slices(slices, used);

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
        slices[i].pin_index = i;
        slices[i].finished = NULL;
        slices[i].job_id = NULL;
        slices[i].ntime = NULL;
        slices[i].en2 = 0;
        slices[i].timed = 0;
        slices[i].t_start_ns = 0;
        slices[i].t_end_ns = 0;
        slices[i].hash_ticks = 0;
        slices[i].share_ticks = 0;
        slices[i].submit_ticks = 0;
    }
    if (used <= 1) {
        scan_slice_worker(&slices[0]);
    } else {
        run_workers(used, scan_slice_worker, slices, sizeof slices[0]);
    }
    account_scan_slices(slices, used);

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
            /* Section (__TEXT, __text): <bytes> */
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

    time_split_reset();
    if (selftest_threaded_genesis(1) != 0)
        return 1;
    if (threads != 1 && selftest_threaded_genesis(threads) != 0)
        return 1;
    if (selftest_scan_once(1) != 0)
        return 1;
    if (threads != 1 && selftest_scan_once(threads) != 0)
        return 1;
    if (g_cpu_hash_ticks == 0 || g_cpu_share_ticks == 0 ||
        g_flight_wall_ns == 0 || g_scan_slices_timed == 0) {
        printf("SELFTEST: FAIL (TIME_SPLIT empty hash_ticks=%llu share_ticks=%llu flight_ns=%llu scan_slices=%llu)\n",
               (unsigned long long)g_cpu_hash_ticks,
               (unsigned long long)g_cpu_share_ticks,
               (unsigned long long)g_flight_wall_ns,
               (unsigned long long)g_scan_slices_timed);
        return 1;
    }
    printf("SELFTEST: TIME_SPLIT counters armed\n");
    time_split_off();
    return 0;
}

/* One prepared header. Workers read it; the main thread fills the other copy. */
typedef struct {
    uint32_t mid[8];
    uint32_t w_be[16];
    uint8_t  target[32];
    char     job_id[STRATUM_JOB_ID_MAX];
    char     ntime[16];
    uint64_t seq;
    uint64_t en2;
    uint32_t nonce_cursor;
    int      clean;
    int      ready;
} work_buf_t;

typedef struct {
    pthread_t tid[MAX_MINE_THREADS];
    unsigned char started[MAX_MINE_THREADS];
    scan_slice_t slices[MAX_MINE_THREADS];
    int n;
    int running;
} scan_flight_t;

#define SHARE_Q 64
typedef struct {
    char job_id[STRATUM_JOB_ID_MAX];
    char ntime[16];
    uint64_t en2;
    uint32_t nonce;
} share_q_item_t;

static share_q_item_t g_share_q[SHARE_Q];
static int g_share_head;
static int g_share_tail;
static pthread_mutex_t g_share_mu = PTHREAD_MUTEX_INITIALIZER;

static int share_q_push(const char *job_id, const char *ntime, uint64_t en2, uint32_t nonce) {
    pthread_mutex_lock(&g_share_mu);
    int next = (g_share_tail + 1) % SHARE_Q;
    if (next == g_share_head) {
        pthread_mutex_unlock(&g_share_mu);
        fprintf(stderr, "STRATUM: local share queue full nonce=%08x\n", nonce);
        return -1;
    }
    share_q_item_t *it = &g_share_q[g_share_tail];
    snprintf(it->job_id, sizeof it->job_id, "%s", job_id ? job_id : "");
    snprintf(it->ntime, sizeof it->ntime, "%s", ntime ? ntime : "");
    it->en2 = en2;
    it->nonce = nonce;
    g_share_tail = next;
    pthread_mutex_unlock(&g_share_mu);
    return 0;
}

/* Send queued shares. A failed send leaves the item queued for the next poll.
 * Hash workers are not joined for the pool reply. */
static void share_q_flush(stratum_client_t *c) {
    for (;;) {
        share_q_item_t it;
        pthread_mutex_lock(&g_share_mu);
        if (g_share_head == g_share_tail) {
            pthread_mutex_unlock(&g_share_mu);
            return;
        }
        it = g_share_q[g_share_head];
        pthread_mutex_unlock(&g_share_mu);
        uint64_t t0 = time_split_on() ? mono_ns() : 0;
        int rc = stratum_submit_async(c, it.job_id, it.en2, it.ntime, it.nonce);
        if (t0) account_submit_ns(mono_ns() - t0);
        if (rc != 0)
            return;
        pthread_mutex_lock(&g_share_mu);
        g_share_head = (g_share_head + 1) % SHARE_Q;
        pthread_mutex_unlock(&g_share_mu);
        printf("SHARE_QUEUED nonce=0x%08x job=%s pending=%d accepted=%llu rejected=%llu\n",
               it.nonce, it.job_id, c->submit_pending,
               (unsigned long long)c->shares_accepted,
               (unsigned long long)c->shares_rejected);
        fflush(stdout);
    }
}

static int prepare_work(stratum_client_t *c, work_buf_t *w, uint64_t en2) {
    int timing = time_split_on();
    uint64_t t0 = timing ? mono_ns() : 0;
    uint8_t header[80];
    if (stratum_build_header(c, en2, 0, header) != 0) {
        if (timing) account_mid_ns(mono_ns() - t0);
        return -1;
    }
    compute_midstate(w->mid, header);
    build_block1_wbe(w->w_be, header);
    stratum_share_target(c->difficulty, w->target);
    snprintf(w->job_id, sizeof w->job_id, "%s", c->job.job_id);
    snprintf(w->ntime, sizeof w->ntime, "%s", c->job.ntime);
    w->seq = c->job.seq;
    w->en2 = en2;
    w->nonce_cursor = 0;
    w->clean = c->job.clean ? 1 : 0;
    w->ready = 1;
    if (timing) account_mid_ns(mono_ns() - t0);
    return 0;
}

static void scan_join(scan_flight_t *f, scan_result_t *r) {
    r->hit = 0;
    r->nonce = 0;
    r->hashes = 0;
    if (!f->running) return;
    for (int i = 0; i < f->n; i++) {
        if (f->started[i]) pthread_join(f->tid[i], NULL);
    }
    uint32_t best_off = 0;
    uint32_t origin = 0;
    int have_origin = 0;
    for (int i = 0; i < f->n; i++) {
        r->hashes += f->slices[i].hashed;
        if (!have_origin) {
            origin = f->slices[i].nonce_start;
            have_origin = 1;
        }
        if (!f->slices[i].hit) continue;
        if (earlier_hit(r->hit, best_off, origin, f->slices[i].found)) {
            r->hit = 1;
            r->nonce = f->slices[i].found;
            best_off = f->slices[i].found - origin;
        }
    }
    account_scan_slices(f->slices, f->n);
    f->running = 0;
    f->n = 0;
}

/* Background share scan. Main keeps the socket. Returns 0, or -1 if no thread. */
static int scan_start(scan_flight_t *f, const work_buf_t *w, uint32_t count, int threads) {
    memset(f, 0, sizeof *f);
    if (!w->ready || count == 0) return -1;
    threads = clamp_threads(threads);
    uint32_t starts[MAX_MINE_THREADS];
    uint32_t counts[MAX_MINE_THREADS];
    int used = partition_nonce_ranges(w->nonce_cursor, count, threads, starts, counts);
    if (used < 1) return -1;

    atomic_store_explicit(&g_scan_cancel, 0, memory_order_relaxed);
    atomic_store_explicit(&g_scan_finished, 0, memory_order_relaxed);

    for (int i = 0; i < used; i++) {
        scan_slice_t *s = &f->slices[i];
        s->mid = w->mid;
        s->w_be = w->w_be;
        s->target = w->target;
        s->nonce_start = starts[i];
        s->nonce_count = counts[i];
        s->found = 0;
        s->hit = 0;
        s->hashed = 0;
        s->pin_index = i;
        s->finished = &g_scan_finished;
        s->job_id = w->job_id;
        s->ntime = w->ntime;
        s->en2 = w->en2;
        if (pthread_create(&f->tid[i], NULL, scan_slice_worker, s) != 0) {
            fprintf(stderr, "NOTE: pthread_create failed at scan worker %d\n", i);
            atomic_store_explicit(&g_scan_cancel, 1, memory_order_relaxed);
            for (int j = 0; j < i; j++) {
                if (f->started[j]) pthread_join(f->tid[j], NULL);
            }
            f->n = 0;
            f->running = 0;
            return -1;
        }
        f->started[i] = 1;
    }
    f->n = used;
    f->running = 1;
    return 0;
}

static int scan_done(const scan_flight_t *f) {
    if (!f->running) return 1;
    return atomic_load_explicit(&g_scan_finished, memory_order_acquire) >= f->n;
}

/*
 * Offline multi-thread soak. Prints periodic H/s so a short batch and a
 * sustained run can be compared. Does not open a socket.
 */
static int run_soak(const uint32_t mid[8], const uint32_t w_be[16],
                    int seconds, int threads, double report_s) {
    if (seconds < 1) seconds = 1;
    if (report_s < 0.2) report_s = 0.2;
    const uint32_t chunk = 1u << 20;
    printf("\n=== SOAK (offline, no pool) ===\n");
    printf("SOAK_SECONDS=%d THREADS=%d REPORT_S=%.2f CHUNK=%u\n",
           seconds, threads, report_s, chunk);
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    uint64_t hashes = 0;
    uint64_t hashes_mark = 0;
    uint32_t nonce = 0;
    time_split_reset();
    double t0 = monotonic_seconds();
    double t_mark = t0;
    while (!g_stop) {
        double now = monotonic_seconds();
        if ((now - t0) >= (double)seconds) break;
        uint32_t found = 0;
        mine_midstate_n(mid, w_be, nonce, chunk, TARGET_NEVER, &found, threads);
        hashes += chunk;
        nonce += chunk;
        now = monotonic_seconds();
        if ((now - t_mark) >= report_s) {
            double idt = now - t_mark;
            double adt = now - t0;
            if (idt < 1e-9) idt = 1e-9;
            if (adt < 1e-9) adt = 1e-9;
            printf("SOAK t=%.1f hashes=%llu H/s=%.0f H/s_avg=%.0f threads=%d\n",
                   adt, (unsigned long long)hashes,
                   (double)(hashes - hashes_mark) / idt,
                   (double)hashes / adt, threads);
            fflush(stdout);
            t_mark = now;
            hashes_mark = hashes;
        }
    }
    double dt = monotonic_seconds() - t0;
    if (dt < 1e-9) dt = 1e-9;
    double hs = (double)hashes / dt;
    printf("SOAK_HASHES=%llu\n", (unsigned long long)hashes);
    printf("SOAK_ELAPSED_S=%.3f\n", dt);
    printf("SOAK_AVG_H/s=%.0f\n", hs);
    printf("H/s=%.0f\n", hs);
    printf("threads=%d\n", threads);
    time_split_print(dt);
    time_split_off();
    printf("RESULT: PASS\n");
    return 0;
}

/*
 * Testnet Stratum mine loop:
 *  connect → jobs → hash workers
 *  main thread polls the socket while workers hash, stages the next job's
 *  midstate on the side, and sends shares without waiting for the reply.
 *  TIME_SPLIT is printed with the summary.
 */

static void poll_accounted(stratum_client_t *c, int timeout_ms) {
    uint64_t w0 = c->poll_wait_ns;
    uint64_t b0 = c->poll_busy_ns;
    stratum_poll(c, timeout_ms);
    if (!time_split_on()) return;
    uint64_t dw = c->poll_wait_ns - w0;
    uint64_t db = c->poll_busy_ns - b0;
    if (g_in_flight) {
        g_overlap_poll_wait_ns += dw;
        g_overlap_poll_busy_ns += db;
    } else {
        /* No batch running: this poll stalls the next hash. */
        g_stall_poll_ns += dw + db;
    }
}
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

    printf("STRATUM: difficulty=%.8g\n", client.difficulty);

    work_buf_t active, staging;
    memset(&active, 0, sizeof active);
    memset(&staging, 0, sizeof staging);
    g_share_head = 0;
    g_share_tail = 0;
    if (prepare_work(&client, &active, 0) != 0) {
        printf("RESULT: FAIL (build_header)\n");
        stratum_close(&client);
        return 1;
    }
    printf("STRATUM: job id=%s clean=%d\n", active.job_id, active.clean);

    /* Long enough that a notify usually arrives mid-batch, so the next
     * midstate is built while workers are still hashing. */
    uint32_t scan_batch = 2u << 20;
    printf("STRATUM: scan_batch=%u threads=%d\n", scan_batch, threads);

    uint64_t hashes = 0;
    uint64_t staged_while_hashing = 0;
    int staged = 0;
    time_split_reset();
    double t0 = monotonic_seconds();
    double t_last_report = t0;
    scan_flight_t flight;
    memset(&flight, 0, sizeof flight);

    while (!g_stop) {
        double now = monotonic_seconds();
        if (seconds > 0 && (now - t0) >= (double)seconds) break;
        if (max_shares > 0 && (int)client.shares_accepted >= max_shares) break;

        if (!flight.running) {
            if (!active.ready && prepare_work(&client, &active, active.en2) != 0) {
                poll_accounted(&client, 50);
                continue;
            }
            if (scan_start(&flight, &active, scan_batch, threads) != 0) {
                fprintf(stderr, "STRATUM: scan_start failed\n");
                break;
            }
            g_in_flight = 1;
        }

        poll_accounted(&client, 20);
        share_q_flush(&client);

        {
            uint64_t cur_seq = staged ? staging.seq : active.seq;
            if (client.have_job && client.job.seq != cur_seq) {
                int clean = client.job.clean ? 1 : 0;
                int hashing = flight.running && !scan_done(&flight);
                if (clean)
                    atomic_store_explicit(&g_scan_cancel, 1, memory_order_relaxed);
                if (prepare_work(&client, &staging, 0) == 0) {
                    staged = 1;
                    if (hashing) staged_while_hashing++;
                    printf("STRATUM: staged job id=%s seq=%llu clean=%d while_hashing=%d\n",
                           staging.job_id, (unsigned long long)staging.seq,
                           staging.clean, hashing);
                    fflush(stdout);
                }
            }
        }

        if (flight.running && scan_done(&flight)) {
            scan_result_t sr;
            uint32_t batch_start = active.nonce_cursor;
            int abandoned = atomic_load_explicit(&g_scan_cancel, memory_order_relaxed);
            /* Workers have left the hash loop. Rebuilds and submits here
             * stall the next batch, so they belong in the stall buckets. */
            g_in_flight = 0;
            scan_join(&flight, &sr);
            hashes += sr.hashes;
            /* Hits were queued by the worker that found them, while the
             * other slices kept hashing. Flush anything still local. */
            if (sr.hit)
                printf("SHARE_CANDIDATE nonce=0x%08x en2=%llu job=%s\n",
                       sr.nonce, (unsigned long long)active.en2, active.job_id);
            share_q_flush(&client);

            if (staged) {
                active = staging;
                memset(&staging, 0, sizeof staging);
                staged = 0;
                active.nonce_cursor = 0;
                printf("STRATUM: switch job id=%s clean=%d (midstate already built)\n",
                       active.job_id, active.clean);
            } else if (abandoned) {
                active.ready = 0;
                active.nonce_cursor = 0;
                if (client.have_job && prepare_work(&client, &active, 0) == 0)
                    printf("STRATUM: resumed on job id=%s after clean cancel\n", active.job_id);
            } else if (sr.hit) {
                uint64_t en2 = active.en2 + 1;
                if (prepare_work(&client, &active, en2) != 0) {
                    fprintf(stderr, "STRATUM: rebuild after share failed\n");
                    break;
                }
            } else {
                uint64_t next = (uint64_t)batch_start + sr.hashes;
                if (sr.hashes == 0) next = (uint64_t)batch_start + scan_batch;
                /* batch_start + hashes is uint64, so wrap is next past 2^32.
                 * A uint32 comparison would promote and miss the wrap. */
                if (next >= 0x100000000ULL) {
                    uint64_t en2 = active.en2 + 1;
                    if (prepare_work(&client, &active, en2) != 0) break;
                } else {
                    active.nonce_cursor = batch_start + (uint32_t)sr.hashes;
                    stratum_share_target(client.difficulty, active.target);
                }
            }

            now = monotonic_seconds();
            if (g_stop) break;
            if (seconds > 0 && (now - t0) >= (double)seconds) break;
            if (max_shares > 0 && (int)client.shares_accepted >= max_shares) break;
            if (!active.ready) continue;
            if (scan_start(&flight, &active, scan_batch, threads) != 0) {
                fprintf(stderr, "STRATUM: scan_start failed\n");
                break;
            }
            g_in_flight = 1;
        }

        now = monotonic_seconds();
        if (now - t_last_report >= 2.0) {
            double dt = now - t0;
            double hs = (dt > 1e-9) ? (double)hashes / dt : 0.0;
            printf("STATUS connected=1 jobs=%llu hashes=%llu H/s=%.0f threads=%d "
                   "diff=%.8g shares_ok=%llu shares_bad=%llu pending=%d "
                   "staged_overlap=%llu en2=%llu\n",
                   (unsigned long long)client.jobs_seen,
                   (unsigned long long)hashes, hs, threads, client.difficulty,
                   (unsigned long long)client.shares_accepted,
                   (unsigned long long)client.shares_rejected,
                   client.submit_pending,
                   (unsigned long long)staged_while_hashing,
                   (unsigned long long)active.en2);
            fflush(stdout);
            t_last_report = now;
        }
    }

    g_in_flight = 0;
    if (flight.running) {
        atomic_store_explicit(&g_scan_cancel, 1, memory_order_relaxed);
        scan_result_t sr;
        scan_join(&flight, &sr);
        hashes += sr.hashes;
    }
    share_q_flush(&client);
    /* Reply wait is pool RTT. It stays in other_s, not submit_s or poll_s. */
    int pending_left = stratum_submit_drain(&client, 3000);

    double t1 = monotonic_seconds();
    double dt = t1 - t0;
    if (dt < 1e-9) dt = 1e-9;
    double hs = (double)hashes / dt;

    printf("\n=== TESTNET SUMMARY ===\n");
    printf("endpoint=%s:%d\n", host, port);
    printf("authorized=%d\n", (int)client.authorized);
    printf("jobs_seen=%llu\n", (unsigned long long)client.jobs_seen);
    printf("jobs_staged_while_hashing=%llu\n", (unsigned long long)staged_while_hashing);
    printf("difficulty=%.8g\n", client.difficulty);
    printf("hashes=%llu\n", (unsigned long long)hashes);
    printf("H/s=%.0f\n", hs);
    printf("threads=%d\n", threads);
    printf("shares_submitted=%llu\n", (unsigned long long)client.shares_submitted);
    printf("shares_accepted=%llu\n", (unsigned long long)client.shares_accepted);
    printf("shares_rejected=%llu\n", (unsigned long long)client.shares_rejected);
    printf("submit_pending=%d\n", pending_left);
    printf("elapsed_s=%.2f\n", dt);
    printf("expect_share_s@this_rate=%.2f\n",
           client.difficulty * 4294967296.0 / (hs > 1.0 ? hs : 1.0));
    time_split_print(dt);
    time_split_off();

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
        "  %s --soak SEC          offline multi-thread hash for SEC seconds\n"
        "                         prints H/s every --report interval (default 2s)\n"
        "  %s --threads N         worker count (default: P-cores or hw.ncpu)\n"
        "  %s --pin / --no-pin    macOS P-core QoS + affinity tags (default --pin)\n"
        "  %s --testnet           mine BTCLab testnet3 (suggest_diff=0.001)\n"
        "  %s --stratum HOST:PORT --user USER [--pass PASS] [--suggest-diff D]\n"
        "                         [--seconds N] [--max-shares N] [--threads N]\n"
        "\n"
        "Educational testnet only. No mainnet / AntPool.\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0);
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
    int soak_mode = 0;
    int soak_seconds = 0;
    double report_s = 2.0;

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
        } else if (strcmp(argv[i], "--soak") == 0 && i + 1 < argc) {
            soak_mode = 1;
            soak_seconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--report") == 0 && i + 1 < argc) {
            report_s = strtod(argv[++i], NULL);
        } else if (strcmp(argv[i], "--pin") == 0) {
            g_pin_cores = 1;
        } else if (strcmp(argv[i], "--no-pin") == 0) {
            g_pin_cores = 0;
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
    report_pin_policy(threads);

    if (soak_mode && (have_stratum || testnet_mode)) {
        fprintf(stderr, "--soak is offline and cannot be combined with --testnet/--stratum\n");
        return 2;
    }
    if (soak_mode && soak_seconds < 1) {
        fprintf(stderr, "--soak requires a positive number of seconds\n");
        return 2;
    }

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

    if (soak_mode)
        return run_soak(mid, w_be, soak_seconds, threads, report_s);

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
    time_split_reset();
    double t0 = monotonic_seconds();
    int hit = mine_midstate_n(mid, w_be, 0u, batch, TARGET_NEVER, &found, threads);
    double t1 = monotonic_seconds();
    double dt = t1 - t0;
    if (dt < 1e-9) dt = 1e-9;
    double hs = (double)batch / dt;
    printf("TIMING: hit=%d  elapsed=%.6f s  threads=%d  H/s=%.0f\n", hit, dt, threads, hs);
    printf("H/s=%.0f\n", hs);
    printf("threads=%d\n", threads);
    time_split_print(dt);
    time_split_off();

    printf("ENERGY_PLACEHOLDER_IDLE_W=na\n");
    printf("ENERGY_PLACEHOLDER_PKG_W=na\n");
    printf("ENERGY_PLACEHOLDER_W_PER_HASH=na\n");
    printf("ENERGY_PLACEHOLDER_J_PER_HASH=na\n");

    printf("RESULT: PASS\n");
    return 0;
}
