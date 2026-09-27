/*
 * harness.c — C only outside the hash path.
 * Tests, timing, metrics glue, threads, and optional testnet Stratum mining loop.
 * Hash path remains pure ARM64 asm (sha256d_mine.s). Workers call
 * _sha256d_mine_midstate on disjoint nonce ranges. Stratum share checks are a
 * target inequality, so that loop partitions the same way and hashes each
 * slice with the existing asm compress (sha256d_asm_one). A live share is
 * queued and the slice finishes; it does not cancel siblings or roll
 * extranonce2. TIME_SPLIT (mono_clock.h) accounts wall time around those calls.
 *
 * E7 (--dual-job on) is a formal experiment: two midstate slots stay live and
 * a worker whose slot runs dry claims the other one. Default --dual-job off
 * is the single-job path. The asm hash path is not rewritten.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/select.h>
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
/* E7. Default off: one live job, same as main. --dual-job on keeps two. */
static int g_dual_job = 0;
/* Set by the testnet loop so a clean_jobs notify stops stale hashing.
 * Not checked on every nonce: a share-path load here was pure overhead.
 * 256 nonces is a few tens of microseconds at live rates. */
#define SCAN_CANCEL_EVERY 256u
static _Atomic int g_scan_cancel = 0;
static _Atomic int g_scan_finished = 0;
/* Last finishing scan worker writes one byte. Main select watches the
 * read end together with the Stratum socket. -1 until the pipe is open. */
static int g_batch_wake_r = -1;
static int g_batch_wake_w = -1;

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
 *   other_s = the rest of the wall clock.
 *
 * TIME_SPLIT_GAPS partitions other_s (same clock). Those fields plus the
 * non-other TIME_SPLIT buckets sum to elapsed wall. unexplained_s is the
 * residual. Flight is [first worker t_start, last worker t_end]. The gap
 * flight_s << elapsed_s is everything outside those intervals:
 *   batch_setup_s  — decide to start a batch until the first worker is
 *                    about to enter the hash loop (range split, spawn, pin)
 *   teardown_s     — last worker left the hash loop until join has collected
 *                    results, plus full-batch bookkeeping before the next
 *                    start. The in-flight select also watches a self-pipe
 *                    the last worker writes, so this tail is wakeup latency
 *                    rather than the rest of the poll timeout.
 *   share_restart_s — extra wall after that join when a short batch (a slice
 *                    stopped before its assignment) rolls extranonce2.
 *                    A live share that finishes the slice does not (stall
 *                    midstate/submit removed)
 *   cancel_restart_s — same, when clean_jobs / cancel resumes work
 *   end_drain_s    — stratum_submit_drain after hashing has stopped
 *   status_s       — status/soak printf while no batch is in flight
 *
 * TIME_SPLIT_OVERLAP is main-thread poll / midstate / submit that ran
 * while a batch was in flight. It is concurrent with hash and is not
 * part of the 100% line. A poll that straddles worker exit still lands
 * entirely in OVERLAP; the post-exit tail is also in teardown_s.
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

/*
 * Gap buckets are main-thread only (workers publish t_start_ns / t_end_ns;
 * the main thread reads them after join). No lock on the nonce loop.
 * wake_s + join_s split the join-side part of teardown; they are not added
 * again on the 100% line. wake_s ends when the self-pipe wakes select.
 */
static uint64_t g_gap_setup_ns;
static uint64_t g_gap_teardown_ns;
static uint64_t g_gap_share_restart_ns;
static uint64_t g_gap_cancel_restart_ns;
static uint64_t g_gap_end_drain_ns;
static uint64_t g_gap_status_ns;
static uint64_t g_gap_wake_ns;
static uint64_t g_gap_join_ns;
static uint64_t g_batches_started;
static uint64_t g_batches_early_share;
static uint64_t g_batches_early_clean;
static uint64_t g_batches_full;
static uint64_t g_flight_spans;
static uint64_t g_flight_hashes;

/* Open across the post-join restart block in the testnet loop. Main thread. */
static int g_restart_open;
static uint64_t g_restart_t0;
static uint64_t g_restart_mid0;
static uint64_t g_restart_sub0;
static uint64_t g_restart_poll0;

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
    g_gap_setup_ns = 0;
    g_gap_teardown_ns = 0;
    g_gap_share_restart_ns = 0;
    g_gap_cancel_restart_ns = 0;
    g_gap_end_drain_ns = 0;
    g_gap_status_ns = 0;
    g_gap_wake_ns = 0;
    g_gap_join_ns = 0;
    g_batches_started = 0;
    g_batches_early_share = 0;
    g_batches_early_clean = 0;
    g_batches_full = 0;
    g_flight_spans = 0;
    g_flight_hashes = 0;
    g_restart_open = 0;
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

static void add_flight_wall(uint64_t lo, uint64_t hi) {
    if (hi > lo) {
        g_flight_wall_ns += hi - lo;
        g_flight_spans++;
    }
}

/* Exclusive pre-flight setup and post-flight join. have_notice splits the
 * tail into poll-wake (workers already stopped, main has not joined yet)
 * and pthread_join. Both are inside teardown_s. */
static void gap_add_batch_edges(uint64_t t_decide, uint64_t t_after,
                                uint64_t lo, uint64_t hi,
                                uint64_t t_notice, int have_notice) {
    if (!time_split_on()) return;
    if (t_decide && lo != UINT64_MAX && hi >= lo && lo > t_decide)
        g_gap_setup_ns += lo - t_decide;
    if (!t_after || hi == 0 || lo == UINT64_MAX || t_after <= hi) return;
    uint64_t tail = t_after - hi;
    g_gap_teardown_ns += tail;
    if (have_notice && t_notice > hi) {
        g_gap_wake_ns += t_notice - hi;
        if (t_after > t_notice)
            g_gap_join_ns += t_after - t_notice;
    } else {
        g_gap_join_ns += tail;
    }
}

static void batch_count_begin(void) {
    if (time_split_on()) g_batches_started++;
}

/* early_clean wins over early_share. A full nonce assignment is full even
 * if a share landed on the last nonce. */
static void batch_count_end(int early_share, int early_clean) {
    if (!time_split_on()) return;
    if (early_clean) g_batches_early_clean++;
    else if (early_share) g_batches_early_share++;
    else g_batches_full++;
}

static void restart_window_open(void) {
    if (!time_split_on()) {
        g_restart_open = 0;
        return;
    }
    g_restart_t0 = mono_ns();
    g_restart_mid0 = g_stall_mid_ns;
    g_restart_sub0 = g_stall_submit_ns;
    g_restart_poll0 = g_stall_poll_ns;
    g_restart_open = 1;
}

/* kind: 0 full-batch bookkeeping (folded into teardown), 1 share, 2 cancel.
 * Stall poll/mid/submit inside the window stays in those buckets. */
static void restart_window_close(int kind) {
    if (!g_restart_open) return;
    g_restart_open = 0;
    uint64_t t1 = mono_ns();
    uint64_t dt = t1 > g_restart_t0 ? t1 - g_restart_t0 : 0;
    uint64_t stall = (g_stall_mid_ns - g_restart_mid0)
                   + (g_stall_submit_ns - g_restart_sub0)
                   + (g_stall_poll_ns - g_restart_poll0);
    uint64_t gap = dt > stall ? dt - stall : 0;
    if (gap == 0) return;
    if (kind == 1) g_gap_share_restart_ns += gap;
    else if (kind == 2) g_gap_cancel_restart_ns += gap;
    else g_gap_teardown_ns += gap;
}

static void status_account_begin(uint64_t *t0, int *on) {
    *on = time_split_on() && !g_in_flight;
    *t0 = *on ? mono_ns() : 0;
}

static void status_account_end(uint64_t t0, int on) {
    if (!on || !t0) return;
    uint64_t t1 = mono_ns();
    if (t1 > t0) g_gap_status_ns += t1 - t0;
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

    double setup_s = ns_to_s(g_gap_setup_ns);
    double teardown_s = ns_to_s(g_gap_teardown_ns);
    double share_restart_s = ns_to_s(g_gap_share_restart_ns);
    double cancel_restart_s = ns_to_s(g_gap_cancel_restart_ns);
    double end_drain_s = ns_to_s(g_gap_end_drain_ns);
    double status_s = ns_to_s(g_gap_status_ns);
    double named = setup_s + teardown_s + share_restart_s + cancel_restart_s
                 + end_drain_s + status_s;
    double unexplained_s = other_s - named;
    if (unexplained_s < 0.0) {
        /* Mono vs CLOCK_MONOTONIC sliver. Trim the largest gap so this line
         * still partitions other_s and the percentages add to 100. */
        double overflow = -unexplained_s;
        double *parts[6] = {
            &setup_s, &teardown_s, &share_restart_s,
            &cancel_restart_s, &end_drain_s, &status_s
        };
        for (int n = 0; n < 6 && overflow > 1e-12; n++) {
            int k = 0;
            for (int i = 1; i < 6; i++)
                if (*parts[i] > *parts[k]) k = i;
            double cut = *parts[k] < overflow ? *parts[k] : overflow;
            *parts[k] -= cut;
            overflow -= cut;
            if (*parts[k] <= 0.0 && cut <= 0.0) break;
        }
        unexplained_s = other_s - (setup_s + teardown_s + share_restart_s
                                   + cancel_restart_s + end_drain_s + status_s);
        if (unexplained_s < 0.0) unexplained_s = 0.0;
    }

    printf("TIME_SPLIT_GAPS batch_setup_s=%.4f teardown_s=%.4f share_restart_s=%.4f "
           "cancel_restart_s=%.4f end_drain_s=%.4f status_s=%.4f unexplained_s=%.4f\n",
           setup_s, teardown_s, share_restart_s, cancel_restart_s,
           end_drain_s, status_s, unexplained_s);
    printf("TIME_SPLIT_GAPS_PCT batch_setup=%.2f teardown=%.2f share_restart=%.2f "
           "cancel_restart=%.2f end_drain=%.2f status=%.2f unexplained=%.2f\n",
           setup_s * pct, teardown_s * pct, share_restart_s * pct,
           cancel_restart_s * pct, end_drain_s * pct, status_s * pct,
           unexplained_s * pct);
    printf("TIME_SPLIT_GAPS_DETAIL wake_s=%.4f join_s=%.4f\n",
           ns_to_s(g_gap_wake_ns), ns_to_s(g_gap_join_ns));
    {
        double avg_flight = g_flight_spans ? flight / (double)g_flight_spans : 0.0;
        double hpf = g_batches_started
                         ? (double)g_flight_hashes / (double)g_batches_started
                         : 0.0;
        printf("BATCHES started=%llu early_share=%llu early_clean=%llu full=%llu "
               "avg_flight_s=%.4f hashes_per_flight=%.0f\n",
               (unsigned long long)g_batches_started,
               (unsigned long long)g_batches_early_share,
               (unsigned long long)g_batches_early_clean,
               (unsigned long long)g_batches_full,
               avg_flight, hpf);
    }
}

#ifdef __APPLE__
static int apple_sysctl_int(const char *name) {
    int n = 0;
    size_t sz = sizeof n;
    if (sysctlbyname(name, &n, &sz, NULL, 0) != 0 || n <= 0)
        return 0;
    return n;
}

/* P-core count. 0 if the sysctl is missing (not Apple Silicon perf levels). */
static int perflevel0_physicalcpu(void) {
    static int cached = -1;
    if (cached < 0)
        cached = apple_sysctl_int("hw.perflevel0.physicalcpu");
    return cached;
}

/*
 * Slots below the P-core count ask for performance cores. Further slots ask
 * for QOS_CLASS_UTILITY, which the scheduler may place on efficiency cores.
 * USER_INTERACTIVE on every worker oversubscribes the P cluster and fights
 * the point of a hw.physicalcpu default. More cores, possibly worse W/hash.
 */
static qos_class_t worker_qos_for_index(int index) {
    int pcores = perflevel0_physicalcpu();
    if (pcores > 0 && index >= pcores)
        return QOS_CLASS_UTILITY;
    return QOS_CLASS_USER_INTERACTIVE;
}
#endif

/*
 * Pin one mining thread.
 * macOS has no public "bind to CPU index" API. Two documented knobs:
 *   1. pthread_set_qos_class_self_np — USER_INTERACTIVE prefers P-cores;
 *      UTILITY is used once the worker slot is past hw.perflevel0.physicalcpu
 *      so those workers can run on E-cores.
 *   2. thread_policy_set(THREAD_AFFINITY_POLICY) with a non-zero tag —
 *      threads that share a tag prefer the same L2 cache; distinct tags
 *      (1..N, one per worker) ask the scheduler to spread them.
 * Tag 0 means "no affinity", so tags start at 1. index is the worker slot.
 */
static void apply_worker_pin(int index) {
#ifdef __APPLE__
    if (!g_pin_cores) return;
    if (index < 0) index = 0;
    (void)pthread_set_qos_class_self_np(worker_qos_for_index(index), 0);
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
    int pcores = perflevel0_physicalcpu();
    int eworkers = (pcores > 0 && threads > pcores) ? threads - pcores : 0;
    int qos_rc = pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    thread_affinity_policy_data_t pol;
    pol.affinity_tag = 1;
    thread_port_t th = pthread_mach_thread_np(pthread_self());
    kern_return_t aff_rc = thread_policy_set(th, THREAD_AFFINITY_POLICY,
                                              (thread_policy_t)&pol,
                                              THREAD_AFFINITY_POLICY_COUNT);
    printf("PIN=on\n");
    if (eworkers > 0) {
        fprintf(stderr,
                "PIN_METHOD=slots<P QOS_CLASS_USER_INTERACTIVE; slots>=P QOS_CLASS_UTILITY; "
                "THREAD_AFFINITY_POLICY tags=1..%d\n"
                "PIN_QOS_RC=%d PIN_AFFINITY_RC=%d PIN_PCORES=%d PIN_EWORKERS=%d\n"
                "PIN_NOTE=First %d workers request performance cores. The other %d request "
                "QOS_CLASS_UTILITY so they can run on efficiency cores. Feeding E-cores "
                "raises H/s and can worsen W/hash. Not a hard CPU-index pin.\n",
                threads, qos_rc, (int)aff_rc, pcores, eworkers, pcores, eworkers);
    } else {
        fprintf(stderr,
                "PIN_METHOD=QOS_CLASS_USER_INTERACTIVE + THREAD_AFFINITY_POLICY tags=1..%d\n"
                "PIN_QOS_RC=%d PIN_AFFINITY_RC=%d PIN_PCORES=%d PIN_EWORKERS=0\n"
                "PIN_NOTE=QoS requests performance cores; distinct affinity tags spread workers. "
                "Not a hard CPU-index pin (no public API for that).\n",
                threads, qos_rc, (int)aff_rc, pcores);
    }
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

/*
 * All physical CPUs, else hw.ncpu, else online processors.
 * On Apple Silicon hw.physicalcpu is P+E (8 on MacBookPro18,3: 6P+2E).
 * hw.perflevel0.physicalcpu is P-cores only and is not the default.
 * --threads N still overrides this.
 */
static int default_thread_count(const char **src) {
#ifdef __APPLE__
    int n = apple_sysctl_int("hw.physicalcpu");
    if (n > 0) {
        if (src) *src = "default hw.physicalcpu";
        return clamp_threads(n);
    }
    n = apple_sysctl_int("hw.ncpu");
    if (n > 0) {
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
    int wake_n;            /* signal the self-pipe when finished reaches this */
    /* Live Stratum scan sets job_id and stop_on_share=0: each hit is queued
     * from this worker and the slice finishes its nonce range. The synchronous
     * selftest scan leaves job_id NULL and sets stop_on_share so early_share
     * stays armed. Siblings are not cancelled by a share either way. */
    const char *job_id;
    const char *ntime;
    uint64_t en2;
    int stop_on_share;
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

static void batch_wake_drain(void) {
    int fd = g_batch_wake_r;
    if (fd < 0) return;
    char buf[64];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n > 0) continue;
        if (n < 0 && errno == EINTR) continue;
        return;
    }
}

/* One pipe for the process. O_NONBLOCK so the last worker never stalls
 * if the main thread has not drained a previous byte. */
static int batch_wake_open(void) {
    if (g_batch_wake_r >= 0) return 0;
    int fds[2];
    if (pipe(fds) != 0) return -1;
    for (int i = 0; i < 2; i++) {
        int fl = fcntl(fds[i], F_GETFL, 0);
        if (fl < 0 || fcntl(fds[i], F_SETFL, fl | O_NONBLOCK) != 0) {
            close(fds[0]);
            close(fds[1]);
            return -1;
        }
    }
    g_batch_wake_r = fds[0];
    g_batch_wake_w = fds[1];
    return 0;
}

static void batch_wake_signal(void) {
    int fd = g_batch_wake_w;
    if (fd < 0) return;
    char b = 1;
    for (;;) {
        ssize_t n = write(fd, &b, 1);
        if (n == 1) return;
        if (n < 0 && errno == EINTR) continue;
        return;
    }
}

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
    uint32_t msw[8];
    if (timing) {
        s->t_start_ns = mono_ns();
        t_enter = mono_ticks();
    }
    /* Once per slice. The hot path compares one bswapped word, then the
     * rest of the target only when that word ties. */
    stratum_target_msw(s->target, msw);

    for (uint32_t i = 0; i < s->nonce_count; i++) {
        if ((i & (SCAN_CANCEL_EVERY - 1u)) == 0 &&
            (g_stop || atomic_load_explicit(&g_scan_cancel, memory_order_relaxed)))
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
        if (__builtin_expect(stratum_hash_meets_target_msw(dig, msw), 0)) {
            /* Nonces are scanned in order, so the first hit is the earliest. */
            if (!s->hit) {
                s->hit = 1;
                s->found = nonce;
            }
            if (s->job_id) {
                if (timing) {
                    uint64_t d0 = mono_ticks();
                    (void)share_q_push(s->job_id, s->ntime, s->en2, nonce);
                    submit_ticks += mono_ticks() - d0;
                } else {
                    (void)share_q_push(s->job_id, s->ntime, s->en2, nonce);
                }
            }
            if (s->stop_on_share)
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

    if (s->finished) {
        /* t_end_ns is already stored. The release add publishes it.
         * Only the worker that brings the count to wake_n writes the
         * pipe, after that add, so select cannot wake early. */
        int nfin = atomic_fetch_add_explicit(s->finished, 1, memory_order_release) + 1;
        if (s->wake_n > 0 && nfin == s->wake_n)
            batch_wake_signal();
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

static void account_mine_slices(const mine_slice_t *s, int n,
                                uint64_t *lo_out, uint64_t *hi_out) {
    uint64_t lo = UINT64_MAX;
    uint64_t hi = 0;
    int any = 0;
    if (time_split_on() && n >= 1) {
        for (int i = 0; i < n; i++) {
            if (!s[i].timed) continue;
            any = 1;
            if (s[i].t_start_ns < lo) lo = s[i].t_start_ns;
            if (s[i].t_end_ns > hi) hi = s[i].t_end_ns;
            g_cpu_hash_ticks += s[i].hash_ticks;
        }
        if (any) add_flight_wall(lo, hi);
    }
    if (!any) {
        lo = UINT64_MAX;
        hi = 0;
    }
    if (lo_out) *lo_out = lo;
    if (hi_out) *hi_out = hi;
}

static void account_scan_slices(const scan_slice_t *s, int n,
                                uint64_t *lo_out, uint64_t *hi_out) {
    uint64_t lo = UINT64_MAX;
    uint64_t hi = 0;
    int any = 0;
    if (time_split_on() && n >= 1) {
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
        if (any) add_flight_wall(lo, hi);
    }
    if (!any) {
        lo = UINT64_MAX;
        hi = 0;
    }
    if (lo_out) *lo_out = lo;
    if (hi_out) *hi_out = hi;
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
    uint64_t t_decide = time_split_on() ? mono_ns() : 0;
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
        batch_count_begin();
        uint64_t t_start = mono_ns();
        uint64_t a = mono_ticks();
        int hit = sha256d_mine_midstate(mid, w_be, nonce_start, nonce_count,
                                        expect, found_nonce);
        g_cpu_hash_ticks += mono_ticks() - a;
        uint64_t t_end = mono_ns();
        add_flight_wall(t_start, t_end);
        uint64_t t_after = mono_ns();
        gap_add_batch_edges(t_decide, t_after, t_start, t_end, 0, 0);
        g_flight_hashes += nonce_count;
        batch_count_end(0, 0);
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
    batch_count_begin();
    run_workers(used, mine_slice_worker, slices, sizeof slices[0]);
    uint64_t t_after = time_split_on() ? mono_ns() : 0;
    uint64_t lo = UINT64_MAX, hi = 0;
    account_mine_slices(slices, used, &lo, &hi);
    gap_add_batch_edges(t_decide, t_after, lo, hi, 0, 0);
    if (time_split_on()) {
        g_flight_hashes += nonce_count;
        batch_count_end(0, 0);
    }

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
    uint64_t t_decide = time_split_on() ? mono_ns() : 0;
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
        slices[i].wake_n = 0;
        slices[i].job_id = NULL;
        slices[i].ntime = NULL;
        slices[i].en2 = 0;
        /* First-hit stop keeps the synchronous selftest's early_share
         * counter armed. Live scan_start finishes the range instead. */
        slices[i].stop_on_share = 1;
        slices[i].timed = 0;
        slices[i].t_start_ns = 0;
        slices[i].t_end_ns = 0;
        slices[i].hash_ticks = 0;
        slices[i].share_ticks = 0;
        slices[i].submit_ticks = 0;
    }
    batch_count_begin();
    if (used <= 1) {
        scan_slice_worker(&slices[0]);
    } else {
        run_workers(used, scan_slice_worker, slices, sizeof slices[0]);
    }
    uint64_t t_after = time_split_on() ? mono_ns() : 0;
    uint64_t lo = UINT64_MAX, hi = 0;
    account_scan_slices(slices, used, &lo, &hi);
    gap_add_batch_edges(t_decide, t_after, lo, hi, 0, 0);

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
    if (time_split_on()) {
        g_flight_hashes += r.hashes;
        /* stop_on_share cuts this scan short on a hit. The batch is "early"
         * when the assignment was not fully hashed. No separate restart gap
         * here: the caller returns. Testnet restart time is measured in the loop. */
        batch_count_end(r.hit && r.hashes < nonce_count, 0);
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

static int dual_mine_span(const uint32_t mid[8], const uint32_t w_be[16],
                          uint32_t nonce_start, uint32_t nonce_count,
                          const uint32_t expect[8], uint32_t *found_nonce,
                          int threads);
static int selftest_dual_job(int threads);

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
    int hit = g_dual_job
        ? dual_mine_span(mid, w_be, 0u, batch, TARGET_NEVER, &found, threads)
        : mine_midstate_n(mid, w_be, 0u, batch, TARGET_NEVER, &found, threads);
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

static int selftest_target_equiv(void);
static int selftest_share_continue(int threads);
static int selftest_batch_wake(int threads);

/* Byte walk kept only as the oracle for the word compare. */
static int share_meets_ref(const uint32_t digest_words[8], const uint8_t target_be[32]) {
    uint8_t hash[32];
    for (int i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (uint8_t)(digest_words[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(digest_words[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(digest_words[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(digest_words[i]);
    }
    for (int i = 31; i >= 0; i--) {
        uint8_t hb = hash[i];
        uint8_t tb = target_be[31 - i];
        if (hb < tb) return 1;
        if (hb > tb) return 0;
    }
    return 1;
}

static void digest_as_target(const uint32_t dig[8], uint8_t target_be[32]) {
    uint8_t hash[32];
    for (int i = 0; i < 8; i++)
        store_be32(hash + i * 4, dig[i]);
    for (int i = 0; i < 32; i++)
        target_be[31 - i] = hash[i];
}

static int expect_meet(const char *what, const uint32_t dig[8], const uint8_t target[32]) {
    int ref = share_meets_ref(dig, target);
    int got = stratum_hash_meets_target(dig, target) ? 1 : 0;
    uint32_t msw[8];
    stratum_target_msw(target, msw);
    int got_msw = stratum_hash_meets_target_msw(dig, msw) ? 1 : 0;
    if (ref != got || ref != got_msw) {
        printf("SELFTEST: FAIL (target equiv %s ref=%d got=%d msw=%d)\n",
               what, ref, got, got_msw);
        return 1;
    }
    return 0;
}

static int selftest_target_equiv(void) {
    uint32_t dig[8];
    uint8_t target[32];
    int n = 0;

    memset(dig, 0, sizeof dig);
    memset(target, 0, sizeof target);
    if (expect_meet("zero", dig, target)) return 1;
    n++;

    memset(target, 0xff, sizeof target);
    if (expect_meet("zero-hash-all-target", dig, target)) return 1;
    n++;

    memset(dig, 0xff, sizeof dig);
    memset(target, 0, sizeof target);
    if (expect_meet("all-hash-zero-target", dig, target)) return 1;
    n++;

    memset(target, 0xff, sizeof target);
    if (expect_meet("all", dig, target)) return 1;
    n++;

    /* Top words equal, only the last target byte decides. */
    memset(dig, 0, sizeof dig);
    memset(target, 0, sizeof target);
    target[31] = 1;
    if (expect_meet("tail-hit", dig, target)) return 1;
    n++;
    dig[0] = 0x02000000u;
    if (expect_meet("tail-miss", dig, target)) return 1;
    n++;
    dig[0] = 0x01000000u;
    if (expect_meet("tail-eq", dig, target)) return 1;
    n++;

    /* diff1: top word is 0, so the fast path must fall through to word 1. */
    {
        const double diffs[] = {0.001, 0.16, 1.0, 16384.0, 1e-6};
        uint32_t state = 0xC0FFEEu;
        for (unsigned di = 0; di < sizeof diffs / sizeof diffs[0]; di++) {
            stratum_share_target(diffs[di], target);
            memset(dig, 0, sizeof dig);
            if (expect_meet("diff-zero-hash", dig, target)) return 1;
            n++;
            for (int k = 0; k < 64; k++) {
                for (int w = 0; w < 8; w++) {
                    state = state * 1664525u + 1013904223u;
                    dig[w] = state;
                }
                char label[64];
                snprintf(label, sizeof label, "diff %.8g n=%d", diffs[di], n);
                if (expect_meet(label, dig, target)) return 1;
                n++;
            }
            /* Hash equal to this target, then one step above and below
             * the top byte, so both the tie path and the first-word
             * reject are checked against the byte oracle. */
            digest_as_target(dig, target);
            if (expect_meet("equal-hash", dig, target)) return 1;
            n++;
            target[0] ^= 0x80u;
            if (expect_meet("top-byte-flip", dig, target)) return 1;
            n++;
        }
    }

    printf("SELFTEST: share target equiv OK (cases=%d)\n", n);
    return 0;
}

static int run_selftest(int threads) {
    if (selftest_partition() != 0)
        return 1;
    if (selftest_target_equiv() != 0)
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
    if (selftest_share_continue(1) != 0)
        return 1;
    if (threads != 1 && selftest_share_continue(threads) != 0)
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
    if (g_gap_setup_ns == 0 || g_gap_teardown_ns == 0 ||
        g_batches_started == 0 || g_batches_full == 0 ||
        g_batches_early_share == 0) {
        printf("SELFTEST: FAIL (TIME_SPLIT_GAPS empty setup_ns=%llu teardown_ns=%llu "
               "started=%llu full=%llu early_share=%llu)\n",
               (unsigned long long)g_gap_setup_ns,
               (unsigned long long)g_gap_teardown_ns,
               (unsigned long long)g_batches_started,
               (unsigned long long)g_batches_full,
               (unsigned long long)g_batches_early_share);
        return 1;
    }
    printf("SELFTEST: TIME_SPLIT_GAPS counters armed\n");
    if (selftest_batch_wake(1) != 0)
        return 1;
    if (threads != 1 && selftest_batch_wake(threads) != 0)
        return 1;
    if (selftest_dual_job(threads) != 0)
        return 1;
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
    uint64_t t_decide_ns;
    uint64_t t_notice_ns;
    uint32_t assigned;
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
    {
        uint64_t lo = UINT64_MAX, hi = 0;
        account_scan_slices(f->slices, f->n, &lo, &hi);
        uint64_t t_after = time_split_on() ? mono_ns() : 0;
        int have_notice = f->t_notice_ns != 0;
        gap_add_batch_edges(f->t_decide_ns, t_after, lo, hi,
                            f->t_notice_ns, have_notice);
        if (time_split_on()) {
            int abandoned = atomic_load_explicit(&g_scan_cancel, memory_order_relaxed);
            int short_batch = f->assigned > 0 && r->hashes < f->assigned;
            g_flight_hashes += r->hashes;
            batch_count_end(r->hit && short_batch && !abandoned,
                            abandoned && short_batch);
        }
    }
    f->running = 0;
    f->n = 0;
}

/* Background share scan. Main keeps the socket. Returns 0, or -1 if no thread. */
static int scan_start(scan_flight_t *f, const work_buf_t *w, uint32_t count, int threads) {
    uint64_t t_decide = time_split_on() ? mono_ns() : 0;
    memset(f, 0, sizeof *f);
    f->t_decide_ns = t_decide;
    f->assigned = count;
    if (!w->ready || count == 0) return -1;
    threads = clamp_threads(threads);
    uint32_t starts[MAX_MINE_THREADS];
    uint32_t counts[MAX_MINE_THREADS];
    int used = partition_nonce_ranges(w->nonce_cursor, count, threads, starts, counts);
    if (used < 1) return -1;

    atomic_store_explicit(&g_scan_cancel, 0, memory_order_relaxed);
    atomic_store_explicit(&g_scan_finished, 0, memory_order_relaxed);
    /* Drop a byte from the previous batch before anyone new can write. */
    batch_wake_drain();

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
        s->wake_n = used;
        s->job_id = w->job_id;
        s->ntime = w->ntime;
        s->en2 = w->en2;
        s->stop_on_share = 0;
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
    batch_count_begin();
    return 0;
}

static int scan_done(const scan_flight_t *f) {
    if (!f->running) return 1;
    return atomic_load_explicit(&g_scan_finished, memory_order_acquire) >= f->n;
}

/* Live path: one real hit inside the range, and every nonce still hashed.
 * Target is the minimum hash in the window, so later nonces miss and the
 * queue gets that one share. stop_on_share is off (scan_start). */
static int selftest_share_continue(int threads) {
    uint32_t mid[8], w_be[16];
    compute_midstate(mid, GENESIS_HEADER);
    build_block1_wbe(w_be, GENESIS_HEADER);

    const uint32_t count = 48;
    uint32_t start = 0;
    uint32_t best = 0;
    uint32_t best_dig[8];
    uint8_t target[32];
    int guard = 0;
    for (;;) {
        sha256d_asm_one(mid, w_be, start, best_dig);
        best = start;
        digest_as_target(best_dig, target);
        for (uint32_t n = 1; n < count; n++) {
            uint32_t dig[8];
            uint8_t back[32];
            sha256d_asm_one(mid, w_be, start + n, dig);
            if (!stratum_hash_meets_target(dig, target))
                continue;
            digest_as_target(dig, back);
            if (stratum_hash_meets_target(best_dig, back))
                continue; /* tie: keep the earlier nonce */
            memcpy(best_dig, dig, sizeof best_dig);
            best = start + n;
            memcpy(target, back, sizeof target);
        }
        /* The hit has to sit strictly inside its slice. Otherwise stopping
         * at the share still hashes the full assignment and this test
         * cannot see the difference. One thread is the strict case. */
        int interior = 0;
        if (best + 1u < start + count) {
            uint32_t pst[MAX_MINE_THREADS];
            uint32_t pcn[MAX_MINE_THREADS];
            int used = partition_nonce_ranges(start, count, clamp_threads(threads), pst, pcn);
            for (int si = 0; si < used; si++) {
                if (pcn[si] < 2) continue;
                uint32_t last = pst[si] + pcn[si] - 1u;
                if (best >= pst[si] && best < last) {
                    interior = 1;
                    break;
                }
            }
            if (interior || threads <= 1)
                break;
        }
        start += 3u;
        if (++guard > 8) {
            if (threads <= 1) {
                printf("SELFTEST: FAIL (share continue no interior hit)\n");
                return 1;
            }
            break;
        }
    }

    work_buf_t w;
    memset(&w, 0, sizeof w);
    memcpy(w.mid, mid, sizeof w.mid);
    memcpy(w.w_be, w_be, sizeof w.w_be);
    memcpy(w.target, target, sizeof w.target);
    snprintf(w.job_id, sizeof w.job_id, "cont");
    snprintf(w.ntime, sizeof w.ntime, "00000000");
    w.nonce_cursor = start;
    w.ready = 1;

    pthread_mutex_lock(&g_share_mu);
    g_share_head = 0;
    g_share_tail = 0;
    pthread_mutex_unlock(&g_share_mu);

    scan_flight_t flight;
    if (scan_start(&flight, &w, count, threads) != 0) {
        printf("SELFTEST: FAIL (share continue scan_start threads=%d)\n", threads);
        return 1;
    }
    if (time_split_on())
        flight.t_notice_ns = mono_ns();
    scan_result_t sr;
    scan_join(&flight, &sr);

    int queued = 0;
    int queued_best = 0;
    pthread_mutex_lock(&g_share_mu);
    for (int i = g_share_head; i != g_share_tail; i = (i + 1) % SHARE_Q) {
        queued++;
        if (g_share_q[i].nonce == best)
            queued_best = 1;
    }
    g_share_head = 0;
    g_share_tail = 0;
    pthread_mutex_unlock(&g_share_mu);

    if (!sr.hit || sr.nonce != best || sr.hashes != count || !queued_best) {
        printf("SELFTEST: FAIL (share continue threads=%d hit=%d nonce=%08x exp=%08x "
               "hashes=%llu queued=%d)\n",
               threads, sr.hit, sr.nonce, best,
               (unsigned long long)sr.hashes, queued);
        return 1;
    }
    printf("SELFTEST: share continue OK (threads=%d nonce=%08x hashes=%llu queued=%d)\n",
           threads, best, (unsigned long long)sr.hashes, queued);
    return 0;
}

/* Last worker must wake a blocked stratum_poll_wake well inside the
 * timeout, and a later socket byte must still be delivered. */
static int selftest_batch_wake(int threads) {
    if (batch_wake_open() != 0) {
        printf("SELFTEST: FAIL (wake pipe)\n");
        return 1;
    }
    batch_wake_drain();

    int sv[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        printf("SELFTEST: FAIL (wake socketpair errno=%d)\n", errno);
        return 1;
    }
    int fl = fcntl(sv[0], F_GETFL, 0);
    if (fl < 0 || fcntl(sv[0], F_SETFL, fl | O_NONBLOCK) != 0) {
        close(sv[0]);
        close(sv[1]);
        printf("SELFTEST: FAIL (wake socket flags)\n");
        return 1;
    }

    stratum_client_t client;
    memset(&client, 0, sizeof client);
    client.fd = sv[0];

    work_buf_t w;
    memset(&w, 0, sizeof w);
    compute_midstate(w.mid, GENESIS_HEADER);
    build_block1_wbe(w.w_be, GENESIS_HEADER);
    memset(w.target, 0, sizeof w.target);
    snprintf(w.job_id, sizeof w.job_id, "wake");
    snprintf(w.ntime, sizeof w.ntime, "00000000");
    w.ready = 1;

    scan_flight_t flight;
    memset(&flight, 0, sizeof flight);
    if (scan_start(&flight, &w, 32, threads) != 0) {
        close(sv[0]);
        close(sv[1]);
        printf("SELFTEST: FAIL (wake scan_start threads=%d)\n", threads);
        return 1;
    }

    int woke = 0;
    uint64_t t0 = mono_ns();
    int rc = stratum_poll_wake(&client, 2000, g_batch_wake_r, &woke);
    uint64_t dt = mono_ns() - t0;
    int done = scan_done(&flight);
    int failed = 0;
    if (rc < 0 || !woke || !done || dt >= 1500000000ULL) {
        printf("SELFTEST: FAIL (wake poll rc=%d woke=%d done=%d dt_us=%llu threads=%d)\n",
               rc, woke, done, (unsigned long long)(dt / 1000ull), threads);
        failed = 1;
        atomic_store_explicit(&g_scan_cancel, 1, memory_order_relaxed);
    } else {
        char ping = '\n';
        if (write(sv[1], &ping, 1) != 1) {
            printf("SELFTEST: FAIL (wake socket write errno=%d)\n", errno);
            failed = 1;
        } else {
            woke = 0;
            rc = stratum_poll_wake(&client, 2000, g_batch_wake_r, &woke);
            /* A lone newline is an empty line. Socket must report data
             * and the already-drained pipe must not look like another wake. */
            if (rc != 1 || woke) {
                printf("SELFTEST: FAIL (wake socket rc=%d woke=%d threads=%d)\n",
                       rc, woke, threads);
                failed = 1;
            }
        }
    }

    if (flight.running) {
        if (time_split_on())
            flight.t_notice_ns = mono_ns();
        scan_result_t sr;
        scan_join(&flight, &sr);
        if (!failed && sr.hashes != 32) {
            printf("SELFTEST: FAIL (wake hashes=%llu threads=%d)\n",
                   (unsigned long long)sr.hashes, threads);
            failed = 1;
        }
    } else if (!failed) {
        printf("SELFTEST: FAIL (wake flight not running)\n");
        failed = 1;
    }

    close(sv[0]);
    close(sv[1]);
    if (failed) return 1;
    printf("SELFTEST: batch wake OK (threads=%d dt_us=%llu)\n",
           threads, (unsigned long long)(dt / 1000ull));
    return 0;
}

/*
 * E7 dual-job feed.
 * Two slots, each with its own midstate. Workers claim a slice and call the
 * existing asm (mine: _sha256d_mine_midstate, testnet: sha256d_asm_one).
 * When a slot cannot fill the workers, the next claim takes the other slot.
 * No join between those claims. --dual-job off does not call this.
 * Live shares match Step 1: queue the hit, finish the slice, do not roll
 * extranonce2. The target compare is the same MSW check as the single-job scan.
 */
#define DJ_MINE_SLICE (1u << 20)
#define DJ_SCAN_SLICE (1u << 16)

typedef struct {
    work_buf_t work;
    const uint32_t *expect;
    uint32_t cursor;
    uint32_t left;
    uint32_t claim_size; /* fixed at arm time so later claims do not dice the slot */
    int underfed;        /* armed window had fewer nonces than workers */
    int mine;
    int live;
    int inflight;
    _Atomic int cancel;
    int batch_open;
} dj_slot_t;

typedef struct dj_feed dj_feed_t;
typedef struct dj_worker dj_worker_t;

typedef struct {
    int slot;
    uint32_t nonce_start;
    uint32_t nonce_count;
    int mine;
    uint32_t mid[8];
    uint32_t w_be[16];
    uint8_t target[32];
    const uint32_t *expect;
    char job_id[STRATUM_JOB_ID_MAX];
    char ntime[16];
    uint64_t en2;
    _Atomic int *cancel;
} dj_claim_t;

struct dj_worker {
    int index;
    dj_feed_t *feed;
    int prev_slot;
    uint64_t hash_ticks;
    uint64_t share_ticks;
    uint64_t submit_ticks;
    uint64_t idle_ns;
    uint64_t t_start_ns;
    uint64_t t_end_ns;
};

struct dj_feed {
    dj_slot_t slot[2];
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int nthreads;
    int refillable;
    int stop;
    int count_overlap;
    int any_hit;
    uint32_t found;
    uint32_t best_off;
    uint32_t origin;
    _Atomic uint64_t hashes;
    uint64_t switches;
    uint64_t underfeed;
    uint64_t install_while_live;
    uint64_t idle_ns_total;
    uint64_t last_staged_seq;
    int idle;
    work_buf_t pending;
    int have_pending;
    int pending_hot;
    uint32_t pending_count;
};

static void poll_accounted(stratum_client_t *c, int timeout_ms, int wake_fd);

static void dj_feed_init(dj_feed_t *f, int threads, int refillable) {
    memset(f, 0, sizeof *f);
    pthread_mutex_init(&f->mu, NULL);
    pthread_cond_init(&f->cv, NULL);
    f->nthreads = clamp_threads(threads);
    f->refillable = refillable;
    f->origin = 0;
}

static void dj_feed_destroy(dj_feed_t *f) {
    pthread_cond_destroy(&f->cv);
    pthread_mutex_destroy(&f->mu);
}

static int dj_slot_free_locked(const dj_slot_t *s) {
    return s->inflight == 0 && s->left == 0;
}

static void dj_close_batch_locked(dj_slot_t *s) {
    if (!s->batch_open) return;
    int was = atomic_load_explicit(&s->cancel, memory_order_relaxed);
    /* A share that finishes the window is a full batch (Step 1). */
    batch_count_end(0, was);
    s->batch_open = 0;
}

static uint32_t dj_claim_size(uint32_t count, int nthreads, int mine) {
    if (count == 0) return 0;
    if (nthreads < 1) nthreads = 1;
    uint32_t cap = mine ? DJ_MINE_SLICE : DJ_SCAN_SLICE;
    uint32_t piece = count / (uint32_t)nthreads;
    if (piece < 1) piece = count;
    if (piece > cap) piece = cap;
    if (mine && piece >= 2) piece &= ~1u;
    if (piece < 1) piece = count < cap ? count : cap;
    if (piece > count) piece = count;
    return piece;
}

static void dj_arm_window_locked(dj_feed_t *f, dj_slot_t *s, uint32_t count, int mine) {
    s->claim_size = dj_claim_size(count, f->nthreads, mine);
    s->underfed = f->nthreads > 0 && count > 0 && count < (uint32_t)f->nthreads;
    s->mine = mine;
    s->left = count;
    s->live = count > 0;
}

static void dj_arm_slot_locked(dj_feed_t *f, int idx,
                               const uint32_t mid[8], const uint32_t w_be[16],
                               const uint8_t *target, const uint32_t *expect,
                               uint32_t start, uint32_t count, int mine) {
    dj_slot_t *s = &f->slot[idx];
    dj_close_batch_locked(s);
    memset(&s->work, 0, sizeof s->work);
    if (mid) memcpy(s->work.mid, mid, sizeof s->work.mid);
    if (w_be) memcpy(s->work.w_be, w_be, sizeof s->work.w_be);
    if (target) memcpy(s->work.target, target, sizeof s->work.target);
    s->expect = expect;
    s->cursor = start;
    s->work.ready = count > 0;
    atomic_store_explicit(&s->cancel, 0, memory_order_relaxed);
    dj_arm_window_locked(f, s, count, mine);
    if (count > 0) {
        batch_count_begin();
        s->batch_open = 1;
    }
}

static void dj_note_install_locked(dj_feed_t *f, uint64_t seq, int other_hot,
                                   uint64_t *staged) {
    if (!f->count_overlap || !other_hot) return;
    f->install_while_live++;
    if (staged && seq != f->last_staged_seq) {
        (*staged)++;
        f->last_staged_seq = seq;
    }
}

static void dj_install_work_locked(dj_feed_t *f, int idx, const work_buf_t *w,
                                   uint32_t count, int mine) {
    dj_slot_t *s = &f->slot[idx];
    dj_close_batch_locked(s);
    s->work = *w;
    s->expect = NULL;
    s->cursor = w->nonce_cursor;
    atomic_store_explicit(&s->cancel, 0, memory_order_relaxed);
    dj_arm_window_locked(f, s, count, mine);
    if (count > 0) {
        batch_count_begin();
        s->batch_open = 1;
    }
}

static void dj_cancel_slot_locked(dj_slot_t *s) {
    atomic_store_explicit(&s->cancel, 1, memory_order_relaxed);
    s->live = 0;
    s->left = 0;
}

static int dj_try_claim_locked(dj_feed_t *f, dj_worker_t *w, dj_claim_t *c) {
    int best = -1;
    uint32_t best_left = 0;
    for (int i = 0; i < 2; i++) {
        dj_slot_t *s = &f->slot[i];
        if (!s->live || s->left == 0) continue;
        if (atomic_load_explicit(&s->cancel, memory_order_relaxed)) continue;
        if (s->left > best_left) {
            best = i;
            best_left = s->left;
        }
    }
    if (best < 0) return 0;
    dj_slot_t *s = &f->slot[best];
    uint32_t left = s->left;
    uint32_t take = s->claim_size ? s->claim_size : left;
    if (take > left) take = left;
    if (take < 1) take = left;
    if (s->underfed) {
        f->underfeed++;
        s->underfed = 0;
    }
    if (w->prev_slot >= 0 && w->prev_slot != best)
        f->switches++;
    w->prev_slot = best;

    memset(c, 0, sizeof *c);
    c->slot = best;
    c->nonce_start = s->cursor;
    c->nonce_count = take;
    c->mine = s->mine;
    memcpy(c->mid, s->work.mid, sizeof c->mid);
    memcpy(c->w_be, s->work.w_be, sizeof c->w_be);
    memcpy(c->target, s->work.target, sizeof c->target);
    c->expect = s->expect;
    memcpy(c->job_id, s->work.job_id, sizeof c->job_id);
    memcpy(c->ntime, s->work.ntime, sizeof c->ntime);
    c->en2 = s->work.en2;
    c->cancel = &s->cancel;
    s->cursor += take;
    s->left -= take;
    if (s->left == 0) s->live = 0;
    s->inflight++;
    return 1;
}

static void dj_record_hit_locked(dj_feed_t *f, uint32_t nonce) {
    uint32_t off = nonce - f->origin;
    if (earlier_hit(f->any_hit, f->best_off, f->origin, nonce)) {
        f->any_hit = 1;
        f->found = nonce;
        f->best_off = off;
    }
}

static void dj_hash_mine(dj_worker_t *w, const dj_claim_t *c, int timing) {
    uint32_t found = 0;
    const uint32_t *expect = c->expect ? c->expect : TARGET_NEVER;
    uint64_t a = timing ? mono_ticks() : 0;
    int hit = sha256d_mine_midstate(c->mid, c->w_be, c->nonce_start, c->nonce_count,
                                    expect, &found);
    if (timing) w->hash_ticks += mono_ticks() - a;
    atomic_fetch_add_explicit(&w->feed->hashes, c->nonce_count, memory_order_relaxed);
    if (!hit) return;
    pthread_mutex_lock(&w->feed->mu);
    dj_record_hit_locked(w->feed, found);
    pthread_mutex_unlock(&w->feed->mu);
}

static void dj_hash_scan(dj_worker_t *w, const dj_claim_t *c, int timing, uint64_t ov) {
    uint32_t dig[8];
    uint32_t msw[8];
    uint64_t t_enter = timing ? mono_ticks() : 0;
    uint64_t hash_raw = 0;
    uint64_t submit_ticks = 0;
    uint32_t timed_n = 0;
    uint32_t hashed = 0;
    int hit = 0;
    uint32_t found = 0;
    int job_ok = c->job_id[0] != '\0';
    /* Once per slice, same as the single-job scan. */
    stratum_target_msw(c->target, msw);

    for (uint32_t i = 0; i < c->nonce_count; i++) {
        if ((i & (SCAN_CANCEL_EVERY - 1u)) == 0 &&
            (g_stop ||
             atomic_load_explicit(&g_scan_cancel, memory_order_relaxed) ||
             (c->cancel &&
              atomic_load_explicit(c->cancel, memory_order_relaxed))))
            break;
        uint32_t nonce = c->nonce_start + i;
        if (timing) {
            uint64_t a = mono_ticks();
            sha256d_asm_one(c->mid, c->w_be, nonce, dig);
            hash_raw += mono_ticks() - a;
            timed_n++;
        } else {
            sha256d_asm_one(c->mid, c->w_be, nonce, dig);
        }
        hashed++;
        if (__builtin_expect(stratum_hash_meets_target_msw(dig, msw), 0)) {
            if (!hit) {
                hit = 1;
                found = nonce;
                if (job_ok)
                    printf("SHARE_CANDIDATE nonce=0x%08x en2=%llu job=%s\n",
                           nonce, (unsigned long long)c->en2, c->job_id);
            }
            if (job_ok) {
                if (timing) {
                    uint64_t d0 = mono_ticks();
                    (void)share_q_push(c->job_id, c->ntime, c->en2, nonce);
                    submit_ticks += mono_ticks() - d0;
                } else {
                    (void)share_q_push(c->job_id, c->ntime, c->en2, nonce);
                }
            }
            /* Finish the slice. A share does not roll extranonce2. */
        }
    }

    atomic_fetch_add_explicit(&w->feed->hashes, hashed, memory_order_relaxed);
    if (timing) {
        uint64_t total = mono_ticks() - t_enter;
        uint64_t pull = (uint64_t)timed_n * ov;
        w->hash_ticks += hash_raw > pull ? hash_raw - pull : 0;
        w->submit_ticks += submit_ticks;
        uint64_t used = hash_raw + submit_ticks + pull;
        w->share_ticks += total > used ? total - used : 0;
    }
    if (!hit) return;
    pthread_mutex_lock(&w->feed->mu);
    dj_record_hit_locked(w->feed, found);
    pthread_mutex_unlock(&w->feed->mu);
}

static void *dj_worker(void *arg) {
    dj_worker_t *w = (dj_worker_t *)arg;
    dj_feed_t *f = w->feed;
    worker_qos_hint(w->index);
    (void)mono_ns();
    int timing = time_split_on();
    uint64_t ov = timing ? tick_overhead() : 0;

    for (;;) {
        dj_claim_t claim;
        int got = 0;
        pthread_mutex_lock(&f->mu);
        int idling = 0;
        uint64_t idle_t0 = 0;
        for (;;) {
            if (dj_try_claim_locked(f, w, &claim)) {
                got = 1;
                break;
            }
            if (f->stop || !f->refillable) break;
            if (!idling) {
                idling = 1;
                f->idle++;
                if (f->idle == f->nthreads)
                    batch_wake_signal();
                if (timing) idle_t0 = mono_ns();
            }
            pthread_cond_wait(&f->cv, &f->mu);
        }
        if (idling) {
            f->idle--;
            if (timing && idle_t0) {
                uint64_t t1 = mono_ns();
                if (t1 > idle_t0) w->idle_ns += t1 - idle_t0;
            }
        }
        pthread_mutex_unlock(&f->mu);
        if (!got) break;

        if (timing && w->t_start_ns == 0)
            w->t_start_ns = mono_ns();
        if (claim.mine)
            dj_hash_mine(w, &claim, timing);
        else
            dj_hash_scan(w, &claim, timing, ov);
        if (timing)
            w->t_end_ns = mono_ns();

        pthread_mutex_lock(&f->mu);
        dj_slot_t *s = &f->slot[claim.slot];
        if (s->inflight > 0) s->inflight--;
        if (s->inflight == 0 && s->left == 0) {
            dj_close_batch_locked(s);
            batch_wake_signal();
            pthread_cond_broadcast(&f->cv);
        }
        pthread_mutex_unlock(&f->mu);
    }
    return NULL;
}

static int dj_start(dj_feed_t *f, dj_worker_t *ws, pthread_t *tids) {
    for (int i = 0; i < f->nthreads; i++) {
        memset(&ws[i], 0, sizeof ws[i]);
        ws[i].index = i;
        ws[i].feed = f;
        ws[i].prev_slot = -1;
        if (pthread_create(&tids[i], NULL, dj_worker, &ws[i]) != 0) {
            fprintf(stderr, "NOTE: pthread_create failed at dual-job worker %d\n", i);
            pthread_mutex_lock(&f->mu);
            f->stop = 1;
            pthread_cond_broadcast(&f->cv);
            pthread_mutex_unlock(&f->mu);
            for (int j = 0; j < i; j++) pthread_join(tids[j], NULL);
            return -1;
        }
    }
    return 0;
}

static void dj_join(dj_feed_t *f, pthread_t *tids) {
    pthread_mutex_lock(&f->mu);
    f->stop = 1;
    for (int i = 0; i < 2; i++)
        dj_cancel_slot_locked(&f->slot[i]);
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    for (int i = 0; i < f->nthreads; i++)
        pthread_join(tids[i], NULL);
}

static void dj_account(dj_feed_t *f, dj_worker_t *ws, uint64_t t_decide, int scan) {
    uint64_t lo = UINT64_MAX;
    uint64_t hi = 0;
    int any = 0;
    uint64_t idle = 0;
    for (int i = 0; i < f->nthreads; i++) {
        idle += ws[i].idle_ns;
        if (!ws[i].t_start_ns) continue;
        any = 1;
        if (ws[i].t_start_ns < lo) lo = ws[i].t_start_ns;
        if (ws[i].t_end_ns > hi) hi = ws[i].t_end_ns;
        g_cpu_hash_ticks += ws[i].hash_ticks;
        g_cpu_share_ticks += ws[i].share_ticks;
        g_cpu_submit_ticks += ws[i].submit_ticks;
        if (scan) g_scan_slices_timed++;
    }
    uint64_t span = (any && hi > lo) ? hi - lo : 0;
    uint64_t idle_avg = f->nthreads ? idle / (uint64_t)f->nthreads : 0;
    if (idle_avg > span) idle_avg = span;
    if (any && hi > lo) {
        add_flight_wall(lo, hi);
        if (g_flight_wall_ns >= idle_avg)
            g_flight_wall_ns -= idle_avg;
    }
    uint64_t t_after = time_split_on() ? mono_ns() : 0;
    gap_add_batch_edges(t_decide, t_after, any ? lo : UINT64_MAX, any ? hi : 0, 0, 0);
    if (time_split_on())
        g_flight_hashes += atomic_load_explicit(&f->hashes, memory_order_relaxed);
    for (int i = 0; i < 2; i++) {
        dj_slot_t *s = &f->slot[i];
        if (!s->batch_open) continue;
        int was = atomic_load_explicit(&s->cancel, memory_order_relaxed);
        int shortb = s->left > 0;
        batch_count_end(0, was || shortb);
        s->batch_open = 0;
    }
    f->idle_ns_total = idle;
}

static void dj_print_stats(const dj_feed_t *f) {
    double idle_s = 0.0;
    if (f->nthreads > 0)
        idle_s = (double)f->idle_ns_total / (double)f->nthreads / 1e9;
    printf("DUAL_JOB mode=on slots=2 switches=%llu underfeed=%llu "
           "install_while_live=%llu idle_s=%.4f\n",
           (unsigned long long)f->switches,
           (unsigned long long)f->underfeed,
           (unsigned long long)f->install_while_live,
           idle_s);
}

static int dual_run_pair(int mine,
                         const uint32_t mid0[8], const uint32_t w0[16],
                         const uint8_t *t0, uint32_t s0, uint32_t n0,
                         const uint32_t mid1[8], const uint32_t w1[16],
                         const uint8_t *t1, uint32_t s1, uint32_t n1,
                         const uint32_t *expect, int threads,
                         uint32_t *found, uint64_t *hashes_out,
                         uint64_t *switches_out, int print_stats) {
    threads = clamp_threads(threads);
    uint64_t t_decide = time_split_on() ? mono_ns() : 0;
    dj_feed_t feed;
    dj_feed_init(&feed, threads, 0);
    pthread_mutex_lock(&feed.mu);
    dj_arm_slot_locked(&feed, 0, mid0, w0, t0, expect, s0, n0, mine);
    dj_arm_slot_locked(&feed, 1, mid1, w1, t1, expect, s1, n1, mine);
    pthread_mutex_unlock(&feed.mu);

    dj_worker_t ws[MAX_MINE_THREADS];
    pthread_t tids[MAX_MINE_THREADS];
    if (dj_start(&feed, ws, tids) != 0) {
        dj_feed_destroy(&feed);
        return -1;
    }
    for (int i = 0; i < feed.nthreads; i++)
        pthread_join(tids[i], NULL);
    dj_account(&feed, &ws[0], t_decide, mine ? 0 : 1);
    if (found) *found = feed.found;
    if (hashes_out)
        *hashes_out = atomic_load_explicit(&feed.hashes, memory_order_relaxed);
    if (switches_out) *switches_out = feed.switches;
    int hit = feed.any_hit;
    if (print_stats) dj_print_stats(&feed);
    dj_feed_destroy(&feed);
    return hit;
}

static int dual_mine_span(const uint32_t mid[8], const uint32_t w_be[16],
                          uint32_t nonce_start, uint32_t nonce_count,
                          const uint32_t expect[8], uint32_t *found_nonce,
                          int threads) {
    if (nonce_count == 0) return 0;
    uint32_t n1 = nonce_count / 2u;
    uint32_t n0 = nonce_count - n1;
    return dual_run_pair(1,
                         mid, w_be, NULL, nonce_start, n0,
                         mid, w_be, NULL, nonce_start + n0, n1,
                         expect, threads, found_nonce, NULL, NULL, 1);
}

static int selftest_dual_job(int threads) {
    uint32_t mid[8], w_be[16], found = 0;
    compute_midstate(mid, GENESIS_HEADER);
    build_block1_wbe(w_be, GENESIS_HEADER);
    uint32_t start = 0x7c2bac1du - 3u;

    int hit = dual_run_pair(1, mid, w_be, NULL, start, 4,
                            mid, w_be, NULL, start + 4, 4,
                            GENESIS_DIGEST, threads, &found, NULL, NULL, 0);
    if (hit != 1 || found != 0x7c2bac1du) {
        printf("SELFTEST: FAIL (dual-job slot0 genesis hit=%d found=%08x)\n",
               hit, found);
        return 1;
    }

    found = 0;
    hit = dual_run_pair(1, mid, w_be, NULL, start + 4, 4,
                        mid, w_be, NULL, start, 4,
                        GENESIS_DIGEST, threads, &found, NULL, NULL, 0);
    if (hit != 1 || found != 0x7c2bac1du) {
        printf("SELFTEST: FAIL (dual-job slot1 genesis hit=%d found=%08x)\n",
               hit, found);
        return 1;
    }

    uint8_t hdr2[80];
    memcpy(hdr2, GENESIS_HEADER, 80);
    hdr2[0] ^= 0xff;
    uint32_t mid2[8], w2[16];
    compute_midstate(mid2, hdr2);
    build_block1_wbe(w2, hdr2);

    /* Wrong midstate owns the genesis nonce. Real midstate owns a range that
     * does not. A swapped feed would hit; the real feed must miss. */
    found = 0;
    hit = dual_run_pair(1, mid2, w2, NULL, start, 4,
                        mid, w_be, NULL, 0, 4,
                        GENESIS_DIGEST, threads, &found, NULL, NULL, 0);
    if (hit != 0) {
        printf("SELFTEST: FAIL (dual-job swapped midstate hit=%d found=%08x)\n",
               hit, found);
        return 1;
    }

    found = 0;
    hit = dual_run_pair(1, mid2, w2, NULL, 0, 4,
                        mid, w_be, NULL, start, 4,
                        GENESIS_DIGEST, threads, &found, NULL, NULL, 0);
    if (hit != 1 || found != 0x7c2bac1du) {
        printf("SELFTEST: FAIL (dual-job real midstate slot hit=%d found=%08x)\n",
               hit, found);
        return 1;
    }

    uint64_t switches = 0;
    found = 0;
    hit = dual_run_pair(1, mid, w_be, NULL, 0, 4,
                        mid, w_be, NULL, start, 4,
                        GENESIS_DIGEST, 1, &found, NULL, &switches, 0);
    if (hit != 1 || found != 0x7c2bac1du || switches < 1) {
        printf("SELFTEST: FAIL (dual-job switch hit=%d found=%08x switches=%llu)\n",
               hit, found, (unsigned long long)switches);
        return 1;
    }

    found = 0;
    uint64_t hashes = 0;
    hit = dual_run_pair(1, mid, w_be, NULL, 0, 32,
                        mid, w_be, NULL, 32, 32,
                        TARGET_NEVER, threads, &found, &hashes, NULL, 0);
    if (hit != 0 || hashes != 64) {
        printf("SELFTEST: FAIL (dual-job never-target hit=%d hashes=%llu)\n",
               hit, (unsigned long long)hashes);
        return 1;
    }

    uint8_t target_zero[32];
    memset(target_zero, 0, sizeof target_zero);
    uint32_t dig[8];
    sha256d_asm_one(mid, w_be, 0x7c2bac1du, dig);
    uint8_t hash[32], target_exact[32];
    for (int i = 0; i < 8; i++)
        store_be32(hash + i * 4, dig[i]);
    for (int i = 0; i < 32; i++)
        target_exact[31 - i] = hash[i];

    found = 0;
    hashes = 0;
    hit = dual_run_pair(0, mid, w_be, target_zero, 0, 16,
                        mid, w_be, target_exact, start, 4,
                        NULL, threads, &found, &hashes, NULL, 0);
    if (hit != 1 || found != 0x7c2bac1du) {
        printf("SELFTEST: FAIL (dual-job scan hit=%d found=%08x hashes=%llu)\n",
               hit, found, (unsigned long long)hashes);
        return 1;
    }

    found = 0;
    hashes = 0;
    hit = dual_run_pair(0, mid, w_be, target_zero, 0, 16,
                        mid, w_be, target_zero, 16, 16,
                        NULL, threads, &found, &hashes, NULL, 0);
    if (hit != 0 || hashes != 32) {
        printf("SELFTEST: FAIL (dual-job scan miss hit=%d hashes=%llu)\n",
               hit, (unsigned long long)hashes);
        return 1;
    }

    printf("SELFTEST: dual-job feed OK (threads=%d nonce=%08x)\n",
           threads, 0x7c2bac1du);
    return 0;
}

static int run_soak_dual(const uint32_t mid[8], const uint32_t w_be[16],
                         int seconds, int threads, double report_s) {
    if (seconds < 1) seconds = 1;
    if (report_s < 0.2) report_s = 0.2;
    const uint32_t chunk = 1u << 20;
    printf("\n=== SOAK (offline, no pool) ===\n");
    printf("SOAK_SECONDS=%d THREADS=%d REPORT_S=%.2f CHUNK=%u\n",
           seconds, threads, report_s, chunk);
    printf("DUAL_JOB=on\n");
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    time_split_reset();
    dj_feed_t feed;
    dj_feed_init(&feed, threads, 1);
    uint32_t next = 0;
    uint64_t t_decide = mono_ns();
    pthread_mutex_lock(&feed.mu);
    dj_arm_slot_locked(&feed, 0, mid, w_be, NULL, TARGET_NEVER, next, chunk, 1);
    next += chunk;
    dj_arm_slot_locked(&feed, 1, mid, w_be, NULL, TARGET_NEVER, next, chunk, 1);
    next += chunk;
    pthread_mutex_unlock(&feed.mu);

    dj_worker_t ws[MAX_MINE_THREADS];
    pthread_t tids[MAX_MINE_THREADS];
    if (dj_start(&feed, ws, tids) != 0) {
        printf("RESULT: FAIL (dual-job soak threads)\n");
        dj_feed_destroy(&feed);
        time_split_off();
        return 1;
    }

    double t0 = monotonic_seconds();
    double t_mark = t0;
    uint64_t hashes_mark = 0;
    while (!g_stop) {
        double now = monotonic_seconds();
        if ((now - t0) >= (double)seconds) break;
        pthread_mutex_lock(&feed.mu);
        for (int i = 0; i < 2 && !feed.stop; i++) {
            if (feed.slot[i].inflight == 0 && feed.slot[i].left == 0) {
                dj_arm_slot_locked(&feed, i, mid, w_be, NULL, TARGET_NEVER,
                                   next, chunk, 1);
                next += chunk;
                pthread_cond_broadcast(&feed.cv);
            }
        }
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100000000L;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&feed.cv, &feed.mu, &ts);
        pthread_mutex_unlock(&feed.mu);

        now = monotonic_seconds();
        if ((now - t_mark) >= report_s) {
            double idt = now - t_mark;
            double adt = now - t0;
            if (idt < 1e-9) idt = 1e-9;
            if (adt < 1e-9) adt = 1e-9;
            uint64_t hashes = atomic_load_explicit(&feed.hashes, memory_order_relaxed);
            uint64_t st0 = 0;
            int st_on = 0;
            status_account_begin(&st0, &st_on);
            printf("SOAK t=%.1f hashes=%llu H/s=%.0f H/s_avg=%.0f threads=%d\n",
                   adt, (unsigned long long)hashes,
                   (double)(hashes - hashes_mark) / idt,
                   (double)hashes / adt, threads);
            fflush(stdout);
            status_account_end(st0, st_on);
            t_mark = now;
            hashes_mark = hashes;
        }
    }

    dj_join(&feed, tids);
    dj_account(&feed, ws, t_decide, 0);
    double dt = monotonic_seconds() - t0;
    if (dt < 1e-9) dt = 1e-9;
    uint64_t hashes = atomic_load_explicit(&feed.hashes, memory_order_relaxed);
    double hs = (double)hashes / dt;
    printf("SOAK_HASHES=%llu\n", (unsigned long long)hashes);
    printf("SOAK_ELAPSED_S=%.3f\n", dt);
    printf("SOAK_AVG_H/s=%.0f\n", hs);
    printf("H/s=%.0f\n", hs);
    printf("threads=%d\n", threads);
    dj_print_stats(&feed);
    time_split_print(dt);
    time_split_off();
    dj_feed_destroy(&feed);
    printf("RESULT: PASS\n");
    return 0;
}

/* Install a new header, or extend a drained slot, while the other stays live. */
static int dj_maintain_testnet(dj_feed_t *f, stratum_client_t *c,
                               uint64_t *en2_alloc, uint32_t scan_batch,
                               uint64_t want_seq, int want_clean,
                               uint64_t *staged) {
    for (int guard = 0; guard < 4; guard++) {
        int idx = -1;
        int need_build = 0;
        int hot = 0;
        pthread_mutex_lock(&f->mu);
        for (int i = 0; i < 2; i++) {
            if (f->slot[i].live || f->slot[i].inflight > 0)
                hot = 1;
        }
        if (want_clean) {
            for (int i = 0; i < 2; i++) {
                dj_slot_t *s = &f->slot[i];
                if (s->work.ready && s->work.seq != want_seq)
                    dj_cancel_slot_locked(s);
            }
        }
        if (f->have_pending) {
            for (int i = 0; i < 2; i++) {
                if (!dj_slot_free_locked(&f->slot[i])) continue;
                int other = i ^ 1;
                int other_hot = f->slot[other].live || f->slot[other].inflight > 0;
                int show_hot = other_hot || f->pending_hot;
                char job_id[STRATUM_JOB_ID_MAX];
                uint64_t en2_print;
                uint64_t seq_print;
                snprintf(job_id, sizeof job_id, "%s", f->pending.job_id);
                en2_print = f->pending.en2;
                seq_print = f->pending.seq;
                dj_install_work_locked(f, i, &f->pending, f->pending_count, 0);
                dj_note_install_locked(f, seq_print, show_hot, staged);
                f->have_pending = 0;
                pthread_cond_broadcast(&f->cv);
                pthread_mutex_unlock(&f->mu);
                printf("STRATUM: dual-job slot=%d job=%s en2=%llu seq=%llu other_hot=%d\n",
                       i, job_id, (unsigned long long)en2_print,
                       (unsigned long long)seq_print, show_hot);
                fflush(stdout);
                pthread_mutex_lock(&f->mu);
                break;
            }
        }
        if (!f->have_pending) {
            for (int i = 0; i < 2; i++) {
                dj_slot_t *s = &f->slot[i];
                if (!dj_slot_free_locked(s)) continue;
                int cancelled = atomic_load_explicit(&s->cancel, memory_order_relaxed);
                int wrap = s->work.ready && s->cursor > (0xffffffffu - scan_batch);
                int stale = !s->work.ready || s->work.seq != want_seq ||
                            cancelled || wrap;
                if (!stale) {
                    atomic_store_explicit(&s->cancel, 0, memory_order_relaxed);
                    dj_arm_window_locked(f, s, scan_batch, s->mine);
                    if (!s->batch_open) {
                        batch_count_begin();
                        s->batch_open = 1;
                    }
                    pthread_cond_broadcast(&f->cv);
                    continue;
                }
                idx = i;
                need_build = 1;
                break;
            }
        }
        pthread_mutex_unlock(&f->mu);
        if (!need_build) return 0;

        work_buf_t built;
        uint64_t en2 = *en2_alloc;
        if (prepare_work(c, &built, en2) != 0) {
            fprintf(stderr, "STRATUM: dual-job prepare_work failed\n");
            return -1;
        }
        (*en2_alloc)++;
        pthread_mutex_lock(&f->mu);
        if (dj_slot_free_locked(&f->slot[idx])) {
            int other = idx ^ 1;
            int other_hot = f->slot[other].live || f->slot[other].inflight > 0;
            dj_install_work_locked(f, idx, &built, scan_batch, 0);
            dj_note_install_locked(f, built.seq, other_hot || hot, staged);
            pthread_cond_broadcast(&f->cv);
            pthread_mutex_unlock(&f->mu);
            printf("STRATUM: dual-job slot=%d job=%s en2=%llu seq=%llu other_hot=%d\n",
                   idx, built.job_id, (unsigned long long)built.en2,
                   (unsigned long long)built.seq, other_hot || hot);
            fflush(stdout);
        } else {
            f->pending = built;
            f->pending_count = scan_batch;
            f->pending_hot = hot;
            f->have_pending = 1;
            pthread_mutex_unlock(&f->mu);
        }
    }
    return 0;
}

static int run_testnet_dual(const char *host, int port, const char *user, const char *pass,
                            double suggest_diff, int seconds, int max_shares, int threads) {
    printf("\n=== TESTNET STRATUM ===\n");
    printf("endpoint=%s:%d user=%s suggest_diff=%.8g duration=%ds threads=%d\n",
           host, port, user, suggest_diff, seconds, threads);
    printf("DUAL_JOB=on\n");

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
    if (max_shares == 0 && suggest_diff > 0.0 && suggest_diff < 1.0) {
        printf("NOTE: suggest_diff %.8g with --max-shares 0 can flood submits "
               "before vardiff rises. For an H/s soak pass --suggest-diff 1. "
               "The share target is still the pool difficulty.\n",
               suggest_diff);
    }
    if (batch_wake_open() != 0)
        fprintf(stderr, "NOTE: batch wake pipe unavailable; in-flight poll keeps its timeout\n");

    uint32_t scan_batch = 2u << 20;
    printf("STRATUM: scan_batch=%u threads=%d dual_slots=2 scan_slice=%u\n",
           scan_batch, threads, DJ_SCAN_SLICE);

    g_share_head = 0;
    g_share_tail = 0;
    time_split_reset();

    dj_feed_t feed;
    dj_feed_init(&feed, threads, 1);
    uint64_t en2_alloc = 0;
    uint64_t staged = 0;
    uint64_t want_seq = client.job.seq;
    uint64_t t_decide = mono_ns();
    if (dj_maintain_testnet(&feed, &client, &en2_alloc, scan_batch,
                            want_seq, 0, NULL) != 0) {
        printf("RESULT: FAIL (dual-job header)\n");
        dj_feed_destroy(&feed);
        stratum_close(&client);
        time_split_off();
        return 1;
    }

    dj_worker_t ws[MAX_MINE_THREADS];
    pthread_t tids[MAX_MINE_THREADS];
    if (dj_start(&feed, ws, tids) != 0) {
        printf("RESULT: FAIL (dual-job threads)\n");
        dj_feed_destroy(&feed);
        stratum_close(&client);
        time_split_off();
        return 1;
    }
    feed.count_overlap = 1;
    g_in_flight = 1;

    double t0 = monotonic_seconds();
    double t_last_report = t0;
    while (!g_stop) {
        double now = monotonic_seconds();
        if (seconds > 0 && (now - t0) >= (double)seconds) break;
        if (max_shares > 0 && (int)client.shares_accepted >= max_shares) break;

        poll_accounted(&client, 20, g_batch_wake_r);
        share_q_flush(&client);

        if (client.have_job)
            want_seq = client.job.seq;
        if (dj_maintain_testnet(&feed, &client, &en2_alloc, scan_batch,
                                want_seq, client.job.clean ? 1 : 0,
                                &staged) != 0)
            break;

        pthread_mutex_lock(&feed.mu);
        for (int i = 0; i < 2; i++) {
            if (feed.slot[i].work.ready)
                stratum_share_target(client.difficulty, feed.slot[i].work.target);
        }
        pthread_mutex_unlock(&feed.mu);

        now = monotonic_seconds();
        if (now - t_last_report >= 2.0) {
            double dt = now - t0;
            uint64_t hashes = atomic_load_explicit(&feed.hashes, memory_order_relaxed);
            double hs = (dt > 1e-9) ? (double)hashes / dt : 0.0;
            uint64_t st0 = 0;
            int st_on = 0;
            status_account_begin(&st0, &st_on);
            printf("STATUS connected=1 jobs=%llu hashes=%llu H/s=%.0f threads=%d "
                   "diff=%.8g shares_ok=%llu shares_bad=%llu pending=%d "
                   "staged_overlap=%llu en2=%llu\n",
                   (unsigned long long)client.jobs_seen,
                   (unsigned long long)hashes, hs, threads, client.difficulty,
                   (unsigned long long)client.shares_accepted,
                   (unsigned long long)client.shares_rejected,
                   client.submit_pending,
                   (unsigned long long)staged,
                   (unsigned long long)en2_alloc);
            fflush(stdout);
            status_account_end(st0, st_on);
            t_last_report = now;
        }
    }

    g_in_flight = 0;
    dj_join(&feed, tids);
    dj_account(&feed, ws, t_decide, 1);
    share_q_flush(&client);
    uint64_t drain_t0 = time_split_on() ? mono_ns() : 0;
    int pending_left = stratum_submit_drain(&client, 3000);
    if (drain_t0) {
        uint64_t drain_t1 = mono_ns();
        if (drain_t1 > drain_t0)
            g_gap_end_drain_ns += drain_t1 - drain_t0;
    }

    double dt = monotonic_seconds() - t0;
    if (dt < 1e-9) dt = 1e-9;
    uint64_t hashes = atomic_load_explicit(&feed.hashes, memory_order_relaxed);
    double hs = (double)hashes / dt;

    printf("\n=== TESTNET SUMMARY ===\n");
    printf("endpoint=%s:%d\n", host, port);
    printf("authorized=%d\n", (int)client.authorized);
    printf("jobs_seen=%llu\n", (unsigned long long)client.jobs_seen);
    printf("jobs_staged_while_hashing=%llu\n", (unsigned long long)staged);
    printf("difficulty=%.8g\n", client.difficulty);
    printf("hashes=%llu\n", (unsigned long long)hashes);
    printf("H/s=%.0f\n", hs);
    printf("threads=%d\n", threads);
    printf("dual_job=on\n");
    printf("shares_submitted=%llu\n", (unsigned long long)client.shares_submitted);
    printf("shares_accepted=%llu\n", (unsigned long long)client.shares_accepted);
    printf("shares_rejected=%llu\n", (unsigned long long)client.shares_rejected);
    printf("submit_pending=%d\n", pending_left);
    printf("elapsed_s=%.2f\n", dt);
    printf("expect_share_s@this_rate=%.2f\n",
           client.difficulty * 4294967296.0 / (hs > 1.0 ? hs : 1.0));
    dj_print_stats(&feed);
    time_split_print(dt);
    time_split_off();
    dj_feed_destroy(&feed);
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

/*
 * Offline multi-thread soak. Prints periodic H/s so a short batch and a
 * sustained run can be compared. Does not open a socket.
 */
static int run_soak(const uint32_t mid[8], const uint32_t w_be[16],
                    int seconds, int threads, double report_s) {
    if (g_dual_job)
        return run_soak_dual(mid, w_be, seconds, threads, report_s);
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
            uint64_t st0 = 0;
            int st_on = 0;
            status_account_begin(&st0, &st_on);
            printf("SOAK t=%.1f hashes=%llu H/s=%.0f H/s_avg=%.0f threads=%d\n",
                   adt, (unsigned long long)hashes,
                   (double)(hashes - hashes_mark) / idt,
                   (double)hashes / adt, threads);
            fflush(stdout);
            status_account_end(st0, st_on);
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

static void poll_accounted(stratum_client_t *c, int timeout_ms, int wake_fd) {
    uint64_t w0 = c->poll_wait_ns;
    uint64_t b0 = c->poll_busy_ns;
    stratum_poll_wake(c, timeout_ms, wake_fd, NULL);
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
    if (g_dual_job)
        return run_testnet_dual(host, port, user, pass, suggest_diff,
                                seconds, max_shares, threads);
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
    /* 0.001 proves a share quickly (make testnet). On a long unlimited
     * soak the pool then vardiffs through a submit flood (seen 0.001 → 0.16).
     * Suggesting 1 asks for a quieter rate. The check still uses whatever
     * mining.set_difficulty the pool sends. */
    if (max_shares == 0 && suggest_diff > 0.0 && suggest_diff < 1.0) {
        printf("NOTE: suggest_diff %.8g with --max-shares 0 can flood submits "
               "before vardiff rises. For an H/s soak pass --suggest-diff 1. "
               "The share target is still the pool difficulty.\n",
               suggest_diff);
    }
    if (batch_wake_open() != 0)
        fprintf(stderr, "NOTE: batch wake pipe unavailable; in-flight poll keeps its timeout\n");

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
                poll_accounted(&client, 50, -1);
                continue;
            }
            if (scan_start(&flight, &active, scan_batch, threads) != 0) {
                fprintf(stderr, "STRATUM: scan_start failed\n");
                break;
            }
            g_in_flight = 1;
        }

        /* 20ms is only the backstop if the wake write fails. The last
         * worker writes one byte to the self-pipe, so this select returns
         * when the batch ends. Socket readability still wakes the same
         * select, so job staging and async submit stay overlapped. */
        poll_accounted(&client, 20, g_batch_wake_r);
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
            uint32_t assigned = flight.assigned;
            int abandoned = atomic_load_explicit(&g_scan_cancel, memory_order_relaxed);
            /* Workers have left the hash loop. t_notice is the moment the
             * main thread sees that, so teardown can split poll-wake from join.
             * Rebuilds and submits here stall the next batch when g_in_flight
             * is clear, so they stay in the stall buckets. */
            if (time_split_on())
                flight.t_notice_ns = mono_ns();
            g_in_flight = 0;
            scan_join(&flight, &sr);
            restart_window_open();
            hashes += sr.hashes;
            /* Hits were queued by the worker that found them. The slice
             * kept hashing, so a share does not by itself leave a hole. */
            if (sr.hit)
                printf("SHARE_CANDIDATE nonce=0x%08x en2=%llu job=%s\n",
                       sr.nonce, (unsigned long long)active.en2, active.job_id);
            share_q_flush(&client);

            /* 2 = clean/cancel resume, 1 = short batch rolls extranonce2,
             * 0 = full assignment (share or not) or a job switch (teardown).
             * A finished slice keeps this header. Rolling en2 on every share
             * threw away the rest of the nonce space and rebuilt midstate. */
            int restart_kind = 0;
            if (abandoned)
                restart_kind = 2;

            int leave = 0;
            int short_batch = assigned > 0 && sr.hashes < assigned;
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
            } else if (short_batch && !g_stop) {
                uint64_t en2 = active.en2 + 1;
                if (prepare_work(&client, &active, en2) != 0) {
                    fprintf(stderr, "STRATUM: rebuild after short batch failed\n");
                    leave = 1;
                }
                if (sr.hit)
                    restart_kind = 1;
            } else if (!g_stop) {
                uint64_t next = (uint64_t)batch_start + sr.hashes;
                if (sr.hashes == 0) next = (uint64_t)batch_start + scan_batch;
                /* batch_start + hashes is uint64, so wrap is next past 2^32.
                 * A uint32 comparison would promote and miss the wrap. */
                if (next >= 0x100000000ULL) {
                    uint64_t en2 = active.en2 + 1;
                    if (prepare_work(&client, &active, en2) != 0) leave = 1;
                } else {
                    active.nonce_cursor = batch_start + (uint32_t)sr.hashes;
                    stratum_share_target(client.difficulty, active.target);
                }
            }

            if (!leave) {
                now = monotonic_seconds();
                if (g_stop)
                    leave = 1;
                else if (seconds > 0 && (now - t0) >= (double)seconds)
                    leave = 1;
                else if (max_shares > 0 && (int)client.shares_accepted >= max_shares)
                    leave = 1;
            }
            if (leave) {
                restart_window_close(restart_kind);
                break;
            }
            if (!active.ready) {
                restart_window_close(restart_kind);
                continue;
            }
            restart_window_close(restart_kind);
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
            uint64_t st0 = 0;
            int st_on = 0;
            status_account_begin(&st0, &st_on);
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
            status_account_end(st0, st_on);
            t_last_report = now;
        }
    }

    g_in_flight = 0;
    if (flight.running) {
        atomic_store_explicit(&g_scan_cancel, 1, memory_order_relaxed);
        if (time_split_on())
            flight.t_notice_ns = mono_ns();
        scan_result_t sr;
        scan_join(&flight, &sr);
        hashes += sr.hashes;
    }
    share_q_flush(&client);
    /* Pool RTT after hashing stopped. Named end_drain_s, not submit_s or poll_s. */
    uint64_t drain_t0 = time_split_on() ? mono_ns() : 0;
    int pending_left = stratum_submit_drain(&client, 3000);
    if (drain_t0) {
        uint64_t drain_t1 = mono_ns();
        if (drain_t1 > drain_t0)
            g_gap_end_drain_ns += drain_t1 - drain_t0;
    }

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
    printf("dual_job=off\n");
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
        "  %s --threads N         worker count (default: hw.physicalcpu)\n"
        "  %s --pin / --no-pin    macOS P-core QoS + affinity tags (default --pin)\n"
        "  %s --dual-job off|on   E7 two hot midstates (default off, current single-job)\n"
        "  %s --testnet           mine BTCLab testnet3 (suggest_diff=0.001)\n"
        "  %s --stratum HOST:PORT --user USER [--pass PASS] [--suggest-diff D]\n"
        "                         [--seconds N] [--max-shares N] [--threads N]\n"
        "\n"
        "Default --suggest-diff is 0.001 so a short run can accept one share.\n"
        "For an H/s soak (--max-shares 0) pass --suggest-diff 1 so the pool\n"
        "is not asked to start at a share every few million hashes. The\n"
        "target check still uses mining.set_difficulty from the pool.\n"
        "\n"
        "Educational testnet only. No mainnet / AntPool.\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
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
        } else if (strcmp(argv[i], "--dual-job") == 0 && i + 1 < argc) {
            const char *mode = argv[++i];
            if (strcmp(mode, "on") == 0) g_dual_job = 1;
            else if (strcmp(mode, "off") == 0) g_dual_job = 0;
            else {
                fprintf(stderr, "--dual-job requires off or on\n");
                return 2;
            }
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
    printf("DUAL_JOB=%s\n", g_dual_job ? "on" : "off");
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
    int hit = g_dual_job
        ? dual_mine_span(mid, w_be, 0u, batch, TARGET_NEVER, &found, threads)
        : mine_midstate_n(mid, w_be, 0u, batch, TARGET_NEVER, &found, threads);
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
