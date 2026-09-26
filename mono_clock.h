/*
 * mono_clock.h — TIME_SPLIT time base.
 *
 * macOS: mach_absolute_time() ticks converted with mach_timebase_info
 *        (ns = ticks * numer / denom). One read is cheap enough to bracket
 *        a testnet nonce; clock_gettime per nonce is not.
 * Other hosts (including the qemu self-test): clock_gettime(CLOCK_MONOTONIC),
 *        already in nanoseconds. numer/denom stay 1/1.
 *
 * Each translation unit keeps its own cached scale. Call mono_ns() once on
 * the thread that will use it before sharing work with other threads.
 */
#ifndef SILICON_MINER_MONO_CLOCK_H
#define SILICON_MINER_MONO_CLOCK_H

#include <stdint.h>
#include <time.h>

#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

typedef struct {
    uint32_t numer;
    uint32_t denom;
    int      ready;
} mono_scale_t;

static inline mono_scale_t *mono_scale(void) {
    static mono_scale_t s;
    if (!s.ready) {
#ifdef __APPLE__
        mach_timebase_info_data_t tb;
        mach_timebase_info(&tb);
        s.numer = tb.numer ? tb.numer : 1;
        s.denom = tb.denom ? tb.denom : 1;
#else
        s.numer = 1;
        s.denom = 1;
#endif
        s.ready = 1;
    }
    return &s;
}

static inline uint64_t mono_ticks(void) {
#ifdef __APPLE__
    return mach_absolute_time();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

/* ticks * numer / denom, exact while (ticks/denom)*numer fits in uint64. */
static inline uint64_t mono_ticks_to_ns(uint64_t ticks) {
    mono_scale_t *s = mono_scale();
    uint64_t q = ticks / s->denom;
    uint64_t r = ticks % s->denom;
    return q * (uint64_t)s->numer + (r * (uint64_t)s->numer) / s->denom;
}

static inline uint64_t mono_ns(void) {
    return mono_ticks_to_ns(mono_ticks());
}

static inline const char *mono_clock_name(void) {
#ifdef __APPLE__
    return "mach_absolute_time*mach_timebase_info";
#else
    return "clock_gettime(CLOCK_MONOTONIC)";
#endif
}

#endif /* SILICON_MINER_MONO_CLOCK_H */
