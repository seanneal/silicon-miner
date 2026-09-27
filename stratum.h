/*
 * stratum.h — Bitcoin Stratum V1 client (testnet educational mining)
 * bare TCP, no TLS. Hash path stays in sha256d_mine.s.
 */
#ifndef SILICON_MINER_STRATUM_H
#define SILICON_MINER_STRATUM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define STRATUM_JOB_ID_MAX     128
#define STRATUM_EN1_MAX        64
#define STRATUM_HEX_FIELD_MAX  512
#define STRATUM_COINB_MAX      4096
#define STRATUM_MERKLE_MAX     32
#define STRATUM_USER_MAX       256
#define STRATUM_SUBMIT_SLOTS   16

typedef struct {
    char     job_id[STRATUM_JOB_ID_MAX];
    char     prevhash[65];          /* 32-byte hex */
    char     coinb1[STRATUM_COINB_MAX];
    char     coinb2[STRATUM_COINB_MAX];
    char     merkle[STRATUM_MERKLE_MAX][65];
    int      n_merkle;
    char     version[16];
    char     nbits[16];
    char     ntime[16];
    bool     clean;
    uint64_t seq;                   /* increments on each notify */
} stratum_job_t;

typedef struct {
    int      fd;
    char     extranonce1[STRATUM_EN1_MAX];
    int      extranonce2_size;      /* bytes */
    double   difficulty;
    bool     authorized;
    bool     have_job;
    stratum_job_t job;
    uint64_t jobs_seen;
    uint64_t shares_accepted;
    uint64_t shares_rejected;
    uint64_t shares_submitted;
    int      next_id;
    char     user[STRATUM_USER_MAX];
    char     pass[64];
    /* rx buffer */
    char     rx[16384];
    size_t   rx_len;
    /* pending JSON-RPC replies keyed by small id window */
    char     last_reply[2048];
    int      last_reply_id;
    bool     last_reply_ok;
    bool     last_reply_ready;
    /* In-flight mining.submit ids. Replies are applied inside stratum_poll
     * so hash workers are not stalled on the pool round-trip. id 0 = empty. */
    struct {
        int      id;
        uint32_t nonce;
    } submit_slot[STRATUM_SUBMIT_SLOTS];
    int      submit_pending;
    /* stratum_poll split. wait = blocked in select; busy = recv + JSON.
     * Main thread only. Durations use mono_clock.h. */
    uint64_t poll_wait_ns;
    uint64_t poll_busy_ns;
} stratum_client_t;

/* Connect host:port, subscribe, optional suggest_diff, authorize. */
int  stratum_connect(stratum_client_t *c, const char *host, int port,
                     const char *user, const char *pass, double suggest_diff);

void stratum_close(stratum_client_t *c);

/* Non-blocking-ish poll: read socket, handle notify/difficulty/replies. */
int  stratum_poll(stratum_client_t *c, int timeout_ms);

/* Same as stratum_poll, and also return when wake_fd is readable.
 * wake_fd < 0 watches the socket only. A readable wake_fd is drained
 * and *woke is set to 1 (woke may be NULL). Socket bytes are still read
 * when both fire. The select wait stays in poll_wait_ns. */
int  stratum_poll_wake(stratum_client_t *c, int timeout_ms, int wake_fd, int *woke);

/* Build 80-byte header for job + extranonce2 + nonce. Returns 0 on success. */
int  stratum_build_header(const stratum_client_t *c, uint64_t extranonce2,
                          uint32_t nonce, uint8_t header80[80]);

/* Share target from current difficulty (Bitcoin diff1 / difficulty).
 * target_be[32] is big-endian 256-bit target (MSB first). */
void stratum_share_target(double difficulty, uint8_t target_be[32]);

/* Pack target_be into 8 big-endian uint32 words, MSB word first.
 * Same bytes as target_be; done once per slice, not once per nonce. */
static inline void stratum_target_msw(const uint8_t target_be[32], uint32_t msw[8])
    __attribute__((unused));
static inline void stratum_target_msw(const uint8_t target_be[32], uint32_t msw[8]) {
    for (int i = 0; i < 8; i++) {
        const uint8_t *p = target_be + (i * 4);
        msw[i] = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                 ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
}

/* digest_words: 8 SHA-256 state words (as produced by sha256_compress).
 * Returns true if the Bitcoin hash integer is <= target.
 *
 * The hash is a little-endian uint256. Its most significant byte is the
 * low byte of word 7, so bswap32(word 7) is the top 32 bits of that integer.
 * msw[] is the target in the same order (stratum_target_msw). A miss almost
 * always returns on word 0; lower words are only read when the top word ties.
 * This is the same comparison as walking the 32 hash bytes from index 31. */
static inline bool stratum_hash_meets_target_msw(const uint32_t digest_words[8],
                                                const uint32_t msw[8])
    __attribute__((unused));
static inline bool stratum_hash_meets_target_msw(const uint32_t digest_words[8],
                                                const uint32_t msw[8]) {
    uint32_t h = __builtin_bswap32(digest_words[7]);
    if (h > msw[0]) return false;
    if (h < msw[0]) return true;
    for (int i = 1; i < 8; i++) {
        h = __builtin_bswap32(digest_words[7 - i]);
        uint32_t t = msw[i];
        if (h > t) return false;
        if (h < t) return true;
    }
    return true;
}

/* digest_words: 8 SHA-256 state words (as produced by sha256_compress).
 * Returns true if Bitcoin LE hash <= target. */
static inline bool stratum_hash_meets_target(const uint32_t digest_words[8],
                                            const uint8_t target_be[32])
    __attribute__((unused));
static inline bool stratum_hash_meets_target(const uint32_t digest_words[8],
                                            const uint8_t target_be[32]) {
    uint32_t msw[8];
    stratum_target_msw(target_be, msw);
    return stratum_hash_meets_target_msw(digest_words, msw);
}

/* Submit share and wait for the reply. Returns 1 accepted, 0 rejected, -1 error. */
int  stratum_submit(stratum_client_t *c, uint64_t extranonce2,
                    const char *ntime_hex, uint32_t nonce);

/* Send mining.submit and return. The reply is counted on a later stratum_poll.
 * job_id is the job that was hashed (not necessarily c->job, which may have moved).
 * Returns 0 if the request was written, -1 on send/queue failure. */
int  stratum_submit_async(stratum_client_t *c, const char *job_id,
                          uint64_t extranonce2, const char *ntime_hex,
                          uint32_t nonce);

/* Poll until outstanding async submits drain or timeout. Returns how many remain. */
int  stratum_submit_drain(stratum_client_t *c, int timeout_ms);

/* Format helpers — size_bytes clamped to 1..8 (SoloPool uses 8). */
void stratum_en2_hex(uint64_t en2, int size_bytes, char *out /* size*2+1 */);

#endif /* SILICON_MINER_STRATUM_H */
