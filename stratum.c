#define _DEFAULT_SOURCE
/*
 * stratum.c — Bitcoin Stratum V1 over bare TCP (educational testnet miner)
 */
#include "stratum.h"
#include "mono_clock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* ---------- hex ---------- */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, uint8_t *out, size_t out_max) {
    size_t n = strlen(hex);
    if (n % 2) return -1;
    size_t nb = n / 2;
    if (nb > out_max) return -1;
    for (size_t i = 0; i < nb; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)nb;
}

void stratum_en2_hex(uint64_t en2, int size_bytes, char *out) {
    /* big-endian hex of en2, width = size_bytes*2 (clamped 1..8) */
    if (size_bytes < 1) size_bytes = 1;
    if (size_bytes > 8) size_bytes = 8;
    for (int i = size_bytes - 1; i >= 0; i--) {
        uint8_t b = (uint8_t)((en2 >> (8 * i)) & 0xff);
        static const char *H = "0123456789abcdef";
        *out++ = H[b >> 4];
        *out++ = H[b & 0xf];
    }
    *out = '\0';
}

/* ---------- crypto helpers (SHA-256d via CommonCrypto on Apple, else portable) ---------- */

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>
static void sha256(const uint8_t *in, size_t n, uint8_t out[32]) {
    CC_SHA256(in, (CC_LONG)n, out);
}
#else
/* Portable SHA-256 for coinbase/merkle only (not the mining hash path). */
typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  data[64];
    size_t   datalen;
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SIG0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SIG1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t m[64], a,b,c,d,e,f,g,h,t1,t2;
    for (int i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = ((uint32_t)data[j]<<24)|((uint32_t)data[j+1]<<16)|
               ((uint32_t)data[j+2]<<8)|((uint32_t)data[j+3]);
    for (int i = 16; i < 64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]) {
    size_t i = ctx->datalen;
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0;
        sha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) ctx->data[i++] = 0;
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = (uint8_t)ctx->bitlen;
    ctx->data[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->data[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->data[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->data[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->data[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->data[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->data[56] = (uint8_t)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; i++) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

static void sha256(const uint8_t *in, size_t n, uint8_t out[32]) {
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, in, n);
    sha256_final(&ctx, out);
}
#endif

static void sha256d(const uint8_t *in, size_t n, uint8_t out[32]) {
    uint8_t mid[32];
    sha256(in, n, mid);
    sha256(mid, 32, out);
}

/* ---------- target / difficulty ---------- */

void stratum_share_target(double difficulty, uint8_t target_be[32]) {
    if (difficulty <= 0.0) difficulty = 1.0;
    memset(target_be, 0, 32);
    /*
     * DIFF1 = 0x00000000FFFF0000 << 192.
     * For pool share difficulties we only need the top 8 bytes:
     *   top64 = floor(0xFFFF0000 / difficulty)   (when d>=1, top stays in bytes4..7 area)
     *   or     floor(0xFFFF0000 / difficulty)     (when d<1, expands into bytes0..7)
     * Matches Bitcoin "target = diff1_target / difficulty".
     */
    double top = (double)0xFFFF0000ULL / difficulty;
    uint64_t v = (uint64_t)top;
    target_be[0] = (uint8_t)(v >> 56);
    target_be[1] = (uint8_t)(v >> 48);
    target_be[2] = (uint8_t)(v >> 40);
    target_be[3] = (uint8_t)(v >> 32);
    target_be[4] = (uint8_t)(v >> 24);
    target_be[5] = (uint8_t)(v >> 16);
    target_be[6] = (uint8_t)(v >> 8);
    target_be[7] = (uint8_t)(v);
}

bool stratum_hash_meets_target(const uint32_t digest_words[8],
                               const uint8_t target_be[32]) {
    /* SHA words → 32-byte BE digest */
    uint8_t hash[32];
    for (int i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (uint8_t)(digest_words[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(digest_words[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(digest_words[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(digest_words[i]);
    }
    /* Bitcoin: interpret hash as little-endian uint256; compare to target as LE uint256.
     * Equivalent: compare bytes from index 31 down to 0 against target_be which is BE,
     * so hash_le_byte[i] = hash[i], target_le_byte[i] = target_be[31-i].
     * hash_int <= target_int iff comparing from MSB of the LE number (byte 31). */
    for (int i = 31; i >= 0; i--) {
        uint8_t hb = hash[i];                 /* LE byte i */
        uint8_t tb = target_be[31 - i];       /* LE byte i of BE target */
        if (hb < tb) return true;
        if (hb > tb) return false;
    }
    return true;
}

/* ---------- JSON helpers (minimal) ---------- */

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return p;
}

static int json_get_int(const char *json, const char *key, long *out) {
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    p = skip_ws(p);
    if (*p != ':') return -1;
    p = skip_ws(p + 1);
    char *end = NULL;
    long v = strtol(p, &end, 10);
    if (end == p) return -1;
    *out = v;
    return 0;
}

static int json_result_true(const char *json) {
    const char *p = strstr(json, "\"result\"");
    if (!p) return 0;
    p = strchr(p, ':');
    if (!p) return 0;
    p = skip_ws(p + 1);
    return (strncmp(p, "true", 4) == 0);
}

static int json_result_null_error(const char *json) {
    /* error:null is success-ish for some replies */
    const char *e = strstr(json, "\"error\"");
    if (!e) return 0;
    e = strchr(e, ':');
    if (!e) return 0;
    e = skip_ws(e + 1);
    return (strncmp(e, "null", 4) == 0);
}

/* Extract string at array index from a JSON array starting at '['.
 * Returns pointer after the element, or NULL. Copies into out. */
static const char *json_array_string_at(const char *arr, int index, char *out, size_t out_sz) {
    const char *p = skip_ws(arr);
    if (*p != '[') return NULL;
    p++;
    for (int i = 0; i <= index; i++) {
        p = skip_ws(p);
        if (*p == ']') return NULL;
        if (*p == '"') {
            p++;
            size_t n = 0;
            /*
             * Always consume through the closing quote. Earlier fields (esp.
             * coinb1/coinb2) may be longer than out_sz; truncating the scan
             * used to desync and leave version/nbits/ntime empty.
             */
            while (*p && *p != '"') {
                char ch = *p++;
                if (ch == '\\' && *p) {
                    ch = *p++;
                }
                if (i == index && n + 1 < out_sz)
                    out[n++] = ch;
            }
            if (i == index) out[n] = '\0';
            if (*p == '"') p++;
            if (i == index) return skip_ws(p);
            p = skip_ws(p);
            if (*p == ',') p++;
        } else if (*p == '[') {
            /* nested array — skip balanced, respecting strings */
            int depth = 0;
            do {
                if (*p == '"') {
                    p++;
                    while (*p && *p != '"') {
                        if (*p == '\\' && p[1]) p += 2;
                        else p++;
                    }
                    if (*p == '"') p++;
                    continue;
                }
                if (*p == '[') depth++;
                else if (*p == ']') depth--;
                if (*p) p++;
            } while (*p && depth > 0);
            if (i == index) { out[0] = '\0'; return skip_ws(p); }
            p = skip_ws(p);
            if (*p == ',') p++;
        } else if (*p == 't' || *p == 'f' || (*p >= '0' && *p <= '9') || *p == '-') {
            while (*p && *p != ',' && *p != ']') p++;
            if (i == index) { out[0] = '\0'; return skip_ws(p); }
            if (*p == ',') p++;
        } else {
            return NULL;
        }
    }
    return NULL;
}
static const char *json_find_params_array(const char *json) {
    const char *p = strstr(json, "\"params\"");
    if (!p) return NULL;
    p = strchr(p, ':');
    if (!p) return NULL;
    p = skip_ws(p + 1);
    if (*p != '[') return NULL;
    return p;
}

static const char *json_find_result_array(const char *json) {
    const char *p = strstr(json, "\"result\"");
    if (!p) return NULL;
    p = strchr(p, ':');
    if (!p) return NULL;
    p = skip_ws(p + 1);
    if (*p != '[') return NULL;
    return p;
}

/* Skip a nested JSON value; return pointer after it. */
static const char *json_skip_value(const char *p) {
    p = skip_ws(p);
    if (*p == '"') {
        p++;
        while (*p && *p != '"') {
            if (*p == '\\' && p[1]) p += 2;
            else p++;
        }
        if (*p == '"') p++;
        return p;
    }
    if (*p == '[') {
        int d = 0;
        do {
            if (*p == '[') d++;
            else if (*p == ']') d--;
            else if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && p[1]) p += 2;
                    else p++;
                }
            }
            if (*p) p++;
        } while (*p && d > 0);
        return p;
    }
    if (*p == '{') {
        int d = 0;
        do {
            if (*p == '{') d++;
            else if (*p == '}') d--;
            else if (*p == '"') {
                p++;
                while (*p && *p != '"') {
                    if (*p == '\\' && p[1]) p += 2;
                    else p++;
                }
            }
            if (*p) p++;
        } while (*p && d > 0);
        return p;
    }
    while (*p && *p != ',' && *p != ']' && *p != '}') p++;
    return p;
}

/* Get nth element start inside array. */
static const char *json_array_elem(const char *arr, int index) {
    const char *p = skip_ws(arr);
    if (*p != '[') return NULL;
    p++;
    for (int i = 0; i < index; i++) {
        p = skip_ws(p);
        p = json_skip_value(p);
        p = skip_ws(p);
        if (*p == ',') p++;
    }
    return skip_ws(p);
}

/* ---------- socket IO ---------- */

static int stratum_send_raw(stratum_client_t *c, const char *line) {
    size_t n = strlen(line);
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(c->fd, line + off, n - off, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static int stratum_send_req(stratum_client_t *c, int id, const char *method, const char *params_json) {
    char buf[4096];
    int n = snprintf(buf, sizeof buf,
                     "{\"id\":%d,\"method\":\"%s\",\"params\":%s}\n",
                     id, method, params_json);
    if (n <= 0 || n >= (int)sizeof buf) return -1;
    fprintf(stderr, ">> %.*s\n", n - 1, buf);
    return stratum_send_raw(c, buf);
}

static void handle_line(stratum_client_t *c, const char *line) {
    fprintf(stderr, "<< %.400s%s\n", line, strlen(line) > 400 ? "…" : "");

    if (strstr(line, "\"method\":\"mining.set_difficulty\"") ||
        strstr(line, "\"method\": \"mining.set_difficulty\"")) {
        const char *pa = json_find_params_array(line);
        if (pa) {
            const char *e = json_array_elem(pa, 0);
            if (e) {
                c->difficulty = strtod(e, NULL);
                fprintf(stderr, "STRATUM: difficulty=%.8g\n", c->difficulty);
            }
        }
        return;
    }

    if (strstr(line, "\"method\":\"mining.notify\"") ||
        strstr(line, "\"method\": \"mining.notify\"")) {
        const char *pa = json_find_params_array(line);
        if (!pa) return;
        stratum_job_t *j = &c->job;
        memset(j, 0, sizeof(*j));
        if (!json_array_string_at(pa, 0, j->job_id, sizeof j->job_id)) return;
        if (!json_array_string_at(pa, 1, j->prevhash, sizeof j->prevhash)) return;
        if (!json_array_string_at(pa, 2, j->coinb1, sizeof j->coinb1)) return;
        if (!json_array_string_at(pa, 3, j->coinb2, sizeof j->coinb2)) return;

        /* merkle branches = params[4] nested array */
        const char *merk = json_array_elem(pa, 4);
        j->n_merkle = 0;
        if (merk && *merk == '[') {
            const char *p = merk + 1;
            while (j->n_merkle < STRATUM_MERKLE_MAX) {
                p = skip_ws(p);
                if (*p == ']') break;
                if (*p != '"') break;
                p++;
                size_t n = 0;
                while (*p && *p != '"' && n + 1 < sizeof j->merkle[0])
                    j->merkle[j->n_merkle][n++] = *p++;
                j->merkle[j->n_merkle][n] = '\0';
                j->n_merkle++;
                if (*p == '"') p++;
                p = skip_ws(p);
                if (*p == ',') p++;
            }
        }

        if (!json_array_string_at(pa, 5, j->version, sizeof j->version)) return;
        if (!json_array_string_at(pa, 6, j->nbits, sizeof j->nbits)) return;
        if (!json_array_string_at(pa, 7, j->ntime, sizeof j->ntime)) return;

        const char *cl = json_array_elem(pa, 8);
        j->clean = true;
        if (cl && strncmp(cl, "false", 5) == 0) j->clean = false;

        j->seq = ++c->jobs_seen;
        c->have_job = true;
        fprintf(stderr, "STRATUM: job id=%s ver=%s nbits=%s ntime=%s merkle=%d clean=%d\n",
                j->job_id, j->version, j->nbits, j->ntime, j->n_merkle, (int)j->clean);
        return;
    }

    /* JSON-RPC reply with id */
    long id = -1;
    if (json_get_int(line, "id", &id) == 0 && id >= 0) {
        c->last_reply_id = (int)id;
        strncpy(c->last_reply, line, sizeof c->last_reply - 1);
        c->last_reply[sizeof c->last_reply - 1] = '\0';
        c->last_reply_ok = json_result_true(line) ||
                           (json_result_null_error(line) && strstr(line, "\"result\":null") == NULL);
        /* authorize/subscribe: result may be array or true */
        if (strstr(line, "\"result\":true") || strstr(line, "\"result\": true"))
            c->last_reply_ok = true;
        if (json_find_result_array(line))
            c->last_reply_ok = json_result_null_error(line) || c->last_reply_ok;
        /* rejected share: result false */
        if (strstr(line, "\"result\":false") || strstr(line, "\"result\": false"))
            c->last_reply_ok = false;
        c->last_reply_ready = true;
        /* Async mining.submit: account here so the hash pool is not joined
         * on the pool round-trip. Blocking stratum_submit does not use a slot. */
        for (int i = 0; i < STRATUM_SUBMIT_SLOTS; i++) {
            if (c->submit_slot[i].id == (int)id) {
                uint32_t nonce = c->submit_slot[i].nonce;
                c->submit_slot[i].id = 0;
                c->submit_slot[i].nonce = 0;
                if (c->submit_pending > 0) c->submit_pending--;
                if (c->last_reply_ok) {
                    c->shares_accepted++;
                    fprintf(stderr, "STRATUM: share ACCEPTED nonce=%08x\n", nonce);
                } else {
                    c->shares_rejected++;
                    fprintf(stderr, "STRATUM: share REJECTED nonce=%08x\n", nonce);
                }
                break;
            }
        }
    }
}

int stratum_poll(stratum_client_t *c, int timeout_ms) {
    if (c->fd < 0) return -1;
    /* Select wait is not JSON work. Callers that print TIME_SPLIT can keep
     * the two counters apart (a timeout must not look like notify parsing). */
    uint64_t t0 = mono_ns();
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(c->fd, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int rv = select(c->fd + 1, &rfds, NULL, NULL, &tv);
    c->poll_wait_ns += mono_ns() - t0;
    if (rv < 0) {
        if (errno == EINTR) return 0;
        return -1;
    }
    if (rv == 0) return 0;

    t0 = mono_ns();
    int rc = 1;
    char tmp[4096];
    ssize_t n = recv(c->fd, tmp, sizeof tmp, 0);
    if (n == 0) {
        rc = -1;
    } else if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) rc = 0;
        else rc = -1;
    } else {
        if (c->rx_len + (size_t)n >= sizeof c->rx) {
            /* overflow — reset */
            c->rx_len = 0;
        }
        memcpy(c->rx + c->rx_len, tmp, (size_t)n);
        c->rx_len += (size_t)n;
        c->rx[c->rx_len] = '\0';

        char *start = c->rx;
        char *nl;
        while ((nl = strchr(start, '\n')) != NULL) {
            *nl = '\0';
            if (nl > start && nl[-1] == '\r') nl[-1] = '\0';
            if (*start) handle_line(c, start);
            start = nl + 1;
        }
        size_t rem = strlen(start);
        memmove(c->rx, start, rem + 1);
        c->rx_len = rem;
        rc = 1;
    }
    c->poll_busy_ns += mono_ns() - t0;
    return rc;
}

static int wait_reply(stratum_client_t *c, int id, int timeout_ms) {
    int waited = 0;
    c->last_reply_ready = false;
    while (waited < timeout_ms) {
        stratum_poll(c, 100);
        waited += 100;
        if (c->last_reply_ready && c->last_reply_id == id)
            return c->last_reply_ok ? 1 : 0;
    }
    return -1;
}

int stratum_connect(stratum_client_t *c, const char *host, int port,
                    const char *user, const char *pass, double suggest_diff) {
    memset(c, 0, sizeof(*c));
    c->fd = -1;
    c->difficulty = 1.0;
    c->next_id = 1;
    c->extranonce2_size = 4;
    strncpy(c->user, user, sizeof c->user - 1);
    strncpy(c->pass, pass ? pass : "x", sizeof c->pass - 1);

    char portstr[16];
    snprintf(portstr, sizeof portstr, "%d", port);
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int ga = getaddrinfo(host, portstr, &hints, &res);
    if (ga != 0) {
        fprintf(stderr, "STRATUM: getaddrinfo(%s): %s\n", host, gai_strerror(ga));
        return -1;
    }
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
        fprintf(stderr, "STRATUM: connect %s:%d failed\n", host, port);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    c->fd = fd;

    fprintf(stderr, "STRATUM: connected %s:%d\n", host, port);

    /* subscribe */
    int id = c->next_id++;
    if (stratum_send_req(c, id, "mining.subscribe", "[\"silicon-miner/0.2\"]") != 0)
        return -1;
    int ok = wait_reply(c, id, 8000);
    if (ok < 0) {
        fprintf(stderr, "STRATUM: subscribe timeout\n");
        return -1;
    }
    /* parse extranonce1 + size from result array */
    const char *ra = json_find_result_array(c->last_reply);
    if (ra) {
        /* result: [ [subs], extranonce1, extranonce2_size ] */
        const char *en1 = json_array_elem(ra, 1);
        if (en1 && *en1 == '"') {
            en1++;
            size_t n = 0;
            while (*en1 && *en1 != '"' && n + 1 < sizeof c->extranonce1)
                c->extranonce1[n++] = *en1++;
            c->extranonce1[n] = '\0';
        }
        const char *esz = json_array_elem(ra, 2);
        if (esz) c->extranonce2_size = (int)strtol(esz, NULL, 10);
        if (c->extranonce2_size < 1) c->extranonce2_size = 1;
        if (c->extranonce2_size > 8) c->extranonce2_size = 8;
    }
    fprintf(stderr, "STRATUM: subscribed en1=%s en2_size=%d\n",
            c->extranonce1, c->extranonce2_size);

    if (suggest_diff > 0.0) {
        id = c->next_id++;
        char params[64];
        snprintf(params, sizeof params, "[%.8g]", suggest_diff);
        stratum_send_req(c, id, "mining.suggest_difficulty", params);
        /* may push set_difficulty without reply */
        stratum_poll(c, 500);
    }

    /* authorize */
    id = c->next_id++;
    char params[512];
    /* escape not needed for our tb1 users */
    snprintf(params, sizeof params, "[\"%s\",\"%s\"]", c->user, c->pass);
    if (stratum_send_req(c, id, "mining.authorize", params) != 0)
        return -1;
    ok = wait_reply(c, id, 8000);
    if (ok != 1) {
        fprintf(stderr, "STRATUM: authorize failed: %s\n", c->last_reply);
        return -1;
    }
    c->authorized = true;
    fprintf(stderr, "STRATUM: authorized user=%s\n", c->user);

    /* wait briefly for first job */
    for (int i = 0; i < 50 && !c->have_job; i++)
        stratum_poll(c, 100);

    return 0;
}

void stratum_close(stratum_client_t *c) {
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

/* ---------- header construction ---------- */

static void store_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void stratum_prevhash_decode(const char *hex, uint8_t out[32]) {
    uint8_t raw[32];
    hex_decode(hex, raw, 32);
    for (int i = 0; i < 8; i++) {
        out[i * 4 + 0] = raw[i * 4 + 3];
        out[i * 4 + 1] = raw[i * 4 + 2];
        out[i * 4 + 2] = raw[i * 4 + 1];
        out[i * 4 + 3] = raw[i * 4 + 0];
    }
}

int stratum_build_header(const stratum_client_t *c, uint64_t extranonce2,
                         uint32_t nonce, uint8_t header80[80]) {
    if (!c->have_job) return -1;
    const stratum_job_t *j = &c->job;
    if (!j->ntime[0] || !j->nbits[0] || !j->version[0]) {
        fprintf(stderr, "STRATUM: build_header missing ver/nbits/ntime\n");
        return -1;
    }

    uint8_t coinb1[STRATUM_COINB_MAX / 2];
    uint8_t coinb2[STRATUM_COINB_MAX / 2];
    uint8_t en1[32];
    int n1 = hex_decode(j->coinb1, coinb1, sizeof coinb1);
    int n2 = hex_decode(j->coinb2, coinb2, sizeof coinb2);
    int ne = hex_decode(c->extranonce1, en1, sizeof en1);
    if (n1 < 0 || n2 < 0 || ne < 0) return -1;

    char en2hex[32];
    stratum_en2_hex(extranonce2, c->extranonce2_size, en2hex);
    uint8_t en2[16];
    int n_en2 = hex_decode(en2hex, en2, sizeof en2);
    if (n_en2 < 0) return -1;

    uint8_t coinbase[2048];
    size_t cb_len = 0;
    memcpy(coinbase + cb_len, coinb1, (size_t)n1); cb_len += (size_t)n1;
    memcpy(coinbase + cb_len, en1, (size_t)ne);    cb_len += (size_t)ne;
    memcpy(coinbase + cb_len, en2, (size_t)n_en2); cb_len += (size_t)n_en2;
    memcpy(coinbase + cb_len, coinb2, (size_t)n2); cb_len += (size_t)n2;

    uint8_t merkle[32];
    sha256d(coinbase, cb_len, merkle);
    for (int i = 0; i < j->n_merkle; i++) {
        uint8_t br[32];
        if (hex_decode(j->merkle[i], br, 32) != 32) return -1;
        uint8_t cat[64];
        memcpy(cat, merkle, 32);
        memcpy(cat + 32, br, 32);
        sha256d(cat, 64, merkle);
    }

    uint32_t version = (uint32_t)strtoul(j->version, NULL, 16);
    uint32_t ntime   = (uint32_t)strtoul(j->ntime, NULL, 16);
    uint32_t nbits   = (uint32_t)strtoul(j->nbits, NULL, 16);

    store_u32_le(header80 + 0, version);
    stratum_prevhash_decode(j->prevhash, header80 + 4);
    memcpy(header80 + 36, merkle, 32);
    store_u32_le(header80 + 68, ntime);
    store_u32_le(header80 + 72, nbits);
    store_u32_le(header80 + 76, nonce);
    return 0;
}

static int submit_alloc_slot(stratum_client_t *c, int id, uint32_t nonce) {
    for (int i = 0; i < STRATUM_SUBMIT_SLOTS; i++) {
        if (c->submit_slot[i].id == 0) {
            c->submit_slot[i].id = id;
            c->submit_slot[i].nonce = nonce;
            c->submit_pending++;
            return 0;
        }
    }
    return -1;
}

int stratum_submit_async(stratum_client_t *c, const char *job_id,
                         uint64_t extranonce2, const char *ntime_hex,
                         uint32_t nonce) {
    if (c->fd < 0 || !job_id || !job_id[0] || !ntime_hex) return -1;
    char en2hex[32];
    char noncehex[16];
    stratum_en2_hex(extranonce2, c->extranonce2_size, en2hex);
    snprintf(noncehex, sizeof noncehex, "%08x", nonce);

    int id = c->next_id++;
    if (submit_alloc_slot(c, id, nonce) != 0) {
        c->next_id--;
        fprintf(stderr, "STRATUM: submit queue full\n");
        return -1;
    }
    char params[1024];
    snprintf(params, sizeof params, "[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]",
             c->user, job_id, en2hex, ntime_hex, noncehex);
    c->shares_submitted++;
    if (stratum_send_req(c, id, "mining.submit", params) != 0) {
        for (int i = 0; i < STRATUM_SUBMIT_SLOTS; i++) {
            if (c->submit_slot[i].id == id) {
                c->submit_slot[i].id = 0;
                c->submit_slot[i].nonce = 0;
                if (c->submit_pending > 0) c->submit_pending--;
                break;
            }
        }
        c->shares_submitted--;
        return -1;
    }
    fprintf(stderr, "STRATUM: share queued nonce=%s job=%s (hash continues)\n",
            noncehex, job_id);
    return 0;
}

int stratum_submit_drain(stratum_client_t *c, int timeout_ms) {
    int waited = 0;
    if (timeout_ms < 0) timeout_ms = 0;
    while (c->submit_pending > 0 && waited < timeout_ms) {
        if (stratum_poll(c, 100) < 0) break;
        waited += 100;
    }
    return c->submit_pending;
}

int stratum_submit(stratum_client_t *c, uint64_t extranonce2,
                   const char *ntime_hex, uint32_t nonce) {
    if (c->fd < 0 || !c->have_job) return -1;
    char en2hex[32];
    char noncehex[16];
    stratum_en2_hex(extranonce2, c->extranonce2_size, en2hex);
    snprintf(noncehex, sizeof noncehex, "%08x", nonce);

    int id = c->next_id++;
    char params[1024];
    snprintf(params, sizeof params, "[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]",
             c->user, c->job.job_id, en2hex, ntime_hex, noncehex);
    c->shares_submitted++;
    if (stratum_send_req(c, id, "mining.submit", params) != 0) return -1;
    int ok = wait_reply(c, id, 10000);
    if (ok == 1) {
        c->shares_accepted++;
        fprintf(stderr, "STRATUM: share ACCEPTED nonce=%s\n", noncehex);
        return 1;
    }
    if (ok == 0) {
        c->shares_rejected++;
        fprintf(stderr, "STRATUM: share REJECTED: %s\n", c->last_reply);
        return 0;
    }
    fprintf(stderr, "STRATUM: share submit timeout\n");
    return -1;
}
