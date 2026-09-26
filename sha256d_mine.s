// sha256d_mine.s — Educational Bitcoin SHA-256d mining core for Apple Silicon
// Pure ARM64 assembly using ARMv8 Crypto Extension:
//   SHA256H, SHA256H2, SHA256SU0, SHA256SU1
// NO C in the hash path. macOS Mach-O: underscore-prefixed exports.
//
// v1+v2 opts IN this file:
//   - K staged from .rodata (LK256 in __TEXT,__const): 4-vector sliding
//     window in v28–v31, reloaded every 4 round-groups (ld1 4s×4). K is NOT
//     kept resident in v16–v31, freeing those regs for a second nonce lane.
//   - Dual-lane mine: two nonces in flight. Reg map (mine hot path):
//       Lane A: v0/v1 state, v4–v7 W, v16 WK, v17 h2tmp
//       Lane B: v18/v19 state, v22–v25 W, v26 WK, v27 h2tmp
//       K window: v28–v31 (from LK256)
//       Cached (callee-saved): v8/v9 midstate, v10/v11 expect,
//                              v12/v13 2nd-SHA pad, v14/v15 IV
//     v2/v3/v20/v21 are not used as save copies on this path. The dual-lane
//     tail adds v8/v9 (midstate) and v14/v15 (IV) in place. Single-lane
//     leftover still keeps its own save copies. No third lane: the freed
//     regs are not enough to hold another W/state/tmp set without evicting
//     the cached midstate, IV, or pad.
//   - Dual-lane schedule: the next group's SU0 issues before sha256h (H
//     latency covers it) and SU1 sits between sha256h and sha256h2. The next
//     K window ld1 is after the add that consumed v31, still under that hash.
//     First-SHA rounds 4–15 share one WK (only W3/nonce differs per lane).
//   - Nonce splice: fixed block1 words pre-REV32'd; only W3 updated per nonce
//   - Second-SHA (item 2) — precomputed vs per-nonce:
//       PRECOMPUTED / shared across nonces + lanes:
//         • pad W8–W15 (0x80.. len 256) in v12/v13; IV in v14/v15; K base x25
//         • rounds 8–15 WK identical for both lanes → one add, dual sha256h
//         • sha256su0(W8–11,W12–15) is a no-op for 32-byte pad AND for
//           block1 W8–11=0 → skip at W24–27 extend (SU1 still digest-dep)
//       PER-NONCE (digest-dependent; full W16+ pre-extend is NOT valid):
//         • W0–W7 = digest1; SU0/SU1 from W16 up all digest-tainted after
//       Amortization: K0–15 reload overlapped with first-SHA final adds;
//         shared pad WK on rounds 8–15; skip no-op pad/zero SU0 at W24.
//   - Odd leftover nonce: single-lane path with same K-window staging
//   - Batched full-digest compare vs expect (self-test / gate)
//
// Calling convention (AAPCS64 / Apple):
//   _sha256_compress(uint32_t state[8], const uint8_t block[64])
//   _sha256d_genesis_selftest(void) -> w0: 0=pass, nonzero=fail code
//   _sha256d_mine_midstate(const uint32_t mid[8], const uint32_t w_be[16],
//                          uint32_t nonce0, uint32_t count,
//                          const uint32_t expect[8], uint32_t *found) -> w0: 1=found, 0=not
//
.arch armv8-a+crypto
.text
.align 4

//------------------------------------------------------------------------------
// void _sha256_compress(uint32_t state[8], const uint8_t block[64]);
// Non-hot path: loads full K into v16–v31 (single-block; not dual-lane).
//------------------------------------------------------------------------------
.globl _sha256_compress
.p2align 4
_sha256_compress:
    stp     q8, q9, [sp, #-32]!

    adrp    x9, LK256@PAGE
    add     x9, x9, LK256@PAGEOFF
    ld1     {v16.4s, v17.4s, v18.4s, v19.4s}, [x9], #64
    ld1     {v20.4s, v21.4s, v22.4s, v23.4s}, [x9], #64
    ld1     {v24.4s, v25.4s, v26.4s, v27.4s}, [x9], #64
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9]

    ld1     {v0.4s, v1.4s}, [x0]
    mov     v2.16b, v0.16b
    mov     v3.16b, v1.16b

    ld1     {v4.16b, v5.16b, v6.16b, v7.16b}, [x1]
    rev32   v4.16b, v4.16b
    rev32   v5.16b, v5.16b
    rev32   v6.16b, v6.16b
    rev32   v7.16b, v7.16b

    add     v8.4s, v4.4s, v16.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    add     v8.4s, v5.4s, v17.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    add     v8.4s, v6.4s, v18.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    add     v8.4s, v7.4s, v19.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    add     v8.4s, v4.4s, v20.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    add     v8.4s, v5.4s, v21.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v6.4s, v7.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    add     v8.4s, v6.4s, v22.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    add     v8.4s, v7.4s, v23.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    add     v8.4s, v4.4s, v24.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    add     v8.4s, v5.4s, v25.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v6.4s, v7.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    add     v8.4s, v6.4s, v26.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    add     v8.4s, v7.4s, v27.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    add     v8.4s, v4.4s, v28.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    add     v8.4s, v5.4s, v29.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v6.4s, v7.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    add     v8.4s, v6.4s, v30.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    add     v8.4s, v7.4s, v31.4s
    mov     v9.16b, v0.16b
    sha256h q0, q1, v8.4s
    sha256h2 q1, q9, v8.4s

    add     v0.4s, v0.4s, v2.4s
    add     v1.4s, v1.4s, v3.4s
    st1     {v0.4s, v1.4s}, [x0]

    ldp     q8, q9, [sp], #32
    ret

//------------------------------------------------------------------------------
// int _sha256d_genesis_selftest(void);
//------------------------------------------------------------------------------
.globl _sha256d_genesis_selftest
.p2align 4
_sha256d_genesis_selftest:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    stp     q8, q9, [sp, #-32]!

    adrp    x0, Labc_state@PAGE
    add     x0, x0, Labc_state@PAGEOFF
    adrp    x1, Lsha_iv@PAGE
    add     x1, x1, Lsha_iv@PAGEOFF
    ld1     {v0.4s, v1.4s}, [x1]
    st1     {v0.4s, v1.4s}, [x0]
    adrp    x1, Labc_block@PAGE
    add     x1, x1, Labc_block@PAGEOFF
    bl      _sha256_compress
    adrp    x2, Labc_expect@PAGE
    add     x2, x2, Labc_expect@PAGEOFF
    adrp    x0, Labc_state@PAGE
    add     x0, x0, Labc_state@PAGEOFF
    ld1     {v0.4s, v1.4s}, [x0]
    ld1     {v2.4s, v3.4s}, [x2]
    eor     v0.16b, v0.16b, v2.16b
    eor     v1.16b, v1.16b, v3.16b
    orr     v0.16b, v0.16b, v1.16b
    umaxv   s0, v0.4s
    fmov    w0, s0
    cbnz    w0, Lst_fail_abc

    adrp    x0, Lgen_mid@PAGE
    add     x0, x0, Lgen_mid@PAGEOFF
    adrp    x1, Lgen_wbe@PAGE
    add     x1, x1, Lgen_wbe@PAGEOFF
    movz    w2, #0xac1d
    movk    w2, #0x7c2b, lsl #16
    mov     w3, #1
    adrp    x4, Lgen_expect@PAGE
    add     x4, x4, Lgen_expect@PAGEOFF
    adrp    x5, Lfound_nonce@PAGE
    add     x5, x5, Lfound_nonce@PAGEOFF
    bl      _sha256d_mine_midstate
    cbz     w0, Lst_fail_gen
    adrp    x5, Lfound_nonce@PAGE
    add     x5, x5, Lfound_nonce@PAGEOFF
    ldr     w6, [x5]
    movz    w7, #0xac1d
    movk    w7, #0x7c2b, lsl #16
    cmp     w6, w7
    b.ne    Lst_fail_gen

    adrp    x0, Lgen_mid@PAGE
    add     x0, x0, Lgen_mid@PAGEOFF
    adrp    x1, Lgen_wbe@PAGE
    add     x1, x1, Lgen_wbe@PAGEOFF
    movz    w2, #0xac1c
    movk    w2, #0x7c2b, lsl #16
    mov     w3, #3
    adrp    x4, Lgen_expect@PAGE
    add     x4, x4, Lgen_expect@PAGEOFF
    adrp    x5, Lfound_nonce@PAGE
    add     x5, x5, Lfound_nonce@PAGEOFF
    bl      _sha256d_mine_midstate
    cbz     w0, Lst_fail_gen
    adrp    x5, Lfound_nonce@PAGE
    add     x5, x5, Lfound_nonce@PAGEOFF
    ldr     w6, [x5]
    movz    w7, #0xac1d
    movk    w7, #0x7c2b, lsl #16
    cmp     w6, w7
    b.ne    Lst_fail_gen

    mov     w0, #0
    b       Lst_done
Lst_fail_abc:
    mov     w0, #1
    b       Lst_done
Lst_fail_gen:
    mov     w0, #2
Lst_done:
    ldp     q8, q9, [sp], #32
    ldp     x29, x30, [sp], #16
    ret

//------------------------------------------------------------------------------
// int _sha256d_mine_midstate(
//   const uint32_t midstate[8],   // x0
//   const uint32_t w_be[16],      // x1
//   uint32_t nonce_start,         // w2
//   uint32_t nonce_count,         // w3
//   const uint32_t expect[8],     // x4
//   uint32_t *found_nonce);       // x5
//
// K staging (mine loop): LK256 in .rodata; 4-vector window v28–v31 reloaded
// every 4 round-groups so dual-lane state/W/temps fit in caller-saved NEON.
//------------------------------------------------------------------------------
.globl _sha256d_mine_midstate
.p2align 4
_sha256d_mine_midstate:
    // Frame layout (208 bytes):
    //   [0]=x29,x30  [16]=x19,x20  [32]=x21,x22  [48]=x23,x24
    //   [64]=x25     [80]=q8,q9  [112]=q10,q11  [144]=q12,q13  [176]=q14,q15
    stp     x29, x30, [sp, #-208]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    str     x25, [sp, #64]
    stp     q8, q9, [sp, #80]
    stp     q10, q11, [sp, #112]
    stp     q12, q13, [sp, #144]
    stp     q14, q15, [sp, #176]

    mov     x19, x0                     // midstate*
    mov     x20, x1                     // w_be*
    mov     w21, w2                     // nonce
    mov     w22, w3                     // remaining
    mov     x23, x4                     // expect* (also cached in NEON)
    mov     x24, x5                     // found*

    // LK256 base for K-window resets
    adrp    x25, LK256@PAGE
    add     x25, x25, LK256@PAGEOFF

    // Cache midstate / expect / pad / IV in callee-saved v8–v15
    ld1     {v8.4s, v9.4s}, [x19]
    ld1     {v10.4s, v11.4s}, [x23]
    adrp    x9, Lsha2_pad@PAGE
    add     x9, x9, Lsha2_pad@PAGEOFF
    ld1     {v12.4s, v13.4s}, [x9]
    adrp    x9, Lsha_iv@PAGE
    add     x9, x9, Lsha_iv@PAGEOFF
    ld1     {v14.4s, v15.4s}, [x9]

    cbz     w22, Lmine_miss
    cmp     w22, #1
    b.eq    Lmine_single

Lmine_dual_loop:
    // Need at least 2 nonces. Schedule: next group's SU0 issues before
    // sha256h and SU1 between sha256h and sha256h2. K ld1 for the next
    // window is after the add that consumed v31. Midstate/IV are added
    // from v8/v9 and v14/v15 — no save copies in v2/v3/v20/v21.
    // First-SHA rounds 4–15 share one WK (only W3 differs per lane).
    cmp     w22, #2
    b.lo    Lmine_single
    // Working state from cached midstate (v8/v9). Both lanes.
    mov     v0.16b, v8.16b
    mov     v1.16b, v9.16b
    mov     v18.16b, v8.16b
    mov     v19.16b, v9.16b
    // W template + nonce splice into W3 only.
    ld1     {v4.4s, v5.4s, v6.4s, v7.4s}, [x20]
    ld1     {v22.4s, v23.4s, v24.4s, v25.4s}, [x20]
    rev     w8, w21
    mov     v4.s[3], w8
    add     w9, w21, #1
    rev     w8, w9
    mov     v22.s[3], w8
    // ---- first SHA (block1) ----
    mov     x9, x25
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    add     v16.4s, v4.4s, v28.4s
    add     v26.4s, v22.4s, v28.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v5.4s, v29.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v16.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v16.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    sha256su0 v4.4s, v5.4s
    sha256su0 v22.4s, v23.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v16.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    sha256su1 v22.4s, v24.4s, v25.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v16.4s
    add     v16.4s, v4.4s, v28.4s
    add     v26.4s, v22.4s, v28.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v5.4s, v6.4s
    sha256su0 v23.4s, v24.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    sha256su1 v23.4s, v25.4s, v22.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v5.4s, v29.4s
    add     v26.4s, v23.4s, v29.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    sha256su1 v24.4s, v22.4s, v23.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v6.4s, v30.4s
    add     v26.4s, v24.4s, v30.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v7.4s, v4.4s
    sha256su0 v25.4s, v22.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    sha256su1 v25.4s, v23.4s, v24.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v7.4s, v31.4s
    add     v26.4s, v25.4s, v31.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    sha256su0 v4.4s, v5.4s
    sha256su0 v22.4s, v23.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    sha256su1 v22.4s, v24.4s, v25.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v4.4s, v28.4s
    add     v26.4s, v22.4s, v28.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v5.4s, v6.4s
    sha256su0 v23.4s, v24.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    sha256su1 v23.4s, v25.4s, v22.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v5.4s, v29.4s
    add     v26.4s, v23.4s, v29.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v6.4s, v7.4s
    sha256su0 v24.4s, v25.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    sha256su1 v24.4s, v22.4s, v23.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v6.4s, v30.4s
    add     v26.4s, v24.4s, v30.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v7.4s, v4.4s
    sha256su0 v25.4s, v22.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    sha256su1 v25.4s, v23.4s, v24.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v7.4s, v31.4s
    add     v26.4s, v25.4s, v31.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9]
    sha256su0 v4.4s, v5.4s
    sha256su0 v22.4s, v23.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    sha256su1 v22.4s, v24.4s, v25.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v4.4s, v28.4s
    add     v26.4s, v22.4s, v28.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v5.4s, v6.4s
    sha256su0 v23.4s, v24.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    sha256su1 v23.4s, v25.4s, v22.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v5.4s, v29.4s
    add     v26.4s, v23.4s, v29.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v6.4s, v7.4s
    sha256su0 v24.4s, v25.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    sha256su1 v24.4s, v22.4s, v23.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v6.4s, v30.4s
    add     v26.4s, v24.4s, v30.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v7.4s, v4.4s
    sha256su0 v25.4s, v22.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    sha256su1 v25.4s, v23.4s, v24.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v7.4s, v31.4s
    add     v26.4s, v25.4s, v31.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    mov     x9, x25
    // Bridge: fold midstate, reload K0–15 under those adds.
    add     v0.4s, v0.4s, v8.4s
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    add     v1.4s, v1.4s, v9.4s
    add     v18.4s, v18.4s, v8.4s
    add     v19.4s, v19.4s, v9.4s
    // Digest -> W0–W7, cached pad -> W8–W15, cached IV -> state.
    // ---- second SHA ----
    mov     v4.16b, v0.16b
    mov     v5.16b, v1.16b
    mov     v22.16b, v18.16b
    mov     v23.16b, v19.16b
    mov     v6.16b, v12.16b
    mov     v7.16b, v13.16b
    mov     v24.16b, v12.16b
    mov     v25.16b, v13.16b
    mov     v0.16b, v14.16b
    mov     v1.16b, v15.16b
    mov     v18.16b, v14.16b
    mov     v19.16b, v15.16b
    add     v16.4s, v4.4s, v28.4s
    add     v26.4s, v22.4s, v28.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v5.4s, v29.4s
    add     v26.4s, v23.4s, v29.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v16.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    sha256su0 v4.4s, v5.4s
    sha256su0 v22.4s, v23.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v16.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    sha256su1 v22.4s, v24.4s, v25.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v16.4s
    add     v16.4s, v4.4s, v28.4s
    add     v26.4s, v22.4s, v28.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v5.4s, v6.4s
    sha256su0 v23.4s, v24.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    sha256su1 v23.4s, v25.4s, v22.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v5.4s, v29.4s
    add     v26.4s, v23.4s, v29.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    sha256su1 v24.4s, v22.4s, v23.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v6.4s, v30.4s
    add     v26.4s, v24.4s, v30.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v7.4s, v4.4s
    sha256su0 v25.4s, v22.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    sha256su1 v25.4s, v23.4s, v24.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v7.4s, v31.4s
    add     v26.4s, v25.4s, v31.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    sha256su0 v4.4s, v5.4s
    sha256su0 v22.4s, v23.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    sha256su1 v22.4s, v24.4s, v25.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v4.4s, v28.4s
    add     v26.4s, v22.4s, v28.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v5.4s, v6.4s
    sha256su0 v23.4s, v24.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    sha256su1 v23.4s, v25.4s, v22.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v5.4s, v29.4s
    add     v26.4s, v23.4s, v29.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v6.4s, v7.4s
    sha256su0 v24.4s, v25.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    sha256su1 v24.4s, v22.4s, v23.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v6.4s, v30.4s
    add     v26.4s, v24.4s, v30.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v7.4s, v4.4s
    sha256su0 v25.4s, v22.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    sha256su1 v25.4s, v23.4s, v24.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v7.4s, v31.4s
    add     v26.4s, v25.4s, v31.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9]
    sha256su0 v4.4s, v5.4s
    sha256su0 v22.4s, v23.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    sha256su1 v22.4s, v24.4s, v25.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v4.4s, v28.4s
    add     v26.4s, v22.4s, v28.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v5.4s, v6.4s
    sha256su0 v23.4s, v24.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    sha256su1 v23.4s, v25.4s, v22.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v5.4s, v29.4s
    add     v26.4s, v23.4s, v29.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v6.4s, v7.4s
    sha256su0 v24.4s, v25.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    sha256su1 v24.4s, v22.4s, v23.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v6.4s, v30.4s
    add     v26.4s, v24.4s, v30.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256su0 v7.4s, v4.4s
    sha256su0 v25.4s, v22.4s
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    sha256su1 v25.4s, v23.4s, v24.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    add     v16.4s, v7.4s, v31.4s
    add     v26.4s, v25.4s, v31.4s
    mov     v17.16b, v0.16b
    mov     v27.16b, v18.16b
    sha256h q0, q1, v16.4s
    sha256h q18, q19, v26.4s
    sha256h2 q1, q17, v16.4s
    sha256h2 q19, q27, v26.4s
    // Tail: lane A compare overlaps lane B's IV add. Earliest nonce wins.
    add     v0.4s, v0.4s, v14.4s
    add     v1.4s, v1.4s, v15.4s
    eor     v16.16b, v0.16b, v10.16b
    add     v18.4s, v18.4s, v14.4s
    eor     v17.16b, v1.16b, v11.16b
    add     v19.4s, v19.4s, v15.4s
    orr     v16.16b, v16.16b, v17.16b
    umaxv   s16, v16.4s
    fmov    w8, s16
    cbz     w8, Lmine_hit_A
    eor     v16.16b, v18.16b, v10.16b
    eor     v17.16b, v19.16b, v11.16b
    orr     v16.16b, v16.16b, v17.16b
    umaxv   s16, v16.4s
    fmov    w8, s16
    cbz     w8, Lmine_hit_B
    add     w21, w21, #2
    sub     w22, w22, #2
    cbnz    w22, Lmine_dual_loop
    b       Lmine_miss
Lmine_hit_A:
    str     w21, [x24]
    mov     w0, #1
    b       Lmine_epi

Lmine_hit_B:
    add     w8, w21, #1
    str     w8, [x24]
    mov     w0, #1
    b       Lmine_epi

//------------------------------------------------------------------------------
// Single-lane leftover (count==1) or entry when only one nonce remains
//------------------------------------------------------------------------------
Lmine_single:
    cbz     w22, Lmine_miss

    mov     v0.16b, v8.16b
    mov     v1.16b, v9.16b
    mov     v2.16b, v8.16b
    mov     v3.16b, v9.16b
    ld1     {v4.4s, v5.4s, v6.4s, v7.4s}, [x20]
    rev     w8, w21
    mov     v4.s[3], w8
    mov     x9, x25
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    add     v16.4s, v4.4s, v28.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    add     v16.4s, v5.4s, v29.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    add     v16.4s, v4.4s, v28.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    add     v16.4s, v5.4s, v29.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    // W24–27: pad/zero SU0 no-op (see dual); SU1 only
    sha256su1 v6.4s, v4.4s, v5.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    add     v16.4s, v4.4s, v28.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    add     v16.4s, v5.4s, v29.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v6.4s, v7.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9]
    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    add     v16.4s, v4.4s, v28.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    add     v16.4s, v5.4s, v29.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v6.4s, v7.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    // Item 2 single: overlap K0–15 reload with digest finalize
    mov     x9, x25
    add     v0.4s, v0.4s, v2.4s
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    add     v1.4s, v1.4s, v3.4s

    mov     v4.16b, v0.16b
    mov     v5.16b, v1.16b
    mov     v6.16b, v12.16b
    mov     v7.16b, v13.16b
    mov     v0.16b, v14.16b
    mov     v1.16b, v15.16b
    mov     v2.16b, v14.16b
    mov     v3.16b, v15.16b
    add     v16.4s, v4.4s, v28.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    add     v16.4s, v5.4s, v29.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    add     v16.4s, v4.4s, v28.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    add     v16.4s, v5.4s, v29.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    // W24–27: pad/zero SU0 no-op (see dual); SU1 only
    sha256su1 v6.4s, v4.4s, v5.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9], #64
    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    add     v16.4s, v4.4s, v28.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    add     v16.4s, v5.4s, v29.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v6.4s, v7.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    ld1     {v28.4s, v29.4s, v30.4s, v31.4s}, [x9]
    sha256su0 v4.4s, v5.4s
    sha256su1 v4.4s, v6.4s, v7.4s
    add     v16.4s, v4.4s, v28.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v5.4s, v6.4s
    sha256su1 v5.4s, v7.4s, v4.4s
    add     v16.4s, v5.4s, v29.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v6.4s, v7.4s
    sha256su1 v6.4s, v4.4s, v5.4s
    add     v16.4s, v6.4s, v30.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    sha256su0 v7.4s, v4.4s
    sha256su1 v7.4s, v5.4s, v6.4s
    add     v16.4s, v7.4s, v31.4s
    mov     v17.16b, v0.16b
    sha256h q0, q1, v16.4s
    sha256h2 q1, q17, v16.4s
    add     v0.4s, v0.4s, v2.4s
    add     v1.4s, v1.4s, v3.4s

    eor     v16.16b, v0.16b, v10.16b
    eor     v17.16b, v1.16b, v11.16b
    orr     v16.16b, v16.16b, v17.16b
    umaxv   s16, v16.4s
    fmov    w8, s16
    cbz     w8, Lmine_hit_A

    add     w21, w21, #1
    sub     w22, w22, #1
    cbnz    w22, Lmine_single

Lmine_miss:
    mov     w0, #0

Lmine_epi:
    ldp     q14, q15, [sp, #176]
    ldp     q12, q13, [sp, #144]
    ldp     q10, q11, [sp, #112]
    ldp     q8, q9, [sp, #80]
    ldr     x25, [sp, #64]
    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #208
    ret

//------------------------------------------------------------------------------
// Read-only constants (Mach-O const section ≈ .rodata)
//------------------------------------------------------------------------------
.section __TEXT,__const
.p2align 4

LK256:
    .long 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
    .long 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    .long 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
    .long 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
    .long 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
    .long 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
    .long 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
    .long 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
    .long 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
    .long 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
    .long 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
    .long 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
    .long 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
    .long 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
    .long 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
    .long 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2

Lsha_iv:
    .long 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    .long 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

// Second-SHA fixed pad for 32-byte digest1 (bitlen=256). Cached in v12/v13.
// sha256su0(W8–11,W12–15) == W8–11 (no-op) — enables W24–27 SU0 skip.
Lsha2_pad:
    .long 0x80000000, 0x00000000, 0x00000000, 0x00000000
    .long 0x00000000, 0x00000000, 0x00000000, 0x00000100

Labc_block:
    .byte 0x61,0x62,0x63,0x80
    .byte 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
    .byte 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
    .byte 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
    .byte 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
    .byte 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
    .byte 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00
    .byte 0x00,0x00,0x00,0x00
    .byte 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x18

Labc_expect:
    .long 0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223
    .long 0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad

.p2align 4
Lgen_mid:
    .long 0xbc909a33, 0x6358bff0, 0x90ccac7d, 0x1e59caa8
    .long 0xc3c8d8e9, 0x4f0103c8, 0x96b18736, 0x4719f91b

Lgen_wbe:
    .long 0x4b1e5e4a, 0x29ab5f49, 0xffff001d, 0x1dac2b7c
    .long 0x80000000, 0x00000000, 0x00000000, 0x00000000
    .long 0x00000000, 0x00000000, 0x00000000, 0x00000000
    .long 0x00000000, 0x00000000, 0x00000000, 0x00000280

Lgen_expect:
    .long 0x6fe28c0a, 0xb6f1b372, 0xc1a6a246, 0xae63f74f
    .long 0x931e8365, 0xe15a089c, 0x68d61900, 0x00000000

//------------------------------------------------------------------------------
// Writable scratch
//------------------------------------------------------------------------------
.data
.p2align 4
Labc_state:
    .long 0,0,0,0, 0,0,0,0
Lfound_nonce:
    .long 0
