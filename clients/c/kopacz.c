/*
 * kopacz.c — Portable, zero-dependency Kopacz v3 DNS Tunnel Client in C99
 *
 * Implements the complete Kopacz v3 wire protocol:
 *   - X25519 ECDH key exchange (RFC 7748)
 *   - SHA-256, HMAC-SHA256, and HKDF-SHA256 (RFC 5869)
 *   - ChaCha20-Poly1305 AEAD (RFC 7539 / RFC 8439)
 *   - LZ4 frame decompression (RFC / LZ4 Frame Format)
 *   - Base32 lowercase unpadded DNS QNAME & TXT carrier encoding
 *   - 8-byte Kopacz v3 Header + 8-byte AEAD Control MAC + Fragment Reassembly
 *   - Raw UDP/53 DNS packet builder & multi-segment TXT parser
 *
 * Build (Linux / macOS / BSD):
 *   cc -O2 -Wall -Wextra -std=c99 -o kopacz kopacz.c
 *
 * Usage:
 *   ./kopacz -d t.example.com -k <64-hex-psk> [-r 1.1.1.1] fetch https://example.com
 *   ./kopacz -d t.example.com -k <64-hex-psk> [-r 1.1.1.1] ssh
 */

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ── CSPRNG ──────────────────────────────────────────────────────── */

static int csprng_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, buf + off, len - off);
        if (r <= 0) { close(fd); return -1; }
        off += (size_t)r;
    }
    close(fd);
    return 0;
}

/* ── SHA-256 & HMAC-SHA256 & HKDF-SHA256 ────────────────────────── */

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
} sha256_ctx;

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(sha256_ctx *ctx, const uint8_t data[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i*4] << 24) | ((uint32_t)data[i*4+1] << 16) |
               ((uint32_t)data[i*4+2] << 8) | (uint32_t)data[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotr32(w[i-2], 17) ^ rotr32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t e = ctx->state[4], f = ctx->state[5], g = ctx->state[6], h = ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
    ctx->bitcount = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3F);
    ctx->bitcount += (uint64_t)len << 3;
    size_t i = 0;
    if (idx) {
        size_t left = 64 - idx;
        if (len < left) { memcpy(ctx->buffer + idx, data, len); return; }
        memcpy(ctx->buffer + idx, data, left);
        sha256_transform(ctx, ctx->buffer);
        i += left;
    }
    for (; i + 64 <= len; i += 64) sha256_transform(ctx, data + i);
    if (i < len) memcpy(ctx->buffer, data + i, len - i);
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3F);
    ctx->buffer[idx++] = 0x80;
    if (idx > 56) {
        memset(ctx->buffer + idx, 0, 64 - idx);
        sha256_transform(ctx, ctx->buffer);
        idx = 0;
    }
    memset(ctx->buffer + idx, 0, 56 - idx);
    for (int i = 0; i < 8; i++) ctx->buffer[56 + i] = (uint8_t)(ctx->bitcount >> (56 - i * 8));
    sha256_transform(ctx, ctx->buffer);
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        out[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len, uint8_t out[32]) {
    uint8_t k_ipad[64], k_opad[64], tk[32];
    if (key_len > 64) {
        sha256_ctx tctx; sha256_init(&tctx); sha256_update(&tctx, key, key_len); sha256_final(&tctx, tk);
        key = tk; key_len = 32;
    }
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);
    for (size_t i = 0; i < key_len; i++) { k_ipad[i] ^= key[i]; k_opad[i] ^= key[i]; }
    uint8_t inner[32];
    sha256_ctx ictx; sha256_init(&ictx); sha256_update(&ictx, k_ipad, 64); sha256_update(&ictx, data, data_len); sha256_final(&ictx, inner);
    sha256_ctx octx; sha256_init(&octx); sha256_update(&octx, k_opad, 64); sha256_update(&octx, inner, 32); sha256_final(&octx, out);
}

static void hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *salt, size_t salt_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len) {
    uint8_t prk[32];
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    uint8_t t[32];
    size_t t_len = 0, pos = 0;
    uint8_t ctr = 1;
    while (pos < okm_len) {
        uint8_t buf[128];
        memcpy(buf, t, t_len);
        memcpy(buf + t_len, info, info_len);
        buf[t_len + info_len] = ctr++;
        hmac_sha256(prk, 32, buf, t_len + info_len + 1, t);
        t_len = 32;
        size_t copy = (okm_len - pos < 32) ? (okm_len - pos) : 32;
        memcpy(okm + pos, t, copy);
        pos += copy;
    }
}

/* ── X25519 (TweetNaCl public domain field arithmetic) ─────────── */

typedef int64_t gf[16];

static void car25519(gf o) {
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b) {
    int64_t t, c = ~(b - 1);
    for (int i = 0; i < 16; i++) { t = c & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; }
}

static void pack25519(uint8_t o[32], const gf n) {
    gf m, t;
    for (int i = 0; i < 16; i++) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = (int)((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) { o[2 * i] = (uint8_t)(t[i] & 0xff); o[2 * i + 1] = (uint8_t)(t[i] >> 8); }
}

static void unpack25519(gf o, const uint8_t n[32]) {
    for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A25519(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void Z25519(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

static void M25519(gf o, const gf a, const gf b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++) for (int j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o); car25519(o);
}

static void S25519(gf o, const gf a) { M25519(o, a, a); }

static void inv25519(gf o, const gf i) {
    gf c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) { S25519(c, c); if (a != 2 && a != 4) M25519(c, c, i); }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}

static void x25519_scalarmult(uint8_t q[32], const uint8_t n[32], const uint8_t p[32]) {
    uint8_t z[32];
    int64_t x[80];
    gf a = {0}, b = {0}, c = {0}, d = {0}, e, f;
    static const gf _121665 = {0xDB41, 1};
    for (int i = 0; i < 31; i++) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x, p);
    for (int i = 0; i < 16; i++) b[i] = x[i];
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        int r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, r); sel25519(c, d, r);
        A25519(e, a, c); Z25519(a, a, c); A25519(c, b, d); Z25519(b, b, d);
        S25519(d, e); S25519(f, a); M25519(a, c, a); M25519(c, b, e);
        A25519(e, a, c); Z25519(a, a, c); S25519(b, a); Z25519(c, d, f);
        M25519(a, c, _121665); A25519(a, a, d); M25519(c, c, a); M25519(a, d, f);
        M25519(d, b, x); S25519(b, e);
        sel25519(a, b, r); sel25519(c, d, r);
    }
    for (int i = 0; i < 16; i++) { x[i + 16] = a[i]; x[i + 32] = c[i]; x[i + 48] = b[i]; x[i + 64] = d[i]; }
    inv25519(x + 32, x + 32);
    M25519(x + 16, x + 16, x + 32);
    pack25519(q, x + 16);
}

static void x25519_base(uint8_t pk[32], const uint8_t sk[32]) {
    uint8_t base[32] = {9};
    x25519_scalarmult(pk, sk, base);
}

/* ── ChaCha20-Poly1305 (RFC 7539 / RFC 8439) ─────────────────────── */

static inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t load32_le(const uint8_t s[4]) {
    return (uint32_t)s[0] | ((uint32_t)s[1] << 8) | ((uint32_t)s[2] << 16) | ((uint32_t)s[3] << 24);
}
static inline void store32_le(uint8_t d[4], uint32_t v) {
    d[0] = (uint8_t)v; d[1] = (uint8_t)(v >> 8); d[2] = (uint8_t)(v >> 16); d[3] = (uint8_t)(v >> 24);
}

#define QR(s, a, b, c, d) do { \
    s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a], 16); \
    s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c], 12); \
    s[a] += s[b]; s[d] = rotl32(s[d] ^ s[a], 8);  \
    s[c] += s[d]; s[b] = rotl32(s[b] ^ s[c], 7);  \
} while (0)

static void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
    uint32_t st[16], ws[16];
    st[0] = 0x61707865u; st[1] = 0x3320646eu; st[2] = 0x79622d32u; st[3] = 0x6b206574u;
    for (int i = 0; i < 8; i++) st[4 + i] = load32_le(key + i * 4);
    st[12] = counter;
    st[13] = load32_le(nonce); st[14] = load32_le(nonce + 4); st[15] = load32_le(nonce + 8);
    memcpy(ws, st, sizeof(st));
    for (int r = 0; r < 10; r++) {
        QR(ws, 0, 4, 8, 12); QR(ws, 1, 5, 9, 13); QR(ws, 2, 6, 10, 14); QR(ws, 3, 7, 11, 15);
        QR(ws, 0, 5, 10, 15); QR(ws, 1, 6, 11, 12); QR(ws, 2, 7, 8, 13); QR(ws, 3, 4, 9, 14);
    }
    for (int i = 0; i < 16; i++) store32_le(out + i * 4, ws[i] + st[i]);
}

static void chacha20_xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter,
                         const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t ks[64];
    for (size_t off = 0; off < len; off += 64) {
        chacha20_block(key, counter++, nonce, ks);
        size_t chunk = (len - off < 64) ? (len - off) : 64;
        for (size_t j = 0; j < chunk; j++) out[off + j] = in[off + j] ^ ks[j];
    }
}

static void poly1305_mac(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t tag[16]) {
    uint32_t r0 = load32_le(key +  0) & 0x3ffffff;
    uint32_t r1 = (load32_le(key +  3) >> 2) & 0x3ffff03;
    uint32_t r2 = (load32_le(key +  6) >> 4) & 0x3ffc0ff;
    uint32_t r3 = (load32_le(key +  9) >> 6) & 0x3f03fff;
    uint32_t r4 = (load32_le(key + 12) >> 8) & 0x00fffff;

    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    for (size_t off = 0; off < len; off += 16) {
        uint8_t blk[17] = {0};
        size_t chunk = (len - off < 16) ? (len - off) : 16;
        memcpy(blk, msg + off, chunk);
        blk[chunk] = 1;
        h0 += load32_le(blk + 0) & 0x3ffffff;
        h1 += (load32_le(blk + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(blk + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(blk + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(blk + 12) >> 8) | ((uint32_t)blk[16] << 24);

        uint64_t d0 = (uint64_t)h0*r0 + (uint64_t)h1*s4 + (uint64_t)h2*s3 + (uint64_t)h3*s2 + (uint64_t)h4*s1;
        uint64_t d1 = (uint64_t)h0*r1 + (uint64_t)h1*r0 + (uint64_t)h2*s4 + (uint64_t)h3*s3 + (uint64_t)h4*s2;
        uint64_t d2 = (uint64_t)h0*r2 + (uint64_t)h1*r1 + (uint64_t)h2*r0 + (uint64_t)h3*s4 + (uint64_t)h4*s3;
        uint64_t d3 = (uint64_t)h0*r3 + (uint64_t)h1*r2 + (uint64_t)h2*r1 + (uint64_t)h3*r0 + (uint64_t)h4*s4;
        uint64_t d4 = (uint64_t)h0*r4 + (uint64_t)h1*r3 + (uint64_t)h2*r2 + (uint64_t)h3*r1 + (uint64_t)h4*r0;

        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    }

    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    uint64_t f0 = ((h0) | (h1 << 26)) + (uint64_t)load32_le(key + 16);
    uint64_t f1 = ((h1 >> 6) | (h2 << 20)) + (uint64_t)load32_le(key + 20);
    uint64_t f2 = ((h2 >> 12) | (h3 << 14)) + (uint64_t)load32_le(key + 24);
    uint64_t f3 = ((h3 >> 18) | (h4 << 8)) + (uint64_t)load32_le(key + 28);

    store32_le(tag + 0, (uint32_t)f0); f1 += (f0 >> 32);
    store32_le(tag + 4, (uint32_t)f1); f2 += (f1 >> 32);
    store32_le(tag + 8, (uint32_t)f2); f3 += (f2 >> 32);
    store32_le(tag + 12, (uint32_t)f3);
}

static void aead_compute_tag(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t *ct, size_t ct_len, uint8_t tag[16]) {
    uint8_t poly_key[64];
    chacha20_block(key, 0, nonce, poly_key);
    size_t pad_aad = (16 - (aad_len & 15)) & 15;
    size_t pad_ct  = (16 - (ct_len & 15)) & 15;
    size_t mac_len = aad_len + pad_aad + ct_len + pad_ct + 16;
    uint8_t *mac_buf = calloc(1, mac_len);
    if (aad_len) memcpy(mac_buf, aad, aad_len);
    if (ct_len) memcpy(mac_buf + aad_len + pad_aad, ct, ct_len);
    size_t len_off = aad_len + pad_aad + ct_len + pad_ct;
    for (int i = 0; i < 8; i++) {
        mac_buf[len_off + i] = (uint8_t)((uint64_t)aad_len >> (i * 8));
        mac_buf[len_off + 8 + i] = (uint8_t)((uint64_t)ct_len >> (i * 8));
    }
    poly1305_mac(poly_key, mac_buf, mac_len, tag);
    free(mac_buf);
}

static void aead_seal(const uint8_t key[32], const uint8_t nonce[12],
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *pt, size_t pt_len, uint8_t *out) {
    chacha20_xor(key, nonce, 1, pt, out, pt_len);
    aead_compute_tag(key, nonce, aad, aad_len, out, pt_len, out + pt_len);
}

static int aead_open(const uint8_t key[32], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *blob, size_t blob_len, uint8_t *out) {
    if (blob_len < 16) return -1;
    size_t ct_len = blob_len - 16;
    uint8_t expected[16];
    aead_compute_tag(key, nonce, aad, aad_len, blob, ct_len, expected);
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= expected[i] ^ blob[ct_len + i];
    if (diff != 0) return -1;
    chacha20_xor(key, nonce, 1, blob, out, ct_len);
    return (int)ct_len;
}

/* ── Base32 (RFC 4648 lowercase no-pad) ─────────────────────────── */

static const char B32_ALPHA[] = "abcdefghijklmnopqrstuvwxyz234567";

static size_t base32_encode(const uint8_t *in, size_t len, char *out) {
    size_t pos = 0;
    uint32_t val = 0;
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[pos++] = B32_ALPHA[(val >> bits) & 31];
        }
    }
    if (bits > 0) out[pos++] = B32_ALPHA[(val << (5 - bits)) & 31];
    out[pos] = '\0';
    return pos;
}

static int b32_val(char c) {
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return 26 + (c - '2');
    return -1;
}

static int base32_decode(const char *in, uint8_t *out, size_t max_out) {
    uint32_t val = 0;
    int bits = 0;
    size_t pos = 0;
    for (size_t i = 0; in[i] && in[i] != '='; i++) {
        int v = b32_val(in[i]);
        if (v < 0) continue;
        val = (val << 5) | (uint32_t)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (pos >= max_out) return -1;
            out[pos++] = (uint8_t)((val >> bits) & 0xff);
        }
    }
    return (int)pos;
}

/* ── Minimal LZ4 Frame Decompressor ─────────────────────────────── */

static int lz4_decompress_frame(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_cap) {
    if (src_len < 7) return -1;
    if (load32_le(src) != 0x184D2204u) return -1;
    uint8_t flg = src[4];
    size_t pos = 6;
    if (flg & 0x08) pos += 8; /* content size */
    if (flg & 0x01) pos += 4; /* dict id */
    pos += 1;                 /* header checksum */
    int blk_csum = (flg >> 4) & 1;
    size_t out_pos = 0;

    while (pos + 4 <= src_len) {
        uint32_t bsz = load32_le(src + pos);
        pos += 4;
        if (bsz == 0) break;
        int uncomp = (bsz & 0x80000000u) != 0;
        bsz &= 0x7fffffffu;
        if (pos + bsz > src_len) return -1;
        if (uncomp) {
            if (out_pos + bsz > dst_cap) return -1;
            memcpy(dst + out_pos, src + pos, bsz);
            out_pos += bsz;
        } else {
            size_t bpos = pos, bend = pos + bsz;
            while (bpos < bend) {
                uint8_t token = src[bpos++];
                size_t lit = (token >> 4) & 0x0f;
                if (lit == 15) {
                    uint8_t s;
                    do { if (bpos >= bend) return -1; s = src[bpos++]; lit += s; } while (s == 255);
                }
                if (bpos + lit > bend || out_pos + lit > dst_cap) return -1;
                memcpy(dst + out_pos, src + bpos, lit);
                out_pos += lit;
                bpos += lit;
                if (bpos >= bend) break;
                if (bpos + 2 > bend) return -1;
                uint16_t offset = (uint16_t)src[bpos] | ((uint16_t)src[bpos + 1] << 8);
                bpos += 2;
                if (offset == 0 || offset > out_pos) return -1;
                size_t mlen = (token & 0x0f) + 4;
                if (mlen == 19) {
                    uint8_t s;
                    do { if (bpos >= bend) return -1; s = src[bpos++]; mlen += s; } while (s == 255);
                }
                if (out_pos + mlen > dst_cap) return -1;
                size_t msrc = out_pos - offset;
                for (size_t i = 0; i < mlen; i++) dst[out_pos++] = dst[msrc + i];
            }
        }
        pos += bsz + (blk_csum ? 4 : 0);
    }
    return (int)out_pos;
}

/* ── UDP/53 DNS Query & TXT Parser ──────────────────────────────── */

static int dns_query_txt(const char *nameserver, int port, const char *fqdn,
                         char *txt_out, size_t txt_cap, int timeout_ms) {
    uint8_t pkt[512];
    uint8_t txid[2];
    csprng_bytes(txid, 2);
    pkt[0] = txid[0]; pkt[1] = txid[1];
    pkt[2] = 0x01; pkt[3] = 0x00; /* RD=1 */
    pkt[4] = 0x00; pkt[5] = 0x01; /* QDCOUNT=1 */
    pkt[6] = 0x00; pkt[7] = 0x00;
    pkt[8] = 0x00; pkt[9] = 0x00;
    pkt[10] = 0x00; pkt[11] = 0x01; /* ARCOUNT=1 (EDNS0 4096) */

    size_t off = 12;
    const char *p = fqdn;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t llen = dot ? (size_t)(dot - p) : strlen(p);
        if (llen == 0 || llen > 63 || off + llen + 2 > sizeof(pkt) - 16) return -1;
        pkt[off++] = (uint8_t)llen;
        memcpy(pkt + off, p, llen);
        off += llen;
        if (!dot) break;
        p = dot + 1;
    }
    pkt[off++] = 0x00;
    pkt[off++] = 0x00; pkt[off++] = 16; /* QTYPE = TXT (16) */
    pkt[off++] = 0x00; pkt[off++] = 1;  /* QCLASS = IN (1) */

    /* EDNS0 OPT record requesting 4096-byte UDP payload */
    pkt[off++] = 0x00;
    pkt[off++] = 0x00; pkt[off++] = 41;
    pkt[off++] = 0x10; pkt[off++] = 0x00;
    pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00; pkt[off++] = 0x00;
    pkt[off++] = 0x00; pkt[off++] = 0x00;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, nameserver, &sa.sin_addr) != 1) { close(sock); return -1; }

    if (sendto(sock, pkt, off, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(sock); return -1; }
    uint8_t resp[4096];
    ssize_t rlen = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
    close(sock);
    if (rlen < 12 || resp[0] != txid[0] || resp[1] != txid[1]) return -1;

    uint16_t qdcount = ((uint16_t)resp[4] << 8) | resp[5];
    uint16_t ancount = ((uint16_t)resp[6] << 8) | resp[7];
    size_t roff = 12;

    for (uint16_t q = 0; q < qdcount; q++) {
        while (roff < (size_t)rlen && resp[roff] != 0) {
            if ((resp[roff] & 0xC0) == 0xC0) { roff += 2; goto q_done; }
            roff += 1 + resp[roff];
        }
        roff++;
q_done:
        roff += 4;
    }

    txt_out[0] = '\0';
    size_t txt_pos = 0;
    for (uint16_t a = 0; a < ancount && roff + 10 <= (size_t)rlen; a++) {
        while (roff < (size_t)rlen && resp[roff] != 0) {
            if ((resp[roff] & 0xC0) == 0xC0) { roff += 2; goto name_done; }
            roff += 1 + resp[roff];
        }
        roff++;
name_done:
        if (roff + 10 > (size_t)rlen) break;
        uint16_t rtype = ((uint16_t)resp[roff] << 8) | resp[roff + 1];
        uint16_t rdlen = ((uint16_t)resp[roff + 8] << 8) | resp[roff + 9];
        roff += 10;
        if (roff + rdlen > (size_t)rlen) break;
        if (rtype == 16) {
            size_t end = roff + rdlen;
            while (roff < end) {
                uint8_t slen = resp[roff++];
                if (roff + slen > end || txt_pos + slen >= txt_cap) break;
                memcpy(txt_out + txt_pos, resp + roff, slen);
                txt_pos += slen;
                roff += slen;
            }
            txt_out[txt_pos] = '\0';
            return (int)txt_pos;
        }
        roff += rdlen;
    }
    return 0;
}

/* ── Kopacz v3 Session State ────────────────────────────────────── */

#define FLAG_SYN  0x80
#define FLAG_FIN  0x40
#define FLAG_ACK  0x20
#define FLAG_DATA 0x10
#define FLAG_POLL 0x08
#define FLAG_FRAG 0x04
#define FLAG_COMP 0x01

typedef struct {
    uint8_t psk[32];
    uint8_t c2s_key[32];
    uint8_t s2c_key[32];
    uint64_t send_ctr;
    uint16_t seq;
    uint16_t poll_seq;
    int has_ack;
    uint16_t ack_num;
    char domain[128];
    char nameserver[64];
    int ns_port;
    char tag[12];
    /* Reassembly buffer for current downstream message */
    int reasm_seq;
    int reasm_total;
    int reasm_got;
    uint8_t reasm_parts[256][512];
    size_t reasm_lens[256];
} kopacz_session;

static void pack_header(uint8_t out[8], uint8_t flags, uint16_t stream_id,
                        uint16_t seq, uint8_t frag_idx, uint8_t total_frags, uint8_t rsv) {
    out[0] = flags;
    out[1] = (uint8_t)(stream_id >> 8); out[2] = (uint8_t)stream_id;
    out[3] = (uint8_t)(seq >> 8);       out[4] = (uint8_t)seq;
    out[5] = frag_idx;
    out[6] = total_frags ? total_frags : 1;
    out[7] = rsv;
}

static void sign_control(const kopacz_session *s, const uint8_t hdr[8], uint8_t tag8[8]) {
    uint8_t nonce[12] = {'c', 't', 'r', 'l'};
    memcpy(nonce + 4, hdr, 8);
    uint8_t full_tag[16];
    aead_seal(s->c2s_key, nonce, hdr, 8, NULL, 0, full_tag);
    memcpy(tag8, full_tag, 8);
}

static int build_qname(const kopacz_session *s, const uint8_t *pkt, size_t pkt_len, char *fqdn, size_t cap) {
    char b32[512];
    size_t elen = base32_encode(pkt, pkt_len, b32);
    size_t pos = 0;
    for (size_t i = 0; i < elen; i += 63) {
        size_t chunk = (elen - i < 63) ? (elen - i) : 63;
        if (pos + chunk + 2 >= cap) return -1;
        memcpy(fqdn + pos, b32 + i, chunk);
        pos += chunk;
        fqdn[pos++] = '.';
    }
    snprintf(fqdn + pos, cap - pos, "%s.%s", s->tag, s->domain);
    return 0;
}

static int kopacz_connect(kopacz_session *s) {
    uint8_t eph_sk[32], eph_pk[32], es[32];
    csprng_bytes(eph_sk, 32);
    x25519_base(eph_pk, eph_sk);
    x25519_scalarmult(es, eph_sk, s->psk); /* s->psk holds server_static_pub */

    uint8_t syn_salt[64], syn_key[32];
    memcpy(syn_salt, eph_pk, 32);
    memcpy(syn_salt + 32, s->psk, 32);
    hkdf_sha256(es, 32, syn_salt, 64, (const uint8_t *)"kopacz-v3-syn", 13, syn_key, 32);

    uint8_t ts_bytes[8];
    uint64_t now = (uint64_t)time(NULL);
    for (int i = 0; i < 8; i++) ts_bytes[i] = (uint8_t)(now >> (56 - i * 8));

    uint8_t syn_aad[13 + 32];
    memcpy(syn_aad, "kopacz-v3-syn", 13);
    memcpy(syn_aad + 13, eph_pk, 32);

    uint8_t zero_nonce[12] = {0};
    uint8_t syn_pkt[8 + 32 + 8 + 16]; /* 8B header + 56B SYN payload */
    pack_header(syn_pkt, FLAG_SYN, 0, 0, 0, 1, 60); /* request 480B downstream MTU */
    memcpy(syn_pkt + 8, eph_pk, 32);
    aead_seal(syn_key, zero_nonce, syn_aad, sizeof(syn_aad), ts_bytes, 8, syn_pkt + 40);

    char fqdn[300], txt[2048];
    build_qname(s, syn_pkt, sizeof(syn_pkt), fqdn, sizeof(fqdn));
    if (dns_query_txt(s->nameserver, s->ns_port, fqdn, txt, sizeof(txt), 4000) <= 0) return -1;

    uint8_t raw[512];
    int rlen = base32_decode(txt, raw, sizeof(raw));
    if (rlen != 8 + 32 + 16) return -1;
    if ((raw[0] & (FLAG_SYN | FLAG_ACK)) != (FLAG_SYN | FLAG_ACK)) return -1;

    const uint8_t *s_pub = raw + 8;
    const uint8_t *tag = raw + 40;

    uint8_t ee[32], ikm[64], salt[64], material[96];
    x25519_scalarmult(ee, eph_sk, s_pub);
    memcpy(ikm, es, 32);
    memcpy(ikm + 32, ee, 32);
    memcpy(salt, eph_pk, 32);
    memcpy(salt + 32, s_pub, 32);
    hkdf_sha256(ikm, 64, salt, 64, (const uint8_t *)"kopacz-v3", 9, material, 96);

    uint8_t synack_aad[17 + 64];
    memcpy(synack_aad, "kopacz-v3-synack:", 17);
    memcpy(synack_aad + 17, eph_pk, 32);
    memcpy(synack_aad + 49, s_pub, 32);

    uint8_t dummy[1];
    if (aead_open(material + 64, zero_nonce, synack_aad, sizeof(synack_aad), tag, 16, dummy) != 0) {
        return -1;
    }

    memcpy(s->c2s_key, material, 32);
    memcpy(s->s2c_key, material + 32, 32);
    s->reasm_seq = -1;
    return 0;
}

static int kopacz_ingest(kopacz_session *s, const uint8_t *raw, size_t rlen,
                         uint8_t *app_out, size_t app_cap) {
    if (rlen < 8) return 0;
    uint8_t flags = raw[0];
    uint16_t stream_id = ((uint16_t)raw[1] << 8) | raw[2];
    uint16_t seq = ((uint16_t)raw[3] << 8) | raw[4];
    uint8_t fidx = raw[5];
    uint8_t ftotal = raw[6];
    if (!(flags & FLAG_DATA)) return 0;
    if (ftotal < 1 || fidx >= ftotal) return 0;

    if (s->reasm_seq != (int)seq || s->reasm_total != (int)ftotal) {
        s->reasm_seq = (int)seq;
        s->reasm_total = (int)ftotal;
        s->reasm_got = 0;
        memset(s->reasm_lens, 0, sizeof(s->reasm_lens));
    }
    size_t plen = rlen - 8;
    if (plen > 512) return 0;
    if (s->reasm_lens[fidx] == 0) s->reasm_got++;
    memcpy(s->reasm_parts[fidx], raw + 8, plen);
    s->reasm_lens[fidx] = plen;

    if (s->reasm_got < s->reasm_total) return 0;

    uint8_t enc[65536];
    size_t elen = 0;
    for (int i = 0; i < s->reasm_total; i++) {
        memcpy(enc + elen, s->reasm_parts[i], s->reasm_lens[i]);
        elen += s->reasm_lens[i];
    }
    s->reasm_seq = -1;
    if (elen < 28) return 0;

    uint8_t aad[5] = { (flags & FLAG_COMP) ? 1 : 0, (uint8_t)(stream_id >> 8), (uint8_t)stream_id,
                       (uint8_t)(seq >> 8), (uint8_t)seq };
    uint8_t dec[65536];
    int dlen = aead_open(s->s2c_key, enc, aad, 5, enc + 12, elen - 12, dec);
    if (dlen < 0) return 0;

    s->has_ack = 1;
    s->ack_num = seq;

    if (flags & FLAG_COMP) {
        return lz4_decompress_frame(dec, (size_t)dlen, app_out, app_cap);
    }
    if ((size_t)dlen > app_cap) return -1;
    memcpy(app_out, dec, (size_t)dlen);
    return dlen;
}

static int kopacz_send(kopacz_session *s, const uint8_t *data, size_t len,
                       uint8_t *down_out, size_t down_cap) {
    uint16_t seq = s->seq++;
    uint8_t aad[5] = { 0, 0, 0, (uint8_t)(seq >> 8), (uint8_t)seq };
    uint8_t nonce[12] = {0};
    uint64_t ctr = s->send_ctr++;
    for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(ctr >> (56 - i * 8));

    size_t enc_len = 12 + len + 16;
    uint8_t *enc = malloc(enc_len);
    memcpy(enc, nonce, 12);
    aead_seal(s->c2s_key, nonce, aad, 5, data, len, enc + 12);

    size_t max_frag = 96;
    size_t total_frags = (enc_len + max_frag - 1) / max_frag;
    if (total_frags == 0) total_frags = 1;

    int got_down = 0;
    for (size_t idx = 0; idx < total_frags; idx++) {
        size_t off = idx * max_frag;
        size_t clen = (enc_len - off < max_frag) ? (enc_len - off) : max_frag;
        uint8_t pkt[128];
        uint8_t flg = FLAG_DATA | (total_frags > 1 ? FLAG_FRAG : 0) | (s->has_ack ? FLAG_ACK : 0);
        uint8_t rsv = s->has_ack ? (uint8_t)(s->ack_num & 0xff) : 0;
        pack_header(pkt, flg, 0, seq, (uint8_t)idx, (uint8_t)total_frags, rsv);
        memcpy(pkt + 8, enc + off, clen);

        char fqdn[300], txt[2048];
        build_qname(s, pkt, 8 + clen, fqdn, sizeof(fqdn));
        if (dns_query_txt(s->nameserver, s->ns_port, fqdn, txt, sizeof(txt), 4000) > 0) {
            uint8_t raw[1024];
            int rlen = base32_decode(txt, raw, sizeof(raw));
            if (rlen > 0 && got_down == 0) {
                int d = kopacz_ingest(s, raw, (size_t)rlen, down_out, down_cap);
                if (d > 0) got_down = d;
            }
        }
    }
    free(enc);
    return got_down;
}

static int kopacz_poll(kopacz_session *s, uint8_t *down_out, size_t down_cap) {
    uint16_t pseq = s->poll_seq++;
    uint8_t pkt[16];
    if (s->has_ack) {
        pack_header(pkt, FLAG_POLL | FLAG_ACK, 0, s->ack_num, (uint8_t)(pseq >> 8), 1, (uint8_t)(pseq & 0xff));
    } else {
        pack_header(pkt, FLAG_POLL, 0, pseq, 0, 1, 0);
    }
    sign_control(s, pkt, pkt + 8);
    char fqdn[300], txt[2048];
    build_qname(s, pkt, 16, fqdn, sizeof(fqdn));
    if (dns_query_txt(s->nameserver, s->ns_port, fqdn, txt, sizeof(txt), 4000) <= 0) return 0;
    uint8_t raw[1024];
    int rlen = base32_decode(txt, raw, sizeof(raw));
    if (rlen <= 0) return 0;
    return kopacz_ingest(s, raw, (size_t)rlen, down_out, down_cap);
}

static void kopacz_close(kopacz_session *s) {
    uint16_t pseq = s->poll_seq++;
    uint8_t pkt[16];
    pack_header(pkt, FLAG_FIN, 0, pseq, 0, 1, 0);
    sign_control(s, pkt, pkt + 8);
    char fqdn[300], txt[512];
    build_qname(s, pkt, 16, fqdn, sizeof(fqdn));
    dns_query_txt(s->nameserver, s->ns_port, fqdn, txt, sizeof(txt), 1500);
}

/* ── CLI Entrypoint ─────────────────────────────────────────────── */

static int parse_hex(const char *hex, uint8_t *out, size_t len) {
    if (strlen(hex) != len * 2) return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

int main(int argc, char **argv) {
    kopacz_session sess;
    memset(&sess, 0, sizeof(sess));
    strncpy(sess.nameserver, "1.1.1.1", sizeof(sess.nameserver) - 1);
    sess.ns_port = 53;

    const char *psk_hex = getenv("KOPACZ_PUBKEY");
    if (!psk_hex) psk_hex = getenv("KOPACZ_PSK");
    const char *domain = getenv("KOPACZ_DOMAIN");

    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (!strcmp(argv[argi], "-d") && argi + 1 < argc) { domain = argv[++argi]; }
        else if (!strcmp(argv[argi], "-k") && argi + 1 < argc) { psk_hex = argv[++argi]; }
        else if (!strcmp(argv[argi], "-r") && argi + 1 < argc) {
            strncpy(sess.nameserver, argv[++argi], sizeof(sess.nameserver) - 1);
            char *colon = strchr(sess.nameserver, ':');
            if (colon) { *colon = '\0'; sess.ns_port = atoi(colon + 1); }
        } else if (!strcmp(argv[argi], "-t") && argi + 1 < argc) {
            strncpy(sess.tag, argv[++argi], 8);
        } else break;
        argi++;
    }

    if (!domain || !psk_hex || parse_hex(psk_hex, sess.psk, 32) < 0) {
        fprintf(stderr, "Usage: %s -d <domain> -k <64-hex-pubkey> [-r resolver[:port]] <fetch <url> | ssh | echo>\n", argv[0]);
        return 1;
    }
    strncpy(sess.domain, domain, sizeof(sess.domain) - 1);
    if (!sess.tag[0]) {
        uint8_t rb[8];
        csprng_bytes(rb, 8);
        const char *al = "0123456789abcdefghijklmnopqrstuvwxyz";
        for (int i = 0; i < 8; i++) sess.tag[i] = al[rb[i] % 36];
        sess.tag[8] = '\0';
    }

    if (argi >= argc) {
        fprintf(stderr, "Error: specify command 'fetch <url>' or 'ssh'\n");
        return 1;
    }
    const char *cmd = argv[argi++];
    if (!strcmp(cmd, "ssh") && !strcmp(sess.tag, "")) strncpy(sess.tag, "bridge", 8);

    if (kopacz_connect(&sess) < 0) {
        fprintf(stderr, "Error: Kopacz 1-RTT handshake failed\n");
        return 1;
    }

    uint8_t down[65536];
    if (!strcmp(cmd, "fetch") && argi < argc) {
        const char *url = argv[argi];
        size_t ulen = strlen(url);
        uint8_t *req = malloc(2 + ulen);
        req[0] = 0x04; /* APP_WEB */
        req[1] = 0x03; /* FETCH_READER (distilled HTML) */
        memcpy(req + 2, url, ulen);
        int d = kopacz_send(&sess, req, 2 + ulen, down, sizeof(down));
        free(req);

        int empty = 0, done = 0;
        while (!done && empty < 60) {
            if (d > 0) {
                empty = 0;
                if (down[0] == 0x02 && d > 1) fwrite(down + 1, 1, (size_t)(d - 1), stdout);
                else if (down[0] == 0x03) done = 1;
            } else {
                empty++;
                struct timespec ts = {0, 80 * 1000000L};
                nanosleep(&ts, NULL);
            }
            if (!done) d = kopacz_poll(&sess, down, sizeof(down));
        }
        fflush(stdout);
    } else if (!strcmp(cmd, "echo")) {
        uint8_t inbuf[4096];
        ssize_t n;
        while ((n = read(STDIN_FILENO, inbuf, sizeof(inbuf))) > 0) {
            int d = kopacz_send(&sess, inbuf, (size_t)n, down, sizeof(down));
            int got = 0;
            while (got < n) {
                if (d > 0) {
                    ssize_t w = write(STDOUT_FILENO, down, (size_t)d);
                    (void)w;
                    got += d;
                }
                if (got < n) {
                    d = kopacz_poll(&sess, down, sizeof(down));
                }
            }
        }
        fflush(stdout);
    } else if (!strcmp(cmd, "ssh")) {
        while (1) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(STDIN_FILENO, &rfds);
            struct timeval tv = {0, 30000};
            int r = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
            if (r > 0 && FD_ISSET(STDIN_FILENO, &rfds)) {
                uint8_t buf[1024];
                buf[0] = 0x02; /* APP_SSH */
                ssize_t n = read(STDIN_FILENO, buf + 1, sizeof(buf) - 1);
                if (n <= 0) break;
                int d = kopacz_send(&sess, buf, (size_t)n + 1, down, sizeof(down));
                if (d > 0) { ssize_t w = write(STDOUT_FILENO, down, (size_t)d); (void)w; }
            } else {
                int d = kopacz_poll(&sess, down, sizeof(down));
                if (d > 0) { ssize_t w = write(STDOUT_FILENO, down, (size_t)d); (void)w; }
            }
        }
    }

    kopacz_close(&sess);
    return 0;
}
