#include "identity.h"
#include "packet.h"
#include "armor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
nox_ident_init(nox_ident *id)
{
    memset(id, 0, sizeof *id);
}

void
nox_ident_wipe(nox_ident *id)
{
    int i;

    if (id->raw != NULL) {
        nox_wipe(id->raw, id->raw_len);
        free(id->raw);
    }
    for (i = 0; i < NOX_MAX_KEYS; i++) {
        nox_wipe(id->keys[i].sk, sizeof id->keys[i].sk);
        nox_wipe(id->keys[i].pk, sizeof id->keys[i].pk);
    }
    nox_wipe(id, sizeof *id);
}

nox_key *
nox_ident_find(nox_ident *id, uint16_t alg)
{
    int i;

    for (i = 0; i < id->nkeys; i++) {
        if (id->keys[i].alg == alg)
            return &id->keys[i];
    }
    return NULL;
}

int
nox_ident_has_hybrid_enc(const nox_ident *id)
{
    int i, have_x = 0, have_k = 0;

    for (i = 0; i < id->nkeys; i++) {
        if (id->keys[i].alg == NOX_ALG_X25519 &&
            (id->keys[i].usage & NOX_USAGE_ENCRYPT))
            have_x = 1;
        if (id->keys[i].alg == NOX_ALG_MLKEM768 &&
            (id->keys[i].usage & NOX_USAGE_ENCRYPT))
            have_k = 1;
    }
    return have_x && have_k;
}

int
nox_ident_recip_alg(const nox_ident *id)
{
    int i, have_x = 0, have_k = 0;

    for (i = 0; i < id->nkeys; i++) {
        if (id->keys[i].alg == NOX_ALG_X25519 &&
            (id->keys[i].usage & NOX_USAGE_ENCRYPT))
            have_x = 1;
        if (id->keys[i].alg == NOX_ALG_MLKEM768 &&
            (id->keys[i].usage & NOX_USAGE_ENCRYPT))
            have_k = 1;
    }
    if (have_x && have_k)
        return NOX_ALG_HYBRID;
    if (have_x)
        return NOX_ALG_X25519;
    if (have_k)
        return NOX_ALG_MLKEM768;
    return -1;
}

int
nox_ident_suite(char *dst, size_t n, const nox_ident *id)
{
    char tmp[128];
    size_t off = 0;
    int i, r;

    r = snprintf(tmp + off, sizeof tmp - off, "sign:");
    if (r > 0)
        off += (size_t)r;
    for (i = 0; i < id->nkeys; i++) {
        if ((id->keys[i].usage & NOX_USAGE_SIGN) == 0)
            continue;
        if (off >= sizeof tmp - 16)
            break;
        r = snprintf(tmp + off, sizeof tmp - off,
                     " %s", nox_alg_name(id->keys[i].alg));
        if (r > 0)
            off += (size_t)r;
    }
    if (off < sizeof tmp - 16) {
        r = snprintf(tmp + off, sizeof tmp - off, "; enc:");
        if (r > 0)
            off += (size_t)r;
    }
    for (i = 0; i < id->nkeys; i++) {
        if ((id->keys[i].usage & NOX_USAGE_ENCRYPT) == 0)
            continue;
        if (off >= sizeof tmp - 16)
            break;
        r = snprintf(tmp + off, sizeof tmp - off,
                     " %s", nox_alg_name(id->keys[i].alg));
        if (r > 0)
            off += (size_t)r;
    }
    tmp[sizeof tmp - 1] = 0;
    if (n == 0)
        return -1;
    snprintf(dst, n, "%s", tmp);
    return strlen(tmp) < n ? 0 : -1;
}

static int
put_pubkey(nox_buf *b, uint16_t alg, uint8_t usage,
           const uint8_t *pk, int pkl)
{
    uint8_t val[3 + 1312];

    nox_be16(val, alg);
    val[2] = usage;
    memcpy(val + 3, pk, (size_t)pkl);
    return nox_buf_pkt(b, NOX_PKT_PUBKEY, val, (uint32_t)(3 + pkl));
}

static int
put_sig(nox_buf *b, uint16_t alg, const uint8_t *sig, int sl)
{
    uint8_t val[2 + 2420];

    nox_be16(val, alg);
    memcpy(val + 2, sig, (size_t)sl);
    return nox_buf_pkt(b, NOX_PKT_SIG, val, (uint32_t)(2 + sl));
}

static void
fingerprint(uint8_t fp[NOX_FP_LEN], const uint8_t *keys, size_t n)
{
    ncrypt_blake2b_ctx ctx;

    ncrypt_blake2b_init(&ctx, NOX_FP_LEN);
    ncrypt_blake2b_update(&ctx, (const uint8_t *)DS_FINGERPRINT,
                          sizeof(DS_FINGERPRINT) - 1);
    ncrypt_blake2b_update(&ctx, keys, n);
    ncrypt_blake2b_final(&ctx, fp);
}

int
nox_key_expand(const nox_key *k, uint8_t *sk, size_t *sk_len)
{
    uint8_t seed[64];
    size_t slen;
    int want;

    if (!k->has_sk)
        return nox_seterr("no secret key");
    want = nox_sk_exp_len(k->alg);
    if (want < 0)
        return nox_seterr("unknown algorithm");

    if (k->encoding == NOX_ENC_EXP) {
        if (k->sk_len != (size_t)want)
            return nox_seterr("expanded secret has the wrong length");
        switch (k->alg) {
        case NOX_ALG_X25519: {
            uint8_t pk[32];
            ncrypt_x25519_public_key(pk, k->sk);
            if (nox_memeq(pk, k->pk, 32) != 0)
                return nox_seterr("X25519 secret does not match public key");
            break;
        }
        case NOX_ALG_ED25519: {
            uint8_t seed[32], pk[32], tmp[64];
            memcpy(seed, k->sk, 32);
            ncrypt_ed25519_key_pair(tmp, pk, seed);
            if (nox_memeq(pk, k->pk, 32) != 0 ||
                nox_memeq(tmp, k->sk, 64) != 0) {
                nox_wipe(tmp, sizeof tmp);
                return nox_seterr("Ed25519 secret does not match public key");
            }
            nox_wipe(tmp, sizeof tmp);
            break;
        }
        case NOX_ALG_MLKEM768: {
            uint8_t seed[32], ct[1088], ss1[32], ss2[32];
            int st;
            if (nox_random(seed, 32) < 0)
                return -1;
            st = ncrypt_mlkem768_encapsulate(ct, ss1, k->pk, seed);
            if (st != 0)
                return nox_seterr("ML-KEM-768 public key is malformed");
            if (ncrypt_mlkem768_decapsulate(ss2, ct, k->sk) != 0) {
                nox_wipe(ss1, 32);
                nox_wipe(ss2, 32);
                return nox_seterr("ML-KEM-768 secret key is corrupted");
            }
            st = ncrypt_verify32(ss1, ss2);
            nox_wipe(ss1, 32);
            nox_wipe(ss2, 32);
            nox_wipe(ct, sizeof ct);
            if (st != 0)
                return nox_seterr("ML-KEM-768 secret does not match public key");
            break;
        }
        case NOX_ALG_MLDSA44: {
            uint8_t sig[2420];
            static const uint8_t chk[] = "noxcrypt/v1/sk-check";
            ncrypt_mldsa44_sign(sig, k->sk, chk, sizeof chk - 1);
            if (ncrypt_mldsa44_check(sig, k->pk, chk, sizeof chk - 1) != 0) {
                nox_wipe(sig, sizeof sig);
                return nox_seterr("ML-DSA-44 secret does not match public key");
            }
            nox_wipe(sig, sizeof sig);
            break;
        }
        default:
            return nox_seterr("unknown algorithm");
        }
        memcpy(sk, k->sk, (size_t)want);
        *sk_len = (size_t)want;
        return 0;
    }

    slen = (size_t)nox_sk_seed_len(k->alg);
    if (k->sk_len != slen)
        return nox_seterr("secret seed has the wrong length");
    memcpy(seed, k->sk, slen);

    switch (k->alg) {
    case NOX_ALG_X25519: {
        uint8_t pk[32];
        ncrypt_x25519_public_key(pk, seed);
        if (nox_memeq(pk, k->pk, 32) != 0) {
            nox_wipe(seed, sizeof seed);
            return nox_seterr("X25519 secret does not match public key");
        }
        memcpy(sk, seed, 32);
        *sk_len = 32;
        nox_wipe(seed, sizeof seed);
        return 0;
    }
    case NOX_ALG_ED25519: {
        uint8_t pk[32];
        ncrypt_ed25519_key_pair(sk, pk, seed); /* wipes seed[0..32] */
        if (nox_memeq(pk, k->pk, 32) != 0) {
            nox_wipe(sk, 64);
            return nox_seterr("Ed25519 secret does not match public key");
        }
        *sk_len = 64;
        return 0;
    }
    case NOX_ALG_MLKEM768: {
        uint8_t pk[1184];
        ncrypt_mlkem768_key_pair(sk, pk, seed);
        if (nox_memeq(pk, k->pk, 1184) != 0) {
            nox_wipe(sk, 2400);
            return nox_seterr("ML-KEM-768 secret does not match public key");
        }
        *sk_len = 2400;
        return 0;
    }
    case NOX_ALG_MLDSA44: {
        uint8_t pk[1312];
        ncrypt_mldsa44_key_pair(sk, pk, seed);
        if (nox_memeq(pk, k->pk, 1312) != 0) {
            nox_wipe(sk, 2560);
            return nox_seterr("ML-DSA-44 secret does not match public key");
        }
        *sk_len = 2560;
        return 0;
    }
    default:
        nox_wipe(seed, sizeof seed);
        return nox_seterr("unknown algorithm");
    }
}

static int
check_sigs(const nox_ident *id, const uint8_t *body, size_t body_len,
           const uint8_t *sigpkts, size_t sigpkts_len)
{
    uint8_t *msg;
    size_t msg_len = (sizeof(DS_IDENTITY) - 1) + body_len;
    nox_parser p;
    int i, left, rc = -1;

    left = 0;
    for (i = 0; i < id->nkeys; i++) {
        if (id->keys[i].usage & NOX_USAGE_SIGN)
            left++;
    }
    if (left == 0)
        return nox_seterr("identity has no signing key");

    msg = malloc(msg_len);
    if (msg == NULL)
        return nox_seterr("out of memory");
    memcpy(msg, DS_IDENTITY, sizeof(DS_IDENTITY) - 1);
    memcpy(msg + sizeof(DS_IDENTITY) - 1, body, body_len);

    nox_parser_init(&p, sigpkts, sigpkts_len);
    for (i = 0; i < id->nkeys; i++) {
        const nox_key *k = &id->keys[i];
        uint16_t type, alg;
        int crit;
        const uint8_t *val;
        uint32_t vlen;
        int sl;

        if ((k->usage & NOX_USAGE_SIGN) == 0)
            continue;
        if (nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0)
            goto out;
        if (type != NOX_PKT_SIG || vlen < 2)
            goto bad;
        alg = nox_rd16(val);
        sl = nox_sig_len(alg);
        if (alg != k->alg || sl < 0 || vlen != (uint32_t)(2 + sl))
            goto bad;
        if (alg == NOX_ALG_ED25519) {
            if (ncrypt_ed25519_check(val + 2, k->pk, msg, msg_len) != 0)
                goto bad;
        } else if (alg == NOX_ALG_MLDSA44) {
            if (ncrypt_mldsa44_check(val + 2, k->pk, msg, msg_len) != 0)
                goto bad;
        } else {
            goto bad;
        }
        left--;
    }
    if (left != 0 || nox_parser_left(&p))
        goto bad;
    rc = 0;
    goto out;
bad:
    nox_seterr("identity self-signature is invalid");
out:
    nox_wipe(msg, msg_len);
    free(msg);
    return rc;
}

int
nox_ident_generate(nox_ident *id, const char *comment, uint64_t created)
{
    return nox_ident_generate_ex(id, comment, created,
                                 NOX_SIGN_ED25519 | NOX_SIGN_MLDSA44,
                                 NOX_ENC_X25519 | NOX_ENC_MLKEM768);
}

int
nox_ident_generate_ex(nox_ident *id, const char *comment, uint64_t created,
                      unsigned sign_mask, unsigned enc_mask)
{
    int want_ed, want_dsa, want_x, want_kem;
    uint8_t ed_seed[32], ed_sk[64], ed_pk[32];
    uint8_t x_sk[32], x_pk[32];
    uint8_t kem_seed[64], kem_sk[2400], kem_pk[1184];
    uint8_t dsa_seed[32], dsa_sk[2560], dsa_pk[1312];
    uint8_t ed_sig[64], dsa_sig[2420];
    uint8_t ed_keep[32], kem_keep[64], dsa_keep[32];
    nox_buf body, full;
    size_t clen, keys_off, keys_len, msg_len;
    uint8_t *msg = NULL;
    int rc = -1;

    want_ed = (sign_mask & NOX_SIGN_ED25519) != 0;
    want_dsa = (sign_mask & NOX_SIGN_MLDSA44) != 0;
    want_x = (enc_mask & NOX_ENC_X25519) != 0;
    want_kem = (enc_mask & NOX_ENC_MLKEM768) != 0;

    nox_ident_init(id);
    if ((sign_mask & ~(unsigned)(NOX_SIGN_ED25519 | NOX_SIGN_MLDSA44)) != 0 ||
        (enc_mask & ~(unsigned)(NOX_ENC_X25519 | NOX_ENC_MLKEM768)) != 0)
        return nox_seterr("unknown algorithm in key suite");
    if (!want_ed && !want_dsa)
        return nox_seterr("key suite needs a signing algorithm");
    if (!want_x && !want_kem)
        return nox_seterr("key suite needs an encryption algorithm");
    if (comment == NULL)
        comment = "";
    clen = strlen(comment);
    if (clen > NOX_MAX_COMMENT)
        return nox_seterr("comment longer than 1024 bytes");
    if (!nox_utf8_ok((const uint8_t *)comment, clen))
        return nox_seterr("comment is not valid UTF-8 (or contains NUL/CR/LF)");

    if ((want_ed && nox_random(ed_seed, 32) < 0) ||
        (want_x && nox_random(x_sk, 32) < 0) ||
        (want_kem && nox_random(kem_seed, 64) < 0) ||
        (want_dsa && nox_random(dsa_seed, 32) < 0))
        return -1;

    if (want_ed) {
        memcpy(ed_keep, ed_seed, 32);
        ncrypt_ed25519_key_pair(ed_sk, ed_pk, ed_seed);
    }
    if (want_x)
        ncrypt_x25519_public_key(x_pk, x_sk);
    if (want_kem) {
        memcpy(kem_keep, kem_seed, 64);
        ncrypt_mlkem768_key_pair(kem_sk, kem_pk, kem_seed);
    }
    if (want_dsa) {
        memcpy(dsa_keep, dsa_seed, 32);
        ncrypt_mldsa44_key_pair(dsa_sk, dsa_pk, dsa_seed);
    }

    if (nox_buf_init(&body, NOX_MAX_IDENT) < 0)
        goto wipe;
    nox_buf_u64(&body, created);
    nox_buf_u16(&body, (uint16_t)clen);
    nox_buf_put(&body, comment, clen);
    keys_off = body.n;
    if (want_ed)
        put_pubkey(&body, NOX_ALG_ED25519, NOX_USAGE_SIGN | NOX_USAGE_AUTH,
                   ed_pk, 32);
    if (want_dsa)
        put_pubkey(&body, NOX_ALG_MLDSA44, NOX_USAGE_SIGN, dsa_pk, 1312);
    if (want_x)
        put_pubkey(&body, NOX_ALG_X25519, NOX_USAGE_ENCRYPT, x_pk, 32);
    if (want_kem)
        put_pubkey(&body, NOX_ALG_MLKEM768, NOX_USAGE_ENCRYPT, kem_pk, 1184);
    if (body.err) {
        nox_buf_free(&body);
        goto wipe;
    }
    keys_len = body.n - keys_off;

    msg_len = (sizeof(DS_IDENTITY) - 1) + body.n;
    msg = malloc(msg_len);
    if (msg == NULL) {
        nox_buf_free(&body);
        nox_seterr("out of memory");
        goto wipe;
    }
    memcpy(msg, DS_IDENTITY, sizeof(DS_IDENTITY) - 1);
    memcpy(msg + sizeof(DS_IDENTITY) - 1, body.p, body.n);
    if (want_ed)
        ncrypt_ed25519_sign(ed_sig, ed_sk, msg, msg_len);
    if (want_dsa)
        ncrypt_mldsa44_sign(dsa_sig, dsa_sk, msg, msg_len);
    nox_wipe(msg, msg_len);
    free(msg);
    msg = NULL;

    if (nox_buf_init(&full, NOX_MAX_IDENT) < 0) {
        nox_buf_free(&body);
        goto wipe;
    }
    nox_buf_put(&full, body.p, body.n);
    if (want_ed)
        put_sig(&full, NOX_ALG_ED25519, ed_sig, 64);
    if (want_dsa)
        put_sig(&full, NOX_ALG_MLDSA44, dsa_sig, 2420);
    nox_buf_free(&body);
    if (full.err || full.n > NOX_MAX_IDENT) {
        int too_big = !full.err && full.n > NOX_MAX_IDENT;
        nox_buf_free(&full);
        if (too_big)
            nox_seterr("identity exceeds 65536 bytes");
        goto wipe;
    }

    id->created = created;
    memcpy(id->comment, comment, clen);
    id->comment[clen] = 0;
    fingerprint(id->fp, full.p + keys_off, keys_len);
    id->raw = full.p;
    id->raw_len = full.n;
    id->body_len = keys_off + keys_len;
    full.p = NULL;
    nox_buf_free(&full);

    id->nkeys = 0;

    if (want_ed) {
        nox_key *k = &id->keys[id->nkeys++];
        k->alg = NOX_ALG_ED25519;
        k->usage = NOX_USAGE_SIGN | NOX_USAGE_AUTH;
        k->encoding = NOX_ENC_SEED;
        memcpy(k->pk, ed_pk, 32);
        k->pk_len = 32;
        memcpy(k->sk, ed_keep, 32);
        k->sk_len = 32;
        k->has_sk = 1;
    }
    if (want_dsa) {
        nox_key *k = &id->keys[id->nkeys++];
        k->alg = NOX_ALG_MLDSA44;
        k->usage = NOX_USAGE_SIGN;
        k->encoding = NOX_ENC_SEED;
        memcpy(k->pk, dsa_pk, 1312);
        k->pk_len = 1312;
        memcpy(k->sk, dsa_keep, 32);
        k->sk_len = 32;
        k->has_sk = 1;
    }
    if (want_x) {
        nox_key *k = &id->keys[id->nkeys++];
        k->alg = NOX_ALG_X25519;
        k->usage = NOX_USAGE_ENCRYPT;
        k->encoding = NOX_ENC_SEED;
        memcpy(k->pk, x_pk, 32);
        k->pk_len = 32;
        memcpy(k->sk, x_sk, 32);
        k->sk_len = 32;
        k->has_sk = 1;
    }
    if (want_kem) {
        nox_key *k = &id->keys[id->nkeys++];
        k->alg = NOX_ALG_MLKEM768;
        k->usage = NOX_USAGE_ENCRYPT;
        k->encoding = NOX_ENC_SEED;
        memcpy(k->pk, kem_pk, 1184);
        k->pk_len = 1184;
        memcpy(k->sk, kem_keep, 64);
        k->sk_len = 64;
        k->has_sk = 1;
    }

    rc = 0;
wipe:
    nox_wipe(ed_seed, sizeof ed_seed);
    nox_wipe(ed_keep, sizeof ed_keep);
    nox_wipe(ed_sk, sizeof ed_sk);
    nox_wipe(x_sk, sizeof x_sk);
    nox_wipe(kem_seed, sizeof kem_seed);
    nox_wipe(kem_keep, sizeof kem_keep);
    nox_wipe(kem_sk, sizeof kem_sk);
    nox_wipe(dsa_seed, sizeof dsa_seed);
    nox_wipe(dsa_keep, sizeof dsa_keep);
    nox_wipe(dsa_sk, sizeof dsa_sk);
    nox_wipe(ed_sig, sizeof ed_sig);
    nox_wipe(dsa_sig, sizeof dsa_sig);
    if (rc != 0)
        nox_ident_wipe(id);
    return rc;
}

int
nox_ident_parse_value(nox_ident *id, const uint8_t *val, size_t vlen)
{
    nox_parser inner;
    uint16_t clen;
    size_t off;
    int state = 0; /* 0 = need PK, 1 = PKs, 2 = unknown, 3 = SIGs */
    int nsign = 0;
    unsigned seen = 0;
    const uint8_t *keys_start = NULL;
    size_t keys_len = 0;
    size_t body_len = 0;
    const uint8_t *sig_start = NULL;

    nox_ident_init(id);
    if (vlen > NOX_MAX_IDENT)
        return nox_seterr("identity larger than 65536 bytes");
    if (vlen < 10)
        return nox_seterr("identity is truncated");

    id->created = nox_rd64(val);
    clen = nox_rd16(val + 8);
    if ((size_t)10 + clen > vlen)
        return nox_seterr("comment overruns identity");
    if (!nox_utf8_ok(val + 10, clen))
        return nox_seterr("comment is not valid UTF-8 (or contains NUL/CR/LF)");
    memcpy(id->comment, val + 10, clen);
    id->comment[clen] = 0;

    off = 10 + (size_t)clen;
    nox_parser_init(&inner, val + off, vlen - off);

    while (nox_parser_left(&inner)) {
        const uint8_t *pkt = inner.buf + inner.off;
        size_t pkt_off = inner.off;
        uint16_t t;
        int c;
        const uint8_t *v;
        uint32_t vn;

        if (nox_pkt_next(&inner, &t, &c, &v, &vn) < 0) {
            nox_ident_wipe(id);
            return -1;
        }
        if (t == NOX_PKT_PUBKEY) {
            uint16_t alg;
            uint8_t usage;
            int pkl;
            nox_key *k;

            if (state > 1)
                goto bad;
            state = 1;
            if (vn < 3)
                goto bad;
            alg = nox_rd16(v);
            usage = v[2];
            pkl = nox_pk_len(alg);
            if (pkl < 0) {
                nox_ident_wipe(id);
                return nox_seterr("unknown public key algorithm");
            }
            if (!nox_usage_ok(alg, usage) || vn != (uint32_t)(3 + pkl))
                goto bad;
            if (seen & (1u << alg))
                goto bad; /* each algorithm appears at most once */
            seen |= 1u << alg;
            if (id->nkeys >= NOX_MAX_KEYS) {
                nox_ident_wipe(id);
                return nox_seterr("too many keys in identity");
            }
            k = &id->keys[id->nkeys++];
            k->alg = alg;
            k->usage = usage;
            memcpy(k->pk, v + 3, (size_t)pkl);
            k->pk_len = (size_t)pkl;
            if (usage & NOX_USAGE_SIGN)
                nsign++;
            if (keys_start == NULL)
                keys_start = pkt;
            keys_len = (size_t)((inner.buf + inner.off) - keys_start);
        } else if (t == NOX_PKT_SIG) {
            if (state < 1)
                goto bad;
            if (state < 3) {
                body_len = off + pkt_off;
                sig_start = pkt;
                state = 3;
            }
            nsign--; /* one signature consumed; nsign was the expected count */
            if (nsign == 0)
                break;
        } else {
            if (c) {
                nox_ident_wipe(id);
                return nox_seterr("unknown critical packet in identity");
            }
            if (state == 0 || state == 3)
                goto bad;
            state = 2;
        }
    }
    if (state != 3 || nsign != 0)
        goto bad;

    {
        size_t consumed = off + inner.off;
        id->raw = malloc(consumed);
        if (id->raw == NULL) {
            nox_ident_wipe(id);
            return nox_seterr("out of memory");
        }
        memcpy(id->raw, val, consumed);
        id->raw_len = consumed;
        id->body_len = body_len;
        fingerprint(id->fp, keys_start, keys_len);

        if (check_sigs(id, val, body_len, sig_start,
                       consumed - body_len) < 0) {
            nox_ident_wipe(id);
            return -1;
        }
    }
    return 0;
bad:
    nox_ident_wipe(id);
    return nox_seterr("malformed identity");
}

int
nox_ident_parse(nox_ident *id, const uint8_t *buf, size_t n)
{
    nox_parser p;
    uint16_t type;
    int crit;
    const uint8_t *val;
    uint32_t vlen;

    nox_parser_init(&p, buf, n);
    if (nox_skip_magic(&p) < 0)
        return -1;
    if (nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0)
        return -1;
    if (type != NOX_PKT_IDENTITY)
        return nox_seterr("expected an identity packet");
    if (nox_parser_left(&p))
        return nox_seterr("trailing bytes after identity");
    if (nox_ident_parse_value(id, val, vlen) < 0)
        return -1;
    if (id->raw_len != vlen) {
        nox_ident_wipe(id);
        return nox_seterr("trailing bytes inside identity");
    }
    return 0;
}

int
nox_ident_load_pub(nox_ident *id, const uint8_t *buf, size_t n)
{
    uint8_t *raw = NULL;
    size_t rn = 0;
    int rc;

    if (nox_unwrap_blob(&raw, &rn, buf, n) < 0)
        return -1;
    rc = nox_ident_parse(id, raw, rn);
    free(raw);
    return rc;
}

int
nox_ident_public_blob(const nox_ident *id, uint8_t **out, size_t *n)
{
    nox_buf b;

    if (nox_buf_init(&b, 16 + id->raw_len) < 0)
        return -1;
    nox_buf_u8(&b, NOX_MAGIC0);
    nox_buf_u8(&b, NOX_MAGIC1);
    nox_buf_u8(&b, NOX_MAGIC2);
    nox_buf_u8(&b, NOX_MAGIC3);
    nox_buf_pkt(&b, NOX_PKT_IDENTITY, id->raw, (uint32_t)id->raw_len);
    if (b.err) {
        nox_buf_free(&b);
        return -1;
    }
    *out = b.p;
    *n = b.n;
    b.p = NULL;
    nox_buf_free(&b);
    return 0;
}
