#include "armor.h"
#include "cipher.h"
#include "identity.h"
#include "packet.h"
#include "sign.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails;

static void
ok(int cond, const char *what)
{
    if (!cond) {
        fprintf(stderr, "FAIL %s: %s\n", what, nox_err[0] ? nox_err : "");
        fails++;
    }
}

int
main(void)
{
    uint8_t raw[] = { 0, 1, 2, 3, 4, 250, 255 };
    char *b64 = NULL;
    uint8_t *dec = NULL;
    size_t n = 0, m = 0;
    char *arm = NULL;
    uint8_t *body = NULL;
    nox_ident id, id2;
    uint8_t *pub = NULL;
    char hex[65];
    uint8_t pkt[64];
    nox_parser p;
    uint16_t type;
    int crit;
    const uint8_t *val;
    uint32_t vlen;

    nox_set_faketime(1700000000);

    ok(nox_b64_encode(&b64, &n, raw, sizeof raw) == 0, "b64 encode");
    ok(nox_b64_decode(&dec, &m, (const uint8_t *)b64, n) == 0, "b64 decode");
    ok(m == sizeof raw && memcmp(dec, raw, m) == 0, "b64 round-trip");
    free(b64);
    free(dec);

    ok(nox_armor(&arm, &n, raw, sizeof raw, NOX_KIND_MSG) == 0, "armor");
    {
        const char *nl = strchr(arm, '\n');
        ok(nl != NULL && strncmp(arm, "-----BEGIN NOX MESSAGE-----", 27) == 0,
           "armor header");
        /* body lines wrap at 64; this payload is tiny so one short line */
        ok(strstr(arm, "-----END NOX MESSAGE-----") != NULL, "armor footer");
    }
    ok(nox_dearmor(&body, &m, (const uint8_t *)arm, n) == 0, "dearmor");
    ok(m == sizeof raw && memcmp(body, raw, m) == 0, "dearmor round-trip");
    free(arm);
    free(body);

    /* whitespace-lenient decode */
    {
        const char *messy = "  AA==\n\t\r ";
        ok(nox_b64_decode(&dec, &m, (const uint8_t *)messy, strlen(messy)) == 0,
           "b64 ignores whitespace");
        free(dec);
    }

    pkt[0] = NOX_MAGIC0;
    pkt[1] = NOX_MAGIC1;
    pkt[2] = NOX_MAGIC2;
    pkt[3] = NOX_MAGIC3;
    nox_be16(pkt + 4, NOX_PKT_IDENTITY);
    nox_be32(pkt + 6, 3);
    pkt[10] = 'a';
    pkt[11] = 'b';
    pkt[12] = 'c';
    nox_parser_init(&p, pkt, 13);
    ok(nox_skip_magic(&p) == 0, "magic");
    ok(nox_pkt_next(&p, &type, &crit, &val, &vlen) == 0, "packet");
    ok(type == NOX_PKT_IDENTITY && vlen == 3 && val[0] == 'a', "packet fields");
    ok(!nox_parser_left(&p), "no trailing");

    nox_be16(pkt + 4, 0);
    nox_parser_init(&p, pkt, 13);
    nox_skip_magic(&p);
    ok(nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0, "type 0 rejected");

    ok(!nox_utf8_ok((const uint8_t *)"a\nb", 3), "utf8 rejects LF");
    ok(!nox_utf8_ok((const uint8_t *)"a\0b", 3), "utf8 rejects NUL");
    ok(nox_utf8_ok((const uint8_t *)"ok \xE2\x9C\x93", 6), "utf8 accepts");

    nox_ident_init(&id);
    ok(nox_ident_generate(&id, "alice@example.com", nox_now()) == 0, "generate");
    ok(id.nkeys == 4, "four keys");
    ok(nox_ident_has_hybrid_enc(&id), "hybrid enc");
    ok(nox_ident_find(&id, NOX_ALG_ED25519) != NULL, "ed25519");
    ok(nox_ident_find(&id, NOX_ALG_MLDSA44) != NULL, "mldsa");
    ok(nox_ident_find(&id, NOX_ALG_X25519) != NULL, "x25519");
    ok(nox_ident_find(&id, NOX_ALG_MLKEM768) != NULL, "mlkem");
    ok(id.created == 1700000000ull, "faketime");
    ok(nox_ident_public_blob(&id, &pub, &n) == 0, "public blob");
    nox_ident_init(&id2);
    ok(nox_ident_parse(&id2, pub, n) == 0, "parse public");
    ok(nox_memeq(id.fp, id2.fp, NOX_FP_LEN) == 0, "fingerprint stable");
    ok(strcmp(id2.comment, "alice@example.com") == 0, "comment");
    nox_hex(hex, id.fp, NOX_FP_LEN);
    ok(nox_fp_prefix(id.fp, hex) == 1, "fp full");
    {
        char pre[9];
        memcpy(pre, hex, 8);
        pre[8] = 0;
        ok(nox_fp_prefix(id.fp, pre) == 1, "fp prefix 8");
        pre[7] = 0;
        ok(nox_fp_prefix(id.fp, pre) == 0, "fp prefix 7 rejected");
    }
    /* trailing bytes inside identity.value rejected */
    {
        uint8_t *dirty = malloc(n + 1);
        memcpy(dirty, pub, n);
        dirty[n] = 0xff;
        nox_ident id3;
        nox_ident_init(&id3);
        ok(nox_ident_parse(&id3, dirty, n + 1) < 0, "trailing rejected");
        free(dirty);
    }
    nox_ident_wipe(&id);
    nox_ident_wipe(&id2);
    free(pub);

    /* Key suites: every signing x encryption combination must
     * round-trip through encrypt/decrypt and sign/verify. */
    {
        static const struct {
            unsigned sm, em;
            int recip;
            int nkeys;
            const char *name;
        } suites[] = {
            { NOX_SIGN_ED25519 | NOX_SIGN_MLDSA44,
              NOX_ENC_X25519 | NOX_ENC_MLKEM768,
              NOX_ALG_HYBRID, 4, "hybrid" },
            { NOX_SIGN_ED25519, NOX_ENC_X25519,
              NOX_ALG_X25519, 2, "classic" },
            { NOX_SIGN_MLDSA44, NOX_ENC_MLKEM768,
              NOX_ALG_MLKEM768, 2, "pqc" },
            { NOX_SIGN_ED25519, NOX_ENC_MLKEM768,
              NOX_ALG_MLKEM768, 2, "ed+mlkem" },
            { NOX_SIGN_MLDSA44, NOX_ENC_X25519,
              NOX_ALG_X25519, 2, "mldsa+x" },
            { NOX_SIGN_ED25519 | NOX_SIGN_MLDSA44, NOX_ENC_X25519,
              NOX_ALG_X25519, 3, "sign-hybrid" },
            { NOX_SIGN_ED25519, NOX_ENC_X25519 | NOX_ENC_MLKEM768,
              NOX_ALG_HYBRID, 3, "enc-hybrid" },
        };
        static const char msg[] = "the quick brown fox jumps over the fence";
        size_t si;

#define TAG(what) (snprintf(tag, sizeof tag, "%s %s", suites[si].name, what), tag)

        for (si = 0; si < sizeof suites / sizeof suites[0]; si++) {
            nox_ident g, gp, other;
            nox_ident *rp[1], *ip[1];
            uint8_t *gb = NULL, *sig = NULL, hash[32], bad[32];
            size_t gn = 0, sign_n = 0;
            uint8_t back[128];
            size_t nr;
            FILE *in, *ct, *pt, *mf;
            char tag[128];
            char suite[128];

            nox_ident_init(&g);
            nox_ident_init(&gp);
            nox_ident_init(&other);
            if (nox_ident_generate_ex(&g, suites[si].name, nox_now(),
                                      suites[si].sm, suites[si].em) < 0) {
                ok(0, TAG("generate"));
                continue;
            }
            ok(g.nkeys == suites[si].nkeys, TAG("nkeys"));
            ok(nox_ident_recip_alg(&g) == suites[si].recip, TAG("recip alg"));
            ok(nox_ident_suite(suite, sizeof suite, &g) == 0, TAG("suite"));
            ok(nox_ident_public_blob(&g, &gb, &gn) == 0, TAG("pub blob"));
            ok(nox_ident_parse(&gp, gb, gn) == 0, TAG("parse"));
            ok(nox_memeq(g.fp, gp.fp, NOX_FP_LEN) == 0, TAG("fp"));

            in = tmpfile();
            ct = tmpfile();
            pt = tmpfile();
            mf = tmpfile();
            if (in == NULL || ct == NULL || pt == NULL || mf == NULL) {
                ok(0, TAG("tmpfile"));
                if (in != NULL)
                    fclose(in);
                if (ct != NULL)
                    fclose(ct);
                if (pt != NULL)
                    fclose(pt);
                if (mf != NULL)
                    fclose(mf);
                free(gb);
                nox_ident_wipe(&g);
                nox_ident_wipe(&gp);
                nox_ident_wipe(&other);
                continue;
            }

            /* encrypt to self, decrypt with self */
            fwrite(msg, 1, sizeof msg - 1, in);
            rewind(in);
            rp[0] = &g;
            ok(nox_encrypt(in, ct, 0, rp, 1, NULL, 0) == 0, TAG("encrypt"));
            rewind(ct);
            ip[0] = &g;
            ok(nox_decrypt(ct, pt, ip, 1, NULL, 0) == 0, TAG("decrypt"));
            rewind(pt);
            nr = fread(back, 1, sizeof back, pt);
            ok(nr == sizeof msg - 1 && memcmp(back, msg, nr) == 0,
               TAG("round-trip"));

            /* someone else's key must not open it */
            ok(nox_ident_generate(&other, "other", nox_now()) == 0,
               TAG("other"));
            rewind(ct);
            ip[0] = &other;
            ok(nox_decrypt(ct, pt, ip, 1, NULL, 0) < 0,
               TAG("no cross-decrypt"));
            fclose(in);
            fclose(ct);
            fclose(pt);

            /* sign with self, verify against the public half */
            fwrite(msg, 1, sizeof msg - 1, mf);
            rewind(mf);
            ok(nox_hash_file(mf, hash) == 0, TAG("hash"));
            fclose(mf);
            ok(nox_sign_detached(&sig, &sign_n, &g, hash) == 0, TAG("sign"));
            ok(nox_verify_detached(sig, sign_n, &gp, hash) == 0, TAG("verify"));
            memcpy(bad, hash, 32);
            bad[0] ^= 1;
            ok(nox_verify_detached(sig, sign_n, &gp, bad) < 0,
               TAG("no verify tampered"));
            ok(nox_verify_detached(sig, sign_n, &other, hash) < 0,
               TAG("no verify wrong key"));
            sig[sign_n - 1] ^= 1;
            ok(nox_verify_detached(sig, sign_n, &gp, hash) < 0,
               TAG("no verify damaged sig"));

            free(gb);
            free(sig);
            nox_ident_wipe(&g);
            nox_ident_wipe(&gp);
            nox_ident_wipe(&other);
        }
#undef TAG
    }

    ok(strcmp(nox_alg_name(NOX_ALG_X25519), "x25519") == 0, "alg name");
    ok(strcmp(nox_alg_name(NOX_ALG_MLDSA44), "mldsa44") == 0, "alg name pqc");
    ok(strcmp(nox_alg_name(0x9999), "unknown") == 0, "alg name unknown");

    {
        char esc[64];
        nox_escape_comment(esc, sizeof esc, "a\"b\\c\x01");
        ok(strcmp(esc, "a\\\"b\\\\c\\x01") == 0, "escape comment");
        nox_escape_comment(esc, sizeof esc, "ok \xE2\x9C\x93");
        ok(strcmp(esc, "ok \xE2\x9C\x93") == 0, "escape keeps utf-8");
    }

    /* generate_ex refuses empty or unknown suites */
    {
        nox_ident g;
        nox_ident_init(&g);
        ok(nox_ident_generate_ex(&g, "x", 0, 0, NOX_ENC_X25519) < 0,
           "no empty sign");
        ok(nox_ident_generate_ex(&g, "x", 0, NOX_SIGN_ED25519, 0) < 0,
           "no empty enc");
        ok(nox_ident_generate_ex(&g, "x", 0, 0x10, NOX_ENC_X25519) < 0,
           "no bad sign bit");
        nox_ident_wipe(&g);
    }

    if (fails) {
        fprintf(stderr, "%d test(s) failed\n", fails);
        return 1;
    }
    printf("test_unit: ok\n");
    return 0;
}
