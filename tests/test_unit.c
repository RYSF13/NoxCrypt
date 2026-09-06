#include "armor.h"
#include "identity.h"
#include "packet.h"

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

    if (fails) {
        fprintf(stderr, "%d test(s) failed\n", fails);
        return 1;
    }
    printf("test_unit: ok\n");
    return 0;
}
