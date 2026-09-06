#ifndef NOX_IDENTITY_H
#define NOX_IDENTITY_H

#include "util.h"

typedef struct {
    uint16_t alg;
    uint8_t usage;
    uint8_t encoding;          /* NOX_ENC_SEED or NOX_ENC_EXP when has_sk */
    uint8_t pk[1312];
    size_t pk_len;
    uint8_t sk[2560];
    size_t sk_len;
    int has_sk;
} nox_key;

typedef struct {
    uint64_t created;
    char comment[NOX_MAX_COMMENT + 1];
    uint8_t fp[NOX_FP_LEN];
    nox_key keys[NOX_MAX_KEYS];
    int nkeys;
    uint8_t *raw;              /* Identity.value */
    size_t raw_len;
    size_t body_len;           /* bytes before the first Signature packet */
} nox_ident;

void nox_ident_init(nox_ident *id);
void nox_ident_wipe(nox_ident *id);

int nox_ident_generate(nox_ident *id, const char *comment, uint64_t created);
int nox_ident_parse(nox_ident *id, const uint8_t *buf, size_t n);
int nox_ident_parse_value(nox_ident *id, const uint8_t *val, size_t vlen);
int nox_ident_public_blob(const nox_ident *id, uint8_t **out, size_t *n);
int nox_ident_load_pub(nox_ident *id, const uint8_t *buf, size_t n);

/* Expand a secret into `sk` (caller wipes). Does not consume the stored seed. */
int nox_key_expand(const nox_key *k, uint8_t *sk, size_t *sk_len);

nox_key *nox_ident_find(nox_ident *id, uint16_t alg);
int nox_ident_has_hybrid_enc(const nox_ident *id);

#endif
