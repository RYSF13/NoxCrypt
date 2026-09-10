#ifndef NOX_KEYRING_H
#define NOX_KEYRING_H

#include "identity.h"

int nox_keyring_dir(char *buf, size_t n);
int nox_keyring_init(void);

int nox_keyring_store_pub(const nox_ident *id);
int nox_keyring_store_sec(const uint8_t fp[NOX_FP_LEN],
                          const uint8_t *blob, size_t n);

int nox_keyring_load_pub(const char *query, nox_ident *id);
int nox_keyring_load_sec_blob(const char *query, uint8_t **blob, size_t *n,
                              uint8_t fp[NOX_FP_LEN]);

/* `fp` may be NULL; otherwise it receives the deleted fingerprint. */
int nox_keyring_delete(const char *query, uint8_t fp[NOX_FP_LEN]);
int nox_keyring_list(FILE *out, const char *query);
int nox_keyring_count_sec(void);

#endif
