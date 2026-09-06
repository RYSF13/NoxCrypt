// libncrypt-pqc 0.1.0
// Post-quantum extension for libncrypt
//
// Key encapsulation : ML-KEM-768  (FIPS 203)
// Signatures        : ML-DSA-44   (FIPS 204)
// Hybrid encryption : ML-KEM-768 + XChaCha20-Poly1305
//
// ncrypt-pqc.c carries the ML-KEM-768 and ML-DSA-44 reference cores
// (FIPS 203 / FIPS 204) in this unit, so this module is self-contained:
// it depends only on ncrypt.h / ncrypt.c (BLAKE2b, AEAD, and the
// constant-time comparison and wiping routines) and needs no external
// post-quantum library at build time.

#ifndef NCRYPT_PQC_H
#define NCRYPT_PQC_H

#include <string.h>
#include "ncrypt.h"

// Buffer sizes, in bytes
// ----------------------
//
//                       public key  secret key  ciphertext  signature
//   ML-KEM-768             1184        2400        1088         -
//   ML-DSA-44              1312        2560          -        2420
//
// Shared secrets are always 32 bytes.  ML-KEM key generation uses a
// 64 byte seed, encapsulation and ML-DSA key generation a 32 byte
// seed.


// ML-KEM-768 (key encapsulation)
// ------------------------------

// Deterministic key generation.  The seed is wiped.
void ncrypt_mlkem768_key_pair(uint8_t secret_key[2400],
                              uint8_t public_key[1184],
                              uint8_t seed      [64]);

// We wrap a 32 byte shared secret for the holder of public_key.
// The seed is wiped.  Returns 0 on success, -1 if the public key is
// malformed (not a valid ML-KEM-768 encapsulation key).  On failure
// nothing is written to ciphertext or shared_secret.
int ncrypt_mlkem768_encapsulate(uint8_t       ciphertext   [1088],
                                uint8_t       shared_secret[32],
                                const uint8_t public_key   [1184],
                                uint8_t       seed         [32]);

// Recovers the shared secret.  Returns 0 on success, -1 if the
// secret key is inconsistent (corrupted or truncated at import).
// A forged or damaged ciphertext is *not* reported: as FIPS 203
// mandates, decapsulation then yields an unrelated random-looking
// secret (implicit rejection), and whatever is encrypted under it
// will fail to authenticate.
int ncrypt_mlkem768_decapsulate(uint8_t       shared_secret[32],
                                const uint8_t ciphertext   [1088],
                                const uint8_t secret_key   [2400]);


// ML-DSA-44 (signatures)
// ----------------------

// Deterministic key generation.  The seed is wiped.
void ncrypt_mldsa44_key_pair(uint8_t secret_key[2560],
                             uint8_t public_key[1312],
                             uint8_t seed      [32]);

// Signs a message (pure ML-DSA-44, empty context string, the
// deterministic variant of FIPS 204).  Same message, same key,
// same signature.
void ncrypt_mldsa44_sign(uint8_t        signature [2420],
                         const uint8_t  secret_key[2560],
                         const uint8_t *message, size_t message_size);

// Returns 0 if the signature is genuine, -1 otherwise.
int ncrypt_mldsa44_check(const uint8_t  signature [2420],
                         const uint8_t  public_key[1312],
                         const uint8_t *message, size_t message_size);


// High level interface
// --------------------
//
// The functions below are what a typical application should call.
// Encryption keys are ML-KEM-768 key pairs, signing keys are
// ML-DSA-44 key pairs.  Keep the two separate: never reuse one seed
// or one key pair for both purposes.

// Encryption identity (alias for ncrypt_mlkem768_key_pair)
void ncrypt_pqc_key_pair(uint8_t secret_key[2400],
                         uint8_t public_key[1184],
                         uint8_t seed      [64]);

// Signing identity (alias for ncrypt_mldsa44_key_pair)
void ncrypt_pqc_sign_key_pair(uint8_t secret_key[2560],
                              uint8_t public_key[1312],
                              uint8_t seed      [32]);

// One shot public key authenticated encryption:
// encapsulates a fresh secret for their_public_key, derives a
// message key with BLAKE2b, then locks the plaintext with
// XChaCha20-Poly1305.  Send kem_ct, mac, and cipher_text; ad is
// authenticated but not transmitted by this function.
// The seed is wiped.  Returns 0 on success, -1 if the public key is
// malformed.
int ncrypt_pqc_encrypt(uint8_t       *cipher_text,
                       uint8_t        mac       [16],
                       uint8_t        kem_ct    [1088],
                       const uint8_t  their_public_key[1184],
                       uint8_t        seed      [32],
                       const uint8_t *ad,         size_t ad_size,
                       const uint8_t *plain_text, size_t text_size);

// Reverses ncrypt_pqc_encrypt.  Returns 0 on success, -1 if
// anything (kem_ct, mac, ad, or cipher_text) was tampered with.
// On failure the plaintext buffer is left untouched.
int ncrypt_pqc_decrypt(uint8_t       *plain_text,
                       const uint8_t  kem_ct    [1088],
                       const uint8_t  mac       [16],
                       const uint8_t  secret_key[2400],
                       const uint8_t *ad,          size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

// Detached signatures (aliases for the ML-DSA-44 pair above)
void ncrypt_pqc_sign(uint8_t        signature [2420],
                     const uint8_t  secret_key[2560],
                     const uint8_t *message, size_t message_size);
int ncrypt_pqc_check(const uint8_t  signature [2420],
                     const uint8_t  public_key[1312],
                     const uint8_t *message, size_t message_size);

#endif // NCRYPT_PQC_H
