# NoxCrypt Format Specification

Status: SPEC-v1 (draft)
Date: 2026-09-10

This document is the English specification of the NoxCrypt version 1
wire format. A v1 generator MUST emit only the packet types and
algorithms listed here, and MUST NOT set the critical bit on any
packet. A v1 parser MUST reject malformed input rather than treat it
as valid.

Integers are unsigned big-endian. `u8`, `u16`, `u32`, and `u64` mean
8-, 16-, 32-, and 64-bit unsigned integers. Concatenation is written
`||`. Byte strings are raw, not NUL-terminated.

## 1. Goals

NoxCrypt is a small Linux tool for hybrid (classical + post-quantum)
encryption and signatures. It follows the Unix tradition of age and
minisign: one job, pipes, auditable C, no network protocol.

- An identity carries at least one signing algorithm (Ed25519,
  ML-DSA-44) and at least one encryption algorithm (X25519,
  ML-KEM-768). The generator offers three profiles: hybrid (all four),
  ecc (Ed25519 + X25519), and pqc (ML-DSA-44 + ML-KEM-768), plus an
  explicit mixed pair.
- Which algorithms an identity holds decides how it is addressed. The
  generator emits exactly one recipient algorithm per identity:
  `0x0005` when it holds both X25519 and ML-KEM-768, `0x0001` when it
  holds only X25519, and `0x0003` when it holds only ML-KEM-768. A
  decryptor only tries the flavor its own key set implies, so a hybrid
  identity is never unwrapped through a single-algorithm recipient.
- Nothing encrypts bytes with ML-KEM-768 directly. The KEM shared
  secret (and, for hybrid recipients, an ephemeral X25519 DH) is hashed
  into a key that wraps the file key under XChaCha20-Poly1305.
- A passphrase recipient (`0x0006`) is exclusive: if present, it is
  the only recipient.
- Secret keys are always wrapped with Argon2id. Unprotected private
  key material is never written to disk or stdout.
- Randomness comes from the OS CSPRNG (`getrandom` on Linux).

## 2. File framing

Every binary document begins with a 4-byte magic:

```
0x4E 0x4F 0x58 0x01      "NOX" || version
```

Version `0x01` is this specification. Any other version is rejected.

The remainder of the file is a sequence of packets. A document
contains exactly one top-level packet after the magic (Identity,
Secret, Encrypted Header followed by Chunks, or Detached Signature).
Trailing bytes after that packet (or after the last Chunk of a
ciphertext) are an error.

### 2.1 Packet

```
type    u16     bit 15 is the critical flag; bits 14..0 are the type
length  u32     number of bytes in value
value   bytes   `length` bytes
```

Type `0` is reserved and illegal. If `length` exceeds the remaining
input, the file is truncated and MUST be rejected.

If bit 15 is set and the type is unknown, parsing fails. If bit 15 is
clear and the type is unknown, a v1 parser ignores that packet.
A v1 generator MUST NOT set bit 15 and MUST NOT emit unknown types.

### 2.2 Packet types

| Type     | Name                 | Where it appears                          |
|----------|----------------------|-------------------------------------------|
| `0x0001` | Identity             | public key file (top-level)               |
| `0x0002` | Secret               | secret key file (top-level)               |
| `0x0003` | Encrypted Header     | ciphertext (top-level, then Chunks)       |
| `0x0004` | Detached Signature   | signature file (top-level)                |
| `0x0010` | Public Key           | inside Identity                           |
| `0x0011` | Secret Key           | inside unlocked Secret plaintext          |
| `0x0012` | Signature            | inside Identity, Detached Signature       |
| `0x0013` | Recipient            | inside Encrypted Header                   |
| `0x0014` | Chunk                | ciphertext payload                        |

### 2.3 Algorithms

| Id       | Name        | Role                                      |
|----------|-------------|-------------------------------------------|
| `0x0001` | X25519      | encryption key, X25519 file-key wrap      |
| `0x0002` | Ed25519     | signatures / authentication               |
| `0x0003` | ML-KEM-768  | encryption key, ML-KEM file-key wrap      |
| `0x0004` | ML-DSA-44   | signatures                                |
| `0x0005` | Hybrid      | X25519 + ML-KEM-768 file-key wrap         |
| `0x0006` | Argon2id    | passphrase file-key wrap                  |

All three key wrap algorithms (`0x0001`, `0x0003`, `0x0005`) are
current; which one appears is decided by the recipient identity, never
by a preference of the sender. `0x0001` and `0x0003` are for identities
that carry a single encryption algorithm. An identity holding both
X25519 and ML-KEM-768 MUST be wrapped with `0x0005`, and a decryptor
holding both MUST NOT unwrap `0x0001` or `0x0003` (anti-downgrade).
A message MAY mix recipients of different algorithms, up to the
recipient limit.

### 2.4 Usage bits (Public Key / Secret Key)

```
bit 0  0x01  ENCRYPT
bit 1  0x02  SIGN
bit 2  0x04  AUTH
```

X25519 and ML-KEM-768 MUST use usage `0x01`. Ed25519 and ML-DSA-44
MUST NOT set ENCRYPT, and MUST set at least one of SIGN or AUTH.
Ed25519 on a new identity is `SIGN|AUTH` (`0x06`). ML-DSA-44 is
`SIGN` (`0x02`).

### 2.5 Secret encodings

| Value | Meaning                                      |
|-------|----------------------------------------------|
| `0x01`| seed (v1 generator always writes this)       |
| `0x02`| expanded secret (accepted on import)         |

Seed lengths: X25519 32, Ed25519 32, ML-KEM-768 64, ML-DSA-44 32.
Expanded lengths: X25519 32, Ed25519 64, ML-KEM-768 2400, ML-DSA-44 2560.

libncrypt wipes seeds passed to `*_key_pair` and `encapsulate`. A
generator that needs to keep the seed MUST copy it first.

## 3. Domain separation

Every hash and AEAD additional-data string is a UTF-8 constant with no
terminating NUL in the input:

| Constant                 | Bytes                         |
|--------------------------|-------------------------------|
| `noxcrypt/v1/identity`   | identity self-signatures      |
| `noxcrypt/v1/fingerprint`| fingerprint hash              |
| `noxcrypt/v1/signature`  | detached signatures           |
| `noxcrypt/v1/secret`     | secret-key wrapping AD        |
| `noxcrypt/v1/header`     | file-key wrapping AD          |
| `noxcrypt/v1/payload`    | chunk AEAD AD                 |
| `noxcrypt/v1/x25519-wrap`| X25519 DH transcript          |
| `noxcrypt/v1/mlkem768-wrap` | ML-KEM shared-secret transcript |
| `noxcrypt/v1/hybrid-wrap`| combination of the two wraps  |

## 4. Identity (public key)

A public-key file is:

```
magic || Identity packet
```

`Identity.value`:

```
created      u64     Unix seconds
comment_len  u16     byte length of comment
comment      bytes   UTF-8, no NUL / CR / LF, at most 1024 bytes
PublicKey packets    one or more, contiguous
optional unknown non-critical packets
Signature packets    one per SIGN key, same order as those keys
```

The Identity packet (and therefore `Identity.value`) is at most 65536
bytes. A public-key file MUST NOT contain bytes after the Identity
packet. `Identity.value` MUST end at the last required Signature
packet; extra bytes inside the value are rejected.

`PublicKey.value`:

```
alg     u16
usage   u8
key     bytes    length fixed by alg
              X25519 / Ed25519: 32
              ML-KEM-768: 1184
              ML-DSA-44: 1312
```

`Signature.value` (inside an identity):

```
alg     u16
sig     bytes    Ed25519: 64    ML-DSA-44: 2420
```

Each SIGN key signs, in order:

```
"noxcrypt/v1/identity" || Identity.value[0 .. body)
```

where `body` is everything in `Identity.value` before the first
Signature packet.

Public Key packets come in a fixed order, signing keys first, with the
algorithms an identity does not use left out:

1. Ed25519, usage `0x06`
2. ML-DSA-44, usage `0x02`
3. X25519, usage `0x01`
4. ML-KEM-768, usage `0x01`

The order is part of the fingerprint, so it is not a matter of taste.
The generator writes one Signature packet per signing key, in the same
order. An identity with no signing key is rejected; an identity with no
encryption key parses, but nothing can be encrypted to it.

The four combinations the CLI can generate are named after their key
sets: `hybrid` (all four), `ecc` (Ed25519 + X25519), `pqc` (ML-DSA-44 +
ML-KEM-768), and `mixed` (one signing plus one encryption algorithm
chosen by hand).

### 4.1 Fingerprint

The fingerprint is BLAKE2b-256 of

```
"noxcrypt/v1/fingerprint" || concatenated PublicKey packets
```

It is displayed as 64 lowercase hex characters. Lookups accept a
prefix of at least 8 hex characters and fail if the prefix is
ambiguous.

## 5. Secret key

A secret-key file is:

```
magic || Secret packet
```

Secrets are always passphrase-protected. `Secret.value`:

```
t           u32     Argon2id passes
m           u32     Argon2id memory in KiB
p           u32     Argon2id lanes
outlen      u32     must be 32
salt_len    u8      must be 16
salt        16
nonce       24      XChaCha20-Poly1305 nonce
mac         16
ciphertext  rest    AEAD of the secret plaintext
```

v1 writes `t = 3`, `m = 65536`, `p = 1`. A parser that sees `t < 3`
or `m < 16384` MUST warn on stderr but MAY continue. `m` above
`2^21` is rejected.

The wrapping key is Argon2id with the passphrase, the salt, those
parameters, and a 32-byte output. AEAD additional data is:

```
"noxcrypt/v1/secret" || magic || Secret.value[0 .. 33)
```

i.e. the KDF parameters and salt, not the nonce or MAC.

Plaintext of the ciphertext:

```
Identity.value (exactly as in the public file) ||
SecretKey packet for each public key, same order
```

`SecretKey.value`:

```
alg        u16
usage      u8     must match the corresponding Public Key
encoding   u8     0x01 seed or 0x02 expanded
material   bytes  length from section 2.5
```

After unlock, each secret is expanded and checked against the public
key. A mismatch is an error, not a usable key.

## 6. Encrypted message

```
magic || Encrypted Header packet || Chunk packets
```

`Encrypted Header.value`:

```
payload_nonce   24     XChaCha20-Poly1305 extended nonce
Recipient packets
```

At most 16 recipients. If any recipient uses algorithm `0x0006`, it
MUST be the only recipient. Unknown non-critical packets in the
header are ignored; a critical unknown packet is fatal. Recipients of
different algorithms may sit in the same header: a sender that encrypts
to a hybrid, an ecc, and a pqc identity writes one recipient of each
kind.

The 32-byte file key is random. Every recipient wraps that same file
key. Wrapping AEAD additional data is:

```
"noxcrypt/v1/header" || magic || payload_nonce
```

### 6.1 Hybrid recipient (`0x0005`)

Used for identities that hold both X25519 and ML-KEM-768.

`Recipient.value`:

```
alg          u16     0x0005
fingerprint  32      recipient identity fingerprint
eph_pk       32      ephemeral X25519 public key
kem_ct       1088    ML-KEM-768 ciphertext
nonce        24
mac          16
wrapped      32      AEAD ciphertext of the file key
```

Derivation (sender):

1. Generate ephemeral X25519 secret `eph_sk` and public `eph_pk`.
2. `raw = X25519(eph_sk, recipient_x25519_pk)`. If `raw` is all
   zeros, abort.
3. `xk = BLAKE2b-256("noxcrypt/v1/x25519-wrap" || eph_pk || recipient_x25519_pk || raw)`
4. Encapsulate to the recipient ML-KEM-768 public key, obtaining
   `kem_ct` and shared secret `ss`.
5. `kk = BLAKE2b-256("noxcrypt/v1/mlkem768-wrap" || kem_ct || recipient_mlkem_pk || ss)`
6. `wk = BLAKE2b-256("noxcrypt/v1/hybrid-wrap" || xk || kk || fingerprint)`
7. AEAD-lock the file key under `wk`.

The recipient performs the DH with `(recipient_sk, eph_pk)` and
ML-KEM decapsulation, then the same hashes. A hybrid identity MUST
NOT be decrypted via an `0x0001` or `0x0003` recipient even if those
keys would otherwise unwrap the file key.

### 6.2 X25519 recipient (`0x0001`)

Used for ecc and mixed identities that hold no ML-KEM-768 key.

`Recipient.value`:

```
alg          u16     0x0001
fingerprint  32      recipient identity fingerprint
eph_pk       32      ephemeral X25519 public key
nonce        24
mac          16
wrapped      32      AEAD ciphertext of the file key
```

Derivation (sender):

1. Generate ephemeral X25519 secret `eph_sk` and public `eph_pk`.
2. `raw = X25519(eph_sk, recipient_x25519_pk)`. If `raw` is all
   zeros, abort.
3. `wk = BLAKE2b-256("noxcrypt/v1/x25519-wrap" || eph_pk || recipient_x25519_pk || raw)`
4. AEAD-lock the file key under `wk` with the header additional data
   from section 6.

The recipient repeats step 2 with `(recipient_x25519_sk, eph_pk)` and
then step 3. Both sides hash the same three inputs in the same order:
the ephemeral public key, the recipient's static X25519 public key,
and the raw shared secret.

### 6.3 ML-KEM-768 recipient (`0x0003`)

Used for pqc and mixed identities that hold no X25519 key.

`Recipient.value`:

```
alg          u16     0x0003
fingerprint  32      recipient identity fingerprint
kem_ct       1088    ML-KEM-768 ciphertext
nonce        24
mac          16
wrapped      32      AEAD ciphertext of the file key
```

Derivation (sender):

1. Encapsulate to the recipient ML-KEM-768 public key, obtaining
   `kem_ct` and shared secret `ss`.
2. `wk = BLAKE2b-256("noxcrypt/v1/mlkem768-wrap" || kem_ct || recipient_mlkem_pk || ss)`
3. AEAD-lock the file key under `wk` with the header additional data
   from section 6.

The recipient decapsulates `kem_ct` and repeats step 2. The AEAD is
still XChaCha20-Poly1305; ML-KEM only contributes key material.

### 6.4 Passphrase recipient (`0x0006`)

`Recipient.value`:

```
alg        u16     0x0006
t m p      u32     Argon2id parameters (same layout as Secret)
outlen     u32     32
salt_len   u8      16
salt       16
nonce      24
mac        16
wrapped    32
```

Argon2id(passphrase) -> 32-byte key -> AEAD-lock the file key with the
header additional data above. KDF parameters travel in the recipient
itself, so the recipient can read a file written with other parameters
than its own.

### 6.5 Payload chunks

The payload is XChaCha20-Poly1305 in streaming mode (`aead_init_x`
with the file key and `payload_nonce`). Each step ratchets the key,
so reordering is detected. Truncation is not, so the last chunk is
flagged in the additional data.

`Chunk.value`:

```
mac          16
ciphertext   rest    at most 65536 bytes of plaintext
```

Additional data for chunk index `i` (u64, starting at 0):

```
"noxcrypt/v1/payload" || i || last
```

`last` is a single byte, `0x01` if this is the final chunk, else
`0x00`. Non-final chunks MUST encrypt exactly 65536 plaintext bytes.
The final chunk MAY be empty (used for the empty file, and for a
file whose length is a positive multiple of 65536). A ciphertext
with no final chunk, or with bytes after the final chunk, is
rejected.

## 7. Detached signature

```
magic || Detached Signature packet
```

`Detached Signature.value`:

```
created       u64
fingerprint   32      signer identity
Signature packets     one per SIGN key of that identity, same order
```

Let `H = BLAKE2b-256(message bytes)` (streamed; the message is never
required to fit in memory). Each SIGN key signs:

```
"noxcrypt/v1/signature" || created || fingerprint || H
```

A signer emits one Signature packet per SIGN key of its identity, in
identity order, and nothing else: one for an ecc or pqc identity, two
for a hybrid one. A verifier MUST require every SIGN key of the
offered public identity to verify, no more and no fewer; a signature
that drops ML-DSA-44 from a hybrid identity, or that carries an
algorithm the identity does not have, is rejected. On success the CLI
prints only:

```
Good signature
```

and nothing else.

## 8. ASCII armor

Armored documents are PEM-style, RFC 4648 base64 (`+/` with `=`),
wrapped at 64 columns.

```
-----BEGIN NOX KIND-----

<base64>

-----END NOX KIND-----
```

`KIND` is one of `PUBLIC KEY`, `SECRET KEY`, `MESSAGE`, `SIGNATURE`.
Output is strict: a blank line after BEGIN, 64-column body, newline
after the last body line, then END.

Input is lenient:

- All whitespace in the base64 body is ignored.
- Any header lines between `BEGIN` and the first blank line are
  ignored. If the first non-empty line after BEGIN is already
  base64, it is treated as the body (no blank line required).

Writing a binary NoxCrypt document to a terminal is refused unless
`--armor` is set. Plaintext produced by `decrypt` is not subject to
that rule.

## 9. Keyring

Default directory: `$NOX_HOME/.nox` if `NOX_HOME` is set, else
`~/.nox`. The directory is created with mode `0700`. Each identity
is two files, mode `0600`:

```
<64-hex-fingerprint>.pub
<64-hex-fingerprint>.sec
```

`nox list` walks the whole keyring and prints one block per identity:
fingerprint and UTC creation date on the first line, the profile and
its algorithms on the second, the comment in double quotes on the
third. Keys whose secret half is missing say so on the second line.
Blocks are sorted by fingerprint, because directory order is not.
An optional query matches a fingerprint prefix or a substring of the
comment.

## 10. CLI

Subcommand form, not a flag soup:

```
nox [--faketime UNIX] [--home DIR] COMMAND [OPTIONS]
```

| Command    | Purpose                                                |
|------------|--------------------------------------------------------|
| `gen`      | generate an identity, always passphrase-wrapped        |
| `encrypt`  | `-r` fingerprint, `-R` public file, or `-p` passphrase |
| `decrypt`  | `-i` identity, or `-p` for a passphrase ciphertext     |
| `sign`     | detached signature                                     |
| `verify`   | prints `Good signature` on success                     |
| `list`     | list the keyring                                       |
| `export`   | `-s` for secret; prefix of at least 8 hex chars        |
| `import`   | public or secret; secret requires the passphrase       |
| `delete`   | remove pub and sec for a fingerprint                   |
| `info`     | version, author, algorithms, keyring summary           |

`gen` picks algorithms with `-A hybrid|ecc|pqc` and, alternatively,
`--sig ALG --kem ALG` for a pair chosen by hand. Using neither is the
same as `-A hybrid`. There is no separate flag for encryption and
signing keys at use time: `encrypt`, `sign`, and `verify` read the
identity and use whatever it holds.

Global options come before the command: `nox --home DIR list`, not
`nox list --home DIR`. `--faketime` replaces `time()` for `created`
timestamps. Stdin and stdout are used when a path is omitted or is `-`.

Passphrases are read from `/dev/tty` with echo off. Terminal
attributes are restored on success, error, and the usual terminating
signals. `--passphrase-file` reads the first line of a file (for
scripts and tests). Empty passphrases are rejected.

## 11. Cryptographic primitives

Provided by vendored libncrypt (Monocypher 4.0.3 plus the bundled
ML-KEM-768 / ML-DSA-44 cores). Every algorithm this tool can use is
listed here; the specification has no optional ones:

- XChaCha20-Poly1305 (`ncrypt_aead_*`)
- X25519, Ed25519 (SHA-512 EdDSA, not EdDSA-BLAKE2b)
- BLAKE2b
- Argon2id
- ML-KEM-768, ML-DSA-44 (pure, empty context, deterministic)

The following libncrypt entry points MUST NOT be called:

- `ncrypt_eddsa_*`
- `ncrypt_ed25519_ph_*`
- `ncrypt_pqc_encrypt` / `ncrypt_pqc_decrypt`
- `ncrypt_x25519_to_eddsa` / `ncrypt_eddsa_to_x25519`

X25519 encryption keys and Ed25519 signing keys are independent.
They are never converted into each other.

## 12. Limits

| Limit                        | Value        |
|------------------------------|--------------|
| Identity.value               | 65536 bytes  |
| Comment                      | 1024 bytes   |
| Keys per identity            | 8            |
| Signing keys (generator)     | 2            |
| Encryption keys (generator)  | 2            |
| Recipients per message       | 16           |
| Chunk plaintext              | 65536 bytes  |
| Passphrase                   | 1023 bytes   |
| Argon2id m (KiB)             | 8*p .. 2^21  |

## 13. Security notes

- Parsers fail closed. There is no "best effort" recovery of bad
  packets, no type 0, and no critical-bit surprises from a v1
  generator.
- Hybrid documents require the post-quantum half. Stripping ML-KEM
  from a hybrid recipient, or ML-DSA-44 from a hybrid signature, does
  not yield a usable document.
- An ecc identity protects nothing against a quantum computer. It is
  what the name says: classical. The same holds for an Ed25519-only
  signature. Choose it knowing that, not by accident.
- Streaming encryption writes plaintext chunks as they authenticate.
  A failure in a later chunk cannot un-write earlier ones; callers
  that need all-or-nothing semantics should use a temporary file.
- Argon2id uses 64 MiB and 3 passes. That is a desktop parameter
  set, not a password-hashing competition winner.
- This is a draft. Do not pretend it has seen a third-party audit.
