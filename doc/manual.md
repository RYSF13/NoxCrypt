# NoxCrypt manual

This is the long form of the `nox(1)` man page: what the tool is for,
how the pieces fit together, and which parts are worth being careful
about. The wire format itself is in [SPEC.md](SPEC.md), which is the
document to read if you want to implement a compatible tool rather
than use this one.

## What NoxCrypt is

NoxCrypt encrypts files and streams to a public key and signs them
with a secret key. It is built around two ideas:

- Every key pair is *hybrid* by default. An identity carries an
  Ed25519 and an ML-DSA-44 signing key plus an X25519 and an
  ML-KEM-768 encryption key. A message is readable only if both the
  classical and the post-quantum half are broken.
- Everything else stays small. No configuration file, no daemon, no
  key server, no network code, no plugin system. One subcommand does
  one thing, plain files go in and out, and a pipe is a first-class
  citizen.

If you want the short version: it is `age` plus `minisign`, with
post-quantum algorithms, a keyring under `~/.nox`, and a passphrase on
every secret key.

## Building and installing

```
make            # builds ./nox
make test       # unit tests plus a CLI round-trip in tests/tmp
make install    # PREFIX=/usr/local by default, installs nox and nox.1
```

The build needs a C11 compiler and nothing else; the post-quantum code
is vendored in `vendor/libncrypt`, so liboqs is not required. The test
suite spends a few seconds in Argon2id on purpose.

`make install` also honors `DESTDIR` for packaging, and
`BINDIR`/`MANDIR` if you want the files somewhere unusual.

## Identities

An identity is one key pair. Generating one writes two files into the
keyring and prints the fingerprint:

```
$ nox gen -c 'alice@example.com'
nox: fingerprint  7f3c9d02...8b41
nox: algorithms   hybrid: Ed25519 + ML-DSA-44 + X25519 + ML-KEM-768
nox: public key   /home/alice/.nox/7f3c9d02....pub
nox: secret key   /home/alice/.nox/7f3c9d02....sec
7f3c9d02...8b41
```

The fingerprint is 64 hex characters: BLAKE2b-256 over the identity's
public key packets, in the order the file stores them. It does not
depend on the comment or the creation date, so it is stable across
every re-encoding. The comment and the date are signed by the
identity's own signing keys, so a comment cannot be swapped out
without breaking the self-signature.

Commands that need a key accept any unambiguous prefix of at least
eight hex characters. Eight characters is 32 bits, which is fine for a
keyring and useless as a global identifier; export the full
fingerprint when two machines have to agree.

## Algorithm profiles

`gen` writes one of four kinds of identity.

| Profile  | Signing             | Encryption           | Notes                       |
|----------|---------------------|----------------------|-----------------------------|
| `hybrid` | Ed25519 + ML-DSA-44 | X25519 + ML-KEM-768  | the default                 |
| `ecc`    | Ed25519             | X25519               | classical only, tiny keys   |
| `pqc`    | ML-DSA-44           | ML-KEM-768           | post-quantum only           |
| mixed    | one, by `--sig`     | one, by `--kem`      | e.g. Ed25519 + ML-KEM-768   |

```
nox gen -A hybrid -c 'default'
nox gen -A ecc    -c 'classical fallback'
nox gen -A pqc    -c 'nothing classical'
nox gen --sig ed25519 --kem mlkem768 -c 'curious mixture'
```

Which profile to pick depends on what you are protecting against:

- **hybrid** is the right default. It is the only one where an
  attacker has to break both a classical and a post-quantum
  assumption, and it is the only one whose ciphertexts are safe
  against "record now, decrypt later" if either assumption holds.
- **ecc** exists because the classical algorithms are small, fast, and
  well studied, and because some environments do not want the larger
  keys. A recorded ciphertext from an `ecc` key becomes readable the
  day a quantum computer shows up.
- **pqc** is for when you want nothing to do with the classical
  assumptions at all, or when you need keys whose security is not
  tied to discrete logarithms. Budget the space: ML-DSA-44 signatures
  are 2420 bytes and ML-KEM-768 public keys are 1184 bytes.
- **mixed** is mostly a research and migration tool, and a way to
  demonstrate that the file format does not care which pair you picked.
  It has the same weakness as the weaker half of its pair. Picking
  Ed25519 for signing plus ML-KEM-768 for encryption gives you
  post-quantum confidentiality with classical signatures, and that
  combination has no post-quantum authentication.

A key pair cannot be converted from one profile to another, because
the fingerprint covers exactly which algorithms are present. Generate
a new identity and tell your correspondents about it.

### Why ML-KEM never encrypts anything by itself

ML-KEM-768 is a KEM: it turns a public key into a shared secret and a
ciphertext of that secret. It has no notion of a message. NoxCrypt
therefore never uses it to protect data directly. The actual sequence
for an ML-KEM-only recipient is:

1. Generate a random 32-byte file key.
2. Encapsulate to the recipient's ML-KEM-768 public key, getting a
   ciphertext and a 32-byte shared secret.
3. Hash the shared secret together with the ciphertext and the public
   key: `wk = BLAKE2b-256("noxcrypt/v1/mlkem768-wrap" || ct || pk || ss)`.
4. Wrap the file key with XChaCha20-Poly1305 under `wk`.

The payload is then encrypted with XChaCha20-Poly1305 in streaming
mode under the file key. So ML-KEM is always paired with
XChaCha20-Poly1305. The hybrid recipient adds an ephemeral X25519
Diffie-Hellman to the mix, and the two derived keys are combined with
a third BLAKE2b call before any file key is wrapped:

```
wk = BLAKE2b-256("noxcrypt/v1/hybrid-wrap" || xk || kk || fingerprint)
```

Both flavors of the derivation are described byte by byte in
[SPEC.md](SPEC.md), sections 6.1 to 6.3.

### Recipient selection is not a preference

When you encrypt to a key, the tool looks at what the key holds and
picks the matching recipient flavor. It does not fall back:

- both X25519 and ML-KEM-768 present -> combined recipient;
- X25519 only -> X25519 recipient;
- ML-KEM-768 only -> ML-KEM recipient.

The same rule applies when decrypting: an identity holding both keys
will not unwrap a message addressed to its X25519 key alone, and an
ECC identity will not unwrap a combined recipient, even in the
hypothetical case where the key material would allow it. This closes
the usual downgrade attack, where an attacker strips the strong half
of a message and hopes the victim's software accepts the remainder.

One message can carry recipients of different kinds, so sending the
same file to a hybrid, an ecc, and a pqc correspondent works in a
single pass, with one recipient packet per key.

## The keyring

The keyring lives in `$NOX_HOME/.nox`, or `$HOME/.nox` if `NOX_HOME`
is unset, or wherever `--home` points. The directory is created with
mode 0700 if needed, including missing parents. Each identity is two
files:

```
7f3c9d02...8b41.pub    public key,   mode 0600
7f3c9d02...8b41.sec    secret key,   mode 0600
```

Both are NoxCrypt documents. The `.sec` file is never plaintext: the
secret seeds are wrapped with Argon2id and XChaCha20-Poly1305 under
your passphrase, and the passphrase is asked for every time the
secret key is used.

`nox list` shows what is in there:

```
$ nox list alice
7f3c9d02...8b41  2026-09-10
  hybrid: Ed25519 + ML-DSA-44 + X25519 + ML-KEM-768
  "alice@example.com"
```

A key imported from a public key file has no `.sec` half, and says so:

```
  ecc: Ed25519 + X25519 (no secret key)
```

Backing up the keyring means backing up `~/.nox`, or the `.sec` files
you care about. The `.sec` files are safe to copy to a backup that is
less than perfectly secure, as long as the passphrase is not in the
same place. That is the whole point of the wrapping.

Moving a key to another machine is `export -s` on one side and
`import` on the other. Secret keys are exported in exactly the format
they have on disk, still locked, so the transport does not need to be
trusted for confidentiality (though it should still be your own
channel, not a paste into a group chat).

## Passphrases

Every secret key is protected by a passphrase, and there is no way to
store one without it. The passphrase is read from `/dev/tty` with echo
disabled, twice for `gen`, once for everything else; terminal settings
are restored on error and on the usual signals, so a control-C does
not leave a terminal with echo off.

Scripts use `--passphrase-file`, which reads the first line of a file.
That option is a convenience for automation and tests; be aware that
the passphrase is then sitting in a file, which may be exactly the
thing you were trying to avoid.

The key derivation is Argon2id with t=3, m=65536 KiB, and p=1. That is
a desktop parameter set: about 64 MiB of memory and a fraction of a
second per attempt. It makes bulk guessing expensive and does nothing
at all about a passphrase like `hunter2`. Four or five random words
beat a short complicated string.

## Messages

Encryption to a key:

```
nox encrypt -r 7f3c9d02 -a -o note.nox.asc note.txt
nox decrypt -i 7f3c9d02 -o note.txt note.nox.asc
```

Encryption to several keys, including keys that are not in your
keyring, by passing their public key files:

```
nox encrypt -r 7f3c9d02 -R bob.pub -R carol.pub -o note.nox note.txt
```

Passphrase-only encryption, when there is no recipient key at all:

```
nox encrypt -p -a -o secret.nox.asc secret.txt
nox decrypt -p -o secret.txt secret.nox.asc
```

A passphrase recipient is always the only recipient. Mixing one with
public keys is refused, because it would be too easy to end up with a
message whose real protection is the weak passphrase rather than the
strong key.

Without `-o`, output goes to stdout, which makes pipes work:

```
tar cf - ~/notes | nox encrypt -r 7f3c9d02 -a | ssh host 'cat > notes.nox'
```

Plaintext is processed in 64 KiB chunks. Each chunk is authenticated
with its index and a "last chunk" flag in the additional data, so
reordering and splicing are detected. Truncating the file is not
detectable on its own -- there is no length field to compare against --
but the final chunk is flagged, and a ciphertext that just stops is
rejected rather than accepted as a shorter message.

`decrypt` writes plaintext as it authenticates. If chunk 12 of 20
fails, chunks 1 to 11 are already out of the door. Redirect to a
temporary file and rename it on success if a partial plaintext is
worse than the failure itself.

Binary output to a terminal is refused unless `--armor` is given.
Armor is PEM-like: `-----BEGIN NOX MESSAGE-----`, base64 in 64-column
lines, `-----END NOX MESSAGE-----`. The kinds are `PUBLIC KEY`,
`SECRET KEY`, `MESSAGE`, and `SIGNATURE`. Reading armor is lenient
about whitespace and headers; writing it is strict, so armored files
are byte-for-byte reproducible.

## Signatures

```
nox sign -i 7f3c9d02 -o note.sig note.txt
nox verify -k alice.pub note.sig note.txt
```

A detached signature contains the creation time, the signer's
fingerprint, and one signature packet per signing key of the signer's
identity. The message itself is not needed to produce it beyond its
BLAKE2b-256 hash, so signing a 100 GB file does not use 100 GB of
memory, and signing from a pipe works:

```
nox sign -i 7f3c9d02 < archive.tar > archive.sig
```

Verification checks every signing key the public identity lists, and
fails if the signature carries a different set. For a hybrid identity
that means both Ed25519 and ML-DSA-44 must verify; a signature that
drops the post-quantum half is rejected. On success the tool prints
one line and nothing else:

```
Good signature
```

Nothing is printed on failure, and the exit status is non-zero.

## Import and export

`nox export` writes a key from the keyring to a file or stdout.
`nox import` reads a public or secret key file and stores it.
Both accept armored and raw input. An exported public key is the
identity as it was created, self-signature included, so two machines
that import the same key agree on its fingerprint and on its comment.

```
nox export -a -o alice.pub 7f3c9d02
nox import alice.pub
nox export -s -a -o alice.sec 7f3c9d02
nox import --passphrase-file ~/.nox-pass alice.sec
```

Importing a secret key unlocks it first, which means a wrong
passphrase fails before anything is written to the keyring. Importing
a key that already exists overwrites it, atomically.

## Testing and reproducible output

`--faketime` replaces the clock for anything that reads the time, so
timestamps in generated keys, signatures, and listings are what you
say they are:

```
nox --home /tmp/demo --faketime 1700000000 gen -c 'fixture'
```

The key material still comes from `getrandom(2)`, of course. The
option exists for the test suite and for making documentation
examples stable.

`make test` runs the unit tests and `tests/test.sh`, which builds a
few keyrings in `tests/tmp`, exercises every profile, checks that keys
of one profile refuse messages of another, and verifies that a
tampered message fails to verify. It takes a handful of seconds,
mostly Argon2id.

## What NoxCrypt does not protect against

Worth reading before trusting it with anything that matters.

- **A compromised machine.** Secret keys live on disk, unlocked with a
  passphrase typed into the same machine. Malware with your
  privileges gets everything.
- **No forward secrecy.** The file key is wrapped to long-term keys.
  Whoever holds the identity's secret key later, and kept the
  ciphertext, can read it then.
- **Metadata.** A message reveals how many recipients it has, which
  algorithms they use, and the approximate length of the plaintext
  rounded up to 64 KiB chunks. Detached signatures reveal the signer
  fingerprint and a timestamp.
- **Weak passphrases.** Argon2id raises the price of a guess; it does
  not fix a bad passphrase.
- **Clock games.** Timestamps come from the local clock. They are
  signed once they are in a document, but nothing checks that they are
  plausible.
- **A quantum computer, if you chose `ecc`.** That profile exists for
  people who decided the trade-off is acceptable. It is not the
  default for a reason.

And the honest summary: this is a small, readable implementation that
has not been audited. It is a good place to read about hybrid
encryption, and it is not a replacement for a widely deployed tool
with a bug bounty.

## Troubleshooting

- `no public key matches 'xyz'` - the prefix is not in the keyring.
  `nox list` shows the full fingerprints. Only `nox list` matches a
  comment substring; the commands that select a key want hex.

- `fingerprint prefix 'abc' is ambiguous` - two keys in the keyring
  share the prefix. Use more characters.

- `'alice' is not a fingerprint prefix (hex only)` - a comment cannot
  be used where a key is expected. Run `nox list alice` to see which
  fingerprint belongs to that comment, then use that.

- `fingerprint prefix must be at least 8 hex characters` - the query
  was hex and too short.

- `no matching recipient or wrong passphrase` - the message was not
  encrypted to this key, or the passphrase is not the one that locks
  it, or the message is truncated. Also the error you get when the
  recipient flavor does not match the identity: a hybrid key cannot
  read an `ecc` message, even with the right passphrase.

- `wrong passphrase or corrupted secret key` - the wrapping AEAD did
  not authenticate. Almost always the passphrase.

- `corrupted ciphertext` - a chunk failed to authenticate. The file
  changed in transit, or it is not the file you think it is.

- `multiple secret keys; specify -i FINGERPRINT` - the keyring holds
  more than one secret key and the command could not guess which one
  you meant.

- `refusing to write binary to the terminal (use --armor)` - redirect
  to a file, or add `--armor`. Binary NoxCrypt documents do not
  survive a terminal, and the tool would rather not produce one.

- `identity self-signature is invalid` - the public key file was
  edited. It is not a usable key; import it again from a trustworthy
  copy.

## Where the source keeps things

| File              | What it does                                  |
|-------------------|-----------------------------------------------|
| `src/nox.c`       | command line parsing and output               |
| `src/identity.c`  | key generation, parsing, fingerprints         |
| `src/secret.c`    | passphrase wrapping of secret keys            |
| `src/cipher.c`    | recipient flavors and payload encryption      |
| `src/sign.c`      | detached signatures                           |
| `src/keyring.c`   | `~/.nox` and the `list` output                |
| `src/armor.c`     | PEM-style armor, streaming                    |
| `src/passphrase.c`| no-echo prompt                                |
| `src/packet.c`    | packet framing                                |
| `src/util.c`      | bytes, randomness, files, Argon2id, names     |

The library surface is `include/noxcrypt.h`; `noxcrypt_version()` and
`noxcrypt_error()` are the two functions it promises. Link the
`src/*.c` modules you need plus the two files in `vendor/libncrypt`.
