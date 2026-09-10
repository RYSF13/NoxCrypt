# NoxCrypt User Guide

This guide covers everyday use of `nox`: generating identities,
encrypting, signing, and managing the keyring. For the wire format,
see [SPEC.md](SPEC.md); for the command reference, see [nox.1](nox.1)
(`man ./doc/nox.1` after install, or `man nox`).

## 1. Build and install

Linux, GCC or Clang, no extra libraries. The post-quantum code is
vendored, so there is nothing else to fetch:

```
make
sudo make install        # PREFIX defaults to /usr/local
```

`make install` copies the `nox` binary and the manual page. `make
test` runs the unit tests plus a CLI round-trip suite; run it once
after building to make sure your toolchain produces a working
binary.

`nox --version` prints the release (currently 1.1.0). `nox info`
prints the version, author, spec revision, keyring path, and the
compiled-in algorithms.

## 2. Your first identity

```
nox gen -c 'alice@example.com'
```

You will be asked for a passphrase twice (echo is off). The command
prints the new identity's fingerprint, a 64-character hex string,
and stores two files under `~/.nox`:

```
~/.nox/<fingerprint>.pub     public identity, safe to share
~/.nox/<fingerprint>.sec     secret identity, passphrase-protected
```

The comment (`-c`) is only a label; it can be anything, it is stored
with the key, and it is shown by `nox list`. It does not have to be
an email address and it is not verified in any way.

By default `gen` creates the hybrid suite: Ed25519 and ML-DSA-44
signing keys plus X25519 and ML-KEM-768 encryption keys. Key
selection is described in the next section; when in doubt, keep the
default.

## 3. Key suites

`gen` picks signing and encryption keys independently:

```
--sign ed25519|mldsa44|hybrid    (default: hybrid)
--enc  x25519|mlkem768|hybrid    (default: hybrid)
```

`hybrid` means both algorithms of that kind. The useful combinations:

| Command                        | Suite   | Keys                            |
|--------------------------------|---------|---------------------------------|
| `gen` (defaults)               | hybrid  | Ed25519, ML-DSA-44, X25519, ML-KEM-768 |
| `gen --sign ed25519 --enc x25519` | classic | Ed25519, X25519              |
| `gen --sign mldsa44 --enc mlkem768` | pqc  | ML-DSA-44, ML-KEM-768           |
| `gen --sign ed25519 --enc mlkem768` | mixed | Ed25519, ML-KEM-768            |
| `gen --sign mldsa44 --enc x25519` | mixed | ML-DSA-44, X25519              |

Which one to pick:

- **hybrid (default).** Use this unless you have a concrete reason
  not to. Documents stay readable as long as *either* the classical
  or the post-quantum half holds up.
- **classic.** Smaller keys and signatures (tens of bytes instead of
  kilobytes). Reasonable for short-lived data or constrained
  environments. No quantum resistance.
- **pqc.** For policies that require post-quantum-only operation.
  Keys and signatures are large (public keys around 2.5 KB,
  signatures around 2.4 KB).
- **mixed.** Rarely needed, but supported: any one signing key with
  any one encryption key. One example is Ed25519 signatures (small,
  widely supported) combined with ML-KEM-768 encryption.

Every identity needs at least one signing key (it self-signs) and at
least one encryption key. The suite is fixed at generation time; a
different suite is a different identity with a different
fingerprint, so nobody can silently downgrade you to weaker
algorithms. `nox list` always shows each key's suite.

## 4. Encrypt and decrypt

Encrypt for someone's public key, then decrypt with your secret key:

```
nox encrypt -r 0123abcd -a -o secret.asc message.txt
nox decrypt -i 0123abcd -o message.txt secret.asc
```

- `-r` takes a fingerprint prefix (at least 8 hex characters) from
  your keyring. `-R file` reads a public key from a file instead,
  useful for keys you do not want to import.
- `-i` selects the secret key to decrypt with. If your keyring holds
  exactly one secret key, you may omit `-i`.
- `-a` / `--armor` produces PEM text instead of binary. Binary output
  to a terminal is refused, so use `-a` (or redirect) there.
- Omit the input path, or pass `-`, to read stdin; omit `-o` to
  write stdout. `decrypt` output is raw plaintext and is never
  subject to the binary-on-terminal rule.

Encryption always matches the recipient's suite: a hybrid identity
gets the combined X25519+ML-KEM-768 wrap, a classic identity the
X25519 wrap, and so on. You do not select this; the sender's `nox`
reads it from the recipient's public key. Decryption enforces the
same rule in reverse: a recipient block that names your fingerprint
with the wrong suite is refused as a downgrade attempt.

### Passphrase mode

Without any identities, `-p` encrypts to a passphrase:

```
nox encrypt -p -a -o secret.asc message.txt
nox decrypt -p -o message.txt secret.asc
```

A passphrase recipient is always the sole recipient; `-p` cannot be
combined with `-r`/`-R`. Key derivation is Argon2id with the same
parameters as secret-key wrapping (3 passes, 64 MiB).

### Multiple recipients

List `-r`/`-R` up to 16 times to encrypt one file for several
identities, possibly of different suites. Each recipient unwraps the
same file key with their own secret key:

```
nox encrypt -r aaaa1111 -r bbbb2222 -R carol.pub -o team.nox memo.txt
```

## 5. Sign and verify

```
nox sign -i 0123abcd -a -o message.sig message.txt
nox verify message.sig message.txt
```

- `sign` emits a detached signature: one packet per signing key of
  your identity (two for hybrid, one for single-suite).
- `verify` prints exactly `Good signature` on success and exits
  nonzero otherwise. It requires *every* signing key of the signer's
  public identity to check out.
- Without `-k`/`-i`, `verify` finds the signer's public key in your
  keyring using the fingerprint stored in the signature. Use `-k
  file` to verify against a public key file, or `-i prefix` to pick
  a keyring identity explicitly.

Signatures bind the signer's fingerprint and a timestamp along with
the message hash, so a signature cannot be transplanted onto another
key's message.

## 6. Managing the keyring

```
nox list                    # all keys, three lines each
nox list alice              # fingerprint prefix or comment substring
nox export -a -o alice.pub 0123abcd
nox export -s -a -o alice.sec 0123abcd   # secret stays encrypted
nox import alice.pub
nox import --passphrase-file pw.txt alice.sec
nox delete 0123abcd
nox info                    # version, algorithms, keyring path
```

`list` output looks like this (date is UTC, entries sorted by
fingerprint, blank line between entries):

```
d7ca2eca...c105 2023-11-14 sec
sign: ed25519 mldsa44; enc: x25519 mlkem768
"alice@example.com"
```

`sec` means you hold the secret key; `pub` means the public half
only (someone else's key, or a secret you removed). Imports are
verified before they are stored: the self-signatures must check,
and an imported secret must unlock with the passphrase you give and
match its public half, otherwise the import is rejected and nothing
is written.

The keyring defaults to `~/.nox` (directory mode 0700, files 0600).
Set `NOX_HOME` or pass `--home DIR` to relocate it; `--home` wins.
`--faketime UNIX` replaces the clock for `created` timestamps and
exists for tests, not for daily use.

## 7. Armor and pipes

Every command speaks stdin/stdout when paths are omitted, so `nox`
composes with pipes:

```
tar czf - notes/ | nox encrypt -r 0123abcd -a > notes.asc
nox decrypt -i 0123abcd notes.asc | tar xzf -
printf 'piped' | nox encrypt -r 0123abcd -a | nox decrypt -i 0123abcd
```

Armor is strict on output (PEM, 64-column base64, blank line after
the `BEGIN` line) and lenient on input (whitespace ignored, headers
skipped). `decrypt` and `verify` accept armored or binary input
interchangeably; `import` likewise.

## 8. How ML-KEM encryption works here

ML-KEM-768 cannot encrypt: it is a key encapsulation mechanism
(KEM). It produces a ciphertext and a 32-byte shared secret for the
holder of a public key, nothing more. Every NoxCrypt recipient type
therefore follows the same pattern:

1. Produce a shared secret: ML-KEM encapsulation, an ephemeral
   X25519 Diffie-Hellman, or both (hybrid).
2. Hash the secret with a transcript (ephemeral key, recipient
   public key, ciphertext, recipient fingerprint) using BLAKE2b to
   get a wrap key. Each mode has its own domain string, so wrap keys
   cannot cross between modes.
3. Lock the random 32-byte file key with XChaCha20-Poly1305 under
   the wrap key. The file key encrypts the payload in streaming
   chunks.

So "ML-KEM encryption" in NoxCrypt always means ML-KEM-768 plus
XChaCha20-Poly1305, and "X25519 encryption" means ephemeral X25519
plus XChaCha20-Poly1305. The X25519 half only appears in hybrid mode
(`0x0005`); single-suite ML-KEM recipients (`0x0003`) never touch
X25519. The exact derivations are in [SPEC.md](SPEC.md), section 6.

## 9. Security practices

- Prefer the hybrid suite. Single algorithms are for size, policy,
  or hardware reasons, not for taste.
- Pick a real passphrase. The KDF (Argon2id, 64 MiB, 3 passes)
  slows guessing; it does not save `password123`. `nox` refuses
  empty passphrases.
- `--passphrase-file` reads the first line of a file. Use it for
  scripts and tests, keep the file at mode 0600, and prefer it over
  environment variables or process arguments, which leak to other
  users via `/proc`.
- Decryption streams: each chunk is written as it authenticates. If
  you need all-or-nothing behavior (reject the whole output when any
  byte is bad), decrypt to a temporary file and move it into place
  only on success.
- Verify fingerprints out of band before first use. `nox` checks
  signatures and suite bindings; it cannot tell you that the key
  labeled "alice" belongs to Alice.
- This software is unaudited. Treat version 1.x as a robust draft,
  not as reviewed cryptography.

## 10. Troubleshooting

**`no matching recipient or wrong passphrase`.** Either the file was
not encrypted for the identity you offered (check `-i`, or the wrong
keyring via `--home`/`NOX_HOME`), or a `-p` passphrase is wrong.
Note that `nox` deliberately does not tell you which.

**`recipient suite does not match the identity (downgrade refused)`.**
A recipient block names your fingerprint but uses the wrong suite.
With untampered files this should not happen; if you see it on a
file you just received, treat the file as hostile.

**`refusing to write binary to the terminal`.** Add `-a` or redirect
with `-o file` / `> file`.

**`multiple secret keys; specify -i FINGERPRINT`.** Your keyring has
more than one secret key and you omitted `-i`. List the keyring and
pick one.

**`fingerprint prefix ... is ambiguous`.** Use more hex characters
(up to the full 64).

**`wrong passphrase or corrupted secret key`.** The passphrase is
wrong, or the `.sec` file is damaged. After three wrong attempts,
double-check you are unlocking the key you think you are (`nox list`
shows which identities have secrets).

**`no terminal for passphrase prompt`.** `nox` reads passphrases
from `/dev/tty`. In scripts and cron jobs, use `--passphrase-file`.
