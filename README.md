# NoxCrypt

A small Linux command-line tool for hybrid (classical + post-quantum)
encryption and signatures. It is meant to be closer to
[age](https://age-encryption.org/) and
[minisign](https://jedisct1.github.io/minisign/) than to OpenSSL:
auditable C, no network protocol, stdin/stdout, one job per
subcommand.

This is SPEC-v1 (draft). See [SPEC.md](SPEC.md) for the binary
format. Do not treat it as audited production cryptography.

## Features

- Hybrid identities: Ed25519, ML-DSA-44, X25519, ML-KEM-768
- Encrypt / decrypt (hybrid wrap, or a passphrase)
- Detached sign / verify
- Passphrase-protected secret keys (Argon2id + XChaCha20-Poly1305)
- ASCII armor (PEM, 64-column wrap)
- Keyring under `~/.nox` (mode 0700, files 0600)
- Pipes

Post-quantum algorithms are compiled from the vendored
`ncrypt-pqc.c`. Building NoxCrypt does **not** require liboqs.

## Build

Linux, GCC or Clang, no extra libraries:

```
make
```

That produces `./nox`. `make test` runs the unit tests and a CLI
round-trip (Argon2id uses 64 MiB; the first `gen` takes a few
seconds).

```
make test
```

## Usage

```
nox gen -c 'alice@example.com'
nox list
nox encrypt -r 0123abcd -a -o secret.nox message.txt
nox decrypt -i 0123abcd -o message.txt secret.nox
nox sign -i 0123abcd -a -o message.sig message.txt
nox verify message.sig message.txt
nox export -a 0123abcd
nox import alice.pub
nox delete 0123abcd
```

Passphrase-only encryption (no identities):

```
nox encrypt -p -a -o secret.nox message.txt
nox decrypt -p -o message.txt secret.nox
```

Global options, anywhere before the operands:

```
nox --home /tmp/demo --faketime 1700000000 gen -c alice
```

`--faketime` replaces the system clock for `created` timestamps.
`--home` (or `NOX_HOME`) relocates the keyring to `$HOME/.nox`.

Every command accepts `--help`. `nox verify` prints only
`Good signature` when the signature is genuine.

Keys are selected by a hex fingerprint prefix of at least eight
characters. Secret keys always prompt for a passphrase (echo is
disabled on `/dev/tty`). Scripts can pass `--passphrase-file`.

Binary NoxCrypt documents are refused on a terminal unless `--armor`
is set.

## Library

The CLI is a thin `src/nox.c` over small modules:

| Module      | Role                                      |
|-------------|-------------------------------------------|
| `util`      | endianness, RNG, hex, files, Argon2id     |
| `packet`    | magic and typed length-prefixed packets   |
| `armor`     | RFC 4648 / PEM, streaming reader/writer   |
| `identity`  | generate and parse hybrid identities      |
| `secret`    | passphrase wrap for secret keys           |
| `passphrase`| no-echo prompt, restore terminal          |
| `cipher`    | hybrid and passphrase encryption          |
| `sign`      | detached signatures                       |
| `keyring`   | `~/.nox`                                  |

`include/noxcrypt.h` exports `noxcrypt_version()` and
`noxcrypt_error()`. Link the `src/*.c` you need plus
`vendor/libncrypt/ncrypt.c` and `ncrypt-pqc.c`.

## Cryptography

- XChaCha20-Poly1305 (Monocypher via libncrypt)
- X25519, Ed25519
- BLAKE2b
- Argon2id (t=3, m=65536 KiB, p=1)
- ML-KEM-768, ML-DSA-44

Encryption to an identity always uses a single hybrid recipient
(`0x0005`). The tool will not emit or accept a classic X25519-only
or ML-KEM-only wrap for those identities. A passphrase recipient, if
present, is the only recipient. Detached signatures always carry
both Ed25519 and ML-DSA-44; verify requires both.

Random bytes come from `getrandom(2)`.

## License

MIT. See [LICENSE](LICENSE).
