#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
NOX="$ROOT/nox"
TMP="$ROOT/tests/tmp"
PASS="$TMP/pass"
PASS2="$TMP/pass2"

rm -rf "$TMP"
mkdir -p "$TMP/home" "$TMP/home2"
echo 'correct horse battery staple' > "$PASS"
echo 'other passphrase' > "$PASS2"

NOX_HOME="$TMP/home"
export NOX_HOME
# --home also works; keep env for child paths we print ourselves

die() { echo "FAIL: $*" >&2; exit 1; }

FP=$("$NOX" --home "$TMP/home" --faketime 1700000000 gen -c 'alice@example.com' --passphrase-file "$PASS")
[ ${#FP} -eq 64 ] || die "fingerprint length"

"$NOX" --home "$TMP/home" list | grep -q "$FP" || die "list missing fp"
"$NOX" --home "$TMP/home" list | grep -q 'alice@example.com' || die "list missing comment"
"$NOX" --home "$TMP/home" list alice | grep -q "$FP" || die "list query comment"
"$NOX" --home "$TMP/home" list "${FP%????????????????????????????????????????????????????????}" >/dev/null 2>&1 || true
PRE=$(printf '%s' "$FP" | cut -c1-8)
"$NOX" --home "$TMP/home" list "$PRE" | grep -q "$FP" || die "list query prefix"

echo 'hello noxcrypt' > "$TMP/msg"
dd if=/dev/zero bs=70000 count=1 2>/dev/null | tr '\0' 'x' > "$TMP/big"

"$NOX" --home "$TMP/home" encrypt -r "$PRE" -o "$TMP/msg.nox" "$TMP/msg"
"$NOX" --home "$TMP/home" decrypt -i "$PRE" --passphrase-file "$PASS" -o "$TMP/msg.out" "$TMP/msg.nox"
cmp "$TMP/msg" "$TMP/msg.out" || die "encrypt/decrypt mismatch"

"$NOX" --home "$TMP/home" encrypt -r "$FP" -a -o "$TMP/msg.asc" "$TMP/msg"
grep -q 'BEGIN NOX MESSAGE' "$TMP/msg.asc" || die "armor header"
"$NOX" --home "$TMP/home" decrypt -i "$FP" --passphrase-file "$PASS" -o "$TMP/msg.out2" "$TMP/msg.asc"
cmp "$TMP/msg" "$TMP/msg.out2" || die "armored encrypt/decrypt mismatch"

"$NOX" --home "$TMP/home" encrypt -r "$PRE" -o "$TMP/big.nox" "$TMP/big"
"$NOX" --home "$TMP/home" decrypt -i "$PRE" --passphrase-file "$PASS" -o "$TMP/big.out" "$TMP/big.nox"
cmp "$TMP/big" "$TMP/big.out" || die "chunked encrypt/decrypt mismatch"

: > "$TMP/empty"
"$NOX" --home "$TMP/home" encrypt -r "$PRE" -o "$TMP/empty.nox" "$TMP/empty"
"$NOX" --home "$TMP/home" decrypt -i "$PRE" --passphrase-file "$PASS" -o "$TMP/empty.out" "$TMP/empty.nox"
cmp "$TMP/empty" "$TMP/empty.out" || die "empty file mismatch"

"$NOX" --home "$TMP/home" encrypt -p --passphrase-file "$PASS2" -a -o "$TMP/pw.asc" "$TMP/msg"
"$NOX" --home "$TMP/home" decrypt -p --passphrase-file "$PASS2" -o "$TMP/pw.out" "$TMP/pw.asc"
cmp "$TMP/msg" "$TMP/pw.out" || die "passphrase encrypt/decrypt mismatch"

if "$NOX" --home "$TMP/home" decrypt -p --passphrase-file "$PASS" -o "$TMP/pw.bad" "$TMP/pw.asc" 2>"$TMP/err"; then
    die "wrong passphrase succeeded"
fi
grep -q . "$TMP/err" || die "wrong passphrase produced no error"

"$NOX" --home "$TMP/home" sign -i "$PRE" --passphrase-file "$PASS" -a -o "$TMP/msg.sig" "$TMP/msg"
grep -q 'BEGIN NOX SIGNATURE' "$TMP/msg.sig" || die "sig armor"
GOOD=$("$NOX" --home "$TMP/home" verify "$TMP/msg.sig" "$TMP/msg")
[ "$GOOD" = "Good signature" ] || die "verify output was '$GOOD'"

echo 'tampered' > "$TMP/msg.bad"
if "$NOX" --home "$TMP/home" verify "$TMP/msg.sig" "$TMP/msg.bad" >/dev/null 2>&1; then
    die "tampered message verified"
fi

"$NOX" --home "$TMP/home" export -a -o "$TMP/alice.pub" "$PRE"
"$NOX" --home "$TMP/home" export -s -a -o "$TMP/alice.sec" "$PRE"
grep -q 'BEGIN NOX PUBLIC KEY' "$TMP/alice.pub" || die "export pub armor"
grep -q 'BEGIN NOX SECRET KEY' "$TMP/alice.sec" || die "export sec armor"

"$NOX" --home "$TMP/home2" import "$TMP/alice.pub"
"$NOX" --home "$TMP/home2" list | grep -q "$FP" || die "import pub"
"$NOX" --home "$TMP/home2" import --passphrase-file "$PASS" "$TMP/alice.sec" >/dev/null
"$NOX" --home "$TMP/home2" encrypt -r "$PRE" -o "$TMP/h2.nox" "$TMP/msg"
"$NOX" --home "$TMP/home2" decrypt -i "$PRE" --passphrase-file "$PASS" -o "$TMP/h2.out" "$TMP/h2.nox"
cmp "$TMP/msg" "$TMP/h2.out" || die "imported secret cannot decrypt"

# pipes
printf 'piped' | "$NOX" --home "$TMP/home" encrypt -r "$PRE" -a | \
    "$NOX" --home "$TMP/home" decrypt -i "$PRE" --passphrase-file "$PASS" > "$TMP/pipe.out"
[ "$(cat "$TMP/pipe.out")" = "piped" ] || die "pipe round-trip"

# public round-trip via re-export
"$NOX" --home "$TMP/home2" export -o "$TMP/alice2.pub" "$FP"
"$NOX" --home "$TMP/home" export -o "$TMP/alice1.pub" "$FP"
cmp "$TMP/alice1.pub" "$TMP/alice2.pub" || die "public export not stable"

"$NOX" --home "$TMP/home2" delete "$PRE"
if "$NOX" --home "$TMP/home2" list | grep -q "$FP"; then
    die "delete left the key"
fi

# key suites: classic, pqc, mixed
FP_C=$("$NOX" --home "$TMP/home" --faketime 1700000000 gen --sign ed25519 --enc x25519 -c 'classic@example.com' --passphrase-file "$PASS")
FP_Q=$("$NOX" --home "$TMP/home" --faketime 1700000000 gen --sign mldsa44 --enc mlkem768 -c 'pq@example.com' --passphrase-file "$PASS")
COMMENT="mix \"q\" $(printf '\t')end"
FP_M=$("$NOX" --home "$TMP/home" --faketime 1700000000 gen --sign ed25519 --enc mlkem768 -c "$COMMENT" --passphrase-file "$PASS")
[ ${#FP_C} -eq 64 ] || die "classic fp length"
[ ${#FP_Q} -eq 64 ] || die "pqc fp length"
[ ${#FP_M} -eq 64 ] || die "mixed fp length"

for F in "$FP_C" "$FP_Q" "$FP_M"; do
    P=$(printf '%s' "$F" | cut -c1-8)
    "$NOX" --home "$TMP/home" encrypt -r "$P" -o "$TMP/s.nox" "$TMP/msg"
    "$NOX" --home "$TMP/home" decrypt -i "$P" --passphrase-file "$PASS" -o "$TMP/s.out" "$TMP/s.nox"
    cmp "$TMP/msg" "$TMP/s.out" || die "suite $P round-trip"
    "$NOX" --home "$TMP/home" sign -i "$P" --passphrase-file "$PASS" -o "$TMP/s.sig" "$TMP/msg"
    GOOD=$("$NOX" --home "$TMP/home" verify "$TMP/s.sig" "$TMP/msg")
    [ "$GOOD" = "Good signature" ] || die "suite $P verify"
done

# cross-suite decrypt must fail
PRE_C=$(printf '%s' "$FP_C" | cut -c1-8)
PRE_Q=$(printf '%s' "$FP_Q" | cut -c1-8)
"$NOX" --home "$TMP/home" encrypt -r "$PRE_C" -o "$TMP/x.nox" "$TMP/msg"
if "$NOX" --home "$TMP/home" decrypt -i "$PRE_Q" --passphrase-file "$PASS" -o "$TMP/x.out" "$TMP/x.nox" 2>/dev/null; then
    die "cross-suite decrypt succeeded"
fi

# verify against the wrong key must fail
"$NOX" --home "$TMP/home" export -o "$TMP/q.pub" "$PRE_Q"
"$NOX" --home "$TMP/home" sign -i "$PRE_C" --passphrase-file "$PASS" -o "$TMP/c.sig" "$TMP/msg"
if "$NOX" --home "$TMP/home" verify -k "$TMP/q.pub" "$TMP/c.sig" "$TMP/msg" >/dev/null 2>&1; then
    die "wrong-key verify succeeded"
fi

# list shows one three-line block per key
"$NOX" --home "$TMP/home" list | grep -q "$FP_C 2023-11-14 sec" || die "list classic line"
"$NOX" --home "$TMP/home" list | grep -q '^sign: ed25519; enc: x25519$' || die "list classic suite"
"$NOX" --home "$TMP/home" list | grep -q '^sign: mldsa44; enc: mlkem768$' || die "list pqc suite"
"$NOX" --home "$TMP/home" list | grep -q '^sign: ed25519; enc: mlkem768$' || die "list mixed suite"
"$NOX" --home "$TMP/home" list | grep -q '^sign: ed25519 mldsa44; enc: x25519 mlkem768$' || die "list hybrid suite"
"$NOX" --home "$TMP/home" list | grep -q 'mix \\"q\\" \\x09end' || die "list escapes comment"

# single-suite keys survive export/import
"$NOX" --home "$TMP/home" export -o "$TMP/c.pub" "$PRE_C"
"$NOX" --home "$TMP/home2" import "$TMP/c.pub" | grep -q "$FP_C" || die "import classic"
"$NOX" --home "$TMP/home2" list | grep -q "$FP_C 2023-11-14 pub" || die "imported pub has no sec"

# info and help
"$NOX" info | grep -q '^nox 1\.1\.0$' || die "info version"
"$NOX" info | grep -q '^author: ' || die "info author"
"$NOX" --home "$TMP/home" info | grep -q "keyring: $TMP/home/.nox" || die "info keyring"
"$NOX" help gen | grep -q 'Usage: nox gen' || die "help gen"
if "$NOX" help frobnicate >/dev/null 2>&1; then
    die "help for unknown command succeeded"
fi

# bad suite values are rejected
if "$NOX" --home "$TMP/home" gen --sign rsa --passphrase-file "$PASS" >/dev/null 2>&1; then
    die "bad --sign accepted"
fi
if "$NOX" --home "$TMP/home" gen --enc des --passphrase-file "$PASS" >/dev/null 2>&1; then
    die "bad --enc accepted"
fi

echo "test.sh: ok"
