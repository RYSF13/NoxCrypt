CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
CPPFLAGS += -Iinclude -Isrc -Ivendor/libncrypt
LDFLAGS ?=

SRC = \
	src/util.c \
	src/packet.c \
	src/armor.c \
	src/identity.c \
	src/secret.c \
	src/passphrase.c \
	src/cipher.c \
	src/sign.c \
	src/keyring.c \
	src/nox.c

VENDOR = \
	vendor/libncrypt/ncrypt.c \
	vendor/libncrypt/ncrypt-pqc.c

LIBSRC = \
	src/util.c \
	src/packet.c \
	src/armor.c \
	src/identity.c \
	src/secret.c \
	src/passphrase.c \
	src/cipher.c \
	src/sign.c \
	src/keyring.c

.PHONY: all clean test

all: nox

nox: $(SRC) $(VENDOR) include/noxcrypt.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(SRC) $(VENDOR) $(LDFLAGS)

tests/test_unit: tests/test_unit.c $(LIBSRC) $(VENDOR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ tests/test_unit.c $(LIBSRC) $(VENDOR) $(LDFLAGS)

test: nox tests/test_unit
	./tests/test_unit
	./tests/test.sh

clean:
	rm -f nox tests/test_unit
	rm -rf tests/tmp
