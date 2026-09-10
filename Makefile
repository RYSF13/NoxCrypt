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

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man/man1

.PHONY: all clean test install uninstall

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

install: nox
	install -d "$(DESTDIR)$(BINDIR)" "$(DESTDIR)$(MANDIR)"
	install -m 0755 nox "$(DESTDIR)$(BINDIR)/nox"
	install -m 0644 doc/nox.1 "$(DESTDIR)$(MANDIR)/nox.1"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/nox" "$(DESTDIR)$(MANDIR)/nox.1"
