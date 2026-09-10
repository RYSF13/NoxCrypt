#define _GNU_SOURCE

#include "keyring.h"
#include "armor.h"
#include "packet.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

int
nox_keyring_dir(char *buf, size_t n)
{
    const char *home = nox_home_dir(NULL);
    int k;

    if (home == NULL)
        return nox_seterr("HOME is not set");
    k = snprintf(buf, n, "%s/.nox", home);
    if (k < 0 || (size_t)k >= n)
        return nox_seterr("path too long");
    return 0;
}

int
nox_keyring_init(void)
{
    char dir[4096];

    if (nox_keyring_dir(dir, sizeof dir) < 0)
        return -1;
    return nox_ensure_dir(dir, 0700);
}

static int
key_path(char *buf, size_t n, const uint8_t fp[NOX_FP_LEN], const char *ext)
{
    char dir[4096], hex[65];
    int k;

    if (nox_keyring_dir(dir, sizeof dir) < 0)
        return -1;
    nox_hex(hex, fp, NOX_FP_LEN);
    k = snprintf(buf, n, "%s/%s.%s", dir, hex, ext);
    if (k < 0 || (size_t)k >= n)
        return nox_seterr("path too long");
    return 0;
}

int
nox_keyring_store_pub(const nox_ident *id)
{
    char path[4096];
    uint8_t *blob = NULL;
    size_t n = 0;
    int rc;

    if (nox_keyring_init() < 0)
        return -1;
    if (key_path(path, sizeof path, id->fp, "pub") < 0)
        return -1;
    if (nox_ident_public_blob(id, &blob, &n) < 0)
        return -1;
    rc = nox_replace_file(path, blob, n, 0600);
    free(blob);
    return rc;
}

int
nox_keyring_store_sec(const uint8_t fp[NOX_FP_LEN],
                      const uint8_t *blob, size_t n)
{
    char path[4096];

    if (nox_keyring_init() < 0)
        return -1;
    if (key_path(path, sizeof path, fp, "sec") < 0)
        return -1;
    return nox_replace_file(path, blob, n, 0600);
}

typedef struct {
    uint8_t fp[NOX_FP_LEN];
    char path[8192];
    int nmatch;
} kr_match;

static int
scan_ext(const char *query, const char *ext, kr_match *m)
{
    char dir[4096], want[65];
    DIR *dp;
    struct dirent *de;
    size_t elen, qlen;

    memset(m, 0, sizeof *m);
    if (nox_keyring_dir(dir, sizeof dir) < 0)
        return -1;
    elen = strlen(ext);
    qlen = query ? strlen(query) : 0;
    if (qlen > 0) {
        size_t i;
        if (qlen > 64)
            return nox_seterr("fingerprint query too long");
        for (i = 0; i < qlen; i++) {
            int c = (unsigned char)query[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                  (c >= 'A' && c <= 'F')))
                return nox_seterr("fingerprint query must be hex");
            want[i] = (char)((c >= 'A' && c <= 'F') ? c + 'a' - 'A' : c);
        }
        want[qlen] = 0;
        if (qlen < 8 && qlen != 0)
            return nox_seterr("fingerprint prefix must be at least 8 hex characters");
    }

    dp = opendir(dir);
    if (dp == NULL) {
        if (errno == ENOENT)
            return 0;
        return nox_seterr("open %s: %s", dir, strerror(errno));
    }
    while ((de = readdir(dp)) != NULL) {
        size_t n = strlen(de->d_name);
        char hex[65];
        uint8_t fp[NOX_FP_LEN];
        size_t fpn = NOX_FP_LEN;

        if (n != 64 + 1 + elen)
            continue;
        if (de->d_name[64] != '.' || strcmp(de->d_name + 65, ext) != 0)
            continue;
        memcpy(hex, de->d_name, 64);
        hex[64] = 0;
        if (nox_unhex(fp, &fpn, hex) < 0 || fpn != NOX_FP_LEN)
            continue;
        if (qlen > 0 && strncmp(hex, want, qlen) != 0)
            continue;
        m->nmatch++;
        if (m->nmatch == 1) {
            memcpy(m->fp, fp, NOX_FP_LEN);
            snprintf(m->path, sizeof m->path, "%s/%s", dir, de->d_name);
        }
    }
    closedir(dp);
    return 0;
}

int
nox_keyring_load_pub(const char *query, nox_ident *id)
{
    kr_match m;
    uint8_t *buf = NULL;
    size_t n = 0;
    int rc;

    if (scan_ext(query, "pub", &m) < 0)
        return -1;
    if (m.nmatch == 0)
        return nox_seterr("no public key matches '%s'", query ? query : "");
    if (m.nmatch > 1)
        return nox_seterr("fingerprint prefix '%s' is ambiguous", query);
    if (nox_read_file(m.path, &buf, &n, NOX_MAX_BLOB) < 0)
        return -1;
    rc = nox_ident_load_pub(id, buf, n);
    free(buf);
    return rc;
}

int
nox_keyring_load_sec_blob(const char *query, uint8_t **blob, size_t *n,
                          uint8_t fp[NOX_FP_LEN])
{
    kr_match m;

    if (scan_ext(query, "sec", &m) < 0)
        return -1;
    if (m.nmatch == 0)
        return nox_seterr("no secret key matches '%s'", query ? query : "");
    if (m.nmatch > 1)
        return nox_seterr("fingerprint prefix '%s' is ambiguous", query);
    memcpy(fp, m.fp, NOX_FP_LEN);
    return nox_read_file(m.path, blob, n, NOX_MAX_BLOB);
}

int
nox_keyring_delete(const char *query, uint8_t fp[NOX_FP_LEN])
{
    kr_match pub, sec;
    int did = 0;

    if (query == NULL || query[0] == 0)
        return nox_seterr("delete requires a fingerprint prefix");
    if (scan_ext(query, "pub", &pub) < 0)
        return -1;
    if (scan_ext(query, "sec", &sec) < 0)
        return -1;
    if (pub.nmatch > 1 || sec.nmatch > 1)
        return nox_seterr("fingerprint prefix '%s' is ambiguous", query);
    if (pub.nmatch == 0 && sec.nmatch == 0)
        return nox_seterr("no key matches '%s'", query);
    if (pub.nmatch && sec.nmatch && nox_memeq(pub.fp, sec.fp, NOX_FP_LEN) != 0)
        return nox_seterr("fingerprint prefix '%s' is ambiguous", query);
    if (fp != NULL)
        memcpy(fp, pub.nmatch ? pub.fp : sec.fp, NOX_FP_LEN);
    if (pub.nmatch) {
        if (unlink(pub.path) < 0)
            return nox_seterr("unlink %s: %s", pub.path, strerror(errno));
        did = 1;
    }
    if (sec.nmatch) {
        if (unlink(sec.path) < 0)
            return nox_seterr("unlink %s: %s", sec.path, strerror(errno));
        did = 1;
    }
    return did ? 0 : nox_seterr("no key matches '%s'", query);
}

int
nox_keyring_count_sec(void)
{
    kr_match m;

    if (scan_ext(NULL, "sec", &m) < 0)
        return -1;
    return m.nmatch;
}

struct kr_entry {
    char hex[65];
    uint64_t created;
    int has_sec;
    char suite[128];
    char comment[NOX_MAX_COMMENT + 1];
};

static int
entry_cmp(const void *a, const void *b)
{
    return strcmp(((const struct kr_entry *)a)->hex,
                  ((const struct kr_entry *)b)->hex);
}

static int
match_prefix(const char *hex, const char *query, size_t qlen)
{
    size_t i;

    if (qlen > 64)
        return 0;
    for (i = 0; i < qlen; i++) {
        int a = query[i], b = hex[i];
        if (a >= 'A' && a <= 'F')
            a += 'a' - 'A';
        if (a != b)
            return 0;
    }
    return 1;
}

static void
fmt_date(char *buf, size_t n, uint64_t ts)
{
    time_t t = (time_t)ts;
    struct tm tm;

    if (gmtime_r(&t, &tm) == NULL) {
        snprintf(buf, n, "0000-00-00");
        return;
    }
    snprintf(buf, n, "%04d-%02d-%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
}

int
nox_keyring_list(FILE *out, const char *query)
{
    char dir[4096];
    DIR *dp;
    struct dirent *de;
    struct kr_entry *ents = NULL;
    size_t nent = 0, cap = 0;
    size_t qlen = query ? strlen(query) : 0;
    size_t i;
    int rc = -1;

    if (nox_keyring_dir(dir, sizeof dir) < 0)
        return -1;
    dp = opendir(dir);
    if (dp == NULL) {
        if (errno == ENOENT)
            return 0;
        return nox_seterr("open %s: %s", dir, strerror(errno));
    }
    while ((de = readdir(dp)) != NULL) {
        size_t n = strlen(de->d_name);
        char path[8192], hex[65];
        char secpath[8192];
        struct stat st;
        uint8_t *buf = NULL;
        size_t bn = 0;
        nox_ident id;
        struct kr_entry *e;
        int match;

        if (n != 64 + 4)
            continue;
        if (strcmp(de->d_name + 64, ".pub") != 0)
            continue;
        memcpy(hex, de->d_name, 64);
        hex[64] = 0;
        match = qlen == 0 || match_prefix(hex, query, qlen);
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        if (nox_read_file(path, &buf, &bn, NOX_MAX_BLOB) < 0) {
            closedir(dp);
            free(ents);
            return -1;
        }
        nox_ident_init(&id);
        if (nox_ident_load_pub(&id, buf, bn) < 0) {
            free(buf);
            fprintf(stderr, "nox: skipping %s: %s\n", de->d_name, nox_err);
            continue;
        }
        free(buf);
        if (!match && qlen > 0) {
            if (strcasestr(id.comment, query) == NULL) {
                nox_ident_wipe(&id);
                continue;
            }
        }
        if (nent == cap) {
            struct kr_entry *p;
            size_t ncap = cap ? cap * 2 : 16;
            p = realloc(ents, ncap * sizeof *p);
            if (p == NULL) {
                nox_ident_wipe(&id);
                closedir(dp);
                free(ents);
                return nox_seterr("out of memory");
            }
            ents = p;
            cap = ncap;
        }
        e = &ents[nent++];
        memcpy(e->hex, hex, sizeof e->hex);
        e->created = id.created;
        snprintf(secpath, sizeof secpath, "%s/%.64s.sec", dir, hex);
        e->has_sec = stat(secpath, &st) == 0;
        nox_ident_suite(e->suite, sizeof e->suite, &id);
        memcpy(e->comment, id.comment, sizeof e->comment);
        nox_ident_wipe(&id);
    }
    closedir(dp);

    qsort(ents, nent, sizeof *ents, entry_cmp);
    for (i = 0; i < nent; i++) {
        char date[64], esc[NOX_MAX_COMMENT_ESC];

        fmt_date(date, sizeof date, ents[i].created);
        nox_escape_comment(esc, sizeof esc, ents[i].comment);
        if (i > 0 && fputc('\n', out) == EOF)
            goto out;
        if (fprintf(out, "%s %s %s\n%s\n\"%s\"\n", ents[i].hex, date,
                    ents[i].has_sec ? "sec" : "pub",
                    ents[i].suite, esc) < 0)
            goto out;
    }
    rc = 0;
out:
    free(ents);
    if (rc < 0)
        nox_seterr("write: %s", strerror(errno));
    return rc;
}
