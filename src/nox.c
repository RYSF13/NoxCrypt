#define _GNU_SOURCE

#include "armor.h"
#include "cipher.h"
#include "identity.h"
#include "keyring.h"
#include "packet.h"
#include "passphrase.h"
#include "secret.h"
#include "sign.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
die(void)
{
    fprintf(stderr, "nox: %s\n", nox_err);
    exit(1);
}

static void
usage(FILE *fp)
{
    fprintf(fp,
        "Usage: nox [--faketime UNIX] [--home DIR] COMMAND [OPTIONS]\n"
        "\n"
        "Commands:\n"
        "  gen       generate a hybrid identity\n"
        "  encrypt   encrypt a message\n"
        "  decrypt   decrypt a message\n"
        "  sign      create a detached signature\n"
        "  verify    verify a detached signature\n"
        "  list      list keys in the keyring\n"
        "  export    export a public or secret key\n"
        "  import    import a public or secret key\n"
        "  delete    delete a key from the keyring\n"
        "\n"
        "Run \"nox COMMAND --help\" for command options.\n");
}

static int
get_pass(char *buf, size_t n, int confirm, const char *passfile)
{
    if (passfile != NULL)
        return nox_read_passfile(buf, n, passfile);
    if (confirm)
        return nox_confirm_passphrase(buf, n);
    return nox_read_passphrase(buf, n, "Passphrase: ");
}

static int
refuse_binary(int armor, FILE *out)
{
    if (!armor && nox_isatty(out))
        return nox_seterr("refusing to write binary to the terminal (use --armor)");
    return 0;
}

static int
emit_blob(FILE *out, const uint8_t *buf, size_t n, int armor, const char *kind)
{
    if (refuse_binary(armor, out) < 0)
        return -1;
    if (armor) {
        char *s = NULL;
        size_t sn = 0;
        int rc;
        if (nox_armor(&s, &sn, buf, n, kind) < 0)
            return -1;
        rc = nox_write_all(out, s, sn);
        free(s);
        return rc;
    }
    return nox_write_all(out, buf, n);
}

static FILE *
open_in(const char *path, int *opened)
{
    *opened = 0;
    if (path == NULL || strcmp(path, "-") == 0)
        return stdin;
    {
        FILE *fp = fopen(path, "rb");
        if (fp == NULL) {
            nox_seterr("open %s: %s", path, strerror(errno));
            return NULL;
        }
        *opened = 1;
        return fp;
    }
}

static FILE *
open_out(const char *path, int *opened)
{
    *opened = 0;
    if (path == NULL || strcmp(path, "-") == 0)
        return stdout;
    {
        FILE *fp = fopen(path, "wb");
        if (fp == NULL) {
            nox_seterr("open %s: %s", path, strerror(errno));
            return NULL;
        }
        *opened = 1;
        return fp;
    }
}

static int
finish_out(FILE *fp, int opened)
{
    if (fflush(fp) != 0)
        return nox_seterr("write: %s", strerror(errno));
    if (opened && fclose(fp) != 0)
        return nox_seterr("close: %s", strerror(errno));
    return 0;
}

static int
unlock_query(nox_ident *id, const char *query, const char *passfile)
{
    uint8_t *blob = NULL, *raw = NULL;
    size_t n = 0, rn = 0;
    uint8_t fp[NOX_FP_LEN];
    char pass[NOX_PASS_MAX + 1];
    int rc;

    if (nox_keyring_load_sec_blob(query, &blob, &n, fp) < 0)
        return -1;
    if (nox_unwrap_blob(&raw, &rn, blob, n) < 0) {
        free(blob);
        return -1;
    }
    free(blob);
    if (get_pass(pass, sizeof pass, 0, passfile) < 0) {
        free(raw);
        return -1;
    }
    rc = nox_secret_unlock(id, raw, rn, pass, strlen(pass));
    nox_wipe(pass, sizeof pass);
    nox_wipe(raw, rn);
    free(raw);
    return rc;
}

static int
cmd_gen(int argc, char **argv)
{
    const char *comment = "";
    const char *pub_out = NULL, *sec_out = NULL, *passfile = NULL;
    int armor = 0;
    nox_ident id;
    char pass[NOX_PASS_MAX + 1];
    uint8_t *sec = NULL, *pub = NULL;
    size_t sec_n = 0, pub_n = 0;
    char hex[65];
    int c;

    static const struct option opts[] = {
        { "comment",         required_argument, 0, 'c' },
        { "pub",             required_argument, 0, 'P' },
        { "sec",             required_argument, 0, 'S' },
        { "armor",           no_argument,       0, 'a' },
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "c:aF:h", opts, NULL)) != -1) {
        switch (c) {
        case 'c': comment = optarg; break;
        case 'P': pub_out = optarg; break;
        case 'S': sec_out = optarg; break;
        case 'a': armor = 1; break;
        case 'F': passfile = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox gen [-c COMMENT] [--pub FILE] [--sec FILE] [-a]\n"
                "               [--passphrase-file FILE]\n");
            return 0;
        default:
            return 2;
        }
    }
    if (get_pass(pass, sizeof pass, 1, passfile) < 0)
        die();
    nox_ident_init(&id);
    if (nox_ident_generate(&id, comment, nox_now()) < 0) {
        nox_wipe(pass, sizeof pass);
        die();
    }
    if (nox_secret_lock(&sec, &sec_n, &id, pass, strlen(pass)) < 0) {
        nox_wipe(pass, sizeof pass);
        nox_ident_wipe(&id);
        die();
    }
    nox_wipe(pass, sizeof pass);
    if (nox_ident_public_blob(&id, &pub, &pub_n) < 0) {
        nox_ident_wipe(&id);
        nox_wipe(sec, sec_n);
        free(sec);
        die();
    }
    nox_hex(hex, id.fp, NOX_FP_LEN);

    if (nox_keyring_store_pub(&id) < 0 ||
        nox_keyring_store_sec(id.fp, sec, sec_n) < 0) {
        nox_ident_wipe(&id);
        nox_wipe(sec, sec_n);
        free(sec);
        free(pub);
        die();
    }
    fprintf(stderr, "nox: public  %s/.nox/%s.pub\n", nox_home_dir(NULL), hex);
    fprintf(stderr, "nox: secret  %s/.nox/%s.sec\n", nox_home_dir(NULL), hex);
    if (pub_out != NULL) {
        FILE *fp;
        int op;
        fp = open_out(pub_out, &op);
        if (fp == NULL)
            goto fail;
        if (emit_blob(fp, pub, pub_n, armor || nox_isatty(fp), NOX_KIND_PUB) < 0 ||
            finish_out(fp, op) < 0)
            goto fail;
    }
    if (sec_out != NULL) {
        FILE *fp;
        int op;
        fp = open_out(sec_out, &op);
        if (fp == NULL)
            goto fail;
        if (emit_blob(fp, sec, sec_n, armor || nox_isatty(fp), NOX_KIND_SEC) < 0 ||
            finish_out(fp, op) < 0)
            goto fail;
    }
    printf("%s\n", hex);
    nox_ident_wipe(&id);
    nox_wipe(sec, sec_n);
    free(sec);
    free(pub);
    return 0;
fail:
    nox_ident_wipe(&id);
    nox_wipe(sec, sec_n);
    free(sec);
    free(pub);
    die();
    return 1;
}

static int
cmd_encrypt(int argc, char **argv)
{
    const char *out_path = NULL, *passfile = NULL, *in_path = NULL;
    char *recip_q[NOX_MAX_RECIPIENTS];
    char *recip_f[NOX_MAX_RECIPIENTS];
    int nq = 0, nf = 0, armor = 0, want_pass = 0;
    nox_ident recips[NOX_MAX_RECIPIENTS];
    nox_ident *rp[NOX_MAX_RECIPIENTS];
    int nrec = 0, c, i;
    char pass[NOX_PASS_MAX + 1];
    FILE *in, *out;
    int in_open = 0, out_open = 0;

    static const struct option opts[] = {
        { "recipient",       required_argument, 0, 'r' },
        { "recipient-file",  required_argument, 0, 'R' },
        { "passphrase",      no_argument,       0, 'p' },
        { "armor",           no_argument,       0, 'a' },
        { "output",          required_argument, 0, 'o' },
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "r:R:pao:F:h", opts, NULL)) != -1) {
        switch (c) {
        case 'r':
            if (nq + nf >= NOX_MAX_RECIPIENTS) {
                nox_seterr("too many recipients");
                die();
            }
            recip_q[nq++] = optarg;
            break;
        case 'R':
            if (nq + nf >= NOX_MAX_RECIPIENTS) {
                nox_seterr("too many recipients");
                die();
            }
            recip_f[nf++] = optarg;
            break;
        case 'p': want_pass = 1; break;
        case 'a': armor = 1; break;
        case 'o': out_path = optarg; break;
        case 'F': passfile = optarg; want_pass = 1; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox encrypt [-r FP]... [-R FILE]... [-p] [-a] [-o FILE]\n"
                "                   [--passphrase-file FILE] [IN]\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind < argc)
        in_path = argv[optind];
    if (want_pass && (nq > 0 || nf > 0)) {
        nox_seterr("passphrase recipient must be the sole recipient");
        die();
    }
    if (!want_pass && nq == 0 && nf == 0) {
        nox_seterr("no recipients (use -r, -R, or -p)");
        die();
    }
    for (i = 0; i < nq; i++) {
        nox_ident_init(&recips[nrec]);
        if (nox_keyring_load_pub(recip_q[i], &recips[nrec]) < 0)
            die();
        rp[nrec] = &recips[nrec];
        nrec++;
    }
    for (i = 0; i < nf; i++) {
        uint8_t *buf = NULL;
        size_t n = 0;
        if (nox_read_file(recip_f[i], &buf, &n, NOX_MAX_BLOB) < 0)
            die();
        nox_ident_init(&recips[nrec]);
        if (nox_ident_load_pub(&recips[nrec], buf, n) < 0) {
            free(buf);
            die();
        }
        free(buf);
        rp[nrec] = &recips[nrec];
        nrec++;
    }
    if (want_pass) {
        if (get_pass(pass, sizeof pass, 1, passfile) < 0)
            die();
    }
    in = open_in(in_path, &in_open);
    if (in == NULL)
        die();
    out = open_out(out_path, &out_open);
    if (out == NULL)
        die();
    if (refuse_binary(armor, out) < 0)
        die();
    if (nox_encrypt(in, out, armor, want_pass ? NULL : rp, want_pass ? 0 : nrec,
                    want_pass ? pass : NULL,
                    want_pass ? strlen(pass) : 0) < 0) {
        if (want_pass)
            nox_wipe(pass, sizeof pass);
        die();
    }
    if (want_pass)
        nox_wipe(pass, sizeof pass);
    if (in_open)
        fclose(in);
    if (finish_out(out, out_open) < 0)
        die();
    for (i = 0; i < nrec; i++)
        nox_ident_wipe(&recips[i]);
    return 0;
}

static int
cmd_decrypt(int argc, char **argv)
{
    const char *out_path = NULL, *passfile = NULL, *in_path = NULL;
    const char *ident = NULL;
    int want_pass = 0, c;
    char pass[NOX_PASS_MAX + 1];
    nox_ident id, *ids[1];
    FILE *in, *out;
    int in_open = 0, out_open = 0;

    static const struct option opts[] = {
        { "identity",        required_argument, 0, 'i' },
        { "passphrase",      no_argument,       0, 'p' },
        { "output",          required_argument, 0, 'o' },
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "i:po:F:h", opts, NULL)) != -1) {
        switch (c) {
        case 'i': ident = optarg; break;
        case 'p': want_pass = 1; break;
        case 'o': out_path = optarg; break;
        case 'F': passfile = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox decrypt [-i FP] [-p] [-o FILE] [--passphrase-file FILE] [IN]\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind < argc)
        in_path = argv[optind];
    in = open_in(in_path, &in_open);
    if (in == NULL)
        die();
    out = open_out(out_path, &out_open);
    if (out == NULL)
        die();

    if (want_pass) {
        if (get_pass(pass, sizeof pass, 0, passfile) < 0)
            die();
        if (nox_decrypt(in, out, NULL, 0, pass, strlen(pass)) < 0) {
            nox_wipe(pass, sizeof pass);
            die();
        }
        nox_wipe(pass, sizeof pass);
    } else {
        const char *q = ident;
        if (q == NULL) {
            int nsec = nox_keyring_count_sec();
            if (nsec < 0)
                die();
            if (nsec == 0) {
                nox_seterr("no secret keys in the keyring (use -i or -p)");
                die();
            }
            if (nsec > 1) {
                nox_seterr("multiple secret keys; specify -i FINGERPRINT");
                die();
            }
        }
        nox_ident_init(&id);
        if (unlock_query(&id, q, passfile) < 0)
            die();
        ids[0] = &id;
        if (nox_decrypt(in, out, ids, 1, NULL, 0) < 0) {
            nox_ident_wipe(&id);
            die();
        }
        nox_ident_wipe(&id);
    }
    if (in_open)
        fclose(in);
    if (finish_out(out, out_open) < 0)
        die();
    return 0;
}

static int
cmd_sign(int argc, char **argv)
{
    const char *out_path = NULL, *passfile = NULL, *in_path = NULL, *ident = NULL;
    int armor = 0, c;
    nox_ident id;
    uint8_t hash[32], *sig = NULL;
    size_t sig_n = 0;
    FILE *in, *out;
    int in_open = 0, out_open = 0;

    static const struct option opts[] = {
        { "identity",        required_argument, 0, 'i' },
        { "armor",           no_argument,       0, 'a' },
        { "output",          required_argument, 0, 'o' },
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "i:ao:F:h", opts, NULL)) != -1) {
        switch (c) {
        case 'i': ident = optarg; break;
        case 'a': armor = 1; break;
        case 'o': out_path = optarg; break;
        case 'F': passfile = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox sign [-i FP] [-a] [-o FILE] [--passphrase-file FILE] [IN]\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind < argc)
        in_path = argv[optind];
    if (ident == NULL) {
        int nsec = nox_keyring_count_sec();
        if (nsec < 0)
            die();
        if (nsec == 0) {
            nox_seterr("no secret keys in the keyring (use -i)");
            die();
        }
        if (nsec > 1) {
            nox_seterr("multiple secret keys; specify -i FINGERPRINT");
            die();
        }
    }
    nox_ident_init(&id);
    if (unlock_query(&id, ident, passfile) < 0)
        die();
    in = open_in(in_path, &in_open);
    if (in == NULL) {
        nox_ident_wipe(&id);
        die();
    }
    if (nox_hash_file(in, hash) < 0) {
        nox_ident_wipe(&id);
        die();
    }
    if (in_open)
        fclose(in);
    if (nox_sign_detached(&sig, &sig_n, &id, hash) < 0) {
        nox_ident_wipe(&id);
        die();
    }
    nox_ident_wipe(&id);
    out = open_out(out_path, &out_open);
    if (out == NULL) {
        free(sig);
        die();
    }
    if (emit_blob(out, sig, sig_n, armor, NOX_KIND_SIG) < 0) {
        free(sig);
        die();
    }
    free(sig);
    if (finish_out(out, out_open) < 0)
        die();
    return 0;
}

static int
cmd_verify(int argc, char **argv)
{
    const char *pubfile = NULL, *ident = NULL, *sigpath = NULL, *msgpath = NULL;
    int c;
    uint8_t *sig = NULL, hash[32];
    size_t sig_n = 0;
    nox_ident id;
    FILE *msg;
    int msg_open = 0;

    static const struct option opts[] = {
        { "key",      required_argument, 0, 'k' },
        { "identity", required_argument, 0, 'i' },
        { "help",     no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "k:i:h", opts, NULL)) != -1) {
        switch (c) {
        case 'k': pubfile = optarg; break;
        case 'i': ident = optarg; break;
        case 'h':
            fprintf(stdout,
                "Usage: nox verify [-k PUBFILE | -i FP] SIG [MESSAGE]\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind >= argc) {
        nox_seterr("missing signature file");
        die();
    }
    sigpath = argv[optind++];
    if (optind < argc)
        msgpath = argv[optind];
    if (nox_read_file(sigpath, &sig, &sig_n, NOX_MAX_BLOB) < 0)
        die();

    nox_ident_init(&id);
    if (pubfile != NULL) {
        uint8_t *buf = NULL;
        size_t n = 0;
        if (nox_read_file(pubfile, &buf, &n, NOX_MAX_BLOB) < 0) {
            free(sig);
            die();
        }
        if (nox_ident_load_pub(&id, buf, n) < 0) {
            free(buf);
            free(sig);
            die();
        }
        free(buf);
    } else {
        uint8_t *raw = NULL;
        size_t rn = 0;
        nox_parser p;
        uint16_t type;
        int crit;
        const uint8_t *val;
        uint32_t vlen;
        char hex[65];
        const char *q = ident;

        if (nox_unwrap_blob(&raw, &rn, sig, sig_n) < 0) {
            free(sig);
            die();
        }
        nox_parser_init(&p, raw, rn);
        if (nox_skip_magic(&p) < 0 ||
            nox_pkt_next(&p, &type, &crit, &val, &vlen) < 0) {
            free(raw);
            free(sig);
            die();
        }
        if (type != NOX_PKT_DETSIG || vlen < 40) {
            free(raw);
            free(sig);
            nox_seterr("not a detached signature");
            die();
        }
        nox_hex(hex, val + 8, NOX_FP_LEN);
        free(raw);
        if (q == NULL)
            q = hex;
        if (nox_keyring_load_pub(q, &id) < 0) {
            free(sig);
            die();
        }
    }
    msg = open_in(msgpath, &msg_open);
    if (msg == NULL) {
        nox_ident_wipe(&id);
        free(sig);
        die();
    }
    if (nox_hash_file(msg, hash) < 0) {
        nox_ident_wipe(&id);
        free(sig);
        die();
    }
    if (msg_open)
        fclose(msg);
    if (nox_verify_detached(sig, sig_n, &id, hash) < 0) {
        nox_ident_wipe(&id);
        free(sig);
        die();
    }
    nox_ident_wipe(&id);
    free(sig);
    printf("Good signature\n");
    return 0;
}

static int
cmd_list(int argc, char **argv)
{
    const char *q = NULL;
    int c;

    optind = 1;
    while ((c = getopt_long(argc, argv, "h", NULL, NULL)) != -1) {
        if (c == 'h') {
            fprintf(stdout, "Usage: nox list [QUERY]\n");
            return 0;
        }
        return 2;
    }
    if (optind < argc)
        q = argv[optind];
    if (nox_keyring_list(stdout, q) < 0)
        die();
    return 0;
}

static int
cmd_export(int argc, char **argv)
{
    const char *out_path = NULL, *query = NULL;
    int armor = 0, secret = 0, c;
    FILE *out;
    int out_open = 0;

    static const struct option opts[] = {
        { "secret", no_argument,       0, 's' },
        { "armor",  no_argument,       0, 'a' },
        { "output", required_argument, 0, 'o' },
        { "help",   no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "sao:h", opts, NULL)) != -1) {
        switch (c) {
        case 's': secret = 1; break;
        case 'a': armor = 1; break;
        case 'o': out_path = optarg; break;
        case 'h':
            fprintf(stdout, "Usage: nox export [-s] [-a] [-o FILE] FINGERPRINT\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind >= argc) {
        nox_seterr("missing fingerprint");
        die();
    }
    query = argv[optind];
    out = open_out(out_path, &out_open);
    if (out == NULL)
        die();
    if (secret) {
        uint8_t *blob = NULL, fp[NOX_FP_LEN];
        size_t n = 0;
        if (nox_keyring_load_sec_blob(query, &blob, &n, fp) < 0)
            die();
        if (emit_blob(out, blob, n, armor, NOX_KIND_SEC) < 0) {
            nox_wipe(blob, n);
            free(blob);
            die();
        }
        nox_wipe(blob, n);
        free(blob);
    } else {
        nox_ident id;
        uint8_t *blob = NULL;
        size_t n = 0;
        nox_ident_init(&id);
        if (nox_keyring_load_pub(query, &id) < 0)
            die();
        if (nox_ident_public_blob(&id, &blob, &n) < 0) {
            nox_ident_wipe(&id);
            die();
        }
        if (emit_blob(out, blob, n, armor, NOX_KIND_PUB) < 0) {
            nox_ident_wipe(&id);
            free(blob);
            die();
        }
        nox_ident_wipe(&id);
        free(blob);
    }
    if (finish_out(out, out_open) < 0)
        die();
    return 0;
}

static int
cmd_import(int argc, char **argv)
{
    const char *path = NULL, *passfile = NULL;
    uint8_t *buf = NULL, *raw = NULL;
    size_t n = 0, rn = 0;
    uint16_t type;
    int c;
    char hex[65];

    static const struct option opts[] = {
        { "passphrase-file", required_argument, 0, 'F' },
        { "help",            no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    optind = 1;
    while ((c = getopt_long(argc, argv, "F:h", opts, NULL)) != -1) {
        switch (c) {
        case 'F': passfile = optarg; break;
        case 'h':
            fprintf(stdout, "Usage: nox import [--passphrase-file FILE] FILE\n");
            return 0;
        default:
            return 2;
        }
    }
    if (optind >= argc) {
        nox_seterr("missing file");
        die();
    }
    path = argv[optind];
    if (nox_read_file(path, &buf, &n, NOX_MAX_BLOB) < 0)
        die();
    if (nox_unwrap_blob(&raw, &rn, buf, n) < 0) {
        free(buf);
        die();
    }
    free(buf);
    if (nox_first_packet(raw, rn, &type) < 0) {
        free(raw);
        die();
    }
    if (type == NOX_PKT_IDENTITY) {
        nox_ident id;
        nox_ident_init(&id);
        if (nox_ident_parse(&id, raw, rn) < 0) {
            free(raw);
            die();
        }
        if (nox_keyring_store_pub(&id) < 0) {
            nox_ident_wipe(&id);
            free(raw);
            die();
        }
        nox_hex(hex, id.fp, NOX_FP_LEN);
        nox_ident_wipe(&id);
        printf("%s\n", hex);
        free(raw);
        return 0;
    }
    if (type == NOX_PKT_SECRET) {
        nox_ident id;
        char pass[NOX_PASS_MAX + 1];
        uint8_t *pub = NULL;
        size_t pn = 0;
        nox_ident_init(&id);
        if (get_pass(pass, sizeof pass, 0, passfile) < 0) {
            free(raw);
            die();
        }
        if (nox_secret_unlock(&id, raw, rn, pass, strlen(pass)) < 0) {
            nox_wipe(pass, sizeof pass);
            free(raw);
            die();
        }
        nox_wipe(pass, sizeof pass);
        if (nox_ident_public_blob(&id, &pub, &pn) < 0) {
            nox_ident_wipe(&id);
            free(raw);
            die();
        }
        if (nox_keyring_store_pub(&id) < 0 ||
            nox_keyring_store_sec(id.fp, raw, rn) < 0) {
            nox_ident_wipe(&id);
            free(pub);
            free(raw);
            die();
        }
        nox_hex(hex, id.fp, NOX_FP_LEN);
        nox_ident_wipe(&id);
        free(pub);
        free(raw);
        printf("%s\n", hex);
        return 0;
    }
    free(raw);
    nox_seterr("file is neither a public nor a secret key");
    die();
    return 1;
}

static int
cmd_delete(int argc, char **argv)
{
    int c;

    optind = 1;
    while ((c = getopt_long(argc, argv, "h", NULL, NULL)) != -1) {
        if (c == 'h') {
            fprintf(stdout, "Usage: nox delete FINGERPRINT\n");
            return 0;
        }
        return 2;
    }
    if (optind >= argc) {
        nox_seterr("missing fingerprint");
        die();
    }
    if (nox_keyring_delete(argv[optind]) < 0)
        die();
    return 0;
}

int
main(int argc, char **argv)
{
    char **av;
    int ac, i, n;
    const char *cmd;

    av = malloc((size_t)(argc + 1) * sizeof *av);
    if (av == NULL) {
        fprintf(stderr, "nox: out of memory\n");
        return 1;
    }
    av[0] = argv[0];
    n = 1;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--faketime") == 0) {
            char *e = NULL;
            long long ts;
            if (i + 1 >= argc) {
                fprintf(stderr, "nox: --faketime needs a unix timestamp\n");
                return 2;
            }
            ts = strtoll(argv[++i], &e, 10);
            if (e == argv[i] || *e != 0 || ts < 0) {
                fprintf(stderr, "nox: invalid timestamp\n");
                return 2;
            }
            nox_set_faketime((int64_t)ts);
            continue;
        }
        if (strcmp(argv[i], "--home") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "nox: --home needs a directory\n");
                return 2;
            }
            nox_set_home(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("%s\n", noxcrypt_version());
            return 0;
        }
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(stdout);
            return 0;
        }
        av[n++] = argv[i];
    }
    av[n] = NULL;
    ac = n;
    if (ac < 2) {
        usage(stderr);
        return 2;
    }
    cmd = av[1];
    {
        int rc;
        if (strcmp(cmd, "gen") == 0)
            rc = cmd_gen(ac - 1, av + 1);
        else if (strcmp(cmd, "encrypt") == 0)
            rc = cmd_encrypt(ac - 1, av + 1);
        else if (strcmp(cmd, "decrypt") == 0)
            rc = cmd_decrypt(ac - 1, av + 1);
        else if (strcmp(cmd, "sign") == 0)
            rc = cmd_sign(ac - 1, av + 1);
        else if (strcmp(cmd, "verify") == 0)
            rc = cmd_verify(ac - 1, av + 1);
        else if (strcmp(cmd, "list") == 0)
            rc = cmd_list(ac - 1, av + 1);
        else if (strcmp(cmd, "export") == 0)
            rc = cmd_export(ac - 1, av + 1);
        else if (strcmp(cmd, "import") == 0)
            rc = cmd_import(ac - 1, av + 1);
        else if (strcmp(cmd, "delete") == 0)
            rc = cmd_delete(ac - 1, av + 1);
        else if (strcmp(cmd, "help") == 0) {
            usage(stdout);
            rc = 0;
        } else {
            fprintf(stderr, "nox: unknown command '%s'\n", cmd);
            usage(stderr);
            rc = 2;
        }
        free(av);
        return rc;
    }
}
