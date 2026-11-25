/*
 * nimvault BearSSL thin C shim
 *
 * Isolates opaque BearSSL struct layouts, provides a capturing X.509 wrapper
 * (so peer leaf certificates are inspectable even when validation fails),
 * parses PEM trust bundles and server keys/chains, and exposes audited
 * ECDSA P-256 keygen/signing primitives to Nim.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bearssl.h"

#define NV_MAX_LEAF_DER 16384
#define NV_MAX_ALPN     16

/* -------------------------------------------------------------------------
 * Dynamic byte buffer helper
 * ------------------------------------------------------------------------- */

typedef struct {
    unsigned char *data;
    size_t len;
    size_t cap;
    int oom;
} nv_buf;

static void nv_buf_append(void *ctx, const void *src, size_t len) {
    nv_buf *b = (nv_buf *)ctx;
    if (b->oom || len == 0) return;
    if (b->len + len > b->cap) {
        size_t ncap = b->cap == 0 ? 1024 : b->cap * 2;
        while (ncap < b->len + len) {
            ncap *= 2;
        }
        unsigned char *ndata = (unsigned char *)realloc(b->data, ncap);
        if (ndata == NULL) {
            b->oom = 1;
            return;
        }
        b->data = ndata;
        b->cap = ncap;
    }
    memcpy(b->data + b->len, src, len);
    b->len += len;
}

static void nv_buf_free(nv_buf *b) {
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
    b->oom = 0;
}

/* -------------------------------------------------------------------------
 * Capturing / optionally-insecure X.509 wrapper around br_x509_minimal
 * ------------------------------------------------------------------------- */

typedef struct {
    const br_x509_class *vtable;
    br_x509_minimal_context inner;
    br_x509_decoder_context insecure_dec;
    int insecure_skip_verify;
    unsigned char leaf_der[NV_MAX_LEAF_DER];
    size_t leaf_der_len;
    int leaf_truncated;
    size_t chain_len;
    size_t cert_index;
    unsigned last_err;
} nv_x509_ctx;

static void nv_x509_start_chain(const br_x509_class **ctx, const char *server_name) {
    nv_x509_ctx *self = (nv_x509_ctx *)ctx;
    self->leaf_der_len = 0;
    self->leaf_truncated = 0;
    self->chain_len = 0;
    self->cert_index = 0;
    self->last_err = 0;
    if (!self->insecure_skip_verify) {
        self->inner.vtable->start_chain(&self->inner.vtable, server_name);
    }
}

static void nv_x509_start_cert(const br_x509_class **ctx, uint32_t length) {
    nv_x509_ctx *self = (nv_x509_ctx *)ctx;
    self->chain_len++;
    if (self->cert_index == 0) {
        self->leaf_der_len = 0;
        self->leaf_truncated = 0;
        if (self->insecure_skip_verify) {
            br_x509_decoder_init(&self->insecure_dec, NULL, NULL);
        }
    }
    if (!self->insecure_skip_verify) {
        self->inner.vtable->start_cert(&self->inner.vtable, length);
    }
}

static void nv_x509_append(const br_x509_class **ctx, const unsigned char *buf, size_t len) {
    nv_x509_ctx *self = (nv_x509_ctx *)ctx;
    if (self->cert_index == 0) {
        if (!self->leaf_truncated) {
            if (self->leaf_der_len + len <= NV_MAX_LEAF_DER) {
                memcpy(self->leaf_der + self->leaf_der_len, buf, len);
                self->leaf_der_len += len;
            } else {
                self->leaf_truncated = 1;
            }
        }
        if (self->insecure_skip_verify) {
            br_x509_decoder_push(&self->insecure_dec, buf, len);
        }
    }
    if (!self->insecure_skip_verify) {
        self->inner.vtable->append(&self->inner.vtable, buf, len);
    }
}

static void nv_x509_end_cert(const br_x509_class **ctx) {
    nv_x509_ctx *self = (nv_x509_ctx *)ctx;
    self->cert_index++;
    if (!self->insecure_skip_verify) {
        self->inner.vtable->end_cert(&self->inner.vtable);
    }
}

static unsigned nv_x509_end_chain(const br_x509_class **ctx) {
    nv_x509_ctx *self = (nv_x509_ctx *)ctx;
    if (self->insecure_skip_verify) {
        if (self->chain_len == 0) {
            self->last_err = BR_ERR_X509_EMPTY_CHAIN;
            return BR_ERR_X509_EMPTY_CHAIN;
        }
        int derr = br_x509_decoder_last_error(&self->insecure_dec);
        self->last_err = (unsigned)derr;
        return (unsigned)derr;
    }
    unsigned r = self->inner.vtable->end_chain(&self->inner.vtable);
    self->last_err = r;
    return r;
}

static const br_x509_pkey *nv_x509_get_pkey(const br_x509_class *const *ctx, unsigned *usages) {
    const nv_x509_ctx *self = (const nv_x509_ctx *)ctx;
    if (self->insecure_skip_verify) {
        if (usages != NULL) {
            *usages = BR_KEYTYPE_KEYX | BR_KEYTYPE_SIGN;
        }
        return br_x509_decoder_get_pkey((br_x509_decoder_context *)&self->insecure_dec);
    }
    return self->inner.vtable->get_pkey(&self->inner.vtable, usages);
}

static const br_x509_class nv_x509_vtable = {
    sizeof(nv_x509_ctx),
    nv_x509_start_chain,
    nv_x509_start_cert,
    nv_x509_append,
    nv_x509_end_cert,
    nv_x509_end_chain,
    nv_x509_get_pkey
};

/* -------------------------------------------------------------------------
 * Trust anchor PEM parser
 * ------------------------------------------------------------------------- */

typedef struct {
    br_x509_trust_anchor *items;
    size_t count;
    size_t cap;
} nv_ta_list;

static void nv_ta_free(nv_ta_list *list) {
    if (list == NULL) return;
    for (size_t i = 0; i < list->count; i++) {
        br_x509_trust_anchor *ta = &list->items[i];
        free(ta->dn.data);
        if (ta->pkey.key_type == BR_KEYTYPE_RSA) {
            free(ta->pkey.key.rsa.n);
            free(ta->pkey.key.rsa.e);
        } else if (ta->pkey.key_type == BR_KEYTYPE_EC) {
            free(ta->pkey.key.ec.q);
        }
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int nv_ta_add_der(nv_ta_list *list, const unsigned char *der, size_t der_len) {
    br_x509_decoder_context dc;
    nv_buf dn_buf = {0};

    br_x509_decoder_init(&dc, nv_buf_append, &dn_buf);
    br_x509_decoder_push(&dc, der, der_len);
    int derr = br_x509_decoder_last_error(&dc);
    if (derr != 0 || dn_buf.oom) {
        nv_buf_free(&dn_buf);
        return 0; /* Skip unparseable/unsupported certs (e.g. Ed25519 roots) */
    }
    br_x509_pkey *pk = br_x509_decoder_get_pkey(&dc);
    if (pk == NULL) {
        nv_buf_free(&dn_buf);
        return 0;
    }

    br_x509_trust_anchor ta;
    memset(&ta, 0, sizeof(ta));
    ta.dn.data = dn_buf.data;
    ta.dn.len = dn_buf.len;
    ta.flags = br_x509_decoder_isCA(&dc) ? BR_X509_TA_CA : 0;
    ta.pkey.key_type = pk->key_type;

    if (pk->key_type == BR_KEYTYPE_RSA) {
        ta.pkey.key.rsa.n = (unsigned char *)malloc(pk->key.rsa.nlen);
        ta.pkey.key.rsa.e = (unsigned char *)malloc(pk->key.rsa.elen);
        if (ta.pkey.key.rsa.n == NULL || ta.pkey.key.rsa.e == NULL) {
            free(ta.dn.data);
            free(ta.pkey.key.rsa.n);
            free(ta.pkey.key.rsa.e);
            return -1;
        }
        memcpy(ta.pkey.key.rsa.n, pk->key.rsa.n, pk->key.rsa.nlen);
        ta.pkey.key.rsa.nlen = pk->key.rsa.nlen;
        memcpy(ta.pkey.key.rsa.e, pk->key.rsa.e, pk->key.rsa.elen);
        ta.pkey.key.rsa.elen = pk->key.rsa.elen;
    } else if (pk->key_type == BR_KEYTYPE_EC) {
        ta.pkey.key.ec.curve = pk->key.ec.curve;
        ta.pkey.key.ec.q = (unsigned char *)malloc(pk->key.ec.qlen);
        if (ta.pkey.key.ec.q == NULL) {
            free(ta.dn.data);
            return -1;
        }
        memcpy(ta.pkey.key.ec.q, pk->key.ec.q, pk->key.ec.qlen);
        ta.pkey.key.ec.qlen = pk->key.ec.qlen;
    } else {
        free(ta.dn.data);
        return 0;
    }

    if (list->count == list->cap) {
        size_t ncap = list->cap == 0 ? 64 : list->cap * 2;
        br_x509_trust_anchor *nitems = (br_x509_trust_anchor *)realloc(
            list->items, ncap * sizeof(br_x509_trust_anchor));
        if (nitems == NULL) {
            free(ta.dn.data);
            if (ta.pkey.key_type == BR_KEYTYPE_RSA) {
                free(ta.pkey.key.rsa.n);
                free(ta.pkey.key.rsa.e);
            } else if (ta.pkey.key_type == BR_KEYTYPE_EC) {
                free(ta.pkey.key.ec.q);
            }
            return -1;
        }
        list->items = nitems;
        list->cap = ncap;
    }
    list->items[list->count++] = ta;
    return 1;
}

static int nv_parse_pem_trust_anchors(const char *pem, size_t pem_len, nv_ta_list *out) {
    br_pem_decoder_context pc;
    br_pem_decoder_init(&pc);
    nv_buf cert_buf = {0};
    int in_cert = 0;

    const unsigned char *p = (const unsigned char *)pem;
    size_t rem = pem_len;

    while (rem > 0) {
        size_t consumed = br_pem_decoder_push(&pc, p, rem);
        p += consumed;
        rem -= consumed;

        int ev = br_pem_decoder_event(&pc);
        if (ev == BR_PEM_BEGIN_OBJ) {
            const char *name = br_pem_decoder_name(&pc);
            if (strcmp(name, "CERTIFICATE") == 0 ||
                strcmp(name, "X509 CERTIFICATE") == 0 ||
                strcmp(name, "TRUSTED CERTIFICATE") == 0) {
                cert_buf.len = 0;
                cert_buf.oom = 0;
                in_cert = 1;
                br_pem_decoder_setdest(&pc, nv_buf_append, &cert_buf);
            } else {
                in_cert = 0;
                br_pem_decoder_setdest(&pc, NULL, NULL);
            }
        } else if (ev == BR_PEM_END_OBJ) {
            if (in_cert && !cert_buf.oom && cert_buf.len > 0) {
                if (nv_ta_add_der(out, cert_buf.data, cert_buf.len) < 0) {
                    nv_buf_free(&cert_buf);
                    return -1;
                }
            }
            in_cert = 0;
        } else if (ev == BR_PEM_ERROR) {
            in_cert = 0;
        }
    }
    /* Push a trailing newline in case PEM lacked final newline */
    unsigned char nl = '\n';
    br_pem_decoder_push(&pc, &nl, 1);
    int ev = br_pem_decoder_event(&pc);
    if (ev == BR_PEM_END_OBJ && in_cert && !cert_buf.oom && cert_buf.len > 0) {
        if (nv_ta_add_der(out, cert_buf.data, cert_buf.len) < 0) {
            nv_buf_free(&cert_buf);
            return -1;
        }
    }

    nv_buf_free(&cert_buf);
    return (int)out->count;
}

/* -------------------------------------------------------------------------
 * Engine handle (supports both Client and Server roles)
 * ------------------------------------------------------------------------- */

typedef struct {
    int is_server;
    union {
        br_ssl_client_context client;
        br_ssl_server_context server;
    } ctx;
    nv_x509_ctx x509;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];
    nv_ta_list tas;

    /* Owned ALPN strings */
    char *alpn_names[NV_MAX_ALPN];
    size_t alpn_count;

    /* Server-only owned cert chain & private key */
    br_x509_certificate *server_chain;
    size_t server_chain_len;
    br_skey_decoder_context server_skey;
} nv_engine;

static br_ssl_engine_context *nv_get_eng(nv_engine *e) {
    return e->is_server ? &e->ctx.server.eng : &e->ctx.client.eng;
}

static void nv_engine_set_alpn(nv_engine *e, const char **alpn, size_t alpn_count, int fail_on_mismatch) {
    if (alpn == NULL || alpn_count == 0) return;
    if (alpn_count > NV_MAX_ALPN) alpn_count = NV_MAX_ALPN;
    for (size_t i = 0; i < alpn_count; i++) {
        if (alpn[i] == NULL || alpn[i][0] == '\0') continue;
        size_t slen = strlen(alpn[i]);
        char *dup = (char *)malloc(slen + 1);
        if (dup == NULL) break;
        memcpy(dup, alpn[i], slen + 1);
        e->alpn_names[e->alpn_count++] = dup;
    }
    if (e->alpn_count > 0) {
        br_ssl_engine_set_protocol_names(
            nv_get_eng(e), (const char **)e->alpn_names, e->alpn_count);
        if (fail_on_mismatch) {
            br_ssl_engine_add_flags(nv_get_eng(e), BR_OPT_FAIL_ON_ALPN_MISMATCH);
        }
    }
}

void nv_engine_free(nv_engine *e) {
    if (e == NULL) return;
    nv_ta_free(&e->tas);
    for (size_t i = 0; i < e->alpn_count; i++) {
        free(e->alpn_names[i]);
    }
    if (e->server_chain != NULL) {
        for (size_t i = 0; i < e->server_chain_len; i++) {
            free(e->server_chain[i].data);
        }
        free(e->server_chain);
    }
    free(e);
}

nv_engine *nv_client_create(
    const char *server_name,
    const char *ca_pem,
    size_t ca_pem_len,
    int insecure_skip_verify,
    unsigned version_min,
    unsigned version_max,
    const char **alpn,
    size_t alpn_count,
    int fail_on_alpn_mismatch,
    uint64_t validation_time_unix,
    int *out_ta_count,
    int *out_err
) {
    if (out_err) *out_err = 0;
    if (out_ta_count) *out_ta_count = 0;

    nv_engine *e = (nv_engine *)calloc(1, sizeof(nv_engine));
    if (e == NULL) {
        if (out_err) *out_err = -1;
        return NULL;
    }
    e->is_server = 0;

    if (!insecure_skip_verify && ca_pem != NULL && ca_pem_len > 0) {
        int n = nv_parse_pem_trust_anchors(ca_pem, ca_pem_len, &e->tas);
        if (n < 0) {
            nv_engine_free(e);
            if (out_err) *out_err = -2;
            return NULL;
        }
        if (out_ta_count) *out_ta_count = n;
    }

    br_ssl_client_init_full(&e->ctx.client, &e->x509.inner, e->tas.items, e->tas.count);

    /* Configure optional explicit validation time */
    if (validation_time_unix > 0) {
        uint32_t days = (uint32_t)(validation_time_unix / 86400ULL) + 719528U;
        uint32_t secs = (uint32_t)(validation_time_unix % 86400ULL);
        br_x509_minimal_set_time(&e->x509.inner, days, secs);
    }

    /* Install our capturing X.509 wrapper vtable */
    e->x509.vtable = &nv_x509_vtable;
    e->x509.insecure_skip_verify = insecure_skip_verify ? 1 : 0;
    br_ssl_engine_set_x509(&e->ctx.client.eng, &e->x509.vtable);

    if (version_min != 0 && version_max != 0) {
        br_ssl_engine_set_versions(&e->ctx.client.eng, version_min, version_max);
    }

    nv_engine_set_alpn(e, alpn, alpn_count, fail_on_alpn_mismatch);

    br_ssl_engine_set_buffer(&e->ctx.client.eng, e->iobuf, sizeof(e->iobuf), 1);

    const char *sni = (server_name != NULL && server_name[0] != '\0') ? server_name : NULL;
    if (!br_ssl_client_reset(&e->ctx.client, sni, 0)) {
        int br_err = br_ssl_engine_last_error(&e->ctx.client.eng);
        nv_engine_free(e);
        if (out_err) *out_err = br_err != 0 ? br_err : BR_ERR_NO_RANDOM;
        return NULL;
    }
    return e;
}

static int nv_parse_pem_certs(const char *pem, size_t pem_len, br_x509_certificate **out_chain, size_t *out_len) {
    br_pem_decoder_context pc;
    br_pem_decoder_init(&pc);
    nv_buf buf = {0};
    int in_cert = 0;

    br_x509_certificate *chain = NULL;
    size_t count = 0, cap = 0;

    const unsigned char *p = (const unsigned char *)pem;
    size_t rem = pem_len;

    while (rem > 0) {
        size_t c = br_pem_decoder_push(&pc, p, rem);
        p += c;
        rem -= c;
        int ev = br_pem_decoder_event(&pc);
        if (ev == BR_PEM_BEGIN_OBJ) {
            const char *name = br_pem_decoder_name(&pc);
            if (strcmp(name, "CERTIFICATE") == 0 || strcmp(name, "X509 CERTIFICATE") == 0) {
                buf.len = 0;
                buf.oom = 0;
                in_cert = 1;
                br_pem_decoder_setdest(&pc, nv_buf_append, &buf);
            } else {
                in_cert = 0;
                br_pem_decoder_setdest(&pc, NULL, NULL);
            }
        } else if (ev == BR_PEM_END_OBJ) {
            if (in_cert && !buf.oom && buf.len > 0) {
                if (count == cap) {
                    size_t ncap = cap == 0 ? 4 : cap * 2;
                    br_x509_certificate *nc = (br_x509_certificate *)realloc(chain, ncap * sizeof(br_x509_certificate));
                    if (nc == NULL) {
                        for (size_t i = 0; i < count; i++) free(chain[i].data);
                        free(chain);
                        nv_buf_free(&buf);
                        return -1;
                    }
                    chain = nc;
                    cap = ncap;
                }
                unsigned char *copy = (unsigned char *)malloc(buf.len);
                if (copy == NULL) {
                    for (size_t i = 0; i < count; i++) free(chain[i].data);
                    free(chain);
                    nv_buf_free(&buf);
                    return -1;
                }
                memcpy(copy, buf.data, buf.len);
                chain[count].data = copy;
                chain[count].data_len = buf.len;
                count++;
            }
            in_cert = 0;
        } else if (ev == BR_PEM_ERROR) {
            in_cert = 0;
        }
    }
    nv_buf_free(&buf);
    *out_chain = chain;
    *out_len = count;
    return (int)count;
}

static int nv_decode_pem_skey(const char *pem, size_t pem_len, br_skey_decoder_context *dc) {
    br_pem_decoder_context pc;
    br_pem_decoder_init(&pc);
    nv_buf buf = {0};
    int in_key = 0;
    int got_key = 0;

    const unsigned char *p = (const unsigned char *)pem;
    size_t rem = pem_len;

    while (rem > 0) {
        size_t c = br_pem_decoder_push(&pc, p, rem);
        p += c;
        rem -= c;
        int ev = br_pem_decoder_event(&pc);
        if (ev == BR_PEM_BEGIN_OBJ) {
            const char *name = br_pem_decoder_name(&pc);
            if (strcmp(name, "PRIVATE KEY") == 0 ||
                strcmp(name, "EC PRIVATE KEY") == 0 ||
                strcmp(name, "RSA PRIVATE KEY") == 0) {
                buf.len = 0;
                buf.oom = 0;
                in_key = 1;
                br_pem_decoder_setdest(&pc, nv_buf_append, &buf);
            } else {
                in_key = 0;
                br_pem_decoder_setdest(&pc, NULL, NULL);
            }
        } else if (ev == BR_PEM_END_OBJ) {
            if (in_key && !buf.oom && buf.len > 0) {
                got_key = 1;
                break;
            }
            in_key = 0;
        }
    }
    if (!got_key) {
        nv_buf_free(&buf);
        return -1;
    }
    br_skey_decoder_init(dc);
    br_skey_decoder_push(dc, buf.data, buf.len);
    nv_buf_free(&buf);
    return br_skey_decoder_last_error(dc);
}

nv_engine *nv_server_create(
    const char *cert_pem,
    size_t cert_pem_len,
    const char *key_pem,
    size_t key_pem_len,
    unsigned version_min,
    unsigned version_max,
    const char **alpn,
    size_t alpn_count,
    int fail_on_alpn_mismatch,
    int *out_err
) {
    if (out_err) *out_err = 0;
    nv_engine *e = (nv_engine *)calloc(1, sizeof(nv_engine));
    if (e == NULL) {
        if (out_err) *out_err = -1;
        return NULL;
    }
    e->is_server = 1;

    int ncerts = nv_parse_pem_certs(cert_pem, cert_pem_len, &e->server_chain, &e->server_chain_len);
    if (ncerts <= 0) {
        nv_engine_free(e);
        if (out_err) *out_err = BR_ERR_X509_EMPTY_CHAIN;
        return NULL;
    }

    int kerr = nv_decode_pem_skey(key_pem, key_pem_len, &e->server_skey);
    if (kerr != 0) {
        nv_engine_free(e);
        if (out_err) *out_err = kerr;
        return NULL;
    }

    int ktype = br_skey_decoder_key_type(&e->server_skey);
    if (ktype == BR_KEYTYPE_EC) {
        const br_ec_private_key *ec_sk = br_skey_decoder_get_ec(&e->server_skey);
        br_ssl_server_init_full_ec(
            &e->ctx.server, e->server_chain, e->server_chain_len, BR_KEYTYPE_EC, ec_sk);
    } else if (ktype == BR_KEYTYPE_RSA) {
        const br_rsa_private_key *rsa_sk = br_skey_decoder_get_rsa(&e->server_skey);
        br_ssl_server_init_full_rsa(
            &e->ctx.server, e->server_chain, e->server_chain_len, rsa_sk);
    } else {
        nv_engine_free(e);
        if (out_err) *out_err = BR_ERR_X509_WRONG_KEY_TYPE;
        return NULL;
    }

    if (version_min != 0 && version_max != 0) {
        br_ssl_engine_set_versions(&e->ctx.server.eng, version_min, version_max);
    }

    nv_engine_set_alpn(e, alpn, alpn_count, fail_on_alpn_mismatch);
    br_ssl_engine_set_buffer(&e->ctx.server.eng, e->iobuf, sizeof(e->iobuf), 1);

    if (!br_ssl_server_reset(&e->ctx.server)) {
        int br_err = br_ssl_engine_last_error(&e->ctx.server.eng);
        nv_engine_free(e);
        if (out_err) *out_err = br_err != 0 ? br_err : BR_ERR_NO_RANDOM;
        return NULL;
    }
    return e;
}

/* -------------------------------------------------------------------------
 * Sans-I/O state machine operations
 * ------------------------------------------------------------------------- */

unsigned nv_engine_state(const nv_engine *e) {
    if (e == NULL) return BR_SSL_CLOSED;
    return br_ssl_engine_current_state(e->is_server ? &e->ctx.server.eng : &e->ctx.client.eng);
}

int nv_engine_last_error(const nv_engine *e) {
    if (e == NULL) return BR_ERR_BAD_PARAM;
    return br_ssl_engine_last_error(e->is_server ? &e->ctx.server.eng : &e->ctx.client.eng);
}

size_t nv_engine_feed_encrypted(nv_engine *e, const unsigned char *data, size_t len) {
    if (e == NULL || data == NULL || len == 0) return 0;
    br_ssl_engine_context *eng = nv_get_eng(e);
    size_t total = 0;
    while (total < len) {
        size_t avail = 0;
        unsigned char *buf = br_ssl_engine_recvrec_buf(eng, &avail);
        if (buf == NULL || avail == 0) break;
        size_t rem = len - total;
        size_t n = rem < avail ? rem : avail;
        memcpy(buf, data + total, n);
        br_ssl_engine_recvrec_ack(eng, n);
        total += n;
    }
    return total;
}

size_t nv_engine_drain_encrypted(nv_engine *e, unsigned char *dest, size_t cap) {
    if (e == NULL || dest == NULL || cap == 0) return 0;
    br_ssl_engine_context *eng = nv_get_eng(e);
    size_t avail = 0;
    unsigned char *buf = br_ssl_engine_sendrec_buf(eng, &avail);
    if (buf == NULL || avail == 0) return 0;
    size_t n = cap < avail ? cap : avail;
    memcpy(dest, buf, n);
    br_ssl_engine_sendrec_ack(eng, n);
    return n;
}

size_t nv_engine_write_plaintext(nv_engine *e, const unsigned char *data, size_t len) {
    if (e == NULL || data == NULL || len == 0) return 0;
    br_ssl_engine_context *eng = nv_get_eng(e);
    size_t avail = 0;
    unsigned char *buf = br_ssl_engine_sendapp_buf(eng, &avail);
    if (buf == NULL || avail == 0) return 0;
    size_t n = len < avail ? len : avail;
    memcpy(buf, data, n);
    br_ssl_engine_sendapp_ack(eng, n);
    return n;
}

size_t nv_engine_read_plaintext(nv_engine *e, unsigned char *dest, size_t cap) {
    if (e == NULL || dest == NULL || cap == 0) return 0;
    br_ssl_engine_context *eng = nv_get_eng(e);
    size_t avail = 0;
    unsigned char *buf = br_ssl_engine_recvapp_buf(eng, &avail);
    if (buf == NULL || avail == 0) return 0;
    size_t n = cap < avail ? cap : avail;
    memcpy(dest, buf, n);
    br_ssl_engine_recvapp_ack(eng, n);
    return n;
}

void nv_engine_flush(nv_engine *e) {
    if (e == NULL) return;
    br_ssl_engine_flush(nv_get_eng(e), 0);
}

void nv_engine_close(nv_engine *e) {
    if (e == NULL) return;
    br_ssl_engine_close(nv_get_eng(e));
}

unsigned nv_engine_get_version(const nv_engine *e) {
    if (e == NULL) return 0;
    return br_ssl_engine_get_version(e->is_server ? &e->ctx.server.eng : &e->ctx.client.eng);
}

uint16_t nv_engine_get_cipher_suite(const nv_engine *e) {
    if (e == NULL) return 0;
    br_ssl_session_parameters pp;
    br_ssl_engine_get_session_parameters(
        e->is_server ? &e->ctx.server.eng : &e->ctx.client.eng, &pp);
    return pp.cipher_suite;
}

const char *nv_engine_get_alpn(nv_engine *e) {
    if (e == NULL) return NULL;
    return br_ssl_engine_get_selected_protocol(nv_get_eng(e));
}

const char *nv_engine_get_server_name(const nv_engine *e) {
    if (e == NULL) return "";
    return br_ssl_engine_get_server_name(e->is_server ? &e->ctx.server.eng : &e->ctx.client.eng);
}

const unsigned char *nv_engine_get_peer_cert(const nv_engine *e, size_t *out_len) {
    if (out_len) *out_len = 0;
    if (e == NULL || e->is_server || e->x509.leaf_truncated || e->x509.leaf_der_len == 0) {
        return NULL;
    }
    if (out_len) *out_len = e->x509.leaf_der_len;
    return e->x509.leaf_der;
}

size_t nv_engine_get_peer_chain_len(const nv_engine *e) {
    if (e == NULL || e->is_server) return 0;
    return e->x509.chain_len;
}

unsigned nv_engine_get_x509_error(const nv_engine *e) {
    if (e == NULL || e->is_server) return 0;
    return e->x509.last_err;
}

/* -------------------------------------------------------------------------
 * Audited OS CSPRNG + ECDSA P-256 key generation & signing (for keygen.nim)
 * ------------------------------------------------------------------------- */

int nv_random_bytes(unsigned char *out, size_t len) {
    if (out == NULL || len == 0) return 0;
    br_hmac_drbg_context rng;
    br_prng_seeder seeder = br_prng_seeder_system(NULL);
    if (seeder == NULL) return 0;
    br_hmac_drbg_init(&rng, &br_sha256_vtable, NULL, 0);
    if (!seeder(&rng.vtable)) return 0;
    br_hmac_drbg_generate(&rng, out, len);
    return 1;
}

int nv_ec_keygen_p256(
    unsigned char *priv_raw32,
    size_t *priv_raw_len,
    unsigned char *pub_uncompressed65,
    size_t *pub_len,
    unsigned char *pkcs8_der_out,
    size_t *pkcs8_der_len
) {
    br_hmac_drbg_context rng;
    br_prng_seeder seeder = br_prng_seeder_system(NULL);
    if (seeder == NULL) return 0;
    br_hmac_drbg_init(&rng, &br_sha256_vtable, NULL, 0);
    if (!seeder(&rng.vtable)) return 0;

    const br_ec_impl *ec = br_ec_get_default();
    br_ec_private_key sk;
    unsigned char kbuf_priv[BR_EC_KBUF_PRIV_MAX_SIZE];
    size_t xlen = br_ec_keygen(&rng.vtable, ec, &sk, kbuf_priv, BR_EC_secp256r1);
    if (xlen == 0 || xlen > 32) return 0;

    br_ec_public_key pk;
    unsigned char kbuf_pub[BR_EC_KBUF_PUB_MAX_SIZE];
    size_t qlen = br_ec_compute_pub(ec, &pk, kbuf_pub, &sk);
    if (qlen == 0 || qlen > 65) return 0;

    memcpy(priv_raw32, sk.x, xlen);
    *priv_raw_len = xlen;

    memcpy(pub_uncompressed65, pk.q, qlen);
    *pub_len = qlen;

    size_t der_needed = br_encode_ec_pkcs8_der(NULL, &sk, &pk);
    if (der_needed == 0 || der_needed > *pkcs8_der_len) return 0;
    *pkcs8_der_len = br_encode_ec_pkcs8_der(pkcs8_der_out, &sk, &pk);
    return (*pkcs8_der_len > 0) ? 1 : 0;
}

size_t nv_ecdsa_sign_p256_sha256(
    const unsigned char *priv_raw,
    size_t priv_len,
    const unsigned char *hash32,
    unsigned char *sig_asn1_out,
    size_t sig_cap
) {
    if (sig_cap < 72 || priv_raw == NULL || hash32 == NULL) return 0;
    br_ec_private_key sk;
    sk.curve = BR_EC_secp256r1;
    sk.x = (unsigned char *)priv_raw;
    sk.xlen = priv_len;

    br_ecdsa_sign signer = br_ecdsa_sign_asn1_get_default();
    return signer(br_ec_get_default(), &br_sha256_vtable, hash32, &sk, sig_asn1_out);
}
