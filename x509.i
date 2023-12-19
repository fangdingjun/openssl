%{
  #include <openssl/x509_vfy.h>  
  #include <openssl/pem.h>
  #include <openssl/store.h>
  #include <openssl/x509.h>
%}
X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void);
X509_LOOKUP_METHOD *X509_LOOKUP_file(void);

int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type);


typedef int pem_password_cb(char *buf, int size, int rwflag, void *u);

EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bp, EVP_PKEY **x,
                                  pem_password_cb *cb, void *u);
EVP_PKEY *PEM_read_PrivateKey(FILE *fp, EVP_PKEY **x,
                              pem_password_cb *cb, void *u);
int PEM_write_bio_PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cb, void *u);
int PEM_write_bio_PrivateKey_traditional(BIO *bp, EVP_PKEY *x,
                                        const EVP_CIPHER *enc,
                                        unsigned char *kstr, int klen,
                                        pem_password_cb *cb, void *u);
int PEM_write_PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                        unsigned char *kstr, int klen,
                        pem_password_cb *cb, void *u);

int PEM_write_bio_PKCS8PrivateKey(BIO *bp, EVP_PKEY *x, const EVP_CIPHER *enc,
                                  char *kstr, int klen,
                                  pem_password_cb *cb, void *u);
int PEM_write_PKCS8PrivateKey(FILE *fp, EVP_PKEY *x, const EVP_CIPHER *enc,
                              char *kstr, int klen,
                              pem_password_cb *cb, void *u);
int PEM_write_bio_PKCS8PrivateKey_nid(BIO *bp, EVP_PKEY *x, int nid,
                                      char *kstr, int klen,
                                      pem_password_cb *cb, void *u);
int PEM_write_PKCS8PrivateKey_nid(FILE *fp, EVP_PKEY *x, int nid,
                                  char *kstr, int klen,
                                  pem_password_cb *cb, void *u);

EVP_PKEY *PEM_read_bio_PUBKEY(BIO *bp, EVP_PKEY **x,
                              pem_password_cb *cb, void *u);
EVP_PKEY *PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x,
                          pem_password_cb *cb, void *u);
int PEM_write_bio_PUBKEY(BIO *bp, EVP_PKEY *x);
int PEM_write_PUBKEY(FILE *fp, EVP_PKEY *x);

RSA *PEM_read_bio_RSAPrivateKey(BIO *bp, RSA **x,
                                pem_password_cb *cb, void *u);
RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x,
                            pem_password_cb *cb, void *u);
int PEM_write_bio_RSAPrivateKey(BIO *bp, RSA *x, const EVP_CIPHER *enc,
                                unsigned char *kstr, int klen,
                                pem_password_cb *cb, void *u);
int PEM_write_RSAPrivateKey(FILE *fp, RSA *x, const EVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cb, void *u);

RSA *PEM_read_bio_RSAPublicKey(BIO *bp, RSA **x,
                              pem_password_cb *cb, void *u);
RSA *PEM_read_RSAPublicKey(FILE *fp, RSA **x,
                          pem_password_cb *cb, void *u);
int PEM_write_bio_RSAPublicKey(BIO *bp, RSA *x);
int PEM_write_RSAPublicKey(FILE *fp, RSA *x);

RSA *PEM_read_bio_RSA_PUBKEY(BIO *bp, RSA **x,
                            pem_password_cb *cb, void *u);
RSA *PEM_read_RSA_PUBKEY(FILE *fp, RSA **x,
                        pem_password_cb *cb, void *u);
int PEM_write_bio_RSA_PUBKEY(BIO *bp, RSA *x);
int PEM_write_RSA_PUBKEY(FILE *fp, RSA *x);

DSA *PEM_read_bio_DSAPrivateKey(BIO *bp, DSA **x,
                                pem_password_cb *cb, void *u);
DSA *PEM_read_DSAPrivateKey(FILE *fp, DSA **x,
                            pem_password_cb *cb, void *u);
int PEM_write_bio_DSAPrivateKey(BIO *bp, DSA *x, const EVP_CIPHER *enc,
                                unsigned char *kstr, int klen,
                                pem_password_cb *cb, void *u);
int PEM_write_DSAPrivateKey(FILE *fp, DSA *x, const EVP_CIPHER *enc,
                            unsigned char *kstr, int klen,
                            pem_password_cb *cb, void *u);

DSA *PEM_read_bio_DSA_PUBKEY(BIO *bp, DSA **x,
                            pem_password_cb *cb, void *u);
DSA *PEM_read_DSA_PUBKEY(FILE *fp, DSA **x,
                        pem_password_cb *cb, void *u);
int PEM_write_bio_DSA_PUBKEY(BIO *bp, DSA *x);
int PEM_write_DSA_PUBKEY(FILE *fp, DSA *x);

EVP_PKEY *PEM_read_bio_Parameters(BIO *bp, EVP_PKEY **x);
int PEM_write_bio_Parameters(BIO *bp, EVP_PKEY *x);

DSA *PEM_read_bio_DSAparams(BIO *bp, DSA **x, pem_password_cb *cb, void *u);
DSA *PEM_read_DSAparams(FILE *fp, DSA **x, pem_password_cb *cb, void *u);
int PEM_write_bio_DSAparams(BIO *bp, DSA *x);
int PEM_write_DSAparams(FILE *fp, DSA *x);

DH *PEM_read_bio_DHparams(BIO *bp, DH **x, pem_password_cb *cb, void *u);
DH *PEM_read_DHparams(FILE *fp, DH **x, pem_password_cb *cb, void *u);
int PEM_write_bio_DHparams(BIO *bp, DH *x);
int PEM_write_DHparams(FILE *fp, DH *x);

X509 *PEM_read_bio_X509(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
X509 *PEM_read_X509(FILE *fp, X509 **x, pem_password_cb *cb, void *u);
int PEM_write_bio_X509(BIO *bp, X509 *x);
int PEM_write_X509(FILE *fp, X509 *x);

X509 *PEM_read_bio_X509_AUX(BIO *bp, X509 **x, pem_password_cb *cb, void *u);
X509 *PEM_read_X509_AUX(FILE *fp, X509 **x, pem_password_cb *cb, void *u);
int PEM_write_bio_X509_AUX(BIO *bp, X509 *x);
int PEM_write_X509_AUX(FILE *fp, X509 *x);

X509_REQ *PEM_read_bio_X509_REQ(BIO *bp, X509_REQ **x,
                                pem_password_cb *cb, void *u);
X509_REQ *PEM_read_X509_REQ(FILE *fp, X509_REQ **x,
                            pem_password_cb *cb, void *u);
int PEM_write_bio_X509_REQ(BIO *bp, X509_REQ *x);
int PEM_write_X509_REQ(FILE *fp, X509_REQ *x);
int PEM_write_bio_X509_REQ_NEW(BIO *bp, X509_REQ *x);
int PEM_write_X509_REQ_NEW(FILE *fp, X509_REQ *x);

X509_CRL *PEM_read_bio_X509_CRL(BIO *bp, X509_CRL **x,
                                pem_password_cb *cb, void *u);
X509_CRL *PEM_read_X509_CRL(FILE *fp, X509_CRL **x,
                            pem_password_cb *cb, void *u);
int PEM_write_bio_X509_CRL(BIO *bp, X509_CRL *x);
int PEM_write_X509_CRL(FILE *fp, X509_CRL *x);

PKCS7 *PEM_read_bio_PKCS7(BIO *bp, PKCS7 **x, pem_password_cb *cb, void *u);
PKCS7 *PEM_read_PKCS7(FILE *fp, PKCS7 **x, pem_password_cb *cb, void *u);
int PEM_write_bio_PKCS7(BIO *bp, PKCS7 *x);
int PEM_write_PKCS7(FILE *fp, PKCS7 *x);


typedef struct x509_lookup_st X509_LOOKUP;

typedef enum X509_LOOKUP_TYPE;

X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method);
int X509_LOOKUP_init(X509_LOOKUP *ctx);
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);
void X509_LOOKUP_free(X509_LOOKUP *ctx);

int X509_LOOKUP_set_method_data(X509_LOOKUP *ctx, void *data);
void *X509_LOOKUP_get_method_data(const X509_LOOKUP *ctx);

int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
                    long argl, char **ret);
int X509_LOOKUP_load_file(X509_LOOKUP *ctx, char *name, long type);
int X509_LOOKUP_add_dir(X509_LOOKUP *ctx, char *name, long type);

X509_STORE *X509_LOOKUP_get_store(const X509_LOOKUP *ctx);

int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                          X509_NAME *name, X509_OBJECT *ret);
int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                X509_NAME *name, ASN1_INTEGER *serial,
                                X509_OBJECT *ret);
int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                              const unsigned char *bytes, int len,
                              X509_OBJECT *ret);
int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                        const char *str, int len, X509_OBJECT *ret);




//typedef x509_store_st X509_STORE;

int X509_STORE_add_cert(X509_STORE *ctx, X509 *x);
int X509_STORE_add_crl(X509_STORE *ctx, X509_CRL *x);
int X509_STORE_set_depth(X509_STORE *store, int depth);
int X509_STORE_set_flags(X509_STORE *ctx, unsigned long flags);
int X509_STORE_set_purpose(X509_STORE *ctx, int purpose);
int X509_STORE_set_trust(X509_STORE *ctx, int trust);

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *store,
                                  X509_LOOKUP_METHOD *meth);

int X509_STORE_load_locations(X509_STORE *ctx,
                              const char *file, const char *dir);
int X509_STORE_set_default_paths(X509_STORE *ctx);


X509_STORE_CTX *X509_STORE_CTX_new(void);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);
void X509_STORE_CTX_free(X509_STORE_CTX *ctx);

int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store,
                        X509 *x509, STACK_OF(X509) *chain);

void X509_STORE_CTX_set0_trusted_stack(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);

void X509_STORE_CTX_set_cert(X509_STORE_CTX *ctx, X509 *x);
STACK_OF(X509) *X509_STORE_CTX_get0_chain(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *ctx, STACK_OF(X509) *chain);
void X509_STORE_CTX_set0_crls(X509_STORE_CTX *ctx, STACK_OF(X509_CRL) *sk);

X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param);
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name);

STACK_OF(X509)* X509_STORE_CTX_get0_untrusted(X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);

int X509_STORE_CTX_get_num_untrusted(X509_STORE_CTX *ctx);

typedef int (*X509_STORE_CTX_verify_fn)(X509_STORE_CTX *);
void X509_STORE_CTX_set_verify(X509_STORE_CTX *ctx, X509_STORE_CTX_verify_fn verify);

int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust);
int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose,
                                  int purpose, int trust);

int SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int SSL_CTX_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);
int BIO_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);

void *X509_STORE_CTX_get_ex_data(X509_STORE_CTX *s, int idx);

int X509_NAME_print_ex(BIO *out, const X509_NAME *nm, int indent, unsigned long flags);
int X509_NAME_print_ex_fp(FILE *fp, const X509_NAME *nm, int indent, unsigned long flags);
char *X509_NAME_oneline(const X509_NAME *a, char *buf, int size);
int X509_NAME_print(BIO *bp, const X509_NAME *name, int obase);

X509_NAME *X509_get_subject_name(const X509 *x);
int X509_set_subject_name(X509 *x, X509_NAME *name);

X509_NAME *X509_get_issuer_name(const X509 *x);
int X509_set_issuer_name(X509 *x, X509_NAME *name);

X509_NAME *X509_REQ_get_subject_name(const X509_REQ *req);
int X509_REQ_set_subject_name(X509_REQ *req, X509_NAME *name);

X509_NAME *X509_CRL_get_issuer(const X509_CRL *crl);
int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name);
