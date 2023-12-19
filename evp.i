%{
#include <openssl/evp.h>
#include <openssl/engine.h>
%}

int EVP_PKEY_set1_RSA(EVP_PKEY *pkey, RSA *key);
int EVP_PKEY_set1_DSA(EVP_PKEY *pkey, DSA *key);
int EVP_PKEY_set1_DH(EVP_PKEY *pkey, DH *key);
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);

RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
DSA *EVP_PKEY_get1_DSA(EVP_PKEY *pkey);
DH *EVP_PKEY_get1_DH(EVP_PKEY *pkey);
EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);

const unsigned char *EVP_PKEY_get0_hmac(const EVP_PKEY *pkey, size_t *len);
const unsigned char *EVP_PKEY_get0_poly1305(const EVP_PKEY *pkey, size_t *len);
const unsigned char *EVP_PKEY_get0_siphash(const EVP_PKEY *pkey, size_t *len);
RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey);
DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey);
DH *EVP_PKEY_get0_DH(EVP_PKEY *pkey);
EC_KEY *EVP_PKEY_get0_EC_KEY(EVP_PKEY *pkey);

int EVP_PKEY_assign_RSA(EVP_PKEY *pkey, RSA *key);
int EVP_PKEY_assign_DSA(EVP_PKEY *pkey, DSA *key);
int EVP_PKEY_assign_DH(EVP_PKEY *pkey, DH *key);
int EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey, EC_KEY *key);
int EVP_PKEY_assign_POLY1305(EVP_PKEY *pkey, ASN1_OCTET_STRING *key);
int EVP_PKEY_assign_SIPHASH(EVP_PKEY *pkey, ASN1_OCTET_STRING *key);

int EVP_PKEY_id(const EVP_PKEY *pkey);
int EVP_PKEY_base_id(const EVP_PKEY *pkey);
int EVP_PKEY_type(int type);
int EVP_PKEY_set_alias_type(EVP_PKEY *pkey, int type);

ENGINE *EVP_PKEY_get0_engine(const EVP_PKEY *pkey);
int EVP_PKEY_set1_engine(EVP_PKEY *pkey, ENGINE *engine);

EVP_PKEY *EVP_PKEY_new(void);
int EVP_PKEY_up_ref(EVP_PKEY *key);
void EVP_PKEY_free(EVP_PKEY *key);

EVP_PKEY *EVP_PKEY_new_raw_private_key(int type, ENGINE *e,
                                const unsigned char *key, size_t keylen);
EVP_PKEY *EVP_PKEY_new_raw_public_key(int type, ENGINE *e,
                                const unsigned char *key, size_t keylen);
EVP_PKEY *EVP_PKEY_new_CMAC_key(ENGINE *e, const unsigned char *priv,
                            size_t len, const EVP_CIPHER *cipher);
EVP_PKEY *EVP_PKEY_new_mac_key(int type, ENGINE *e, const unsigned char *key,
                        int keylen);

int EVP_PKEY_get_raw_private_key(const EVP_PKEY *pkey, unsigned char *priv,
                            size_t *len);
int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub,
                            size_t *len);


void ENGINE_load_builtin_engines(void);
ENGINE *ENGINE_get_default_RSA(void);
ENGINE *ENGINE_get_default_DSA(void);
ENGINE *ENGINE_get_default_DH(void);
ENGINE *ENGINE_get_default_RAND(void);
ENGINE *ENGINE_get_cipher_engine(int nid);
ENGINE *ENGINE_get_digest_engine(int nid);
int ENGINE_free(ENGINE *e);
int ENGINE_up_ref(ENGINE *e);

int EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey,
                    int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_private(BIO *out, const EVP_PKEY *pkey,
                    int indent, ASN1_PCTX *pctx);
int EVP_PKEY_print_params(BIO *out, const EVP_PKEY *pkey,
                    int indent, ASN1_PCTX *pctx);


const EVP_MD *EVP_sha224(void);
const EVP_MD *EVP_sha256(void);
const EVP_MD *EVP_sha512_224(void);
const EVP_MD *EVP_sha512_256(void);
const EVP_MD *EVP_sha384(void);
const EVP_MD *EVP_sha512(void);

const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_md5(void);
const EVP_MD *EVP_md5_sha1(void);
const EVP_CIPHER * EVP_aes_128_cbc(void);
const EVP_CIPHER * EVP_aes_192_cbc(void);
const EVP_CIPHER * EVP_aes_256_cbc(void);
const EVP_CIPHER * EVP_aes_128_cfb(void);
const EVP_CIPHER * EVP_aes_192_cfb(void);
const EVP_CIPHER * EVP_aes_256_cfb(void);
const EVP_CIPHER * EVP_aes_128_cfb1(void);
const EVP_CIPHER * EVP_aes_192_cfb1(void);
const EVP_CIPHER * EVP_aes_256_cfb1(void);
const EVP_CIPHER * EVP_aes_128_cfb8(void);
const EVP_CIPHER * EVP_aes_192_cfb8(void);
const EVP_CIPHER * EVP_aes_256_cfb8(void);
const EVP_CIPHER * EVP_aes_128_cfb128(void);
const EVP_CIPHER * EVP_aes_192_cfb128(void);
const EVP_CIPHER * EVP_aes_256_cfb128(void);
const EVP_CIPHER * EVP_aes_128_ctr(void);
const EVP_CIPHER * EVP_aes_192_ctr(void);
const EVP_CIPHER * EVP_aes_256_ctr(void);
const EVP_CIPHER * EVP_aes_128_ecb(void);
const EVP_CIPHER * EVP_aes_192_ecb(void);
const EVP_CIPHER * EVP_aes_256_ecb(void);
const EVP_CIPHER * EVP_aes_128_ofb(void);
const EVP_CIPHER * EVP_aes_192_ofb(void);
const EVP_CIPHER * EVP_aes_256_ofb(void);

const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void);
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha1(void);
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256(void);
const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256(void);
const EVP_CIPHER *EVP_aes_128_ccm(void);
const EVP_CIPHER *EVP_aes_192_ccm(void);
const EVP_CIPHER *EVP_aes_256_ccm(void);
const EVP_CIPHER *EVP_aes_128_gcm(void);
const EVP_CIPHER *EVP_aes_192_gcm(void);
const EVP_CIPHER *EVP_aes_256_gcm(void);
const EVP_CIPHER *EVP_aes_128_ocb(void);
const EVP_CIPHER *EVP_aes_192_ocb(void);
const EVP_CIPHER *EVP_aes_256_ocb(void);
const EVP_CIPHER *EVP_aes_128_wrap(void);
const EVP_CIPHER *EVP_aes_192_wrap(void);
const EVP_CIPHER *EVP_aes_256_wrap(void);
const EVP_CIPHER *EVP_aes_128_wrap_pad(void);
const EVP_CIPHER *EVP_aes_128_wrap(void);
const EVP_CIPHER *EVP_aes_192_wrap(void);
const EVP_CIPHER *EVP_aes_256_wrap(void);
const EVP_CIPHER *EVP_aes_192_wrap_pad(void);
const EVP_CIPHER *EVP_aes_128_wrap(void);
const EVP_CIPHER *EVP_aes_192_wrap(void);
const EVP_CIPHER *EVP_aes_256_wrap(void);
const EVP_CIPHER *EVP_aes_256_wrap_pad(void);
const EVP_CIPHER *EVP_aes_128_xts(void);
const EVP_CIPHER *EVP_aes_256_xts(void);
