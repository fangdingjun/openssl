
%{
    #include <openssl/ssl.h>
    #include <openssl/bio.h>
    #include <openssl/err.h>
    #include <openssl/crypto.h>
    #include <stdint.h>
%}

void SSL_CTX_free(SSL_CTX *);
//int SSL_get_fd(const SSL *s);
int SSL_set_fd(SSL *s, int fd);
int SSL_shutdown(SSL *s);
void SSL_free(SSL *ssl);
//
typedef int (*SSL_verify_cb)(int preverify_ok, X509_STORE_CTX *x509_ctx);
//
//
int SSL_accept(SSL *ssl);
int SSL_connect(SSL *ssl);
//int SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str);
//int SSL_set_ciphersuites(SSL *s, const char *str);
//void SSL_set_read_ahead(SSL *s, int yes);
//int SSL_get_verify_mode(const SSL *s);
//int SSL_get_verify_depth(const SSL *s);
%{

extern int GoSslVerifyCb(int preverify_ok, uintptr_t x509_ctx);
int custom_ssl_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx){
    return GoSslVerifyCb(preverify_ok, (uintptr_t)(x509_ctx));
}
%}

%constant int custom_ssl_verify_cb(int preverify_ok, X509_STORE_CTX *x509_ctx);

//SSL_verify_cb SSL_get_verify_callback(const SSL *s);
void SSL_set_verify(SSL *s, int mode, SSL_verify_cb callback);
//void SSL_set_cert_cb(SSL *s, int (*cb) (SSL *ssl, void *arg), void *arg);
//int SSL_set_rfd(SSL *s, int fd);
//int SSL_set_wfd(SSL *s, int fd);
int SSL_write(SSL *ssl, const void *VOIDBUF, int len);
//int SSL_write_ex(SSL *s, const void *buf, size_t num, size_t *written);
int SSL_do_handshake(SSL *s);
int SSL_read(SSL *ssl, void *inbuf, int len);
//
//
//#define PSK_MAX_IDENTITY_LEN 128
//#define PSK_MAX_PSK_LEN 256
typedef unsigned int (*SSL_psk_client_cb_func)(SSL *ssl,
                                               const char *hint,
                                               char *identity,
                                               unsigned int max_identity_len,
                                               unsigned char *psk,
                                               unsigned int max_psk_len);

%{
extern unsigned int GoSslPskClientCbFunc(SSL *ssl,
                                               const char *hint,
                                               char *identity,
                                               unsigned int max_identity_len,
                                               unsigned char *psk,
                                               unsigned int max_psk_len);

unsigned int custom_ssl_psk_client_cb_func(SSL *ssl,
                                               const char *hint,
                                               char *identity,
                                               unsigned int max_identity_len,
                                               unsigned char *psk,
                                               unsigned int max_psk_len){
    return GoSslPskClientCbFunc(ssl, hint, identity, max_identity_len, psk, max_psk_len);
}

%}
%constant unsigned int custom_ssl_psk_client_cb_func(SSL *ssl,
                                               const char *hint,
                                               char *identity,
                                               unsigned int max_identity_len,
                                               unsigned char *psk,
                                               unsigned int max_psk_len);
void SSL_CTX_set_psk_client_callback(SSL_CTX *ctx, SSL_psk_client_cb_func cb);
void SSL_set_psk_client_callback(SSL *ssl, SSL_psk_client_cb_func cb);

//typedef unsigned int (*SSL_psk_server_cb_func)(SSL *ssl,
//                                               const char *identity,
//                                               unsigned char *psk,
//                                               unsigned int max_psk_len);
//void SSL_CTX_set_psk_server_callback(SSL_CTX *ctx, SSL_psk_server_cb_func cb);
//void SSL_set_psk_server_callback(SSL *ssl, SSL_psk_server_cb_func cb);
//
//int SSL_CTX_use_psk_identity_hint(SSL_CTX *ctx, const char *identity_hint);
//int SSL_use_psk_identity_hint(SSL *s, const char *identity_hint);
//const char *SSL_get_psk_identity_hint(const SSL *s);
//const char *SSL_get_psk_identity(const SSL *s);
//
//
//X509 *SSL_get_certificate(const SSL *ssl);
//struct evp_pkey_st *SSL_get_privatekey(const SSL *ssl);
X509 *SSL_CTX_get0_certificate(const SSL_CTX *ctx);
EVP_PKEY *SSL_CTX_get0_privatekey(const SSL_CTX *ctx);


#define SSL_VERIFY_NONE                 0x00
#define SSL_VERIFY_PEER                 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE          0x04
#define SSL_VERIFY_POST_HANDSHAKE       0x08

void SSL_set_connect_state(SSL *ssl);

void SSL_set_accept_state(SSL *ssl);

//int SSL_is_server(const SSL *ssl);
//long SSL_CTX_set_mode(SSL_CTX *ctx, long mode);
//long SSL_CTX_clear_mode(SSL_CTX *ctx, long mode);
//long SSL_set_mode(SSL *ssl, long mode);
//long SSL_clear_mode(SSL *ssl, long mode);
//
//long SSL_CTX_get_mode(SSL_CTX *ctx);
//long SSL_get_mode(SSL *ssl);
//
int SSL_get_error(const SSL *ssl, int ret);
//
////ossl_ssize_t SSL_sendfile(SSL *s, int fd, off_t offset, size_t size, int flags);
//
//int SSL_peek_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes);
//int SSL_peek(SSL *ssl, void *buf, int num);
//
//SSL *SSL_dup(SSL *s);
SSL *SSL_new(SSL_CTX *ctx);
//int SSL_up_ref(SSL *s);
//
void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);
//void SSL_set0_rbio(SSL *s, BIO *rbio);
//void SSL_set0_wbio(SSL *s, BIO *wbio);
//
//
////SSL_CTX *SSL_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq,
// //                       const SSL_METHOD *method);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
//int SSL_CTX_up_ref(SSL_CTX *ctx);
//
const SSL_METHOD *TLS_method(void);
const SSL_METHOD *TLS_server_method(void);
const SSL_METHOD *TLS_client_method(void);

////const SSL_METHOD *SSLv23_method(void);
////const SSL_METHOD *SSLv23_server_method(void);
////const SSL_METHOD *SSLv23_client_method(void);
//
//
////const SSL_METHOD *TLSv1_method(void);
////const SSL_METHOD *TLSv1_server_method(void);
////const SSL_METHOD *TLSv1_client_method(void);
//
////const SSL_METHOD *TLSv1_1_method(void);
////const SSL_METHOD *TLSv1_1_server_method(void);
////const SSL_METHOD *TLSv1_1_client_method(void);
//
////const SSL_METHOD *TLSv1_2_method(void);
////const SSL_METHOD *TLSv1_2_server_method(void);
////const SSL_METHOD *TLSv1_2_client_method(void);
//
const SSL_METHOD *DTLS_method(void);
const SSL_METHOD *DTLS_server_method(void);
const SSL_METHOD *DTLS_client_method(void);
//
////const SSL_METHOD *DTLSv1_method(void);
////const SSL_METHOD *DTLSv1_server_method(void);
////const SSL_METHOD *DTLSv1_client_method(void);
//
////const SSL_METHOD *DTLSv1_2_method(void);
////const SSL_METHOD *DTLSv1_2_server_method(void);
////const SSL_METHOD *DTLSv1_2_client_method(void);
//
//
//
int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x);
//int SSL_CTX_use_certificate_ASN1(SSL_CTX *ctx, int len, unsigned char *d);
//int SSL_CTX_use_certificate_file(SSL_CTX *ctx, const char *file, int type);
int SSL_use_certificate(SSL *ssl, X509 *x);
//int SSL_use_certificate_ASN1(SSL *ssl, unsigned char *d, int len);
int SSL_use_certificate_file(SSL *ssl, const char *file, int type);
//
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
int SSL_use_certificate_chain_file(SSL *ssl, const char *file);
//
int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey);
//int SSL_CTX_use_PrivateKey_ASN1(int pk, SSL_CTX *ctx, unsigned char *d,
//                                long len);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
//int SSL_CTX_use_RSAPrivateKey(SSL_CTX *ctx, RSA *rsa);
//int SSL_CTX_use_RSAPrivateKey_ASN1(SSL_CTX *ctx, unsigned char *d, long len);
//int SSL_CTX_use_RSAPrivateKey_file(SSL_CTX *ctx, const char *file, int type);
int SSL_use_PrivateKey(SSL *ssl, EVP_PKEY *pkey);
//int SSL_use_PrivateKey_ASN1(int pk, SSL *ssl, unsigned char *d, long len);
//int SSL_use_PrivateKey_file(SSL *ssl, const char *file, int type);
//int SSL_use_RSAPrivateKey(SSL *ssl, RSA *rsa);
//int SSL_use_RSAPrivateKey_ASN1(SSL *ssl, unsigned char *d, long len);
//int SSL_use_RSAPrivateKey_file(SSL *ssl, const char *file, int type);
//
//int SSL_CTX_check_private_key(const SSL_CTX *ctx);
//int SSL_check_private_key(const SSL *ssl);
//
//int SSL_CTX_use_cert_and_key(SSL_CTX *ctx, X509 *x, EVP_PKEY *pkey, STACK_OF(X509) *chain, int override);
//int SSL_use_cert_and_key(SSL *ssl, X509 *x, EVP_PKEY *pkey, STACK_OF(X509) *chain, int override);
//
//
//long SSL_CTX_set_tlsext_servername_callback(SSL_CTX *ctx,
//                                int (*cb)(SSL *s, int *al, void *arg));
//long SSL_CTX_set_tlsext_servername_arg(SSL_CTX *ctx, void *arg);
//
//const char *SSL_get_servername(const SSL *s, const int type);
//int SSL_get_servername_type(const SSL *s);
//
int SSL_set_tlsext_host_name(SSL *s, const char *name);
//
//
int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile,
                                const char *CApath);
//
int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
//
//int SSL_CTX_set_default_verify_dir(SSL_CTX *ctx);
//
//int SSL_CTX_set_default_verify_file(SSL_CTX *ctx);
//
//
//int SSL_want(const SSL *ssl);
//int SSL_want_nothing(const SSL *ssl);
int SSL_want_read(const SSL *ssl);
int SSL_want_write(const SSL *ssl);
//int SSL_want_x509_lookup(const SSL *ssl);
//int SSL_want_async(const SSL *ssl);
//int SSL_want_async_job(const SSL *ssl);
//int SSL_want_client_hello_cb(const SSL *ssl);
//
%apply (const void *VOIDBUF, int len) {(const unsigned char *protos, unsigned int protos_len)}
int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
                            unsigned int protos_len);
int SSL_set_alpn_protos(SSL *ssl, const unsigned char *protos,
                        unsigned int protos_len);
//void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
//                                int (*cb) (SSL *ssl,
//                                        const unsigned char **out,
//                                        unsigned char *outlen,
//                                        const unsigned char *in,
//                                        unsigned int inlen,
//                                        void *arg), void *arg);
%{
char *my_ssl_get_alpn_selected(const SSL *ssl){
    char *tmp;
    int len;
    SSL_get0_alpn_selected(ssl, (const unsigned char **)&tmp, &len);
    tmp[len] = '\0';
    return tmp;
}
%}

%rename(SSL_get_alpn_selected) my_ssl_get_alpn_selected;

const char *my_ssl_get_alpn_selected(const SSL *ssl);
////void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
////                           unsigned int *len);
//
//void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *ctx,
//                                            int (*cb)(SSL *ssl,
//                                                      const unsigned char **out,
//                                                      unsigned int *outlen,
//                                                      void *arg),
//                                            void *arg);
//void SSL_CTX_set_next_proto_select_cb(SSL_CTX *ctx,
//                               int (*cb)(SSL *s,
//                                         unsigned char **out,
//                                         unsigned char *outlen,
//                                         const unsigned char *in,
//                                         unsigned int inlen,
//                                         void *arg),
//                               void *arg);
//int SSL_select_next_proto(unsigned char **out, unsigned char *outlen,
//                           const unsigned char *server,
//                           unsigned int server_len,
//                           const unsigned char *client,
//                           unsigned int client_len);
//void SSL_get0_next_proto_negotiated(const SSL *s, const unsigned char **data,
//                             unsigned *len);
//                             
void *SSL_CTX_get_ex_data(const SSL_CTX *s, int idx);

int SSL_CTX_set_ex_data(SSL_CTX *s, int idx, void *arg);

void *SSL_get_ex_data(const SSL *s, int idx);

int SSL_set_ex_data(SSL *s, int idx, void *arg);
//
//const char *SSL_state_string(const SSL *ssl);
//const char *SSL_state_string_long(const SSL *ssl);
//
//char *ERR_error_string(unsigned long e, char *buf);
//
//%apply (char *OUTCHARBUF, int len) {(char *buf, size_t len)}
//void ERR_error_string_n(unsigned long e, char *buf, size_t len);
//
//const char *ERR_lib_error_string(unsigned long e);
//const char *ERR_func_error_string(unsigned long e);
//const char *ERR_reason_error_string(unsigned long e);
//
//#define SSL_ERROR_NONE                  0
//#define SSL_ERROR_SSL                   1
//#define SSL_ERROR_WANT_READ             2
//#define SSL_ERROR_WANT_WRITE            3
//#define SSL_ERROR_WANT_X509_LOOKUP      4
//#define SSL_ERROR_SYSCALL               5/* look at error stack/return
//                                           * value/errno */
//#define SSL_ERROR_ZERO_RETURN           6
//#define SSL_ERROR_WANT_CONNECT          7
//#define SSL_ERROR_WANT_ACCEPT           8
//#define SSL_ERROR_WANT_ASYNC            9
//#define SSL_ERROR_WANT_ASYNC_JOB       10
//#define SSL_ERROR_WANT_CLIENT_HELLO_CB 11
//
void ERR_print_errors(BIO *bp);
//void ERR_print_errors_fp(FILE *fp);
//void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u), void *u);
//
//
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, SSL_verify_cb verify_callback);
int SSL_get_ex_data_X509_STORE_CTX_idx(void);
//
void SSL_CTX_set_verify_depth(SSL_CTX *ctx, int depth);
void SSL_set_verify_depth(SSL *ssl, int depth);
//
//int SSL_verify_client_post_handshake(SSL *ssl);
//void SSL_CTX_set_post_handshake_auth(SSL_CTX *ctx, int val);
//void SSL_set_post_handshake_auth(SSL *ssl, int val);
//
//int OPENSSL_init_ssl(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
//int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
//
X509 *SSL_get_peer_certificate(const SSL *ssl);
//
//int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
//int SSL_set_cipher_list(SSL *ssl, const char *str);
//
// void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store);
// void SSL_CTX_set1_cert_store(SSL_CTX *ctx, X509_STORE *store);
 X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx);

long SSL_get_verify_result(const SSL *ssl);

uint64_t SSL_CTX_set_options(SSL_CTX *ctx, uint64_t options);
uint64_t SSL_set_options(SSL *ssl, uint64_t options);

#define SSL_OP_NO_SSLv3                                 0x02000000U
#define SSL_OP_NO_TLSv1                                 0x04000000U
#define SSL_OP_NO_TLSv1_2                               0x08000000U
#define SSL_OP_NO_TLSv1_1                               0x10000000U
#define SSL_OP_NO_TLSv1_3                               0x20000000U

#define SSL_OP_NO_DTLSv1                                0x04000000U
#define SSL_OP_NO_DTLSv1_2                              0x08000000U
