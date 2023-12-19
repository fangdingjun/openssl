
%{
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
%}


#define BIO_NOCLOSE             0x00
#define BIO_CLOSE               0x01

const BIO_METHOD *BIO_f_base64(void);
const BIO_METHOD *BIO_f_buffer(void);

long BIO_get_buffer_num_lines(BIO *b);
long BIO_set_read_buffer_size(BIO *b, long size);
long BIO_set_write_buffer_size(BIO *b, long size);
long BIO_set_buffer_size(BIO *b, long size);
long BIO_set_buffer_read_data(BIO *b, void *buf, long num);
const BIO_METHOD *BIO_f_cipher(void);
int BIO_set_cipher(BIO *b, const EVP_CIPHER *cipher,
                const unsigned char *key, const unsigned char *iv, int enc);
int BIO_get_cipher_status(BIO *b);
int BIO_get_cipher_ctx(BIO *b, EVP_CIPHER_CTX **pctx);
const BIO_METHOD *BIO_f_md(void);
int BIO_set_md(BIO *b, EVP_MD *md);
int BIO_get_md(BIO *b, EVP_MD **mdp);
int BIO_get_md_ctx(BIO *b, EVP_MD_CTX **mdcp);
const BIO_METHOD *BIO_f_null(void);

const BIO_METHOD *BIO_f_ssl(void);
%{
SSL *my_bio_get_ssl(BIO *b){
    SSL *tmp;
    BIO_get_ssl(b, &tmp);
    return tmp;
}
%}
%rename(BIO_get_ssl) my_bio_get_ssl;
SSL *my_bio_get_ssl(BIO *b);
//long BIO_get_ssl(BIO *b, SSL **sslp);
long BIO_set_ssl(BIO *b, SSL *ssl, long c);
long BIO_set_ssl_mode(BIO *b, long client);
long BIO_set_ssl_renegotiate_bytes(BIO *b, long num);
long BIO_set_ssl_renegotiate_timeout(BIO *b, long seconds);
long BIO_get_num_renegotiates(BIO *b);

//const BIO_METHOD *BIO_f_readbuffer(void);

BIO *BIO_find_type(BIO *b, int bio_type);
BIO *BIO_next(BIO *b);
int BIO_method_type(const BIO *b);

//BIO *BIO_new_ex(OSSL_LIB_CTX *libctx, const BIO_METHOD *type);
BIO *BIO_new(const BIO_METHOD *type);
int BIO_up_ref(BIO *a);
int BIO_free(BIO *a);
void BIO_vfree(BIO *a);
void BIO_free_all(BIO *a);


BIO *BIO_push(BIO *b, BIO *next);
BIO *BIO_pop(BIO *b);
void BIO_set_next(BIO *b, BIO *next);

int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);
int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);

//int BIO_get_line(BIO *b, char *buf, int size);
int BIO_puts(BIO *b, const char *buf);


BIO *BIO_new_ssl(SSL_CTX *ctx, int client);
BIO *BIO_new_ssl_connect(SSL_CTX *ctx);
BIO *BIO_new_buffer_ssl_connect(SSL_CTX *ctx);
int BIO_ssl_copy_session_id(BIO *to, BIO *from);
void BIO_ssl_shutdown(BIO *bio);

const BIO_METHOD *BIO_s_accept(void);

long BIO_set_accept_name(BIO *b, char *name);
char *BIO_get_accept_name(BIO *b);

long BIO_set_accept_port(BIO *b, char *port);
char *BIO_get_accept_port(BIO *b);

BIO *BIO_new_accept(char *host_port);

long BIO_set_nbio_accept(BIO *b, int n);
long BIO_set_accept_bios(BIO *b, char *bio);

char *BIO_get_peer_name(BIO *b);
char *BIO_get_peer_port(BIO *b);
long BIO_get_accept_ip_family(BIO *b);
long BIO_set_accept_ip_family(BIO *b, long family);

long BIO_set_bind_mode(BIO *b, long mode);
long BIO_get_bind_mode(BIO *b);

int BIO_do_accept(BIO *b);

long BIO_do_handshake(BIO *b);


void BIO_set_data(BIO *a, void *ptr);
void *BIO_get_data(BIO *a);
void BIO_set_init(BIO *a, int init);
int BIO_get_init(BIO *a);
void BIO_set_shutdown(BIO *a, int shut);
int BIO_get_shutdown(BIO *a);
int BIO_read_ex(BIO *b, void *data, size_t dlen, size_t *readbytes);
int BIO_gets(BIO *bp, char *buf, int size);
int BIO_write(BIO *b, const void *VOIDBUF, int len);
int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);
int BIO_indent(BIO *b, int indent, int max);
BIO *BIO_dup_chain(BIO *in);
int BIO_read(BIO *b, void *inbuf, int len);

const BIO_METHOD *BIO_s_bio(void);

int BIO_make_bio_pair(BIO *b1, BIO *b2);
int BIO_destroy_bio_pair(BIO *b);
int BIO_shutdown_wr(BIO *b);

int BIO_set_write_buf_size(BIO *b, long size);
size_t BIO_get_write_buf_size(BIO *b, long size);

int BIO_new_bio_pair(BIO **bio1, size_t writebuf1, BIO **bio2, size_t writebuf2);

int BIO_get_write_guarantee(BIO *b);
size_t BIO_ctrl_get_write_guarantee(BIO *b);
int BIO_get_read_request(BIO *b);
size_t BIO_ctrl_get_read_request(BIO *b);
int BIO_ctrl_reset_read_request(BIO *b);

const BIO_METHOD *BIO_s_connect(void);

BIO *BIO_new_connect(const char *name);

long BIO_set_conn_hostname(BIO *b, char *name);
long BIO_set_conn_port(BIO *b, char *port);
long BIO_set_conn_address(BIO *b, BIO_ADDR *addr);
long BIO_set_conn_ip_family(BIO *b, long family);
const char *BIO_get_conn_hostname(BIO *b);
const char *BIO_get_conn_port(BIO *b);
const BIO_ADDR *BIO_get_conn_address(BIO *b);
const long BIO_get_conn_ip_family(BIO *b);

long BIO_set_nbio(BIO *b, long n);

long BIO_do_connect(BIO *b);

const BIO_METHOD *BIO_s_fd(void);

int BIO_set_fd(BIO *b, int fd, int c);
int BIO_get_fd(BIO *b, int *c);

BIO *BIO_new_fd(int fd, int close_flag);

const BIO_METHOD *BIO_s_file(void);
BIO *BIO_new_file(const char *filename, const char *mode);
BIO *BIO_new_fp(FILE *stream, int flags);

BIO_set_fp(BIO *b, FILE *fp, int flags);
BIO_get_fp(BIO *b, FILE **fpp);

int BIO_read_filename(BIO *b, char *name);
int BIO_write_filename(BIO *b, char *name);
int BIO_append_filename(BIO *b, char *name);
int BIO_rw_filename(BIO *b, char *name);

const BIO_METHOD *BIO_s_mem(void);
const BIO_METHOD *BIO_s_secmem(void);

BIO_set_mem_eof_return(BIO *b, int v);
long BIO_get_mem_data(BIO *b, char **pp);
BIO_set_mem_buf(BIO *b, BUF_MEM *bm, int c);
BIO_get_mem_ptr(BIO *b, BUF_MEM **pp);

BIO *BIO_new_mem_buf(const void *buf, int len);

const BIO_METHOD *BIO_s_null(void);

const BIO_METHOD *BIO_s_socket(void);

BIO *BIO_new_socket(int sock, int close_flag);

typedef long (*BIO_callback_fn_ex)(BIO *b, int oper, const char *argp,
                                size_t len, int argi,
                                long argl, int ret, size_t *processed);

void BIO_set_callback_ex(BIO *b, BIO_callback_fn_ex callback);
BIO_callback_fn_ex BIO_get_callback_ex(const BIO *b);

void BIO_set_callback_arg(BIO *b, char *arg);
char *BIO_get_callback_arg(const BIO *b);

//long BIO_debug_callback_ex(BIO *bio, int oper, const char *argp, size_t len,
//                           int argi, long argl, int ret, size_t *processed);


typedef long (*BIO_callback_fn)(BIO *b, int oper, const char *argp, int argi,
                            long argl, long ret);
void BIO_set_callback(BIO *b, BIO_callback_fn cb);
BIO_callback_fn BIO_get_callback(const BIO *b);
long BIO_debug_callback(BIO *bio, int cmd, const char *argp, int argi,
                    long argl, long ret);
                    
int BIO_should_read(BIO *b);
int BIO_should_write(BIO *b);
int BIO_should_io_special(BIO *b);
int BIO_retry_type(BIO *b);
int BIO_should_retry(BIO *b);

BIO *BIO_get_retry_BIO(BIO *bio, int *reason);
int BIO_get_retry_reason(BIO *bio);
void BIO_set_retry_reason(BIO *bio, int reason);

typedef int BIO_info_cb(BIO *b, int state, int res);

long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
long BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *cb);
void *BIO_ptr_ctrl(BIO *bp, int cmd, long larg);
long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);

int BIO_reset(BIO *b);
int BIO_seek(BIO *b, int ofs);
int BIO_tell(BIO *b);
int BIO_flush(BIO *b);
int BIO_eof(BIO *b);
int BIO_set_close(BIO *b, long flag);
int BIO_get_close(BIO *b);
int BIO_pending(BIO *b);
int BIO_wpending(BIO *b);
size_t BIO_ctrl_pending(BIO *b);
size_t BIO_ctrl_wpending(BIO *b);

int BIO_get_info_callback(BIO *b, BIO_info_cb **cbp);
int BIO_set_info_callback(BIO *b, BIO_info_cb *cb);

//int BIO_get_ktls_send(BIO *b);
//int BIO_get_ktls_recv(BIO *b);


// int BIO_printf(BIO *bio, const char *format, ...);
//int BIO_vprintf(BIO *bio, const char *format, va_list args);

//int BIO_snprintf(char *buf, size_t n, const char *format, ...);
//int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args);

void *BIO_get_ex_data(BIO *s, int idx);

int BIO_set_ex_data(BIO *s, int idx, void *arg);
