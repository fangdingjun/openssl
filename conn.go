package openssl

// #include <stdlib.h>
// #include <string.h>
// #cgo LDFLAGS: -lcrypto -lssl
import "C"

import (
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"
	"unsafe"
)

//export GoSslPskClientCbFunc
func GoSslPskClientCbFunc(_ssl uintptr, hint *C.char, identity *C.char,
	max_identity_len C.uint, psk *C.uchar, max_psk_len C.uint) C.uint {

	fmt.Printf("psk client cb\n")

	ssl := SwigcptrSSL(_ssl)
	c := SSL_get_ex_data(ssl, sslDataIdx)
	conn := (*Conn)(unsafe.Pointer(c))
	fmt.Printf("config %+v\n", conn.config)

	identityC := C.CString(conn.config.Identity)
	defer C.free(unsafe.Pointer(identityC))

	C.strcpy(identity, identityC)

	pskC := C.CBytes(conn.config.Psk)
	defer C.free(pskC)

	C.memcpy(unsafe.Pointer(psk), pskC, C.ulong(len(conn.config.Psk)))

	return C.uint(len(conn.config.Psk))
}

//export GoSslVerifyCb
func GoSslVerifyCb(preverify_ok C.int, x509_ctx uintptr) C.int {
	//fmt.Printf("verify callback\n")
	a := X509_STORE_CTX_get_ex_data(SwigcptrX509_STORE_CTX(x509_ctx), SSL_get_ex_data_X509_STORE_CTX_idx())
	ssl := SwigcptrSSL(a)
	c := SSL_get_ex_data(ssl, sslDataIdx)
	conn := (*Conn)(unsafe.Pointer(c))

	//fmt.Printf("config %+v\n", conn.config)

	if conn.config.InsecureSkipVerify || conn.isServer {
		return C.int(1)
	}
	return preverify_ok
}

var sslDataIdx = 0
var ctxDataIdx = 0

type Config struct {
	ServerName         string
	PrivateKey         EVP_PKEY
	NextProtos         []string
	Certificate        X509
	Identity           string
	Psk                []byte
	InsecureSkipVerify bool
}

type listener struct {
	ln     net.Listener
	config *Config
}

var _ net.Listener = &listener{}

func (l *listener) Accept() (net.Conn, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	fmt.Printf("accept connection from %s\n", conn.RemoteAddr())
	c := &Conn{c: conn, config: l.config}
	if err := c.setupServer(); err != nil {
		fmt.Printf("set server error %s\n", err)
		conn.Close()
		return nil, err
	}
	fmt.Printf("setup tls finished\n")
	if err := c.Handshake(); err != nil {
		fmt.Printf("handshake error %s\n", err)
	}
	return c, nil
}

func (l *listener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *listener) Close() error {
	return l.ln.Close()
}

func Listen(network, laddr string, config *Config) (net.Listener, error) {
	cln, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	ln := &listener{
		ln:     cln,
		config: config,
	}
	return ln, nil
}

func NewListener(inner net.Listener, config *Config) net.Listener {
	ln := &listener{ln: inner, config: config}
	return ln
}

type Conn struct {
	ctx               SSL_CTX
	ssl               SSL
	bio               BIO
	f                 *os.File
	c                 net.Conn
	config            *Config
	handshakeComplete int64
	isServer          bool
}

var _ net.Conn = &Conn{}

func Client(conn net.Conn, config *Config) *Conn {
	tcpconn, ok := conn.(*net.TCPConn)
	if !ok {
		panic("only tcp connection supported")
		//return nil
	}
	fconn, _ := tcpconn.File()

	ctx := SSL_CTX_new(TLS_client_method())
	bio := BIO_new_fd(int(fconn.Fd()), BIO_NOCLOSE)

	bio1 := BIO_new_ssl(ctx, 1)
	BIO_push(bio1, bio)

	ssl := BIO_get_ssl(bio1)

	sslconn := &Conn{
		ctx:    ctx,
		f:      fconn,
		c:      conn,
		bio:    bio1,
		ssl:    ssl,
		config: config,
	}
	sslconn.setupClient()
	return sslconn
}

func Dial(network, addr string, config *Config) (*Conn, error) {
	ctx := SSL_CTX_new(TLS_client_method())
	bio := BIO_new_ssl_connect(ctx)
	BIO_set_conn_hostname(bio, addr)
	BIO_set_ssl_mode(bio, 1)
	ssl := BIO_get_ssl(bio)

	c := &Conn{
		ctx: ctx, bio: bio,
		config: config,
		ssl:    ssl,
	}
	c.setupClient()
	return c, nil
}

func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{c: conn, config: config}
	if err := c.setupServer(); err != nil {
		panic(err)
	}
	return c
}

func (c *Conn) setupServer() error {
	if c.config.PrivateKey == nil || c.config.Certificate == nil {
		return fmt.Errorf("certificate and private key is needed")
	}

	tcpconn, ok := c.c.(*net.TCPConn)
	if !ok {
		panic("only tcp supported")
	}

	fconn, err := tcpconn.File()
	if err != nil {
		return err
	}

	ctx := SSL_CTX_new(TLS_server_method())

	ret := SSL_CTX_use_PrivateKey(ctx, c.config.PrivateKey)
	if ret < 0 {
		return fmt.Errorf("set private key %s", GetSslError())
	}

	ret = SSL_CTX_use_certificate(ctx, c.config.Certificate)
	if ret < 0 {
		return fmt.Errorf("set certificate %s", GetSslError())
	}

	sbio := BIO_new_ssl(ctx, 0)
	bio := BIO_new_fd(int(fconn.Fd()), BIO_NOCLOSE)
	BIO_push(sbio, bio)

	ssl := BIO_get_ssl(sbio)

	c.f = fconn
	c.ssl = ssl
	c.ctx = ctx
	c.bio = sbio
	c.isServer = true

	SSL_CTX_set_ex_data(c.ctx, ctxDataIdx, uintptr(unsafe.Pointer(c)))
	SSL_set_ex_data(c.ssl, sslDataIdx, uintptr(unsafe.Pointer(c)))
	//fmt.Printf("setup server done\n")
	return nil
}

func (c *Conn) setupClient() error {
	if c.config.ServerName != "" {
		SSL_set_tlsext_host_name(c.ssl, c.config.ServerName)
	}
	if len(c.config.NextProtos) > 0 {
		buf := []byte{}
		for _, p := range c.config.NextProtos {
			buf = append(buf, byte(len(p)))
			buf = append(buf, []byte(p)...)
		}
		SSL_set_alpn_protos(c.ssl, buf)
	}

	if c.config.PrivateKey != nil && c.config.Certificate != nil {
		SSL_CTX_use_PrivateKey(c.ctx, c.config.PrivateKey)
		SSL_CTX_use_certificate(c.ctx, c.config.Certificate)
	}

	SSL_set_verify(c.ssl, SSL_VERIFY_PEER, MY_ssl_verify_cb)
	SSL_CTX_set_ex_data(c.ctx, ctxDataIdx, uintptr(unsafe.Pointer(c)))
	SSL_set_ex_data(c.ssl, sslDataIdx, uintptr(unsafe.Pointer(c)))
	return nil
}

func (c *Conn) Handshake() error {
	val := atomic.LoadInt64(&c.handshakeComplete)
	if val > 0 {
		return nil
	}
	ret := SSL_do_handshake(c.ssl)
	if ret < 0 {
		return fmt.Errorf("%s", GetSslError())
	}
	atomic.StoreInt64(&c.handshakeComplete, 1)
	return nil
}

func (c *Conn) Read(buf []byte) (int, error) {
	a := atomic.LoadInt64(&c.handshakeComplete)
	if a == 0 {
		err := c.Handshake()
		if err != nil {
			return 0, err
		}
	}
	n := BIO_read(c.bio, buf)
	if n <= 0 {
		return 0, fmt.Errorf("read error %s", GetSslError())
	}
	return n, nil
}

func (c *Conn) Write(buf []byte) (int, error) {
	a := atomic.LoadInt64(&c.handshakeComplete)
	if a == 0 {
		err := c.Handshake()
		if err != nil {
			return 0, err
		}
	}
	n := BIO_write(c.bio, buf)
	if n <= 0 {
		return 0, fmt.Errorf("write error %s", GetSslError())
	}
	return n, nil
}

func (c *Conn) Close() error {
	if c.ssl != nil {
		SSL_shutdown(c.ssl)
	}
	if c.f != nil {
		c.f.Close()
	}

	if c.c != nil {
		c.c.Close()
	}

	if c.bio != nil {
		BIO_free_all(c.bio)
	}

	if c.ctx != nil {
		SSL_CTX_free(c.ctx)
	}
	return nil
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.c != nil {
		return c.c.RemoteAddr()
	}
	return &net.TCPAddr{}
}

func (c *Conn) LocalAddr() net.Addr {
	if c.c != nil {
		return c.c.LocalAddr()
	}
	return &net.TCPAddr{}
}

func (c *Conn) SetDeadline(t time.Time) error {
	return fmt.Errorf("not implement")
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("not implement")
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("not implement")
}

func (c *Conn) ConnectionState() ConnectionState {
	state := ConnectionState{}
	val := atomic.LoadInt64(&c.handshakeComplete)
	if val > 0 {
		state.HandshakeComplete = true
		state.PeerCertificate = SSL_get_peer_certificate(c.ssl)
	}
	if val > 0 && len(c.config.NextProtos) > 0 {
		state.NegotiatedProtocol = SSL_get_alpn_selected(c.ssl)
	}
	return state
}

type ConnectionState struct {
	NegotiatedProtocol string
	HandshakeComplete  bool
	PeerCertificate    X509
}

func GetCertificateSubject(cert X509) string {
	name := X509_get_subject_name(cert)
	bio := BIO_new(BIO_s_mem())
	X509_NAME_print(bio, name, ' ')
	buf := make([]byte, 4096)
	n := BIO_read(bio, buf)
	if n > 0 {
		return string(buf[:n])
	}
	return ""
}

func GetCertificateIssuer(cert X509) string {
	name := X509_get_issuer_name(cert)
	bio := BIO_new(BIO_s_mem())
	X509_NAME_print(bio, name, ' ')
	buf := make([]byte, 4096)
	n := BIO_read(bio, buf)
	if n > 0 {
		return string(buf[:n])
	}
	return ""
}

func GetSslError() string {
	bio := BIO_new(BIO_s_mem())
	ERR_print_errors(bio)
	buf := make([]byte, 1024)
	n := BIO_read(bio, buf)
	if n > 0 {
		return string(buf[:n])
	}
	return ""
}

func init() {
	//opt := 0
	//OPENSSL_init_ssl(SwigcptrUint64_t(uintptr(unsafe.Pointer(&opt))), SwigcptrOPENSSL_INIT_SETTINGS(0))
	//OPENSSL_init_crypto(SwigcptrUint64_t(uintptr(unsafe.Pointer(&opt))), SwigcptrOPENSSL_INIT_SETTINGS(0))
	sslDataIdx = SSL_get_ex_new_index(0, uintptr(0), SwigcptrCRYPTO_EX_new(0), SwigcptrCRYPTO_EX_dup(0), SwigcptrCRYPTO_EX_free(0))
	ctxDataIdx = SSL_CTX_get_ex_new_index(0, uintptr(0), SwigcptrCRYPTO_EX_new(0), SwigcptrCRYPTO_EX_dup(0), SwigcptrCRYPTO_EX_free(0))
}
