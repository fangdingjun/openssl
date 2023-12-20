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

	//fmt.Printf("psk client cb\n")

	ssl := SwigcptrSSL(_ssl)
	c := SSL_get_ex_data(ssl, sslDataIdx)
	conn := (*Conn)(unsafe.Pointer(c))
	//fmt.Printf("config %+v\n", conn.config)

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
	//fmt.Printf("verify callback, preverify %d\n", preverify_ok)
	storeCtx := SwigcptrX509_STORE_CTX(x509_ctx)
	a := X509_STORE_CTX_get_ex_data(storeCtx, SSL_get_ex_data_X509_STORE_CTX_idx())

	ssl := SwigcptrSSL(a)

	c := SSL_get_ex_data(ssl, sslDataIdx)
	conn := (*Conn)(unsafe.Pointer(c))

	//fmt.Printf("config %+v\n", conn.config)

	if conn.config.InsecureSkipVerify || conn.isServer {
		return C.int(1)
	}

	if int(preverify_ok) == 0 {
		errcode := X509_STORE_CTX_get_error(storeCtx)
		fmt.Printf("certificate verify error: %s\n", X509_verify_cert_error_string(int64(errcode)))
	}
	return preverify_ok
}

var sslDataIdx = 0
var ctxDataIdx = 0

// Config tls config
type Config struct {
	// ServerName server sni name
	ServerName string

	// private key to use
	PrivateKey EVP_PKEY

	// ALPN names
	NextProtos []string

	// certificate to use
	Certificate X509

	// psk identity used in psk mode
	Identity string

	// the pre-shared key used in psk mode, this field set will enable psk mode
	Psk []byte

	// skip verify server certificate
	InsecureSkipVerify bool

	// additional root ca to use
	RootCA X509

	ClientCA X509

	// verify client or not
	ClientAuth int
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
	//fmt.Printf("accept connection from %s\n", conn.RemoteAddr())
	c := &Conn{c: conn, config: l.config}
	if err := c.setupServer(); err != nil {
		fmt.Printf("set server error %s\n", err)
		conn.Close()
		return nil, err
	}
	//fmt.Printf("setup tls finished\n")
	return c, nil
}

func (l *listener) Addr() net.Addr {
	return l.ln.Addr()
}

func (l *listener) Close() error {
	return l.ln.Close()
}

// Listen create a listener, when accept, auto create a tls context for the new connection
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

// NewListener create listener with exists listener and config
func NewListener(inner net.Listener, config *Config) net.Listener {
	ln := &listener{ln: inner, config: config}
	return ln
}

// Conn a tls connection
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

// Client initail a tls client use exists connection conn and config
func Client(conn net.Conn, config *Config) *Conn {
	tcpconn, ok := conn.(*net.TCPConn)
	if !ok {
		panic("only tcp connection supported")
		//return nil
	}
	fconn, _ := tcpconn.File()

	ctx := SSL_CTX_new(TLS_client_method())
	SSL_CTX_set_default_verify_paths(ctx)

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

// Dial create a connection to addr and intial the tls context
func Dial(network, addr string, config *Config) (*Conn, error) {
	ctx := SSL_CTX_new(TLS_client_method())
	SSL_CTX_set_default_verify_paths(ctx)

	bio := BIO_new_ssl_connect(ctx)
	BIO_set_conn_hostname(bio, addr)
	//BIO_set_ssl_mode(bio, 1)
	ssl := BIO_get_ssl(bio)

	c := &Conn{
		ctx: ctx, bio: bio,
		config: config,
		ssl:    ssl,
	}
	c.setupClient()
	return c, nil
}

// Server create tls context for server use exists connection conn
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

	if c.config.ClientAuth > 0 {
		//fmt.Printf("server set client auth\n")
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, MY_ssl_verify_cb)
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
		//fmt.Printf("client set certificate\n")
		SSL_use_PrivateKey(c.ssl, c.config.PrivateKey)
		SSL_use_certificate(c.ssl, c.config.Certificate)
	}

	if c.config.RootCA != nil {
		store := SSL_CTX_get_cert_store(c.ctx)
		if store.Swigcptr() != uintptr(0) {
			//fmt.Printf("add custom ca\n")
			ret := X509_STORE_add_cert(store, c.config.RootCA)
			if ret < 0 {
				fmt.Printf("add root cert failed %s\n", GetSslError())
			}
		} else {
			fmt.Printf("get cert store failed\n")
		}
	}

	SSL_set_verify(c.ssl, SSL_VERIFY_PEER, MY_ssl_verify_cb)
	SSL_set_verify_depth(c.ssl, 4)
	SSL_CTX_set_ex_data(c.ctx, ctxDataIdx, uintptr(unsafe.Pointer(c)))
	SSL_set_ex_data(c.ssl, sslDataIdx, uintptr(unsafe.Pointer(c)))
	return nil
}

// Handshake perform the tls handshake
func (c *Conn) Handshake() error {
	val := atomic.LoadInt64(&c.handshakeComplete)
	if val > 0 {
		return nil
	}
	ret := BIO_do_handshake(c.bio)
	if ret <= 0 {
		return fmt.Errorf("handshake error %s", GetSslError())
	}
	atomic.StoreInt64(&c.handshakeComplete, 1)
	return nil
}

// Read read data from tls conn
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

// Write write data through tls conn
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

// Close close the tls connection
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

// RemoteAddr get the remote addr
func (c *Conn) RemoteAddr() net.Addr {
	if c.c != nil {
		return c.c.RemoteAddr()
	}
	return &net.TCPAddr{}
}

// LocalAddr get local addr
func (c *Conn) LocalAddr() net.Addr {
	if c.c != nil {
		return c.c.LocalAddr()
	}
	return &net.TCPAddr{}
}

// SetDeadline set the dead line
func (c *Conn) SetDeadline(t time.Time) error {
	return fmt.Errorf("not implement")
}

// SetReadDeadline set the read dead line
func (c *Conn) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("not implement")
}

// SetWriteDeadline set the write dead line
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("not implement")
}

// ConnectionState get connection state
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

// ConnectionState connection state
type ConnectionState struct {
	NegotiatedProtocol string
	HandshakeComplete  bool
	PeerCertificate    X509
}

// GetCertificateSubject get the subject from x509 certificate
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

// GetCertificateIssuer get the issuer subject from x509 certificate
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

// GetSslError get the current ssl error
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
