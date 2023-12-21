package libssl

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
)

func TestReadCert(t *testing.T) {
	b := BIO_new_file("../certs/server.cert", "r")
	cert := PEM_read_bio_X509(b, SwigcptrX509(0), nil, 0)
	BIO_free(b)
	if cert.Swigcptr() == 0 {
		t.Errorf("read cert failed")
		return
	}
	b = BIO_new_file("../certs/server.key", "r")
	key := PEM_read_bio_PrivateKey(b, SwigcptrEVP_PKEY(0), nil, 0)
	BIO_free(b)
	if key.Swigcptr() == 0 {
		t.Errorf("read key failed")
		return
	}

	ctx := SSL_CTX_new(TLS_server_method())
	ret := SSL_CTX_use_PrivateKey(ctx, key)
	if ret < 0 {
		t.Errorf("set private failed")
		return
	}
	ret = SSL_CTX_use_certificate(ctx, cert)
	if ret < 0 {
		t.Errorf("set certificate failed")
		return
	}

	laddr, err := net.ResolveTCPAddr("tcp", ":0")
	if err != nil {
		t.Error(err)
		return
	}
	ln, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		client, err := ln.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		conn := client.(*net.TCPConn)
		fconn, err := conn.File()
		if err != nil {
			t.Error(err)
			return
		}
		conn.Close()
		sbio := BIO_new_fd(int(fconn.Fd()), BIO_NOCLOSE)
		bio := BIO_new_ssl(ctx, 0)
		//ssl := BIO_get_ssl(bio)
		BIO_push(bio, sbio)
		BIO_write(bio, []byte("hello\n"))
		BIO_free_all(bio)
		/*
			ssl := SSL_new(ctx)
			SSL_set_fd(ssl, int(fconn.Fd()))
			ret := SSL_accept(ssl)
			if ret < 0 {
				fmt.Printf("ssl handshake error\n")
				return
			}
			fmt.Println("server send bytes")
			SSL_write(ssl, []byte("hello\n"))
			SSL_shutdown(ssl)
			SSL_free(ssl)
		*/
		fconn.Close()
	}()
	fmt.Printf("connect to %s\n", ln.Addr().String())
	c2, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Error(err)
		return
	}
	defer c2.Close()
	state := c2.ConnectionState()
	fmt.Printf("server cert %+v\n", state.PeerCertificates[0])

	buf := make([]byte, 100)
	n, err := c2.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("received %s", buf[:n])

	SSL_CTX_free(ctx)
}
