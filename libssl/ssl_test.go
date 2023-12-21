package libssl

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestConnect(t *testing.T) {
	ctx := SSL_CTX_new(TLS_client_method())
	defer SSL_CTX_free(ctx)

	ssl := SSL_new(ctx)

	defer SSL_free(ssl)

	raddr, err := net.ResolveTCPAddr("tcp", "httpbin.org:443")
	if err != nil {
		t.Fatal(err)
	}

	conn, err := net.DialTCP("tcp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fconn, err := conn.File()
	if err != nil {
		t.Fatal(err)
	}
	defer fconn.Close()

	SSL_set_fd(ssl, int(fconn.Fd()))
	ret := SSL_connect(ssl)
	if ret < 0 {
		t.Errorf("connet error %d", ret)
		return
	}

	defer SSL_shutdown(ssl)

	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "GET /get HTTP/1.1\r\n")
	fmt.Fprintf(buf, "Host: httpbin.org\r\n")
	fmt.Fprintf(buf, "connection: close\r\n")
	fmt.Fprintf(buf, "user-agent: go-openssl/1.0\r\n")
	fmt.Fprintf(buf, "a: b\r\n")
	fmt.Fprintf(buf, "b: c\r\n")
	fmt.Fprintf(buf, "\r\n")

	SSL_write(ssl, buf.Bytes())
	buf1 := make([]byte, 1024)
	for {
		ret := SSL_read(ssl, buf1)
		if ret <= 0 {
			break
		}
		fmt.Printf("%s", buf1[:ret])
	}

}

func TestBioSSL(t *testing.T) {

}
