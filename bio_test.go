package openssl

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"
)

func TestBioConnect(t *testing.T) {
	b := BIO_new_connect("httpbin.org:80")

	req, _ := http.NewRequest("GET", "http://httpbin.org/get", nil)
	req.Header.Add("a", "b")
	req.Header.Add("c", "d")
	req.Header.Add("connection", "close")

	buf := new(bytes.Buffer)
	req.Write(buf)

	BIO_write(b, buf.Bytes())
	buf1 := make([]byte, 1024)

	for {
		n := BIO_read(b, buf1)
		if n <= 0 {
			break
		}
		fmt.Printf("%s", buf1[:n])
	}
	BIO_free(b)
}
