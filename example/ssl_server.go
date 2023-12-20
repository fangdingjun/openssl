package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/fangdingjun/openssl"
)

func handleConn(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Println(err)
		return
	}

	// dump request to console
	req.Write(os.Stdout)

	// custom a http response
	res := &http.Response{}

	res.Header = make(http.Header)
	res.Header.Add("x-custom-header", "aaa")
	res.Header.Add("server", "openssl_server/1.0")

	responseText := "hello, world\n"

	res.Header.Add("content-type", "text/plain")
	res.Header.Add("content-length", fmt.Sprintf("%d", len(responseText)))

	res.StatusCode = 200
	res.ProtoMajor = 1
	res.ProtoMinor = 1

	body := strings.NewReader(responseText)
	res.Body = io.NopCloser(body)

	res.Write(conn)
}

func main() {
	key, err := openssl.LoadPrivateKey("../certs/server.key")
	if err != nil {
		log.Fatal(err)
	}
	cert, err := openssl.LoadCertificate("../certs/server.cert")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := openssl.Listen("tcp", ":7777", &openssl.Config{
		Certificate: cert,
		PrivateKey:  key,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			break
		}
		go handleConn(conn)
	}
}
