package main

import (
	"bufio"
	"log"
	"net/http"
	"os"

	"github.com/fangdingjun/openssl"
)

func main() {
	conn, err := openssl.Dial("tcp", "httpbin.org:443", &openssl.Config{
		ServerName:         "httpbin.org",
		InsecureSkipVerify: false,
	})
	if err != nil {
		log.Fatalf("connect failed %s", err)
	}
	defer conn.Close()

	req, _ := http.NewRequest("GET", "https://httpbin.org/get?key1=value1&key2=value2", nil)
	req.Header.Add("x-cusom-header1", "hello")
	req.Header.Add("connection", "close")

	req.Write(os.Stdout)
	req.Write(conn)

	bufio := bufio.NewReader(conn)
	resp, err := http.ReadResponse(bufio, req)
	if err != nil {
		log.Fatalf("read response failed %#v", err)
	}
	resp.Write(os.Stdout)
}
