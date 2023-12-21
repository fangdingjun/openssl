openssl
=======

This is golang binding for openssl, use swig generated interface.

support SSL client, SSL server, digest(md5, sha1, sha256) and cipher(AES).


# Usage example

## SSL/TLS Client example

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


## SSL/TLS Server example


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

## Crypto example

    func md5example() {
        h := openssl.NewMD5()
        defer h.Close()

        h.Write([]byte("hello"))
        h.Flush()
        result := make([]byte, 32)
        n, err := h.Read(result)
        if err != nil {
            log.Println(err)
            return
        }
        fmt.Printf("md5 result %x\n", result[:n])
    }

    func sha256example() {
        h := openssl.NewSha256()
        defer h.Close()

        h.Write([]byte("hello"))
        h.Flush()
        result := make([]byte, 32)
        n, err := h.Read(result)
        if err != nil {
            log.Println(err)
            return
        }
        fmt.Printf("sha256 result %x\n", result[:n])
    }

    func aesExample() {
        data := []byte("hello")

        // use random key and iv
        key := make([]byte, 16)
        iv := make([]byte, 12)
        rand.Reader.Read(key)
        rand.Reader.Read(iv)

        encCipher := openssl.NewCipherEncrypt(libssl.EVP_aes_128_gcm(), key, iv)
        defer encCipher.Close()

        encCipher.Write(data)
        encCipher.Flush() // no more data to encrypt

        result := make([]byte, 20)
        n, _ := encCipher.Read(result)
        fmt.Printf("aes encrypt result %x\n", result[:n])

        decCipher := openssl.NewCipherDecrypt(libssl.EVP_aes_128_gcm(), key, iv)
        defer decCipher.Close()

        decCipher.Write(result[:n])
        decCipher.Flush() // no more data to decrypt

        result2 := make([]byte, 32)
        n, _ = decCipher.Read(result2)

        fmt.Printf("aes decrypted result: %s\n", result2[:n])
    }

WARNING: this code is not full tested, use it at your own risk!