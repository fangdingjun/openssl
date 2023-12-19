package openssl

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
)

func startTLSServerGo(config *tls.Config, handler func(c net.Conn) error) (addr string, closefunc func(), err error) {
	ln, err := tls.Listen("tcp", ":0", config)
	if err != nil {
		return "", nil, err
	}
	//defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				fmt.Println(err)
				return
			}
			go handler(conn)
		}
	}()
	a := func() {
		fmt.Printf("close listener\n")
		ln.Close()
	}
	return ln.Addr().String(), a, nil
}

func startTLSServerOpenssl(config *Config, handler func(c net.Conn) error) (addr string, closefunc func(), err error) {
	ln, err := Listen("tcp", ":0", config)
	if err != nil {
		return "", nil, err
	}
	//defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				fmt.Println(err)
				return
			}
			go handler(conn)
		}
	}()
	a := func() {
		fmt.Printf("close listener\n")
		ln.Close()
	}
	return ln.Addr().String(), a, nil
}

func TestConnDial(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("./client.cert", "./client.key")
	if err != nil {
		t.Fatal(err)
	}
	addr, closeFunc, err := startTLSServerGo(
		&tls.Config{Certificates: []tls.Certificate{cert}},
		func(c net.Conn) error {
			defer c.Close()
			buf := make([]byte, 1024)
			n, err := c.Read(buf)
			if err != nil {
				fmt.Println(err)
				return err
			}
			c.Write(buf[:n])
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFunc()

	fmt.Printf("dial to %s\n", addr)
	conn, err := Dial("tcp", addr, &Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()
	_, err = conn.Write([]byte("hello\n"))
	if err != nil {
		t.Error(err)
		return
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("received %s", buf[:n])
}

func TestConnClient(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("./client.cert", "./client.key")
	if err != nil {
		t.Fatal(err)
	}
	addr, closeFunc, err := startTLSServerGo(
		&tls.Config{Certificates: []tls.Certificate{cert}},
		func(c net.Conn) error {
			defer c.Close()
			buf := make([]byte, 1024)
			n, err := c.Read(buf)
			if err != nil {
				fmt.Println(err)
				return err
			}
			c.Write(buf[:n])
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFunc()

	fmt.Printf("dial to %s\n", addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	client := Client(conn, &Config{
		InsecureSkipVerify: true,
	})
	_, err = client.Write([]byte("hello\n"))
	if err != nil {
		t.Error(err)
		return
	}
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("received %s", buf[:n])
}

func TestConnAlpn(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("./client.cert", "./client.key")
	if err != nil {
		t.Fatal(err)
	}
	addr, closeFunc, err := startTLSServerGo(
		&tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h1", "h2"},
		},
		func(c net.Conn) error {
			defer c.Close()
			buf := make([]byte, 1024)
			n, err := c.Read(buf)
			if err != nil {
				fmt.Println(err)
				return err
			}
			c.Write(buf[:n])
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFunc()

	fmt.Printf("dial to %s\n", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Error(err)
		return
	}
	defer conn.Close()

	client := Client(conn, &Config{
		NextProtos:         []string{"h1", "h3"},
		InsecureSkipVerify: true,
	})
	if err := client.Handshake(); err != nil {
		t.Error(err)
		return
	}
	state := client.ConnectionState()
	fmt.Printf("%+v\n", state)
	fmt.Printf("certificate, issuer %s, subject %s\n",
		GetCertificateIssuer(state.PeerCertificate),
		GetCertificateSubject(state.PeerCertificate))
	if state.NegotiatedProtocol != "h1" {
		t.Error("alpn test failed")
		return
	}
	_, err = client.Write([]byte("hello\n"))
	if err != nil {
		t.Errorf("%s\n", err)
		return
	}
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("received %s", buf[:n])
}

func TestSSLConn(t *testing.T) {
	b := BIO_new_file("./client.cert", "r")
	cert := PEM_read_bio_X509(b, SwigcptrX509(0), nil, 0)
	BIO_free(b)
	if cert.Swigcptr() == 0 {
		t.Errorf("read cert failed")
		return
	}
	b = BIO_new_file("./client.key", "r")
	key := PEM_read_bio_PrivateKey(b, SwigcptrEVP_PKEY(0), nil, 0)
	BIO_free(b)
	if key.Swigcptr() == 0 {
		t.Errorf("read key failed")
		return
	}

	addr, closeFunc, err := startTLSServerOpenssl(&Config{PrivateKey: key, Certificate: cert}, func(c net.Conn) error {
		defer c.Close()

		fmt.Printf("connected\n")

		buf := make([]byte, 1024)
		n, err := c.Read(buf)
		if err != nil {
			fmt.Printf("read %s\n", err)
			return err
		}
		c.Write(buf[:n])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFunc()

	conn, err := Dial("tcp", addr, &Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("receive %s\n", buf[:n])

}
