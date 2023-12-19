package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	cadata, err := os.ReadFile("ca.key")
	if err != nil {
		log.Fatal(err)
	}
	cablock, _ := pem.Decode(cadata)
	caKey, err := x509.ParsePKCS1PrivateKey(cablock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now()

	caTmpl := &x509.Certificate{
		NotBefore:    now,
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ca"},
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		log.Fatal(err)
	}
	d := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err = os.WriteFile("ca.cert", d, 0644); err != nil {
		log.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		log.Fatal(err)
	}

	clientdata, err := os.ReadFile("client.key")
	if err != nil {
		log.Fatal(err)
	}
	clientBlock, _ := pem.Decode(clientdata)

	clientKey, err := x509.ParsePKCS1PrivateKey(clientBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	clientTmpl := &x509.Certificate{
		NotBefore:    now,
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "client"},
		IsCA:         false,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost", "example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	clientBytes, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, clientKey.Public(), caKey)
	if err != nil {
		log.Fatal(err)
	}
	p2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientBytes})
	if err := os.WriteFile("client.cert", p2, 0644); err != nil {
		log.Fatal(err)
	}

	serverdata, err := os.ReadFile("server.key")
	if err != nil {
		log.Fatal(err)
	}

	serverBlock, _ := pem.Decode(serverdata)
	serverKey, err := x509.ParsePKCS1PrivateKey(serverBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	serverTmpl := &x509.Certificate{
		NotBefore:    now,
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour),
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "server"},
		IsCA:         false,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "example.com"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	serverBytes, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, serverKey.Public(), caKey)
	if err != nil {
		log.Fatal(err)
	}
	p3 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverBytes})
	if err := os.WriteFile("server.cert", p3, 0644); err != nil {
		log.Fatal(err)
	}
}
