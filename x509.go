package openssl

import (
	"fmt"

	"github.com/fangdingjun/openssl/libssl"
)

func LoadPrivateKey(filename string) (libssl.EVP_PKEY, error) {
	b := libssl.BIO_new_file(filename, "r")
	key := libssl.PEM_read_bio_PrivateKey(b, libssl.SwigcptrEVP_PKEY(0), nil, 0)
	libssl.BIO_free(b)
	if key.Swigcptr() == 0 {
		return nil, fmt.Errorf("read key failed")
	}
	return key, nil
}

func LoadCertificate(filename string) (libssl.X509, error) {
	b := libssl.BIO_new_file(filename, "r")
	cert := libssl.PEM_read_bio_X509(b, libssl.SwigcptrX509(0), nil, 0)
	libssl.BIO_free(b)
	if cert.Swigcptr() == 0 {
		return nil, fmt.Errorf("read ca cert failed")
	}
	return cert, nil
}
