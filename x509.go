package openssl

import "fmt"

func LoadPrivateKey(filename string) (EVP_PKEY, error) {
	b := BIO_new_file(filename, "r")
	key := PEM_read_bio_PrivateKey(b, SwigcptrEVP_PKEY(0), nil, 0)
	BIO_free(b)
	if key.Swigcptr() == 0 {
		return nil, fmt.Errorf("read key failed")
	}
	return key, nil
}

func LoadCertificate(filename string) (X509, error) {
	b := BIO_new_file(filename, "r")
	cert := PEM_read_bio_X509(b, SwigcptrX509(0), nil, 0)
	BIO_free(b)
	if cert.Swigcptr() == 0 {
		return nil, fmt.Errorf("read ca cert failed")
	}
	return cert, nil
}
