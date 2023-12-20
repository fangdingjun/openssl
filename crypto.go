package openssl

import (
	"fmt"
	"io"
)

type hashMethod struct {
	bio BIO
}

type HASH interface {
	io.ReadWriteCloser
	Flush() error
}

var _ HASH = &hashMethod{}

func (h *hashMethod) Write(data []byte) (int, error) {
	n := BIO_write(h.bio, data)
	if n < 0 {
		return 0, fmt.Errorf("write error %s", GetSslError())
	}
	return n, nil
}

func (h *hashMethod) Read(data []byte) (int, error) {
	n := BIO_gets(h.bio, data)
	if n < 0 {
		return 0, fmt.Errorf("read error %s", GetSslError())
	}
	return n, nil
}

func (h *hashMethod) Close() error {
	BIO_free_all(h.bio)
	return nil
}

func (h *hashMethod) Flush() error {
	BIO_flush(h.bio)
	return nil
}

func createHash(md EVP_MD, size int) *hashMethod {
	h := &hashMethod{}
	if md.Swigcptr() == uintptr(0) {
		panic("create md5 method failed")
	}
	h.bio = BIO_new(BIO_f_md())
	if h.bio.Swigcptr() == uintptr(0) {
		panic("create bio failed")
	}
	ret := BIO_set_md(h.bio, md)
	if ret < 0 {
		panic(GetSslError())
	}
	BIO_push(h.bio, BIO_new(BIO_s_null()))

	return h
}

// NewMD5 create a md5 hash instance
func NewMD5() HASH {
	return createHash(EVP_md5(), 16)
}

// NewSha1 create a sha1 hash instance
func NewSha1() HASH {
	return createHash(EVP_sha1(), 24)
}

// NewSha256 create a sha256 hash instance
func NewSha256() HASH {
	return createHash(EVP_sha256(), 32)
}

// NewSha512 create a sha512 hash instance
func NewSha512() HASH {
	return createHash(EVP_sha512(), 64)
}

type cipherMethod struct {
	bio BIO
	out BIO
}

func (c *cipherMethod) Write(data []byte) (int, error) {
	n := BIO_write(c.bio, data)
	if n <= 0 {
		return 0, fmt.Errorf("write error %s", GetSslError())
	}
	return n, nil
}

func (c *cipherMethod) Read(data []byte) (int, error) {
	n := BIO_read(c.out, data)
	if n <= 0 {
		return 0, fmt.Errorf("read error %s", GetSslError())
	}
	return n, nil
}

func (c *cipherMethod) Flush() error {
	ret := BIO_flush(c.bio)
	if ret < 0 {
		return fmt.Errorf("flush error %s", GetSslError())
	}
	return nil
}

func (c *cipherMethod) Close() error {
	BIO_free_all(c.bio)
	return nil
}

type Cipher interface {
	io.ReadWriteCloser
	Flush() error
}

// NewCipherEncrypt create a encrypt cipher with cipher md with key and iv,
// key and iv size must match the cipher md.
//
// use Write() write the plaintext to cipher.
//
// Read() get the ciphertext.
//
// Flush() signal no more data to cipher.
//
// Close() free the resource.
func NewCipherEncrypt(md EVP_CIPHER, key, iv []byte) Cipher {
	keylen := EVP_CIPHER_key_length(md)
	ivlen := EVP_CIPHER_iv_length(md)
	if len(key) != keylen {
		panic(fmt.Sprintf("invalid key length, expected %d, got %d", keylen, len(key)))
	}
	if len(iv) != ivlen {
		panic(fmt.Sprintf("invalid iv length, expected %d, got %d", ivlen, len(iv)))
	}
	bio := BIO_new(BIO_f_cipher())
	BIO_set_cipher(bio, md, key, iv, 1)
	out := BIO_new(BIO_s_mem())
	BIO_push(bio, out)
	c := &cipherMethod{bio: bio, out: out}
	return c
}

// NewCipherDecrypt create a decrypt cipher with cipher md with key and iv,
// key and iv size must match the cipher md.
//
// Write() write the ciphertext to cipher.
//
// Read() get the plaintext.
//
// Flush() signal no more data to cipher.
//
// Close() free the resource.
func NewCipherDecrypt(md EVP_CIPHER, key, iv []byte) Cipher {
	keylen := EVP_CIPHER_key_length(md)
	ivlen := EVP_CIPHER_iv_length(md)
	if len(key) != keylen {
		panic(fmt.Sprintf("invalid key length, expected %d, got %d", keylen, len(key)))
	}
	if len(iv) != ivlen {
		panic(fmt.Sprintf("invalid iv length, expected %d, got %d", ivlen, len(iv)))
	}
	bio := BIO_new(BIO_f_cipher())
	BIO_set_cipher(bio, md, key, iv, 0)
	out := BIO_new(BIO_s_mem())
	BIO_push(bio, out)
	c := &cipherMethod{bio: bio, out: out}
	return c
}
