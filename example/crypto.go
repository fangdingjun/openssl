package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/fangdingjun/openssl"
)

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

	encCipher := openssl.NewCipherEncrypt(openssl.EVP_aes_128_gcm(), key, iv)
	defer encCipher.Close()

	encCipher.Write(data)
	encCipher.Flush() // no more data to encrypt

	result := make([]byte, 20)
	n, _ := encCipher.Read(result)
	fmt.Printf("aes encrypt result %x\n", result[:n])

	decCipher := openssl.NewCipherDecrypt(openssl.EVP_aes_128_gcm(), key, iv)
	defer decCipher.Close()

	decCipher.Write(result[:n])
	decCipher.Flush() // no more data to decrypt

	result2 := make([]byte, 32)
	n, _ = decCipher.Read(result2)

	fmt.Printf("aes decrypted result: %s\n", result2[:n])
}

func main() {
	md5example()
	sha256example()
	aesExample()
}
