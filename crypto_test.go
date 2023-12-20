package openssl

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"testing"
)

func TestMD5(t *testing.T) {
	data := []byte("hello")

	h1 := md5.New()
	h1.Write(data)
	hash1 := h1.Sum(nil)
	fmt.Printf("%x\n", hash1[:])

	h2 := NewMD5()
	defer h2.Close()
	h2.Write(data)
	h2.Flush()

	buf := make([]byte, 100)
	n, err := h2.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("%x\n", buf[:n])

	if !bytes.Equal(hash1[:], buf[:n]) {
		t.Errorf("not equal %x != %x", hash1, buf[:n])
	}
}

func TestSha1(t *testing.T) {
	data := []byte("hello")

	h1 := sha1.New()
	h1.Write(data)
	hash1 := h1.Sum(nil)
	fmt.Printf("%x\n", hash1[:])

	h2 := NewSha1()
	defer h2.Close()
	h2.Write(data)
	buf := make([]byte, 100)
	n, err := h2.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("%x\n", buf[:n])

	if !bytes.Equal(hash1[:], buf[:n]) {
		t.Errorf("not equal %x != %x", hash1, buf[:n])
	}
}

func TestSha256(t *testing.T) {
	data := []byte("hello")

	h1 := sha256.New()
	h1.Write(data)
	hash1 := h1.Sum(nil)
	fmt.Printf("%x\n", hash1[:])

	h2 := NewSha256()
	defer h2.Close()
	h2.Write(data)
	buf := make([]byte, 100)
	n, err := h2.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("%x\n", buf[:n])

	if !bytes.Equal(hash1[:], buf[:n]) {
		t.Errorf("not equal %x != %x", hash1, buf[:n])
	}
}

func TestSha512(t *testing.T) {
	data := []byte("hello")

	h1 := sha512.New()
	h1.Write(data)
	hash1 := h1.Sum(nil)
	fmt.Printf("%x\n", hash1[:])

	h2 := NewSha512()
	defer h2.Close()

	h2.Write(data)
	buf := make([]byte, 100)
	n, err := h2.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("%x\n", buf[:n])

	if !bytes.Equal(hash1[:], buf[:n]) {
		t.Errorf("not equal %x != %x", hash1, buf[:n])
	}
}

func TestAesGCM(t *testing.T) {
	key := make([]byte, 16)
	iv := make([]byte, 12)
	data := make([]byte, 10)
	//data := []byte("hello")

	cp := EVP_aes_128_gcm()

	rand.Reader.Read(key)
	rand.Reader.Read(iv)
	rand.Reader.Read(data)
	c1 := NewCipherEncrypt(cp, key, iv)
	defer c1.Close()
	_, err := c1.Write(data)
	if err != nil {
		t.Error(err)
		return
	}
	err = c1.Flush()
	if err != nil {
		t.Error(err)
		return
	}

	buf := make([]byte, 100)
	n, err := c1.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("after encrypt %x %d\n", buf[:n], n)

	c2 := NewCipherDecrypt(cp, key, iv)
	defer c2.Close()
	_, err = c2.Write(buf[:n])
	if err != nil {
		t.Error(err)
		return
	}
	err = c2.Flush()
	if err != nil {
		t.Error(err)
		return
	}

	buf1 := make([]byte, 100)
	n, err = c2.Read(buf1)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(data, buf1[:n]) {
		t.Errorf("encrypt and decrypt failed, not equal")
	}
}
