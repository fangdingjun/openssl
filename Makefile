all: gen build

gen: openssl.go

openssl.go: bio.i evp.i openssl.i ssl_typemaps.i ssl.i x509.i
	swig -go -intgosize 64 openssl.i

build: 
	go build