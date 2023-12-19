all: gen build

gen:
	swig -I/usr/include -go -intgosize 64 openssl.i

build:
	go build