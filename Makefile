all: gen build

gen:
	${MAKE} -C libssl

build: 
	go build