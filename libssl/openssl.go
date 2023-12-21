package libssl

// #include <stdlib.h>
// #include <string.h>
// #cgo LDFLAGS: -lcrypto -lssl
import "C"
import "unsafe"

type PSKClientCallback func(ssl uintptr, hint string) (identity string, psk []byte)
type CertificateVerifyCallback func(preverify int, ctx uintptr) int

var globalPSKClientCallback PSKClientCallback
var globalVerifyCallback CertificateVerifyCallback

//export GoSslPskClientCbFunc
func GoSslPskClientCbFunc(_ssl uintptr, hint *C.char, identity *C.char,
	max_identity_len C.uint, psk *C.uchar, max_psk_len C.uint) C.uint {

	if globalPSKClientCallback != nil {
		_hint := C.GoString(hint)
		_identity, _psk := globalPSKClientCallback(_ssl, _hint)
		identity_ := C.CString(_identity)
		C.strcpy(identity, identity_)
		C.free(unsafe.Pointer(identity_))

		if len(_psk) > 0 {
			psk_ := C.CBytes(_psk)
			C.memcpy(unsafe.Pointer(psk), psk_, C.ulong(len(_psk)))
			C.free(psk_)
		}
		return C.uint(len(_psk))
	}
	/*

		//fmt.Printf("psk client cb\n")

		ssl := SwigcptrSSL(_ssl)
		c := SSL_get_ex_data(ssl, sslDataIdx)
		conn := (*Conn)(unsafe.Pointer(c))
		//fmt.Printf("config %+v\n", conn.config)

		identityC := C.CString(conn.config.Identity)
		defer C.free(unsafe.Pointer(identityC))

		C.strcpy(identity, identityC)

		pskC := C.CBytes(conn.config.Psk)
		defer C.free(pskC)

		C.memcpy(unsafe.Pointer(psk), pskC, C.ulong(len(conn.config.Psk)))

		return C.uint(len(conn.config.Psk))
	*/
	return C.uint(0)
}

//export GoSslVerifyCb
func GoSslVerifyCb(preverify_ok C.int, x509_ctx uintptr) C.int {
	if globalVerifyCallback != nil {
		ret := globalVerifyCallback(int(preverify_ok), x509_ctx)
		return C.int(ret)
	}
	/*
		//fmt.Printf("verify callback, preverify %d\n", preverify_ok)
		storeCtx := SwigcptrX509_STORE_CTX(x509_ctx)
		a := X509_STORE_CTX_get_ex_data(storeCtx, SSL_get_ex_data_X509_STORE_CTX_idx())

		ssl := SwigcptrSSL(a)

		c := SSL_get_ex_data(ssl, sslDataIdx)
		conn := (*Conn)(unsafe.Pointer(c))

		//fmt.Printf("config %+v\n", conn.config)

		if conn.config.InsecureSkipVerify || conn.isServer {
			return C.int(1)
		}

		if int(preverify_ok) == 0 {
			errcode := X509_STORE_CTX_get_error(storeCtx)
			fmt.Printf("certificate verify error: %s\n", X509_verify_cert_error_string(int64(errcode)))
		}
		return preverify_ok
	*/
	return C.int(1)
}

func RegisterPSKCallback(callback PSKClientCallback) {
	globalPSKClientCallback = callback
}

func RegisterCertificateCallback(callback CertificateVerifyCallback) {
	globalVerifyCallback = callback
}
