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
	return C.uint(0)
}

//export GoSslVerifyCb
func GoSslVerifyCb(preverify_ok C.int, x509_ctx uintptr) C.int {
	if globalVerifyCallback != nil {
		ret := globalVerifyCallback(int(preverify_ok), x509_ctx)
		return C.int(ret)
	}
	return C.int(1)
}

func RegisterPSKCallback(callback PSKClientCallback) {
	globalPSKClientCallback = callback
}

func RegisterCertificateCallback(callback CertificateVerifyCallback) {
	globalVerifyCallback = callback
}
