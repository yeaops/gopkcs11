module github.com/yeaops/gopkcs11/tools/p11tool

go 1.24.4

require (
	github.com/pkg/errors v0.9.1
	github.com/yeaops/gopkcs11 v0.0.0
)

require github.com/miekg/pkcs11 v1.1.1 // indirect

replace github.com/yeaops/gopkcs11 => ../../
