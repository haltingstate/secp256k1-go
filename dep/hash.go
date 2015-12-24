package secp256k1

import (
	//"crypto/sha256"
	//"encoding/hex"
	//"errors"
	"hash"
	//"log"

	"github.com/skycoin/skycoin/src/cipher/ripemd160"
)

var (
	//sha256Hash    hash.Hash = sha256.New()
	ripemd160Hash hash.Hash = ripemd160.New()
)

// Ripemd160

func _HashRipemd160(data []byte) []byte {
	ripemd160Hash.Reset()
	ripemd160Hash.Write(data)
	sum := ripemd160Hash.Sum(nil)
	return sum
}

// SHA256

// Double SHA256
func _DoubleSHA256(b []byte) []byte {
	//h := SumSHA256(b)
	//return AddSHA256(h, h)
	h1 := SumSHA256(b)
	h2 := SumSHA256(h1[:])
	return h2
}
