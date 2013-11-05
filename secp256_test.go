package secp256

import (
	"testing"
	//"fmt"
)

const TESTS   = 10000 // how many tests
const SigSize = 65 //64+1


func Test_Secp256_00(t *testing.T) {

    var nonce []byte = RandByte(32) //going to get bitcoins stolen!

	if len(nonce) != 32 {t.Fatal()}

}

//test pubkey/private generation
func Test_Secp256_01(t *testing.T) { 
	pubkey,seckey := GenerateKeyPair()
	if VerifySeckey(seckey) != 1 { t.Fatal()}
	if VerifyPubkey(pubkey) != 1 { t.Fatal()}
}

//test size of messages
func Test_Secp256_02s(t *testing.T) { 
	pubkey,seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	if len(pubkey) != 33 {t.Fail()}
	if lent(seckey) != 32 {t.Fail()}
	if len(sig) != 32 {t.Fail()}
}

//test signing message
func Test_Secp256_02(t *testing.T) { 
	_,seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	ret := VerifySignature(msg, sig)
	if ret != 1 {  t.Fatal("Signature invalid") }
}


//test random messages for the same pub/private key
func Test_Secp256_03(t *testing.T) { 
	_,seckey := GenerateKeyPair()
	for i:=0; i<TESTS; i++ {
		msg := RandByte(32)
		sig := Sign(msg, seckey)
		ret := VerifySignature(msg, sig)
		if ret != 1 {  t.Fail() }
	}
}

//test random messages for different pub/private keys
func Test_Secp256_04(t *testing.T) { 
	for i:=0; i<TESTS; i++ {
		_,seckey := GenerateKeyPair()
		msg := RandByte(32)
		sig := Sign(msg, seckey)
		ret := VerifySignature(msg, sig)
		if ret != 1 {  t.Fail() }
	}
}

//test random signatures that should fail

//crashes
func Test_Secp256_05(t *testing.T) { 
	_,seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	for i:=0; i<TESTS; i++ {
		sig = RandByte(len(sig))
		//sig[len(sig)-1] %= 4
		ret := VerifySignature(msg, sig)
		if ret == 1 { t.Fail()}
	}
}


//test random messages that should fail
func Test_Secp256_06(t *testing.T) { 
	_,seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	for i:=0; i<TESTS; i++ {
		msg = RandByte(32)
		ret := VerifySignature(msg, sig)
		if ret == 1 { t.Fail()}
	}
}