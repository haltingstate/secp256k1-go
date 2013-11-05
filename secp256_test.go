package secp256

import (
	"testing"
	"fmt"
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
	if len(seckey) != 32 {t.Fail()}
	if len(sig) != 64+1 {t.Fail()}
	if int(sig[64]) > 4 {t.Fail()} //should be 0 to 4
}

//test signing message
func Test_Secp256_02(t *testing.T) { 
	_,seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	ret := VerifySignature(msg, sig)
	if ret != 1 {  t.Fatal("Signature invalid") }
}

//test pubkey recovery
func Test_Secp256_02a(t *testing.T) { 
	pubkey1,seckey1 := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey1)
	ret := VerifySignature(msg, sig)
	if ret != 1 {  t.Fatal("Signature invalid") }

	pubkey2 := RecoverPubkey(msg, sig)
	if len(pubkey1) != len(pubkey2) {t.Fatal()}
	for i,_ := range pubkey1 { 
		if pubkey1[i] != pubkey2[i] {
			t.Fatal()
		} 
	}
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

//test random signatures against fixed messages; should fail

//crashes: 
//	-SIPA look at this


func Test_Secp256_06a(t *testing.T) { 
	_,seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	for i:=0; i<TESTS; i++ {
		sig = RandByte(len(sig))
		//sig[len(sig)-1] %= 4
		ret := VerifySignature(msg, sig)
		if ret == 1 { t.FailNow()}
	}
}


//test random messages against valid signature: should fail
//crashes
// -SIPA look at this

/*
--- FAIL: Test_Secp256_06b (2.08 seconds)
secp256.test: /home/atomos/secp256/./secp256k1/src/impl/num_gmp.h:55: secp256k1_num_get_bin: Assertion `len-shift <= rlen' failed.
SIGABRT: abort
PC=0x7fe6237def77
signal arrived during cgo execution
*/


func Test_Secp256_06b(t *testing.T) { 
	_,seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)

	fail_count := 0
	for i:=0; i<TESTS; i++ {
		msg = RandByte(32)
		ret := VerifySignature(msg, sig)
		if ret == 1 { 
			fail_count++;
			t.FailNow()
		}
	}
	if fail_count != 0 {
		fmt.Printf("ERROR: Accepted signature for %v of %v random messages\n", fail_count, TESTS)
	}
}


//test random messages against random signatures: should fail

func Test_Secp256_06c(t *testing.T) { 
	fail_count := 0
	for i:=0; i<TESTS; i++ {
		sig := RandByte(65)
		sig[64] %= 4; 
		msg := RandByte(32)
		ret := VerifySignature(msg, sig)
		if ret == 1 { 
			fail_count++;
			t.FailNow()
		}
	}
	if fail_count != 0 {
		fmt.Printf("ERROR: Accepted signature for %v of %v random messages\n", fail_count, TESTS)
	}
}
