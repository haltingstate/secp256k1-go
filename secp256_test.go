package secp256k1

import (
	"bytes"
	"log"
	"testing"
)

const TESTS = 10000 // how many tests
const SigSize = 65  //64+1

func Test_GenerateKeyPair(t *testing.T) {
	pub, pri := GenerateKeyPair()
	if pub == nil || pri == nil {
		t.Fail()
	}
}

func Test_Secp256_00(t *testing.T) {

	var nonce []byte = RandByte(32) //going to get bitcoins stolen!

	if len(nonce) != 32 {
		t.Fatal()
	}

}

//tests for Malleability
//highest bit of S must be 0; 32nd byte
func CompactSigTest(sig []byte) {

	var b int = int(sig[32])
	if b < 0 {
		log.Panic()
	}
	if ((b >> 7) == 1) != ((b & 0x80) == 0x80) {
		log.Panic("b= %v b2= %v \n", b, b>>7)
	}
	if (b & 0x80) == 0x80 {
		log.Panic("b= %v b2= %v \n", b, b&0x80)
	}
}

//test pubkey/private generation
func Test_Secp256_01(t *testing.T) {
	pubkey, seckey := GenerateKeyPair()
	if VerifySeckeyValidity(seckey) != 1 {
		t.Fatal()
	}
	if VerifyPubkeyValidity(pubkey) != 1 {
		t.Fatal()
	}
}

//test size of messages
func Test_Secp256_02s(t *testing.T) {
	pubkey, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig, err := Sign(msg, seckey)
	if err != nil {
		t.Fatal(err.Error())
	}
	CompactSigTest(sig)
	if sig == nil {
		t.Fatal("Signature nil")
	}
	if len(pubkey) != 33 {
		t.Fail()
	}
	if len(seckey) != 32 {
		t.Fail()
	}
	if len(sig) != 64+1 {
		t.Fail()
	}
	if int(sig[64]) > 4 {
		t.Fail()
	} //should be 0 to 4
}

//test signing message
func Test_Secp256_02(t *testing.T) {
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig, err := Sign(msg, seckey)
	if err != nil {
		t.Fatal(err.Error())
	}
	if sig == nil {
		t.Fatal("Signature nil")
	}

	pubkey2, err := RecoverPubkey(msg, sig)
	if err != nil {
		t.Fatal(err.Error())
	}
	if pubkey2 == nil {
		t.Fatal("Recovered pubkey invalid")
	}
	if !bytes.Equal(pubkey1, pubkey2) {
		t.Fatal("Recovered pubkey does not match")
	}

	err = VerifySignature(msg, sig, pubkey1)
	if err != nil {
		t.Logf("Signature invalid: %v", err)
		t.FailNow()
	}
}

//test pubkey recovery
func Test_Secp256_02a(t *testing.T) {
	pubkey1, seckey1 := GenerateKeyPair()
	msg := RandByte(32)
	sig, err := Sign(msg, seckey1)
	if err != nil {
		t.Fatal(err.Error())
	}
	if sig == nil {
		t.Fatal("Signature nil")
	}

	err = VerifySignature(msg, sig, pubkey1)
	if err != nil {
		t.Logf("Signature invalid: %v", err)
		t.FailNow()
	}

	pubkey2, err := RecoverPubkey(msg, sig)
	if err != nil {
		t.Fatal(err.Error())
	}
	if len(pubkey1) != len(pubkey2) {
		t.Fatal()
	}
	for i, _ := range pubkey1 {
		if pubkey1[i] != pubkey2[i] {
			t.Fatal()
		}
	}
	if !bytes.Equal(pubkey1, pubkey2) {
		t.Fatal()
	}
}

//test random messages for the same pub/private key
func Test_Secp256_03(t *testing.T) {
	_, seckey := GenerateKeyPair()
	for i := 0; i < TESTS; i++ {
		msg := RandByte(32)
		sig, err := Sign(msg, seckey)
		if err != nil {
			t.Fatal(err.Error())
		}
		CompactSigTest(sig)

		sig[len(sig)-1] %= 4
		pubkey2, err := RecoverPubkey(msg, sig)
		if err != nil {
			t.Fail()
		}
		if pubkey2 == nil {
			t.Fail()
		}
	}
}

//test random messages for different pub/private keys
func Test_Secp256_04(t *testing.T) {
	for i := 0; i < TESTS; i++ {
		pubkey1, seckey := GenerateKeyPair()
		msg := RandByte(32)
		sig, err := Sign(msg, seckey)
		if err != nil {
			t.Fatal(err.Error())
		}
		CompactSigTest(sig)

		if sig[len(sig)-1] >= 4 {
			t.Fail()
		}
		pubkey2, err := RecoverPubkey(msg, sig)
		if err != nil {
			t.Fail()
		}
		if pubkey2 == nil {
			t.Fail()
		}
		if !bytes.Equal(pubkey1, pubkey2) {
			t.Fail()
		}
	}
}

//test random signatures against fixed messages; should fail

//crashes:
//	-SIPA look at this

func randSig() []byte {
	sig := RandByte(65)
	sig[32] &= 0x70
	sig[64] %= 4
	return sig
}

func Test_Secp256_06a_alt0(t *testing.T) {
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig, err := Sign(msg, seckey)
	if err != nil {
		t.Fatal(err.Error())
	}
	if sig == nil {
		t.Fatal()
	}
	if len(sig) != 65 {
		t.Fatal()
	}

	for i := 0; i < TESTS; i++ {
		sig = randSig()
		pubkey2, err := RecoverPubkey(msg, sig)
		if err == nil {
			t.Fail()
			continue
		}

		if bytes.Equal(pubkey1, pubkey2) {
			t.Fail()
			continue
		}

		if VerifySignature(msg, sig, pubkey2) == nil {
			t.Fail()
			continue
		}

		if VerifySignature(msg, sig, pubkey1) != nil {
			t.Fail()
			continue
		}
	}
}

//test random messages against valid signature: should fail

func Test_Secp256_06b(t *testing.T) {
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig, err := Sign(msg, seckey)
	if err != nil {
		t.Fatal(err.Error())
	}

	fail_count := 0
	for i := 0; i < TESTS; i++ {
		msg = RandByte(32)
		pubkey2, err := RecoverPubkey(msg, sig)
		if err == nil {
			t.Logf("Recovered key without error")
			t.Fail()
			fail_count += 1
			continue
		}
		if bytes.Equal(pubkey1, pubkey2) {
			t.Logf("Bytes equal")
			t.Fail()
			fail_count += 1
			continue
		}

		if VerifySignature(msg, sig, pubkey2) == nil {
			t.Logf("Verified invalid pubkey sig without error")
			t.Fail()
			fail_count += 1
			continue
		}

		if VerifySignature(msg, sig, pubkey1) != nil {
			t.Logf("Failed to verify valid pubkey sig")
			t.Fail()
			fail_count += 1
			continue
		}
	}
	if fail_count != 0 {
		t.Logf("ERROR: Accepted signature for %v of %v random messages\n",
			fail_count, TESTS)
		t.Fail()
	}
}
