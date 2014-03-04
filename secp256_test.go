package secp256k1

import (
	"bytes"
	"fmt"
	"log"
	"testing"
	"encoding/hex"
)

const TESTS = 10000 // how many tests
const SigSize = 65  //64+1

func Test_Secp256_00(t *testing.T) {

	var nonce []byte = RandByte(32) //going to get bitcoins stolen!

	if len(nonce) != 32 {
		t.Fatal()
	}

}

//test agreement for highest bit test
func Test_BitTwiddle(t *testing.T) {
	var b byte
	for i:=0; i<512; i++ {
		var bool1 bool = ((b >> 7) == 1)
		var bool2 bool = ((b & 0x80) == 0x80)
		if bool1 != bool2 {
			t.Fatal()
		}
		b++
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
	if VerifySeckey(seckey) != 1 {
		t.Fatal()
	}
	if VerifyPubkey(pubkey) != 1 {
		t.Fatal()
	}
}

//returns random pubkey, seckey, hash and signature
func RandX () ([]byte,[]byte,[]byte,[]byte) {
	pubkey, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	return pubkey,seckey,msg,sig
}

func Test_SignatureVerifyPubkey(t *testing.T) {
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
	if VerifyPubkey(pubkey1) == 0 {
		t.Fail()
	}
	pubkey2 := RecoverPubkey(msg, sig)
	if bytes.Equal(pubkey1, pubkey2) == false {
		t.Fatal("Recovered pubkey does not match")
	}
}

func Test_verify_functions(t *testing.T) {
	pubkey,seckey,hash,sig := RandX()
	if VerifySeckey(seckey) == 0 {
		t.Fail()
	}
	if VerifySeckey(seckey) == 0 {
		t.Fail()
	}
	if VerifyPubkey(pubkey) == 0 {
		t.Fail()
	}
	if VerifySignature(hash,sig,pubkey) == 0 {
		t.Fail()
	}
	_ = sig
}

func Test_SignatureVerifySecKey(t *testing.T) {
	pubkey, seckey := GenerateKeyPair()
	if VerifySeckey(seckey) == 0 {
		t.Fail()
	}
	if VerifyPubkey(pubkey) == 0 {
		t.Fail()
	}
}

//test size of messages
func Test_Secp256_02s(t *testing.T) {
	pubkey, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)
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
	sig := Sign(msg, seckey)
	if sig == nil {
		t.Fatal("Signature nil")
	}

	pubkey2 := RecoverPubkey(msg, sig)
	if pubkey2 == nil {
		t.Fatal("Recovered pubkey invalid")
	}
	if bytes.Equal(pubkey1, pubkey2) == false {
		t.Fatal("Recovered pubkey does not match")
	}

	ret := VerifySignature(msg, sig, pubkey1)
	if ret != 1 {
		t.Fatal("Signature invalid")
	}
}

//test pubkey recovery
func Test_Secp256_02a(t *testing.T) {
	pubkey1, seckey1 := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey1)

	if sig == nil {
		t.Fatal("Signature nil")
	}
	ret := VerifySignature(msg, sig, pubkey1)
	if ret != 1 {
		t.Fatal("Signature invalid")
	}

	pubkey2 := RecoverPubkey(msg, sig)
	if len(pubkey1) != len(pubkey2) {
		t.Fatal()
	}
	for i, _ := range pubkey1 {
		if pubkey1[i] != pubkey2[i] {
			t.Fatal()
		}
	}
	if bytes.Equal(pubkey1, pubkey2) == false {
		t.Fatal()
	}
}

//test random messages for the same pub/private key
func Test_Secp256_03(t *testing.T) {
	_, seckey := GenerateKeyPair()
	for i := 0; i < TESTS; i++ {
		msg := RandByte(32)
		sig := Sign(msg, seckey)
		CompactSigTest(sig)

		sig[len(sig)-1] %= 4
		pubkey2 := RecoverPubkey(msg, sig)
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
		sig := Sign(msg, seckey)
		CompactSigTest(sig)

		if sig[len(sig)-1] >= 4 {
			t.Fail()
		}
		pubkey2 := RecoverPubkey(msg, sig)
		if pubkey2 == nil {
			t.Fail()
		}
		if bytes.Equal(pubkey1, pubkey2) == false {
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
	sig := Sign(msg, seckey)

	if sig == nil {
		t.Fail()
	}
	if len(sig) != 65 {
		t.Fail()
	}
	for i := 0; i < TESTS; i++ {
		sig = randSig()
		pubkey2 := RecoverPubkey(msg, sig)

		if bytes.Equal(pubkey1, pubkey2) == true {
			t.Fail()
		}

		if pubkey2 != nil && VerifySignature(msg, sig, pubkey2) != 1 {
			t.Fail()
		}

		if VerifySignature(msg, sig, pubkey1) == 1 {
			t.Fail()
		}
	}
}

//test random messages against valid signature: should fail

func Test_Secp256_06b(t *testing.T) {
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := Sign(msg, seckey)

	fail_count := 0
	for i := 0; i < TESTS; i++ {
		msg = RandByte(32)
		pubkey2 := RecoverPubkey(msg, sig)
		if bytes.Equal(pubkey1, pubkey2) == true {
			t.Fail()
		}

		if pubkey2 != nil && VerifySignature(msg, sig, pubkey2) != 1 {
			t.Fail()
		}

		if VerifySignature(msg, sig, pubkey1) == 1 {
			t.Fail()
		}
	}
	if fail_count != 0 {
		fmt.Printf("ERROR: Accepted signature for %v of %v random messages\n", fail_count, TESTS)
	}
}

/*
	Deterministic Keypair Tests
*/

func Test_Deterministic_Keypairs_00(t *testing.T) {
	for i := 0;i<64; i++ {
		seed := RandByte(64)
		_,pub1,sec1 := DeterministicKeyPairIterator(seed)
		pub2,sec2 := GenerateDeterministicKeyPair(seed)

		if bytes.Equal(pub1,pub2) == false {
			t.Fail()
		}
		if bytes.Equal(sec1,sec2) == false {
			t.Fail()
		}
	}
}

func Test_Deterministic_Keypairs_01(t *testing.T) {
	for i := 0;i<64; i++ {
		seed := RandByte(32)
		_,pub1,sec1 := DeterministicKeyPairIterator(seed)
		pub2,sec2 := GenerateDeterministicKeyPair(seed)

		if bytes.Equal(pub1,pub2) == false {
			t.Fail()
		}
		if bytes.Equal(sec1,sec2) == false {
			t.Fail()
		}
	}
}

func Test_Deterministic_Keypairs_02(t *testing.T) {
	for i := 0;i<64; i++ {
		seed := RandByte(32)
		_,pub1,sec1 := DeterministicKeyPairIterator(seed)
		pub2,sec2 := GenerateDeterministicKeyPair(seed)

		if bytes.Equal(pub1,pub2) == false {
			t.Fail()
		}
		if bytes.Equal(sec1,sec2) == false {
			t.Fail()
		}
	}
}


func Test_Deterministic_Keypairs_03(t *testing.T) {

	//test vectors: seed, seckey
	var test_array []string = []string {
		"tQ93w5Aqcunm9SGUfnmF4fJv", "ea2ed66a9e9a15b755d40e42d562e474bb6504925dc597ad5b2f952b92490347",
		"DC7qdQQtbWSSaekXnFmvQgse", "798e38e35c8a7c0386dff87a068f62e86adec98e82d343c012221a6b777e85b4",
		"X8EkuUZC7Td7PAXeS7Duc7vR", "c9391c4e706ecc69af7583ade913e1dd279e229d24b3b54d6fb2da25d3a15a99",
		"tVqPYHHNVPRWyEed62v7f23u", "11b1c5334efb8c8c4e342e0ba9f668cafc1126381285965bb781c60292fe349c",
		"kCy4R57HDfLqF3pVhBWxuMcg", "5361af256a58704970cc0a4d193959b8bf57b3d66f1a2c8df895ab137b4c7115",
		"j8bjv86ZNjKqzafR6mtSUVCE", "67243db363bd0b9b9dfbd5796a2753c15f9cb4693e2aedbe8e80d0a368f6ffa3",
		"qShryAzVY8EtsuD3dsAc7qnG", "76873fc7f324b3afa40f1d87cb8ae9f82ae25391ec9d6993d03eeef99edb6657",
		"5FGG7ZBa8wVMBJkmzpXj5ESX", "4029cd2863cdede053cac9869f78f53b814105fcf3fda79f2282239f8ea80937",
		"f46TZG4xJHXUGWx8ekbNqa9F", "cb9d5100049b0a50f7f7a2a47e74b76ec8f0993809c9959c554202b81c8b6687",
		"XkZdQJ5LT96wshN8JBH8rvEt", "738d97db6281485a2bffc1a574baf51d0962bfffcceecd061065ed75c3911141",
		"GFDqXU4zYymhJJ9UGqRgS8ty", "a54431cb5d397d29ebfe42bce88427976f60f127b74d9142fa777b4745b6a047",
		"tmwZksH2XyvuamnddYxyJ5Lp", "51e48511d1c3515a01f21dfe84c38f815c049c6b641eb674e469ea461d7a4bcf",
		"EuqZFsbAV5amTzkhgAMgjr7W", "4516c1712581afc300daff0bb7c9d2a9d6586f4fb82db6ca402d1dd47d9765f8",
		"TW6j8rMffZfmhyDEt2JUCrLB", "6997bde88a9c74079b7970b23b161b631de352892e01c5f45fdc10cff79b94d9",
		"8rvkBnygfhWP8kjX9aXq68CY", "35a6ee7823f23b63aecca98de891fa59d14cc3b60ab6a06a9bfed5a257009f8a",
		"phyRfPDuf9JMRFaWdGh7NXPX", "8f0fd7a670e3cc18d76c43d252da00ba44a99dd806fe03064a32ab025c73cd89",
	}

	for i:=0; i<len(test_array)/2; i++ {
		seed := []byte(test_array[2*i+0])
		sec1, err := hex.DecodeString(test_array[2*i+1])
		if err != nil {
			t.Fail()
		}
		_,sec2 := GenerateDeterministicKeyPair(seed)
		if bytes.Equal(sec1,sec2) == false {
			t.Fail()
		}
	}

}
