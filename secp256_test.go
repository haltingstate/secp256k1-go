package secp256

import (
	"testing"
	"fmt"
)


func Test_Secp0(t *testing.T) {

    var nonce []byte = RandByte(32) //going to get bitcoins stolen!

	if len(nonce) != 32 {t.Fatal()}

}

//test pubkey/private generation
func Test_Secp1(t *testing.T) { 
	pubkey,seckey := GenerateKeyPair()

	if VerifySeckey(seckey) != 1 { t.Fatal()}
	if VerifyPubkey(pubkey) != 1 { t.Fatal()}
}

/* Verify an ECDSA signature.
*  Returns: 1: correct signature
*           0: incorrect signature
*          -1: invalid public key
*          -2: invalid signature
*/

func Test_Secp2(t *testing.T) { 
	pubkey,seckey := GenerateKeyPair()

	if VerifyPubkey(pubkey) != 1 { t.Fatal()}
	if VerifySeckey(seckey) != 1 { t.Fatal()}

	msg := RandByte(32)

	sig := Sign(msg, seckey)

	ret := VerifySignature(msg, sig) //does not need pubkey for compact signatures


	if ret != 1 { 
		fmt.Printf("VerifySignature: ret= %v \n", ret)
		t.Fatal()
	}

}
