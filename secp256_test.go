package secp256

import (
	"testing"
)


func Test_Secp0(t *testing.T) {

    var nonce []byte = RandByte(32) //going to get bitcoins stolen!

	if len(nonce) != 32 {t.FailNow()}

}


//see if it crashes
func Test_Secp1(t *testing.T) { 
	pubkey,seckey := GenerateKeyPair()

	if VerifySeckey(seckey) != 1 { t.Fail()}
	if VerifyPubkey(pubkey) != 1 { t.Fail()}

}
