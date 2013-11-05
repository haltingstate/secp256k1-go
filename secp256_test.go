package secp256

import (
	"testing"
)


func Test_Secp0(t *testing.T) {

    var nonce []byte = RandByte(32) //going to get bitcoins stolen!

	if len(nonce) != 32 {t.FailNow()}

}

//test pubkey/private generation
func Test_Secp1(t *testing.T) { 
	pubkey,seckey := GenerateKeyPair()

	if VerifySeckey(seckey) != 1 { t.FailNow()}
	if VerifyPubkey(pubkey) != 1 { t.FailNow()}
}

func Test_Secp2(t *testing.T) { 
	pubkey,seckey := GenerateKeyPair()

	if VerifySeckey(seckey) != 1 { t.FailNow()}
	if VerifyPubkey(pubkey) != 1 { t.FailNow()}

	msg := RandBytes(32)

	//func Sign(msg []byte, seckey []byte) []byte {
	sig := Sign(msg, seckey)

	//func VerifySignature(msg []byte, sig []byte, pubkey []byte ) int {

	ret := VerifySignature(msg, sig, pubkey)

	if ret != 1 { t.FailNow()}

}
