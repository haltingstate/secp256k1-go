package secp256k1

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/skycoin/skycoin/src/cipher/base58"
	"log"
	"testing"
)

//const TESTS = 10000 // how many tests
//const SigSize = 65  //64+1

func Test_Secp256_002(t *testing.T) {

	var nonce []byte = RandByte(32) //going to get bitcoins stolen!

	if len(nonce) != 32 {
		t.Fatal()
	}

}

//test agreement for highest bit test
func Test_BitTwiddle2(t *testing.T) {
	var b byte
	for i := 0; i < 512; i++ {
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
func CompactSigTest2(sig []byte) {
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
func Test_Secp256_012(t *testing.T) {
	pubkey, seckey := _GenerateKeyPair()
	if _VerifySeckey(seckey) != 1 {
		t.Fatal()
	}
	if _VerifyPubkey(pubkey) != 1 {
		t.Fatal()
	}
}

// test compressed pubkey from private key
func Test_PubkeyFromSeckey2(t *testing.T) {
	// http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
	privkey, _ := hex.DecodeString(`f19c523315891e6e15ae0608a35eec2e00ebd6d1984cf167f46336dabd9b2de4`)
	desiredPubKey, _ := hex.DecodeString(`03fe43d0c2c3daab30f9472beb5b767be020b81c7cc940ed7a7e910f0c1d9feef1`)
	if pubkey := _PubkeyFromSeckey(privkey); pubkey == nil {
		t.Fatal()
	} else if !bytes.Equal(pubkey, desiredPubKey) {
		t.Fatal()
	}
}

// test uncompressed pubkey from private key
func Test_UncompressedPubkeyFromSeckey2(t *testing.T) {
	// http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
	privkey, _ := hex.DecodeString(`f19c523315891e6e15ae0608a35eec2e00ebd6d1984cf167f46336dabd9b2de4`)
	desiredPubKey, _ := hex.DecodeString(`04fe43d0c2c3daab30f9472beb5b767be020b81c7cc940ed7a7e910f0c1d9feef10fe85eb3ce193405c2dd8453b7aeb6c1752361efdbf4f52ea8bf8f304aab37ab`)
	if pubkey := _UncompressedPubkeyFromSeckey(privkey); pubkey == nil {
		t.Fatal()
	} else if !bytes.Equal(pubkey, desiredPubKey) {
		t.Fatal()
	}
}

//returns random pubkey, seckey, hash and signature
func _RandX() ([]byte, []byte, []byte, []byte) {
	pubkey, seckey := _GenerateKeyPair()
	msg := RandByte(32)
	sig := _Sign(msg, seckey)
	return pubkey, seckey, msg, sig
}

func Test_SignatureVerifyPubkey2(t *testing.T) {
	pubkey1, seckey := _GenerateKeyPair()
	if _VerifyPubkey(pubkey1) == 0 {
		t.Fail()
	}
	msg := RandByte(32)
	sig := _Sign(msg, seckey)
	if sig == nil {
		//t.Fail()
		t.Error("Signature is nil")
	}
	pubkey2 := _RecoverPubkey(msg, sig)

	if pubkey2 == nil {
		//t.Fail()
		t.Error("Recovered pubkey is nil")
	}
	if bytes.Equal(pubkey1, pubkey2) == false {
		//t.Fail()
		t.Error("Recovered pubkey does not match")
	}
}

func Test_verify_functions2(t *testing.T) {
	pubkey, seckey, hash, sig := _RandX()
	if _VerifySeckey(seckey) == 0 {
		t.Error("")
	}
	if _VerifySeckey(seckey) == 0 {
		t.Error("1")
	}
	if _VerifyPubkey(pubkey) == 0 {
		t.Error("2")
	}
	if _VerifySignature(hash, sig, pubkey) == 0 {
		//fmt.Printf("3")
		str := _SignatureErrorString(hash, sig, pubkey)
		t.Error("ERROR: %s\n", str)
	}
	_ = sig
}

func Test_SignatureVerifySecKey2(t *testing.T) {
	pubkey, seckey := _GenerateKeyPair()
	if _VerifySeckey(seckey) == 0 {
		t.Fail()
	}
	if _VerifyPubkey(pubkey) == 0 {
		t.Fail()
	}
}

//test size of messages
func Test_Secp256_02s2(t *testing.T) {
	pubkey, seckey := _GenerateKeyPair()
	msg := RandByte(32)
	sig := _Sign(msg, seckey)
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
func Test_Secp256_022(t *testing.T) {
	pubkey1, seckey := GenerateKeyPair()
	msg := RandByte(32)
	sig := _Sign(msg, seckey)
	if sig == nil {
		t.Fatal("Signature nil")
	}

	pubkey2 := _RecoverPubkey(msg, sig)
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
func Test_Secp256_02a2(t *testing.T) {
	pubkey1, seckey1 := _GenerateKeyPair()
	msg := RandByte(32)
	sig := _Sign(msg, seckey1)

	if sig == nil {
		t.Fatal("Signature nil")
	}
	ret := _VerifySignature(msg, sig, pubkey1)
	if ret != 1 {
		t.Fatal("Signature invalid")
	}

	pubkey2 := _RecoverPubkey(msg, sig)
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
func Test_Secp256_032(t *testing.T) {
	_, seckey := GenerateKeyPair()
	for i := 0; i < TESTS; i++ {
		msg := RandByte(32)
		sig := _Sign(msg, seckey)
		CompactSigTest(sig)

		sig[len(sig)-1] %= 4
		pubkey2 := _RecoverPubkey(msg, sig)
		if pubkey2 == nil {
			t.Fail()
		}
	}
}

//test random messages for different pub/private keys
func Test_Secp256_042(t *testing.T) {
	for i := 0; i < TESTS; i++ {
		pubkey1, seckey := _GenerateKeyPair()
		msg := RandByte(32)
		sig := _Sign(msg, seckey)
		CompactSigTest(sig)

		if sig[len(sig)-1] >= 4 {
			t.Fail()
		}
		pubkey2 := _RecoverPubkey(msg, sig)
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

func randSig2() []byte {
	sig := RandByte(65)
	sig[32] &= 0x70
	sig[64] %= 4
	return sig
}

func Test_Secp256_06a_alt02(t *testing.T) {
	pubkey1, seckey := _GenerateKeyPair()
	msg := RandByte(32)
	sig := _Sign(msg, seckey)

	if sig == nil {
		t.Fail()
	}
	if len(sig) != 65 {
		t.Fail()
	}
	for i := 0; i < TESTS; i++ {
		sig = randSig()
		pubkey2 := _RecoverPubkey(msg, sig)

		if bytes.Equal(pubkey1, pubkey2) == true {
			t.Fail()
		}

		if pubkey2 != nil && _VerifySignature(msg, sig, pubkey2) != 1 {
			t.Fail()
		}

		if _VerifySignature(msg, sig, pubkey1) == 1 {
			t.Fail()
		}
	}
}

//test random messages against valid signature: should fail

func Test_Secp256_06b2(t *testing.T) {
	pubkey1, seckey := _GenerateKeyPair()
	msg := RandByte(32)
	sig := _Sign(msg, seckey)

	fail_count := 0
	for i := 0; i < TESTS; i++ {
		msg = RandByte(32)
		pubkey2 := _RecoverPubkey(msg, sig)
		if bytes.Equal(pubkey1, pubkey2) == true {
			t.Fail()
		}

		if pubkey2 != nil && _VerifySignature(msg, sig, pubkey2) != 1 {
			t.Fail()
		}

		if _VerifySignature(msg, sig, pubkey1) == 1 {
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

func Test_Deterministic_Keypairs_002(t *testing.T) {
	for i := 0; i < 64; i++ {
		seed := RandByte(64)
		_, pub1, sec1 := _DeterministicKeyPairIterator(seed)
		pub2, sec2 := _GenerateDeterministicKeyPair(seed)

		if bytes.Equal(pub1, pub2) == false {
			t.Fail()
		}
		if bytes.Equal(sec1, sec2) == false {
			t.Fail()
		}
	}
}

func Test_Deterministic_Keypairs_012(t *testing.T) {
	for i := 0; i < 64; i++ {
		seed := RandByte(32)
		_, pub1, sec1 := _DeterministicKeyPairIterator(seed)
		pub2, sec2 := _GenerateDeterministicKeyPair(seed)

		if bytes.Equal(pub1, pub2) == false {
			t.Fail()
		}
		if bytes.Equal(sec1, sec2) == false {
			t.Fail()
		}
	}
}

func Test_Deterministic_Keypairs_022(t *testing.T) {
	for i := 0; i < 64; i++ {
		seed := RandByte(32)
		_, pub1, sec1 := _DeterministicKeyPairIterator(seed)
		pub2, sec2 := _GenerateDeterministicKeyPair(seed)

		if bytes.Equal(pub1, pub2) == false {
			t.Fail()
		}
		if bytes.Equal(sec1, sec2) == false {
			t.Fail()
		}
	}
}

func Decode2(str string) []byte {
	byt, err := hex.DecodeString(str)
	if err != nil {
		log.Panic()
	}
	return byt
}

func Test_Deterministic_Keypairs_032(t *testing.T) {

	//test vectors: seed, seckey
	var test_array []string = []string{
		"tQ93w5Aqcunm9SGUfnmF4fJv", "9b8c3e36adce64dedc80d6dfe51ff1742cc1d755bbad457ac01177c5a18a789f",
		"DC7qdQQtbWSSaekXnFmvQgse", "d2deaf4a9ff7a5111fe1d429d6976cbde78811fdd075371a2a4449bb0f4d8bf9",
		"X8EkuUZC7Td7PAXeS7Duc7vR", "cad79b6dcf7bd21891cbe20a51c57d59689ae6e3dc482cd6ec22898ac00cd86b",
		"tVqPYHHNVPRWyEed62v7f23u", "2a386e94e9ffaa409517cbed81b9b2d4e1c5fb4afe3cbd67ce8aba11af0b02fa",
		"kCy4R57HDfLqF3pVhBWxuMcg", "26a7c6d8809c476a56f7455209f58b5ff3f16435fcf208ff2931ece60067f305",
		"j8bjv86ZNjKqzafR6mtSUVCE", "ea5c0f8c9f091a70bf38327adb9b2428a9293e7a7a75119920d759ecfa03a995",
		"qShryAzVY8EtsuD3dsAc7qnG", "331206176509bcae31c881dc51e90a4e82ec33cd7208a5fb4171ed56602017fa",
		"5FGG7ZBa8wVMBJkmzpXj5ESX", "4ea2ad82e7730d30c0c21d01a328485a0cf5543e095139ba613929be7739b52c",
		"f46TZG4xJHXUGWx8ekbNqa9F", "dcddd403d3534c4ef5703cc07a771c107ed49b7e0643c6a2985a96149db26108",
		"XkZdQJ5LT96wshN8JBH8rvEt", "3e276219081f072dff5400ca29a9346421eaaf3c419ff1474ac1c81ad8a9d6e1",
		"GFDqXU4zYymhJJ9UGqRgS8ty", "95be4163085b571e725edeffa83fff8e7a7db3c1ccab19d0f3c6e105859b5e10",
		"tmwZksH2XyvuamnddYxyJ5Lp", "2666dd54e469df56c02e82dffb4d3ea067daafe72c54dc2b4f08c4fb3a7b7e42",
		"EuqZFsbAV5amTzkhgAMgjr7W", "40c325c01f2e4087fcc97fcdbea6c35c88a12259ebf1bce0b14a4d77f075abbf",
		"TW6j8rMffZfmhyDEt2JUCrLB", "e676e0685c5d1afd43ad823b83db5c6100135c35485146276ee0b0004bd6689e",
		"8rvkBnygfhWP8kjX9aXq68CY", "21450a646eed0d4aa50a1736e6c9bf99fff006a470aab813a2eff3ee4d460ae4",
		"phyRfPDuf9JMRFaWdGh7NXPX", "ca7bc04196c504d0e815e125f7f1e086c8ae8c10d5e9df984aeab4b41bf9e398",
	}

	for i := 0; i < len(test_array)/2; i++ {
		seed := []byte(test_array[2*i+0])
		sec1 := Decode(test_array[2*i+1])

		_, sec2 := _GenerateDeterministicKeyPair(seed)
		if bytes.Equal(sec1, sec2) == false {
			t.Fail()
		}
	}
}

func Test_DeterministicWallets12(t *testing.T) {

	var test_array []string = []string{
		"90c56f5b8d78a46fb4cddf6fd9c6d88d6d2d7b0ec35917c7dac12c03b04e444e", "94dd1a9de9ffd57b5516b8a7f090da67f142f7d22356fa5d1b894ee4d4fba95b",
		"a3b08ccf8cbae4955c02f223be1f97d2bb41d92b7f0c516eb8467a17da1e6057", "82fba4cc2bc29eef122f116f45d01d82ff488d7ee713f8a95c162a64097239e0",
		"7048eb8fa93cec992b93dc8e93c5543be34aad05239d4c036cf9e587bbcf7654", "44c059496aac871ac168bb6889b9dd3decdb9e1fa082442a95fcbca982643425",
		"6d25375591bbfce7f601fc5eb40e4f3dde2e453dc4bf31595d8ec29e4370cd80", "d709ceb1a6fb906de506ea091c844ca37c65e52778b8d257d1dd3a942ab367fb",
		"7214b4c09f584c5ddff971d469df130b9a3c03e0277e92be159279de39462120", "5fe4986fa964773041e119d2b6549acb392b2277a72232af75cbfb62c357c1a7",
		"b13e78392d5446ae304b5fc9d45b85f26996982b2c0c86138afdac8d2ea9016e", "f784abc2e7f11ee84b4adb72ea4730a6aabe27b09604c8e2b792d8a1a31881ac",
		"9403bff4240a5999e17e0ab4a645d6942c3a7147c7834e092e461a4580249e6e", "d495174b8d3f875226b9b939121ec53f9383bd560d34aa5ca3ac6b257512adf4",
		"2665312a3e3628f4df0b9bc6334f530608a9bcdd4d1eef174ecda99f51a6db94", "1fdc9fbfc6991b9416b3a8385c9942e2db59009aeb2d8de349b73d9f1d389374",
		"6cb37532c80765b7c07698502a49d69351036f57a45a5143e33c57c236d841ca", "c87c85a6f482964db7f8c31720981925b1e357a9fdfcc585bc2164fdef1f54d0",
		"8654a32fa120bfdb7ca02c487469070eba4b5a81b03763a2185fdf5afd756f3c", "e2767d788d1c5620f3ef21d57f2d64559ab203c044f0a5f0730b21984e77019c",
		"66d1945ceb6ef8014b1b6703cb624f058913e722f15d03225be27cb9d8aabe4a", "3fcb80eb1d5b91c491408447ac4e221fcb2254c861adbb5a178337c2750b0846",
		"22c7623bf0e850538329e3e6d9a6f9b1235350824a3feaad2580b7a853550deb", "5577d4be25f1b44487140a626c8aeca2a77507a1fc4fd466dd3a82234abb6785",
		"a5eebe3469d68c8922a1a8b5a0a2b55293b7ff424240c16feb9f51727f734516", "c07275582d0681eb07c7b51f0bca0c48c056d571b7b83d84980ab40ac7d7d720",
		"479ec3b589b14aa7290b48c2e64072e4e5b15ce395d2072a5a18b0a2cf35f3fd", "f10e2b7675dfa557d9e3188469f12d3e953c2d46dce006cd177b6ae7f465cfc0",
		"63952334b731ec91d88c54614925576f82e3610d009657368fc866e7b1efbe73", "0bcbebb39d8fe1cb3eab952c6f701656c234e462b945e2f7d4be2c80b8f2d974",
		"256472ee754ef6af096340ab1e161f58e85fb0cc7ae6e6866b9359a1657fa6c1", "88ba6f6c66fc0ef01c938569c2dd1f05475cb56444f4582d06828e77d54ffbe6",
	}

	for i := 0; i < len(test_array)/2; i++ {
		seed := Decode(test_array[2*i+0])                    //input
		seckey1 := Decode(test_array[2*i+1])                 //target
		_, _, seckey2 := _DeterministicKeyPairIterator(seed) //output
		if bytes.Equal(seckey1, seckey2) == false {
			t.Fail()
		}
	}
}

func Test_Secp256k1_Hash2(t *testing.T) {

	var test_array []string = []string{
		"90c56f5b8d78a46fb4cddf6fd9c6d88d6d2d7b0ec35917c7dac12c03b04e444e", "a70c36286be722d8111e69e910ce4490005bbf9135b0ce8e7a59f84eee24b88b",
		"a3b08ccf8cbae4955c02f223be1f97d2bb41d92b7f0c516eb8467a17da1e6057", "e9db072fe5817325504174253a056be7b53b512f1e588f576f1f5a82cdcad302",
		"7048eb8fa93cec992b93dc8e93c5543be34aad05239d4c036cf9e587bbcf7654", "5e9133e83c4add2b0420d485e1dcda5c00e283c6509388ab8ceb583b0485c13b",
		"6d25375591bbfce7f601fc5eb40e4f3dde2e453dc4bf31595d8ec29e4370cd80", "8d5579cd702c06c40fb98e1d55121ea0d29f3a6c42f5582b902ac243f29b571a",
		"7214b4c09f584c5ddff971d469df130b9a3c03e0277e92be159279de39462120", "3a4e8c72921099a0e6a4e7f979df4c8bced63063097835cdfd5ee94548c9c41a",
		"b13e78392d5446ae304b5fc9d45b85f26996982b2c0c86138afdac8d2ea9016e", "462efa1bf4f639ffaedb170d6fb8ba363efcb1bdf0c5aef0c75afb59806b8053",
		"9403bff4240a5999e17e0ab4a645d6942c3a7147c7834e092e461a4580249e6e", "68dd702ea7c7352632876e9dc2333142fce857a542726e402bb480cad364f260",
		"2665312a3e3628f4df0b9bc6334f530608a9bcdd4d1eef174ecda99f51a6db94", "5db72c31d575c332e60f890c7e68d59bd3d0ac53a832e06e821d819476e1f010",
		"6cb37532c80765b7c07698502a49d69351036f57a45a5143e33c57c236d841ca", "0deb20ec503b4c678213979fd98018c56f24e9c1ec99af3cd84b43c161a9bb5c",
		"8654a32fa120bfdb7ca02c487469070eba4b5a81b03763a2185fdf5afd756f3c", "36f3ede761aa683813013ffa84e3738b870ce7605e0a958ed4ffb540cd3ea504",
		"66d1945ceb6ef8014b1b6703cb624f058913e722f15d03225be27cb9d8aabe4a", "6bcb4819a96508efa7e32ee52b0227ccf5fbe5539687aae931677b24f6d0bbbd",
		"22c7623bf0e850538329e3e6d9a6f9b1235350824a3feaad2580b7a853550deb", "8bb257a1a17fd2233935b33441d216551d5ff1553d02e4013e03f14962615c16",
		"a5eebe3469d68c8922a1a8b5a0a2b55293b7ff424240c16feb9f51727f734516", "d6b780983a63a3e4bcf643ee68b686421079c835a99eeba6962fe41bb355f8da",
		"479ec3b589b14aa7290b48c2e64072e4e5b15ce395d2072a5a18b0a2cf35f3fd", "39c5f108e7017e085fe90acfd719420740e57768ac14c94cb020d87e36d06752",
		"63952334b731ec91d88c54614925576f82e3610d009657368fc866e7b1efbe73", "79f654976732106c0e4a97ab3b6d16f343a05ebfcc2e1d679d69d396e6162a77",
		"256472ee754ef6af096340ab1e161f58e85fb0cc7ae6e6866b9359a1657fa6c1", "387883b86e2acc153aa334518cea48c0c481b573ccaacf17c575623c392f78b2",
	}

	for i := 0; i < len(test_array)/2; i++ {
		hash1 := Decode(test_array[2*i+0]) //input
		hash2 := Decode(test_array[2*i+1]) //target
		hash3 := _Secp256k1Hash(hash1)     //output
		if bytes.Equal(hash2, hash3) == false {
			t.Fail()
		}
	}
}

func Test_Secp256k1_Equal2(t *testing.T) {

	for i := 0; i < 64; i++ {
		seed := RandByte(128)

		hash1 := _Secp256k1Hash(seed)
		hash2, _, _ := _DeterministicKeyPairIterator(seed)

		if bytes.Equal(hash1, hash2) == false {
			t.Fail()
		}
	}
}

func Test_DeterministicWalletGeneration2(t *testing.T) {
	in := "8654a32fa120bfdb7ca02c487469070eba4b5a81b03763a2185fdf5afd756f3c"
	sec_out := "10ba0325f1b8633ca463542950b5cd5f97753a9829ba23477c584e7aee9cfbd5"
	pub_out := "0249964ac7e3fe1b2c182a2f10abe031784e374cc0c665a63bc76cc009a05bc7c6"

	var seed []byte = []byte(in)
	var pubkey []byte
	var seckey []byte

	for i := 0; i < 1024; i++ {
		seed, pubkey, seckey = _DeterministicKeyPairIterator(seed)
	}

	if bytes.Equal(seckey, Decode(sec_out)) == false {
		t.Fail()
	}

	if bytes.Equal(pubkey, Decode(pub_out)) == false {
		t.Fail()
	}
}

func Test_ECDH22(t *testing.T) {

	pubkey1, seckey1 := _GenerateKeyPair()
	pubkey2, seckey2 := _GenerateKeyPair()

	puba := _ECDH(pubkey1, seckey2)
	pubb := _ECDH(pubkey2, seckey1)

	if puba == nil {
		t.Fail()
	}

	if pubb == nil {
		t.Fail()
	}

	if bytes.Equal(puba, pubb) == false {
		t.Fail()
	}

}

func Test_ECDH222a(t *testing.T) {

	for i := 0; i < 1024; i++ {

		pubkey1, seckey1 := _GenerateKeyPair()
		pubkey2, seckey2 := _GenerateKeyPair()

		puba := _ECDH(pubkey1, seckey2)
		pubb := _ECDH(pubkey2, seckey1)

		if puba == nil {
			t.Fatal("puba is nil")
			//t.Fail()
		}

		if pubb == nil {
			t.Fatal("pubb is nil")
			//t.Fail()
		}

		if bytes.Equal(puba, pubb) == false {
			t.Fatal("puba and pubb not equal")
			//t.Fail()
		}
	}
}

//returns random pubkey, seckey, hash and signature
func Test_Interop_sigs(t *testing.T) {

	for i := 0; i < 1024; i++ {
		seed := RandByte(32)
		msg := RandByte(32)
		nonce := RandByte(32)

		pubkey1, seckey1 := _GenerateDeterministicKeyPair(seed)
		sig1 := _SignDeterministic(msg, seckey1, nonce)
		//return pubkey, seckey, msg, sig

		pubkey2, seckey2 := GenerateDeterministicKeyPair(seed)
		sig2 := _SignDeterministic(msg, seckey2, nonce)

		if sig1 == nil {
			t.Fatal("signature1 is nil")
		}
		if pubkey1 == nil {
			t.Fatal("pubkey1 is nil")
		}
		if sig2 == nil {
			t.Fatal("signature2 is nil")
		}
		if pubkey2 == nil {
			t.Fatal("pubkey2 is nil")
		}

		if bytes.Equal(seckey1, seckey2) == false {
			t.Fatal("seckeys not equal")
			//t.Fail()
		}
		if bytes.Equal(pubkey1, pubkey2) == false {
			t.Fatal("pubkeys not equal")
			//t.Fail()
		}
		if bytes.Equal(sig1, sig2) == false {
			t.Fatal("signatures not equal")
			//t.Fail()
		}
	}
}
func Test_SeckeyValidity(t *testing.T) {

	for i := 0; i < 64*1024; i++ {

		seckey := RandByte(32)

		if _VerifySeckey(seckey) != VerifySeckey(seckey) {
			t.Fatal("Seckey validity mismatch, ", i, _VerifySeckey(seckey), VerifySeckey(seckey))
		}
	}
}

//test that same input, gives same output
func Test_DeterministicKeyGen(t *testing.T) {

	for i := 0; i < 8*1024; i++ {

		seed1 := RandByte(32)
		//seed2 := RandByte(32)

		pubkey1, seckey1 := _GenerateDeterministicKeyPair(seed1)
		pubkey2, seckey2 := GenerateDeterministicKeyPair(seed1)

		if bytes.Equal(seckey1, seckey2) == false {
			t.Fatal("deterministic seckeys do not match", i)
		}
		if bytes.Equal(pubkey1, pubkey2) == false {
			t.Fatal("deterministic pubkeys do not match", i)
		}
	}
}

//test that same input, gives same output
func Test_ECDH_interop1(t *testing.T) {

	for i := 0; i < 1024; i++ {

		seed1 := RandByte(32)
		//seed2 := RandByte(32)

		pubkey1, seckey1 := _GenerateDeterministicKeyPair(seed1)
		pubkey2, seckey2 := GenerateDeterministicKeyPair(seed1)

		if bytes.Equal(seckey1, seckey2) == false {
			t.Fatal("deterministic seckeys do not match", i)
		}
		if bytes.Equal(pubkey1, pubkey2) == false {
			t.Fatal("deterministic pubkeys do not match", i)
		}

		puba := _ECDH(pubkey1, seckey2)
		pubb := ECDH(pubkey1, seckey2)

		if puba == nil {
			t.Fail()
		}

		if pubb == nil {
			t.Fail()
		}

		if bytes.Equal(puba, pubb) == false {
			t.Fail()
		}
	}
}

func Test_ECDH_interop2(t *testing.T) {

	for i := 0; i < 1024; i++ {

		seed1 := RandByte(32)
		seed2 := RandByte(32)

		pubkey1, seckey1 := _GenerateDeterministicKeyPair(seed1)
		pubkey2, seckey2 := GenerateDeterministicKeyPair(seed2)

		puba := _ECDH(pubkey1, seckey2)
		pubb := ECDH(pubkey2, seckey1)

		if puba == nil {
			t.Fail()
		}

		if pubb == nil {
			t.Fail()
		}

		if bytes.Equal(puba, pubb) == false {
			t.Fail()
		}
	}
}

func Test_Keygen(t *testing.T) {

	for i := 0; i < 4096; i++ {

		seed1 := RandByte(32)

		pubkey1, seckey1 := _GenerateDeterministicKeyPair(seed1)

		if seckey1 == nil {
			t.Fatal("seckey is nil")
		}
		if pubkey1 == nil {
			t.Fatal("pubkey is nil")
		}
		if _VerifyPubkey(pubkey1) != 1 {
			t.Fatal("pubkey invalid, impossible")
		}
	}
}

//returns random pubkey, seckey, hash and signature
func Test_signature_recovery1(t *testing.T) {

	for i := 0; i < 1024; i++ {
		seed := RandByte(32)
		msg := RandByte(32)
		nonce := RandByte(32)

		//use new generator
		pubkey1, seckey1 := _GenerateDeterministicKeyPair(seed)
		sig1 := _SignDeterministic(msg, seckey1, nonce)

		//use old generator
		pubkey2, seckey2 := GenerateDeterministicKeyPair(seed)
		sig2 := SignDeterministic(msg, seckey2, nonce)

		if pubkey1 == nil {
			t.Fatal("pubkey1 is nil")
		}
		if sig1 == nil {
			t.Fatal("signature1 is nil")
		}

		if pubkey2 == nil {
			t.Fatal("pubkey2 is nil")
		}
		if sig2 == nil {
			t.Fatal("signature2 is nil")
		}

		if bytes.Equal(seckey1, seckey2) == false {
			t.Fatal("seckeys not equal")
			//t.Fail()
		}
		if bytes.Equal(pubkey1, pubkey2) == false {
			t.Fatal("pubkeys not equal")
			//t.Fail()
		}

		if bytes.Equal(sig1, sig2) == false {
			t.Fatal("signatures not equal, %i", i)
			//t.Fail()
		}
		//test signature recovery
		rec_pub1 := _RecoverPubkey(msg, sig1)
		rec_pub2 := RecoverPubkey(msg, sig2)
		if rec_pub1 == nil {
			t.Fatal("recovered public key 1 is null")
		}
		if bytes.Equal(rec_pub1, pubkey1) == false {
			t.Fatal("recovered pubkey 1 wrong")
		}
		if bytes.Equal(rec_pub2, pubkey2) == false {
			t.Fatal("recovered pubkey 2 wrong")
		}
		if bytes.Equal(rec_pub1, rec_pub2) == false {
			t.Fatal("recovered pubkeys do not match")
		}
		if rec_pub2 == nil {
			t.Fatal("recovered public key 2 is wrong")
		}
	}
}

//returns random pubkey, seckey, hash and signature
func Test_signature_recovery2(t *testing.T) {

	for i := 0; i < 1024; i++ {
		seed := RandByte(32)
		msg := RandByte(32)
		nonce := RandByte(32)

		//use new generator
		pubkey1, seckey1 := _GenerateDeterministicKeyPair(seed)
		sig1 := _SignDeterministic(msg, seckey1, nonce)

		//use old generator
		pubkey2, seckey2 := GenerateDeterministicKeyPair(seed)
		sig2 := SignDeterministic(msg, seckey2, nonce)

		if seckey1 == nil {
			t.Fatal("seckey1 is nil")
		}
		if pubkey1 == nil {
			t.Fatal("pubkey1 is nil")
		}
		if sig1 == nil {
			t.Fatal("signature1 is nil")
		}

		if seckey2 == nil {
			t.Fatal("seckey2 is nil")
		}
		if pubkey2 == nil {
			t.Fatal("pubkey2 is nil")
		}
		if sig2 == nil {
			t.Fatal("signature2 is nil")
		}

		if bytes.Equal(seckey1, seckey2) == false {
			t.Fatal("seckeys not equal")
			//t.Fail()
		}
		if bytes.Equal(pubkey1, pubkey2) == false {
			t.Fatal("pubkeys not equal")
			//t.Fail()
		}
		//if bytes.Equal(sig1, sig2) == false {
		//	t.Fatal("signatures not equal, %i", i)
		//	//t.Fail()
		//}

		//test signature recovery
		rec_pub1 := _RecoverPubkey(msg, sig1)
		rec_pub2 := RecoverPubkey(msg, sig2)
		if rec_pub1 == nil {
			t.Fatal("recovered public key 1 is null")
		}
		if bytes.Equal(rec_pub1, pubkey1) == false {
			t.Fatal("recovered pubkey 1 wrong")
		}
		if bytes.Equal(rec_pub2, pubkey2) == false {
			t.Fatal("recovered pubkey 2 wrong")
		}
		if bytes.Equal(rec_pub1, rec_pub2) == false {
			t.Fatal("recovered pubkeys do not match")
		}
		if rec_pub2 == nil {
			t.Fatal("recovered public key 2 is wrong")
		}
	}
}

func TestSecp256k1_hash(t *testing.T) {
	for i := 0; i < 4096; i++ {
		seed := RandByte(32)
		hash1 := _Secp256k1Hash(seed)
		hash2 := Secp256k1Hash(seed)
		if bytes.Equal(hash1, hash2) == false {
			t.Fatal("secp256k1 hashes do not match: %i", i)
		}

	}
}

func TestMain1(t *testing.T) {
	for i := 0; i < 6*1024; i++ {

		seed := RandByte(32)
		//seed2 := RandByte(32)

		pubkey1, seckey1 := _GenerateDeterministicKeyPair(seed)
		pubkey2, seckey2 := _GenerateDeterministicKeyPair(seed)

		if bytes.Equal(seckey1, seckey2) == false {
			t.Fatal("deterministic seckeys do not match", i)
		}
		if bytes.Equal(pubkey1, pubkey2) == false {
			t.Fatal("deterministic pubkeys do not match", i)
		}
	}
}

func TestMain2(t *testing.T) {

	fail := false
	for i := 0; i < 6*1024; i++ {

		seed := RandByte(32)
		//seed2 := RandByte(32)

		pubkey1, seckey1 := _GenerateDeterministicKeyPair(seed)
		pubkey2, seckey2 := GenerateDeterministicKeyPair(seed)

		if bytes.Equal(seckey1, seckey2) == false {
			fail = true
			log.Printf("deterministic seckeys do not match %d", i)
		}
		if bytes.Equal(pubkey1, pubkey2) == false {
			fail = true
			log.Printf("deterministic pubkeys do not match %d", i)
		}
	}

	if fail == true {
		log.Fatal("Failed")
	}
}

func TestMain3(t *testing.T) {

	fail := false
	for i := 0; i < 16*1024; i++ {

		seed := RandByte(32)
		//seed2 := RandByte(32)

		pubkey1, seckey1 := _generateDeterministicKeyPair(seed)
		pubkey2, seckey2 := generateDeterministicKeyPair(seed)

		if bytes.Equal(seckey1, seckey2) == false {
			fail = true
			log.Printf("deterministic seckeys do not match %d", i)
			log.Fatal()
		}
		sechex := hex.EncodeToString(seckey1)

		if bytes.Equal(pubkey1, pubkey2) == false {
			fail = true
			log.Printf("deterministic pubkeys do not match %d", i)

			seedhex := hex.EncodeToString(seed)
			pubhex1 := hex.EncodeToString(pubkey1)
			pubhex2 := hex.EncodeToString(pubkey2)

			log.Printf("seed= %s", seedhex)
			log.Printf("seckey  = %s", sechex)
			log.Printf("pubkey1 = %s", pubhex1)
			log.Printf("pubkey2 = %s", pubhex2)
		}
	}

	if fail == true {
		log.Fatal("Failed")
	}
}

//2015/12/13 03:02:44 seckey  = 27fa25141c11169208c822e8bb6a1dcd3f991dfd20f393a184498434695e0e14
//2015/12/13 03:02:44 pubkey1 = 03bd957a507e3f7fdeeb7487613acfbd931a600f9d0806000042fc54bc548a2e05
//2015/12/13 03:02:44 pubkey2 = 03bd957a507e3f7fdeeb7487613acfbd931a600f9d0806400042fc54bc548a2e05

//prints the bitcoin address for a seckey
func BitcoinAddressFromPubkey(pubkey []byte) string {
	b1 := SumSHA256(pubkey[:])
	b2 := _HashRipemd160(b1[:])
	b3 := append([]byte{byte(0)}, b2[:]...)
	b4 := _DoubleSHA256(b3)
	b5 := append(b3, b4[0:4]...)
	return string(base58.Hex2Base58(b5))
}

//exports seckey in wallet import format
//key must be compressed
func BitcoinWalletImportFormatFromSeckey(seckey []byte) string {
	b1 := append([]byte{byte(0x80)}, seckey[:]...)
	b2 := append(b1[:], []byte{0x01}...)
	b3 := _DoubleSHA256(b2) //checksum
	b4 := append(b2, b3[0:4]...)
	return string(base58.Hex2Base58(b4))
}

var _test_seeds []string = []string{
	"ee78b2fb5bef47aaab1abf54106b3b022ed3d68fdd24b5cfdd6e639e1c7baa6f",
	"0e86692d755fd39a51acf6c935bdf425a6aad03a7914867e3f6db27371c966b4",
}

func TestMain4(t *testing.T) {
	//seed := RandByte(32)
	//seed2 := RandByte(32)

	for i := 0; i < len(_test_seeds); i++ {

		//seed, _ := hex.DecodeString("ee78b2fb5bef47aaab1abf54106b3b022ed3d68fdd24b5cfdd6e639e1c7baa6f")
		seed, _ := hex.DecodeString(_test_seeds[i])

		pubkey1, seckey1 := _generateDeterministicKeyPair(seed)
		pubkey2, seckey2 := generateDeterministicKeyPair(seed)

		if bytes.Equal(seckey1, seckey2) == false {

			log.Printf("deterministic seckeys do not match")
			log.Fatal()
		}

		sechex := hex.EncodeToString(seckey1)

		if bytes.Equal(pubkey1, pubkey2) == false {

			log.Printf("deterministic pubkeys do not match")

			seedhex := hex.EncodeToString(seed)
			pubhex1 := hex.EncodeToString(pubkey1)
			pubhex2 := hex.EncodeToString(pubkey2)

			log.Printf("seed  = %s", seedhex)
			log.Printf("seckey  = %s", sechex)
			log.Printf("pubkey1 = %s", pubhex1)
			log.Printf("pubkey2 = %s", pubhex2)

			seckey_wif := BitcoinWalletImportFormatFromSeckey(seckey1)
			btc_addr1 := BitcoinAddressFromPubkey(pubkey1)
			btc_addr2 := BitcoinAddressFromPubkey(pubkey2)

			log.Printf("key_wif = %s", seckey_wif)
			log.Printf("btc_addr1 = %s", btc_addr1)
			log.Printf("btc_addr2 = %s", btc_addr2)
			//log.Fatal()
		}
	}

}

//_PubkeyFromSeckey
