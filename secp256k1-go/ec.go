package secp256k1

import (
	//"encoding/hex"
	"log"
)

func ecdsa_verify(pubkey, sig, msg []byte) int {
	var m Number
	var s Signature
	m.SetBytes(msg)

	var q XY
	if !q.ParsePubkey(pubkey) {
		return -1
	}

	if s.ParseBytes(sig) < 0 {
		return -2
	}

	if !s.Verify(&q, &m) {
		return 0
	}
	return 1
}

func Verify(k, s, m []byte) bool {
	return ecdsa_verify(k, s, m) == 1
}

func DecompressPoint(X []byte, off bool, Y []byte) {
	var rx, ry, c, x2, x3 Field
	rx.SetB32(X)
	rx.Sqr(&x2)
	rx.Mul(&x3, &x2)
	c.SetInt(7)
	c.SetAdd(&x3)
	c.Sqrt(&ry)
	ry.Normalize()
	if ry.IsOdd() != off {
		ry.Negate(&ry, 1)
	}
	ry.Normalize()
	ry.GetB32(Y)
	return
}

//TODO: change signature to []byte type
func RecoverPublicKey2(sig Signature, h []byte, recid int, pubkey *XY) int {
	//var sig Signature
	var msg Number

	if sig.R.Sign() <= 0 || sig.R.Cmp(&TheCurve.Order.Int) >= 0 {
		if sig.R.Sign() == 0 {
			return -10
		}
		if sig.R.Sign() <= 0 {
			return -11
		}
		if sig.R.Cmp(&TheCurve.Order.Int) >= 0 {
			return -12
		}
		return -1
	}
	if sig.S.Sign() <= 0 || sig.S.Cmp(&TheCurve.Order.Int) >= 0 {
		return -2
	}

	msg.SetBytes(h)
	if !sig.Recover(pubkey, &msg, recid) {
		return -3
	}
	return 1
}

//TODO: deprecate
func RecoverPublicKey(r, s, h []byte, recid int, pubkey *XY) bool {
	var sig Signature
	var msg Number
	sig.R.SetBytes(r)
	if sig.R.Sign() <= 0 || sig.R.Cmp(&TheCurve.Order.Int) >= 0 {
		return false
	}
	sig.S.SetBytes(s)
	if sig.S.Sign() <= 0 || sig.S.Cmp(&TheCurve.Order.Int) >= 0 {
		return false
	}
	msg.SetBytes(h)
	if !sig.Recover(pubkey, &msg, recid) {
		return false
	}
	return true
}

// Standard EC multiplacation k(xy)
// xy - is the standarized public key format (33 or 65 bytes long)
// out - should be the buffer for 33 bytes (1st byte will be set to either 02 or 03)
// TODO: change out to return type
func Multiply(xy, k, out []byte) bool {
	var pk XY
	var xyz XYZ
	var na, nzero Number
	if !pk.ParsePubkey(xy) {
		return false
	}
	xyz.SetXY(&pk)
	na.SetBytes(k)
	xyz.ECmult(&xyz, &na, &nzero)
	pk.SetXYZ(&xyz)
	pk.GetPublicKey(out)
	return true
}

// Multiply k by G
// returns public key
// out - should be the buffer for 33 bytes (1st byte will be set to either 02 or 03)
// return nil on error, but never returns nil
func BaseMultiply(k []byte) []byte {
	var out []byte = make([]byte, 33)
	var r XYZ
	var n Number
	var pk XY
	n.SetBytes(k)
	ECmultGen(&r, &n)
	pk.SetXYZ(&r)
	pk.GetPublicKey(out)
	return out
}

// out = G*k + xy
// TODO: switch to returning output as []byte
func BaseMultiplyAdd(xy, k, out []byte) bool {
	var r XYZ
	var n Number
	var pk XY
	if !pk.ParsePubkey(xy) {
		return false
	}
	n.SetBytes(k)
	ECmultGen(&r, &n)
	r.AddXY(&r, &pk)
	pk.SetXYZ(&r)
	pk.GetPublicKey(out)
	return true
}

//returns nil on failure
func GeneratePublicKey(k []byte) []byte {
	if len(k) != 32 {
		log.Panic()
	}
	var r XYZ
	var n Number
	var pk XY
	var out []byte
	//must not be zero
	//must not be negative
	//must be less than order of curve
	n.SetBytes(k)
	if n.Sign() <= 0 || n.Cmp(&TheCurve.Order.Int) >= 0 {
		return nil
	}
	ECmultGen(&r, &n)
	pk.SetXYZ(&r)
	pk.GetPublicKey(out)
	return out
}

//1 on success
//must not be zero
// must not be negative
//must be less than order of curve
func SeckeyIsValid(seckey []byte) int {
	if len(seckey) != 32 {
		log.Panic()
	}
	var n Number
	n.SetBytes(seckey)
	if n.Sign() <= 0 {
		return -1
	}
	if n.Cmp(&TheCurve.Order.Int) >= 0 {
		return -2
	}
	return 1
}

//returns 1 on success
func PubkeyIsValid(pubkey []byte) int {
	if len(pubkey) != 33 {
		log.Panic()
	}
	var pub_test XY
	err := pub_test.ParsePubkey(pubkey)
	if err == false {
		//log.Panic("PubkeyIsValid, ERROR: pubkey parse fail, bad pubkey from private key")
		return -1
	}

	if pub_test.IsValid() == false {
		return -2
	}
	return 1
}

/*
int secp256k1_ecdsa_seckey_verify(const unsigned char *seckey) {
    secp256k1_num_t sec;
    secp256k1_num_init(&sec);
    secp256k1_num_set_bin(&sec, seckey, 32);
    int ret = !secp256k1_num_is_zero(&sec) &&
              (secp256k1_num_cmp(&sec, &secp256k1_ge_consts->order) < 0);
    secp256k1_num_free(&sec);
    return ret;
}
*/
