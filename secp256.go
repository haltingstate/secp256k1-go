package secp256
/*
#cgo CFLAGS: -std=gnu99 -Wno-error
#cgo LDFLAGS: -lgmp
#define USE_FIELD_5X64
#define USE_NUM_GMP
#define USE_FIELD_INV_BUILTIN
#include "./secp256k1/src/secp256k1.c"
*/
import "C"

import (
        "unsafe"
//    "fmt"
        "math/rand"
        //"errors"
        "log"
)
//#include "./src/secp256k1.c"
//removing the "-std=std99" or replacing it with "-std=gnu99"
//#cgo LDFLAGS: -L. -L./lib -L../../../lib -Wl,-rpath='./lib/' -lsecp256k1 -lgmp

//#include "./include/secp256k1.h"

/*
#cgo CFLAGS: -std=gnu99 -Wno-error
#cgo LDFLAGS: -L. -L./lib -L../../../lib -Wl,-rpath='./lib/' -lsecp256k1 -lgmp
#define USE_FIELD_5X64
#define USE_NUM_GMP
#define USE_FIELD_INV_BUILTIN
#include "./secp256k1/src/secp256k1.c"
*/

/*
    Todo:
    > Centralize key management in module
    > add pubkey/private key struct
    > Dont let keys leave module; address keys as ints

    > store private keys in buffer and shuffle (deters persistance on swap disc)
    > Byte permutation (changing)
    > xor with chaning random block (to deter scanning memory for 0x63) (stream cipher?)
    > randomize buffer size to between 16 MB and 32MB and multiple of 4096 bytes

    On Disk
    > Store keys in wallets
    > use slow key derivation function for wallet encryption key (2 seconds)
*/

/*
 For instance, nonces are used in HTTP digest access authentication to calculate an MD5 digest
 of the password. The nonces are different each time the 401 authentication challenge 
 response code is presented, thus making replay attacks virtually impossible.

can verify client/server match without sending password over network
*/

var lock = make(chan int, 1)

//var g_k *C.struct_EC_KEY;

//func unlock() {
//    lock <- 1
//}

var inited int = 0

//void secp256k1_start(void);
func init() {
    //takes 10ms to 100ms; do in goroutine thread
    go func() {
        C.secp256k1_start()
        //lock <- 1
        inited = 1 
    }()
}

// void secp256k1_stop(void);
func Stop() {
    C.secp256k1_stop()
}

/*
<HaltingState> sipa, int secp256k1_ecdsa_pubkey_create(unsigned char *pubkey, int *pubkeylen, const unsigned char *seckey, int compressed);
<HaltingState> is that how i generate private/public keys?
<sipa> HaltingState: you pass in a random 32-byte string as seckey
<sipa> HaltingState: if it is valid, the corresponding pubkey is put in pubkey
<sipa> and true is returned
<sipa> otherwise, false is returned
<sipa> around 1 in 2^128 32-byte strings are invalid, so the odds of even ever seeing one is extremely rare

<sipa> private keys are mathematically numbers
<sipa> each has a corresponding point on the curve as public key
<sipa> a private key is just a number
<sipa> a public key is a point with x/y coordinates
<sipa> almost every 256-bit number is a valid private key (one with a point on the curve corresponding to it)
<sipa> HaltingState: ok?

<sipa> more than half of random points are not on the curve
<sipa> and actually, it is less than  the square root, not less than half, sorry :)
!!!
<sipa> a private key is a NUMBER
<sipa> a public key is a POINT
<gmaxwell> half the x,y values in the field are not on the curve, a private key is an integer.

*/

type _not_secure struct {
    src rand.Source
}

//completely insecure random number generator
//use entropy pool etc and cryptographic random number generator
func (r *_not_secure) RandByte(n int) []byte {
    var ret []byte = make([]byte, n)
    offset := 0
    todo := n
    for {
        val := int64(r.src.Int63())
        for i := 0; i < 8; i++ {
            ret[offset] = byte(val & 0xff)
            todo--
            if todo == 0 {
                return ret
            }
            offset++
            val >>= 8
        }
    }
    return nil //unreachable
}

var not_secure _not_secure

/*
int secp256k1_ecdsa_pubkey_create(
    unsigned char *pubkey, int *pubkeylen, 
    const unsigned char *seckey, int compressed);
*/

//returns pubkey, seckey
func GenerateKeyPair() ([]byte, []byte) {
    pubkey_len := C.int(0)
    const seckey_len = 32

    var pubkey []byte = make([]byte, pubkey_len);
    var seckey []byte = not_secure.RandByte(seckey_len) //going to get bitcoins stolen!

    var pubkey_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&pubkey[0]))
    var seckey_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&seckey[0]))

    ret := C.secp256k1_ecdsa_pubkey_create(
        pubkey_ptr, &pubkey_len,
        seckey_ptr,1)

    if ret != 1 {
        return GenerateKeyPair() //invalid secret, try again
    }
    return pubkey, seckey
}


func Sign(hash_in []byte ) []byte {
    return nil
}

 /* Verify an ECDSA signature.
 *  Returns: 1: correct signature
 *           0: incorrect signature
 *          -1: invalid public key
 *          -2: invalid signature
 */
func VerifySignature(msg []byte, sig []byte, pubkey []byte ) int {

    var msg_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&msg[0]))
    var sig_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&sig[0]))
    var pubkey_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&pubkey[0]))

    ret := C.secp256k1_ecdsa_verify(
        msg_ptr, C.int(len(msg)),
        sig_ptr, C.int(len(sig)),
        pubkey_ptr, C.int(len(pubkey)) );

    return int(ret)
}

/*
int secp256k1_ecdsa_recover_compact(const unsigned char *msg, int msglen,
                                    const unsigned char *sig64,
                                    unsigned char *pubkey, int *pubkeylen,
                                    int compressed, int recid);
*/

/*
 * Recover an ECDSA public key from a compact signature.
 *  Returns: 1: public key succesfully recovered (which guarantees a correct signature).
 *           0: otherwise.
 *  In:      msg:        the message assumed to be signed
 *           msglen:     the length of the message
 *           compressed: whether to recover a compressed or uncompressed pubkey
 *           recid:      the recovery id (as returned by ecdsa_sign_compact)
 *  Out:     pubkey:     pointer to a 33 or 65 byte array to put the pubkey.
 *           pubkeylen:  pointer to an int that will contain the pubkey length.
 */

//recovers the public key from the signature
func RecoverPubkey(msg []byte, sig []byte) ([]byte) {
    if len(sig) != 65 {log.Panic()}

    var pubkey []byte = make([]byte, 33)

    var msg_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&msg[0]))
    var sig_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&sig[0]))
    var pubkey_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&pubkey[0]))

    var pubkeylen C.int;

    ret := C.secp256k1_ecdsa_recover_compact(
        msg_ptr, C.int(len(msg)),
        sig_ptr,
        pubkey_ptr, &pubkeylen,
        C.int(1), C.int(sig[64]),
    );

    if ret == 0 || int(pubkeylen) != 33 {
        return nil
    }

    return pubkey

}