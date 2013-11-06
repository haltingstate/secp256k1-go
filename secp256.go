package secp256
/*
#cgo CFLAGS: -std=gnu99 -Wno-error
#cgo LDFLAGS: -lgmp
#define USE_FIELD_10X26
#define USE_NUM_GMP
#define USE_FIELD_INV_BUILTIN
#include "./secp256k1/src/secp256k1.c"
*/
import "C"

import (
        "unsafe"
//    "fmt"
        //"errors"
        "log"
)
//#include "./src/secp256k1.c"
//removing the "-std=std99" or replacing it with "-std=gnu99"
//#cgo LDFLAGS: -L. -L./lib -L../../../lib -Wl,-rpath='./lib/' -lsecp256k1 -lgmp
//#include "./include/secp256k1.h"

//#define USE_FIELD_5X64

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


//void secp256k1_start(void);
func init() {
    C.secp256k1_start()     //takes 10ms to 100ms
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

<sipa> HaltingState: yes, n,q = private keys; N,Q = corresponding public keys (N=n*G, Q=q*G); then it follows that n*Q = n*q*G = q*n*G = q*N
<sipa> that's the reason ECDH works
<sipa> multiplication is associative and commutativ

*/

/*
int secp256k1_ecdsa_pubkey_create(
    unsigned char *pubkey, int *pubkeylen, 
    const unsigned char *seckey, int compressed);
*/

/** Compute the public key for a secret key.
 *  In:     compressed: whether the computed public key should be compressed
 *          seckey:     pointer to a 32-byte private key.
 *  Out:    pubkey:     pointer to a 33-byte (if compressed) or 65-byte (if uncompressed)
 *                      area to store the public key.
 *          pubkeylen:  pointer to int that will be updated to contains the pubkey's
 *                      length.
 *  Returns: 1: secret was valid, public key stores
 *           0: secret was invalid, try again.
 */

//pubkey, seckey

func GenerateKeyPair() ([]byte, []byte) {

    pubkey_len := C.int(33)
    const seckey_len = 32

    var pubkey []byte = make([]byte, pubkey_len);
    var seckey []byte = RandByte(seckey_len) //going to get bitcoins stolen!

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


/* 
*  Create a compact ECDSA signature (64 byte + recovery id).
*  Returns: 1: signature created
*           0: nonce invalid, try another one
*  In:      msg:    the message being signed
*           msglen: the length of the message being signed
*           seckey: pointer to a 32-byte secret key (assumed to be valid)
*           nonce:  pointer to a 32-byte nonce (generated with a cryptographic PRNG)
*  Out:     sig:    pointer to a 64-byte array where the signature will be placed.
*           recid:  pointer to an int, which will be updated to contain the recovery id.
*/

/*
int secp256k1_ecdsa_sign_compact(const unsigned char *msg, int msglen,
                                 unsigned char *sig64,
                                 const unsigned char *seckey,
                                 const unsigned char *nonce,
                                 int *recid);
*/

func Sign(msg []byte, seckey []byte) []byte {
    var nonce []byte = RandByte(32) //going to get bitcoins stolen!

    var sig []byte = make([]byte,65)
    var recid C.int;

    var msg_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&msg[0]))
    var seckey_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&seckey[0]))
    var nonce_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&nonce[0]))
    var sig_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&sig[0]))

    if C.secp256k1_ecdsa_seckey_verify(seckey_ptr) != C.int(1) {
        log.Panic() //invalid seckey
    }

    ret := C.secp256k1_ecdsa_sign_compact(
        msg_ptr, C.int(len(msg)),
        sig_ptr,
        seckey_ptr,
        nonce_ptr,
        &recid);

    sig[64] = byte(int(recid))

    if ret != 1 {
        return Sign(msg,seckey) //nonce invalid,retry
    }

    return sig

}

/*
* Verify an ECDSA secret key.
*  Returns: 1: secret key is valid
*           0: secret key is invalid
*  In:      seckey: pointer to a 32-byte secret key
*/
func VerifySeckey(seckey []byte) int {
    if len(seckey) != 32 {return 0}
    var seckey_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&seckey[0]))
    ret := C.secp256k1_ecdsa_seckey_verify(seckey_ptr)
    return int(ret)
}

/*
* Validate a public key.
*  Returns: 1: valid public key
*           0: invalid public key
*/

func VerifyPubkey(pubkey []byte) int {
    if len(pubkey) != 33 {return 0}
    var pubkey_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&pubkey[0]))
    ret := C.secp256k1_ecdsa_pubkey_verify(pubkey_ptr, 33)
    return int(ret)
}


//for compressed signatures, does not need pubkey
func VerifySignature(msg []byte, sig []byte, pubkey1 []byte) int {
    pubkey2 := RecoverPubkey(msg, sig) //if pubkey recovered, signature valid
    
    if len(pubkey1) != 65 || len(pubkey2) != 65 { return 0;}
    for i:=0; i<65; i++ { if(pubkey1[i] != pubkey2[i]) {return 0;}}
    if pubkey != nil { return 1 }

    return 0
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
//recovery of pubkey means correct signature
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


/* Verify an ECDSA signature.
*  Returns: 1: correct signature
*           0: incorrect signature
*          -1: invalid public key
*          -2: invalid signature
*/
/*
for non-compressed
func VerifySignature(msg []byte, sig []byte, pubkey []byte ) int {

    if len(sig) != 72 || len(pubkey) != 65

    var msg_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&msg[0]))
    var sig_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&sig[0]))
    var pubkey_ptr *C.uchar = (*C.uchar)(unsafe.Pointer(&pubkey[0]))

    ret := C.secp256k1_ecdsa_verify(
        msg_ptr, C.int(len(msg)),
        sig_ptr, C.int(len(sig)),
        pubkey_ptr, C.int(len(pubkey)) );

    return int(ret)

}
*/
