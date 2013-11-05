package secp256

import (
    //"math/rand"
)

import "crypto/rand"



//completely insecure random number generator
//use entropy pool etc and cryptographic random number generator
func RandByte(n int) []byte {
    b := make([]byte, n)
    buff, err := io.ReadFull(rand.Reader, n)
    if len(buff) != n || err != nil {
        return nil
    }

}
