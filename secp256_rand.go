package secp256

import (
    "io"
    "crypto/rand"
)


//completely insecure random number generator
//use entropy pool etc and cryptographic random number generator
func RandByte(n int) []byte {
    buff := make([]byte, n)
    ret, err := io.ReadFull(rand.Reader, buff)
    if len(buff) != ret || err != nil {
        return nil
    }
    return buff
}
