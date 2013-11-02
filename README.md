secp256
=======

golang secp256k1 library for Bitcoin Cryptographic operations.

Installing
===
sudo apt-get install gmp-dev
cd secp256k1
./configure
make
mv libsecp256k1.so ../lib/

In theory, cgo should be able to compile and staticly link secp256k1.c, however has never worked.  I would appreciate help with this.
