// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Contributed by Brandon Smietana / HaltingState

/*
	This is a fuzzer. It inputs random data to detect failures. 
	Failure of these tests suggests but does not imply a bug.
	
	This was used to find the following two bugs:
	secp256.test: /home/atomos/secp256/./secp256k1/src/impl/num_gmp.h:55: secp256k1_num_get_bin: Assertion `len-shift <= rlen' failed.
	SIGABRT: abort

*/

#define USE_FIELD_10X26
//#define USE_NUM_GMP
#define USE_FIELD_INV_BUILTIN

#include <stdio.h>
#include <stdlib.h>

#include <assert.h>

#include "../include/secp256k1.h" //added by haltingstate

unsigned long rand_long() {          //period 2^96-1
	static unsigned long x=123456789, y=362436069, z=521288629;
	unsigned long t;
    x ^= x << 16; 
    x ^= x >> 5; 
    x ^= x << 1;
	
	t = x;
	x = y;
	y = z;
	
	z = t ^ x ^ y;
	return z;
}

unsigned char rand_byte() {
	unsigned char t = 0;
	unsigned long v = rand_long();
	for(int i=0; i<sizeof(unsigned long);i++) {
		t ^= v & 0xff;
		v >>= 8;
	}
	return t;
}

void rand_bytes(unsigned char* b, int n) {
	for(int i=0;i<n;i++) {
			b[i] = rand_byte();
	}
}

/*
	Generate random compact signatures and messagse and check
*/
void test_random_sigs(int count) {
	
	int error_count = 0;
	for(int i=0;i<count; i++) {
		
		unsigned char sig[64];
		unsigned char msg[32];
		unsigned char pubkey[33];
		int pubkeylen;
		
		rand_bytes(sig,64); //try 65
		rand_bytes(msg,32);

		int ret = secp256k1_ecdsa_recover_compact(
			msg, 32,
            sig,
            pubkey, &pubkeylen,
            1, (int)(rand_byte()%4)
        );
		if(ret == 1) { error_count++; }
	}
	
	printf("test_random_sigs: %d out of %d randomly generated messages/signatures returned 1 for secp256k1_ecdsa_recover_compact\n", error_count, count);
	
}

int main(int argc, char **argv) {
	int count = 10000;
	
    if (argc > 1)
        count = strtol(argv[1], NULL, 0)*47;

    printf("test count = %i\n", count);

    // initialize
    secp256k1_start();

    // num tests
	test_random_sigs(count);

    // shutdown
    secp256k1_stop();
    return 0;
}
