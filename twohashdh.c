#include <sodium.h>

int main(void) {

#define MESSAGE_LEN 22
    unsigned char message[MESSAGE_LEN] = "test_rust_verification";

    unsigned char sk[crypto_vrf_twohashdh_SECRETKEYBYTES];

    crypto_vrf_twohashdh_keypair(sk);

    unsigned char vrf_proof[crypto_vrf_twohashdh_PROOFBYTES];
    if (crypto_vrf_twohashdh_prove(vrf_proof, sk, message, MESSAGE_LEN) != 0) {
        printf("failed generating proof\n");
        return -1;
    }

    unsigned char proof_output[crypto_vrf_twohashdh_OUTPUTBYTES];
    if (crypto_vrf_twohashdh_verify(proof_output, sk + 32, vrf_proof, message, MESSAGE_LEN) != 0) {
        printf("failed\n");
    }
    else {
        printf("passed\n");
    }
    return 0;
}	