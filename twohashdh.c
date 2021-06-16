#include <sodium.h>

int main(void) {

#define MESSAGE_LEN 22
    unsigned char message[MESSAGE_LEN] = "test_rust_verification";

    unsigned char pk[crypto_vrf_twohashdh_PUBLICKEYBYTES];
    unsigned char sk[crypto_vrf_twohashdh_SECRETKEYBYTES];

    crypto_vrf_twohashdh_keypair(pk, sk);

    unsigned char vrf_proof[crypto_vrf_twohashdh_PROOFBYTES];
    crypto_vrf_twohashdh_prove(vrf_proof, sk, message, MESSAGE_LEN);

    unsigned char proof_output[crypto_vrf_twohashdh_OUTPUTBYTES];
    if (crypto_vrf_twohashdh_verify(proof_output, pk, vrf_proof, message, MESSAGE_LEN) != 0) {
        printf("failed\n");
    }
    else {
        printf("passed\n");
    }
    return 0;
}	