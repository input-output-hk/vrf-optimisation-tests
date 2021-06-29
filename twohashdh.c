#include <sodium.h>
#include <time.h>

int main(void) {
    FILE *fpt;
    fpt = fopen("results_2hashdh.csv", "w+");
    fprintf(fpt,"verif\n");
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


    for (int i = 0; i < 1000; i++){
        clock_t t_api;
        t_api = clock();
        int result = crypto_vrf_twohashdh_verify(proof_output, sk + 32, vrf_proof, message, MESSAGE_LEN);
        t_api = clock() - t_api;
        double time_api = ((double) t_api) / CLOCKS_PER_SEC;

        if (result != 0) {
            printf("failed\n");
        }

        fprintf(fpt,"%f\n", time_api);
    }

    return 0;
}	