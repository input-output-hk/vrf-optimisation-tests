#include <stdio.h>
#include <sodium.h>
#include <time.h>


/***
 * BATCH COMPATIBLE BENCHMARKS CODE. Check the README.md to see with which version of libsodium
 * this code compiles. We show a comparison between individual verification and bath verification,
 * using the modifications presented in https://iohk.io/en/research/library/papers/on-uc-secure-range-extension-and-batch-verification-for-ecvrf/
***/

int main(void) {
    FILE *fpt;
    fpt = fopen("results_batch.csv", "w+");
    fprintf(fpt,"normal_verif, batch_compat_verif, batch_verif\n");

    const unsigned long BATCH_SIZE = 856;
    const unsigned char MSG_SIZE = 255;
    const unsigned char NR_TRIES = 200;

    const unsigned char** m = malloc(sizeof(char*) * BATCH_SIZE);
    unsigned long long* msglen = malloc(sizeof(long long*) * BATCH_SIZE);
    unsigned char** pk = malloc(sizeof(char*) * BATCH_SIZE);
    unsigned char** batch_compat_proof = malloc(sizeof(char*) * BATCH_SIZE);
    unsigned char** normal_proof = malloc(sizeof(char*) * BATCH_SIZE);
    unsigned char** batch_compat_output = malloc(sizeof(char*) * BATCH_SIZE);
    unsigned char** normal_output = malloc(sizeof(char*) *BATCH_SIZE);


    for (int j = 0; j < NR_TRIES; j++) {
        for (int i = 0; i < BATCH_SIZE; i++) {
            unsigned char sk[64];
            unsigned char seed[32];

            msglen[i] = MSG_SIZE;

            m[i] = malloc(sizeof(char) * msglen[i]);
            pk[i] = malloc(sizeof(char) * 32);
            batch_compat_proof[i] = malloc(sizeof(char) * 128);
            normal_proof[i] = malloc(sizeof(char) * 80);
            batch_compat_output[i] = malloc(sizeof(char) * 64);
            normal_output[i] = malloc(sizeof(char) * 64);

            randombytes_buf(m[i], MSG_SIZE);
            randombytes_buf(&seed, 32);
            crypto_vrf_seed_keypair(pk[i], sk, seed);

            crypto_vrf_ietfdraft03_prove(normal_proof[i], m[i], msglen[i], sk);
            crypto_vrf_ietfdraft13_prove_batchcompat(batch_compat_proof[i], m[i], msglen[i], sk);
        }
        clock_t normal_verif;
        normal_verif = clock();

        for (int i = 0; i < BATCH_SIZE; i++) {
            if (crypto_vrf_ietfdraft03_verify(normal_output[i], (const unsigned char *) pk[i], normal_proof[i], m[i], msglen[i]) != 0) {
                printf("Failed simple\n");
                return -1;
            }
        }

        normal_verif = clock() - normal_verif;
        double time_taken_verif = ((double) normal_verif) / CLOCKS_PER_SEC;

        clock_t batch_compat_verif;
        batch_compat_verif = clock();

        for (int i = 0; i < BATCH_SIZE; i++) {
            if (crypto_vrf_ietfdraft13_verify_batchcompat(batch_compat_output[i], (const unsigned char *) pk[i], batch_compat_proof[i], m[i], msglen[i]) != 0) {
                printf("Failed batch compat\n");
                return -1;
            }
        }

        batch_compat_verif = clock() - batch_compat_verif;
        double time_taken_batch_compat_verif = ((double) batch_compat_verif) / CLOCKS_PER_SEC;

        clock_t batch_verif;
        batch_verif = clock();

        if (crypto_vrf_ietfdraft13_batch_verify(batch_compat_proof, (const unsigned char **) pk, (const unsigned char **) batch_compat_proof, m, msglen, BATCH_SIZE) != 0) {
            printf("Failed batch verif\n");
            return -1;
        }

        batch_verif = clock() - batch_verif;
        double time_taken_bverif = ((double) batch_verif) / CLOCKS_PER_SEC;

        fprintf(fpt," %f, %f, %f\n", time_taken_verif, time_taken_batch_compat_verif, time_taken_bverif);
    }

    fclose(fpt);
    return 0;
}

