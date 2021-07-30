#include <stdio.h>
#include <sodium.h>
#include <time.h>

int main(void) {
    FILE *fpt;
    fpt = fopen("Results.csv", "w+");
    fprintf(fpt,"verif, verif_opt, verif_opt_blake, verif_try_inc, batch_compatible, api_mul, internal_mul, "
                "single_multi, 100_multi, 200_multi\n");

	#define MESSAGE_LEN 22
	unsigned char message[MESSAGE_LEN] = "test_rust_verification";

	unsigned char pk[crypto_vrf_ietfdraft03_PUBLICKEYBYTES];
	unsigned char sk[crypto_vrf_ietfdraft03_SECRETKEYBYTES];
	
	crypto_vrf_ietfdraft03_keypair(pk, sk);

	unsigned char zero_point[32];
    if (crypto_core_ed25519_sub(zero_point, pk, pk) == -1) {
        printf("failed");
    }
    printf("zero bytes: ");
    for (int i = 0; i < 32; i++) {
        printf("%d", zero_point[i]);
    }
    printf("\n");

    unsigned char random_scalar[32];
    crypto_core_ed25519_scalar_random(random_scalar);

    unsigned char vrf_proof[crypto_vrf_ietfdraft03_PROOFBYTES];
    crypto_vrf_ietfdraft03_prove(vrf_proof, sk, message, MESSAGE_LEN);
    unsigned char vrf_proof_batch_compatible[crypto_vrf_ietfdraft03_BATCH_PROOFBYTES];
    crypto_vrf_ietfdraft03_prove_batch_compatible(vrf_proof_batch_compatible, sk, message, MESSAGE_LEN);
    unsigned char vrf_proof_blake[crypto_vrf_ietfdraft03_PROOFBYTES];
    crypto_vrf_ietfdraft03_prove_blake(vrf_proof_blake, sk, message, MESSAGE_LEN);
    unsigned char vrf_proof_own[crypto_vrf_ietfdraft03_PROOFBYTES];
    crypto_vrf_ietfdraft03_prove_try_inc(vrf_proof_own, sk, message, MESSAGE_LEN);
    unsigned char proof_output[crypto_vrf_ietfdraft03_OUTPUTBYTES];
    for (int i = 0; i < 10; i++){
        unsigned char v[crypto_core_ed25519_BYTES];
        clock_t t_api;
        t_api = clock();
        crypto_scalarmult_ed25519(v, random_scalar, pk);
        t_api = clock() - t_api;
        double time_api = ((double) t_api) / CLOCKS_PER_SEC;

        clock_t t_internal;
        t_internal = clock();
        int int_mul = internal_scalarmul(pk, random_scalar);
        t_internal = clock() - t_internal;
        double time_internal = ((double) t_internal) / CLOCKS_PER_SEC;

        double time_single_multi_mult = time_per_proof(1);
        double time_100_multi_mult = time_per_proof(20);
        double time_200_multi_mult = time_per_proof_200();
//        double time_1000_multi_mult = time_per_proof(1000);

        if (int_mul != 0) {
            printf("failed internal multiplication");
        }

        clock_t t_verif_batch_comp;
        t_verif_batch_comp = clock();

        int verification_batch = crypto_vrf_ietfdraft03_verify_batch_compatible(proof_output, pk, vrf_proof_batch_compatible, message, MESSAGE_LEN);

        t_verif_batch_comp = clock() - t_verif_batch_comp;
        double time_taken_verif_batch_comp = ((double) t_verif_batch_comp) / CLOCKS_PER_SEC;

        if (verification_batch == -1) {
            printf("Something went wrong with batch compatible version\n");
            break;
        }

        clock_t t_verif;
        t_verif = clock();

        int verification = crypto_vrf_ietfdraft03_verify(proof_output, pk, vrf_proof, message, MESSAGE_LEN);

        t_verif = clock() - t_verif;
        double time_taken_verif = ((double) t_verif) / CLOCKS_PER_SEC;

        if (verification == -1) {
            printf("Something went wrong here\n");
            break;
        }

        clock_t t_verif_opt;
        t_verif_opt = clock();

        int verification_opt = crypto_vrf_ietfdraft03_verify_opt(proof_output, pk, vrf_proof, message, MESSAGE_LEN);

        t_verif_opt = clock() - t_verif_opt;
        double time_taken_verif_opt = ((double) t_verif_opt) / CLOCKS_PER_SEC;

        if (verification_opt == -1) {
            printf("Something went wrong in optimisation");
            break;
        }

        clock_t t_verif_try_inc;
        t_verif_try_inc = clock();

        int verification_try_inc = crypto_vrf_ietfdraft03_verify_try_inc(proof_output, pk, vrf_proof_own, message, MESSAGE_LEN);

        t_verif_try_inc = clock() - t_verif_try_inc;
        double time_taken_verif_try_inc = ((double) t_verif_try_inc) / CLOCKS_PER_SEC;

        if (verification_try_inc == -1) {
            printf("Something went wrong in try and increment\n");
            break;
        }

        clock_t t_verif_blake;
        t_verif_blake = clock();

        int verification_blake = crypto_vrf_ietfdraft03_verify_opt_blake(proof_output, pk, vrf_proof_blake, message, MESSAGE_LEN);

        t_verif_blake = clock() - t_verif_blake;
        double time_taken_verif_blake = ((double) t_verif_blake) / CLOCKS_PER_SEC;

        if (verification_blake == -1) {
            printf("Something went wrong in blake verif\n");
            return -1;
        }

//        double old_times;
//        double opt_times;
//        running_times_scalar_ops(&old_times, &opt_times, proof_output, pk, vrf_proof, message, MESSAGE_LEN);

        fprintf(fpt,"%f, %f, %f, %f, %f, %f, %f, %f, %f, %f\n", time_taken_verif, time_taken_verif_opt,
                time_taken_verif_blake, time_taken_verif_try_inc, time_taken_verif_batch_comp, time_api,
                time_internal, time_single_multi_mult, time_100_multi_mult, time_200_multi_mult);
    }

    fclose(fpt);
    return 0;
}	
