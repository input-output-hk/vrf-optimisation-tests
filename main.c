#include <stdio.h>
#include <sodium.h>
#include <time.h>

int main(void) {
    FILE *fpt;
    fpt = fopen("Results.csv", "w+");
    fprintf(fpt,"verif, verif_opt, verif_try_inc, api_mul, internal_mul\n");

	#define MESSAGE_LEN 22
	unsigned char message[MESSAGE_LEN] = "test_rust_verification";

	unsigned char pk[crypto_vrf_ietfdraft03_PUBLICKEYBYTES];
	unsigned char sk[crypto_vrf_ietfdraft03_SECRETKEYBYTES];
	
	crypto_vrf_ietfdraft03_keypair(pk, sk);

    unsigned char random_scalar[32];
    crypto_core_ed25519_scalar_random(random_scalar);

    unsigned char vrf_proof[crypto_vrf_ietfdraft03_PROOFBYTES];
    crypto_vrf_ietfdraft03_prove(vrf_proof, sk, message, MESSAGE_LEN);
    unsigned char vrf_proof_own[crypto_vrf_ietfdraft03_PROOFBYTES];
    crypto_vrf_ietfdraft03_prove_try_inc(vrf_proof_own, sk, message, MESSAGE_LEN);
    unsigned char proof_output[crypto_vrf_ietfdraft03_OUTPUTBYTES];
    for (int i = 0; i < 100000; i++){
        clock_t t_api;
        t_api = clock();
        api_scalarmul(pk, random_scalar);
        t_api = clock() - t_api;
        double time_api = ((double) t_api) / CLOCKS_PER_SEC;

        clock_t t_internal;
        t_internal = clock();
        int int_mul = internal_scalarmul(pk, random_scalar);
        t_internal = clock() - t_internal;
        double time_internal = ((double) t_internal) / CLOCKS_PER_SEC;

        if (int_mul != 0) {
            printf("failed internal multiplication");
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

//        double old_times;
//        double opt_times;
//        running_times_scalar_ops(&old_times, &opt_times, proof_output, pk, vrf_proof, message, MESSAGE_LEN);

        fprintf(fpt,"%f, %f, %f, %f, %f\n", time_taken_verif, time_taken_verif_opt, time_taken_verif_try_inc, time_api, time_internal);
    }

    fclose(fpt);
    return 0;
}	
