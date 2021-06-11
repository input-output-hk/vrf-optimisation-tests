#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include <time.h>

static const unsigned char SUITE = 0x04; /* ECVRF-ED25519-SHA512-Elligator2 */
static const unsigned char ONE = 0x01;
static const unsigned char TWO = 0x02;

int gen_keys(unsigned char *pk, unsigned char *sk) {
    unsigned char seed[32];

    randombytes_buf(seed, sizeof seed);

    crypto_hash_sha512(sk, seed, 32);
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;
    crypto_scalarmult_ristretto255_base(pk, sk);
    memmove(sk, seed, 32);
    memmove(sk + 32, pk, 32);

    sodium_memzero(seed, sizeof seed);

    return 0;
}

int string_to_point(unsigned char *Y_point, const unsigned char pk[32]) {
    if (crypto_core_ristretto255_is_valid_point(pk) == 0) {
        return -1;
    }
    memmove(Y_point, pk, 32);
    return 0;
}

int vrf_expand_sk(unsigned char *Y_point, unsigned char x_scalar[32],
                  unsigned char truncated_hashed_sk_string[32],
                  const unsigned char skpk[64]) {
    unsigned char h[64];

    crypto_hash_sha512(h, skpk, 32);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    memmove(x_scalar, h, 32);
    memmove(truncated_hashed_sk_string, h + 32, 32);
    sodium_memzero(h, 64);

    return string_to_point(Y_point, skpk + 32);
}

int hash_to_curve_elligator2_25519(unsigned char *H_point, const unsigned char *Y_point, const unsigned char *message, unsigned long long mlen) {
    crypto_hash_sha512_state hs;
    unsigned char            r_string[64];

    /* r = first 32 bytes of SHA512(suite || 0x01 || Y || alpha) */
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &ONE, 1);
    crypto_hash_sha512_update(&hs, Y_point, 32);
    crypto_hash_sha512_update(&hs, message, mlen);
    crypto_hash_sha512_final(&hs, r_string);

    r_string[31] &= 0x7f; /* clear sign bit */
    crypto_core_ed25519_from_uniform(H_point, r_string); /* elligator2 */

    return 0;
}

int vrf_nonce_generation(unsigned char k_scalar[32],
                         const unsigned char truncated_hashed_sk_string[32],
                         const unsigned char h_string[32]) {
    crypto_hash_sha512_state hs;
    unsigned char            k_string[64];

    /* k_string = SHA512(truncated_hashed_sk_string || h_string) */
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, truncated_hashed_sk_string, 32);
    crypto_hash_sha512_update(&hs, h_string, 32);
    crypto_hash_sha512_final(&hs, k_string);

    crypto_core_ed25519_scalar_reduce(k_scalar, k_string); /* k_string[0:32] = string_to_int(k_string) mod q */

    sodium_memzero(k_string, sizeof k_string);

    return 0;
}

void hash_points(unsigned char c_scalar[16],
                const unsigned char *H_point,
                const unsigned char *Gamma_point,
                const unsigned char *kB_point,
                const unsigned char *kH_point) {
    unsigned char c1[64];

    crypto_hash_sha512_state hs;
    crypto_hash_sha512_init(&hs);
    crypto_hash_sha512_update(&hs, &SUITE, 1);
    crypto_hash_sha512_update(&hs, &TWO, 1);
    crypto_hash_sha512_update(&hs, H_point, 32);
    crypto_hash_sha512_update(&hs, Gamma_point, 32);
    crypto_hash_sha512_update(&hs, kB_point, 32);
    crypto_hash_sha512_update(&hs, kH_point, 32);
    crypto_hash_sha512_final(&hs, c1);

    memmove(c_scalar, c1, 16);
    sodium_memzero(c1, 64);
}

int vrf_prove(unsigned char vrf_proof[80],
              const unsigned char *Y_point,
              const unsigned char x_scalar[32],
              const unsigned char truncated_hashed_sk_string[32],
              const unsigned char *message,
              unsigned long long mlen) {
    /* c fits in 16 bytes, but we store it in a 32-byte array because
     * sc25519_muladd expects a 32-byte scalar */
    unsigned char k_scalar[32], c_scalar[32],
    H_point[crypto_core_ed25519_BYTES],
    Gamma_point[crypto_core_ed25519_BYTES],
    kB_point[crypto_core_ed25519_BYTES],
    kH_point[crypto_core_ed25519_BYTES];

    hash_to_curve_elligator2_25519(H_point, Y_point, message, mlen);

    if (crypto_scalarmult_ed25519(Gamma_point, x_scalar, H_point) != 0) {
        printf("something went wrong");
        return -1;
    } /* Gamma = x*H */
    vrf_nonce_generation(k_scalar, truncated_hashed_sk_string, H_point);

    crypto_scalarmult_ed25519_base_noclamp(kB_point, k_scalar); /* compute k*B */
    if (crypto_scalarmult_ed25519_noclamp(kH_point, k_scalar, H_point) != 0) { /* compute k*H */
        printf("something went wrong here");
        return -1;
    }

    /* c = ECVRF_hash_points(h, gamma, k*B, k*H)
     * (writes only to the first 16 bytes of c_scalar */

    hash_points(c_scalar, H_point, Gamma_point, kB_point, kH_point);
    memset(c_scalar+16, 0, 16); /* zero the remaining 16 bytes of c_scalar */

    /* output pi */
    memmove(vrf_proof, Gamma_point, 32); /* pi[0:32] = point_to_string(Gamma) */
    memmove(vrf_proof+32, c_scalar, 16); /* pi[32:48] = c (16 bytes) */
    crypto_core_ed25519_scalar_mul(vrf_proof+48, c_scalar, x_scalar); /* pi[48:80] = s = c*x + k (mod q) */
    crypto_core_ed25519_scalar_add(vrf_proof+48, vrf_proof+48, k_scalar);

    sodium_memzero(k_scalar, sizeof k_scalar); /* k must remain secret */
    /* erase other non-sensitive intermediate state for good measure */
    sodium_memzero(c_scalar, sizeof c_scalar);
    sodium_memzero(&H_point, sizeof H_point);
    sodium_memzero(&Gamma_point, sizeof Gamma_point);
    sodium_memzero(&kB_point, sizeof kB_point);
    sodium_memzero(&kH_point, sizeof kH_point);

    return 0;
}

int vrf_prove_own(unsigned char vrf_proof[crypto_vrf_ietfdraft03_PROOFBYTES],
                  const unsigned char skpk[crypto_vrf_ietfdraft03_SECRETKEYBYTES],
                  const unsigned char *message,
                  unsigned long long mlen) {
    unsigned char x_scalar[32], truncated_hashed_sk_string[32], Y_point[crypto_core_ed25519_BYTES];

    if (vrf_expand_sk(Y_point, x_scalar, truncated_hashed_sk_string, skpk) != 0) {
        sodium_memzero(x_scalar, 32);
        sodium_memzero(truncated_hashed_sk_string, 32);
        sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
        return -1;
    }
    vrf_prove(vrf_proof, Y_point, x_scalar, truncated_hashed_sk_string, message, mlen);
    sodium_memzero(x_scalar, 32);
    sodium_memzero(truncated_hashed_sk_string, 32);
    sodium_memzero(&Y_point, sizeof Y_point); /* for good measure */
    return 0;
}

int main(void) {
    FILE *fpt;
    fpt = fopen("Results.csv", "w+");
    fprintf(fpt,"verif, verif_try_inc, verif_opt, api_mul, internal_mul\n");

	#define MESSAGE_LEN 22
	unsigned char message[MESSAGE_LEN] = "test_rust_verification";

	unsigned char pk[crypto_vrf_ietfdraft03_PUBLICKEYBYTES];
	unsigned char sk[crypto_vrf_ietfdraft03_SECRETKEYBYTES];
	
	crypto_vrf_ietfdraft03_keypair(pk, sk);

	unsigned char pk_own[crypto_vrf_ietfdraft03_PUBLICKEYBYTES];
	unsigned char sk_own[crypto_vrf_ietfdraft03_SECRETKEYBYTES];

    gen_keys(pk_own, sk_own);

    unsigned char random_scalar[32];
    crypto_core_ed25519_scalar_random(random_scalar);

    unsigned char vrf_proof[crypto_vrf_ietfdraft03_PROOFBYTES];
    crypto_vrf_ietfdraft03_prove(vrf_proof, sk, message, MESSAGE_LEN);
    unsigned char vrf_proof_own[crypto_vrf_ietfdraft03_PROOFBYTES];
    crypto_vrf_ietfdraft03_prove_try_inc(vrf_proof_own, sk, message, MESSAGE_LEN);
    unsigned char proof_output[crypto_vrf_ietfdraft03_OUTPUTBYTES];
    for (int i = 0; i < 1000; i++){
        clock_t t_api;
        t_api = clock();
        api_scalarmul(pk, random_scalar);
        t_api = clock() - t_api;
        double time_api = ((double) t_api) / CLOCKS_PER_SEC;

        clock_t t_internal;
        t_internal = clock();
        internal_scalarmul(pk, random_scalar);
        t_internal = clock() - t_internal;
        double time_internal = ((double) t_internal) / CLOCKS_PER_SEC;

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

        fprintf(fpt,"%f, %f, %f, %f, %f\n", time_taken_verif, time_taken_verif_try_inc, time_taken_verif_opt, time_api, time_internal);
    }

    fclose(fpt);
    return 0;
}	
