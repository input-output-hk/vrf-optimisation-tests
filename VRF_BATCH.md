# VRF Batching
This document describes the changes required to allow for VRF 
batch-verification and its consequences. This change would allow 
for a >x2 improvement in the verification time. However, it 
requires a hard fork, and suffers worst communication performance 
(more data needs to be published on-chain). The proposal presented 
here is based in the exact same VRF construction used currently---it 
only requires a minor change. This document focuses _exclusively_ 
in the performance estimates---a thorough review of the changes with 
respect to the security properties is required.

We begin by introducing notation and general functions. Next, 
we present the VRF algorithm currently in use, and proceed with 
an explanation of the modified (batch compatible) construction 
(which was first discussed in this [e-mail thread](https://mailarchive.ietf.org/arch/msg/cfrg/KJwe92nLEkmJGpBe-OST_ilr_MQ/)). 
We discuss in detail the changes, presenting the pros and cons. 
Finally, we present a performance study of the effects of this 
modification.

### Notation
* `ECVRF_hash_to_curve`: This function takes a transcript `S`, and hashes it to
a point in the group.
* `point_to_string`: Conversion of EC point to an octet string
* `ECVRF_nonce_generation`: A function that derives a pseudorandom
  nonce from SK and the input as part of ECVRF proving.
* `ECVRF_hash_points`: A function that takes EC points and hashes them
* `ECVRF_decode_proof`: Given a proof represented as a string, this 
  function parses the different values, and converts them to their
  corresponding types.
* `ECVRF_proof_to_hash`: Given a valid proof, this function returns the
VRF output.


### VRF
In this section we describe a summary of the two functions that define 
the VRF, `ECVRF_prove` and `ECVRF_verify`. For a thorough description
we refer the reader to the [IRTF draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-09).
```
ECVRF_prove(SK, alpha_string)
Input:

      SK - VRF private key

      alpha_string = input alpha, an octet string

Output:

      pi_string - VRF proof, octet string

Steps:

1.  Use SK to derive the VRF secret scalar x and the VRF public key Y
    = x*B
    
2.  H = ECVRF_hash_to_curve(Y, alpha_string)

3.  h_string = point_to_string(H)

4.  Gamma = x*H

5.  k = ECVRF_nonce_generation(SK, h_string)

6.  c = ECVRF_hash_points(H, Gamma, k*B, k*H) (see Section 5.4.3)

7.  s = (k + c*x) mod q

8.  pi_string = point_to_string(Gamma) || int_to_string(c) ||
    int_to_string(s)

9.  Output pi_string
```

```
ECVRF_verify(Y, pi_string, alpha_string)

Input:

      Y - public key, an EC point

      pi_string - VRF proof, octet string of length ptLen+n+qLen

      alpha_string - VRF input, octet string

Output:

      ("VALID", beta_string), where beta_string is the VRF hash output; 
      or
      "INVALID"

Steps:

1.  D = ECVRF_decode_proof(pi_string)

2.  (Gamma, c, s) = D

3.  H = ECVRF_hash_to_curve(Y, alpha_string)

4.  U = s*B - c*Y

5.  V = s*H - c*Gamma

6.  c' = ECVRF_hash_points(H, Gamma, U, V) (see Section 5.4.3)

7.  If c and c' are equal, output ("VALID",
    ECVRF_proof_to_hash(pi_string)); else output "INVALID"
```

### Batching verifications
To achieve an efficient batch of the verifications, the single operations
which can be improved by computing them for several proofs are points
4 and 5. We can achieve an important improvement if, instead of computing
sequential scalar multiplications, we perform a _single_ multiscalar
multiplication for all proofs that are being verified. 

However, this trick can only be exploited if points 4 and 5 are equality
checks rather than computations. As it is currently defined, the verifier
has no knowledge of points `U` and `V`, and computes them with equations 4 
and 5. However, if the prover included points `U` and `V` in the 
transacript, and the verifier simply checked for equality, then the
multiscalar optimisation could be exploited. 

In particular, this would require changes in step 8 of `ECVRF_prove`, and
steps 2, 4 and 5 of `ECVRF_verify`. In particular: 
```
ECVRF_prove
8. pi_string = point_to_string(Gamma) || point_to_string(k*B) || 
point_to_string(k*H) || int_to_string(c) || int_to_string(s)
```

```
ECVRF_verify
2. (Gamma, U, V, c, s) = D

4.  U =? s*B - c*Y

5.  V =? s*H - c*Gamma
```
where `=?` denotes equality check. Now, assume that there are `n` different
VRF proofs to verify. The verifier needs to compute
```
U_i =? s_i * B_i - c_i * Y_i
V_i =? s_i * H_i - c_i * Gamma_i
```
which can be converted to
```
0 =? s_i * B_i - c_i * Y_i - U_i 
0 =? s_i * H_i - c_i * Gamma_i - V_i
```
for `i` in `[1,n]`. The performance boost comes when we combine all these
checks, into a single verification, by using linear combinations of 
each equation using random scalars. In particular, the verifier could 
compute the following check
```
0 =? SUM(r_i * (s_i * B_i - c_i * Y_i - U_i) + 
            l_i * (s_i * H_i - c_i * Gamma_i - V_i))
```

with `r_i` and `l_i` being random scalars. As far as my understanding
goes, we assume that the nodes do have sufficient source of randomness, 
and therefore these scalars can exploit this source of randomness
to be selected. 

Note that an invalid proof will invalidate the whole batch, and then we need
to break down the batches to determine which is the invalid proof. However, 
in our use case, when multiple VRFs are expected to be validated we expect all
of them to be valid, making this risk reasonable in practice. 

### Performance analysis
We run a performance analysis to understand how much improvement such a 
change would bring to the VRF verification. For a preliminary analysis, 
we use a `rust` binary using `curve_25519_dalek`, which has a better
API for multiscalar multiplication. Our main goal is to compare the 
efficiency improvements of computing batched multiscalar multiplications 
of different sizes
vs computing individual computations of `U` and `V`. The current experiments 
focus exclusively in steps 4 and 5 of the verification function, therefore
these estimates are not fully precise. We analyse the running times of verifying
`1024` proofs with no batch, and with batches of sizes `2^i` for `i` in `[0, 10]`.
Note that the difference between no batch and batch of size one is that for the
batched case we batch the equations 4 and 5, while in the non-batched case, we
compute them individually. 

If we run the batched experiments
```bash
cargo run
```
and check the `batch_results.csv` using python
```python
python3
>>> batch_data = pd.read_csv("batch_results.csv")
>>> batch_data.mean()
No batch           83.547052
Batch size 1       76.738304
Batch size 2       65.952413
Batch size 4       67.722751
Batch size 8       64.462740
Batch size 16      57.596202
Batch size 32      46.550699
Batch size 64      50.980108
Batch size 128     42.380395
Batch size 256     33.820934
Batch size 512     32.630467
Batch size 1024    29.648970
```
We see that the optimisation results in an important improvement. This 
comes at the cost of non-backwards compatibility, and a bigger proof
transcript, as we now need to include two additional points to the transcript. 

Note that this performance only considers steps 4 and 5 of the algorithm (see above). 
This does not represent the time of verifying 1024 proofs. 