# VRF benchmarks
This repo contains exploratory benchmarks for VRF functions. On the one hand we explore modifications 
that can be made to the currently used implementation, and how this affects the performance. On the 
other hand, we explore batch verification of VRF functions, as presented in the paper by 
[Badertscher et al.](https://eprint.iacr.org/2022/1045.pdf). 
## Possible VRF optimisations
In this document we expose the results of performance experiments, exploring possible 
improvements for the VRF verification function. We expose two main properties of the 
improvements: (i) if they follow the standard, and (ii) if the change requires a hard fork.

#### Note:
The implementation of VRF used for Praos does not follow the current standard definition, in the following: 
- Computation of the Elligator2 function performs a `bit` modification where it shouldn't, 
resulting in a completely different VRF output. [Here](https://github.com/input-output-hk/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_vrf/ietfdraft03/convert.c#L84)
  we clear the sign bit, when it should be cleared only [here](https://github.com/input-output-hk/libsodium/blob/draft-irtf-cfrg-vrf-03/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L2527).
  This does not reduce the security of the scheme, but makes it incompatible with other 
  implementations .
- The latest ietf draft defines differently the `hash_to_curve` 
function (the domain separation is now set to `ECVRF_edwards25519_XMD:SHA-512_ELL2_NU_4`).
  Furthermore, it 
  concatenates a zero byte when computing the `proof_to_hash` function. 
  This can be easily seen in the [diff](https://www.ietf.org/rfcdiff?difftype=--hwdiff&url2=draft-irtf-cfrg-vrf-07.txt)
  between version 6 and 7. 
  
It is recommended then to update the VRF function to the latest draft (which is expected to receive
small changes as they are in the last round of comments). This means that a hard-fork _is_ required. 

### Results

|    | Verification time (us)   | Ratio with current  | Requirements | Status | Follows standard | Requires hard fork |  
| ------------- |:-------------:| -----:|:---------:|:---------:|:---------:|:---------:|
| Current fn    | 206 | 1 | N/A | Done | Yes | No | 
| Vartime ops      | 152      |   0.73 | Implement vartime multiscalar  multiplications for two variable bases | [Done](https://github.com/input-output-hk/libsodium/blob/vrf_opts/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L767) | Yes | No |
| Vartime ops + Blake2b | 151 |  0.73 |  Implement new functions using blake2b | [Done](https://github.com/input-output-hk/libsodium/blob/vrf_opts/src/libsodium/crypto_vrf/ietfdraft03/prove.c#L202) | Yes | Yes |
| Try and increment (over vartime) | 139 | 0.67 | Implement try and increment hash to group function | [Done](https://github.com/input-output-hk/libsodium/blob/vrf_opts/src/libsodium/crypto_vrf/ietfdraft03/convert.c#L92) | Yes ([see here](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-vrf-09#section-5.4.1)) | Yes |

### Running tests
This code compiles using the `vrf_opts` [branch](https://github.com/input-output-hk/libsodium/tree/vrf_opts) 
of IOHK's `libsodium` fork. First install libsodium:
```
git clone https://github.com/input-output-hk/libsodium.git
cd libsodium
git fetch --all
git checkout vrf_opts
./autogen.sh
./configure
make
make install
```

We are also studying the possibility of not relying on a fork of libsodium,
and instead use it as a library. For that, we also benchmark the performance
of the operations available in the API vs the internal operations. 
To run benchmarks:
```
make praosvrf
./praos_bench
```
which generates `results_praos.csv` file with the running times. `pandas` makes
it quite simple to analyse the data. A run with 100_000 iterations get us the 
following numbers:
```python
python3
>>> import pandas as pd
>>> data.mean()
verif               0.000201
verif_opt           0.000142
verif_opt_blake     0.000142
verif_try_inc       0.000135
batch_compatible    0.000124
api_mul             0.000090
internal_mul        0.000051
single_multi        0.000084
```

`verif` is the implementation used currently, with no optimisations. 
`verif_opt` runs the VRF verification with variable time operations. We 
can see a considerable improvement in this case. To make matters better,
this would be compatible with the current node implementation---we would
simply need to change the verification function, and no hard-fork would be
required. We test the VRF functions using a different hash function, namely
blake2b. We also experiment using a different `hash_to_curve` function
(also in the IETF draft). We can see that using try and increment technique, 
`verif_try_inc`, instead of `elligator`, gives a
slight improvement. However, it is to note that this would require a
hard fork.

We compare the operations made available in the api, `api_mul`,
with the internal ones, `internal_mul`, and show that the latter is much
more efficient. This 
is due to the fact that the api assumes the caller does not "know what
it is doing", and before performing the operation makes a bunch of 
tests and conversions.

Finally, we implement multiscalar multiplication with undetermined number 
of elements. Our current implementation does not efficiently handle the heap
(we are now working with arrays of unknown size), and some more work is required
to have a reasonable estimate for larger sizes. Our end goal is to batch 200 proofs
in a single batch verification.

### EC optimisations and Hash optimisations
The VRF verification equation is separated in two main blocks. EC-related operations and 
hash-related operations. The optimisations that can be exploited by the EC operations, cannot
be exploited by the hashing operations, and viceversa. This means that the variable time operations, 
or the batch verification does not improve the hash-related functions. Similarly, using try and 
increment, does not result in a performance proportional to the overall time, but rather an 
absolute improvement. In other words, the improvement of 0.013ms we saw above would be maintained
if we reduce the verification time to half by exploiting batch verification. This means that 
if we manage to reduce the VRF verification time to ~0.075ms by using batch verification, the 
try and increment function would bring us a further ~17% improvement, down to ~0.063ms. These
particular experiments cannot be performed, as currently the batch-verification is only estimated
using a [rust binary](./src/main.rs). If we decide to go forward with batch verification, we will
implement this in Libsodium's fork (which is a considerable amount of work). 

#### Blake2b
We can see that switching to Blake2b does not give us a considerate improvement. 
Hashing time is negligible with respect to arithmetic operations.  

#### On the objections of using "try and increment"
The use of the "try and increment" algorithm (also known as sampling methods) is oftentimes rejected
on several grounds.  Shallue and van de Woestijne argue that such a mechanism is 
[not proven to take polynomial time](https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.831.5299&rep=rep1&type=pdf).
Nonetheless, such a mechanism is conjectured to take polynomial time, and particularly in cryptography where
its foundation is full of similar conjectures, this should not be a reason to exclude it from the
options. More practical concerns affect this mechanism, in particular that it does not take constant time 
(these are the grounds over which the [IETF draft](https://tools.ietf.org/pdf/draft-irtf-cfrg-hash-to-curve-11.pdf)
excludes this mechanism). 
This makes it vulnerable to timing attacks. However, this is only a concern when the
message being mapped to a group element needs to be secret (with [practical attacks](https://eprint.iacr.org/2019/383.pdf)
performed in such cases). However, for our scenario, the message mapped to a group element is public, and 
known to any participant of the protocol. Therefore, an adversary could not exploit the non-constant
timeness of the "try and increment" algorithm to break the security of the system. Note that these sort
of attacks only affect the messages hashed to the group, and therefore there is no concern for the 
VRF secret key. 

### Difference between internal and exposed multiplication
It is quite surprising to see that the scalar multiplication exposed by libsodium's API
is almost two times slower. We here explore what can be the reasons of such a performance
effect. First, we describe how both function calls (`api_scalarmul` and `internal_scalarmul`)
are defined. 

```C
int internal_scalarmul(unsigned char *point, const unsigned char *scalar) {
    ge25519_p3 result, point_in;
    ge25519_frombytes(&point_in, point);
    ge25519_scalarmult(&result, scalar, &point_in);

    return 0;
}

int api_scalarmul(unsigned char *point, const unsigned char *scalar) {
    unsigned char result[32];
    crypto_scalarmult_ed25519_noclamp(result, scalar, point);
    
    return 0;
}
```
One key point to understand what is going on, is that there are different representation
of elliptic curve points: projective, extended, or completed (nice explanation can be found 
[here](https://doc-internal.dalek.rs/curve25519_dalek/backend/serial/curve_models/index.html)).
The different representation of curve points allows for faster operations. In the internal 
scalar multiplication function, we can directly operate over the `p3` representation (aka extended). 
However, if we see what `crypto_scalarmult_ed25519` does: 

```C
static int
_crypto_scalarmult_ed25519(unsigned char *q, const unsigned char *n,
                           const unsigned char *p)
{
    unsigned char *t = q;
    ge25519_p3     Q;
    ge25519_p3     P;
    unsigned int   i;

    if (ge25519_is_canonical(p) == 0 || ge25519_has_small_order(p) != 0 ||
        ge25519_frombytes(&P, p) != 0 || ge25519_is_on_main_subgroup(&P) == 0) {
        return -1;
    }
    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    
    t[31] &= 127;

    ge25519_scalarmult(&Q, t, &P);
    ge25519_p3_tobytes(q, &Q);
    if (_crypto_scalarmult_ed25519_is_inf(q) != 0 || sodium_is_zero(n, 32)) {
        return -1;
    }
    return 0;
}
```

We can see that the library first checks that the point is in valid form: 
* Is canonical
* Does not have small order
* Is part of the main subgroup

Then it computes the scalar multiplication, and finally performs two additional checks. 
If the resulting point is infinity, or the input scalar is zero. 

This results in important useless overhead. This checks are there to ensure safe
operations, but are not always required, in particular when designing a protocol for 
which we are certain that the bytes represent valid points. Moreover, the API does not
expose optimised operations, such as `ge25519_double_scalarmult_vartime` (for instance, 
this function uses a different representation of EC points for more optimal
operations), which is crucial for the performance optimisation in the VRF verification.
Similarly, it does not expose all point representations, not allowing us to implement
optimised algorithms. 

The reasons above are strong reasons to not use `libsodium` as a library, but rather 
use a fork. 


# Batch verification
This section describes an overview of the changes required to allow for VRF
batch-verification and its consequences. This change would allow
for a ~x2 improvement in the verification time. However, it
requires a hard fork, and suffers worst communication performance
(more data needs to be published on-chain). The proposal presented
here is based in the exact same VRF construction used currently---it
only requires a minor change. This document focuses _exclusively_
in the performance estimates---a thorough review of the changes with
respect to the security properties is proposed in the paper by
[Badertscher et al.](https://eprint.iacr.org/2022/1045.pdf).

We begin by introducing notation and general functions. Next,
we present the VRF algorithm currently in use, and proceed with
an explanation of the modified (batch compatible) construction
(which was first discussed in this [e-mail thread](https://mailarchive.ietf.org/arch/msg/cfrg/KJwe92nLEkmJGpBe-OST_ilr_MQ/)).
We discuss in detail the changes, presenting the pros and cons.
Finally, we present a performance study of the effects of this
modification.

## Notation
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


## VRF
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

## Batching verifications
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
steps 2, 4 and 5 of `ECVRF_verify`. Also, we would need to move the challenge
computation from step 6, to somewhere somewhere in between step 3 and 4 (we
call it step 3.5 for now). In particular:
```
ECVRF_prove
8. pi_string = point_to_string(Gamma) || point_to_string(k*B) || 
point_to_string(k*H) || int_to_string(s)
```

```
ECVRF_verify
2. (Gamma, U, V, s) = D

3,5. c = ECVRF_hash_points(H, Gamma, U, V)

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

with `r_i` and `l_i` being random scalars. However, we are still interested in
computing these scalar in a deterministic way, so that the function
remains pure. See section below.

Note that an invalid proof will invalidate the whole batch, and then we need
to break down the batches to determine which is the invalid proof. However,
in our use case, when multiple VRFs are expected to be validated we expect all
of them to be valid, making this risk reasonable in practice.

## Note on the changes
It is important to note that the changes discussed above are not changes to the protocol
but to how the Discrete Log Equality Sigma Proof is shared with the verifier. Let
the three messages exchanged during the sigma proof between the prover and verifier be named  
as "announcement", "challenge" and "response". The non-interactive version removes the
interaction between prover and verifier, and the former computes the challenge by hashing a
determined list of elements.
To improve communication complexity of sigma protocols, the proof either consists of the challenge
and the response, or of the announcement and the response. On the one hand, the announcement can
be computed by the challenge, response and common reference string. On the other hand the challenge
can be computed using the announcement and the common reference string. Both mechanisms
are considered secure for sigma-protocols (note that a sigma protocol is built
in a way that announcement, challenge and response can be shared without affecting
the zero-knowledge property of the proof).

## Performance analysis
We run a performance analysis to understand how much improvement such a
change would bring to the VRF verification. For a preliminary analysis,
we implement batch verification over the VRF implementation of libsodium
using random coefficient generation (see discussion below).

This code compiles using the `iquerejeta/batch_verify` [branch](https://github.com/ChainCrypto/libsodium/tree/iquerejeta/vrf13_batchverify)
of ChainCrypto's `libsodium` fork. First install libsodium:
```
git clone https://github.com/ChainCrypto/libsodium.git
cd libsodium
git fetch --all
git checkout iquerejeta/batch_verify
./autogen.sh
./configure
make
make install
```

To run the benchmarks

```shell
make batch
./batch_bench
```

and check the `results_batch.csv` using python (following numbers for batches of size 856)
```python
python3
>>> batch_data = pd.read_csv("results_batch.csv")
>>> batch_data.mean()
normal_verif          0.093472
batch_compat_verif    0.094056
batch_verif           0.054576
```
We see that the optimisation results in an important improvement. This
comes at the cost of non-backwards compatibility, and a bigger proof
transcript, as we now need to include two additional points to the transcript.
In particular, the current proof is 80 bytes (the challenge `c` is only
16 bytes), while the new proof would require 128 bytes.

### On the purity of VRF batching
It is of interest to maintain the deterministic nature of the VRF verification intact.
If for batch verification we require a source of randomness to divide each of the
verifying equations, this determinism would be lost. Hence, we explore what would
be the best way to compute this randomness in a deterministic manner. The important
property of this deterministic (pseudo) randomness generation, is that the value
CANNOT be known to the prover at the time of generating the proof. Which raises
the question---what value(s) can we use to deterministically (by the means of hash
function) generate this randomness?

* The inputs to the verification function are the public key, the proof itself, and
  the string used to generate randomness. All these values are known to the prover,
  but only the proof itself is unknown when generating the proof. These values can be
  hashed to compute a pseudorandom scalar.
* The evolving nonce (of the Cardano blockchain) of each block would also be another
  candidate to consider. It's  value is included in the header (where the VRF proof is
  included), and therefore is not known at the time of proof generation.
* Finally, the block body hash could also be a candidate. This hash includes the VRF
  proof. More information can be found in the [Shelley formal spec](https://hydra.iohk.io/build/6752483/download/1/ledger-spec.pdf).

The big positive mark on the first point (using the proof itself), is that it is a
generic solution. This would work for any application that uses the VRF proof, and
would therefore be more susceptible to be included in a future version of the draft.

As described previously, we need randomness for each and every proof the verifier
includes in the batch. The three options described above allow for independent random
scalar generation; each VRF proof is related to a single proof, evolving nonce or
block body hash (respectively). This means that there are two options to generate
the random scalars: either by using a different source of randomness for each of the
scalars, or by using a single source of randomness, and generating several scalars
from it. In particular, let `S_i` be the source of randomness related to proof `i`. 

#### Chosen option
Given the reasoning above, our conclusion for the best option to batch
verify several proofs, is to use the proofs themselves as a source of randomness
(to facilitate standardisation), and to use a single seed for all proofs. 
