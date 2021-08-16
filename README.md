## VRF optimisations
In this document we expose the results of performance experiments, exploring possible 
improvements for the VRF verification function. We expose two main properties of the 
improvements: (i) if they follow the standard, and (ii) if the change requires a hard fork.

#### Note:
The implementation of vrf does not follow the current standard definition, in the following: 
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
| Batch verification (estimate) | 75 | 0.36| Implement vartime multiscalar multiplication for many variable bases | [Estimate in rust](./src/main.rs) | No | Yes|
| Try and increment (over batch, estimate) | 62 | 0.3 | Two above | ⇧ | ⇧ | ⇧

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

To run tests:
```
make
./vrf_tests
```
which generates `Results.csv` file with the running times. `pandas` makes
it quite simple to analyse the data:
```python
python3
>>> import pandas as pd
>>> pd.read_csv('Results.csv')
# To get the mean of the different values
>>> pd.mean()
# To get the standard deviation
>>> pd.std()

```

We are also studying the possibility of not relying on a fork of libsodium,
and instead use it as a library. For that, we also benchmark the performance
of the operations available in the API vs the internal operations. A run 
with 100_000 iterations get us the following numbers. 

```python
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

### Batch verification
We give details of the changes required for batch verification in [VRF_BATCH](VRF_BATCH.md)
file, and perform a preliminary performance study using the rust binary. 

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