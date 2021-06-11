# VRF Batching
This document describes the changes required to allow for VRF batch-verification and its consequences. This change would allow for a XXX improvement in the verification time. However, it requires a hard fork, and suffers worst communication performance (more data needs to be published onchain). The proposal presented here is based in the exact same VRF construction used currently---it only requires a minor change. This document focuses _exclusively_ in the performance estimates---a thorough review of the changes with respect to the security properties is required.

We begin by introducing notation and general functions. Next, we present the VRF algorithm currently in use, and proceed with an explanation of the modified (batch compatible) construction (which was first discussed in this [e-mail thread](https://mailarchive.ietf.org/arch/msg/cfrg/KJwe92nLEkmJGpBe-OST_ilr_MQ/)). We discuss in detail the changes, presenting the pros and cons. Finally, we present a performance study of the effects of this modification.

### Notation
* $\texttt{ECVRF_hash_to_curve}(S):$ This function takes a transcript $S$, and hashes it to get a

point_to_string

ECVRF_nonce_generation

ECVRF_hash_points


### VRF 