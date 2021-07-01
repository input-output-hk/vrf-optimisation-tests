# Do we want to stick with Libsodium
In this document we expose some pros and cons of sticking with libsodium

Pros: 
* Open source
* Actively maintained
* Main standardised cryptographic primitives
* 

Cons:
* We will always depend on a fork
* Exposed EC API has terrible performance
* No intention of merging non-standardised protocols (and us, using cutting edge 
  crypto will most likely need such protocols)
* Even doubt of merging standardised protocols if not widely used (e.g. VRF)
* Few options on hash functions (e.g. no Keccak, no Sha3, )