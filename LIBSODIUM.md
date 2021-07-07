# Do we want to stick with Libsodium?
In this document we expose some pros and cons of sticking with libsodium

Pros: 
* Open source
* Portable
* C
* Actively maintained
* Main standardised cryptographic primitives in one place
* Formally verified code in their [roadmap](https://libsodium.gitbook.io/doc/roadmap).

Cons:
* We will always depend on a fork
* Exposed EC API has terrible performance
* No intention of merging non-standardised protocols (and us, using cutting edge 
  crypto will most likely need such protocols)
* Even doubt of merging standardised protocols if not widely used (e.g. VRF)
* Few options on hash functions (e.g. no Keccak, no Sha3, ). This makes us
  rely on other implementations (e.g. with [Keccak](https://github.com/input-output-hk/cardano-base/pull/221)).
* The ed25519 verification equation is strict. This does not allow for batch 
  verifications as described in the original paper (we would have to change the 
  verification equation, and rely on the fork even for ED25519).
* Not considerably more efficient than other EC libraries (curve25519_dalek edwards op take ~55 us. Benchmarks
  can be run in their crate using `cargo bench` or from this folder running `cargo run --release`)