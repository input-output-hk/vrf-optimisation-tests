use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};

use blake2::{Blake2b, Digest};
use std::iter;

use rand_core::{CryptoRng, RngCore};

pub struct TwoHashVrfProof {
    u: RistrettoPoint,
    proof: EqDl,
}

impl TwoHashVrfProof {
    pub fn prove(sk: Scalar, pk: RistrettoPoint, message: &[u8]) -> Self {
        let hashed_message = RistrettoPoint::hash_from_bytes::<Blake2b>(message);
        let u = hashed_message * sk;
        let proof = EqDl::generate(
            sk,
            pk,
            u,
            RISTRETTO_BASEPOINT_POINT,
            hashed_message,
            &mut rand::thread_rng(),
        );

        Self { u, proof }
    }

    pub fn verify(&self, pk: RistrettoPoint, message: &[u8]) -> bool {
        let hashed_message = RistrettoPoint::hash_from_bytes::<Blake2b>(message);
        self.proof
            .verify(pk, self.u, RISTRETTO_BASEPOINT_POINT, hashed_message)
    }

    pub fn proof_to_hash(&self, pk: RistrettoPoint, message: &[u8]) -> Option<Vec<u8>> {
        if self.verify(pk, message) {
            let mut hasher = Blake2b::new();
            hasher.update(message);
            hasher.update(self.u.compress().as_bytes());
            let result = &hasher.finalize().to_vec();
            return Some(result.clone());
        }
        None
    }
}

pub struct EqDl {
    announcement_1: RistrettoPoint,
    announcement_2: RistrettoPoint,
    response: Scalar,
}

impl EqDl {
    pub fn generate<R>(
        dlog: Scalar,
        pk: RistrettoPoint,
        commitment: RistrettoPoint,
        base_1: RistrettoPoint,
        base_2: RistrettoPoint,
        rng: &mut R,
    ) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let randomness = Scalar::random(rng);
        let announcement_1 = base_1 * randomness;
        let announcement_2 = base_2 * randomness;

        let mut hash = Blake2b::new();
        hash.update(pk.compress().as_bytes());
        hash.update(commitment.compress().as_bytes());
        hash.update(base_1.compress().as_bytes());
        hash.update(base_2.compress().as_bytes());
        hash.update(announcement_1.compress().as_bytes());
        hash.update(announcement_2.compress().as_bytes());

        let challenge = Scalar::from_hash(hash);

        let response = randomness + challenge * dlog;

        Self {
            announcement_1,
            announcement_2,
            response,
        }
    }

    pub fn verify(
        &self,
        pk: RistrettoPoint,
        commitment: RistrettoPoint,
        base_1: RistrettoPoint,
        base_2: RistrettoPoint,
    ) -> bool {
        let mut hash = Blake2b::new();

        hash.update(pk.compress().as_bytes());
        hash.update(commitment.compress().as_bytes());
        hash.update(base_1.compress().as_bytes());
        hash.update(base_2.compress().as_bytes());
        hash.update(self.announcement_1.compress().as_bytes());
        hash.update(self.announcement_2.compress().as_bytes());

        let challenge = Scalar::from_hash(hash);

        let random_scal = Scalar::random(&mut rand::thread_rng());
        let check = RistrettoPoint::vartime_multiscalar_mul(
            iter::once(-self.response)
                .chain(iter::once(Scalar::one()))
                .chain(iter::once(challenge))
                .chain(iter::once(-(self.response * random_scal)))
                .chain(iter::once(random_scal))
                .chain(iter::once(random_scal * challenge)),
            iter::once(base_1)
                .chain(iter::once(self.announcement_1))
                .chain(iter::once(pk))
                .chain(iter::once(base_2))
                .chain(iter::once(self.announcement_2))
                .chain(iter::once(commitment)),
        );

        check == RistrettoPoint::identity()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    pub fn eqdl_check() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let dlog = Scalar::random(&mut rng);
        let pk = RISTRETTO_BASEPOINT_POINT * dlog;
        let base_2 = RistrettoPoint::random(&mut rng);
        let commitment = base_2 * dlog;

        let proof = EqDl::generate(
            dlog,
            pk,
            commitment,
            RISTRETTO_BASEPOINT_POINT,
            base_2,
            &mut rng,
        );

        assert!(proof.verify(pk, commitment, RISTRETTO_BASEPOINT_POINT, base_2))
    }

    #[test]
    pub fn vrf_proof() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = Scalar::random(&mut rng);
        let pk = RISTRETTO_BASEPOINT_POINT * sk;

        let message = b"test message";

        let vrf_proof = TwoHashVrfProof::prove(sk, pk, message);
        assert!(vrf_proof.verify(pk, message))
    }

    #[test]
    pub fn vrf_result() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let sk = Scalar::random(&mut rng);
        let pk = RISTRETTO_BASEPOINT_POINT * sk;

        let message = b"test message";

        let vrf_proof = TwoHashVrfProof::prove(sk, pk, message);
        let vrf_result = vrf_proof.proof_to_hash(pk, message);

        assert!(vrf_result.is_some());

        assert_eq!(
            vrf_result.unwrap(),
            [
                204, 131, 81, 45, 206, 235, 1, 164, 157, 228, 196, 188, 9, 175, 166, 72, 23, 91,
                221, 145, 107, 230, 0, 84, 170, 223, 239, 54, 222, 103, 234, 65, 0, 143, 220, 48,
                232, 220, 254, 237, 194, 76, 120, 100, 129, 243, 115, 176, 44, 20, 71, 188, 107,
                166, 196, 182, 198, 166, 232, 153, 106, 212, 70, 212
            ]
        );
    }
}
