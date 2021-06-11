#![allow(non_snake_case)]
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use csv::Writer;
use rand;
use std::time::Instant;

/// In this preliminary performance analysis we compare the run of computing
///
/// U_i = s_i * B_i - c_i * Y_i
/// V_i = s_i * H_i - c_i * Gamma_i
///
/// for i in [1, n], versus computing 2n random scalars, r_i and l_i, and computing
/// the following:
///
/// 0 =? SUM(r_i * (s_i * B_i - c_i * Y_i - U_i) +
///             l_i * (s_i * H_i - c_i * Gamma_i - V_i))
///
/// which translates into
///
/// 0 =? SUM((r_i * s_i) * B_i - (r_i * c_i) * Y_i - r_i * U_i +
///             (l_i * s_i) * H_i - (l_i * c_i) * Gamma_i - l_i * V_i)
///
/// We write the results into `batch_results.csv`.
const NR_ITERATIONS: usize = 1_000;
fn main() {
    let mut wtr = Writer::from_path("batch_results.csv").expect("failed to open file");
    wtr.write_record(&["current", "optimised"])
        .expect("failed to write to file");

    let nr_equations = 100usize;

    for _ in 0..NR_ITERATIONS {
        let random_r = vec![Scalar::random(&mut rand::thread_rng()); nr_equations];
        let random_l = vec![Scalar::random(&mut rand::thread_rng()); nr_equations];

        let mut s_vector_r = vec![Scalar::random(&mut rand::thread_rng()); nr_equations];
        let mut c_vector_r = vec![Scalar::random(&mut rand::thread_rng()); nr_equations];

        let B_vector = vec![RistrettoPoint::random(&mut rand::thread_rng()); nr_equations];
        let Y_vector = vec![RistrettoPoint::random(&mut rand::thread_rng()); nr_equations];
        let U_vector = vec![RistrettoPoint::random(&mut rand::thread_rng()); nr_equations];
        let H_vector = vec![RistrettoPoint::random(&mut rand::thread_rng()); nr_equations];
        let G_vector = vec![RistrettoPoint::random(&mut rand::thread_rng()); nr_equations];
        let V_vector = vec![RistrettoPoint::random(&mut rand::thread_rng()); nr_equations];

        let start_current = Instant::now();
        for i in 0..nr_equations {
            let _U = RistrettoPoint::vartime_multiscalar_mul(
                &[s_vector_r[i], -c_vector_r[i]],
                &[B_vector[i], Y_vector[i]],
            );
            let _V = RistrettoPoint::vartime_multiscalar_mul(
                &[s_vector_r[i], -c_vector_r[i]],
                &[H_vector[i], G_vector[i]],
            );
        }
        let duration_current = start_current.elapsed();

        let start_opt = Instant::now();
        let mut s_vector_l = vec![Scalar::random(&mut rand::thread_rng()); nr_equations];
        let mut c_vector_l = vec![Scalar::random(&mut rand::thread_rng()); nr_equations];

        let it = random_r.iter().zip(random_l.iter());

        for (i, (r, l)) in it.enumerate() {
            s_vector_l[i] *= l;
            s_vector_r[i] *= r;
            c_vector_l[i] *= l;
            c_vector_r[i] *= r;
        }

        // we should negate some of the scalar eventually
        let _R = RistrettoPoint::vartime_multiscalar_mul(
            s_vector_r
                .iter()
                .chain(c_vector_r.iter())
                .chain(random_r.iter())
                .chain(s_vector_l.iter())
                .chain(c_vector_l.iter())
                .chain(random_l.iter()),
            B_vector
                .iter()
                .chain(Y_vector.iter())
                .chain(U_vector.iter())
                .chain(H_vector.iter())
                .chain(G_vector.iter())
                .chain(V_vector.iter()),
        );

        let duration_opt = start_opt.elapsed();

        wtr.write_record(&[
            format!("{:?}", duration_current.as_millis()),
            format!("{:?}", duration_opt.as_millis()),
        ])
        .expect("failed to write to file");
    }
    wtr.flush().expect("Failed to flush the writer");
}
