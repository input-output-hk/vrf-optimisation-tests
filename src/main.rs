#![allow(non_snake_case)]
#![allow(clippy::too_many_arguments)]
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;

use csv::Writer;
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
const NR_ITERATIONS: usize = 1000;

fn main() {
    let nr_equations = 1024usize;
    let batches: Vec<usize> = vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

    let mut labels: Vec<String> = batches
        .iter()
        .map(|size| format!("Batch size {}", size))
        .collect();
    labels.insert(0, "No batch".to_owned());
    let mut wtr = Writer::from_path("batch_results.csv").expect("failed to open file");
    wtr
        .write_record(&labels)
        .expect("failed to write first line to file");

    for _ in 0..NR_ITERATIONS {
        comparison_helper(nr_equations, &batches, &mut wtr);
    }
    wtr.flush().expect("Failed to flush the writer");
}

fn batched_elapse(
    batch_size: usize,
    random_r: &[Scalar],
    random_l: &[Scalar],
    s_vector_r: &mut [Scalar],
    c_vector_r: &mut [Scalar],
    B_vector: &[RistrettoPoint],
    Y_vector: &[RistrettoPoint],
    U_vector: &[RistrettoPoint],
    H_vector: &[RistrettoPoint],
    G_vector: &[RistrettoPoint],
    V_vector: &[RistrettoPoint],
) -> String {
    let full_size = random_r.len();
    let nr_batches = full_size / batch_size;

    let start_opt = Instant::now();
    let mut s_vector_l = vec![Scalar::random(&mut rand::thread_rng()); batch_size];
    let mut c_vector_l = vec![Scalar::random(&mut rand::thread_rng()); batch_size];

    for i in 0..nr_batches {
        let it = random_r[i * batch_size..(i + 1) * batch_size]
            .iter()
            .zip(random_l[i * batch_size..(i + 1) * batch_size].iter());

        for (j, (r, l)) in it.enumerate() {
            s_vector_l[j] *= l;
            s_vector_r[j] *= r;
            c_vector_l[j] *= l;
            c_vector_r[j] *= r;
        }

        // we should negate some of the scalars eventually
        let _R = RistrettoPoint::vartime_multiscalar_mul(
            s_vector_l
                .iter()
                .chain(c_vector_r[i * batch_size..(i + 1) * batch_size].iter())
                .chain(random_r[i * batch_size..(i + 1) * batch_size].iter())
                .chain(s_vector_r[i * batch_size..(i + 1) * batch_size].iter())
                .chain(c_vector_l.iter())
                .chain(random_l[i * batch_size..(i + 1) * batch_size].iter()),
            B_vector[i * batch_size..(i + 1) * batch_size]
                .iter()
                .chain(Y_vector[i * batch_size..(i + 1) * batch_size].iter())
                .chain(U_vector[i * batch_size..(i + 1) * batch_size].iter())
                .chain(H_vector[i * batch_size..(i + 1) * batch_size].iter())
                .chain(G_vector[i * batch_size..(i + 1) * batch_size].iter())
                .chain(V_vector[i * batch_size..(i + 1) * batch_size].iter()),
        );
    }

    let duration_opt = start_opt.elapsed();
    format!("{}", duration_opt.as_millis())
}

fn comparison_helper<W: std::io::Write>(
    nr_equations: usize,
    batches: &[usize],
    wtr: &mut Writer<W>,
) {
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

    let batched_time: Vec<String> = batches
        .iter()
        .map(|batch| {
            batched_elapse(
                *batch,
                &random_r,
                &random_l,
                &mut s_vector_r,
                &mut c_vector_r,
                &B_vector,
                &Y_vector,
                &U_vector,
                &H_vector,
                &G_vector,
                &V_vector,
            )
        })
        .collect();

    let mut times = vec![format!("{:?}", duration_current.as_millis())];
    times.extend_from_slice(&batched_time);
    wtr.write_record(&times).expect("failed to write to file");
}
