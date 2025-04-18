use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Instant;
use ff::derive::bitvec::macros::internal::funty::Fundamental;
use ff::Field;
use flate2::Compression;
use flate2::write::ZlibEncoder;
use nova_snark::provider::ipa_pc::EvaluationEngine;
use nova_snark::provider::{PallasEngine, VestaEngine};
use nova_snark::spartan::snark::RelaxedR1CSSNARK;
use alpaca::traits::blocklist::AnonymousBlocklistingScheme;
use alpaca::{BlocklistingScheme, PallasCurve, PastaCurve, VestaCurve};

pub const USYNC_TIMER_FILE: &str = "usync_time.txt";
pub const USYNC_SIZE_FILE: &str = "usync_size.txt";
pub const AUTH_TIMER_FILE: &str = "auth_time.txt";
pub const AUTH_SIZE_FILE: &str = "auth_size.txt";
pub const VER_TIMER_FILE: &str = "ver_time.txt";

fn main() {
    let mut size_vector = Vec::new();
    for i in 1..2 {
        size_vector.push(2_i32.pow(i));
    }
    experiment_with_blocklist_size(size_vector);
}

fn experiment_with_blocklist_size(sizes: Vec<i32>) {
    let scheme = BlocklistingScheme::<
        PallasCurve,
        VestaCurve,
        PallasEngine,
        VestaEngine,
        RelaxedR1CSSNARK<PallasEngine, EvaluationEngine<PallasEngine>>,
        RelaxedR1CSSNARK<VestaEngine, EvaluationEngine<VestaEngine>>
    >::new();
    let (pp, pk_sp, pk_id, pk_r, pk_zksnark, sk_sp, sk_id, vk_r, vk_zksnark)
        = scheme.setup().unwrap();
    let public_keys = (&pk_sp, &pk_id, &pk_r, &pk_zksnark);
    println!("Set up complete");

    // set blocklist and ban_over_signatures map
    let mut blocklist = scheme.initialize_blocklist().unwrap();
    let mut ban_over_signatures = HashMap::new();
    println!("Initialized blocklist");

    // set a blocked user
    let (block_k, block_r_com, block_com_k) =
        scheme.register_user1().unwrap();
    let (block_cold_start_block, sign_start) =
        scheme.register_idp(sk_id.clone(), block_com_k.clone(), blocklist.clone()).unwrap();
    let malicious_cred = scheme.register_user2(block_k, block_r_com, &block_com_k, &block_cold_start_block, sign_start.clone()).unwrap();

    // set an honest user
    let (honest_k, honest_r_com, honest_com_k) =
        scheme.register_user1().unwrap();
    let (honest_cold_start_block, sign_start) =
        scheme.register_idp(sk_id.clone(), honest_com_k.clone(), blocklist.clone()).unwrap();
    let honest_cred = scheme.register_user2(honest_k, honest_r_com, &honest_com_k, &honest_cold_start_block, sign_start.clone()).unwrap();

    for blocklist_size in sizes {
        // block for n times
        while blocklist.len().as_usize() < blocklist_size.as_usize() {
            let msg = <<PallasCurve as PastaCurve>::Scalar>::random(rand::thread_rng());
            let token = scheme.extract_token(&malicious_cred, &msg).unwrap();
            blocklist = scheme.add_token_to_blocklist(&token, &mut blocklist).unwrap().clone();
        }

        // for experiment
        let mut usync_timer_file = OpenOptions::new().append(true).create(true).open(USYNC_TIMER_FILE).expect("cannot open the file");
        let mut usync_size_file = OpenOptions::new().append(true).create(true).open(USYNC_SIZE_FILE).expect("cannot open the file");

        let usync_timer = Instant::now();
        let (usync_proof, usync_status) =
            scheme.synchronize(&pp, &pk_id, &pk_sp, &blocklist, &ban_over_signatures, &honest_cred, None, None).unwrap();
        let time_data = format!("{}, {:.2?} \n", blocklist.len(), usync_timer.elapsed().as_secs_f32());
        usync_timer_file.write(time_data.as_bytes()).expect("failed to write to the file");

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        bincode::serialize_into(&mut encoder, &usync_proof).unwrap();
        let usync_proof_encoded = encoder.finish().unwrap();
        let size_data = format!(
            "{}, {:?} bytes\n",
            blocklist.len(), usync_proof_encoded.len()
        );
        usync_size_file.write(size_data.as_bytes()).expect("failed to write to the file");

        let len = blocklist.len();
        let last_block = blocklist[len - 1].clone();
        let last_prev_block = if len - 1 > 0 { Some(&blocklist[len - 2]) } else { None };
        let honest_user_msg = <<PallasCurve as PastaCurve>::Scalar>::random(rand::thread_rng());
        let honest_user_token = scheme.extract_token(&honest_cred, &honest_user_msg).unwrap();

        let auth_timer = Instant::now();
        let auth_proof =
            scheme.authorize_token(&pp, &honest_user_token, &honest_cred, public_keys, usync_proof, usync_status).unwrap();
        let mut auth_timer_file = OpenOptions::new().append(true).create(true).open(AUTH_TIMER_FILE).expect("cannot open the file");
        let auth_time_data = format!("{}, {:.2?} \n", len, auth_timer.elapsed().as_secs_f32());
        auth_timer_file.write(auth_time_data.as_bytes()).expect("failed to write to the file");

        let mut auth_size_file = OpenOptions::new().append(true).create(true).open(AUTH_SIZE_FILE).expect("cannot open the file");
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        bincode::serialize_into(&mut encoder, &auth_proof).unwrap();
        let auth_proof_encoded = encoder.finish().unwrap();
        let size_data = format!(
            "{}, {:?} bytes \n",
            blocklist.len(), auth_proof_encoded.len()
        );
        auth_size_file.write(size_data.as_bytes()).expect("failed to write to the file");

        let digest = scheme.digest_blocklist(&blocklist).unwrap();

        let mut ver_timer_file = OpenOptions::new().append(true).create(true).open(VER_TIMER_FILE).expect("cannot open the file");
        let ver_timer = Instant::now();
        let result = scheme.verify_auth_proof(&honest_user_token, &honest_user_msg, digest, &pk_id, &pk_sp, (&vk_r, &vk_zksnark), &auth_proof);
        assert!(result.is_ok());
        let ver_time_data = format!("{}, {:.2?} \n", len, ver_timer.elapsed().as_secs_f32());
        ver_timer_file.write(ver_time_data.as_bytes()).expect("failed to write to the file");
    }
}
