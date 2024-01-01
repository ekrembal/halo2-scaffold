use clap::Parser;
use ethers_core::k256::elliptic_curve::PrimeField;
use halo2_base::gates::{circuit::builder::BaseCircuitBuilder};
use halo2_base::utils::{BigPrimeField, ScalarField};
use halo2_base::{AssignedValue, Context};
use halo2_ecc::fields::FpStrategy;
// use halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run;
use serde::{Deserialize, Serialize};
use std::env::var;
use std::fs::File;

use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip};
use halo2_ecc::fields::FieldChip;
use halo2_ecc::secp256k1::{FpChip, FqChip};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub x: String, // field element, but easier to deserialize as a string
    pub m: String,
    pub r: String,
    pub s: String,
    pub pk1: String,
    pub pk2: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct CircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

fn ecdsa_verify<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // create a Range chip that contains methods for basic arithmetic operations
    let range = builder.range_chip();
    let ctx = builder.main(0);

    let path = "examples/ecdsa_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();
    let m = Fq::from_str_vartime(&inp.m).expect("deserialize field element should not fail");
    let r = Fq::from_str_vartime(&inp.r).expect("deserialize field element should not fail");
    let s = Fq::from_str_vartime(&inp.s).expect("deserialize field element should not fail");
    let pk1 = Fp::from_str_vartime(&inp.pk1).expect("deserialize field element should not fail");
    let pk2 = Fp::from_str_vartime(&inp.pk2).expect("deserialize field element should not fail");

    // `Context` can roughly be thought of as a single-threaded execution trace of a program we want to ZK prove. We do some post-processing on `Context` to optimally divide the execution trace into multiple columns in a PLONKish arithmetization
    // More advanced usage with multi-threaded witness generation is possible, but we do not explain it here

    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);

    let [m, r, s] = [m, r, s].map(|x| fq_chip.load_private(ctx, x));
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);
    let pubkey = EcPoint::<F, Fp>::new(pk1, pk2);

    let pk = ecc_chip.load_private_unchecked(ctx, (pubkey.x, pubkey.y));

    // test ECDSA
    let res = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip, ctx, pk, r, s, m, 4, 4,
    );

    // make it public
    make_public.push(res);
}

fn main() {
    env_logger::init();

    let args = Cli::parse();

    // run different zk commands based on the command line arguments
    run(ecdsa_verify, args);
}
