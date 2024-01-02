use clap::Parser;
use ethers_core::k256::elliptic_curve::PrimeField;
// use ethers_core::k256::elliptic_curve::PrimeField;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::{GateChip, GateInstructions};
use halo2_base::poseidon::hasher::PoseidonHasher;
use halo2_base::utils::BigPrimeField;
use halo2_base::{AssignedValue, Context};
use halo2_ecc::fields::FpStrategy;
// use halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_scaffold::scaffold::cmd::Cli;
use halo2_scaffold::scaffold::run;
use serde::{Deserialize, Serialize};
use snark_verifier_sdk::halo2::OptimizedPoseidonSpec;
use std::env::var;
use std::fs::File;

use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq, Secp256k1, Secp256k1Affine};
use halo2_ecc::ecc::EcPoint;
use halo2_ecc::ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip};
use halo2_ecc::fields::FieldChip;
use halo2_ecc::secp256k1::{FpChip, FqChip};

const R_F: usize = 8;
const R_P: [usize; 16] = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];
const LEVELS: usize = 5;
const N_INS: usize = 2;
const N_OUTS: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CircuitInput {
    pub root: String,
    pub public_amount: String,
    pub ext_data_hash: String,
    pub input_nullifier: [String; N_INS],
    pub in_amount: [String; N_INS],
    pub nullifying_key: String,
    pub public_key: [String; 2],
    pub signature: [String; 2],
    pub in_blinding: [String; N_INS],
    pub in_path_indices: [[String; LEVELS]; N_INS],
    pub in_path_elements: [[String; LEVELS]; N_INS],
    pub output_commitment: [String; N_OUTS],
    pub out_amount: [String; N_OUTS],
    pub out_pubkey: [String; N_OUTS],
    pub out_blinding: [String; N_OUTS],
    pub hash_message: String,
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

fn cond_swap<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &mut GateChip<F>,
    a: AssignedValue<F>,
    b: AssignedValue<F>,
    swap: AssignedValue<F>,
) -> (AssignedValue<F>, AssignedValue<F>) {
    // Compute (1 - swap) * a and (1 - swap) * b
    let swap_a = gate.mul_not(ctx, swap.clone(), a.clone());
    let swap_b = gate.mul_not(ctx, swap.clone(), b.clone());

    // Compute (1 - swap) * a + swap * b and (1 - swap) * b + swap * a
    let l = gate.mul_add(ctx, swap.clone(), b, swap_a);
    let r = gate.mul_add(ctx, swap, a, swap_b);

    return (l, r);
}

fn poseidon2<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &mut GateChip<F>,
    inputs: &[AssignedValue<F>; 2],
) -> AssignedValue<F> {
    let zero = ctx.load_constant(F::ZERO); // circomlib's poseidon hash requires zero constant at the beginning
    let mut poseidon = PoseidonHasher::<F, 3, 2>::new(OptimizedPoseidonSpec::new::<R_F, 57, 0>());
    poseidon.initialize_consts(ctx, gate);
    poseidon.hash_fix_len_array(ctx, gate, &[zero, inputs[0], inputs[1]])
}

fn poseidon3<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &mut GateChip<F>,
    inputs: &[AssignedValue<F>; 3],
) -> AssignedValue<F> {
    let zero = ctx.load_constant(F::ZERO); // circomlib's poseidon hash requires zero constant at the beginning
    let mut poseidon = PoseidonHasher::<F, 4, 3>::new(OptimizedPoseidonSpec::new::<R_F, 56, 0>());
    poseidon.initialize_consts(ctx, gate);
    poseidon.hash_fix_len_array(ctx, gate, &[zero, inputs[0], inputs[1]])
}

fn poseidon7<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &mut GateChip<F>,
    inputs: &[AssignedValue<F>; 7],
) -> AssignedValue<F> {
    let zero = ctx.load_constant(F::ZERO); // circomlib's poseidon hash requires zero constant at the beginning
    let mut poseidon = PoseidonHasher::<F, 8, 7>::new(OptimizedPoseidonSpec::new::<R_F, 56, 0>());
    poseidon.initialize_consts(ctx, gate);
    poseidon.hash_fix_len_array(
        ctx,
        gate,
        &[zero, inputs[0], inputs[1], inputs[2], inputs[3], inputs[4], inputs[5]],
    )
}

fn merkle_proof<F: BigPrimeField>(
    ctx: &mut Context<F>,
    gate: &mut GateChip<F>,
    path_elements: &[AssignedValue<F>; LEVELS],
    path_indices: &[AssignedValue<F>; LEVELS],
    leaf: AssignedValue<F>,
    root: AssignedValue<F>,
) {
    let mut cur_leaf = leaf.clone();
    for i in 0..LEVELS {
        let (l, r) = cond_swap(ctx, gate, cur_leaf, path_elements[i], path_indices[i]);
        cur_leaf = poseidon2(ctx, gate, &[l, r]);
    }
    ctx.constrain_equal(&cur_leaf, &root);
}

fn transaction<F: BigPrimeField>(
    builder: &mut BaseCircuitBuilder<F>,
    inp: CircuitInput,
    make_public: &mut Vec<AssignedValue<F>>,
) {
    // create a Range chip that contains methods for basic arithmetic operations
    let range = builder.range_chip();
    let ctx = builder.main(0);
    let mut gate = GateChip::<F>::default();

    let path = "examples/transaction_circuit.config";
    let params: CircuitParams = serde_json::from_reader(
        File::open(path).unwrap_or_else(|e| panic!("{path} does not exist: {e:?}")),
    )
    .unwrap();

    let fp_chip = FpChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let fq_chip = FqChip::<F>::new(&range, params.limb_bits, params.num_limbs);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    // Read the input from the JSON file
    macro_rules! load_witness_from_str {
        ($x: expr) => {
            ctx.load_witness(
                F::from_str_vartime(&$x).expect("deserialize field element should not fail"),
            )
        };
    }

    macro_rules! load_witness_from_str_arr {
        ($x: expr) => {
            $x.map(|x| {
                ctx.load_witness(
                    F::from_str_vartime(&x).expect("deserialize field element should not fail"),
                )
            })
        };
    }

    let root = load_witness_from_str!(inp.root);
    let public_amount = load_witness_from_str!(inp.public_amount);
    let ext_data_hash = load_witness_from_str!(inp.ext_data_hash);
    let input_nullifier = load_witness_from_str_arr!(inp.input_nullifier);
    let in_amount = load_witness_from_str_arr!(inp.in_amount);
    let nullifying_key = load_witness_from_str!(inp.nullifying_key);
    let public_key = inp
        .public_key
        .map(|x| Fp::from_str_vartime(&x).expect("deserialize field element should not fail"));
    let signature = inp.signature.map(|x: String| {
        Fq::from_str_vartime(&x).expect("deserialize field element should not fail")
    });
    let in_blinding = load_witness_from_str_arr!(inp.in_blinding);
    let in_path_indices = inp.in_path_indices.map(|x| load_witness_from_str_arr!(x));
    let in_path_elements = inp.in_path_elements.map(|x| load_witness_from_str_arr!(x));
    let output_commitment = load_witness_from_str_arr!(inp.output_commitment);
    let out_amount = load_witness_from_str_arr!(inp.out_amount);
    let out_pubkey = load_witness_from_str_arr!(inp.out_pubkey);
    let out_blinding = load_witness_from_str_arr!(inp.out_blinding);
    let hash_message =
        Fq::from_str_vartime(&inp.hash_message).expect("deserialize field element should not fail");

    let [signature_r, signature_s] = signature.map(|x| fq_chip.load_private(ctx, x));
    let hash_message = fq_chip.load_private(ctx, hash_message);
    let public_key = EcPoint::<F, Fp>::new(public_key[0], public_key[1]);
    let public_key = ecc_chip.load_private_unchecked(ctx, (public_key.x, public_key.y));

    // make_public.extend(vec![root, public_amount, ext_data_hash]);
    // make_public.extend(input_nullifier);
    // make_public.extend(output_commitment);

    // hash public inputs
    let _hash = poseidon7(
        ctx,
        &mut gate,
        &[
            root,
            public_amount,
            ext_data_hash,
            input_nullifier[0],
            input_nullifier[1],
            output_commitment[0],
            output_commitment[1],
        ],
    );

    // TODO: ENFORCE hash_message = hash

    // verify ECDSA
    let res = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
        &ecc_chip,
        ctx,
        public_key,
        signature_r,
        signature_s,
        hash_message,
        4,
        4,
    );
    let one = ctx.load_constant(F::ONE);
    ctx.constrain_equal(&res, &one);

    for i in 0..N_INS {
        // verify input nullifier
        let nullifier =
            poseidon3(ctx, &mut gate, &[nullifying_key.clone(), in_amount[i], in_blinding[i]]);
        ctx.constrain_equal(&nullifier, &input_nullifier[i]);

        let in_commitment = poseidon2(ctx, &mut gate, &[in_amount[i], in_blinding[i]]);

        merkle_proof(
            ctx,
            &mut gate,
            &in_path_elements[i],
            &in_path_indices[i],
            in_commitment,
            root,
        );
    }
}

fn main() {
    env_logger::init();

    let args = Cli::parse();
    run(transaction, args);
}
// TODO: Add tests for poseidon
