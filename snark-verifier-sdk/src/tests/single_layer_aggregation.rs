use super::StandardPlonk;
use crate::evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier};
use crate::halo2::aggregation::AggregationCircuit;
use crate::CircuitExt;
use crate::{gen_pk, halo2::gen_snark_shplonk};
use ark_std::test_rng;
use halo2_base::halo2_proofs;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::poly::commitment::Params;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::utils::fs::gen_srs;
use snark_verifier::pcs::kzg::{Bdfg21, Kzg};
use std::path::Path;
#[test]
fn test_aggregation_evm_verification() {
    std::env::set_var("VERIFY_CONFIG", "./configs/example_evm_accumulator.config");
    let k = 8;
    let k_agg = 21;

    let mut rng = test_rng();

    let circuit = StandardPlonk::rand(&mut rng);
    let params_outer = gen_srs(k_agg);
    let params_inner = {
        let mut params = params_outer.clone();
        params.downsize(k);
        params
    };
    let pk_inner = gen_pk(&params_inner, &circuit, Some(Path::new("data/inner.pkey")));
    let snarks = (0..3)
        .map(|i| {
            gen_snark_shplonk(
                &params_inner,
                &pk_inner,
                circuit.clone(),
                &mut rng,
                Some(Path::new(&format!("data/inner_{}.snark", i).to_string())),
            )
        })
        .collect::<Vec<_>>();
    println!("finished snark generation");

    let agg_circuit = AggregationCircuit::new(&params_outer, snarks, &mut rng);
    let pk_outer = gen_pk(&params_outer, &agg_circuit, Some(Path::new("data/outer.pkey")));
    println!("finished outer pk generation");
    let instances = agg_circuit.instances();
    let proof = gen_evm_proof_shplonk(
        &params_outer,
        &pk_outer,
        agg_circuit.clone(),
        instances.clone(),
        &mut rng,
    );
    println!("finished aggregation generation");

    let deployment_code = gen_evm_verifier::<AggregationCircuit, Kzg<Bn256, Bdfg21>>(
        &params_outer,
        pk_outer.get_vk(),
        agg_circuit.num_instance(),
        Some(Path::new("data/single_layer_recur.sol")),
    );

    println!("finished bytecode generation");
    evm_verify(deployment_code, instances, proof)
}
