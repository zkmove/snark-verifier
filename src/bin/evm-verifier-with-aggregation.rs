use ark_std::{end_timer, start_timer};
use ethereum_types::Address;
use foundry_evm::executor::{fork::MultiFork, Backend, ExecutorBuilder};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_mpt::eth::block_header::EthBlockHeaderTestCircuit;
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use hex::FromHex;
use itertools::Itertools;
use plonk_verifier::{
    loader::evm::{encode_calldata, EvmLoader},
    pcs::kzg::{Gwc19, Kzg, LimbsEncoding},
    system::halo2::{
        aggregation::{self, create_snark_shplonk, gen_pk, gen_srs, TargetCircuit},
        compile,
        transcript::evm::EvmTranscript,
        Config, BITS, LIMBS,
    },
    verifier::{self, PlonkVerifier},
};
use rand::rngs::OsRng;
use std::{io::Cursor, marker::PhantomData, rc::Rc};

type Pcs = Kzg<Bn256, Gwc19>;
// type As = KzgAs<Pcs>;
type Plonk = verifier::Plonk<Pcs, LimbsEncoding<LIMBS, BITS>>;

fn gen_proof<
    C: Circuit<Fr>,
    E: EncodedChallenge<G1Affine>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, G1Affine, E>,
    TW: TranscriptWriterBuffer<Vec<u8>, G1Affine, E>,
>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    //MockProver::run(params.k(), &circuit, instances.clone()).unwrap().assert_satisfied();

    let instances = instances.iter().map(|instances| instances.as_slice()).collect_vec();
    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, TW, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TR::init(Cursor::new(proof.clone()));
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, TR, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn gen_aggregation_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
    accumulator_indices: Vec<(usize, usize)>,
) -> Vec<u8> {
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(
        params,
        vk,
        Config::kzg()
            .with_num_instance(num_instance.clone())
            .with_accumulator_indices(accumulator_indices),
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(loader.clone());

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::read_proof(&svk, &protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(&svk, &dk, &protocol, &instances, &proof).unwrap();

    loader.deployment_code()
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) {
    let calldata = encode_calldata(&instances, &proof);
    let success = {
        let mut evm = ExecutorBuilder::default()
            .with_gas_limit(u64::MAX.into())
            .build(Backend::new(MultiFork::new().0, None));

        let caller = Address::from_low_u64_be(0xfe);
        let verifier = evm.deploy(caller, deployment_code.into(), 0.into(), None).unwrap().address;
        let result = evm.call_raw(caller, verifier, calldata.into(), 0.into()).unwrap();

        dbg!(result.gas);

        !result.reverted
    };
    assert!(success);
}

pub fn load_aggregation_circuit_degree() -> u32 {
    let path = "./src/configs/verify_circuit.config";
    let params_str =
        std::fs::read_to_string(path).expect(format!("{} file should exist", path).as_str());
    let params: plonk_verifier::system::halo2::Halo2VerifierCircuitConfigParams =
        serde_json::from_str(params_str.as_str()).unwrap();
    params.degree
}

struct EthBlockHeaderCircuit;

impl aggregation::TargetCircuit for EthBlockHeaderCircuit {
    const TARGET_CIRCUIT_K: u32 = 15;
    const PUBLIC_INPUT_SIZE: usize = 0; //(Self::TARGET_CIRCUIT_K * 2) as usize;
    const N_PROOFS: usize = 1;
    const NAME: &'static str = "eth";
    const READABLE_VKEY: bool = true;

    type Circuit = EthBlockHeaderTestCircuit<Fr>;
    fn default_circuit() -> Self::Circuit {
        let input_hex = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e600000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let input_bytes_pre: Vec<u8> = Vec::from_hex(input_hex).unwrap();
        let input_bytes: Vec<Option<u8>> = input_bytes_pre.iter().map(|x| Some(*x)).collect();
        // let input_nones: Vec<Option<u8>> = input_bytes.iter().map(|x| None).collect();

        EthBlockHeaderTestCircuit::<Fr> { inputs: input_bytes, _marker: PhantomData }
    }

    fn instances() -> Vec<Vec<Fr>> {
        vec![]
    }
}

fn default_circuits<T: TargetCircuit>() -> Vec<T::Circuit> {
    (0..T::N_PROOFS).map(|_| T::default_circuit()).collect_vec()
}
fn default_instances<T: TargetCircuit>() -> Vec<Vec<Vec<Fr>>> {
    (0..T::N_PROOFS).map(|_| T::instances()).collect_vec()
}

fn main() {
    let (params_app, snark) = create_snark_shplonk::<EthBlockHeaderCircuit>(
        default_circuits::<EthBlockHeaderCircuit>(),
        default_instances::<EthBlockHeaderCircuit>(),
        None,
    );
    let snarks = vec![snark];
    let agg_circuit = aggregation::AggregationCircuit::new(&params_app, snarks, true);
    println!("finished creating agg_circuit");

    let k = load_aggregation_circuit_degree();
    let params = gen_srs(k);

    let pk_time = start_timer!(|| "agg_circuit vk & pk time");
    let pk = gen_pk(&params, &agg_circuit);
    end_timer!(pk_time);

    let deploy_time = start_timer!(|| "generate aggregation evm verifier code");
    let deployment_code = gen_aggregation_evm_verifier(
        &params,
        pk.get_vk(),
        aggregation::AggregationCircuit::num_instance(),
        aggregation::AggregationCircuit::accumulator_indices(),
    );
    end_timer!(deploy_time);

    let proof_time = start_timer!(|| "create agg_circuit proof");
    let proof = gen_proof::<_, _, EvmTranscript<G1Affine, _, _, _>, EvmTranscript<G1Affine, _, _, _>>(
        &params,
        &pk,
        agg_circuit.clone(),
        agg_circuit.instances(),
    );
    end_timer!(proof_time);

    let verify_time = start_timer!(|| "on-chain verification");
    evm_verify(deployment_code, agg_circuit.instances(), proof);
    end_timer!(verify_time);
}
