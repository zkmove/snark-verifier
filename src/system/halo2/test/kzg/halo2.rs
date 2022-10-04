use crate::{
    loader::{
        self,
        halo2::test::{Snark, SnarkWitness, StandardPlonk},
        native::NativeLoader,
    },
    pcs::{
        kzg::{
            Bdfg21, Kzg, KzgAccumulator, KzgAs, KzgAsProvingKey, KzgAsVerifyingKey,
            KzgSuccinctVerifyingKey, LimbsEncoding,
        },
        AccumulationScheme, AccumulationSchemeProver,
    },
    system::halo2::{
        test::{
            kzg::{
                halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_verify,
                halo2_kzg_prepare, BITS, LIMBS,
            },
            load_verify_circuit_degree,
        },
        transcript::halo2::{ChallengeScalar, PoseidonTranscript as GenericPoseidonTranscript},
        Halo2VerifierCircuitConfig, Halo2VerifierCircuitConfigParams,
    },
    util::{arithmetic::fe_to_limbs, Itertools},
    verifier::{self, PlonkVerifier},
};
use ark_std::{end_timer, start_timer};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_ecc::{
    fields::fp::FpConfig,
    gates::{Context, ContextParams},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{self, create_proof, verify_proof, Circuit},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{
    io::{Cursor, Read, Write},
    rc::Rc,
};

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 60;

type Halo2Loader<'a, 'b> = loader::halo2::Halo2Loader<'a, 'b, G1Affine>;
type PoseidonTranscript<L, S, B> = GenericPoseidonTranscript<G1Affine, L, S, B, T, RATE, R_F, R_P>;

type Pcs = Kzg<Bn256, Bdfg21>;
type Svk = KzgSuccinctVerifyingKey<G1Affine>;
type As = KzgAs<Pcs>;
type AsPk = KzgAsProvingKey<G1Affine>;
type AsVk = KzgAsVerifyingKey;
type Plonk = verifier::Plonk<Pcs, LimbsEncoding<LIMBS, BITS>>;

pub fn accumulate<'a, 'b>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a, 'b>>,
    snarks: &[SnarkWitness<G1Affine>],
    as_vk: &AsVk,
    as_proof: Value<&'_ [u8]>,
) -> KzgAccumulator<G1Affine, Rc<Halo2Loader<'a, 'b>>> {
    let assign_instances = |instances: &[Vec<Value<Fr>>]| {
        instances
            .iter()
            .map(|instances| {
                instances.iter().map(|instance| loader.assign_scalar(*instance)).collect_vec()
            })
            .collect_vec()
    };

    let mut accumulators = snarks
        .iter()
        .flat_map(|snark| {
            let instances = assign_instances(&snark.instances);
            let mut transcript =
                PoseidonTranscript::<Rc<Halo2Loader>, _, _>::new(loader, snark.proof());
            let proof =
                Plonk::read_proof(svk, &snark.protocol, &instances, &mut transcript).unwrap();
            Plonk::succinct_verify(svk, &snark.protocol, &instances, &proof).unwrap()
        })
        .collect_vec();

    let acccumulator = if accumulators.len() > 1 {
        let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _, _>::new(loader, as_proof);
        let proof = As::read_proof(as_vk, &accumulators, &mut transcript).unwrap();
        As::verify(as_vk, &accumulators, &proof).unwrap()
    } else {
        accumulators.pop().unwrap()
    };

    acccumulator
}

pub struct Accumulation {
    svk: Svk,
    snarks: Vec<SnarkWitness<G1Affine>>,
    instances: Vec<Fr>,
    as_vk: AsVk,
    as_proof: Value<Vec<u8>>,
}

impl Accumulation {
    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
    }

    pub fn new(
        params: &ParamsKZG<Bn256>,
        snarks: impl IntoIterator<Item = Snark<G1Affine>>,
    ) -> Self {
        let svk = params.get_g()[0].into();
        let snarks = snarks.into_iter().collect_vec();

        let mut accumulators = snarks
            .iter()
            .flat_map(|snark| {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _, _>::new(snark.proof.as_slice());
                let proof =
                    Plonk::read_proof(&svk, &snark.protocol, &snark.instances, &mut transcript)
                        .unwrap();
                Plonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof).unwrap()
            })
            .collect_vec();

        let as_pk = AsPk::new(Some((params.get_g()[0], params.get_g()[1])));
        let (accumulator, as_proof) = if accumulators.len() > 1 {
            let mut transcript = PoseidonTranscript::<NativeLoader, _, _>::new(Vec::new());
            let accumulator = As::create_proof(
                &as_pk,
                &accumulators,
                &mut transcript,
                ChaCha20Rng::from_seed(Default::default()),
            )
            .unwrap();
            (accumulator, Value::known(transcript.finalize()))
        } else {
            (accumulators.pop().unwrap(), Value::unknown())
        };

        let KzgAccumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y].map(fe_to_limbs::<_, _, LIMBS, BITS>).concat();

        Self {
            svk,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
            as_vk: as_pk.vk(),
            as_proof,
        }
    }

    pub fn two_snark() -> Self {
        let (params, snark1) = {
            const K: u32 = 9;
            let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(true, 1),
                StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
            );
            let snark = halo2_kzg_create_snark!(
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                PoseidonTranscript<_, _, _>,
                PoseidonTranscript<_, _, _>,
                ChallengeScalar<_>,
                &params,
                &pk,
                &protocol,
                &circuits
            );
            (params, snark)
        };
        let snark2 = {
            const K: u32 = 9;
            let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(true, 1),
                StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
            );
            halo2_kzg_create_snark!(
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                PoseidonTranscript<_, _, _>,
                PoseidonTranscript<_, _, _>,
                ChallengeScalar<_>,
                &params,
                &pk,
                &protocol,
                &circuits
            )
        };
        Self::new(&params, [snark1, snark2])
    }

    pub fn two_snark_with_accumulator() -> Self {
        let (params, pk, protocol, circuits) = {
            const K: u32 = 22;
            halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(true, 2, Self::accumulator_indices()),
                Self::two_snark()
            )
        };
        let snark = halo2_kzg_create_snark!(
            ProverSHPLONK<_>,
            VerifierSHPLONK<_>,
            PoseidonTranscript<_, _, _>,
            PoseidonTranscript<_, _, _>,
            ChallengeScalar<_>,
            &params,
            &pk,
            &protocol,
            &circuits
        );
        Self::new(&params, [snark])
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl Circuit<Fr> for Accumulation {
    type Config = Halo2VerifierCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            svk: self.svk,
            snarks: self.snarks.iter().map(SnarkWitness::without_witnesses).collect(),
            instances: Vec::new(),
            as_vk: self.as_vk,
            as_proof: Value::unknown(),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        let path = "./src/configs/verify_circuit.config";
        let params_str =
            std::fs::read_to_string(path).expect(format!("{} should exist", path).as_str());
        let params: Halo2VerifierCircuitConfigParams =
            serde_json::from_str(params_str.as_str()).unwrap();

        assert!(
            params.limb_bits == BITS && params.num_limbs == LIMBS,
            "For now we fix limb_bits = {}, otherwise change code",
            BITS
        );
        let base_field_config = FpConfig::configure(
            meta,
            params.strategy,
            params.num_advice,
            params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            halo2_ecc::utils::modulus::<Fq>(),
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self::Config { base_field_config, instance }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        let mut layouter = layouter.namespace(|| "aggregation");
        config.base_field_config.load_lookup_table(&mut layouter)?;

        // Need to trick layouter to skip first pass in get shape mode
        let using_simple_floor_planner = true;
        let mut first_pass = true;
        let mut final_pair = None;
        layouter.assign_region(
            || "",
            |region| {
                if using_simple_floor_planner && first_pass {
                    first_pass = false;
                    return Ok(());
                }
                let ctx = Context::new(
                    region,
                    ContextParams {
                        num_advice: config.base_field_config.range.gate.num_advice,
                        using_simple_floor_planner,
                        first_pass,
                    },
                );

                let loader = Halo2Loader::new(&config.base_field_config, ctx);
                let KzgAccumulator { lhs, rhs } =
                    accumulate(&self.svk, &loader, &self.snarks, &self.as_vk, self.as_proof());

                // REQUIRED STEP
                loader.finalize();
                final_pair = Some((lhs.assigned(), rhs.assigned()));

                Ok(())
            },
        )?;
        let (lhs, rhs) = final_pair.unwrap();
        Ok({
            // TODO: use less instances by following Scroll's strategy of keeping only last bit of y coordinate
            let mut layouter = layouter.namespace(|| "expose");
            for (i, assigned_instance) in lhs
                .x
                .truncation
                .limbs
                .iter()
                .chain(lhs.y.truncation.limbs.iter())
                .chain(rhs.x.truncation.limbs.iter())
                .chain(rhs.y.truncation.limbs.iter())
                .enumerate()
            {
                layouter.constrain_instance(
                    assigned_instance.cell().clone(),
                    config.instance,
                    i,
                )?;
            }
        })
    }
}

macro_rules! test {
    (@ $(#[$attr:meta],)* $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        paste! {
            $(#[$attr])*
            fn [<test_shplonk_ $name>]() {
                let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                    $k,
                    $config,
                    $create_circuit
                );
                let snark = halo2_kzg_create_snark!(
                    ProverSHPLONK<_>,
                    VerifierSHPLONK<_>,
                    Blake2bWrite<_, _, _>,
                    Blake2bRead<_, _, _>,
                    Challenge255<_>,
                    &params,
                    &pk,
                    &protocol,
                    &circuits
                );
                halo2_kzg_native_verify!(
                    Plonk,
                    params,
                    &snark.protocol,
                    &snark.instances,
                    &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
                );
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test], $name, $k, $config, $create_circuit);
    };
    ($(#[$attr:meta],)* $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test] $(,#[$attr])*, $name, $k, $config, $create_circuit);
    };
}

test!(
    // create aggregation circuit A that aggregates two simple snarks {B,C}, then verify proof of this aggregation circuit A
    zk_aggregate_two_snarks,
    21,
    halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark()
);
test!(
    // create aggregation circuit A that aggregates two copies of same aggregation circuit B that aggregates two simple snarks {C, D}, then verifies proof of this aggregation circuit A
    zk_aggregate_two_snarks_with_accumulator,
    22, // 22 = 21 + 1 since there are two copies of circuit B
    halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark_with_accumulator()
);

pub trait TargetCircuit: Circuit<Fr> {
    const TARGET_CIRCUIT_K: u32;
    const PUBLIC_INPUT_SIZE: usize;
    const N_PROOFS: usize;
    const NAME: &'static str;

    fn default_circuit() -> Self;
    fn instances(&self) -> Vec<Vec<Fr>>;
}

pub fn create_snark<T: TargetCircuit>() -> (ParamsKZG<Bn256>, Snark<G1Affine>) {
    let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
        T::TARGET_CIRCUIT_K,
        halo2_kzg_config!(true, T::N_PROOFS),
        T::default_circuit()
    );

    let proof_time = start_timer!(|| "create proof");
    // usual shenanigans to turn nested Vec into nested slice
    let instances0: Vec<Vec<Vec<Fr>>> =
        circuits.iter().map(|circuit| T::instances(circuit)).collect_vec();
    let instances1: Vec<Vec<&[Fr]>> = instances0
        .iter()
        .map(|instances| instances.iter().map(Vec::as_slice).collect_vec())
        .collect_vec();
    let instances2: Vec<&[&[Fr]]> = instances1.iter().map(Vec::as_slice).collect_vec();
    // TODO: need to cache the instances as well!

    let proof = {
        let path = format!("./src/system/halo2/test/data/proof_{}.data", T::NAME);
        match std::fs::File::open(path.as_str()) {
            Ok(mut file) => {
                let mut buf = vec![];
                file.read_to_end(&mut buf).unwrap();
                buf
            }
            Err(_) => {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, Vec<u8>, _>::init(Vec::new());
                create_proof::<KZGCommitmentScheme<_>, ProverSHPLONK<_>, _, _, _, _>(
                    &params,
                    &pk,
                    &circuits,
                    instances2.as_slice(),
                    &mut ChaCha20Rng::from_seed(Default::default()),
                    &mut transcript,
                )
                .unwrap();
                let proof = transcript.finalize();
                let mut file = std::fs::File::create(path.as_str()).unwrap();
                file.write_all(&proof).unwrap();
                proof
            }
        }
    };
    end_timer!(proof_time);

    let verify_time = start_timer!(|| "verify proof");
    {
        let verifier_params = params.verifier_params();
        let strategy = SingleStrategy::new(&params);
        let mut transcript =
            <PoseidonTranscript<NativeLoader, Cursor<Vec<u8>>, _> as TranscriptReadBuffer<
                _,
                _,
                _,
            >>::init(Cursor::new(proof.clone()));
        verify_proof::<_, VerifierSHPLONK<_>, _, _, _>(
            verifier_params,
            pk.get_vk(),
            strategy,
            instances2.as_slice(),
            &mut transcript,
        )
        .unwrap()
    }
    end_timer!(verify_time);

    (params, Snark::new(protocol.clone(), instances0.into_iter().flatten().collect_vec(), proof))
}

pub mod zkevm {
    use std::marker::PhantomData;

    use super::*;
    use halo2_mpt::eth::block_header::EthBlockHeaderTestCircuit;
    use hex::FromHex;
    use zkevm_circuit_benchmarks::evm_circuit::TestCircuit as EvmCircuit;
    use zkevm_circuits::evm_circuit::witness::RwMap;
    use zkevm_circuits::state_circuit::StateCircuit;

    impl TargetCircuit for EvmCircuit<Fr> {
        const TARGET_CIRCUIT_K: u32 = 18;
        const PUBLIC_INPUT_SIZE: usize = 0; // (Self::TARGET_CIRCUIT_K * 2) as usize;
        const N_PROOFS: usize = 1;
        const NAME: &'static str = "zkevm";

        fn default_circuit() -> Self {
            Self::default()
        }
        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![]
        }
    }

    fn evm_verify_circuit() -> Accumulation {
        let (params, evm_snark) = create_snark::<EvmCircuit<Fr>>();
        println!("creating aggregation circuit");
        Accumulation::new(&params, [evm_snark])
    }

    test!(
        bench_evm_circuit,
        load_verify_circuit_degree(),
        halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
        evm_verify_circuit()
    );

    impl TargetCircuit for StateCircuit<Fr> {
        const TARGET_CIRCUIT_K: u32 = 18;
        const PUBLIC_INPUT_SIZE: usize = 0; //(Self::TARGET_CIRCUIT_K * 2) as usize;
        const N_PROOFS: usize = 1;
        const NAME: &'static str = "state-circuit";

        fn default_circuit() -> Self {
            StateCircuit::<Fr>::new(Fr::default(), RwMap::default(), 1)
        }
        fn instances(&self) -> Vec<Vec<Fr>> {
            self.instance()
        }
    }

    fn state_verify_circuit() -> Accumulation {
        let (params, snark) = create_snark::<StateCircuit<Fr>>();
        println!("creating aggregation circuit");
        Accumulation::new(&params, [snark])
    }

    test!(
        bench_state_circuit,
        load_verify_circuit_degree(),
        halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
        state_verify_circuit()
    );

    fn evm_and_state_aggregation_circuit() -> Accumulation {
        let (params, evm_snark) = create_snark::<EvmCircuit<Fr>>();
        let (_, state_snark) = create_snark::<StateCircuit<Fr>>();
        println!("creating aggregation circuit");
        Accumulation::new(&params, [evm_snark, state_snark])
    }

    test!(
        bench_evm_and_state,
        load_verify_circuit_degree(),
        halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
        evm_and_state_aggregation_circuit()
    );

    impl TargetCircuit for EthBlockHeaderTestCircuit<Fr> {
        const TARGET_CIRCUIT_K: u32 = 15;
        const PUBLIC_INPUT_SIZE: usize = 0; //(Self::TARGET_CIRCUIT_K * 2) as usize;
        const N_PROOFS: usize = 1;
        const NAME: &'static str = "eth";

        fn default_circuit() -> Self {
            let input_hex = "f90201a0d7519abd494a823b2c9c28908eaf250fe4a6287d747f1cc53a5a193b6533a549a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944675c7e5baafbffbca748158becba61ef3b0a263a025000d51f040ee5c473fed74eda9ace87d55a35187b11bcde6f5176025c395bfa0a5800a6de6d28d7425ff72714af2af769b9f8f9e1baf56fb42f793fbb40fde07a056e1062a3dc63791e8a8496837606b14062da70ee69178cea97d6eeb5047550cb9010000236420014dc00423903000840002280080282100004704018340c0241c20011211400426000f900001d8088000011006020002ce98bc00c0000020c9a02040000688040200348c3a0082b81402002814922008085d008008200802802c4000130000101703124801400400018008a6108002020420144011200070020bc0202681810804221304004800088600300000040463614a000e200201c00611c0008e800b014081608010a0218a0b410010082000428209080200f50260a00840006700100f40a000000400000448301008c4a00341040e343500800d06250020010215200c008018002c88350404000bc5000a8000210c00724a0d0a4010210a448083eee2468401c9c3808343107884633899e780a07980d8d1f15474c9185e4d1cef5f207167735009daad2eb6af6da37ffba213c28800000000000000008501e08469e600000000000000000000000000000000000000000000000000000000000000000000000000000000";
            let input_bytes_pre: Vec<u8> = Vec::from_hex(input_hex).unwrap();
            let input_bytes: Vec<Option<u8>> = input_bytes_pre.iter().map(|x| Some(*x)).collect();
            let input_nones: Vec<Option<u8>> = input_bytes.iter().map(|x| None).collect();

            EthBlockHeaderTestCircuit::<Fr> { inputs: input_bytes, _marker: PhantomData }
        }

        fn instances(&self) -> Vec<Vec<Fr>> {
            vec![]
        }
    }

    fn eth_verify_circuit() -> Accumulation {
        let (params, snark) = create_snark::<EthBlockHeaderTestCircuit<Fr>>();
        Accumulation::new(&params, [snark])
    }
    test!(
        bench_eth_circuit,
        load_verify_circuit_degree(),
        halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
        eth_verify_circuit()
    );
}
