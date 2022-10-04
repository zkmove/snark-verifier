use super::{BITS, LIMBS};
use crate::{
    loader::{self, native::NativeLoader},
    pcs::{
        kzg::{
            Bdfg21, Kzg, KzgAccumulator, KzgAs, KzgAsProvingKey, KzgAsVerifyingKey,
            KzgSuccinctVerifyingKey, LimbsEncoding,
        },
        AccumulationScheme, AccumulationSchemeProver,
    },
    system::{
        self,
        halo2::{
            compile, read_or_create_srs, transcript::halo2::ChallengeScalar, Config,
            Halo2VerifierCircuitConfig, Halo2VerifierCircuitConfigParams,
        },
    },
    util::arithmetic::fe_to_limbs,
    verifier::{self, PlonkVerifier},
    Protocol,
};
use ark_std::{end_timer, start_timer};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_ecc::{
    fields::fp::FpConfig,
    gates::{Context, ContextParams},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{self, create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, ProvingKey},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::{AccumulatorStrategy, SingleStrategy},
        },
        VerificationStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use rand::rngs::OsRng;
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
type PoseidonTranscript<L, S, B> =
    system::halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, B, T, RATE, R_F, R_P>;

type Pcs = Kzg<Bn256, Bdfg21>;
type Svk = KzgSuccinctVerifyingKey<G1Affine>;
type As = KzgAs<Pcs>;
type AsPk = KzgAsProvingKey<G1Affine>;
type AsVk = KzgAsVerifyingKey;
type Plonk = verifier::Plonk<Pcs, LimbsEncoding<LIMBS, BITS>>;

pub struct Snark {
    protocol: Protocol<G1Affine>,
    instances: Vec<Vec<Fr>>,
    proof: Vec<u8>,
}

impl Snark {
    pub fn new(protocol: Protocol<G1Affine>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> Self {
        Self { protocol, instances, proof }
    }
}

impl From<Snark> for SnarkWitness {
    fn from(snark: Snark) -> Self {
        Self {
            protocol: snark.protocol,
            instances: snark
                .instances
                .into_iter()
                .map(|instances| instances.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

#[derive(Clone)]
pub struct SnarkWitness {
    protocol: Protocol<G1Affine>,
    instances: Vec<Vec<Value<Fr>>>,
    proof: Value<Vec<u8>>,
}

impl SnarkWitness {
    fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            instances: self
                .instances
                .iter()
                .map(|instances| vec![Value::unknown(); instances.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }

    fn proof(&self) -> Value<&[u8]> {
        self.proof.as_ref().map(Vec::as_slice)
    }
}

pub fn aggregate<'a, 'b>(
    svk: &Svk,
    loader: &Rc<Halo2Loader<'a, 'b>>,
    snarks: &[SnarkWitness],
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

#[derive(Clone)]
pub struct AggregationCircuit {
    svk: Svk,
    snarks: Vec<SnarkWitness>,
    instances: Vec<Fr>,
    as_vk: AsVk,
    as_proof: Value<Vec<u8>>,
}

impl AggregationCircuit {
    pub fn new(params: &ParamsKZG<Bn256>, snarks: impl IntoIterator<Item = Snark>) -> Self {
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

    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
    }

    pub fn num_instance() -> Vec<usize> {
        vec![4 * LIMBS]
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }

    pub fn as_proof(&self) -> Value<&[u8]> {
        self.as_proof.as_ref().map(Vec::as_slice)
    }
}

impl Circuit<Fr> for AggregationCircuit {
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
                    aggregate(&self.svk, &loader, &self.snarks, &self.as_vk, self.as_proof());

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

pub fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    read_or_create_srs::<G1Affine, _>(k, |k| {
        ParamsKZG::<Bn256>::setup(k, ChaCha20Rng::from_seed(Default::default()))
    })
}

pub fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk_time = start_timer!(|| "vkey");
    let vk = keygen_vk(params, circuit).unwrap();
    end_timer!(vk_time);
    let pk_time = start_timer!(|| "pkey");
    let pk = keygen_pk(params, vk, circuit).unwrap();
    end_timer!(pk_time);
    pk
}

pub trait TargetCircuit {
    const TARGET_CIRCUIT_K: u32;
    const PUBLIC_INPUT_SIZE: usize;
    const N_PROOFS: usize;
    const NAME: &'static str;

    type Circuit: Circuit<Fr>;

    fn default_circuit() -> Self::Circuit;
    fn instances() -> Vec<Vec<Fr>>;
}

pub fn create_snark_shplonk<T: TargetCircuit>(
    accumulator_indices: Option<Vec<(usize, usize)>>,
) -> (ParamsKZG<Bn256>, Snark) {
    println!("CREATING SNARK FOR: {}", T::NAME);
    let circuits = (0..T::N_PROOFS).map(|_| T::default_circuit()).collect_vec();
    let config = if let Some(accumulator_indices) = accumulator_indices {
        Config::kzg()
            .set_zk(true)
            .with_num_proof(T::N_PROOFS)
            .with_accumulator_indices(accumulator_indices)
    } else {
        Config::kzg().set_zk(true).with_num_proof(T::N_PROOFS)
    };
    let params = gen_srs(T::TARGET_CIRCUIT_K);

    let pk = gen_pk(&params, &circuits[0]);
    let num_instance = T::instances().iter().map(|instances| instances.len()).collect();
    let protocol = compile(&params, pk.get_vk(), config.with_num_instance(num_instance));

    let proof_time = start_timer!(|| "create proof");
    // usual shenanigans to turn nested Vec into nested slice
    let instances0: Vec<Vec<Vec<Fr>>> = circuits.iter().map(|_| T::instances()).collect_vec();
    let instances1: Vec<Vec<&[Fr]>> = instances0
        .iter()
        .map(|instances| instances.iter().map(Vec::as_slice).collect_vec())
        .collect_vec();
    let instances2: Vec<&[&[Fr]]> = instances1.iter().map(Vec::as_slice).collect_vec();
    // TODO: need to cache the instances as well!

    let proof = {
        let path = format!("./data/proof_{}.data", T::NAME);
        match std::fs::File::open(path.as_str()) {
            Ok(mut file) => {
                let mut buf = vec![];
                file.read_to_end(&mut buf).unwrap();
                buf
            }
            Err(_) => {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, Vec<u8>, _>::init(Vec::new());
                create_proof::<KZGCommitmentScheme<_>, ProverSHPLONK<_>, ChallengeScalar<_>, _, _, _>(
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
        let strategy = AccumulatorStrategy::new(verifier_params);
        let mut transcript =
            <PoseidonTranscript<NativeLoader, Cursor<Vec<u8>>, _> as TranscriptReadBuffer<
                _,
                _,
                _,
            >>::init(Cursor::new(proof.clone()));
        assert!(VerificationStrategy::<_, VerifierSHPLONK<_>>::finalize(
            verify_proof::<_, VerifierSHPLONK<_>, _, _, _>(
                verifier_params,
                pk.get_vk(),
                strategy,
                instances2.as_slice(),
                &mut transcript,
            )
            .unwrap()
        ))
    }
    end_timer!(verify_time);

    (params, Snark::new(protocol.clone(), instances0.into_iter().flatten().collect_vec(), proof))
}
