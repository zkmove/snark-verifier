use crate::{
    loader,
    loader::{
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
        test::kzg::{
            halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_verify, halo2_kzg_prepare,
            BITS, LIMBS,
        },
        transcript::halo2::{ChallengeScalar, PoseidonTranscript as GenericPoseidonTranscript},
    },
    util::{arithmetic::fe_to_limbs, Itertools},
    verifier::{self, PlonkVerifier},
};
use halo2_curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2_ecc::{
    fields::fp::{FpConfig, FpStrategy},
    gates::{Context, ContextParams},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk,
    plonk::{Circuit, Column, Instance},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::ParamsKZG,
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use paste::paste;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use serde::{Deserialize, Serialize};
use std::rc::Rc;

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

    let accumulators = snarks
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

    let acccumulator = {
        let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _, _>::new(loader, as_proof);
        let proof = As::read_proof(as_vk, &accumulators, &mut transcript).unwrap();
        As::verify(as_vk, &accumulators, &proof).unwrap()
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

        let accumulators = snarks
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
        let (accumulator, as_proof) = {
            let mut transcript = PoseidonTranscript::<NativeLoader, _, _>::new(Vec::new());
            let accumulator = As::create_proof(
                &as_pk,
                &accumulators,
                &mut transcript,
                ChaCha20Rng::from_seed(Default::default()),
            )
            .unwrap();
            (accumulator, transcript.finalize())
        };

        let KzgAccumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y].map(fe_to_limbs::<_, _, LIMBS, BITS>).concat();

        Self {
            svk,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
            as_vk: as_pk.vk(),
            as_proof: Value::known(as_proof),
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

// for tuning the circuit
#[derive(Serialize, Deserialize)]
pub struct Halo2VerifierCircuitConfigParams {
    pub strategy: FpStrategy,
    pub degree: u32,
    pub num_advice: usize,
    pub num_lookup_advice: usize,
    pub num_fixed: usize,
    pub lookup_bits: usize,
    pub limb_bits: usize,
    pub num_limbs: usize,
}

#[derive(Clone)]
pub struct Halo2VerifierCircuitConfig {
    pub base_field_config: FpConfig<Fr, Fq>,
    pub instance: Column<Instance>,
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
