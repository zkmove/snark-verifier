use crate::{
    collect_slice, halo2_kzg_config, halo2_kzg_create_snark, halo2_kzg_native_accumulate,
    halo2_kzg_native_verify, halo2_kzg_prepare,
    loader::{halo2::Halo2Loader, native::NativeLoader},
    protocol::{
        halo2::{
            test::{
                kzg::{load_verify_circuit_degree, BITS, LIMBS},
                StandardPlonk,
            },
            util::halo2::ChallengeScalar,
        },
        Protocol, Snark,
    },
    scheme::kzg::{AccumulationScheme, ShplonkAccumulationScheme},
    util::{fe_to_limbs, Curve, Group, Itertools, PrimeCurveAffine},
};
use halo2_ecc::{
    fields::fp::{FpConfig, FpStrategy},
    gates::{Context, ContextParams},
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::{Fq, Fr, G1Affine, G1},
    plonk,
    plonk::{Circuit, Column, Instance},
    poly::{
        commitment::ParamsProver,
        kzg::{
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::AccumulatorStrategy,
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
const R_P: usize = 57;

type PoseidonTranscript<C, L, S, B> =
    crate::loader::halo2::PoseidonTranscript<C, L, S, B, T, RATE, R_F, R_P>;
type SameCurveAccumulation<C, L> = crate::scheme::kzg::SameCurveAccumulation<C, L>;

pub struct SnarkWitness<C: Curve> {
    protocol: Protocol<C>,
    statements: Vec<Vec<Value<<C as Group>::Scalar>>>,
    proof: Value<Vec<u8>>,
}

impl<C: Curve> From<Snark<C>> for SnarkWitness<C> {
    fn from(snark: Snark<C>) -> Self {
        Self {
            protocol: snark.protocol,
            statements: snark
                .statements
                .into_iter()
                .map(|statements| statements.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

impl<C: Curve> SnarkWitness<C> {
    pub fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            statements: self
                .statements
                .iter()
                .map(|statements| vec![Value::unknown(); statements.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }
}

pub fn accumulate<'a, 'b>(
    loader: &Rc<Halo2Loader<'a, 'b, G1Affine>>,
    stretagy: &mut SameCurveAccumulation<G1, Rc<Halo2Loader<'a, 'b, G1Affine>>>,
    snark: &SnarkWitness<G1>,
) -> Result<(), plonk::Error> {
    let mut transcript = PoseidonTranscript::<_, Rc<Halo2Loader<G1Affine>>, _, _>::new(
        loader,
        snark.proof.as_ref().map(|proof| proof.as_slice()),
    );
    let statements = snark
        .statements
        .iter()
        .map(|statements| {
            statements.iter().map(|statement| loader.assign_scalar(*statement)).collect_vec()
        })
        .collect_vec();
    ShplonkAccumulationScheme::accumulate(
        &snark.protocol,
        loader,
        statements,
        &mut transcript,
        stretagy,
    )
    .map_err(|_| plonk::Error::Synthesis)?;
    Ok(())
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

pub struct Accumulation {
    g1: G1Affine,
    snarks: Vec<SnarkWitness<G1>>,
    instances: Vec<Fr>,
}

impl Accumulation {
    pub fn accumulator_indices() -> Vec<(usize, usize)> {
        (0..4 * LIMBS).map(|idx| (0, idx)).collect()
    }

    pub fn two_snark(zk: bool) -> Self {
        const K: u32 = 9;

        let (params, snark1) = {
            let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(zk, 1),
                StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
            );
            let snark = halo2_kzg_create_snark!(
                &params,
                &pk,
                &protocol,
                &circuits,
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                AccumulatorStrategy<_>,
                PoseidonTranscript<_, _, _, _>,
                PoseidonTranscript<_, _, _, _>,
                ChallengeScalar<_>
            );
            (params, snark)
        };
        let snark2 = {
            let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                K,
                halo2_kzg_config!(zk, 1),
                StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
            );
            halo2_kzg_create_snark!(
                &params,
                &pk,
                &protocol,
                &circuits,
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                AccumulatorStrategy<_>,
                PoseidonTranscript<_, _, _, _>,
                PoseidonTranscript<_, _, _, _>,
                ChallengeScalar<_>
            )
        };

        let mut strategy = SameCurveAccumulation::<G1, NativeLoader>::default();
        halo2_kzg_native_accumulate!(
            &snark1.protocol,
            snark1.statements.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark1.proof.as_slice()),
            &mut strategy
        );
        /*halo2_kzg_native_accumulate!(
            &snark2.protocol,
            snark2.statements.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark2.proof.as_slice()),
            &mut strategy
        );*/

        let g1 = params.get_g()[0];
        let accumulator = strategy.finalize(g1.to_curve());
        let instances = [
            accumulator.0.to_affine().x,
            accumulator.0.to_affine().y,
            accumulator.1.to_affine().x,
            accumulator.1.to_affine().y,
        ]
        .map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .concat();

        println!("finished constructing aggregation circuit.");
        Self { g1, snarks: vec![snark1.into() /*, snark2.into()*/], instances }
    }

    pub fn two_snark_with_accumulator(zk: bool) -> Self {
        const K: u32 = 20;

        let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
            K,
            halo2_kzg_config!(zk, 2, Self::accumulator_indices()),
            Self::two_snark(zk)
        );
        let snark = halo2_kzg_create_snark!(
            &params,
            &pk,
            &protocol,
            &circuits,
            ProverSHPLONK<_>,
            VerifierSHPLONK<_>,
            AccumulatorStrategy<_>,
            PoseidonTranscript<_, _, _, _>,
            PoseidonTranscript<_, _, _, _>,
            ChallengeScalar<_>
        );

        let mut strategy = SameCurveAccumulation::<G1, NativeLoader>::default();
        halo2_kzg_native_accumulate!(
            &snark.protocol,
            snark.statements.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark.proof.as_slice()),
            &mut strategy
        );

        let g1 = params.get_g()[0];
        let accumulator = strategy.finalize(g1.to_curve());
        let instances = [
            accumulator.0.to_affine().x,
            accumulator.0.to_affine().y,
            accumulator.1.to_affine().x,
            accumulator.1.to_affine().y,
        ]
        .map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .concat();

        Self { g1, snarks: vec![snark.into()], instances }
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }
}

impl Circuit<Fr> for Accumulation {
    type Config = Halo2VerifierCircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            g1: self.g1,
            snarks: self.snarks.iter().map(SnarkWitness::without_witnesses).collect(),
            instances: Vec::new(),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        let mut folder = std::path::PathBuf::new();
        folder.push("src/configs");
        folder.push("verify_circuit.config");
        let params_str = std::fs::read_to_string(folder.as_path())
            .expect(format!("{} should exist", folder.to_str().unwrap()).as_str());
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

                let loader = Halo2Loader::<G1Affine>::new(&config.base_field_config, ctx);
                let mut strategy = SameCurveAccumulation::default();
                for snark in self.snarks.iter() {
                    accumulate(&loader, &mut strategy, snark)?;
                }
                let (lhs, rhs) = strategy.finalize(self.g1);

                // REQUIRED STEP
                loader.finalize();
                final_pair = Some((lhs, rhs));

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
    (@ #[$($attr:meta),*], $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        paste! {
            $(#[$attr])*
            fn [<test_kzg_shplonk_ $name>]() {
                let (params, pk, protocol, circuits) = halo2_kzg_prepare!(
                    $k,
                    $config,
                    $create_circuit
                );
                let snark = halo2_kzg_create_snark!(
                    &params,
                    &pk,
                    &protocol,
                    &circuits,
                    ProverSHPLONK<_>,
                    VerifierSHPLONK<_>,
                    AccumulatorStrategy<_>,
                    Blake2bWrite<_, _, _>,
                    Blake2bRead<_, _, _>,
                    Challenge255<_>
                );
                /*
                halo2_kzg_native_verify!(
                    params,
                    &snark.protocol,
                    snark.statements,
                    ShplonkAccumulationScheme,
                    &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
                );
                */
            }
        }
    };
    ($name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test], $name, $k, $config, $create_circuit);
    };
    (#[ignore = $reason:literal], $name:ident, $k:expr, $config:expr, $create_circuit:expr) => {
        test!(@ #[test, ignore = $reason], $name, $k, $config, $create_circuit);
    };
}

test!(
    // create aggregation circuit A that aggregates two simple snarks {B,C}, then verify proof of this aggregation circuit A
    zk_aggregate_two_snarks,
    20,
    halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark(true)
);
test!(
    // create aggregation circuit A that aggregates two copies of same aggregation circuit B that aggregates two simple snarks {C, D}, then verifies proof of this aggregation circuit A
    zk_aggregate_two_snarks_with_accumulator,
    21, // 21 = 20 + 1 since there are two copies of circuit B
    halo2_kzg_config!(true, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark_with_accumulator(true)
);
// same as above but with zero-knowledge turned off
test!(
    aggregate_two_snarks,
    20,
    halo2_kzg_config!(false, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark(false)
);
test!(
    aggregate_two_snarks_with_accumulator,
    21,
    halo2_kzg_config!(false, 1, Accumulation::accumulator_indices()),
    Accumulation::two_snark_with_accumulator(false)
);
