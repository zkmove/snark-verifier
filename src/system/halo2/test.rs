use crate::util::arithmetic::CurveAffine;
use ark_std::{end_timer, start_timer};
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, verify_proof, Circuit, ProvingKey},
    poly::{
        commitment::{CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        VerificationStrategy,
    },
    transcript::{EncodedChallenge, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand_chacha::rand_core::RngCore;
use std::{fs, io::Cursor};

mod kzg;

pub fn read_or_create_srs<'a, C: CurveAffine, P: ParamsProver<'a, C>>(
    k: u32,
    setup: impl Fn(u32) -> P,
) -> P {
    let dir = "./params";
    let path = format!("{}/kzg_bn254_{}.params", dir, k);
    match fs::File::open(path.as_str()) {
        Ok(mut file) => {
            println!("read params from {}", path);
            P::read(&mut file).unwrap()
        }
        Err(_) => {
            println!("creating params for {}", k);
            fs::create_dir_all(dir).unwrap();
            let params = setup(k);
            params.write(&mut fs::File::create(path).unwrap()).unwrap();
            params
        }
    }
}

pub fn load_verify_circuit_degree() -> u32 {
    let path = "./src/configs/verify_circuit.config";
    let params_str =
        std::fs::read_to_string(path).expect(format!("{} file should exist", path).as_str());
    let params: kzg::halo2::Halo2VerifierCircuitConfigParams =
        serde_json::from_str(params_str.as_str()).unwrap();
    params.degree
}

pub fn create_proof_checked<'a, S, C, P, V, VS, TW, TR, EC, R>(
    params: &'a S::ParamsProver,
    pk: &ProvingKey<S::Curve>,
    circuits: &[C],
    instances: &[&[&[S::Scalar]]],
    mut rng: R,
    finalize: impl Fn(Vec<u8>, VS::Output) -> Vec<u8>,
) -> Vec<u8>
where
    S: CommitmentScheme,
    S::ParamsVerifier: 'a,
    C: Circuit<S::Scalar>,
    P: Prover<'a, S>,
    V: Verifier<'a, S>,
    VS: VerificationStrategy<'a, S, V>,
    TW: TranscriptWriterBuffer<Vec<u8>, S::Curve, EC>,
    TR: TranscriptReadBuffer<Cursor<Vec<u8>>, S::Curve, EC>,
    EC: EncodedChallenge<S::Curve>,
    R: RngCore,
{
    /*
    let mock_time = start_timer!(|| "mock prover");
    for (circuit, instances) in circuits.iter().zip(instances.iter()) {
        MockProver::run(
            params.k(),
            circuit,
            instances.iter().map(|instance| instance.to_vec()).collect(),
        )
        .unwrap()
        .assert_satisfied();
    }
    end_timer!(mock_time);
    */

    let proof_time = start_timer!(|| "create proof");
    let proof = {
        let mut transcript = TW::init(Vec::new());
        create_proof::<S, P, _, _, _, _>(
            params,
            pk,
            circuits,
            instances,
            &mut rng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };
    end_timer!(proof_time);

    let verify_time = start_timer!(|| "verify proof");
    let output = {
        let params = params.verifier_params();
        let strategy = VS::new(params);
        let mut transcript = TR::init(Cursor::new(proof.clone()));
        verify_proof(params, pk.get_vk(), strategy, instances, &mut transcript).unwrap()
    };
    end_timer!(verify_time);

    finalize(proof, output)
}

macro_rules! halo2_prepare {
    ($dir:expr, $k:expr, $setup:expr, $config:expr, $create_circuit:expr) => {{
        use halo2_proofs::plonk::{keygen_pk, keygen_vk};
        use std::iter;
        use $crate::{
            system::halo2::{compile, test::read_or_create_srs},
            util::{Itertools},
        };
        use ark_std::{start_timer, end_timer};

        let circuits = (0..$config.num_proof).map(|_| $create_circuit).collect_vec();

        let params = read_or_create_srs($k, $setup);

        let pk = if $config.zk {
            let vk_time = start_timer!(|| "vkey");
            let vk = keygen_vk(&params, &circuits[0]).unwrap();
            end_timer!(vk_time);

            let pk_time = start_timer!(|| "pkey");
            let pk = keygen_pk(&params, vk, &circuits[0]).unwrap();
            end_timer!(pk_time);

            pk
        } else {
            // TODO: Re-enable optional-zk when it's merged in pse/halo2.
            unimplemented!()
        };

        let num_instance = circuits[0]
            .instances()
            .iter()
            .map(|instances| instances.len())
            .collect();
        let protocol = compile(
            &params,
            pk.get_vk(),
            $config.with_num_instance(num_instance),
        );

        /* assert fails when fixed column is all 0s
        assert_eq!(
            protocol.preprocessed.len(),
            protocol
                .preprocessed
                .iter()
                .map(
                    |ec_point| <[u8; 32]>::try_from(ec_point.to_bytes().as_ref().to_vec()).unwrap()
                )
                .unique()
                .count()
        );
        */

        (params, pk, protocol, circuits)
    }};
}

macro_rules! halo2_create_snark {
    (
        $commitment_scheme:ty,
        $prover:ty,
        $verifier:ty,
        $verification_strategy:ty,
        $transcript_read:ty,
        $transcript_write:ty,
        $encoded_challenge:ty,
        $finalize:expr,
        $params:expr,
        $pk:expr,
        $protocol:expr,
        $circuits:expr
    ) => {{
        use itertools::Itertools;
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        use $crate::{loader::halo2::test::Snark, system::halo2::test::create_proof_checked};

        let instances = $circuits.iter().map(|circuit| circuit.instances()).collect_vec();
        let proof = {
            #[allow(clippy::needless_borrow)]
            let instances = instances
                .iter()
                .map(|instances| instances.iter().map(Vec::as_slice).collect_vec())
                .collect_vec();
            let instances = instances.iter().map(Vec::as_slice).collect_vec();
            create_proof_checked::<
                $commitment_scheme,
                _,
                $prover,
                $verifier,
                $verification_strategy,
                $transcript_read,
                $transcript_write,
                $encoded_challenge,
                _,
            >(
                $params,
                $pk,
                $circuits,
                &instances,
                &mut ChaCha20Rng::from_seed(Default::default()),
                $finalize,
            )
        };

        Snark::new($protocol.clone(), instances.into_iter().flatten().collect_vec(), proof)
    }};
}

macro_rules! halo2_native_verify {
    (
        $plonk_verifier:ty,
        $params:expr,
        $protocol:expr,
        $instances:expr,
        $transcript:expr,
        $svk:expr,
        $dk:expr
    ) => {{
        use halo2_proofs::poly::commitment::ParamsProver;
        use $crate::verifier::PlonkVerifier;

        let proof =
            <$plonk_verifier>::read_proof($svk, $protocol, $instances, $transcript).unwrap();
        assert!(<$plonk_verifier>::verify($svk, $dk, $protocol, $instances, &proof).unwrap())
    }};
}

pub(crate) use {halo2_create_snark, halo2_native_verify, halo2_prepare};
