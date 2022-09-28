use crate::protocol::halo2::{BITS, LIMBS};
use halo2_proofs::{
    halo2curves::pairing::Engine,
    poly::{
        commitment::{CommitmentScheme, Params},
        kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
    },
};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{fmt::Debug, fs};

mod halo2;
mod native;

#[cfg(feature = "evm")]
mod evm;

pub fn read_or_create_srs<E: Engine + Debug>(k: u32) -> ParamsKZG<E> {
    let mut params_folder = std::path::PathBuf::new();
    params_folder.push("params");
    if !params_folder.is_dir() {
        std::fs::create_dir(params_folder.as_path())
            .expect("params folder creation should not fail");
    }
    params_folder.push(format!("kzg_bn254_{}.params", k));
    let path = params_folder.as_path();

    match fs::File::open(path) {
        Ok(mut file) => {
            println!("read params from {:?}", path);
            ParamsKZG::<E>::read(&mut file).unwrap()
        }
        Err(_) => {
            println!("write params to {:?}", path);
            let mut file = std::fs::File::create(path).unwrap();
            let params =
                KZGCommitmentScheme::<E>::new_params(k, ChaCha20Rng::from_seed(Default::default()));

            params.write(&mut file).unwrap();
            params
        }
    }
}

pub fn load_verify_circuit_degree() -> u32 {
    let mut folder = std::path::PathBuf::new();
    folder.push("src/configs");
    folder.push("verify_circuit.config");
    let params_str = std::fs::read_to_string(folder.as_path())
        .expect(format!("{} file should exist", folder.to_str().unwrap()).as_str());
    let params: halo2::Halo2VerifierCircuitConfigParams =
        serde_json::from_str(params_str.as_str()).unwrap();
    params.degree
}

#[macro_export]
macro_rules! halo2_kzg_config {
    ($zk:expr, $num_proof:expr) => {
        $crate::protocol::halo2::Config {
            zk: $zk,
            query_instance: false,
            num_instance: Vec::new(),
            num_proof: $num_proof,
            accumulator_indices: None,
        }
    };
    ($zk:expr, $num_proof:expr, $accumulator_indices:expr) => {
        $crate::protocol::halo2::Config {
            zk: $zk,
            query_instance: false,
            num_instance: Vec::new(),
            num_proof: $num_proof,
            accumulator_indices: Some($accumulator_indices),
        }
    };
}

#[macro_export]
macro_rules! halo2_kzg_prepare {
    ($k:expr, $config:expr, $create_circuit:expr) => {{
        use $crate::{
            protocol::halo2::{compile, test::kzg::read_or_create_srs},
            util::{GroupEncoding, Itertools},
        };
        use halo2_proofs::{
            halo2curves::bn256::{Bn256, G1},
            plonk::{keygen_pk, keygen_vk},
            poly::kzg::commitment::KZGCommitmentScheme,
        };
        use std::{iter};
        use ark_std::{end_timer, start_timer};

        let circuits = iter::repeat_with(|| $create_circuit)
            .take($config.num_proof)
            .collect_vec();

        let params = read_or_create_srs::<Bn256>($k);

        let pk_time = start_timer!(|| "pkey");
        let pk = if $config.zk {
            let vk = keygen_vk::<KZGCommitmentScheme<_>, _, true>(&params, &circuits[0]).unwrap();
            let pk = keygen_pk::<KZGCommitmentScheme<_>, _, true>(&params, vk, &circuits[0]).unwrap();
            pk
        } else {
            let vk = keygen_vk::<KZGCommitmentScheme<_>, _, false>(&params, &circuits[0]).unwrap();
            let pk = keygen_pk::<KZGCommitmentScheme<_>, _, false>(&params, vk, &circuits[0]).unwrap();
            pk
        };
        end_timer!(pk_time);

        let mut config = $config;
        config.num_instance = circuits[0].instances().iter().map(|instances| instances.len()).collect();
        let protocol = compile::<G1>(pk.get_vk(), config);
        assert_eq!(
            protocol.preprocessed.len(),
            protocol.preprocessed
                .iter()
                .map(|ec_point| <[u8; 32]>::try_from(ec_point.to_bytes().as_ref().to_vec()).unwrap())
                .unique()
                .count()
        );

        (params, pk, protocol, circuits)
    }};
}

#[macro_export]
macro_rules! halo2_kzg_create_snark {
    ($params:expr, $pk:expr, $protocol:expr, $circuits:expr, $prover:ty, $verifier:ty, $verification_strategy:ty, $transcript_read:ty, $transcript_write:ty, $encoded_challenge:ty) => {{
        use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
        use $crate::{
            collect_slice,
            protocol::{halo2::test::create_proof_checked, Snark},
            util::Itertools,
        };

        let instances = $circuits.iter().map(|circuit| circuit.instances()).collect_vec();
        let proof = {
            collect_slice!(instances, 2);
            #[allow(clippy::needless_borrow)]
            if $protocol.zk {
                create_proof_checked::<
                    KZGCommitmentScheme<_>,
                    _,
                    $prover,
                    $verifier,
                    $verification_strategy,
                    $transcript_read,
                    $transcript_write,
                    $encoded_challenge,
                    _,
                    true,
                >(
                    $params,
                    $pk,
                    $circuits,
                    &instances,
                    &mut ChaCha20Rng::from_seed(Default::default()),
                )
            } else {
                create_proof_checked::<
                    KZGCommitmentScheme<_>,
                    _,
                    $prover,
                    $verifier,
                    $verification_strategy,
                    $transcript_read,
                    $transcript_write,
                    $encoded_challenge,
                    _,
                    false,
                >(
                    $params,
                    $pk,
                    $circuits,
                    &instances,
                    &mut ChaCha20Rng::from_seed(Default::default()),
                )
            }
        };

        Snark::new($protocol.clone(), instances.into_iter().flatten().collect_vec(), proof)
    }};
}

#[macro_export]
macro_rules! halo2_kzg_native_accumulate {
    ($protocol:expr, $statements:expr, $scheme:ty, $transcript:expr, $stretagy:expr) => {{
        use $crate::{loader::native::NativeLoader, scheme::kzg::AccumulationScheme};

        <$scheme>::accumulate($protocol, &NativeLoader, $statements, $transcript, $stretagy)
            .unwrap();
    }};
}

#[macro_export]
macro_rules! halo2_kzg_native_verify {
    ($params:ident, $protocol:expr, $statements:expr, $scheme:ty, $transcript:expr) => {{
        use halo2_proofs::halo2curves::bn256::Bn256;
        use halo2_proofs::poly::commitment::ParamsProver;
        use $crate::{halo2_kzg_native_accumulate, scheme::kzg::SameCurveAccumulation};

        let mut strategy = SameCurveAccumulation::default();
        halo2_kzg_native_accumulate!($protocol, $statements, $scheme, $transcript, &mut strategy);

        assert!(strategy.decide::<Bn256>($params.get_g()[0], $params.g2(), $params.s_g2()));
    }};
}
