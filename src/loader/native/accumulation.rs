use crate::{
    loader::native::NativeLoader,
    protocol::{
        halo2::{BITS, LIMBS},
        Protocol,
    },
    scheme::kzg::{AccumulationStrategy, Accumulator, SameCurveAccumulation, MSM},
    util::{fe_from_limbs, Curve, Group, Itertools, PrimeCurveAffine, Transcript},
    Error,
};
use halo2_proofs::halo2curves::{
    pairing::{MillerLoopResult, MultiMillerLoop},
    CurveAffine, CurveExt,
};

impl<C: Curve> SameCurveAccumulation<C, NativeLoader> {
    pub fn finalize(self, g1: C) -> (C, C) {
        self.accumulator.unwrap().evaluate(g1)
    }
}

impl<C: Curve> SameCurveAccumulation<C, NativeLoader> {
    pub fn decide<M: MultiMillerLoop<G1 = C>>(
        self,
        g1: M::G1Affine,
        g2: M::G2Affine,
        s_g2: M::G2Affine,
    ) -> bool {
        let (lhs, rhs) = self.finalize(g1.to_curve());

        let g2 = M::G2Prepared::from(g2);
        let minus_s_g2 = M::G2Prepared::from(-s_g2);

        let terms = [(&lhs.into(), &g2), (&rhs.into(), &minus_s_g2)];
        M::multi_miller_loop(&terms).final_exponentiation().is_identity().into()
    }
}

impl<C, T, P> AccumulationStrategy<C, NativeLoader, T, P> for SameCurveAccumulation<C, NativeLoader>
where
    C: CurveExt,
    T: Transcript<C, NativeLoader>,
{
    type Output = P;

    fn extract_accumulator(
        &self,
        protocol: &Protocol<C>,
        _: &NativeLoader,
        transcript: &mut T,
        statements: &[Vec<C::ScalarExt>],
    ) -> Option<Accumulator<C, NativeLoader>> {
        let accumulator_indices = protocol.accumulator_indices.as_ref()?;

        let challenges = transcript.squeeze_n_challenges(accumulator_indices.len());
        let accumulators = accumulator_indices
            .iter()
            .map(|indices| {
                assert_eq!(indices.len(), 4 * LIMBS);
                let [lhs_x, lhs_y, rhs_x, rhs_y]: [_; 4] = indices
                    .chunks(4)
                    .into_iter()
                    .map(|indices| {
                        fe_from_limbs(
                            indices.iter().map(|index| statements[index.0][index.1]).collect_vec(),
                            BITS,
                        )
                    })
                    .collect_vec()
                    .try_into()
                    .unwrap();
                let lhs = <C::AffineExt as CurveAffine>::from_xy(lhs_x, lhs_y).unwrap().to_curve();
                let rhs = <C::AffineExt as CurveAffine>::from_xy(rhs_x, rhs_y).unwrap().to_curve();
                Accumulator::new(MSM::base(lhs), MSM::base(rhs))
            })
            .collect_vec();

        Some(Accumulator::random_linear_combine(challenges.into_iter().zip(accumulators)))
    }

    fn process(
        &mut self,
        _: &NativeLoader,
        transcript: &mut T,
        proof: P,
        accumulator: Accumulator<C, NativeLoader>,
    ) -> Result<Self::Output, Error> {
        self.accumulator = Some(match self.accumulator.take() {
            Some(curr_accumulator) => {
                accumulator + curr_accumulator * &transcript.squeeze_challenge()
            }
            None => accumulator,
        });
        Ok(proof)
    }
}
