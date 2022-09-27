use crate::{
    loader::halo2::loader::{AssignedInteger, Halo2Loader, Scalar},
    protocol::Protocol,
    scheme::kzg::{AccumulationStrategy, Accumulator, SameCurveAccumulation, MSM},
    util::{Itertools, Transcript},
    Error,
};
use halo2_ecc::ecc::EccPoint;
use halo2_proofs::halo2curves::CurveAffine;
use std::rc::Rc;

impl<'a, 'b, C: CurveAffine> SameCurveAccumulation<C::CurveExt, Rc<Halo2Loader<'a, 'b, C>>> {
    pub fn finalize(
        self,
        g1: C,
    ) -> (EccPoint<C::Scalar, AssignedInteger<C>>, EccPoint<C::Scalar, AssignedInteger<C>>) {
        let (lhs, rhs) = self.accumulator.unwrap().evaluate(g1.to_curve());
        (lhs.assigned(), rhs.assigned())
    }
}

impl<'a, 'b, C, T, P> AccumulationStrategy<C::CurveExt, Rc<Halo2Loader<'a, 'b, C>>, T, P>
    for SameCurveAccumulation<C::CurveExt, Rc<Halo2Loader<'a, 'b, C>>>
where
    C: CurveAffine,
    T: Transcript<C::CurveExt, Rc<Halo2Loader<'a, 'b, C>>>,
{
    type Output = ();

    fn extract_accumulator(
        &self,
        protocol: &Protocol<C::CurveExt>,
        loader: &Rc<Halo2Loader<'a, 'b, C>>,
        transcript: &mut T,
        statements: &[Vec<Scalar<'a, 'b, C>>],
    ) -> Option<Accumulator<C::CurveExt, Rc<Halo2Loader<'a, 'b, C>>>> {
        let accumulator_indices = protocol.accumulator_indices.as_ref()?;

        let challenges = transcript.squeeze_n_challenges(accumulator_indices.len());
        let accumulators = accumulator_indices
            .iter()
            .map(|indices| {
                let num_limbs = loader.ecc_chip.field_chip.num_limbs;
                assert_eq!(indices.len(), 4 * num_limbs);
                let assigned = indices
                    .iter()
                    .map(|index| statements[index.0][index.1].assigned())
                    .collect_vec();
                let lhs = loader.assign_ec_point_from_limbs(
                    assigned[..num_limbs].to_vec(),
                    assigned[num_limbs..2 * num_limbs].to_vec(),
                );
                let rhs = loader.assign_ec_point_from_limbs(
                    assigned[2 * num_limbs..3 * num_limbs].to_vec().try_into().unwrap(),
                    assigned[3 * num_limbs..].to_vec().try_into().unwrap(),
                );
                Accumulator::new(MSM::base(lhs), MSM::base(rhs))
            })
            .collect_vec();

        Some(Accumulator::random_linear_combine(challenges.into_iter().zip(accumulators)))
    }

    fn process(
        &mut self,
        _: &Rc<Halo2Loader<'a, 'b, C>>,
        transcript: &mut T,
        _: P,
        accumulator: Accumulator<C::CurveExt, Rc<Halo2Loader<'a, 'b, C>>>,
    ) -> Result<Self::Output, Error> {
        self.accumulator = Some(match self.accumulator.take() {
            Some(curr_accumulator) => {
                accumulator + curr_accumulator * &transcript.squeeze_challenge()
            }
            None => accumulator,
        });
        Ok(())
    }
}
