use crate::{loader::Loader, util::arithmetic::CurveAffine};
use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct KzgAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub lhs: L::LoadedEcPoint,
    pub rhs: L::LoadedEcPoint,
}

impl<C, L> KzgAccumulator<C, L>
where
    C: CurveAffine,
    L: Loader<C>,
{
    pub fn new(lhs: L::LoadedEcPoint, rhs: L::LoadedEcPoint) -> Self {
        Self { lhs, rhs }
    }
}

/// `AccumulatorEncoding` that encodes `Accumulator` into limbs.
///
/// Since in circuit everything are in scalar field, but `Accumulator` might contain base field elements, so we split them into limbs.
/// The const generic `LIMBS` and `BITS` respectively represents how many limbs
/// a base field element are split into and how many bits each limbs could have.
#[derive(Clone, Debug)]
pub struct LimbsEncoding<const LIMBS: usize, const BITS: usize>;

mod native {
    use crate::{
        loader::native::NativeLoader,
        pcs::{
            kzg::{KzgAccumulator, LimbsEncoding},
            AccumulatorEncoding, PolynomialCommitmentScheme,
        },
        util::{
            arithmetic::{fe_from_limbs, CurveAffine},
            Itertools,
        },
        Error,
    };

    impl<C, PCS, const LIMBS: usize, const BITS: usize> AccumulatorEncoding<C, NativeLoader, PCS>
        for LimbsEncoding<LIMBS, BITS>
    where
        C: CurveAffine,
        PCS: PolynomialCommitmentScheme<
            C,
            NativeLoader,
            Accumulator = KzgAccumulator<C, NativeLoader>,
        >,
    {
        fn from_repr(limbs: Vec<C::Scalar>) -> Result<PCS::Accumulator, Error> {
            assert_eq!(limbs.len(), 4 * LIMBS);

            let [lhs_x, lhs_y, rhs_x, rhs_y]: [_; 4] = limbs
                .chunks(LIMBS)
                .into_iter()
                .map(|limbs| fe_from_limbs::<_, _, LIMBS, BITS>(limbs.try_into().unwrap()))
                .collect_vec()
                .try_into()
                .unwrap();
            let accumulator = KzgAccumulator::new(
                C::from_xy(lhs_x, lhs_y).unwrap(),
                C::from_xy(rhs_x, rhs_y).unwrap(),
            );

            Ok(accumulator)
        }
    }
}

#[cfg(feature = "loader_evm")]
mod evm {
    use crate::{
        loader::evm::{EvmLoader, Scalar},
        pcs::{
            kzg::{KzgAccumulator, LimbsEncoding},
            AccumulatorEncoding, PolynomialCommitmentScheme,
        },
        util::{
            arithmetic::{CurveAffine, PrimeField},
            Itertools,
        },
        Error,
    };
    use std::rc::Rc;

    impl<C, PCS, const LIMBS: usize, const BITS: usize> AccumulatorEncoding<C, Rc<EvmLoader>, PCS>
        for LimbsEncoding<LIMBS, BITS>
    where
        C: CurveAffine,
        C::Scalar: PrimeField<Repr = [u8; 0x20]>,
        PCS: PolynomialCommitmentScheme<
            C,
            Rc<EvmLoader>,
            Accumulator = KzgAccumulator<C, Rc<EvmLoader>>,
        >,
    {
        fn from_repr(limbs: Vec<Scalar>) -> Result<PCS::Accumulator, Error> {
            assert_eq!(limbs.len(), 4 * LIMBS);

            let loader = limbs[0].loader();

            let [lhs_x, lhs_y, rhs_x, rhs_y]: [[_; LIMBS]; 4] = limbs
                .chunks(LIMBS)
                .into_iter()
                .map(|limbs| limbs.to_vec().try_into().unwrap())
                .collect_vec()
                .try_into()
                .unwrap();
            let accumulator = KzgAccumulator::new(
                loader.ec_point_from_limbs::<LIMBS, BITS>(lhs_x, lhs_y),
                loader.ec_point_from_limbs::<LIMBS, BITS>(rhs_x, rhs_y),
            );

            Ok(accumulator)
        }
    }
}

#[cfg(feature = "loader_halo2")]
mod halo2 {
    use crate::{
        loader::halo2::{Halo2Loader, Scalar},
        loader::LoadedScalar,
        pcs::{
            kzg::{KzgAccumulator, LimbsEncoding},
            AccumulatorEncoding, PolynomialCommitmentScheme,
        },
        util::{arithmetic::CurveAffine, Itertools},
        Error,
    };
    use std::rc::Rc;

    impl<'a, 'b, C, PCS, const LIMBS: usize, const BITS: usize>
        AccumulatorEncoding<C, Rc<Halo2Loader<'a, 'b, C>>, PCS> for LimbsEncoding<LIMBS, BITS>
    where
        C: CurveAffine,
        PCS: PolynomialCommitmentScheme<
            C,
            Rc<Halo2Loader<'a, 'b, C>>,
            Accumulator = KzgAccumulator<C, Rc<Halo2Loader<'a, 'b, C>>>,
        >,
    {
        fn from_repr(limbs: Vec<Scalar<'a, 'b, C>>) -> Result<PCS::Accumulator, Error> {
            assert_eq!(limbs.len(), 4 * LIMBS);

            let loader = limbs[0].loader();

            let assigned_limbs = limbs.iter().map(|limb| limb.assigned()).collect_vec();
            let [lhs, rhs] = [&assigned_limbs[..2 * LIMBS], &assigned_limbs[2 * LIMBS..]].map(
                |assigned_limbs| {
                    loader.assign_ec_point_from_limbs(
                        assigned_limbs[..LIMBS].to_vec(),
                        assigned_limbs[LIMBS..2 * LIMBS].to_vec(),
                    )
                },
            );

            let accumulator = KzgAccumulator::new(lhs, rhs);

            Ok(accumulator)
        }
    }
}
