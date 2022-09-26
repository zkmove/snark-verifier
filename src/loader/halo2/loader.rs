use crate::{
    loader::{EcPointLoader, LoadedEcPoint, LoadedScalar, Loader, ScalarLoader},
    util::{Curve, Field, FieldOps, Group, Itertools},
};
use ff::PrimeField;
use halo2_curves::CurveAffine;
use halo2_ecc::{
    bigint::CRTInteger,
    ecc::{fixed::FixedEccPoint, EccChip, EccPoint},
    fields::{fp, FieldChip},
    gates::{
        flex_gate::FlexGateConfig,
        range::RangeConfig,
        Context, GateInstructions,
        QuantumCell::{Constant, Existing, Witness},
        RangeInstructions,
    },
};
use halo2_proofs::{
    circuit::{self, AssignedCell},
    plonk::Assigned,
};
use rand::rngs::OsRng;
use std::{
    cell::RefCell,
    fmt::{self, Debug},
    iter,
    ops::{Add, AddAssign, Deref, DerefMut, Mul, MulAssign, Neg, Sub, SubAssign},
    rc::Rc,
};

pub type FpChip<C> = fp::FpConfig<<C as CurveAffine>::ScalarExt, <C as CurveAffine>::Base>;
pub type FpPoint<C> = CRTInteger<<C as CurveAffine>::ScalarExt>;

// Sometimes it is useful to know that a cell is really a constant, for optimization purposes
#[derive(Clone, Debug, Clone, Debug)]
pub enum Value<T, L> {
    Constant(T),
    Assigned(L),
}

pub struct Halo2Loader<'a, 'b, C: CurveAffine> {
    pub ecc_chip: EccChip<'a, C::Scalar, FpChip<C>>,
    pub ctx: &mut Context<'b, C::Scalar>,
}

impl<'a, 'b, C: CurveAffine> Halo2Loader<'a, 'b, C>
where
    C::Base: PrimeField,
{
    pub fn new(field_chip: &'a FpChip<C>, ctx: &mut Context<'b, C::Scalar>) -> Self {
        Self {
            ecc_chip: ecc::EccChip::construct(field_chip),
            ctx,
        }
    }

    pub fn assign_const_scalar(
        self: &Rc<Self>,
        scalar: C::Scalar,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let assigned = self.gate().assign_region_smart(
            self.ctx,
            vec![Constant(scalar)],
            vec![],
            vec![],
            vec![],
        )?;
        self.scalar(Value::Assigned(assigned[0].clone()))
    }

    pub fn assign_scalar(
        self: &Rc<Self>,
        scalar: circuit::Value<C::Scalar>,
    ) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let assigned = self.gate().assign_region_smart(
            self.ctx,
            vec![Witness(scalar)],
            vec![],
            vec![],
            vec![],
        )?;
        self.scalar(Value::Assigned(assigned[0].clone()))
    }

    pub fn scalar(
        self: &Rc<Self>,
        value: Value<C::Scalar, AssignedCell<C::Scalar, C::Scalar>>,
    ) -> Scalar<'a, 'b, C> {
        Scalar {
            loader: self.clone(),
            value,
        }
    }

    pub fn ecc_chip(&self) -> &EccChip<'a, C::Scalar, FpChip<C>> {
        &self.ecc_chip
    }

    pub fn field_chip(&self) -> &FpChip<C> {
        &self.ecc_chip.field_chip
    }

    pub fn range(&self) -> &RangeConfig<C::Scalar> {
        self.field_chip().range()
    }

    pub fn gate(&self) -> &FlexGateConfig<C::Scalar> {
        &self.range().gate
    }

    pub fn ec_point(
        self: &Rc<Self>,
        assigned: EccPoint<C::Scalar, FpPoint<C>>,
    ) -> EcPoint<'a, 'b, C> {
        EcPoint {
            loader: self.clone(),
            value: Value::Assigned(assigned),
        }
    }

    fn add(self: &Rc<Self>, lhs: &Scalar<'a, 'b, C>, rhs: &Scalar<'a, 'b, C>) -> Scalar<'a, 'b, C> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs + rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => Value::Assigned(
                self.gate()
                    .add(self.ctx, &Existing(assigned), &Constant(*constant))
                    .expect("add should not fail"),
            ),
            (Value::Assigned(lhs), Value::Assigned(rhs)) => Value::Assigned(
                self.gate()
                    .add(self.ctx, &Existing(lhs), &Existing(rhs))
                    .expect("add should not fail"),
            ),
        };
        self.scalar(output)
    }

    fn sub(self: &Rc<Self>, lhs: &Scalar<'a, 'b, C>, rhs: &Scalar<'a, 'b, C>) -> Scalar<'a, 'b, C> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs - rhs),
            (Value::Constant(constant), Value::Assigned(assigned)) => Value::Assigned(
                self.gate()
                    .sub(self.ctx, &Constant(*constant), &Existing(assigned))
                    .expect("sub should not fail"),
            ),
            (Value::Assigned(assigned), Value::Constant(constant)) => Value::Assigned(
                self.gate()
                    .sub(self.ctx, &Existing(assigned), &Constant(*constant))
                    .expect("sub should not fail"),
            ),
            (Value::Assigned(lhs), Value::Assigned(rhs)) => Value::Assigned(
                self.gate()
                    .sub(self.ctx, &Existing(lhs), &Existing(rhs))
                    .expect("sub should not fail"),
            ),
        };
        self.scalar(output)
    }

    fn mul(self: &Rc<Self>, lhs: &Scalar<'a, 'b, C>, rhs: &Scalar<'a, 'b, C>) -> Scalar<'a, 'b, C> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => Value::Constant(*lhs * rhs),
            (Value::Assigned(assigned), Value::Constant(constant))
            | (Value::Constant(constant), Value::Assigned(assigned)) => Value::Assigned(
                self.gate()
                    .mul(self.ctx, &Existing(assigned), &Constant(*constant))
                    .expect("mul should not fail"),
            ),
            (Value::Assigned(lhs), Value::Assigned(rhs)) => Value::Assigned(
                self.gate()
                    .mul(self.ctx, &Existing(lhs), &Existing(rhs))
                    .expect("mul should not fail"),
            ),
        };
        self.scalar(output)
    }

    fn neg(self: &Rc<Self>, scalar: &Scalar<'a, 'b, C>) -> Scalar<'a, 'b, C> {
        let output = match &scalar.value {
            Value::Constant(constant) => Value::Constant(constant.neg()),
            Value::Assigned(assigned) => Value::Assigned(
                self.gate()
                    .neg(self.ctx, &Existing(assigned))
                    .expect("neg should not fail"),
            ),
        };
        self.scalar(output)
    }

    fn invert(self: &Rc<Self>, scalar: &Scalar<'a, 'b, C>) -> Scalar<'a, 'b, C> {
        let output = match &scalar.value {
            Value::Constant(constant) => Value::Constant(constant.invert().unwrap()),
            Value::Assigned(assigned) => Value::Assigned(
                self.gate()
                    .div_unsafe(self.ctx, &Constant(C::Scalar::one()), &Existing(assigned))
                    .expect("invert should not fail"),
            ),
        };
        self.scalar(output)
    }

    fn div(self: &Rc<Self>, lhs: &Scalar<'a, 'b, C>, rhs: &Scalar<'a, 'b, C>) -> Scalar<'a, 'b, C> {
        let output = match (&lhs.value, &rhs.value) {
            (Value::Constant(lhs), Value::Constant(rhs)) => {
                Value::Constant(*lhs * rhs.invert().unwrap())
            }
            (Value::Constant(constant), Value::Assigned(assigned)) => Value::Assigned(
                self.gate()
                    .div_unsafe(self.ctx, &Constant(*constant), &Existing(assigned))
                    .expect("div should not fail"),
            ),
            (Value::Assigned(assigned), Value::Constant(constant)) => Value::Assigned(
                self.gate()
                    .div_unsafe(self.ctx, &Existing(assigned), &Constant(*constant))
                    .expect("div should not fail"),
            ),
            (Value::Assigned(lhs), Value::Assigned(rhs)) => {
                self.gate()
                    .div_unsafe(self.ctx, &Existing(lhs), &Existing(rhs))
                    .expect("div should not fail");
            }
        };
        self.scalar(output)
    }
}

#[derive(Clone)]
pub struct Scalar<'a, 'b, C: CurveAffine> {
    loader: Rc<Halo2Loader<'a, 'b, C>>,
    value: Value<C::Scalar, AssignedCell<C::Scalar, C::Scalar>>,
}

impl<'a, 'b, C: CurveAffine> Scalar<'a, 'b, C> {
    pub fn assigned(&self) -> AssignedCell<C::Scalar, C::Scalar> {
        match &self.value {
            Value::Constant(constant) => self.loader.assign_const_scalar(*constant).assigned(),
            Value::Assigned(assigned) => assigned.clone(),
        }
    }
}

impl<'a, 'b, C: CurveAffine> LoadedScalar<C::Scalar> for Scalar<'a, 'b, C> {
    type Loader = Rc<Halo2Loader<'a, 'b, C>>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }

    fn sum_with_coeff_and_constant(values: &[(C::Scalar, Self)], constant: &C::Scalar) -> Self {
        let loader = values.first().unwrap().1.loader();
        let a = Vec::with_capacity(values.len() + 1);
        let b = Vec::with_capacity(values.len() + 1);
        if *constant != C::Scalar::zero() {
            a.push(Constant(C::Scalar::one()));
            b.push(Constant(*constant));
        }
        a.extend(values.iter().map(|(_, a)| match &a.value {
            Value::Constant(constant) => Constant(*constant),
            Value::Assigned(assigned) => Existing(assigned),
        }));
        b.extend(values.iter().map(|(c, _)| Constant(*c)));
        let (_, _, sum, gate_index) = loader.gate().inner_product(loader.ctx, &a, &b)?;

        loader.scalar(sum)
    }

    fn sum_products_with_coeff_and_constant(
        values: &[(C::Scalar, Self, Self)],
        constant: &C::Scalar,
    ) -> Self {
        let loader = values.first().unwrap().1.loader();
        let prods = Vec::with_capacity(values.len());
        for val in values {
            let prod = val.1 * val.2;
            prods.push((val.0, prod));
        }
        Self::sum_with_coeff_and_constant(&prods[..], constant)
    }

    fn pow_const(&self, mut exp: u64) -> Self {
        fn get_naf(mut e: u64) -> Vec<i8> {
            // https://en.wikipedia.org/wiki/Non-adjacent_form
            // NAF for exp:
            let mut naf: Vec<i8> = Vec::with_capacity(32);

            // generate the NAF for exp
            for _ in 0..64 {
                if e & 1 == 1 {
                    let z = 2i8 - (e % 4) as i8;
                    e = e / 2;
                    if z == -1 {
                        e += 1;
                    }
                    naf.push(z);
                } else {
                    naf.push(0);
                    e = e / 2;
                }
            }
            if e != 0 {
                assert_eq!(e, 1);
                naf.push(1);
            }
            naf
        }

        assert!(exp > 0);
        let naf = get_naf(exp);
        let mut acc = self.clone();
        let mut is_started = false;

        for &z in naf.iter().rev() {
            if is_started {
                acc *= acc;
            }
            if z != 0 {
                if is_started {
                    acc = if z == 1 {
                        acc * self
                    } else {
                        (&self.loader).div(&acc, self)
                    };
                } else {
                    is_started = true;
                }
            }
        }
        Ok(acc)
    }
}

impl<'a, 'b, C: CurveAffine> Debug for Scalar<'a, 'b, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalar")
            .field("value", &self.value)
            .finish()
    }
}

impl<'a, 'b, C: CurveAffine> FieldOps for Scalar<'a, 'b, C> {
    fn invert(&self) -> Option<Self> {
        Some((&self.loader).invert(self))
    }
}

impl<'a, 'b, C: CurveAffine> Add for Scalar<'a, 'b, C> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        (&self.loader).add(&self, &rhs)
    }
}
impl<'a, 'b, C: CurveAffine> Sub for Scalar<'a, 'b, C> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        (&self.loader).sub(&self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine> Mul for Scalar<'a, 'b, C> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        (&self.loader).mul(&self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine> Neg for Scalar<'a, 'b, C> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        (&self.loader).neg(&self)
    }
}

impl<'a, 'b, 'c, C: CurveAffine> Add<&'c Self> for Scalar<'a, 'b, C> {
    type Output = Self;

    fn add(self, rhs: &'c Self) -> Self::Output {
        (&self.loader).add(&self, rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine> Sub<&'c Self> for Scalar<'a, 'b, C> {
    type Output = Self;

    fn sub(self, rhs: &'c Self) -> Self::Output {
        (&self.loader).sub(&self, rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine> Mul<&'c Self> for Scalar<'a, 'b, C> {
    type Output = Self;

    fn mul(self, rhs: &'c Self) -> Self::Output {
        (&self.loader).mul(&self, rhs)
    }
}

impl<'a, 'b, C: CurveAffine> AddAssign for Scalar<'a, 'b, C> {
    fn add_assign(&mut self, rhs: Self) {
        *self = (&self.loader).add(self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine> SubAssign for Scalar<'a, 'b, C, LIMBS, BITS> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = (&self.loader).sub(self, &rhs)
    }
}

impl<'a, 'b, C: CurveAffine> MulAssign for Scalar<'a, 'b, C, LIMBS, BITS> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = (&self.loader).mul(self, &rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine> AddAssign<&'c Self> for Scalar<'a, 'b, C, LIMBS, BITS> {
    fn add_assign(&mut self, rhs: &'c Self) {
        *self = (&self.loader).add(self, rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine> SubAssign<&'c Self> for Scalar<'a, 'b, C, LIMBS, BITS> {
    fn sub_assign(&mut self, rhs: &'c Self) {
        *self = (&self.loader).sub(self, rhs)
    }
}

impl<'a, 'b, 'c, C: CurveAffine> MulAssign<&'c Self> for Scalar<'a, 'b, C, LIMBS, BITS> {
    fn mul_assign(&mut self, rhs: &'c Self) {
        *self = (&self.loader).mul(self, rhs)
    }
}

#[derive(Clone)]
pub struct EcPoint<'a, 'b, C: CurveAffine> {
    loader: Rc<Halo2Loader<'a, 'b, C>>,
    pub value: Value<FixedEccPoint<C::Scalar, C>, EccPoint<C::Scalar, FpPoint<C>>>,
}

impl<'a, 'b, C: CurveAffine> EcPoint<'a, 'b, C> {
    pub fn assigned(&self) -> EccPoint<C::Scalar, FpPoint<C>> {
        match &self.value {
            Value::Constant(constant) => constant
                .assign(self.loader.field_chip(), self.loader.ctx)
                .unwrap(),
            Value::Assigned(assigned) => assigned.clone(),
        }
    }
}

impl<'a, 'b, C: CurveAffine> LoadedEcPoint<C::CurveExt> for EcPoint<'a, 'b, C> {
    type Loader = Rc<Halo2Loader<'a, 'b, C>>;

    fn loader(&self) -> &Self::Loader {
        &self.loader
    }

    fn multi_scalar_multiplication(
        pairs: impl IntoIterator<Item = (Scalar<'a, 'b, C, LIMBS, BITS>, Self)>,
    ) -> Self {
        let pairs = pairs.into_iter().collect_vec();
        let loader = &pairs[0].0.loader;

        let (non_scaled, fixed, scaled) = pairs.iter().fold(
            (Vec::new(), Vec::new(), Vec::new()),
            |(mut non_scaled, mut fixed, mut scaled), (scalar, ec_point)| {
                if matches!(scalar.value, Value::Constant(constant) if constant == C::Scalar::one())
                {
                    non_scaled.push(ec_point.assigned());
                } else {
                    match ec_point.value {
                        Constant(constant_pt) => {
                            fixed.push((constant_pt.clone(), scalar.assigned()));
                        }
                        Assigned(assigned_pt) => {
                            scaled.push((assigned_pt.clone(), scalar.assigned()));
                        }
                    }
                }
                (non_scaled, fixed, scaled)
            },
        );

        let mut sum = None;
        if !scaled.is_empty() {
            sum = loader
                .ecc_chip
                .multi_scalar_mult(
                    ctx,
                    scaled.iter().map(|pair| pair.0).collect(),
                    scaled.iter().map(|pair| pair.1).collect(),
                    <C::Scalar as PrimeField>::NUM_BITS as usize,
                    4,
                )
                .ok();
        }
        if !non_scaled.is_empty() || !fixed.is_empty() {
            let rand_point = loader.ecc_chip.load_random_point(loader.ctx).unwrap();
            let sum = if let Some(prev) = sum {
                loader
                    .ecc_chip
                    .add_unequal(loader.ctx, &prev, &rand_point, true)
                    .unwrap()
            } else {
                rand_point.clone()
            };
            for point in non_scaled.into_iter() {
                sum = loader
                    .ecc_chip
                    .add_unequal(loader.ctx, &sum, &point, true)
                    .unwrap();
            }
            for (fixed_point, scalar) in fixed.iter() {
                let fixed_msm = loader
                    .ecc_chip
                    .fixed_base_scalar_mult(loader.ctx, fixed_point, scalar, C::Scalar::NUM_BITS, 4)
                    .expect("fixed msms should not fail");
                sum = loader
                    .ecc_chip
                    .add_unequal(loader.ctx, &sum, &fixed_msm, true)
                    .unwrap();
            }
            sum = loader
                .ecc_chip
                .sub_unequal(loader.ctx, &sum, &rand_point, true)
                .unwrap();
        }
        loader.ec_point(output)
    }
}

impl<'a, 'b, C: CurveAffine> Debug for EcPoint<'a, 'b, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcPoint")
            .field("assigned", &self.assigned)
            .finish()
    }
}

impl<'a, 'b, C: CurveAffine> Add for EcPoint<'a, 'b, C> {
    type Output = Self;

    fn add(self, _: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, 'b, C: CurveAffine> Sub for EcPoint<'a, 'b, C> {
    type Output = Self;

    fn sub(self, _: Self) -> Self::Output {
        todo!()
    }
}

impl<'a, 'b, C: CurveAffine> Neg for EcPoint<'a, 'b, C> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl<'a, 'b, 'c, C: CurveAffine> Add<&'c Self> for EcPoint<'a, 'b, C> {
    type Output = Self;

    fn add(self, rhs: &'c Self) -> Self::Output {
        self + rhs.clone()
    }
}

impl<'a, 'b, 'c, C: CurveAffine> Sub<&'c Self> for EcPoint<'a, 'b, C> {
    type Output = Self;

    fn sub(self, rhs: &'c Self) -> Self::Output {
        self - rhs.clone()
    }
}

impl<'a, 'b, C: CurveAffine> AddAssign for EcPoint<'a, 'b, C> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.clone() + rhs
    }
}

impl<'a, 'b, C: CurveAffine> SubAssign for EcPoint<'a, 'b, C> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.clone() - rhs
    }
}

impl<'a, 'b, 'c, C: CurveAffine> AddAssign<&'c Self> for EcPoint<'a, 'b, C> {
    fn add_assign(&mut self, rhs: &'c Self) {
        *self = self.clone() + rhs
    }
}

impl<'a, 'b, 'c, C: CurveAffine> SubAssign<&'c Self> for EcPoint<'a, 'b, C> {
    fn sub_assign(&mut self, rhs: &'c Self) {
        *self = self.clone() - rhs
    }
}

impl<'a, 'b, C: CurveAffine> ScalarLoader<C::Scalar> for Rc<Halo2Loader<'a, 'b, C>> {
    type LoadedScalar = Scalar<'a, 'b, C>;

    fn load_const(&self, value: &C::Scalar) -> Scalar<'a, 'b, C> {
        self.scalar(Value::Constant(*value))
    }
}

impl<'a, 'b, C: CurveAffine> EcPointLoader<C::CurveExt> for Rc<Halo2Loader<'a, 'b, C>> {
    type LoadedEcPoint = EcPoint<'a, 'b, C>;

    fn ec_point_load_const(&self, ec_point: &C::CurveExt) -> EcPoint<'a, 'b, C> {
        let constant_point = FixedEccPoint::from_g1(
            &ec_point.to_affine(),
            self.ecc_chip.field_chip.num_limbs,
            self.ecc_chip.field_chip.limb_bits,
        );
        EcPoint {
            loader: self.clone(),
            value: Value::Constant(constant_point),
        }
    }
}

impl<'a, 'b, C: CurveAffine> Loader<C::CurveExt> for Rc<Halo2Loader<'a, 'b, C>> {}
