use std::{marker::PhantomData, slice::from_ref};

use crate::loader::{LoadedScalar, ScalarLoader};

use ff::PrimeField;
// taken from https://github.com/scroll-tech/halo2-snark-aggregator/tree/main/halo2-snark-aggregator-api/src/hash
use halo2_proofs::halo2curves::FieldExt;
use poseidon::{SparseMDSMatrix, Spec, State};

struct PoseidonState<F: PrimeField, L: LoadedScalar<F>, const T: usize, const RATE: usize> {
    s: [L; T],
    _marker: PhantomData<F>,
}

impl<F: PrimeField + FieldExt, L: LoadedScalar<F>, const T: usize, const RATE: usize>
    PoseidonState<F, L, T, RATE>
{
    fn x_power5_with_constant(x: &L, constant: &F) -> L {
        let x2 = x.clone() * x;
        let x4 = x2.clone() * x2;
        LoadedScalar::mul_add_constant(&x, &x4, constant)
    }

    fn sbox_full(&mut self, constants: &[F; T]) {
        for (x, constant) in self.s.iter_mut().zip(constants.iter()) {
            *x = Self::x_power5_with_constant(x, constant);
        }
    }

    fn sbox_part(&mut self, constant: &F) {
        let x = &mut self.s[0];
        *x = Self::x_power5_with_constant(x, constant);
    }

    fn absorb_with_pre_constants(&mut self, inputs: Vec<L>, pre_constants: &[F; T]) {
        assert!(inputs.len() < T);
        let offset = inputs.len() + 1;

        self.s[0] = L::sum_with_const(&self.s[..1], &pre_constants[0]);

        for ((x, constant), input) in
            self.s.iter_mut().skip(1).zip(pre_constants.iter().skip(1)).zip(inputs.iter())
        {
            *x = L::sum_with_const(&[x.clone(), input.clone()], constant);
        }

        for (i, (x, constant)) in
            self.s.iter_mut().skip(offset).zip(pre_constants.iter().skip(offset)).enumerate()
        {
            *x = L::sum_with_const(
                from_ref(x),
                &if i == 0 { F::one() + constant } else { *constant },
            );
        }
    }

    fn apply_mds(&mut self, mds: &[[F; T]; T]) {
        let res = mds
            .iter()
            .map(|row| {
                let a = self
                    .s
                    .iter()
                    .zip(row.iter())
                    .map(|(e, word)| (*word, e.clone()))
                    .collect::<Vec<_>>();

                L::sum_with_coeff(&a[..])
            })
            .collect::<Vec<_>>();

        self.s = res.try_into().unwrap();
    }

    fn apply_sparse_mds(&mut self, mds: &SparseMDSMatrix<F, T, RATE>) {
        let a = self
            .s
            .iter()
            .zip(mds.row().iter())
            .map(|(e, word)| (*word, e.clone()))
            .collect::<Vec<_>>();

        let mut res = vec![LoadedScalar::sum_with_coeff(&a[..])];

        for (e, x) in mds.col_hat().iter().zip(self.s.iter().skip(1)) {
            res.push(LoadedScalar::sum_with_coeff(&[
                (*e, self.s[0].clone()),
                (F::one(), x.clone()),
            ]));
        }

        for (x, new_x) in self.s.iter_mut().zip(res.into_iter()) {
            *x = new_x
        }
    }
}

pub struct PoseidonChip<
    F: PrimeField + FieldExt,
    L: LoadedScalar<F>,
    const T: usize,
    const RATE: usize,
> {
    state: PoseidonState<F, L, T, RATE>,
    spec: Spec<F, T, RATE>,
    absorbing: Vec<L>,
}

impl<F: PrimeField + FieldExt, L: LoadedScalar<F>, const T: usize, const RATE: usize>
    PoseidonChip<F, L, T, RATE>
{
    pub fn new(loader: L::Loader, r_f: usize, r_p: usize) -> Self {
        let init_state = State::<F, T>::default()
            .words()
            .iter()
            .map(|x| loader.load_const(x))
            .collect::<Vec<L>>();

        Self {
            spec: Spec::new(r_f, r_p),
            state: PoseidonState { s: init_state.try_into().unwrap(), _marker: PhantomData },
            absorbing: Vec::new(),
        }
    }

    pub fn update(&mut self, elements: &[L]) {
        self.absorbing.extend_from_slice(elements);
    }

    pub fn squeeze(&mut self) -> L {
        let mut input_elements = vec![];
        input_elements.append(&mut self.absorbing);

        let mut padding_offset = 0;

        for chunk in input_elements.chunks(RATE) {
            padding_offset = RATE - chunk.len();
            self.permutation(chunk.to_vec());
        }

        if padding_offset == 0 {
            self.permutation(vec![]);
        }

        self.state.s[1].clone()
    }

    fn permutation(&mut self, inputs: Vec<L>) {
        let r_f = self.spec.r_f() / 2;
        let mds = &self.spec.mds_matrices().mds().rows();

        let constants = &self.spec.constants().start();
        self.state.absorb_with_pre_constants(inputs, &constants[0]);
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.state.sbox_full(constants);
            self.state.apply_mds(mds);
        }

        let pre_sparse_mds = &self.spec.mds_matrices().pre_sparse_mds().rows();
        self.state.sbox_full(constants.last().unwrap());
        self.state.apply_mds(&pre_sparse_mds);

        let sparse_matrices = &self.spec.mds_matrices().sparse_matrices();
        let constants = &self.spec.constants().partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.state.sbox_part(constant);
            self.state.apply_sparse_mds(sparse_mds);
        }

        let constants = &self.spec.constants().end();
        for constants in constants.iter() {
            self.state.sbox_full(constants);
            self.state.apply_mds(mds);
        }
        self.state.sbox_full(&[F::zero(); T]);
        self.state.apply_mds(mds);
    }
}
