use crate::{
    loader::{
        halo2::{
            loader::{AssignedEcPoint, EcPoint, Halo2Loader, Scalar, Value},
            poseidon_chip::PoseidonChip,
        },
        native::NativeLoader,
        Loader,
    },
    util::{
        arithmetic::{Coordinates, CurveAffine, PrimeField},
        transcript::{Transcript, TranscriptRead, TranscriptWrite},
    },
    Error,
};
use ::poseidon::Poseidon;
use halo2_base::utils::{biguint_to_fe, fe_to_biguint};
use halo2_curves::group::GroupEncoding;
use halo2_proofs::{circuit, transcript::EncodedChallenge};
use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    rc::Rc,
    slice::from_ref,
};

pub struct PoseidonTranscript<
    C: CurveAffine,
    L: Loader<C>,
    S,
    B,
    const T: usize,
    const RATE: usize,
    const R_F: usize,
    const R_P: usize,
> {
    loader: L,
    stream: S,
    buf: B,
    _marker: PhantomData<C>,
}

impl<
        'a,
        'b,
        R: Read,
        C: CurveAffine,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    >
    PoseidonTranscript<
        C,
        Rc<Halo2Loader<'a, 'b, C>>,
        circuit::Value<R>,
        PoseidonChip<C::Scalar, Scalar<'a, 'b, C>, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    pub fn new(loader: &Rc<Halo2Loader<'a, 'b, C>>, stream: circuit::Value<R>) -> Self {
        Self {
            loader: loader.clone(),
            stream,
            buf: PoseidonChip::new(loader.clone(), R_F, R_P),
            _marker: PhantomData,
        }
    }

    fn encode_point(&self, v: &AssignedEcPoint<C>) -> Vec<Scalar<'a, 'b, C>> {
        let x_native = v.x.native.clone();
        let y_native = v.y.native.clone();
        [x_native, y_native]
            .into_iter()
            .map(|x| (&self.loader).scalar(Value::Assigned(x)))
            .collect()
    }
}

impl<
        'a,
        'b,
        R: Read,
        C: CurveAffine,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > Transcript<C, Rc<Halo2Loader<'a, 'b, C>>>
    for PoseidonTranscript<
        C,
        Rc<Halo2Loader<'a, 'b, C>>,
        circuit::Value<R>,
        PoseidonChip<C::Scalar, Scalar<'a, 'b, C>, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn loader(&self) -> &Rc<Halo2Loader<'a, 'b, C>> {
        &self.loader
    }

    fn squeeze_challenge(&mut self) -> Scalar<'a, 'b, C> {
        self.buf.squeeze()
    }

    fn common_scalar(&mut self, scalar: &Scalar<'a, 'b, C>) -> Result<(), Error> {
        self.buf.update(from_ref(scalar));
        Ok(())
    }

    fn common_ec_point(&mut self, ec_point: &EcPoint<'a, 'b, C>) -> Result<(), Error> {
        self.buf.update(&self.encode_point(&ec_point.assigned())[..]);
        Ok(())
    }
}

impl<
        'a,
        'b,
        R: Read,
        C: CurveAffine,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptRead<C, Rc<Halo2Loader<'a, 'b, C>>>
    for PoseidonTranscript<
        C,
        Rc<Halo2Loader<'a, 'b, C>>,
        circuit::Value<R>,
        PoseidonChip<C::Scalar, Scalar<'a, 'b, C>, T, RATE>,
        T,
        RATE,
        R_F,
        R_P,
    >
{
    fn read_scalar(&mut self) -> Result<Scalar<'a, 'b, C>, Error> {
        let scalar = self.stream.as_mut().and_then(|stream| {
            let mut data = <C::Scalar as PrimeField>::Repr::default();
            if stream.read_exact(data.as_mut()).is_err() {
                return circuit::Value::unknown();
            }
            Option::<C::Scalar>::from(C::Scalar::from_repr(data))
                .map(circuit::Value::known)
                .unwrap_or_else(circuit::Value::unknown)
        });
        let scalar = self.loader.assign_scalar(scalar);
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<EcPoint<'a, 'b, C>, Error> {
        let ec_point = self.stream.as_mut().and_then(|stream| {
            let mut compressed = C::Repr::default();
            if stream.read_exact(compressed.as_mut()).is_err() {
                return circuit::Value::unknown();
            }
            Option::<C>::from(C::from_bytes(&compressed))
                .map(circuit::Value::known)
                .unwrap_or_else(circuit::Value::unknown)
        });
        let ec_point = self.loader.assign_ec_point(ec_point);
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<C: CurveAffine, S, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    PoseidonTranscript<C, NativeLoader, S, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    pub fn new(stream: S) -> Self {
        Self { loader: NativeLoader, stream, buf: Poseidon::new(R_F, R_P), _marker: PhantomData }
    }
}

impl<C: CurveAffine, S, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    Transcript<C, NativeLoader>
    for PoseidonTranscript<C, NativeLoader, S, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    fn loader(&self) -> &NativeLoader {
        &self.loader
    }

    fn squeeze_challenge(&mut self) -> C::Scalar {
        self.buf.squeeze()
    }

    fn common_scalar(&mut self, scalar: &C::Scalar) -> Result<(), Error> {
        self.buf.update(&[*scalar]);
        Ok(())
    }

    fn common_ec_point(&mut self, ec_point: &C) -> Result<(), Error> {
        let coords: Coordinates<C> = Option::from(ec_point.coordinates()).ok_or_else(|| {
            Error::Transcript(
                io::ErrorKind::Other,
                "Cannot write points at infinity to the transcript".to_string(),
            )
        })?;
        let x = biguint_to_fe(&fe_to_biguint(coords.x()));
        let y = biguint_to_fe(&fe_to_biguint(coords.y()));
        self.buf.update(&[x, y]);
        Ok(())
    }
}

impl<
        C: CurveAffine,
        R: Read,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptRead<C, NativeLoader>
    for PoseidonTranscript<C, NativeLoader, R, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    fn read_scalar(&mut self) -> Result<C::Scalar, Error> {
        let mut data = <C::Scalar as PrimeField>::Repr::default();
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        let scalar = C::Scalar::from_repr_vartime(data).ok_or_else(|| {
            Error::Transcript(io::ErrorKind::Other, "Invalid scalar encoding in proof".to_string())
        })?;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<C, Error> {
        let mut data = C::Repr::default();
        self.stream
            .read_exact(data.as_mut())
            .map_err(|err| Error::Transcript(err.kind(), err.to_string()))?;
        let ec_point =
            Option::<C>::from(<C as GroupEncoding>::from_bytes(&data)).ok_or_else(|| {
                Error::Transcript(
                    io::ErrorKind::Other,
                    "Invalid elliptic curve point encoding in proof".to_string(),
                )
            })?;
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}

impl<
        C: CurveAffine,
        W: Write,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > PoseidonTranscript<C, NativeLoader, W, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    pub fn stream_mut(&mut self) -> &mut W {
        &mut self.stream
    }

    pub fn finalize(self) -> W {
        self.stream
    }
}

impl<
        C: CurveAffine,
        W: Write,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > TranscriptWrite<C>
    for PoseidonTranscript<C, NativeLoader, W, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    fn write_scalar(&mut self, scalar: C::Scalar) -> Result<(), Error> {
        self.common_scalar(&scalar)?;
        let data = scalar.to_repr();
        self.stream_mut().write_all(data.as_ref()).map_err(|err| {
            Error::Transcript(err.kind(), "Failed to write scalar to transcript".to_string())
        })
    }

    fn write_ec_point(&mut self, ec_point: C) -> Result<(), Error> {
        self.common_ec_point(&ec_point)?;
        let data = ec_point.to_bytes();
        self.stream_mut().write_all(data.as_ref()).map_err(|err| {
            Error::Transcript(
                err.kind(),
                "Failed to write elliptic curve to transcript".to_string(),
            )
        })
    }
}

pub struct ChallengeScalar<C: CurveAffine>(C::Scalar);

impl<C: CurveAffine> EncodedChallenge<C> for ChallengeScalar<C> {
    type Input = C::Scalar;

    fn new(challenge_input: &C::Scalar) -> Self {
        ChallengeScalar(*challenge_input)
    }

    fn get_scalar(&self) -> C::Scalar {
        self.0
    }
}

impl<C: CurveAffine, S, const T: usize, const RATE: usize, const R_F: usize, const R_P: usize>
    halo2_proofs::transcript::Transcript<C, ChallengeScalar<C>>
    for PoseidonTranscript<C, NativeLoader, S, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    fn squeeze_challenge(&mut self) -> ChallengeScalar<C> {
        ChallengeScalar::new(&Transcript::squeeze_challenge(self))
    }

    fn common_point(&mut self, ec_point: C) -> io::Result<()> {
        match Transcript::common_ec_point(self, &ec_point) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            _ => Ok(()),
        }
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        match Transcript::common_scalar(self, &scalar) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            _ => Ok(()),
        }
    }
}

impl<
        C: CurveAffine,
        R: Read,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > halo2_proofs::transcript::TranscriptRead<C, ChallengeScalar<C>>
    for PoseidonTranscript<C, NativeLoader, R, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    fn read_point(&mut self) -> io::Result<C> {
        match TranscriptRead::read_ec_point(self) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            Ok(value) => Ok(value),
        }
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        match TranscriptRead::read_scalar(self) {
            Err(Error::Transcript(kind, msg)) => Err(io::Error::new(kind, msg)),
            Err(_) => unreachable!(),
            Ok(value) => Ok(value),
        }
    }
}

impl<
        C: CurveAffine,
        R: Read,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > halo2_proofs::transcript::TranscriptReadBuffer<R, C, ChallengeScalar<C>>
    for PoseidonTranscript<C, NativeLoader, R, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    fn init(reader: R) -> Self {
        Self::new(reader)
    }
}

impl<
        C: CurveAffine,
        W: Write,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > halo2_proofs::transcript::TranscriptWrite<C, ChallengeScalar<C>>
    for PoseidonTranscript<C, NativeLoader, W, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    fn write_point(&mut self, ec_point: C) -> io::Result<()> {
        halo2_proofs::transcript::Transcript::<C, ChallengeScalar<C>>::common_point(
            self, ec_point,
        )?;
        let data = ec_point.to_bytes();
        self.stream_mut().write_all(data.as_ref())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        halo2_proofs::transcript::Transcript::<C, ChallengeScalar<C>>::common_scalar(self, scalar)?;
        let data = scalar.to_repr();
        self.stream_mut().write_all(data.as_ref())
    }
}

impl<
        C: CurveAffine,
        W: Write,
        const T: usize,
        const RATE: usize,
        const R_F: usize,
        const R_P: usize,
    > halo2_proofs::transcript::TranscriptWriterBuffer<W, C, ChallengeScalar<C>>
    for PoseidonTranscript<C, NativeLoader, W, Poseidon<C::Scalar, T, RATE>, T, RATE, R_F, R_P>
{
    fn init(writer: W) -> Self {
        Self::new(writer)
    }

    fn finalize(self) -> W {
        self.finalize()
    }
}
