use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

type CipherSuite = voprf::Ristretto255;
type OprfResult = digest::Output<<CipherSuite as voprf::CipherSuite>::Hash>;
type BlindedElement = voprf::BlindedElement<CipherSuite>;
type EvaluationElement = voprf::EvaluationElement<CipherSuite>;

mod random {
    use super::*;

    fn random<R: Rng + CryptoRng>(rng: &mut R) -> [u8; 32] {
        let mut result = [0u8; 32];
        rng.fill(&mut result);
        result
    }

    pub fn benchmark(c: &mut Criterion) {
        let mut group = c.benchmark_group("random");
        group.throughput(criterion::Throughput::Elements(1));

        group.bench_function("OsRng", |b| b.iter(|| random(&mut OsRng)));
        group.bench_function("ChaCha RNG", |b| {
            let mut rng = ChaCha12Rng::seed_from_u64(7);
            b.iter(|| random(&mut rng))
        });
    }
}

mod unverifiable {
    use super::*;
    type Client = voprf::OprfClient<CipherSuite>;
    type Server = voprf::OprfServer<CipherSuite>;
    type ClientBlindResult = voprf::OprfClientBlindResult<CipherSuite>;

    fn client_blind<R: Rng + CryptoRng>(input: &[u8], rng: &mut R) -> ClientBlindResult {
        Client::blind(input, rng).unwrap()
    }

    fn server_evaluate(blinded_input: &BlindedElement) -> EvaluationElement {
        let key = hex!("98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4");
        let server = Server::new_from_seed(&key, &[]).unwrap();
        server.blind_evaluate(blinded_input)
    }

    fn client_unblind(
        input: &[u8],
        state: &Client,
        blinded_result: &EvaluationElement,
    ) -> OprfResult {
        state.finalize(input, blinded_result).unwrap()
    }

    fn oprf<R: Rng + CryptoRng>(input: &[u8], rng: &mut R) -> OprfResult {
        let blinded_input = client_blind(input, rng);
        let blinded_result = server_evaluate(&blinded_input.message);
        client_unblind(input, &blinded_input.state, &blinded_result)
    }

    pub fn benchmark(c: &mut Criterion) {
        let mut group = c.benchmark_group("unverifiable");
        group.throughput(criterion::Throughput::Elements(1));

        group.bench_function("client blind", |b| {
            let mut rng = ChaCha12Rng::seed_from_u64(7);
            b.iter(|| client_blind(black_box(b"1234"), &mut rng))
        });

        group.bench_function("server evaluate", |b| {
            let blinded_input = client_blind(b"1234", &mut OsRng).message;
            b.iter(|| server_evaluate(black_box(&blinded_input)));
        });

        group.bench_function("client unblind", |b| {
            let input = b"1234";
            let blinded_input = client_blind(input, &mut OsRng);
            let blinded_result = server_evaluate(&blinded_input.message);
            b.iter(|| {
                client_unblind(
                    black_box(input),
                    black_box(&blinded_input.state),
                    black_box(&blinded_result),
                )
            })
        });

        group.bench_function("OPRF", |b| {
            let mut rng = ChaCha12Rng::seed_from_u64(7);
            b.iter(|| oprf(black_box(b"1234"), &mut rng))
        });
    }
}

mod verifiable {
    use super::*;
    type Client = voprf::VoprfClient<CipherSuite>;
    type Server = voprf::VoprfServer<CipherSuite>;
    type ClientBlindResult = voprf::VoprfClientBlindResult<CipherSuite>;
    type ServerEvaluateResult = voprf::VoprfServerEvaluateResult<CipherSuite>;
    type Proof = voprf::Proof<CipherSuite>;
    type PublicKey = <<CipherSuite as voprf::CipherSuite>::Group as voprf::Group>::Elem;

    fn client_blind<R: Rng + CryptoRng>(input: &[u8], rng: &mut R) -> ClientBlindResult {
        Client::blind(input, rng).unwrap()
    }

    fn make_server() -> Server {
        let key = hex!("98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4");
        Server::new_from_seed(&key, &[]).unwrap()
    }

    fn server_evaluate<R: Rng + CryptoRng>(
        server: &Server,
        blinded_input: &BlindedElement,
        rng: &mut R,
    ) -> ServerEvaluateResult {
        server.blind_evaluate(rng, blinded_input)
    }

    fn client_unblind_and_verify(
        input: &[u8],
        state: &Client,
        blinded_result: &EvaluationElement,
        proof: &Proof,
        public_key: PublicKey,
    ) -> OprfResult {
        state
            .finalize(input, blinded_result, proof, public_key)
            .unwrap()
    }

    pub fn run_voprf<R: Rng + CryptoRng>(input: &[u8], rng: &mut R) -> OprfResult {
        let blinded_input = client_blind(input, rng);

        let server = make_server();
        let ServerEvaluateResult {
            message: blinded_result,
            proof,
        } = server_evaluate(&server, &blinded_input.message, rng);

        let public_key = server.get_public_key();
        client_unblind_and_verify(
            input,
            &blinded_input.state,
            &blinded_result,
            &proof,
            public_key,
        )
    }

    pub fn benchmark(c: &mut Criterion) {
        let mut group = c.benchmark_group("verifiable");
        group.throughput(criterion::Throughput::Elements(1));

        group.bench_function("client blind", |b| {
            let mut rng = ChaCha12Rng::seed_from_u64(7);
            b.iter(|| client_blind(black_box(b"1234"), &mut rng))
        });

        group.bench_function("server evaluate", |b| {
            let mut rng = ChaCha12Rng::seed_from_u64(7);
            let server = make_server();
            let blinded_input = client_blind(b"1234", &mut rng).message;
            b.iter(|| server_evaluate(black_box(&server), black_box(&blinded_input), &mut rng));
        });

        group.bench_function("client unblind & verify", |b| {
            let input = b"1234";
            let mut rng = ChaCha12Rng::seed_from_u64(7);
            let blinded_input = client_blind(input, &mut rng);
            let server = make_server();
            let blinded_result = server_evaluate(&server, &blinded_input.message, &mut rng);
            let public_key = server.get_public_key();
            b.iter(|| {
                client_unblind_and_verify(
                    black_box(input),
                    black_box(&blinded_input.state),
                    black_box(&blinded_result.message),
                    black_box(&blinded_result.proof),
                    black_box(public_key),
                )
            })
        });

        group.bench_function("VOPRF", |b| {
            let mut rng = ChaCha12Rng::seed_from_u64(7);
            b.iter(|| run_voprf(black_box(b"1234"), &mut rng))
        });
    }
}

criterion_group!(
    benches,
    random::benchmark,
    unverifiable::benchmark,
    verifiable::benchmark
);
criterion_main!(benches);
