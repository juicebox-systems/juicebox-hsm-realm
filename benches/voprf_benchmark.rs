use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hex_literal::hex;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

type CipherSuite = voprf::Ristretto255;
type OprfClient = voprf::OprfClient<CipherSuite>;
type OprfServer = voprf::OprfServer<CipherSuite>;
type OprfResult = digest::Output<<CipherSuite as voprf::CipherSuite>::Hash>;

fn random<R: Rng + CryptoRng>(rng: &mut R) -> [u8; 32] {
    let mut result = [0u8; 32];
    rng.fill(&mut result);
    result
}

fn client_blind<R: Rng + CryptoRng>(
    input: &[u8],
    rng: &mut R,
) -> voprf::OprfClientBlindResult<CipherSuite> {
    OprfClient::blind(input, rng).unwrap()
}

fn server_evaluate(
    blinded_input: &voprf::BlindedElement<CipherSuite>,
) -> voprf::EvaluationElement<CipherSuite> {
    let key = hex!("98ea6e4f216f2fb4b69fff9b3a44842c38686ca685f3f55dc48c5d3fb1107be4");
    let oprf = OprfServer::new_from_seed(&key, &[]).unwrap();
    oprf.blind_evaluate(blinded_input)
}

fn client_unblind(
    input: &[u8],
    state: &voprf::OprfClient<CipherSuite>,
    blinded_result: &voprf::EvaluationElement<CipherSuite>,
) -> OprfResult {
    state.finalize(input, blinded_result).unwrap()
}

fn oprf<R: Rng + CryptoRng>(input: &[u8], rng: &mut R) -> OprfResult {
    let blinded_input = client_blind(input, rng);
    let blinded_result = server_evaluate(&blinded_input.message);
    client_unblind(input, &blinded_input.state, &blinded_result)
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("voprf");
    group.throughput(criterion::Throughput::Elements(1));

    group.bench_function("random: OsRng", |b| b.iter(|| random(&mut OsRng)));
    group.bench_function("random: ChaCha RNG", |b| {
        let mut rng = ChaCha12Rng::seed_from_u64(7);
        b.iter(|| random(&mut rng))
    });

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

    group.bench_function("oprf", |b| {
        let mut rng = ChaCha12Rng::seed_from_u64(7);
        b.iter(|| oprf(black_box(b"1234"), &mut rng))
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
