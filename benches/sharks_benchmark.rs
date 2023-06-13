use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::rngs::OsRng;
use sharks::{Share, Sharks};

pub fn benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sharks");
    group.throughput(criterion::Throughput::Elements(1));

    for secret_len in [16, 32, 145] {
        for num_shares in (1..=10).chain([16, 32]) {
            let mut thresholds = vec![num_shares / 2, num_shares * 3 / 4, num_shares];
            thresholds.dedup();
            thresholds.retain(|t| *t > 0);
            for threshold in thresholds {
                group.bench_with_input(
                    BenchmarkId::new(
                        "recover",
                        format!("len={secret_len}/n={num_shares}/t={threshold}"),
                    ),
                    &(secret_len, num_shares, threshold),
                    |b, &(secret_len, num_shares, threshold)| {
                        let secret = black_box(vec![77; secret_len]);
                        let shares: Vec<Share> = Sharks(threshold)
                            .dealer_rng(&secret, &mut OsRng)
                            .take(usize::from(num_shares))
                            .collect();
                        b.iter(|| {
                            Sharks(threshold)
                                .recover(&shares[..usize::from(threshold)])
                                .unwrap()
                        })
                    },
                );
            }
        }
    }
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
