use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use tentacle_secio::crypto::{cipher::CipherType, new_stream, CryptoMode};

fn decode_encode(data: &[u8], cipher: CipherType) {
    let cipher_key = (0..cipher.key_size())
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();

    let mut encode_cipher = new_stream(cipher, &cipher_key, CryptoMode::Encrypt);
    let mut decode_cipher = new_stream(cipher, &cipher_key, CryptoMode::Decrypt);

    let encode_data = encode_cipher.encrypt(&data[..]).unwrap();

    let decode_data = decode_cipher.decrypt(&encode_data).unwrap();

    assert_eq!(&decode_data[..], &data[..]);
}

fn bench_test(bench: &mut Bencher, cipher: CipherType, data: &[u8]) {
    bench.iter(|| {
        decode_encode(data, cipher);
    })
}

fn criterion_benchmark(bench: &mut Criterion) {
    let data = (0..1024 * 256)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();
    bench.bench_function("1kb_aes128gcm", {
        let data = data.clone();
        move |b| bench_test(b, CipherType::Aes128Gcm, &data)
    });
    bench.bench_function("1kb_aes256gcm", {
        let data = data.clone();
        move |b| bench_test(b, CipherType::Aes256Gcm, &data)
    });
    bench.bench_function("1kb_chacha20poly1305", move |b| {
        bench_test(b, CipherType::ChaCha20Poly1305, &data)
    });

    let data = (0..1024 * 1024)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();
    bench.bench_function("1mb_aes128gcm", {
        let data = data.clone();
        move |b| bench_test(b, CipherType::Aes128Gcm, &data)
    });
    bench.bench_function("1mb_aes256gcm", {
        let data = data.clone();
        move |b| bench_test(b, CipherType::Aes256Gcm, &data)
    });
    bench.bench_function("1mb_chacha20poly1305", move |b| {
        bench_test(b, CipherType::ChaCha20Poly1305, &data)
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
