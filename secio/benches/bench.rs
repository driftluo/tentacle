use bytes::BytesMut;
use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use secio::{
    codec::Hmac,
    stream_cipher::{ctr_init, Cipher},
    Digest,
};

const NULL_IV: [u8; 16] = [0; 16];

fn decode_encode(data: &[u8], cipher: Cipher) {
    let cipher_key = (0..cipher.key_size())
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();
    let hmac_key: [u8; 32] = rand::random();

    let mut encode_data = BytesMut::from(data);

    let mut encode_cipher = ctr_init(cipher, &cipher_key, &NULL_IV);
    let mut encode_hmac = Hmac::from_key(Digest::Sha256, &hmac_key);
    let mut decode_cipher = ctr_init(cipher, &cipher_key, &NULL_IV);
    let mut decode_hmac = encode_hmac.clone();

    encode_cipher.encrypt(&mut encode_data[..]);
    let signature = encode_hmac.sign(&encode_data[..]);
    encode_data.extend_from_slice(signature.as_ref());

    let content_length = encode_data.len() - decode_hmac.num_bytes();

    let (crypted_data, expected_hash) = encode_data.split_at(content_length);

    assert!(decode_hmac.verify(crypted_data, expected_hash));

    let mut decode_data = encode_data.to_vec();
    decode_data.truncate(content_length);
    decode_cipher.decrypt(&mut decode_data);

    assert_eq!(&decode_data[..], &data[..]);
}

fn bench_test(bench: &mut Bencher, cipher: Cipher, data: &[u8]) {
    bench.iter(|| {
        decode_encode(data, cipher);
    })
}

fn criterion_benchmark(bench: &mut Criterion) {
    let data = (0..1024).map(|_| rand::random::<u8>()).collect::<Vec<_>>();
    bench.bench_function("1kb_aes128", {
        let data = data.clone();
        move |b| bench_test(b, Cipher::Aes128, &data)
    });
    bench.bench_function("1kb_aes256", {
        let data = data.clone();
        move |b| bench_test(b, Cipher::Aes256, &data)
    });
    bench.bench_function("1kb_twofish", move |b| {
        bench_test(b, Cipher::TwofishCtr, &data)
    });

    let data = (0..1024 * 1024)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();
    bench.bench_function("1mb_aes128", {
        let data = data.clone();
        move |b| bench_test(b, Cipher::Aes128, &data)
    });
    bench.bench_function("1mb_aes256", {
        let data = data.clone();
        move |b| bench_test(b, Cipher::Aes256, &data)
    });
    bench.bench_function("1mb_twofish", move |b| {
        bench_test(b, Cipher::TwofishCtr, &data)
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
