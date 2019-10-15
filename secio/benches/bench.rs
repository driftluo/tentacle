use bytes::BytesMut;
use criterion::{criterion_group, criterion_main, Bencher, Criterion};
use tentacle_secio::{
    codec::Hmac,
    crypto::{cipher::CipherType, new_stream, CryptoMode},
    Digest,
};

fn decode_encode(data: &[u8], cipher: CipherType) {
    let cipher_key = (0..cipher.key_size())
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();
    let hmac_key: [u8; 32] = rand::random();
    let iv = (0..cipher.iv_size())
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();

    let mut encode_cipher = new_stream(cipher, &cipher_key, &iv, CryptoMode::Encrypt);
    let mut decode_cipher = new_stream(cipher, &cipher_key, &iv, CryptoMode::Decrypt);
    let (mut decode_hmac, mut encode_hmac) = match cipher {
        CipherType::ChaCha20Poly1305 | CipherType::Aes128Gcm | CipherType::Aes256Gcm => {
            (None, None)
        }
        _ => {
            let encode_hmac = Hmac::from_key(Digest::Sha256, &hmac_key);
            let decode_hmac = encode_hmac.clone();
            (Some(decode_hmac), Some(encode_hmac))
        }
    };

    let mut encode_data = BytesMut::new();
    encode_cipher.update(&data[..], &mut encode_data).unwrap();
    if encode_hmac.is_some() {
        let signature = encode_hmac.as_mut().unwrap().sign(&encode_data[..]);
        encode_data.extend_from_slice(signature.as_ref());
    }

    if decode_hmac.is_some() {
        let content_length = encode_data.len() - decode_hmac.as_mut().unwrap().num_bytes();

        let (crypted_data, expected_hash) = encode_data.split_at(content_length);

        assert!(decode_hmac
            .as_mut()
            .unwrap()
            .verify(crypted_data, expected_hash));

        encode_data.truncate(content_length);
    }

    let mut decode_data = BytesMut::new();
    decode_cipher
        .update(&encode_data, &mut decode_data)
        .unwrap();

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
    bench.bench_function("1kb_aes128ctr", {
        let data = data.clone();
        move |b| bench_test(b, CipherType::Aes128Ctr, &data)
    });
    bench.bench_function("1kb_aes256ctr", {
        let data = data.clone();
        move |b| bench_test(b, CipherType::Aes256Ctr, &data)
    });
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
    bench.bench_function("1mb_aes128ctr", {
        let data = data.clone();
        move |b| bench_test(b, CipherType::Aes128Ctr, &data)
    });
    bench.bench_function("1mb_aes256ctr", {
        let data = data.clone();
        move |b| bench_test(b, CipherType::Aes256Ctr, &data)
    });
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
