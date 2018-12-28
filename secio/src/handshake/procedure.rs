use bincode::{deserialize, serialize};
use bytes::{Bytes, BytesMut};
use futures::{future, prelude::*, Future};
use log::{debug, trace};
use sha2::{Digest as SHADigest, Sha256};
use std::{
    cmp::Ordering,
    io::{self, Write},
};
use tokio::codec::length_delimited::Builder;
use tokio::prelude::{AsyncRead, AsyncWrite};

use crate::{
    codec::{secure_stream::SecureStream, stream_handle::StreamHandle, Hmac},
    error::SecioError,
    exchange,
    handshake::Config,
    handshake::{handshake_context::HandshakeContext, handshake_struct::Exchange},
    stream_cipher::ctr_int,
    EphemeralPublicKey, PublicKey,
};

/// Performs a handshake on the given socket.
///
/// This function expects that the remote is identified with `remote_public_key`, and the remote
/// will expect that we are identified with `local_key`.Any mismatch somewhere will produce a
/// `SecioError`.
///
/// On success, returns an object that implements the `Sink` and `Stream` trait whose items are
/// buffers of data, plus the public key of the remote, plus the ephemeral public key used during
/// negotiation.
pub(in crate::handshake) fn handshake<T>(
    socket: T,
    config: Config,
) -> impl Future<Item = (StreamHandle, PublicKey, EphemeralPublicKey), Error = SecioError>
where
    T: AsyncRead + AsyncWrite + Send + 'static,
{
    // The handshake messages all start with a 4-bytes message length prefix.
    let socket = Builder::new()
        .big_endian()
        .length_field_length(4)
        .new_framed(socket);

    future::ok::<_, SecioError>(HandshakeContext::new(config))
        .and_then(|context| {
            // Generate our nonce.
            let context = context.with_local();
            trace!(
                "starting handshake; local nonce = {:?}",
                context.state.nonce
            );
            Ok(context)
        })
        .and_then(|context| {
            trace!("sending proposition to remote");
            socket
                .send(BytesMut::from(context.state.proposition_bytes.clone()).freeze())
                .from_err()
                .map(|socket| (socket, context))
        })
        .and_then(move |(socket, context)| {
            // Receive the remote's proposition.
            socket.into_future().map_err(|(e, _)| e.into()).and_then(
                move |(remote_propose, socket)| {
                    let context = match remote_propose {
                        Some(p) => context.with_remote(p)?,
                        None => {
                            let err = io::Error::new(io::ErrorKind::BrokenPipe, "unexpected eof");
                            debug!("unexpected eof while waiting for remote's proposition");
                            return Err(err.into());
                        }
                    };
                    trace!(
                        "received proposition from remote; pubkey = {:?}; nonce = {:?}",
                        context.state.public_key,
                        context.state.nonce
                    );
                    Ok((socket, context))
                },
            )
        })
        .and_then(|(socket, context)| {
            // Generate an ephemeral key for the negotiation.
            exchange::generate_agreement(context.state.chosen_exchange).map(
                move |(tmp_priv_key, tmp_pub_key)| (socket, context, tmp_priv_key, tmp_pub_key),
            )
        })
        .and_then(|(socket, context, tmp_priv, tmp_pub_key)| {
            // Send the ephemeral pub key to the remote in an `Exchange` struct. The `Exchange` also
            // contains a signature of the two propositions encoded with our static public key.
            let context = context.with_ephemeral(tmp_priv, tmp_pub_key.clone());
            let exchanges = {
                let mut exchanges = Exchange::new();

                let mut data_to_sign = context.state.remote.local.proposition_bytes.clone();
                data_to_sign.extend_from_slice(&context.state.remote.proposition_bytes);
                data_to_sign.extend_from_slice(&tmp_pub_key);

                exchanges.epubkey = tmp_pub_key;

                let data_to_sign = Sha256::digest(&data_to_sign);
                let message = secp256k1::Message::from_slice(data_to_sign.as_ref())
                    .expect("digest output length doesn't match secp256k1 input length");
                let secp256k1_key = secp256k1::Secp256k1::signing_only();
                let signature = secp256k1_key
                    .sign(&message, &context.config.key.inner)
                    .serialize_der();
                exchanges.signature = signature;
                exchanges
            };
            let local_exchanges = serialize(&exchanges).unwrap();

            // Send our local `Exchange`.
            trace!("sending exchange to remote");
            socket
                .send(Bytes::from(local_exchanges))
                .from_err()
                .map(|socket| (socket, context))
        })
        .and_then(|(socket, context)| {
            // Receive the remote's `Exchange`.
            socket
                .into_future()
                .map_err(|(e, _)| e.into())
                .and_then(|(raw_exchanges, socket)| {
                    let raw_exchanges = match raw_exchanges {
                        Some(raw) => raw,
                        None => {
                            let err = io::Error::new(io::ErrorKind::BrokenPipe, "unexpected eof");
                            debug!("unexpected eof while waiting for remote's proposition");
                            return Err(err.into());
                        }
                    };

                    let remote_exchanges = match deserialize::<Exchange>(&raw_exchanges) {
                        Ok(e) => e,
                        Err(err) => {
                            debug!("failed to parse remote's exchange protobuf; {:?}", err);
                            return Err(SecioError::HandshakeParsingFailure);
                        }
                    };

                    trace!("received and decoded the remote's exchange");
                    Ok((remote_exchanges, socket, context))
                })
        })
        .and_then(|(remote_exchanges, socket, context)| {
            // Check the validity of the remote's `Exchange`. This verifies that the remote was really
            // the sender of its proposition, and that it is the owner of both its global and ephemeral
            // keys.

            let mut data_to_verify = context.state.remote.proposition_bytes.clone();
            data_to_verify.extend_from_slice(&context.state.remote.local.proposition_bytes);
            data_to_verify.extend_from_slice(&remote_exchanges.epubkey);

            let data_to_verify = Sha256::digest(&data_to_verify);
            let message = secp256k1::Message::from_slice(data_to_verify.as_ref())
                .expect("digest output length doesn't match secp256k1 input length");
            let secp256k1 = secp256k1::Secp256k1::verification_only();
            let signature = secp256k1::Signature::from_der(&remote_exchanges.signature);
            let remote_public_key =
                secp256k1::key::PublicKey::from_slice(&context.state.remote.public_key);
            if let (Ok(signature), Ok(remote_public_key)) = (signature, remote_public_key) {
                match secp256k1.verify(&message, &signature, &remote_public_key) {
                    Ok(()) => (),
                    Err(_) => {
                        debug!("failed to verify the remote's signature");
                        return Err(SecioError::SignatureVerificationFailed);
                    }
                }
            } else {
                debug!("remote's secp256k1 signature has wrong format");
                return Err(SecioError::SignatureVerificationFailed);
            }

            trace!("successfully verified the remote's signature");
            Ok((remote_exchanges, socket, context))
        })
        .and_then(|(remote_exchanges, socket, context)| {
            // Generate a key from the local ephemeral private key and the remote ephemeral public key,
            // derive from it a cipher key, an iv, and a hmac key, and build the encoder/decoder.

            let (context, local_priv_key) = context.take_private_key();
            let key_size = context.state.remote.chosen_hash.num_bytes();
            exchange::agree(
                context.state.remote.chosen_exchange,
                local_priv_key,
                &remote_exchanges.epubkey,
                key_size,
            )
            .map(move |key_material| (socket, context, key_material))
        })
        .and_then(|(socket, context, key_material)| {
            // Generate a key from the local ephemeral private key and the remote ephemeral public key,
            // derive from it a cipher key, an iv, and a hmac key, and build the encoder/decoder.

            let chosen_cipher = context.state.remote.chosen_cipher;
            let cipher_key_size = chosen_cipher.key_size();
            let iv_size = chosen_cipher.iv_size();

            let key = Hmac::from_key(context.state.remote.chosen_hash, &key_material);
            let mut longer_key = vec![0u8; 2 * (iv_size + cipher_key_size + 20)];
            stretch_key(key, &mut longer_key);

            let (local_infos, _remote_infos) = {
                let (first_half, second_half) = longer_key.split_at(longer_key.len() / 2);
                match context.state.remote.hashes_ordering {
                    Ordering::Equal => {
                        let msg = "equal digest of public key and nonce for local and remote";
                        return Err(SecioError::InvalidProposition(msg));
                    }
                    Ordering::Less => (second_half, first_half),
                    Ordering::Greater => (first_half, second_half),
                }
            };

            let (cipher, hmac) = {
                let (iv, rest) = local_infos.split_at(iv_size);
                let (cipher_key, mac_key) = rest.split_at(cipher_key_size);
                let hmac = Hmac::from_key(context.state.remote.chosen_hash, mac_key);
                let cipher = ctr_int(chosen_cipher, cipher_key, iv);
                (cipher, hmac)
            };

            let secure_stream = SecureStream::new(
                socket,
                cipher,
                hmac,
                context.state.remote.local.nonce.to_vec(),
            );
            Ok((secure_stream, context))
        })
        .and_then(|(mut secure_stream, context)| {
            // We send back their nonce to check if the connection works.
            trace!("checking encryption by sending back remote's nonce");
            let mut handle = secure_stream.create_handle().unwrap();

            tokio::spawn(secure_stream.for_each(|_| Ok(())));

            match handle.write_all(&context.state.remote.nonce) {
                Ok(_) => (),
                Err(e) => return Err(e.into()),
            }
            Ok((
                handle,
                context.state.remote.public_key,
                context.state.local_tmp_pub_key,
            ))
        })
}

/// Custom algorithm translated from reference implementations. Needs to be the same algorithm
/// amongst all implementations.
fn stretch_key(hmac: Hmac, result: &mut [u8]) {
    match hmac {
        Hmac::Sha256(hmac) => stretch_key_inner(hmac, result),
        Hmac::Sha512(hmac) => stretch_key_inner(hmac, result),
    }
}

fn stretch_key_inner<D: ::hmac::digest::Digest + Clone>(hmac: ::hmac::Hmac<D>, result: &mut [u8])
where
    ::hmac::Hmac<D>: Clone,
    D: hmac::digest::Input
        + hmac::digest::BlockInput
        + hmac::digest::FixedOutput
        + hmac::digest::Reset
        + Default
        + Clone,
    D::BlockSize: hmac::digest::generic_array::ArrayLength<u8> + Clone,
{
    use ::hmac::Mac;
    const SEED: &[u8] = b"key expansion";

    let mut init_ctxt = hmac.clone();
    init_ctxt.input(SEED);
    let mut a = init_ctxt.result().code();

    let mut j = 0;
    while j < result.len() {
        let mut context = hmac.clone();
        context.input(a.as_ref());
        context.input(SEED);
        let b = context.result().code();

        let todo = ::std::cmp::min(b.as_ref().len(), result.len() - j);

        result[j..j + todo].copy_from_slice(&b.as_ref()[..todo]);

        j += todo;

        let mut context = hmac.clone();
        context.input(a.as_ref());
        a = context.result().code();
    }
}

#[cfg(test)]
mod tests {
    use super::stretch_key;
    use crate::{codec::Hmac, handshake::Config, Digest, SecioKeyPair};

    use futures::prelude::*;
    use std::io::Write;
    use tokio::net::{TcpListener, TcpStream};

    fn handshake_with_self_sucess(config_1: Config, config_2: Config) {
        let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let data = b"hello world";

        let server = listener
            .incoming()
            .into_future()
            .map_err(|(e, _)| e.into())
            .and_then(move |(connect, _)| config_1.handshake(connect.unwrap()))
            .and_then(|(handle, _, _)| {
                let task = tokio::io::read_exact(handle, [0u8; 11])
                    .and_then(move |(mut handle, data)| {
                        let _ = handle.write_all(&data);
                        Ok(())
                    })
                    .map_err(|_| ());
                tokio::spawn(task);
                Ok(())
            });

        let client = TcpStream::connect(&listener_addr)
            .map_err(|e| e.into())
            .and_then(move |stream| config_2.handshake(stream))
            .and_then(move |(mut handle, _, _)| {
                let _ = handle.write_all(data);

                let task = tokio::io::read_exact(handle, [0u8; 11])
                    .and_then(move |(_, data)| {
                        assert_eq!(b"hello world", &data[..]);
                        Ok(())
                    })
                    .map_err(|_| ());

                tokio::spawn(task);

                Ok(())
            });

        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let _ = rt.block_on(server.join(client)).unwrap();
    }

    #[test]
    fn handshake_with_self_sucess_secp256k1() {
        let key_1 = SecioKeyPair::secp256k1_generated();
        let key_2 = SecioKeyPair::secp256k1_generated();
        handshake_with_self_sucess(Config::new(key_1), Config::new(key_2))
    }

    #[test]
    fn stretch() {
        let mut output = [0u8; 32];

        let key1 = Hmac::from_key(Digest::Sha256, &[]);
        stretch_key(key1, &mut output);
        assert_eq!(
            &output,
            &[
                103, 144, 60, 199, 85, 145, 239, 71, 79, 198, 85, 164, 32, 53, 143, 205, 50, 48,
                153, 10, 37, 32, 85, 1, 226, 61, 193, 1, 154, 120, 207, 80,
            ]
        );

        let key2 = Hmac::from_key(
            Digest::Sha256,
            &[
                157, 166, 80, 144, 77, 193, 198, 6, 23, 220, 87, 220, 191, 72, 168, 197, 54, 33,
                219, 225, 84, 156, 165, 37, 149, 224, 244, 32, 170, 79, 125, 35, 171, 26, 178, 176,
                92, 168, 22, 27, 205, 44, 229, 61, 152, 21, 222, 81, 241, 81, 116, 236, 74, 166,
                89, 145, 5, 162, 108, 230, 55, 54, 9, 17,
            ],
        );
        stretch_key(key2, &mut output);
        assert_eq!(
            &output,
            &[
                39, 151, 182, 63, 180, 175, 224, 139, 42, 131, 130, 116, 55, 146, 62, 31, 157, 95,
                217, 15, 73, 81, 10, 83, 243, 141, 64, 227, 103, 144, 99, 121,
            ]
        );

        let key3 = Hmac::from_key(
            Digest::Sha256,
            &[
                98, 219, 94, 104, 97, 70, 139, 13, 185, 110, 56, 36, 66, 3, 80, 224, 32, 205, 102,
                170, 59, 32, 140, 245, 86, 102, 231, 68, 85, 249, 227, 243, 57, 53, 171, 36, 62,
                225, 178, 74, 89, 142, 151, 94, 183, 231, 208, 166, 244, 130, 130, 209, 248, 65,
                19, 48, 127, 127, 55, 82, 117, 154, 124, 108,
            ],
        );
        stretch_key(key3, &mut output);
        assert_eq!(
            &output,
            &[
                28, 39, 158, 206, 164, 16, 211, 194, 99, 43, 208, 36, 24, 141, 90, 93, 157, 236,
                238, 111, 170, 0, 60, 11, 49, 174, 177, 121, 30, 12, 182, 25,
            ]
        );
    }
}
