use bytes::BytesMut;
use env_logger;
use futures::prelude::*;
use log::info;
use secio::{handshake::Config, SecioKeyPair};
use std::io::Write;
use std::thread;
use tokio::net::{TcpListener, TcpStream};

fn main() {
    env_logger::init();
    let key_1 = SecioKeyPair::secp256k1_generated();
    let key_2 = SecioKeyPair::secp256k1_generated();
    let config_1 = Config::new(key_1);
    let config_2 = Config::new(key_2);

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
        })
        .map_err(|_| ());

    let client = TcpStream::connect(&listener_addr)
        .map_err(|e| e.into())
        .and_then(move |stream| config_2.handshake(stream))
        .and_then(move |(mut handle, _, _)| {
            match handle.write_all(data) {
                Ok(_) => info!("send all"),
                Err(e) => info!("err: {:?}", e),
            }

            let task = tokio::io::read_exact(handle, [0u8; 11])
                .and_then(move |(_, data)| {
                    info!("receive: {:?}", BytesMut::from(data.to_vec()));
                    Ok(())
                })
                .map_err(|_| ());
            tokio::spawn(task);

            Ok(())
        })
        .map_err(|_| ());

    thread::spawn(|| {
        tokio::run(server);
    });

    tokio::run(client);
}
