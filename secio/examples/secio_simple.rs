use bytes::BytesMut;
use env_logger;
use futures::prelude::*;
use log::info;
use std::io::Write;
use tentacle_secio::{handshake::Config, SecioKeyPair};
use tokio::net::{TcpListener, TcpStream};

fn main() {
    env_logger::init();

    if std::env::args().nth(1) == Some("server".to_string()) {
        info!("Starting server ......");
        server();
    } else {
        info!("Starting client ......");
        client();
    }
}

fn server() {
    let key = SecioKeyPair::secp256k1_generated();
    let config = Config::new(key);

    let listener = TcpListener::bind(&"127.0.0.1:1337".parse().unwrap()).unwrap();

    let server = listener
        .incoming()
        .for_each(move |socket| {
            let task = config
                .clone()
                .handshake(socket)
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
            tokio::spawn(task);

            Ok(())
        })
        .map_err(|e| info!("server error: {:?}", e));
    tokio::run(server);
}

fn client() {
    let key = SecioKeyPair::secp256k1_generated();
    let config = Config::new(key);

    let data = b"hello world";

    let client = TcpStream::connect(&"127.0.0.1:1337".parse().unwrap())
        .and_then(move |stream| config.handshake(stream).map_err(|e| e.into()))
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
        .map_err(|e| info!("client: {:?}", e));

    tokio::run(client);
}
