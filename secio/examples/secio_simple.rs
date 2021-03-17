use bytes::BytesMut;
use env_logger;
use log::info;
use tentacle_secio::{handshake::Config, SecioKeyPair};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

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

    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:1337").await.unwrap();

        while let Ok((socket, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                let (mut handle, _, _) = config.handshake(socket).await.unwrap();
                let mut data = [0u8; 11];
                handle.read_exact(&mut data).await.unwrap();
                info!("receive: {:?}", BytesMut::from(&data[..]));
                handle.write_all(&data).await.unwrap();
            });
        }
    });
}

fn client() {
    let key = SecioKeyPair::secp256k1_generated();
    let config = Config::new(key);

    let data = b"hello world";

    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async move {
        let stream = TcpStream::connect("127.0.0.1:1337").await.unwrap();
        let (mut handle, _, _) = config.handshake(stream).await.unwrap();
        match handle.write_all(data).await {
            Ok(_) => info!("send all"),
            Err(e) => info!("err: {:?}", e),
        }
        let mut data = [0u8; 11];
        handle.read_exact(&mut data).await.unwrap();
        info!("receive: {:?}", BytesMut::from(&data[..]));
    });
}
