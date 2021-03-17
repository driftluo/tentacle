use futures::prelude::*;
use log::info;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_yamux::{config::Config, session::Session};

fn main() {
    env_logger::init();
    if std::env::args().nth(1) == Some("server".to_string()) {
        info!("Starting server ......");
        run_server();
    } else {
        info!("Starting client ......");
        run_client();
    }
}

fn run_server() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();

        while let Ok((socket, _)) = listener.accept().await {
            info!("accepted a socket: {:?}", socket.peer_addr());
            let mut session = Session::new_server(socket, Config::default());
            tokio::spawn(async move {
                while let Some(Ok(mut stream)) = session.next().await {
                    info!("Server accept a stream from client: id={}", stream.id());
                    tokio::spawn(async move {
                        let mut data = [0u8; 3];
                        stream.read_exact(&mut data).await.unwrap();
                        info!("[server] read data: {:?}", data);

                        info!("[server] send 'def' to remote");
                        stream.write_all(b"def").await.unwrap();

                        let mut data = [0u8; 2];
                        stream.read_exact(&mut data).await.unwrap();
                        info!("[server] read again: {:?}", data);
                    });
                }
            });
        }
    });
}

fn run_client() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async move {
        let socket = TcpStream::connect("127.0.0.1:12345").await.unwrap();
        info!("[client] connected to server: {:?}", socket.peer_addr());
        let mut session = Session::new_client(socket, Config::default());
        let mut stream = session.open_stream().unwrap();

        tokio::spawn(async move {
            loop {
                match session.next().await {
                    Some(Ok(_)) => (),
                    Some(Err(e)) => {
                        info!("{}", e);
                        break;
                    }
                    None => {
                        info!("closed");
                        break;
                    }
                }
            }
        });

        info!("[client] send 'abc' to remote");
        stream.write_all(b"abc").await.unwrap();

        info!("[client] reading data");
        let mut data = [0u8; 3];
        stream.read_exact(&mut data).await.unwrap();
        info!("[client] read data: {:?}", data);

        info!("[client] send 'dd' to remote");
        stream.write_all(b"dd").await.unwrap();
        stream.shutdown().await.unwrap();
    });
}
