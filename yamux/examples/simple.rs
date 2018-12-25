use std::io::{Read, Write};
use std::thread;
use std::time::Duration;

use futures::Future;
use futures::Stream;
use log::{debug, error, info, trace, warn};
use tokio::io as tokio_io;
use tokio::io::{copy, AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use yamux::{config::Config, session::Session, stream::StreamHandle};

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
    // Bind the server's socket.
    let addr = "127.0.0.1:12345".parse().unwrap();
    let listener = TcpListener::bind(&addr).expect("unable to bind TCP listener");

    // Pull out a stream of sockets for incoming connections
    let server = listener
        .incoming()
        .map_err(|e| eprintln!("accept failed = {:?}", e))
        .for_each(|sock| {
            info!("accepted a socket: {:?}", sock.peer_addr());
            let session = Session::new_server(sock, Config::default());
            // Split up the reading and writing parts of the
            // socket.
            let fut = session
                .for_each(|stream| {
                    info!("Server accept a stream from client: id={}", stream.id());
                    let fut = tokio_io::read_exact(stream, [0u8; 3])
                        .and_then(|(stream, data)| {
                            info!("[server] read data: {:?}", data);
                            Ok(stream)
                        })
                        .and_then(|mut stream| {
                            info!("[server] send 'def' to remote");
                            stream.write(b"def").unwrap();
                            stream.flush().unwrap();
                            Ok(stream)
                        })
                        .and_then(|stream| {
                            tokio_io::read_exact(stream, [0u8; 2]).and_then(|(stream, data)| {
                                info!("[server] read again: {:?}", data);
                                Ok(stream)
                            })
                        })
                        .map_err(|err| {
                            error!("server stream error: {:?}", err);
                            ()
                        })
                        .map(|_| ());
                    tokio::spawn(fut);
                    Ok(())
                })
                .map_err(|err| {
                    error!("server stream error: {:?}", err);
                    ()
                });

            // Spawn the future as a concurrent task.
            tokio::spawn(fut)
        });

    // Start the Tokio runtime
    tokio::run(server);
}

fn run_client() {
    use tokio::net::TcpStream;
    let addr = "127.0.0.1:12345".parse().unwrap();
    let socket = TcpStream::connect(&addr)
        .and_then(|sock| {
            info!("[client] connected to server: {:?}", sock.peer_addr());
            let mut session = Session::new_client(sock, Config::default());

            let mut stream = session.open_stream().unwrap();
            info!("[client] send 'abc' to remote");
            stream.write(b"abc").unwrap();

            info!("[client] reading data");
            let fut = tokio_io::read_exact(stream, [0u8; 3])
                .and_then(|(mut stream, data)| {
                    info!("[client] read data: {:?}", data);
                    stream.shutdown().unwrap();
                    Ok(())
                })
                .map_err(|_| ());
            tokio::spawn(fut);

            session.for_each(|stream| {
                info!("[client] accept a stream from server: id={}", stream.id());
                Ok(())
            })
        })
        .map_err(|err| {
            error!("[client] error: {:?}", err);
            ()
        });
    tokio::run(socket);
}
