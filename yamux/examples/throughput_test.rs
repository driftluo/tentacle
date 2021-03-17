use bytesize::ByteSize;
use futures::prelude::*;
use log::{info, warn};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::sleep,
};
use tokio_yamux::stream::StreamHandle;
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

const STR: &str = "fakeu1234567890cmxcmmmmmmmmmsssmssmsmsmxcmcmcnxzlllslsllcccccsannmxmxmxmxmxmxmxmxmmsssjjkzoso.";
const LEN: usize = STR.len();

static REQC: AtomicUsize = AtomicUsize::new(0);
static RESPC: AtomicUsize = AtomicUsize::new(0);

use std::{
    str,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

fn reqc_incr() -> usize {
    REQC.fetch_add(1, Ordering::Relaxed)
}

fn reqc() -> usize {
    REQC.swap(0, Ordering::SeqCst)
}

fn respc_incr() -> usize {
    RESPC.fetch_add(1, Ordering::Relaxed)
}

fn respc() -> usize {
    RESPC.swap(0, Ordering::SeqCst)
}

async fn show_metric() {
    let secs = 10;
    loop {
        sleep(Duration::from_millis(1000 * secs)).await;
        let reqc = reqc();
        let respc = respc();
        info!(
            "{} secs req {}, resp {}; {} req/s, {}/s; {} resp/s {}/s",
            secs,
            reqc,
            respc,
            reqc as f64 / secs as f64,
            ByteSize::b(((reqc * LEN) as f64 / secs as f64) as u64).to_string_as(true),
            respc as f64 / secs as f64,
            ByteSize::b(((respc * LEN) as f64 / secs as f64) as u64).to_string_as(true),
        );
    }
}

fn run_server() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.spawn(show_metric());

    rt.block_on(async move {
        let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();

        while let Ok((socket, _)) = listener.accept().await {
            info!("accepted a socket: {:?}", socket.peer_addr());
            let mut session = Session::new_server(socket, Config::default());
            tokio::spawn(async move {
                while let Some(Ok(mut stream)) = session.next().await {
                    info!("Server accept a stream from client: id={}", stream.id());
                    tokio::spawn(async move {
                        let mut data = [0u8; LEN];
                        stream.read_exact(&mut data).await.unwrap();
                        assert_eq!(data.as_ref(), STR.as_bytes());

                        loop {
                            stream.write_all(STR.as_bytes()).await.unwrap();
                            respc_incr();

                            stream.read_exact(&mut data).await.unwrap();
                            reqc_incr();

                            assert_eq!(data.as_ref(), STR.as_bytes());
                        }
                    });
                }
            });
        }
    });
}

fn run_client() {
    let num = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(2);

    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async move {
        let socket = TcpStream::connect("127.0.0.1:12345").await.unwrap();
        let sa = socket.peer_addr().unwrap();
        info!("[client] connected to server: {:?}", sa);

        let mut session = Session::new_client(socket, Config::default());
        let streams = (0..num)
            .into_iter()
            .map(|_| session.open_stream().unwrap())
            .collect::<Vec<_>>();

        tokio::spawn(async move {
            loop {
                match session.next().await {
                    Some(res) => warn!("res: {:?}", res),
                    None => break,
                }
            }
            warn!("{:?} broken", sa);
        });

        let f = |mut s: StreamHandle| {
            tokio::spawn(async move {
                s.write_all(STR.as_bytes()).await.unwrap();

                let mut data = [0u8; LEN];

                loop {
                    s.read_exact(&mut data).await.unwrap();
                    assert_eq!(data.as_ref(), STR.as_bytes());
                    respc_incr();

                    s.write_all(STR.as_bytes()).await.unwrap();
                    reqc_incr();
                }
            })
        };

        for stream in streams {
            f(stream);
        }

        show_metric().await;
    });
}
