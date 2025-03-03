use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use futures::prelude::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_yamux::stream::StreamHandle;
use tokio_yamux::{config::Config, session::Session};

pub(crate) fn rt() -> &'static tokio::runtime::Runtime {
    static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RT.get_or_init(|| tokio::runtime::Runtime::new().unwrap())
}

fn run_server() {
    rt().spawn(async move {
        let listener = TcpListener::bind("127.0.0.1:12345").await.unwrap();

        while let Ok((socket, _)) = listener.accept().await {
            let mut session = Session::new_server(socket, Config::default());
            tokio::spawn(async move {
                while let Some(Ok(mut stream)) = session.next().await {
                    tokio::spawn(async move {
                        let mut data = [0u8; 512 * 1024];

                        loop {
                            stream.read_exact(&mut data).await.unwrap();
                            stream.write_all(&data).await.unwrap();
                        }
                    });
                }
            });
        }
    });
}

fn get_handle() -> &'static mut StreamHandle {
    static mut HANDLE: std::sync::OnceLock<StreamHandle> = std::sync::OnceLock::new();
    unsafe {
        HANDLE.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::channel();
            rt().spawn(async move {
                let socket = TcpStream::connect("127.0.0.1:12345").await.unwrap();
                let sa = socket.peer_addr().unwrap();

                let mut session = Session::new_client(socket, Config::default());
                let stream = session.open_stream().unwrap();

                tokio::spawn(async move {
                    loop {
                        match session.next().await {
                            Some(res) => log::warn!("res: {:?}", res),
                            None => break,
                        }
                    }
                    log::warn!("{:?} broken", sa);
                });

                tx.send(stream).unwrap();
            });
            rx.recv().unwrap()
        });

        HANDLE.get_mut().unwrap()
    }
}

async fn bench_test(data: &[u8]) {
    let handle = get_handle();
    handle.write_all(data).await.unwrap();
    let mut responed = vec![0u8; data.len()];
    handle.read_exact(&mut responed).await.unwrap();
    assert_eq!(&responed, data);
}

fn criterion_benchmark(bench: &mut Criterion) {
    run_server();

    let data = (0..512 * 1024)
        .map(|_| rand::random::<u8>())
        .collect::<Vec<_>>();
    let rt = tokio::runtime::Runtime::new().unwrap();
    bench.bench_with_input(BenchmarkId::new("yamux_beach", ""), &data, |b, data| {
        b.to_async(&rt).iter(|| bench_test(data));
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
