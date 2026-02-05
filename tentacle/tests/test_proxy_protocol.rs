//! Integration tests for HAProxy PROXY protocol and X-Forwarded-For header support
//!
//! These tests verify that when connections come from loopback addresses,
//! the real client IP is correctly extracted from:
//! - PROXY protocol v1/v2 headers for TCP connections
//! - X-Forwarded-For headers for WebSocket connections

use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use futures::channel;
use tentacle::{
    ProtocolId, async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    secio::SecioKeyPair,
    service::{ProtocolHandle, ProtocolMeta, Service, ServiceEvent},
    traits::{ServiceHandle, ServiceProtocol},
};
#[cfg(feature = "ws")]
use tokio::io::AsyncReadExt;
use tokio::{io::AsyncWriteExt, net::TcpStream};

/// Build PROXY protocol v1 header
fn build_proxy_v1_header(src_ip: &str, dst_ip: &str, src_port: u16, dst_port: u16) -> String {
    let protocol = if src_ip.contains(':') { "TCP6" } else { "TCP4" };
    format!(
        "PROXY {} {} {} {} {}\r\n",
        protocol, src_ip, dst_ip, src_port, dst_port
    )
}

/// Build PROXY protocol v2 header for IPv4
fn build_proxy_v2_header_ipv4(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut header = Vec::new();

    // Signature (12 bytes)
    header.extend_from_slice(&[
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ]);

    // Version (2) and command (PROXY = 1)
    header.push(0x21);

    // Family (AF_INET = 1) and protocol (STREAM = 1)
    header.push(0x11);

    // Address length: 4 + 4 + 2 + 2 = 12 bytes
    header.extend_from_slice(&12u16.to_be_bytes());

    // Source IP
    header.extend_from_slice(&src_ip);
    // Destination IP
    header.extend_from_slice(&dst_ip);
    // Source port
    header.extend_from_slice(&src_port.to_be_bytes());
    // Destination port
    header.extend_from_slice(&dst_port.to_be_bytes());

    header
}

/// Build PROXY protocol v2 header for IPv6
fn build_proxy_v2_header_ipv6(
    src_ip: [u8; 16],
    dst_ip: [u8; 16],
    src_port: u16,
    dst_port: u16,
) -> Vec<u8> {
    let mut header = Vec::new();

    // Signature (12 bytes)
    header.extend_from_slice(&[
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ]);

    // Version (2) and command (PROXY = 1)
    header.push(0x21);

    // Family (AF_INET6 = 2) and protocol (STREAM = 1)
    header.push(0x21);

    // Address length: 16 + 16 + 2 + 2 = 36 bytes
    header.extend_from_slice(&36u16.to_be_bytes());

    // Source IP
    header.extend_from_slice(&src_ip);
    // Destination IP
    header.extend_from_slice(&dst_ip);
    // Source port
    header.extend_from_slice(&src_port.to_be_bytes());
    // Destination port
    header.extend_from_slice(&dst_port.to_be_bytes());

    header
}

/// Collected session addresses from the server
#[derive(Clone, Default)]
struct CollectedAddresses {
    inner: Arc<Mutex<Vec<Multiaddr>>>,
}

impl CollectedAddresses {
    fn push(&self, addr: Multiaddr) {
        self.inner.lock().unwrap().push(addr);
    }

    fn get_all(&self) -> Vec<Multiaddr> {
        self.inner.lock().unwrap().clone()
    }
}

/// Service handle that collects session addresses
struct AddressCollectorHandle {
    collected: CollectedAddresses,
    sender: crossbeam_channel::Sender<()>,
}

#[async_trait]
impl ServiceHandle for AddressCollectorHandle {
    async fn handle_event(
        &mut self,
        _context: &mut tentacle::context::ServiceContext,
        event: ServiceEvent,
    ) {
        if let ServiceEvent::SessionOpen { session_context } = event {
            self.collected.push(session_context.address.clone());
            self.sender.try_send(()).unwrap();
        }
    }
}

/// Protocol handle for testing
struct TestProtocol;

#[async_trait]
impl ServiceProtocol for TestProtocol {
    async fn init(&mut self, _context: &mut ProtocolContext) {}
    async fn connected(&mut self, _context: ProtocolContextMutRef<'_>, _version: &str) {}
    async fn disconnected(&mut self, _context: ProtocolContextMutRef<'_>) {}
}

fn create_meta(id: ProtocolId) -> ProtocolMeta {
    MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            let handle = Box::new(TestProtocol);
            ProtocolHandle::Callback(handle)
        })
        .build()
}

fn create_service(
    collected: CollectedAddresses,
    sender: crossbeam_channel::Sender<()>,
) -> Service<AddressCollectorHandle, SecioKeyPair> {
    let meta = create_meta(1.into());
    ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(false)
        .build(AddressCollectorHandle { collected, sender })
}

/// Extract IP from multiaddr (e.g., "/ip4/192.168.1.100/tcp/12345" -> "192.168.1.100")
fn extract_ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
    use tentacle::multiaddr::Protocol;

    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => continue,
        }
    }
    None
}

/// Test PROXY protocol v1 with IPv4
#[test]
fn test_proxy_protocol_v1_ipv4() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip4(i) => ip = Some(IpAddr::V4(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect and send PROXY protocol v1 header
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut stream = TcpStream::connect(socket_addr).await.unwrap();

        // Send PROXY protocol v1 header with fake source IP
        let proxy_header = build_proxy_v1_header("203.0.113.50", "192.168.1.1", 54321, 80);
        stream.write_all(proxy_header.as_bytes()).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The first address should have the PROXY protocol source IP
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert_eq!(
        ip.unwrap().to_string(),
        "203.0.113.50",
        "Should use the IP from PROXY protocol header"
    );
}

/// Test PROXY protocol v2 with IPv4
#[test]
fn test_proxy_protocol_v2_ipv4() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip4(i) => ip = Some(IpAddr::V4(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect and send PROXY protocol v2 header
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut stream = TcpStream::connect(socket_addr).await.unwrap();

        // Send PROXY protocol v2 header with fake source IP 10.20.30.40
        let proxy_header = build_proxy_v2_header_ipv4(
            [10, 20, 30, 40], // Source IP
            [192, 168, 1, 1], // Destination IP
            12345,            // Source port
            80,               // Destination port
        );
        stream.write_all(&proxy_header).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The first address should have the PROXY protocol source IP
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert_eq!(
        ip.unwrap().to_string(),
        "10.20.30.40",
        "Should use the IP from PROXY protocol v2 header"
    );
}

/// Test PROXY protocol v1 with IPv6
#[test]
fn test_proxy_protocol_v1_ipv6() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            // Listen on IPv6 loopback
            let listen_addr = service
                .listen("/ip6/::1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip6(i) => ip = Some(IpAddr::V6(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect and send PROXY protocol v1 header with IPv6
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut stream = TcpStream::connect(socket_addr).await.unwrap();

        // Send PROXY protocol v1 header with IPv6 source
        let proxy_header = build_proxy_v1_header("2001:db8::1", "2001:db8::2", 54321, 80);
        stream.write_all(proxy_header.as_bytes()).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The first address should have the PROXY protocol source IP
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert_eq!(
        ip.unwrap().to_string(),
        "2001:db8::1",
        "Should use the IPv6 from PROXY protocol header"
    );
}

/// Test PROXY protocol v2 with IPv6
#[test]
fn test_proxy_protocol_v2_ipv6() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            // Listen on IPv6 loopback
            let listen_addr = service
                .listen("/ip6/::1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip6(i) => ip = Some(IpAddr::V6(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect and send PROXY protocol v2 header with IPv6
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut stream = TcpStream::connect(socket_addr).await.unwrap();

        // 2001:db8:85a3::8a2e:370:7334
        let src_ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ];
        // 2001:db8::1
        let dst_ip: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let proxy_header = build_proxy_v2_header_ipv6(src_ip, dst_ip, 12345, 80);
        stream.write_all(&proxy_header).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The first address should have the PROXY protocol source IP
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert_eq!(
        ip.unwrap().to_string(),
        "2001:db8:85a3::8a2e:370:7334",
        "Should use the IPv6 from PROXY protocol v2 header"
    );
}

/// Test that non-PROXY protocol connections still work (fallback to socket address)
#[test]
fn test_normal_connection_without_proxy_protocol() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip4(i) => ip = Some(IpAddr::V4(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect without PROXY protocol - send at least 16 bytes of non-PROXY data
    // The server requires at least 16 bytes before processing the connection
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut stream = TcpStream::connect(socket_addr).await.unwrap();

        // Send 16+ bytes of non-PROXY data
        // This data does NOT start with "PROXY" or the v2 signature
        // Simulates a normal protocol message (e.g., yamux/secio handshake)
        let non_proxy_data = [
            0x00, 0x01, 0x00, 0x01, // 4 bytes
            0x00, 0x00, 0x00, 0x01, // 4 bytes
            0x00, 0x00, 0x00, 0x01, // 4 bytes
            0x00, 0x00, 0x00, 0x01, // 4 bytes
            0x00, 0x00, 0x00, 0x01, // 4 bytes extra for safety
        ];
        stream.write_all(&non_proxy_data).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The address should be the local loopback since no PROXY protocol was used
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert_eq!(
        ip.unwrap().to_string(),
        "127.0.0.1",
        "Should use the socket address when no PROXY protocol is present"
    );
}

/// Build a WebSocket upgrade request with X-Forwarded-For header
#[cfg(feature = "ws")]
fn build_ws_upgrade_request_with_forwarded_for(host: &str, forwarded_ip: &str) -> String {
    // Use a fixed WebSocket key for testing (this is valid base64)
    let ws_key = "dGhlIHNhbXBsZSBub25jZQ==";

    format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         X-Forwarded-For: {}\r\n\
         \r\n",
        host, ws_key, forwarded_ip
    )
}

/// Build a WebSocket upgrade request with X-Forwarded-For and X-Forwarded-Port headers
#[cfg(feature = "ws")]
fn build_ws_upgrade_request_with_forwarded_for_and_port(
    host: &str,
    forwarded_ip: &str,
    forwarded_port: u16,
) -> String {
    let ws_key = "dGhlIHNhbXBsZSBub25jZQ==";

    format!(
        "GET / HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         X-Forwarded-For: {}\r\n\
         X-Forwarded-Port: {}\r\n\
         \r\n",
        host, ws_key, forwarded_ip, forwarded_port
    )
}

/// Test WebSocket connection with X-Forwarded-For header
#[cfg(feature = "ws")]
#[test]
fn test_ws_x_forwarded_for() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            // Listen on WebSocket address
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0/ws".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip4(i) => ip = Some(IpAddr::V4(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect and send WebSocket upgrade request with X-Forwarded-For
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut stream = TcpStream::connect(socket_addr).await.unwrap();

        // Send WebSocket upgrade request with X-Forwarded-For header
        let ws_request = build_ws_upgrade_request_with_forwarded_for(
            &format!("127.0.0.1:{}", socket_addr.port()),
            "198.51.100.178",
        );
        stream.write_all(ws_request.as_bytes()).await.unwrap();

        // Read the response (we need to complete the handshake)
        let mut response = vec![0u8; 1024];
        stream.read_buf(&mut response).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The address should have the X-Forwarded-For IP
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert_eq!(
        ip.unwrap().to_string(),
        "198.51.100.178",
        "Should use the IP from X-Forwarded-For header"
    );
}

/// Test WebSocket connection without X-Forwarded-For header (fallback)
#[cfg(feature = "ws")]
#[test]
fn test_ws_without_x_forwarded_for() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            // Listen on WebSocket address
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0/ws".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip4(i) => ip = Some(IpAddr::V4(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect with a WebSocket client without X-Forwarded-For
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        use tokio_tungstenite::connect_async;

        let ws_url = format!("ws://127.0.0.1:{}/", socket_addr.port());
        connect_async(&ws_url).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The address should be the local loopback since no X-Forwarded-For was sent
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert_eq!(
        ip.unwrap().to_string(),
        "127.0.0.1",
        "Should use the socket address when no X-Forwarded-For is present"
    );
}

/// Test WebSocket connection with multiple IPs in X-Forwarded-For (should use first)
#[cfg(feature = "ws")]
#[test]
fn test_ws_x_forwarded_for_multiple_ips() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            // Listen on WebSocket address
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0/ws".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip4(i) => ip = Some(IpAddr::V4(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect and send WebSocket upgrade request with multiple IPs in X-Forwarded-For
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut stream = TcpStream::connect(socket_addr).await.unwrap();

        // X-Forwarded-For with multiple IPs: client, proxy1, proxy2
        // Should use the first one (the original client)
        let ws_request = build_ws_upgrade_request_with_forwarded_for(
            &format!("127.0.0.1:{}", socket_addr.port()),
            "203.0.113.195, 70.41.3.18, 150.172.238.178",
        );
        stream.write_all(ws_request.as_bytes()).await.unwrap();

        // Read the response
        let mut response = vec![0u8; 1024];
        stream.read_buf(&mut response).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The address should have the first IP from X-Forwarded-For chain
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert_eq!(
        ip.unwrap().to_string(),
        "203.0.113.195",
        "Should use the first IP from X-Forwarded-For header chain"
    );
}

/// Test WebSocket connection with X-Forwarded-For header containing IPv6
#[cfg(feature = "ws")]
#[test]
fn test_ws_x_forwarded_for_ipv6() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            // Listen on WebSocket address (IPv4 loopback for simplicity)
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0/ws".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip4(i) => ip = Some(IpAddr::V4(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect and send WebSocket upgrade request with IPv6 in X-Forwarded-For
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut stream = TcpStream::connect(socket_addr).await.unwrap();

        // Send WebSocket upgrade request with IPv6 X-Forwarded-For header
        let ws_request = build_ws_upgrade_request_with_forwarded_for(
            &format!("127.0.0.1:{}", socket_addr.port()),
            "2001:db8:cafe::17",
        );
        stream.write_all(ws_request.as_bytes()).await.unwrap();

        // Read the response (we need to complete the handshake)
        let mut response = vec![0u8; 1024];
        stream.read_buf(&mut response).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The address should have the IPv6 from X-Forwarded-For
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert_eq!(
        ip.unwrap().to_string(),
        "2001:db8:cafe::17",
        "Should use the IPv6 from X-Forwarded-For header"
    );
}

/// Extract port from multiaddr
#[cfg(feature = "ws")]
fn extract_port_from_multiaddr(addr: &Multiaddr) -> Option<u16> {
    use tentacle::multiaddr::Protocol;

    for proto in addr.iter() {
        if let Protocol::Tcp(port) = proto {
            return Some(port);
        }
    }
    None
}

/// Test WebSocket connection with X-Forwarded-For and X-Forwarded-Port headers
#[cfg(feature = "ws")]
#[test]
fn test_ws_x_forwarded_for_with_port() {
    let collected = CollectedAddresses::default();
    let (sender, receiver) = crossbeam_channel::bounded(1);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    let collected_clone = collected.clone();
    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create_service(collected_clone, sender);
        rt.block_on(async move {
            let listen_addr = service
                .listen("/ip4/127.0.0.1/tcp/0/ws".parse().unwrap())
                .await
                .unwrap();
            addr_sender.send(listen_addr).unwrap();
            service.run().await
        });
    });

    // Wait for server to start and get listen address
    let listen_addr = futures::executor::block_on(addr_receiver).unwrap();
    let socket_addr: SocketAddr = {
        use tentacle::multiaddr::Protocol;
        let mut ip = None;
        let mut port = None;
        for proto in listen_addr.iter() {
            match proto {
                Protocol::Ip4(i) => ip = Some(IpAddr::V4(i)),
                Protocol::Tcp(p) => port = Some(p),
                _ => {}
            }
        }
        SocketAddr::new(ip.unwrap(), port.unwrap())
    };

    // Connect and send WebSocket upgrade request with X-Forwarded-For and X-Forwarded-Port
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let mut stream = TcpStream::connect(socket_addr).await.unwrap();

        // Send WebSocket upgrade request with both headers
        let ws_request = build_ws_upgrade_request_with_forwarded_for_and_port(
            &format!("127.0.0.1:{}", socket_addr.port()),
            "198.51.100.50",
            54321,
        );
        stream.write_all(ws_request.as_bytes()).await.unwrap();

        // Read the response
        let mut response = vec![0u8; 1024];
        stream.read_buf(&mut response).await.unwrap();

        // Keep connection open briefly
        tokio::time::sleep(Duration::from_millis(500)).await;
    });

    // Wait for session to be established
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    // Give server a moment to process
    thread::sleep(Duration::from_millis(100));

    // Check collected addresses
    let addresses = collected.get_all();
    assert!(
        !addresses.is_empty(),
        "Should have collected at least one address"
    );

    // The address should have both the IP and port from X-Forwarded headers
    let first_addr = &addresses[0];
    let ip = extract_ip_from_multiaddr(first_addr);
    let port = extract_port_from_multiaddr(first_addr);
    assert!(ip.is_some(), "Should be able to extract IP from address");
    assert!(
        port.is_some(),
        "Should be able to extract port from address"
    );
    assert_eq!(
        ip.unwrap().to_string(),
        "198.51.100.50",
        "Should use the IP from X-Forwarded-For header"
    );
    assert_eq!(
        port.unwrap(),
        54321,
        "Should use the port from X-Forwarded-Port header"
    );
}
