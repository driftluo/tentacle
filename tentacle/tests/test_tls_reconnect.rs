#![cfg(feature = "tls")]
use crossbeam_channel::Receiver;
use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use std::io::BufReader;
use std::str::FromStr;
use std::time::Duration;
use std::{fs, thread};
use tentacle::bytes::Bytes;
use tentacle::service::ServiceControl;
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef},
    multiaddr::Multiaddr,
    service::{ProtocolHandle, ProtocolMeta, Service, TargetProtocol, TlsConfig},
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId,
};
use tokio_rustls::rustls::server::AllowAnyAuthenticatedClient;
use tokio_rustls::rustls::version::{TLS12, TLS13};
use tokio_rustls::rustls::{
    Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig, SupportedCipherSuite,
    SupportedProtocolVersion, ALL_CIPHER_SUITES,
};

pub fn create<F>(meta: ProtocolMeta, shandle: F, cert_path: String) -> Service<F>
where
    F: ServiceHandle + Unpin,
{
    let mut builder = ServiceBuilder::default()
        .insert_protocol(meta)
        .forever(true);

    let tls_config = TlsConfig::new(
        Some(make_server_config(&NetConfig::example(cert_path.clone()))),
        Some(make_client_config(&NetConfig::example(cert_path))),
    );
    builder = builder.tls_config(tls_config);

    builder.build(shandle)
}

struct PHandle {
    sender: crossbeam_channel::Sender<bytes::Bytes>,
    send: bool,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        if !self.send {
            context
                .send_message(bytes::Bytes::from("hello world"))
                .await
                .unwrap();
        }
    }

    async fn received(&mut self, _context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        if self.send {
            self.sender.try_send(data).unwrap();
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetConfig {
    server_cert_chain: Option<String>,
    server_key: Option<String>,

    ca_cert: Option<String>,

    protocols: Option<Vec<String>>,
    cypher_suits: Option<Vec<String>>,
}

impl NetConfig {
    fn example(node_dir: String) -> Self {
        Self {
            server_cert_chain: Some(node_dir.clone() + "server.crt"),
            server_key: Some(node_dir.clone() + "server.key"),
            ca_cert: Some(node_dir + "ca.crt"),

            protocols: None,
            cypher_suits: None,
        }
    }
}

fn create_meta(
    id: ProtocolId,
    send: bool,
) -> (ProtocolMeta, crossbeam_channel::Receiver<bytes::Bytes>) {
    // NOTE: channel size must large, otherwise send will failed.
    let (sender, receiver) = crossbeam_channel::unbounded();

    let meta = MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle { sender, send });
                ProtocolHandle::Callback(handle)
            }
        })
        .build();

    (meta, receiver)
}

fn create_shandle() -> Box<dyn ServiceHandle + Send> {
    // NOTE: channel size must large, otherwise send will failed.
    Box::new(())
}

fn find_suite(name: &str) -> Option<SupportedCipherSuite> {
    for suite in ALL_CIPHER_SUITES {
        let cs_name = format!("{:?}", suite.suite()).to_lowercase();

        if cs_name == name.to_string().to_lowercase() {
            return Some(*suite);
        }
    }

    None
}

fn lookup_suites(suites: &[String]) -> Vec<SupportedCipherSuite> {
    let mut out = Vec::new();

    for cs_name in suites {
        let scs = find_suite(cs_name);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up cipher suite '{}'", cs_name),
        }
    }

    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<&'static SupportedProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => &TLS12,
            "1.3" => &TLS13,
            _ => panic!(
                "cannot look up version '{}', valid are '1.2' and '1.3'",
                vname
            ),
        };
        out.push(version);
    }

    out
}

fn load_certs(filename: &str) -> Vec<Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let rsa_keys = rsa_private_keys(&mut reader).expect("file contains invalid rsa private key");

    if !rsa_keys.is_empty() {
        return PrivateKey(rsa_keys[0].clone());
    }

    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let pkcs8_keys =
        pkcs8_private_keys(&mut reader).expect("file contains invalid pkcs8 private key");

    assert!(!pkcs8_keys.is_empty());
    PrivateKey(pkcs8_keys[0].clone())
}

/// Build a `ServerConfig` from our NetConfig
pub fn make_server_config(config: &NetConfig) -> ServerConfig {
    let server_config = ServerConfig::builder();

    let server_config = if config.cypher_suits.is_some() {
        server_config.with_cipher_suites(&lookup_suites(config.cypher_suits.as_ref().unwrap()))
    } else {
        server_config.with_safe_default_cipher_suites()
    };

    let server_config = server_config.with_safe_default_kx_groups();

    let server_config = if config.protocols.is_some() {
        server_config
            .with_protocol_versions(lookup_versions(config.protocols.as_ref().unwrap()).as_slice())
            .unwrap()
    } else {
        server_config.with_safe_default_protocol_versions().unwrap()
    };

    let cacerts = load_certs(config.ca_cert.as_ref().unwrap());

    let mut client_auth_roots = RootCertStore::empty();
    for cacert in &cacerts {
        client_auth_roots.add(cacert).unwrap();
    }
    let client_auth = AllowAnyAuthenticatedClient::new(client_auth_roots);

    let server_config = server_config.with_client_cert_verifier(client_auth);

    let mut certs = load_certs(
        config
            .server_cert_chain
            .as_ref()
            .expect("server_cert_chain option missing"),
    );
    let privkey = load_private_key(
        config
            .server_key
            .as_ref()
            .expect("server_key option missing"),
    );

    // Specially for server.crt not a cert-chain only one server certificate, so manually make
    // a cert-chain.
    if certs.len() == 1 && !cacerts.is_empty() {
        certs.extend(cacerts);
    }

    server_config.with_single_cert(certs, privkey).unwrap()
}

/// Build a `ClientConfig` from our NetConfig
pub fn make_client_config(config: &NetConfig) -> ClientConfig {
    let client_config = ClientConfig::builder();

    let client_config = if config.cypher_suits.is_some() {
        client_config.with_cipher_suites(&lookup_suites(config.cypher_suits.as_ref().unwrap()))
    } else {
        client_config.with_safe_default_cipher_suites()
    };

    let client_config = client_config.with_safe_default_kx_groups();

    let client_config = if config.protocols.is_some() {
        client_config
            .with_protocol_versions(lookup_versions(config.protocols.as_ref().unwrap()).as_slice())
            .unwrap()
    } else {
        client_config.with_safe_default_protocol_versions().unwrap()
    };

    let cafile = config.ca_cert.as_ref().unwrap();

    let certfile = fs::File::open(cafile).expect("Cannot open CA file");
    let mut reader = BufReader::new(certfile);

    let mut client_root_cert_store = RootCertStore::empty();
    client_root_cert_store.add_parsable_certificates(&certs(&mut reader).unwrap());

    let client_config = client_config.with_root_certificates(client_root_cert_store);

    if config.server_key.is_some() || config.server_cert_chain.is_some() {
        let certsfile = config
            .server_cert_chain
            .as_ref()
            .expect("must provide client_cert with client_key");

        let keyfile = config
            .server_key
            .as_ref()
            .expect("must provide client_key with client_cert");

        let mut certs = load_certs(certsfile);
        let cacerts = load_certs(cafile);
        let privkey = load_private_key(keyfile);

        // Specially for server.crt not a cert-chain only one server certificate, so manually make
        // a cert-chain.
        if certs.len() == 1 && !cacerts.is_empty() {
            certs.extend(cacerts);
        }

        client_config.with_single_cert(certs, privkey).unwrap()
    } else {
        client_config.with_no_client_auth()
    }
}

fn server_node(path: String, listen_address: Multiaddr) -> (Receiver<Bytes>, Multiaddr) {
    let (meta, receiver) = create_meta(1.into(), true);
    let shandle = create_shandle();
    let (addr_sender, addr_receiver) = crossbeam_channel::unbounded();

    thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(meta, shandle, path);
        rt.block_on(async move {
            let listen_addr = service.listen(listen_address).await.unwrap();
            let _res = addr_sender.send(listen_addr);
            service.run().await
        });
    });

    (receiver, addr_receiver.recv().unwrap())
}

fn clint_node_connect(path: String, dial_address: Multiaddr) {
    let (meta, _) = create_meta(1.into(), false);
    let shandle = create_shandle();

    let mut service = create(meta, shandle, path);
    let control: ServiceControl = service.control().clone().into();
    let handle = thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let _ = service.dial(dial_address, TargetProtocol::All).await;
            service.run().await
        });
    });
    thread::sleep(Duration::from_secs(3));

    let _ignore = control.shutdown();
    handle.join().expect("test fail");
}

#[test]
// only node1 connect node0
fn test_tls_reconnect_ok() {
    let (receiver, dail_addr) = server_node(
        "tests/certificates/node0/".to_string(),
        Multiaddr::from_str("/ip4/127.0.0.1/tcp/0/tls/0x09cbaa785348dabd54c61f5f9964474f7bfad7df")
            .unwrap(),
    );

    for _ in 0..2 {
        clint_node_connect("tests/certificates/node1/".to_string(), dail_addr.clone());
        assert_eq!(receiver.recv(), Ok(bytes::Bytes::from("hello world")));
    }
}

#[test]
// node1 and node2-wrong connect node1
fn test_tls_reconnect_wrong() {
    let (receiver, dail_addr) = server_node(
        "tests/certificates/node0/".to_string(),
        Multiaddr::from_str("/ip4/127.0.0.1/tcp/0/tls/0x09cbaa785348dabd54c61f5f9964474f7bfad7df")
            .unwrap(),
    );

    // the first round everything is ok, but the second round node1 can't connect node0, and the
    // test blocked
    for _ in 0..2 {
        clint_node_connect("tests/certificates/node1/".to_string(), dail_addr.clone());
        // due to error certificates the node2 would connect error
        clint_node_connect(
            "tests/certificates/node2-wrong/".to_string(),
            dail_addr.clone(),
        );
        assert_eq!(receiver.recv(), Ok(bytes::Bytes::from("hello world")));
    }
}
