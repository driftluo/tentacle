#![cfg(feature = "tls")]
use futures::channel;
use std::io::BufReader;
use std::str::FromStr;
use std::sync::Arc;
use std::{fs, thread};
use tentacle::{
    async_trait,
    builder::{MetaBuilder, ServiceBuilder},
    context::{ProtocolContext, ProtocolContextMutRef, ServiceContext},
    error::{DialerErrorKind, ListenErrorKind},
    multiaddr::Multiaddr,
    service::{
        ProtocolHandle, ProtocolMeta, Service, ServiceError, ServiceEvent, SessionType,
        TargetProtocol, TlsConfig,
    },
    traits::{ServiceHandle, ServiceProtocol},
    ProtocolId, SessionId,
};
use tokio_rustls::rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use tokio_rustls::rustls::{
    AllowAnyAuthenticatedClient, Certificate, ClientConfig, KeyLogFile, NoClientAuth, PrivateKey,
    ProtocolVersion, RootCertStore, ServerConfig, SupportedCipherSuite, ALL_CIPHERSUITES,
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

#[derive(Clone, Copy, Debug)]
enum ServiceErrorType {
    Dialer,
    Listen,
}

#[derive(Clone)]
pub struct SHandle {
    sender: crossbeam_channel::Sender<ServiceErrorType>,
    tls: bool,
    session_id: SessionId,
    kind: SessionType,
}

#[async_trait]
impl ServiceHandle for SHandle {
    async fn handle_error(&mut self, _env: &mut ServiceContext, error: ServiceError) {
        let error_type = match error {
            ServiceError::DialerError { error, .. } => {
                match error {
                    DialerErrorKind::HandshakeError(_) => (),
                    DialerErrorKind::RepeatedConnection(id) => assert_eq!(id, self.session_id),
                    err => panic!(
                        "test fail, expected DialerErrorKind::RepeatedConnection, got {:?}",
                        err
                    ),
                }
                ServiceErrorType::Dialer
            }
            ServiceError::ListenError { error, .. } => {
                match error {
                    ListenErrorKind::RepeatedConnection(id) => assert_eq!(id, self.session_id),
                    err => panic!(
                        "test fail, expected ListenErrorKind::RepeatedConnection, got {:?}",
                        err
                    ),
                }
                ServiceErrorType::Listen
            }
            e => panic!("test fail, error: {:?}", e),
        };

        let _res = self.sender.try_send(error_type);
    }

    async fn handle_event(&mut self, _env: &mut ServiceContext, event: ServiceEvent) {
        if let ServiceEvent::SessionOpen { session_context } = event {
            self.session_id = session_context.id;
            self.kind = session_context.ty;
        }
    }
}

struct PHandle {
    sender: crossbeam_channel::Sender<bytes::Bytes>,
}

#[async_trait]
impl ServiceProtocol for PHandle {
    async fn init(&mut self, _context: &mut ProtocolContext) {}

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, _version: &str) {
        context
            .send_message(bytes::Bytes::from("hello world"))
            .await
            .unwrap();
    }

    async fn received(&mut self, _context: ProtocolContextMutRef<'_>, data: bytes::Bytes) {
        self.sender.try_send(data).unwrap();
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

fn create_meta(id: ProtocolId) -> (ProtocolMeta, crossbeam_channel::Receiver<bytes::Bytes>) {
    // NOTE: channel size must large, otherwise send will failed.
    let (sender, receiver) = crossbeam_channel::unbounded();

    let meta = MetaBuilder::new()
        .id(id)
        .service_handle(move || {
            if id == 0.into() {
                ProtocolHandle::None
            } else {
                let handle = Box::new(PHandle { sender });
                ProtocolHandle::Callback(handle)
            }
        })
        .build();

    (meta, receiver)
}

fn create_shandle(
    tls: bool,
) -> (
    Box<dyn ServiceHandle + Send>,
    crossbeam_channel::Receiver<ServiceErrorType>,
) {
    // NOTE: channel size must large, otherwise send will failed.
    let (sender, receiver) = crossbeam_channel::unbounded();

    (
        Box::new(SHandle {
            sender,
            tls,
            session_id: 0.into(),
            kind: SessionType::Inbound,
        }),
        receiver,
    )
}

fn find_suite(name: &str) -> Option<&'static SupportedCipherSuite> {
    for suite in &ALL_CIPHERSUITES {
        let cs_name = format!("{:?}", suite.suite).to_lowercase();

        if cs_name == name.to_string().to_lowercase() {
            return Some(suite);
        }
    }

    None
}

fn lookup_suites(suites: &[String]) -> Vec<&'static SupportedCipherSuite> {
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
fn lookup_versions(versions: &[String]) -> Vec<ProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => ProtocolVersion::TLSv1_2,
            "1.3" => ProtocolVersion::TLSv1_3,
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
    certs(&mut reader).unwrap()
}

fn load_private_key(filename: &str) -> PrivateKey {
    let rsa_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        rsa_private_keys(&mut reader).expect("file contains invalid rsa private key")
    };

    let pkcs8_keys = {
        let keyfile = fs::File::open(filename).expect("cannot open private key file");
        let mut reader = BufReader::new(keyfile);
        pkcs8_private_keys(&mut reader)
            .expect("file contains invalid pkcs8 private key (encrypted keys not supported)")
    };

    // prefer to load pkcs8 keys
    if !pkcs8_keys.is_empty() {
        pkcs8_keys[0].clone()
    } else {
        assert!(!rsa_keys.is_empty());
        rsa_keys[0].clone()
    }
}

fn load_key_and_cert(config: &mut ClientConfig, keyfile: &str, certsfile: &str, cafile: &str) {
    let mut certs = load_certs(certsfile);
    let cacerts = load_certs(cafile);
    let privkey = load_private_key(keyfile);

    // Specially for server.crt not a cert-chain only one server certificate, so manually make
    // a cert-chain.
    if certs.len() == 1 && !cacerts.is_empty() {
        certs.extend(cacerts);
    }

    config
        .set_single_client_cert(certs, privkey)
        .expect("invalid certificate or private key");
}

/// Build a `ServerConfig` from our NetConfig
pub fn make_server_config(config: &NetConfig) -> ServerConfig {
    let cacerts = load_certs(config.ca_cert.as_ref().unwrap());

    // server could use `NoClientAuth` mod let client connect freely
    let client_auth = if config.ca_cert.is_some() {
        let mut client_auth_roots = RootCertStore::empty();
        for cacert in &cacerts {
            client_auth_roots.add(cacert).unwrap();
        }
        AllowAnyAuthenticatedClient::new(client_auth_roots)
    } else {
        NoClientAuth::new()
    };

    let mut server_config = ServerConfig::new(client_auth);
    server_config.key_log = Arc::new(KeyLogFile::new());

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

    server_config
        .set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .expect("bad certificates/private key");

    if config.cypher_suits.is_some() {
        server_config.ciphersuites = lookup_suites(
            &config
                .cypher_suits
                .as_ref()
                .expect("cypher_suits option error"),
        );
    }

    if config.protocols.is_some() {
        server_config.versions = lookup_versions(config.protocols.as_ref().unwrap());
        server_config.set_protocols(
            &config
                .protocols
                .as_ref()
                .unwrap()
                .iter()
                .map(|proto| proto.as_bytes().to_vec())
                .collect::<Vec<_>>()[..],
        );
    }

    server_config
}

/// Build a `ClientConfig` from our NetConfig
pub fn make_client_config(config: &NetConfig) -> ClientConfig {
    let mut client_config = ClientConfig::new();
    client_config.key_log = Arc::new(KeyLogFile::new());

    if config.cypher_suits.is_some() {
        client_config.ciphersuites = lookup_suites(config.cypher_suits.as_ref().unwrap());
    }

    if config.protocols.is_some() {
        client_config.versions = lookup_versions(config.protocols.as_ref().unwrap());

        client_config.set_protocols(
            &config
                .protocols
                .as_ref()
                .unwrap()
                .iter()
                .map(|proto| proto.as_bytes().to_vec())
                .collect::<Vec<_>>()[..],
        );
    }

    let cafile = config.ca_cert.as_ref().unwrap();

    let certfile = fs::File::open(cafile).expect("Cannot open CA file");
    let mut reader = BufReader::new(certfile);
    client_config.root_store.add_pem_file(&mut reader).unwrap();

    if config.server_key.is_some() || config.server_cert_chain.is_some() {
        load_key_and_cert(
            &mut client_config,
            config
                .server_key
                .as_ref()
                .expect("must provide client_key with client_cert"),
            config
                .server_cert_chain
                .as_ref()
                .expect("must provide client_cert with client_key"),
            cafile,
        );
    }

    client_config
}

fn test_tls_dial() {
    let (meta_1, receiver_1) = create_meta(1.into());
    let (meta_2, receiver_2) = create_meta(1.into());
    let (shandle, _error_receiver_1) = create_shandle(true);
    let (addr_sender, addr_receiver) = channel::oneshot::channel::<Multiaddr>();

    thread::spawn(move || {
        let multi_addr_1 = Multiaddr::from_str(
            "/dns4/127.0.0.1/tcp/0/tls/0x09cbaa785348dabd54c61f5f9964474f7bfad7df",
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(meta_1, shandle, "tests/certificates/node0/".to_string());
        rt.block_on(async move {
            let listen_addr = service.listen(multi_addr_1).await.unwrap();
            let _res = addr_sender.send(listen_addr);
            service.run().await
        });
    });

    let (shandle, _error_receiver_2) = create_shandle(true);

    thread::spawn(move || {
        let _multi_addr_2 = Multiaddr::from_str(
            "/ip4/127.0.0.1/tcp/0/tls/0x388f042dd011824b91ecda56c85eeec993894f88",
        )
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let mut service = create(meta_2, shandle, "tests/certificates/node1/".to_string());
        rt.block_on(async move {
            let listen_addr = addr_receiver.await.unwrap();
            service
                .dial(listen_addr, TargetProtocol::All)
                .await
                .unwrap();
            service.run().await
        });
    });

    assert_eq!(receiver_1.recv(), Ok(bytes::Bytes::from("hello world")));
    assert_eq!(receiver_2.recv(), Ok(bytes::Bytes::from("hello world")));
}

#[test]
fn test_tls_message_send() {
    test_tls_dial()
}
