#![cfg(feature = "tls")]

use std::{fs, io::BufReader, sync::Arc};

use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::version::{TLS12, TLS13};
use tokio_rustls::rustls::{
    crypto::aws_lc_rs::default_provider,
    crypto::aws_lc_rs::ALL_CIPHER_SUITES,
    pki_types::{
        pem::PemObject, CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
    },
    ClientConfig, RootCertStore, ServerConfig, SupportedCipherSuite, SupportedProtocolVersion,
};

#[derive(Debug, Clone)]
pub struct NetConfig {
    server_cert_chain: Option<String>,
    server_key: Option<String>,

    ca_cert: Option<String>,

    protocols: Option<Vec<String>>,
    cypher_suits: Option<Vec<String>>,
}

impl NetConfig {
    pub fn example(node_dir: String) -> Self {
        Self {
            server_cert_chain: Some(node_dir.clone() + "server.crt"),
            server_key: Some(node_dir.clone() + "server.key"),
            ca_cert: Some(node_dir + "ca.crt"),

            protocols: None,
            cypher_suits: None,
        }
    }
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

fn load_certs(filename: &str) -> Vec<CertificateDer<'static>> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn load_private_key(filename: &str) -> PrivateKeyDer<'static> {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let mut rsa_keys = PrivatePkcs1KeyDer::pem_reader_iter(&mut reader);

    let rsa_keys_peek = rsa_keys.next();

    if let Some(rsa_keys_peek) = rsa_keys_peek {
        return PrivateKeyDer::Pkcs1(rsa_keys_peek.unwrap().clone_key());
    }

    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);
    let mut pkcs8_keys = PrivatePkcs8KeyDer::pem_reader_iter(&mut reader);
    let pkcs8_keys_peek = pkcs8_keys.next();

    assert!(pkcs8_keys_peek.is_some());
    PrivateKeyDer::Pkcs8(pkcs8_keys_peek.unwrap().unwrap().clone_key())
}

/// Build a `ServerConfig` from our NetConfig
pub fn make_server_config(config: &NetConfig) -> ServerConfig {
    let mut cryp = default_provider();

    if config.cypher_suits.is_some() {
        cryp.cipher_suites = lookup_suites(config.cypher_suits.as_ref().unwrap())
    };

    let server_config = ServerConfig::builder_with_provider(Arc::new(cryp));

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
        client_auth_roots.add(cacert.clone()).unwrap();
    }
    let client_auth = WebPkiClientVerifier::builder(client_auth_roots.into())
        .build()
        .unwrap();

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
    let mut cryp = default_provider();

    if config.cypher_suits.is_some() {
        cryp.cipher_suites = lookup_suites(config.cypher_suits.as_ref().unwrap());
    };

    let client_config = ClientConfig::builder_with_provider(Arc::new(cryp));

    let client_config = if config.protocols.is_some() {
        client_config
            .with_protocol_versions(lookup_versions(config.protocols.as_ref().unwrap()).as_slice())
            .unwrap()
    } else {
        client_config.with_safe_default_protocol_versions().unwrap()
    };

    let cafile = config.ca_cert.as_ref().unwrap();

    let mut client_root_cert_store = RootCertStore::empty();
    client_root_cert_store.add_parsable_certificates(load_certs(cafile));

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

        client_config.with_client_auth_cert(certs, privkey).unwrap()
    } else {
        client_config.with_no_client_auth()
    }
}
