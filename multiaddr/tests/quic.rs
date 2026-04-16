use data_encoding::HEXUPPER;
use parity_multiaddr::{Multiaddr as OtherMultiaddr, Protocol as OtherProtocol};
use std::convert::TryFrom;
use tentacle_multiaddr::{Multiaddr, Protocol};

/// Helper: parse a multiaddr string, verify hex encoding roundtrip, protocol list, and Display roundtrip.
fn ma_valid(source: &str, target: &str, protocols: Vec<Protocol<'_>>) {
    let parsed = source.parse::<Multiaddr>().unwrap();
    assert_eq!(HEXUPPER.encode(&parsed.to_vec()[..]), target);
    assert_eq!(parsed.iter().collect::<Vec<_>>(), protocols);
    assert_eq!(parsed.to_string(), source);
    assert_eq!(
        Multiaddr::try_from(HEXUPPER.decode(target.as_bytes()).unwrap()).unwrap(),
        parsed
    );
}

// ────────────────────────── String parse → Display roundtrip ──────────────────────────

#[test]
fn parse_ip4_udp_quic() {
    let addr: Multiaddr = "/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap();
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/4433/quic-v1");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip4("127.0.0.1".parse().unwrap()),
            Protocol::Udp(4433),
            Protocol::QuicV1,
        ]
    );
}

#[test]
fn parse_ip6_udp_quic() {
    let addr: Multiaddr = "/ip6/::1/udp/4433/quic-v1".parse().unwrap();
    assert_eq!(addr.to_string(), "/ip6/::1/udp/4433/quic-v1");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip6("::1".parse().unwrap()),
            Protocol::Udp(4433),
            Protocol::QuicV1,
        ]
    );
}

#[test]
fn parse_udp_port_zero() {
    let addr: Multiaddr = "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap();
    assert_eq!(addr.to_string(), "/ip4/0.0.0.0/udp/0/quic-v1");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip4("0.0.0.0".parse().unwrap()),
            Protocol::Udp(0),
            Protocol::QuicV1,
        ]
    );
}

#[test]
fn parse_udp_port_max() {
    let addr: Multiaddr = "/ip4/10.0.0.1/udp/65535/quic-v1".parse().unwrap();
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip4("10.0.0.1".parse().unwrap()),
            Protocol::Udp(65535),
            Protocol::QuicV1,
        ]
    );
}

#[test]
fn parse_udp_alone() {
    // UDP without /quic-v1 is also a valid multiaddr
    let addr: Multiaddr = "/ip4/127.0.0.1/udp/1234".parse().unwrap();
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/1234");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Ip4("127.0.0.1".parse().unwrap()),
            Protocol::Udp(1234),
        ]
    );
}

#[test]
fn parse_quic_with_p2p_suffix() {
    // A realistic QUIC address with /p2p/<peer_id> suffix
    // Use a well-formed peer_id (sha256 multihash)
    let peer_id_b58 = "QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC";
    let source = format!("/ip4/192.168.1.1/udp/4433/quic-v1/p2p/{}", peer_id_b58);
    let addr: Multiaddr = source.parse().unwrap();
    assert_eq!(addr.to_string(), source);

    let protos: Vec<_> = addr.iter().collect();
    assert_eq!(protos.len(), 4);
    assert_eq!(protos[0], Protocol::Ip4("192.168.1.1".parse().unwrap()));
    assert_eq!(protos[1], Protocol::Udp(4433));
    assert_eq!(protos[2], Protocol::QuicV1);
    match &protos[3] {
        Protocol::P2P(_) => {} // ok
        other => panic!("expected P2P, got {:?}", other),
    }
}

// ────────────────────────── Binary (bytes) roundtrip ──────────────────────────

#[test]
fn bytes_roundtrip_ip4_udp_quic() {
    let addr: Multiaddr = "/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap();
    let bytes = addr.to_vec();
    let decoded = Multiaddr::try_from(bytes).unwrap();
    assert_eq!(decoded, addr);
}

#[test]
fn bytes_roundtrip_ip6_udp_quic() {
    let addr: Multiaddr = "/ip6/::1/udp/4433/quic-v1".parse().unwrap();
    let bytes = addr.to_vec();
    let decoded = Multiaddr::try_from(bytes).unwrap();
    assert_eq!(decoded, addr);
}

#[test]
fn bytes_roundtrip_udp_alone() {
    let addr: Multiaddr = "/ip4/10.0.0.1/udp/8080".parse().unwrap();
    let bytes = addr.to_vec();
    let decoded = Multiaddr::try_from(bytes).unwrap();
    assert_eq!(decoded, addr);
}

// ────────────────────────── Hex encoding roundtrip (ma_valid style) ──────────────────────────

#[test]
fn hex_roundtrip_ip4_udp_quic() {
    let addr: Multiaddr = "/ip4/127.0.0.1/udp/4433/quic-v1".parse().unwrap();
    let hex = HEXUPPER.encode(&addr.to_vec()[..]);

    ma_valid(
        "/ip4/127.0.0.1/udp/4433/quic-v1",
        &hex,
        vec![
            Protocol::Ip4("127.0.0.1".parse().unwrap()),
            Protocol::Udp(4433),
            Protocol::QuicV1,
        ],
    );
}

// ────────────────────────── Protocol push / pop ──────────────────────────

#[test]
fn push_pop_quic() {
    let mut addr: Multiaddr = "/ip4/127.0.0.1/udp/4433".parse().unwrap();
    addr.push(Protocol::QuicV1);
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/4433/quic-v1");

    let popped = addr.pop().unwrap();
    assert_eq!(popped, Protocol::QuicV1);
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/4433");
}

#[test]
fn push_pop_udp() {
    let mut addr: Multiaddr = "/ip4/127.0.0.1".parse().unwrap();
    addr.push(Protocol::Udp(9999));
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/9999");

    let popped = addr.pop().unwrap();
    assert_eq!(popped, Protocol::Udp(9999));
    assert_eq!(addr.to_string(), "/ip4/127.0.0.1");
}

// ────────────────────────── acquire() (owned conversion) ──────────────────────────

#[test]
fn acquire_udp_quic() {
    let addr: Multiaddr = "/ip4/10.0.0.1/udp/4433/quic-v1".parse().unwrap();
    let protos: Vec<Protocol<'static>> = addr.iter().map(|p| p.acquire()).collect();
    assert_eq!(protos.len(), 3);
    assert_eq!(protos[1], Protocol::Udp(4433));
    assert_eq!(protos[2], Protocol::QuicV1);
}

// ────────────────────────── DNS + QUIC (parseable at multiaddr layer) ──────────────────────────
// NOTE: DNS-based QUIC addresses are rejected by tentacle's transport layer (v1),
// but multiaddr itself should parse them fine — it's a generic address format.

#[test]
fn parse_dns4_udp_quic_is_valid_multiaddr() {
    let addr: Multiaddr = "/dns4/example.com/udp/4433/quic-v1".parse().unwrap();
    assert_eq!(addr.to_string(), "/dns4/example.com/udp/4433/quic-v1");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Dns4("example.com".into()),
            Protocol::Udp(4433),
            Protocol::QuicV1,
        ]
    );
}

#[test]
fn parse_dns6_udp_quic_is_valid_multiaddr() {
    let addr: Multiaddr = "/dns6/example.com/udp/4433/quic-v1".parse().unwrap();
    assert_eq!(addr.to_string(), "/dns6/example.com/udp/4433/quic-v1");
    assert_eq!(
        addr.iter().collect::<Vec<_>>(),
        vec![
            Protocol::Dns6("example.com".into()),
            Protocol::Udp(4433),
            Protocol::QuicV1,
        ]
    );
}

// ────────────────────────── Error cases ──────────────────────────

#[test]
fn fail_udp_missing_port() {
    // "/udp" without a port number
    assert!("/udp".parse::<Multiaddr>().is_err());
}

#[test]
fn fail_udp_non_numeric_port() {
    assert!("/udp/abc".parse::<Multiaddr>().is_err());
}

#[test]
fn fail_udp_port_overflow() {
    // 65536 > u16::MAX
    assert!("/ip4/127.0.0.1/udp/65536".parse::<Multiaddr>().is_err());
}

#[test]
fn fail_udp_negative_port() {
    assert!("/ip4/127.0.0.1/udp/-1".parse::<Multiaddr>().is_err());
}

#[test]
fn fail_unknown_protocol() {
    // Make sure adding udp/quic-v1 didn't break unknown protocol detection
    assert!("/ip4/127.0.0.1/foobar/123".parse::<Multiaddr>().is_err());
}

// ────────────────────────── Cross-crate compatibility (tentacle vs parity) ──────────────────────────

#[test]
fn compat_udp_parse_string() {
    // Both crates should parse the same /ip4/.../udp/... string identically
    let source = "/ip4/127.0.0.1/udp/4433";
    let addr_t: Multiaddr = source.parse().unwrap();
    let addr_p: OtherMultiaddr = source.parse().unwrap();

    assert_eq!(addr_t.to_string(), addr_p.to_string());
}

#[test]
fn compat_udp_binary_encoding() {
    // UDP wire encoding should be identical between tentacle and parity
    let source = "/ip4/127.0.0.1/udp/4433";
    let addr_t: Multiaddr = source.parse().unwrap();
    let addr_p: OtherMultiaddr = source.parse().unwrap();

    assert_eq!(addr_t.to_vec(), addr_p.to_vec());
}

#[test]
fn compat_udp_binary_cross_decode() {
    // Bytes produced by one crate should be decodable by the other
    let source = "/ip4/10.0.0.1/udp/8080";

    let addr_t: Multiaddr = source.parse().unwrap();
    let bytes_t = addr_t.to_vec();
    let decoded_p = OtherMultiaddr::try_from(bytes_t).unwrap();
    assert_eq!(decoded_p.to_string(), source);

    let addr_p: OtherMultiaddr = source.parse().unwrap();
    let bytes_p = addr_p.to_vec();
    let decoded_t = Multiaddr::try_from(bytes_p).unwrap();
    assert_eq!(decoded_t.to_string(), source);
}

#[test]
fn compat_udp_protocol_iter() {
    // Both crates should iterate to the same protocol components for UDP
    let source = "/ip4/192.168.1.1/udp/9999";
    let addr_t: Multiaddr = source.parse().unwrap();
    let addr_p: OtherMultiaddr = source.parse().unwrap();

    let protos_t: Vec<_> = addr_t.iter().collect();
    let protos_p: Vec<_> = addr_p.iter().collect();

    assert_eq!(protos_t.len(), protos_p.len());

    // Compare Ip4
    match (&protos_t[0], &protos_p[0]) {
        (Protocol::Ip4(a), OtherProtocol::Ip4(b)) => assert_eq!(a, b),
        e => panic!("expected Ip4, got {:?}", e),
    }

    // Compare Udp
    match (&protos_t[1], &protos_p[1]) {
        (Protocol::Udp(a), OtherProtocol::Udp(b)) => assert_eq!(a, b),
        e => panic!("expected Udp, got {:?}", e),
    }
}

#[test]
fn compat_udp_push_pop() {
    // Push UDP on both crates, verify same result, then pop and compare
    let base = "/ip4/127.0.0.1";
    let mut addr_t: Multiaddr = base.parse().unwrap();
    let mut addr_p: OtherMultiaddr = base.parse().unwrap();

    addr_t.push(Protocol::Udp(5555));
    addr_p.push(OtherProtocol::Udp(5555));

    assert_eq!(addr_t.to_string(), addr_p.to_string());
    assert_eq!(addr_t.to_vec(), addr_p.to_vec());

    let popped_t = addr_t.pop().unwrap();
    let popped_p = addr_p.pop().unwrap();

    match (popped_t, popped_p) {
        (Protocol::Udp(a), OtherProtocol::Udp(b)) => assert_eq!(a, b),
        e => panic!("expected Udp, got {:?}", e),
    }

    assert_eq!(addr_t.to_string(), addr_p.to_string());
}

#[test]
fn compat_udp_port_boundaries() {
    // Verify port 0 and port 65535 produce identical encodings
    for port in [0u16, 1, 1234, 65535] {
        let source = format!("/ip4/0.0.0.0/udp/{}", port);
        let addr_t: Multiaddr = source.parse().unwrap();
        let addr_p: OtherMultiaddr = source.parse().unwrap();

        assert_eq!(addr_t.to_string(), addr_p.to_string());
        assert_eq!(addr_t.to_vec(), addr_p.to_vec());
    }
}

#[test]
fn compat_ip6_udp_binary() {
    // IPv6 + UDP should also produce identical binary encodings
    let source = "/ip6/::1/udp/4433";
    let addr_t: Multiaddr = source.parse().unwrap();
    let addr_p: OtherMultiaddr = source.parse().unwrap();

    assert_eq!(addr_t.to_string(), addr_p.to_string());
    assert_eq!(addr_t.to_vec(), addr_p.to_vec());
}

#[test]
fn compat_ip6_udp_cross_decode() {
    let source = "/ip6/fe80::1/udp/8443";

    let addr_t: Multiaddr = source.parse().unwrap();
    let decoded_p = OtherMultiaddr::try_from(addr_t.to_vec()).unwrap();
    assert_eq!(decoded_p.to_string(), source);

    let addr_p: OtherMultiaddr = source.parse().unwrap();
    let decoded_t = Multiaddr::try_from(addr_p.to_vec()).unwrap();
    assert_eq!(decoded_t.to_string(), source);
}

#[test]
fn compat_quicv1_shared_prefix_binary() {
    // parity-multiaddr 0.11 does not have QuicV1 (only Quic, code 460),
    // while tentacle has QuicV1 (code 461). However, the /ip4/.../udp/...
    // prefix is shared and must produce identical binary encodings.
    let full_source = "/ip4/127.0.0.1/udp/4433/quic-v1";
    let prefix_source = "/ip4/127.0.0.1/udp/4433";

    let addr_t: Multiaddr = full_source.parse().unwrap();
    let addr_p: OtherMultiaddr = prefix_source.parse().unwrap();

    let bytes_t = addr_t.to_vec();
    let bytes_p = addr_p.to_vec();

    // The tentacle bytes should start with the same prefix as parity
    assert!(
        bytes_t.starts_with(&bytes_p),
        "tentacle quic-v1 address bytes should start with the same ip4+udp prefix as parity"
    );

    // The extra bytes after the prefix are the QuicV1 protocol code (varint 461 = 0x01cd)
    let quicv1_suffix = &bytes_t[bytes_p.len()..];
    assert!(
        !quicv1_suffix.is_empty(),
        "quic-v1 should add extra bytes beyond the udp prefix"
    );
}

#[test]
fn compat_quicv1_tentacle_bytes_not_decodable_by_parity() {
    // Since parity doesn't know QuicV1, decoding the full address should fail
    let source = "/ip4/127.0.0.1/udp/4433/quic-v1";
    let addr_t: Multiaddr = source.parse().unwrap();
    let bytes = addr_t.to_vec();

    // parity should fail to decode the full bytes (unknown protocol code 461)
    assert!(
        OtherMultiaddr::try_from(bytes).is_err(),
        "parity should not be able to decode quic-v1 (protocol code 461 is unknown to it)"
    );
}

#[test]
fn compat_quicv1_string_not_parseable_by_parity() {
    // parity doesn't recognize "quic-v1" as a protocol string
    assert!(
        "/ip4/127.0.0.1/udp/4433/quic-v1"
            .parse::<OtherMultiaddr>()
            .is_err(),
        "parity should not parse quic-v1 string"
    );
}

#[test]
fn compat_parity_quic_not_parseable_by_tentacle() {
    // Conversely, tentacle doesn't have the legacy Quic protocol (code 460)
    assert!(
        "/ip4/127.0.0.1/udp/4433/quic".parse::<Multiaddr>().is_err(),
        "tentacle should not parse legacy /quic string"
    );

    // Also verify binary: parity's /quic bytes should fail to decode in tentacle
    let addr_p: OtherMultiaddr = "/ip4/127.0.0.1/udp/4433/quic".parse().unwrap();
    let bytes = addr_p.to_vec();
    assert!(
        Multiaddr::try_from(bytes).is_err(),
        "tentacle should not decode parity's /quic binary (protocol code 460 is unknown to it)"
    );
}

#[test]
fn compat_udp_hex_roundtrip_cross_crate() {
    // Verify that hex-encoded bytes from one crate decode correctly in the other
    let source = "/ip4/10.0.0.1/udp/12345";
    let addr_t: Multiaddr = source.parse().unwrap();
    let hex = HEXUPPER.encode(&addr_t.to_vec());

    let bytes_from_hex = HEXUPPER.decode(hex.as_bytes()).unwrap();
    let decoded_p = OtherMultiaddr::try_from(bytes_from_hex).unwrap();
    assert_eq!(decoded_p.to_string(), source);
}

#[test]
fn compat_udp_with_p2p_suffix() {
    // Full address with UDP + P2P suffix should be identical between crates
    let source = "/ip4/47.111.169.36/udp/8111/p2p/QmNQ4jky6uVqLDrPU7snqxARuNGWNLgSrTnssbRuy3ij2W";

    let mut addr_t: Multiaddr = source.parse().unwrap();
    let mut addr_p: OtherMultiaddr = source.parse().unwrap();

    assert_eq!(addr_t.to_string(), addr_p.to_string());
    assert_eq!(addr_t.to_vec(), addr_p.to_vec());

    // Pop P2P and compare the inner bytes
    let p_t = addr_t.pop().unwrap();
    let p_p = addr_p.pop().unwrap();

    match (p_t, p_p) {
        (Protocol::P2P(s_1), OtherProtocol::P2p(s_2)) => assert_eq!(s_1.as_ref(), s_2.to_bytes()),
        e => panic!("expected P2P, got {:?}", e),
    }

    // After popping P2P, the remaining UDP part should match
    let u_t = addr_t.pop().unwrap();
    let u_p = addr_p.pop().unwrap();

    match (u_t, u_p) {
        (Protocol::Udp(a), OtherProtocol::Udp(b)) => assert_eq!(a, b),
        e => panic!("expected Udp, got {:?}", e),
    }
}
