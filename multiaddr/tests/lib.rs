use parity_multiaddr::{Multiaddr as OtherMultiaddr, Protocol as OtherProtocol};
use tentacle_multiaddr::{Multiaddr, Protocol};
mod onion;
mod quic;

#[test]
fn compatibility_test() {
    let mut address: Multiaddr = "/ip4/127.0.0.1".parse().unwrap();
    address.push(Protocol::Tcp(10000));
    assert_eq!(address, "/ip4/127.0.0.1/tcp/10000".parse().unwrap());

    let _address: Multiaddr = "/ip4/127.0.0.1/tcp/20/tls/main".parse().unwrap();

    let mut address_1: Multiaddr =
        "/ip4/47.111.169.36/tcp/8111/p2p/QmNQ4jky6uVqLDrPU7snqxARuNGWNLgSrTnssbRuy3ij2W"
            .parse()
            .unwrap();

    let mut address_2: OtherMultiaddr =
        "/ip4/47.111.169.36/tcp/8111/p2p/QmNQ4jky6uVqLDrPU7snqxARuNGWNLgSrTnssbRuy3ij2W"
            .parse()
            .unwrap();

    let p_1 = address_1.pop().unwrap();
    let p_2 = address_2.pop().unwrap();

    match (p_1, p_2) {
        (Protocol::P2P(s_1), OtherProtocol::P2p(s_2)) => assert_eq!(s_1, s_2.to_bytes()),
        e => panic!("not expect protocol: {:?}", e),
    }
}
