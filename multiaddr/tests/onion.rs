use data_encoding::HEXUPPER;
use std::convert::TryFrom;
use tentacle_multiaddr::*;

fn ma_valid(source: &str, target: &str, protocols: Vec<Protocol<'_>>) {
    let parsed = source.parse::<Multiaddr>().unwrap();
    assert_eq!(HEXUPPER.encode(&parsed.to_vec()[..]), target);
    assert_eq!(parsed.iter().collect::<Vec<_>>(), protocols);
    assert_eq!(source.parse::<Multiaddr>().unwrap().to_string(), source);
    assert_eq!(
        Multiaddr::try_from(HEXUPPER.decode(target.as_bytes()).unwrap()).unwrap(),
        parsed
    );
}

#[test]
fn construct_success() {
    use Protocol::*;

    ma_valid(
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:1234",
        "BD03ADADEC040BE047F9658668B11A504F3155001F231A37F54C4476C07FB4CC139ED7E30304D2",
        vec![Onion3(
            (
                [
                    173, 173, 236, 4, 11, 224, 71, 249, 101, 134, 104, 177, 26, 80, 79, 49, 85, 0,
                    31, 35, 26, 55, 245, 76, 68, 118, 192, 127, 180, 204, 19, 158, 215, 227, 3,
                ],
                1234,
            )
                .into(),
        )],
    );
}

#[test]
fn construct_fail() {
    let addresses = [
        "/onion3/9ww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:80",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd7:80",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:0",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd:-1",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd",
        "/onion3/vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyy@:666",
    ];

    for address in &addresses {
        assert!(
            address.parse::<Multiaddr>().is_err(),
            "{}",
            address.to_string()
        );
    }
}
