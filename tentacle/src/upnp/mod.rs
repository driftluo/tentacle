use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{Duration, Instant},
};

use log::debug;

use crate::{
    multiaddr::Multiaddr,
    utils::{is_reachable, multiaddr_to_socketaddr},
};

#[cfg(not(windows))]
use self::unix::get_local_net_state;
#[cfg(windows)]
use self::windows::get_local_net_state;
use std::collections::HashMap;

#[cfg(not(windows))]
mod unix;
#[cfg(windows)]
mod windows;

#[derive(Copy, Clone, Debug)]
pub struct Network {
    /// local address
    address: Ipv4Addr,
    /// subnet mask
    net_mask: Ipv4Addr,
}

pub struct IgdClient {
    gateway: igd::Gateway,
    state: Network,
    only_leases_support: bool,
    succeeded: HashSet<SocketAddr>,
    leases: HashMap<SocketAddr, Option<Instant>>,
}

impl IgdClient {
    /// init
    pub fn new() -> Option<Self> {
        let gateway = match igd::search_gateway(Default::default()) {
            Err(err) => {
                debug!("get gateway error: {:?}", err);
                return None;
            }
            Ok(gateway) => {
                // if gateway address is public, don't need upnp, disable it
                if is_reachable((*gateway.addr.ip()).into()) {
                    return None;
                }

                match gateway.get_external_ip() {
                    Ok(ip) => {
                        if is_reachable(ip.into()) {
                            gateway
                        } else {
                            // if route external ip is not public,
                            // upnp cannot traverse a multi-layer NAT network,
                            // just disable it
                            return None;
                        }
                    }
                    Err(err) => {
                        debug!("get external ip error: {:?}", err);
                        return None;
                    }
                }
            }
        };

        let state = get_local_net_state().ok().and_then(|networks| {
            networks.into_iter().find(|network| {
                in_same_subnet(network.address, *gateway.addr.ip(), network.net_mask)
            })
        })?;

        Some(IgdClient {
            gateway,
            state,
            only_leases_support: false,
            succeeded: HashSet::default(),
            leases: HashMap::default(),
        })
    }

    /// Register ip
    pub fn register(&mut self, address: &Multiaddr) {
        if let Some(addr) = multiaddr_to_socketaddr(address) {
            // filter duplication
            if self.succeeded.contains(&addr) || self.leases.contains_key(&addr) {
                return;
            }

            if addr.ip().is_loopback() || addr.ip().is_multicast() {
                return;
            }

            if self.only_leases_support {
                self.leases.insert(addr, None);
                self.process_only_leases_support();
            } else {
                // Try to register permanently
                match self.gateway.add_port(
                    igd::PortMappingProtocol::TCP,
                    addr.port(),
                    SocketAddrV4::new(self.state.address, addr.port()),
                    0, // forever
                    "p2p",
                ) {
                    Err(err) => match err {
                        igd::AddPortError::OnlyPermanentLeasesSupported => {
                            self.leases.insert(addr, None);
                            self.process_only_leases_support();
                            self.only_leases_support = true;
                        }
                        err => debug!("register upnp error: {:?}", err),
                    },
                    Ok(_) => {
                        self.succeeded.insert(addr);
                    }
                }
            }
        }
    }

    /// Remove ip
    pub fn remove(&mut self, address: &Multiaddr) {
        if let Some(addr) = multiaddr_to_socketaddr(address) {
            if self.succeeded.remove(&addr) || self.leases.remove(&addr).is_some() {
                // don't care about it
                let _ignore = self
                    .gateway
                    .remove_port(igd::PortMappingProtocol::TCP, addr.port());
            }
        }
    }

    /// Register for 60 seconds
    pub fn process_only_leases_support(&mut self) {
        for (addr, interval) in self.leases.iter_mut() {
            let register = interval
                .map(|inner| {
                    Instant::now().saturating_duration_since(inner) > Duration::from_secs(40)
                })
                .unwrap_or(true);

            if register {
                // don't care about it
                let _ignore = self.gateway.add_port(
                    igd::PortMappingProtocol::TCP,
                    addr.port(),
                    SocketAddrV4::new(self.state.address, addr.port()),
                    60, // 60s
                    "p2p",
                );
                *interval = Some(Instant::now())
            }
        }
    }

    /// Clear all registered port
    pub fn clear(&mut self) {
        for addr in self
            .succeeded
            .drain()
            .chain(self.leases.drain().map(|item| item.0))
        {
            // don't care about it
            let _ignore = self
                .gateway
                .remove_port(igd::PortMappingProtocol::TCP, addr.port());
        }
    }
}

impl Drop for IgdClient {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Return `true` if two addresses are in the same subnet
fn in_same_subnet(addr1: Ipv4Addr, addr2: Ipv4Addr, subnet_mask: Ipv4Addr) -> bool {
    addr1
        .octets()
        .iter()
        .zip(subnet_mask.octets().iter())
        .map(|(o1, o2)| o1 & o2)
        .eq(addr2
            .octets()
            .iter()
            .zip(subnet_mask.octets().iter())
            .map(|(o1, o2)| o1 & o2))
}

#[cfg(test)]
mod test {
    use super::in_same_subnet;

    #[test]
    fn test_is_same_subnet() {
        // valid test
        vec![
            ("202.194.128.9", "202.194.128.14", "255.255.255.0"),
            ("220.230.1.1", "220.255.230.1", "255.192.0.0"),
            ("100.0.0.1", "100.0.0.100", "255.255.255.128"),
            ("100.200.2.100", "100.200.14.230", "255.255.240.0"),
            ("10.50.100.100", "10.50.200.70", "255.255.0.0"),
        ]
        .into_iter()
        .map(|(a, b, c)| (a.parse().unwrap(), b.parse().unwrap(), c.parse().unwrap()))
        .for_each(|(a, b, c)| assert!(in_same_subnet(a, b, c)));

        // invalid test
        vec![
            ("202.194.128.9", "202.193.128.14", "255.255.255.0"),
            ("220.230.1.1", "220.0.230.1", "255.192.0.0"),
            ("100.0.0.1", "100.200.0.100", "255.255.255.128"),
            ("100.200.2.100", "100.100.14.230", "255.255.240.0"),
            ("10.50.100.100", "10.0.0.70", "255.255.0.0"),
        ]
        .into_iter()
        .map(|(a, b, c)| (a.parse().unwrap(), b.parse().unwrap(), c.parse().unwrap()))
        .for_each(|(a, b, c)| assert!(!in_same_subnet(a, b, c)));
    }
}
