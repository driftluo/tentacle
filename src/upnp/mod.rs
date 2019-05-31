use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
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

pub struct IGDClient {
    gateway: igd::Gateway,
    state: Network,
    only_leases_support: bool,
    successed: HashSet<SocketAddr>,
    leases: HashSet<SocketAddr>,
}

impl IGDClient {
    /// init
    pub fn new() -> Option<Self> {
        let gateway = match igd::search_gateway(Default::default()) {
            Err(err) => {
                debug!("get gateway error: {:?}", err);
                return None;
            }
            Ok(gateway) => match gateway.get_external_ip() {
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
            },
        };

        // if gateway address is public, don't need upnp, disable it
        if is_reachable((*gateway.addr.ip()).into()) {
            return None;
        }

        let state = get_local_net_state().ok().and_then(|networks| {
            networks.into_iter().find(|network| {
                in_same_subnet(network.address, *gateway.addr.ip(), network.net_mask)
            })
        })?;

        Some(IGDClient {
            gateway,
            state,
            only_leases_support: false,
            successed: HashSet::default(),
            leases: HashSet::default(),
        })
    }

    /// Register ip
    pub fn register(&mut self, address: &Multiaddr) {
        if let Some(addr) = multiaddr_to_socketaddr(address) {
            // filter duplication
            if self.successed.contains(&addr) || self.leases.contains(&addr) {
                return;
            }

            if addr.ip().is_loopback() || addr.ip().is_multicast() {
                return;
            }

            if self.only_leases_support {
                self.leases.insert(addr);
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
                            self.leases.insert(addr);
                            self.only_leases_support = true;
                        }
                        err => debug!("register upnp error: {:?}", err),
                    },
                    Ok(_) => {
                        self.successed.insert(addr);
                    }
                }
            }
        }
    }

    /// Remove ip
    pub fn remove(&mut self, address: &Multiaddr) {
        if let Some(addr) = multiaddr_to_socketaddr(address) {
            if self.successed.remove(&addr) {
                let _ = self
                    .gateway
                    .remove_port(igd::PortMappingProtocol::TCP, addr.port());
            }
        }
    }

    /// Register for 60 seconds
    pub fn process_only_leases_support(&mut self) {
        for addr in self.leases.iter() {
            let _ = self.gateway.add_port(
                igd::PortMappingProtocol::TCP,
                addr.port(),
                SocketAddrV4::new(self.state.address, addr.port()),
                60, // 60s
                "p2p",
            );
        }
    }

    /// Clear all registered port
    pub fn clear(&mut self) {
        for addr in self.successed.drain().chain(self.leases.drain()) {
            let _ = self
                .gateway
                .remove_port(igd::PortMappingProtocol::TCP, addr.port());
        }
    }
}

impl Drop for IGDClient {
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
