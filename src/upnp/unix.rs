use std::net::Ipv4Addr;
use std::{ffi, io, ptr};

use libc::{freeifaddrs, getifaddrs, ifaddrs, sockaddr, AF_INET};

use crate::upnp::Network;

/// Get machine local network status
pub fn get_local_net_state() -> io::Result<Vec<Network>> {
    let mut p_ifa: *mut ifaddrs = ptr::null_mut();
    if unsafe { getifaddrs(&mut p_ifa) } != 0 {
        return Err(io::Error::new(io::ErrorKind::Other, "getifaddrs() failed"));
    }

    // free it when leave this function
    let top_ptr = p_ifa;

    let mut result = Vec::new();

    while !p_ifa.is_null() {
        let ifa = unsafe { *p_ifa };
        let name = unsafe { ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy() };
        // Filter docker virtual NIC and lo
        if name.starts_with("docker") || name.starts_with("lo") {
            p_ifa = unsafe { (*p_ifa).ifa_next };
            continue;
        }
        if let Some(address) = parse_addr(ifa.ifa_addr) {
            result.push(Network {
                address,
                net_mask: parse_addr(ifa.ifa_netmask).expect("Invalid subnet mask"),
            });
        }

        p_ifa = unsafe { (*p_ifa).ifa_next };
    }

    unsafe { freeifaddrs(top_ptr) };
    Ok(result)
}

/// parse ptr to std struct
fn parse_addr(p_sock: *const sockaddr) -> Option<Ipv4Addr> {
    if p_sock.is_null() {
        return None;
    }
    let addr = unsafe { *p_sock };
    // Why ignore ipv6?
    // Because igd does not support ipv6
    match i32::from(addr.sa_family) {
        AF_INET => Some(Ipv4Addr::new(
            addr.sa_data[2] as u8,
            addr.sa_data[3] as u8,
            addr.sa_data[4] as u8,
            addr.sa_data[5] as u8,
        )),
        _ => None,
    }
}
