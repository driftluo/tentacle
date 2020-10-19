/// I have tested this mod on win10, and other windows platforms are theoretically no problem.
///
/// To write this code, I looked at the code that includes the crates like
/// `ipconfig`/`systemstat`/`get_if_addr` and flipped through the documentation for mdns.
///
use std::{io, net::Ipv4Addr, ptr, slice::from_raw_parts};

use winapi::ctypes::*;
use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{DWORD, LPVOID, ULONG},
        winerror::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        ws2def::{AF_INET, SOCKADDR},
    },
    um::heapapi::{GetProcessHeap, HeapAlloc, HeapFree},
};

use crate::upnp::Network;

const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;
const WORKING_BUFFER_SIZEL: SIZE_T = 15000;

#[repr(C)]
struct LengthIfIndex {
    length: ULONG,
    ifindex: DWORD,
}

#[repr(C)]
struct LengthFlags {
    length: ULONG,
    flags: DWORD,
}

#[repr(C)]
struct SoketAddress {
    lp_sockaddr: *mut SOCKADDR,
    i_sockaddr_length: c_int,
}

#[repr(C)]
struct IpAdapterPrefix {
    aol: LengthIfIndex,
    next: *mut IpAdapterPrefix,
    address: SoketAddress,
    prefix_length: ULONG,
}

#[repr(C)]
struct IpAdapterUnicastAddress {
    aol: LengthFlags,
    next: *mut IpAdapterUnicastAddress,
    address: SoketAddress,
    prefix_origin: c_int,
    suffix_origin: c_int,
    dad_state: c_int,
    valid_lifetime: ULONG,
    preferred_lifetime: ULONG,
    lease_lifetime: ULONG,
    on_link_prefix_length: __uint8,
}

#[repr(C)]
struct IpAdapterAddresses {
    aol: LengthIfIndex,
    next: *mut IpAdapterAddresses,
    adapter_name: *mut c_char,
    first_unicass_address: *mut IpAdapterUnicastAddress,
    first_anycass_address: *const c_void,
    first_multicass_address: *const c_void,
    first_dns_server_address: *const c_void,
    dns_suffix: *mut wchar_t,
    description: *mut wchar_t,
    friendly_name: *mut wchar_t,
    physical_address: [u8; MAX_ADAPTER_ADDRESS_LENGTH],
    physical_address_length: DWORD,
    flags: DWORD,
    mtu: DWORD,
    if_type: DWORD,
    oper_status: c_int,
    ipv6_if_index: DWORD,
    zone_indices: [DWORD; 16],
    first_prefix: *mut IpAdapterPrefix,
}

// https://msdn.microsoft.com/en-us/library/aa365915(v=vs.85).aspx
// https://msdn.microsoft.com/zh-cn/library/windows/desktop/aa366066(d=printer,v=vs.85).aspx
// https://docs.microsoft.com/zh-cn/windows/desktop/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
// C:\Program Files (x86)\Windows Kits\10\Include\um\iphlpApi.h
#[link(name = "iphlpapi")]
extern "system" {
    fn GetAdaptersAddresses(
        family: ULONG,
        flags: ULONG,
        reserved: *const c_void,
        addresses: *mut IpAdapterAddresses,
        size: *mut ULONG,
    ) -> ULONG;
}

pub fn get_local_net_state() -> io::Result<Vec<Network>> {
    let mut new_size: ULONG = WORKING_BUFFER_SIZEL as ULONG;
    // free it when leave this function
    let mut p_adapter: *mut IpAdapterAddresses;

    loop {
        unsafe {
            // https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
            p_adapter =
                HeapAlloc(GetProcessHeap(), 0, WORKING_BUFFER_SIZEL) as *mut IpAdapterAddresses;
            if p_adapter.is_null() {
                return Err(io::Error::new(io::ErrorKind::Other, "Failed: malloc!"));
            }
            let res_code = GetAdaptersAddresses(
                2,               // ipv4
                0x0002 as ULONG, // ipv4
                ptr::null(),
                p_adapter,
                &mut new_size as *mut ULONG,
            );
            match res_code {
                // 0
                ERROR_SUCCESS => break,
                // 111, retry
                ERROR_BUFFER_OVERFLOW => {
                    new_size *= 2;
                    let res = HeapFree(GetProcessHeap(), 0, p_adapter as LPVOID);
                    if res == 0 {
                        return Err(io::Error::new(io::ErrorKind::Other, "Failed: HeapFree!"));
                    }
                    continue;
                }
                _ => {
                    return Err(io::Error::last_os_error());
                }
            }
        }
    }

    let mut result = Vec::new();
    unsafe {
        let mut cur_p_adapter = p_adapter;
        while !cur_p_adapter.is_null() {
            let friendly_name = u16_array_to_string((*cur_p_adapter).friendly_name).to_lowercase();
            // Filter docker virtual NIC and lo
            if friendly_name.starts_with("loopback") || friendly_name.starts_with("docker") {
                cur_p_adapter = (*cur_p_adapter).next;
                continue;
            }

            // ip
            let mut cur_p_addr = (*cur_p_adapter).first_unicass_address;
            while !cur_p_addr.is_null() {
                if let Some(address) = parse_addr((*cur_p_addr).address.lp_sockaddr) {
                    result.push(Network {
                        address,
                        net_mask: netmask_v4((*cur_p_addr).on_link_prefix_length)
                            .expect("Invalid subnet mask"),
                    });
                }

                // next addr
                cur_p_addr = (*cur_p_addr).next;
            }

            // next adapter
            cur_p_adapter = (*cur_p_adapter).next;
        }
    }

    unsafe {
        // https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree#return-value
        let res = HeapFree(GetProcessHeap(), 0, p_adapter as LPVOID);
        if res == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "Failed: HeapFree!"));
        }
    }
    Ok(result)
}

fn parse_addr(p_sock: *const SOCKADDR) -> Option<Ipv4Addr> {
    if p_sock.is_null() {
        return None;
    }
    let addr = unsafe { *p_sock };
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

fn u16_array_to_string(p_array: *const u16) -> String {
    use std::char::{decode_utf16, REPLACEMENT_CHARACTER};
    unsafe {
        if p_array.is_null() {
            return String::new();
        }
        let mut cur = 0usize;
        while !p_array.add(cur).is_null() && *p_array.add(cur) != 0u16 {
            cur += 1;
        }
        let u16s = from_raw_parts(p_array, cur);
        decode_utf16(u16s.iter().cloned())
            .map(|r| r.unwrap_or(REPLACEMENT_CHARACTER))
            .collect::<String>()
    }
}

fn netmask_v4(bits: u8) -> Option<Ipv4Addr> {
    if bits <= 32 {
        let mut i = (0..4u8).map(|idx| {
            let idx8 = idx << 3;
            match (bits > idx8, bits > idx8 + 8) {
                (true, true) => 255,
                (true, false) => 255u8.wrapping_shl(u32::from(8 - bits % 8)),
                _ => 0,
            }
        });

        Some(Ipv4Addr::new(
            i.next().unwrap(),
            i.next().unwrap(),
            i.next().unwrap(),
            i.next().unwrap(),
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::{netmask_v4, Ipv4Addr};

    #[test]
    fn netmask_v4_test() {
        vec![
            (0, "0.0.0.0"),
            (1, "128.0.0.0"),
            (2, "192.0.0.0"),
            (3, "224.0.0.0"),
            (4, "240.0.0.0"),
            (5, "248.0.0.0"),
            (6, "252.0.0.0"),
            (7, "254.0.0.0"),
            (8, "255.0.0.0"),
            (9, "255.128.0.0"),
            (10, "255.192.0.0"),
            (11, "255.224.0.0"),
            (12, "255.240.0.0"),
            (13, "255.248.0.0"),
            (14, "255.252.0.0"),
            (15, "255.254.0.0"),
            (16, "255.255.0.0"),
            (17, "255.255.128.0"),
            (18, "255.255.192.0"),
            (19, "255.255.224.0"),
            (20, "255.255.240.0"),
            (21, "255.255.248.0"),
            (22, "255.255.252.0"),
            (23, "255.255.254.0"),
            (24, "255.255.255.0"),
            (25, "255.255.255.128"),
            (26, "255.255.255.192"),
            (27, "255.255.255.224"),
            (28, "255.255.255.240"),
            (29, "255.255.255.248"),
            (30, "255.255.255.252"),
            (31, "255.255.255.254"),
            (32, "255.255.255.255"),
        ]
        .into_iter()
        .for_each(|(i, addr)| assert_eq!(netmask_v4(i), addr.parse::<Ipv4Addr>().ok()))
    }
}
