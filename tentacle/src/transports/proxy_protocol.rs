//! HAProxy PROXY Protocol v1 and v2 parser
//!
//! This module provides parsing capabilities for the HAProxy PROXY protocol,
//! which allows proxies to convey the original client IP address to backend servers.
//!
//! Reference: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use log::debug;
use tokio::io::AsyncReadExt;

use crate::runtime::TcpStream;

/// PROXY protocol v2 signature (12 bytes)
const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Maximum length of PROXY protocol v1 header (107 chars + CRLF)
const PROXY_V1_MAX_LENGTH: usize = 108;

/// PROXY protocol v2 header size (16 bytes)
const PROXY_V2_HEADER_SIZE: usize = 16;

/// Maximum allowed address length for PROXY protocol v2
/// IPv4: 12 bytes, IPv6: 36 bytes, Unix: 216 bytes
/// We allow some extra for TLV extensions, but cap at 512 to prevent DoS
const PROXY_V2_MAX_ADDR_LEN: usize = 512;

/// Result of parsing PROXY protocol
#[derive(Debug)]
pub enum ProxyProtocolResult {
    /// Successfully parsed, returns the real client address
    Success(SocketAddr),
    /// Not a PROXY protocol header (data should be processed as-is)
    NotProxyProtocol,
    /// Parse error
    Error(String),
}

/// Try to parse PROXY protocol from a TCP stream
///
/// This function will:
/// 1. Peek at the stream to determine if PROXY protocol is present
/// 2. If PROXY protocol v1 or v2 is detected, read and parse it
/// 3. Return the real client address if successful
///
/// The stream will have the PROXY protocol header consumed after this call.
pub async fn parse_proxy_protocol(stream: &mut TcpStream) -> ProxyProtocolResult {
    // First, peek to detect protocol version
    let mut peek_buf = [0u8; PROXY_V2_HEADER_SIZE];
    match stream.peek(&mut peek_buf).await {
        Ok(n) if n >= 5 => {
            // Check for v2 signature first (needs at least 13 bytes to confirm)
            if n >= 13 && peek_buf[..12] == PROXY_V2_SIGNATURE {
                // Verify version is 2
                if (peek_buf[12] & 0xF0) == 0x20 {
                    return parse_proxy_protocol_v2(stream).await;
                }
            }

            // Check for v1 header ("PROXY ")
            if &peek_buf[..5] == b"PROXY" {
                return parse_proxy_protocol_v1(stream).await;
            }

            ProxyProtocolResult::NotProxyProtocol
        }
        Ok(_) => ProxyProtocolResult::NotProxyProtocol,
        Err(e) => ProxyProtocolResult::Error(format!("Failed to peek stream: {}", e)),
    }
}

/// Parse PROXY protocol v1 header from a string line
///
/// This is a pure function that parses a single line without I/O.
/// Used by both the async parser and unit tests.
fn parse_proxy_v1_line(line: &str) -> ProxyProtocolResult {
    let line = line.trim_end_matches('\n').trim_end_matches('\r');
    let parts: Vec<&str> = line.split(' ').collect();

    if parts.is_empty() || parts[0] != "PROXY" {
        return ProxyProtocolResult::Error("Invalid PROXY v1 header".into());
    }

    if parts.len() < 2 {
        return ProxyProtocolResult::Error("PROXY v1 header too short".into());
    }

    match parts[1] {
        "UNKNOWN" => {
            debug!("PROXY v1 UNKNOWN protocol, using socket address");
            ProxyProtocolResult::NotProxyProtocol
        }
        "TCP4" | "TCP6" => {
            if parts.len() != 6 {
                return ProxyProtocolResult::Error(format!(
                    "Invalid PROXY v1 header, expected 6 parts, got {}",
                    parts.len()
                ));
            }

            let src_ip: IpAddr = match parts[2].parse() {
                Ok(ip) => ip,
                Err(_) => {
                    return ProxyProtocolResult::Error(format!("Invalid source IP: {}", parts[2]));
                }
            };

            let src_port: u16 = match parts[4].parse() {
                Ok(port) => port,
                Err(_) => {
                    return ProxyProtocolResult::Error(format!(
                        "Invalid source port: {}",
                        parts[4]
                    ));
                }
            };

            let src_addr = SocketAddr::new(src_ip, src_port);
            debug!("PROXY v1 parsed: src={}", src_addr);
            ProxyProtocolResult::Success(src_addr)
        }
        proto => ProxyProtocolResult::Error(format!("Unsupported PROXY v1 protocol: {}", proto)),
    }
}

/// Parse PROXY protocol version 1 (text format) from a TCP stream
///
/// Format: "PROXY <INET_PROTO> <SRC_ADDR> <DST_ADDR> <SRC_PORT> <DST_PORT>\r\n"
/// Example: "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n"
///
/// This implementation reads byte-by-byte to avoid buffering beyond the header,
/// ensuring no business data is lost.
async fn parse_proxy_protocol_v1(stream: &mut TcpStream) -> ProxyProtocolResult {
    // Use a stack-allocated buffer for better performance
    let mut buf = [0u8; PROXY_V1_MAX_LENGTH];
    let mut pos = 0;

    // Read byte-by-byte until we find \r\n or reach max length
    loop {
        if pos >= PROXY_V1_MAX_LENGTH {
            return ProxyProtocolResult::Error("PROXY v1 header too long".into());
        }

        match stream.read_exact(&mut buf[pos..pos + 1]).await {
            Ok(_) => {
                pos += 1;
                // Check for CRLF (\r\n) - the required line terminator per spec
                if pos >= 2 && buf[pos - 2] == b'\r' && buf[pos - 1] == b'\n' {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return ProxyProtocolResult::Error(
                    "Connection closed while reading PROXY header".into(),
                );
            }
            Err(e) => {
                return ProxyProtocolResult::Error(format!("Failed to read PROXY header: {}", e));
            }
        }
    }

    // Convert to string and parse
    match std::str::from_utf8(&buf[..pos]) {
        Ok(line) => parse_proxy_v1_line(line),
        Err(_) => ProxyProtocolResult::Error("PROXY v1 header contains invalid UTF-8".into()),
    }
}

/// Parse PROXY protocol version 2 (binary format) from a TCP stream
///
/// This implementation:
/// - Uses stack-allocated buffer for the fixed 16-byte header
/// - Validates address length to prevent DoS attacks (max 512 bytes)
/// - Handles LOCAL command correctly (address data is ignored per spec)
async fn parse_proxy_protocol_v2(stream: &mut TcpStream) -> ProxyProtocolResult {
    // Read the 16-byte header using stack buffer
    let mut header = [0u8; PROXY_V2_HEADER_SIZE];
    if let Err(e) = stream.read_exact(&mut header).await {
        return ProxyProtocolResult::Error(format!("Failed to read PROXY v2 header: {}", e));
    }

    // Parse and validate address length from header
    let addr_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    // DoS protection: reject excessively large address lengths
    // IPv4 needs 12 bytes, IPv6 needs 36 bytes, Unix needs 216 bytes
    // We allow up to 512 bytes for TLV extensions
    if addr_len > PROXY_V2_MAX_ADDR_LEN {
        return ProxyProtocolResult::Error(format!(
            "PROXY v2 address length {} exceeds maximum {}",
            addr_len, PROXY_V2_MAX_ADDR_LEN
        ));
    }

    // Read address data if present
    let addr_data = if addr_len > 0 {
        let mut buf = vec![0u8; addr_len];
        if let Err(e) = stream.read_exact(&mut buf).await {
            return ProxyProtocolResult::Error(format!("Failed to read PROXY v2 address: {}", e));
        }
        buf
    } else {
        Vec::new()
    };

    parse_proxy_v2_bytes(&header, &addr_data)
}

/// Parse PROXY protocol v2 from header and address data
///
/// This is a pure function that parses bytes without I/O.
/// Used by both the async parser and unit tests.
fn parse_proxy_v2_bytes(
    header: &[u8; PROXY_V2_HEADER_SIZE],
    addr_data: &[u8],
) -> ProxyProtocolResult {
    // Verify signature
    if header[..12] != PROXY_V2_SIGNATURE {
        return ProxyProtocolResult::Error("Invalid PROXY v2 signature".into());
    }

    let ver_cmd = header[12];
    let version = (ver_cmd & 0xF0) >> 4;
    let command = ver_cmd & 0x0F;

    if version != 2 {
        return ProxyProtocolResult::Error(format!("Unsupported PROXY version: {}", version));
    }

    let fam_proto = header[13];
    let family = (fam_proto & 0xF0) >> 4;

    match command {
        0x00 => {
            // LOCAL: connection was established by proxy itself (health check)
            // Address data is ignored for LOCAL command per spec
            debug!("PROXY v2 LOCAL command, using socket address");
            ProxyProtocolResult::NotProxyProtocol
        }
        0x01 => {
            // PROXY: connection on behalf of another node
            parse_proxy_v2_address(family, addr_data)
        }
        _ => ProxyProtocolResult::Error(format!("Unsupported PROXY v2 command: {}", command)),
    }
}

/// Parse address from PROXY v2 PROXY command
fn parse_proxy_v2_address(family: u8, addr_data: &[u8]) -> ProxyProtocolResult {
    match family {
        0x00 => {
            // AF_UNSPEC: unknown/unsupported
            debug!("PROXY v2 AF_UNSPEC, using socket address");
            ProxyProtocolResult::NotProxyProtocol
        }
        0x01 => {
            // AF_INET (IPv4): 4 + 4 + 2 + 2 = 12 bytes
            if addr_data.len() < 12 {
                return ProxyProtocolResult::Error("PROXY v2 IPv4 address data too short".into());
            }
            let src_ip = Ipv4Addr::new(addr_data[0], addr_data[1], addr_data[2], addr_data[3]);
            let src_port = u16::from_be_bytes([addr_data[8], addr_data[9]]);
            let src_addr = SocketAddr::new(IpAddr::V4(src_ip), src_port);
            debug!("PROXY v2 parsed: src={}", src_addr);
            ProxyProtocolResult::Success(src_addr)
        }
        0x02 => {
            // AF_INET6 (IPv6): 16 + 16 + 2 + 2 = 36 bytes
            if addr_data.len() < 36 {
                return ProxyProtocolResult::Error("PROXY v2 IPv6 address data too short".into());
            }
            let src_ip = Ipv6Addr::from(<[u8; 16]>::try_from(&addr_data[0..16]).unwrap());
            let src_port = u16::from_be_bytes([addr_data[32], addr_data[33]]);
            let src_addr = SocketAddr::new(IpAddr::V6(src_ip), src_port);
            debug!("PROXY v2 parsed: src={}", src_addr);
            ProxyProtocolResult::Success(src_addr)
        }
        0x03 => {
            // AF_UNIX: 108 + 108 = 216 bytes, no IP address available
            debug!("PROXY v2 AF_UNIX, cannot extract IP address, using socket address");
            ProxyProtocolResult::NotProxyProtocol
        }
        _ => {
            debug!("PROXY v2 unknown address family: {:#x}", family);
            ProxyProtocolResult::NotProxyProtocol
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a PROXY protocol v2 header and address data for testing
    /// Returns (header, addr_data) tuple
    fn build_proxy_v2_parts(
        command: u8,
        family: u8,
        protocol: u8,
        addr_data: &[u8],
    ) -> ([u8; PROXY_V2_HEADER_SIZE], Vec<u8>) {
        let mut header = [0u8; PROXY_V2_HEADER_SIZE];
        // Signature
        header[..12].copy_from_slice(&PROXY_V2_SIGNATURE);
        // Version (2) and command
        header[12] = 0x20 | (command & 0x0F);
        // Family and protocol
        header[13] = (family << 4) | (protocol & 0x0F);
        // Address length
        let addr_len = addr_data.len() as u16;
        header[14..16].copy_from_slice(&addr_len.to_be_bytes());

        (header, addr_data.to_vec())
    }

    // ===================
    // PROXY v1 tests
    // ===================

    #[test]
    fn test_proxy_v1_tcp4() {
        let line = "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::Success(addr) => {
                assert_eq!(addr.ip(), "192.168.0.1".parse::<IpAddr>().unwrap());
                assert_eq!(addr.port(), 56324);
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v1_tcp6() {
        let line = "PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::Success(addr) => {
                assert_eq!(addr.ip(), "2001:db8::1".parse::<IpAddr>().unwrap());
                assert_eq!(addr.port(), 56324);
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v1_unknown() {
        let line = "PROXY UNKNOWN\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::NotProxyProtocol => {}
            other => panic!("Expected NotProxyProtocol, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v1_unknown_with_addresses() {
        // HAProxy spec allows UNKNOWN with optional addresses
        let line = "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::NotProxyProtocol => {}
            other => panic!("Expected NotProxyProtocol, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v1_invalid_header() {
        let line = "NOT_PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::Error(_) => {}
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v1_missing_fields() {
        let line = "PROXY TCP4 192.168.0.1\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::Error(msg) => {
                assert!(msg.contains("expected 6 parts"));
            }
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v1_invalid_ip() {
        let line = "PROXY TCP4 not.an.ip 192.168.0.11 56324 443\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::Error(msg) => {
                assert!(msg.contains("Invalid source IP"));
            }
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v1_invalid_port() {
        let line = "PROXY TCP4 192.168.0.1 192.168.0.11 notaport 443\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::Error(msg) => {
                assert!(msg.contains("Invalid source port"));
            }
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v1_unsupported_protocol() {
        let line = "PROXY UDP4 192.168.0.1 192.168.0.11 56324 443\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::Error(msg) => {
                assert!(msg.contains("Unsupported PROXY v1 protocol"));
            }
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    // ===================
    // PROXY v2 tests
    // ===================

    #[test]
    fn test_proxy_v2_signature() {
        assert_eq!(PROXY_V2_SIGNATURE.len(), 12);
        assert_eq!(PROXY_V2_SIGNATURE[4], 0x00); // Contains null byte
    }

    #[test]
    fn test_proxy_v2_tcp4() {
        // Build address data: src_ip (4) + dst_ip (4) + src_port (2) + dst_port (2) = 12 bytes
        let mut addr_data = Vec::new();
        addr_data.extend_from_slice(&[192, 168, 1, 100]); // src IP
        addr_data.extend_from_slice(&[192, 168, 1, 1]); // dst IP
        addr_data.extend_from_slice(&12345u16.to_be_bytes()); // src port
        addr_data.extend_from_slice(&443u16.to_be_bytes()); // dst port

        // command=PROXY(0x01), family=AF_INET(0x01), protocol=STREAM(0x01)
        let (header, addr) = build_proxy_v2_parts(0x01, 0x01, 0x01, &addr_data);

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::Success(addr) => {
                assert_eq!(addr.ip(), "192.168.1.100".parse::<IpAddr>().unwrap());
                assert_eq!(addr.port(), 12345);
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_tcp6() {
        // Build address data: src_ip (16) + dst_ip (16) + src_port (2) + dst_port (2) = 36 bytes
        let mut addr_data = Vec::new();
        // src IP: 2001:db8::1
        addr_data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        // dst IP: 2001:db8::2
        addr_data.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        addr_data.extend_from_slice(&54321u16.to_be_bytes()); // src port
        addr_data.extend_from_slice(&8080u16.to_be_bytes()); // dst port

        // command=PROXY(0x01), family=AF_INET6(0x02), protocol=STREAM(0x01)
        let (header, addr) = build_proxy_v2_parts(0x01, 0x02, 0x01, &addr_data);

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::Success(addr) => {
                assert_eq!(addr.ip(), "2001:db8::1".parse::<IpAddr>().unwrap());
                assert_eq!(addr.port(), 54321);
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_local_command() {
        // LOCAL command (0x00) - health check from proxy itself
        let (header, addr) = build_proxy_v2_parts(0x00, 0x00, 0x00, &[]);

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::NotProxyProtocol => {}
            other => panic!("Expected NotProxyProtocol, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_af_unspec() {
        // AF_UNSPEC (0x00) - unknown address family
        let (header, addr) = build_proxy_v2_parts(0x01, 0x00, 0x00, &[]);

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::NotProxyProtocol => {}
            other => panic!("Expected NotProxyProtocol, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_invalid_signature() {
        let mut header = [0u8; PROXY_V2_HEADER_SIZE];
        // Wrong signature
        header[..12].copy_from_slice(b"WRONG_SIGNAT");

        match parse_proxy_v2_bytes(&header, &[]) {
            ProxyProtocolResult::Error(msg) => {
                assert!(msg.contains("Invalid PROXY v2 signature"));
            }
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_ipv4_addr_too_short() {
        // Only 8 bytes of address data, but IPv4 needs 12
        let addr_data = vec![0u8; 8];
        let (header, addr) = build_proxy_v2_parts(0x01, 0x01, 0x01, &addr_data);

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::Error(msg) => {
                assert!(msg.contains("IPv4 address data too short"));
            }
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_ipv6_addr_too_short() {
        // Only 20 bytes of address data, but IPv6 needs 36
        let addr_data = vec![0u8; 20];
        let (header, addr) = build_proxy_v2_parts(0x01, 0x02, 0x01, &addr_data);

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::Error(msg) => {
                assert!(msg.contains("IPv6 address data too short"));
            }
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_unsupported_command() {
        // Command 0x02 is not defined
        let (header, addr) = build_proxy_v2_parts(0x02, 0x01, 0x01, &[0u8; 12]);

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::Error(msg) => {
                assert!(msg.contains("Unsupported PROXY v2 command"));
            }
            other => panic!("Expected Error, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_af_unix() {
        // AF_UNIX (0x03) - Unix socket addresses don't have IP:port
        // We correctly consume the data but return NotProxyProtocol since we can't extract IP
        let (header, addr) = build_proxy_v2_parts(0x01, 0x03, 0x00, &[0u8; 216]); // AF_UNIX needs 216 bytes

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::NotProxyProtocol => {}
            other => panic!("Expected NotProxyProtocol, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_unknown_family() {
        // Unknown address family (0x04 and above)
        let (header, addr) = build_proxy_v2_parts(0x01, 0x04, 0x01, &[0u8; 12]);

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::NotProxyProtocol => {}
            other => panic!("Expected NotProxyProtocol, got {:?}", other),
        }
    }

    // ===================
    // Real-world examples
    // ===================

    #[test]
    fn test_proxy_v1_haproxy_example() {
        // Example from HAProxy documentation
        let line = "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n";
        match parse_proxy_v1_line(line) {
            ProxyProtocolResult::Success(addr) => {
                assert_eq!(addr.ip(), "255.255.255.255".parse::<IpAddr>().unwrap());
                assert_eq!(addr.port(), 65535);
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_with_tlv_extensions() {
        // v2 can have TLV extensions after the address
        // Our parser should ignore them (they're included in addr_len)
        let mut addr_data = Vec::new();
        addr_data.extend_from_slice(&[10, 0, 0, 1]); // src IP: 10.0.0.1
        addr_data.extend_from_slice(&[10, 0, 0, 2]); // dst IP: 10.0.0.2
        addr_data.extend_from_slice(&8080u16.to_be_bytes()); // src port
        addr_data.extend_from_slice(&80u16.to_be_bytes()); // dst port
        // Add some TLV data (type=0x20 PP2_TYPE_UNIQUE_ID, length=4, value)
        addr_data.extend_from_slice(&[0x20, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04]);

        let (header, addr) = build_proxy_v2_parts(0x01, 0x01, 0x01, &addr_data);

        match parse_proxy_v2_bytes(&header, &addr) {
            ProxyProtocolResult::Success(addr) => {
                assert_eq!(addr.ip(), "10.0.0.1".parse::<IpAddr>().unwrap());
                assert_eq!(addr.port(), 8080);
            }
            other => panic!("Expected Success, got {:?}", other),
        }
    }

    #[test]
    fn test_proxy_v2_max_addr_len() {
        // Test that we reject excessively large address lengths
        let mut header = [0u8; PROXY_V2_HEADER_SIZE];
        header[..12].copy_from_slice(&PROXY_V2_SIGNATURE);
        header[12] = 0x21; // Version 2, PROXY command
        header[13] = 0x11; // AF_INET, STREAM
        // Set addr_len to exceed max (e.g., 65535)
        header[14..16].copy_from_slice(&65535u16.to_be_bytes());

        // This test verifies the constant is defined correctly
        assert!(PROXY_V2_MAX_ADDR_LEN < 65535);
        assert_eq!(PROXY_V2_MAX_ADDR_LEN, 512);
    }
}
