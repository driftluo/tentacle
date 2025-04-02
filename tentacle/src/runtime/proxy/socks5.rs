use fast_socks5::{
    AuthenticationMethod, Socks5Command,
    client::{Config as ConnectConfig, Socks5Stream},
};
use tokio::net::TcpStream;

pub async fn connect(
    socks_server: url::Url,
    target_addr: String,
    target_port: u16,
) -> Result<TcpStream, fast_socks5::SocksError> {
    let auth = {
        if socks_server.username().is_empty() {
            AuthenticationMethod::None
        } else {
            AuthenticationMethod::Password {
                username: socks_server.username().to_string(),
                password: socks_server.password().unwrap_or_default().to_string(),
            }
        }
    };
    let socks_server_str = format!(
        "{}:{}",
        socks_server.host_str().ok_or_else(|| {
            fast_socks5::SocksError::ArgumentInputError("socks_server should have host")
        })?,
        socks_server.port().ok_or_else(|| {
            fast_socks5::SocksError::ArgumentInputError("socks_server should have port")
        })?
    );
    Socks5Stream::connect_raw(
        Socks5Command::TCPConnect,
        socks_server_str,
        target_addr,
        target_port,
        Some(auth),
        ConnectConfig::default(),
    )
    .await
    .map(|socket| socket.get_socket())
}
