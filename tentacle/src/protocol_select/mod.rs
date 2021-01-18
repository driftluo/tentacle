use molecule::prelude::{Builder, Entity, Reader};

use bytes::Bytes;
use futures::prelude::*;
use log::{debug, trace};
use std::cmp::Ordering;
use std::{collections::HashMap, io};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{length_delimited::LengthDelimitedCodec, Framed};

#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod protocol_select_mol;

/// Function for protocol version select
pub type SelectFn<T> = Box<dyn Fn(&[T], &[T]) -> Option<T> + Send + 'static>;

/// Protocol Info
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProtocolInfo {
    /// Protocol name
    pub name: String,
    /// Support version
    pub support_versions: Vec<String>,
}

impl ProtocolInfo {
    /// new
    pub fn new(name: &str, support_versions: Vec<String>) -> Self {
        ProtocolInfo {
            name: name.to_owned(),
            support_versions,
        }
    }

    /// Encode with molecule
    pub fn encode(self) -> Bytes {
        let name = protocol_select_mol::String::new_builder()
            .set(self.name.into_bytes().into_iter().map(Into::into).collect())
            .build();
        let mut versions = Vec::new();
        for version in self.support_versions {
            versions.push(
                protocol_select_mol::String::new_builder()
                    .set(version.into_bytes().into_iter().map(Into::into).collect())
                    .build(),
            );
        }

        let versions = protocol_select_mol::StringVec::new_builder()
            .set(versions)
            .build();

        protocol_select_mol::ProtocolInfo::new_builder()
            .name(name)
            .support_versions(versions)
            .build()
            .as_bytes()
    }

    /// Decode with molecule
    pub fn decode(data: &[u8]) -> Option<Self> {
        let reader = protocol_select_mol::ProtocolInfoReader::from_compatible_slice(data).ok()?;

        let mut supports = Vec::new();
        for version in reader.support_versions().iter() {
            supports.push(String::from_utf8(version.raw_data().to_owned()).ok()?)
        }

        Some(ProtocolInfo {
            name: String::from_utf8(reader.name().raw_data().to_owned()).ok()?,
            support_versions: supports,
        })
    }
}

/// Performs a handshake on the given socket.
///
/// Select the protocol version, return a handle that implements the `AsyncWrite` and `AsyncRead` trait,
/// plus the protocol name, plus the version option.
pub(crate) async fn client_select<T: AsyncWrite + AsyncRead + Send + Unpin>(
    handle: T,
    proto_info: ProtocolInfo,
) -> Result<(Framed<T, LengthDelimitedCodec>, String, Option<String>), io::Error> {
    let mut socket = Framed::new(handle, LengthDelimitedCodec::new());

    let data = proto_info.encode();
    trace!("client_select send_proto(len={}): {:#x}", data.len(), data);
    socket.send(data).await?;

    let (raw_remote_info, socket) = socket.into_future().await;

    let mut remote_info = match raw_remote_info.transpose()? {
        Some(info) => {
            trace!("client_select recv_proto(len={}): {:#x}", info.len(), info);
            ProtocolInfo::decode(&info)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?
        }
        None => {
            debug!("client_select unexpected eof while waiting for remote's protocol proposition");
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof",
            ));
        }
    };

    Ok((
        // Due to possible business data in the buffer, it cannot be directly discarded.
        socket,
        remote_info.name,
        remote_info.support_versions.pop(),
    ))
}

/// Performs a handshake on the given socket.
///
/// Select the protocol version, return a handle that implements the `AsyncWrite` and `AsyncRead` trait,
/// plus the protocol name, plus the version option.
pub(crate) async fn server_select<T: AsyncWrite + AsyncRead + Send + Unpin>(
    handle: T,
    mut proto_infos: HashMap<String, (ProtocolInfo, Option<SelectFn<String>>)>,
) -> Result<(Framed<T, LengthDelimitedCodec>, String, Option<String>), io::Error> {
    let socket = Framed::new(handle, LengthDelimitedCodec::new());

    let (raw_remote_info, mut socket) = socket.into_future().await;
    let remote_info = match raw_remote_info.transpose()? {
        Some(info) => {
            trace!("server_select recv_proto(len={}): {:#x}", info.len(), info);
            ProtocolInfo::decode(&info)
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?
        }
        None => {
            debug!("server_select unexpected eof while waiting for remote's protocol proposition");
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected eof",
            ));
        }
    };

    let version = proto_infos
        .remove(&remote_info.name)
        .and_then(|(local_info, select)| {
            select
                .map(|f| f(&local_info.support_versions, &remote_info.support_versions))
                .unwrap_or_else(|| {
                    select_version(&local_info.support_versions, &remote_info.support_versions)
                })
        });

    let data = ProtocolInfo {
        name: remote_info.name.clone(),
        support_versions: version.clone().into_iter().collect(),
    }
    .encode();
    trace!("server_select send_proto(len={}): {:#x}", data.len(), data);
    socket.send(data).await?;

    Ok((socket, remote_info.name, version))
}

/// Choose the highest version of the two sides, assume that slices are sorted
#[inline]
pub fn select_version<T: Ord + Clone>(local: &[T], remote: &[T]) -> Option<T> {
    let (mut local_iter, mut remote_iter) = (local.iter().rev(), remote.iter().rev());
    let (mut local, mut remote) = (local_iter.next(), remote_iter.next());
    while let (Some(l), Some(r)) = (local, remote) {
        match l.cmp(r) {
            Ordering::Less => remote = remote_iter.next(),
            Ordering::Greater => local = local_iter.next(),
            Ordering::Equal => return Some(l.clone()),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{client_select, select_version, server_select, ProtocolInfo};
    use futures::channel;
    use std::collections::HashMap;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn protocol_message_decode_encode() {
        let message = ProtocolInfo {
            name: "test".to_owned(),
            support_versions: vec!["1.0.0".to_string(), "1.1.1".to_string()],
        };

        let byte = message.clone();
        assert_eq!(message, ProtocolInfo::decode(&byte.encode()).unwrap())
    }

    #[test]
    fn test_select_version() {
        let test_a = vec![
            "1.0.0".to_string(),
            "1.1.1".to_string(),
            "2.0.0".to_string(),
        ];
        let test_b = vec![
            "1.0.0".to_string(),
            "2.0.0".to_string(),
            "3.0.0".to_string(),
        ];
        let test_c = vec![];
        let test_d = vec!["5.0.0".to_string()];
        let test_e = vec!["1.0.0".to_string()];

        assert_eq!(select_version(&test_b, &test_a), Some("2.0.0".to_string()));
        assert_eq!(select_version(&test_b, &test_e), Some("1.0.0".to_string()));
        assert!(select_version(&test_b, &test_c).is_none());
        assert!(select_version(&test_b, &test_d).is_none());
        assert!(select_version(&test_d, &test_a).is_none());
        assert!(select_version(&test_d, &test_e).is_none());
        assert!(select_version(&test_e, &test_d).is_none());
    }

    fn select_protocol(server: Vec<String>, client: Vec<String>, result: Option<String>) {
        let (sender_1, receiver_1) = channel::oneshot::channel::<Option<String>>();
        let (sender_2, receiver_2) = channel::oneshot::channel::<Option<String>>();
        let (addr_sender, addr_receiver) = channel::oneshot::channel::<::std::net::SocketAddr>();

        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener_addr = listener.local_addr().unwrap();
            let _res = addr_sender.send(listener_addr);

            let (connect, _) = listener.accept().await.unwrap();

            let message = ProtocolInfo {
                name: "test".to_owned(),
                support_versions: server,
            };
            let mut messages = HashMap::new();
            messages.insert("test".to_owned(), (message, None));

            let (_, _, a) = server_select(connect, messages).await.unwrap();
            let _res = sender_1.send(a);
        });

        rt.spawn(async move {
            let listener_addr = addr_receiver.await.unwrap();
            let connect = TcpStream::connect(&listener_addr).await.unwrap();

            let message = ProtocolInfo {
                name: "test".to_owned(),
                support_versions: client,
            };

            let (_, _, a) = client_select(connect, message).await.unwrap();
            let _res = sender_2.send(a);
        });

        rt.block_on(async move {
            assert_eq!(receiver_1.await.unwrap(), result);
            assert_eq!(receiver_2.await.unwrap(), result);
        });
    }

    #[test]
    fn test_select_success_same() {
        select_protocol(
            vec!["1.0.0".to_string(), "1.1.1".to_string()],
            vec!["1.0.0".to_string(), "1.1.1".to_string()],
            Some("1.1.1".to_owned()),
        )
    }

    #[test]
    fn test_select_success_different() {
        select_protocol(
            vec!["1.0.0".to_string(), "2.1.1".to_string()],
            vec!["1.0.0".to_string(), "1.1.1".to_string()],
            Some("1.0.0".to_owned()),
        )
    }

    #[test]
    fn test_select_fail() {
        select_protocol(
            vec!["1.0.0".to_string(), "1.1.1".to_string()],
            vec!["2.0.0".to_string(), "2.1.1".to_string()],
            None,
        )
    }
}
