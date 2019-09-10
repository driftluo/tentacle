#[cfg(all(feature = "flatc", feature = "molc"))]
compile_error!("features `flatc` and `molc` are mutually exclusive");
#[cfg(all(not(feature = "flatc"), not(feature = "molc")))]
compile_error!("Please choose a serialization format via feature. Possible choices: flatc, molc");

#[cfg(feature = "flatc")]
use crate::protocol_select::protocol_select_generated::p2p::protocol_select::{
    ProtocolInfo as FBSProtocolInfo, ProtocolInfoBuilder,
};
#[cfg(feature = "molc")]
use molecule::prelude::{Builder, Entity, Reader};

use bytes::Bytes;
use futures::prelude::*;
use log::debug;
use std::cmp::Ordering;
use std::{collections::HashMap, io};
use tokio::codec::{length_delimited::LengthDelimitedCodec, Framed};
use tokio::prelude::{AsyncRead, AsyncWrite};

#[cfg(feature = "flatc")]
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(unused_imports)]
mod protocol_select_generated;
#[cfg(feature = "flatc")]
#[rustfmt::skip]
#[allow(clippy::all)]
#[allow(dead_code)]
mod protocol_select_generated_verifier;
#[cfg(feature = "molc")]
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

    // TODO: return type change to Bytes on 0.3

    /// Encode to flatbuffer
    #[cfg(feature = "flatc")]
    pub fn encode(&self) -> Vec<u8> {
        let mut fbb = flatbuffers::FlatBufferBuilder::new();
        let name = fbb.create_string(&self.name);
        let versions = &self
            .support_versions
            .iter()
            .map(|version| fbb.create_string(version))
            .collect::<Vec<_>>();
        let versions = fbb.create_vector(versions);

        let mut builder = ProtocolInfoBuilder::new(&mut fbb);
        builder.add_name(name);
        builder.add_support_versions(versions);
        let data = builder.finish();

        fbb.finish(data, None);
        fbb.finished_data().to_vec()
    }

    /// Decode from flatbuffer
    #[cfg(feature = "flatc")]
    pub fn decode(data: &[u8]) -> Option<Self> {
        let fbs_protocol_info = flatbuffers_verifier::get_root::<FBSProtocolInfo>(data).ok()?;
        match (
            fbs_protocol_info.name(),
            fbs_protocol_info.support_versions(),
        ) {
            (Some(name), Some(fbs_versions)) => {
                let mut versions: Vec<String> = Vec::with_capacity(fbs_versions.len() + 1);
                for i in 0..fbs_versions.len() {
                    versions.push(fbs_versions.get(i).to_owned());
                }
                Some(ProtocolInfo {
                    name: name.to_owned(),
                    support_versions: versions,
                })
            }
            _ => None,
        }
    }

    /// Encode with molecule
    #[cfg(feature = "molc")]
    pub fn encode(self) -> Vec<u8> {
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
            .as_slice()
            .to_vec()
    }

    /// Decode with molecule
    #[cfg(feature = "molc")]
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

    socket.send(Bytes::from(proto_info.encode())).await?;

    let (raw_remote_info, socket) = socket.into_future().await;

    let mut remote_info = match raw_remote_info {
        Some(info) => match ProtocolInfo::decode(&info?) {
            Some(info) => info,
            None => return Err(io::ErrorKind::InvalidData.into()),
        },
        None => {
            let err = io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof");
            debug!("unexpected eof while waiting for remote's protocol proposition");
            return Err(err);
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
    let remote_info = match raw_remote_info {
        Some(info) => match ProtocolInfo::decode(&info?) {
            Some(info) => info,
            None => return Err(io::ErrorKind::InvalidData.into()),
        },
        None => {
            let err = io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof");
            debug!("unexpected eof while waiting for remote's protocol proposition");
            return Err(err);
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

    socket
        .send(Bytes::from(
            ProtocolInfo {
                name: remote_info.name.clone(),
                support_versions: version.clone().into_iter().collect(),
            }
            .encode(),
        ))
        .await?;

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
    use futures::{channel, prelude::*};
    use std::collections::HashMap;
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn protocol_message_decode_encode() {
        let mut message = ProtocolInfo::default();
        message.name = "test".to_owned();
        message.support_versions = vec!["1.0.0".to_string(), "1.1.1".to_string()];

        let byte = message.clone().encode();
        assert_eq!(message, ProtocolInfo::decode(&byte).unwrap())
    }

    #[test]
    fn test_select_version() {
        let a = vec![
            "1.0.0".to_string(),
            "1.1.1".to_string(),
            "2.0.0".to_string(),
        ];
        let b = vec![
            "1.0.0".to_string(),
            "2.0.0".to_string(),
            "3.0.0".to_string(),
        ];
        let c = vec![];
        let d = vec!["5.0.0".to_string()];
        let e = vec!["1.0.0".to_string()];

        assert_eq!(select_version(&b, &a), Some("2.0.0".to_string()));
        assert_eq!(select_version(&b, &e), Some("1.0.0".to_string()));
        assert!(select_version(&b, &c).is_none());
        assert!(select_version(&b, &d).is_none());
        assert!(select_version(&d, &a).is_none());
        assert!(select_version(&d, &e).is_none());
        assert!(select_version(&e, &d).is_none());
    }

    fn select_protocol(server: Vec<String>, client: Vec<String>, result: Option<String>) {
        let (sender_1, receiver_1) = channel::oneshot::channel::<Option<String>>();
        let (sender_2, receiver_2) = channel::oneshot::channel::<Option<String>>();
        let (addr_sender, addr_receiver) = channel::oneshot::channel::<::std::net::SocketAddr>();

        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.spawn(async move {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let listener_addr = listener.local_addr().unwrap();
            let _ = addr_sender.send(listener_addr);

            let (connect, _stream) = listener.incoming().into_future().await;

            let mut message = ProtocolInfo::default();
            message.name = "test".to_owned();
            message.support_versions = server;
            let mut messages = HashMap::new();
            messages.insert("test".to_owned(), (message, None));

            let (_, _, a) = server_select(connect.unwrap().unwrap(), messages)
                .await
                .unwrap();
            let _ = sender_1.send(a);
        });

        rt.spawn(async move {
            let listener_addr = addr_receiver.await.unwrap();
            let connect = TcpStream::connect(&listener_addr).await.unwrap();

            let mut message = ProtocolInfo::default();
            message.name = "test".to_owned();
            message.support_versions = client;

            let (_, _, a) = client_select(connect, message).await.unwrap();
            let _ = sender_2.send(a);
        });

        rt.spawn(async move {
            assert_eq!(receiver_1.await.unwrap(), result);
            assert_eq!(receiver_2.await.unwrap(), result);
        });

        rt.shutdown_on_idle();
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
