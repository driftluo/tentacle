use crate::protocol_select::protocol_select_generated::p2p::protocol_select::{
    ProtocolInfo as FBSProtocolInfo, ProtocolInfoBuilder,
};

use bytes::Bytes;
use flatbuffers::{get_root, FlatBufferBuilder};
use futures::{future, prelude::*};
use log::debug;
use std::cmp::Ordering;
use std::{collections::HashMap, io};
use tokio::codec::{length_delimited::LengthDelimitedCodec, Framed};
use tokio::prelude::{AsyncRead, AsyncWrite};

#[rustfmt::skip]
#[allow(clippy::all)]
mod protocol_select_generated;

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

    /// Encode to flatbuffer
    pub fn encode(&self) -> Vec<u8> {
        let mut fbb = FlatBufferBuilder::new();
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
    pub fn decode(data: &[u8]) -> Result<Self, ()> {
        let fbs_protocol_info = get_root::<FBSProtocolInfo>(data);
        match (
            fbs_protocol_info.name(),
            fbs_protocol_info.support_versions(),
        ) {
            (Some(name), Some(fbs_versions)) => {
                let mut versions: Vec<String> = Vec::new();
                for i in 0..fbs_versions.len() {
                    versions.push(fbs_versions.get(i).to_owned());
                }
                Ok(ProtocolInfo {
                    name: name.to_owned(),
                    support_versions: versions,
                })
            }
            _ => Err(()),
        }
    }
}

/// Performs a handshake on the given socket.
///
/// Select the protocol version, return a handle that implements the `AsyncWrite` and `AsyncRead` trait,
/// plus the protocol name, plus the version option.
pub(crate) fn client_select<T: AsyncWrite + AsyncRead + Send>(
    handle: T,
    proto_info: ProtocolInfo,
) -> impl Future<Item = (Framed<T, LengthDelimitedCodec>, String, Option<String>), Error = io::Error>
{
    let socket = Framed::new(handle, LengthDelimitedCodec::new());
    future::ok::<_, io::Error>(proto_info)
        .and_then(|proto_info| {
            socket
                .send(Bytes::from(proto_info.encode()))
                .from_err()
                .map(|socket| socket)
        })
        .and_then(|socket| {
            socket
                .into_future()
                .map_err(|(e, socket)| {
                    let _ = socket.into_inner().shutdown();
                    e
                })
                .and_then(|(raw_remote_info, socket)| {
                    let remote_info = match raw_remote_info {
                        Some(info) => match ProtocolInfo::decode(&info) {
                            Ok(info) => info,
                            Err(_) => return Err(io::ErrorKind::InvalidData.into()),
                        },
                        None => {
                            let err =
                                io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof");
                            debug!(
                                "unexpected eof while waiting for remote's protocol proposition"
                            );
                            return Err(err);
                        }
                    };
                    Ok((remote_info, socket))
                })
        })
        .and_then(|(mut remote_info, socket)| {
            Ok((
                // Due to possible business data in the buffer, it cannot be directly discarded.
                socket,
                remote_info.name,
                remote_info.support_versions.pop(),
            ))
        })
}

/// Performs a handshake on the given socket.
///
/// Select the protocol version, return a handle that implements the `AsyncWrite` and `AsyncRead` trait,
/// plus the protocol name, plus the version option.
pub(crate) fn server_select<T: AsyncWrite + AsyncRead + Send>(
    handle: T,
    proto_infos: HashMap<String, ProtocolInfo>,
) -> impl Future<Item = (Framed<T, LengthDelimitedCodec>, String, Option<String>), Error = io::Error>
{
    let socket = Framed::new(handle, LengthDelimitedCodec::new());
    future::ok::<_, io::Error>(proto_infos)
        .and_then(|mut proto_infos| {
            socket
                .into_future()
                .map_err(|(e, socket)| {
                    let _ = socket.into_inner().shutdown();
                    e
                })
                .and_then(move |(raw_remote_info, socket)| {
                    let remote_info = match raw_remote_info {
                        Some(info) => match ProtocolInfo::decode(&info) {
                            Ok(info) => info,
                            Err(_) => return Err(io::ErrorKind::InvalidData.into()),
                        },
                        None => {
                            let err =
                                io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected eof");
                            debug!(
                                "unexpected eof while waiting for remote's protocol proposition"
                            );
                            return Err(err);
                        }
                    };
                    let version = proto_infos
                        .remove(&remote_info.name)
                        .and_then(|local_info| {
                            select_version(
                                &local_info.support_versions,
                                &remote_info.support_versions,
                            )
                        });
                    Ok((socket, remote_info.name, version))
                })
        })
        .and_then(|(socket, name, version)| {
            socket
                .send(Bytes::from(
                    ProtocolInfo {
                        name: name.clone(),
                        support_versions: version.clone().into_iter().collect(),
                    }
                    .encode(),
                ))
                .from_err()
                .map(|socket| (socket, name, version))
        })
        .and_then(|(socket, name, version)| Ok((socket, name, version)))
}

/// Choose the highest version of the two sides, assume that slices are sorted
#[inline]
fn select_version<T: Ord + Clone>(local: &[T], remote: &[T]) -> Option<T> {
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
    use futures::{prelude::*, sync};
    use std::{collections::HashMap, thread};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn protocol_message_decode_encode() {
        let mut message = ProtocolInfo::default();
        message.name = "test".to_owned();
        message.support_versions = vec!["1.0.0".to_string(), "1.1.1".to_string()];

        let byte = message.encode();
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

    fn select_protocol(server: Vec<String>, client: Vec<String>, result: &Option<String>) {
        let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let (sender, receiver_1) = sync::oneshot::channel::<Option<String>>();

        let server = listener
            .incoming()
            .into_future()
            .and_then(move |(connect, _)| {
                let mut message = ProtocolInfo::default();
                message.name = "test".to_owned();
                message.support_versions = server;
                let mut messages = HashMap::new();
                messages.insert("test".to_owned(), message);

                let task = server_select(connect.unwrap(), messages)
                    .map(|(_, _, a)| {
                        let _ = sender.send(a);
                    })
                    .map_err(|_| ());
                tokio::spawn(task);
                Ok(())
            })
            .map_err(|_| ());

        let (sender, receiver_2) = sync::oneshot::channel::<Option<String>>();
        let client = TcpStream::connect(&listener_addr)
            .and_then(move |connect| {
                let mut message = ProtocolInfo::default();
                message.name = "test".to_owned();
                message.support_versions = client;
                let task = client_select(connect, message)
                    .map(move |(_, _, a)| {
                        let _ = sender.send(a);
                    })
                    .map_err(|_| ());
                tokio::spawn(task);
                Ok(())
            })
            .map_err(|_| ());

        thread::spawn(|| {
            tokio::run(server);
        });

        thread::spawn(|| {
            tokio::run(client);
        });

        assert_eq!(&receiver_1.wait().unwrap(), result);
        assert_eq!(&receiver_2.wait().unwrap(), result);
    }

    #[test]
    fn test_select_success_same() {
        select_protocol(
            vec!["1.0.0".to_string(), "1.1.1".to_string()],
            vec!["1.0.0".to_string(), "1.1.1".to_string()],
            &Some("1.1.1".to_owned()),
        )
    }

    #[test]
    fn test_select_success_different() {
        select_protocol(
            vec!["1.0.0".to_string(), "2.1.1".to_string()],
            vec!["1.0.0".to_string(), "1.1.1".to_string()],
            &Some("1.0.0".to_owned()),
        )
    }

    #[test]
    fn test_select_fail() {
        select_protocol(
            vec!["1.0.0".to_string(), "1.1.1".to_string()],
            vec!["2.0.0".to_string(), "2.1.1".to_string()],
            &None,
        )
    }
}
