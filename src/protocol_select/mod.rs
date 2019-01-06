use crate::protocol_select::protocol_select_generated::p2p::protocol_select::{
    ProtocolMessage as FBSProtocolMessage, ProtocolMessageBuilder,
};

use bytes::Bytes;
use flatbuffers::{get_root, FlatBufferBuilder};
use futures::{future, prelude::*};
use log::debug;
use std::{collections::HashMap, io};
use tokio::codec::{length_delimited::LengthDelimitedCodec, Framed};
use tokio::prelude::{AsyncRead, AsyncWrite};

#[rustfmt::skip]
#[allow(clippy::all)]
mod protocol_select_generated;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ProtocolMessage {
    pub name: String,
    pub support_versions: Vec<String>,
}

impl ProtocolMessage {
    pub fn new(name: &str, support_versions: Vec<String>) -> Self {
        ProtocolMessage {
            name: name.to_owned(),
            support_versions,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut fbb = FlatBufferBuilder::new();
        let name = fbb.create_string(&self.name);
        let versions = &self
            .support_versions
            .iter()
            .map(|version| fbb.create_string(version))
            .collect::<Vec<_>>();
        let versions = fbb.create_vector(versions);

        let mut builder = ProtocolMessageBuilder::new(&mut fbb);
        builder.add_name(name);
        builder.add_support_versions(versions);
        let data = builder.finish();

        fbb.finish(data, None);
        fbb.finished_data().to_vec()
    }

    pub fn decode(data: &[u8]) -> Result<Self, ()> {
        let fbs_protocol_message = get_root::<FBSProtocolMessage>(data);
        if fbs_protocol_message.name().is_none()
            || fbs_protocol_message.support_versions().is_none()
        {
            Err(())
        } else {
            let mut versions: Vec<String> = Vec::new();
            let fbs_versions = fbs_protocol_message.support_versions().unwrap();
            for i in 0..fbs_versions.len() {
                versions.push(fbs_versions.get(i).to_owned());
            }
            Ok(ProtocolMessage {
                name: fbs_protocol_message.name().unwrap().to_owned(),
                support_versions: versions,
            })
        }
    }
}

/// Performs a handshake on the given socket.
///
/// Select the protocol version, return a handle that implements the `AsyncWrite` and `AsyncRead` trait,
/// plus the protocol name, plus the version option.
pub(crate) fn client_select<T: AsyncWrite + AsyncRead + Send>(
    handle: T,
    message: ProtocolMessage,
) -> impl Future<Item = (T, String, Option<String>), Error = io::Error> {
    let socket = Framed::new(handle, LengthDelimitedCodec::new());
    future::ok::<_, io::Error>(message)
        .and_then(|message| {
            socket
                .send(Bytes::from(message.encode()))
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
                .and_then(|(raw_remote_message, socket)| {
                    let message = match raw_remote_message {
                        Some(msg) => match ProtocolMessage::decode(&msg) {
                            Ok(msg) => msg,
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
                    Ok((message, socket))
                })
        })
        .and_then(|(mut message, socket)| {
            Ok((
                socket.into_inner(),
                message.name,
                message.support_versions.pop(),
            ))
        })
}

/// Performs a handshake on the given socket.
///
/// Select the protocol version, return a handle that implements the `AsyncWrite` and `AsyncRead` trait,
/// plus the protocol name, plus the version option.
pub(crate) fn server_select<T: AsyncWrite + AsyncRead + Send>(
    handle: T,
    messages: HashMap<String, ProtocolMessage>,
) -> impl Future<Item = (T, String, Option<String>), Error = io::Error> {
    let socket = Framed::new(handle, LengthDelimitedCodec::new());
    future::ok::<_, io::Error>(messages)
        .and_then(|mut messages| {
            socket
                .into_future()
                .map_err(|(e, socket)| {
                    let _ = socket.into_inner().shutdown();
                    e
                })
                .and_then(move |(raw_remote_message, socket)| {
                    let remote_message = match raw_remote_message {
                        Some(msg) => match ProtocolMessage::decode(&msg) {
                            Ok(msg) => msg,
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
                    let version = match messages.remove(&remote_message.name) {
                        Some(local_message) => select_version(
                            &local_message.support_versions,
                            &remote_message.support_versions,
                        ),
                        None => Vec::new(),
                    };
                    Ok((socket, remote_message.name, version))
                })
        })
        .and_then(|(socket, name, version)| {
            socket
                .send(Bytes::from(
                    ProtocolMessage {
                        name: name.clone(),
                        support_versions: version.clone(),
                    }
                    .encode(),
                ))
                .from_err()
                .map(|socket| (socket, name, version))
        })
        .and_then(|(socket, name, mut version)| Ok((socket.into_inner(), name, version.pop())))
}

/// Choose the highest version of the two sides
#[inline]
fn select_version<T: Ord + Clone>(local: &[T], remote: &[T]) -> Vec<T> {
    let mut remote_index = if remote.is_empty() {
        return Vec::new();
    } else {
        remote.len() - 1
    };
    let mut local_index = if local.is_empty() {
        return Vec::new();
    } else {
        local.len() - 1
    };

    loop {
        if local[local_index] > remote[remote_index] {
            if local_index > 0 {
                local_index -= 1;
            } else {
                break;
            }
        } else if local[local_index] < remote[remote_index] {
            if remote_index > 0 {
                remote_index -= 1;
            } else {
                break;
            }
        } else {
            return vec![local[local_index].clone()];
        }
    }

    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::{client_select, select_version, server_select, ProtocolMessage};
    use futures::{prelude::*, sync};
    use std::{collections::HashMap, thread};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn protocol_message_decode_encode() {
        let mut message = ProtocolMessage::default();
        message.name = "test".to_owned();
        message.support_versions = vec!["1.0.0".to_string(), "1.1.1".to_string()];

        let byte = message.encode();
        assert_eq!(message, ProtocolMessage::decode(&byte).unwrap())
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

        assert_eq!(select_version(&b, &a), vec!["2.0.0".to_string()]);
        assert_eq!(select_version(&b, &e), vec!["1.0.0".to_string()]);
        assert!(select_version(&b, &c).is_empty());
        assert!(select_version(&b, &d).is_empty());
        assert!(select_version(&d, &a).is_empty());
        assert!(select_version(&d, &e).is_empty());
        assert!(select_version(&e, &d).is_empty());
    }

    fn select_protocol(server: Vec<String>, client: Vec<String>, result: &Option<String>) {
        let listener = TcpListener::bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let (sender, receiver_1) = sync::oneshot::channel::<Option<String>>();

        let server = listener
            .incoming()
            .into_future()
            .and_then(move |(connect, _)| {
                let mut message = ProtocolMessage::default();
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
                let mut message = ProtocolMessage::default();
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
