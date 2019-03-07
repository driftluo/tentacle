use crate::{yamux::config::Config as YamuxConfig, ProtocolId};
use std::collections::HashSet;
use std::time::Duration;

pub(crate) struct ServiceConfig {
    pub timeout: Duration,
    pub yamux_config: YamuxConfig,
    pub max_frame_length: usize,
    /// event output or callback output
    pub event: HashSet<ProtocolId>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            timeout: Duration::from_secs(10),
            yamux_config: YamuxConfig::default(),
            max_frame_length: 1024 * 1024 * 8,
            event: HashSet::default(),
        }
    }
}

/// When dial, specify which protocol want to open
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum DialProtocol {
    /// Try open all protocol
    All,
    /// Try open one protocol
    Single(ProtocolId),
    /// Try open some protocol
    Multi(Vec<ProtocolId>),
}
