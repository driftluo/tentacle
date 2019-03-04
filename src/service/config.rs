use crate::{yamux::config::Config as YamuxConfig, ProtocolId};
use std::collections::HashMap;
use std::time::Duration;

pub(crate) struct ServiceConfig {
    pub timeout: Duration,
    pub yamux_config: YamuxConfig,
    pub max_frame_length: usize,
    /// event output or callback output
    pub event: HashMap<ProtocolId, bool>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        ServiceConfig {
            timeout: Duration::from_secs(10),
            yamux_config: YamuxConfig::default(),
            max_frame_length: 1024 * 1024 * 8,
            event: HashMap::default(),
        }
    }
}
