//! Configuration of session and stream

use std::time::Duration;

/// Both sides assume the initial 256KB window size
pub const INITIAL_STREAM_WINDOW: u32 = 256 * 1024;
/// Default value for accept_backlog
pub const DEFAULT_ACCEPT_BACKLOG: usize = 256;
/// Default max stream count
pub const DEFAULT_MAX_STREAM_COUNT: usize = 65535;
/// Default keepalive interval duration
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// Default write timeout duration
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Configuration of session and stream
#[derive(Clone, Copy)]
pub struct Config {
    /// AcceptBacklog is used to limit how many streams may be
    /// waiting an accept.
    pub accept_backlog: usize,

    /// EnableKeepalive is used to do a period keep alive
    /// messages using a ping.
    pub enable_keepalive: bool,

    /// KeepAliveInterval is how often to perform the keep alive
    pub keepalive_interval: Duration,

    /// ConnectionWriteTimeout is meant to be a "safety valve" timeout after
    /// we which will suspect a problem with the underlying connection and
    /// close it. This is only applied to writes, where's there's generally
    /// an expectation that things will move along quickly.
    pub connection_write_timeout: Duration,

    /// Max stream count
    pub max_stream_count: usize,

    /// MaxStreamWindowSize is used to control the maximum
    /// window size that we allow for a stream.
    /// Must be greater than or equal to 256 * 1024
    pub max_stream_window_size: u32,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            accept_backlog: DEFAULT_ACCEPT_BACKLOG,
            enable_keepalive: true,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            connection_write_timeout: DEFAULT_WRITE_TIMEOUT,
            max_stream_count: DEFAULT_MAX_STREAM_COUNT,
            max_stream_window_size: INITIAL_STREAM_WINDOW,
        }
    }
}
