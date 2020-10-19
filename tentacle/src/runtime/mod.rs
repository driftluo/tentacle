#![allow(dead_code)]

#[cfg(feature = "async-runtime")]
mod async_runtime;
#[cfg(feature = "generic-timer")]
mod generic_timer;
#[cfg(all(not(target_os = "unknown"), feature = "tokio-runtime"))]
mod tokio_runtime;

#[cfg(feature = "async-runtime")]
pub use async_runtime::*;
#[cfg(feature = "generic-timer")]
pub use generic_timer::*;
#[cfg(all(not(target_os = "unknown"), feature = "tokio-runtime"))]
pub use tokio_runtime::*;
