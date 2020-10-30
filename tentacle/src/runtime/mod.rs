#![allow(dead_code)]

#[cfg(feature = "async-runtime")]
mod async_runtime;
#[cfg(any(feature = "generic-timer", target_arch = "wasm32"))]
mod generic_timer;
#[cfg(all(not(target_arch = "wasm32"), feature = "tokio-runtime"))]
mod tokio_runtime;
#[cfg(target_arch = "wasm32")]
mod wasm_runtime;

#[cfg(feature = "async-runtime")]
pub use async_runtime::*;
#[cfg(any(
    feature = "generic-timer",
    target_arch = "wasm32",
    feature = "wasm-timers"
))]
pub use generic_timer::*;
#[cfg(all(not(target_arch = "wasm32"), feature = "tokio-runtime"))]
pub use tokio_runtime::*;
#[cfg(target_arch = "wasm32")]
pub use wasm_runtime::*;
