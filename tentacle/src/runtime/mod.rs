#![allow(dead_code)]

#[cfg(all(not(target_arch = "wasm32"), feature = "async-runtime"))]
mod async_runtime;
#[cfg(any(
    feature = "generic-timer",
    all(target_arch = "wasm32", feature = "wasm-timer")
))]
mod generic_timer;
#[cfg(all(not(target_arch = "wasm32"), feature = "tokio-runtime"))]
mod tokio_runtime;
#[cfg(target_arch = "wasm32")]
mod wasm_runtime;

#[cfg(all(not(target_arch = "wasm32"), feature = "async-runtime"))]
pub use async_runtime::*;
#[cfg(any(
    feature = "generic-timer",
    all(target_arch = "wasm32", feature = "wasm-timer")
))]
pub use generic_timer::*;
#[cfg(all(not(target_arch = "wasm32"), feature = "tokio-runtime"))]
pub use tokio_runtime::*;
#[cfg(target_arch = "wasm32")]
pub use wasm_runtime::*;
