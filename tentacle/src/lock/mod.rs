#![allow(dead_code, unused_imports)]

#[cfg(feature = "parking_lot")]
pub use parking_lot::{FairMutex, Mutex, RwLock, const_fair_mutex, const_mutex, const_rwlock};
#[cfg(not(feature = "parking_lot"))]
pub mod native;

#[cfg(not(feature = "parking_lot"))]
pub use native::{Mutex, RwLock};
