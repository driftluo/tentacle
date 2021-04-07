#![allow(dead_code)]

#[cfg(feature = "parking_lot")]
pub use parking_lot::{const_fair_mutex, const_mutex, const_rwlock, FairMutex, Mutex, RwLock};
#[cfg(not(feature = "parking_lot"))]
pub mod native;

#[cfg(not(feature = "parking_lot"))]
pub use native::{Mutex, RwLock};
