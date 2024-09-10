mod simple;
mod utils;

use wasm_bindgen::prelude::*;

#[cfg(feature = "talc")]
static mut ARENA: [u8; 10000] = [0; 1000000];

#[cfg(feature = "talc")]
#[global_allocator]
static ALLOCATOR: talc::Talck<spin::Mutex<()>, talc::ClaimOnOom> = talc::Talc::new(unsafe {
    // if we're in a hosted environment, the Rust runtime may allocate before
    // main() is called, so we need to initialize the arena automatically
    talc::ClaimOnOom::new(talc::Span::from_const_array(core::ptr::addr_of!(ARENA)))
})
.lock();

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet() {
    utils::set_panic_hook();
    wasm_logger::init(wasm_logger::Config::new(log::Level::Info));
    simple::client();
}
