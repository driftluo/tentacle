use std::env;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(ossl110)");
    if let Ok(v) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&v, 16).unwrap();

        if version >= 0x1010_0000 {
            println!("cargo:rustc-cfg=ossl110");
        }
    }
}
