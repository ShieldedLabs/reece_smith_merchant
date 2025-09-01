use cbindgen::*;
fn main() {
    let config = Config{
        language: Language::C,
        cpp_compat: true,
        usize_is_size_t: true,
        no_includes: true,
        enumeration: EnumConfig {
            prefix_with_name: true,
            .. Default::default()
        },
        .. Default::default()
    };

    match generate_with_config(".", config) {
        Err(err) => { eprintln!("Header-gen error: {}", err); }
        Ok(v) => { v.write_to_file("reece_smith_merchant.h"); }
    }
}
