use cbindgen::*;
fn main() {
    eprintln!("Starting header-gen");
    let config = Config{
        language: Language::C,
        cpp_compat: true,
        usize_is_size_t: true,
        no_includes: true,
        tab_width: 4,
        style: Style::Both,
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
