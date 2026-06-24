// Adapted directly from bdk-dart/native/uniffi-bindgen.rs.
// uniffi::uniffi_bindgen_main() only supports kotlin/swift/python/ruby.
// Dart requires manual interception and uniffi_dart::gen::generate_dart_bindings().

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let language = args
        .iter()
        .position(|arg| arg == "--language")
        .and_then(|idx| args.get(idx + 1));

    match language {
        Some(lang) if lang == "dart" => {
            use camino::Utf8Path;

            let library_path = args
                .iter()
                .find_map(|arg| {
                    if !arg.starts_with("--")
                        && (arg.ends_with(".dylib")
                            || arg.ends_with(".so")
                            || arg.ends_with(".dll"))
                    {
                        Some(arg.clone())
                    } else {
                        None
                    }
                })
                .expect("Library path not found — pass a .dylib, .so, or .dll file");

            let output_dir = args
                .iter()
                .position(|arg| arg == "--out-dir")
                .and_then(|idx| args.get(idx + 1))
                .expect("--out-dir is required");

            // For proc-macro projects the udl_path is a placeholder.
            // uniffi-dart reads the actual interface from the library's
            // embedded UNIFFI_META_* metadata, not from the udl_path.
            let udl_path = Utf8Path::new("src/lib.rs");

            // Get absolute path to uniffi.toml
            let current_dir = std::env::current_dir().expect("Failed to get current directory");
            let config_abs = current_dir.join("uniffi.toml");
            let config_path =
                Utf8Path::from_path(&config_abs).expect("uniffi.toml path contains invalid UTF-8");

            uniffi_dart::gen::generate_dart_bindings(
                udl_path,
                Some(config_path),
                Some(Utf8Path::new(output_dir.as_str())),
                Utf8Path::new(library_path.as_str()),
                true, // library mode (read from compiled .so)
            )
            .expect("Failed to generate Dart bindings");
        }

        _ => uniffi::uniffi_bindgen_main(),
    }
}
