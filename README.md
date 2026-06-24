# sp_dart

An experimental library to research the implementation of silent payments (BIP-352) in [bdk_dart](https://github.com/bitcoindevkit/bdk-dart)

---
* **Core SP Logic:** Built on top of the [spdk](https://github.com/cygnet3/spdk) repository.
* **Crate Routing:** `sp_dart` binds into the underlying [`silentpayments` sub-crate inside spdk](https://github.com/cygnet3/spdk/tree/master/silentpayments)
---
## 🧑‍💻 Contributor Workflow & Compilation

If you make modifications to the underlying Rust codebase, modify function signatures, or update dependency versions, you **must** regenerate the Dart FFI bridge definitions to avoid `UniFFI API checksum mismatch` runtime panics.

Follow this sequential workflow to clean, compile, and execute:

### 1. Re-generate Native FFI Interfaces
Navigate to the Rust crate root and invoke the binary code generator:

```powershell
# Navigate into the native layer
cd rust

# Wipe old target builds
cargo clean

# Build native executable binary
cargo build

# Build and execute the uniffi-bindgen runner
cargo run `
  --bin uniffi-bindgen `
  -- generate `
  --library target\debug\sp_dart_ffi.dll `
  --language dart `
  --config uniffi.toml `
  --out-dir ..\lib\src\generated\
```

### Note:
If you are building on Linux/macOS, adapt the `--library` path suffix to locate `libsp_dart_ffi.so` or `libsp_dart_ffi.dylib` respectively.

### 2. Purge and Run the Example App
Flutter strongly caches compiled native artifacts. Run a complete sweep before starting your target testing layout:

```powershell
cd example
flutter clean
flutter pub get
flutter run
```


## License
This experimental integration workspace is licensed under the MIT License.