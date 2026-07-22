import 'package:hooks/hooks.dart';
import 'package:native_toolchain_rust/native_toolchain_rust.dart';

void main(List<String> args) async {
  await build(args, (BuildInput input, BuildOutputBuilder output) async {
    // native_toolchain_rust checks internally whether code assets
    // are being requested — no manual codeConfig null check needed.
    // It also handles:
    //   - Android NDK detection and cargo-ndk invocation
    //   - iOS/macOS Xcode toolchain
    //   - Linux/Windows host detection
    //   - Correct Rust target triple per platform
    //   - Native asset declaration
    //   - Build cache invalidation (Cargo.toml + src/ deps)

    await RustBuilder(
      // Path to the Rust crate, relative to the Flutter package root.
      // native_toolchain_rust looks for Cargo.toml at rust/Cargo.toml.
      cratePath: 'native',

      // CRITICAL: must match the asset name in the generated Dart code.
      // Generated code uses: "package:sp_flutter/uniffi:spffi"
      // The asset name portion (after the package prefix) is: "uniffi:spffi"
      assetName: 'uniffi:sp_dart_ffi',
    ).run(input: input, output: output);
  });
}
