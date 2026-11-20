#!/bin/sh
# Builds klav-ffi for iOS and macOS and packs it for Xcode (ADR 0018,
# ADR 0027 §3):
#
#   target/ios/KlavFFI.xcframework     static library: iPhone, simulator
#                                       and Mac slices, each with its C header
#                                       and module map
#   target/ios/bindings/klav_ffi.swift    Swift bindings of the iOS slices
#   target/macos/bindings/klav_ffi.swift  Swift bindings of the Mac slice
#
# The Mac slice has the `daemon` feature (`DaemonEngine`, a client of
# klavd); the iOS slices and their bindings are built without it, so the
# iOS app does not change. Each slice links only against its own bindings
# (uniffi checks them at startup).
#
# Everything goes under target/ (which may be a symlink to an external
# disk); nothing generated is committed.
#
#   scripts/ios/build-xcframework.sh            debug (fast, for the simulator)
#   scripts/ios/build-xcframework.sh --release  release
#   KLAV_IOS_TARGETS="aarch64-apple-ios-sim"   build only some slices
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"

profile=debug
cargo_profile=
if [ "${1:-}" = "--release" ]; then
	profile=release
	cargo_profile=--release
fi
targets=${KLAV_IOS_TARGETS:-"aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin"}
out=target/ios
mac_out=target/macos
min_ios=${IPHONEOS_DEPLOYMENT_TARGET:-18.0}
min_macos=${MACOSX_DEPLOYMENT_TARGET:-15.0}

command -v xcodebuild >/dev/null || { echo "xcodebuild not found: install Xcode" >&2; exit 1; }
for t in $targets; do
	rustup target list --installed | grep -qx "$t" || rustup target add "$t"
done

# Swift bindings for one feature set: `$1` is the output directory, the
# rest go to cargo. The host library is enough for uniffi-bindgen (library
# mode reads the interface metadata from it).
bindings() {
	dir=$1
	shift
	cargo build -p klav-ffi --lib --locked "$@"
	rm -rf "$dir/bindings" "$dir/headers"
	mkdir -p "$dir/bindings" "$dir/headers"
	target/debug/uniffi-bindgen generate --library target/debug/libklav_ffi.dylib \
		--language swift --out-dir "$dir/bindings"
	mv "$dir/bindings/klav_ffiFFI.h" "$dir/headers/"
	# Xcode looks for exactly `module.modulemap` inside the framework headers.
	mv "$dir/bindings/klav_ffiFFI.modulemap" "$dir/headers/module.modulemap"
}

cargo build -p klav-ffi --features bindgen --bin uniffi-bindgen --locked
bindings "$out"
case " $targets " in
*" aarch64-apple-darwin "*) bindings "$mac_out" --features daemon ;;
esac

args=
for t in $targets; do
	case "$t" in
	*-apple-darwin)
		MACOSX_DEPLOYMENT_TARGET=$min_macos cargo build -p klav-ffi --lib --locked \
			--features daemon --target "$t" $cargo_profile
		args="$args -library target/$t/$profile/libklav_ffi.a -headers $mac_out/headers"
		;;
	*)
		IPHONEOS_DEPLOYMENT_TARGET=$min_ios cargo build -p klav-ffi --lib --locked --target "$t" $cargo_profile
		args="$args -library target/$t/$profile/libklav_ffi.a -headers $out/headers"
		;;
	esac
done
rm -rf "$out/KlavFFI.xcframework"
# shellcheck disable=SC2086
xcodebuild -create-xcframework $args -output "$out/KlavFFI.xcframework" >/dev/null
echo "$out/KlavFFI.xcframework"
echo "$out/bindings/klav_ffi.swift"
[ -f "$mac_out/bindings/klav_ffi.swift" ] && echo "$mac_out/bindings/klav_ffi.swift"
exit 0
