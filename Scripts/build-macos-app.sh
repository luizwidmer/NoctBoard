#!/usr/bin/env bash
set -euo pipefail

configuration="${1:-release}"
case "$configuration" in
    debug|release) ;;
    *)
        echo "usage: $0 [debug|release]" >&2
        exit 64
        ;;
esac

script_dir="$(cd "$(dirname "$0")" && pwd)"
repository_dir="$(cd "$script_dir/.." && pwd)"
scratch_path="${NOCTBOARD_BUILD_PATH:-$repository_dir/.build}"
bundle_path="$repository_dir/dist/NoctBoard.app"
contents_path="$bundle_path/Contents"
codesign_identity="${NOCTBOARD_CODESIGN_IDENTITY:--}"

swift build \
    --package-path "$repository_dir" \
    --scratch-path "$scratch_path" \
    --configuration "$configuration" \
    --product NoctBoardApp

binary_dir="$(swift build \
    --package-path "$repository_dir" \
    --scratch-path "$scratch_path" \
    --configuration "$configuration" \
    --show-bin-path)"

rm -rf -- "$bundle_path"
mkdir -p "$contents_path/MacOS"
cp "$binary_dir/NoctBoardApp" "$contents_path/MacOS/NoctBoardApp"
cp "$repository_dir/Packaging/Info.plist" "$contents_path/Info.plist"
chmod 755 "$contents_path/MacOS/NoctBoardApp"

signing_options=(--force --sign "$codesign_identity")
if [[ "$codesign_identity" == "-" ]]; then
    signing_options+=(--timestamp=none)
else
    signing_options+=(--options runtime --timestamp)
fi
codesign \
    "${signing_options[@]}" \
    --entitlements "$repository_dir/Packaging/NoctBoardApp.entitlements" \
    "$bundle_path"
codesign --verify --strict --verbose=2 "$bundle_path"
touch "$bundle_path"

echo "$bundle_path"
