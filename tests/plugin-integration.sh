#!/bin/sh
set -eu
# Run from the repository root with the same Go toolchain used for the proxy.
task_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ads-plugin-integration.XXXXXX")
trap 'rm -rf "$task_tmp"' EXIT HUP INT TERM
for version in v1 v2 incompatible; do
    go build -buildmode=plugin -o "$task_tmp/$version.so" "./internal/plugin/testdata/$version"
done
go run ./internal/plugin/testdata/check "$task_tmp/v1.so" "$task_tmp/v2.so" "$task_tmp/incompatible.so"
