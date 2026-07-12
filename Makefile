# Regenerate the committed C header from the Rust FFI surface (src/ffi.rs). The
# harness runs the same cbindgen invocation and fails the build on any drift, so
# after changing the FFI surface run `make header` and commit include/sextant.h.
.PHONY: header
header:
	cbindgen --config cbindgen.toml --crate sextant --lang c --output include/sextant.h
