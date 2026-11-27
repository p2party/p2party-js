# mlkem-native provenance

This directory vendors the portable C implementation of ML-KEM from
[`pq-code-package/mlkem-native`](https://github.com/pq-code-package/mlkem-native).

- Upstream release: `v2.1.0`
- Upstream commit: `4d69d6b0358e678e3a694ea1bb8404a41770f68e`
- Retrieved: 2026-11-27
- License: Apache-2.0 OR ISC OR MIT (see `LICENSE`)

The files under `mlkem/` are unmodified upstream files. The native assembly
backends and `mlkem_native_asm.S` are intentionally omitted: p2party builds the
portable C backend for WebAssembly with `MLK_CONFIG_NO_ASM`.

The p2party-specific configuration and ABI wrapper live outside this vendored
tree in the three `src/cryptography/mlkem{512,768,1024}.{c,h}` wrappers. The upstream
README retains its CC-BY-4.0 license.
