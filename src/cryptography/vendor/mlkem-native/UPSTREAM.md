# mlkem-native provenance

This directory vendors the portable C implementation of ML-KEM from
[`pq-code-package/mlkem-native`](https://github.com/pq-code-package/mlkem-native).

- Upstream release: `v1.2.0`
- Upstream commit: `0ba906cb14b1c241476134d7403a811b382ca498`
- Retrieved: 2026-07-23
- License: Apache-2.0 OR ISC OR MIT (see `LICENSE`)

The files under `mlkem/` are unmodified upstream files. The native assembly
backends and `mlkem_native_asm.S` are intentionally omitted: p2party builds the
portable C backend for WebAssembly with `MLK_CONFIG_NO_ASM`.

The p2party-specific configuration and ABI wrapper live outside this vendored
tree in `src/cryptography/mlkem768.c` and
`src/cryptography/mlkem768.h`.
