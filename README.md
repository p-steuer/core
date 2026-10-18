# secure_core

The security core of the app: cryptography, keys, file and sync formats, sync merging, sharing and permissions (D26). The Flutter app in `../app` uses it; the screens never see keys.

- **Brand-neutral on purpose:** the app's name lives only in `../app/branding.json`, so renaming the app never touches this repository.
- **Never published or pushed** (the owner's rule): `publish = false` in `Cargo.toml`, and a git hook refuses every push.
- **Toolchain pinned** in `rust-toolchain.toml`, for reproducible builds.

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

- **Design:** `docs/crypto-design.tex` (build the PDF with `latexmk -pdf -outdir=build crypto-design.tex` in `docs/`).
- **Test vectors** and their sources: `tests/vectors/README.md`. **Golden files** (`tests/golden/`) pin the file formats; rewrite them only after a deliberate format change, with `UPDATE_GOLDEN=1 cargo test golden`.
- More commands (timing Argon2id, valgrind): `../DEVELOPMENT.md`, "Core commands".
