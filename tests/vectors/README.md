# Test vectors

Official test vectors, run through the core's own wrappers (not only the
libraries') so that a wrong parameter or byte order in our code fails a test.

| File / place | Source | Downloaded | SHA-256 of the file | Licence |
|---|---|---|---|---|
| `wycheproof_xchacha20_poly1305_test.json` | Wycheproof, `testvectors_v1/xchacha20_poly1305_test.json` from <https://github.com/C2SP/wycheproof> (315 tests: 246 valid, 69 invalid) | 18 Oct 2026 | `a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9` | Apache License 2.0 |
| XChaCha20-Poly1305 AEAD vector, inline in `src/crypto/aead.rs` | draft-irtf-cfrg-xchacha-03, appendix A.3.1 | 18 Oct 2026 | – | IETF Trust |
| Argon2id vector, inline in `src/crypto/pwhash.rs` | RFC 9106, section 5.3 | 18 Oct 2026 | – | IETF Trust |
| HKDF-SHA-256 vectors, inline in `src/crypto/kdf.rs` | RFC 5869, appendix A.1–A.3 | 18 Oct 2026 | – | IETF Trust |

`src/keys/eff_large_wordlist.txt` (for suggested passphrases) is EFF's long
word list from <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>,
downloaded 18 Oct 2026, SHA-256
`addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`, licensed
CC BY 3.0 US (attribution in the app's licence screen).
