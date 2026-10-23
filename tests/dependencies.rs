//! Checks on the locked dependencies of the security core.

/// The version of a locked package, as (major, minor, patch).
fn locked(name: &str) -> (u32, u32, u32) {
    let lock = include_str!("../Cargo.lock");
    let entry = lock
        .split("[[package]]")
        .find(|p| p.contains(&format!("\nname = \"{name}\"\n")))
        .unwrap_or_else(|| panic!("{name} isn't in Cargo.lock"));
    let version = entry
        .lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .and_then(|v| v.strip_suffix('"'))
        .expect("a version");
    let mut parts = version
        .split('.')
        .map(|p| p.parse::<u32>().expect("a number"));
    (
        parts.next().expect("major"),
        parts.next().expect("minor"),
        parts.next().expect("patch"),
    )
}

/// Regression (23 Oct 2026): RUSTSEC-2026-0385. `ctutils` before 0.4.4 could
/// compile its constant-time masks into branches on secrets, and its `u128`
/// comparisons branched on 32-bit targets (the app also ships 32-bit ARM).
/// It sits under HMAC, SHA-256, HKDF, Argon2 and the Poly1305 tag check.
/// `cargo deny` catches advisories too, but only in the full checks, with
/// network access; this test runs with every `cargo test`.
#[test]
fn regression_2026_10_23_ctutils_has_the_constant_time_fix() {
    assert!(locked("ctutils") >= (0, 4, 4), "{:?}", locked("ctutils"));
}

#[test]
fn the_lock_reader_finds_versions() {
    // A pinned direct dependency (Cargo.toml: subtle = "=2.6.1").
    assert_eq!(locked("subtle"), (2, 6, 1));
}
