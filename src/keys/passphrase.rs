//! Passphrase rules (P63): normalisation, length, strength and suggestions.

use std::sync::OnceLock;

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::rand::{self, OsRng, Rng};
use crate::{Error, Result};

/// NIST SP 800-63B-4's minimum for a password that is the only factor (D54,
/// 19 Oct 2026): a copied vault can be attacked offline, so ours mustn't be
/// lower.
pub const MIN_CHARS: usize = 15;
pub const MAX_CHARS: usize = 1024;
/// zxcvbn's score 3: "safely unguessable: moderate protection from offline
/// slow-hash scenario".
pub const MIN_SCORE: u8 = 3;
const SUGGESTED_WORDS: usize = 5;

/// EFF's long word list (7,776 words, so log2(7776) ≈ 12.9 bits per word).
const WORDLIST: &str = include_str!("eff_large_wordlist.txt");

/// What the user typed, prepared for hashing. Applied the same way when the
/// passphrase is set and whenever it is entered:
/// - every kind of whitespace becomes an ordinary space (RFC 8265's
///   OpaqueString profile maps non-ASCII spaces the same way);
/// - Unicode NFC, so the same visible text always gives the same bytes on
///   every keyboard and system;
/// - spaces at the start and end are dropped, because keyboards add them
///   after a word (NIST SP 800-63B allows this).
pub fn normalize(input: &str) -> Zeroizing<String> {
    let spaced: Zeroizing<String> = Zeroizing::new(
        input
            .chars()
            .map(|c| if c.is_whitespace() { ' ' } else { c })
            .collect(),
    );
    let composed: Zeroizing<String> = Zeroizing::new(spaced.nfc().collect());
    Zeroizing::new(composed.trim_matches(' ').to_owned())
}

/// A hint to show under the passphrase field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hint {
    None,
    TooShort,
    TooLong,
    CommonPassword,
    KeyboardPattern,
    Repeats,
    Sequence,
    DatesOrYears,
    SingleWordOrName,
    AddWords,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Strength {
    /// zxcvbn's score, 0 to 4.
    pub score: u8,
    pub acceptable: bool,
    pub hint: Hint,
}

pub fn strength(input: &str) -> Strength {
    let p = normalize(input);
    let chars = p.chars().count();
    let entropy = zxcvbn::zxcvbn(&p, &[]);
    let score: u8 = entropy.score().into();
    let hint = if chars < MIN_CHARS {
        Hint::TooShort
    } else if chars > MAX_CHARS {
        Hint::TooLong
    } else if score >= MIN_SCORE {
        Hint::None
    } else {
        hint_from(entropy.feedback().and_then(|f| f.warning()))
    };
    Strength {
        score,
        acceptable: hint == Hint::None,
        hint,
    }
}

fn hint_from(warning: Option<zxcvbn::feedback::Warning>) -> Hint {
    use zxcvbn::feedback::Warning as W;
    match warning {
        Some(
            W::ThisIsATop10Password
            | W::ThisIsATop100Password
            | W::ThisIsACommonPassword
            | W::ThisIsSimilarToACommonlyUsedPassword,
        ) => Hint::CommonPassword,
        Some(W::StraightRowsOfKeysAreEasyToGuess | W::ShortKeyboardPatternsAreEasyToGuess) => {
            Hint::KeyboardPattern
        }
        Some(
            W::RepeatsLikeAaaAreEasyToGuess | W::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess,
        ) => Hint::Repeats,
        Some(W::SequencesLikeAbcAreEasyToGuess) => Hint::Sequence,
        Some(W::RecentYearsAreEasyToGuess | W::DatesAreOftenEasyToGuess) => Hint::DatesOrYears,
        Some(
            W::AWordByItselfIsEasyToGuess
            | W::NamesAndSurnamesByThemselvesAreEasyToGuess
            | W::CommonNamesAndSurnamesAreEasyToGuess,
        ) => Hint::SingleWordOrName,
        None => Hint::AddWords,
    }
}

/// Checks an already normalised passphrase against the rules.
pub(crate) fn check(normalized: &str) -> Result<()> {
    match strength(normalized).hint {
        Hint::None => Ok(()),
        Hint::TooShort => Err(Error::PassphraseTooShort),
        Hint::TooLong => Err(Error::PassphraseTooLong),
        _ => Err(Error::PassphraseTooWeak),
    }
}

fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST
            .lines()
            .map(|line| line.split_once('\t').expect("dice\tword").1)
            .collect()
    })
}

/// Five random words from EFF's list, separated by spaces (about 64.6 bits).
pub fn suggest() -> Result<Zeroizing<String>> {
    suggest_with(&mut OsRng)
}

pub(crate) fn suggest_with(rng: &mut dyn Rng) -> Result<Zeroizing<String>> {
    let list = words();
    loop {
        let mut out = Zeroizing::new(String::new());
        for i in 0..SUGGESTED_WORDS {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(list[rand::below(rng, list.len() as u32)? as usize]);
        }
        // Practically always true; the check guards against a rare
        // combination that zxcvbn would rate lower.
        if strength(&out).acceptable {
            return Ok(out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::TestRng;
    use sha2::Digest;

    #[test]
    fn wordlist_is_the_downloaded_file() {
        // See tests/vectors/README.md.
        assert_eq!(
            hex::encode(sha2::Sha256::digest(WORDLIST.as_bytes())),
            "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
        );
        let w = words();
        assert_eq!(w.len(), 7776);
        let unique: std::collections::HashSet<_> = w.iter().collect();
        assert_eq!(unique.len(), 7776);
    }

    #[test]
    fn normalisation() {
        assert_eq!(
            &normalize("  horse\u{00A0}battery\tstaple ")[..],
            "horse battery staple"
        );
        // "é" typed as e + combining accent equals the precomposed "é".
        assert_eq!(normalize("cafe\u{0301}"), normalize("caf\u{00E9}"));
        assert_eq!(&normalize("caf\u{00E9}")[..], "caf\u{00E9}");
        // Case is kept, and inner double spaces are kept.
        assert_eq!(&normalize("A  b")[..], "A  b");
        assert_eq!(&normalize("   ")[..], "");
    }

    #[test]
    fn length_rules() {
        assert_eq!(strength("").hint, Hint::TooShort);
        // D54: 15 characters at least; 14 are too few.
        assert_eq!(strength("Kx9#mQ2$vL7&pR").hint, Hint::TooShort);
        assert_eq!(strength("Kx9#mQ2$vL7&pR4").hint, Hint::None);
        assert_eq!(strength(&"word ".repeat(300)).hint, Hint::TooLong);
        // Trailing spaces don't count towards the length.
        assert_eq!(strength("Kx9#mQ2$vL7&pR    ").hint, Hint::TooShort);
    }

    #[test]
    fn weak_passphrases_are_refused_with_a_hint() {
        for (p, hint) in [
            // One entry of zxcvbn's list (rank 12,590), so no other match
            // ties with it and the hint is always the same (see below).
            ("qwerty123456789", Hint::CommonPassword),
            // Most keyboard walks are on zxcvbn's list of common passwords
            // ("qwertyuiopasdf" is), so this one is longer and unusual.
            ("asdfghjkl;'zxcvb", Hint::KeyboardPattern),
            ("aaaaaaaaaaaaaaaa", Hint::Repeats),
            ("abcdefghijklmnop", Hint::Sequence),
        ] {
            let s = strength(p);
            assert!(!s.acceptable, "{p}");
            assert_eq!(s.hint, hint, "{p}");
            assert_eq!(check(&normalize(p)), Err(Error::PassphraseTooWeak), "{p}");
        }
    }

    // Regression (19 Oct 2026): zxcvbn 3.1.1 walks hash maps in random order
    // and keeps the first of two equally cheap match sequences. For
    // "password123456789" the digits are a dictionary word or a sequence,
    // both at its floor of 50 guesses, so its warning, and our hint, change
    // from call to call. A test that expected one of them failed at random.
    // Only the hint may change, never the score: whether a passphrase is
    // accepted must not depend on chance.
    #[test]
    fn regression_2026_10_19_zxcvbn_ties_change_only_the_hint() {
        for p in ["password123456789", "football12345678", "letmein123456789"] {
            let first = strength(p);
            for _ in 0..300 {
                let s = strength(p);
                assert_eq!(
                    (s.score, s.acceptable),
                    (first.score, first.acceptable),
                    "{p}"
                );
                assert!(
                    matches!(s.hint, Hint::CommonPassword | Hint::Sequence),
                    "{p}: {:?}",
                    s.hint
                );
            }
        }
    }

    #[test]
    fn strong_passphrases_are_accepted() {
        for p in [
            "crisp banjo delta mower tulip",
            "Mein Hund frisst gern Brokkoli 1987!",
        ] {
            let s = strength(p);
            assert!(s.acceptable, "{p}: {s:?}");
            assert!(s.score >= MIN_SCORE);
            assert_eq!(check(&normalize(p)), Ok(()));
        }
    }

    #[test]
    fn suggestions_are_five_list_words_and_acceptable() {
        let mut rng = TestRng::new("suggest");
        let list: std::collections::HashSet<&str> = words().iter().copied().collect();
        for _ in 0..100 {
            let s = suggest_with(&mut rng).unwrap();
            let parts: Vec<&str> = s.split(' ').collect();
            assert_eq!(parts.len(), 5);
            assert!(parts.iter().all(|w| list.contains(w)));
            assert!(strength(&s).acceptable);
        }
    }
}
