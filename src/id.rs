//! Record identifiers: UUID version 7 (RFC 9562), a millisecond timestamp
//! followed by random bits, so new records sort by creation time. Identifiers
//! only appear inside encrypted data.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::Result;
use crate::rand::{self, OsRng, Rng};

pub fn new_record_id() -> Result<String> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    uuid_v7(ms, &mut OsRng)
}

fn uuid_v7(ms: u64, rng: &mut dyn Rng) -> Result<String> {
    let mut b: [u8; 16] = rand::array(rng)?;
    b[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
    b[6] = 0x70 | (b[6] & 0x0F); // version 7
    b[8] = 0x80 | (b[8] & 0x3F); // variant 10
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rand::TestRng;

    #[test]
    fn layout_follows_rfc_9562() {
        let id = uuid_v7(0x0123_4567_89AB, &mut TestRng::new("id")).unwrap();
        assert_eq!(id.len(), 36);
        assert!(id.starts_with("01234567-89ab-7"), "{id}");
        let variant = u8::from_str_radix(&id[19..20], 16).unwrap();
        assert_eq!(variant & 0b1100, 0b1000, "{id}");
        assert!(
            id.bytes()
                .all(|c| c == b'-' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn ids_are_unique_and_sort_by_time() {
        let a = uuid_v7(1_000, &mut TestRng::new("a")).unwrap();
        let b = uuid_v7(1_001, &mut TestRng::new("a")).unwrap();
        assert!(a < b);
        let set: std::collections::HashSet<String> =
            (0..1000).map(|_| new_record_id().unwrap()).collect();
        assert_eq!(set.len(), 1000);
    }
}
