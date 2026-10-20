//! Record identifiers: UUID version 7 (RFC 9562), a millisecond timestamp
//! followed by random bits, so new records sort by creation time. Identifiers
//! only appear inside encrypted data.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::rand::{self, OsRng, Rng};
use crate::{Error, Result};

pub fn new_record_id() -> Result<String> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    uuid_v7(ms, &mut OsRng)
}

/// An identifier stamped with another time than now: a session logged
/// afterwards, or one imported with its real date. Archives go by this time
/// (D55, P95), so the record lands in the year it belongs to.
pub fn new_record_id_at(ms: u64) -> Result<String> {
    if ms >= 1 << 48 {
        return Err(Error::InvalidInput("time"));
    }
    uuid_v7(ms, &mut OsRng)
}

pub(crate) fn uuid_v7(ms: u64, rng: &mut dyn Rng) -> Result<String> {
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

/// The UTC year a record was created in, from its UUIDv7 id; `None` for any
/// other id. Archives go by it (D55).
pub(crate) fn created_year(id: &[u8; 16]) -> Option<i32> {
    if id[6] >> 4 != 7 || id[8] >> 6 != 0b10 {
        return None;
    }
    let mut ms = [0u8; 8];
    ms[2..].copy_from_slice(&id[..6]);
    Some(year_of_ms(u64::from_be_bytes(ms)))
}

/// The UTC year of a time in milliseconds since 1970 (the civil calendar,
/// after Howard Hinnant's `civil_from_days`).
pub(crate) fn year_of_ms(ms: u64) -> i32 {
    let z = (ms / 86_400_000) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    // March is month 0 here, so January and February belong to the next year.
    let year = yoe + era * 400 + i64::from(mp >= 10);
    year as i32
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
    fn years_follow_the_calendar() {
        // 1970-01-01, 2000-02-29 (a leap day), 2026-12-31T23:59:59.999Z,
        // 2027-01-01, 2100-03-01, and the largest 48-bit time (year 10889).
        for (ms, year) in [
            (0, 1970),
            (951_782_400_000, 2000),
            (1_798_761_599_999, 2026),
            (1_798_761_600_000, 2027),
            (4_107_542_400_000, 2100),
            ((1 << 48) - 1, 10889),
        ] {
            assert_eq!(year_of_ms(ms), year, "{ms}");
        }
        let id = uuid_v7(1_798_761_599_999, &mut TestRng::new("y")).unwrap();
        let bytes = crate::store::unhex16(&id.replace('-', "")).unwrap();
        assert_eq!(created_year(&bytes), Some(2026));
        // Other versions and variants have no year.
        let mut other = bytes;
        other[6] = 0x40 | (other[6] & 0x0F);
        assert_eq!(created_year(&other), None);
        let mut other = bytes;
        other[8] &= 0x3F;
        assert_eq!(created_year(&other), None);
    }

    #[test]
    fn ids_can_carry_another_time() {
        // 1 June 2019, as for an imported session.
        let ms = 1_559_347_200_000;
        let id = new_record_id_at(ms).unwrap();
        let bytes = crate::store::unhex16(&id.replace('-', "")).unwrap();
        assert_eq!(created_year(&bytes), Some(2019));
        assert_eq!(crate::store::year_of(&id), Some(2019));
        assert_ne!(new_record_id_at(ms).unwrap(), id);
        assert!(new_record_id_at((1 << 48) - 1).is_ok());
        assert_eq!(new_record_id_at(1 << 48), Err(Error::InvalidInput("time")));
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
